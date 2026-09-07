#!/usr/bin/env python3
"""Launch a real SEV-SNP loader instance from a prebuilt AMI.

Companion to create.py (which launches an Ubuntu dev instance) for the real-TEE
path: the instance boots the two-tier SNP loader image built by deploy/snp-
build.sh, so there is no sshd — results are read back via EC2 console output.
Deletion still works purely by tag (delete.py), never by this file.

    python3 launch.py <ami-id>          launch and write hosts.json
    python3 launch.py --dry-run <ami>   ensure infra + resolve AMI, launch nothing
"""

import json
import sys
import time
from pathlib import Path

CLOUDTEST = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CLOUDTEST))  # import aws/config from the cloudtest dir

import boto3

from aws import ensure_igw, ensure_sg, ensure_subnet, ensure_vpc, wait_running
from config import load

HERE = Path(__file__).resolve().parent
HOSTS_FILE = CLOUDTEST / "hosts.json"


def run_snp(ec2, cfg, ami_id, vpc_id, subnet_id, sg_id):
    return ec2.run_instances(
        ImageId=ami_id,
        InstanceType=cfg.instance_type,
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[
            {
                "AssociatePublicIpAddress": True,
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
                "Groups": [sg_id],
            }
        ],
        CpuOptions={"AmdSevSnp": "enabled"},
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": cfg.tags(name=cfg.name_prefix)}
        ],
    )["Instances"][0]


def main() -> None:
    dry_run = "--dry-run" in sys.argv[1:]
    args = [a for a in sys.argv[1:] if a != "--dry-run"]
    if not args:
        sys.exit("usage: python3 launch.py [--dry-run] <ami-id>")
    ami_id = args[0]
    cfg = load()
    if not cfg.user:
        sys.exit("TOKENHIVE_USER is empty; refusing to launch untagged instances")

    ec2 = boto3.client("ec2", region_name=cfg.region)
    print(f"==> ensuring infrastructure in {cfg.region} (user tag: {cfg.user})")
    vpc_id = ensure_vpc(ec2, cfg)
    subnet_id = ensure_subnet(ec2, cfg, vpc_id)
    ensure_igw(ec2, cfg, vpc_id)
    sg_id = ensure_sg(ec2, cfg, vpc_id)
    print(f"==> AMI {ami_id} type {cfg.instance_type} AmdSevSnp=enabled")
    if dry_run:
        print("==> dry-run: would launch, launching nothing")
        return

    inst = run_snp(ec2, cfg, ami_id, vpc_id, subnet_id, sg_id)
    inst = wait_running(ec2, inst["InstanceId"])
    entry = {
        "instance_id": inst["InstanceId"],
        "public_ip": inst.get("PublicIpAddress", ""),
        "region": cfg.region,
        "instance_type": cfg.instance_type,
        "user_tag": cfg.user,
        "ami_id": ami_id,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    HOSTS_FILE.write_text(json.dumps(entry, indent=2) + "\n")
    print(f"==> instance {entry['instance_id']} running at {entry['public_ip']}")
    print(f"==> wrote {HOSTS_FILE}")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""Create a cloudtest TEE instance (step 1 of the lifecycle).

Idempotent: every piece of infrastructure is ensured (looked up, created only
if missing), and the launched instance's info is written to hosts.json,
overwriting whatever a previous run left there.

    python3 create.py

Refuses to touch any real resource unless AWS credentials are present; the only
safety valve here is that this script never deletes anything.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

from aws import (
    ensure_igw,
    ensure_key,
    ensure_sg,
    ensure_subnet,
    ensure_vpc,
    latest_ami,
    launch,
    wait_running,
)
from config import load

HERE = Path(__file__).resolve().parent
HOSTS_FILE = HERE / "hosts.json"
KEY_FILE = HERE / "ssh-key.pem"


def boto3_client(cfg):
    try:
        import boto3
    except ImportError:
        sys.exit("boto3 is not installed; run: pip install boto3")
    return boto3.client("ec2", region_name=cfg.region)


def ensure_local_key() -> None:
    if KEY_FILE.exists():
        return
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(KEY_FILE)], check=True
    )


def main() -> None:
    cfg = load()
    if not cfg.user:
        sys.exit("TOKENHIVE_USER is empty; refusing to launch untagged instances")
    ensure_local_key()
    ec2 = boto3_client(cfg)

    print(f"==> ensuring infrastructure in {cfg.region} (user tag: {cfg.user})")
    vpc_id = ensure_vpc(ec2, cfg)
    subnet_id = ensure_subnet(ec2, cfg, vpc_id)
    ensure_igw(ec2, cfg, vpc_id)
    sg_id = ensure_sg(ec2, cfg, vpc_id)
    ensure_key(ec2, cfg, public_key=KEY_FILE.with_suffix(".pem.pub").read_text().strip())

    ami = latest_ami(ec2, cfg)
    print(f"==> launching {cfg.instance_type} ({ami}) with AmdSevSnp=enabled")
    inst = launch(ec2, cfg, ami, vpc_id, subnet_id, sg_id)
    inst = wait_running(ec2, inst["InstanceId"])

    entry = {
        "instance_id": inst["InstanceId"],
        "public_ip": inst.get("PublicIpAddress", ""),
        "region": cfg.region,
        "instance_type": cfg.instance_type,
        "user_tag": cfg.user,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    HOSTS_FILE.write_text(json.dumps(entry, indent=2) + "\n")
    print(f"==> instance {entry['instance_id']} running at {entry['public_ip']}")
    print(f"==> wrote {HOSTS_FILE}")


if __name__ == "__main__":
    main()

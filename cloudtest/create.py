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


def ensure_local_key(key_name: str) -> None:
    """Refuse to mint a key: AWS has one key pair and this file must be its half.

    Same rule as cloudtest/snp/crosshost.py, and for the same reason: a key
    generated here can only ever be one AWS does not know, while ensure_key()
    skips the import whenever the pair already exists — so the fresh file
    replaces the deployment's only login key and only the machines launched
    afterwards accept it.
    """
    if KEY_FILE.exists():
        return
    sys.exit(
        f"no SSH private key at {KEY_FILE}; refusing to generate one.\n"
        f"It has to be the private half of the AWS key pair '{key_name}' — a "
        f"freshly generated key would not match it, and instances launched "
        f"with that pair would reject it.\n"
        f"Restore that key and rerun. Only a deployment whose key pair does "
        f"not exist yet may create one here (ssh-keygen -t ed25519 -N '' -f "
        f"{KEY_FILE}), because then it is the key AWS imports."
    )


def main() -> None:
    cfg = load()
    if not cfg.user:
        sys.exit("TOKENHIVE_USER is empty; refusing to launch untagged instances")
    ensure_local_key(cfg.key_name)
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

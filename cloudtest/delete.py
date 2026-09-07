#!/usr/bin/env python3
"""Delete cloudtest TEE instances (step 3 of the lifecycle).

Deletion NEVER reads hosts.json. Instances are found solely by the two
cloudtest tags (tokenhive-TEE=true AND user=<configured user>), every match is
re-verified locally, and anything that does not carry both tags is left alone.

    python3 delete.py            terminate every matching instance
    python3 delete.py --dry-run  list what would be terminated, delete nothing
"""

import sys

from aws import find_by_tags, terminate
from config import load


def boto3_client(cfg):
    try:
        import boto3
    except ImportError:
        sys.exit("boto3 is not installed; run: pip install boto3")
    return boto3.client("ec2", region_name=cfg.region)


def main() -> None:
    dry_run = "--dry-run" in sys.argv[1:]
    cfg = load()
    if not cfg.user:
        sys.exit("TOKENHIVE_USER is empty; refusing to delete by tag")

    ec2 = boto3_client(cfg)
    found = find_by_tags(ec2, cfg)
    if not found:
        print(
            f"==> no instances carry tag:{cfg.tag_owner}={cfg.tag_owner_value} "
            f"and tag:{cfg.tag_user}={cfg.user} in {cfg.region}"
        )
        return

    for inst in found:
        print(
            f"    {inst['InstanceId']}  {inst['State']['Name']}  "
            f"{inst.get('PublicIpAddress', '-')}"
        )
    if dry_run:
        print(f"==> dry-run: {len(found)} instance(s) would be terminated")
        return

    ids = [i["InstanceId"] for i in found]
    print(f"==> terminating {len(ids)} instance(s)")
    terminate(ec2, ids)
    print(f"==> terminated: {', '.join(ids)}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Tear down cloudtest NETWORK infrastructure (VPC, subnet, internet gateway,
security group, key pair) in the configured region/user.

THIS IS A RARELY-USED, DESTRUCTIVE TOOL. The normal lifecycle
(create -> test -> delete) only terminates instances; it leaves the (free)
network scaffolding in place so re-runs converge instead of rebuilding. Run
this only when you want to remove that scaffolding too — e.g. to fully reset a
region, or before rotating the cloudtest key pair.

Safety, identical to delete.py:
  * every resource is discovered solely by the two cloudtest tags
    (tokenhive-TEE=true AND user=<configured user>), locally re-verified;
  * removal is scoped to cfg.region, so other regions are unreachable;
  * nothing without both tags is touched;
  * always preview with --dry-run first.

    python3 delete_infra.py            tear down tagged infra
    python3 delete_infra.py --dry-run  list what would be torn down
"""

import sys

from aws import terminate_infra
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
    summary = terminate_infra(ec2, cfg, dry_run=dry_run)

    print(f"==> region {cfg.region}, user tag {cfg.user}")
    for kind, ids in summary.items():
        if ids:
            print(f"    {kind}: {', '.join(ids)}")
    if dry_run:
        print("==> dry-run: nothing deleted")
    else:
        print("==> torn down the resources listed above")


if __name__ == "__main__":
    main()

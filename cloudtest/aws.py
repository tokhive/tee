"""Idempotent AWS EC2 primitives for cloudtest.

Every ensure_* function follows the same contract: look the resource up by the
cloudtest tags; if it exists, return it unchanged; if it does not, create it
and tag it with the same pair. Re-running create.py therefore converges to the
existing setup instead of duplicating anything.

Every function takes the ec2 client as an argument and never constructs one, so
the unit tests drive them with a fake client and no AWS credentials are needed.
"""

from __future__ import annotations

import time

from config import Config

CANONICAL_OWNER = "099720109477"  # Ubuntu AMI owner account


def tag_filters(cfg: Config) -> list[dict]:
    return [
        {"Name": f"tag:{cfg.tag_owner}", "Values": [cfg.tag_owner_value]},
        {"Name": f"tag:{cfg.tag_user}", "Values": [cfg.user]},
    ]


def ensure_vpc(ec2, cfg: Config) -> str:
    vpcs = ec2.describe_vpcs(Filters=tag_filters(cfg))["Vpcs"]
    if vpcs:
        return vpcs[0]["VpcId"]
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    ec2.create_tags(Resources=[vpc["VpcId"]], Tags=cfg.tags(name=cfg.name_prefix))
    return vpc["VpcId"]


def ensure_subnet(ec2, cfg: Config, vpc_id: str) -> str:
    subnets = ec2.describe_subnets(
        Filters=tag_filters(cfg) + [{"Name": "vpc-id", "Values": [vpc_id]}]
    )["Subnets"]
    if subnets:
        return subnets[0]["SubnetId"]
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=az
    )["Subnet"]
    ec2.create_tags(Resources=[subnet["SubnetId"]], Tags=cfg.tags())
    ec2.modify_subnet_attribute(
        SubnetId=subnet["SubnetId"], MapPublicIpOnLaunch={"Value": True}
    )
    return subnet["SubnetId"]


def ensure_igw(ec2, cfg: Config, vpc_id: str) -> str:
    igws = ec2.describe_internet_gateways(
        Filters=tag_filters(cfg)
        + [{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
    )["InternetGateways"]
    if igws:
        return igws[0]["InternetGatewayId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]
    ec2.create_tags(Resources=[igw["InternetGatewayId"]], Tags=cfg.tags())
    ec2.attach_internet_gateway(InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id)
    # The VPC's main route table gets the default route to the gateway.
    rts = ec2.describe_route_tables(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "association.main", "Values": ["true"]},
        ]
    )["RouteTables"]
    rt_id = rts[0]["RouteTableId"]
    routes = [r.get("DestinationCidrBlock") for r in rts[0].get("Routes", [])]
    if "0.0.0.0/0" not in routes:
        ec2.create_route(
            RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0",
            GatewayId=igw["InternetGatewayId"],
        )
    return igw


def ensure_sg(ec2, cfg: Config, vpc_id: str) -> str:
    sgs = ec2.describe_security_groups(
        Filters=tag_filters(cfg) + [{"Name": "vpc-id", "Values": [vpc_id]}]
    )["SecurityGroups"]
    if sgs:
        return sgs[0]["GroupId"]
    sg_id = ec2.create_security_group(
        GroupName=f"{cfg.name_prefix}-sg",
        Description="tokenhive cloudtest: SSH only",
        VpcId=vpc_id,
    )["GroupId"]
    ec2.create_tags(Resources=[sg_id], Tags=cfg.tags())
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    return sg_id


def ensure_key(ec2, cfg: Config, public_key: str) -> str:
    """Import the local public key under the key name if AWS lacks it."""
    keys = ec2.describe_key_pairs(
        Filters=[{"Name": "key-name", "Values": [cfg.key_name]}]
    )["KeyPairs"]
    if keys:
        return keys[0]["KeyName"]
    ec2.import_key_pair(
        KeyName=cfg.key_name,
        PublicKeyMaterial=public_key,
        # Tag the key like every other cloudtest resource, so delete_infra can
        # discover and remove it by the same dual-tag rule as the rest.
        TagSpecifications=[{"ResourceType": "key-pair", "Tags": cfg.tags()}],
    )
    return cfg.key_name


def latest_ami(ec2, cfg: Config) -> str:
    images = ec2.describe_images(
        Owners=[CANONICAL_OWNER],
        Filters=[
            {"Name": "name", "Values": [cfg.ami_filter]},
            {"Name": "architecture", "Values": ["x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise RuntimeError(f"no AMI matches filter {cfg.ami_filter!r}")
    images.sort(key=lambda i: i["CreationDate"])
    return images[-1]["ImageId"]


def launch(ec2, cfg: Config, ami_id: str, vpc_id: str, subnet_id: str, sg_id: str) -> dict:
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=cfg.instance_type,
        KeyName=cfg.key_name,
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
    )
    return resp["Instances"][0]


def wait_running(ec2, instance_id: str, timeout: int = 300) -> dict:
    """Poll until the instance is running with a public IP."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
            "Instances"
        ][0]
        state = inst["State"]["Name"]
        if state == "running":
            ip = inst.get("PublicIpAddress")
            if ip:
                return inst
        if state in ("terminated", "shutting-down"):
            raise RuntimeError(f"instance {instance_id} entered state {state}")
        time.sleep(5)
    raise TimeoutError(f"instance {instance_id} not running within {timeout}s")


def find_by_tags(ec2, cfg: Config) -> list[dict]:
    """Non-terminated instances carrying both cloudtest tags.

    The server-side filter is matched again locally on the returned tags, so a
    stale or unexpected describe result can never widen the match set.
    """
    resp = ec2.describe_instances(
        Filters=tag_filters(cfg)
        + [
            {
                "Name": "instance-state-name",
                "Values": ["pending", "running", "stopping", "stopped"],
            }
        ]
    )
    found = []
    for res in resp.get("Reservations", []):
        for inst in res.get("Instances", []):
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            if (
                tags.get(cfg.tag_owner) == cfg.tag_owner_value
                and tags.get(cfg.tag_user) == cfg.user
            ):
                found.append(inst)
    return found


def terminate(ec2, instance_ids: list[str]) -> None:
    if instance_ids:
        ec2.terminate_instances(InstanceIds=instance_ids)


def wait_terminated(ec2, instance_ids: list[str], timeout: int = 360) -> None:
    """Poll until every listed instance is fully terminated.

    Instance termination is asynchronous on AWS: the security group, subnet and
    VPC stay pinned by a terminating instance's ENI until it fully disappears.
    delete_infra must wait here or its SG/subnet/VPC deletes fail mid-way and
    leak the scaffolding it was asked to remove.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = ec2.describe_instances(InstanceIds=instance_ids)
        states = [
            i["State"]["Name"]
            for r in resp.get("Reservations", [])
            for i in r.get("Instances", [])
        ]
        if not states or not ({s for s in states} - {"terminated", "shutting-down"}):
            return
        time.sleep(5)
    raise TimeoutError(f"instances not terminated within {timeout}s")


def _delete_with_retry(func, attempts: int = 8, delay: int = 5, **kwargs):
    """Retry a delete call a few times, absorbing transient AWS dependency
    errors (an ENI or SG still in use just after instance termination)."""
    for n in range(attempts):
        try:
            func(**kwargs)
            return
        except Exception:
            if n == attempts - 1:
                raise
            time.sleep(delay)


def _tagged(items: list[dict], cfg: Config) -> list[dict]:
    """Keep only items carrying BOTH cloudtest tags, re-checked locally.

    The server-side filter is a performance hint; this local re-verify is what
    actually prevents a stale or unexpectedly-broad describe from widening the
    match set. Mirrors find_by_tags for non-instance resources.
    """
    out = []
    for it in items:
        tags = {t["Key"]: t["Value"] for t in it.get("Tags", [])}
        if (
            tags.get(cfg.tag_owner) == cfg.tag_owner_value
            and tags.get(cfg.tag_user) == cfg.user
        ):
            out.append(it)
    return out


def find_vpcs_by_tags(ec2, cfg: Config) -> list[dict]:
    resp = ec2.describe_vpcs(Filters=tag_filters(cfg))
    return _tagged(resp.get("Vpcs", []), cfg)


def find_subnets_by_tags(ec2, cfg: Config) -> list[dict]:
    resp = ec2.describe_subnets(Filters=tag_filters(cfg))
    return _tagged(resp.get("Subnets", []), cfg)


def find_igws_by_tags(ec2, cfg: Config) -> list[dict]:
    resp = ec2.describe_internet_gateways(Filters=tag_filters(cfg))
    return _tagged(resp.get("InternetGateways", []), cfg)


def find_sgs_by_tags(ec2, cfg: Config) -> list[dict]:
    resp = ec2.describe_security_groups(Filters=tag_filters(cfg))
    return _tagged(resp.get("SecurityGroups", []), cfg)


def find_keys_by_tags(ec2, cfg: Config) -> list[dict]:
    resp = ec2.describe_key_pairs(Filters=tag_filters(cfg))
    return _tagged(resp.get("KeyPairs", []), cfg)


def terminate_infra(ec2, cfg: Config, dry_run: bool = False) -> dict:
    """Tear down every cloudtest-tagged resource in this region/user.

    Discovery is solely by the two cloudtest tags (locally re-verified), and
    removal happens in dependency order so AWS accepts each delete. Nothing
    that lacks both tags is touched, and the client is scoped to cfg.region so
    other regions are unreachable. Pass dry_run to list without deleting.

    This is the rare-use, destructive counterpart to delete.py: the normal
    lifecycle only terminates instances and leaves the (free) network
    scaffolding in place so re-runs converge.
    """
    insts = find_by_tags(ec2, cfg)
    vpcs = find_vpcs_by_tags(ec2, cfg)
    subnets = find_subnets_by_tags(ec2, cfg)
    igws = find_igws_by_tags(ec2, cfg)
    sgs = find_sgs_by_tags(ec2, cfg)
    keys = find_keys_by_tags(ec2, cfg)

    summary = {
        "instances": [i["InstanceId"] for i in insts],
        "vpcs": [v["VpcId"] for v in vpcs],
        "subnets": [s["SubnetId"] for s in subnets],
        "igws": [g["InternetGatewayId"] for g in igws],
        "security_groups": [g["GroupId"] for g in sgs],
        "key_pairs": [k["KeyName"] for k in keys],
    }
    if dry_run:
        return summary

    # 1. instances first, so subnets/VPC can be freed.
    if insts:
        terminate(ec2, summary["instances"])
        # Wait for the ENIs to release before the network deletes below, which
        # otherwise fail with DependencyViolation and leak the scaffolding.
        wait_terminated(ec2, summary["instances"])
    # 2. detach + delete internet gateways.
    for g in igws:
        for a in g.get("Attachments", []):
            try:
                ec2.detach_internet_gateway(
                    InternetGatewayId=g["InternetGatewayId"], VpcId=a["VpcId"]
                )
            except Exception:
                pass
        _delete_with_retry(ec2.delete_internet_gateway,
                           InternetGatewayId=g["InternetGatewayId"])
    # 3. security groups.
    for g in sgs:
        _delete_with_retry(ec2.delete_security_group, GroupId=g["GroupId"])
    # 4. subnets.
    for s in subnets:
        _delete_with_retry(ec2.delete_subnet, SubnetId=s["SubnetId"])
    # 5. vpcs (the auto-created main route table is removed with the VPC).
    for v in vpcs:
        _delete_with_retry(ec2.delete_vpc, VpcId=v["VpcId"])
    # 6. key pairs (identified by name, which embeds the user tag, so a
    #    different operator's key can never match).
    for k in keys:
        ec2.delete_key_pair(KeyName=k["KeyName"])
    return summary

"""Local unit tests for cloudtest. No boto3, no network: a fake EC2 client
drives the same aws.py code paths the real client would.

Run:  python3 -m unittest discover -s tests -v   (from the cloudtest dir)
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config as config_mod
import aws
from config import Config


def tags_dict(tags):
    return {t["Key"]: t["Value"] for t in (tags or [])}


class FakeEC2:
    """In-memory stand-in for a boto3 ec2 client, shaped like the real API."""

    def __init__(self):
        self.vpcs, self.subnets, self.igws, self.rts = [], [], [], []
        self.sgs, self.keys, self.images = [], [], []
        self.instances, self.next_id = [], 1
        self.last_run_instances = None

    # -- generic helpers ----------------------------------------------------
    def _match(self, tags, attrs, filters):
        for f in filters:
            name, values = f["Name"], f["Values"]
            if name.startswith("tag:"):
                if tags.get(name[4:]) not in values:
                    return False
            elif attrs.get(name) not in values:
                return False
        return True

    def _tag(self, resource_id, tags, stores):
        for store in stores:
            for r in store:
                if r.get("VpcId") == resource_id or r.get("SubnetId") == resource_id \
                   or r.get("InternetGatewayId") == resource_id \
                   or r.get("GroupId") == resource_id or r.get("InstanceId") == resource_id:
                    r.setdefault("Tags", []).extend(tags)
                    return
        raise KeyError(f"unknown resource {resource_id}")

    # -- VPC -----------------------------------------------------------------
    def describe_vpcs(self, Filters=None):
        return {"Vpcs": [v for v in self.vpcs if self._match(tags_dict(v.get("Tags")), {"vpc-id": v["VpcId"]}, Filters or [])]}

    def create_vpc(self, CidrBlock):
        vpc = {"VpcId": f"vpc-{len(self.vpcs)+1}", "CidrBlock": CidrBlock, "Tags": []}
        self.vpcs.append(vpc)
        # AWS auto-creates the VPC's main route table.
        self.rts.append({"RouteTableId": f"rt-{len(self.rts)+1}", "VpcId": vpc["VpcId"],
                         "Associations": [{"Main": True}],
                         "Routes": [{"DestinationCidrBlock": CidrBlock}]})
        return {"Vpc": vpc}

    def create_tags(self, Resources, Tags):
        for rid in Resources:
            self._tag(rid, Tags, (self.vpcs, self.subnets, self.igws, self.sgs, self.instances))

    # -- subnet ---------------------------------------------------------------
    def describe_subnets(self, Filters=None):
        return {"Subnets": [s for s in self.subnets if self._match(tags_dict(s.get("Tags")), {"vpc-id": s["VpcId"], "subnet-id": s["SubnetId"]}, Filters or [])]}

    def create_subnet(self, VpcId, CidrBlock, AvailabilityZone):
        sn = {"SubnetId": f"subnet-{len(self.subnets)+1}", "VpcId": VpcId,
              "CidrBlock": CidrBlock, "AvailabilityZone": AvailabilityZone, "Tags": []}
        self.subnets.append(sn)
        return {"Subnet": sn}

    def modify_subnet_attribute(self, SubnetId, MapPublicIpOnLaunch):
        pass

    def describe_availability_zones(self):
        return {"AvailabilityZones": [{"ZoneName": "us-west-2a"}]}

    # -- internet gateway ------------------------------------------------------
    def describe_internet_gateways(self, Filters=None):
        def attrs(g):
            return {"vpc-id": g["Attachments"][0]["VpcId"] if g["Attachments"] else None,
                    "internet-gateway-id": g["InternetGatewayId"]}
        return {"InternetGateways": [g for g in self.igws if self._match(tags_dict(g.get("Tags")), attrs(g), Filters or [])]}

    def create_internet_gateway(self):
        igw = {"InternetGatewayId": f"igw-{len(self.igws)+1}", "Attachments": [], "Tags": []}
        self.igws.append(igw)
        return {"InternetGateway": igw}

    def attach_internet_gateway(self, InternetGatewayId, VpcId):
        next(g for g in self.igws if g["InternetGatewayId"] == InternetGatewayId)["Attachments"].append({"VpcId": VpcId})

    def describe_route_tables(self, Filters=None):
        def attrs(rt):
            return {"vpc-id": rt["VpcId"],
                    "association.main": "true" if any(a.get("Main") for a in rt["Associations"]) else "false"}
        return {"RouteTables": [rt for rt in self.rts if self._match({}, attrs(rt), Filters or [])]}

    def create_route(self, RouteTableId, DestinationCidrBlock, GatewayId):
        rt = next(r for r in self.rts if r["RouteTableId"] == RouteTableId)
        rt["Routes"].append({"DestinationCidrBlock": DestinationCidrBlock, "GatewayId": GatewayId})
        self.last_create_route = {"RouteTableId": RouteTableId, "GatewayId": GatewayId}

    # -- security group ----------------------------------------------------------
    def describe_security_groups(self, Filters=None):
        return {"SecurityGroups": [g for g in self.sgs if self._match(tags_dict(g.get("Tags")), {"vpc-id": g["VpcId"], "group-id": g["GroupId"]}, Filters or [])]}

    def create_security_group(self, GroupName, Description, VpcId):
        sg = {"GroupId": f"sg-{len(self.sgs)+1}", "VpcId": VpcId,
              "GroupName": GroupName, "Description": Description, "Tags": []}
        self.sgs.append(sg)
        return {"GroupId": sg["GroupId"]}

    def authorize_security_group_ingress(self, GroupId, IpPermissions):
        pass

    # -- key pair -----------------------------------------------------------------
    def describe_key_pairs(self, Filters=None):
        return {"KeyPairs": [k for k in self.keys if self._match(tags_dict(k.get("Tags")), {"key-name": k["KeyName"]}, Filters or [])]}

    def import_key_pair(self, KeyName, PublicKeyMaterial, TagSpecifications=None):
        tags = []
        if TagSpecifications:
            for spec in TagSpecifications:
                tags.extend(spec.get("Tags", []))
        self.keys.append({"KeyName": KeyName, "KeyPairId": f"key-{len(self.keys)+1}",
                          "Tags": tags})
        return {"KeyName": KeyName}

    # -- images ---------------------------------------------------------------------
    def describe_images(self, Owners, Filters):
        images = [i for i in self.images
                  if i.get("Architecture") == "x86_64" and i.get("State") == "available"]
        return {"Images": images}

    # -- instances ---------------------------------------------------------------------
    def add_instance(self, tag_map, state="running", public_ip=None):
        inst = {"InstanceId": f"i-{self.next_id}", "State": {"Name": state},
                "Tags": [{"Key": k, "Value": v} for k, v in tag_map.items()],
                "PublicIpAddress": public_ip}
        self.next_id += 1
        self.instances.append(inst)
        return inst

    def run_instances(self, **kwargs):
        self.last_run_instances = kwargs
        tags = []
        for spec in kwargs.get("TagSpecifications", []):
            tags.extend(spec.get("Tags", []))
        inst = {"InstanceId": f"i-{self.next_id}", "State": {"Name": "pending"}, "Tags": tags}
        self.next_id += 1
        self.instances.append(inst)
        return {"Instances": [inst]}

    def describe_instances(self, InstanceIds=None, Filters=None):
        pool = [i for i in self.instances if InstanceIds is None or i["InstanceId"] in InstanceIds]
        if Filters is not None:
            pool = [i for i in pool if self._match(tags_dict(i.get("Tags")),
                    {"instance-state-name": i["State"]["Name"], "instance-id": i["InstanceId"]}, Filters)]
        return {"Reservations": [{"Instances": pool}]}

    def terminate_instances(self, InstanceIds):
        for i in self.instances:
            if i["InstanceId"] in InstanceIds:
                i["State"]["Name"] = "terminated"

    # -- infrastructure helpers (for delete_infra tests) --------------------
    def add_vpc(self, tag_map, cidr="10.0.0.0/16"):
        vpc = {"VpcId": f"vpc-{len(self.vpcs)+1}", "CidrBlock": cidr,
               "Tags": [{"Key": k, "Value": v} for k, v in tag_map.items()]}
        self.vpcs.append(vpc)
        self.rts.append({"RouteTableId": f"rt-{len(self.rts)+1}", "VpcId": vpc["VpcId"],
                         "Associations": [{"Main": True}],
                         "Routes": [{"DestinationCidrBlock": cidr}]})
        return vpc

    def add_subnet(self, tag_map, vpc_id=None, cidr="10.0.1.0/24"):
        vid = vpc_id or (self.vpcs[-1]["VpcId"] if self.vpcs else "vpc-1")
        sn = {"SubnetId": f"subnet-{len(self.subnets)+1}", "VpcId": vid, "CidrBlock": cidr,
              "Tags": [{"Key": k, "Value": v} for k, v in tag_map.items()]}
        self.subnets.append(sn)
        return sn

    def add_igw(self, tag_map, attachments=None):
        igw = {"InternetGatewayId": f"igw-{len(self.igws)+1}",
               "Attachments": attachments or [],
               "Tags": [{"Key": k, "Value": v} for k, v in tag_map.items()]}
        self.igws.append(igw)
        return igw

    def add_sg(self, tag_map, vpc_id=None):
        vid = vpc_id or (self.vpcs[-1]["VpcId"] if self.vpcs else "vpc-1")
        sg = {"GroupId": f"sg-{len(self.sgs)+1}", "VpcId": vid,
              "Tags": [{"Key": k, "Value": v} for k, v in tag_map.items()]}
        self.sgs.append(sg)
        return sg

    def add_key(self, name, tag_map=None):
        key = {"KeyName": name, "KeyPairId": f"key-{len(self.keys)+1}",
               "Tags": [{"Key": k, "Value": v} for k, v in (tag_map or {}).items()]}
        self.keys.append(key)
        return key

    def delete_vpc(self, VpcId):
        self.vpcs = [v for v in self.vpcs if v["VpcId"] != VpcId]

    def delete_subnet(self, SubnetId):
        self.subnets = [s for s in self.subnets if s["SubnetId"] != SubnetId]

    def delete_internet_gateway(self, InternetGatewayId):
        self.igws = [g for g in self.igws if g["InternetGatewayId"] != InternetGatewayId]

    def detach_internet_gateway(self, InternetGatewayId, VpcId):
        for g in self.igws:
            if g["InternetGatewayId"] == InternetGatewayId:
                g["Attachments"] = [a for a in g["Attachments"] if a.get("VpcId") != VpcId]

    def delete_security_group(self, GroupId):
        self.sgs = [g for g in self.sgs if g["GroupId"] != GroupId]

    def delete_key_pair(self, KeyName):
        self.keys = [k for k in self.keys if k["KeyName"] != KeyName]


class EnsureIdempotencyTest(unittest.TestCase):
    def test_vpc_ensure_creates_once(self):
        fake, cfg = FakeEC2(), Config(user="chenxinghao")
        v1 = aws.ensure_vpc(fake, cfg)
        v2 = aws.ensure_vpc(fake, cfg)
        self.assertEqual(v1, v2)
        self.assertEqual(len(fake.vpcs), 1)
        tags = tags_dict(fake.vpcs[0]["Tags"])
        self.assertEqual(tags["tokenhive-TEE"], "true")
        self.assertEqual(tags["user"], "chenxinghao")

    def test_infra_ensure_is_idempotent_end_to_end(self):
        fake, cfg = FakeEC2(), Config(user="chenxinghao")
        v = aws.ensure_vpc(fake, cfg)
        s1 = aws.ensure_subnet(fake, cfg, v)
        aws.ensure_igw(fake, cfg, v)
        g1 = aws.ensure_sg(fake, cfg, v)
        k1 = aws.ensure_key(fake, cfg, "ssh-ed25519 AAA test")
        s2 = aws.ensure_subnet(fake, cfg, v)
        aws.ensure_igw(fake, cfg, v)
        g2 = aws.ensure_sg(fake, cfg, v)
        k2 = aws.ensure_key(fake, cfg, "ssh-ed25519 AAA test")
        self.assertEqual(s1, s2)
        self.assertEqual(g1, g2)
        self.assertEqual(k1, k2)
        self.assertEqual(len(fake.subnets), 1)
        self.assertEqual(len(fake.sgs), 1)
        self.assertEqual(len(fake.keys), 1)

    def test_igw_route_is_created_once(self):
        fake, cfg = FakeEC2(), Config(user="chenxinghao")
        v = aws.ensure_vpc(fake, cfg)
        aws.ensure_igw(fake, cfg, v)
        aws.ensure_igw(fake, cfg, v)
        default = [r for r in fake.rts[0]["Routes"]
                   if r["DestinationCidrBlock"] == "0.0.0.0/0"]
        self.assertEqual(len(default), 1)
        # GatewayId must be the IGW id string, not the IGW dict — passing the
        # dict would make real AWS reject the call (ParamValidationError).
        self.assertIsInstance(fake.last_create_route["GatewayId"], str)
        self.assertTrue(fake.last_create_route["GatewayId"].startswith("igw-"))


class LaunchTest(unittest.TestCase):
    def test_launch_enables_sevsnp_and_both_tags(self):
        fake, cfg = FakeEC2(), Config(user="chenxinghao")
        aws.launch(fake, cfg, "ami-1", "vpc-1", "subnet-1", "sg-1")
        kwargs = fake.last_run_instances
        self.assertEqual(kwargs["CpuOptions"], {"AmdSevSnp": "enabled"})
        tags = kwargs["TagSpecifications"][0]["Tags"]
        self.assertIn({"Key": "tokenhive-TEE", "Value": "true"}, tags)
        self.assertIn({"Key": "user", "Value": "chenxinghao"}, tags)

    def test_wait_running_returns_public_ip(self):
        fake, cfg = FakeEC2(), Config(user="chenxinghao")
        inst = fake.add_instance({"tokenhive-TEE": "true", "user": "chenxinghao"}, public_ip="1.2.3.4")
        got = aws.wait_running(fake, inst["InstanceId"], timeout=1)
        self.assertEqual(got["PublicIpAddress"], "1.2.3.4")


class DeleteSafetyTest(unittest.TestCase):
    def setUp(self):
        self.fake, self.cfg = FakeEC2(), Config(user="chenxinghao")
        self.fake.add_instance({"tokenhive-TEE": "true", "user": "chenxinghao"}, "running", "1.0.0.1")
        self.fake.add_instance({"tokenhive-TEE": "true", "user": "someone-else"}, "running", "1.0.0.2")
        self.fake.add_instance({"tokenhive-TEE": "true"}, "running", "1.0.0.3")
        self.fake.add_instance({"user": "chenxinghao"}, "running", "1.0.0.4")
        self.fake.add_instance({"tokenhive-TEE": "true", "user": "chenxinghao"}, "terminated")

    def test_find_by_tags_only_matching_running(self):
        found = aws.find_by_tags(self.fake, self.cfg)
        self.assertEqual([i["InstanceId"] for i in found], ["i-1"])

    def test_delete_only_targets_matching_instances(self):
        found = aws.find_by_tags(self.fake, self.cfg)
        ids = [i["InstanceId"] for i in found]
        self.assertEqual(ids, ["i-1"])
        aws.terminate(self.fake, ids)
        states = {i["InstanceId"]: i["State"]["Name"] for i in self.fake.instances}
        self.assertEqual(states["i-1"], "terminated")
        self.assertEqual(states["i-2"], "running")
        self.assertEqual(states["i-3"], "running")
        self.assertEqual(states["i-4"], "running")


class ConfigTest(unittest.TestCase):
    def setUp(self):
        # Point load_env at a file that does not exist so these tests are
        # hermetic: a developer's real cloudtest/.env (which legitimately sets
        # TOKENHIVE_USER) must not decide whether they pass.
        self._saved_env_file = config_mod.ENV_FILE
        config_mod.ENV_FILE = Path("/nonexistent/.env")

    def tearDown(self):
        config_mod.ENV_FILE = self._saved_env_file

    def test_env_overrides_defaults(self):
        os.environ["TOKENHIVE_USER"] = "alice"
        try:
            cfg = config_mod.load()
            self.assertEqual(cfg.user, "alice")
            # Operator policy: eu-west-1 (Ireland) is the only allowed region.
            self.assertEqual(cfg.region, "eu-west-1")
        finally:
            del os.environ["TOKENHIVE_USER"]

    def test_load_requires_user(self):
        os.environ.pop("TOKENHIVE_USER", None)
        with self.assertRaises(SystemExit):
            config_mod.load()


class DeleteInfraSafetyTest(unittest.TestCase):
    def setUp(self):
        self.fake, self.cfg = FakeEC2(), Config(user="chenxinghao")
        self.fake.add_vpc({"tokenhive-TEE": "true", "user": "chenxinghao"})
        self.fake.add_subnet({"tokenhive-TEE": "true", "user": "chenxinghao"})
        self.fake.add_igw({"tokenhive-TEE": "true", "user": "chenxinghao"},
                          attachments=[{"VpcId": "vpc-1"}])
        self.fake.add_sg({"tokenhive-TEE": "true", "user": "chenxinghao"})
        self.fake.add_key("tokenhive-tee-chenxinghao",
                          {"tokenhive-TEE": "true", "user": "chenxinghao"})
        self.owned_inst = self.fake.add_instance(
            {"tokenhive-TEE": "true", "user": "chenxinghao"}, "running", "1.0.0.1")
        # foreign / untagged — must survive
        self.fake.add_vpc({"tokenhive-TEE": "true", "user": "someone-else"})
        self.fake.add_vpc({"user": "chenxinghao"})             # missing owner tag
        self.fake.add_vpc({})                                  # untagged
        self.fake.add_key("tokenhive-tee-someone-else",
                          {"tokenhive-TEE": "true", "user": "someone-else"})

    def test_dry_run_lists_only_owned(self):
        s = aws.terminate_infra(self.fake, self.cfg, dry_run=True)
        self.assertEqual(s["vpcs"], ["vpc-1"])
        self.assertEqual(s["subnets"], ["subnet-1"])
        self.assertEqual(s["igws"], ["igw-1"])
        self.assertEqual(s["security_groups"], ["sg-1"])
        self.assertEqual(s["key_pairs"], ["tokenhive-tee-chenxinghao"])
        self.assertEqual(s["instances"], [self.owned_inst["InstanceId"]])
        # dry-run touches nothing
        self.assertEqual(len(self.fake.vpcs), 4)

    def test_delete_removes_only_owned(self):
        aws.terminate_infra(self.fake, self.cfg, dry_run=False)
        vpc_ids = {v["VpcId"] for v in self.fake.vpcs}
        self.assertNotIn("vpc-1", vpc_ids)    # owned removed
        self.assertIn("vpc-2", vpc_ids)       # someone-else kept
        self.assertIn("vpc-3", vpc_ids)       # missing-owner kept
        self.assertIn("vpc-4", vpc_ids)       # untagged kept
        self.assertNotIn("subnet-1", {s["SubnetId"] for s in self.fake.subnets})
        self.assertNotIn("igw-1", {g["InternetGatewayId"] for g in self.fake.igws})
        self.assertNotIn("sg-1", {g["GroupId"] for g in self.fake.sgs})
        key_names = {k["KeyName"] for k in self.fake.keys}
        self.assertNotIn("tokenhive-tee-chenxinghao", key_names)
        self.assertIn("tokenhive-tee-someone-else", key_names)
        states = {i["InstanceId"]: i["State"]["Name"] for i in self.fake.instances}
        self.assertEqual(states[self.owned_inst["InstanceId"]], "terminated")


class WaitTerminatedTest(unittest.TestCase):
    def test_wait_terminated_blocks_until_all_terminated(self):
        self.fake, self.cfg = FakeEC2(), Config(user="chenxinghao")
        ids = [
            self.fake.add_instance({"tokenhive-TEE": "true", "user": "chenxinghao"}, "running")["InstanceId"],
            self.fake.add_instance({"tokenhive-TEE": "true", "user": "chenxinghao"}, "running")["InstanceId"],
        ]
        orig = aws.time.sleep
        n = {"v": 0}
        def fake_sleep(_):
            n["v"] += 1
            if n["v"] == 1:  # first poll still sees running; second sees terminated
                for i in self.fake.instances:
                    if i["State"]["Name"] == "running":
                        i["State"]["Name"] = "terminated"
        aws.time.sleep = fake_sleep
        try:
            aws.wait_terminated(self.fake, ids, timeout=30)  # must not raise
        finally:
            aws.time.sleep = orig


class StructureTest(unittest.TestCase):
    def test_delete_never_depends_on_hosts_file(self):
        src = Path(__file__).resolve().parent.parent.joinpath("delete.py").read_text()
        self.assertNotIn("HOSTS_FILE", src)
        self.assertNotIn("open(", src)


if __name__ == "__main__":
    unittest.main()

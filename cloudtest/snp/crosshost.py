#!/usr/bin/env python3
"""Cross-host launch: an ordinary host (Hub/agent/mockprovider) + a real SEV-SNP
confidential instance running the real `tee` binary under the two-tier loader.

The confidential instance has no sshd. Its runtime config is injected by the
loader from EC2 user-data, so this script encodes it as KEY=VAL lines:

    TOKENHIVE_SIM_DIR=/tmp/tee        writable state dir (loader mounts /tmp 0777)
    TEE_ADDR=0.0.0.0:18090            mTLS request plane the Hub dials
    TEE_RELAY=ws://<host-ip>:18085/v1/relay    reverse tunnel back to the Hub
    TEE_RELAY_KEY=<relay-key>          Hub TeeRelay authentication (shared with
                                       crosshost.sh's -relay-key)
    TEE_PLATFORM=sevsnp               real attestation (fail-fast off SNP)
    TEE_MTLS=1                         RA-TLS + demand a Hub client cert
    TEE_MTLS_CLIENT_CA=/run/bundle/mtls/hub-ca.pem
    TEE_INIT_ADDR=0.0.0.0:18091        one-shot TOFU bootstrap listener
    TEE_INIT_TOKEN=<random>            gates GET /v1/init-cert

Both instances share one VPC/subnet/SG. The SG additionally permits the
cross-host ports (18085 hub relay, 18090/18091 tee) between its own members
(source = the SG itself), so they reach each other regardless of public IP.

    python3 crosshost.py <snp-ami-id> --token <init-token> [--host-ip <hub-public-ip>]
                          [--single] [--tee-only] [--dry-run]
Writes crosshost.json {host:{...}, tee:{...}} and never deletes anything.
Refuses to run without TOKENHIVE_USER.

--single launches ONLY the confidential tee, running the whole loop (tee + Hub +
agent + mockprovider) inside that one instance through the supervisor bundle
(TOKENHIVE_BUILD_SINGLE=1); no ordinary host is started.

--tee-only launches ONLY the confidential tee from the cross-host bundle (its
./app is the real `tee` binary, not the supervisor) and starts no ordinary host.
The tee still needs a Hub TeeRelay URL in TEE_RELAY, but with no Hub there is
nothing to dial — the relay connection is lazy (dialed only when a provider
connection is needed), so a placeholder is harmless at boot. Pass --host-ip to
aim TEE_RELAY at a real Hub instead of the placeholder.
"""

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # cloudtest dir

from aws import (  # noqa: E402
    ensure_igw,
    ensure_key,
    ensure_sg,
    ensure_subnet,
    ensure_vpc,
    latest_ami,
    wait_running,
)
from config import load  # noqa: E402

CLOUDTEST = Path(__file__).resolve().parents[1]  # cloudtest dir
HERE = Path(__file__).resolve().parent
HOSTS_FILE = CLOUDTEST / "crosshost.json"
KEY_FILE = CLOUDTEST / "ssh-key.pem"

CROSS_PORTS = [18085, 18090, 18091]

# The Hub's TeeRelay now requires the TEE to present a key, and the Hub refuses
# to serve without it. crosshost.sh starts the Hub with this same default, so a
# run with no TOKENHIVE_RELAY_KEY still lines up end to end.
DEFAULT_RELAY_KEY = "xhost-relay-key"

# --tee-only has no Hub to dial, but the tee binary still requires a TEE_RELAY
# URL. This placeholder is inert: the relay handshake only happens when the tee
# needs a provider connection, and nothing dispatches jobs without a Hub. Pass
# --host-ip (or edit this) to point TEE_RELAY at a real Hub.
TEE_ONLY_RELAY_PLACEHOLDER = "ws://127.0.0.1:18085/v1/relay"


def ensure_local_key() -> None:
    if KEY_FILE.exists():
        return
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(KEY_FILE)], check=True)


def open_cross_ports(ec2, cfg, sg_id: str) -> None:
    """Permit the cross-host ports to other members of the same SG (idempotent).
    The port sources may be CIDRs or group pairs; only the port itself matters.
    """
    existing = set()
    for gp in ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0].get(
        "IpPermissions", []
    ):
        if "FromPort" not in gp:
            continue
        lo, hi = gp["FromPort"], gp["ToPort"]
        existing.update(range(lo, hi + 1))
    to_add = [p for p in CROSS_PORTS if p not in existing]
    if not to_add:
        return
    try:
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": p,
                    "ToPort": p,
                    "UserIdGroupPairs": [{"GroupId": sg_id}],
                }
                for p in to_add
            ],
        )
    except ec2.exceptions.ClientError as e:
        # A pre-existing identical rule is fine; anything else is a real error.
        if "Duplicate" not in str(e):
            raise
    print(f"  authorized cross-host ports {to_add} to SG members")


def run_ordinary(ec2, cfg, ami_id, vpc_id, subnet_id, sg_id):
    return ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.small",
        MinCount=1,
        MaxCount=1,
        KeyName=cfg.key_name,
        NetworkInterfaces=[
            {
                "AssociatePublicIpAddress": True,
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
                "Groups": [sg_id],
            }
        ],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": cfg.tags(name=cfg.name_prefix + "-host")}
        ],
    )["Instances"][0]


def run_confidential(ec2, cfg, ami_id, vpc_id, subnet_id, sg_id, userdata: str):
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
        UserData=base64.b64encode(userdata.encode()).decode(),
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": cfg.tags(name=cfg.name_prefix + "-tee")}
        ],
    )["Instances"][0]


def main() -> None:
    dry_run = "--dry-run" in sys.argv[1:]
    single = "--single" in sys.argv[1:]
    tee_only = "--tee-only" in sys.argv[1:]
    if single and tee_only:
        sys.exit("--single and --tee-only are mutually exclusive")
    # "no ordinary host" covers both --single (whole loop in the tee) and
    # --tee-only (a bare cross-host tee, no Hub anywhere).
    no_host = single or tee_only
    args = [a for a in sys.argv[1:] if a not in ("--dry-run", "--single", "--tee-only")]
    token = host_ip = None
    ami_id = None
    i = 0
    while i < len(args):
        if args[i] == "--token":
            token = args[i + 1]; i += 2
        elif args[i] == "--host-ip":
            host_ip = args[i + 1]; i += 2
        else:
            ami_id = args[i]; i += 1
    # --host-ip is optional: the ordinary host is launched first and its public
    # ip feeds the tee's relay URL automatically when not supplied.
    if not (ami_id and token):
        sys.exit("usage: python3 crosshost.py <snp-ami-id> --token <init-token> [--host-ip <hub-public-ip>] [--single] [--dry-run]")
    cfg = load()
    if not cfg.user:
        sys.exit("TOKENHIVE_USER is empty; refusing to launch untagged instances")
    ensure_local_key()
    ec2 = boto3("ec2")

    print(f"==> ensuring infrastructure in {cfg.region} (user tag: {cfg.user})")
    vpc_id = ensure_vpc(ec2, cfg)
    subnet_id = ensure_subnet(ec2, cfg, vpc_id)
    ensure_igw(ec2, cfg, vpc_id)
    sg_id = ensure_sg(ec2, cfg, vpc_id)
    open_cross_ports(ec2, cfg, sg_id)
    ensure_key(ec2, cfg, public_key=(KEY_FILE).with_suffix(".pem.pub").read_text().strip())
    if dry_run:
        label = "confidential tee (single-mode)" if single else (
            "confidential tee only (tee-only, no ordinary host)" if tee_only
            else "ordinary-host + confidential-tee")
        print(f"==> dry-run: would launch {label}; nothing launched")
        return

    # Leftover from a previous interrupted run must not double-launch: load any
    # prior state and reuse the still-running records.
    state = {}
    if HOSTS_FILE.exists():
        try:
            state = json.loads(HOSTS_FILE.read_text())
        except Exception:
            state = {}

    # 1) Session basis: single/tee-only launch no ordinary host. Drop any stale
    # host record so a later cross-host run starts from a clean slate; tee-only
    # must also discard its ip, or a dead Hub address would leak into TEE_RELAY.
    if single:
        host = state.pop("host", None) or {}
    elif tee_only:
        state.pop("host", None)
        host = {}
    else:
        host = state.get("host") or {}
    if not no_host and host.get("instance_id") and host_state(ec2, host["instance_id"]) != "terminated":
        print(f"==> reusing ordinary host {host['instance_id']} @ {host.get('public_ip')}")
    elif not no_host:
        host_ami = latest_ami(ec2, cfg)
        print(f"==> launching ordinary host ({host_ami}) t3.small")
        inst = run_ordinary(ec2, cfg, host_ami, vpc_id, subnet_id, sg_id)
        inst = wait_running(ec2, inst["InstanceId"])
        host = {
            "instance_id": inst["InstanceId"],
            "public_ip": inst.get("PublicIpAddress", ""),
            "private_ip": inst.get("PrivateIpAddress", ""),
            "role": "host",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        state["host"] = host
        HOSTS_FILE.write_text(json.dumps(state, indent=2) + "\n")

    host_ip = host_ip or host.get("public_ip", "")
    if not no_host:
        print(f"  -> ordinary host public ip: {host_ip}")

    # Records written before the private-ip fields existed may be missing them;
    # backfill from AWS so reused instances still route the cross-host plane.
    if host.get("instance_id") and not host.get("private_ip"):
        host["private_ip"] = describe(ec2, host["instance_id"]).get("PrivateIpAddress", "")

    # 2) Confidential tee with user-data injected config. In single mode the tee
    # supervises everything on loopback, so no relay back to an external hub.
    tee = state.get("tee") or {}
    if tee.get("instance_id") and not tee.get("private_ip"):
        tee["private_ip"] = describe(ec2, tee["instance_id"]).get("PrivateIpAddress", "")
    # Runtime config injected by the loader as EC2 user-data. TEE_RELAY (the
    # reverse tunnel back to the external Hub) only exists in cross-host mode:
    # the supervisor in single mode runs hub/agent/tee all on loopback and
    # ignores it. Cross-host traffic uses the PRIVATE ips: both instances share
    # one VPC/subnet/SG, and AWS group-pair SG rules only match in-VPC traffic —
    # a public-ip dial from a group member is not matched and gets dropped.
    host_priv = host.get("private_ip", "")
    # The relay key authenticates the TEE's dial-in to the Hub. In cross-host
    # mode it rides in as TEE_RELAY_KEY (the tee binary reads that env); in
    # single mode the supervisor reads TOKENHIVE_RELAY_KEY and hands it to both
    # its Hub and its tee child. Either way it matches crosshost.sh's Hub.
    relay_key = os.environ.get("TOKENHIVE_RELAY_KEY") or DEFAULT_RELAY_KEY
    if single:
        relay_url = ""
        relay = ""
    else:
        # tee-only has no Hub to dial, so fall back to the documented placeholder
        # to keep the tee's required TEE_RELAY well-formed. The relay is lazy
        # (dialed only when a provider connection is needed), so this never fires
        # at boot; a later --host-ip aims it at a real Hub.
        if tee_only and not (host_priv or host_ip):
            relay_url = TEE_ONLY_RELAY_PLACEHOLDER
        else:
            relay_url = f"ws://{host_priv or host_ip}:18085/v1/relay"
        relay = f"TEE_RELAY={relay_url}\nTEE_RELAY_KEY={relay_key}\n"
    userdata = (
        "TOKENHIVE_SIM_DIR=/tmp/tee\n"
        "TEE_ADDR=0.0.0.0:18090\n"
        f"{relay}"
        "TEE_PLATFORM=sevsnp\n"
        "TEE_MTLS=1\n"
        "TEE_MTLS_CLIENT_CA=/run/bundle/mtls/hub-ca.pem\n"
        # The mock provider's CA rides in the measured bundle: the TEE trusts it
        # for the upstream TLS leg, which is otherwise system roots on sevsnp.
        "TEE_CA=/run/bundle/mtls/mp-ca.pem\n"
        "TEE_INIT_ADDR=0.0.0.0:18091\n"
        f"TEE_INIT_TOKEN={token}\n"
    )
    if single:
        userdata += f"TOKENHIVE_RELAY_KEY={relay_key}\n"
        userdata += "TOKENHIVE_SUPERVISE=1\n"
        print("==> single-instance mode: whole loop inside the confidential tee")
    if tee.get("instance_id") and host_state(ec2, tee["instance_id"]) != "terminated":
        print(f"==> reusing confidential tee {tee['instance_id']} @ {tee.get('public_ip')}")
        print("  (N.B. user-data changes do not apply to a reused instance)")
    else:
        print(f"==> launching confidential tee ({ami_id}) {cfg.instance_type} AmdSevSnp=enabled")
        inst = run_confidential(ec2, cfg, ami_id, vpc_id, subnet_id, sg_id, userdata)
        inst = wait_running(ec2, inst["InstanceId"])
        tee = {
            "instance_id": inst["InstanceId"],
            "public_ip": inst.get("PublicIpAddress", ""),
            "private_ip": inst.get("PrivateIpAddress", ""),
            "role": "tee",
            "ami_id": ami_id,
            "user_data_token": token,
            "mode": "single" if single else ("tee-only" if tee_only else "cross-host"),
            # Where this tee will dial for a provider connection. Recorded so a
            # decoupled deploy is self-describing: with no ordinary host in this
            # state, nothing else on disk says which Hub address the tee aims at
            # (or that --host-ip was left out and it holds the inert placeholder).
            "relay_url": relay_url,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        state["tee"] = tee
        HOSTS_FILE.write_text(json.dumps(state, indent=2) + "\n")

    print("==> wrote crosshost.json")
    if single:
        print(f"==> single tee {tee['instance_id']} @ {tee.get('public_ip')} (supervise=1)")
    elif tee_only:
        print(f"==> tee-only {tee['instance_id']} @ {tee.get('public_ip')} (no ordinary host)")
        print(f"==>    TEE_RELAY={relay_url}")
        print(f"==>    bootstrap http://{tee.get('private_ip')}:18091/v1/init-cert?token={token}")
    else:
        print(f"==> host {host['instance_id']} @ {host['public_ip']}")
        print(f"==> tee  {tee['instance_id']} @ {tee.get('public_ip')}")
        print(f"==> tee relay {relay_url}; bootstrap http://<tee-priv>:18091/v1/init-cert?token={token}")


def describe(ec2, iid: str) -> dict:
    """Describe one instance; {} when it no longer exists.

    A record in crosshost.json can outlive its instance (it was terminated, or
    purged after the retention window). describe_instances then returns no
    Reservations, so callers must treat "absent" as a first-class state instead
    of indexing an empty list.
    """
    res = ec2.describe_instances(InstanceIds=[iid]).get("Reservations", [])
    for r in res:
        for i in r.get("Instances", []):
            return i
    return {}


def host_state(ec2, iid: str) -> str:
    """Instance state, or "terminated" when the instance is gone.

    "Gone" collapses to "terminated" because neither can be reused: any recorded
    instance that no longer exists must trigger a fresh launch.
    """
    return describe(ec2, iid).get("State", {}).get("Name", "terminated")


def boto3(service: str):
    import boto3 as _boto3
    return _boto3.client(service, region_name=load().region)


if __name__ == "__main__":
    main()
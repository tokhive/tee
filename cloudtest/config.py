"""Single source of truth for cloudtest configuration.

Values are read from environment variables (with the local .env loaded first)
and carry safe defaults, so the Python steps and the shell orchestrator always
agree. The user tag and region are the two values that must never drift:
instances are launched and deleted in the same region, matched by the same tag.
"""

import os
import sys
from dataclasses import dataclass
from pathlib import Path

# The only region cloudtest launches machines in. Pinned to eu-west-1
# (Ireland) by operator policy; do not launch in other regions.
DEFAULT_REGION = "eu-west-1"

# Tag pair that marks every resource cloudtest owns. Deletion matches on both.
TAG_OWNER = "tokenhive-TEE"
TAG_OWNER_VALUE = "true"
TAG_USER = "user"

ENV_FILE = Path(__file__).with_name(".env")


def load_env() -> None:
    """Load KEY=VALUE lines from .env into os.environ (never overwriting)."""
    if not ENV_FILE.exists():
        return
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


@dataclass(frozen=True)
class Config:
    # user is REQUIRED: it is the only tag that separates one operator's
    # machines from another's, so it must be set explicitly (never defaulted).
    user: str
    region: str = DEFAULT_REGION
    instance_type: str = "m6a.large"  # AMD SEV-SNP only: m6a / c6a / r6a
    ami_filter: str = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"

    @property
    def key_name(self) -> str:
        return f"tokenhive-tee-{self.user}"

    @property
    def name_prefix(self) -> str:
        return f"tokenhive-tee-{self.user}"

    @property
    def tag_owner(self) -> str:
        return TAG_OWNER

    @property
    def tag_owner_value(self) -> str:
        return TAG_OWNER_VALUE

    @property
    def tag_user(self) -> str:
        return TAG_USER

    def tags(self, name: str = "") -> list[dict]:
        tags = [
            {"Key": TAG_OWNER, "Value": TAG_OWNER_VALUE},
            {"Key": TAG_USER, "Value": self.user},
        ]
        if name:
            tags.append({"Key": "Name", "Value": name})
        return tags


def load() -> Config:
    load_env()
    user = os.environ.get("TOKENHIVE_USER", "").strip()
    if not user:
        sys.exit(
            "TOKENHIVE_USER is required (set it to a unique value, e.g. your name); "
            "refusing to run cloudtest without an owner tag"
        )
    return Config(
        user=user,
        region=os.environ.get("TOKENHIVE_REGION", DEFAULT_REGION),
        instance_type=os.environ.get("TOKENHIVE_INSTANCE_TYPE", "m6a.large"),
        ami_filter=os.environ.get(
            "TOKENHIVE_AMI_FILTER",
            "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*",
        ),
    )

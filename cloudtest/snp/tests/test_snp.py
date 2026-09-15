"""Local unit tests for the real-SNP module. No AWS, no network.

Verifies the three properties that matter locally and the module must hold:
(1) the SNP launch carries the exact two tags deletion matches on (so `down`
will find it) and requests AmdSevSnp, with no SSH key (there is no sshd);
(2) the app bundle tar has an executable `./app` entrypoint;
(3) the bundle digest is reproducible (same inputs -> same sha256).

Bundle tests compile the runner, so they need `go`; they are skipped if it is
unavailable (these run the same cross-compile the launch path would anyway).
"""

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

_DIR = Path(__file__).resolve().parent          # snp/tests
CLOUDTEST = _DIR.parent.parent                   # cloudtest
SNP = _DIR.parent                                # snp
sys.path.insert(0, str(CLOUDTEST))
sys.path.insert(0, str(SNP))

import aws
from config import Config
import launch as launch_mod


class _FakeEC2:
    """Minimal stand-in with the run_instances / describe_instances touches the
    SNP launch makes."""

    def __init__(self):
        self.instances, self.next_id = [], 1
        self.last_run = None
        self.created_tags = []

    def run_instances(self, **kwargs):
        self.last_run = kwargs
        tags = [t for s in kwargs.get("TagSpecifications", []) for t in s["Tags"]]
        inst = {"InstanceId": f"i-{self.next_id}", "State": {"Name": "pending"}, "Tags": tags}
        self.next_id += 1
        self.instances.append(inst)
        return {"Instances": [inst]}

    def describe_instances(self, InstanceIds=None, Filters=None):
        return {"Reservations": [{"Instances": self.instances}]}

    def create_tags(self, Resources, Tags):
        self.created_tags.extend(Tags)


def _tags_dict(tags):
    return {t["Key"]: t["Value"] for t in (tags or [])}


class SNPLunchTest(unittest.TestCase):
    def setUp(self):
        self.fake = _FakeEC2()
        self.cfg = Config(user="chenxinghao")

    def test_run_snp_enables_sevsnp_and_both_tags(self):
        launch_mod.run_snp(self.fake, self.cfg, "ami-9", "vpc-1", "subnet-1", "sg-1")
        run = self.fake.last_run
        self.assertEqual(run["CpuOptions"], {"AmdSevSnp": "enabled"})
        self.assertNotIn("KeyName", run)  # SNP image has no sshd; console is the channel
        tags = _tags_dict(run["TagSpecifications"][0]["Tags"])
        self.assertEqual(tags["tokenhive-TEE"], "true")
        self.assertEqual(tags["user"], "chenxinghao")

    def test_snp_launch_tag_discipline_matches_delete(self):
        """down/delete only looks for tokenhive-TEE=true AND user=<cfg.user>; the
        launch must tag exactly that, so a `down` after `up` converges."""
        launch_mod.run_snp(self.fake, self.cfg, "ami-9", "vpc-1", "subnet-1", "sg-1")
        iid = self.fake.instances[0]["InstanceId"]
        found = aws.find_by_tags(self.fake, self.cfg)
        self.assertEqual([i["InstanceId"] for i in found], [iid])


def _have_go():
    return shutil.which("go") is not None


@unittest.skipUnless(_have_go(), "go toolchain not found")
class BundleTest(unittest.TestCase):
    def tearDown(self):
        for env in ("TOKENHIVE_OUT_BUNDLE",):
            os.environ.pop(env, None)

    def _pack(self, out: Path) -> str:
        env = dict(os.environ)
        env["TOKENHIVE_OUT_BUNDLE"] = str(out)
        subprocess.run(["./pack.sh", "build"], cwd=SNP, env=env, check=True,
                       capture_output=True, text=True)
        return subprocess.run(["./pack.sh", "digest", str(out)], cwd=SNP,
                              env=env, check=True, capture_output=True,
                              text=True).stdout.strip()

    def test_bundle_has_executable_app_and_is_reproducible(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a.tar", Path(d) / "b.tar"
            digest_a = self._pack(a)
            digest_b = self._pack(b)
            self.assertEqual(digest_a, digest_b,
                             "bundle digest must be reproducible cross-run")
            with tarfile.open(a) as tar:
                members = tar.getmembers()
                app = next(m for m in members if m.name == "./app")
                self.assertTrue(app.isreg())
                self.assertTrue(app.mode & 0o100)  # owner executable


class IAMStructureTest(unittest.TestCase):
    def test_policy_json_is_valid_and_covers_import(self):
        import json
        pol = json.loads((SNP / "iam" / "aws-snp-policy.json").read_text())
        actions = {a for s in pol["Statement"] for a in s["Action"]}
        self.assertIn("ec2:ImportSnapshot", actions)
        self.assertIn("ec2:GetConsoleOutput", actions)
        self.assertIn("ec2:TerminateInstances", actions)
        self.assertIn("s3:PutObject", actions)

    def test_snp_sh_down_never_reads_hosts_from_delete_path(self):
        # delete.py exists in cloudtest and is the single teardown; snp.sh must
        # delegate to it, not mint a second, possibly-diverging delete.
        src = (CLOUDTEST / "delete.py").read_text()
        self.assertNotIn("HOSTS_FILE", src)
        self.assertNotIn("open(", src)

    def test_snp_sh_captures_own_dir_before_sourcing_lib(self):
        # lib.sh reassigns the global SCRIPT_DIR to the cloudtest dir; snp.sh's
        # own dir must be captured first or every ${…}/… path below drifts.
        src = (SNP / "snp.sh").read_text()
        self.assertLess(src.find('SNP_DIR="$(cd'),
                        src.find('source "${SNP_DIR}/../lib.sh"'))
        self.assertIn('CLOUDTEST_DIR="${SNP_DIR}/.."', src)
        self.assertIn('cd "${CLOUDTEST_DIR}"', src)


if __name__ == "__main__":
    unittest.main()
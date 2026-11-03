"""The confidential launch's IAM instance profile. No AWS, no network.

On AWS the TEE's structured logger ships to CloudWatch Logs with the instance
role, so a confidential instance launched without a profile cannot ship a log:
the SDK builds its client happily and every ship is dropped, leaving a serial
console a few minutes deep as the only channel. TOKENHIVE_TEE_INSTANCE_PROFILE
is how the launch carries one.

The property worth pinning is the *absence* of the key when nothing is named.
IamInstanceProfile is fixed at RunInstances, and boto3 rejects
{"Name": ""} — so "no profile" has to stay the shape of a launch that never
asked for one, not a profile whose name happens to be empty.
"""

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_DIR = Path(__file__).resolve().parent          # snp/tests
CLOUDTEST = _DIR.parent.parent                   # cloudtest
SNP = _DIR.parent                                # snp
sys.path.insert(0, str(CLOUDTEST))
sys.path.insert(0, str(SNP))

import crosshost                                # noqa: E402
from config import Config                       # noqa: E402


class _FakeEC2:
    """Minimal stand-in capturing the RunInstances request verbatim."""

    def __init__(self):
        self.last_run = None

    def run_instances(self, **kwargs):
        self.last_run = kwargs
        return {"Instances": [{"InstanceId": "i-tee", "State": {"Name": "pending"}}]}


def _launch(profile: str):
    fake = _FakeEC2()
    crosshost.run_confidential(
        fake, Config(user="chenxinghao"), "ami-9", "vpc-1", "subnet-1", "sg-1",
        "TEE_PLATFORM=sevsnp\n", profile,
    )
    return fake.last_run


class ConfidentialLaunchProfileTest(unittest.TestCase):
    def test_no_profile_leaves_the_key_out_entirely(self):
        run = _launch("")
        self.assertNotIn("IamInstanceProfile", run,
                         "an unnamed profile must not become IamInstanceProfile={'Name': ''}")
        # The rest of the launch is unaffected: still a confidential instance.
        self.assertEqual(run["CpuOptions"], {"AmdSevSnp": "enabled"})
        self.assertTrue(run["UserData"])

    def test_named_profile_rides_into_the_launch(self):
        run = _launch("tokenhive-tee-logs")
        self.assertEqual(run["IamInstanceProfile"], {"Name": "tokenhive-tee-logs"})

    def test_env_name_is_the_one_the_docs_and_example_advertise(self):
        """The name is an operator-facing contract: it lives in .env.example and
        the deploy manual, not only in the code. Drift between them would leave an
        operator setting a variable nothing reads."""
        name = crosshost.TEE_PROFILE_ENV
        self.assertEqual(name, "TOKENHIVE_TEE_INSTANCE_PROFILE")
        self.assertIn(name, (CLOUDTEST / ".env.example").read_text())


class LocalKeyTest(unittest.TestCase):
    """A missing private key is refused, never generated.

    Generating one is how this repo lost the only private half of its AWS key
    pair (2026-10-28): the fresh file could not match the pair imported back in
    September, and ensure_key() skips the import whenever the pair exists — so
    the replacement went unnoticed until old machines rejected it. The property
    worth pinning is therefore negative: no file appears.
    """

    def test_a_missing_key_is_refused_and_nothing_is_created(self):
        with tempfile.TemporaryDirectory() as d:
            missing = Path(d) / "ssh-key.pem"
            original = crosshost.KEY_FILE
            crosshost.KEY_FILE = missing
            try:
                with self.assertRaises(SystemExit) as refused:
                    crosshost.ensure_local_key("tokenhive-tee-chenxinghao")
            finally:
                crosshost.KEY_FILE = original
            self.assertIn("refusing to generate", str(refused.exception))
            self.assertIn("tokenhive-tee-chenxinghao", str(refused.exception))
            self.assertFalse(missing.exists(), "a key was generated after all")


class LaunchKeyGateTest(unittest.TestCase):
    """A launch with no ordinary host must not demand SSH key material.

    Only the ordinary host is launched with a key pair (run_ordinary) and later
    reached over SSH by deploy/verify/fetch/run. --single and --tee-only launch
    the confidential instance without KeyName, so there is nothing to log into;
    requiring the private half there refused a launch that could not use a key
    at all (2026-11-03).
    """

    def _run_through_dry_run(self, *flags: str, key_dir: str) -> None:
        """Run main() to the dry-run return with AWS stubbed out.

        --dry-run returns right after the key gate, so this pins the gate
        without launching anything or touching instance state.
        """
        patches = [
            mock.patch.object(crosshost, "load", return_value=Config(user="chenxinghao")),
            mock.patch.object(crosshost, "boto3", return_value=object()),
            mock.patch.object(crosshost, "ensure_vpc", return_value="vpc-1"),
            mock.patch.object(crosshost, "ensure_subnet", return_value="subnet-1"),
            mock.patch.object(crosshost, "ensure_igw"),
            mock.patch.object(crosshost, "ensure_sg", return_value="sg-1"),
            mock.patch.object(crosshost, "open_cross_ports"),
            mock.patch.object(
                crosshost, "ensure_key",
                side_effect=AssertionError("ensure_key ran without an ordinary host")),
            mock.patch.object(crosshost, "KEY_FILE", Path(key_dir) / "ssh-key.pem"),
            mock.patch.object(sys, "argv", ["crosshost.py", "ami-9", "--dry-run", *flags]),
            contextlib.redirect_stdout(io.StringIO()),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            crosshost.main()

    def test_tee_only_needs_no_key_material(self):
        # No ssh-key.pem and no .pub anywhere: the gate must not run, and the
        # unpatched ensure_local_key would sys.exit if it did.
        with tempfile.TemporaryDirectory() as d:
            self._run_through_dry_run("--tee-only", key_dir=d)

    def test_single_needs_no_key_material(self):
        with tempfile.TemporaryDirectory() as d:
            self._run_through_dry_run("--single", key_dir=d)

    def test_cross_host_still_requires_the_private_key(self):
        with tempfile.TemporaryDirectory() as d:
            patches = [
                mock.patch.object(crosshost, "load", return_value=Config(user="chenxinghao")),
                mock.patch.object(crosshost, "KEY_FILE", Path(d) / "ssh-key.pem"),
                mock.patch.object(sys, "argv", ["crosshost.py", "ami-9", "--dry-run"]),
            ]
            with contextlib.ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                with self.assertRaises(SystemExit) as refused:
                    crosshost.main()
            self.assertIn("refusing to generate", str(refused.exception))


if __name__ == "__main__":
    unittest.main()

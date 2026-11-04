"""Actual OpenSSH signatures, external trust and release-state refusal paths."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy/signed_release.py"


@unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH is required")
class SignedReleaseTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.key = self.root / "signing-key"
        self.run_command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.key)
        self.trust = self.root / "allowed_signers"
        self.trust.write_text('publisher namespaces="tokhive-tee-release" ' + self.key.with_suffix(".pub").read_text())
        self.catalog = self.root / "catalog.json"
        release = json.loads((ROOT / "releases/catalog.json").read_text())["releases"][0]
        self.value = {"version": 1, "releases": [release], "revocations": [],
                      "deployment_events": [{"environment": "production", "application_id": release["application_id"],
                                             "action": "activate", "at": release["published_at"]}]}
        self.signature = self.root / "catalog.sig"
        self.run_command("git", "init", "-q", self.root)
        self.run_command("git", "-C", self.root, "config", "user.name", "Test")
        self.run_command("git", "-C", self.root, "config", "user.email", "test@example.com")
        self.run_command("git", "-C", self.root, "config", "commit.gpgsign", "false")
        self.commit_catalog(self.value)

    def run_command(self, *args):
        return subprocess.run(list(map(str, args)), check=True, capture_output=True).stdout

    def commit_catalog(self, value):
        self.catalog.write_text(json.dumps(value) + "\n")
        self.run_command("git", "-C", self.root, "add", "catalog.json")
        self.run_command("git", "-C", self.root, "commit", "-qm", "catalog")

    def cli(self, *args, ok=True):
        result = subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, ok, result.stderr)
        return result

    def sign(self, ok=True):
        return self.cli("sign", "--catalog", self.catalog, "--key", self.key, "--signature", self.signature, ok=ok)

    def verify(self, *extra, ok=True):
        return self.cli("verify", "--catalog", self.catalog, "--signature", self.signature,
                        "--allowed-signers", self.trust, "--identity", "publisher", "--environment", "production", *extra, ok=ok)

    def test_roundtrip_and_external_trust(self):
        self.sign()
        result = json.loads(self.verify().stdout)
        self.assertEqual(result["environment"], "production")
        self.assertEqual(result["current_application_id"], self.value["deployment_events"][-1]["application_id"])
        self.verify("--identity", "impostor", ok=False)
        other = self.root / "other-key"
        self.run_command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", other)
        self.trust.write_text("publisher " + other.with_suffix(".pub").read_text())
        self.verify(ok=False)

    def test_tampering_and_namespace(self):
        self.sign()
        self.catalog.write_bytes(self.catalog.read_bytes() + b" ")
        self.verify(ok=False)
        self.catalog.write_bytes(self.catalog.read_bytes()[:-1])
        signature = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", "other-purpose"],
                                   input=self.catalog.read_bytes(), capture_output=True, check=True).stdout
        self.signature.write_bytes(signature)
        self.verify(ok=False)

    def test_uncommitted_catalog_and_overwrites_rejected(self):
        self.catalog.write_bytes(self.catalog.read_bytes() + b" ")
        self.sign(ok=False)
        self.assertFalse(self.signature.exists())
        self.catalog.write_bytes(self.catalog.read_bytes()[:-1])
        self.sign()
        original = self.signature.read_bytes()
        self.sign(ok=False)
        self.assertEqual(self.signature.read_bytes(), original)
        self.verify("--output", self.catalog, ok=False)

    def test_missing_environment_and_revoked_active_release(self):
        self.sign()
        self.verify("--environment", "missing", ok=False)
        self.signature.unlink()
        value = copy.deepcopy(self.value)
        identity = value["deployment_events"][-1]["application_id"]
        value["revocations"].append({"application_id": identity, "at": "2099-01-01T00:00:00Z",
                                     "reason": "test revocation", "reference_url": "https://example.com/advisory"})
        self.commit_catalog(value)
        self.sign()
        self.verify(ok=False)

    def test_signed_invalid_catalog_is_not_exported(self):
        self.catalog.write_text('{"version":1,"version":1}')
        signature = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", "tokhive-tee-release"],
                                   input=self.catalog.read_bytes(), capture_output=True, check=True).stdout
        self.signature.write_bytes(signature)
        output = self.root / "export.json"
        self.verify("--output", output, ok=False)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

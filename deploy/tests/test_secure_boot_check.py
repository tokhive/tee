"""The verdict on whether the Secure Boot artifacts describe one key.

snp-build.sh refuses to build on it and crosshost.sh refuses to commit on it, so
the cases below are the mistakes that actually happen: a rotation that only
replaced the public half, one that only replaced the private half, and a key
vault that does not travel with the source tree. Real keys are generated with
openssl because the comparison is over DER SubjectPublicKeyInfo -- fake PEM text
would only exercise the error message.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "secure-boot-check.sh"
OPENSSL = shutil.which("openssl")


def openssl(cwd, *args):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


@unittest.skipUnless(OPENSSL, "openssl is required to generate the key fixtures")
class SecureBootCheckTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.deploy = self.root / "deploy"
        self.secure_boot = self.deploy / "secure-boot"
        self.secure_boot.mkdir(parents=True)
        (self.root / "shared").mkdir()
        shutil.copy(SCRIPT, self.deploy / "secure-boot-check.sh")
        self.release_pem = self.root / "shared" / "secure_boot_release_pub.pem"

    def rotate(self, cn="release key"):
        """Write a complete, internally consistent set for one key."""
        openssl(self.secure_boot, "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:2048", "-out", "R.key")
        openssl(self.secure_boot, "req", "-new", "-x509", "-key", "R.key",
                "-sha256", "-days", "1", "-subj", f"/CN={cn}", "-out", "R.crt.pem")
        openssl(self.secure_boot, "x509", "-in", "R.crt.pem", "-outform", "DER",
                "-out", "R.crt.der")
        openssl(self.secure_boot, "pkey", "-in", "R.key", "-pubout", "-out", "R.pub.pem")
        shutil.copy(self.secure_boot / "R.pub.pem", self.release_pem)

    def check(self):
        return subprocess.run(["bash", str(self.deploy / "secure-boot-check.sh")],
                              capture_output=True, text=True)

    def test_one_key_passes_and_names_its_fingerprint(self):
        self.rotate()
        out = self.check()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("one key, SPKI sha256", out.stdout)

    def test_a_stale_verifier_copy_is_refused(self):
        # The image would be signed by the new key while the Hub still embeds the
        # old one -- the failure this check exists to catch.
        self.rotate()
        stale = self.release_pem.read_bytes()
        self.rotate("the rotated key")
        self.release_pem.write_bytes(stale)
        out = self.check()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("secure_boot_release_pub.pem", out.stderr)
        self.assertIn("must be one key", out.stderr)

    def test_a_rotation_that_forgot_the_certificates_is_refused(self):
        # Regenerating R.key alone leaves db trusting a certificate for a key
        # that no longer signs anything: the image would not boot.
        self.rotate()
        openssl(self.secure_boot, "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:2048", "-out", "R.key")
        out = self.check()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("R.key is", out.stderr)
        self.assertIn("its certificate names", out.stderr)

    def test_the_private_half_may_live_offline(self):
        # The vault, not the build host, may be the only place R.key exists.
        self.rotate()
        (self.secure_boot / "R.key").unlink()
        out = self.check()
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_an_esl_built_from_the_current_certificate_passes(self):
        # An ESL is a header plus the DER certificate verbatim, which is what
        # makes containment a meaningful check.
        self.rotate()
        (self.secure_boot / "R.esl").write_bytes(
            b"ESLHDR" + (self.secure_boot / "R.crt.der").read_bytes() + b"tail")
        out = self.check()
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_an_esl_left_over_from_the_previous_certificate_is_refused(self):
        # cert-to-efi-sig-list is a separate step from re-issuing the
        # certificate; skipping it leaves db trusting a certificate the build no
        # longer signs with, and the instance will not boot.
        self.rotate()
        (self.secure_boot / "R.esl").write_bytes(
            b"ESLHDR" + (self.secure_boot / "R.crt.der").read_bytes() + b"tail")
        self.rotate("the rotated key")
        out = self.check()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("R.esl does not contain the certificate", out.stderr)
        self.assertIn("cert-to-efi-sig-list", out.stderr)

    def test_missing_public_material_is_named(self):
        self.rotate()
        (self.secure_boot / "R.crt.der").unlink()
        out = self.check()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("missing", out.stderr)
        self.assertIn("R.crt.der", out.stderr)


if __name__ == "__main__":
    unittest.main()

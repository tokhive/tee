"""The AWS packaging step must not register an image that lies about itself.

`snp-build.sh` tags the AMI with the digest of the app bundle it *built*, and
`crosshost.sh up` pins the TEE to that tag, so the tag is a claim about the
image's bytes. The path from those bytes to the image runs through S3:

    local raw -> VMDK -> s3://<bucket>/<key> -> import-snapshot -> register-image

and import-snapshot reads *whatever is at that key*. When the key was a fixed
name, an upload that silently did nothing was indistinguishable from success:
import-snapshot consumed the previous build's disk and the new AMI was
registered carrying a tag the disk does not measure. Every later step then
agrees with the tag -- the archiver files the new bundle under the new digest,
`deploy` ships that bundle's whitelist to the Hub -- while the enclave runs the
old app.

These tests exercise the real `package_aws` against a stubbed `aws`, and hold
the two properties that close the hole: the staging key names the app, and the
bytes at that key are proven to be this build's before an import is paid for.
"""

import base64
import json
import os
import re
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

_DIR = Path(__file__).resolve().parent          # snp/tests
REPO = _DIR.parents[3]                           # reclaim-tee
SNP_BUILD = REPO / "deploy" / "snp-build.sh"
SRC = SNP_BUILD.read_text()

HEX = "a" * 64
DIGEST = f"snp-app:{HEX}"
KEY = f"snp-tokenhive-{HEX}.vmdk"
# A previous build with the same app can have left an object at this same
# content-addressed key: the disk is not byte-deterministic (the ESP carries FAT
# timestamps), so "same key" does not imply "same bytes".
STALE_CHECKSUM = base64.b64encode(b"\x00" * 32).decode()

# Stub `aws`. Keeps a tiny object store on disk so that "the upload did not
# land" and "the object is stale" are states the test can actually produce.
AWS_STUB = r'''#!/usr/bin/env python3
import base64, hashlib, json, os, sys

store_path, log_path = os.environ["AWS_STUB_STORE"], os.environ["AWS_STUB_LOG"]
with open(store_path) as f:
    store = json.load(f)
args = sys.argv[1:]
with open(log_path, "a") as f:
    f.write(" ".join(args) + "\n")
if args[:1] == ["--region"]:
    args = args[2:]
service = args[0]

def save():
    with open(store_path, "w") as f:
        json.dump(store, f)

def checksum(path):
    return base64.b64encode(hashlib.sha256(open(path, "rb").read()).digest()).decode()

def query_of(args):
    return args[args.index("--query") + 1] if "--query" in args else ""

if service == "sts":
    print("123456789012")
elif service == "s3" and args[1] == "mb":
    sys.exit(0)
elif service == "s3api" and args[1] == "put-object":
    key = args[args.index("--key") + 1]
    body = args[args.index("--body") + 1]
    if os.environ.get("AWS_STUB_NOOP") == "1":
        pass                      # the bug under test: the upload does nothing
    else:
        store[key] = checksum(body)
        save()
elif service == "s3" and args[1] == "rm":
    store.pop(args[2].split("/", 3)[3], None)
    save()
elif service == "s3api" and args[1] == "head-object":
    key = args[args.index("--key") + 1]
    if key not in store:
        sys.exit(254)             # aws exits non-zero: no such object
    print(store[key])
elif service == "ec2" and args[1] == "import-snapshot":
    print("import-snap-0test")
elif service == "ec2" and args[1] == "describe-import-snapshot-tasks":
    print("snap-0test" if "SnapshotId" in query_of(args) else "completed")
elif service == "ec2" and args[1] == "describe-images":
    print("ami-0old")
elif service == "ec2" and args[1] == "register-image":
    print("ami-0new")
elif service == "ec2" and args[1] == "deregister-image":
    pass
else:
    sys.stderr.write("unexpected aws call: %s\n" % " ".join(args))
    sys.exit(2)
'''

# Stub `qemu-img`: writes the smallest file the CID patch in snp-build.sh
# accepts (KDMV magic, descriptor offset/size in sectors, one CID and one
# parentCID line).
QEMU_STUB = r'''#!/usr/bin/env python3
import struct, sys
out = sys.argv[-1]
desc = b"CID=0000abcd\nparentCID=ffffffff\n"
buf = bytearray(1024)
buf[0:4] = b"KDMV"
struct.pack_into("<Q", buf, 28, 1)      # descriptor at sector 1
struct.pack_into("<Q", buf, 36, 1)      # descriptor is one sector
buf[512:512 + len(desc)] = desc
open(out, "wb").write(bytes(buf))
'''


def _shell_function(name, src=SRC, path=SNP_BUILD):
    """The literal text of a top-level shell function, so the tests exercise the
    real code rather than a copy that can drift from it."""
    m = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", src, re.M | re.S)
    if not m:
        raise AssertionError(f"no {name}() in {path}")
    return m.group(0)


class PackageAwsTest(unittest.TestCase):
    """Run the real package_aws with a stubbed aws/qemu-img."""

    def _run(self, noop_upload=False, preexisting=False):
        """Returns (CompletedProcess, aws calls, object store)."""
        tmp = Path(tempfile.mkdtemp(prefix="snpbuild-"))
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        for name, body in (("aws", AWS_STUB), ("qemu-img", QEMU_STUB)):
            p = bin_dir / name
            p.write_text(body)
            p.chmod(0o755)

        (tmp / "snp-tier.raw").write_bytes(b"raw")
        secure_boot = tmp / "secure-boot"
        secure_boot.mkdir()
        (secure_boot / "aws-uefi-data.b64").write_text("dGVzdA==\n")

        store, log = tmp / "store.json", tmp / "aws.log"
        store.write_text(json.dumps({KEY: STALE_CHECKSUM}) if preexisting else "{}")
        log.write_text("")

        driver = tmp / "driver.sh"
        driver.write_text(
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            f'RAW="{tmp}/snp-tier.raw"\n'
            f'DIGEST="{DIGEST}"\n'
            f'SECURE_BOOT_DIR="{secure_boot}"\n'
            "AWS_SNP_REGION=eu-west-1\n"
            f"{_shell_function('package_aws')}\n"
            "package_aws tokenhive\n"
        )
        driver.chmod(0o755)

        env = dict(os.environ)
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["AWS_STUB_STORE"], env["AWS_STUB_LOG"] = str(store), str(log)
        if noop_upload:
            env["AWS_STUB_NOOP"] = "1"
        p = subprocess.run(["/bin/bash", str(driver)], capture_output=True, text=True, env=env)
        return p, log.read_text().splitlines(), json.loads(store.read_text())

    @staticmethod
    def _argv(line):
        """The stub's argv for one logged call, with any leading --region pair
        stripped, so a call is identified by its own tokens and not by a
        substring that another call can also contain."""
        tok = line.split()
        if tok[:1] == ["--region"]:
            tok = tok[2:]
        return tok

    @classmethod
    def _calls(cls, calls, service, verb):
        return [c for c in (cls._argv(line) for line in calls) if c[:2] == [service, verb]]

    @classmethod
    def _uploaded_key(cls, calls):
        ups = cls._calls(calls, "s3api", "put-object")
        assert len(ups) == 1, calls
        return ups[0][ups[0].index("--key") + 1]

    def test_staging_key_names_the_app(self):
        # A fixed key is what made a stale object look like this build's.
        p, calls, store = self._run()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self._uploaded_key(calls), KEY,
                         "the staging key must name the app digest the disk carries")
        self.assertEqual(store, {},
                         "the staging object is deleted once the snapshot has copied it")

    def test_import_reads_the_verified_object(self):
        p, calls, _ = self._run()
        self.assertEqual(p.returncode, 0, p.stderr)
        imports = self._calls(calls, "ec2", "import-snapshot")
        self.assertEqual(len(imports), 1, calls)
        self.assertIn(f"S3Key={KEY}", " ".join(imports[0]),
                      "the import must read the object that was just uploaded")

    def test_the_tag_names_the_digest_that_was_verified(self):
        p, calls, _ = self._run()
        registers = self._calls(calls, "ec2", "register-image")
        self.assertEqual(len(registers), 1, calls)
        self.assertIn(f"Value={HEX}", " ".join(registers[0]),
                      "the AMI tag is the claim the launcher pins the TEE to")

    def test_upload_is_verified_against_the_object(self):
        p, calls, _ = self._run()
        self.assertTrue(self._calls(calls, "s3api", "head-object"),
                        "the build must read the object back, not assume the cp landed")
        self.assertTrue(any("--checksum-algorithm" in c for c in calls),
                        "the upload must request a checksum to verify against")

    def test_an_upload_that_did_not_land_never_becomes_an_image(self):
        # cp does nothing, as it silently did in the field.
        p, calls, _ = self._run(noop_upload=True)
        self.assertNotEqual(p.returncode, 0, "a failed upload must fail the build")
        self.assertIn("upload verification failed", p.stderr)
        self.assertFalse(self._calls(calls, "ec2", "import-snapshot"),
                         "no import may start when the object is not this build's")
        self.assertFalse(self._calls(calls, "ec2", "register-image"),
                         "no AMI may be registered when the object is not this build's")

    def test_a_stale_object_at_the_key_is_caught_by_content(self):
        # The sharper case: an object exists at exactly this key, carries a
        # different digest's bytes, and the upload does not replace it. Only a
        # content check catches this; presence and size would both pass.
        p, calls, store = self._run(noop_upload=True, preexisting=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("upload verification failed", p.stderr)
        self.assertIn(STALE_CHECKSUM, p.stderr, "the mismatch must be shown, not just asserted")
        self.assertFalse(self._calls(calls, "ec2", "import-snapshot"))
        self.assertEqual(store[KEY], STALE_CHECKSUM, "the stale object survived")


if __name__ == "__main__":
    unittest.main()

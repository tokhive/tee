#!/usr/bin/env python3
"""Sign a committed release catalog or verify one against external SSH trust."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from release_catalog import export_catalog, no_duplicate_keys, require, validate_catalog

NAMESPACE = "tokhive-tee-release"
MAX_CATALOG_BYTES = 8 << 20


def catalog_bytes(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_CATALOG_BYTES + 1)
    require(len(raw) <= MAX_CATALOG_BYTES, "catalog exceeds 8 MiB")
    return raw


def parse_catalog(raw):
    value = json.loads(raw, object_pairs_hook=no_duplicate_keys)
    validate_catalog(value)
    return value


def command(args, raw=None):
    result = subprocess.run(args, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(result.returncode == 0, result.stderr.decode(errors="replace").strip() or "command failed")
    return result.stdout


def committed_revision(path, raw):
    root = Path(command(["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"]).decode().strip())
    relative = path.relative_to(root.resolve()).as_posix()
    revision = command(["git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip()
    committed = command(["git", "-C", str(root), "show", revision + ":" + relative])
    require(raw == committed, "catalog must match the committed HEAD bytes before signing")
    return revision


def write_new(path, raw):
    # Refuse overwrites, including symlinks. Never replace inputs or a published signature.
    with path.open("xb") as stream:
        stream.write(raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sign = commands.add_parser("sign", help="sign exact committed catalog bytes with an operator key")
    sign.add_argument("--catalog", type=Path, required=True)
    sign.add_argument("--key", type=Path, required=True, help="SSH signing key, or public key available through ssh-agent")
    sign.add_argument("--signature", type=Path, required=True, help="new detached signature output file")
    verify = commands.add_parser("verify", help="verify signature and export an environment for Hive")
    verify.add_argument("--catalog", type=Path, required=True)
    verify.add_argument("--signature", type=Path, required=True)
    verify.add_argument("--allowed-signers", type=Path, required=True, help="independently trusted OpenSSH allowed_signers file")
    verify.add_argument("--identity", required=True, help="expected principal from the trusted allowed_signers file")
    verify.add_argument("--environment", required=True)
    verify.add_argument("--output", type=Path, help="new export file; otherwise write JSON to stdout")
    args = parser.parse_args(argv)
    try:
        path = args.catalog.resolve(strict=True)
        raw = catalog_bytes(path)
        if args.command == "sign":
            parse_catalog(raw)
            revision = committed_revision(path, raw)
            signature = command(["ssh-keygen", "-Y", "sign", "-f", str(args.key.resolve(strict=True)), "-n", NAMESPACE], raw)
            write_new(args.signature, signature)
            print("Signed catalog commit " + revision + "; SHA-256 " + hashlib.sha256(raw).hexdigest())
        else:
            # Never accept a key from the catalog itself. Verify exactly the bytes we parse.
            command(["ssh-keygen", "-Y", "verify", "-f", str(args.allowed_signers.resolve(strict=True)),
                     "-I", args.identity, "-n", NAMESPACE, "-s", str(args.signature.resolve(strict=True))], raw)
            exported = export_catalog(parse_catalog(raw), args.environment)
            identity = exported["current_application_id"]
            require(identity is not None, "signed catalog has no active deployment for this environment")
            current = next(release for release in exported["releases"] if release["application_id"] == identity)
            require(current["status"] != "revoked", "active deployment is revoked; do not use it as a trusted current release")
            output = (json.dumps(exported, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()
            if args.output:
                write_new(args.output, output)
            else:
                sys.stdout.buffer.write(output)
            print("Catalog signature verified; SHA-256 " + hashlib.sha256(raw).hexdigest() +
                  ". This authenticates publication, not the running deployment or catalog freshness.", file=sys.stderr)
        return 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
        print("signed-release: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

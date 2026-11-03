#!/usr/bin/env python3
"""Record measured bundles and reviewed TEE releases without cloud access.

Build manifests are sidecars, never members of the measured archive. The public
catalog records operator-reviewed provenance; it is not hardware attestation.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
ENVIRONMENT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\Z")
BUILD_KEYS = {
    "version", "application_id", "bundle_sha256", "bundle_size_bytes",
    "app_binary_sha256", "policy_hash", "policy_file_sha256", "ca_bundle_sha256",
    "bundle_kind", "source_repository", "source_commit", "source_dirty", "built_at",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def timestamp(value):
    require(isinstance(value, str), "timestamp must be an RFC 3339 string")
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value),
            "timestamp must include a date, time and UTC offset")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def https_url(value):
    require(isinstance(value, str), "release/source URL must be a string")
    parsed = urlparse(value)
    require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password,
            "release/source URL must use HTTPS without credentials")


def application(value):
    require(isinstance(value, str) and value.startswith("snp-app:") and HEX.fullmatch(value[8:]),
            "application identity must be snp-app: followed by 64 lowercase hex characters")


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path):
    with Path(path).open() as stream:
        return json.load(stream, object_pairs_hook=no_duplicate_keys)


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".catalog-", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def git(repo, *arguments):
    result = subprocess.run(["git", "-C", str(repo), *arguments], capture_output=True, text=True)
    require(result.returncode == 0, "could not read build source from Git")
    return result.stdout.strip()


def capture_source(repo):
    try:
        commit = git(repo, "rev-parse", "HEAD")
        dirty = bool(git(repo, "status", "--porcelain", "--untracked-files=normal"))
        remote = git(repo, "remote", "get-url", "origin")
        if remote.startswith("git@") and ":" in remote:
            host, repository = remote[4:].split(":", 1)
            remote = "https://" + host + "/" + repository
        remote = remote.removesuffix(".git")
        https_url(remote)
        require(COMMIT.fullmatch(commit), "invalid Git commit")
        return {"source_repository": remote, "source_commit": commit, "source_dirty": dirty}
    except (ValueError, FileNotFoundError):
        # Source archives and local diagnostic builds may have no Git metadata.
        # They remain buildable, but cannot be registered as public releases.
        return {"source_repository": None, "source_commit": None, "source_dirty": True}


def stream_digest(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1 << 20), b""):
        digest.update(chunk)
    return digest.hexdigest()


def inspect_bundle(path):
    path = Path(path)
    before = path.stat()
    with path.open("rb") as stream:
        digest = stream_digest(stream)
    measured_files = {"app": None, "policy/policy.cbor": None, "etc/ssl/certs/ca-certificates.crt": None}
    policy_hash = None
    seen = set()
    with tarfile.open(path, "r:") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and ".." not in name.parts, "unsafe bundle member path")
            normalized = str(name)
            require(normalized not in seen, "duplicate bundle member: " + normalized)
            seen.add(normalized)
            if normalized not in measured_files:
                continue
            require(member.isfile() and member.size > 0, "measured bundle inputs must be nonempty regular files")
            if normalized == "app":
                require(member.mode & 0o111, "bundle app must be executable")
            with archive.extractfile(member) as stream:
                if normalized == "policy/policy.cbor":
                    raw = stream.read((2 << 20) + 1)
                    require(len(raw) <= 2 << 20, "bundle policy exceeds the 2 MiB limit")
                    # Reuse policy.Hash and canonical decoding from the TEE,
                    # rather than duplicating the receipt's hash protocol here.
                    environment = {**os.environ, "GOOS": "", "GOARCH": ""}
                    result = subprocess.run(["go", "run", "./cmd/tee-policy-info", "-"], cwd=ROOT,
                                            input=raw, capture_output=True, env=environment)
                    require(result.returncode == 0, "cannot validate bundle policy: " + result.stderr.decode(errors="replace").strip())
                    info = json.loads(result.stdout)
                    policy_hash = info["policy_hash"]
                    measured_files[normalized] = info["policy_file_sha256"]
                else:
                    measured_files[normalized] = stream_digest(stream)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "bundle changed while reading")
    require(measured_files["app"], "bundle has no executable app")
    return {
        "application_id": "snp-app:" + digest, "bundle_sha256": digest,
        "bundle_size_bytes": after.st_size, "app_binary_sha256": measured_files["app"],
        "policy_hash": policy_hash, "policy_file_sha256": measured_files["policy/policy.cbor"],
        "ca_bundle_sha256": measured_files["etc/ssl/certs/ca-certificates.crt"],
    }


def build_manifest(repo, bundle, snapshot, kind):
    require(kind in {"tee", "single", "stub"}, "unknown bundle kind")
    require(isinstance(snapshot, dict) and set(snapshot) == {"source_repository", "source_commit", "source_dirty"},
            "invalid source snapshot")
    require(type(snapshot["source_dirty"]) is bool, "invalid source snapshot dirty flag")
    current = capture_source(repo)
    require(snapshot["source_commit"] == current["source_commit"] and
            snapshot["source_repository"] == current["source_repository"], "Git source changed during the build")
    source = {**snapshot, "source_dirty": snapshot["source_dirty"] or current["source_dirty"]}
    return {"version": 1, **inspect_bundle(bundle), **source, "bundle_kind": kind, "built_at": utc_now()}


def validate_manifest(value):
    require(isinstance(value, dict) and set(value) == BUILD_KEYS, "invalid build manifest fields")
    require(type(value["version"]) is int and value["version"] == 1, "unsupported build manifest version")
    application(value["application_id"])
    require(value["bundle_sha256"] == value["application_id"][8:], "bundle digest does not match application identity")
    require(type(value["bundle_size_bytes"]) is int and value["bundle_size_bytes"] > 0, "invalid bundle size")
    require(value["bundle_kind"] == "tee", "only real TEE bundles can be registered as releases")
    require(value["source_dirty"] is False, "dirty or unknown source cannot be registered as a release")
    require(isinstance(value["source_commit"], str) and COMMIT.fullmatch(value["source_commit"]), "missing source commit")
    https_url(value["source_repository"])
    for key in ("app_binary_sha256", "policy_hash", "policy_file_sha256", "ca_bundle_sha256"):
        require(isinstance(value[key], str) and HEX.fullmatch(value[key]), "missing or invalid " + key)
    timestamp(value["built_at"])


def validate_catalog(catalog, previous=None):
    require(isinstance(catalog, dict) and set(catalog) == {"version", "releases", "deployment_events", "revocations"},
            "invalid catalog fields")
    require(type(catalog["version"]) is int and catalog["version"] == 1, "unsupported catalog version")
    for key in ("releases", "deployment_events", "revocations"):
        require(isinstance(catalog[key], list), "invalid catalog list: " + key)
    releases = {}
    for release in catalog["releases"]:
        require(isinstance(release, dict) and set(release) == BUILD_KEYS | {"release_url", "published_at"}, "invalid release fields")
        validate_manifest({key: release[key] for key in BUILD_KEYS})
        identity = release["application_id"]
        require(identity not in releases, "duplicate released application identity")
        https_url(release["release_url"])
        require(timestamp(release["published_at"]) >= timestamp(release["built_at"]), "release predates build")
        releases[identity] = release
    revoked = {}
    for event in catalog["revocations"]:
        require(isinstance(event, dict) and set(event) == {"application_id", "at", "reason", "reference_url"}, "invalid revocation fields")
        identity = event["application_id"]
        require(isinstance(identity, str) and identity in releases and identity not in revoked, "unknown or already revoked application")
        require(isinstance(event["reason"], str) and event["reason"].strip(), "revocation requires a reason")
        https_url(event["reference_url"])
        require(timestamp(event["at"]) >= timestamp(releases[identity]["published_at"]), "revocation predates release")
        revoked[identity] = event
    active, last = {}, {}
    for event in catalog["deployment_events"]:
        require(isinstance(event, dict) and set(event) == {"environment", "application_id", "action", "at"}, "invalid deployment event fields")
        environment, identity = event["environment"], event["application_id"]
        require(isinstance(environment, str) and ENVIRONMENT.fullmatch(environment), "invalid environment name")
        require(isinstance(identity, str) and identity in releases, "deployment references an unknown release")
        when = timestamp(event["at"])
        require(when >= timestamp(releases[identity]["published_at"]), "deployment predates release")
        require(environment not in last or when >= last[environment], "deployment events are out of order")
        if event["action"] == "activate":
            require(environment not in active, "environment already has an active deployment")
            require(identity not in revoked or when < timestamp(revoked[identity]["at"]), "cannot activate a revoked release")
            active[environment] = identity
        else:
            require(event["action"] == "deactivate" and active.get(environment) == identity,
                    "deactivation does not match the active application")
            del active[environment]
        last[environment] = when
    if previous is not None:
        validate_catalog(previous)
        for key in ("releases", "deployment_events", "revocations"):
            require(catalog[key][:len(previous[key])] == previous[key], "catalog history is append-only: " + key)
    return releases, revoked, active


@contextmanager
def locked_catalog(path):
    path = Path(path)
    # Operators may run two updates at once. Lock the stable sidecar rather
    # than the catalog inode that atomic replacement swaps underneath readers.
    with path.with_name("." + path.name + ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        catalog = load_json(path)
        validate_catalog(catalog)
        previous = json.loads(json.dumps(catalog))
        yield catalog
        validate_catalog(catalog, previous)
        if catalog != previous:
            write_json(path, catalog)


def register_release(catalog, bundle, manifest, release_url, when):
    validate_manifest(manifest)
    actual = inspect_bundle(bundle)
    require(all(manifest[key] == value for key, value in actual.items()), "bundle does not match its build manifest")
    releases, _, _ = validate_catalog(catalog)
    identity = manifest["application_id"]
    https_url(release_url)
    if identity in releases:
        existing = releases[identity]
        immutable = BUILD_KEYS - {"built_at"}
        require(all(existing[key] == manifest[key] for key in immutable) and existing["release_url"] == release_url,
                "conflicting metadata for an existing release")
        return  # Rebuilds preserve the first registration and publication date.
    catalog["releases"].append({**manifest, "release_url": release_url, "published_at": when})


def deployment(catalog, environment, identity, action, when):
    releases, revoked, active = validate_catalog(catalog)
    require(identity in releases, "register the release before recording a deployment")
    events = catalog["deployment_events"]
    matching = [event for event in events if event["environment"] == environment]
    require(not matching or timestamp(when) >= timestamp(matching[-1]["at"]), "cannot backdate a deployment")
    if action == "activate":
        require(identity not in revoked, "cannot activate a revoked release")
        if active.get(environment) == identity:
            return
        if environment in active:
            events.append({"environment": environment, "application_id": active[environment], "action": "deactivate", "at": when})
    else:
        require(active.get(environment) == identity, "deactivation does not match the active application")
    events.append({"environment": environment, "application_id": identity, "action": action, "at": when})


def export_catalog(catalog, environment):
    releases, revoked, active = validate_catalog(catalog)
    require(ENVIRONMENT.fullmatch(environment), "invalid environment name")
    periods = []
    for event in catalog["deployment_events"]:
        if event["environment"] != environment:
            continue
        if event["action"] == "activate":
            periods.append({"application_id": event["application_id"], "activated_at": event["at"], "retired_at": None})
        else:
            # validate_catalog guarantees a deactivation always follows the
            # activation it retires, so this only guards against a future
            # caller reaching export with an unvalidated catalog.
            require(periods, "deactivation without an activation period")
            periods[-1]["retired_at"] = event["at"]
    return {
        "version": 1, "environment": environment, "current_application_id": active.get(environment),
        "releases": [{**release, "status": "revoked" if identity in revoked else
                      "current" if active.get(environment) == identity else
                      "retired" if any(period["application_id"] == identity for period in periods) else "available",
                      "revocation": revoked.get(identity)} for identity, release in releases.items()],
        "deployments": periods,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("source", help="capture source provenance before compiling")
    source.add_argument("--repo", type=Path, default=ROOT)
    source.add_argument("--output", type=Path, required=True)
    build = commands.add_parser("build-manifest", help="hash a finished bundle and write its sidecar")
    build.add_argument("--repo", type=Path, default=ROOT)
    build.add_argument("--bundle", type=Path, required=True)
    build.add_argument("--source-snapshot", type=Path, required=True)
    build.add_argument("--kind", choices=["tee", "single", "stub"], required=True)
    build.add_argument("--output", type=Path)
    for name in ("release", "activate", "deactivate", "revoke", "validate", "export"):
        command = commands.add_parser(name)
        command.add_argument("--catalog", type=Path, default=ROOT / "releases/catalog.json")
        if name in {"release", "activate", "deactivate", "revoke"}:
            command.add_argument("--at", default=utc_now(), help="RFC 3339 event time (defaults to UTC now)")
        if name == "release":
            command.add_argument("--bundle", type=Path, required=True)
            command.add_argument("--manifest", type=Path)
            command.add_argument("--release-url", required=True)
        if name in {"activate", "deactivate", "revoke"}:
            command.add_argument("--application-id", required=True)
        if name in {"activate", "deactivate", "export"}:
            command.add_argument("--environment", required=True)
        if name == "revoke":
            command.add_argument("--reason", required=True)
            command.add_argument("--reference-url", required=True)
        if name == "validate":
            command.add_argument("--previous", type=Path)
        if name == "export":
            command.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "source":
            write_json(args.output, capture_source(args.repo))
        elif args.command == "build-manifest":
            output = args.output or Path(str(args.bundle) + ".build.json")
            require(output.resolve() not in {args.bundle.resolve(), args.source_snapshot.resolve()}, "sidecar output would overwrite build input")
            write_json(output, build_manifest(args.repo, args.bundle, load_json(args.source_snapshot), args.kind))
        elif args.command == "validate":
            validate_catalog(load_json(args.catalog), load_json(args.previous) if args.previous else None)
            print("Release catalog is valid.")
        elif args.command == "export":
            result = export_catalog(load_json(args.catalog), args.environment)
            if args.output:
                require(args.output.resolve() != args.catalog.resolve(), "export would overwrite the release catalog")
                write_json(args.output, result)
            else:
                print(json.dumps(result, indent=2))
        else:
            timestamp(args.at)
            with locked_catalog(args.catalog) as catalog:
                if args.command == "release":
                    manifest_path = args.manifest or Path(str(args.bundle) + ".build.json")
                    register_release(catalog, args.bundle, load_json(manifest_path), args.release_url, args.at)
                elif args.command == "revoke":
                    catalog["revocations"].append({"application_id": args.application_id, "at": args.at,
                                                   "reason": args.reason, "reference_url": args.reference_url})
                else:
                    deployment(catalog, args.environment, args.application_id, args.command, args.at)
            print("Release catalog updated.")
        return 0
    except (ValueError, OSError, tarfile.TarError, KeyError, TypeError, AttributeError) as error:
        print("release-catalog: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

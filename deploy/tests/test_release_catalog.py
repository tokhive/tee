"""Offline acceptance of actual bundle bytes, publication and rollout history."""

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy/release_catalog.py"
spec = importlib.util.spec_from_file_location("release_catalog", SCRIPT)
catalog_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog_tool)


def empty_catalog():
    return {"version": 1, "releases": [], "deployment_events": [], "revocations": []}


class ReleaseCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(["go", "run", "./cmd/tee-policy-info", "--emit-default"], cwd=ROOT, capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode())
        cls.policy_bytes = result.stdout

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        self.run_git("init", "-q", "-b", "main")
        self.run_git("config", "user.name", "Release Test")
        self.run_git("config", "user.email", "release-test@example.com")
        self.run_git("config", "commit.gpgsign", "false")
        self.run_git("remote", "add", "origin", "git@github.com:tokhive/tee.git")
        (self.repo / "source.txt").write_text("original source")
        self.run_git("add", "source.txt")
        self.run_git("commit", "-qm", "fixture source")
        self.catalog = self.root / "catalog.json"
        catalog_tool.write_json(self.catalog, empty_catalog())

    def run_git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True, text=True).stdout.strip()

    def cli(self, *args, success=True):
        result = subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def bundle(self, name="bundle.tar", app=b"test executable", policy=True, roots=b"public roots"):
        if policy is True:
            policy = self.policy_bytes
        path = self.root / name
        with tarfile.open(path, "w") as archive:
            for member, content in {"./app": app, "./policy/policy.cbor": policy,
                                    "./etc/ssl/certs/ca-certificates.crt": roots}.items():
                if content is None:
                    continue
                info = tarfile.TarInfo(member)
                info.mode = 0o755 if member == "./app" else 0o644
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return path

    def manifest(self, bundle, kind="tee"):
        snapshot = self.root / "snapshot.json"
        self.cli("source", "--repo", self.repo, "--output", snapshot)
        self.cli("build-manifest", "--repo", self.repo, "--source-snapshot", snapshot,
                 "--bundle", bundle, "--kind", kind)
        return catalog_tool.load_json(str(bundle) + ".build.json")

    def release(self, name="a", kind="tee"):
        bundle = self.bundle(name + ".tar", app=name.encode())
        manifest = self.manifest(bundle, kind)
        when = manifest["built_at"]
        result = self.cli("release", "--catalog", self.catalog, "--bundle", bundle,
                         "--release-url", "https://github.com/tokhive/tee/releases/tag/" + name,
                         "--at", when, success=kind == "tee")
        return bundle, manifest, result

    def event(self, action, identity, when, environment="dev", success=True):
        return self.cli(action, "--catalog", self.catalog, "--environment", environment,
                        "--application-id", identity, "--at", when, success=success)

    def test_manifest_hashes_the_finished_archive_and_records_real_build_commit(self):
        bundle = self.bundle()
        before = bundle.read_bytes()
        manifest = self.manifest(bundle)
        self.assertEqual(bundle.read_bytes(), before)
        self.assertEqual(manifest["application_id"], "snp-app:" + hashlib.sha256(before).hexdigest())
        self.assertEqual(manifest["source_commit"], self.run_git("rev-parse", "HEAD"))
        self.assertEqual(manifest["source_repository"], "https://github.com/tokhive/tee")
        self.assertFalse(manifest["source_dirty"])
        self.assertEqual(manifest["policy_file_sha256"], hashlib.sha256(self.policy_bytes).hexdigest())
        self.assertEqual(manifest["policy_hash"], hashlib.sha256(b"TokenHive.Policy.v1" + self.policy_bytes).hexdigest())
        self.assertNotEqual(manifest["policy_hash"], manifest["policy_file_sha256"])
        with tarfile.open(bundle) as archive:
            self.assertFalse(any("build.json" in member.name for member in archive))

    def test_source_commit_must_remain_the_same_during_build(self):
        snapshot = self.root / "snapshot.json"
        self.cli("source", "--repo", self.repo, "--output", snapshot)
        self.run_git("commit", "--allow-empty", "-qm", "source changed during build")
        bundle = self.bundle()
        result = self.cli("build-manifest", "--repo", self.repo, "--source-snapshot", snapshot,
                          "--bundle", bundle, "--kind", "tee", success=False)
        self.assertIn("source changed", result.stderr)
        self.assertFalse(Path(str(bundle) + ".build.json").exists())

    def test_release_uses_build_commit_even_after_the_checkout_advances(self):
        bundle = self.bundle()
        manifest = self.manifest(bundle)
        self.run_git("commit", "--allow-empty", "-qm", "a later source commit")
        self.cli("release", "--catalog", self.catalog, "--bundle", bundle,
                 "--release-url", "https://github.com/tokhive/tee/releases/tag/test")
        release = catalog_tool.load_json(self.catalog)["releases"][0]
        self.assertEqual(release["source_commit"], manifest["source_commit"])
        self.assertNotEqual(release["source_commit"], self.run_git("rev-parse", "HEAD"))

    def test_dirty_unknown_and_diagnostic_sources_cannot_be_published(self):
        (self.repo / "source.txt").write_text("local uncommitted edit")
        bundle = self.bundle()
        self.assertTrue(self.manifest(bundle)["source_dirty"])
        before = self.catalog.read_bytes()
        result = self.cli("release", "--catalog", self.catalog, "--bundle", bundle,
                          "--release-url", "https://example.com/release", success=False)
        self.assertIn("dirty or unknown", result.stderr)
        self.assertEqual(self.catalog.read_bytes(), before)
        self.run_git("add", "source.txt")
        self.run_git("commit", "-qm", "fixture change")
        for kind in ("single", "stub"):
            with self.subTest(kind=kind):
                self.release(kind, kind)
        self.run_git("remote", "remove", "origin")
        self.assertTrue(self.manifest(bundle)["source_dirty"])
        self.cli("release", "--catalog", self.catalog, "--bundle", bundle,
                 "--release-url", "https://example.com/release", success=False)
        self.assertEqual(catalog_tool.load_json(self.catalog), empty_catalog())

    def test_bundle_tampering_and_missing_production_inputs_are_rejected(self):
        bundle = self.bundle()
        self.manifest(bundle)
        original = self.catalog.read_bytes()
        self.bundle(app=b"changed after manifest creation")
        result = self.cli("release", "--catalog", self.catalog, "--bundle", bundle,
                          "--release-url", "https://example.com/release", success=False)
        self.assertIn("does not match", result.stderr)
        for missing in ("policy", "roots"):
            bundle = self.bundle(missing + ".tar", **{missing: None})
            self.manifest(bundle)
            self.cli("release", "--catalog", self.catalog, "--bundle", bundle,
                     "--release-url", "https://example.com/release", success=False)
        self.assertEqual(self.catalog.read_bytes(), original)

    def test_changing_bundled_policy_changes_both_application_and_policy_identity(self):
        first = self.manifest(self.bundle("first-policy.tar"))
        changed = self.policy_bytes.replace(b"api.openai.com", b"api.sample.com", 1)
        self.assertNotEqual(changed, self.policy_bytes)
        second = self.manifest(self.bundle("second-policy.tar", policy=changed))
        self.assertNotEqual(first["application_id"], second["application_id"])
        self.assertNotEqual(first["policy_hash"], second["policy_hash"])
        self.assertEqual(first["app_binary_sha256"], second["app_binary_sha256"])
        invalid = self.bundle("invalid-policy.tar", policy=b"not canonical CBOR")
        result = self.cli("build-manifest", "--repo", self.repo, "--source-snapshot", self.root / "snapshot.json",
                          "--bundle", invalid, "--kind", "tee", success=False)
        self.assertIn("bundle policy", result.stderr)

    def test_bundle_archiving_preserves_the_original_manifest(self):
        bundle = self.bundle()
        manifest = self.manifest(bundle)
        original = Path(str(bundle) + ".build.json").read_bytes()
        self.run_git("commit", "--allow-empty", "-qm", "later checkout")
        source = (ROOT / "cloudtest/snp/crosshost.sh").read_text()
        function = re.search(r"^archive_bundle\(\) \{.*?^\}", source, re.M | re.S).group(0)
        archive = self.root / "archive"
        driver = "set -euo pipefail\nlog() { :; }\n" + function + '\narchive_bundle "$1" "$2"\n'
        result = subprocess.run(["bash", "-c", driver, "archive-test", str(bundle), manifest["application_id"]],
                                env={**os.environ, "BUNDLES_DIR": str(archive)}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        archived = archive / (manifest["bundle_sha256"] + ".tar")
        self.assertEqual(archived.read_bytes(), bundle.read_bytes())
        self.assertEqual(Path(str(archived) + ".build.json").read_bytes(), original)

    def test_existing_identity_cannot_be_relabelled_and_retry_is_idempotent(self):
        bundle, _, _ = self.release()
        before = self.catalog.read_bytes()
        self.cli("release", "--catalog", self.catalog, "--bundle", bundle,
                 "--release-url", "https://github.com/tokhive/tee/releases/tag/a")
        self.assertEqual(self.catalog.read_bytes(), before)
        self.cli("release", "--catalog", self.catalog, "--bundle", bundle,
                 "--release-url", "https://example.com/another-release", success=False)
        self.assertEqual(self.catalog.read_bytes(), before)

    def test_rollbacks_preserve_separate_periods_and_environment_state(self):
        _, a, _ = self.release("a")
        _, b, _ = self.release("b")
        a, b = a["application_id"], b["application_id"]
        self.event("activate", a, "2099-01-01T00:00:00Z")
        self.event("activate", b, "2099-01-02T00:00:00Z")
        self.event("activate", a, "2099-01-03T00:00:00Z")
        self.event("activate", b, "2099-01-03T00:00:00Z", environment="production")
        exported = json.loads(self.cli("export", "--catalog", self.catalog, "--environment", "dev").stdout)
        self.assertEqual(exported["current_application_id"], a)
        self.assertEqual([period["application_id"] for period in exported["deployments"]], [a, b, a])
        self.assertEqual(exported["deployments"][0]["retired_at"], "2099-01-02T00:00:00Z")
        self.assertIsNone(exported["deployments"][-1]["retired_at"])
        self.assertEqual({row["application_id"]: row["status"] for row in exported["releases"]}, {a: "current", b: "retired"})
        prod = json.loads(self.cli("export", "--catalog", self.catalog, "--environment", "production").stdout)
        self.assertEqual(prod["current_application_id"], b)
        before = self.catalog.read_bytes()
        self.event("activate", a, "2099-01-04T00:00:00Z")
        self.assertEqual(self.catalog.read_bytes(), before)
        self.event("deactivate", a, "2099-01-04T00:00:00Z")
        stopped = json.loads(self.cli("export", "--catalog", self.catalog, "--environment", "dev").stdout)
        self.assertIsNone(stopped["current_application_id"])

    def test_unknown_backdated_and_mismatched_deployments_leave_catalog_unchanged(self):
        _, manifest, _ = self.release()
        identity = manifest["application_id"]
        self.event("activate", identity, "2099-01-02T00:00:00Z")
        before = self.catalog.read_bytes()
        for action, app, when, environment in (
            ("activate", "snp-app:" + "0" * 64, "2099-01-03T00:00:00Z", "dev"),
            ("activate", identity, "2099-01-01T00:00:00Z", "dev"),
            ("deactivate", identity, "2099-01-03T00:00:00Z", "another-env"),
            ("activate", identity, "2000-01-01T00:00:00Z", "production"),
            ("activate", identity, "2099-01-03T00:00:00Z", "bad environment"),
        ):
            with self.subTest(action=action, app=app, when=when, environment=environment):
                self.event(action, app, when, environment, success=False)
                self.assertEqual(self.catalog.read_bytes(), before)

    def test_revoked_running_release_stays_visible_and_cannot_be_reactivated(self):
        _, manifest, _ = self.release()
        identity = manifest["application_id"]
        self.event("activate", identity, "2099-01-01T00:00:00Z")
        self.cli("revoke", "--catalog", self.catalog, "--application-id", identity,
                 "--at", "2099-01-02T00:00:00Z", "--reason", "fixture revocation", "--reference-url", "https://example.com/advisory")
        exported = json.loads(self.cli("export", "--catalog", self.catalog, "--environment", "dev").stdout)
        self.assertEqual(exported["current_application_id"], identity)
        self.assertEqual(exported["releases"][0]["status"], "revoked")
        self.event("activate", identity, "2099-01-03T00:00:00Z", environment="production", success=False)
        self.event("deactivate", identity, "2099-01-03T00:00:00Z")
        self.event("activate", identity, "2099-01-04T00:00:00Z", success=False)

    def test_published_records_and_events_cannot_be_deleted_or_rewritten(self):
        _, manifest, _ = self.release()
        self.event("activate", manifest["application_id"], "2099-01-01T00:00:00Z")
        self.cli("revoke", "--catalog", self.catalog, "--application-id", manifest["application_id"],
                 "--at", "2099-01-02T00:00:00Z", "--reason", "withdraw fixture release", "--reference-url", "https://example.com/advisory")
        previous = self.root / "previous.json"
        previous.write_bytes(self.catalog.read_bytes())
        catalog = catalog_tool.load_json(self.catalog)
        for field in ("releases", "deployment_events", "revocations"):
            changed = copy.deepcopy(catalog)
            changed[field] = []
            catalog_tool.write_json(self.catalog, changed)
            self.cli("validate", "--catalog", self.catalog, "--previous", previous, success=False)
        changed = copy.deepcopy(catalog)
        changed["releases"][0]["release_url"] = "https://example.com/rewritten"
        catalog_tool.write_json(self.catalog, changed)
        result = self.cli("validate", "--catalog", self.catalog, "--previous", previous, success=False)
        self.assertIn("append-only", result.stderr)

    def test_malformed_json_versions_and_credentials_in_urls_are_rejected(self):
        for content in ('{"version":1,"version":1}', '{"version":true,"releases":[],"deployment_events":[],"revocations":[]}',
                        '{"version":2,"releases":[],"deployment_events":[],"revocations":[]}'):
            self.catalog.write_text(content)
            self.cli("validate", "--catalog", self.catalog, success=False)
        catalog_tool.write_json(self.catalog, empty_catalog())
        bundle = self.bundle()
        self.manifest(bundle)
        for url in ("http://example.com/release", "https://secret@example.com/release"):
            self.cli("release", "--catalog", self.catalog, "--bundle", bundle, "--release-url", url, success=False)
        self.assertEqual(catalog_tool.load_json(self.catalog), empty_catalog())

    def test_export_and_manifest_outputs_cannot_overwrite_their_inputs(self):
        before = self.catalog.read_bytes()
        self.cli("export", "--catalog", self.catalog, "--environment", "dev", "--output", self.catalog, success=False)
        self.assertEqual(self.catalog.read_bytes(), before)
        bundle = self.bundle()
        before = bundle.read_bytes()
        snapshot = self.root / "snapshot.json"
        self.cli("source", "--repo", self.repo, "--output", snapshot)
        self.cli("build-manifest", "--repo", self.repo, "--bundle", bundle, "--source-snapshot", snapshot,
                 "--kind", "tee", "--output", bundle, success=False)
        self.assertEqual(bundle.read_bytes(), before)


class PackManifestTest(unittest.TestCase):
    def test_real_pack_generates_an_external_sidecar_without_changing_measured_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Run the unchanged pack script in an isolated layout, so an
            # operator's ignored .env and TLS fixtures cannot affect this test.
            fixture_repo = root / "fixture-repo"
            pack = fixture_repo / "cloudtest/snp/pack.sh"
            pack.parent.mkdir(parents=True)
            (fixture_repo / "deploy").mkdir()
            shutil.copyfile(ROOT / "cloudtest/snp/pack.sh", pack)
            shutil.copyfile(SCRIPT, fixture_repo / "deploy/release_catalog.py")
            tools = root / "bin"
            tools.mkdir()
            go = tools / "go"
            go.write_text("#!/usr/bin/env python3\nimport pathlib,sys\nargs=sys.argv[1:]\npathlib.Path(args[args.index('-o')+1]).write_bytes(b'fake build output')\n")
            go.chmod(0o755)
            digests = []
            for name in ("first.tar", "second.tar"):
                bundle = root / name
                inherited = {key: value for key, value in os.environ.items() if not key.startswith(("SNP_", "TOKENHIVE_"))}
                environment = {**inherited, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
                               "TOKENHIVE_BUILD_STUB": "1", "TOKENHIVE_BUILD_SINGLE": "0", "TOKENHIVE_OUT_BUNDLE": str(bundle)}
                result = subprocess.run(["bash", str(pack), "build"],
                                        env=environment, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                manifest = catalog_tool.load_json(str(bundle) + ".build.json")
                actual = hashlib.sha256(bundle.read_bytes()).hexdigest()
                digests.append(actual)
                self.assertEqual(manifest["application_id"], "snp-app:" + actual)
                self.assertEqual(manifest["bundle_kind"], "stub")
                with tarfile.open(bundle) as archive:
                    self.assertEqual(archive.getnames(), ["./app"])
            self.assertEqual(digests[0], digests[1])


if __name__ == "__main__":
    unittest.main()

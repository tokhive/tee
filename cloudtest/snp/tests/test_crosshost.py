"""Local tests for the cross-host deploy's whitelist plumbing. No AWS, no network.

The Hub admits agents and advertises /v1/policies from a whitelist, and the
enclave enforces one. They have to be the same document, and it has to be the
document the running app was measured with. Two ways that broke, both by hand:

(1) deploy uploaded the whitelist to ~/policy but started the Hub with
    -policy-dir $HOME/tee/policy, so on a clean host the Hub loaded no policy at
    all and refused every agent registration;
(2) deploy took the current build's policy file, so rebuilding for a newer
    whitelist and then deploying an instance launched earlier handed the Hub
    rules the enclave was not running.

These tests hold the properties that fix depends on: one place says where the
whitelist lives, deploy derives it from the running app's bundle, and the
bundle it picks is verified rather than trusted from its filename.

`record` is held to the same rule from the other side. It may only describe an
app whose archived bundle still hashes to the identity it is filed under, it may
only use an environment name Hive renders a page for, and recording is never a
side effect of a launch: a smoke test stays out of the history by not asking.
"""

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_DIR = Path(__file__).resolve().parent          # snp/tests
SNP = _DIR.parent                                # snp
REPO = _DIR.parents[2]                           # repository root
CROSSHOST = SNP / "crosshost.sh"
SRC = CROSSHOST.read_text()


def _shell_function(name):
    """The literal text of a top-level shell function, so the tests exercise the
    real code rather than a copy that can drift from it."""
    m = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}", SRC, re.M | re.S)
    if not m:
        raise AssertionError(f"no {name}() in {CROSSHOST}")
    return m.group(0)


class WhitelistLocationTest(unittest.TestCase):
    """Where deploy puts the whitelist and where it tells the Hub to read it."""

    def test_one_name_decides_where_the_whitelist_lives(self):
        # The bug was two hand-written paths for one location. They now derive
        # from a single variable, so this asserts the variable is the only
        # definition and that both users go through it.
        self.assertEqual(SRC.count('REMOTE_POLICY_REL="'), 1,
                         "REMOTE_POLICY_REL must be defined exactly once")
        self.assertNotIn("tee/policy", SRC,
                         "a hardcoded policy path is how the upload and -policy-dir drifted apart")
        self.assertIn('mkdir -p tee mtls ${REMOTE_POLICY_REL}', SRC)
        self.assertIn('"${REMOTE_POLICY_REL}/policy.cbor" >/dev/null', SRC,
                      "the whitelist upload must land in the shared location")
        self.assertIn('-policy-dir "\\$HOME/${REMOTE_POLICY_REL}"', SRC,
                      "the Hub's -policy-dir must be that same location")


class DeployWhitelistVersionTest(unittest.TestCase):
    """Which build's whitelist deploy ships."""

    def test_deploy_uses_the_running_apps_bundle(self):
        body = _shell_function("cmd_deploy")
        self.assertIn('archived_bundle "${app_hash}"', body,
                      "deploy must resolve the whitelist by the attested app identity")
        self.assertNotIn("POLICY_DIR", body,
                         "the current build's policy dir does not say which app is running")

    def test_every_build_archives_its_bundle(self):
        # The lookup above can only work if a build files its bundle under the
        # digest it measures.
        self.assertEqual(SRC.count('archive_bundle "${bundle}" "${digest}"'), 2,
                         "both build and build-single must archive")

    def test_deploy_refuses_when_no_bundle_measures_the_running_app(self):
        body = _shell_function("cmd_deploy")
        self.assertIn("exit 1", body)
        self.assertIn("no archived bundle measuring", body)


class AppIdentityTest(unittest.TestCase):
    """Which app identity gets pinned, and where that identity comes from.

    deploy resolves the whitelist by the app_hash in state, so a state file that
    records a digest the launched image does not measure would defeat the whole
    scheme: the pair (recorded digest, archived policy) is internally consistent
    even when both describe a different build than the enclave is running. The
    recorded identity therefore has to come from the image itself.
    """

    def test_up_records_the_launched_images_own_digest(self):
        body = _shell_function("cmd_up")
        self.assertIn('ami_app_digest "${a}"', body,
                      "up must read the digest off the AMI it launched")
        self.assertNotIn("pack.sh digest", body,
                         "re-hashing bin/ can name a build the launched AMI does not embed")

    def test_images_carry_the_digest_they_embed(self):
        src = (REPO / "deploy" / "snp-build.sh").read_text()
        m = re.search(r"ec2 register-image.*?--output text\)", src, re.S)
        self.assertIsNotNone(m, "no register-image call found")
        # The value must be the bare sha256. "snp-app:" is the app-identity
        # prefix up adds when it pins the TEE, so tagging the image with the
        # prefixed form would name an identity no image can ever satisfy.
        self.assertIn("{Key=snp-app,Value=${DIGEST#snp-app:}}", m.group(0),
                      "the tag value must be the digest the image embeds, unprefixed")

    def test_up_pins_the_image_before_paying_for_it(self):
        # The tag is the only thing that can pin the run, so an image without
        # one has to be refused before an instance is bought for it.
        body = _shell_function("cmd_up")
        self.assertLess(body.index('ami_app_digest "${a}"'),
                        body.index('crosshost.py "${a}"'),
                        "up must read the image's tag before launching it")

    def test_up_records_the_identity_in_state(self):
        # deploy resolves the whitelist by tee.app_hash in crosshost.json, so up
        # has to write it there — and only after the launch, because
        # crosshost.py is what creates the tee record that write merges into.
        body = _shell_function("cmd_up")
        self.assertRegex(body, r"p\['tee'\]\['app_hash'\]\s*=")
        self.assertIn("${HOSTS}", body)
        self.assertGreater(body.index("p['tee']['app_hash']"),
                           body.index('crosshost.py "${a}"'),
                           "the identity is recorded once the instance exists")

    def test_a_missing_tag_is_refused_rather_than_guessed(self):
        body = _shell_function("ami_app_digest")
        self.assertIn("no snp-app tag", body)
        self.assertIn("sys.exit", body)
        # No fallback that would re-introduce the guess this replaces.
        self.assertNotIn("sha256sum", body)


class ArchivedBundleTest(unittest.TestCase):
    """archived_bundle is the gate: it must not hand back a bundle on trust."""

    def _run(self, bundles_dir, app_hash):
        script = "set -euo pipefail\n" + _shell_function("archived_bundle") + "\n"
        script += f'BUNDLES_DIR={bundles_dir}\narchived_bundle {app_hash}\n'
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True)

    def test_returns_the_bundle_that_measures_the_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = b"the-bundle-the-enclave-measures"
            digest = hashlib.sha256(payload).hexdigest()
            archive = Path(tmp) / f"{digest}.tar"
            archive.write_bytes(payload)

            out = self._run(tmp, digest)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(out.stdout.strip(), str(archive))

    def test_refuses_a_bundle_that_does_not_measure_the_digest(self):
        # The filename claims the digest; the contents are not the app that
        # digest names. Trusting the name here would hand the Hub a whitelist
        # from some other build.
        with tempfile.TemporaryDirectory() as tmp:
            claimed = "0" * 64
            (Path(tmp) / f"{claimed}.tar").write_bytes(b"a different build")

            out = self._run(tmp, claimed)
            self.assertNotEqual(out.returncode, 0,
                                "a tampered/wrong bundle must not be accepted")
            self.assertEqual(out.stdout.strip(), "")

    def test_refuses_when_nothing_was_archived(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._run(tmp, "1" * 64)
            self.assertNotEqual(out.returncode, 0)
            self.assertEqual(out.stdout.strip(), "")


class SwapWiringTest(unittest.TestCase):
    """`up --new` / `down --superseded`: the shell half of the no-wait swap.

    The swap's safety lives in crosshost.py and retire.py, but the operator
    reaches both through these two shells — and a flag that is accepted and then
    dropped is silent: `up --new` without --new quietly becomes "adopt whatever
    is recorded", which is the very thing the swap was written to avoid.
    """

    def test_up_parses_and_forwards_new(self):
        body = _shell_function("cmd_up")
        self.assertIn('new_arg="--new"', body)
        self.assertIn("${new_arg}", body,
                      "--new must reach crosshost.py, not just be accepted here")

    def test_down_superseded_delegates_to_retire_py(self):
        body = _shell_function("cmd_down")
        self.assertIn("retire.py", body)
        self.assertIn('--state "${HOSTS}"', body)
        # Its only narrowing is the recorded superseded set; the tag-wide
        # delete.py must not be reachable on that path.
        self.assertNotIn("delete.py", body[body.index("--superseded"):body.index("if [[ -z \"${tee_only}\"")])

    def test_down_keeps_the_two_narrowings_apart(self):
        body = _shell_function("cmd_down")
        self.assertIn("mutually exclusive", body)

    def test_console_dump_asks_for_the_latest_output(self):
        # Without Latest=True get_console_output returns a stale buffer, so a TEE
        # that came up after boot looks like one that never logged again — the
        # check a swap leans on to decide the new enclave is serving.
        body = _shell_function("dump_tee_console")
        self.assertIn("Latest=True", body)


class RecordTest(unittest.TestCase):
    """record turns a deployed identity into catalog history, and refuses the
    identities it cannot vouch for."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.repo = root / "repo"
        (self.repo / "releases").mkdir(parents=True)
        self.catalog = self.repo / "releases" / "catalog.json"
        self.catalog.write_text('{"version":1,"releases":[],"deployment_events":[],"revocations":[]}\n')
        self.bundles = root / "bundles"
        self.bundles.mkdir()
        self.deploy = root / "deploy"
        self.deploy.mkdir()
        self.calls = root / "calls.log"
        # Stand-in for release_catalog.py: logs the argv it was handed and keeps
        # the catalog in the shape record reads back (a digest keeps the URL it
        # was published under, activating what is already active changes
        # nothing). The tool's real behaviour is deploy/tests' subject; here the
        # point is the contract record passes it.
        stub = """import json, os, sys
argv = sys.argv[1:]
with open(@CALLS@, 'a') as log:
    log.write(' '.join(argv) + '\\n')
if '--catalog' not in argv:
    sys.exit(0)
path = argv[argv.index('--catalog') + 1]
data = json.load(open(path))
if argv[0] == 'release':
    identity = 'snp-app:' + os.path.basename(argv[argv.index('--manifest') + 1]).split('.')[0]
    if not any(r['application_id'] == identity for r in data['releases']):
        data['releases'].append({'application_id': identity,
                                 'release_url': argv[argv.index('--release-url') + 1]})
else:
    identity = argv[argv.index('--application-id') + 1]
    environment = argv[argv.index('--environment') + 1]
    active = {e['environment']: e['application_id'] for e in data['deployment_events']}
    if active.get(environment) != identity:
        data['deployment_events'].append({'environment': environment, 'application_id': identity})
with open(path, 'w') as catalog:
    json.dump(data, catalog)
"""
        self.deploy.joinpath("release_catalog.py").write_text(stub.replace("@CALLS@", repr(str(self.calls))))
        self.hosts = root / "crosshost.json"
        payload = b"the bundle the enclave is measured with"
        self.digest = hashlib.sha256(payload).hexdigest()
        self.bundle = self.bundles / f"{self.digest}.tar"
        self.bundle.write_bytes(payload)
        self.sidecar = self.bundles / f"{self.digest}.tar.build.json"
        self.sidecar.write_text(json.dumps({
            "source_repository": "https://github.com/tokhive/tee",
            "source_commit": "1" * 40,
            "policy_hash": "2" * 64,
        }))
        self._init_repo()

    def test_records_the_bundle_state_says_is_running(self):
        self._state(self.digest)
        out = self._run("--environment", "staging")
        self.assertEqual(out.returncode, 0, out.stderr)
        release, activate = self._calls()
        self.assertIn(f"--catalog {self.catalog}", release)
        self.assertIn(f"--bundle {self.bundle}", release)
        self.assertIn(f"--manifest {self.sidecar}", release)
        self.assertIn("https://github.com/tokhive/tee/commit/" + "1" * 40, release)
        self.assertIn("--environment staging", activate)
        self.assertIn("--application-id snp-app:" + self.digest, activate)

    def test_dry_run_resolves_the_inputs_without_writing(self):
        # --dry-run exists so the real digest and release URL can be read before
        # anything is committed to history.
        self._state(self.digest)
        out = self._run("--environment", "staging", "--dry-run")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse(self.calls.exists(), "dry-run must not reach the catalog")
        self.assertIn("  release  --catalog", out.stdout)
        self.assertIn("--application-id snp-app:" + self.digest, out.stdout)
        self.assertIn("https://github.com/tokhive/tee/commit/" + "1" * 40, out.stdout)

    def test_environment_name_must_match_the_published_view(self):
        # 'prod' would not fail anywhere on its own: it would start a second
        # history that no page reads, while 'production' kept showing nothing.
        self._state(self.digest)
        out = self._run("--environment", "prod")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("staging production", out.stdout + out.stderr)
        self.assertFalse(self.calls.exists(), "a rejected name must not reach the catalog")

    def test_records_a_build_this_machine_did_not_launch(self):
        # No state file: production hosts are launched elsewhere, so the identity
        # has to be acceptable from the command line.
        out = self._run("--environment", "production", "--application-id", "snp-app:" + self.digest)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(len(self._calls()), 2)

    def test_refuses_a_bundle_without_a_sidecar(self):
        # No sidecar means no source commit and no policy hash, which is exactly
        # what the catalog entry exists to state.
        self._state(self.digest)
        self.sidecar.unlink()
        out = self._run("--environment", "staging")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("sidecar", out.stdout + out.stderr)
        self.assertFalse(self.calls.exists())

    def test_refuses_a_bundle_that_does_not_measure_the_identity(self):
        self._state(self.digest)
        self.bundle.write_bytes(b"a different build")
        out = self._run("--environment", "staging")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("no archived bundle measures", out.stdout + out.stderr)
        self.assertFalse(self.calls.exists())

    def test_commit_lands_only_the_catalog(self):
        # The deploy host is somebody's working tree. Committing whatever else
        # they had staged would attach unrelated work to a release record, so
        # the staged README below has to survive the commit untouched.
        (self.repo / "README").write_text("an unrelated local edit\n")
        self._git("add", "README")
        self._state(self.digest)
        out = self._run("--environment", "staging")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self._git("rev-list", "--count", "HEAD").stdout.strip(), "2")
        self.assertEqual(self._git("show", "--name-only", "--pretty=format:", "HEAD").stdout.split(),
                         ["releases/catalog.json"])
        self.assertIn("README", self._git("status", "--porcelain").stdout)

    def test_no_commit_leaves_the_entry_for_review(self):
        self._state(self.digest)
        out = self._run("--environment", "staging", "--no-commit")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self._git("rev-list", "--count", "HEAD").stdout.strip(), "1")
        self.assertIn("releases/catalog.json", self._git("status", "--porcelain").stdout)

    def test_repeating_a_record_does_not_add_an_empty_commit(self):
        # The catalog tool is idempotent for a digest already registered and an
        # environment already running it, so the second run has nothing to say.
        # Turning that into a commit would fill the history with no-ops.
        self._state(self.digest)
        self._run("--environment", "staging")
        out = self._run("--environment", "staging")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("nothing to commit", out.stdout)
        self.assertEqual(self._git("rev-list", "--count", "HEAD").stdout.strip(), "2")

    def test_record_reuses_the_url_of_an_already_published_build(self):
        # register_release refuses to relabel a digest, so the default here must
        # not be derived fresh: promoting a build that was recorded with an
        # announcement link would otherwise fail on a URL nobody changed.
        self.catalog.write_text(json.dumps({
            "version": 1,
            "releases": [{"application_id": "snp-app:" + self.digest,
                          "release_url": "https://example.invalid/announcement"}],
            "deployment_events": [], "revocations": []}))
        self._state(self.digest)
        out = self._run("--environment", "production", "--no-commit")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("--release-url https://example.invalid/announcement", self._calls()[0])

    def test_refuses_to_commit_an_untracked_catalog(self):
        # git reports no diff for a path it does not track, so without this the
        # run would claim "already recorded" and leave the entry out of history.
        self._git("rm", "-q", "--cached", "releases/catalog.json")
        self._git("commit", "-q", "-m", "drop the catalog")
        self._state(self.digest)
        out = self._run("--environment", "staging")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("not tracked", out.stdout + out.stderr)
        self.assertEqual(self._git("rev-list", "--count", "HEAD").stdout.strip(), "2")

    def _state(self, app_hash):
        self.hosts.write_text(json.dumps({"tee": {"app_hash": app_hash}}))

    def _calls(self):
        return self.calls.read_text().splitlines()

    def _git_env(self):
        # A throwaway repository must not inherit the operator's signing setup
        # or identity, or the commit under test would depend on this machine.
        return {**os.environ,
                "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_AUTHOR_NAME": "record test", "GIT_AUTHOR_EMAIL": "record@example.invalid",
                "GIT_COMMITTER_NAME": "record test", "GIT_COMMITTER_EMAIL": "record@example.invalid"}

    def _git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args],
                              capture_output=True, text=True, env=self._git_env(), check=True)

    def _init_repo(self):
        self._git("init", "-q")
        (self.repo / "README").write_text("the deploy host's working tree\n")
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "initial")

    def _run(self, *args):
        script = "\n".join([
            "set -euo pipefail",
            'log() { echo "$*"; }',
            'py() { "$PY" "$@"; }',
            _shell_function("archived_bundle"),
            _shell_function("cmd_record"),
            # Mirrors crosshost.sh's tee_field, which the extractor cannot lift
            # because it is written on one line.
            'tee_field() { "$PY" -c "import json,sys; print(json.load(open(sys.argv[1]))[\'tee\'][\'$1\'])" "$HOSTS"; }',
            f"PY={shlex.quote(sys.executable)}",
            f"HOSTS={shlex.quote(str(self.hosts))}",
            f"BUNDLES_DIR={shlex.quote(str(self.bundles))}",
            f"REPO_ROOT={shlex.quote(str(self.repo))}",
            f"DEPLOY_DIR={shlex.quote(str(self.deploy))}",
            'RECORD_ENVIRONMENTS="staging production"',
            "cmd_record " + " ".join(shlex.quote(arg) for arg in args),
        ])
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=self._git_env())


if __name__ == "__main__":
    unittest.main()

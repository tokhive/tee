# Public release materials and independent verification

This page covers Hive #200. A publisher signature shows who published the catalog. A hardware attestation shows that the receipt signing key is bound to the attested execution environment. The two checks are separate, and each must be done on its own. The tooling can already sign the catalog, but the repository never generates or trusts an official release key by itself.

## Where to find the materials

- [Application releases and environment history](../releases/catalog.json): build digests, source commits, policy hashes, activation and deactivation events, and revocations.
- [Build and registration workflow](tee-release-catalog.md): how the provenance of the actual bundle and its build sidecar is checked.
- [Build, deployment and signed release workflow](release-publishing.md): who does what, source and catalog commits, tag order, and handing over release assets.
- [Whitelist source](../policy/whitelist.json): for a formal check, use the source commit of the matching release and the `policy/policy.cbor` inside the bundle. Do not treat the policy on `main` as the policy of a past release.
- [Independent verifier](https://github.com/tokhive/verifier), [pinned release downloads](https://github.com/tokhive/verifier/releases), [web verifier](https://verifier.tokhive.ai/).
- [Verification contract](https://github.com/tokhive/verifier/blob/main/API.md), [trust boundaries](#trust-boundaries).

A formal release should include as assets: the original `catalog.json` and its `.sig`; the signing public key, with a note on how to confirm its fingerprint through an independent channel; the relevant build records and publishable artifact digests; the verifier version and download checksums; and a real hardware receipt produced by a synthetic request, with its verification report. Mark any material that is not ready yet as pending. Do not substitute a software-simulated receipt for a passing hardware sample.

## Release signing identity

Signatures use the OpenSSH 8.2+ SSHSIG format with the fixed namespace `tokhive-tee-release`. Use a dedicated Ed25519 release key. Do not reuse the TEE epoch key, the Hive client certificate or the Relay TLS private key. The release owner arranges how the official key is generated, encrypted at rest, backed up and authorized for use. The tooling can use a key loaded into `ssh-agent` or a private key file you name. It never accepts a passphrase on the command line.

Read the public key fingerprint with:

```bash
ssh-keygen -lf /secure/release-signing.pub -E sha256
```

To establish trust the first time, a maintainer confirms the public key fingerprint through an independently maintained channel, such as an official website notice or the organization's security channel. Users then compare it against the public key they downloaded. Reading the public key from the catalog being verified, or from the same set of assets, is not independent trust. Until the official public key has been published and confirmed, a local signing rehearsal is not a trusted formal release.

Users build their own trusted `allowed_signers` file. Replace the key part of this example with the full public key you have confirmed:

```text
tokhive-release namespaces="tokhive-tee-release" ssh-ed25519 <independently-verified-public-key>
```

`tokhive-release` is the signing principal, which the verifier names explicitly. Never add an identity or public key read from the catalog to this file automatically.

## Signing a formal catalog

First review and commit `releases/catalog.json`, and confirm that the entries reflect what was actually deployed. Then, in the same checkout, run:

```bash
git rev-parse HEAD
python3 deploy/release_catalog.py validate
python3 deploy/signed_release.py sign \
  --catalog releases/catalog.json \
  --key /secure/release-signing.pub \
  --signature /secure/output/catalog.json.sig
```

The example uses a public key file whose private key is loaded into `ssh-agent`; a controlled private key file also works. The tool signs only committed catalog bytes that are identical to the current HEAD. It refuses uncommitted changes and never overwrites an existing signature file. It does not modify the catalog, activate an environment, or push or upload anything. Publish the original catalog from that commit together with its signature. Reformatting the JSON breaks the signature.

The command prints the catalog's source commit and SHA-256. The signature covers the raw catalog bytes. The Git commit only locates where the release came from; SSHSIG does not sign it as an extra field. To check the Git provenance, compare the file bytes at that pinned commit separately.

### Rotating and revoking the signing key

For a normal rotation, announce the old and new fingerprints, the switch time and the reason in advance through the independent channel. The old key may sign a migration notice that contains the new fingerprint, but users still have to judge it by the channel and by whether the old key is still trusted. After a short overlap window during which both confirmed keys are accepted, remove the old key's authority for future releases. Keep the original catalogs, signatures and notices, and do not overwrite past assets.

If the old key is compromised, a new-key statement signed by the old key is not enough. Restore trust through the independent channel, update users' `allowed_signers`, and state clearly which past releases need to be checked again. The tooling never downloads or updates trust files by itself, and it has no trusted historical timestamps: a plain SSHSIG does not prove that a signature was made before the key was compromised.

Revoking an application release and revoking the release key are two different operations. For the first, append a record with `release_catalog.py revoke`, then sign and publish the new full catalog. For the second, update the independent trust channel and `allowed_signers`.

## How users check the catalog

Get the original catalog and its signature from the confirmed release channel, then run this with your independently trusted `allowed_signers`:

```bash
python3 deploy/signed_release.py verify \
  --catalog catalog.json \
  --signature catalog.json.sig \
  --allowed-signers allowed_signers \
  --identity tokhive-release \
  --environment production \
  --output tee-production.json
```

The tool verifies the signature first, then validates the catalog against the current schema and exports the view. It refuses to export for an unknown environment, an environment with no active release, or an environment whose current identity is revoked, and the output file must not already exist. The output can be given to Hive as `HIVE_TEE_RELEASE_CATALOG_FILE`; the environment and the catalog's source commit are configured separately. Hive's current loader does not verify SSHSIG itself, so whoever deploys it must run the check above first.

This proves that the signing publisher once published these bytes. It does not prove that this is the latest catalog or what the instance is doing right now. An old, valid signature can still be replayed, so get the latest catalog from the confirmed channel and check the version, dates, revocation notices and expected environment. Offline materials cannot tell you about revocations published later. For a test environment, use the environment name that was actually registered. Do not pass `production` just to make the tool succeed.

## How users check their own receipts

1. Open your call in Hive's Call Records and download the raw CBOR receipt for each execution attempt. Verify each attempt separately.
2. Take the application identity and policy hash from the confirmed release record, and check that the call time falls inside an actual activation window and that the release was not revoked. Do not copy the application identity the receipt claims for itself and use it as the source of trust.
3. In the web verifier, choose **Receipt file**, enter the trusted application identity, and enter the policy hash under **Additional expectations**. Or use a pinned CLI release:

```bash
tokhive-verify verify \
  --expected-app 'snp-app:<trusted-application-hash>' \
  --expected-policy '<trusted-policy-hash>' \
  --json receipt.cbor
```

4. Save the report and review the signature, hardware attestation, application identity and policy checks one by one. A software-simulated attestation must fail. Missing material must show as insufficient information or a failure, never be swapped for a passing example.

The CLI can also download a receipt from the buyer API by request ID. It reads the buyer key from `HIVE_API_KEY` by default; for a test environment, pass `--api-base-url` explicitly. The web verifier is a static site: file mode needs no key, and the file stays in your browser. Request ID mode currently needs the restricted local bridge that ships with the verifier. Never expose that local service to the internet.

The verifier does not yet read the catalog or revocation notices by itself. Check the catalog first, then supply the expected application identity and policy by hand. Do not claim that opening the web page alone establishes release trust.

## Public samples from real hardware

Use only synthetic requests created for this purpose, whose content can be made public. The raw receipt and evidence must come from a real hardware instance. Record the environment, version, time, execution ID, SHA-256 of the downloaded file, verifier version, command and expected result. Get it working in the test environment first, then add a production sample after the formal deployment is done.

Before publishing, check whether the receipt's signed fields include provider routing identifiers, upstream paths or similar details, and choose test supply that can be made public. Never edit a receipt and still call it original signed evidence. Keep real business content, tokens, buyer keys, provider email addresses, internal connection settings and private keys out of the assets. An application bundle may contain deployment certificates or other runtime material, and publishing a digest does not authorize publishing the whole bundle. Check each item before publishing any original artifact.

## Trust boundaries

- Hive handles request semantics, scheduling and billing. The TEE injects credentials, establishes upstream TLS and signs execution receipts. Bee forwards ciphertext and does not read buyer content. Official upstreams and third-party relays are told apart by the receipt's host and path; reaching a relay is not the same as connecting to the official provider directly.
- Bee currently trusts the recipient public key that Hive hands it, and does not yet defend against a malicious Hive replacing that key. The plain ProviderSeq file has no trusted rollback protection.
- The model name and usage are what the upstream reports. The verifier does not independently identify the real model or recount tokens.
- The mapping from a buyer request ID to an execution ID comes from Hive. The request ID itself is not a field the TEE signs.
- A passing receipt does not mean the content has been checked. Hive's current download does not include the full JobSpec or the exact upstream request and response bytes. Protocol conversion, compression and history restoration can change what the client sees, so do not try to make it match by re-serializing JSON.
- The pinned library's [SNP verification](../shared/sev_snp_attestation.go) rejects DEBUG and any VMPL other than 0, with a minimum TCB of `0xde1d000000000004` (compared field by field). The code, embedded public keys and root certificates in [combined attestation](../shared/snp_combined_verify.go) and [Secure Boot verification](../shared/secure_boot.go) define the actual behavior. A release should link these files at the commit it uses and record the public key fingerprints. The exact checks for combined AWS SEV-SNP and NitroTPM attestation depend on the pinned verifier and TEE library versions. Check the AMD and AWS roots, the Secure Boot release public key, and the debug and TCB policy in the corresponding source. Do not treat the application `snp-app`, the base image `snp-base` and the SNP launch measurement as the same hash.
- Certificates are verified against the current time. Once a past certificate expires, verification may fail; trusted historical timestamps are not implemented.
- Hive's diagnostics for failed requests may keep prompts and code, which are handled under the actual privacy policy and retention period. A TEE attestation does not mean Hive holds no business content.

# TokenHive TEE

The confidential half of TokenHive: an AMD SEV-SNP enclave that turns a buyer's
request into an attested execution against an AI provider, acting as a provider
agent's network proxy, and returns a signed receipt the Hub settles against.

The Hub, the provider agent and the public docs live in sibling repositories:

| Repository | Role |
| --- | --- |
| [`tokhive/hive`](https://github.com/tokhive/hive) | Production Hub: routing, pricing, billing, settlement. Imports this module as a Go library. |
| [`tokhive/bee`](https://github.com/tokhive/bee) | Provider agent: a TCP-layer repeater that dials the Hub and carries TLS bytes to the AI provider. |
| [`tokhive/doc-site`](https://github.com/tokhive/doc-site) | Public documentation site. |

## What the enclave does

1. The Hub hands it a job: which provider agent to dial, which credential to use,
   which upstream host to reach.
2. The enclave opens a provider connection through the Hub's relay and the agent's
   reverse tunnel, then speaks TLS to the AI provider itself. The agent only moves
   ciphertext; it never sees a plaintext request.
3. The response streams back to the Hub, and the enclave signs a receipt over the
   bytes it carried. The Hub verifies that receipt against the attested image
   before it settles anything.

The Hub never sees a provider credential in plaintext, and the provider agent never
sees a buyer's prompt. Both trust the enclave's measurement, not each other.

## Layout

```
cmd/tee/            the TEE binary (also the attestation broker under the SNP loader)
tee/                execution service, receipts, sessions, credential handling
transport/          provider channel, relay client, failure classification
tunnel/             reverse-tunnel framing shared with the provider agent
jobs/ policy/ proof/  job specs, the egress whitelist, receipts
platform/           attestation platforms: sevsnp (production), simulated (tests)
evidence/ metrics/  evidence retrieval, timing instrumentation
shared/             runtime base: RA-TLS, SNP attestation,
                    Secure Boot, logging, env helpers
proto/              generated protocol types used by shared

hub/ provider/      reference Hub and provider agent, used only by the test harness
integration/        in-process end-to-end tests
harness/            the local simulation harness
cloudtest/          AWS provisioning and the cross-host real-TEE test
deploy/             the SEV-SNP image build (loader, pins, Secure Boot material)
docs/               design, audit and operations notes
```

`cmd/tee` is the only binary that ships. Everything under `hub/` and `provider/`
exists so the harness can drive a full business loop without a cloud account.

## Build and test

Go 1.27.3 or newer, per `go.mod`.

```sh
go build ./...
go vet ./...
go test ./...

# The Linux binary that goes into the measured app bundle.
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -tags 'sevsnp enclave osusergo netgo static_build' -trimpath ./cmd/tee
```

The local harness starts a reference Hub, a reference provider agent, a mock AI
provider and the TEE on loopback and drives eighteen scenarios end to end:

```sh
bash harness/harness.sh
```

Run it from a clean checkout. A leftover `.sim/` directory from an interrupted run
makes scenarios fail for the wrong reason; the harness wipes it before starting.

## Running the TEE

```sh
./tee -addr 127.0.0.1:18090 -platform simulated
```

Configuration is environment-driven. The ones that matter operationally:

| Variable | Meaning |
| --- | --- |
| `TEE_PLATFORM` | `simulated` for local runs, `sevsnp` inside a real enclave. |
| `TEE_ADDR` | Listen address, default `127.0.0.1:18090`. |
| `TEE_RELAY` / `TEE_RELAY_KEY` | The Hub's relay WebSocket and its shared key. Without a relay the TEE cannot reach any provider. |
| `TEE_MTLS` | Demand a Hub client certificate on the RA-TLS listener. Production sets this. |
| `TEE_EVIDENCE` | Embed full attestation evidence in every receipt. The Hub cannot settle without it. |
| `TEE_REQUEST_TIMEOUT` | Bound on one provider exchange. Must stay below the Hub's execution budget. |
| `TEE_TIMING` / `TEE_METRICS_ADDR` | Stage timing: `off`, `summary` or `full`, and an optional plaintext `/timing` endpoint. |

Routes: `POST /v1/execute` (a job), `GET /v1/session` (a WebSocket upgrade for a
long-lived stream), `GET /v1/credential-key` (the enclave's current envelope key).

## Deploying to AWS

The image is a two-tier UKI: a Secure-Boot-signed base that carries the loader, plus
a replaceable app bundle whose SHA-256 is the `snp-app:` identity the Hub pins.

```sh
cp deploy/.env.example deploy/.env      # GCP_PROJECT and AWS_SNP_REGION
cp cloudtest/.env.example cloudtest/.env # TOKENHIVE_USER: the tag prefix on every resource
# provision deploy/secure-boot/R.key out of band; it is gitignored on purpose

cd cloudtest/snp
./crosshost.sh build                    # bundle + AMI, about 13 minutes
./crosshost.sh up --tee-only --host-ip <hub-ip>
./crosshost.sh deploy
./crosshost.sh verify
./crosshost.sh down
```

The full operations manual, including what each step creates and the traps found
while doing it for real, is [`docs/aws-snp-deployment.md`](docs/aws-snp-deployment.md);
[`cloudtest/snp/README.md`](cloudtest/snp/README.md) documents the cross-host tool itself.

The build prints two values worth recording: the app digest (`snp-app:<sha256>`),
which the Hub must pin via `HIVE_TEE_EXPECTED_APP`, and the base UKI hash, which
must not change when only the app changes.

Structured logs ship to CloudWatch Logs under `/tokhive/tee/snp` when the instance
carries an IAM profile. Without one they only reach the serial console, which keeps
a few minutes.

AWS resources this tooling creates are still tagged `tokenhive-TEE` and named
`snp-tokenhive*`. Those strings are resource identities, not repository paths, and
deletion matches on them; renaming them would orphan live instances.

## Consuming this module

`hive` and `bee` import the packages above. The contract they rely on:

- `policy.Default()` defines the egress whitelist, and its hash is what a receipt
  must name. Both sides compute it from this module so they cannot drift.
- `tunnel` is the wire format between the Hub and a provider agent.
- `tee`, `jobs`, `proof` carry the job spec, the response framing and the receipt.

Pin a commit, not a version range. `hive` and `bee` keep the pinned commit in a
`TEE_REVISION` file and vendor it into `.cache/` at build time.

## Documentation

`docs/README.md` indexes the design notes, the external interface contract, the
AWS deployment manual, and the incident audits. Paths in every note are written as
they are in this repository; commit hashes in the audit notes predate the move and
do not resolve here.

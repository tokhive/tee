# Documentation

The notes below are the working record of the TEE: why it is built this way, what
it promises the Hub, and what went wrong along the way. Body text is in Chinese;
the filenames and this index are in English so links and searches stay usable.

| Document | What it covers |
| --- | --- |
| [`architecture-reverse-tunnel.md`](architecture-reverse-tunnel.md) | The data planes: Hub relay, provider reverse tunnel, why the agent only moves ciphertext, and how the local full-stack simulation mirrors production. |
| [`tee-interface.md`](tee-interface.md) | The external contract. Job spec encoding, response framing, receipt fields, evidence, and what an integrator must implement to talk to a TEE. Start here if you are not this repository. |
| [`tee-responsibility.md`](tee-responsibility.md) | Why the enclave does as little as possible: what it must own to stay trustworthy, and what belongs to the Hub. |
| [`tokenhive-relay-protocol.md`](tokenhive-relay-protocol.md) | The TEE-to-Hub relay WebSocket, written for someone implementing the Hub side. |
| [`hub-to-new-tee.md`](hub-to-new-tee.md) | The one Hub-side change a receipt that spans a certificate rotation requires. |
| [`aws-snp-deployment.md`](aws-snp-deployment.md) | The operations manual: provisioning, image build, launch, verification, teardown, and the traps found while doing it for real. |
| [`tee-timing.md`](tee-timing.md) | Stage instrumentation: what is measured, where the records live, and how to pull them without disturbing the enclave. |
| [`tee-failure-classes.md`](tee-failure-classes.md) | The unsigned failure frame. Eight classes, the stage that names them, and what the Hub is allowed to conclude from each. |
| [`cert-lifetime-audit.md`](cert-lifetime-audit.md) | Certificate lifetime audit. Three independent deadlines, the platform's reissue window, and the receipt rules that follow from them. |
| [`tee-clock-drift.md`](tee-clock-drift.md) | A guest clock that drifted out of the attestation window, how it was found, and the discipline that keeps it there. |
| [`tokhive-security-audit.md`](tokhive-security-audit.md) | Security audit of the marketplace branch: trust boundaries, findings, and what was fixed. |

`cert-lifetime-audit.md` and `tokhive-security-audit.md` were written before this
repository was split out of `reclaim-tee`. Their `tokenhive/` path prefixes and
commit hashes refer to that earlier layout and are left as written, because they
are audit records, not current instructions.

Ground truth for behaviour is the code and its tests. Where a document and the
code disagree, the code wins, and the document should be corrected in the same
change.

# Owner-v1 execution contract

The owner-v1 worker and broker V3 implement independent verification between
[accepted upload delivery](ownership-delivery-contract.md) and capsule execution.
This has [source-specific native acceptance](../evidence/20261015-owner-worker-execution/public/README.md),
not completed TM02 or owner Compose/deployment acceptance. Historical V2 receipts retain their original source
and protocol scope. The [requirements matrix](../requirements-and-gates.md) and
[ADR 004](../decisions/004-authenticated-ownership.md) retain the remaining gates.

## Authority and verification order

Consumers receive the authority's Ed25519 public pin, exact authority
store/policy scope, pipeline mode and execution-profile SHA through trusted
configuration. They verify historical `SignedAcceptance` offline; the authority's
private signing key is not supplied to upload, worker or broker. Owner identity is
the exact certificate DER SHA, not mutable job fields or a certificate CN.
The worker separately receives the pinned RSA decryption key.

Before plaintext staging, custody publication or broker submission, the worker:

1. Verifies the signed acceptance and its external pin/scope/mode/profile.
2. Matches job ID, canonical acceptance SHA, original name and original
   ciphertext hash/length. Checks the actual decoded OAEP envelope against its
   signed hash before reading ciphertext.
3. Reads one anchored, bounded ciphertext snapshot, measures the actual bytes,
   unwraps the envelope and performs AES-GCM Open with the canonical signed AAD.
   A valid new B acceptance over copied A ciphertext does not authenticate that
   ciphertext with B's different job/nonce/credential/profile AAD.
4. Stages the authenticated plaintext in the existing verified-input tmpfs and
   checks its actual SHA/length before publishing owner custody.

The authority signs original ciphertext facts. Processed plaintext/context facts
are established by the trusted worker after authenticated decryption; they are
not signed by the authority. A compromised trusted worker or host is outside this
boundary. Configuration and narrow mounts must keep signing/decryption secrets
outside upload's authority; local tests do not establish deployed isolation.

## Separate durable worker custody

[Worker configuration and commands](../../services/enclave-runner/README-owner-worker.md)
select a fresh, explicit owner custody root. Create requires a new destination;
Open requires established matching history. No legacy journal is imported.

The journal header fixes an owner domain, public pin, authority scope, profile,
mode and SHA of the complete original worker config bytes. Changing config bytes,
including whitespace, paths, polling or timeout, is not an automatic migration.
Bindings retain job ID, canonical acceptance SHA/length, credential SHA, original
upload SHA, decoded envelope SHA, original name, processed SHA/length and analysis
context. Context requires matching name/size, `decrypted` and `signature_valid`
true, and empty crypto error strings. These facts establish no execution verdict.

Layout is `instance.lock`, `journal.json` and
`acceptances/<canonical-acceptance-sha>.json`. Private directories are mode 0700;
files are current-UID regular single-link mode 0600. Anchored no-follow readers
check bounds, stable metadata and hashes. JSON rejects unknown/missing fields,
case aliases, duplicate keys, typed nulls, trailing data and excessive depth.
The signed sidecar must be canonical and match every signed binding field.

A durable `transaction.pending` precedes sidecar and journal publication. Private
exclusive temporaries, file fsync, no-clobber sidecar publication, atomic journal
replacement and directory fsync precede acknowledgement. Unknown names, orphan
sidecars, markers or replacements are preserved and refused on Open. A sticky
writer retains its raw lifetime flock through Close, lost handles and GC until
process death; there is no repair, adoption, deletion or refund API. Failure to
retire a marker durably latches the live writer; this does not promise that a
removed marker will necessarily survive a subsequent restart.

Custody allows at most 64 bindings, each acceptance at most 64 KiB, a 1 MiB journal
plus one replacement, and at most 4 MiB of retained sidecars plus one 64 KiB
publication. These are logical metadata bounds, not a host filesystem quota.
The stage is retained when custody durability is uncertain, even before Submit.

## Broker V3 and two distinct hash chains

The [owner broker](../../services/artifact-executor/README-owner-broker.md) has a
separate explicit service, socket and V3 journal. V1/V2 cannot adopt its history.
Each frame is a four-byte big-endian length plus at most 64 KiB of strict JSON.
Submit carries exactly two read-only SCM_RIGHTS descriptors, in this order:
verified plaintext, then canonical signed acceptance. The acceptance is bounded
64 KiB and travels outside the JSON frame. Status, receipt and cancel queries
carry no descriptors, require the acceptance SHA and have zero processed/context
request fields. Caller-selected commands, paths, images or policies are absent.

Broker independently verifies the acceptance FD's actual bytes, signature,
external scope, original job/upload/envelope facts and expected profile. It binds
owner facts and the worker's processed/context facts in its own journal before
execution. Peer UID authenticates the local worker channel; it is not a user TLS
identity or hardware attestation. The broker does not receive the original
ciphertext or OAEP envelope and does not decrypt them; it verifies their signed
facts and trusts the worker to establish the plaintext relationship after GCM.
A forged upload cache cannot choose an owner.

| Identity | Where it remains bound |
| --- | --- |
| Original encrypted upload SHA | Authority acceptance; worker/broker custody; Store, manifest and keeper proof input identity |
| Actual processed plaintext SHA/length | Verified stage; broker journal; capsule receipt input and analysis context |
| Canonical signed acceptance SHA | Worker and broker custody; V3 Submit, queries and response owner facts |

V3 responses supply owner scope/credential, acceptance SHA and processed/context
facts from broker history, wrapping the existing schema-2 execution response.
Worker checks these facts and compares status/receipt responses before projecting
actual receipt bytes. The shared `enclave-runner/receiptprojection` package retains
the existing strict science, detection, source-pin, artifact and release checks;
there is no second evaluator. Storage commitment alone is not scientific approval.

## Recovery and observable state

Every existing worker custody record is recovered by status/receipt queries only.
Mutable job terminal status and local result-cache existence never authorize a
new Submit. A crash between custody publication and the first Submit can therefore
remain pending; absence of a broker job is not permission to resend. A transport
error or timeout also never authorizes resubmission or charge reset.

The worker releases only a stage created and owned by that process, after verified
committed receipt projection. Close alone retains its filename. An unknown stage
left by a predecessor blocks fresh admission even if committed history can be
queried; it is not adopted or deleted. Broker/provider quiescence and uncertainty
remain subject to their own keeper/Store contracts. Cancellation does not certify
quiescence or erase plaintext.

The owner result cache is bounded local observability, not the legacy result
schema or an authoritative Results endpoint. It is never consulted to authorize
execution or release. Cache conflicts/uncertain publication fail closed. Existing
Results API/Gateway routes must not serve it as protected owner evidence. The
owner loop does not run the legacy rejection/SOC outbox automatically.

## Remaining acceptance and deployment gates

Component tests are distinct from the separately retained53-control native owner
execution and96-control independent readback. Every new acceptance must bind its full source/binary/config/input inventory and retain original logs,
journals, stages, receipts, manifests, proofs and recomputed charges. It must prove
actual AAD rebinding rejection before Stage/Reserve, positive execution and
withholding, plus separately measured response-loss and restart behavior.
Public exports contain reviewed aggregates/hashes, without private paths, raw
records, keys, certificates, inputs or per-job identifiers.

TM02 remains open for authoritative Results authorization before private bytes,
a dedicated receipt/status-only reader channel without Submit/cancel privileges,
Gateway/UI integration, integrated owner/result-substitution negatives and deployed
key/network/mount isolation. Host/root, CA, authority, worker and broker trust,
revocation/rotation and explicit migrations remain. Full physical quotas across
artifacts/results/events/caches/references, per-principal artifact accounting,
retention, queues/multiple workers, image dependency/build closure and hardware
attestation are separate gates. Active broker death, upstream ACK-write failure,
process-only plaintext retention and storage/attach/removal uncertainty still need
explicit source-specific acceptance and reconciliation without reset or adoption.

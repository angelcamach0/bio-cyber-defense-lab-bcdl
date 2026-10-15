# Trusted worker descriptor broker

This Linux broker composes the existing Store, registry, coordinator and configured
provider with a separate FD-aware Unix transport. The
[protected worker](../enclave-runner/README-worker-backend.md) now calls v2 after
actual verification, with separate native/Compose acceptance using the native
provider. The [fixed host service](README-service.md) and
[actual complete analysis](README-analysis-integration.md) now combine v2 broker,
native/Docker capsules, pipeline, evaluator and pinned analysis. Their crypto facts
are synthetic in those earlier component receipts. Persistent deployment and the
protected Docker-provider end-to-end route remain pending.

## Authority and bounded protocol

[Bridge transport](README-bridge-transport.md) authenticates a configured local UID,
receives one bounded strict request and rejects paths, commands, images, rules,
mounts, policies and keeper proofs. The host supplies a fixed provider and profile
SHA identifier. A request can check that identifier, never select a free-form
profile. This is trusted host/shared-UID provenance, not tenant identity or
cryptographic proof that the caller verified an upload. The installed worker must
call submit only after integrity, signature, key unwrap and GCM authentication.

All request fields are required: schema_version, operation, job_id, upload_sha256,
expected_profile_sha256, processed_sha256, processed_bytes and original_name.
Submit carries the processed fields/name and exactly one read-only input FD;
status/cancel/receipt require them empty/zero and carry no input FD. Original name
is private bounded context for detection, not a filesystem name to open. Frames
are64KiB, plaintext25MiB and retained receipt16MiB, within the64MiB Store export
budget. Input metadata must be regular0600, current UID, single-link, read-only
and exact size/hash. Broker duplicates/rechecks it before durable intent; registry
and provider independently check it again. A named private tmpfs input must remain
linked through provider use; unlink immediately after transfer breaks this policy.

Only receipt returns a descriptor: the private execution_receipt whose actual
bytes/hash match the committed manifest. The broker revalidates proof, manifest,
exports and Store health under Store's lock; the client checks received size/hash
before returning ownership to its caller. No arbitrary artifact name/path is
accepted. Missing receipts from genuine empty failed commits remain unavailable;
the committed failed/withheld manifest is still visible through status.

## Explicit analysis protocol v2

`NewBrokerV2` selects a separate journal schema and must be paired with
`ListenBridgeUnixV2` and `CallBridgeUnixV2`. There is no automatic negotiation,
fallback or adoption of a v1 journal, including an empty v1 journal. V1 constructors,
request shape and journal serialization remain separate and unchanged.

`BridgeRequestV2` adds the required `analysis_context` object with all six fields:
`original_name`, `processed_size_bytes`, `decrypted`, `decryption_error`,
`signature_valid` and `signature_error`. Submit's name and processed size must
match the outer request. Queries carry a complete zero-valued context. These are
bounded facts asserted by the trusted caller, not evidence of cryptographic
verification. They cannot select commands, reference assets or configuration.

V2 journals include `analysis_contexts` with exactly the same keys as `records`.
Each context must match its binding's name and size. Intent and context are
published together before Reserve, and `BindWithAnalysis` copies the same value
into the one-shot input registry after durable lease linkage. Exact duplicates
reuse custody; changing any context value conflicts, including in the ACK gate.
Version and fixed profile checks also apply to status/cancel/receipt. Recovery
requires that exact v2 history; no missing context is invented from a baseline.

V2 uses the same FD constraints, receipt validation, locks and causal commit/ACK
barriers as v1. Responses and error envelopes use schema version2 on its listener.
The new source requires its own validation; the earlier receipts below retain
only their recorded pre-v2 scope.

## Durable binding and acknowledgement

The broker's separate private journal records job/upload/processed digest and size,
original name, fixed profile/store/policy identity, lease, stage and committed
manifest/receipt hashes. A lifetime flock excludes another broker. Its directory
cannot overlap Store in either direction. Unknown files, temporary remnants,
changed policy/profile, unsafe metadata, nonempty locks, a missing journal with
existing Store records, or inconsistent history are refused without deletion.

The journal is at most1MiB with at most the Store's configured job count (<=64),
plus one atomic replacement of at most1MiB. This additional bounded metadata is
outside Store's logical1GiB managed-artifact charge; it is not a physical host
quota or a claim that every spool is accounted inside that charge. A failed
publication latches admission and preserves any remaining temporary file; startup does not
clean it away to invent an accepted baseline. No TTL, refunds or eviction exist.

The actual sequence is:

```text
verified input FD
  -> journal intent fsync
  -> Store Reserve
  -> journal linked lease fsync
  -> registry Bind
  -> coordinator Begin / configured provider
  -> real provider Wait / export fence / Prepare / Proof / Commit
  -> journal committed fsync
  -> actual bounded socket ACK
  -> later worker result publication (not yet integrated)
```

An identical duplicate consults the existing binding and never calls Reserve or
provider again. A changed upload/processed hash, size, name or profile conflicts.
Only one new submit can be active. Status/cancel remain available for that exact
job/upload tuple; cancel requests termination without proof or quota release.
Before the journal is sealed, a committed Store cannot be advertised/ACKed as a
committed bridge result. Broker and Store locks cover the predicates and actual
write together, including a concurrent Store commit. The shared internal Store
ACK helper retains the existing durable gate, fault injection and sticky failure
semantics. A pending-journal rejection occurs before that helper, so a benign
status race does not latch an otherwise healthy committed Store.

Lost actual ACK keeps the charge and latches Store; live readback cannot bypass
that health latch. After an explicit keeper restart, fully validated committed
Store history and its prior durable linked/committed binding can serve the same
result. A preexisting linked binding may be sealed from that exact verified commit
without tools, Reserve, proof invention or Store ledger changes. Intent-only,
reserved/executing/prepared or otherwise ambiguous history never becomes a retry.
The ACK proves executor custody, not that the worker durably wrote its result.

Close requests cancellation and prevents new handlers. Wait must observe the
active handler and provider return before journal lock release. Unhealthy or
uncertain completion keeps that lock and Store/flock custody; callers must not
close them merely because a deadline elapsed. Only the fake-provider tests directly
close raw fixture handles to simulate process termination; that is not an operator
recovery API.

## Executed checks and limits

Nine broker test functions plus subcases cover duplicate/conflict identity,
actual receipt bytes, real Unix submit/receipt, commit before response, lost ACK
and committed-only restart, injected intent/Reserve/link/Bind/Commit crash gaps,
journal write/fsync/rename/directory-fsync failures, unknown history and unsafe
FD/profile rejection. Two causal barrier tests cover Store commit before journal
seal and a commit racing the ACK lock acquisition. Readback is never a new run.

After the final ACK lock correction, the complete artifact-module suite passed
with the race detector and all six native/Docker opt-ins enabled:90top-level
functions plus subcases,23.847s, zero failures. Two internal keeper entry functions
skip in the parent and execute in their spawned subprocesses. The synthetic real
native/Docker provider tests in that suite retain their own scope; the new broker
tests use fake providers and do not combine bridge+worker crypto+real provider.
The journal/ACK corrections and transport received independent review. Earlier
narrow broker eight-test runs predate the final ACK fix and ninth barrier test.

Fresh make test on the final source passed252Python cases (250passed/two helper
kernel skips) and test/vet in all eight Go modules. The enclave-runner module also
contains the new analysis package/CLI tests:15functions and36subcases passed in
ordinary and race runs, with vet. Source changes after these checks were docs only.

The analysis executable was subsequently built twice on ARM64 with separate empty
Go caches and fixed build flags; both3,565,542-byte outputs are byte-identical,
SHA256 cb95d52dcf6c601039a4f801fd4b1ca02fa16a8c89b7a87706ffbc553fd1edf6.
The compiled CLI ran actual minimap2 2.31-r1302 against the public synthetic fixture:
1,171mapped/1,171SAM records, one target and expected configured score0.9/high.
Crypto facts were synthetic caller context. This is standalone analysis, without
broker, capsule or protected entry. Target names and raw output remain private.
Independent readback verified source/build/binary/result bindings without rerunning.
This demonstrates repeatability in one toolchain/host, not cross-host or OCI builds.
See [analysis scope](../enclave-runner/analysis/README.md) and
[CLI scope](../enclave-runner/cmd/capsule-analysis/README.md).

No model was rerun, dataset downloaded or image built/pulled for these checks.
Existing native/container crash histories and quota receipts remain preserved.
Bridge/analysis source was published at0dd7384 in
[PR22](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/pull/22).
Its CI38660550112 passed unit/PKI and scientific repeat, then failed before
protected-service startup because a recursive build selected multiple packages
for one output. The harness now selects each service executable explicitly and
fresh local protected acceptance passed78assertions. The corrected publication
needs its own CI; the earlier successful bba2637 CI covers its own snapshot only.

Next integration must carry per-job analysis context into both providers, pin the
analysis executable/rules/panel, run evaluation and optional alignment inside the
same capsule budget, and project only validated retained receipts into worker
results. Native plaintext needs a verified private tmpfs; Compose must retain
caps-zero, no network and no worker Docker socket/Store mount. Fresh protected
native/Compose authorization/crypto/science/cancel/restart tests must follow.
Full ownership TM02, principal quotas, operator reconciliation, retention,
image reproducibility, queue/leases, SOC/cloud and delivery gates remain open.

## Analysis protocol v2 checks

The new v2 broker/context tests passed10top-level functions and their subcases
with ordinary execution (0.988s) and the race detector (2.564s); `go vet ./...`
exited0. They use real private Store/journal files and Unix FD sockets with
synthetic providers. They cover fixed v2/error envelopes, complete strict context,
registry propagation, changed-context/profile conflicts, duplicate custody,
lost-ACK committed-only restart, missing/mismatched context history, bilateral
version refusal, durable context before Reserve, storage/crash gaps and both
causal journal/Store ACK barriers. No kernel provider, worker crypto or scientific
pipeline is exercised by this narrow command.

An initial run failed three crash-test subcases because its fixture attempted to
create a registry from correctly unavailable pending Store history. The fixture
now asserts that refusal and unchanged ledger/journal bytes. The failed log is
preserved alongside the corrected ordinary/race/vet logs under the private
`.biozero/bridge-v2-checks-20261015T005815.199358Z/` evidence root. No production
guard was weakened. The earlier v1 receipts above remain scoped to their source.

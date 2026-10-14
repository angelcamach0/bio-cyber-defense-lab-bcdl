# Scoped inputs and trusted coordinator

Status: standalone Linux implementation, independently reviewed by Vale. Local
test/vet passed; the complete module race suite passed with the native opt-in
enabled (64 top-level test functions with subcases, 4.847 seconds). Registry and
coordinator unit providers are synthetic; the separate native test executed a
real three-SNP pipeline, evaluation and storage commitment. See
[native acceptance and limits](README-native.md). Worker integration and complete
installed-worker lifecycle acceptance remain pending. Subsequent standalone
[recovery](README-native-recovery.md) and [Unix composition](README-native-unix.md)
tests extend this earlier checkpoint without changing runtime.

`NewInputRegistry(store)` and `NewCoordinator(store, registry, provider)` configure
the host-side objects. A nil provider fails visibly. An RPC client cannot choose a
provider, command, image, mode, environment, path, mount, resource policy or proof.
`Coordinator` implements the narrow handler and actual ACK interfaces used by
the [Unix listener](README-server.md). The native namespace provider is implemented
and has module-level kernel acceptance. A container capsule provider and installed
worker acceptance remain required.

## Protected entry and input references

The worker must finish its existing upload hash, signature and authenticated
decryption checks before calling local `RegisterInput`. Original-upload SHA and
the verified processed/plaintext SHA remain separate. RegisterInput durably
reserves the Store lease before registering a read-only input FD. Registration
is a trusted local API and is absent from run/status/cancel RPC.

The registry accepts only regular, private0600, same-UID, single-link read-only
descriptors, at most25MiB, with exact observed size and plaintext digest. It makes
an atomic close-on-exec duplicate inside `File.SyscallConn.Control`, so concurrent
caller Close cannot substitute a reused descriptor. Caller cursor and subsequent
closure do not affect the registry's `ReadAt` copy. The input reference is random,
opaque, bound to its exact lease and acquired once. Duplicate registrations,
cross-lease references and replay do not confer authority.

After hashing, registration rechecks context, current Store availability and the
original reserved lease under publication locks. Registry -> Store is the only
nested lock order. A concurrent Store close/latch/state transition cannot publish
an input reference first. The trusted provider copies through `ScopedInput.CopyTo`
into its already bounded workspace and verifies exact size/hash again. A changed
host source fails that copy; its partial destination is not an approved input.
Same-UID/privileged host writers remain trusted. Read-only FDs and digest checks
do not establish an immutable host filesystem or a principal's authorization.

The registry retains at most the configured job limit in reference metadata; FDs
transfer to the provider at acquisition and close after its return. Closing a
reference or registry never releases a reserved/retained slot or byte charge.
Lost registry memory cannot replay pending work: durable Store history fails closed
on restart. Failed new registration retains its reservation and latches admission;
there is no silent compensation, deletion, quota refund or pending-job retry.

## Execution, commitment and channel acknowledgement

The coordinator admits one active provider call. It checks the exact reference
pair, fences one-time acquisition and obtains durable Begin before any provider
tool/workspace creation. Status/cancel operate only on their opaque lease; cancel
means a request was delivered, not proof that the capsule stopped. A second active
run is denied before consuming its reference.

`Provider.Execute(ctx, input, exporter)` is trusted keeper code. Its completion
contains an explicit scientific/execution Outcome and a Quiescent observation.
Only a provider which actually waited for kernel capsule termination may set
Quiescent; an exit code, PID, timeout, marker or channel closure is insufficient.
No provider is currently installed in the worker, and synthetic test completions
are not kernel evidence. Panic or unproven quiescence retains executing history/reservation and
latches the Store. No success frame, proof or new admission follows uncertainty.

The lease-scoped Exporter exposes only configured artifact IDs and verified
streams. Closure waits for current callbacks and fences future calls. After
trusted provider wait and export closure, the coordinator calls Prepare, constructs
the local store/policy/lease/job/input/manifest-bound proof, records quiescence and
commits storage. A provider failure or cancellation cannot retain evaluated_passed.
The Store independently enforces observed=evaluated=retained normalized VCF for a
passed release. The native provider retains bounded pipeline/evaluation JSON as
its private execution_receipt artifact. Other providers must supply their own
verdict custody; the coordinator does not infer science from digests.

Responses contain a bounded manifest and state, not arbitrary host paths or raw
execution output. A committed response is revalidated against its private manifest
hash and strict schema. UnixServer passes the actual bounded WriteFrame callback
to Coordinator.Acknowledge. Committed replies use Store.Acknowledge; write failure
retains custody/charge and latches availability. Nonterminal status replies also
recheck Store health and unchanged state under its lock before their bounded
callback; a snapshot cannot outlive a concurrent latch. A successful kernel write
does not prove the peer received the ACK. Cancelled channels receive no release ACK.

Close cancels active work without closing Store or claiming capsule death. Owners
must Close, then Wait for the provider call/storage handling, before considering
lifetime-flock shutdown. Wait timeout is a verified pending call, not quiescence;
even a returned call with unproven completion leaves sticky pending Store history.
The owner must preserve the keeper/journal boundary and never treat Wait alone as
a safe recovery or permission to clear the old lease.

## Executed tests and remaining integration

Executed registry/coordinator tests cover independent ciphertext/plaintext hashes,
unsafe/writable/closed FDs, hash/size changes, cross-lease/replay, retained quotas,
commit-before-ACK, lost/cancelled ACK, unknown input reference, provider uncertainty
and panic, cancel-before-wait, late export fencing and status-after-latch. Their
providers are explicitly synthetic local test implementations. Native acceptance
is a separate test; it does not repeat the protected TLS/signature/decryption entry.

Native provider death/restart ordering has separate lifecycle-fixture acceptance.
Next gates are container execution with physical tmpfs and authoritative wait,
worker integration, and fresh protected
native/Compose success/failure acceptance. Native source/tool/evaluator bindings
and private verdict custody have module acceptance, not installed-worker approval.
Per-principal artifacts still depend on TM02 immutable ownership. Other result,
event, cache, registry, queue and retention budgets remain separate tasks. No
production quota, external attestation, effective SOC or biological accuracy claim
follows from this standalone composition layer.

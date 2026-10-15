# Artifact executor core (TM01 phase B, standalone)

This standalone module implements durable storage/framing, a Unix listener/client,
a scoped-input registry/coordinator, a native namespace provider and an explicitly
configured host Docker provider. The [host service command](README-service.md)
has compiled native/Docker acceptance, without a persistent production deployment.
It is not installed in the protected worker. Separate module acceptance ran the synthetic
three-SNP pipeline and evaluator, without running a trained model. See
[native evidence](README-native.md), [Docker evidence](README-container.md),
[coordinator ordering](README-coordinator.md), [Unix channel](README-server.md)
and [the contract](../../docs/security/artifact-workspace-contract.md).

A new standalone [worker FD broker](README-broker.md) adds a separate strict
submit/status/cancel/receipt protocol and durable job-to-lease binding. Separate v2
persists verified-caller context for pinned capsule analysis; v1 remains unchanged.
[Combined acceptance](README-analysis-integration.md) now covers broker plus actual
providers/analysis and the compiled service. Protected-worker integration remains
required; earlier receipts retain their original separate scope.

`Open(ctx, root, policy)` requires Linux, private root mode0700, files0600 owned by
the effective UID, descriptor-anchored no-follow traversal and same-filesystem
hard-link/rename publication within each managed directory. A lifetime flock
excludes a second instance. The lock must have size zero before flock or baseline
creation; nonempty historical locks are rejected without truncation. All configuration is supplied by the trusted caller;
RPC requests cannot change it. Default policy retains up to64 jobs and charges up
to1GiB, reserving64MiB export plus128KiB headroom before work. A fixed4KiB reserve
covers both ledger headers; committed charge includes actual exported/manifest/
proof bytes and twice each serialized ledger record/key for atomic replacement.
This is logical managed-byte accounting, not a physical host/filesystem quota.

Reserve -> Begin -> Export -> Prepare -> RecordQuiescence -> Commit -> Acknowledge
is the API ordering. Prepare takes an explicit Outcome: execution status, release status, stable error
code and observed/evaluated digests. Storage commitment does not infer scientific
approval. Failed/incomplete outcomes cannot be evaluated_passed; that verdict
requires succeeded execution and observed=evaluated=retained normalized VCF. Empty
failed/withheld or succeeded/unassessed manifests can commit metadata and their
retained slot after quiescence, permitting the next job within remaining quota.
No release acknowledgement occurs before trusted keeper proof
and durable storage commit. Existing artifacts are never overwritten or evicted.
Pending restart blocks new work even when a quiescence proof exists. This first
layer deliberately offers no automatic crash-recovery admission or quota release.
Changed policy fails startup; adopting/reducing policy needs a separate reviewed
migration. Committed history is revalidated without executing tools.

Bounded typed JSON rejects duplicate fields, aliases, missing fields, null typed
values, trailing input, unknown fields and depth greater than64. Ledger is at most
1MiB, manifest32KiB, proof16KiB, directory scans at most129 entries before rejecting
oversized cardinality. Symlinks, FIFOs, additional links, sparse oversized files,
wrong owners/modes and unaccounted history fail closed. Writes use private temporary
files, file fsync, same-directory no-clobber link or ledger rename, and directory
fsync. Ambiguity preserves files/reservations and latches unavailable. Failed commit
persistence restores the prepared record and full prior charge in memory; no
acknowledgement can advertise a committed state while that latch is set.

Framing is a four-byte big-endian length followed by at most64KiB of strict request
JSON. Only run/status/cancel, opaque lease and configured input-ref IDs are accepted;
paths, commands, image names, mounts, policies and keeper proofs are not request
fields. The Unix listener implements peer-UID authentication, bounded connections,
request/write/run deadlines and cancellation on channel closure. The local registry
binds a separately verified plaintext FD to its reserved lease. ReceiveInput bounds
a generic plaintext transfer to25MiB and compares exact length/hash; it opens no
paths. Generic Reader cancellation cannot interrupt a blocked read; callers need
a separately supervised transport. Worker integration remains pending.

Trusted keeper proof is a local API, not authenticated by this library itself.
The provider/orchestrator must establish actual capsule completion, close export
authority and bind the proof to store/policy/lease/job/input/manifest. Kernel
workspace bounds, keeper death/namespace fencing and scientific verdicts are not
inferred from these unit tests. Per-principal artifact quotas await immutable
identity binding. No deletion/TTL/retention migration is implemented.

Validation: `go test ./...`, `go vet ./...`, `go test -race ./...` from this module.
Default tests use new private fixtures and inject durable publication/ack failures;
they do not edit previous evidence or run a trained model. The native kernel opt-in
separately executes the synthetic variant pipeline; its prerequisites and scope
are documented in README-native.md. Docker opt-ins separately cover the real Unix
composition, aggregate byte/inode exhaustion and cancel/timeout/keeper death; see
[quota scope](README-container-quota.md) and
[recovery scope](README-container-recovery.md). They require the exact cached image
and compatible local kernel/daemon. Image build reproducibility and protected
worker integration remain pending; default/hosted tests skip kernel opt-ins.

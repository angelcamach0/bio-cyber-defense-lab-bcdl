# Durable verified-input facts in the protected worker

`worker_custody_linux.go` keeps a separate private journal before the worker's
first broker Submit. It does not extend the upload/job/admission/result schemas,
reserve executor bytes, run tools or record proof that Submit occurred. The caller
still verifies integrity, signature, key unwrap and authenticated decryption,
computes the immutable job-metadata fingerprint, stages the exact processed bytes
and supplies these facts. Facts asserted by a trusted local worker are not
cryptographic proof, scientific approval or authenticated tenant ownership.

The API is:

```go
custody, err := NewWorkerCustody(ctx, absoluteRoot, expectedProfileSHA256, mode)
err = custody.PutVerified(ctx, binding) // must succeed before the first Submit
binding, found, err := custody.Lookup(jobID)
bindings, err := custody.Bindings() // sorted value copies for restart fencing
err = custody.Close()
```

Each `WorkerCustodyBinding` has job_id(16lowercase hex), job_fingerprint,
upload_sha256, processed_sha256, processed_bytes and the SDK's six-field
analysis_context value. SHA256 identifiers are64lowercase hex. Processed bytes
are0..25MiB and must equal the context size. Name/error strings preserve the SDK's
UTF8 and byte bounds and reject contradictory success/error facts. These values
contain no executable/configuration paths, commands, unwrapped keys or payload.
The caller must compare the stored immutable-metadata fingerprint before using
facts recovered for a job. Upload and processed-input hashes remain distinct.

The exact journal schema is schema_version1, profile_sha256, pipeline_mode and
records. Profile and stats/variants mode are fixed at construction. Every field
and nested context field is required; unknown, missing, duplicate, alias and null
fields, invalid UTF8/types and excess depth are rejected by a parser scoped only
to this journal. Existing metadata parsers and the SDK protocol are unchanged.

Root metadata is current-UID0700. Files are current-UID, regular0600 and single
link; every ancestor and final file is opened without following symlinks. A
lifetime nonblocking exclusive flock prevents a second cooperating writer. The
root/lock use raw CLOEXEC descriptors, with no Go finalizer capable of silently
releasing sticky custody. Live operations also check lock inode identity, layout,
private metadata and the exact previously accepted journal SHA256. Same-UID and
privileged host writers remain trusted; this is not a signed ledger or host
attestation.

Only a lock created exclusively by this constructor in an otherwise empty root
can initialize a journal. An existing lock without journal is ambiguous bootstrap
history and is refused. Missing locks beside existing files, unknown files,
interrupted temporary files, unsafe metadata, changed profile/mode and malformed
history are never deleted, adopted, migrated or turned into an empty baseline.
A constructor error can return a non-nil sticky handle; its raw authority remains
held until process exit even if that handle becomes unreachable.

PutVerified serializes a candidate before creating its temporary replacement,
then writes/fsyncs it, atomically publishes it and fsyncs the directory before
returning success. Identical bindings are idempotent; changing any retained fact
conflicts. There are at most64retained records and an actual serialized1MiB
journal cap, plus one at-most1MiB replacement. Escaping can reach the byte cap
before64records; the candidate is rejected without a temporary file or eviction.
This is additional bounded worker metadata, outside both upload admission and
the executor's logical artifact-byte accounting. It does not establish a physical
quota for every spool, principal, event or result.

Persistence/history uncertainty latches the instance. Lookup, Bindings, further
PutVerified calls and Close cannot bypass that latch or release its raw lock.
Failed publication retains its remaining temporary evidence. An explicit process
restart may read only structurally complete, exact private journal history;
publication before a failed final directory-sync acknowledgement can preserve
new facts on disk. Those facts establish neither a successful prior Submit nor
permission to repeat it. No API refunds or removes a record, including after
failed execution or a lost result/ACK.

At restart, the caller fences every Bindings entry by broker status/receipt before
admitting new plaintext. A generic/unavailable RPC is not proof that the job was
never submitted. A running job with no binding must never be resubmitted. An
existing binding supplies the immutable facts needed to reconcile an actual
committed result, including a genuine failed commit with no retained receipt;
it does not invent an executor lease, receipt or scientific result. Pending state
can be resolved in memory by verified readback while the journal/slots remain
retained. The integration implementing these rules needs its own acceptance.

New unit tests exercise actual private journal files and flock lifetime with
synthetic input facts only: durable restart, duplicates/conflicts, sorted copies,
64record/serialized-byte caps, schema/metadata/header failures, publication and
bootstrap gaps, unknown temporary history, live mutations and raw locks across
GC. No protected cryptography, broker request, provider, namespace, Docker, model,
external network or complete worker acceptance is established by these tests.
Execution results and exact source evidence must be recorded separately.

The dedicated custody run passed9top-level functions and60subcases in ordinary
and race execution, with no failures/skips; `go vet .` exited0. Exact live source
pins, JSON event logs and the summary are private under
`.biozero/worker-custody-checks-20261015T014350.319180Z/`. These tests exercise only
this journal and synthetic facts. They do not establish that a protected worker
caller persists facts before Submit or handles an unavailable broker correctly;
that caller needs independent review and integrated acceptance.

Independent source review identified an ancestor-directory durability gap after
that first snapshot: syncing a parent only when its child was newly created could
skip a previously failed sync when the child already existed on retry. The walker
now synchronizes every opened child's parent, including existing entries. A new
causal fault test creates the root and fails its parent sync, repeats the failure
against that existing root, and requires both attempts to stop before lock/journal
creation. Only an explicit later attempt with healthy sync may initialize it.
The earlier9-function receipt remains scoped to its pre-correction source; this
change needs its own ordinary/race result before the final source is approved.

The corrected parent-sync source subsequently passed10top-level functions and
60subcases in ordinary1.022s and race4.442s, with zero failures/skips; vet exited0.
Before/after source pins matched for the runtime, tests and module definition.
Private evidence: `.biozero/worker-custody-parent-sync-20261015T015440.970327Z/`.
Independent source review confirmed the retry-existing parent sync and its causal
test. This supersedes the earlier snapshot only for the corrected custody source;
it still does not claim protected-worker or actual-provider integration.

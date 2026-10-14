# Job and result metadata boundary

Date: 2026-10-14. Contract owners: Chiquis, Atlas and Vale. QA: Lía; independent
security review is separate from implementation. Native acceptance receipt
`../evidence/20261014T175423-175221Z/public/` passed 53 checks; the rebuilt
four-service receipt `../evidence/20261014T175423-180461Z-reviewer-compose/public/`
passed 30 checks. Historical receipts retain their original scope.

This contract addresses TM-03's spooled job/result JSON reads, including worker
recovery and security-event reconciliation. It does not authenticate ownership
metadata or the host, create disk quotas, establish a queue/lease, or harden all
payload, certificate, key, reference, configuration and artifact reads.

## Filesystem reader

Jobs are at most 65,536 bytes; results at most 16,777,216 bytes. Open each directory
ancestor with descriptor-relative `openat`, `O_DIRECTORY` and `O_NOFOLLOW`; open
the final file with `O_RDONLY`, `O_NOFOLLOW` and `O_NONBLOCK`. Validate the open
descriptor with `fstat`: regular file, invoking effective UID, exact mode 0600
(no setuid/setgid/sticky bits), and size at or below its cap. Read no more than
cap+1 bytes, so a file growing after the size check cannot bypass the limit.

The reader must not use `Lstat` followed by an unrestricted path open. Directory
descriptors anchor traversal; final descriptors anchor reads even if the pathname
is subsequently renamed. Reject symlinks in any ancestor/final entry, FIFOs,
devices, directories, shared/foreign-owned files and oversized files. Close all
descriptors on every success/failure path. Linux syscalls and filesystem behavior
are part of this local runtime contract; `O_NONBLOCK` does not promise bounded
kernel IO latency for every regular file or remote filesystem.

Preserve genuine `ENOENT` as absence. Other IO/type/permission errors must not
become pending status or missing-file fallback. Logs and public errors use stable
codes without raw file content or local paths.

Upload admission must project the exact indented JSON with the longest current
status (`incomplete`), a 20-byte UTC start timestamp, and worst-case escaped
diagnostic copies of 64 and 512 decoded bytes. Each NUL requires six JSON bytes.
Reject a projection larger than 65,536 bytes before publishing the actual job;
serialize and persist the submitted immutable fields without truncation. Return
413 `metadata_too_large` and remove only that request's uncommitted payload.
Cleanup before publication differs from an ambiguous write/fsync failure after
a job may already be visible: retain the payload in that case. Key wrapping,
JSON escaping and lifecycle growth all count toward the admission budget.

Every worker job write (running, recovery and terminal) uses the same bounded
writer. Only its diagnostic copies are limited, at valid UTF-8 boundaries after
normalizing invalid UTF-8; the full result diagnostics remain intact. Check the
final serialized size before atomic publication. Original hashes, sizes,
signatures, encryption metadata and certificate ownership are preserved. Legacy
jobs admitted without this reserve fail closed if an updated record cannot fit;
they must not be overwritten with unreadable JSON. A future change to mutable
fields requires updating and retesting this producer/worker budget together.

## JSON contract and compatibility

Maximum nesting depth is 64. Reject duplicate exact keys anywhere, extra trailing
JSON, incorrect-case aliases of known structured fields, and unknown top-level
job/result fields. Known typed scalar/object fields reject null and incorrect
types. Optional pipeline/evaluation JSON and detection signal maps retain their
values, including valid internal nulls; scientific outputs are not silently
reclassified or normalized by the metadata reader.

A job requires an exact `job_id` string (8–64 lowercase hex characters) and known
`status`. Other currently defined upload/worker fields are recognized and checked
when present. Ownership authorization remains a separate check using the verified
client certificate CN/serial; absence of a binding cannot grant access.

A current result requires integer `schema_version: 1` and every non-optional field
that the worker already always writes:

`schema_version`, `security_mode`, `pipeline_mode`, `job_id`, `status`,
`processed_at`, `upload_sha256`, `processed_sha256`, `size_bytes`, `decrypted`,
`signature_valid`, `release_status`, `detection`.

Detection requires its typed `score` and `reason`; its other declared fields are
optional. Job ID must match the requested/scanned filename and result status must
be terminal. Presence and type checks are not proof of scientific acceptance;
empty hashes/time/mode strings and false crypto flags can legitimately occur in
failed records. Crypto and independent scientific release gates retain their
existing semantics.

Historical `processed` may omit `schema_version`; it still requires job ID/status
and recognized, typed fields. Both this legacy form and schema-1 `processed` are
served as `incomplete` with `legacy_result_unverified`, never promoted to success.
Missing versions for other result states, explicit unknown versions, incomplete
schema-1 envelopes and ambiguous records are invalid. Minimal test fixtures must
represent this contract rather than keep accepting unsupported success envelopes.

## Lifecycle and authorization

Results API validates job metadata and authorizes the caller before opening a
result file. A valid non-owner receives 403 even if the corresponding result is a
FIFO, link or corrupt file. A missing job is 404. Unsafe job/result IO yields a
stable 500 read error; invalid metadata yields a stable 500 record error. Only a
genuinely absent result can use the existing pending/terminal-job fallback.

The worker skips unsafe/invalid metadata and continues other jobs. A corrupt or
unsafe existing result cannot trigger pipeline reexecution or be overwritten as
if it were absent. Recovery and SOC reconciliation use the same bounded parser;
there is no alternate permissive `json.Unmarshal` path. Cancellation is checked
between bounded reads and jobs. File rejection does not alter scientific release,
delete original records or fabricate a security-response acknowledgment.

Cancellation checks here apply to the worker. The Results API bounds its reads
but does not provide request-context cancellation of arbitrary regular-file IO.
Transport timeouts in the fault acceptance prove prompt local responses for
those fixtures, not a general kernel or remote-filesystem deadline.

## Acceptance and remaining gates

Meaningful unit/process/HTTPS cases cover final and ancestor symlinks, FIFO,
sparse oversized files, modes/UID, duplicate owner/status keys, trailing/deep JSON,
incomplete/unknown result schemas, legacy processed behavior, non-owner denial,
continued API health and actual new worker progress while faults remain present.
Temporary faults live only in fresh private synthetic test runtimes and are
removed only if their original inode/device still match. Public evidence contains
fixed case names, outcomes/status codes and provenance, not raw responses, owner
metadata, certificates, IDs, paths or sentinel contents.

TM-01 global admission/storage budgets and TM-02 authenticated immutable owner
provenance remain separate adopted work. The shared host/UID is still trusted.
These changes do not make every worker file read immune to blocking or tampering.

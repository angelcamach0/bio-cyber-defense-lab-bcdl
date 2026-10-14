# Upload API

`POST /upload` admits one retained input for the worker. Protected mode requires
mTLS with a verified, valid certificate CN. The optional `client_id` form field
must match that CN; headers and IP addresses never supply a quota identity.
`GET /health` returns 503 when admission recovery or persistence is ambiguous.

The streaming multipart accepts one `file` and optional `client_id`, `enc_alg`,
`enc_key`, `sig_alg`, `sig`: no repeated or unknown parts, at most seven parts,
and at most 65,536 aggregate field bytes. The wire body is bounded even when
chunked. Rejection stops reading the part rather than draining an arbitrary
remainder. The actual server has a 30-second body/read deadline, a 5-second header
deadline, and a 15-second write deadline. A lost acknowledgement retains its
charge. The standard library still permits up to 10 MiB of MIME headers within
the wire cap; this is not a 64 KiB total multipart-memory guarantee.

## Durable admission and retained-input accounting

Before reading the body, admission persists a reservation of one job and the
maximum wire-body bytes plus 131,072 bytes of metadata/atomic-update headroom.
The same verified CN shares its quota across certificate serial renewal. Serial
numbers remain recorded for audit and existing result authorization. Explicit
`demo` mode uses one global quota namespace and does not establish identity.

The private `<BIOZERO_DATA_DIR>/admission` directory is 0700, its ledger and files
are 0600, and its process-lifetime exclusive lock admits one uploader instance.
Linux regular files, directory fsync, `/proc/self/fd`, same-mount hardlinks,
and reliable local flock semantics are required. Reads and path traversal use
anchored descriptors, no-follow opens, bounded JSON and exact schema fields.
The ledger/lock stay inside this directory. Payload staging is
`uploads/.biozero-admission-staging/<job_id>/payload.part`; job staging is
`jobs/.biozero-admission-staging/<job_id>/job.part`. Both stage bases and per-job
directories are owned by the process UID with mode 0700; files are 0600. Multipart
does not create external temp files. Each publication stays within its destination
mount, since hardlinks across separate bind mounts can fail despite equal device
numbers. Both stage bases are empty after successful or unambiguous rejected
uploads. Unknown directory names are never ignored. Legacy `admission/staging`
layouts refuse startup without deletion or automatic adoption. Publication refuses existing payload/job names. A prepared ledger is
synced before publication; payload, job, cleanup and committed ledger are durable
before acknowledgement. The acknowledgement and ambiguity latch share a mutex.

A committed input costs its retained payload bytes plus the same headroom; it
keeps its job slot and charge after worker completion. Quota never depends on
mutable job status, client form fields, gateway registries or delivery of HTTP
200. Counts are recomputed from the durable ledger under the admission lock,
not reconstructed from mutable jobs or an in-memory counter.

On restart, only definitively unpublished reservations with matching recorded
file identities may have their own staging removed and charges released. Cleanup
validates both payload and job stages before deleting either. A missing ledger
with nonempty staging in either destination also refuses startup. A fully
published prepared input can recover to committed after immutable-job and payload
hash checks. Partial publication, unknown inode/files, unsafe metadata, missing
committed history or failed persistence remains charged and makes health/admission
unavailable. Unknown staging or ledger temporary files are preserved for review.
No existing history is deleted. A missing ledger with nonempty jobs/uploads
refuses startup and requires an explicit future operator migration.

The ledger pins the entire initial policy. **Policy changes, including lower
limits, currently refuse startup** without modifying/resetting charges. Policy
adoption and retention/reclamation are separate future work. Free space is a
sensor: admission subtracts all pending reservations conservatively from available
space before checking the floor; it can double-count already materialized staging.
Other writers and later worker growth can change available disk space. These are
quotas for retained inputs/reservations, not a hard quota for the host filesystem,
worker artifacts, results, outbox or every temporary metadata copy. Full storage,
production operations and disk retention remain separate gates. Ordinary regular
filesystem I/O can still stall despite descriptor-safe metadata reads.

## Configuration

Unset values use defaults; malformed, empty, nonpositive, overflowing or internally
inconsistent admission values fail startup rather than silently falling back.

| Environment variable | Default |
| --- | ---: |
| `BIOZERO_ADMISSION_GLOBAL_JOBS` | 64 |
| `BIOZERO_ADMISSION_PRINCIPAL_JOBS` | 16 |
| `BIOZERO_ADMISSION_GLOBAL_BYTES` | 536870912 |
| `BIOZERO_ADMISSION_PRINCIPAL_BYTES` | 134217728 |
| `BIOZERO_ADMISSION_ACTIVE_UPLOADS` | 2 |
| `BIOZERO_ADMISSION_PRINCIPAL_ACTIVE_UPLOADS` | 1 |
| `BIOZERO_MAX_UPLOAD_BYTES` | 26214400 |
| `BIOZERO_ADMISSION_FREE_SPACE_FLOOR` | 134217728 |

The principal byte budget must accommodate one maximum reservation; principal
limits cannot exceed global limits. `BIOZERO_RATE_LIMIT` defaults to 60 requests
per minute and remains an independent best-effort in-memory limiter keyed by the
verified CN. It does not supply persistent admission authority.

Other settings: `BIOZERO_UPLOAD_ADDR` (`:8081`), `BIOZERO_DATA_DIR` (`./data`),
`BIOZERO_SECURITY_MODE` (`protected`), `BIOZERO_TLS_CERT`, `BIOZERO_TLS_KEY`,
`BIOZERO_TLS_CA`. Protected TLS requires all three credentials. Optional
`BIOZERO_JOB_KEY` is a 32-byte base64/hex key wrapping `enc_key` at rest; worker
configuration must match. No crypto fields, uploaded hash or input size are
truncated to fit quota.

Run with `go run .`; Docker builds the entire module. Validate with `go test ./...`,
`go vet ./...` and `go test -race ./...`. Tests cover authoritative last-slot races,
CN serial renewal and retention across restart, active slots before body reads,
byte budgets, floor subtraction, policy pinning, unsafe/corrupt ledger rejection,
real SIGKILL at durable transitions, no-clobber publication, owned cleanup and
ambiguous acknowledgement suppression. An explicit regression test also runs
publication and restart with three distinct bind mounts; the ordinary suite skips
this infrastructure-specific case unless `BIOZERO_ADMISSION_MOUNT_ROOT` is set.
HTTP multipart tests exercise malformed,
chunked-overflow and cancelled requests followed by a valid request.

## Persisted metadata lifecycle

Admission checks the exact indented projection of the current worker job
lifecycle, including JSON escaping and wrapped-key growth. It reserves status
`incomplete` (ten bytes), UTC `started_at` (20 bytes), error code (64 decoded bytes)
and error message (512 decoded bytes), using NUL's six-byte JSON expansion.
That representation must fit the 65,536-byte job-reader cap. The actual submitted
job is serialized once and retained without truncation. Larger metadata returns
`413 metadata_too_large` and removes only owned unpublished staging. Key-wrap
failure has the same pre-publication cleanup discipline. Post-publication failure
never broadly removes payloads.

Admitted inputs remain readable through the current running/terminal fields;
unsafe metadata and oversized lifecycle writes are not overwritten; upload hash,
signature and size remain complete. Worker truncation affects only the job's
UTF-8-safe diagnostic copy, keeping the full private result. Historical jobs
without this reserve are not promised to fit every state. Tests cover exact and
one-over projected boundaries for ASCII, escapes and wrapped growth, plus a live
worker processing an admitted boundary through protected rejection without
scientific inference. See the [metadata contract](../../docs/security/metadata-contract.md).

# enclave-runner (MVP)

Polls job records, verifies signatures and encryption in protected mode, executes
the explicit pipeline mode, and persists execution and scientific-release states.

The explicitly selected [owner-v1 worker](README-owner-worker.md) has its own
closed configuration and custody, verifies signed acceptance/body/envelope/AAD,
and projects confirmed V3 broker receipts. Its cache and SOC behavior differ from
the historical loop below. See [native owner evidence](../../docs/evidence/20261015-owner-worker-execution/public/README.md).

## Historical protocol config
- `BIOZERO_DATA_DIR` (default `./data`)
- `BIOZERO_RULES_PATH` (default `../../bio/reference-db/rules.json`)
- `BIOZERO_POLL_SECONDS` (default `2`)
- `BIOZERO_PRIVATE_KEY` (RSA private key for decrypting payloads)
- `BIOZERO_SIGNER_CERT` (client cert for verifying payload signatures)
- `BIOZERO_DECRYPT_DIR` (default `./data/decrypted`)
- `BIOZERO_PIPELINE_PATH` (default `../../bio/pipeline/pipeline.py`)
- `BIOZERO_REFERENCE_PATH` (optional reference genome for alignment/variant steps)
- `BIOZERO_PIPELINE_TIMEOUT` (default `10m`)
- `BIOZERO_JOB_KEY` (optional 32-byte key, base64 or hex, to unwrap `enc_key`)
- `BIOZERO_SECURITY_EVENTS_DIR` (optional private local outbox for protected rejections)

## Output
- Results include `upload_sha256`, `processed_sha256`, `pipeline_output`, `decrypted`, and signature status fields.

## Run
```bash
go run .
```

## Metadata boundary (TM-03)

Job JSON is capped at 64 KiB and result JSON at 16 MiB. Processing, recovery and
security-event reconciliation share one reader: Linux `openat` walks every
ancestor with `O_NOFOLLOW`, and opens the final file with `O_NONBLOCK` and
`O_NOFOLLOW`. A held descriptor anchors the read. Files must be regular, owned by
the current effective UID, and exactly mode 0600. Missing records remain distinct
from unsafe/corrupt records; the latter block that job without pipeline execution
or overwriting its result, while other jobs continue.

Every object rejects exact duplicate keys; maximum container depth is 64, and
trailing JSON is rejected. Known job/result/detection fields require exact names
and Go-compatible types. Typed scalar/container nulls are rejected; scientific
RawMessage payloads retain original bytes and may contain ordinary nulls and
case-sensitive keys. Jobs require `job_id` and a known `status`. Version-1 results
require all non-omitempty fields emitted by `resultRecord`, including detection
`score` and `reason`. Only historical `processed` may omit `schema_version`;
recovery marks it incomplete/unverified. This boundary does not establish
immutable ownership or biological accuracy.

The upload producer reserves the complete current job lifecycle before admission:
the longest status (`incomplete`), a 20-byte UTC `started_at`, 64 decoded bytes of
error code and 512 decoded bytes of error message. NUL diagnostics account for
the worst JSON expansion (six encoded bytes per decoded byte). The projected
indented JSON must fit 64 KiB; the actual submitted metadata is persisted intact.
This keeps admitted jobs readable in running and terminal states under the current
fields/statuses. All three worker writes (running, recovery, terminal) use one
writer that caps only the diagnostic copy on UTF-8 boundaries, checks final bytes
before replacement, and leaves the full private result unchanged.

The lifecycle invariants are: admitted input remains readable after state changes;
unsafe/corrupt input or an oversized lifecycle write is never overwritten; upload
hash, signature, size and other submitted metadata are never truncated. Historical
jobs admitted without reserve can fail the lifecycle-size check. They remain
unchanged and require operator review; no larger reader cap or hidden truncation
is applied. Filesystem changes by other local writers remain outside this claim.

Payload, PKI and rules/config reads remain outside TM-03. `O_NONBLOCK` prevents
FIFO metadata hangs; it does not provide a universal deadline for kernel IO on a
regular file or network filesystem. Metadata writes and other local writers are
also outside the read-boundary claim.

## Security outbox

Enabled outboxes require mode 0700 and the current UID. Allowlisted protected
rejections publish minimal 0600 JSON after durable result persistence. Startup
and every poll reconcile terminal results independently of jobs; storage failures
retry without rerunning the pipeline. Linux procfs, same-filesystem hard links and
file/directory fsync support are required. Temporary-file fsync followed by an
atomic no-clobber hard link preserves existing evidence; conflicting or unsafe
events are rejected, never overwritten. Retain event files: publication is a
local quarantine intent, not confirmation of relay delivery or response action.

## Command-output and result budgets

Pipeline and evaluator stdout each cap at1MiB; their stderr and optional alignment
stderr cap at64KiB. An excess byte stops the process group explicitly, including
descendants holding pipes after the leader exits. Pipeline output overflow is
`pipeline_output_limit`; evaluator overflow is `evaluation_output_limit` with
scientific release withheld. A captured prefix is not accepted as successful JSON.
Observed overflow takes precedence over simultaneous cancellation/deadline; the
existing shutdown/deadline cases remain when no overflow is observed. Alignment
scanner failures stop children before waiting; alignment is an optional detector,
so its warning alone does not withhold the independent variant evaluation.

The final serialized result must fit16MiB. Oversized derived output produces a
small `failed`/`withheld` envelope with `result_metadata_too_large`, preserving
identity, timestamp, hashes, size and crypto flags. Oversized derived fields are
not persisted. This does not silently truncate an accepted result. Tests cover
exact/+1 budgets, actual child cleanup, scientific withholding and reader-compatible
fallback. Full worker test/vet and targeted race checks passed locally.

SAM/BAM/BCF/VCF/reference copies, total optional-alignment stdout/target map and
persistent result/event totals still require separate controls. Capture limits
are not an artifact/disk quota. See [admission contract](../../docs/security/admission-contract.md).

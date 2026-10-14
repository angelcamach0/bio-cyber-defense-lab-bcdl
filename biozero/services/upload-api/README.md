# upload-api (MVP)

Accepts file uploads and writes job metadata for the runner to process.

## Endpoints
- `POST /upload` (multipart form, field `file`, required `client_id` or `X-Client-Id`)
- `GET /health`

## Security metadata
When the client provides encryption/signing metadata, the API records:
- `enc_alg`, `enc_key`, `sig_alg`, `sig`
- mTLS client certificate subject/issuer/serial (when enabled)
If `BIOZERO_JOB_KEY` is set, `enc_key` is wrapped at rest and the runner must
use the same key to decrypt.

## Config
- `BIOZERO_UPLOAD_ADDR` (default `:8081`)
- `BIOZERO_DATA_DIR` (default `./data`)
- `BIOZERO_MAX_UPLOAD_BYTES` (default `26214400`)
- `BIOZERO_RATE_LIMIT` (requests per minute, default `60`)
- `BIOZERO_TLS_CERT` (PEM cert path, enables TLS when set)
- `BIOZERO_TLS_KEY` (PEM key path)
- `BIOZERO_TLS_CA` (PEM CA bundle, enables mTLS when set)
- `BIOZERO_JOB_KEY` (optional 32-byte key, base64 or hex, to wrap `enc_key`)

## Run
```bash
go run ./main.go
```

## Persisted metadata size contract

Upload admission checks the exact indented projection of the complete current job
lifecycle, including JSON escaping and wrapped-key growth. It reserves status
`incomplete` (ten bytes), UTC `started_at` (20 bytes), error code (64 decoded bytes)
and error message (512 decoded bytes); NUL bytes account for six-byte JSON escapes.
That worst representation must fit the worker/results-reader 65,536-byte cap.
The actual submitted job is serialized once and persisted without truncation.
Larger projected metadata returns `413 metadata_too_large` before job publication and
removes only that request's uncommitted payload. Key-wrap failures also clean up
that pre-publication payload. A persistence error after publication may be
ambiguous, so it deliberately retains the payload rather than erase input for a
possibly visible job. This does not implement global quotas or retention.

The invariants are: admitted jobs remain readable after running and terminal state
updates under the current fields/statuses; unsafe/corrupt inputs and oversized
lifecycle writes are not overwritten; upload hash, signature and size are never
truncated. The worker caps only the job's diagnostic copy on UTF-8 boundaries,
leaving the full private result intact. Historical jobs admitted without reserve
are not promised to fit every state; an oversized state write fails closed.

Multipart tests cover exact/one-over projected boundaries for ASCII, escaped and
wrapped fields, cleanup and a subsequent valid request. A live-worker test admits
the projected boundary, observes running-to-rejected persistence, and checks the
terminal record remains below the same reader cap with immutable fields intact.
The native metadata acceptance
checks actual mTLS admission and absence of new job/payload after rejection. See
[metadata contract](../../docs/security/metadata-contract.md).

# Results API

`GET /results/{job_id}` authenticates the job owner before opening the result.
Protected mode requires verified mTLS, certificate CN matching `client_id`, and
its decimal certificate serial matching `client_cert_serial`. Headers do not
provide a TLS identity. Only explicit `BIOZERO_SECURITY_MODE=demo` allows a
non-TLS `X-Client-Id` for jobs without a certificate binding. `GET /health` is a
separate liveness endpoint; it does not validate every stored record.

## Metadata read boundary (TM03)

Linux `openat` opens every ancestor using `O_DIRECTORY|O_NOFOLLOW` and the final
file using `O_RDONLY|O_NOFOLLOW|O_NONBLOCK`. Each open is anchored to its previous
directory descriptor. Configured paths containing symlinks are unsupported.
Descriptor `fstat` requires a regular file owned by the process UID, exactly
0600 including no setuid/setgid/sticky bits. Job records are limited to 64KiB;
results to 16MiB, both by initial size and a bounded read. FIFO reads return a
safe error without waiting for a writer. This does not guarantee disk IO deadlines.
Ancestor directory permissions/UIDs are not restricted here: mount/root ancestors
may have different owners. They and the shared host remain trusted.

Only ENOENT means missing: an absent job returns 404; an absent result permits
uploaded/running or saved rejected/failed/timed_out fallback. Other read failures
return 500 with `job_read_failed` or `result_read_failed`. Invalid JSON/schema
returns500 with `job_record_invalid` or `result_record_invalid`. Responses omit
filesystem paths and parser diagnostics. A different authenticated owner gets 403
before result access, including when the result is unsafe.

JSON rejects duplicate keys in every object, trailing values and container depth
greater than 64. Job/result/detection tags are exact and known; unknown tags and
case aliases are invalid. Present typed fields reject null and wrong types.
Scientific/pipeline RawMessage payloads retain their data: internal nulls and
case-sensitive arbitrary map keys are allowed, but duplicates/depth limits still
apply. Detection signal maps are likewise arbitrary. No scientific payload is
interpreted as proof by the reader.

Jobs require valid lowercase-hex `job_id` (8–64 characters) and a known state;
other current Upload/Worker fields are checked when present. Authorization
independently rejects missing owner/certificate bindings in protected mode.

Current results require schema_version 1, job_id and a terminal state, plus all
fields always emitted by the worker: security_mode, pipeline_mode, processed_at,
upload_sha256, processed_sha256, size_bytes, decrypted, signature_valid,
release_status, detection; detection requires score/reason. Presence and types
are checked without new hash/time/mode or scientific value requirements: empty
strings and false values on failed runs remain valid. Terminal states are
succeeded, incomplete, rejected, failed, timed_out and historical processed.

The only unversioned compatibility path is historical processed with valid ID
and status; present known fields still receive type checks. Both that path and a
complete schema 1 processed record respond with status incomplete,
legacy_status processed and error_code legacy_result_unverified. Unversioned
minimal succeeded/failed/etc records are invalid. A succeeded execution by itself
does not approve science; existing release/evaluator gates remain with consumers.

This boundary does not make ownership metadata immutable (TM02), authenticate
stored bytes against a trusted producer, constrain worker payload/PKI/config
reads, or protect against a privileged shared-host writer. A regular file may
still change during/after a read; no cross-file transaction is claimed.

## Configuration and verification

- BIOZERO_RESULTS_ADDR: :8082
- BIOZERO_DATA_DIR: ./data (jobs/ and results/)
- BIOZERO_SECURITY_MODE: protected (or explicit local demo)
- BIOZERO_RATE_LIMIT: 120 requests/minute
- BIOZERO_TLS_CERT / BIOZERO_TLS_KEY / BIOZERO_TLS_CA: protected mode requires all

Run the entire module so the metadata helper is included:

```sh
go run .
go test -race ./...
go vet ./...
```

Tests use real HTTP handlers and verified mTLS client/server requests with client
timeouts, separate health and FIFO probes, subsequent valid requests, A/B denial,
symlink final/ancestor paths, sparse oversized files, unsafe modes, duplicate
ownership/status fields, type/null/case/trailing/depth and current/legacy contracts.
The owner UID condition is enforced by fstat; these tests do not require elevated
privileges to create foreign-owned files. Container integration is separate.

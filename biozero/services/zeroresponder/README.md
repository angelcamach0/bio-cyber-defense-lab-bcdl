# ZeroResponder: authenticated simulation receipts

ZeroResponder records intended security responses. It **does not** alter firewall rules, certificate trust, quarantine state, job execution or scientific release. Every acknowledgment and action explicitly says `mode: simulation` / `enforced: false` (actions use `status: simulated`). There are no blocklist, revocation-list, quarantine-list or append-only action-log writers.

## Configuration

- `BIOZERO_RESPONDER_ADDR`: default `127.0.0.1:8090`. Plain HTTP is permitted only with a literal loopback IP, including `[::1]`; `localhost`, an empty host or wildcard IP requires TLS.
- `BIOZERO_DATA_DIR`: default `./data`. Final receipts are `<data>/actions/<alert_id>.json`. The store directory must be owned by the process with exact `0700`; receipts require exact `0600`. Setuid/setgid/sticky bits are rejected.
- `BIOZERO_WEBHOOK_SECRET`: mandatory, 32–512 bytes. Provision a random secret privately; callers send exactly one `X-Webhook-Secret` header. It is never written in receipts or logs.
- `BIOZERO_TLS_CERT` / `BIOZERO_TLS_KEY`: configured together. Non-loopback listeners require them. TLS uses a minimum version of 1.2. HTTPS callers, including the relay, must verify the certificate hostname and CA.

The body limit is fixed at **64 KiB**; the old `BIOZERO_ALERT_MAX_BYTES` override is removed. All JSON responses use `Cache-Control: no-store`. `GET /health` returns `healthy`, `mode: simulation`, `enforced: false` and responder liveness. An unhealthy store returns HTTP 503. Health does not establish enforcement or an operational SIEM.

## Alert contract

`POST /alert` authenticates the configured shared secret before parsing. The exact top-level fields are:

```json
{
  "schema_version": 1,
  "alert_id": "evt-<deterministic 64 lowercase hex digest>",
  "source": "enclave-runner",
  "event_code": "signature_required",
  "severity": "high",
  "timestamp": "2026-10-14T00:00:00Z",
  "indicators": {"job_id": "abcd1234"},
  "actions": ["quarantine"]
}
```

The example ID is a placeholder. A worker ID is exactly `evt-` + SHA256 of UTF-8 `enclave-runner/<job_id>/<event_code>`. The worker uses the result's stable `processed_at` timestamp. Allowed worker events are `upload_integrity_failed`, `signature_required`, `signature_algorithm_invalid`, `signature_invalid`, `encryption_required`, `encryption_metadata_invalid`, `key_unwrap_failed`, and `decryption_failed`. Worker severity is `high`, and its only action is `quarantine` with a job ID of 8–64 lowercase hex characters.

SIEM requests use `source: siem`, `event_code: policy_alert`, severity `low`, `medium`, `high` or `critical`, and an ASCII alert ID matching `[A-Za-z0-9][A-Za-z0-9_-]{0,127}`. They may request 1–3 distinct actions:

| Action | Required indicator | Validation |
| --- | --- | --- |
| `quarantine` | `job_id` | 8–64 lowercase hex characters |
| `block_ip` | `ip` | Parsed IP address, no zone identifier |
| `revoke_cert` | `cert_serial` | 1–128 hex characters |

Unused indicators are rejected. Unknown fields, case-altered field names, duplicate JSON keys, null values, trailing JSON, missing fields, malformed timestamps and unsupported event/action combinations are rejected. No filenames, genomic sequences, free-text diagnoses, arbitrary commands or paths are accepted.

## Canonical payload and replay

Canonicalization converts timestamps to UTC RFC3339Nano, sorts action names, lowercases certificate serials and normalizes IPs with `netip.Addr.Unmap().String()`. The SHA256 is computed over `json.Marshal(alertPayload)` with this exact struct order:

`schema_version`, `alert_id`, `source`, `event_code`, `severity`, `timestamp`, `indicators`, `actions`.

Go sorts the indicator map keys. Worker events already use the canonical single-action UTC form, compatible with the relay's Python serializer (`ensure_ascii=False`, compact separators, the field order above and sorted indicator keys). SIEM producers must hash the normalized form rather than raw request bytes. A different timestamp changes the payload; retries preserve the original timestamp.

Successful acknowledgments contain:

```json
{
  "status": "recorded",
  "mode": "simulation",
  "enforced": false,
  "alert_id": "<validated ID>",
  "payload_sha256": "<canonical SHA256>",
  "recorded_at": "<stable first-record timestamp>",
  "replay": false,
  "actions": [
    {"action": "quarantine", "target": "abcd1234", "status": "simulated", "enforced": false}
  ]
}
```

An identical canonical retry returns HTTP 200 with `replay: true`, the same digest, original `recorded_at` and deterministic actions. A reused ID with different canonical content returns **409** and never replaces the receipt. Missing/wrong/ambiguous authentication returns **403**, invalid input **400**, oversized input **413**, and storage failures **503**.

## Durability and filesystem boundary

One private receipt holds schema, status, simulation flags, alert ID, digest, recorded timestamp, the complete canonical alert and all simulated actions. It is published by creating a private temporary file, writing and syncing it, atomically linking it **without replacing an existing destination**, removing the temporary name and syncing the directory. File and directory operations are bounded to the local store. Existing-file collisions are validated as replay/conflict, including between independent responder instances.

Directory setup walks each ancestor with `openat`/`O_DIRECTORY`/`O_NOFOLLOW`; every parent is synced, including existing entries left by a previous attempt. The final owned directory descriptor remains pinned, and operations use its internal Linux proc-fd path. Reads use `openat` with `O_NOFOLLOW` and `O_NONBLOCK`, then `fstat` to verify regular-file type, ownership, exact mode and size. Symlinks/FIFOs cannot masquerade as receipts or block the reader. Every existing receipt must pass complete schema, canonical payload digest, action derivation and explicit-false checks; startup validates all final JSON receipts.

The process mutex serializes validation/publication/acknowledgment. No successful acknowledgment precedes the durability boundary. A storage error makes the process unhealthy; later filesystem recovery or a retry does not silently reset it. Repair and restart are required. A failure after linking may leave a visible, unacknowledged receipt: restart must validate and sync it before acknowledging a replay. This is at-least-once delivery with idempotent recording, not an exactly-once distributed transaction.

Legacy non-JSON files are retained as historical evidence and never interpreted or updated as policy. Use a fresh scoped store for the acceptance experiment; migration/retention is an operator responsibility. The service requires a local Linux filesystem supporting hardlinks, regular-file fsync and directory fsync. Ephemeral storage does not establish persistence beyond that storage's lifetime.

## Verification

From this directory:

```bash
go test -race ./...
go vet ./...
```

Eight top-level tests with positive/negative subcases exercise authentication, strict schemas, all eight worker event codes, relay field-order/digest compatibility, restart replay/conflict, injected errors at six persistence stages, sticky/setuid/setgid rejection, corruption/symlink/FIFO rejection, parent sync retries, directory anchoring, two independently locked instances racing a no-clobber publication, 24 simultaneous replays, real verified HTTPS and rejection of legacy TLS/untrusted CA. These passed locally on 2026-10-14. Real worker/outbox/relay/container acceptance is recorded separately by its owning harness.

The shared secret authenticates possession of a producer credential. `source` remains that producer's validated claim; it is not per-source identity attestation. The host operator and privileged storage writers remain trusted, and the payload digest is not independent tamper-evident storage. There is no automated retention/disk quota, production SIEM, live containment, biological-hazard inference or certificate revocation enforcement.

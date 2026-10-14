# Security event and simulated response contract

Version 1. This contract records protected-worker security rejections and explicit
SIEM simulation requests. A recorded response is not enforcement. It changes no
firewall, certificate trust, job state or scientific release decision.

## Worker event

```json
{
  "schema_version": 1,
  "alert_id": "evt-<64 lowercase hex characters>",
  "source": "enclave-runner",
  "event_code": "signature_required",
  "severity": "high",
  "timestamp": "2026-10-14T00:00:00Z",
  "indicators": {"job_id": "0123456789abcdef"},
  "actions": ["quarantine"]
}
```

The worker emits only schema-1, protected, rejected results. Allowed event codes
are `upload_integrity_failed`, `signature_required`,
`signature_algorithm_invalid`, `signature_invalid`, `encryption_required`,
`encryption_metadata_invalid`, `key_unwrap_failed` and `decryption_failed`.
The identifier is `evt-` plus SHA256 of the UTF-8 text
`enclave-runner/<job_id>/<event_code>`. The timestamp is exactly the result's
`processed_at` in UTC seconds (`YYYY-MM-DDTHH:MM:SSZ`), not a redelivery time.
This is an observed verification failure,
not attribution of malicious intent or a biological hazard assessment.

No filename, DNA, free text diagnostics, local paths, client identity, certificate
serial, keys or signatures are included. The existing result remains authoritative
for execution and scientific release.

## Durable handoff

`BIOZERO_SECURITY_EVENTS_DIR` enables a private worker outbox. Files are bounded
to 64 KiB, regular, mode 0600 in a directory mode 0700. Publication uses a private
temporary file, file fsync, an atomic no-clobber hardlink and directory fsync on a
local filesystem supporting those operations. Existing conflicts are not replaced.
Persisted results are reconciled independently of terminal job state; missing
events can be regenerated without running the pipeline again. Spool failures are
reported locally and retried. They do not fabricate delivery or erase a result.

A separate relay has network access; the worker keeps its existing network
isolation. Events and delivery receipts are retained. Transport is at least once;
the responder deduplicates an identical alert ID/payload across process restarts.
This is not an exactly-once distributed transaction. There is no automatic
retention policy or disk quota yet. Loss or privileged alteration of the shared
filesystem is outside this trust boundary.

## Responder boundary

`POST /alert` requires a configured secret of at least 32 bytes in
`X-Webhook-Secret`. Non-loopback listeners require TLS, with certificate and key
configured together. The relay always verifies HTTPS identity and CA trust and
does not follow redirects. Plain HTTP is available only for an explicitly local
loopback listener; it is not used by the end-to-end acceptance experiment.

Strict parsing rejects unknown fields, trailing JSON, invalid event/action
combinations and oversized input. Worker events use exactly the contract above.
SIEM `policy_alert` requests can explicitly simulate `block_ip`, `revoke_cert` or
`quarantine` with their typed target indicators. An identical retry returns the
same durable action receipt; reuse of an ID for changed content is a conflict.

Successful acknowledgments explicitly contain `mode: simulation` and
`enforced: false`, including each action. One receipt per alert holds the entire
request and all simulated actions; no partial append-only block/revocation lists
are created. The server acknowledges only after durable publication. An ambiguous
persistence failure makes the instance unhealthy until operator repair/restart.
These controls do not provide a production SIEM, policy approval, live containment,
certificate revocation checking, independent tamper-evident storage or host attestation.

`payload_sha256` binds the acknowledgment to the canonical request. Canonical JSON
uses the displayed field order, sorted indicator keys, UTC RFC3339Nano timestamps
and sorted actions, without indentation or a trailing newline. Worker events
already have UTC seconds and one action. The relay checks this digest and the
exact simulated quarantine target before recording delivery; JSON numeric zero
does not satisfy a boolean false flag. The relay's descriptor-anchored receipt
storage also requires Linux procfs and no-clobber hardlink support.

## Acceptance

The executed experiment must show a real protected-worker rejection, a durable
event, verified HTTPS delivery, a simulation-only receipt, identical redelivery
across responder restart, conflict rejection, authentication rejection and no
effective action artifacts. Unit checks additionally cover storage faults,
input boundaries and concurrent submissions. Evidence and source hashes must
identify the particular implementation tested; a contract alone is not proof.

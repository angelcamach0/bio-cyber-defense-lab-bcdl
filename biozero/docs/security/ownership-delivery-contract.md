# Owner-v1 upload delivery

This increment connects the durable owner client to a separate upload transport
spool. It preserves the authority's original signed job ID. It does not establish
worker/broker ownership enforcement, authoritative result release, gateway
integration, deployment isolation or scientific execution. Those remain TM02 gates.

## Sources of authority

Each consumer verifies the historical SignedAcceptance with externally provisioned
Ed25519 pin, pipeline mode, execution-profile SHA and authority store/policy scope.
The actual verified mTLS leaf DER SHA must match the signed owner. Certificate CN
is only a quota bucket, so certificate renewal cannot reset that principal's quota.
The upload service receives neither the authority's signing key nor the worker's
RSA decryption key. Its unsigned ledger and TLS receipt are transport evidence;
they cannot establish ownership against a compromised upload service or host.

## Wire and durable client intent

Only HTTPS/mTLS HTTP/1.1 is supported. POST `/v1/uploads` uses known exact
Content-Length and `application/octet-stream`:

```
BE32 acceptance length | signed acceptance | BE32 envelope length |
decoded RSA-OAEP ciphertext envelope | signed ciphertext bytes
```

Acceptance is bounded64KiB, envelope256–512bytes and ciphertext25MiB. The handler
reads framing metadata first; Store verifies signature, scope, exact owner leaf,
envelope digest and signed body length before reading ciphertext. The body is
measured to its exact declared size and EOF, including a one-byte overrun probe,
and SHA256 is compared with the signed acceptance before publication. HTTP query,
encoded path, chunking, trailers, compression, redirects and legacy routes are
not supported on this service. Limits are enforced by actual connection, handler,
header, read and write bounds; body-before-metadata claims exclude kernel/TLS
buffering and the HTTP server's final connection cleanup.

The client retains its accepted bundle in an independent append-only delivery
journal. It publishes a durable delivering phase before its sole POST. Lost or
malformed ACK leaves that phase intact; only GET `/v1/uploads/<known-job>` may
recover. There is no automatic resend, re-encryption, new reserve or legacy
fallback. A matching delivered GET response appends the final phase. The raw
CLOEXEC flock survives uncertain IO or pending Close until actual process exit.

The receipt has only schema_version1, job_id, acceptance_sha256 (the verified
canonical acceptance hash), credential_sha256, ciphertext_sha256, ciphertext_bytes,
key_envelope_sha256 and state=delivered. It means that this TLS peer claims it
retained that transport payload. No scientific or broker outcome is inferred.

## Separate charged spool

Genesis is explicit and exclusive; serving opens an existing private root with
its exact pin/scope/policy context. No legacy admission history is imported or
reset. Before the first ciphertext read, the spool commits a reading record and
charges its configured maximum body plus131072metadata bytes. It synchronizes the
new upload directory entry before reading, then measures and syncs the file.
Known input failures become rejected while retaining partial bytes and the full
charge. Delivered, rejected and uncertain work never refunds charges or slots.
Admission also checks retained global/principal jobs/bytes and concurrent active
uploads, plus observed free space with a floor and replacement-ledger headroom.
These are bounded logical accounting and free-space checks, not a filesystem quota.

The ledger allows at most64records and8MiB; its replacement is separately bounded
8MiB. The upload file, signed-acceptance sidecar and bounded job cache are anchored
private files with no symlinks/hardlinks. A marker precedes ledger replacement;
IO uncertainty latches the writer and raw lock. Cold pending history is refused
unchanged, never adopted, refunded or retried. Explicit operator reconciliation
and retention remain future work.

Only after actual body verification does publication write the signed acceptance
under `acceptances/`, then exclusively publish the lifecycle cache under `jobs/`.
The cache references the acceptance hash; it is not execution proof. An exact
already-delivered POST returns its original receipt without reading another body;
pending/rejected/conflicting attempts cannot reopen admission. GET checks the
actual TLS leaf before reading private spool state and returns only the bounded
receipt for delivered work. Protected response Write/Flush occurs under fresh
Store preflight; failure latches the live writer. A downstream relay losing a
response after receiving an upstream200 does not prove an upstream ACK-write error.

## Execution remains closed

The new job cache uses the distinct
`aes-256-gcm+rsa-oaep-sha256+owner-v1` algorithm and carries no legacy signature.
The existing protected worker rejects it before decryption/custody/broker calls.
A separately constructed adversarial fixture with a valid legacy signature must
still fail the owner algorithm gate before reaching legacy nil-AAD decryption.
That negative does not verify owner-v1 worker decryption or execution.

Future worker/broker custody must bind the canonical acceptance hash, profile,
original upload and actual envelope/AAD before reservation and every replay.
Transport the bounded signed acceptance separately from existing bounded RPCs;
do not silently increase journal capacity or insert a64KiB object into a64KiB
request. Results needs signed-owner authorization before private bytes and a
trusted, fixed receipt/status-only broker channel. It must not release mutable
result JSON or acquire submission/cancellation rights. Authority GET remains
owner-only; service consumers verify signed historical records offline with
external pins, without sharing the owner's private key.

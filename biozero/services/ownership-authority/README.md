# Authenticated ownership authority and durable registry

This standard-library Go package (`biozero/ownership-authority`, package
`ownership`) implements the cryptographic foundation of
[ADR 004](../../docs/decisions/004-authenticated-ownership.md). Its Linux Store
persists reservations and signed accepted records. The new Linux
`cmd/ownership-authority` serves a separate HTTPS/mTLS authority. The explicit
owner-v1 CLI/upload adapter is described below. Gateway, worker, broker and
Results ownership integration remains pending. The historical upload/results/
worker path does not acquire immutable ownership by importing this module.

## Public API and trust boundary

1. The authority authenticates a real server-side mTLS connection and calls
   `PrincipalFromTLS`. It requires a completed handshake, a verified chain whose
   leaf DER equals the peer leaf, and an RSA 2048–4096-bit client-auth leaf with
   exponent 65537 and digital-signature usage. The credential is SHA256 of the
   actual leaf DER; CN and serial are not ownership keys. `Principal` has private
   fields and exposes `CredentialSHA256()` and `CommonName()` getters. Supplying
   fabricated `tls.ConnectionState` or a permissive TLS verifier is outside the
   authenticated transport boundary; the authority must configure real chain
   validation and certificate policy itself.
2. The authority calls `Store.Reserve` before reading a body. It persists the
   full reservation, generates its own unpredictable job ID and nonce and returns
   the signed challenge. `SignChallenge` remains a stateless primitive; using it
   directly does not establish a reservation.
3. The client calls `VerifyChallengeForClient(raw, pin, ownLeaf, now)` and
   `CanonicalAAD`. The local leaf is used because a client's TLS peer certificate
   describes the server. Server-side consumers can use `VerifyChallenge` with a
   `Principal`. `VerifiedChallenge` is opaque; `Claims()` returns a copy and
   `SHA256()` hashes its canonical signed envelope.
4. The client encrypts with the exact AAD bytes, then calls
   `SignManifest(rsaPrivateKey, ownLeaf, verifiedChallenge, ManifestInput)` and
   `MarshalManifest`. It checks that the private key matches both the leaf and
   the challenged credential. `VerifyManifest` checks the same credential and
   strict RSA-PSS SHA256 with a 32-byte salt, never PKCS#1 v1.5 or automatic salt.
5. The authority calls
   `Finalize(ctx, tlsState, rawChallenge, rawManifest, pin, ciphertextReader, now)`.
   TLS, the pinned authority signature and the client signature must verify
   before the first reader call. Finalize hashes actual ciphertext, reads at
   most its declared size plus one byte, requires exact size and EOF, and returns
   a `Binding` only after a matching SHA256. It never signs a checksum merely
   asserted by an upload service.

`AuthorityPin` is trusted configuration containing an explicit authority ID,
Ed25519 public key, pipeline mode and execution-profile SHA256. It must remain
immutable during calls, including its public-key byte slice. No key, mode or
profile is learned from an untrusted claim. The wire key ID is SHA256 of that
pinned public key and is only an identifier. Both private Ed25519 seed/public
consistency and equality with the external pin are checked when signing.

`SignedChallenge`, `SignedManifest` and `Binding` are serializable DTOs, not
unforgeable Go capabilities. Marshal helpers enforce serialization bounds; they
do not authenticate caller-constructed DTOs. Only verification functions produce
opaque verified wrappers. A returned binding still requires an authoritative
durable acceptance record; consumers must not trust a caller-created binding.

## Wire contract

Challenge, AAD and manifest have separate version-1 domain strings. Canonical
bytes use compact `encoding/json` serialization of the declared wire structs in
field declaration order. Signatures cover canonical claim/manifest bytes. A
manifest's challenge hash covers the canonical *signed challenge envelope*;
its AAD hash covers the exact canonical AAD bytes. Whitespace or equivalent JSON
string escapes do not change the reconstructed canonical values. Hashes use
lowercase hex; signatures use lowercase hex of raw signature bytes.

The canonical AAD fields, in order, are `schema_version`, `domain`,
`authority_id`, `job_id`, `nonce`, `credential_sha256`, `original_name`, `enc_alg`,
`pipeline_mode`, `execution_profile_sha256`. They derive from the pinned,
verified challenge. The claim additionally carries `key_id`, `issued_at`, and
`expires_at`. The manifest carries `schema_version`, `domain`, `sig_alg`,
`challenge_sha256`, `aad_sha256`, `ciphertext_sha256`, `ciphertext_bytes`,
`key_envelope_sha256`.

`KeyEnvelopeSHA256` means SHA256 of the exact **decoded RSA-OAEP ciphertext
bytes**, not their hexadecimal or base64 representation. Finalize authenticates
this client declaration but does not receive or inspect the actual envelope.
Future execution consumers must compare that digest with the supplied decoded
envelope before RSA-OAEP SHA256 unwrap. Finalize likewise does not decrypt data
or prove that ciphertext is well-formed AES-GCM: execution must use the signed
AAD on GCM Open. A credential can re-sign a copied ciphertext, but cannot make
ciphertext encrypted with another job's AAD decrypt under its new AAD. This last
gate remains pending until the real worker consumes this protocol.

| Field or resource | Limit or accepted value |
| --- | --- |
| Challenge and manifest wire bytes | Each 1–4096 bytes |
| JSON | Required exact-case keys; no unknown, duplicate, null, trailing or invalid UTF-8 values; typed scalars; maximum depth 64 |
| Authority ID / job ID | 32 / 16 lowercase hexadecimal characters |
| Nonce, credential, profile and content digests | 64 lowercase hexadecimal characters |
| Original name | 1–128 ASCII letters, digits, `.`, `_`, `-`; excludes `.` and `..` |
| Encryption algorithm | `aes-256-gcm+rsa-oaep-sha256+owner-v1` only |
| Pipeline mode | Pinned `stats` or `variants`; no demo or legacy fallback |
| Time | Canonical UTC whole-second RFC3339; expiry strictly after issue and no more than 5 minutes later |
| Ciphertext | 16 bytes–25 MiB; 64 KiB read buffer; at most one excess byte read |
| Leaf certificate DER | At most 16 KiB |

Every wire field is required. Duplicate validation applies inside every accepted
object. Arrays and other structures in scalar positions are rejected rather than
coerced. Errors are stable codes and do not include certificate contents, raw
reader errors, paths or secret values. The stateless authority measures opaque
ciphertext; the durable client contract below now fixes owner-v1 GCM tag/body
framing and the empty-label OAEP key/nonce envelope for future execution consumers.
Their integration remains pending.

## Acceptance time and historical verification

`now` must come from the authority's trusted clock, never from request metadata.
Verification accepts `issued_at <= now < expires_at`. Finalize also counts
elapsed processing/read time and rejects crossing expiry. A generic `io.Reader`
can block inside `Read`; context checks between reads cannot interrupt that
call. HTTP ingress now sets actual connection deadlines. A future file transport
still needs verified regular read-only descriptors/provenance. A reader returning
zero bytes without an error is rejected
as nonprogress rather than retried forever.

The five-minute window applies to the original acceptance decision. Store
Finalize computes `AcceptedAt` after actual ciphertext verification using the
trusted starting time plus elapsed preparation/read time. It checks challenge
and leaf validity at that decision. Signing and durable commit follow; this is
not a claim that the commit completes before expiry. Cancellation observed after
reading or before committing prevents acceptance.

`VerifyAcceptance(raw, pin, expectedScope)` verifies the outer authority
signature, exact external StoreID/policy hash, original certificate DER, challenge,
client manifest, decision time and every reconstructed Binding field. It returns
an opaque `VerifiedAcceptance`; `Claims()`/`Binding()` return copies and
`CanonicalAADFromAcceptance` derives the original AAD. There is no caller-supplied
historical clock. Accepted work does not expire retroactively. `SignedAcceptance`
is only a DTO; `MarshalAcceptance` does not authenticate constructed values.
The acceptance envelope is bounded to 64 KiB and strict JSON.

## Linux durable Store

`CreateStore` creates an exclusive new 0700 directory; it never replaces or adopts
existing history. `OpenStore` requires a trusted external
`AcceptanceScope{StoreID, PolicySHA256}` from genesis. Persist that scope outside
the mutable spool; reading an arbitrary local scope is not enrollment. The policy
hash binds the namespace, authority/key, mode/profile and all numeric limits.
Changed configuration fails rather than silently migrating or resetting quotas.

Reserve takes a 32-hex request token, filename and trusted whole-second time.
An exact same-owner retry returns the original challenge, even after expiry;
changing the leaf or filename conflicts. Ownership uses the exact leaf DER hash.
Quota identity separately hashes the enrollment namespace and verified CN, so
renewing a certificate does not create a fresh quota bucket or transfer a job.
The authority must control namespace/CN enrollment policy.

| Default resource | Bound |
| --- | --- |
| Retained jobs, global / principal | 64 / 16 |
| Charged bytes, global / principal | 512 MiB / 128 MiB |
| Active reserved-or-reading jobs, global / principal | 2 / 1 |
| Body reservation per job | 25 MiB plus 131,072 bytes metadata headroom |
| Free-space sensor floor | 128 MiB plus all retained promises and two ledger bounds |
| Challenge lifetime | 300 seconds |
| Physical ledger / replacement / intent | 8 MiB / 8 MiB / less than 1 KiB, plus empty lock |

All reserved, reading, rejected and accepted jobs retain their full charge and
slot. Expiry never refunds or frees an active reservation; operator retention or
reconciliation is still required. Policies may lower body/record limits and set
the floor to zero for controlled fixtures. The free-space sensor is conservative,
not a filesystem reservation. This module does not retain ciphertext; ingress
must enforce its own physical storage, deadlines and descriptor provenance.

Store Finalize verifies the exact stored challenge, real mTLS leaf and client
signature before reading. It commits `reading` with the exact manifest before
the first Reader call, then releases its mutex for bounded streaming. A second
Finalize cannot start another reader. Known read failures persist `rejected` with
the full charge. Success signs the measured facts, commits `accepted`, then
returns the DTO. An exact accepted retry returns byte-identical history without
reading, resigning or reapplying challenge freshness. `Get` checks the exact
owner before returning protocol records. No public API signs arbitrary Binding
values into authority acceptance records.

The canonical strict ledger is signed with the pinned Ed25519 authority key.
Writes use exclusive intent creation/sync, exclusive replacement write/sync/close,
rename and parent sync, then intent retirement and parent sync. Anchored no-follow
operations check current-UID 0700 directories, 0600 regular single-link files,
bounded contents and live root/lock/ledger identities. Unknown files, transaction
markers, incomplete reading history and invalid signatures fail Open unchanged.

Any ambiguous persistence/ACK failure makes the live Store unavailable, including
in-flight acceptance. `Healthy` rechecks physical history. A raw CLOEXEC duplicate
of the locked open-file description has no Go finalizer; sticky `Close` refuses
to release it, so losing Go handles cannot permit another writer. Healthy Close
releases the lock only after other anchors close. Actual process death releases
the lock. A fresh process may recover a genuinely committed signed record; it
never reads a pending body again or refunds its charge. If intent unlink happened
but its parent sync failed, a later crash may leave no intent: universal rejection
of every such cold restart is not claimed. No antirollback, revocation, secure
erasure, hostile-host protection or operator repair service is provided.

The separate authority service below is implemented. Deployment must still prove
separate key custody and writable-mount isolation. Pending integration includes
direct client/gateway ingress, envelope/AAD enforcement in worker/broker, result
release from protected receipts, revocation/rotation and historical migration.
Repeated stateless Finalize calls remain possible outside Store. Existing
upload/worker/broker/Results interfaces are unchanged and TM02 stays open.

## HTTPS authority service

The command loads private pinned assets into memory, opens only externally
enrolled history and listens on a literal loopback IP. It requires TLS 1.3 with
verified client certificates, disables session tickets and HTTP/2, and accepts
one HTTP/1.1 request per connection. Identity comes exclusively from `r.TLS`;
forwarded headers and owner assertions never establish a caller.

| Endpoint | Request | Response |
| --- | --- | --- |
| POST /v1/reservations | Exact JSON keys schema_version=1, request_id and original_name; application/json, 1–1024 bytes | Original SignedChallenge after durable Reserve |
| POST /v1/finalizations | application/octet-stream; BE32 challenge length, exact signed challenge, BE32 manifest length, exact signed manifest, ciphertext | Original SignedAcceptance after durable Finalize |
| GET /v1/jobs/16-lowercase-hex-job | No body | Owner-only HTTPJobResponse with state/challenge and optional acceptance/failure_code |
| GET /healthz | No body; mTLS required | Minimal status; 503 if unavailable or ingress busy |

Finalize metadata is at most 4096 bytes per signed object. Content-Length is
required and bounded to the policy body limit plus 8200 framing bytes and one
excess byte. Chunked bodies, compression, trailers, Expect, upgrade, queries and
encoded paths are rejected. The remaining HTTP body goes directly to Store;
no multipart parser, spool, checksum assertion or artificial EOF substitutes for
the actual bytes. The client must use the original signed serialization for an
exact Store retry. An accepted retry can return its original record after only
metadata, without consuming another ciphertext body.

Eight connections include handshakes/idle clients; four handlers may run at once.
MaxHeaderBytes is configured to 16 KiB, with a five-second header timeout. Actual body
read and response write deadlines are 30 and ten seconds. FullDuplex disables
the implicit drain before an early response; kernel/TLS buffers and net/http's
final cleanup can still read or drain bytes. Claims about authorization before
ciphertext Read apply to the application reader, not zero socket reception.

Responses are completely serialized and bounded before delivery. For protected
records, a second Store preflight/context check and the complete Write/FlushError
run under its mutex with a real write deadline. A delivery failure latches the
live Store without modifying accepted bytes or charges. The handler aborts the
connection rather than issuing an implicit 200 or a second response after failure.
Successful Write/Flush does not demonstrate client receipt. Public errors use an
explicit code allowlist; private paths, reader errors and certificates are not
returned. A blocked/canceled request never grants ownership or quota credit.

Shutdown stops admission, cancels request contexts and waits for active handlers.
Its five-second wait budget includes contention on the shutdown gate, with the
last fifth reserved for closing its own connections and draining readers. Store
is never closed while handlers remain. A terminal close/drain error is retained;
later calls cannot release its Store authority. Actual process death releases
that raw lock. These are local service controls, not deployed sandbox/hostile-host
isolation or a complete storage-failure reconciliation service.

## Private configuration and explicit genesis

`AuthorityServiceConfig` is a closed schema; every wire field is required. It
contains schema_version=1, listen_address, store_root, namespace, authority_id,
public_key_hex, pipeline_mode, execution_profile_sha256, signing_key,
tls_certificate, tls_private_key, client_ca, policy and expected_scope. The four
assets each contain absolute canonical path and lowercase SHA256. See the
[typed configuration](service_config_linux.go) for exact JSON names and bounds.

Configuration/assets must be current-UID 0600 regular single-link files under
0700 private directories, with no symlink traversal. Store root cannot overlap
configuration/assets. Raw Ed25519 signing material is exactly 64 bytes and must
match the external public pin. TLS material is bounded strict PEM; the server
RSA leaf must have serverAuth/signing usage and a matching key. Client CA files
contain valid CA certificates, never a CA private key. Loaded material is cached
privately: changed public configuration is rejected, and Serve never rereads an
unchecked asset path. Upload/worker must not receive authority key/config mounts;
separate deployed mounts/users remain to be demonstrated.

Build the executable from this module into a new private destination:

```sh
go build -trimpath -buildvcs=false -o /absolute/private/ownership-authority ./cmd/ownership-authority
```

Prepare a trusted private config with empty store_id/policy_sha256 fields inside
expected_scope for genesis only. Run `ownership-authority --config /absolute/private/init.json
--init-store` and capture its scope stdout in a new private file. The command
creates only an exclusive fresh Store, emits its external scope and exits; it
never starts ingress or adopts an existing destination. A failed scope write
does not authorize rerunning genesis or deriving enrollment from mutable files.
Prepare a separate private serve config containing that trusted scope, then run
`ownership-authority --config /absolute/private/serve.json`. Serving never
initializes missing state. SIGTERM stops/drains the service; uncertainty produces
a nonzero exit with history retained. No key generator, client integration,
automatic enrollment, migration or operator repair is hidden in startup.

## Durable client component

The new Linux AuthorityClient is a verified one-call HTTPS/mTLS transport;
ClientOperation adds an exclusive private append-only workspace before Reserve,
prepares one owner-v1 encrypted payload, records Finalize intent and recovers by
Get without resending ciphertext. EncryptForChallenge and DecryptAcceptedPayload
fix the actual OAEP key/nonce framing and mandatory canonical GCM AAD for future
consumers. See the [durable client contract](../../docs/security/ownership-client-contract.md)
for transitions, resource limits, ambiguous IO and trust boundaries.

These shared APIs do not activate the current uploader/gateway or execution path.
The existing upload-generated job ID, gateway post-upload persistence, deployed
key/mount isolation and worker/broker/Results integration remain pending. An
accepted client operation is neither an execution nor a scientific approval.

The [client aggregate and exact source scopes](../../docs/evidence/20261015-ownership-client/public/README.md)
record the focused transport/operation tests, full race and repository regression.
Temporary unit fixture checks do not establish a retained client acceptance or
a newly compiled standalone client command.

## Checks

Run in this module:

```sh
go test -count=1 ./...
go vet ./...
go test -race -count=1 ./...
```

Tests use synthetic local certificates and real verified TLS, negative reads
before authentication, exact and excess ciphertext boundaries, cancellation,
time windows, strict JSON, private-key mismatch, signature-algorithm negatives
and AES-GCM AAD rebinding rejection. They do not exercise the deployed service
path or demonstrate scientific approval.

The service acceptance has a separate Linux opt-in. From repository root:

```sh
install -d -m 700 .biozero
evidence_root=$(mktemp -d "$PWD/.biozero/authority-http-XXXXXXXX")
(
  cd biozero/services/ownership-authority
  BIOZERO_AUTHORITY_HTTP_ACCEPTANCE_ROOT="$evidence_root" \
    go test -race -count=1 -v \
    -run '^(TestAuthorityHTTPProcessAcceptance|TestAuthorityHTTPProcessHelper)$' ./...
)
```

It uses the real service API in owned test processes with transport instrumentation:
verify signed commit before a delegated TCP Write, apply an actual client RST,
observe actual write failure/latch, reject another live writer, SIGKILL/Wait the
original, then recover identical history in a new process. Owner GET and
metadata-only Finalize succeed, the other leaf is denied, and SIGTERM exits
cleanly. It retains keys, trusted scope and pending/accepted evidence privately;
it never cleans or retries that history. This synthetic fixture reuses a dual-EKU
server/client leaf; it does not prove separate deployed client/server key custody.
The standalone compiled CLI has a separately scoped build/start/restart receipt.

The exported-API process fixture is an explicit Linux opt-in. From repository
root, create a new private destination for each run:

```sh
install -d -m 700 .biozero
evidence_root=$(mktemp -d "$PWD/.biozero/ownership-store-XXXXXXXX")
(
  cd biozero/services/ownership-authority
  BIOZERO_OWNERSHIP_ACCEPTANCE_ROOT="$evidence_root" \
    go test -race -count=1 -v \
    -run '^(TestOwnedStoreProcessAcceptance|TestOwnedStoreChild)$' ./...
)
```

It creates synthetic credentials, establishes actual verified mTLS in each
process, applies SIGKILL only to its own live children and verifies WaitStatus
before cold readback. The two cases cover death after durable acceptance and
death inside the first body Read. The accepted record/charges remain identical;
reading remains pending and blocks Open. It compares the physical ledger signature
and all Store-file hashes. The helper's parent test skips while children execute
it explicitly. Without the opt-in, both external entry tests skip. Evidence,
including synthetic private keys and pending Store history, stays in the private
destination; the fixture never deletes or retries that history. This is a Store
process test, not a running authority endpoint or a failed network ACK write.

## Owner delivery adapter

The [owner delivery contract](../../docs/security/ownership-delivery-contract.md)
describes the separate charged ingress spool and client delivery journal.
`ClientOperation.AcceptedBundle` exports only a reverified accepted encrypted
bundle. `ClientDelivery` retains its own ciphertext and append-only intent before
its sole POST; recovery is a known-job GET. `OwnerIngressStore` verifies signed
acceptance and the actual owner leaf before reading ciphertext, retains full
charges after rejection and never adopts pending history. The upload service's
receipt is transport-only. The new CLI/API do not make the existing worker,
broker, Results or gateway ownership-aware; those remain separate gates.

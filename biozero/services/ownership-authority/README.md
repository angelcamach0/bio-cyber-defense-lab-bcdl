# Authenticated ownership protocol library

This standard-library Go package (`biozero/ownership-authority`, package
`ownership`) implements the cryptographic foundation of
[ADR 004](../../docs/decisions/004-authenticated-ownership.md). It does not run a
server, persist reservations or ownership records, or change existing services.
The current upload/results/worker path does not acquire immutable ownership by
importing or testing this module.

## Public API and trust boundary

1. A future authority authenticates a real server-side mTLS connection and calls
   `PrincipalFromTLS`. It requires a completed handshake, a verified chain whose
   leaf DER equals the peer leaf, and an RSA 2048–4096-bit client-auth leaf with
   exponent 65537 and digital-signature usage. The credential is SHA256 of the
   actual leaf DER; CN and serial are not ownership keys. `Principal` has private
   fields and exposes `CredentialSHA256()` and `CommonName()` getters. Supplying
   fabricated `tls.ConnectionState` or a permissive TLS verifier is outside the
   authenticated transport boundary; the authority must configure real chain
   validation and certificate policy itself.
2. After durable reservation, the future authority calls
   `SignChallenge(ed25519PrivateKey, pin, principal, ChallengeInput)` and
   `MarshalChallenge`. This library does not perform that reservation. The
   authority, never upload metadata, must generate a fresh unpredictable nonce
   and job ID and enforce single use in its future store.
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
reader errors, paths or secret values. No ciphertext framing format or OAEP label
is established by this component; those integration contracts remain explicit
future work.

## Acceptance time and remaining stateful work

`now` must come from the authority's trusted clock, never from request metadata.
Verification accepts `issued_at <= now < expires_at`. Finalize also counts
elapsed processing/read time and rejects crossing expiry. A generic `io.Reader`
can block inside `Read`; context checks between reads cannot interrupt that
call. Future ingress needs its own deadlines and verified regular read-only file
descriptors/provenance. A reader returning zero bytes without an error is rejected
as nonprogress rather than retried forever.

The five-minute window applies to reserve-to-finalize acceptance. A future
authority store must durably record an authoritative `acceptedAt` within that
window, then bind its accepted record to the verified content. Historical
execution/results must validate that durable acceptance and signatures rather
than expire accepted work retroactively or accept a historical clock supplied
by the caller. This library provides neither that store nor a historical-record
verification API.

Pending integration includes durable reserve-before-body quotas, nonce/job
uniqueness, atomic single-use finalize, signed durable ownership records,
separate authority-key custody, CLI/gateway authority ingress, envelope/AAD
enforcement in the worker/broker, result authorization from authoritative records,
revocation/rotation policy and explicit historical migration without adoption.
Repeated pure Finalize calls are possible: no quota, replay-prevention,
restart-safety, deployment isolation or full TM02 closure is claimed here.

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

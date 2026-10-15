# Durable owner-v1 client contract

This component is a shared client for the ownership authority. Its original
verification scope below covers authority operations, encryption and local
history; the subsequent [owner delivery adapter](ownership-delivery-contract.md)
has a separate scope and preserves the signed job ID on an explicitly selected
upload route. The historical upload path still assigns a different ID. Neither
mutable spool nor transport ACK supplies owner authority, execution or result
release. Gateway, worker, broker and Results integration remain TM02 gates.

## Trusted configuration and private state

`AuthorityClientConfig` supplies an explicit HTTPS origin, verified client
certificate/private key, CA roots, optional server hostname and external authority
pin/Store scope. The transport copies its key/certificate/pin/roots, requires TLS
1.3, rejects redirects and uses one HTTP/1.1 request per connection. It uses the
configured environment proxy policy and normal hostname/chain validation. Each
method makes one request; it has no retry loop or legacy fallback. Errors expose
stable codes rather than URLs, key/certificate data or underlying IO messages.

`ClientOperationConfig` adds one absolute canonical workspace, the original name
and a separately trusted worker RSA encryption public key. The operation binds its
journal to origin/hostname, authority/key/mode/profile, external Store/policy,
exact client leaf, encryption key and filename. TLS roots are trusted caller
configuration; the journal does not enroll a CA or prove how that configuration
was provisioned. Client and encryption keys have different roles. No authority
private key or worker decryption key belongs in a client workspace.

The workspace is exclusively created as current-UID 0700 with 0600 regular,
single-link, no-follow files and a lifetime flock. Open requires the same trusted
context. It rejects unknown names, missing phases, malformed chains, changed
signatures/bindings/body and retained transaction markers without repair. Live
preflight checks the anchored directory/lock and every retained file hash. The
journal is trusted client state, not protection against host/root or a writer
with that client's UID. It is separate from the upload-writable spool.

## Explicit transitions

| Local phase | Durable facts | Permitted next action |
| --- | --- | --- |
| intent | Original unpredictable request ID and trusted-context hash | Explicit Reserve with that exact ID/name; Open does no network IO |
| reserved | Original raw signed challenge | Prepare once with verified fresh challenge and local leaf |
| prepared | Original ciphertext, decoded OAEP envelope and signed manifest | Explicit Finalize after publishing its intent |
| finalizing | Original prepared bytes plus durable finalize phase | Recover by owner Get only; no ciphertext resend |
| accepted | Verified historical acceptance matching every retained fact | Readback; subsequent execution integration remains pending |

The five small phase records are append-only and hash the preceding record.
`client.intent` is synced before each phase publication. `prepare.intent` is
additionally synced before generating symmetric material; partial encryption is
never recreated or adopted automatically. Ciphertext/file sync, phase sync and
directory sync precede marker retirement. A failed write/sync/close retains a
sticky live lock through a raw CLOEXEC descriptor, including loss of Go handles;
Close cannot release uncertain authority. Actual process death releases that
lock. As with Store, a crash after marker unlink but failed parent sync need not
universally preserve the marker. Antirollback and automatic reconciliation are
not implemented.

A lost Reserve response leaves the original durable ID. Recovery requires an
explicit Reserve action with that same ID; it cannot create a fresh ID in the
workspace. A lost Finalize response leaves finalizing, even when the authority
committed. Recover only queries the known job. Accepted facts are compared with
the original challenge, manifest, exact leaf, body hash/length and envelope hash
before publishing accepted. A directly received Finalize retains its raw acceptance;
Get recovery retains the canonical serialization of the verified signed object,
not unknown bytes of a lost response. Reserved, reading, rejected, unavailable or unknown
responses preserve local state and require an explicit later operator decision.
No method refunds a reservation, deletes history, reencrypts unknown input or
submits execution automatically. A healthy Close permits reopening this same
history; opening it never advances a remote operation.

## Cryptographic framing and bounds

Owner-v1 body bytes are AES-256-GCM ciphertext followed by the 16-byte tag, without
a nonce prefix. The decoded RSA-OAEP-SHA256 envelope contains exactly key[32] then
nonce[12], with an empty OAEP label. Its SHA256 is over those actual RSA ciphertext
bytes, not hex/base64 text. The worker encryption public key is provisioned
separately; the authority TLS server certificate is not an encryption enrollment
channel. The exact verified canonical challenge context is mandatory GCM AAD.
The same RSA key as the local mTLS leaf signs the manifest with PSS SHA256 and
32-byte salt. There is no shared demo signer or nil-AAD fallback.

EncryptForChallenge verifies the pin, local leaf, window at its explicit caller
time, name/context and key match before encryption. Finalize independently checks
freshness using the transport's real clock before sending. DecryptAcceptedPayload requires an opaque
VerifiedAcceptance, compares actual ciphertext and decoded envelope hash/length
before OAEP, then opens GCM with the exact accepted AAD. It is a crypto helper,
not execution admission or scientific release: worker/broker must still match the
trusted job/profile and protect receipt-based projection. A second client can
sign copied ciphertext under its own valid challenge and obtain acceptance of
those measured bytes; opening that ciphertext with the second context must fail
GCM before any execution.

Plaintext is at most 25 MiB minus the GCM tag; ciphertext is at most 25 MiB. The
client buffers bounded payload bytes in memory. Finalize verifies metadata before
reading its input, reads actual declared bytes plus at most one excess byte,
requires EOF/hash, and sends known-length framing once. A generic Reader cannot
be interrupted while inside Read; context checks between chunks are not a hard
kernel deadline. HTTP requests have a 45-second total budget, bounded handshakes,
response headers and bodies. A workspace retains at most five 96-KiB phase
records, one ciphertext, an empty lock and short transaction markers. These are
application limits, not a filesystem reservation or a deployed sandbox.

## Remaining integration gates

Direct CLI/gateway operations need this durable lifecycle before networking;
the old upload ID and post-upload gateway persistence are not compatible with it.
The transport still needs a reviewed deployed endpoint: the current authority
listens only on loopback, so another container cannot reach it through ordinary
service DNS. Separate UIDs/mounts, authority-only signing state, client-only
individual keys and worker-only decryption custody require actual deployment
observations. Then upload must transport the authoritative job unchanged, worker
and broker must verify accepted envelope/AAD before execution, and Results must
project protected receipts after immutable-owner authorization. Existing direct
and gateway substitution negatives must pass on that integrated path.

## Verified component scope

Focused transport tests pass eight principal tests and 39 subcases over actual
local TLS/mTLS. Focused payload/operation tests pass eleven principal tests and
45 subcases, with the process helper skipped in its parent. Three own children
are SIGKILLed and joined with checked WaitStatus: prepared state reopens without
networking, finalizing recovers only by Get, and uncertain marker history rejects
cold Open. GC actually closes both original os.File descriptors while the raw
CLOEXEC flock still excludes another writer. Response-loss fixtures distinguish
loss before forwarding from downstream loss after a successful authority response;
they do not simulate an authority ACK Write failure or relay production identity.

The copied-ciphertext negative exercises the pure measured Finalize/signature
boundary; it is separate from durable Store or HTTP acceptance.

The complete module race run passes 69 principal tests and 318 subcases plus four
CLI tests. Five ownership opt-in/helper tests and one CLI helper are skipped in
that default scope. Its 26 Go/module inputs remain identical throughout. These
are unit/service/process fixtures: physical files are checked during tests, then
temporary directories are cleaned by the test framework. Exact source pins and captured stdout/stderr are retained as execution receipts;
the public export contains aggregates and hashes. No retained acceptance workspace, newly
built standalone CLI, deployed key isolation or integrated pipeline follows.
The earlier transport prototype reused a quota bucket and could hide the wrong-pin
gate; its retained source and transcript-only limitation precede the corrected,
originally captured isolated-fixture run. No failed/weaker evidence is relabeled.

# Durable ownership Store: component evidence

Date: 2026-10-15 UTC. Base commit: af24c9e. This reviewed aggregate covers the
Linux ownership library and historical acceptance, not an authority service or
the existing upload/worker/broker/Results route. TM02 stays open.

## Implemented and checked

Reserve persists full principal/global charges before a body, generates job/nonce
and binds the exact mTLS leaf. Finalize persists reading before the first Read,
measures actual ciphertext and commits a signed acceptance before returning it.
Exact accepted replay returns the original bytes without another read, signature
or freshness decision. Signed historical verification checks the external Store
scope, original leaf/challenge/manifest and every binding field.

| Check | Observed result |
| --- | --- |
| GC-corrected complete module | 34 principal tests / 176 subcases; ordinary and race passed, vet passed, zero failures/skips |
| Raw-lock lifetime | 11 subprocess observations per suite: all three original os.File descriptors actually closed with EBADF; distinct raw CLOEXEC lock still live and second writer denied |
| Original independent exported-API process test | One principal / two cases passed; helper parent skipped and explicitly executed in children |
| Published external reproduction | Default module 34/176 passed, two explicit opt-ins skipped; vet passed; selected process fixture under race passed one principal / two cases, helper parent skipped |
| Full repository regression | 294 Python cases: 292 passed, two kernel opt-ins skipped; nine Go modules uncached tests/vet passed |
| Independent retained-evidence review | Physical before/after history verified and 15 additional cryptographic checks passed using public keys only |

Both process cases establish actual verified HTTPS/mTLS with the same client
credentials across processes and use SIGKILL only on their own children. Actual
WaitStatus proves each death before cold readback. The accepted case preserves
byte-identical acceptance, denies the other owner and performs zero Reader calls
on retry. The reading case retains pending history and refuses Open unchanged.
Each physical ledger retains one full 131,136-byte charge (64 body plus 131,072
metadata), the original leaf fingerprint and all Store-file hashes. The replay
passes a trusted test-time argument 24 hours ahead; it does not wait 24 hours.

The accepted process is killed after Store Finalize has returned: this proves
durable acceptance and cold replay, not a failed HTTP/network ACK write. The
body is synthetic opaque data with a declared envelope hash; no OAEP unwrap,
GCM decryption, genomic analysis or protected-service integration occurs here.

## Exact source and preserved weaker evidence

The original external run and make used the same unchanged 430-file snapshot.
An independent reviewer found that its older GC test retained a deferred Store
receiver; that assertion could not prove last-reference loss. Its original
receipt and source remain preserved, without rewriting the verdict into stronger
evidence. A test-only correction then passed complete module ordinary/race/vet
with 12 module inputs unchanged during the checks. The public external fixture
was added afterward and passed its own module/vet and opt-in race acceptance
with 13 module inputs unchanged. Production Go was identical across these runs.

`test-source-pins.json` records the original 430-file snapshot, both later module
snapshots and all six changes before this bundle: four documents, the GC test
correction and the new public reproduction fixture. This four-file bundle was
added after those checks. No result silently approves a later source snapshot.

The independent cryptographic audit initially hit Python 3.9's fractional-time
parser limitation. Its audit parser was corrected to integer seconds/nanoseconds;
neither original history nor acceptance was rerun. Saved audit sources/outputs
were reconstructed from the original tool transcript afterward and are labeled
as such, not original execution-time stdout. Original test JSON events, make
logs and physical process history have their own retained hashes.

## Reproduction and remaining gates

Run ordinary module test/vet/race as described in the
[library contract](../../../../services/ownership-authority/README.md). Its
exported-API Linux opt-in command creates a new private evidence directory and
executes the actual mTLS/process-death fixture in
`store_external_linux_test.go`. Preserve that directory: it includes synthetic
private keys and pending history and must not be committed as public evidence.
All public files here are aggregate verdicts, technical source paths and hashes.

The Store uses externally pinned genesis/policy and signed bounded transactions;
unknown or pending history is never adopted, retried, refunded or deleted. Sticky
live failures retain the raw flock until actual process exit. Intent unlink
followed by failed parent sync need not preserve an intent across a later crash;
universal cold rejection at that boundary is not established. Acceptance time is
the verified decision, followed by signing/commit; no before-expiry commit claim.

Next gates remain authority ingress and separate key custody, direct/gateway
clients, actual envelope/AAD verification in worker/broker, protected receipt-based
release and all integrated substitution/fault negatives. No antirollback,
revocation, migration, hostile-host defense or scientific approval follows. No
retained service/image artifacts were rebuilt, and no Docker acceptance, model
execution or dataset acquisition ran. Go checks compile test binaries and
temporary service fixtures; this is distinct from building retained runtime
artifacts for the protected route.

Validate this allowlist with `sha256sum -c SHA256SUMS` from this directory.

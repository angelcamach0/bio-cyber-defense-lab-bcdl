# Ownership HTTPS/mTLS authority: local component evidence

The authority now exposes durable Reserve, bounded streaming Finalize and owner-only
readback through a separate TLS 1.3 service. Startup uses pinned private assets and
an external genesis scope; it cannot silently initialize or adopt existing history.
See the [service contract and reproduction commands](../../../../services/ownership-authority/README.md),
[ADR 004](../../../decisions/004-authenticated-ownership.md) and
[current integration status](../../../STATUS.md).

`summary.json` contains reviewed aggregates and original private receipt hashes.
`test-source-pins.json` distinguishes the 19-input full module/race/vet snapshot,
the later test-only 20-input service-process/CLI snapshot and the 442-file final
make snapshot. Production Go is identical across the latter checks. Four technical
documents and these four public files were added/updated after runtime acceptance.

The corrected HTTP tests pass 8 principal/26 subcases. The initial helper's absolute
URL caused three metadata failures and shadowed other negative controls; its source,
failed output and diagnostic output remain retained. Correction used a relative
server target and a valid control. Earlier engineering focused checks have only
tool-transcript evidence; the final module checks preserve actual captured files.

The process acceptance verifies a signed commit before an actual TCP RST and an
actual delegated Write error, sticky failure, repeated Shutdown denial and live
writer exclusion. After confirmed owned SIGKILL, a new process returns the original
owner acceptance without resending ciphertext, denies the other leaf and exits
cleanly on SIGTERM. Its transport instrumentation and service API test-process
scope are explicit. The separate retained ARM64 CLI build passes fresh/repeated
genesis exits 0/1 and two serving restarts with unchanged original history/exits 0/0,
using an independent Python TLS/mTLS driver. Public-key-only independent readback
passes 39 controls without rerunning acceptance. Final make passes 294 Python
cases (292 pass, two kernel opt-ins skipped) and nine Go modules test/vet.

The synthetic fixture shares a dual-EKU server/client leaf; deployed key separation
is not proven. Application Reader gates do not exclude socket/TLS buffering or
net/http final drain. Write/Flush success does not establish peer receipt. Actual
OAEP-envelope comparison and GCM AAD enforcement remain downstream requirements.
Existing client/gateway/worker/broker/Results routes remain unchanged, deployed
key/mount isolation is pending and TM02 stays open. No Docker/model/dataset work,
automatic repair/refund/retry, antirollback or scientific approval is claimed.

Private records, runtime identifiers, credential material and raw acceptance data
are excluded. Verify these public files from this directory:

```sh
sha256sum -c SHA256SUMS
```

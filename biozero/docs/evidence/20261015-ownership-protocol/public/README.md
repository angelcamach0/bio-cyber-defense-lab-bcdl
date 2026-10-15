# Authenticated ownership protocol component

This is an unintegrated library milestone, not a repair of the existing protected
service route or completion of TM02. See [ADR 004](../../../decisions/004-authenticated-ownership.md)
and the [library contract and commands](../../../../services/ownership-authority/README.md).

| Observed scope | Result |
| --- | --- |
| Repository make | 294 Python discovered: 292 passed, two kernel opt-ins skipped; nine Go modules uncached test/vet passed |
| New library with race detection | 10 top-level functions and 72 subcases passed; complete original JSON events retained |
| Independent caller of exported API | One top-level function and 12 subcases passed, with real HTTPS/mTLS |
| Current Results API baseline | Two weaknesses reproduced; zero existing-service repairs demonstrated |

The library verifies a pinned Ed25519 challenge, exact mTLS client leaf and
RSA-PSS client manifest, derives canonical owner/job/nonce/profile AAD, then
measures actual bounded ciphertext before returning binding data. It rejects
invalid identity/signature/pin/time/JSON before the first input read. Its own
unit tests include exact and excess ciphertext, key mismatch, parser and PSS
algorithm negatives, time/cancellation and AAD changes.

The independent caller establishes actual TLS client identities outside the
package and exercises only exported APIs. A valid owner finalizes and decrypts
its input. A second valid client can sign a new manifest over copied ciphertext
and Finalize can authenticate that manifest and measure those bytes. Actual
AES-GCM Open then rejects them under the second job's AAD and with omitted AAD;
the original AAD decrypts exact original bytes. This demonstrates why the worker
must enforce AAD, not just validate a client signature. Its envelope hash is a
placeholder declaration, not an actual OAEP unwrap or filesystem-descriptor test.

A separate private synthetic fixture copied exact current Results API sources
and made real HTTPS/mTLS requests. Changing owner fields in mutable job metadata
changed B's response from 403 to 200 while the result bytes remained untouched.
Relabeling a copied result to another job also returned its private synthetic
marker despite the original result serial/hash. These successful reproductions
prove current weaknesses, not security rejection gates. No remote attack,
genomic analysis or full ciphertext replay through a worker ran.

The test snapshot contains 420 files based on 77a4e03 with the new library and
ADR. It stayed unchanged through final make and the source-specific checks.
STATUS, the requirement matrix and this bundle were written afterward. Existing
upload/results/worker/broker production files are unchanged and do not consume
this protocol. Existing binary/service receipts retain their old scopes.

The make child exited 0 and wrote source-after and its summary. Its outer receipt
wrapper then exited 1 while recording a handle: it reused a Path variable and
accessed .pid. The exception and original successful check log/summary are
preserved separately; no tests were rerun to hide it. An earlier writer receipt
recorded observed test/race/vet results without original stdout; the later race
receipt retains complete original events and exact source pins.

Pending work includes durable pre-body reservation and single-use Finalize,
authoritative accepted records and historical validation, isolated key/store
custody, direct/gateway client encryption, worker/broker binding enforcement and
result delivery from protected confirmed receipts. Legacy ownership is never
adopted from mutable JSON. No complete ownership, deployment, production, image
reproducibility, scientific or biological approval follows from this library.

All public fields are reviewed aggregates and hashes. Certificates, keys,
challenge/manifest values, runtime identifiers, raw data/results and private paths
remain private. Verify this bundle with `sha256sum -c SHA256SUMS` in this directory.

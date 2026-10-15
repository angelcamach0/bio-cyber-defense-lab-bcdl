# Durable shared ownership client: component evidence

The new one-call HTTPS/mTLS transport and private append-only operation workspace
persist intent before Reserve/Finalize and recover by querying the known job.
Payload helpers define actual OAEP key32/nonce12, empty label and mandatory signed
GCM AAD. See the [client contract](../../../security/ownership-client-contract.md),
[service API](../../../../services/ownership-authority/README.md) and
[integration status](../../../STATUS.md).

Focused transport passes 8 principal/39 subcases; payload/operation passes
11 principal/45 subcases with one parent helper skipped. Three owned SIGKILL cases
verify WaitStatus before prepared readback, Get-only recovery or uncertain-history
rejection. GC closes two original Go file descriptors while the raw CLOEXEC flock
still excludes another writer. The copied-ciphertext negative uses pure measured
Finalize/signature verification, not durable Store/HTTP acceptance; a valid second
client signs copied bytes, acceptance verifies, and GCM under its AAD rejects.

The complete race suite passes 69 principal/318 subcases plus four CLI tests;
five ownership opt-in/helper tests and one CLI helper skip. Final make passes
294 Python cases (292 pass/two kernel opt-ins skipped) and nine Go modules test/vet.
Source pins distinguish the transport's 26-file inventory (includes README and
excludes the later operation test), the two 26-Go/module snapshots and 453-file
make snapshot. The operation-focused to race delta is one explanatory Go comment.
Five technical documentation edits and these four exports follow final make;
no runtime Go changed afterward. The initial quota-shadowed prototype has only
source copies, a limitation note and tool-transcript execution; it is not relabeled
as original captured subprocess evidence.

These are temporary unit/service/process fixtures. Their physical histories are
checked during execution and removed by test-framework cleanup. Captured logs,
exact pins and byte-matched source copies remain private. They are not retained
client acceptance workspaces or standalone client CLI runs. Downstream loss after
a successful authority response is distinct from an authority ACK Write failure;
the fixed-identity mTLS test proxy is not a production identity relay. The shared
dual-EKU fixture does not prove deployed client/server key separation. Prepare
uses caller time; fresh Finalize uses the actual transport clock. Get recovery
preserves canonical verified acceptance rather than unknown lost response bytes.

Direct CLI/gateway adapters, authoritative upload job identity, deployed network/
key/mount isolation, worker/broker enforcement and protected Results projection
remain pending. No retained CLI build, Docker/model/dataset execution, scientific
approval or TM02 closure follows. Public files contain aggregates, source pins and
receipt hashes, without keys, raw records, runtime identifiers or private paths.

```sh
sha256sum -c SHA256SUMS
```

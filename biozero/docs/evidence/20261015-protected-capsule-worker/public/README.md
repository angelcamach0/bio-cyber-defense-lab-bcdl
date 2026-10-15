# Protected capsule-worker acceptance

The protected worker now verifies signed encrypted input before bounded plaintext
staging and v2 broker submission. Actual native acceptance passed **25/25** cases;
three-service Compose passed **30/30**. Both execute pipeline, evaluator and detection
in the **native capsule provider**. Independent retained-state readback passed
**78** native checks and **35** Compose checks.

Each environment ran two valid synthetic inputs: TP3/FP0/FN0, precision/recall1,
1,171mapped reads and configured detection0.7/medium. Per-run observed/evaluated/
retained VCF hashes match; repeated normalized allele callsets match. VCF headers
contain runtime paths, so repeated VCF files are not asserted byte-identical.
Invalid FASTQ remains failed/withheld without scientific evaluation. Its separate
analysis capture may execute; that does not approve scientific release.

The checks include actual individual mTLS, signature/decryption, original-ciphertext
versus processed-plaintext provenance, nonowner denial despite spoofed headers,
unsigned rejection before custody, receipt/proof/physical-artifact consistency,
clean worker stop and lost-publication recovery using unchanged leases/artifacts/
charges. Native Store charge is47,545bytes including its header; Compose47,328bytes.
Their record charges are43,449and43,232bytes respectively, plus4,096bytes each
for the Store header reserve.
Both retain3slots. All fixture processes are terminal; the three Compose containers
are stopped and preserved.

`summary.json` contains reviewed aggregates, fixed case verdicts and binary/profile/
private-receipt digests. `runtime-source-pins.json` records the387-file runtime
snapshot based on333995f with uncommitted integration changes. The executable
builds record that dirty VCS state; their hashes do not imply bitwise rebuild
reproducibility. This README, status edits and aggregate files were added after
acceptance and are not retroactively part of that runtime snapshot. `SHA256SUMS`
checks the published aggregate files. Raw results, DNA, targets, job/lease IDs,
credentials, PKI and full receipts remain private.

Earlier failures remain preserved: protected native startup initially failed at
tmpfs mounting through a parent-namespace descriptor; child-namespace reopening
with identity checks fixed that cause. Initial unit child fixtures needed an
explicit legacy selector after capsule became the default. Independent verifiers'
incorrect assumptions about raw versus projected DTOs, invalid-input analysis and
ciphertext names were corrected in new verification receipts; original execution
evidence was not changed or rerun to repair those assertions.

Reproduce using [the native harness](../../../../infra/native/run_capsule_worker.py)
and [Compose prerequisites/invocation](../../../../infra/compose/README-capsule-worker.md).
Use fresh private run directories and existing permitted tools. The Compose run
reused the exact cached image in summary.json and the six prebuilt binaries from
the native run; no image, model or dataset download/build occurred.

Limits: native execution trusts host filesystem/dependencies/same-UID writers.
Compose mounts and network restrictions have their separately measured scope;
API bridge egress is not denied. This acceptance does not establish the protected
Docker capsule-provider route, actual crash/cancel/lost-ACK reconciliation, image
build/dependency/license closure, TM02 immutable ownership, principal retention/
quotas, attestation, production deployment or broader scientific validity. See
[the remaining gates](../../../../docs/requirements-and-gates.md).

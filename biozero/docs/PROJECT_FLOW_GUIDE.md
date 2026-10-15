# BioZero project flow: implemented profile and remaining gates

Updated 2026-10-14. This guide describes the measured local synthetic profile.
The [requirements matrix](requirements-and-gates.md) preserves the wider
Notion roadmap and distinguishes implementation from proposed capabilities.

```mermaid
flowchart LR
  Browser[Reviewer browser] -->|HTTPS session, Origin and CSRF| Gateway[Reviewer gateway]
  Gateway -->|Own mTLS identity, prepared signed/encrypted input| Upload[Upload API]
  CLI[Uploader CLI A or B] -->|Individual mTLS, signed/encrypted input| Upload
  Upload --> Admission[Durable pending and retained input admission]
  Admission --> Jobs[Durable job and encrypted upload files]
  Jobs --> Worker[Single worker: verify digest/signature, decrypt]
  Worker -->|Only accepted input| Pipeline[FASTQ validation and explicit stats/variants pipeline]
  Pipeline --> Evaluator[Independent synthetic truth evaluator]
  Evaluator --> Reports[Terminal execution and separate scientific release]
  Reports --> Results[Results API: certificate ownership]
  Results -->|Own result through mTLS| Gateway
  Results --> CLI
  Gateway -->|Allowlisted report| Browser
  Reports -->|Protected security rejection only| Outbox[Private durable event outbox]
  Outbox --> Relay[Separate verified HTTPS relay]
  Relay --> Responder[Authenticated durable simulation receipt]
  FutureSOC[Production SIEM and live containment: pending] -.-> Responder
```

## Input and identity

CLI clients use individual certificates. The reviewer gateway provisions separate
mTLS transports for each reviewer, with high-entropy invitation codes and opaque
session cookies. Sign-in requires the configured Origin, JSON and rate limiting;
authenticated state-changing requests also require a CSRF token.
The default catalog accepts only prepared synthetic experiments; arbitrary
uploads and command selection are outside that browser interface.

Protected mode requires complete TLS/mTLS configuration. Backend certificate CN
and serial identify a job owner; a caller-supplied client header does not change
ownership. CLI and gateway encrypt inputs for the worker and sign them with
fixture-held demo signing material. The worker verifies cryptography before
analysis: Upload API queue acceptance alone does not approve an input. Original
upload digests are preserved; derived digests are separate.

The locally accepted input gate accounts for global/principal pending and retained
inputs before reading their bodies; verified certificate CN selects that policy
bucket. Terminal jobs retain their charges. Ledger ambiguity fails closed rather
than reconstructing an empty baseline from mutable owner records. This is input
admission, not a full disk/retention quota. A failed publication across separate
bind mounts was preserved; mount-local staging now passes fresh native and
Compose acceptance. Policy is pinned, terminal processing retains charges and
legacy staging is not silently adopted. See STATUS and the
[admission contract](security/admission-contract.md) for source-specific gates.

## Processing and scientific release

The filesystem job store supports one worker. It validates integrity, signature
and encryption, decrypts into a per-job temporary workspace, and removes plaintext
after processing. The container profile additionally bounds its plaintext tmpfs;
native temporary files do not establish a kernel memory/storage cap.
The worker also caps command stdout/stderr and serialized results;
overflow cannot turn a valid JSON prefix into scientific approval. Tool artifact
sizes, total retained output/cache and general filesystem latency remain separate
resource gates.
Cancellation/deadlines stop its process groups; interrupted
work becomes an explicit failure on restart. Container/process isolation does
not demonstrate hardware-enclave attestation.

The pipeline validates FASTQ structure and runs an explicit mode. `stats` supplies
transport/statistics evidence. `variants` requires the configured reference,
minimap2, SAMtools and BCFtools plus their successful stages and artifacts.
Optional QC does not substitute for missing mandatory variant stages.

Execution states are `uploaded`, `running`, `succeeded`, `incomplete`, `rejected`,
`failed` and `timed_out`. Scientific release is independently `evaluated_passed`,
`withheld` or `unassessed`. A successful process alone cannot approve science.
Historical `processed` records remain incomplete until validated.

BZ-EXP-001 fixes a 6 kb reference, 1,171 reads and three expected SNPs. The
evaluator counts all normalized alleles and compares two executions with that
answer key. TP=3, FP=0, FN=0 and equal callsets establish only this synthetic
allele-presence result. Genotype, indel, WGS, biological and clinical accuracy
are separate questions.

## Results, browser and evidence

Results API and gateway enforce ownership. Typed public reports contain statuses,
stage codes, scientific counts and provenance; they exclude private paths, raw
diagnostics, signing records and arbitrary artifact URLs. The UI escapes text
and guards explicit A/logout/B transitions against old asynchronous callbacks.
Profiles share cookies across tabs; automatic identity synchronization of every
tab is not implemented. Simultaneous accounts require separate profiles.

Native acceptance passed ten assertions and was reproduced from another checkout.
Compose/Firefox passed 31 integration assertions and 23 browser checks, with zero
JavaScript errors. Hosted ARM CI separately passed unit/PKI/scientific/native
checks. See [STATUS](STATUS.md), [experiment001](experiments/001-variant-smoke.md)
and [reproduction commands](runbooks/reproduce.md) for exact dated receipts.

Share only reviewed `public/` bundles. Derived VCFs retain normalized allele
presence but omit sample names, paths, commands, genotypes and unevaluated fields.
Original VCFs, keys, invitations, cookies, profiles and diagnostics remain private.
Earlier raw exports contain local paths and must not be published. Checksums
identify the exact exported bytes.

## Runtime and roadmap

Observed: RHEL 9.8 ARM64, one CPU, about 5.45 GiB RAM. Measured containers run
non-root with read-only roots, dropped capabilities, limits and scoped keys.
Entry binds loopback; worker has no network. Normal API/gateway bridges do not
enforce egress denial. Oracle capacity/deployment remains unverified.

SCI01 loaded verified Sei-LLRA checkpoints and measured one synthetic pair.
Comparable FP32 was faster than QNNPACK; the current recomputation path has a
provisional economic no-go. SCI02 has implemented a real-window FP32 adapter with
fixed GM12878 ATAC-seq head aggregation. Ten-locus preflight and hundred-locus
biological evaluation require permitted data, explicit effect alleles, frozen
selection/splits and evidence. Operator tests and mutation controls do not
complete them. Disjoint windows alone do not remove linkage disequilibrium.

A small public Zenodo source has now been acquired and CRC-inspected within the
50 MiB budget: 297,308 descriptive caQTL rows, zero loci inferred. It is GRCh37 and
population-LCL evidence, while the frozen model protocol uses hg38/GM12878 tracks.
Normalization/build/REF/strand/peak/context and selection/splits remain pending;
the exact inaccessible Synapse table has not been replaced by an asserted copy.

ZeroResponder currently records simulation. SIEM ingestion, enforced response,
evolving adversary scenarios, production identity, HSM/KMS, encrypted results,
queue/claim/lease, hardware attestation and external deployment each require
explicit designs and demonstrated acceptance. Component names do not establish
those features.

The new native security handoff passed22 assertions (ten synthetic milestone plus
twelve SOC cases). The worker emits only allowlisted protected rejection codes;
its outbox has no network or responder secret. A separate relay verifies TLS,
request digest, target and explicit simulation flags. ZeroResponder requires
authentication, deduplicates identical requests across restart and refuses
conflicting IDs or failed persistence. It writes no effective action lists and
changes no firewall, certificate trust or running job. See
[STATUS](STATUS.md), [event contract](security/event-contract.md) and
[response decision](decisions/003-security-event-handoff.md) for scope and evidence.

Job/result metadata now has a [bounded reader/lifecycle contract](security/metadata-contract.md).
Unsafe or ambiguous records fail explicitly without bypassing ownership or
scientific release. Upload admission reserves the entire current state growth;
worker diagnostic copies in jobs are bounded, and results have their own serialized
size cap. Native53 and rebuilt
Compose30 acceptance are recorded in STATUS; those checks do not establish the
new retained-input implementation. Its pre-correction native 78 passed and Compose
failed after 10 checks. Corrected native 78 and four-service Compose 30 passed;
independent review approved the selected exports. This local record preceded
publication/new CI; consult the live PR for subsequent head/checks. Input accounting and
capture limits do not establish full artifact quotas, retention, immutable owner
provenance, queues/leases or general filesystem IO deadlines.

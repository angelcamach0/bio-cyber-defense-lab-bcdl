# BioZero implementation status

Updated 2026-10-14. Local branch: biozero/reproducible-milestone.
Base: b8731934fbe7c7dc00bf51fa978ce370361b3f74. First-milestone implementation commit:
a27221c6f2174ea9d116779fcd47c88f9794dddb, published in
[draft PR #21](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/pull/21).
No merge or deployment occurred. See the live PR for subsequent documentation commits.

Checkpoint, 2026-10-14 23:12 UTC: the reviewed 59-file source/aggregate snapshot is
published as [28918a9](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/commit/28918a96484dcb2a015c71540f853d29e34a9836).
[Its hosted ARM CI](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38651583022)
passed (job116151397770):231Python cases,229passed/two kernel skips, eight Go
test/vet modules, PKI, scientific repeat and78protected native assertions. Checkout
used merge ref e56751a6e481d29fc4f09546212567bcd802a01b into unchanged main. Hosted
CI did not execute the biological model, native capsule opt-ins, Compose or Firefox.

Subsequent local recovery/wire additions are separate from that CI snapshot. Four
actual native lifecycle cases/68assertions passed, also with the race detector:
cancel, timeout, PID1 death and keeper death. Immediate restart before observing
cleanup was denied by flock or unhealthy durable pending history; keeper loss
preserved executing/full charge without inventing proof/ACK. Actual Unix client
composition passed three-SNP science, storage/proof before reply, complete status
continuity and replay rejection. Independent reviews checked the receipts and
strengthened status/evaluator/custody assertions. Runtime files were unchanged.
The complete artifact-module race run with all three real opt-ins enabled passed
66top-level functions with subcases,8.928s; only the internal keeper subprocess
entry was skipped in the parent (it ran in its spawned keeper). Vet passed.
These new tests/docs await their own publication/CI at this recording; no model
was repeated and previous private failed/weaker receipts remain preserved.
See [native recovery](../services/artifact-executor/README-native-recovery.md)
and [Unix composition](../services/artifact-executor/README-native-unix.md).

Earlier local checkpoint, 2026-10-14 21:54:51 UTC: published head remains
`57013e76831184bcd6a1153b33ebb5acb40f1ec5`; the source/reference, pipeline-resource
and artifact-executor changes are uncommitted. The reviewed biological input pool
is frozen into10adapter/100evaluation cases. Actual offline adapter inference
completed10/10 with finite, repeat-identical outputs; this is runtime/input PASS,
not an accuracy approval. The receipt binder then passed Vale's independent
12-mutation review. Evaluation100 started offline at21:50UTC on the unchanged
cases; its completed result remains pending. Do not infer liveness from this
saved status: the private handoff records the actual execution handle for polling.
Fresh local checks passed197Python tests and eight Go module test/vet checks.
See [current biological evidence](experiments/004-kumasaka-prepool-evidence.md)
and [artifact implementation scope](security/artifact-workspace-contract.md).
Historical sections below retain earlier zero-case and pending-source snapshots;
they do not supersede this new checkpoint or approve unpublished source with old CI.

Subsequent authored checkpoint, 2026-10-14 22:15 UTC: the actual evaluation handle
was polled live, with65/100 inferred and the same source/ledger pins. The result
remains pending. New Unix listener/client, scoped-input registry and coordinator
files have independent static review; their Go tests/vet/race have not run while
the model measures on this one-CPU host. Vale found and Chiquis corrected three
FD/publication/ACK races before testing. Native/container providers and worker
integration still need implementation and acceptance. Nora also authored a public
biological receipt exporter with13 synthetic tests; Vale reviewed its privacy by
reading/AST, with no concrete escape found. Those tests and actual exports remain
pending. See [composition scope](../services/artifact-executor/README-coordinator.md)
and [biological export boundary](experiments/005-biological-evaluation.md).
The earlier197-Python/eight-Go execution scope does not cover these new additions.

Earlier executed checkpoint, 2026-10-14 22:49 UTC: the same evaluation handle
terminated successfully with100/100 actual biological cases, no rejected/pending
slots and identical repeats. Sign agreement61/100 and Spearman0.1840864086408641
are descriptive GBR-LCL-to-GM12878 transfer results, not an accuracy approval.
Controller2280.947s, worker peak939,098,112bytes; scientific feasibility remains
pending and the prior comparable economic no-go is unchanged. Nora independently
recomputed metrics, checked parents/privacy and reviewed both public receipts,
now integrated locally in [the regulatory directory](../research/regulatory).
No raw DNA/rows/vectors/weights were exported. Publication/new hosted CI is pending.

Fresh make test passed231Python test cases (229PASS, two kernel opt-ins skipped)
and eight Go module test/vet checks. The separate capsule opt-in run passed21/21
including both actual namespace cases, with zero skips. Unix/core/coordinator
race acceptance subsequently passed with the native opt-in enabled:64 top-level
functions with subcases,4.847s. Vet passed on the same source. Actual native
provider/store execution passed the synthetic three-SNP evaluation with four
retained exports and exact observed=evaluated=retained VCF. A first interpreter
failure and the failed FD-remapping harness are retained separately. See
[native scope and evidence](../services/artifact-executor/README-native.md).
Native/provider crash ordering, container provider, worker integration and fresh
protected native/Compose acceptance are still required. No production/artifact
quota, deployment or completed-project claim follows from these module tests.

This local acceptance record was written before publication, from a dirty
working tree above parent `2ad6b91c35e324cde7af882e4011fdffa9435805`. CI for that
committed parent does not validate this new source. See the live PR for subsequent
head/CI. Dated receipts below retain their exact source snapshots; a previous
green run does not approve a subsequent correction.

## Verified synthetic milestone

PR-01/02/03 and DOC-01 are implemented: protected entry, truthful states,
per-certificate ownership, cancellation, explicit pipeline modes, deterministic
three-SNP fixtures, independent evaluator, PKI, evidence and reproduction commands.
The current native run passed all ten assertions, including two valid runs,
A/B denial, original hashes, invalid FASTQ, no-certificate TLS rejection and
unsigned rejection before analysis. Evidence:
biozero/docs/evidence/20261014T150910-330979Z/public/.
This export retains the normalized allele set while omitting private paths,
sample names and unused annotations. Original VCFs are retained outside public/;
earlier raw VCF exports must not be published. Four new export tests passed.

The four-service reviewer container/browser run passed all 31 assertions: real signed and
encrypted submissions through reviewer sessions, exact synthetic science twice,
A/B denial by gateway and backend, Origin/CSRF, immutable original hashes, malformed
FASTQ withheld, restart/relogin recovery, cookie revocation and container controls.
Evidence: biozero/docs/evidence/20261014T150658-139518Z-reviewer-compose/public/.
Ten public-file checksums were checked. Real Firefox157 acceptance passed 23 checks,
including demoCA rejection/trust, desktop/mobile rendering, ownership, invalid
input and delayed history/view/recovery/start callbacks across A/logout/B. Zero
JavaScript errors; four allowlisted screenshots were visually inspected. Luci
reviewed the prior 30-case run; Vale independently verified 28/28 source hashes, 10/10 checksums and all
browser checks. Scope is explicit page transitions; automatic identity
synchronization across all tabs is not implemented.
Lía independently reproduced ten native assertions from a separate checkout:
20261014T150823-057533Z-independent-checkout/public/. Its provenance records
127 snapshot files/modes and the older manifest Unicode-filename limitation;
the current native runner uses NUL-delimited Git filenames.

TP=3, FP=0, FN=0; normalized callsets agree. This proves only the defined synthetic
allele-presence fixture, not genotype, indel, human-genome or clinical accuracy.
Execution status and scientific release are separate. An unassessed successful
execution does not approve science. Failed/missing/inconsistent evaluation is withheld.

At the earlier security/metadata checkpoint, the Python suites passed 81 tests across pipeline, benchmark, native/browser/SOC
contracts, supervisors, operator preflight, bounded download/control acquisition
and biological-adapter validation; test/vet passed in all seven Go modules. Vale also ran gateway and responder tests with
the race detector. PKI acceptance passed including gateway key scope. Current
container tools: Python 3.12.3, minimap2 2.26-r1175, samtools 1.19.2, bcftools 1.19.
Native tools remain fixed in the 39-package Linux ARM64 lock.

## Security event and simulation round

Atlas implemented a private no-network worker outbox for eight protected rejection
codes, with deterministic IDs, retained result timestamps, no-clobber publication
and terminal-result reconciliation without reexecuting analysis. Vale replaced
ZeroResponder's optional-auth/best-effort stub with mandatory authentication,
TLS off loopback, strict bounded JSON and complete durable simulation receipts.
Retries are idempotent across restart; changed content is a conflict. Storage
ambiguity latches health/admission unavailable. Twelve worker and eight responder
Go test functions plus subcases passed, including race checks.

Chiquis added the separate verified-HTTPS relay and native SOC acceptance. Luci
found and verified fixes for a numeric-zero false flag, missing parent-directory
fsync and a TLS test that could accept generic connection failures. All ten relay
tests passed. Native evidence `evidence/20261014T165148-344656Z/public/` passed
22 assertions: original ten synthetic checks plus twelve SOC checks for a real
unsigned-input rejection, outbox recovery, authentication/TLS, simulation receipt,
restart/replay, conflict, strict inputs and absence of effective action files.
This native receipt does not demonstrate container network isolation.

New four-service Compose evidence
`evidence/20261014T164550-385353Z-reviewer-compose/public/` passed 30 assertions,
including exact outbox mount scope and worker `network_mode: none`. Luci checked
27 source hashes and five checksums. It uses HTTP-session acceptance, without a
new browser run; the earlier Firefox receipt retains its own source scope. The
prior run `20261014T164413-651516Z-reviewer-compose` failed only the worker mount
verifier because the new mount was absent from its exact allowlist. That failure
is retained; the corrected verifier names the mount and its source explicitly.

Lía's optional responder container run
`evidence/20261014T165334-020175Z-soc-container/public/` passed13 assertions and
scoped cleanup. It built only ZeroResponder, bound the retained event to the
passed native parent/result, verified HTTPS/authentication, durable receipts and
exact replay across restart, minimal TLS keys, non-root/read-only/capability and
resource limits, and loopback publishing. It executed no pipeline/model. Seventeen
source hashes remained unchanged. This extends simulation acceptance to the real
optional profile; it still demonstrates no effective containment.

[Event contract](security/event-contract.md), [decision003](decisions/003-security-event-handoff.md)
and [SOC commands](../infra/soc/README.md) define the implemented boundary.
There is no effective quarantine, firewall action, certificate revocation,
production SIEM, long-running relay, exactly-once transaction or storage quota.
The secret authenticates possession, not an attested per-source identity. Shared
host/UID and storage remain trusted. Lía's [threat model](security/threat-model.md)
records admission/storage, mutable ownership metadata and unsafe legacy metadata
reads as next gates. Biological data access remains pending and unchanged.

## Bounded metadata and lifecycle round

Atlas and Vale replaced job/result reads with descriptor-anchored, no-follow,
regular-file reads: exact private mode/UID, 64 KiB jobs, 16 MiB results and strict
typed JSON. Both readers pass the same 54-case contract (6 valid, 48 invalid).
Worker recovery and event reconciliation use that boundary; authorization occurs
before opening results. Ancestor links, FIFOs, modes/UID, oversized files,
duplicates, aliases, trailing/deep JSON and legacy results have explicit tests.

Admission projects the entire current lifecycle before accepting a job. A raw
64 KiB admission guard alone was insufficient: worker state growth could make
the job unreadable. The corrected projection reserves the longest status, UTC
start timestamp and worst escaped diagnostics; a common worker writer caps only
the job's diagnostic copies, retaining full results and original upload fields.
Legacy jobs without reserve fail closed if a state update cannot fit.

Fresh native receipt `evidence/20261014T175423-175221Z/public/` passed 53 checks:
the original synthetic/SOC checks, exact projected 65,536-byte admission through
terminal rejection/B403, 65,537-byte rejection without orphan files, nine unsafe
metadata fixtures, continued health/new worker progress and exact cleanup.
The saved boundary job was 62,136 bytes. Its three rejection events came from
actual jobs; the fault fixtures did not fabricate events. Lía built the fault
harness; Luci independently checked 8 checksums, all 215 source hashes at review,
the real budget and private event/result linkage. Earlier 50/51-check receipts
remain historical and do not establish this lifecycle closure.

Rebuilt four-service receipt
`evidence/20261014T175423-180461Z-reviewer-compose/public/` passed 30 checks and
scoped cleanup. Its runtime inventory includes the new metadata/lifecycle files.
Luci verified all 30 runtime hashes and five checksums, compared exported DTOs
with retained private records and approved the 15 public native/Compose files.
This run did not repeat Firefox or the optional responder container. All 81 Python
tests and seven Go test/vet modules passed; Atlas also ran upload/worker race tests.
Separate root-only unit fixtures tested foreign UID rejection without running
services as root: `evidence/20261014T172630-977273Z-metadata-owner/public/`.

See the [metadata contract](security/metadata-contract.md) for exact limits.
This narrows TM-03 for job/result metadata, not every payload/key/config/artifact
read or arbitrary filesystem IO latency. TM-01 global admission/storage limits
and TM-02 authenticated immutable ownership remain next; shared host/UID trust,
queue/leases, effective response and biological gates are unchanged.

## Retained-input admission and bounded-output acceptance

Atlas implemented durable global/per-principal input admission shared by every
Upload API client, before body reads. Verified certificate CN selects the quota;
certificate renewal does not create a new principal bucket. The ledger retains
charges after terminal processing, restart, lost responses or gateway registry
loss. It reserves pending/retained payloads and metadata headroom, streams bounded
multipart input, holds an exclusive uploader-instance lock and fails closed on
ambiguous storage/accounting. It does not adopt legacy inputs by inventing an
empty baseline. The [admission contract](security/admission-contract.md) records
policy and the required persistence boundary. Defaults are 64 global/16 per-CN
retained jobs, 512 MiB global/128 MiB per-CN input charges, two global/one per-CN
active uploads and a 128 MiB free-space floor. Policy is pinned in the ledger;
changing it requires a reviewed migration, not resetting or rewriting charges.

Chiquis bounded worker pipeline/evaluator stdout to 1,048,576 bytes and stderr to
65,536 bytes, with cancellation of the process group on overflow. A passed JSON
prefix followed by excess bytes cannot approve science. Oversized serialized
results fall back to a small failed/withheld envelope within the existing
16,777,216-byte metadata-reader cap, retaining provenance and established crypto
flags. These limits cover command capture/result serialization; SAM/BAM/BCF/VCF,
reference copies, cache and total retained output still need storage controls.
The Python wrapper's own tool capture and optional alignment's total SAM/target
map size are also outside these worker-boundary capture limits.

Pre-correction native receipt `evidence/20261014T190933-375408Z/public/` passed
78 assertions, including 15 retained-input admission and 10 excessive-output
cases in addition to scientific/SOC/metadata acceptance. The run records dirty
parent `2ad6b91c...`. Local `make test` also passed 86 Python tests and test/vet
for seven Go modules. These are evidence for that candidate, not a later fix.
Luci independently approved that native bundle's 11 public files and 10 checksums.
The original snapshot is retained separately from the corrected acceptance below.

Four-service Compose receipt
`evidence/20261014T190933-378316Z-reviewer-compose/public/` failed after its first
10 checks with `prepared_run_submission_failed`; scoped cleanup passed. Publication
returned `EXDEV` from admission staging into uploads/jobs mounted as separate bind
mounts, despite matching device IDs. Atlas's correction stages payloads under
uploads and metadata under jobs so each no-clobber hard link stays inside its
own mount; admission retains only its ledger/instance lock. No extra mount or
payload duplication was added. Legacy admission staging fails closed without
silent adoption. Preserve the failed receipt. Corrected source needs fresh
native/Compose hashes and acceptance; this failure is not an authorization or
scientific PASS.

Corrected native receipt `evidence/20261014T192150-539678Z/public/` passed all
78 checks. Rebuilt four-service receipt
`evidence/20261014T192150-561120Z-reviewer-compose/public/` passed 30 checks and
scoped cleanup, including actual gateway submissions/scientific release and the
exact admission/key/data mount scope. Local `make test` passed 86 Python tests
and seven Go test/vet modules for this corrected source. Atlas's upload race test
passed; a separate real three-bind-mount publication/restart regression is retained
at `evidence/20261014T192234-593374Z-admission-mount/public/` with eight reviewed
source/test hashes. That mount regression did not run TLS, inference or science.
The failed Compose and pre-correction native receipts remain unchanged.
Luci's final independent review approved 32 selected public exports: 19 fresh,
two failed-Compose and 11 historical-native files. The full native inventory had
246 hashes with seven differences confined to documentation; executed sources
matched. Compose matched 34/34 runtime hashes and five checksums. No fresh browser or regulatory
model/checkpoint run was performed in this correction round.

These are local acceptance receipts for the dirty parent2ad snapshot. At this
record's writing, publication and new hosted CI for the reviewed source had not
yet occurred; use the live PR for later head/checks. CI for parent2ad cannot be
relabeled as CI for these changes.

TM-01 is split into input admission/command-output subgates and still-pending
artifact/result/event/receipt/cache disk budgets and retention. Free-space checks
are sensors, not a filesystem quota. TM-02 immutable authenticated ownership,
queue/leases, multiple workers, effective response and external deployment are
not completed by this input/capture acceptance.

## Actual runtime and limits

Observed: RHEL 9.8 aarch64, one CPU, about 5.45 GiB host RAM, Docker 29.9.0.
All four images built; services run non-root with read-only roots, dropped
capabilities, no-new-privileges and CPU/memory/PID limits. The worker has no network.
Published entry binds loopback. Bridges do not enforce API/gateway egress denial.
The first internal-only network run failed host health and is retained; see
[network decision](decisions/002-local-container-network.md).
The planned Oracle account/2-OCPU/12-GB configuration remains unverified.

## Regulatory pilot progress

SCI01 has pinned Sei-LLRA source, public checkpoint sizes and published digests.
The five rank-64 FP32/CPU components total 400,312,985 bytes. All five components were acquired for internal research and independently
verified against their exact sizes and published SHA256. The ledger retained
the first 180-second failed attempt; total charge 435,387,199 bytes (<1 GiB).
[Acquisition evidence](../research/regulatory/checkpoint-acquisition.json) records
actual sizes/digests and attempt durations. Strict trained-model loading and repeatable inference passed for one synthetic
pair in FP32/default-CPU/QNNPACK. [Runtime evidence](../research/regulatory/runtime-feasibility.json)
records the metrics and limits. The new FP32/QNNPACK runs used network namespaces. Checkpoint redistribution is excluded.

Python 3.11.17/Torch 2.14.1+cpu were installed in an isolated prefix and recreated
from fixed ARM artifacts. A small untrained Conv1d+Linear passed nine checks with
the original qconfig/default-engine combination and QNNPACK. Forcing FBGEMM failed.
The trained resource probe measured FP32 11.27 s/pair versus QNNPACK 18.77 s/pair;
the earlier default quantized engine measured 77.84 s/pair. Resource/checkpoint
compatibility is demonstrated for that one synthetic input, with repeatable outputs.
Selective recomputation is a provisional economic no-go for this measured
configuration: the quantized first pass already costs more than FP32. Biological
accuracy, approximately 100 paired biological examples and savings remain pending.
See [SCI01 report](research/2026-10-14-regulatory-feasibility.md).

SCI02 now has an offline normalized-case adapter, frozen head/context/score and
deterministic 110-slot selection. Twenty adapter tests cover input failures,
source/normalization/effect pins, disjoint windows, prior biological 10-locus
receipt before 100, metrics and partial-failure recovery. Three control acquisition
boundary tests passed. No DART TSV schema has been assumed or silently mapped.

One public UCSC hg38 window with artificial central C-to-G ALT passed actual
FP32 head loading and repeat inference in an offline user/network namespace.
The canonical forward returned two probability tensors of shape 1 × 21,907; all were finite
in [0,1] and repeat-identical. Nine fixed GM12878 ATAC tracks were used, with the
61-class projection disabled. Measurement 11.348 s, repeat 11.378 s, self RSS
927,031,296 bytes. The source, protocol and public export were independently
reviewed. [Control runtime](../research/regulatory/adapter-control-runtime.json)
contains only allowlisted metadata/metrics, not DNA or prediction vectors.
It has zero experimental truth cases and leaves biological feasibility pending.
This different input does not revise the earlier FP32/QNNPACK cost comparison.

## Earlier small biological-source acquisition

Nora identified an individual public Zenodo file rather than the incompatible
35.6 GB archive. Chiquis subsequently acquired `lead_caQTL_variants.tsv.gz`
(10,497,915 bytes) and README (5,043 bytes) from record 1405945, with published MD5
and computed SHA256 pins. [Acquisition receipt](../research/regulatory/small-source-acquisition.json)
records the internal-research CC-BY-4.0 source and 10,512,921 charged dataset bytes
under 50 MiB, preserving the earlier 4,251-byte control charge. Checkpoint charges
and cached weights were not reset or downloaded again.

The separate [structure receipt](../research/regulatory/small-source-structure.json)
records complete CRC-checked gzip decoding: 297,308 descriptive rows and
29,004,438 expanded bytes, with no column/type errors. Technical SNV counts are
not approved inference cases. Raw rows are private and biological loci inferred
remain **zero**. The source is GRCh37/population LCL caQTL data; the frozen model
protocol uses hg38 and nine GM12878 ATAC tracks. Header/dictionary aliases,
coordinate/REF/strand mapping, focal-peak correspondence, biological context,
ties, normalization, selection/splits and training-overlap review remain pending.
See [Nora's source investigation](research/2026-10-14-small-caqtl-sources.md).
This file is not established as the exact inaccessible Synapse/DART v2 table.

## Earlier gates (historical)

- The unhealthy-registry latch was tightened for already-in-flight requests;
  its concurrent failure test passed with the race detector, and the current
  gateway image passed the integration again. The final browser run added
  actual UI/TLS and delayed-response session acceptance for local Firefox.
- Hosted ARM CI passed for the implementation commit: run38587738514,
  job115934123005. The downloaded artifact ZIP SHA256 matched GitHub metadata;
  its new native run passed10/10 and TP3/FP0/FN0 with equal repeated callsets.
  Evidence: evidence/20261014T151621-665108Z-hosted-ci/public/.
  The runner tested merge commit62cdea2e2bab36a22c6330e7e096bb8f6f3b49e8.
  Hosted CI covers unit/PKI/scientific/native checks; local Compose/browser
  acceptance is recorded separately. PR remains a draft for review.
- Freeze appropriate biological context/head track, score, data and split; run
  ten FP32 loci for adapter validation before a 100-pair biological benchmark.
  Candidate Synapse syn60756043 version 2 metadata is readable, but anonymous
  file download returned 403. Actual TSV size/hash/header and effect-allele
  semantics await authorized access; no biological cases have been scored.
  An author-linked original caQTL archive is35.6 GB and cannot fit the 50 MiB gate.
  The separately acquired small Zenodo source advances acquisition/structure
  only; it needs reviewed GRCh37-to-hg38, peak/context and selection semantics.
  Source verification receipts, frozen normalization/selection and real ten-locus
  adapter evidence are required before the hundred-locus evaluation. Source
  standard errors/confidence intervals are retained when provided; disjoint 4 kb
  windows alone do not establish linkage-disequilibrium independence.
  Reopen a recomputation gate only if a representative cheaper pass is measured.
- Public genomic benchmark, queues/multiple workers, production keys/identity,
  response actions and Oracle deployment. Optional nginx/responder profiles
  were not part of the four-service acceptance run.
- Publish the independently reviewed corrected working tree and observe
  its own hosted CI. Artifact quotas/retention and TM-02 remain separate security
  gates; native78/Compose30 prove local input/capture acceptance, not the whole
  platform or CI for an unpublished snapshot.

Daily hosted research remains enabled at 09:00 America/New_York and has produced
its first report. Names, ownership, feedback and handoff rules persist in the team
runbook and private Notion team plan. No production readiness or novelty is claimed.
Chiquis reread the existing worker/controller registry during this checkpoint:
both are active/enabled and the worker remains daily 09:00 America/New_York.
No schedule was changed/duplicated and this reread does not establish an
additional research report.

## Current next gates

- Implement the explicitly configured host container provider with physical
  workspace bounds and authoritative capsule wait, without weakening worker
  capabilities or exposing a Docker socket to the worker.
- Integrate artifact custody into the protected worker after verified crypto,
  then repeat native/Compose science, authorization, cancellation and recovery
  against the integrated source. Standalone fixture acceptance cannot substitute.
- Close TM02 authenticated immutable ownership before per-principal artifact
  quotas; complete result/event/cache/registry quotas, retention, queues/leases,
  effective SOC/adversary scenarios and cloud/final delivery as defined by evidence.
- Keep the completed biological baseline descriptive: training holdout/LD and
  biological feasibility remain uncertain. Reopen selective recomputation only
  with a representative cheaper pass under a prospective measured protocol.
- Publish/review each new source snapshot with its own CI. Preserve free-only
  operation and the existing09:00America/New_York research schedule.

# BioZero implementation status

Updated 2026-10-14. Local branch: biozero/reproducible-milestone.
Base: b8731934fbe7c7dc00bf51fa978ce370361b3f74. Implementation commit:
a27221c6f2174ea9d116779fcd47c88f9794dddb, published in
[draft PR #21](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/pull/21).
No merge or deployment occurred. See the live PR for subsequent documentation commits.

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

The Python suites passed 48 tests across pipeline, benchmark, supervisor,
operator preflight and bounded downloader; test/vet passed in all seven Go modules. Vale also ran gateway tests with
the race detector. PKI acceptance passed including gateway key scope. Current
container tools: Python 3.12.3, minimap2 2.26-r1175, samtools 1.19.2, bcftools 1.19.
Native tools remain fixed in the 39-package Linux ARM64 lock.

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

## Next gates

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
  Reopen a recomputation gate only if a representative cheaper pass is measured.
- Public genomic benchmark, queues/multiple workers, production keys/identity,
  response actions and Oracle deployment. Optional nginx/responder profiles
  were not part of the four-service acceptance run.

Daily hosted research remains enabled at 09:00 America/New_York and has produced
its first report. Names, ownership, feedback and handoff rules persist in the team
runbook and private Notion team plan. No production readiness or novelty is claimed.

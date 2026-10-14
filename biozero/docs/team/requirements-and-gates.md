# BioZero requirements, evidence and next gates

Audit date: 2026-10-14. Author: Alba; integration owner: Chiquis.
Snapshot: clean checkout `2994d0555f7fdc20730832c3d0f5a0189dcdac23`.
[Draft PR21](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/pull/21)
is open and unmerged. [ARM CI38588587095](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38588587095)
completed successfully for that head. Subsequent work needs its own evidence;
this audit does not claim that later changes were tested by those runs.

## Requirement authority and scope

The user's objective is an autonomous, documented, reproducible BioZero project,
with a coordinating agent, specialists and support reviewers, research into
existing work/repositories, and daily research at 09:00 America/New_York.
The existing constraint is free-only setup. The goal is broader than one green PR.

The [active notebook](https://app.notion.com/p/3ef7dff9bf6c817cb6d0d6d48b68a9d4)
and [team execution plan](https://app.notion.com/p/3f97dff9bf6c81bca207fae23b529cfa)
select BZ-EXP-001 as the first engineering milestone. Their newer checkpoints
supersede dated implementation states; historical unchecked boxes are not a
fresh statement that completed work is missing. The
[regulatory proposal](https://app.notion.com/p/3ef7dff9bf6c815998e8dbed323a2c45)
preserves approximately 100 paired examples as a conditional feasibility pilot.
The [master outline](https://app.notion.com/p/2df7dff9bf6c806f9609e3d475ffdfa3)
records the broader architecture as a roadmap, not demonstrated capability.

Completed first milestone, measured SCI01 runtime, pending SCI02 biology and
aspirational full-platform capabilities remain distinct. Neither one synthetic
pair nor 100 synthetic pairs satisfy the biological pilot. The current negative
cost finding does not close the platform objective.

## Requirement-to-evidence matrix

Paths below are relative to `biozero/` unless prefixed with `/` for repo root.
Status describes the audited snapshot, not future planned implementation.

| Requirement / scope | Named artifact | Current evidence | Status | Next gate |
| --- | --- | --- | --- | --- |
| Recoverable autonomous team | `/AGENTS.md`, `docs/team/runbook.md`, `docs/team/handoff-2026-10-14.md`, `docs/STATUS.md`; private Notion team plan | Names, routing IDs, writer ownership, handoff fields and independent review recorded | Implemented session workflow | Each new task records requirement, owner/reviewer, file scope, acceptance, run and next action; conversational agents are not permanent processes |
| Specialist/support pairs and respectful feedback | `docs/team/runbook.md` | Chiquis coordinates; Vera/Alba research, Vale/Luci security, Atlas/Lía engineering/QA; concrete contributor acknowledgments in handoff/Notion | Implemented | Preserve independent review; feedback names a verified contribution and actionable next step |
| Daily research at 09:00 New York | [Research journal](https://chatgpt.com/space/page_1b30d8095d408191b8d36f8483159475), native automation registry | Worker `Automation_e92d573c43488191b018b6436611579f` active/enabled, DAILY 09:00 America/New_York, attached to enabled controller `Automation_6f9eb3d564b88191a2dfdf175687d2a9`; reread during audit | Configured; first report recorded in journal/checkpoints | Each run verifies source/controller access, records bounded findings or access failures; reuse existing IDs, do not duplicate schedules |
| Research before novelty claims | Notion regulatory proposal, `docs/research/2026-10-14-regulatory-feasibility.md` | Closest work and source versions recorded; no novelty claim | Preliminary comparison implemented | Read remaining closest full texts/supplements and reconcile with experiments before any originality claim |
| Reuse other user repositories appropriately | Notion team plan, links to `orchastration` and `CTF_Agents` | READMEs inspected, no code copied/executed | Discovery only | Inspect implementation/license/architecture before choosing a reusable component; preserve private-source boundaries |
| BZ-EXP-001 inputs and frozen answer key | `bio/fixtures/variant-smoke/`, `docs/experiments/001-variant-smoke.md` | Deterministic 6 kb reference, 1,171 reads, three expected SNPs, invalid FASTQ and hashes | Complete synthetic scope | A new scientific question needs its own dataset/protocol/acceptance |
| Truthful execution and protected entry | `services/enclave-runner/main.go`, upload/results/CLI contracts, `docs/decisions/001-job-states.md` | Native10/10 includes unsigned rejection before analysis, format-specific failure, TLS denial and immutable upload digests | Implemented and verified in first milestone | Preserve crypto/pipeline/timeouts/restart tests when changing lifecycle |
| Separate execution from scientific release | Worker evaluator, `bio/benchmarks/evaluate_variants.py`, gateway/UI DTOs | Successful execution is separate from evaluated_passed/withheld/unassessed; TP3/FP0/FN0 in repeated runs | Implemented for defined synthetic truth | Every new experiment defines independent scientific acceptance; exit0 alone never approves results |
| Per-user ownership through enabled interfaces | `services/reviewer-gateway/`, individual mTLS certificates, `ui/app.js` | Compose31/31 and browser23/23 include A/B denial, restart/relogin, logout and delayed A callbacks across B session | Verified local reviewer profile | New interfaces require their own identity tests; automatic identity synchronization across all tabs is not implemented |
| Controlled runtime and scoped secrets | `infra/compose/docker-compose.yml`, `infra/PKI/`, network decision002 | Non-root/read-only containers, scoped keys, dropped caps, limits; worker has no network; loopback entry | Verified local four-service profile | API/gateway egress is not denied by normal bridges; external deployment needs explicit identity/network/key policy |
| One-command experiment and independent reproduction | `/Makefile`, `infra/native/run_experiment.py`, `docs/runbooks/reproduce.md`, locks | Native10/10 repeated from another checkout; protected ARM CI and safe evidence | Complete first engineering milestone | Maintain source/input/config hashes and bounded lifecycle for new profiles |
| Reviewable report without private artifacts | Public evidence allowlists, `infra/native/public_vcf.py`, checksums/derivations | Derived VCFs preserve normalized allele set; originals remain private; four export tests and independent review | Implemented current exports | Share only reviewed public bundles; older raw exports remain historical and must not be published |
| SCI01 operator/runtime/checkpoint feasibility | `research/regulatory/preflight.py`, locks, `checkpoints.json`, `checkpoint-acquisition.json`, `model_probe.py`, `runtime-feasibility.json` | Five components size/SHA verified; strict loading/repeat passed for one synthetic pair; FP32/QNNPACK RSS/time recorded | Compatibility GO for that measured input | Preserve scope; untrained operator tests and trained synthetic probes are not biology |
| SCI01 economical recomputation | `runtime-feasibility.json`, SCI01 report | Comparable FP3211.27s vs QNNPACK18.77s/pair; original quantized engine77.84s | Provisional NO-GO for current measured path | Reopen only with a representative cheaper pass, relevant discrepancy and quality/total-cost criteria; include gate/data movement and random/simple/smaller-model baselines when applicable |
| SCI02 authorized data and effect semantics | `docs/experiments/002-regulatory-biological-baseline.md`; future pinned data/terms/digest manifest | Synapse syn60756043v2 metadata readable, anonymous file403; actual TSV size/header/hash/effect dictionary unknown | Data acquisition pending | Authorized file bytes or exact authorized copy, within50MiB; freeze build, assay, effect orientation, usage and split before scoring |
| SCI02 real-window adapter and compatible head output | SCI02 protocol; future adapter/config/case ledger | At audited head `model_probe.py` generates random pairs and returns61 projected classes; no real-window adapter | Implementation pending; possible without dataset access | Build offline validators/tests; fixed trackID→head index, unknown semantics→pending, full4096bp windows, REF/ALT/build/strand checks; do not turn synthetic tests into biological evidence |
| SCI02 ten real adapter loci | SCI02 protocol; future case ledger/report | Zero biological loci scored | Required next biological gate, pending authorized data and adapter | Validate all ten cases and record failures, frozen score, repeat stability, time/RSS and provenance before expanding |
| SCI02 approximately100 biological pairs | SCI02 protocol and Notion pilot acceptance; future evaluation report | No biological benchmark performed | Conditional pilot remains pending | Proceed after ten-locus controls; freeze selection/strata/splits/training-overlap checks and metrics; count all submitted cases and correlated-locus uncertainty |
| Public genomic benchmark beyond synthetic SNP presence | Notebook trackA; future matched benchmark/protocol | Current fixture does not assess genotype, indel, WGS or clinical accuracy | Roadmap pending | Select permitted matched sample/build/evaluable regions/truth, explicit metrics and bounded resources |
| Durable datastore/queue/multiple workers | `docs/BioZero_MVP_Final_Attack_Plan.md`; future schema/migrations/claim/lease tests | Worker currently scans job files; single worker only; no demonstrated Postgres/Redis queue | Broader platform roadmap pending | Design atomic claim/lease, idempotency, restart/retry/quarantine and measured concurrency before enabling multiple consumers |
| SOC telemetry and effective response | Original outline; `services/zeroresponder/`, optional simulation profile | Responder writes action records/lists; SIEM ingestion, effective blocking/revocation and real containment not demonstrated | Stub/simulation, broader roadmap pending | Define event contract and safe end-to-end simulated controls; distinguish recorded action from enforced action |
| Evolving adversary simulator | Original outline; `simulated-adversary/` | Existing component is not evidence of mutating/latent/mimicry/evasion coverage in current accepted profile | Roadmap pending | Freeze harmless scenarios, expected telemetry/response and repeatable tests |
| Oracle/cloud, production identity/storage/keys and hardware attestation | Original outline, STATUS/runtime notes; future deployment/attestation evidence | Actual executor RHELARM1CPU~5.45GiB; planned Oracle2OCPU/12GB not verified; worker name does not establish enclave hardware | Roadmap pending/unverified | Verify existing free resources and capabilities; choose deployable control/threat model; demonstrate each feature rather than infer from naming |
| Final documentation and demonstration | Original outline phase7; runbooks, architecture flow and evidence exist | Current engineering documentation available; original roadmap also names whitepaper/threat model, walkthrough video and executive summary | Partially implemented documentation roadmap | Produce current threat model and requirement coverage; create final artifacts around demonstrated scope, with remaining gates explicit |

## Audited evidence receipts

- `docs/evidence/20261014T150910-330979Z/public/`: native10/10, TP3/FP0/FN0,
  equal normalized callsets. Audit matched122 source hashes; seven later changes
  were README/runbook/status documentation. The original dirty snapshot is retained.
- `docs/evidence/20261014T150658-139518Z-reviewer-compose/public/`:
  Compose31/31 and Firefox23/23, zero JS errors. All28 recorded source hashes
  matched the audited checkout. Explicit session transitions are the tested scope.
- `docs/evidence/20261014T150823-057533Z-independent-checkout/public/`:
  independent native reproduction, with exact snapshot/mode provenance and the
  original Unicode-filename manifest limitation preserved.
- `docs/evidence/20261014T151621-665108Z-hosted-ci/public/hosted-ci.json`:
  earlier implementation CI38587738514 artifact receipt, ZIP digest and original
  native checksums verified. Latest CI38588587095 was separately observed success
  for head2994d055; do not relabel the earlier artifact as belonging to that run.
- `research/regulatory/runtime-feasibility.json`: trained one-pair synthetic
  resources/numerical comparison, not an external biological benchmark.

## Named reproduction commands

Run only when the selected task requires fresh execution; this audit read existing
evidence and did not repeat completed experiments or downloads.

```bash
make bio-tools
make test
bash biozero/infra/PKI/test-pki.sh
make science
make experiment
python3 -B biozero/infra/compose/run_reviewer_experiment.py
.biozero/browser/bin/python -B biozero/infra/compose/run_reviewer_experiment.py --browser
make regulatory-tools
make regulatory-preflight
```

The browser command requires the locked local browser setup described in
[Compose README](../../infra/compose/README.md). Regulatory runtime commands and
private checkpoint caching are described in
[regulatory README](../../research/regulatory/README.md); they do not implement
SCI02 data ingestion. CI covers native/unit/PKI/science, not local Compose/browser.

## Next autonomous work and honest stopping boundaries

The next implementable task is an offline biological adapter/config/case ledger
with negative tests. Access403 blocks the real ten/100-locus measurements, not
these validators or a current threat model, event contract, requirement matrix,
or claim/lease design. Preserve pending effect semantics rather than infer an
unseen TSV schema. Atlas owns the adapter/tests; Chiquis owns protocol integration.

The first milestone can be marked complete within its stated scope. Full-project
completion requires evaluating the remaining adopted requirements and roadmap
decisions explicitly; PR success does not shrink them or satisfy biological gates.
Unverified deployment/attestation must remain unverified. Any change of direction
requires a recorded decision, supported evidence and updated acceptance.

## Post-audit SCI02 implementation round

The original snapshot above remains 2994d055. Atlas subsequently implemented the
offline normalized-window adapter and 20 tests; Chiquis fixed the protocol/control
producer and 3 boundary tests, and all 71 Python tests/seven Go modules passed.
Vera reviewed scientific conventions; Luci checked private input/model/report
boundaries. One public-reference/artificial-ALT instrumentation control passed
actual FP32 head/repeat checks with zero experimental labels. See
[control runtime](../../research/regulatory/adapter-control-runtime.json).
This advances the real-window adapter row; ten/hundred biological loci, the exact
source schema/effect dictionary and broader platform gates remain pending.

## Post-audit security event round

The original matrix remains the 2994d055 audit. Subsequent work implements the
event contract, protected rejection outbox, independent HTTPS relay and a durable
authenticated ZeroResponder simulation. Native receipt
`docs/evidence/20261014T165148-344656Z/public/` passed22 assertions, including12
SOC cases. The current four-service container receipt
`docs/evidence/20261014T164550-385353Z-reviewer-compose/public/` passed30 checks
with the outbox mount and worker network none. The preceding mount-verifier
failure is preserved, with its cause and correction in STATUS. Tests now include
81 Python cases and new worker/responder concurrency and persistence checks.

The optional responder container receipt
`docs/evidence/20261014T165334-020175Z-soc-container/public/` subsequently passed
13 assertions and cleanup, with17 unchanged source hashes and parent native/result
binding. It verifies the real simulation profile, not live containment or a
production SOC. No pipeline or model was executed in that container experiment.

Lía produced the current [threat model](../security/threat-model.md), advancing the
documentation row. It identifies actual residual admission/disk limits, mutable
job authorization metadata, unsafe legacy metadata reads and trusted host/UID
boundaries. [Decision003](../decisions/003-security-event-handoff.md) preserves
effective response as a separate adopted gate: simulation is a prerequisite and
does not complete the SOC requirement. SIEM integration, actual containment,
per-source identity, quotas/retention, queue/leases, adversary scenarios, Oracle
deployment and biological ten/100-locus evaluation remain pending.

## Metadata boundary round — 2026-10-14

This is a further acceptance checkpoint, not completion of the original roadmap.
TM-03 job/result readers, worker recovery and event reconciliation now follow the
[metadata contract](../security/metadata-contract.md); both readers pass54 shared
vectors. Native evidence `docs/evidence/20261014T175423-175221Z/public/` passed53
checks, including the entire admitted metadata lifecycle at its projected limit,
rejection one byte over, nine unsafe fixtures and continued real worker progress.
Rebuilt Compose `docs/evidence/20261014T175423-180461Z-reviewer-compose/public/`
passed30 controls and cleanup.81 Python tests/seven Go test-vet modules passed.
Previous50/51-check receipts did not establish lifecycle growth safety and retain
their historical scope. Root-only unit evidence isolates foreign UID rejection.

Next: TM-01 measurable global/per-client admission and storage limits, then TM-02
authenticated immutable ownership. Remaining biological10/100 loci, queues/leases,
evolving benign adversary scenarios, effective SOC, production identity/storage/
keys, cloud deployment/attestation and final deliverables remain adopted gates.

## Retained-input/output and small-source checkpoint — 2026-10-14

The original matrix/audit above retains snapshot 2994d055. This update records a
dirty admission/output implementation above parent 2ad6b91c, not a new whole-project
completion or approval from CI for the committed parent.

| Updated requirement | Artifact/evidence | Status at this checkpoint | Remaining gate |
| --- | --- | --- | --- |
| Shared global/principal pending and retained input accounting | [Admission contract](../security/admission-contract.md); corrected native 78/78 at `docs/evidence/20261014T192150-539678Z/public/`, including 15 admission cases | Local acceptance and independent review passed | Publication/new CI; pinned-policy migration and explicit legacy adoption remain separate |
| Bounded worker command capture and serialized results | Native 10 output cases in that 78-case receipt; local 86 Python/seven Go test-vet passed | Corrected local source verified | Preserve group cancellation, truthful failure/withholding and provenance; Python tool capture, artifacts and total disk remain outside this subgate |
| Actual container packaging of admission | Corrected `docs/evidence/20261014T192150-561120Z-reviewer-compose/public/`: 30/30 + cleanup; three-bind-mount regression `docs/evidence/20261014T192234-593374Z-admission-mount/public/` | Local container acceptance passed | Preserve failed pre-correction Compose receipt and source-specific review; regression alone is not TLS/science evidence |
| Complete storage/resource management | Same contract explicitly excludes SAM/BAM/BCF/VCF/reference copies, all retained result/event/receipt/registry totals and cache | Artifact quotas/retention pending | Measured policies and durable retention/accounting before calling TM-01 complete; free-space sensor alone is not a hard quota |
| Immutable authenticated ownership and concurrent job processing | TM-02 threat-model finding; broader datastore/queue roadmap | Pending | Canonical CN quota accounting does not authenticate mutable owner JSON or establish leases/idempotent multi-worker claiming |
| Accessible bounded biological candidate | [Acquisition receipt](../../research/regulatory/small-source-acquisition.json): 10,497,915-byte gzip + 5,043-byte README, SHA/MD5 pins, Zenodo 1405945/CC-BY-4.0 source | Acquired for internal research; dataset charge 10,512,921 below 50 MiB | Review exact normalization/effect/build/peak/context and source usage before creating cases; not the exact Synapse/DART v2 file |
| Whole-file structure and denominator preservation | [Structure receipt](../../research/regulatory/small-source-structure.json): complete CRC decode, 297,308 rows, zero type/column errors | Descriptive source inspection complete; zero biological cases inferred | GRCh37-to-hg38/REF/strand mapping, ties/peak rules, context/head agreement, selection/splits and training overlap; ten real loci before 100 evaluation slots |
| CI for current changes | Existing CI of committed parent2ad, previous CI receipts above | New working-tree code not validated by that CI | Publish the reviewed snapshot and observe its own checks; do not transfer old CI provenance to new sources |

Nora's [small-source report](../research/2026-10-14-small-caqtl-sources.md) separates
primary documentation/code support from unapproved header aliases and mapping.
Population-LCL caQTL effects are not automatically GM12878-specific truth. The
technical SNV row count is not an eligible/evaluated-case count; original Sei
chromosome holdouts alone do not prove the rank64 checkpoint's full training
history. The ten/hundred biological gates remain pending, as do effective SOC,
cloud/attestation, production identity and the wider adopted roadmap.
Luci approved the pre-correction native bundle's 11 public files/10 checksums;
that approval is tied to its source snapshot. Pre-correction native 78 at
`docs/evidence/20261014T190933-375408Z/public/` and Compose FAIL-after-10 at
`docs/evidence/20261014T190933-378316Z-reviewer-compose/public/` are retained.
`EXDEV` across separate
bind mounts despite equal device IDs led to the corrected mount-local staging;
no extra mount/payload duplication or silent legacy adoption was added. The
final independent review approved 32 selected exports: 19 fresh, two failed
Compose and 11 historical-native files. Native's seven differences among 246
hashes were documentation only; Compose matched 34 runtime hashes/five checksums.
Local acceptance does not close all
TM-01 storage/retention or TM-02, nor establish new hosted CI before publication.

The coordinator reread the
existing active/enabled daily worker/controller without edits or duplicates;
the configuration observation is not a new daily-report receipt. This update was
written before publication; consult the live PR for the subsequent head/CI rather
than inferring a fresh hosted PASS from parent2ad or the local receipts.

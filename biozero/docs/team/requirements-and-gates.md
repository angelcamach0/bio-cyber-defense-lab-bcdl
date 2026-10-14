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

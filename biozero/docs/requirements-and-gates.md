# BioZero requirements and verification gates

Updated2026-10-15 UTC. This matrix records the adopted technical scope and the
evidence needed for completion. Source plans describe intended capabilities;
completed experiments establish only their measured scope. See
[implementation status](STATUS.md) for the current commit and CI result.

## Required outcomes

BioZero requires protected, reproducible genomic execution, independently assessed
scientific results, bounded resources, observable failures and documented recovery.
The regulatory recomputation proposal is a conditional feasibility pilot. The
setup uses free resources; one synthetic benchmark or green CI does not establish
production readiness, biological accuracy or the complete platform.

| Requirement | Implementation or artifact | Current evidence | Remaining gate |
| --- | --- | --- | --- |
| Deterministic first experiment | bio/fixtures/variant-smoke; experiments/001 | 6kb reference,1,171reads,3known SNPs, invalid FASTQ and source hashes | A different scientific claim requires its own matched dataset, protocol and truth |
| Protected entry and truthful states | upload/results/CLI contracts; enclave-runner; decisions/001 | TLS/mTLS, integrity/signature/decryption before analysis, explicit failed/incomplete/rejected/timed_out/succeeded states | Preserve crypto, cancellation and restart acceptance through new execution paths |
| Scientific release separate from execution | independent variant evaluator; result DTOs | Repeated TP3/FP0/FN0 for normalized synthetic allele presence; evaluated_passed/withheld/unassessed distinct | No genotype, indel, WGS, clinical or novelty approval follows |
| Per-client authorization | individual mTLS identities; reviewer gateway/UI | A/B denial, restart/relogin, logout and delayed-response session tests | Immutable authenticated ownership TM02; automatic synchronization across all tabs remains unimplemented |
| Limited key/network scope | PKI/runtime preparation; Compose | Non-root/read-only/cap-drop services, scoped runtime keys, no worker network, loopback entry | Production key lifecycle, source identity/attestation and explicit deployed network policy |
| Durable input admission | upload-api admission ledger; security/admission-contract | Reserve before body; retained global/per-principal jobs/bytes; bounded active uploads; renewal keeps CN bucket | Explicit migration/retention; never reset unknown history to admit work |
| Strict metadata and output bounds | shared job/result corpus; metadata-contract; pipeline/resource_budget | Bounded private reads and projected lifecycle; stdout/stderr/result/file limits; failure stays withheld | Remaining payload/config/event/cache/cardinality and physical-spool controls |
| Aggregate capsule workspace | native/Docker providers; artifact-workspace-contract | Actual128MiB/4096inode-unit limits,64MiB per file, separate byte/inode exhaustion and capsule controls | Install providers in protected worker and repeat native/Compose integrated acceptance |
| Retained artifact custody | artifact-executor Store/coordinator | Reserve/Begin/export/proof/commit before ACK;1GiB/64slots,64MiB exports; failure/cancel/restart accounting | Full principal binding/quotas, operator reconciliation and explicit provenance-preserving retention |
| Worker FD bridge | broker/bridge protocol and journal; fixed host service | V1 preserved, strict separatev2 with durable exact context, compiled service/profile/restart/receipt/cleanup-error acceptance | Protected crypto→submit, verified bounded plaintext staging, complete result projection/readback and worker-death acceptance |
| Complete bounded analysis | analysis package/CLI in both capsule providers | Actual broker+native/Docker pipeline/evaluator/alignment; exact pins/context/receipt,3SNP truth, rules failure revokes approval | Connect protected worker without moving tools outside quota; repeat full native/Compose crypto and authorization acceptance |
| Image/tool reproducibility | ARM native lock; cached capsule image; analysis build receipts | Same-environment analysis binaries repeat byte-for-byte; tool versions/source pins recorded | Full image base/dependency/builder closure, verified offline builds/transfer, licenses and separate AMD64 acceptance |
| Execution lifecycle and recovery | native/container lifecycle opt-ins | Cancel/timeout/PID1/keeper death, immediate pending restart denial, preserved charges and failed histories | Integrated worker/broker/capsule lifecycle, injected attach/removal/storage uncertainty and safe operator recovery |
| Independent reproducible experiment | Makefile; native/Compose runbooks; public evidence allowlists | Protected native78assertions, Compose30, Firefox23 and optional responder13 at their exact source snapshots | Fresh acceptance for every changed integration; hosted CI does not cover all local opt-ins |
| Research and justified novelty | research notes and source/version references | Closest-work and access investigations; no novelty claim | Verify sources, full methods/supplements and changed assumptions before adopting claims or changing protocols |
| SCI01 runtime and economic feasibility | regulatory probes/checkpoint/runtime receipts | Strict load/repeat on defined synthetic inputs; measured FP32/QNNPACK time/RSS | Comparable FP3211.27s versus QNNPACK18.77s is provisional economic no-go; reopen only after representative cheaper quality-qualified pass |
| SCI02 permitted biological source and frozen semantics | experiments/002–005; source/acquisition/normalization receipts | Small CC-BY caQTL source, coordinate/REF/context normalization, frozen10adapter/100evaluation slots before inference | Exact DART/Synapse source is not verified; preserve licensing, assay/context and coordinate limitations |
| SCI02 biological evaluation | biological-adapter/evaluation aggregate exports |100/100 completed finite identical repeats; sign61/100, Spearman0.1840864086408641 | Descriptive transfer only; head-training holdout, LD independence, comparable scales and biological feasibility remain unverified |
| Broader genomic benchmark | future matched benchmark/protocol | Current fixture assesses synthetic SNP presence only | Permitted sample/build/regions/truth, explicit genotype/indel/WGS metrics and bounded execution |
| Durable queue and multiple workers | broader architecture and future migrations | Current worker scans job files; single active execution | Atomic claim/lease, idempotency, restart/retry/quarantine and measured multi-consumer behavior |
| SOC telemetry and effective response | security/event-contract; private outbox/relay; ZeroResponder | Authenticated durable simulation, retries/idempotency and no effective action | Production SIEM/source identity, durable relay and demonstrated safe containment/revocation; no exactly-once claim |
| Benign adversary scenarios | simulated-adversary and future scenario corpus | Component exists; current acceptance does not establish evolving/evasion coverage | Harmless frozen scenarios with expected telemetry/response and repeatable failure/success checks |
| Cloud and production identity/storage | architecture plans and future IaC/deployment evidence | Managed local ARM executor observed; planned Oracle resources/attestation unverified | Verify existing free capacity; deploy and measure identity, keys, storage, network and attestation under an explicit threat model |
| Final delivery | architecture/runbooks/security contracts and evidence | Technical documentation and reproducible fixtures available | Current threat model/coverage audit, whitepaper, walkthrough demonstration/video and executive summary based on demonstrated scope |

## Evidence rules

- Match each claim to its actual source/input/configuration snapshot and executed
  scope. A unit test, fake provider or version print is not real capsule acceptance.
- Keep original upload, processed plaintext, observed/evaluated/retained VCF and
  public derived-export hashes separate. Successful execution is not scientific
  approval, and committed storage is not proof of peer receipt.
- Preserve failed/weaker attempts and all submitted scientific denominators.
  Unknown pending work is never retried, refunded, adopted or deleted implicitly.
- Public bundles contain only reviewed synthetic/aggregate evidence. Credentials,
  raw sensitive rows/DNA, case IDs, targets, prediction vectors and weights remain
  private. Scientific source attribution and license notices remain intact.
- New source requires its own checks. CI38660550112 at0dd7384 failed before
  protected-service startup on a recursive single-output build; its unit/PKI and
  scientific repeat passed. The corrected harness uses one executable package
  per output and passed a fresh local78-check run and its own CI38661813114 at
  98f2f89. Later capsule/service source has separate local receipts and needs its
  own publication/CI; no previous result silently approves new source.

## Reproduction entry points

```sh
make test
make science BIOZERO_TOOLS_PREFIX=/absolute/tool-prefix
make experiment BIOZERO_TOOLS_PREFIX=/absolute/tool-prefix
make experiment-soc BIOZERO_TOOLS_PREFIX=/absolute/tool-prefix
```

Use [the runbook](runbooks/reproduce.md) for prerequisites and diagnosis and
[Compose setup](../infra/compose/README.md) for its separate acceptance commands.
Kernel/provider and biological-model runs have explicit opt-ins/prerequisites;
select them only when the changed requirement needs fresh execution. Never infer
production/cloud or biological approval from the synthetic fixture.

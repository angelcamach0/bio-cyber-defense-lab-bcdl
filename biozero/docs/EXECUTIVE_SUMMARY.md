# BioZero executive summary

Updated2026-10-15 UTC. BioZero is a local demonstrator for protected genomic
execution with verifiable provenance, bounded analysis and separate scientific
release decisions. It uses free resources. Production deployment, hardware
attestation and clinical use are not established.

## What works

An individual mTLS client uploads signed encrypted input. The worker verifies an
anchored ciphertext snapshot, authenticates decryption and stages the verified
plaintext in bounded private tmpfs. A fixed-profile host broker runs the pipeline,
independent evaluator and detection in a capsule. A trusted coordinator fences
exports and commits retained artifacts with a proof. The worker publishes a
bounded projection of the confirmed receipt; result access remains owner-checked.
Lost local publication can recover the same committed artifacts without running
the analysis again.

The [protected capsule experiment](evidence/20261015-protected-capsule-worker/public/README.md)
passed25native checks and30three-service Compose checks. Both use the native
capsule provider. Each environment repeated a synthetic6kb reference/1,171-read
fixture with three known SNPs: TP3/FP0/FN0, precision/recall1. Tests also covered
actual cryptographic entry, cross-client denial, invalid input withheld, unsigned
rejection before execution custody and clean-stop/result-recovery behavior.
Independent retained-evidence checks passed78native/35Compose. The published
baseline4e9e119 passed its [own hosted ARM CI](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38673044638),
including uncached unit tests, PKI, scientific repeat and the separately selected
earlier protected experiment. Historical browser/SOC/provider tests retain their
own source and execution scope.

A separate [protected Docker-provider run](evidence/20261015-protected-docker-capsule-worker/public/README.md)
passed57assertions and52independent retained-evidence checks. It exercised real
Docker capsules with observed configuration, kernel restrictions and exact
artifact/custody accounting, while preserving the same scientific and access
checks. The392-file runtime snapshot reused verified existing binaries; later
documentation and public aggregates are distinguished. Its publication/CI status
is tracked in the [draft PR](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/pull/22).

[Postcommit interruption acceptance](evidence/20261015-protected-postcommit-faults/public/README.md)
now adds26response-loss and32whole worker-container SIGKILL/restart checks, with
41/45independent readback checks. Each recovers the same committed result through
queries, with one Submit/capsule and unchanged artifacts/proofs/custody/charges.
A fresh default Docker regression passed57checks and52independent checks on the
same399-file snapshot. This establishes downstream response loss and postcommit
container restart, not a failed broker ACK write, process-only recovery retaining
plaintext or broker-death reconciliation. Temporary kernel measurement references
retain both plaintext tmpfs generations until comparison; no secure erase follows.

## What the evidence means

The benchmark measures normalized synthetic SNP presence. It does not establish
genotype, indel, whole-genome, biological or clinical accuracy. Native namespaces
retain access to trusted host files; the host, same-UID writers and any Docker
daemon remain trusted. Docker provider components have separate resource and
lifecycle acceptance, now complemented by that protected positive/recovery run.
The cached image has not been reproduced from a closed dependency/build recipe.

The [regulatory feasibility pilot](experiments/005-biological-evaluation.md)
completed100frozen descriptive transfer cases with identical finite repeats:
sign agreement61/100 and Spearman0.1840864086408641. Training holdout, LD
independence and matched biological interpretation remain unverified. The prior
comparable FP32/QNNPACK timing, approximately11.27s versus18.77s, remains an
economic no-go for the proposed cheaper recomputation strategy. No savings or
novelty claim follows from those results.

## Work required for delivery

Extend protected execution with broker-death, active-cancellation, upstream
ACK-write/storage/removal faults and explicit reconciliation of uncertain custody
and retained plaintext. Then close image/tool/
license provenance, immutable owner records, principal and physical-storage
quotas/retention, durable queues/multiple workers, effective SOC response and
verified free cloud identity/key/storage/network controls. These requirements
remain visible in the [verification matrix](requirements-and-gates.md).

The [implementation status](STATUS.md), [threat model](security/threat-model.md)
and [reproduction runbook](runbooks/reproduce.md) link the technical evidence.
Raw genomic/results data, credentials, private identifiers, vectors and weights
remain outside public bundles. The current capsule delivery is a draft above
the merged initial milestone, without production deployment. Final whitepaper and walkthrough/video must use the
demonstrated scope rather than treating planned capabilities as completed work.

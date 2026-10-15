# BioZero implementation status

Updated2026-10-15 UTC. Branch: `biozero/container-capsule-provider`.
[PR22](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/pull/22) is a draft
above [merged PR21](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/pull/21).
No production deployment is established.

## Protected synthetic experiment

The accepted fixture has a6kb reference,1,171reads and three known SNPs. Repeated
normalized allele callsets have TP3/FP0/FN0. Protected entry uses individual mTLS
identities, signature/integrity/encryption checks before analysis, and separate
execution and scientific-release states. A/B authorization, invalid input,
unsigned/no-certificate rejection, original hashes and restart behavior have
executed acceptance. This does not establish genotype, indel, whole-genome or
clinical accuracy, novelty or hardware-enclave protection.

The current native harness selects each service's root executable with `go build
-o DEST .`; package tests/vet still discover all packages using `./...`. Its prior
recursive build failed after adding analysis/CLI subpackages. The failed
[CI38660550112](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38660550112)
at commit0dd7384 remains preserved: unit/PKI and scientific repeat passed, but
protected-service startup was never reached. After the selector correction, fresh
local protected native acceptance passed all78assertions. Its private receipt is
`.biozero/bridge-buildfix-native-20261015T003540.421150Z/`; source pins and cleanup
remain scoped to that run. The correction awaits its own published CI.

Earlier exact-source evidence remains under docs/evidence and in Git history:
protected native78checks, four-service Compose30checks, Firefox23UI/TLS/session
checks and optional responder-container13checks. These receipts are not relabeled
as integrated broker acceptance. See [reproduction](runbooks/reproduce.md),
[experiment001](experiments/001-variant-smoke.md) and the recorded source hashes.

## Bounded execution components

The artifact module implements private durable reservations, bounded metadata,
registry, Unix transport, coordinator and native/Docker capsule providers.
Configured capsules enforce a128MiB/4096inode-unit workspace,64MiB per-file limit,
capabilities zero and no_new_privs; actual Docker cgroup limits were observed.
Exact provider termination and export fencing precede proof/commit/ACK. Synthetic
module acceptance retains four artifacts and equal observed/evaluated/retained VCF
hashes. Native and Docker cancellation/timeout/keeper-death and byte/inode quota
receipts preserve pending history and charges without automatic retries/refunds.

The new worker FD broker adds a separate strict submit/status/cancel/receipt
protocol and durable job/upload/plaintext/profile-to-lease binding. Journal intent
precedes Reserve, durable lease linkage precedes Bind, and committed journal
sealing precedes actual ACK. Two causal tests cover Store commit before journal
seal and commit racing ACK acquisition. Lost ACK cannot bypass health or rerun
work; explicit restart recovers only a prior binding with verified committed Store
history. Journal metadata is separately bounded to1MiB plus one1MiB replacement,
outside Store's logical1GiB artifact-byte charge.

The analysis package/CLI preserves scoring, defaults, signal shape and historical
SAM-record counting. SAM/target/stderr/time bounds are explicit; failures discard
partial metrics. Rules and argv must agree on panel presence. Input/output are
bounded64KiB; future pipeline projection must fit without truncating accepted
results. Targets and raw results remain private.

These components are not yet connected to the protected worker or installed as a
service. Both evaluation and optional alignment/detection must run inside the
same bounded capsule before integrated acceptance is claimed. The host retains
Docker authority; the worker receives no Docker socket or writable Store mount.
See [broker](../services/artifact-executor/README-broker.md),
[capsule](../services/artifact-executor/README-container.md),
[analysis](../services/enclave-runner/analysis/README.md) and
[workspace contract](security/artifact-workspace-contract.md).

## Verification and reproduction scope

- Final component `make test`:252Python cases,250passed/two helper kernel skips;
  test/vet in eight Go modules. simulated-adversary has no Go tests.
- Complete artifact-module race suite with six native/Docker opt-ins:90top-level
  functions plus subcases passed in23.847s, no failures. Two internal keeper
  entries skip in the parent and run in spawned subprocesses. Nine broker and
  eight bridge functions use synthetic trusted providers; real provider opt-ins
  have their separate scope.
- Analysis/CLI:15functions and36subcases passed ordinary/race/vet. Independent
  review checked source, persistence, ACK barriers, limits and panel configuration.
- Two ARM64 builds with separate empty caches produced identical3,565,542-byte
  binaries: SHA256cb95d52dcf6c601039a4f801fd4b1ca02fa16a8c89b7a87706ffbc553fd1edf6.
  Actual compiled CLI/minimap2 on the public fixture observed1,171mapped/1,171SAM
  records, one private target and configured0.9/high. Caller crypto facts were
  synthetic. This is standalone analysis and same-host/toolchain repeatability,
  not integrated protected entry, cross-host or OCI reproduction.

The earlier [CI38657120252](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38657120252)
passed for bba2637. It does not approve later source. Hosted CI skips provider
kernel opt-ins, biological models, Compose and Firefox. Each new published source
requires its own CI and exact-scope acceptance. Failed/weaker receipts and pending
charges remain preserved; no model or dataset was rerun to repair the build.

## Regulatory feasibility

The frozen10adapter and100evaluation cases completed finite, identical repeats.
Evaluation sign agreement61/100 and Spearman0.1840864086408641 describe GBR/LCL to
GM12878 transfer; they do not approve biological or clinical accuracy. Head-training
holdout, LD independence and feasibility remain unverified. The prior comparable
FP32/QNNPACK economic no-go is unchanged. Public exports contain aggregates and
hashes, without DNA, rows, case IDs, vectors or weights. See
[biological evaluation](experiments/005-biological-evaluation.md).

## Remaining requirements

1. Install pinned analysis/context in both providers and connect protected worker
   crypto, result projection and durable recovery through the broker. Repeat
   protected native/Compose science, A/B authorization, cancellation and restart.
2. Pin and verify the image dependency closure, build/distribution and licences;
   cached-image acceptance alone does not establish image reproducibility.
3. Inject attach/removal/storage uncertainty and define explicit operator
   reconciliation without silent adoption, refunds or reexecution.
4. Complete immutable ownership TM02 before principal artifact quotas, full
   result/event/cache/registry quotas and retention, queues/leases/multiple workers.
5. Complete effective SOC/benign adversary scenarios, cloud identity/storage/key
   controls and the final documented deliverables under the free-only constraint.

The full technical scope remains in [requirements and gates](requirements-and-gates.md).

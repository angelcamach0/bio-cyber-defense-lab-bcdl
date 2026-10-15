# BioZero: Integrated Bio-Cyber Defense Lab

BioZero runs genomic analyses with explicit identity, validation, failure states,
and reproducible evidence. Its first operational experiment is a small synthetic
variant benchmark. The wider roadmap includes regulatory-model evaluation,
sustainment tests, observability, and simulated response.

## Current milestone

The local native profile uses individual mTLS certificates, signed/encrypted
uploads, a single worker, a real variant pipeline, and an independent evaluator.
It checks two valid runs, cross-client denial, original hashes, invalid FASTQ,
missing client certificates, and unsigned submissions.

BZ-EXP-001 contains a deterministic 6 kb reference, 1,171 reads, and three known
SNPs. Acceptance means recovering the agreed allele set without extras, repeating
that callset, and rejecting the specified failure cases. This fixture does not
establish performance on human genomes, genotype accuracy, clinical validity,
scientific novelty, or hardware-enclave protection.

## Reproduce on Linux ARM64

Prerequisites: Git, Go 1.22 or newer, Python 3.9 or newer, OpenSSL, curl, and make.
The observed run used RHEL 9.8 ARM64 and Go 1.26.7. Free bioinformatics tools are
installed in a project-local prefix from a committed ARM package lock.

```bash
make bio-tools
make test
make experiment
```

If tools already exist elsewhere:

```bash
make experiment BIOZERO_TOOLS_PREFIX=/path/to/bio-tools
```

The native command starts its own loopback services, generates disposable demo
credentials, asserts the expected results, and stops its processes. It retains
each run under `biozero/docs/evidence/`. Only the `public/` evidence subdirectory
is suitable for sharing; `private/` contains credentials and runtime data.

Run only the scientific comparison with `make science`. See
[the reproduction runbook](biozero/docs/runbooks/reproduce.md) for diagnosis,
scope, versions, evidence, and the separate Compose configuration.

## Security and states

Protected mode is the default. APIs require complete TLS/mTLS configuration;
certificate CN and serial bind the job owner. The worker rejects failed integrity,
signature, or encryption checks before analysis. Results distinguish `succeeded`,
`incomplete`, `rejected`, `failed`, and `timed_out`. Historical `processed` records
are reported as incomplete until validated.

The HTTPS reviewer gateway now executes prepared experiments with per-user sessions,
CSRF protection, distinct mTLS transports and persistent job ownership. The real
four-service container/browser verification passed 31 assertions, including two scientific
runs, cross-client denial, restart/relogin and cookie revocation. Use
python3 -B biozero/infra/compose/run_reviewer_experiment.py to reproduce it;
see [local reviewer setup](biozero/infra/compose/README.md). Real Firefox acceptance
passed23 UI/TLS/session-race checks with zero JavaScript errors. The planned Oracle
deployment remains pending. ZeroResponder is optional simulation.

The initial implementation and curated evidence were merged through [PR #21](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/pull/21) on2026-10-14.
The [protected worker](biozero/services/enclave-runner/README-worker-backend.md)
now verifies encrypted signed inputs, stages verified plaintext in bounded tmpfs,
and submits through the v2 FD broker. Fresh native25-check and three-service
Compose30-check acceptance cover science, authorization and committed-result
recovery using the native capsule provider. Separate protected Docker-provider
acceptance now passed57checks and52independent retained-evidence checks, including
actual capsule configuration/kernel observations and exact artifact accounting.
The worker projects confirmed receipts
without invoking pipeline/evaluator/detection tools itself. Native execution trusts
the host filesystem; its namespaces do not establish host-file or same-UID isolation.
The standalone [container capsule provider](biozero/services/artifact-executor/README-container.md)
has separate quota and lifecycle acceptance. Integrated crash/cancel/lost-ACK
reconciliation and a reproducible image build remain pending. Pinned analysis executes inside both
providers through the broker, and the compiled
[host service](biozero/services/artifact-executor/README-service.md) has actual
native/Docker science, detection, restart and visible cleanup-failure acceptance.
The earlier provider tests used synthetic crypto facts; the new worker acceptance
performs actual signature/decryption checks. See
[protected acceptance](biozero/docs/evidence/20261015-protected-capsule-worker/public/README.md),
[complete analysis scope](biozero/services/artifact-executor/README-analysis-integration.md)
and the current status for the
source and publication scope of this subsequent delivery.
[Hosted ARM CI for98f2f89](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38661813114)
passed unit/PKI checks, the scientific repeat and the protected native experiment;
subsequent source has its own checks in the current PR.

Reports separate execution status from scientific release: evaluated_passed,
withheld or unassessed. A completed process alone does not approve scientific results.

## Project documentation

- [Implementation status](biozero/docs/STATUS.md)
- [Executive summary](biozero/docs/EXECUTIVE_SUMMARY.md)
- [Requirements, evidence and next gates](biozero/docs/requirements-and-gates.md)
- [Project flow guide](biozero/docs/PROJECT_FLOW_GUIDE.md)
- [Regulatory evaluation](biozero/docs/experiments/005-biological-evaluation.md)

The regulatory pilot completed a frozen100-case descriptive baseline: sign
agreement61/100 and Spearman0.1840864086408641. Biological accuracy, head-training
holdout and clinical usefulness remain unverified. The prior comparable economic
no-go remains unchanged. See [the adapter setup](biozero/research/regulatory/README.md)
for source access, pinned protocols, methods and limitations.

## License

GNU Affero General Public License v3.0 (AGPL-3.0). See `LICENSE` and `NOTICE`.

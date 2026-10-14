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
four-service container verification passed 30 assertions, including two scientific
runs, cross-client denial, restart/relogin and cookie revocation. Use
python3 -B biozero/infra/compose/run_reviewer_experiment.py to reproduce it;
see [local reviewer setup](biozero/infra/compose/README.md). Browser rendering and
the planned Oracle deployment remain pending. ZeroResponder is optional simulation.

Reports separate execution status from scientific release: evaluated_passed,
withheld or unassessed. A completed process alone does not approve scientific results.

## Project and team

- [Implementation status](biozero/docs/STATUS.md)
- [Agent workflow](AGENTS.md)
- [Team runbook and daily research](biozero/docs/team/runbook.md)
- [Active Notion notebook](https://app.notion.com/p/3ef7dff9bf6c817cb6d0d6d48b68a9d4)
- [Project flow guide](biozero/docs/PROJECT_FLOW_GUIDE.md)

The coordinator integrates science, security, engineering, and their support
reviewers. Daily hosted research records source changes separately from code
implementation. The regulatory-recomputation question remains a feasibility pilot.

## License

GNU Affero General Public License v3.0 (AGPL-3.0). See `LICENSE` and `NOTICE`.

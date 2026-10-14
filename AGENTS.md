# BioZero agent workflow

Use a coordinating agent and delegate independent work to science, security,
engineering, and documentation/QA agents. Each specialist should have a support
reviewer to prepare context, track blockers, and maintain evidence. Rotate these
roles within the available concurrency limit.

The user authorized an autonomous, documented, reproducible implementation and
daily research. Preserve the existing free-only constraint and source history.
Read `biozero/docs/STATUS.md` and the team runbook before choosing the next task.
Consult the current Cloud Environment runtime skill before environment/network
work; distinguish observed runtime capabilities from saved deployment plans.

## First milestone

Build a deterministic synthetic variant experiment with a valid run, meaningful
failure cases, per-client authorization, and a repeatable evidence report. The
regulatory-recomputation idea remains a feasibility pilot; do not claim novelty
or biological accuracy without appropriate evidence.

## Coordination and review

- Assign one writer per file or directory. Agree on contracts before parallel edits.
- Preserve unrelated changes. Use an isolated branch or worktree when appropriate.
- Security reviews protected entry, identity, authorization, key scope, and release.
- Science freezes inputs, truth, scope, metrics, and acceptance before evaluation.
- QA checks both success and failure; documentation records what actually happened.
- Thank teammates and give positive reinforcement tied to concrete contributions.
  Make blockers actionable and keep feedback respectful. Praise does not replace review.

## Evidence

Distinguish static inspection, executed tests, published results, inference,
proposal, and pending work. A test passes only with observed results matching its
acceptance criterion. Never infer scientific success from an exit code or the
historical `processed` state. Preserve original upload hashes and separate derived hashes.
Do not expose credentials, raw sensitive datasets, or material from private repos
in public artifacts. Use synthetic/public authorized data for the first milestone.

Persist handoffs, decisions, and run evidence so another session can resume.
Conversational subagents are session workers; the verified scheduled research
automation is separate. Reconcile its existing configuration before creating a duplicate.

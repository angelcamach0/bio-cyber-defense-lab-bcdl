# BioZero repository instructions

Read `biozero/docs/STATUS.md` and `biozero/docs/requirements-and-gates.md` before
changing implementation. Keep changes scoped, assign one writer per file during
parallel edits, and independently review identity, cryptography, durable state,
resource limits and scientific-release changes.

Preserve the free-only constraint. Consult the current Cloud Environment runtime
skill before environment/network work. Distinguish observed capabilities from
saved deployment plans and protect credentials and private data.

Run the checks appropriate to changed code. `make test` discovers all Go modules
and runs their package tests/vet. A service build selects its root executable;
additional commands are compiled explicitly. Native/Compose acceptance has its
own source and runtime scope, separate from unit tests and hosted CI.

Keep original upload hashes separate from processed-input and derived-artifact
hashes. A successful exit does not approve scientific release. Record actual
source/input/configuration pins, outcomes and limitations. Preserve failed and
weaker receipts; never reset historical accounting to make a run pass.

Do not publish credentials, raw sensitive datasets, private-repository material,
internal coordination notes or personal team details. Keep public documentation
focused on architecture, requirements, reproduction, results and known gaps.

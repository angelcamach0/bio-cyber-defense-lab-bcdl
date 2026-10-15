# Analysis inside native and Docker capsules

The native and Docker providers can now run the pinned `capsule-analysis`
executable after the pipeline and scientific evaluator, within the same capsule,
workspace and deadline. The protected worker is not connected to this path yet.
The [host broker service](README-service.md) exposes the fixed v2 FD protocol;
it is a separate host process, without a Docker socket in the worker.

## Configuration and input binding

`CapsuleAnalysisConfig` fixes executable, rules and optional panel path/SHA256
pairs. Providers verify these assets before creating producers and helpers check
them again inside the capsule. Executables must be regular, single-link, owned
by the mapped host UID, executable, without group/other writes or special bits.
Limits are4MiB executable,64KiB rules and32MiB panel. Rules and configured panel
must agree on panel presence; callers cannot silently disable detection.

`AnalysisContext` contains the original name, processed size, signature and
decryption facts, and their bounded error strings. These facts are supplied by
the protected-entry verifier; the broker does not establish their cryptographic
truth. Name is bounded4096 UTF8 bytes, errors128 each, processed size must equal
the verified input length, and contradictory success/error facts are rejected.
Registration and acquisition each copy the value alongside the one-shot input
authority. V2 journals persist the exact context before reservation; changed facts
conflict rather than generating another execution. V1 wire/history remain separate.

Analysis configuration and context must either both exist or both be absent.
The complete host service requires analysis. Legacy providers preserve execution
schema1 when neither exists; configured analysis uses execution/receipt schema2.
The helper FD-response envelope remains schema1. Existing stores/journals are not
migrated, reset or adopted automatically.

## Capsule execution and failure behavior

The native helper binds analysis assets read-only outside the noexec workspace.
Docker mounts them individually read-only at fixed `/run/biozero/analysis/`
paths and verifies the observed mounts. Executable and data sources are not copied
into writable executable storage. Pipeline, evaluator and optional minimap2
alignment/detection share the capsule's128MiB/4096-inode workspace,64MiB file
limit and execution deadline. Native resource observations differ from Docker's
observed512MiB/no-extra-swap/128PID/one-CPU cgroup controls.

The helper supplies exact argv and a schema1 analysis request containing context
and the complete pipeline payload. Request and response are each at most64KiB;
larger input fails explicitly without projection or truncation. Stdin writes and
stdout/stderr reads are multiplexed to avoid pipe deadlock. Stderr is bounded64KiB.
The analysis component separately bounds SAM bytes, lines, records and targets.

Rules may fail before the CLI reads stdin. An early closed stdin is accepted only
with a complete schema1 failed response and exit1, followed by strict response
validation. Successful output with incomplete input is rejected. Partial JSON,
overflow, invalid response or tool failure never approves a result. When no valid
complete response exists, the receipt records null exit/payload and a stable
helper error; it does not invent a process exit or metrics.

Valid failed/incomplete pipeline payloads still receive analysis. A fatal capture,
timeout or invalid evaluator boundary may terminate earlier, with no approval;
those failures do not establish completed detection. Analysis failure changes
the outcome to failed/withheld even if the evaluator already passed. The private
receipt preserves the bounded captures, context and all verified source pins.
Exact provider termination, export fencing, Store proof/commit, journal sealing
and actual socket acknowledgement still precede readback.

## Observed acceptance

Actual v2 Unix/FD broker, registry, native/Docker provider, pipeline, evaluator,
analysis executable, Store and socket acknowledgement were composed on Linux
ARM64. Each backend ran both scenarios:

| Scenario | Scientific evaluator | Analysis | Committed outcome |
| --- | --- | --- | --- |
| Public synthetic panel enabled | TP3/FP0/FN0, precision/recall1 |1,171/1,171 SAM records, score0.7/medium | succeeded/evaluated_passed |
| Unknown field in pinned rules | TP3/FP0/FN0, precision/recall1 | exit1, rules_parse_error, no detection | failed/withheld |

The panel is the fixture's public synthetic reference. The existing rule label
`threat_panel_hit` and configured score describe that fixture match, not biological
danger, clinical accuracy or an independently calibrated security classifier.

Tests verify four retained exports, observed=evaluated=retained VCF hash, exact
analysis pins/context, journal/Store/proof before actual ACK, receipt FD bytes,
duplicate custody without reexecution and conflicting context rejection. Source
assets and all raw receipts remain private. The test's original-upload digest and
crypto flags are synthetic; the named private input is a public fixture, not an
accepted production plaintext-staging design.

The compiled analysis binary is3,565,542 bytes, SHA256
`cb95d52dcf6c601039a4f801fd4b1ca02fa16a8c89b7a87706ffbc553fd1edf6`.
It was rebuilt offline with Go1.26.7/CGO0 and matched the earlier same-host builds.
That does not establish cross-host or OCI image reproducibility. The Docker
acceptance uses the previously cached exact image; it does not build or pull one.

The first combined race invocation preserved110 passing top-level functions,
270 passing subcases, two internal keeper skips and two quota fixture failures:
the selected quota evidence parent did not exist. Those failures occurred before
container execution. The orchestration then created a fresh parent; no runtime
guard or historical directory was changed. The subsequent combined eight-opt-in
run passed121 top-level functions and302 subcases with only the two internal
parent keeper skips. The keepers execute in child processes. This snapshot
preceded the separate host-service socket-close correction; its source inventory
and receipts retain that scope. The later service checks are recorded separately.

Private evidence roots:
`.biozero/complete-analysis-race-20261015T010436.803240Z/` and
`.biozero/complete-broker-checks-20261015T010957.828533Z/`.
Independent readback verified the first four receipt/manifest/proof/journal
bindings and exact accounting without repeating tools. Native receipts contain
process/FSIZE observations; they do not contain an additional mount/statfs snapshot.
Docker receipts include observed read-only analysis mounts, tmpfs and cgroups.

After the separate host-service close correction, final `make test` passed263
Python cases(261 passed/two namespace opt-ins skipped) and test/vet in eight Go
modules. Final artifact race checks passed114 top-level functions and295 subcases
in11.788s, including both actual compiled-service profiles. Eleven other explicit
kernel functions skipped; provider/helper/bridge source pins match the earlier
full snapshot and those tools were not rerun for the service-only correction.

The compiled service passed print-profile without creating state, actual capsule
science/detection, clean SIGTERM exit0, committed-history restart with identical
receipt bytes/lease/manifest and no new execution, then deliberate replacement of
its own test socket with a regular marker. SIGTERM then produced exit1, preserving
the marker, journal, ledger and exact charge. Store revalidation succeeded after
both exits. These processes are terminal; there is no persistent deployment.

Final binary:5,128,722 bytes, SHA256
`c6cea629b14cafc4abc4cda69a4d8db60f5de569cf89036e4460e2f156f57194`.
Private evidence:
`.biozero/broker-service-final-checks-20261015T011527.352455Z/`.
Independent readback matched146 source pins, all three logs, both configuration/
executable-derived profiles, private receipt/proof/manifest bindings and exact
accounting. This was receipt inspection, not another execution.

## Reproduction and remaining integration

Build analysis from `../enclave-runner`, with an existing output directory outside
the chosen state roots:

```sh
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags=-buildid= \
  -o /absolute/private/bin/capsule-analysis ./cmd/capsule-analysis
```

Build broker from this module:

```sh
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags=-buildid= \
  -o /absolute/private/bin/artifact-broker ./cmd/artifact-broker
```

From this module on the prepared host, select new private evidence destinations:

```sh
BIOZERO_RUN_CAPSULE_ANALYSIS_ACCEPTANCE=1 \
BIOZERO_CAPSULE_ANALYSIS_BINARY=/absolute/private/bin/capsule-analysis \
  go test -race -run '^Test(Native|Container)CapsuleCompleteAnalysis$' -count=1 -v
BIOZERO_RUN_BROKER_SERVICE_ACCEPTANCE=1 \
BIOZERO_ARTIFACT_BROKER_BINARY=/absolute/private/bin/artifact-broker \
BIOZERO_CAPSULE_ANALYSIS_BINARY=/absolute/private/bin/capsule-analysis \
  go test -race -run '^TestBrokerServiceActualNativeAndDocker$' -count=1 -v
```

These are explicit kernel/Docker opt-ins. Missing prerequisites fail visibly;
ordinary unit tests skip them. Preserved failed/pending histories are never reused
to make a run pass. Existing native/Docker tool versions have different dependency
closures; synthetic equivalence does not erase those differences.

Remaining work is protected crypto→FD submit, verified bounded tmpfs plaintext
staging, worker result projection from the committed receipt, durable worker
recovery, and fresh protected native/Compose authorization/science/lifecycle
acceptance. Reproducible image closure/distribution, operator reconciliation,
immutable ownership, full quotas/retention, queue/leases, SOC/cloud and final
delivery remain in the [requirements](../../docs/requirements-and-gates.md).

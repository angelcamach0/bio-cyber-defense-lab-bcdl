# Fixed host artifact broker service

`cmd/artifact-broker` provides a v2 FD broker service around the existing Store,
registry, coordinator and one host-configured native or Docker provider. The
protected worker has [separate integrated acceptance](../enclave-runner/README-worker-backend.md)
using the native provider. Requests cannot choose commands,
paths, references, rules, images, policies or mounts. Only the configured Unix UID
can submit its asserted verification facts; this is not tenant authentication,
cryptographic proof, host attestation or a production deployment.

Build the command explicitly from this Go module:

```sh
go build -o /absolute/private/bin/artifact-broker ./cmd/artifact-broker
/absolute/private/bin/artifact-broker --config /absolute/private/service.json --print-profile
/absolute/private/bin/artifact-broker --config /absolute/private/service.json
```

The operator supplies a current-UID, regular, single-link0600 configuration file.
Every path ancestor is traversed without following symlinks. JSON is bounded64KiB;
all fields are required, including unused empty strings, arrays and asset pairs.
Unknown, duplicate, missing or null fields are rejected. Config fields mirror the
exported `BrokerServiceConfig` DTO in `service_config_linux.go`; generating JSON
with that DTO avoids relying on omitted defaults.

Required fields are schema_version1, provider(native/docker), mode(stats/variants),
store_root, journal_root, workspace_root, socket_path, allowed_uid,
timeout_seconds(1..600), python_path, tool_path, docker_command, image_id,
native_helper, container_helper, pipeline, resource_budget, reference, evaluator,
truth, analysis_executable, analysis_rules and analysis_panel. Each asset object
contains exactly path and sha256. Native requires a resolved safe executable
python_path and absolute tool-path directories, empty Docker fields and empty
container_helper. Docker requires its existing local-daemon command allowlist,
an explicit sha256 image ID, empty Python/tool fields and both helper assets.
No image is pulled or built automatically.

Analysis executable/rules are mandatory. Panel presence must agree with rules.
Variants requires reference/evaluator/truth; stats requires empty evaluator/truth.
resource_budget.py must be next to pipeline.py. All paths are absolute and clean.
Store, journal, workspace and socket directory must be separate, with no ancestor
or descendant overlap. Assets/interpreter/tools remain outside those state roots.
Policy is fixed to NativeArtifactPolicy; resource and lifecycle guards are the
existing providers' contracts. Connection count8, request5s, run15min and write5s
are fixed. The provider execution deadline is separately bounded by the config.

`--print-profile` validates config, private metadata, asset bytes, analysis panel
presence and fixed policy before printing only a SHA256 identifier. It creates no
state, socket or provider and contacts no Docker daemon. The canonical profile
binds that exact configuration and NativeArtifactPolicy to the SHA256 of the
running service executable read from the kernel's /proc/self/exe reference, bounded
32MiB. Use the same compiled binary for inspection and service execution. Changed
config/assets/service bytes require their own profile and compatible explicit
state; existing journals are never silently adopted or migrated. This identifier
does not pin every native interpreter/tool dependency, verify image availability,
prove reproducible OCI builds or attest the host.

Serving verifies the profile/assets before provider/state creation and opens the
Unix socket last. SIGINT/SIGTERM stops channels and asks the broker to cancel;
shutdown waits up to40s for proven completion. Provider, registry and Store close
only after broker Wait succeeds and Store remains healthy. Pending work, lost ACK,
storage failure or uncertain provider completion retains its authority in the
service handle until process exit. The command keeps that handle reachable and
exits with a generic error. Durable history/charges remain unchanged; an exit is
not permission to retry, refund, delete or adopt old work. Workspace remnants and
pending Store history continue to prevent an accepted restart.

New source requires its own tests. Unit tests use synthetic providers and real
private Store/journal/Unix sockets, with no namespace, Docker, external network,
models or protected crypto. Those checks do not establish actual worker/capsule
acceptance or deployed readiness.

## Actual compiled-service acceptance

The subsequently rebuilt ARM64 command ran both real providers with the public
synthetic fixture and asserted caller crypto facts. It verified print-profile
without state creation, three-SNP science and in-capsule panel alignment, private
receipt FD custody, clean SIGTERM exit0 and committed restart without reexecution.
Replacing only that fixture's socket pathname with a regular marker then produced
exit1 and preserved the marker, journal, ledger and exact retained charge. The
Store verified successfully after both exits. The profile was obtained using the
same binary that served requests, not the Go test executable.

Final command SHA256:
`c6cea629b14cafc4abc4cda69a4d8db60f5de569cf89036e4460e2f156f57194`
(5,128,722 bytes). Private evidence:
`.biozero/broker-service-final-checks-20261015T011527.352455Z/`.
Independent readback checked profiles/configuration,146 source pins, receipt/
proof/manifest and exact accounting, without rerunning tools. See
[combined analysis acceptance](README-analysis-integration.md) for commands,
counts, preserved earlier failures and scope. Actual worker TLS/signature/
decryption entry, production deployment and OCI reproducibility remain unproven.

The first dedicated service SDK/CLI checks passed8top-level functions and30subcases
in ordinary and race executions; module vet exited0. The real native/Docker
service acceptance function skipped because its opt-in was not enabled. These
unit runs used fake providers and metadata-only synthetic assets; their real
Unix/Store checks prove no namespace or analysis execution. Evidence is private
under `.biozero/broker-service-unit-20261015T010851.075587Z/`. Actual compiled-service
and protected-worker checks require their own evidence.

The service now owns its cancellation callback and caches the actual first socket
cleanup result, leaving the base v1 transport unchanged. A socket replacement or
unsafe metadata remains untouched and produces an error even after healthy,
quiescent custody closes, including on repeated Shutdown calls. A socket cleanup
error never bypasses provider cancellation or Wait. The command therefore exits
nonzero for that cleanup failure; it does not repair/delete the marker or reset
retained accounting.

After this correction, dedicated SDK/CLI ordinary and race runs passed10top-level
functions and34subcases; vet exited0. The actual-service opt-in skipped in these
narrow unit runs. New fault cases cover cancellation-owned and direct shutdown,
replacement/unsafe sockets, persistent repeated errors, unchanged idle ledger and
journal, and an active fake provider that must cancel/complete while preserving
its charged committed history. Evidence remains private under
`.biozero/broker-service-closefix-20261015T011348.151626Z/`. Prior source receipts
remain preserved and are not relabeled as validation of this correction.

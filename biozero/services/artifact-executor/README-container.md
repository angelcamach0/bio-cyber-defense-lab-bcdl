# Pinned Docker capsule provider

The standalone Linux ContainerProvider executes the synthetic pipeline and its
evaluator in a per-job container controlled by the trusted host broker. The
protected worker now uses it through the v2 FD protocol, with
[57actual protected assertions and52independent readback checks](../../docs/evidence/20261015-protected-docker-capsule-worker/public/README.md).
The worker receives no Docker socket or general
container-command API. Existing native and container acceptance have separate
source, resource and lifecycle evidence.

Subsequent [complete analysis acceptance](README-analysis-integration.md) installs
pinned analysis/rules/panel and per-job context inside this capsule. It composes
the v2 FD broker and compiled [host service](README-service.md), including failed
analysis withholding and committed readback. Protected crypto entry now has its
separate acceptance above;
the earlier receipts below are not relabeled as that newer source or scope.

## Trusted configuration and entry

ContainerProviderConfig fixes a local Docker argv prefix, exact cached image ID,
source-file SHA256 pins, mode, workspace metadata root and deadline. Only the
local unix:///var/run/docker.sock endpoint is allowed, directly or through the
configured host sudo command. Image pulls are forbidden. Host Docker credentials
and DOCKER_CONFIG remain configured; endpoint/context/TLS selectors are cleared
for that command. Host administrator/daemon and same-UID source writers remain
trusted. This is not external attestation or a sandboxed host Docker authority.

Store reservation and Begin precede provider execution. A private fsynced intent
precedes create, followed by a private fsynced exact container-ID record. Fresh
random names and store/lease/nonce labels prevent name-based adoption. Ambiguous
create/identity/wait retains full pending custody, metadata and unavailable state.
Startup refuses any previous metadata anchor; there is no timeout-based release,
implicit reconciliation, historical deletion or automatic reexecution.

The host inspects the exact ID/image/labels, command, user, environment, mounts and
resource policy before start. The image's original worker entrypoint is replaced
by the pinned Python helper, without init/tini. Configuration and source hashes
are host-only inputs, absent from run/status/cancel RPC. Source binds are individual
read-only files: both helpers, pipeline/resource_budget, evaluator, reference and
truth when configured. The only directory bind is the private read-only control
directory. No host plaintext staging or input path is mounted.

After connection, host SO_PEERCRED must match UID/GID1000 and the exact running
container PID1 from inspect. Only then does the host transfer byte I and one
read-only input FD. The helper requires CLOEXEC, regular/private/single-link
metadata, exact length and the separately registered plaintext hash, copying only
inside tmpfs. Original-upload identity remains distinct. The protected worker now
registers these facts only after its actual crypto barrier, as separately accepted.

## Observed kernel boundaries and custody

The container runs UID/GID1000 with read-only root, no capabilities,
no_new_privs, no network, private PID/IPC/cgroup namespaces, no restart, no published
ports or extra devices. Its workspace tmpfs is128MiB,4096 inode units, mode0700,
uid/gid1000, nodev/nosuid/noexec. Hard/soft FSIZE are64MiB. Declared memory is512MiB
without extra swap, PID limit128 and CPU quota one core. The helper verifies
actual mount/statfs, process state, FSIZE, interfaces and cgroup-v2 memory/swap/
PID/CPU values before copying input or invoking tools. An unsupported primitive
fails visibly; no per-file fallback replaces aggregate workspace enforcement.
Docker's standard devices and its separately bounded64KiB shared-memory mount
remain outside the workspace; this is not a quota for every filesystem or host.

The pinned native helper is hashed before compiling precisely those bytes; its
unchanged parsers/captures/evaluator/framing functions are reused. Tools inherit
an explicit offline environment and no input/control descriptors. A keeper-loss
monitor exits only its verified namespace PID1 on EOF/error/unexpected data.
That cancellation mechanism is not proof of quiescence. Request cancellation
closes accepted channels promptly without waiting for Docker kill to succeed.

The helper sends bounded outcome metadata and ordered read-only SCM_RIGHTS exports.
The host establishes quiescence through Docker wait plus exact final inspection:
same ID/image/labels/config, exited, no running/restarting/paused/dead state, PID0
and matching exit code. CLI attachment completion is separate. Exact container
removal follows authoritative wait and precedes export commitment; removal is
never used as proof of death. Incomplete attachment/removal retains anchors and
latches admission. Received FDs preserve tmpfs objects across namespace/removal;
actual export bytes, hashes and cumulative budget are rechecked by Store.
Science approval still requires observed=evaluated=retained normalized VCF.

## Executed synthetic module evidence

The cached local image is
`sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d`.
The actual Unix/client/coordinator/container/store opt-in passed with the race
detector: body1.39s, Go2.413s. Private evidence root:
`.biozero/container-provider-second-20261014/`.
Execution receipt SHA:
`a6c28358abc21e72b7a611212e2a56c6ccaf0e2e03b8699d3e2dbb6f8b384a73`.
Independent review verified kernel limits, source pins, four exports, proof and
manifest bindings, TP3/FP0/FN0 with precision/recall1, and identical observed/
evaluated/retained VCF digests. The real socket reply was audited after durable
commit. Host control anchors were empty and the successful container was removed.

The first actual attempt failed before start because Docker's optional CapAdd
list was null and a template called len on it. Serialization now explicitly
encodes absent optional capability/device/port/volume lists as zero, while the
strict predicates still reject every nonempty list. The failed fixture retains
executing/full charge, intent, exact ID and its Created container; it is not
silently adopted or promoted to accepted evidence. No input FD or tools ran there.

The helper's21 stdlib/Unix-IPC tests passed independently; those fake-kernel
predicate tests do not establish actual Docker acceptance by themselves.
[Security review](README-container-security-review.md) distinguishes inspection,
execution and remaining fault cases. Separate actual
[byte/inode acceptance](README-container-quota.md) passed both cases with the race
detector (Go2.933s): ENOSPC independently exhausted data bytes and inode units,
retaining failed/withheld receipt custody and positive charge. Separate
[recovery acceptance](README-container-recovery.md) passed three cases and59
assertions in ordinary and race runs (10.777s/11.912s): cancellation, timeout and
keeper death, including immediate restart denial and preserved pending history.
These fixtures do not exercise science or replace the successful Unix case.

## Reproduction and remaining scope

From the artifact-executor module on the compatible prepared host:

```sh
BIOZERO_RUN_CONTAINER_PROVIDER_ACCEPTANCE=1 go test -race \
  -run '^TestContainerProviderActualSyntheticUnix$' -v -count=1 -timeout=200s
```

BIOZERO_CONTAINER_PROVIDER_EVIDENCE_DIR selects a new absolute private destination;
the default is a new timestamped root under ignored .biozero. Existing destinations
are refused. The cached image must exist with that exact ID: this receipt is not
a reproducible image-build/publishing claim. Image locking/distribution and
production deployment remain open; protected worker integration is separately
accepted above.

No model or external dataset was run or downloaded, and no image was built/pulled
for this acceptance. Original input identity is a synthetic encrypted-upload
placeholder; actual worker TLS/signature/decryption was not exercised in those
earlier component receipts. Protected positive/recovery acceptance is now separate;
integrated worker/broker death/cancel/lost-ACK, operator recovery, full quotas/retention, immutable
ownership and production/cloud delivery remain required. Synthetic allele presence
does not establish genotype, indel, human-genome or clinical accuracy.

# Container provider security review

Status: source review, positive receipt readback and separate recovery/quota
readbacks completed; attach/removal fault injection and worker integration pending.
The code review and readback of positive and quota receipts were read-only,
with no Docker/test execution as part of those reviews. The later actual Docker
lifecycle recovery cases were executed separately and are documented in
[the recovery README](README-container-recovery.md). No image build/pull, model
or external network operation was performed in these acceptance tasks.
Native and earlier Docker prototype receipts retain their separate source scope.

Recorded runtime profile: Docker 29.9, local root-owned Docker CLI/socket and
cached image sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d.
These are required inputs, not readiness observations independently rerun here.
The configured host orchestrator has existing sudo/Docker authority. Capsule
UID 1000/caps-zero restrictions do not sandbox that host authority.

## Identity and creation authority

- DockerCommand is the explicitly configured argv vector for the root-owned local
  CLI: /usr/bin/sudo -n /usr/bin/docker --host=unix:///var/run/docker.sock. There is
  no shell, browser-selected endpoint, image, command, policy or mount surface.
  Clear only DOCKER_HOST/DOCKER_CONTEXT/DOCKER_TLS/DOCKER_TLS_VERIFY/DOCKER_CERT_PATH
  selectors for this local command, as required by the Cloud runtime Docker
  reference. Preserve DOCKER_CONFIG, registry credentials and host SDK guards;
  their local administrative configuration remains trusted. Never dump them.
- Create uses the exact immutable cached image ID and pull=never, with a fresh
  cryptographic nonce and labels tying current store/lease/nonce. Never use --rm,
  --replace, a mutable image tag, a previous cidfile or automatic label/name search.
- Only a newly returned 64-lowercase-hex container ID can become this operation's
  authority. Before start, inspect its exact ID, Image, labels, user, entrypoint,
  command and every relevant HostConfig field. Use that ID for all later commands.
  A known name is not equivalent to this authority.
- Create/start/inspect ambiguity fails pending without adopting/deleting unknown
  containers. In particular, a canceled start plus a transient created/PID 0 state
  is not sufficient teardown proof. Missing container/daemon failure is not an
  exited receipt. Retain full reservation and private anchor for operator review.

## Configured capsule boundary

Helper must be actual PID1, overriding cached worker entrypoint/Cmd. Do not insert
an unreviewed init wrapper that changes peer PID or wait authority. Verify fixed
UID/GID 1000, root read-only, network none, private PID/IPC namespaces, no privileged
mode, added capabilities, devices, ports, Docker socket, host PID/network, or
restart policy. Explicit caps drop ALL and no_new_privs apply before tools.

The intended resource profile is workspace tmpfs 128MiB/nr_inodes4096 with
uid/gid 1000, mode 0700, nosuid/nodev/noexec; hard+soft FSIZE 64MiB; memory 512MiB,
pids 128 and CPUs 1. Inspect the actual Docker values and have the helper check its
kernel-visible state. If total memory including swap is claimed, MemorySwap must
be set consistently with Memory rather than silently using Docker defaults.
FSIZE alone is never aggregate workspace enforcement. The current inspect gate
also requires private cgroup namespace, MemorySwap equal to Memory, zero inherited
image volumes and an explicit 64KiB /dev/shm. The helper checks the read-only
private cgroup-v2 view and its memory/swap/pids/CPU limits before pipeline launch.

Mount only individually configured/pinned source/reference/evaluator/truth assets
read-only. Do not mount whole repository, PKI, signing/CA keys, Store or artifact
root. The control directory/socket are also mounted read-only: connect needs no
new directory entry. Verify this connectivity on the real daemon rather than
silently falling back to RW. No input or artifact data is mounted. Reject separator/control characters that could
change Docker --mount CSV interpretation. /proc/self/fd in a Docker mount source
refers to the CLI/daemon, not the keeper: never treat it as that keeper's anchor.
Host paths, source writers and the Docker daemon remain trusted.
Reject inherited image Volumes and unexpected mounts. Define IPC/shm policy
explicitly; Docker's default /dev/shm and device pseudo-filesystems are not the
workspace tmpfs. Do not claim a complete filesystem or host-memory quota from
the workspace bound alone. Capsule Env is an exact allowlist, with explicit
offline proxy values; reject unexpected Docker-client injected proxy variables.

## Control, input and export descriptors

The chosen input transfer creates no plaintext spool or input mount. Accept the
control connection only after SO_PEERCRED UID 1000 and peer host PID match the
fresh container's inspected running PID1. Same-UID host trust remains; this is not
independent tenant authentication or attestation. Do not weaken UID/PID checks to
accommodate unverified daemon userns remapping.

Only then send byte I plus exactly one read-only SCM_RIGHTS input descriptor.
Helper checks bounded ancillary data, truncation, CLOEXEC, readonly flags, private
regular owner/single-link metadata, exact size and plaintext SHA. It establishes
FD3/4 without accidentally closing or leaking duplicates, then starts EOF monitoring.
No tools inherit control/input, lifetime flock, caller sessions or keeper authority.

Host accepts exactly one bounded typed response and at most four ordered readonly
export descriptors. Extra/truncated/duplicate/unknown rights or frames fail closed;
all installed rights close on every error. Received descriptors must be CLOEXEC,
regular/private/single-link/readonly with actual size and streaming digest checks.
Sources, observed/evaluated/retained digests, execution receipt and outcome must
stay coherent. Export still shares 64MiB and requires execution_receipt policy
explicitly; older Store policies cannot silently migrate.

## Termination, custody and restart

Docker CLI completion alone is never capsule completion. After its wait transport,
inspect the same verified ID and require exited, Running=false, Restarting=false,
Paused=false and PID 0, plus coherent exit/result information. Only after this
boundary may descriptors be exported and the coordinator prepare proof/commit.
Cancellation/timeout kills only the exact owned ID, then uses a fresh bounded
cleanup context for kill/wait/inspect even when the request context is canceled.
Unknown final state returns Quiescent=false and preserves pending charge/anchor.

The helper EOF watchdog must cause PID1 to exit even if ordinary cancellation is
ignored. Keep that EOF fence alive through tools/descriptor send; ensure no CLI or
tool inherits a duplicate keeper endpoint that masks death. Do not use a readiness
marker, a PID-only scan, a response frame or force-removal as teardown proof.
Keeper loss may close flock before cleanup; durable executing history independently
blocks immediate and later restart, even after all observed tasks disappear.

Only the coordinator constructs Store proof after real wait/export fencing and
commits custody before actual socket ACK. A lost write keeps the commit/charge and
latches as specified. A failed/withheld commit after authoritative termination is
legitimate; it is distinct from unknown pending execution. Neither terminal status
nor EOF refunds slots, reruns work or authorizes old-container adoption. Cleanup
removes only positively identified new resources; failures remain visible.

## Required negative acceptance before runtime claims

1. Wrong cached image/config/label/ID, wrong peer UID/PID, unsupported daemon userns,
   unknown existing anchor and ambiguous create/start: no input transfer or tools,
   no adoption and no false quiescence/ACK.
2. Partial/truncated ancillary input/output, duplicate/unexpected rights, readonly/
   mode/size/hash errors, oversize/trailing frames and FD inheritance: safe failure,
   no leaks and no scientific release.
3. Daemon/CLI wait failure or misleading successful CLI, inspect still-running or
   missing/changed container: pending unavailable rather than a manufactured proof.
4. Actual configured kernel resource/state checks, aggregate exact/+1 and inode
   growth, sources RO, source/evaluator/outcome disagreements, export/cleanup/ACK
   failures: no passing result after an invalid boundary.
5. Real cancellation/timeouts and provider/keeper death: exact-ID cleanup, immediate
   flock/pending denial before observing cleanup, late pending denial without
   proof/refund/rerun, private receipts and scoped resources accounted afterward.

No installed worker/Compose, physical host spool/retention quota, operator adoption,
production tenant identity, external attestation, hardware enclave or biological
accuracy follows from design review or native standalone acceptance.

## Second source readback

The following source snapshots were reviewed without executing Go, Python tests,
Docker, tools, models or network operations:

- `container_provider_linux.go`: SHA256
  `f2097585c4c6591661e1a9cbbd745de63b028aeed84aabfb13ed4f28b560d641`.
- `capsule/container_capsule.py`: SHA256
  `56b2a3883d5201f3d227dc58fe4edf0577c0136b4ea707542491ed32c0a29ac8`.

Tests had not yet run at this readback. These hashes identify the reviewed
bytes, not a runtime freeze or passing acceptance result.

| Earlier finding | Readback of the correction | Remaining evidence |
| --- | --- | --- |
| Cancellation waited on Docker kill and left an accepted channel open. | Go `stopOnCancel` closes the listener first; a separate context callback closes the accepted channel. EOF no longer depends on daemon success. | Actual cancellation with daemon/CLI failure and scoped resource accounting. |
| A verified wait followed by unfinished attach or failed removal could discard custody metadata. | Go keeps `verifiedWait` and `removed` separate; either failure latches Store and retains the private anchor and provider uncertainty. No export or ACK occurs on those branches. | Fault injection for both branches, including restart denial. |
| Mounting parent source directories exposed unpinned siblings. | Go `mounts` now enumerates individual source files; the only directory bind is private control, also read-only. | Actual RO Unix-socket connection and inspection of the resulting mounts. |
| Keeper-loss signaling could raise before PID1 exit. | Helper `keeper_lost` uses direct `os._exit(1)`; monitor errors also invoke loss handling. | Actual keeper loss, independent Docker termination observation and durable pending restart. |

Other controls verified by reading: private fsynced creation intent and exact
returned container ID; no old-anchor adoption; pre-start image/label/config
comparison; UID/GID/PID binding before input rights; exact final Docker state and
exit-code comparison before export; helper bootstrap compiles the bytes whose
digest was checked, rather than reopening their pathname. No additional concrete
blocking defect was identified in this second readback. That conclusion is scoped
to static inspection under the trusted-host/daemon/source-writer assumptions.

Cancellation can retain a reservation even after an authoritative wait if cleanup
or attach custody remains uncertain. A restart must not convert that retained
anchor into an implicit retry, refund, adoption or successful ACK. Tests must
observe both the immediate restart window and the state after process cleanup;
neither a response frame nor disappeared processes alone establish custody.

## Real positive acceptance and final template readback

`TestContainerProviderActualSyntheticUnix` executed on 2026-10-14 with the
opt-in real local Docker profile. The first attempt failed before start because
the inspect template called `len` on a nil optional Docker field. It did not
transfer input or execute tools. The private first history remains `executing`
with full export-plus-publication reservation, intent and exact returned ID, and
without manifest or proof. Readback verified those retained files; no old
container was adopted or a ledger reset used to turn this failure into success.

Only four optional count encodings changed: `CapAdd`, `Devices`,
`PortBindings` and image `Volumes` now produce zero when nil/empty, and `len` when
nonempty. Readback confirmed the final template and unchanged zero-count
predicates. An added capability, device, published port or inherited image volume still fails
inspection. This fixes serialization availability rather than relaxing the
configured boundary. The reviewed/accepted Go source SHA256 is now
`36d6e1be27026588a8280def67f72610a7b3bf30fc2fff4ecc8cd64c06c76e1f`;
the helper remains `56b2a3883d5201f3d227dc58fe4edf0577c0136b4ea707542491ed32c0a29ac8`.

The second attempt used a separate new private history. The recorded real
acceptance passed, with 1.39s test body and 2.413s race-instrumented invocation.
Independent readback checked its persisted artifacts without rerunning it:

- Four exports have matching actual sizes and SHA256s; manifest and proof bind
  the same store/lease/input/policy, and the proof hashes the exact manifest bytes.
- Observed, evaluated and retained normalized VCF digests agree. The evaluator
  returned zero with TP=3, FP=0, FN=0, precision=recall=1 and `passed`; manifest
  execution is `succeeded` and release `evaluated_passed`.
- Receipt records actual PID1/UID/GID1000, all capability sets zero, NNP1, loopback
  only, read-only root/source mounts, tmpfs128MiB/inodes4096/private empty workspace,
  FSIZE 64MiB and private cgroup-v2 memory512MiB/swap0/pids128/one-CPU limits.
- Five source asset size/digest pins and the native helper digest match current
  source bytes. Receipt SHA256 is
  `a6c28358abc21e72b7a611212e2a56c6ccaf0e2e03b8699d3e2dbb6f8b384a73`.
- The positive control directory is empty and retained evidence directories/files
  use 0700/0600. The acceptance records removal of its newly created container
  after verified wait; readback made no daemon query. The test checks commit/proof
  before the actual Unix reply callback; this ordering is executed-test evidence,
  not something receipt flags alone independently prove.

This demonstrates the configured standalone Docker/Unix/coordinator/Store path
with the synthetic three-SNP fixture, including read-only control connectivity and
descriptor transfer. It does not establish worker TLS/signature integration,
biological accuracy, tenant authentication or independent attestation. Actual
cancellation/timeout, keeper death, unfinished attach, failed removal and immediate
or late restart acceptance were pending at that checkpoint. Subsequent recovery
evidence below covers cancellation/timeout/keeper loss and restart, while unfinished
attach and failed-removal injection remain pending. The first failed history must stay
separate from positive evidence and cannot be silently retried or refunded.

## Separate recovery and quota reviews

The [recovery acceptance](README-container-recovery.md) subsequently passed three
actual Docker cases/59 assertions, ordinary and race-instrumented, on unchanged
Go provider/helper sources above. A separate source review was completed.
The normal and immediate restart gates preserve failed custody or durable pending
authority as appropriate; lost keeper history is not adopted or silently retried.
That source review is distinct from executing an independent reproduction.

Independent readback checked the [quota tests and receipts](README-container-quota.md)
without executing Docker, test suites, tools or models. Reviewed quota test SHA256:
`ebc7d42f89d087b85d12b39eb733381e0f4ebc7446cbda7d9e001d2183dbfbdc`;
Reviewed quota documentation snapshot SHA256:
`ac131faefc6da76b2c2d4b564718ead5a36f235d3680ef4092e49a5da99abc7f`.
No blocking defect was identified by this readback:

- Both private acceptance digests match the quota document, as do receipt,
  manifest, proof and ledger digests and their input/policy/store/lease bindings.
- The byte receipt demonstrates two complete 63MiB files plus a partial third,
  zero available byte units and remaining inode units. The inode receipt shows
  zero free inode units with positive remaining bytes after 3,719 empty files.
  Both are ENOSPC 28 rather than EFBIG, under hard/soft FSIZE 64MiB. Configured
  4,096 inode units are not represented as a universal regular-file count.
- The fixture deletes only its third partial byte file or the two last-created
  inode files to permit a private failure receipt. No generated growth files
  escaped to host evidence. Control roots are empty and evidence modes 0700/0600.
- Both results remain failed/withheld, no observed/evaluated VCF or evaluator,
  exactly one execution_receipt export, legitimate bound post-Wait proof and
  positive retained charges of 10,715/10,727 bytes. The local failed-custody ACK
  callback is not scientific approval or Unix/TLS integration evidence.
- Each quota acceptance contains five matching source pins: container helper,
  native helper, prepared fixture, resource module and quota test. The provider
  Go hash is not embedded in that JSON; its frozen source matches the reviewed
  `36d6e1be…` snapshot and recorded execution context. This is trusted-host
  provenance, not independent binary attestation. Kernel receipts also match
  the configured capabilities, root/tmpfs/FSIZE and private cgroup-v2 profile.

The uncertain-cleanup custody guard was reviewed in code; these successful quota
cases do not inject attach/removal/Wait uncertainty. The general
[provider README](README-container.md), read at SHA256
`d624a425ab791e7d712299711a4446adedfa4979f2bce5fb2dddaa735182465c`,
correctly separates standalone acceptance from worker/deployment and total-host
quota claims.
These new container files/evidence were still unpublished at this review. Joint
checks retain their own dated source and execution scope.

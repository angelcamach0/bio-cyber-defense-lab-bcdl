# TM01 artifact workspace and retained export contract

Status: implementation contract accepted by Chiquis on 2026-10-14; phase A is
implemented and tested. Phase B has a validated standalone Go storage/framing core
plus private provider preflights. A Unix listener/client and scoped input/coordinator
composition are independently reviewed by Vale and have passed standalone
test/vet/race acceptance. See the
[server addon](../../services/artifact-executor/README-server.md) and
[coordinator addon](../../services/artifact-executor/README-coordinator.md).
The native provider now has actual standalone synthetic/store acceptance and
helper quota acceptance; see [native module evidence](../../services/artifact-executor/README-native.md).
Container provider, real-provider crash/restart tests and worker integration
remain pending: no phase B
artifact ledger, server or retained-export quota is installed in the worker.
Atlas authored the base contract; Chiquis integrates these additions with independent review.

This contract complements admission/input-retention and bounded metadata. An input
quota, a per-file limit, a free-space sensor, and a finite list of expected files do
not bound the aggregate artifact spool. Scientific release still requires its
independent evaluator. Resource acceptance does not establish biological accuracy.

## Phases and effective limits

| Boundary | Phase A: implemented | Phase B: agreed implementation target |
| --- | --- | --- |
| Tool capture in memory | stdout and stderr each 64 KiB; first extra byte fails execution | Retain these bounds inside the capsule |
| Generated regular file | Linux soft and hard RLIMIT_FSIZE both 64 MiB before copy/tools | Retain per-file bound alongside aggregate workspace bound |
| Reference copy | Actual streamed bytes at most 32 MiB; original unchanged | Reference source read-only; copy charged within workspace |
| Expanded FASTQ | 25 MiB, including bounded reads before oversized-line allocation | Input source read-only; derived/decrypted material remains scoped |
| Workspace | Aggregate artifact quota pending | Dedicated tmpfs 128 MiB with nr_inodes=4096, one active capsule |
| Retained artifact exports | Pending | Global 1 GiB and 64 reserved/retained job slots; 64 MiB export plus 128 KiB publication headroom per job |
| Per-principal artifact quota | Pending | Remains pending TM02 immutable identity binding; never derive it from mutable job owner |

Alignment SAM stdout is redirected to an exclusive private artifact file; its
limit is the 64 MiB kernel file bound, rather than the 64 KiB in-memory capture
bound. This exception does not bypass the phase B aggregate workspace budget.

Phase A configuration is strict: BIOZERO_PIPELINE_MAX_FILE_BYTES,
BIOZERO_PIPELINE_MAX_REFERENCE_BYTES, BIOZERO_PIPELINE_MAX_BYTES,
BIOZERO_TOOL_STDOUT_BYTES, BIOZERO_TOOL_STDERR_BYTES and
BIOZERO_PIPELINE_TIMEOUT_SECONDS. Missing variables use the defaults above;
invalid or unsupported limits fail before tools. The CLI applies the hard file
limit; a library call reports explicitly when it has not applied that irreversible
process-wide limit. BIOZERO_PIPELINE_GROUP_MODE=shared does not acquire or kill
an inherited process group. Cancellation targets tool descendants, not unrelated
members of a shell or keeper group.

The phase B provider must be selected explicitly. An unavailable required provider
fails execution/admission visibly; FSIZE is never a substitute for aggregate
workspace enforcement. Native namespace availability and Docker capabilities are
separate observations. No privileged container, added capabilities, disabled
seccomp, host network, or worker Docker socket is authorized by this contract.

The physical host filesystem, caches, reference acquisition, job/result/event
cardinality, registry/log growth, and other processes sharing the host UID remain
outside the retained-artifact quota. No host-admin or compromised-worker resistance
is claimed. Fixed trusted tools and a trusted host orchestrator are assumed.
Statfs is a free-space sensor, not an enforceable quota. RLIMIT_FSIZE is per file,
not per workspace; inode capacity does not equal a universal number of files.

## API and state ordering

The standalone artifact-executor module implements Store.Open/Reserve/Begin/Export/
Prepare/RecordQuiescence/Commit/Acknowledge and bounded request framing. Unix peer
authentication, scoped-reference registration and coordinator composition have
executed standalone tests. Native execution has one module-level synthetic
acceptance plus helper aggregate-quota checks. Container execution and worker
integration remain unimplemented. No production quota claim follows from this
standalone library or static review.

1. `ArtifactStore.Open(policy)` takes an exclusive lifetime flock and validates a
   private, bounded, strict ledger. Ledger and quiescence-proof reads require
   descriptor-anchored no-follow ancestors/final file, nonblocking regular files,
   exact owner/private mode and typed JSON without duplicate/aliased/null scalar
   fields. Proofs bind current store, policy, lease and export digests. Missing ledger with existing managed data,
   unknown originals, unsafe files, and contradictory entries fail closed. Pending
   execution without adequate quiescence/export proof blocks new work. There is no
   timeout-based lease release, silent empty baseline, or legacy adoption.
2. `Reserve(job_id, input_sha256)` durably reserves a slot, 64 MiB of export, and
   128 KiB publication headroom before tools or workspace creation. Its opaque
   random lease is bound to the job, immutable original-upload digest, policy and instance. The scoped-input
   registry separately binds the verified processed/plaintext digest; an encrypted
   original-upload digest must never substitute for a plaintext transfer digest.
   Authority is durable before spawn acknowledgement. It grants one execution; recovery never reruns that execution. Retained slots
   and charges survive terminal states and lost acknowledgements.
3. `Provider.Execute(context, lease, ExecutionSpec)` executes pipeline and
   scientific evaluation inside one bounded capsule. Input/reference/evaluator/
   truth are configured read-only references. Cwd, TMPDIR, sort temporary paths,
   copied reference, SAM/BAM/VCF/index files and generated intermediates stay in
   its workspace. The evaluator sees the exact observed VCF before the ephemeral
   workspace disappears. Tool captures and result-envelope bounds remain active.
4. A trusted exporter streams allowlisted regular files through the lease's
   export authority. It rejects links, unknown names, excessive cardinality and
   actual serialized/streamed bytes exceeding the reservation. Paths never confer
   permission. The source observed VCF digest, evaluator's input digest and
   retained VCF digest must agree. Original execution JSON remains private;
   a derived output map and manifest explain retained locations without rewriting
   the original input, signature or science evidence.
5. Keeper records quiescence only after the provider's kernel boundary has ended
   and no producer can continue exporting under that lease. Store then durably
   commits the bounded immutable manifest/receipt and actual charge, including
   auxiliary files and temporary publication space, before reporting release.
   Publication uses same-filesystem no-clobber primitives and parent directory
   fsync. A marker alone is not a commit or permission to admit another capsule.

Suggested ledger transitions are reserved -> executing -> prepared -> committed.
Any ambiguous transition becomes sticky unavailable with the reservation retained.
A crash or export failure after a passing evaluation produces failed execution and
withheld release, preserving original hashes and the private scientific verdict.
It cannot advertise an approved retained result. Complete execution, passing
science, successful export and durable storage commitment remain distinct facts.

Prepare takes an explicit Outcome: execution status succeeded/incomplete/failed,
release status evaluated_passed/withheld/unassessed, a bounded stable error code,
and observed/evaluated digests. Commit means storage only. A passed release
requires succeeded execution and observed=evaluated=retained normalized VCF;
failed/incomplete never pass. Withheld/unassessed may have zero exports. If a
normalized VCF is retained, observed must match it even when science is withheld;
a nonempty evaluated digest must match observed. An empty failed/withheld or
successful/unassessed manifest may commit after quiescence, retaining its metadata
charge and job slot while permitting the next job within quota. The trusted
provider must actually observe evaluation; the Store does not infer it from hashes.
Full private result/verdict custody remains distinct from scientific approval.

Review corrections are included in this freeze. An existing instance.lock must
be empty before flock or baseline creation; content and sparse oversized locks
are rejected without changing bytes or creating a ledger. If commit persistence
fails, the in-memory record returns to prepared with its full previous reservation,
while the sticky latch suppresses acknowledgements. Tests reproduce both defects
before correction and exercise write/file-fsync/rename/directory-fsync failures.

The core bounds ledger1MiB, manifest32KiB and proof16KiB. Global charge includes a
fixed4KiB reserve for both ledger headers. Per committed job, actual exported,
manifest and proof bytes plus twice its serialized record/map-key size cover the
retained ledger and its atomic replacement copy. The per-job128KiB headroom bounds
publication metadata. Policy changes, including reductions, fail startup without
changing charges; migration is a separate reviewed operation. All defaults remain
1GiB/64slots/64MiB+128KiB, and configuration cannot exceed those ceilings.

Atomic temporary files cannot consume an unreserved second payload. Actual bytes,
metadata/manifest bytes and publication headroom are accounted before writes;
charges are reconciled only after unambiguous durable cleanup/commit. Historical
artifacts are never deleted to satisfy this policy. Retention requires a separate
explicit deletion/provenance/quota-release contract; there is no terminal-state
release, TTL, or automatic eviction in this phase.

## Native provider and keeper lifetime

A native provider uses NEWUSER, NEWNS and NEWPID to create a dedicated PID1 capsule
and mount its private tmpfs. Before trusted tools, capabilities are dropped and
no_new_privs is set. The keeper stays outside that PID namespace. Its creating
Go goroutine locks its OS thread across Start through Wait because Linux Pdeathsig
is tied to the creating thread. Capsule PID1 has SIGKILL Pdeathsig; its death
causes kernel teardown of remaining namespace processes.

The keeper alone inherits the real flock open-file description and worker control
channel. It explicitly marks them close-on-exec; tools never inherit the lease.
Worker death closes the channel and requests cancellation. Keeper retains authority
through namespace completion and a durable proof bound to the lease. Keeper death
can close flock early, so the durable pending journal independently blocks restart,
even after all observed descendants have disappeared. No PID-only authority,
random-process kill, timeout, or stale-marker inference is sufficient recovery.
If safe proof is unavailable, operator recovery remains required and charges stay.

Phase A's PPID/pidfd descendant cleanup is useful for ordinary trusted-tool failure
and deadlines; it is not a substitute for phase B kernel containment, SIGKILL
recovery or a certified empty namespace. Existing scan/reparent races and bounded
reaping do not establish universal quiescence.

## Container provider and narrow host interface

The current hardened reviewer container cannot create the nested native namespace
provider. The chosen container design is a capsule per job created by a trusted
host orchestrator, with Docker-declared tmpfs size/inode bounds. An authoritative
keeper outside the container PID namespace owns creation, cancellation and Docker
wait. The capsule's PID1 supervises its worker; termination closes the kernel PID
namespace rather than relying on a long-lived container's process scan.

The worker has no Docker socket and requests work through a narrow Unix RPC. The
host validates peer identity, opaque lease and configured scoped file references.
It never accepts arbitrary commands, image names, host paths, mounts, environments
or resource-policy changes. RPC/data channels use bounded frames and cumulative
export budgets. Export authority is fenced to the active lease; cancellation on
channel closure cannot clear a durable pending entry by itself.

The orchestrator waits for capsule termination and verifies export commitment
before producing a recovery proof. If the keeper dies, pending admission fails
closed until explicit safe reconciliation. A restart must be denied immediately
by flock or pending journal, including the interval before kernel cleanup ends.
The tested Unix listener/coordinator are not production-accepted or installed;
native module export/proof has actual acceptance, while container/provider crash
acceptance and installed worker integration remain pending, and
capability preflight does not approve it. The
private host-keeper prototype uses existing sudo Docker authority. It does not
claim a sandboxed/no-privilege host keeper; caps-zero/no_new_privs observations
apply to the capsule. A trusted host orchestrator with Docker authority remains
part of the implementation trust boundary.

## Observed private receipts

The earlier preflight fixtures listed below contain only synthetic resource/lifecycle
probes; no pipeline, model, biological dataset, checkpoint download or historical
deletion occurred in those preflight runs. Later native pipeline acceptance is
recorded separately in README-native.md. SHA256 identifies the exact receipt, not a production build.
The fixtures are temporary host evidence and have not been exported as public
acceptance artifacts.

| Receipt basename | SHA256 | Observation and scope |
| --- | --- | --- |
| biozero-artifact-preflight-1nxec0qe/receipt-failed.json | 093f3da0134956c2b60a606849c97fb464efa5c32f9c0de3084b0eb6d30fe8be | Failed assumption that 4096 inode units imply exactly 4095 regular files; retained |
| biozero-artifact-preflight-q0zdoc_m/receipt.json | 38094628d75f1623dfdb91e36fe3ddca2e66880fe2b1bb16b5dba62997ab97de | Native NEWUSER/NEWNS/NEWPID, 128 MiB and inode ENOSPC, caps zero, no_new_privs; earlier lifecycle test waited before restart |
| biozero-keeper-preflight-tu12vy0k/receipt-failed.json | 6291f1c2d6fd11d40a10dd093da3395f2a89756b7d60df6fce3402a1a65e9d7b | Detected inherited lease descriptor; retained, corrected with explicit close-on-exec |
| biozero-keeper-preflight-wr58p9b7/receipt.json | 4d54abbbcee8145c2e78f00cb268597fbff19a9cc5f2fe8002b5f8d5d4804f66 | Native keeper namespace equals host, capsule differs; immediate restart denied for worker/keeper SIGKILL; charges retained and marker never auto-admits |
| biozero-container-capability-tkl7tpa1/receipt.json | 52c483ac8ccf96796720e5295d393764529318c5373fb15bc7cff0b27382e34b | Actual reviewer image: nested NEWUSER/NEWNS/NEWPID denied EPERM; restrictions unchanged; cleanup verified |
| biozero-container-tmpfs-rz4u28ge/receipt.json | 63ae0a540c9bd71ab90c49e9131d00538035c5c9ee55da0830861d47ac984a4a | Docker-declared tmpfs128MiB/nr_inodes4096: two64MiB files succeed, next byte ENOSPC, inode exhaustion; cleanup verified; no export/fencing claim |
| biozero-container-keeper-hdp5_sf3/receipt.json | bc96a787824c16cd1004737bba02da7c8adf200acb97f9d7fa7e8f7cad62b674 | Host keeper and lease-scoped Unix channel, Docker-init PID1; immediate restart denial after worker/keeper SIGKILL, namespace descendants disappear, charges remain; cleanup verified; no export/production RPC claim |

Native keeper receipt pins main.go, init.py and coordinator.py, including the actual
restart guard. Worker SIGKILL test holds a barrier while the capsule is still alive
and proves flock denial before allowing cleanup. Keeper SIGKILL leaves pending
without proof even after descendants vanish. These observations establish the
experimental guard's behavior, not implemented artifact storage.

The Docker receipts used reviewer image
sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d,
UID/GID1000, cap_drop ALL, no_new_privileges, default seccomp unchanged, read-only
root, no network, init, memory512MiB and pids128. All phase B Docker test
containers were removed and their absence checked. Actual empty-file counts vary with inode accounting;
tests require available inode units zero and the next regular file denied.

The container-keeper receipt pins coordinator.py and capsule.py. Worker SIGKILL
holds an explicit cleanup barrier while the capsule remains alive; flock denies
restart during that interval. Keeper SIGKILL closes the lease-scoped socket, the
supervisor exits, Docker-init exits, and captured namespace descendants vanish.
Pending without proof still denies admission afterward. Docker wait precedes
proof publication in the ordinary cancellation case. This is a fixed synthetic
RPC/lifecycle probe: no arbitrary request surface, real exporter, positive restart
admission, authenticated production client, or artifact-ledger decoder was tested.

Standalone storage/framing freeze on 2026-10-14: 29 Go test functions passed,
89 tests including subcases, go vet passed and race detector passed. Tests cover
strict/unsafe metadata, missing/changed history/policy, singleton lock, concurrent
quota, pending and keeper-lost restart denial, exact/+1 and multi-file exports,
source/evaluated/retained digest gates, quiescence mismatches, fsync/link/rename/
ack failures, terminal retention and empty failed/stats continuation. ReceiveInput
exact25MiB/+1 is tested with the independent plaintext digest. No provider,
authenticated listener, real pipeline, model or positive crash-admission recovery
was run by this standalone suite.

API source SHA256:

- files_linux.go: dd71b971cb8dd57d5a4ac6b67ef580c40a83c6269fa6c2075479c6e1f1a03daa
- input.go: 848cd61865e1a69201450a2666cdb3e9fc77096fc9eb14e70e1016567d261148
- json.go: 06bbb636dadabf339434f239808ff41dc300d873d9847e902bf924c5242fbe6a
- rpc.go: 231c8d5e704a8e25900a01231616b256d7ed4b6172e47fef0d887e578e345a65
- store.go: 712ff9d51d46cf81d6af804e64dfaa23c70ca9bc83b45be356ea8ffa1645ce81
- types.go: fbdec7c53544287e8ceae11fcecb6a6fd07213451fa910850cc8f0500d8ef31e

Phase A re-freeze: 29 tests passed; corrupt DEFLATE returns stable invalid_input
JSON with zero tool calls; streamed reference and complete FASTQ exact/+1 limits
are tested. Source SHA256:

- resource_budget.py: 74a374dc01f0157e13a8a16f996ba470eae42b97f80e8fe7cada98d4dc32d024
- pipeline.py: 9f71988bdc5054b83d63e474c6696860c9405c8a84a37ccf90f9c33aeb95d023
- test_resource_budget.py: a5a43bbc96d3511a438f11aad82d7be2b653347a2b6626cfd886f6d088adf92a
- test_pipeline.py: c688777650787a0367ab2cae003043d693509c07a227d01b2fb26e107b81260e

## Acceptance before production claims

Both providers must pass policy/owner/strict metadata/restart accounting tests and
refuse unknown historical data without modification. Actual bytes at the workspace
ceiling plus one, inode exhaustion, and many-file aggregate growth must be checked
separately from FSIZE. Immediate worker and keeper death must deny restart while
producers can still live, preserve charges, revoke export authority, and leave no
unassessed or failed result approved. Lease descriptors must be absent from tools.

Export tests must compare original observed, evaluated and retained VCF digests;
exercise file/serialized-manifest exact boundaries; reject links/conflicts; and
inject copy/fsync/link/ack failures. A passing scientific evaluation followed by
export failure must be withheld. Recovery cannot reexecute a pending job or release
retained charge just because its status is terminal.

Real native and Compose acceptance, including the prior deterministic three-SNP
fixture, must follow implementation freeze and independent review. No production
aggregate-spool claim is permitted from the current preflights or phase A alone.

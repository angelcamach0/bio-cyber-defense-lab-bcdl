# Native namespace provider: observed module acceptance

Observed locally on2026-10-14, host UID/GID1000 and Linux ARM64. NativeProvider is
implemented in this standalone module and has one actual synthetic pipeline/store
acceptance. It is not installed in enclave-runner or the container worker. The
installed-worker integration remains pending. The Docker provider now has its own
acceptance, and subsequent [complete analysis](README-analysis-integration.md)
covers both profiles through v2 broker and host service. The subsequent
[actual native recovery tests](README-native-recovery.md) and
[Unix composition acceptance](README-native-unix.md) have their own source/evidence scope.

Trusted configuration fixes helper/pipeline/resource_budget/reference/evaluator/
truth SHA256, Python/tool paths, stats/variants mode and a1–600-second deadline.
The socket client cannot submit any of these values. Source ancestors/final files
use no-follow descriptors; pins are checked before spawn and again in the helper
before/after read-only mounts. Shared-UID/privileged host writers and the pinned
runtime/tools remain trusted; this is not external attestation.

The provider creates NEWUSER/NEWNS/NEWPID/NEWNET, maps UID/GID0 to1000, sets SIGKILL
Pdeathsig and retains its creator OS thread through Start/Wait. Its isolated
stdlib-only interpreter starts with -I/-B/-S and an explicit offline environment,
without host credentials or loader/Python hooks. Host runtime authentication is
unchanged. Only a STREAM control FD3 and read-only input FD4 are inherited, never
the Store flock or other worker authority. PID1 sets private mount propagation,
mounts a128MiB tmpfs with4096 inode units, mounts its own proc, applies64MiB hard
and soft FSIZE, verifies/copies input and reference, then drops all capabilities
and enables no_new_privs before tools. Cwd/TMPDIR and generated material stay
within that workspace. Sources, tool directories and script imports are read-only
binds in the private mount namespace. Ordinary trusted tools retain their own
64KiB captures; outer pipeline/evaluator JSON is bounded to1MiB each and stderr64KiB.

Pipeline and the independently configured evaluator run inside the same capsule.
Observed VCF is hashed before/after evaluation. The helper retains raw bounded
pipeline/evaluation JSON privately and sends only typed outcome, artifact IDs,
hashes/sizes and up to four readonly SCM_RIGHTS descriptors. Rights appear once;
partial STREAM writes do not resend them. The parent checks framing, CLOEXEC,
private regular single-link readonly FDs, actual size and cumulative64MiB exports.
It waits for PID1 and an authoritative Exited/Signaled WaitStatus before exporting.
An unproven Wait keeps pending history and its workspace anchor; a PID or marker
cannot substitute. Exact helper exit agreement is0 for execution succeeded and1
for failed/incomplete. Storage proof/commit and actual Unix release ACK remain
separate steps in the coordinator.

Use the explicit `NativeArtifactPolicy()` when creating a reviewed fresh store:
execution_receipt plus the three VCF IDs share the existing64MiB export budget.
Global1GiB/64slots and128KiB per-job metadata headroom are unchanged. This changes
the artifact-ID policy, so existing stores reject it without reviewed migration.
It does not adopt historical artifacts, create an empty replacement baseline,
refund failed slots, delete data or claim a physical host disk quota.

## Executed evidence and preserved failures

The first actual synthetic run used the regulatory Python3.11 build, which lacks
os.pidfd_open/signal.pidfd_send_signal. Pipeline therefore failed its existing
resource guard before tools. Capsule capabilities were all zero, NNP1 and FSIZE
64MiB; the failure/withheld private receipt was committed with its retained charge.
The native profile uses host Python3.9, which has both pidfd APIs. No guard was
removed, no file-limit fallback was added and the biological runtime was unchanged.

Preserved diagnostic root:
`.biozero/native-provider-first-diagnostic-20261014T2238/`.
Private execution receipt SHA:
`e68a23aa63fa08973dabd4e8bad09c7c725cb1d92b58f082ed2f0a42abceda91`.
Two earlier failed module invocations were also observed before persistent
diagnostic staging; their tool output records failures, not accepted evidence.

Corrected actual Go provider/store acceptance passed in0.465s: four retained
exports, real synthetic TP3/FP0/FN0 and exact observed=evaluated=retained VCF SHA
`e2bd72b21a3efa1d11d2b4174ad9b342067fdec0cd24a0fc66e78a2036d337f6`.
Private root `.biozero/native-provider-host-python-20261014T2240/` retains the
ledger, manifest, proof, artifacts and acceptance inventory. Execution receipt SHA:
`4703c794ae418b863d32f86ea16d2e3eb6a4326ca5f3a992e1394e69224cd54a`.
Host workspace anchors were removed after provider completion. This module test
used a synthetic original-input digest and separately verified plaintext; it did
not exercise TLS, signature/decryption entry, the real Unix client or the installed
worker. Its ACK callback was a local test callback, not a network delivery claim.

Separate helper acceptance passed21/21 tests, including two actual namespace
tests, with zero skips. It verified tool capabilities zero/NNP, closure of FD3/4,
receipt FD survival after sender/namespace exit and aggregate exhaustion with
multiple individually permitted files: capsule_workspace_full/failed/withheld,
zero exports. It does not certify Go keeper crash ordering. Receipt root:
`.biozero/native-capsule-harness-final-zltu85cl/`; stats receipt SHA
`50a08f498473f447cd0ea8e560997bde9211c001ebbb4489d0da83d6dc993af2`.
The before/after failed harness roots remain preserved. Its post-exec FD mapper
corrects close_fds ordering and explicitly resets inheritable flags when originals
are remapped to the same FD numbers. Helper code itself remained unchanged.

## Reproduction and remaining gates

After compatible local setup, opt-in actual Go acceptance is:

```sh
BIOZERO_RUN_NATIVE_PROVIDER_ACCEPTANCE=1 go test \
  -run '^TestNativeProviderActualSyntheticVariants$' -v -count=1
```

From the repository root, helper acceptance is:

```sh
BIOZERO_NATIVE_CAPSULE_ACCEPTANCE=1 python3 -B -m unittest discover \
  -s biozero/services/artifact-executor/capsule -p test_native_capsule.py -v
```

BIOZERO_NATIVE_PROVIDER_EVIDENCE_DIR may point to a new absolute private directory
to retain the Go test store on success/failure; existing paths are not overwritten.
Default tests skip kernel opt-ins and never interpret namespace unavailability as
PASS. Real worker integration must choose this provider explicitly and fail if
its required primitives are unavailable. Container execution must use the planned
separate host capsule provider; it cannot silently substitute native FSIZE.

Actual native cancellation, timeout, PID1/keeper death and restart fencing now have
separate lifecycle-fixture acceptance in README-native-recovery.md. Actual Unix
commit-before-reply/status/replay has synthetic pipeline acceptance in
README-native-unix.md. Installed-worker death/disconnection, inode exhaustion on
the integrated provider, export/cleanup fault acceptance and full protected
native/Compose replay remain required. Existing
prototype receipts retain their earlier code/scope. Biological accuracy, genotype,
indel/WGS accuracy, production cloud deployment and complete retention/event/cache
budgets are not established by this synthetic module acceptance.

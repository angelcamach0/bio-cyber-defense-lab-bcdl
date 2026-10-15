# Protected worker staging scope

`worker-scope` is a trusted-operator Linux launcher for the protected worker. It
creates a private user, mount and network namespace, mounts an exact 32 MiB tmpfs
with 4096 inode units, `noexec,nosuid,nodev` and mode `0700`, then executes the
already pinned worker descriptor. It creates no PID namespace. Namespace UID/GID 0
maps only to host UID/GID 1000. Host-root ancestors become the kernel overflow UID;
that interpretation is permitted only with the exact expected ID map, after the
parent has validated their host ownership. The target directory must be empty and private;
existing names are never hidden, deleted or adopted deliberately. A missing final
directory may be created under an existing validated parent.

Build each executable explicitly from the enclave-runner module:

```sh
CGO_ENABLED=0 go build -o /absolute/private/bin/enclave-runner .
CGO_ENABLED=0 go build -o /absolute/private/bin/worker-scope ./cmd/worker-scope
/absolute/private/bin/worker-scope \
  --worker /absolute/private/bin/enclave-runner \
  --worker-sha256 WORKER_SHA256 \
  --tmpfs /absolute/private/worker-plaintext
```

The launcher requires real/effective UID and GID 1000. It rejects symlink
ancestors, unsafe ownership/permissions, writable or multiply linked executable
files and executables exceeding 32 MiB. SHA256 is checked through the retained
read-only descriptor before launch and again immediately before exec. The internal
helper verifies the explicit ID maps and namespace changes, makes mount propagation
private and reopens the target with nofollow inside the child namespace. Device,
inode, owner, group, mode, link count, mtime and ctime must match the inherited
identity anchor. The new descriptor supplies the mount target; the inherited FD
is not used as a mountpoint because its mount object belongs to the parent
namespace. The canonical target path is independently reopened after mounting to
verify the resulting filesystem. It requires
only a down loopback network interface, clears ambient/bounding/effective/permitted/
inheritable capabilities, sets `no_new_privs`, verifies the current locked thread's
state and executes `/proc/self/fd/3`. Trusted host files and credentials remain
within the trusted host boundary. This does not attest the host, isolate hostile
same-UID writers, pin every host dependency or establish hardware-enclave protection.

The parent holds its creator OS thread until the child's authoritative process
Wait. The child has `Pdeathsig=SIGKILL`. Parent cancellation forwards SIGTERM;
after a five-second grace it sends SIGKILL to its own child and still requires
Wait. Missing or nonterminal process state is an error, never proof of quiescence.
The worker receives no arguments. The internal setup helper receives only fixed
LANG/LC_ALL environment variables; the intended worker environment crosses a
bounded private stdin envelope and is installed only at final exec.

The child environment contains LANG/LC_ALL=C, `BIOZERO_DECRYPT_DIR` forced to the
configured tmpfs, and only these optional inherited worker fields:

- BIOZERO_DATA_DIR, BIOZERO_POLL_SECONDS, BIOZERO_PRIVATE_KEY, BIOZERO_SIGNER_CERT,
  BIOZERO_JOB_KEY, BIOZERO_SECURITY_MODE, BIOZERO_PIPELINE_MODE and
  BIOZERO_EXECUTION_BACKEND and BIOZERO_PIPELINE_TIMEOUT.
- BIOZERO_SECURITY_EVENTS_DIR, BIOZERO_ARTIFACT_SOCKET,
  BIOZERO_ARTIFACT_PROFILE_SHA256, BIOZERO_ARTIFACT_PROJECTION_POLICY and
  BIOZERO_WORKER_CUSTODY_DIR.
- BIOZERO_WORKER_PROTOCOL and BIOZERO_OWNER_WORKER_CONFIG.

BIOZERO_PIPELINE_TIMEOUT, when present, must be a positive duration of at most
ten minutes. It selects no executable or provider policy. BIOZERO_EXECUTION_BACKEND
may only select capsule here; legacy execution requires its separate explicit
operator path outside this launcher. An absent selector retains the worker's
capsule default.

For owner execution, pass `BIOZERO_WORKER_PROTOCOL=owner-v1` together with an
absolute clean `BIOZERO_OWNER_WORKER_CONFIG` path. Unknown/empty/duplicate protocol
or config values and an owner config without the owner selector are rejected;
config paths reject control characters and invalid UTF-8. The fixed environment
passes only those two additional fields, not arbitrary config or credentials.
The worker loads its own strict pinned config after exec and requires its
`stage_directory` to equal the launcher's forced `BIOZERO_DECRYPT_DIR`. The launcher
does not initialize custody or parse owner config. The [owner worker recipe](../../README-owner-worker.md)
initializes a new journal separately, then starts the worker through this launcher.
Existing legacy capsule selection remains separate; no owner error falls back.

The launcher does not alter its parent's environment. Runtime SDK credentials,
authentication variables, proxies, interpreter/loader hooks and PATH are not
inherited by the worker. No secret value or private path is included in launcher
error messages. BIOZERO_JOB_KEY reaches the intended worker at exec; this is not
secret-memory isolation from the trusted launcher or host.

## Plaintext descriptor contract

`StageVerifiedPlaintext(ctx, dir, jobID, plain)` returns
`*VerifiedPlaintextStage` with `File *os.File`, `SHA256 string` and `Bytes int64`.
The bytes must already have passed protected-entry verification; staging itself
is not proof of signature or encryption. It accepts at most 25 MiB and a lowercase
16-hex job ID, generates its own unpredictable exclusive filename and never uses
OriginalName. It writes/fsyncs, reopens read-only with nofollow/CLOEXEC, checks
regular current-UID `0600`, single link, exact inode/size/hash and closes the write
descriptor before returning. Startup `ValidateWorkerStageDirectory(ctx, dir)`
checks ownership/mode and exact filesystem limits/flags without requiring emptiness.

New staging requires an empty directory and acquires a lifetime directory flock.
Concurrent creators cannot admit another stage while that authority is held.
A retained name continues to block new staging after the file object is closed;
unknown leftovers cannot be deleted, adopted or reset automatically. Startup may
still allow status/receipt recovery without accepting new plaintext. No global
in-memory stage registry bypasses those directory checks.

Use the stage in this order:

1. Before any submit, call `MarkSubmitStarted()`. This irreversibly disables
   `DiscardUnsubmitted()`; a missing ACK never authorizes plaintext deletion.
2. Keep the object reachable and its read-only descriptor open across uncertainty.
   `Close()` only closes descriptors and the directory flock, retaining its name.
3. After independently checking the broker's durable committed receipt/proof, call
   `ReleaseConfirmed()` and then `Close()`. The release method is an explicit
   trusted-caller assertion, not an ACK inference or independent proof verifier.
4. Only when no submission has started may `DiscardUnsubmitted()` unlink its own
   exact inode, followed by `Close()`. Early construction failure attempts the same
   verified cleanup; an error never means all storage has been erased.

Release refuses replacement files, symlinks, changed permissions/ownership or
multiple links and syncs the directory after unlink. A failed sync is reported;
there is no automatic success or accounting refund. Retaining the read-only FD
also retains plaintext pages after unlink until that FD and any borrowed copies
close. A malicious concurrent same-UID/privileged rename is outside this contract;
private directories and trusted host writers are required. Native namespace loss
and Compose tmpfs lifecycle need their own integrated recovery evidence.

## Verification scope

The historical staging/launcher observations below predate the owner-selector
extension. They do not establish actual owner-v1 worker/broker V3 acceptance.
New selector tests and integrated execution require their own source-bound logs.

The original staging/launcher unit snapshot passed 10 top-level functions and
13 subcases without skips or failures, ordinary and race, with targeted vet exit0.
Staging source remained unchanged during the subsequent launcher correction.
File tests deliberately bypass only the tmpfs precondition to examine real
read-only FD, inode, flock, release and uncertainty behavior. They do not establish
mount enforcement. Original private test evidence is retained separately.

The corrected launcher passed seven top-level functions and eight subcases without
skips/failures in ordinary and race runs; targeted vet and static build exited0.
The race package time was1.040s. Checks used GOMAXPROCS=1, GOFLAGS=-p=1 and
GOPROXY=off; race requires CGO_ENABLED=1, while the new launcher build used
CGO_ENABLED=0. Its diagnostic output permits only exact internal error codes;
unknown, wrapped, syscall/path errors and arbitrary matching prefixes remain
`worker_scope_child_failed`. Mount diagnostics distinguish private propagation
from tmpfs attachment and expose only explicit EPERM/EACCES/EINVAL/ENOENT names.

The real empty-workspace diagnostic first observed tmpfs Mount EINVAL when the
mountpoint used the inherited parent-namespace descriptor. That failure and all
prior attempts remain preserved. Reopening and comparing the target inside the
child namespace fixed that specific failure without changing tmpfs, capability,
network, executable-pin or environment guards. The final isolated probe reached
worker startup, handled SIGTERM and exited0 after authoritative Wait, with no
SIGKILL. It created no jobs/uploads/results and started no broker. It used the
same failed acceptance's worker binary, policy and PKI read-only, with fresh
private data/custody/staging roots. Relevant source/input pins and the original
failed Store/broker/worker journals remained unchanged.

The retained final probe summary has SHA256
`55993255cc2fbd42d9d3a88a58f44324d8ab424778650208d50067d521559c93`.
The tested new launcher was4,031,436bytes, SHA256
`8e6d6ffd084163afe75d11d3edc8cbebcafe91371832159579f16e0fcb57276e`.
This probe establishes the isolated setup/startup boundary, not protected
signature/decryption, genomic execution, scientific release or authorization.
Actual native/Compose protected crypto, broker/worker death, retained names,
quiescence and result authorization require their own integrated acceptance.

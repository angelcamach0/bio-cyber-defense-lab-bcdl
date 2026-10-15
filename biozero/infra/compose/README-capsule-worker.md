# Protected capsule worker: three-service Compose acceptance

Status: the earlier **native-provider**30-case acceptance passed on Linux
ARM64/Docker29.9.0, followed by35independent retained-evidence checks. See the
[public aggregate and exact pins](../../docs/evidence/20261015-protected-capsule-worker/public/README.md).
The separate **Docker-provider** run subsequently passed57actual assertions and
52independent retained-evidence checks. See its
[public scope and pins](../../docs/evidence/20261015-protected-docker-capsule-worker/public/README.md).
Execute against a fixed source/binary/configuration snapshot and preserve failed
attempts separately. Earlier component/legacy results retain their own scope.

The harness starts three Compose services: upload API, results API and protected
worker. The artifact broker runs on the host. `--capsule-provider native|docker`
selects where that broker actually executes pipeline, evaluator and detection;
the default remains `native`. Running the three service containers alone does
not exercise the Docker capsule provider. The new Docker selection has its own
57-case executed acceptance. Earlier receipts remain
native-provider evidence. Neither selection exercises the reviewer gateway,
browser, biological model, production deployment or reproducible OCI image
construction.

## Prerequisites and invocation

The current acceptance is Linux ARM64, host UID/GID1000. Provide a new private run
directory outside the source tree or under ignored `.biozero`, and a directory
of prebuilt current-UID ARM64 ELF binaries named:

- upload-api
- results-api
- enclave-runner
- uploader-cli
- artifact-broker
- capsule-analysis

No binary is built by this harness. Each executable is copied through a no-follow
source traversal into a fresh private runtime, pinned, and mounted individually
read-only where needed. Input binary pins, private copies and repository source
inventory are compared before/after. These pins record supplied bytes; their
correspondence to source and compiler/build closure needs the separate build
receipt. Native interpreter/tool dependency closure is also a separate claim.

The exact cached local image is:
`sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d`.
It supplies the service container root filesystem while the supplied Go
executables are individual read-only binds. In Docker-provider mode, the same
image also supplies each capsule's Python interpreter and bioinformatics tools.
No image build, download or pull is
attempted. Missing image/binary/tool/provider capability fails explicitly.

```sh
python3 biozero/infra/compose/run_capsule_worker.py \
  --run-dir "$PWD/.biozero/compose-capsule-NEW" \
  --binaries-dir /absolute/existing/private/bin \
  --capsule-provider native \
  --tools-prefix /absolute/existing/native-tool-prefix

python3 biozero/infra/compose/run_capsule_worker.py \
  --run-dir "$PWD/.biozero/compose-docker-capsule-NEW" \
  --binaries-dir /absolute/existing/private/bin \
  --capsule-provider docker
```

The program has no caller-selected Docker command. It uses fixed argv:
`/usr/bin/sudo -n /usr/bin/env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH /usr/bin/docker --host=unix:///var/run/docker.sock`.
It preserves DOCKER_CONFIG and inherited proxy, CA and authentication guards. It
neither starts/restarts the daemon nor changes host policy. Docker API access is
trusted host harness authority; the worker never receives the Docker socket.
The broker's Docker provider uses its existing allowlisted fixed command
`/usr/bin/sudo -n /usr/bin/docker --host=unix:///var/run/docker.sock`; its runtime
removes the same endpoint/context/TLS selectors and preserves inherited host
credential/proxy guards. It receives the exact image ID and both helper pins;
its native interpreter/tool fields must be empty. Native mode instead requires
`--tools-prefix` with minimap2, samtools, bcftools and fastp. Supplying that option
with Docker mode is rejected rather than implying that host tools are used.
Missing Docker capability never falls back to native. No network acquisition or
model inference belongs to this acceptance.

## Runtime boundary

Fresh PKI, configuration, data, source/binary pins, raw responses and logs remain
in private current-UID directories/files, mode0700/0600. Copied executable files
are0700. The run report identifies the retained short private `/tmp/bz-cw-*`
runtime; no credential, raw result or file path is printed as public evidence.
There is no public export directory. Console output contains fixed case names.

All three containers use UID/GID1000, read-only root, init, cap_drop ALL,
no_new_privileges, one CPU,512MiB and128pids. API TLS ports publish only on127.0.0.1
through a project-scoped normal bridge whose default host-binding address is also
127.0.0.1. This bridge does not enforce an API egress deny policy. The worker still
has network_mode none. Its plaintext
mount is Docker-declared32MiB tmpfs,4096inode units,0700/currentUID, noexec/nosuid/
nodev. The program checks actual statvfs/mountinfo, caps, NoNewPrivs and worker
executable digest, rather than relying solely on rendered Compose configuration.
Both actual NetworkSettings.Ports and requested PortBindings must exactly match
the API's explicit HostIp/HostPort/container TCP port; empty/null API maps fail.
The worker must have no ports. The bridge's actual driver, Internal=false and
loopback default are inspected. See [decision002](../../docs/decisions/002-local-container-network.md)
for the preserved Docker29.9 sole-internal-bridge failure; localhost TLS readiness
must still prove that listeners actually work.

Worker mounts are limited to its executable, uploads/PKI read-only, Unix channel
and projection policy read-only, and jobs/results/custody/security-events read-write.
It has no Store, broker journal, provider executable/rules/tools, whole data-root,
bindir, or Docker-socket mount. Upload API alone receives admission/inputs writes;
results API reads only its job/result data and role-specific TLS material.
Actual inspected bind sources/modes must match the generated private configuration.

The broker uses the same executable for print-profile and service, fixed source
pins, the explicitly selected provider and allowed UID1000. The projection policy
must name that same capsule kind. Both helper hashes are profile/configuration
inputs for Docker; its execution receipt additionally records the native helper
hash, which the harness compares with the configured exact value. The receipt
does not contain an image ID. Image linkage is established through the pinned
configuration/profile, trusted provider implementation and independently inspected
Docker object. Host/UID trust and the separate immutable-ownership TM02 gate
remain; the Unix peer UID is not individual tenant authentication or attestation.

## Docker-provider acceptance contract

The host observer uses the fixed local Docker argv and a fresh Store ID read
after broker socket readiness. Before any submission, it starts a filtered
Docker events stream with a timestamp immediately preceding its own start.
Only the upload service receives an extra Store-ID label plus a private observer
marker. Seeing that service's `start` event, with its exact ID/marker/nonce
confirmed by service inspection, is the subscription barrier. This one exact
actor is excluded from capsule counting; another marked/ambiguous actor fails.
No additional container is created for readiness.

The observer accepts at most128events,64KiB per JSON frame and1MiB in total,
including stderr, with stderr separately capped at64KiB. Events and selected
inspections remain private. Each inspection reads at most1MiB stdout and64KiB
stderr while streaming, with a5second deadline and explicit CLI wait/cleanup.
Each capsule must have a distinct exact64hex ID,
32hex nonce and lease, matching the new Store ID and the three committed journal
leases. Per actor, the required filtered order is `create`, `start`, `die`,
`destroy`. A read-only inspect on create/start must capture the actor while
created or running, before provider removal. If that race is lost, acceptance
fails and preserves the attempt; the harness never pauses, recreates or reruns
a job to obtain an inspection. The watcher does not claim inspection before FD
transfer: the provider independently verifies the live PID/peer before sending
the input descriptor.

Each live snapshot must match the exact image, ID/labels, fixed offline argv/env,
UID/GID1000, read-only root, zero added capabilities, cap-drop ALL, no_new_privs,
network none, private IPC/cgroup namespace, no restart, no logging, one CPU,
512MiB RAM with zero extra swap,128pids,64KiB shm,64MiB FSIZE and the exact
128MiB/4096inode-unit workspace tmpfs declaration. Only the ten individually
pinned helper/pipeline/reference/evaluator/analysis files and the exact job's
control directory may be bound, all read-only. There is no Store, input path,
PKI, results, broad source directory or Docker socket bind into a capsule.

For **each of the two valid runs and invalid FASTQ**, independent receipt checks
require schema2/capsule kind Docker, exact helper/source/context/input pins,
PID1 and UID/EUID/GID/EGID1000, five zero capability sets, NoNewPrivs, FSIZE and
loopback-only interfaces. Recorded kernel observations must show read-only root,
a writable noexec/nosuid/nodev tmpfs128MiB/4096inode-unit workspace with private
0700ownership, read-only covering mounts for every source/control/interpreter,
and read-only cgroup2 with memory.max512MiB, memory.swap.max0, pids.max128 and
one CPU. Namespace strings are checked without claiming that the Docker user
namespace is private. The longest covering mount must be unique; a broad root
mount does not override a more specific writable source mount.

Events `die`/`destroy` and exit0for valid inputs or exit1for invalid input are
independent lifecycle evidence. Authoritative quiescence before export remains
the provider's Docker wait/final exact inspect together with the durable proof
and committed manifest; the event stream alone is not that authority. The
provider removes its own successful capsules only after wait/inspection and
before exporting the retained FDs. No kernel observation after that removal is
claimed. Uncertain provider objects, anchors, pending records and charges remain
untouched. The observer itself is stopped/joined/waited explicitly, with bounded
shutdown; only its private CLI process group may be signalled, never capsules.
An observer process/thread that ended before intentional shutdown is failure,
including an unexpected exit0. The three complete event sequences must be
observed before acceptance; final actors must remain identical after service
and broker shutdown.

All four valid-run artifacts and the invalid run's sole execution receipt must
match binding/manifest/Store hashes and sizes. Context and input provenance must
agree across raw receipt, broker journal and worker custody. Receipt input pins
are the verified plaintext; Store/manifest/proof input pins are the original
ciphertext upload. Both chains are checked separately against journal/custody
facts. Proofs bind the exact Store/policy/job/lease/upload/manifest. Observed, evaluated and retained VCF
hashes must agree for valid science. Retained charges are recomputed from actual
files, manifest, proof and serialized record accounting plus the4096byte header;
no total is copied from an earlier native run. Unsigned input and worker
lost-publication recovery must create no extra capsule or custody reservation.

## Shared scenarios and retained state

The scenarios cover individual mTLS, signed encrypted uploads, exact
three-SNP truth twice, normalized callset equality, original-ciphertext versus
verified-plaintext hashes, all four retained artifacts, manifest/receipt/proof
binding, observed=evaluated=retained VCF digest,1171mapped reads and detection0.7.
They also cover owner/nonowner denial despite spoofed headers, invalid FASTQ
withheld, missing-client-certificate rejection while authenticated TLS stays live,
and unsigned rejection without Store/broker/worker custody changes.

The lifecycle case first stops the worker and requires exit0. Only a confirmed
result created by this fresh fixture is removed to simulate lost publication;
its exact original bytes are saved privately, and its own job status is restored
to running. Store, journal, worker custody, leases, retained files and charges are
unchanged. Starting the same worker container must recover the same bound result,
detection and scientific verdict without executing or reserving again.

Harness shutdown stops only exact service IDs bearing the private run's ownership
nonce. It performs no compose down, rm, volume removal, prune, reset, historical
adoption or refund. The provider's own successful-capsule removal described above
is separate. Stopped service containers, configuration, directories and history
remain for review. APIs may exit0/143; the worker and host broker must exit0 for a
passing run. Forced broker termination is failure and does not authorize another
execution or quota release. Source inventory is re-enumerated with git ls-files
-co --exclude-standard at the end; a changed snapshot invalidates acceptance.

The earlier native-provider report records source/image/binary/profile snapshots, all30case
verdicts, actual controls, retained-state checks and shutdown results. Independent
readback confirmed3retained slots and43,232bytes of record charges. Including the
4,096byte Store header reserve, total charge is47,328bytes. APIs exited143, worker
and broker0; all three containers remain stopped and preserved. Kernel readings
refer to the recorded live worker, not a new measurement after shutdown.
A prior native, component, legacy Compose or browser PASS cannot approve this new
harness or its SDK v2 protected route.

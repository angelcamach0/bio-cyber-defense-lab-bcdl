# Protected capsule worker: three-service Compose acceptance

Status: actual30-case acceptance passed on Linux ARM64/Docker29.9.0, followed by
35independent retained-evidence checks. See the
[public aggregate and exact pins](../../docs/evidence/20261015-protected-capsule-worker/public/README.md).
Execute against a fixed source/binary/configuration snapshot and preserve failed
attempts separately. Earlier component/legacy results retain their own scope.

The harness starts three Compose services: upload API, results API and protected
worker. A fixed native artifact broker runs on the host. Pipeline, evaluator and
alignment/detection execute in that broker's bounded native capsule. This scope
does not exercise the Docker capsule provider, reviewer gateway, browser, biological
model, production deployment or reproducible OCI image construction.

## Prerequisites and invocation

The current acceptance is Linux ARM64, host UID/GID1000. Provide a new private run
directory outside the source tree or under ignored `.biozero`, an existing native
tool prefix, and a directory of prebuilt current-UID ARM64 ELF binaries named:

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
It supplies the service container root filesystem while the newly compiled Go
executables are individual read-only binds. No image build, download or pull is
attempted. Missing image/binary/tool/provider capability fails explicitly.

```sh
python3 biozero/infra/compose/run_capsule_worker.py \
  --run-dir "$PWD/.biozero/compose-capsule-NEW" \
  --binaries-dir /absolute/existing/private/bin \
  --tools-prefix /absolute/existing/native-tool-prefix
```

The program has no caller-selected Docker command. It uses fixed argv:
`/usr/bin/sudo -n /usr/bin/env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH /usr/bin/docker --host=unix:///var/run/docker.sock`.
It preserves DOCKER_CONFIG and inherited proxy, CA and authentication guards. It
neither starts/restarts the daemon nor changes host policy. Docker API access is
trusted host harness authority; the worker never receives the Docker socket.
Native tools required by the fixed broker include minimap2, samtools, bcftools and
fastp. No network acquisition or model inference belongs to this acceptance.

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
pins, native provider and allowed UID1000. The projection policy explicitly says
capsule_kind native. Host/UID trust and the separate immutable-ownership TM02 gate
remain; the Unix peer UID is not individual tenant authentication or attestation.

## Executed assertions and retained state

The executed scenarios cover individual mTLS, signed encrypted uploads, exact
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

Shutdown stops only exact IDs bearing the private run's ownership nonce. No
compose down, rm, volume removal, prune, reset, historical adoption or refund is
performed. Stopped containers, generated configuration, directories and history
remain for review. APIs may exit0/143; the worker and host broker must exit0 for a
passing run. Forced broker termination is failure and does not authorize another
execution or quota release. Source inventory is re-enumerated with git ls-files
-co --exclude-standard at the end; a changed snapshot invalidates acceptance.

The executed report records source/image/binary/profile snapshots, all30case
verdicts, actual controls, retained-state checks and shutdown results. Independent
readback confirmed3retained slots and43,232bytes of record charges. Including the
4,096byte Store header reserve, total charge is47,328bytes. APIs exited143, worker
and broker0; all three containers remain stopped and preserved. Kernel readings
refer to the recorded live worker, not a new measurement after shutdown.
A prior native, component, legacy Compose or browser PASS cannot approve this new
harness or its SDK v2 protected route.

# Docker capsule aggregate byte and inode quota acceptance

Nora owns this test and document; the container provider/helper remain unchanged.
The two opt-in cases use the actual ContainerProvider, InputRegistry, Coordinator
and Store with a pinned synthetic stats pipeline. They use the cached image
sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d,
individual read-only source mounts and the registered read-only input descriptor.
No model, external network request, image pull/build or historical deletion is
part of these cases. Go test compilation is ordinary test preparation.

Observed2026-10-14: both real Docker cases passed with the race detector after
CPU coordination. The byte case took1.01s and the inode case0.90s; Go reported
2.933s for the package. No case failed or was retried in this quota run. The
earlier container-provider smoke attempts retain their separate history.

## Independent resource failures

The bytes case attempts three regular files of63MiB each, individually below the
64MiB soft/hard FSIZE. It records actual statvfs before growth, at ENOSPC and after
cleanup. It requires full128MiB workspace capacity, zero available byte units at
failure, remaining inode units, two complete63MiB files and a smaller third
partial file. EFBIG cannot satisfy the test. Only the third partial file created
by this fixture is unlinked, restoring enough space for the failed private receipt.
The complete126MiB payload remains inside tmpfs until actual capsule teardown.

The inode case creates exclusive empty files until ENOSPC. It requires total4096
inode units, zero free inode units and positive free bytes at failure. It does
not assume4095 regular files or a universal empty-file count. It removes only
the last two files it created to permit one execution_receipt and record the
private observations; generated files never become host exports.

Both pinned fixtures deliberately return pipeline failed/exit1. The helper must
retain execution failed/release withheld, zero observed/evaluated VCF digests,
no evaluator and exactly one allowlisted export: execution_receipt. A committed
Store state means custody of that failure, never scientific approval. The tests
check the actual private receipt's input digest, source pins, PID1/UID/GID1000,
capabilities zero, NNP, loopback-only network, read-only root,128MiB/4096 tmpfs,
64MiB FSIZE and private cgroup-v2 memory/swap/pids/CPU limits.

The actual provider performs Docker wait and final identity/config/state
inspection before exporting. The coordinator then closes export authority,
constructs the bound quiescence proof and commits positive retained charge and
the original job slot. The tests verify the private ledger, manifest, proof and
receipt hashes, and invoke only a local failure-custody ACK callback afterward.
They require no host control anchor or generated quota-growth file to remain.
Original input bytes stay unchanged. No Unix/TLS/signature/decryption worker
integration, tenant authorization or clinical/scientific accuracy is asserted.

## Private evidence and reproduction

Each case creates a new0700 root under ignored .biozero, with0600 pinned fixture
files, prepared.json, the private input, retained Store files and acceptance.json
on success. Existing paths are refused; previous attempts are never overwritten
or removed. If completion/Wait is uncertain, the test fails and retains coordinator,
Store/flock and provider references until process exit, with its persistent
fixture for review. No timeout, process marker or force-removal substitutes for
quiescence. This cleanup guard does not itself inject uncertain-Wait failures.

From the artifact-executor module, after coordinating one active test at a time:

```sh
BIOZERO_RUN_CONTAINER_QUOTA_ACCEPTANCE=1 go test -race \
  -run '^TestContainerQuotaActual(Bytes|Inodes)$' -v -count=1 -timeout=180s
```

BIOZERO_CONTAINER_QUOTA_EVIDENCE_DIR optionally names an existing absolute private
parent; each case creates its new bytes/inodes child and refuses existing children.
Default suites skip the opt-ins. Explicit opt-ins fail if Docker, the exact cached
image or required kernel/interpreter profile is unavailable; no FSIZE-only or
unbounded workspace fallback is permitted. The local orchestrator's existing
sudo/Docker authority and shared-UID host/source writers remain trusted.

## Executed results and readback

The byte case observed134,217,728B capacity and files of66,060,288B,
66,060,288B and2,093,056B. Available bytes reached0, with4,090 inode units still
free. The next write failed with ENOSPC, never EFBIG. Only byte-grow-002, the
2,093,056B partial file, was removed; afterward those byte units were free for
receipt creation. Each individual file remained below67,108,864B FSIZE.

The inode case began with4,093 free inode units after input setup and reached0
while creating3,719 empty files;134,213,632 data bytes remained free. Removing
only the last two created files restored3 inode units. This directly illustrates
why configured inode units and a universal number of regular files differ.

| Case | Private evidence root | Receipt bytes | Retained charge |
| --- | --- | ---: | ---: |
| bytes | .biozero/container-quota-bytes-20261014T234522.891382537Z/ | 8704 | 10715 |
| inodes | .biozero/container-quota-inodes-20261014T234523.901268930Z/ | 8716 | 10727 |

Acceptance JSON SHA256s:

- bytes: a92d5755d1fbc8bcfb8b7a1659b784e30059365a3db2cec3f3f901d994b04939
- inodes: 5ebe38043cbc23f5f254ae9b06398d81a61e34614f1f12a5cd3281627dfd61e8

Private execution_receipt SHA256s:

- bytes: 22571e45e76a7420901b84d955bf477b17f3785f2b88bf14bfc527d9b6f2569f
- inodes: 70127ad5c7192f227fb1684f80fc730f45a625d984bf2c0b8b3984cfbafd1e8e

Frozen source snapshots:

- quota test: ebc7d42f89d087b85d12b39eb733381e0f4ebc7446cbda7d9e001d2183dbfbdc
- ContainerProvider: 36d6e1be27026588a8280def67f72610a7b3bf30fc2fff4ecc8cd64c06c76e1f
- container helper: 56b2a3883d5201f3d227dc58fe4edf0577c0136b4ea707542491ed32c0a29ac8
- native helper: e5ac96587a403476acba3ef6ad7b55a9cbce8951278d94759ca54cb8d8583ea8

A separate read-only script reread both stores, manifests, proofs, source fixtures
and receipts: every retained digest/binding matched, original plaintext was
unchanged, evidence modes were0700/0600, and host control roots were empty. Actual
kernel receipts showed PID1/UID/GID1000, all five capability sets zero, NNP1,
hard/soft FSIZE64MiB, read-only root and the fixed tmpfs. The private cgroup-v2
view showed memory.max536870912, swap.max0, pids.max128 and cpu.max100000/100000.
Neither case approved science or released its retained job slot/charge. The
partial-file deletion was confined to newly created fixture data inside tmpfs.

These new opt-in tests/docs have not yet been published or run by hosted CI at
this checkpoint. Their real Docker evidence is separate from earlier commits,
default suites and biological/model measurements.

This profile bounds a capsule workspace, not all writable pseudo-filesystems,
physical host disk, registry/cache/event growth, retained storage or production
resources. The64MiB retained-export limit and1GiB/64job Store policy remain separate.

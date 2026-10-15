# Protected worker with the Docker capsule provider

Actual acceptance passed **57/57** assertions. Independent retained-evidence
readback passed **52/52**. Individual mTLS, signature verification and authenticated
decryption precede verified-input tmpfs staging and v2 broker submission. Pipeline,
evaluator and detection execute inside three actual Docker analysis capsules,
separate from the three upload/results/worker service containers.

Two valid runs each observed TP3/FP0/FN0, precision/recall1 and1,171mapped reads,
with configured detection0.7/medium. Normalized SNP sets repeat identically;
per-run observed/evaluated/retained VCF hashes match. Complete VCF files across
runs need not be byte-identical because headers can contain runtime paths.
Invalid FASTQ remains failed/withheld with no scientific evaluation and one
retained execution receipt; independent analysis can still execute. Nonowner
access is denied, unsigned input adds no execution custody/capsule, and clean-
stop/lost-publication recovery returns the same artifacts without another run.

The bounded observer verified subscription through the exact upload service's
start event, then correlated three distinct capsule IDs/leases/nonces. Each had
create/start/die/destroy events, actual configuration inspected while created,
and retained live helper kernel observations. Twelve capsule events are separate
from three barrier-service events. Observer capture was12,104bytes, exit143,
joined without error. Daemon events do not establish quiescence or authorize
commit: provider wait/final inspect and coordinator export fencing/proof remain
the trusted authority. The provider removed its successful owned capsules; the
three application containers are stopped and preserved. Broker/worker exited0,
APIs143. No post-termination kernel remeasurement or attestation is claimed.

All nine retained artifact files and three manifest/proof/journal/custody bindings
were checked. Record charges are13,989/23,633/23,636bytes, total61,258; adding the
4,096byte Store header reserve gives **65,354bytes** and3retained slots.
Original ciphertext and processed plaintext hash chains are checked separately.

`summary.json` contains allowlisted aggregates, fixed verdict names, binary/profile/
image pins and private receipt digests. `runtime-source-pins.json` records392files
based on4e9e119 with local changes, unchanged throughout acceptance. Six existing
binaries were reused after verifying all51production Go/module inputs against
the earlier build receipt and checking original/copy hashes. Their build VCS
metadata remains333995f dirty; no new compilation or bitwise rebuild is claimed.
This aggregate and subsequent publication documentation are later than that
runtime snapshot. Raw DNA/results/targets, job/lease/container IDs, PKI, credentials
and full receipts remain private. Failed/weaker verification history is preserved.

Reproduce with [the Compose harness and prerequisites](../../../../infra/compose/README-capsule-worker.md),
selecting `--capsule-provider docker`, an existing permitted binary directory and
a new private run directory. The exact cached image in summary.json must already
exist. No image build/pull, model inference or dataset acquisition occurred here.
The earlier [native-provider acceptance](../../20261015-protected-capsule-worker/public/README.md)
keeps its own source, profile, artifacts and accounting.

This gate establishes protected positive/failure science and clean-stop/result
recovery on Docker. Actual integrated crash/cancel/lost-ACK and uncertain-state
reconciliation, reproducible image/tool/license closure, immutable ownership,
complete quotas/retention, queues/multiworker, effective SOC and free cloud
identity/storage/keys remain open in [the requirement matrix](../../../../docs/requirements-and-gates.md).

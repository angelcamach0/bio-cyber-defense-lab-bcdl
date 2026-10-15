# Protected postcommit fault acceptance

Three fresh local Linux ARM64 runs used the same399-file source snapshot, six
existing binaries and exact cached Docker image. Each has its own profile and
retained history; no analysis was retried.

| Scenario | Actual assertions | Independent readback | Retained slots | Total charged bytes |
| --- | ---: | ---: | ---: | ---: |
| Downstream Submit response lost |26|41|1|27,731|
| Worker container SIGKILL after commit |32|45|1|27,732|
| Default protected Docker regression |57|52|3|65,356|

Each total includes its own4,096-byte header reserve. Record charges are23,635,
23,636 and61,260bytes. These are retained charges, not refunded quota.

## What executed

Each fault case submitted one actual signed/encrypted synthetic FASTQ through
individual mTLS. The broker completed one real Docker capsule, committed its Store
and journal, and delivered its real Submit response and EOF to a fixed private
Unix/SCM_RIGHTS relay. The relay discarded that downstream response. Recovery used
status/receipt queries with zero further Submit or capsule creation. This is
downstream response loss after successful upstream delivery; it does not prove a
failed broker ACK write or worker receipt of that response.

The worker-death case held the response while verified plaintext remained staged
and no result was published. The exact owned worker container was killed; Docker
wait returned137 and inspection showed exited/PID0. Restarting that same ID
recovered the result from its existing receipt. Old/new mount namespaces and
32MiB plaintext tmpfs generations were pinned simultaneously to prevent inode
reuse from masquerading as identity. Their identities/filesystems differed and
the new tmpfs was empty. Four measurement descriptors closed. The fixture can
temporarily retain up to64MiB of plaintext-tmpfs capacity across the two
generations; the namespace reference also retains other old mounts. It neither reads old
plaintext after death nor establishes secure erasure. Process-only restart
retaining the old tmpfs is not covered.

Both cases recovered TP3/FP0/FN0, precision/recall1,1,171mapped reads and configured
0.7/medium detection. Observed/evaluated/retained VCF hashes matched per execution.
Each retained four artifacts plus manifest/proof. Store/broker/custody journals,
artifacts, proofs and charges stayed identical across recovery; the other client
was denied despite a spoofed identity header. The separate default57-case run also
repeated science and covered invalid FASTQ, unsigned/no-certificate rejection and
clean-stop/lost-publication recovery. This is synthetic SNP presence, not clinical
or biological validation.

Three application containers per run remain stopped and preserved. Successful
capsules were removed by their provider only after authoritative wait/inspection.
Proxy/observer threads joined, own child processes were waited, broker exited0,
and source/binary pins stayed unchanged through acceptance.

## Reproduction and source scope

Use the [Compose runbook](../../../../infra/compose/README-capsule-worker.md) and
`run_capsule_faults.py --scenario downstream-response-loss` or
`--scenario worker-sigkill-postcommit`, each with a NEW private run directory and
verified existing binaries. The default Docker-provider harness has its own fresh
regression. No build/pull/model or dataset acquisition occurred. All51freshly
enumerated production Go/module inputs matched the prior binary receipt; build
metadata remains333995f dirty. This establishes correspondence to those existing
bytes, not a new build or reproducible image closure.

The runtime snapshot is based on3296f36 with local fixture changes. Documentation
and this export were added afterward. Same-snapshot make passed279Python cases
(277passed/two helper opt-ins skipped) and test/vet in eight Go modules. It used
fixture umask022. An initial private wrapper's umask077 made two old unsafe-mode
fixtures safe0600 and their assertions failed. Unchanged focused tests and the
complete suite passed with022; the failed receipt remains preserved. Hosted CI
for the new publication is tracked in the draft PR, separately from these local
Docker runs.

Two prior relay attempts failed on an unnecessary empty send after a complete
frame. A causal real-socket test reproduced EPIPE and passes after the fixture-only
correction. A prior worker attempt failed an unpinned namespace-ID measurement
because kernel identifiers were reused; simultaneous pins resolved the
measurement. These failures, an earlier successful downstream snapshot and all
prior history stay separate and unchanged. No production runtime or Go source
changed for these fixtures.

`summary.json` contains aggregate verdicts/counts/hashes. Complete runtime source
hashes are in `runtime-source-pins.json`; `SHA256SUMS` covers these three files.
Raw results, DNA, targets, profiles, IDs, credentials, kernel identities and private
paths stay outside this bundle. The earlier
[Docker57/52 bundle](../../20261015-protected-docker-capsule-worker/public/README.md)
retains its own392-file snapshot and65,354-byte total.

Broker death, active cancellation, a true upstream ACK-write failure, uncertain
pending/plaintext reconciliation, attachment/removal/storage faults, full image
and license closure, immutable owner TM02 and broader delivery gates remain open.
See the [requirements matrix](../../../requirements-and-gates.md).

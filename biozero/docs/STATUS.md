# BioZero implementation status

Updated2026-10-15 UTC. Working branch: `biozero/authenticated-ownership`, based on
the `biozero/container-capsule-provider` milestone at 77a4e03.
[PR22](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/pull/22) is a draft
above [merged PR21](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/pull/21).
No production deployment is established.

## Protected synthetic experiment

The accepted fixture has a6kb reference,1,171reads and three known SNPs. Repeated
normalized allele callsets have TP3/FP0/FN0. Protected entry uses individual mTLS
identities, signature/integrity/encryption checks before analysis, and separate
execution and scientific-release states. A/B authorization, invalid input,
unsigned/no-certificate rejection, original hashes and restart behavior have
executed acceptance. This does not establish genotype, indel, whole-genome or
clinical accuracy, novelty or hardware-enclave protection.

The current native harness selects each service's root executable with `go build
-o DEST .`; package tests/vet still discover all packages using `./...`. Its prior
recursive build failed after adding analysis/CLI subpackages. The failed
[CI38660550112](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38660550112)
at commit0dd7384 remains preserved: unit/PKI and scientific repeat passed, but
protected-service startup was never reached. After the selector correction, fresh
local protected native acceptance passed all78assertions. Its original receipt
remains retained privately; source pins and cleanup remain scoped to that run. The correction's own
[CI38661813114](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38661813114)
passed at98f2f89. Subsequent source needs its own CI; that result is not reused.

Earlier exact-source evidence remains under docs/evidence and in Git history:
protected native78checks, four-service Compose30checks, Firefox23UI/TLS/session
checks and optional responder-container13checks. These receipts are not relabeled
as integrated broker acceptance. See [reproduction](runbooks/reproduce.md),
[experiment001](experiments/001-variant-smoke.md) and the recorded source hashes.

## Bounded execution components

The artifact module implements private durable reservations, bounded metadata,
registry, Unix transport, coordinator and native/Docker capsule providers.
Configured capsules enforce a128MiB/4096inode-unit workspace,64MiB per-file limit,
capabilities zero and no_new_privs; actual Docker cgroup limits were observed.
Exact provider termination and export fencing precede proof/commit/ACK. Synthetic
module acceptance retains four artifacts and equal observed/evaluated/retained VCF
hashes. Native and Docker cancellation/timeout/keeper-death and byte/inode quota
receipts preserve pending history and charges without automatic retries/refunds.

The new worker FD broker adds a separate strict submit/status/cancel/receipt
protocol and durable job/upload/plaintext/profile-to-lease binding. Journal intent
precedes Reserve, durable lease linkage precedes Bind, and committed journal
sealing precedes actual ACK. Two causal tests cover Store commit before journal
seal and commit racing ACK acquisition. Lost ACK cannot bypass health or rerun
work; explicit restart recovers only a prior binding with verified committed Store
history. Journal metadata is separately bounded to1MiB plus one1MiB replacement,
outside Store's logical1GiB artifact-byte charge.

The analysis package/CLI preserves scoring, defaults, signal shape and historical
SAM-record counting. SAM/target/stderr/time bounds are explicit; failures discard
partial metrics. Rules and argv must agree on panel presence. Input/output are
bounded64KiB; future pipeline projection must fit without truncating accepted
results. Targets and raw results remain private.

Both providers now install pinned analysis/rules/panel and per-job context using
execution/receipt schema2. V2 FD broker history persists the exact context before
Reserve and rejects changed facts on duplicate submit/ACK. V1 remains separately
selected with unchanged request/history shapes. Actual native and Docker tests
combine broker, pipeline, evaluator and detection within the same bounded capsule:
three-SNP truth passes; rules failure revokes approval while preserving custody.

`cmd/artifact-broker` now provides the fixed-profile host service. Private strict
configuration, source pins and its own executable SHA determine the profile;
print-profile creates no state/socket/provider. Actual compiled-service acceptance
covered both providers, clean SIGTERM exit0, committed restart/readback without
reexecution, and deliberate socket replacement causing exit1 with marker and
accounting preserved. A cached first-close error cannot disappear behind a later
successful Close. Provider Wait and healthy Store remain required before release.

The protected worker now verifies one anchored ciphertext snapshot, checks its
signature, authenticates decryption and stages the verified plaintext in checked
32MiB/4096inode-unit tmpfs. Durable custody precedes Submit; result projection
requires the retained committed receipt. Pending or ambiguous history fences new
admission; recovery queries prior bindings without decrypting or submitting again.
Missing capsule configuration fails startup; legacy execution is an explicit
separate selector. The worker does not invoke pipeline/evaluator/detection tools.

Fresh native25-check and three-service Compose30-check acceptance passed actual
mTLS, signature/decryption, repeated three-SNP science, A/B denial, invalid FASTQ,
unsigned rejection before custody and clean-stop/lost-publication recovery with
the same artifacts and charges. Both use the host native capsule provider. Native
launching trusts host files/credentials and same-UID writers; it is not a host-file
sandbox. Compose instead checks explicit mounts, no worker network, read-only root
and no Store or Docker-socket mount. The APIs use a loopback-published normal
bridge; API egress is not denied. No persistent deployed service is claimed.

Independent readback passed78native and35Compose checks of retained evidence,
source/binary/profile pins and exact accounting. The native Store retained47,545
charged bytes including its header, and Compose47,328bytes; each retains3slots.
Compose comprises43,232bytes of record charges plus4,096bytes of header reserve.
These are separate runs with distinct profiles and per-run artifact bytes.

The protected Docker capsule-provider route subsequently passed57/57actual
three-service Compose assertions, followed by52independent retained-evidence
checks. The broker used provider=docker with the exact cached image and pinned
helpers/assets. A bounded read-only observer correlated three distinct capsule
IDs/leases/nonces and create/start/die/destroy sequences, inspected actual
configuration while created, and kept those observations separate from the
helper's live kernel records and provider/coordinator proof authority.

Both valid inputs had TP3/FP0/FN0 and1,171mapped reads; invalid FASTQ remained
failed/withheld with only its execution receipt. All nine retained files, proofs,
contexts and journal bindings matched. Record charges61,258bytes plus4,096header
reserve total65,354bytes, with3slots retained. Broker/worker exited0, APIs143;
the observer exited143 and joined without error. Three successful capsules were
removed by the provider after authoritative wait/inspection; the three application
containers remain stopped and preserved.

The runtime snapshot was392files based on4e9e119 with local harness/docs changes,
unchanged throughout acceptance. Six existing binaries were reused after checking
all51production Go/module inputs and their hashes against the earlier build
receipt; their build VCS metadata remains333995f dirty. No new compile, image
build/pull, model run or dataset acquisition occurred. Post-acceptance documents
and aggregates are separate from that snapshot. See
[protected Docker acceptance](evidence/20261015-protected-docker-capsule-worker/public/README.md).
See [protected acceptance](evidence/20261015-protected-capsule-worker/public/README.md)
and [worker configuration](../services/enclave-runner/README-worker-backend.md).
See [broker](../services/artifact-executor/README-broker.md),
[capsule](../services/artifact-executor/README-container.md),
[analysis](../services/enclave-runner/analysis/README.md) and
[workspace contract](security/artifact-workspace-contract.md). See
[complete analysis acceptance](../services/artifact-executor/README-analysis-integration.md)
and [host service](../services/artifact-executor/README-service.md) for current commands.

## Protected postcommit interruption acceptance

Fresh Docker fixtures now passed26downstream-response-loss checks and32worker
container SIGKILL/restart checks; independent retained-evidence audits passed41
and45respectively. Each used one real signed/encrypted upload, one Submit, one
lease/capsule and query-only recovery. Three-SNP science,1,171mapped reads,
per-client denial, actual artifacts/proofs and all custody/accounting stayed
intact. Retained charges including the4,096-byte header were27,731and27,732bytes,
one slot each. This loses a response after successful upstream delivery and EOF;
it does not prove a failed broker ACK write.

SIGKILL was applied to the exact worker container while plaintext was staged and
the real committed response held; Docker Wait137/exited/PID0 preceded restarting
that same ID. Simultaneously retained kernel references proved distinct old/new
namespaces and tmpfs filesystems, with the new plaintext stage empty. Four FDs
closed. The fixture temporarily retains both32MiB generations; it does not prove
secure erasure or recovery after process-only death retaining the original tmpfs.

The shared harness also passed a fresh default57-case Docker regression and52
independent checks, retaining65,356bytes across3slots. All three runs and final
make used the same399-file snapshot based on3296f36 with local fixture changes.
Six binaries were reused after fresh complete51-input Go/module verification;
their original build metadata remains333995f dirty. All own processes terminated;
three application containers per run remain stopped and preserved. Runtime Go,
images, models and datasets did not change. Documentation/exports came afterward.

Same-snapshot make passed279Python cases (277passed/two helper opt-ins skipped)
and test/vet in eight Go modules with fixture umask022. The initial private
wrapper's077 caused two existing unsafe-mode fixtures to become safe0600 and fail
their assertions; unchanged focused/full suites passed with022. Two earlier
relay EPIPE failures and an unpinned namespace-ID measurement failure also remain
preserved. The correction and causal Unix-socket test affect only the fixture.
See the [public aggregate and exact source pins](evidence/20261015-protected-postcommit-faults/public/README.md).

## Active cancellation and committed broker recovery

Protected Docker acceptance now adds 31 broker postcommit SIGKILL/recovery checks
and 17 active-cancellation checks, independently audited with 48 and 49 controls.
A fresh default Docker run passed 57 checks and 52 independent controls. See the
[exact source snapshots and public aggregate](evidence/20261015-broker-cancel-recovery/public/README.md).

The broker test pinned its own live child/socket before SIGKILL and verified
complete committed Store/journal/custody history. The identical first restart
exited 1 with the generic `artifact_service_start_failed` message. After verified
death and unchanged history, an explicit operator fixture retired only that
pinned socket once, fsynced its directory and checked the replacement's identity.
The three broker exits were -9/1/0. One Submit/capsule produced the same four
artifacts, proof, TP3/FP0/FN0, 1,171 mapped reads and 27,729 charged bytes including
header reserve. The proxy held the worker response through the outage; worker
query retries while the broker was down were not exercised. This is committed-only
fixture recovery, not a production socket repair service or pending-state adoption.

The cancellation test used a pinned waiting lifecycle producer, not the scientific
pipeline. Before the local operator V2 Cancel, it preserved the exact original
ledger, journal and custody files, their hashes and stable metadata, synchronized
copies/directories and revalidated original bytes immediately before the frame.
The physical 67,239,936-byte reservation became committed metadata charge 1,617
plus 4,096 header bytes, with the slot and custody retained. Terminal output was
failed/withheld/artifact_cancelled, with zero exports and a post-Wait/fence proof;
Cancel ACK was observed true and terminal publication followed in about 0.419 s.
No public cancellation API or scientific approval follows. The earlier 16-check
run and 41-check audit without physical before copies remain preserved as weaker
evidence, along with an audit-only Docker error-text mismatch.

Broker/default used a 408-file snapshot based on 3770129 with fixture changes;
cancellation/final make used 408 files based on 476e89ee with fixture changes.
The three-file delta consists of the cancellation checkpoint writer and an earlier
public attribution/checksum correction. All six binaries and all 51 production
Go/module inputs were verified unchanged; original build metadata remains
333995f dirty. No new service/image build, download or biological inference ran.
Final make passed 294 Python cases (292 passed, two helper opt-ins skipped), with
uncached test/vet in eight Go modules and unchanged source throughout. The 15 socket
fixture tests require UID/EUID 1000; hosted CI may skip them on other hosts.
Documents and public aggregates were written after runtime acceptance.

## Verification and reproduction scope

The integrated worker snapshot passed `make test`:263Python cases,261passed/two
helper opt-ins skipped, and test/vet in eight Go modules. Focused backend race
tests passed14top-level functions/34subcases. Custody, receipt projection and
staging/launcher have separately recorded ordinary/race/vet checks. The final
Compose-only network correction passed syntax checks and its real30-case run;
Go source did not change. The public acceptance bundle pins the runtime snapshot;
status documents and that bundle were added afterward. Its hashes do not claim a
byte-for-byte rebuild or an immutable published commit at runtime.

The first integrated publication, a226981, failed its own
[CI38672344835](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38672344835)
in upload-api's cross-module lifecycle-boundary fixture before PKI/scientific
acceptance. An uncached causal run reproduced the failure with the backend unset;
selecting legacy alone made that same fixture pass. Its worker now explicitly
selects legacy, preserving the boundary, rejection and no-pipeline assertions.
Repository checks use `go test -count=1 ./...` because Go's package cache does not
track the sibling worker sources that this fixture builds with a subprocess.
The earlier local make pass included cached package results; it did not prove
this cross-module fixture against the changed worker. Corrected source passed a
fresh uncached make:263Python (261passed/two opt-ins skipped), eight Go modules
test/vet, unchanged source inventory throughout. Its hosted CI result is tracked
in the live PR; the failed CI receipt remains preserved.

The following earlier component receipts retain their original source scope:

- Final component `make test`:263Python cases,261passed/two helper kernel skips;
  test/vet in eight Go modules. simulated-adversary has no Go tests.
- Combined eight-opt-in artifact race snapshot:121top-level functions and302
  subcases passed in33.118s; only two internal parent keeper entries skipped and
  execute in child processes. This preceded the host-service socket-close fix;
  helper/provider/broker pins remain identical in final source. The first combined
  attempt's two quota fixture initialization failures remain preserved.
- Final source after that fix:114top-level functions and295subcases passed with
  race detection in11.788s, including actual compiled-service native/Docker
  acceptance and cleanup failure/restart. Eleven other explicit kernel tests
  skipped; those were not reexecuted for a service-only change. Their earlier
  complete snapshot retains its recorded source and scope.
- Helper unit suite:53cases,51passed/two namespace opt-ins skipped. EPIPE handling
  preserves complete failed CLI responses and rejects incomplete-input success.
- Analysis/CLI:15functions and36subcases passed ordinary/race/vet. Independent
  review checked source, persistence, ACK barriers, limits and panel configuration.
- Two ARM64 builds with separate empty caches produced identical3,565,542-byte
  binaries: SHA256cb95d52dcf6c601039a4f801fd4b1ca02fa16a8c89b7a87706ffbc553fd1edf6.
  Actual compiled CLI/minimap2 on the public fixture observed1,171mapped/1,171SAM
  records, one private target and configured0.9/high. Caller crypto facts were
  synthetic. This is standalone analysis and same-host/toolchain repeatability,
  not integrated protected entry, cross-host or OCI reproduction.

Earlier standalone host binary:5,128,722 bytes, SHA256
`c6cea629b14cafc4abc4cda69a4d8db60f5de569cf89036e4460e2f156f57194`.
That source inventory was unchanged throughout its build/make/race acceptance.
Original build/make/race receipts remain retained privately.
No actual acceptance service remains running after its authoritative process Wait.

The earlier [CI38657120252](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38657120252)
passed for bba2637. It does not approve later source. Hosted CI skips provider
kernel opt-ins, biological models, Compose and Firefox. Each new published source
requires its own CI and exact-scope acceptance. Failed/weaker receipts and pending
charges remain preserved; no model or dataset was rerun to repair the build.

## Authenticated ownership protocol component

A new independent [ownership protocol library](../services/ownership-authority/README.md)
implements the cryptographic foundation in [ADR 004](decisions/004-authenticated-ownership.md).
It derives identity from real verified TLS leaf certificates, checks a pinned
Ed25519 challenge and same-leaf RSA-PSS manifest, derives owner/job/nonce/profile
AAD and measures actual ciphertext. It does not start a server or change the
existing upload, worker, broker or Results route. TM02 remains open.

Two private synthetic real-mTLS probes reproduced current Results weaknesses:
mutable owner reassignment and copied result relabeling. No existing-service fix
is inferred. The new library passed 10 top-level/72 subcases with race detection;
an independent exported-API caller passed one top-level/12 subcases, including
actual GCM rejection after another valid client re-signed copied ciphertext.
Finalize measures those signed bytes; only mandatory worker AAD enforcement can
reject their decryption in the real route. RSA-OAEP envelope measurement remains
an integration gate. See the [exact evidence and source pins](evidence/20261015-ownership-protocol/public/README.md).

Final make passed 294 Python cases (292 passed, two kernel opt-ins skipped) and
uncached test/vet in nine Go modules on an unchanged 420-file snapshot. After the
successful child/log/source-after/summary, the wrapper failed while recording a
handle; its exception is preserved without rerunning successful checks. Documents
and aggregates added after acceptance are distinguished. No service/image build,
Docker acceptance or biological model run establishes integration here.

The following component extends this protocol. Direct/gateway clients,
worker/broker verification and protected receipt-based result projection remain
pending. Full same-job reassignment, cross-job ciphertext replay and result
relabel negatives must pass on the integrated protected route before closing TM02.

## Durable ownership registry component

The Linux Store now reserves full slots/bytes before a body, generates job/nonce,
persists the exact manifest before reading and signs measured acceptance before
returning it. Its externally pinned genesis/policy and signed bounded ledger
prevent implicit enrollment or relabeling of history. Exact accepted replay
returns the original bytes without reading or resigning; known read rejection,
expiry, process death and acceptance retain the full charge. Quotas aggregate
renewed credentials by configured namespace/CN while ownership stays exact-leaf.

Historical verification revalidates the authority signature, original leaf,
challenge, manifest, complete binding and original decision time against the
external Store scope. Decision time follows ciphertext verification; durable
commit follows and is not asserted to finish before challenge expiry. There is
no caller-provided historical clock and no retroactive expiry of accepted work.

Independent exported-API acceptance used actual HTTPS/mTLS with the same client
credentials across separate processes. One principal test and two cases passed:
SIGKILL after durable acceptance followed by byte-identical cold replay/nonowner
denial/zero Reader calls, and SIGKILL inside the first Reader followed by rejected
cold Open. Actual WaitStatus proved both deaths. Physical signed ledger, owner
fingerprint, full 131,136-byte charge and all original Store files remained
unchanged on cold readback. The replay supplied a time 24 hours ahead; it did not
wait 24 hours. No HTTP Finalize endpoint or failed network ACK write was tested.

The independent run and full make each fixed the same 430-file source snapshot.
Make passed 294 Python cases (292 passed, two opt-ins skipped) and uncached
test/vet in nine Go modules. A later change only strengthens the Store GC fixture:
its predecessor retained a deferred receiver and could not prove last-reference
loss. Both receipts remain preserved; production Go source is unchanged. The
corrected fixture verifies actual closure of the three os.File descriptors while
the separate raw CLOEXEC flock remains live. Its full module/race/vet passed
34 principal tests and 176 subcases. After adding the public external reproduction
fixture, default module tests/vet passed the same 34/176 with two explicit opt-ins
skipped; the new fixture passed one principal/two subcases under race, with its
parent helper skipped. Production Go stayed unchanged. Exact results and source
delta are recorded in the [public aggregate](evidence/20261015-ownership-store/public/README.md).

Defaults retain 64/16 jobs, 512/128 MiB global/principal charges, 2/1 active
reserved-or-reading jobs and 25 MiB plus 131,072 bytes per reservation. The ledger
and one replacement are each bounded to 8 MiB. Unknown/pending history fails
unchanged; a sticky live writer retains its raw lock until process exit. A crash
after marker unlink but failed parent sync need not preserve the marker, so
universal cold rejection at that boundary is not claimed. No automatic refund,
retry, repair, migration, hostile-host protection or antirollback is implemented.

At that registry snapshot, this was an unintegrated library: no retained
service/image artifacts were rebuilt and no Docker/model acceptance ran. Go checks
compiled temporary test/service fixtures. The next component adds authority ingress;
deployed isolation, envelope/AAD enforcement, worker/broker binding and
receipt-based release remain dependencies. Existing services still have the reproduced
TM02 weaknesses. See the [contract](../services/ownership-authority/README.md) and
[ADR 004](decisions/004-authenticated-ownership.md); the full gate remains open.

## Ownership authority ingress component

The Linux authority now serves HTTPS/mTLS Reserve, streaming Finalize and owner-only
readback. A closed private configuration pins the signing key, TLS assets, policy
and external genesis scope. Initialization is exclusive and separate from serving;
startup never adopts history. Literal loopback, TLS 1.3, eight connections, four
handlers, bounded metadata and real read/write deadlines limit ingress. Protected
response delivery runs under the Store preflight/mutex; failed Write/Flush latches
the live writer. Shutdown stops admission and drains before healthy Store close;
a retained terminal error cannot be cleared by a second Shutdown.

The corrected HTTP fixture passed eight principal tests/26 subcases. Its initial
helper used a client absolute URL for a server request, causing three failures and
shadowing other negatives; that original weaker run is retained. The correction
uses a relative target and valid control, without changing production for that
helper error. Full module ordinary/race/vet then passed 50 principal tests/234
subcases plus four CLI tests, with explicit external/helper skips. Those checks
pin 19 inputs; a later test-only addition has its own 20-input race acceptance.

That service-process acceptance verifies signed durable commit before an actual
TCP RST and delegated Write error, full retained charge, sticky live failure and
repeated Shutdown denial. A second process is denied while that writer lives.
Only after SIGKILL and confirmed WaitStatus does a fresh process reopen the same
trusted scope: owner GET and metadata-only Finalize return the original acceptance,
the other leaf gets 403, and SIGTERM exits cleanly with all history unchanged.
This uses the actual service API in owned test processes with transport
instrumentation. It is separate from the standalone CLI acceptance.

One retained ARM64 CLI binary was explicitly built, then tested through independent
Python TLS 1.3/mTLS clients. Fresh genesis exits zero; reinitialization exits nonzero
without changing history. Two serving starts over the original accepted history
return identical owner readback/metadata-only replay and exit zero on SIGTERM.
The fixture reuses a dual-EKU server/client leaf; deployed client/server key
separation is not established. The independent public-key-only review passes
39 controls without rerunning acceptance or opening private keys.

Final make passed 294 Python cases (292 passed/two kernel opt-ins skipped) and
uncached test/vet in nine Go modules on an unchanged 442-file snapshot. Four
technical documents and the public aggregate were updated afterward; production
Go stayed unchanged. No Docker image, capsule acceptance, dataset acquisition or
biological model ran in this increment. Temporary Go fixture compilation and the
one retained service build have separate receipts. See the
[exact scopes and source pins](evidence/20261015-ownership-authority/public/README.md).

This completes a locally verified authority component, not TM02. Upload/gateway,
worker/broker and Results still use their previous contracts. Deployed key/mount
isolation, actual OAEP-envelope comparison/GCM AAD enforcement, protected receipt
projection and integrated substitution negatives remain pending. Scientific and
economic conclusions below are unchanged.

## Durable shared ownership client component

The new verified HTTPS/mTLS client performs one explicit Reserve, Finalize or Get
call, without redirects, demo fallback or automatic network retries. Its private
operation workspace persists the original request identity before Reserve, the
original challenge and one encrypted payload before Finalize, then a finalizing
phase before the network call. Records are append-only and bounded; unknown files,
transaction markers or changed context fail unchanged. Ambiguous IO keeps the raw
lifetime flock even after both Go file descriptors are collected.

A lost Reserve response permits only an explicit same-token action. A lost
Finalize response is recovered through Get of the already-known job; no method
resends ciphertext or starts execution. A direct acceptance retains its raw bytes;
Get recovery stores the canonical verified signed object. Both are compared with
the original challenge/manifest/leaf/body/envelope. Prepare uses explicit caller
time; fresh Finalize independently enforces its real transport clock.

The payload helper defines AES-GCM body/tag plus RSA-OAEP-SHA256 key32/nonce12,
empty OAEP label and mandatory signed-context AAD. Actual ciphertext and decoded
envelope digests are checked before unwrap. In the pure measured-protocol/signature
fixture, B really signs copied ciphertext and obtains authority acceptance; GCM Open under
B's context fails. This proves the helper gate, not integration into the worker.

Focused transport tests passed eight principal/39 subcases; an initial shared
quota fixture could shadow wrong-pin verification and is preserved as source plus
transcript-only limitation. Corrected isolated fixtures have original captured
stdout/stderr. Payload/operation focused tests passed eleven principal/45 subcases
on the first run. Three owned SIGKILL/WaitStatus cases cover prepared readback,
query-only finalizing recovery and rejection of uncertain history; the last also
observes both original file descriptors closed with the raw CLOEXEC lock live.
All these fixture directories are temporary. Retained source pins/logs do not
constitute a retained client acceptance workspace or standalone client execution.

Full module race passed 69 principal tests/318 subcases and four CLI tests with
five ownership opt-in/helper skips and one CLI helper skip. It pinned 26 Go/module
inputs unchanged. Final make passed 294 Python cases (292 passed/two kernel opt-ins
skipped) and ordinary test/vet in nine Go modules on an unchanged 453-file snapshot.
Five technical documentation updates and the four-file client aggregate follow
that snapshot. No runtime Go changed after race/make; the earlier focused operation
snapshot differs only by a later explanatory comment. No retained CLI build,
Docker/model execution, dataset acquisition or existing-workspace cleanup ran in
this increment. See the [client contract](security/ownership-client-contract.md)
and [reviewed source scopes](evidence/20261015-ownership-client/public/README.md).

This is the dependency for direct CLI/gateway adapters. The old upload creates
another job ID and gateway only persists its run after upload; neither is activated
as owner-v1. Authority network/key/mount isolation, actual worker/broker enforcement,
protected result projection and integrated substitutions remain pending. TM02 and
the full roadmap stay open; scientific/economic conclusions remain unchanged.

## Owner-v1 CLI and upload delivery adapter

The explicit owner-v1 CLI now connects authority operations to a separate upload
spool while retaining the original signed job ID. Client input/config intent
precedes Reserve; separate operation/delivery journals retain two ciphertext
copies (approximately50MiB maximum combined). Deliver publishes intent before
its sole POST. A lost response is recovered only through a known-job GET; local
status verifies both journals without network. The new upload service verifies
external pin/scope, exact owner leaf, decoded OAEP envelope and measured body,
charges its full maximum-body promise before reading ciphertext, and retains
charges for delivered/rejected/uncertain entries. Cold pending history stays
fenced. It has no authority signing key or worker decrypt key in its configuration.

Corrected focused tests passed ingress/delivery26 principal/109 subcases,
CLI11/18, selector2/3 and worker gate1/2. The initial subprocess barrier incorrectly
stopped metadata reads before the intended body read; the original failed run and
source remain preserved. Only that test barrier changed. Full race then passed
146 principal/543 subcases across three modules (including four authority-command
tests), with ten explicit opt-in/helper skips. The136 repository Go/module inputs
were identical in focused/race and retained runtime acceptance.

A fresh native acceptance built four pinned executables: authority, upload API,
uploader and an independent stdlib-only payload inspector. All27 controls passed
actual TLS1.3/mTLS with separate server/client EKUs, trusted genesis scope,
signed-ID preservation, bounded exact frame/body/envelope, and A200/B403 on both
services. The inspector opened the CLI's actual OAEP/GCM ciphertext with canonical
signed-context AAD and matched the synthetic input; changed AAD failed. This
inspects emitted payload bytes, not a worker's ownership enforcement.

A test TLS relay received the complete upstream upload receipt and dropped it
before writing downstream HTTP bytes. Cold CLI recovery made only GET, preserving
both server histories and exactly26,345,472 charged bytes in each single-record
store. Both owned service processes exited zero on SIGTERM/Wait, with history
unchanged; binaries, private keys, journals, ledgers and original logs are retained
privately. Independent public-key-only retained-evidence review passed57 controls
without rerunning acceptance or opening private keys/plaintext. This response-loss
acceptance is separate from the unit fixture's
actual upstream TCP RST/delegated write failure, SIGKILL and cold replay. Those
unit fixture directories were temporary and were cleaned by the test framework.

Final make passed294 Python cases (292 passed/two kernel opt-ins skipped) and
ordinary test/vet in nine Go modules over an unchanged474-file snapshot, identical
to runtime acceptance. An earlier captured make inherited umask077, which made
two historical unsafe-permission fixtures safe and failed their negative checks;
that original run remains preserved. The capture runner corrected only its child
umask to the ordinary022, without changing production/test sources. Later status,
requirement/decision/threat documentation and the public bundle are separate from
that snapshot. See the [public evidence](evidence/20261015-owner-upload-delivery/public/README.md)
and [delivery contract](security/ownership-delivery-contract.md).

Delivered means transport only. The legacy-selected worker rejects owner-v1 before
legacy decryption/custody; a valid legacy signature cannot bypass the algorithm
gate. Gateway, worker/broker acceptance-hash/AAD enforcement, receipt-based Results,
deployed keys/mounts/network and integrated substitutions remain open under TM02.
No Docker/image build, capsule analysis, model/dataset acquisition, deployment or
scientific recomputation ran in this increment. The broader roadmap and prior
scientific/economic conclusions are unchanged.

## Owner-v1 worker and V3 broker execution

The explicitly selected owner-v1 worker independently verifies signed acceptance,
external pin/scope, actual ciphertext and decoded OAEP envelope, then authenticates
GCM with mandatory signed-context AAD before plaintext staging or verified custody.
It records canonical acceptance/credential/original-upload/processed-input facts
before its sole Submit. The separate V3 broker receives two RO FDs, independently
verifies canonical acceptance and preserves owner/context bindings before Reserve.
It trusts the worker for the GCM-to-plaintext relationship and has no decrypt key.
V1/V2 history is never adopted. Query-only recovery ignores mutable terminal jobs
and result caches. Receipt projection is one shared package with the same source,
science, detection and release rules; the owner cache is observability only.

Fresh retained native acceptance passed53/53controls. Actual authority/CLI/upload,
worker launcher, V3 broker and native capsules processed two valid synthetic
three-SNP inputs with TP3/FP0/FN0 and1,171mapped SAM records each; the invalid FASTQ
committed failed/withheld with only its execution receipt. Both valid normalized
SNP callsets matched truth and each other. Nine exported files, manifests, keeper
proofs, receipt/source/context hashes and actual read-only receipt FDs matched.
The worker's actual tmpfs was32MiB/4096inode units with noexec/nosuid/nodev,
NoNewPrivs1 and all capability sets zero. Native host files/same-UID writers remain
trusted; this is not deployed key/mount isolation or hardware attestation.

B obtained a legitimate mTLS challenge/acceptance after signing an exact copy of
A's ciphertext and envelope. Transport delivered it, but the worker emitted its
generic rejection without any observed tmpfs mutation or new worker/broker/Store
record. Inotify had three positive staging controls; physical B input/binding
facts matched and all execution-history bytes stayed identical. A separate real
OAEP/GCM inspector opened the copied bytes with A's AAD and failed with B's AAD.
The worker's particular GCM error is inferred from these controls and verified
code order; it is not a specific error code observed in the process log.
All four admitted inputs retain105,381,888logical bytes in EACH authority/upload
store. Three execution slots retain42,922record bytes plus4,096header reserve,
47,018total. These logical charges do not cap the complete physical filesystem.
Four owned services ended with SIGTERM/Wait0 and unchanged execution-history bytes.

Independent public-key-only readback passed96controls without rerunning execution
or reading private keys/input plaintext; a separate five-control attribution
review verified retained source copies and the later test-only change. Full race
passed264principal/877subcases across artifact/worker modules with13explicit
kernel/ownership skips. Runtime and race pin the same156Go/module inputs.
Final make passed294Python (292passed/two opt-ins skipped), uncached ordinary Go
tests and vet in nine modules over502unchanged source files. Its only delta from
runtime is three keyed-field spellings in one receipt test: the extraction made
SourcePin an external alias and vet refused the prior unkeyed literals. Values,
assertions and production Go are unchanged; no runtime rebuild/repetition was
needed for that test syntax. Post-validation documentation/exports are separate.

Original failed/weaker receipts remain retained. Initial focused fixtures used
subsecond authority time; the first race used private roots without explicit0700
under ordinary umask022. The first native run passed18controls and real3SNP
execution before a verifier used analysis instead of analysis_capture. Its eight
retained binaries were reused only after exact source/hash/metadata checks in a
fresh run with new stores and journals; no old execution was reset or adopted.
The first make stopped at the unkeyed test vet error; its original source/logs
remain. Temporary Go fixtures are distinct from the retained native workspaces.
See [public evidence and source attribution](evidence/20261015-owner-worker-execution/public/README.md),
[execution contract](security/ownership-execution-contract.md),
[worker configuration](../services/enclave-runner/README-owner-worker.md) and
[owner broker](../services/artifact-executor/README-owner-broker.md).

TM02 remains open: authoritative owner Results before private bytes, a dedicated
read-only broker channel, Gateway/UI and result/owner-substitution negatives,
deployed key/network/mount separation and fresh V3 lifecycle fault acceptance.
The owner loop does not automatically run the legacy SOC outbox. No image build,
Docker acceptance, model inference, dataset acquisition or deployment ran in this
increment. Regulatory scientific/economic conclusions and the full roadmap remain.

## Regulatory feasibility

The frozen10adapter and100evaluation cases completed finite, identical repeats.
Evaluation sign agreement61/100 and Spearman0.1840864086408641 describe GBR/LCL to
GM12878 transfer; they do not approve biological or clinical accuracy. Head-training
holdout, LD independence and feasibility remain unverified. The prior comparable
FP32/QNNPACK economic no-go is unchanged. Public exports contain aggregates and
hashes, without DNA, rows, case IDs, vectors or weights. See
[biological evaluation](experiments/005-biological-evaluation.md).

## Remaining requirements

1. Extend lifecycle evidence beyond committed-only broker socket recovery and
   operator active cancellation to broker death during execution, actual upstream
   ACK-write errors, process-only death retaining plaintext and durable
   uncertainty/reconciliation.
2. Pin and verify the image dependency closure, build/distribution and licences;
   cached-image acceptance alone does not establish image reproducibility.
3. Inject attach/removal/storage uncertainty and define explicit operator
   reconciliation without silent adoption, refunds or reexecution.
4. Complete immutable ownership TM02 before principal artifact quotas, full
   result/event/cache/registry quotas and retention, queues/leases/multiple workers.
5. Complete effective SOC/benign adversary scenarios, cloud identity/storage/key
   controls and the final documented deliverables under the free-only constraint.

The full technical scope remains in [requirements and gates](requirements-and-gates.md).

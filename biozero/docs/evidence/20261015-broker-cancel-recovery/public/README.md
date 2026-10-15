# Protected cancellation and committed broker recovery

The Docker fixtures passed broker postcommit SIGKILL/restart 31 checks and active
cancellation 17 checks; independent retained-file readbacks passed 48 and49.
A fresh default Docker regression passed 57 checks and52 independent checks.
Public files contain allowlisted aggregates and source/binary/receipt hashes only.
Raw inputs/results, identifiers, targets, credentials and runtime paths are private.

| Fixture | Actual checks | Independent checks | Exported artifacts | Retained slots | Total charged bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Broker postcommit death | 31 | 48 | 4 | 1 | 27,729 |
| Active cancellation | 17 | 49 | 0 | 1 | 5,713 |
| Default regression | 57 | 52 | 9 | 3 | 65,354 |

Totals include the 4,096-byte Store header reserve. Cancellation retains manifest
and proof metadata; zero retained files means zero exported artifacts, not zero
physical metadata or released admission. Its original 67,239,936-byte reservation
settles to 1,617 bytes of committed metadata plus that header. This is normal
verified commit accounting, not an operator refund or slot release.

## Broker scope

A real signed/encrypted synthetic upload committed four artifacts before the
broker was SIGKILLed. The supervisor pinned its own live child with pidfd and
socket O_PATH, executable/config/profile and complete committed Store/journal/
custody history. The identical restart first exited 1 with the generic
`artifact_service_start_failed` message; no specific internal error is asserted.
After actual death Wait and unchanged committed history, the operator fixture
unlinked only that identified socket once and fsynced its parent. An identical
replacement verified a distinct socket and live peer while the old reference
remained pinned. The three broker processes exited -9/1/0; references closed.

The worker recovered through queries with one Submit and one capsule, unchanged
artifacts/proofs/custody/accounting and TP3/FP0/FN0 with 1,171 mapped reads. The proxy
held the real response throughout the outage and dropped it only after recovery:
this does not test worker retries during broker unavailability or an upstream ACK
write failure. Pending/linked history, live capsule broker death, unknown sockets,
anchors, reservations and plaintext are never adopted or removed by this procedure.
Host/same-UID cooperation is required; unlink is not atomic conditional by inode.

## Cancellation scope

A fixed lifecycle producer actually read authenticated, verified input inside the
pinned Docker capsule and signaled that it was waiting. While Submit remained
open, the fixture validated executing/full-reservation Store state and linked
broker/custody history. It retained byte-exact original copies of all three
private JSON files, checked stable metadata, fsynced copies and directories, then
rechecked original bytes/metadata immediately before sending V2 Cancel.

The observed Cancel ACK was true and terminal publication followed in about 0.419 s
(provider timeout 60 s; producer wait 120 s). The physical result was
failed/withheld/artifact_cancelled, with no scientific output or exports and a
proof recording provider Wait and closed export authority. Custody and slot
remained unchanged. This is a local operator protocol test, not a public/client
cancellation endpoint or scientific inference. The earlier 16-check receipt and
41-check audit without physical before copies remain preserved with that limit;
an earlier audit-only Docker-error case mismatch also remains preserved.

## Exact source and reproduction

Both source snapshots contain 408 files and were unchanged within their runs.
Broker/default used the 3770129 base with local fixture changes. Cancellation and
final make used 476e89ee with local fixture changes. The exact three-file delta is
recorded: the cancellation evidence writer plus an unrelated attribution/checksum
correction in an earlier public evidence file. No Go service source changed.
Six original executables were reused after all 51 production Go/module inputs and
all six executable hashes were freshly verified. Build metadata remains
`333995f dirty`; these receipts do not claim a fresh rebuild from either base.

Final make at the cancellation snapshot passed 294 Python cases: 292 passed and two
helper kernel opt-ins skipped; all eight Go modules passed uncached test/vet.
Fifteen socket reconciliation tests run only as UID/EUID 1000 and may skip on other
hosts. Hosted CI, Docker and kernel acceptance are separate scopes. Documents and
this bundle were written after runtime acceptance; no source pin silently includes
later documentation.

Run from the repository root with the prerequisites and opt-in commands in the
[Compose guide](../../../../infra/compose/README.md). Use fresh private destinations,
verified ARM64 binaries, the exact cached image, UID/EUID 1000 and Linux pidfd.
No automatic build/pull, history cleanup, resubmission or deployment is performed.
Verify the bundle with `sha256sum -c SHA256SUMS` from this directory.

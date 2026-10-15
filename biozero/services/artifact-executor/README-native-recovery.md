# Native keeper/provider lifecycle acceptance

Observed locally on 2026-10-14, Linux ARM64, UID/GID 1000, real host Python 3.9
with both pidfd APIs and configured locked tool directories. The new opt-in uses
the actual NativeProvider, InputRegistry, Coordinator and Store. Runtime files
were unchanged. Source hashes are retained in each private acceptance receipt.
This is separate from CI for snapshot 28918a96484dcb2a015c71540f853d29e34a9836.

The pinned workload is a deliberately blocked synthetic stdlib lifecycle script,
not the variant pipeline or biological model. It runs after the real namespace,
tmpfs, source/input pinning, capdrop and no_new_privs setup. It publishes a private
readiness marker, then waits for termination. Readiness is never proof of
quiescence. Tools are configured to the locked native profile; this fixture does
not run minimap2/samtools/bcftools or make a scientific release claim.

## Observed cases

| Case | Termination and acceptance |
| --- | --- |
| Cancel | Cancel the coordinator context only after actual capsule workload readiness; authoritative PID1 Wait finishes, captured tasks disappear, failed/withheld empty-export commit has a genuine post-Wait proof. A canceled ACK never invokes its callback. |
| Timeout | NativeProvider's three-second budget terminates the real blocked capsule; failed/withheld custody is retained after Wait. This is distinct from a keeper crash and its missing proof. |
| PID1 SIGKILL | Pin the exact helper by pidfd after checking creator ancestry, argv and start-time identity; signal that descriptor, observe actual Wait/teardown, retain failed/withheld commit and charge. |
| Keeper SIGKILL | Run the keeper in a separate test process. Prove live lifetime-flock denial, capture executing/full reservation/no proof, then kill only that created keeper. Immediate restart before observing cleanup is refused by flock or durable unhealthy pending history. Pdeathsig ends the capsule, but later restart still retains executing/full charge, refuses new reservation/Begin/registry/ACK, and does not rewrite the ledger or silently adopt the workspace anchor. |

For the first three cases, a valid failed commit may reopen healthy: actual Wait
has established quiescence and custody is complete. The retained job slot/charge
survive; the old run/reference cannot execute again. Blocking all future unrelated
work after a valid failed commit would be a different contract. A proof in these
cases is legitimate, rather than a false proof fabricated from a process marker.

For lost keeper authority, disappearance of processes never clears pending state.
No manifest or proof is invented, the full reservation stays charged and no
callback ACK fires. The empty host workspace anchor remains as private crash
history, causing NewNativeProvider to refuse unreconciled history. It is not a
live mount or producer, and the test does not delete it to enable admission.

## Executed evidence

The final ordinary opt-in passed all four cases and 68 assertions in 3.421s:
`.biozero/native-recovery-20261014T230557.265475701Z/`.
The same source passed the real opt-in with the race detector in 4.502s:
`.biozero/native-recovery-20261014T230646.072899531Z/`.
Each root has per-case acceptance.json, private stores/manifests/proofs where
legitimate, pinned fixtures and keeper log/registration. The ordinary final run's
immediate attempt was denied by the lifetime flock; subsequent pending denial is
independently checked after cleanup. Receipt JSON records the actual branch.
The race run observed the other immediate branch: the flock had already closed,
but the reopened store was unhealthy with its full pending reservation. Both
actual branches refused admission. All 68 assertions, seven source pins and
0700/0600 evidence modes were independently reread in both final roots.
The default module suite also passed with -race, and go vet passed; these default
tests skip the kernel opt-ins and retain their separate scope.

Earlier accepted receipts remain at 230331.491675440Z and 230504.636874582Z under
`.biozero/native-recovery-20261014T.../`. They do not include the subsequently added
immediate-restart assertion and must retain that narrower scope. Those receipts
are preserved and are not promoted to the newer source scope. No lifecycle case
was silently retried after a test failure.

All captured helper/workload tasks disappeared. The test temporarily enables
subreaper status in its own test process so it can reap only the captured orphan
PID1, then restores the previous flag. It signals helpers via pidfd only; it does
not kill arbitrary host processes. Managed namespace resources were cleaned by
actual kernel teardown. Evidence directories/files were checked as 0700/0600 and
all seven source hashes matched the final ordinary receipt. Raw evidence remains
private and is not an external publication.

## Reproduction

Default module tests skip these two opt-ins and cannot establish kernel recovery
acceptance. On a compatible prepared local host, run from artifact-executor:

```sh
BIOZERO_RUN_NATIVE_RECOVERY_ACCEPTANCE=1 go test \
  -run '^TestNativeRecoveryActualAcceptance$' -v -count=1 -timeout=70s
BIOZERO_RUN_NATIVE_RECOVERY_ACCEPTANCE=1 go test -race \
  -run '^TestNativeRecoveryActualAcceptance$' -v -count=1 -timeout=70s
```

BIOZERO_NATIVE_RECOVERY_EVIDENCE_DIR optionally selects a new absolute destination;
existing destinations are refused. Otherwise a timestamped private root is made
under the repository's ignored .biozero directory, on success or failure. The
internal TestNativeRecoveryKeeperProcess is launched only by this harness, with
explicit private local arguments and no inherited SDK credentials or hooks.
Unavailable Python 3.9/pidfd/kernel/provider capabilities fail the opt-in visibly;
there is no namespace substitute or skip treated as success. Generic Linux pidfd
syscall numbers are restricted by the test to arm64/amd64 hosts.

This receipt establishes one configured native lifecycle boundary. It does not
install the provider in enclave-runner, implement operator recovery/adoption,
certify arbitrary producer hostility, cover the Docker provider, inject every
storage failure, exercise protected TLS/signature/decryption or validate scientific
accuracy. Same-UID/privileged host writers and fixed configured runtime remain
trusted; no external attestation or automatic quota refund/reexecution is claimed.

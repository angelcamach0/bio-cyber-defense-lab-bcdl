# Docker keeper/provider lifecycle acceptance

These opt-ins exercise the actual ContainerProvider, InputRegistry, Coordinator
and Store against the explicitly configured local Docker daemon and cached image
`sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d`.
Runtime remains unchanged: Go provider SHA256
`36d6e1be27026588a8280def67f72610a7b3bf30fc2fff4ecc8cd64c06c76e1f`,
helper SHA256 `56b2a3883d5201f3d227dc58fe4edf0577c0136b4ea707542491ed32c0a29ac8`.
Source pins and private receipts distinguish each execution. Final ordinary and
race-instrumented runs passed on 2026-10-14; earlier accepted evidence has its
narrower scope. Test source SHA256 is
`596d59e674951568a4b108169c84a7a06fb56c0f6df018271d3d2d3341e849b4`.

The trusted pinned `pipeline.py` is a deliberately blocked stdlib lifecycle
fixture in stats mode. It publishes a private readiness marker after actual
container/input/source/capability setup, then sleeps until terminated. It runs no
biological model or scientific tools. The only test-specific Docker exec uses a
fixed Python 3.12 argv to read that marker. Exact new ID, nonce, store and lease are
inspected before this read. A marker is a fault trigger, never quiescence proof.
No builds, image pulls or external network operations are performed.

## Cases and authority

| Case | Required observations |
| --- | --- |
| Cancel | Cancel only after actual readiness. The unchanged provider performs exact-ID kill, Docker wait/inspect, then removal; coordinator retains a failed/withheld empty-export commit with genuine proof binding the durable manifest. A canceled ACK callback cannot fire. Retained slot/charge survive reopening; the old reference cannot invoke the provider again. |
| Timeout | The provider's eight-second budget ends the blocked workload. The same wait/custody/failure/restart checks apply. This is a valid failed commit, distinct from keeper loss and its absent proof. |
| Keeper SIGKILL | Kill only the Go test subprocess created by this test. Immediately attempt Store reopen before observing process wait or Docker cleanup: a held flock or unhealthy durable pending state must refuse admission. The helper EOF monitor ends PID1; independent Docker wait/inspect of the exact owned ID must report exited/PID 0 and matching exit code. Even afterward the Store remains executing, fully charged and without manifest, proof or ACK. New reservation, Begin, registry and old-workspace adoption remain refused without rewriting the journal. |

The keeper case intentionally preserves the stopped owned Docker object and its
private control anchor/intent/container ID as crash history. It never removes or
adopts an earlier failed container, searches by name to recover authority,
resets a ledger, refunds a reservation or reruns its workload. Emergency cleanup,
if needed after a test failure, kills only an ID whose exact current identity and
configuration still match; it does not remove stopped history or turn failure
into PASS. An unavailable daemon is not evidence of container removal: cancel
and timeout query `docker ps` successfully with their exact ID and require no row.

The parent temporarily enables subreaper status in its own test process, captures
only descendants of its created keeper whose argv contains that exact attach
operation/container ID, and reaps those known orphan CLIs after capsule exit.
No host-wide PID lookup or arbitrary process signal is used; the prior subreaper
flag is restored. That process cleanup does not manufacture Store proof.

## Executed evidence

Final ordinary acceptance passed all three cases and 59 assertions in 10.777s:
`.biozero/container-recovery-20261014T234333.760849570Z/`.
The identical source passed with the race detector in 11.912s:
`.biozero/container-recovery-20261014T234427.292851480Z/`.
Cancel and timeout each made 18 checks; keeper loss made 23. Readback independently
within the authoring session confirmed all assertions, nine current source pins
and private directory/file modes in both roots. Chiquis subsequently confirmed
a separate read-only source review; that review is not an independent reproduction.
The joint suite being run by the coordinator retains its separate source/run scope.

The ordinary run observed immediate unhealthy durable pending after the keeper's
flock had closed. The race run observed immediate lifetime-flock denial before
that release. Both actual branches denied admission before any wait/cleanup
observation. Later, Docker independently confirmed the exact owned object exited
with PID 0/code 1, while its Store still retained executing/full charge and neither
proof nor ACK. Captured orphan attach processes were reaped. The stopped Docker
objects, control anchors and journals remain private crash history deliberately.

An earlier ordinary PASS at
`.biozero/container-recovery-20261014T234222.184454645Z/` retains its smaller scope:
it predates explicit attach-orphan reap and exact proof/manifest-byte assertions.
It was not rewritten or attributed to the final source. A preparatory source-edit
command used the wrong working directory and made no change; the accompanying
default Go invocation merely compiled and skipped opt-ins. It established no real
Docker acceptance. Final runs above used the corrected test source. No failed
kernel lifecycle case was retried or erased, and earlier provider failures remain
separate private histories.

## Reproduction and privacy

Run from `biozero/services/artifact-executor` on the prepared compatible local
Linux host, UID/GID 1000 with configured noninteractive Docker authority:

```sh
BIOZERO_RUN_CONTAINER_RECOVERY_ACCEPTANCE=1 go test \
  -run '^TestContainerRecoveryActualAcceptance$' -v -count=1 -timeout=130s
BIOZERO_RUN_CONTAINER_RECOVERY_ACCEPTANCE=1 go test -race \
  -run '^TestContainerRecoveryActualAcceptance$' -v -count=1 -timeout=130s
```

Default tests skip the opt-in. Capability failure in an explicitly enabled run
is a visible failure, not a namespace substitute or accepted skip.
`BIOZERO_CONTAINER_RECOVERY_EVIDENCE_DIR` optionally chooses a new absolute
private destination; existing roots are refused. Otherwise a timestamped root is
created under the repository's ignored `.biozero` directory. Each case retains
its acceptance JSON, Store records, pinned fixture, and keeper registration/log
where applicable, with directory/file modes 0700/0600. Receipts record the actual
immediate-restart branch, every assertion and source hashes. The internal
`TestContainerRecoveryKeeperProcess` is invoked only as this test's subprocess.
Host SDK/Docker auth and DOCKER_CONFIG are preserved; runtime CLI strips exactly
five endpoint selectors for its fixed local socket. Capsule environment is its
separate offline allowlist. Neither environment nor secrets are printed.

This establishes only the configured standalone Docker lifecycle boundary and
synthetic blocked fixture. It does not install the provider in enclave-runner,
exercise worker TLS/signature/decryption, verify scientific accuracy, inject
every attach/removal/storage fault, implement operator recovery/adoption, or
provide tenant identity or external attestation. Same-UID/privileged host writers,
source assets and the local Docker daemon remain trusted. Stopped-object history
retention is intentional; physical daemon/host spool quotas are outside this test.

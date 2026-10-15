# Worker FD bridge transport

This is a separate Linux Unix-stream protocol for the trusted protected worker;
it does not extend v1 run/status/cancel with paths or Docker authority. The broker
owns journal/admission/lease authority; the transport owns sockets, frame/FD
validation, cancellation and bounded real wire writes. It does not establish
crypto validity, provider quiescence or durable custody by itself.

## API and ownership

- `ListenBridgeUnix(UnixServerConfig, BridgeHandler)` returns a server with
  `Serve(ctx)` and `Close()`. Socket anchoring/lifetime and explicit AllowedUID
  reuse v1's existing machinery; its v1 request dispatcher is not used.
- `BridgeHandler.HandleBridge(ctx, request, input)` returns a response and optional
  receipt descriptor. Input is borrowed until the handler returns. Broker code
  duplicates it before retaining it. A returned output FD transfers ownership to
  the server, which duplicates it atomically for sending and closes both copies.
- Optional `BridgeAcknowledger.AcknowledgeBridge(ctx, request, write)` must invoke
  the real socket callback synchronously, at most once before returning. Late or
  duplicate calls fail. Without it, the generic server makes no durable ACK claim.
- `CallBridgeUnix(ctx, socket, request, input)` borrows client input and returns an
  owned receipt FD, which the caller closes. It validates the response, terminal
  EOF, actual private readonly metadata, size and bounded SHA256 before returning.

The shared fixed `BridgeRequest` and `BridgeResponse` DTOs and semantic validators
are owned by the broker. Every JSON field is required, including empty values;
unknown/missing/duplicate/alias/null fields and excess depth fail the strict
parser. Wire UTF8 must be valid before JSON parsing. Client paths, commands,
images, mounts, policies and proofs are absent. OriginalName is bounded data for
preserved detection semantics; it is never a transport path or command.

## Fixed analysis protocol v2

`ListenBridgeUnixV2(config, BridgeHandlerV2)` selects the strict v2 codec for the
entire listener lifetime. `HandleBridgeV2` and optional `AcknowledgeBridgeV2`
receive `BridgeRequestV2`; `CallBridgeUnixV2` validates v2 replies. V1 and v2 do not
negotiate or fall back to one another. Both successful responses and error
envelopes on the v2 listener have `schema_version: 2`.

Every v2 request includes a complete `analysis_context` object. Its six facts
must match submit's processed size/name; queries require the zero-valued object.
Unknown, missing, duplicate or null nested fields are rejected by the existing
strict parser, which has not been widened. The fixed UID remains the caller's
trust boundary; transmitting asserted verification facts does not authenticate
cryptographic work. All framing, FD, deadline and ACK rules below apply unchanged.
The broker separately persists the context with the lease binding; see
[its v2 contract](README-broker.md#explicit-analysis-protocol-v2).

## Framing, resources and cancellation

One request per connection: four-byte big-endian length, then 1..65536 bytes JSON.
A submit carries exactly one readonly FD on its first byte. Other operations
(status, cancel, receipt) carry no FD. A successful receipt response alone carries
one readonly FD. Errors and other responses carry none. Both directions use
recvmsg throughout header, payload and trailing monitoring so late ancillary
authority cannot be silently discarded by ordinary stream Read.

Atomic MSG_CMSG_CLOEXEC is provided by Go's Linux UnixConn recvmsg; descriptor
flags are also checked. Missing, extra, late, truncated or unexpected rights fail
closed and every installed descriptor is closed. Submit FD must be a private
regular file, exact 0600/current UID/Nlink 1, readonly/CLOEXEC, with exact declared
length no greater than 25MiB. Receipt has the same metadata constraints and a 16MiB
cap, matching the declared SHA and bytes. The broker separately verifies the
plaintext digest and its association with the job/crypto barrier. The transport
cannot unlink input early or assume an anonymous memfd satisfies Nlink 1.

Ancillary rights are sent once; partial ordinary byte writes finish without
resending FDs. Socket directories/inodes are descriptor anchored and private,
with no symlink traversal or blind deletion/adoption of old sockets. Close
removes only the same socket inode created by this server. Explicit peer UID is
checked before dispatch. The client requires the private server owner to match
its effective UID. Same-UID/privileged host writers remain trusted; this is not
tenant authentication, host attestation or an authenticated proof of crypto work.

Defaults match v1: 8 connections (configured 1..32), request 5s (at most 30s), run 15min
(at most 1h), write 5s (at most 30s). A caller context can shorten its 1h client cap.
EOF, write-half-close, extra bytes/rights, run deadline, parent cancellation or
Close cancel only the relevant channel/context; Close cancels all active channels.
The monitor remains active while the acknowledger runs, including its actual
write callback. A partial/failed ACK never gets a second appended response.

Queued extra data/EOF is checked before handler dispatch. Data that arrives after
admission can cancel/fence ACK but cannot retroactively undo durable admission;
the transport does not promise zero handler calls for that causal race. Handlers
must honor context or retain pending authority until real provider completion.
Server Close is not a Wait operation or a quota/lease release.

## Validation scope

The recorded runs and source hashes below predate the new v2 codec. They are
not evidence that changed v2 source has passed its new checks.

Tests use real local Unix sockets, descriptor passing and context races with
fake handlers/acknowledgers. They exercise submit/status/cancel/receipt, first-byte
fragmentation, strict JSON and oversize/timeout recovery; invalid/missing/extra/
late/truncated rights, FIFO/mode/link/size errors; post-dispatch data, rights,
half-close and disconnect; real callback once/late rejection and active monitor;
wrong receipt digest/size/presence and handler-error privacy; wrong peer UID,
scoped concurrent cancellation and FD-count readback over 20 rejected transfers.

The initial functional run compiled the broker too but failed positive roundtrips
because this transport compared wrapped EOF directly to io.EOF. Using errors.Is
fixed net.OpError-wrapped EOF handling. Negative cases from the failed run are
not treated as evidence that the final positive path worked. The final functional
TestBridge run passed 8 top-level functions and their subcases in 0.365s. The same
transport passed with the race detector in 1.394s; go vet ./...
completed with exit 0. These eight top-level functions contain 26 subcases. The
module compiled the then-current broker/DTO files too; TestBroker and worker
analysis/CLI behavior are separate tests and were not executed by this command.

Earlier pre-v2 transport snapshot SHA256:
`f489e88851fb25675e36bca1696bd61c8c6912b8cec9eed7619022da4b41fdca`.
Test SHA256:
`258f73db0b8ec561d06b1a44e270c95dd250e055a0a6b70844f7ada22d65536e`.
The transport and tests received independent source review, with no concrete
blocking defect reported. The broker's journal layout, committed readback and
ACK-lock corrections were reviewed separately. Real protected-worker integration
remains pending.

After the shared Store ACK helper changed, the complete module was executed
with the race detector and six native/Docker opt-ins: 90 top-level PASS plus
subcases, two internal keeper entries skipped only in the parent, 23.847s.
Independent readback of the private JSON event log and summary, without rerunning
tests, confirmed eight TestBridge and nine TestBroker top-level cases passed,
zero failures, exit 0;
the log SHA and 33/33 source pins match. Evidence root:
`.biozero/bridge-composed-race-20261015T001622.113158Z/`.
This composition validates the revised Store/broker/transport alongside existing
real provider tests, but the broker fixtures themselves use fake providers. It
does not establish bridge plus worker crypto plus real provider end-to-end
acceptance. The later full repository make/vet gate remains separately recorded
with its own evidence; earlier published capsule CI does not cover this new source.

From this module:

```sh
go test -run '^TestBridge' -v -count=1 -timeout=40s
go test -race -run '^TestBridge' -count=1 -timeout=45s
go vet ./...
```

No real worker crypto, Broker journal recovery, capsule provider, Docker, models,
external network, production service or scientific assessment is exercised by
these fake-handler tests. Those integrations have separate acceptance. Receipt
FD custody/ACK does not grant scientific approval, operator recovery or retention
release. TM02 immutable owner binding, per-principal quotas and retention remain
pending.

## Analysis protocol v2 checks

The new v2 broker/context tests passed10top-level functions and their subcases
with ordinary execution (0.988s) and the race detector (2.564s); `go vet ./...`
exited0. They use real private Store/journal files and Unix FD sockets with
synthetic providers. They cover fixed v2/error envelopes, complete strict context,
registry propagation, changed-context/profile conflicts, duplicate custody,
lost-ACK committed-only restart, missing/mismatched context history, bilateral
version refusal, durable context before Reserve, storage/crash gaps and both
causal journal/Store ACK barriers. No kernel provider, worker crypto or scientific
pipeline is exercised by this narrow command.

An initial run failed three crash-test subcases because its fixture attempted to
create a registry from correctly unavailable pending Store history. The fixture
now asserts that refusal and unchanged ledger/journal bytes. The failed log is
preserved alongside the corrected ordinary/race/vet logs under the private
`.biozero/bridge-v2-checks-20261015T005815.199358Z/` evidence root. No production
guard was weakened. The earlier v1 receipts above remain scoped to their source.

# Linux Unix listener and client addon

Status: implementation with observed Go module acceptance on 2026-10-14.
`go test -race ./...` and `go vet ./...` passed in artifact-executor: 60 test
functions including subcases, of which 16 exercise the Unix listener/client.
The existing core/contract documentation retains its prior source and scope.
Native provider/capsule acceptance now has separate synthetic module evidence in
[the native addon](README-native.md). Subsequent standalone
[lifecycle/restart acceptance](README-native-recovery.md) and
[actual Unix composition](README-native-unix.md) have their own local receipts;
container execution and installed-worker acceptance remain pending. The listener
checkpoint above does not establish those later provider results.

`UnixHandler.Handle(context.Context, Request) ([]byte, error)` is trusted keeper
code. The server checks peer credentials and request grammar; the handler must
check the configured input reference, lease authority and all core ordering.
Clients send only schema_version, operation (run/status/cancel), lease_id and
input_ref. They cannot send paths, commands, images, mounts, proofs or policy.

`ListenUnixServer(UnixServerConfig, UnixHandler)` returns a server with `Serve(ctx)`
and `Close()`. AllowedUID must be an explicit *uint32, including an explicit zero
when appropriate. The server copies that UID; changing the original variable
does not change listener policy. Defaults and ceilings:

| Limit | Default | Maximum |
| --- | --- | --- |
| Concurrent admitted connections | 8 | 32 |
| Request frame read | 5 seconds | 30 seconds |
| Handler and ACK lifetime | 15 minutes | 1 hour |
| Response write | 5 seconds | 30 seconds |
| Request/response payload | 64 KiB | 64 KiB |

The socket parent is created/opened through descriptor-anchored no-follow
ancestors, with final directory ownership equal to the server UID and exact 0700.
Binding uses /proc/self/fd/<directoryfd>/<name>; the descriptor stays alive.
Socket metadata is pinned by O_PATH|O_NOFOLLOW, owned by the server UID and
changed to exact 0600 through the pinned proc descriptor. Socket names are bounded
simple basenames. SO_PEERCRED must match AllowedUID before reading a frame.

An existing socket, FIFO, regular file or symlink causes startup refusal, without
adoption or deletion. Close disables Go's automatic unlink and removes only the
same socket inode under the held directory. A replacement remains untouched;
renaming/replacing the configured directory does not redirect cleanup. Startup
failure or process death may leave a socket requiring explicit operator recovery.
There is no stale-socket automatic deletion.

One request travels over each connection. The client must keep both directions
open: EOF, write half-close, extra input or channel failure cancel that connection's
context, including while ACK is pending. This cancellation does not undo durable
admission or prove provider termination. Trailing bytes can race handler dispatch;
the handler must honor cancellation while retaining reservation/custody. At the
ACK boundary the server rechecks context and peeks for pending bytes/EOF.

An optional `UnixAcknowledger.Acknowledge(ctx, request, func() error) error` wraps
the actual framed response write. Its callback is synchronous and may execute at
most once, before the method returns. The coordinator can delegate that callback
to Store.Acknowledge for committed results. Failed Handle, canceled channels and
oversized responses do not invoke the acknowledger. Actual write failures reach
the acknowledger rather than becoming a marshaling success. The server appends no
second response after an ambiguous ACK. Without this interface it provides only a
generic framed response, with no durable ACK claim.

A successful kernel write cannot prove client receipt: disconnection may race the
write or happen afterward. Lost ACK retains the Store commit/charge. Neither socket
closure nor context cancellation frees a lease or certifies namespace quiescence.
A handler that ignores ctx cannot be forcibly terminated by this library; Close
closes channels and returns without waiting. Such handlers retain connection slots
until return, bounding admission rather than claiming provider cleanup.

`CallUnix(ctx, socket, Request) ([]byte, error)` validates the local request, opens
a safe existing private directory/socket, verifies the connected server UID equals
the caller UID, writes one request, reads one bounded response then requires EOF.
It never half-closes. Its deadline is the caller deadline capped at one hour;
context cancellation closes the channel. Raw upstream errors and filesystem paths
are not returned. Handler errors on the wire use artifact_handler_failed; protocol
errors use stable bounded codes. Successful handler bytes remain trusted private
output and require the coordinator's own DTO/privacy controls.

This is same-UID local host authentication, not independent tenant authorization
or attestation. Configuring a different peer UID does not grant traversal of a
0700 directory or 0600 socket. Privileged/shared-UID writers, the orchestrator and
configured handler remain trusted. No provider, scope registry, worker integration,
physical filesystem quota or biological accuracy is established by this addon.

Executed tests use actual Unix connections for SO_PEERCRED rejection, private modes,
previous-file preservation, symlink ancestors, anchored cleanup, frame/time limits,
FIFO-free channel disconnects/half-close/trailing cancellation, scoped connections,
response cap, safe errors, context/Close cancellation and real Store ACK failure.
The first race run failed two fixtures: Close outran Serve startup, and a raw
response probe used a nonprivate directory and accepted any early error. The
fixtures now synchronize startup, use an exact 0700 directory and demand the exact
artifact_response_oversized code. The complete race suite then passed. This scope
includes actual socket ACK write failures and Store retention, not native capsule
or model execution. No runtime/server code changed for those fixture corrections.

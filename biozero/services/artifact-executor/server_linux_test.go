//go:build linux

package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type unixTestHandler func(context.Context, Request) ([]byte, error)

func (h unixTestHandler) Handle(ctx context.Context, q Request) ([]byte, error) { return h(ctx, q) }
func unixTestRequest(op string) Request {
	input := ""
	if op == "run" {
		input = strings.Repeat("b", 32)
	}
	return Request{1, op, strings.Repeat("a", 32), input}
}
func unixTestStart(t *testing.T, config UnixServerConfig, h UnixHandler) (*UnixServer, string) {
	t.Helper()
	if config.SocketPath == "" {
		config.SocketPath = filepath.Join(t.TempDir(), "private", "keeper.sock")
	}
	if config.AllowedUID == nil {
		uid := uint32(os.Geteuid())
		config.AllowedUID = &uid
	}
	s, err := ListenUnixServer(config, h)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan error, 1)
	go func() { ended <- s.Serve(ctx) }()
	// Tests that immediately Close must not outrun Serve admission startup.
	startupDeadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		started := s.started
		s.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(startupDeadline) {
			t.Fatal("Serve startup did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		s.Close()
		select {
		case err := <-ended:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not return")
		}
	})
	return s, config.SocketPath
}
func unixTestDial(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	dir, name, err := unixName(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := unixExistingDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Net: "unix", Name: fdPath(d) + "/" + name})
	if err != nil {
		t.Fatal(err)
	}
	if c.SetDeadline(time.Now().Add(2*time.Second)) != nil {
		t.Fatal("deadline")
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func unixTestSend(t *testing.T, c *net.UnixConn, q Request) {
	t.Helper()
	b, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if WriteFrame(c, b) != nil {
		t.Fatal("write request")
	}
}
func unixTestError(t *testing.T, c *net.UnixConn, code string) {
	t.Helper()
	raw, err := readUnixFrame(c)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]any
	if json.Unmarshal(raw, &response) != nil || response["error_code"] != code || response["status"] != "failed" {
		t.Fatalf("unexpected error response %s", raw)
	}
}
func unixTestClosed(t *testing.T, c *net.UnixConn) {
	t.Helper()
	var one [1]byte
	n, err := c.Read(one[:])
	if n != 0 || err == nil || isTimeout(err) {
		t.Fatalf("connection not promptly closed: n=%d err=%v", n, err)
	}
}
func unixTestAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("missing channel event")
	}
}

func TestUnixServerRealPeerPrivateModesAndCall(t *testing.T) {
	_, path := unixTestStart(t, UnixServerConfig{}, unixTestHandler(func(ctx context.Context, q Request) ([]byte, error) { return []byte(`{"status":"committed"}`), nil }))
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil || dir.Mode().Perm() != 0700 {
		t.Fatal("directory not private")
	}
	socket, err := os.Lstat(path)
	if err != nil || socket.Mode()&os.ModeSocket == 0 || socket.Mode().Perm() != 0600 {
		t.Fatal("socket not private")
	}
	for _, op := range []string{"run", "status", "cancel"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		raw, err := CallUnix(ctx, path, unixTestRequest(op))
		cancel()
		if err != nil || string(raw) != `{"status":"committed"}` {
			t.Fatal(op, err, string(raw))
		}
	}
}
func TestUnixServerWrongPeerAndExplicitUID(t *testing.T) {
	if _, err := ListenUnixServer(UnixServerConfig{SocketPath: filepath.Join(t.TempDir(), "socket")}, unixTestHandler(func(context.Context, Request) ([]byte, error) { return nil, nil })); err == nil {
		t.Fatal("implicit UID accepted")
	}
	wrong := uint32(os.Geteuid()) + 1
	var calls atomic.Int32
	_, path := unixTestStart(t, UnixServerConfig{AllowedUID: &wrong}, unixTestHandler(func(context.Context, Request) ([]byte, error) { calls.Add(1); return []byte("ok"), nil }))
	c := unixTestDial(t, path)
	unixTestError(t, c, "artifact_peer_forbidden")
	unixTestClosed(t, c)
	if calls.Load() != 0 {
		t.Fatal("wrong peer dispatched")
	}
}
func TestUnixServerNeverAdoptsExistingEntriesOrSymlinkAncestor(t *testing.T) {
	for _, kind := range []string{"file", "socket", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "keeper.sock")
			var prior *net.UnixListener
			switch kind {
			case "file":
				if os.WriteFile(path, []byte("retained"), 0600) != nil {
					t.Fatal("fixture")
				}
			case "symlink":
				if os.Symlink(filepath.Join(parent, "absent"), path) != nil {
					t.Fatal("fixture")
				}
			case "socket":
				var err error
				prior, err = net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
				if err != nil {
					t.Fatal(err)
				}
				prior.SetUnlinkOnClose(false)
				defer prior.Close()
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Geteuid())
			if s, err := ListenUnixServer(UnixServerConfig{SocketPath: path, AllowedUID: &uid}, unixTestHandler(func(context.Context, Request) ([]byte, error) { return nil, nil })); err == nil {
				s.Close()
				t.Fatal("existing entry adopted")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("existing entry replaced/deleted")
			}
			if kind == "file" {
				raw, err := os.ReadFile(path)
				if err != nil || string(raw) != "retained" {
					t.Fatal("file altered")
				}
			}
		})
	}
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	os.Mkdir(real, 0700)
	alias := filepath.Join(parent, "alias")
	os.Symlink(real, alias)
	uid := uint32(os.Geteuid())
	if s, err := ListenUnixServer(UnixServerConfig{SocketPath: filepath.Join(alias, "socket"), AllowedUID: &uid}, unixTestHandler(func(context.Context, Request) ([]byte, error) { return nil, nil })); err == nil {
		s.Close()
		t.Fatal("symlink ancestor accepted")
	}
}
func TestUnixServerClosePreservesReplacementAndAnchorsDirectory(t *testing.T) {
	s, path := unixTestStart(t, UnixServerConfig{}, unixTestHandler(func(context.Context, Request) ([]byte, error) { return []byte("ok"), nil }))
	if os.Remove(path) != nil || os.WriteFile(path, []byte("replacement"), 0600) != nil {
		t.Fatal("replacement fixture")
	}
	if err := s.Close(); err == nil {
		t.Fatal("changed socket not noticed")
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "replacement" {
		t.Fatal("foreign replacement removed")
	}
	s, path = unixTestStart(t, UnixServerConfig{}, unixTestHandler(func(context.Context, Request) ([]byte, error) { return []byte("ok"), nil }))
	dir := filepath.Dir(path)
	old := dir + "-moved"
	if os.Rename(dir, old) != nil || os.Mkdir(dir, 0700) != nil {
		t.Fatal("directory replacement")
	}
	replacement := filepath.Join(dir, filepath.Base(path))
	if os.WriteFile(replacement, []byte("keep"), 0600) != nil {
		t.Fatal("replacement fixture")
	}
	if s.Close() != nil {
		t.Fatal("anchored socket cleanup failed")
	}
	if raw, err := os.ReadFile(replacement); err != nil || string(raw) != "keep" {
		t.Fatal("replacement directory touched")
	}
	if _, err := os.Lstat(filepath.Join(old, filepath.Base(path))); !os.IsNotExist(err) {
		t.Fatal("original socket not removed")
	}
}
func TestUnixServerTimeoutOversizeStrictRequestAndNextValid(t *testing.T) {
	var calls atomic.Int32
	_, path := unixTestStart(t, UnixServerConfig{RequestTimeout: 40 * time.Millisecond}, unixTestHandler(func(context.Context, Request) ([]byte, error) { calls.Add(1); return []byte("ok"), nil }))
	for _, kind := range []string{"timeout", "oversize", "unknown", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			c := unixTestDial(t, path)
			switch kind {
			case "timeout":
				c.Write([]byte{0, 0})
			case "oversize":
				var header [4]byte
				binary.BigEndian.PutUint32(header[:], MaxFrameBytes+1)
				c.Write(header[:])
			case "unknown":
				WriteFrame(c, []byte(`{"schema_version":1,"operation":"run","lease_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","input_ref":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","path":"/private"}`))
			case "duplicate":
				WriteFrame(c, []byte(`{"schema_version":1,"operation":"status","operation":"cancel","lease_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","input_ref":""}`))
			}
			code := "artifact_request_invalid"
			if kind == "timeout" {
				code = "artifact_frame_invalid"
			}
			if kind == "oversize" {
				code = "artifact_frame_oversized"
			}
			unixTestError(t, c, code)
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request dispatched")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := CallUnix(ctx, path, unixTestRequest("status")); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("valid next request missing")
	}
}
func TestUnixServerDisconnectHalfCloseAndTrailingFenceRun(t *testing.T) {
	for _, mode := range []string{"close", "half_close", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			canceled := make(chan struct{})
			_, path := unixTestStart(t, UnixServerConfig{}, unixTestHandler(func(ctx context.Context, q Request) ([]byte, error) {
				close(started)
				<-ctx.Done()
				close(canceled)
				return []byte(`{"status":"committed"}`), nil
			}))
			c := unixTestDial(t, path)
			unixTestSend(t, c, unixTestRequest("run"))
			unixTestAwait(t, started)
			switch mode {
			case "close":
				c.Close()
			case "half_close":
				c.CloseWrite()
			case "trailing":
				c.Write([]byte("extra"))
			}
			unixTestAwait(t, canceled)
			if mode != "close" {
				unixTestClosed(t, c)
			}
		})
	}
}
func TestUnixServerCancellationIsScopedAndConnectionsBounded(t *testing.T) {
	startedA := make(chan struct{})
	startedB := make(chan struct{})
	canceledA := make(chan struct{})
	canceledB := make(chan struct{})
	_, path := unixTestStart(t, UnixServerConfig{MaxConnections: 2}, unixTestHandler(func(ctx context.Context, q Request) ([]byte, error) {
		if q.LeaseID == strings.Repeat("a", 32) {
			close(startedA)
			<-ctx.Done()
			close(canceledA)
		} else {
			close(startedB)
			<-ctx.Done()
			close(canceledB)
		}
		return nil, ctx.Err()
	}))
	a := unixTestDial(t, path)
	unixTestSend(t, a, unixTestRequest("run"))
	unixTestAwait(t, startedA)
	b := unixTestDial(t, path)
	q := unixTestRequest("run")
	q.LeaseID = strings.Repeat("c", 32)
	unixTestSend(t, b, q)
	unixTestAwait(t, startedB)
	third := unixTestDial(t, path)
	unixTestClosed(t, third)
	a.Close()
	unixTestAwait(t, canceledA)
	select {
	case <-canceledB:
		t.Fatal("A disconnect canceled B")
	case <-time.After(40 * time.Millisecond):
	}
	b.Close()
	unixTestAwait(t, canceledB)
}
func TestUnixServerResponseCapAndHandlerErrorPrivacy(t *testing.T) {
	for _, mode := range []string{"oversize", "empty", "private_error", "exact"} {
		t.Run(mode, func(t *testing.T) {
			_, path := unixTestStart(t, UnixServerConfig{}, unixTestHandler(func(context.Context, Request) ([]byte, error) {
				switch mode {
				case "oversize":
					return bytes.Repeat([]byte("a"), MaxFrameBytes+1), nil
				case "empty":
					return nil, nil
				case "private_error":
					return nil, errors.New("/private/secret-token")
				default:
					return bytes.Repeat([]byte("a"), MaxFrameBytes), nil
				}
			}))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			response, err := CallUnix(ctx, path, unixTestRequest("status"))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "exact" {
				if len(response) != MaxFrameBytes {
					t.Fatal("exact cap rejected")
				}
				return
			}
			code := "artifact_response_oversized"
			if mode == "private_error" {
				code = "artifact_handler_failed"
			}
			if !bytes.Contains(response, []byte(code)) || bytes.Contains(response, []byte("secret-token")) || bytes.Contains(response, []byte("/private")) {
				t.Fatal("unsafe error response")
			}
		})
	}
}
func TestUnixServerRunDeadlineAndCloseCancelWithoutProviderClaims(t *testing.T) {
	for _, mode := range []string{"deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			canceled := make(chan struct{})
			s, path := unixTestStart(t, UnixServerConfig{RunTimeout: 50 * time.Millisecond}, unixTestHandler(func(ctx context.Context, q Request) ([]byte, error) {
				close(started)
				<-ctx.Done()
				close(canceled)
				return []byte("must not ACK"), nil
			}))
			c := unixTestDial(t, path)
			unixTestSend(t, c, unixTestRequest("run"))
			unixTestAwait(t, started)
			if mode == "close" {
				s.Close()
			}
			unixTestAwait(t, canceled)
			unixTestClosed(t, c)
		})
	}
}
func TestCallUnixContextCancellationClosesRunChannel(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	_, path := unixTestStart(t, UnixServerConfig{}, unixTestHandler(func(ctx context.Context, q Request) ([]byte, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := CallUnix(ctx, path, unixTestRequest("run")); done <- err }()
	unixTestAwait(t, started)
	cancel()
	unixTestAwait(t, canceled)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled call succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client cancellation blocked")
	}
}
func TestCallUnixRejectsOversizedResponseAndUnsafeSocket(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "socket")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	os.Chmod(path, 0600)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer c.Close()
		ReadRequest(c)
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], MaxFrameBytes+1)
		c.Write(header[:])
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := CallUnix(ctx, path, unixTestRequest("status")); err == nil || err.Error() != "artifact_response_oversized" {
		t.Fatal("oversized server frame not specifically rejected", err)
	}
	unixTestAwait(t, done)
	os.Chmod(path, 0666)
	if _, err := CallUnix(ctx, path, unixTestRequest("status")); err == nil {
		t.Fatal("unsafe socket mode accepted")
	}
}

type unixTestAcknowledger struct {
	handle      unixTestHandler
	acknowledge func(context.Context, Request, func() error) error
}

func (h unixTestAcknowledger) Handle(ctx context.Context, q Request) ([]byte, error) {
	return h.handle(ctx, q)
}
func (h unixTestAcknowledger) Acknowledge(ctx context.Context, q Request, write func() error) error {
	return h.acknowledge(ctx, q, write)
}

func TestUnixServerAcknowledgesActualFramedWrite(t *testing.T) {
	var calls atomic.Int32
	handler := unixTestAcknowledger{
		handle:      func(context.Context, Request) ([]byte, error) { return []byte(`{"status":"committed"}`), nil },
		acknowledge: func(ctx context.Context, q Request, write func() error) error { calls.Add(1); return write() },
	}
	_, path := unixTestStart(t, UnixServerConfig{}, handler)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := CallUnix(ctx, path, unixTestRequest("run"))
	if err != nil || string(response) != `{"status":"committed"}` || calls.Load() != 1 {
		t.Fatal("actual ACK not observed", err)
	}
}
func TestUnixServerAcknowledgerSeesActualWriteFailureAndCanceledChannel(t *testing.T) {
	for _, mode := range []string{"close_read", "close"} {
		t.Run(mode, func(t *testing.T) {
			ackEntered := make(chan struct{})
			release := make(chan struct{})
			ackError := make(chan error, 1)
			handler := unixTestAcknowledger{
				handle: func(context.Context, Request) ([]byte, error) { return []byte(`{"status":"committed"}`), nil },
				acknowledge: func(ctx context.Context, q Request, write func() error) error {
					close(ackEntered)
					<-release
					err := write()
					ackError <- err
					return err
				},
			}
			_, path := unixTestStart(t, UnixServerConfig{}, handler)
			c := unixTestDial(t, path)
			unixTestSend(t, c, unixTestRequest("run"))
			unixTestAwait(t, ackEntered)
			if mode == "close_read" {
				if c.CloseRead() != nil {
					t.Fatal("CloseRead failed")
				}
			} else {
				c.Close()
			}
			close(release)
			select {
			case err := <-ackError:
				if err == nil {
					t.Fatal("lost ACK hidden from keeper")
				}
				if mode == "close_read" && err.Error() != "artifact_frame_failed" {
					t.Fatal("expected actual framed write failure", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("keeper did not see ACK failure")
			}
		})
	}
}
func TestUnixServerNoAcknowledgeAfterHandlerFailureOrDisconnect(t *testing.T) {
	for _, mode := range []string{"handler_error", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			returned := make(chan struct{})
			var calls atomic.Int32
			handler := unixTestAcknowledger{
				handle: func(ctx context.Context, q Request) ([]byte, error) {
					close(started)
					if mode == "disconnect" {
						<-ctx.Done()
					}
					close(returned)
					if mode == "handler_error" {
						return nil, errors.New("private failure")
					}
					return []byte("unsafe ACK"), nil
				},
				acknowledge: func(context.Context, Request, func() error) error { calls.Add(1); return nil },
			}
			_, path := unixTestStart(t, UnixServerConfig{}, handler)
			c := unixTestDial(t, path)
			unixTestSend(t, c, unixTestRequest("run"))
			unixTestAwait(t, started)
			if mode == "disconnect" {
				c.Close()
				unixTestAwait(t, returned)
			} else {
				unixTestError(t, c, "artifact_handler_failed")
				unixTestClosed(t, c)
			}
			if calls.Load() != 0 {
				t.Fatal("ACK entered for failed/canceled handler")
			}
		})
	}
}

func TestUnixServerMonitorRemainsActiveInsideAcknowledger(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	done := make(chan struct{})
	handler := unixTestAcknowledger{
		handle: func(context.Context, Request) ([]byte, error) { return []byte("committed"), nil },
		acknowledge: func(ctx context.Context, q Request, write func() error) error {
			close(entered)
			<-ctx.Done()
			close(canceled)
			defer close(done)
			return write()
		},
	}
	_, path := unixTestStart(t, UnixServerConfig{}, handler)
	c := unixTestDial(t, path)
	unixTestSend(t, c, unixTestRequest("run"))
	unixTestAwait(t, entered)
	c.CloseWrite()
	unixTestAwait(t, canceled)
	unixTestAwait(t, done)
	unixTestClosed(t, c)
}
func TestUnixServerActualStoreACKFailureLatchesRetainedCommit(t *testing.T) {
	store, _, _ := openTest(t, 1)
	lease := prepareTest(t, store, 1)
	if err := store.RecordQuiescence(lease, proofFor(store, lease)); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(lease); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	handler := unixTestAcknowledger{
		handle: func(ctx context.Context, q Request) ([]byte, error) {
			if q.LeaseID != lease {
				return nil, errors.New("authority invalid")
			}
			return []byte(`{"status":"committed"}`), nil
		},
		acknowledge: func(ctx context.Context, q Request, write func() error) error {
			close(entered)
			<-release
			err := store.Acknowledge(q.LeaseID, write)
			done <- err
			return err
		},
	}
	_, path := unixTestStart(t, UnixServerConfig{}, handler)
	c := unixTestDial(t, path)
	q := unixTestRequest("run")
	q.LeaseID = lease
	unixTestSend(t, c, q)
	unixTestAwait(t, entered)
	if c.CloseRead() != nil {
		t.Fatal("CloseRead")
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Store accepted lost ACK")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missing Store ACK outcome")
	}
	after := store.Snapshot()
	if after.Healthy || after.ChargedBytes != before.ChargedBytes || after.RetainedOrReservedJobs != before.RetainedOrReservedJobs {
		t.Fatal("lost ACK did not preserve committed custody and latch")
	}
}

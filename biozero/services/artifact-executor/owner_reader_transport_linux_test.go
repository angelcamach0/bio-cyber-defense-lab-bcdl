//go:build linux

package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type ownerReadTransportHandler struct {
	handle  func(context.Context, OwnerReadRequest) (OwnerReadResponse, *os.File, error)
	deliver func(context.Context, OwnerReadRequest, OwnerReadResponse, *os.File, func() error) error
}

func (h ownerReadTransportHandler) HandleOwnerRead(ctx context.Context, q OwnerReadRequest) (OwnerReadResponse, *os.File, error) {
	if h.handle != nil {
		return h.handle(ctx, q)
	}
	r, err := NewOwnerReadSuccess(q, ownerReadTestBinding(q))
	return r, nil, err
}
func (h ownerReadTransportHandler) DeliverOwnerRead(ctx context.Context, q OwnerReadRequest, r OwnerReadResponse, f *os.File, write func() error) error {
	if h.deliver != nil {
		return h.deliver(ctx, q, r, f, write)
	}
	return write()
}

func ownerReadTransportStart(t *testing.T, h OwnerReadHandler) (*OwnerReadUnixServer, OwnerReadClientConfig) {
	t.Helper()
	uid := uint32(os.Geteuid())
	socket := filepath.Join(t.TempDir(), "private", "reader.sock")
	s, err := ListenOwnerReadUnix(UnixServerConfig{SocketPath: socket, AllowedUID: &uid}, h)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		s.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("reader did not drain")
		}
	})
	return s, OwnerReadClientConfig{SocketPath: socket, ExpectedBrokerUID: uid}
}

func ownerReadTransportPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var conns []*net.UnixConn
	for _, fd := range fds {
		f := os.NewFile(uintptr(fd), "owner-reader-test")
		c, e := net.FileConn(f)
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
		u := c.(*net.UnixConn)
		u.SetDeadline(time.Now().Add(2 * time.Second))
		conns = append(conns, u)
		t.Cleanup(func() { u.Close() })
	}
	return conns[0], conns[1]
}

func TestOwnerReadTransportGuardIsMandatoryAndOnce(t *testing.T) {
	var calls atomic.Int32
	callbacks := make(chan func() error, 1)
	h := ownerReadTransportHandler{deliver: func(_ context.Context, _ OwnerReadRequest, _ OwnerReadResponse, _ *os.File, write func() error) error {
		calls.Add(1)
		callbacks <- write
		if err := write(); err != nil {
			return err
		}
		if write() == nil {
			t.Error("delivery callback accepted twice")
		}
		return nil
	}}
	s, cfg := ownerReadTransportStart(t, h)
	q := ownerReadTestRequest("status")
	r, err := QueryOwnerStatus(context.Background(), cfg, q)
	if err != nil || r.Binding.Execution.State != "executing" || calls.Load() != 1 {
		t.Fatal("status/guard", err)
	}
	// EOF establishes that Deliver returned and the callback was disabled.
	late := <-callbacks
	if late == nil || late() == nil {
		t.Fatal("callback remained usable after delivery")
	}
	if _, err = ReadOwnerReceiptWrongOperation(cfg, q); err == nil {
		t.Fatal("operation mismatch accepted")
	}
	if cap(s.base.slots) != 4 || cap(s.active) != 2 || s.base.config.RunTimeout != 30*time.Second {
		t.Fatal("reader bounds changed")
	}
}

func ReadOwnerReceiptWrongOperation(cfg OwnerReadClientConfig, q OwnerReadRequest) (OwnerReadResponse, error) {
	r, f, e := ReadOwnerReceipt(context.Background(), cfg, q)
	if f != nil {
		f.Close()
	}
	return r, e
}

func TestOwnerReadTransportRejectsRequestRightsAndLateBytes(t *testing.T) {
	var handles atomic.Int32
	_, cfg := ownerReadTransportStart(t, ownerReadTransportHandler{handle: func(ctx context.Context, q OwnerReadRequest) (OwnerReadResponse, *os.File, error) {
		handles.Add(1)
		r, e := NewOwnerReadSuccess(q, ownerReadTestBinding(q))
		return r, nil, e
	}})
	q := ownerReadTestRequest("status")
	raw, _ := json.Marshal(q)
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, late := range []bool{false, true} {
		c := unixTestDial(t, cfg.SocketPath)
		if !late {
			if err := writeOwnerFrame(c, raw, []*os.File{f}); err != nil {
				t.Fatal(err)
			}
		} else {
			frame := make([]byte, 4+len(raw))
			binary.BigEndian.PutUint32(frame[:4], uint32(len(raw)))
			copy(frame[4:], raw)
			if _, err := c.Write(frame[:1]); err != nil {
				t.Fatal(err)
			}
			if _, _, err := c.WriteMsgUnix(frame[1:], syscall.UnixRights(int(f.Fd())), nil); err != nil {
				t.Fatal(err)
			}
		}
		data, files, err := readOwnerFrame(c, 0)
		closeOwnerFiles(files)
		c.Close()
		var r OwnerReadResponse
		if err != nil || strictJSON(data, &r) != nil || r.ErrorCode == "" {
			t.Fatal("request FD accepted", err)
		}
	}
	if handles.Load() != 0 {
		t.Fatal("request rights reached handler")
	}
	// Payload bytes following a valid frame never reach the handler when already queued.
	c := unixTestDial(t, cfg.SocketPath)
	var frame bytes.Buffer
	WriteFrame(&frame, raw)
	frame.WriteByte('x')
	c.Write(frame.Bytes())
	c.CloseWrite()
	var one [1]byte
	c.Read(one[:])
	c.Close()
	if handles.Load() != 0 {
		t.Fatal("queued trailing input reached handler")
	}
}

func TestOwnerReadFrameStrictAncillaryAndEOF(t *testing.T) {
	for _, name := range []string{"late_rights", "extra_rights", "invalid_utf8", "oversize", "trailing_rights"} {
		t.Run(name, func(t *testing.T) {
			a, b := ownerReadTransportPair(t)
			f, err := os.Open("/dev/null")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var frame bytes.Buffer
			if name == "invalid_utf8" {
				WriteFrame(&frame, []byte{0xff})
			} else {
				WriteFrame(&frame, []byte(`{}`))
			}
			data := frame.Bytes()
			done := make(chan struct{})
			go func() {
				defer close(done)
				switch name {
				case "late_rights":
					a.Write(data[:1])
					a.WriteMsgUnix(data[1:], syscall.UnixRights(int(f.Fd())), nil)
				case "extra_rights":
					a.WriteMsgUnix(data[:1], syscall.UnixRights(int(f.Fd()), int(f.Fd())), nil)
					a.Write(data[1:])
				case "oversize":
					var h [4]byte
					binary.BigEndian.PutUint32(h[:], MaxFrameBytes+1)
					a.Write(h[:])
				case "trailing_rights":
					a.Write(data)
					a.WriteMsgUnix([]byte{'x'}, syscall.UnixRights(int(f.Fd())), nil)
				default:
					a.Write(data)
				}
				a.CloseWrite()
			}()
			_, files, err := readOwnerFrame(b, 1)
			closeOwnerFiles(files)
			if name == "trailing_rights" {
				if err != nil {
					t.Fatal(err)
				}
				err = ownerReadEnd(b)
			}
			if err == nil {
				t.Fatal("malformed frame accepted")
			}
			b.Close()
			<-done
		})
	}
	a, b := ownerReadTransportPair(t)
	a.CloseWrite()
	if ownerReadEnd(b) != nil {
		t.Fatal("clean EOF rejected")
	}
}

func TestOwnerReadReceiptDescriptorChecks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "receipt")
	body := []byte("private synthetic test receipt")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := BridgeResponse{ReceiptBytes: int64(len(body)), ReceiptSHA256: digest(body)}
	uid := uint32(os.Geteuid())
	if checkOwnerReceipt(context.Background(), f, uid, r) != nil {
		t.Fatal("valid receipt FD rejected")
	}
	if checkOwnerReceipt(context.Background(), f, uid+1, r) == nil {
		t.Fatal("wrong broker UID accepted")
	}
	bad := r
	bad.ReceiptBytes++
	if checkOwnerReceipt(context.Background(), f, uid, bad) == nil {
		t.Fatal("wrong size accepted")
	}
	bad = r
	bad.ReceiptSHA256 = digest([]byte("other"))
	if checkOwnerReceipt(context.Background(), f, uid, bad) == nil {
		t.Fatal("wrong hash accepted")
	}
	writable, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if checkOwnerReceipt(context.Background(), writable, uid, r) == nil {
		t.Fatal("writable FD accepted")
	}
	writable.Close()
	if err := os.Link(path, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if checkOwnerReceipt(context.Background(), f, uid, r) == nil {
		t.Fatal("multiply linked FD accepted")
	}
	os.Remove(filepath.Join(root, "alias"))
	os.Chmod(path, 0640)
	if checkOwnerReceipt(context.Background(), f, uid, r) == nil {
		t.Fatal("unsafe mode accepted")
	}
}

func TestOwnerReadReceiptRoundTripAndOwnedDescriptorClose(t *testing.T) {
	// Transport-only bytes: this fixture makes no scientific projection claim.
	body := []byte("synthetic transport receipt")
	path := filepath.Join(t.TempDir(), "receipt")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	owned := make(chan *os.File, 1)
	_, cfg := ownerReadTransportStart(t, ownerReadTransportHandler{handle: func(_ context.Context, q OwnerReadRequest) (OwnerReadResponse, *os.File, error) {
		b := ownerReadTestBinding(q)
		b.Execution.State = "committed"
		b.Execution.HasManifest = true
		b.Execution.ReceiptSHA256 = digest(body)
		b.Execution.ReceiptBytes = int64(len(body))
		b.Execution.Manifest = Manifest{SchemaVersion: 1, JobID: q.JobID, InputSHA256: q.UploadSHA256, StoreID: b.Execution.StoreID, LeaseID: b.Execution.LeaseID, PolicySHA256: q.AuthorityScope.PolicySHA256, ExecutionStatus: "failed", ReleaseStatus: "withheld", ErrorCode: "artifact_cancelled", Files: map[string]FileRecord{"execution_receipt": {State: "verified", SHA256: digest(body), Bytes: int64(len(body))}}}
		raw, _ := jsonBytes(b.Execution.Manifest)
		b.Execution.ManifestSHA256 = digest(raw)
		r, err := NewOwnerReadSuccess(q, b)
		if err != nil {
			return r, nil, err
		}
		f, err := os.Open(path)
		if err == nil {
			owned <- f
		}
		return r, f, err
	}})
	r, f, err := ReadOwnerReceipt(context.Background(), cfg, ownerReadTestRequest("receipt"))
	if err != nil || !r.HasReceipt || f == nil {
		t.Fatal("receipt transfer", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(raw, body) {
		t.Fatal("receipt bytes", err)
	}
	serverFD := <-owned
	if _, err := serverFD.Stat(); err == nil {
		t.Fatal("server retained owned descriptor after EOF")
	}
}

func TestOwnerReadCancellationAndFailedDeliveryRemainLocal(t *testing.T) {
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	var deliveries atomic.Int32
	_, cfg := ownerReadTransportStart(t, ownerReadTransportHandler{handle: func(ctx context.Context, q OwnerReadRequest) (OwnerReadResponse, *os.File, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return NewOwnerReadError("artifact_owner_read_cancelled"), nil, ctx.Err()
	}, deliver: func(context.Context, OwnerReadRequest, OwnerReadResponse, *os.File, func() error) error {
		deliveries.Add(1)
		return nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := QueryOwnerStatus(ctx, cfg, ownerReadTestRequest("status")); done <- err }()
	<-entered
	cancel()
	if <-done == nil {
		t.Fatal("cancelled query succeeded")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("peer cancellation not observed")
	}
	if deliveries.Load() != 0 {
		t.Fatal("cancelled read delivered")
	}
	// A reset is induced while the delivery guard holds the callback. Only this
	// owned connection closes; the next explicit query still reaches the guard.
	guard := make(chan struct{})
	release := make(chan struct{})
	writeErr := make(chan error, 1)
	var count atomic.Int32
	_, cfg2 := ownerReadTransportStart(t, ownerReadTransportHandler{deliver: func(_ context.Context, _ OwnerReadRequest, _ OwnerReadResponse, _ *os.File, write func() error) error {
		if count.Add(1) == 1 {
			close(guard)
			<-release
			err := write()
			writeErr <- err
			return err
		}
		return write()
	}})
	c := unixTestDial(t, cfg2.SocketPath)
	raw, _ := json.Marshal(ownerReadTestRequest("status"))
	writeOwnerFrame(c, raw, nil)
	<-guard
	rawConn, _ := c.SyscallConn()
	rawConn.Control(func(fd uintptr) {
		syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1, Linger: 0})
	})
	c.Close()
	close(release)
	if <-writeErr == nil {
		t.Fatal("closed channel write succeeded")
	}
	if _, err := QueryOwnerStatus(context.Background(), cfg2, ownerReadTestRequest("status")); err != nil {
		t.Fatal("transport write failure stopped listener", err)
	}
}

func TestOwnerReadCleanupErrorRetained(t *testing.T) {
	uid := uint32(os.Geteuid())
	root := t.TempDir()
	os.Chmod(root, 0700)
	path := filepath.Join(root, "reader.sock")
	s, err := ListenOwnerReadUnix(UnixServerConfig{SocketPath: path, AllowedUID: &uid}, ownerReadTransportHandler{})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("replacement evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	a, b := s.Close(), s.Close()
	if a == nil || b == nil || a.Error() != b.Error() {
		t.Fatal("first close error lost")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "replacement evidence" {
		t.Fatal("replacement deleted")
	}
	otherUID := uid + 1
	if bad, err := ListenOwnerReadUnix(UnixServerConfig{SocketPath: filepath.Join(root, "other.sock"), AllowedUID: &otherUID}, ownerReadTransportHandler{}); err == nil {
		bad.Close()
		t.Fatal("inaccessible different UID allowed")
	}
}

func TestOwnerReadActualPartialWriteDeadline(t *testing.T) {
	a, b := ownerReadTransportPair(t)
	raw, err := a.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) { setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1024) }); err != nil || setErr != nil {
		t.Fatal("send buffer", err, setErr)
	}
	if err := a.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// The receiver deliberately consumes no bytes until the real write deadline.
	if err := writeOwnerFrame(a, bytes.Repeat([]byte{'x'}, MaxFrameBytes), nil); err == nil {
		t.Fatal("unread full frame did not hit deadline")
	}
	a.CloseWrite()
	partial, err := io.ReadAll(b)
	if err != nil || len(partial) < 1 || len(partial) >= MaxFrameBytes+4 {
		t.Fatal("no causal partial frame", len(partial), err)
	}
}

func TestOwnerReadBoundsActiveHandlersAndDrains(t *testing.T) {
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	s, cfg := ownerReadTransportStart(t, ownerReadTransportHandler{handle: func(ctx context.Context, q OwnerReadRequest) (OwnerReadResponse, *os.File, error) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return OwnerReadResponse{}, nil, ctx.Err()
		}
		r, err := NewOwnerReadSuccess(q, ownerReadTestBinding(q))
		return r, nil, err
	}})
	raw, _ := json.Marshal(ownerReadTestRequest("status"))
	var clients []*net.UnixConn
	for i := 0; i < 4; i++ {
		c := unixTestDial(t, cfg.SocketPath)
		clients = append(clients, c)
		if err := writeOwnerFrame(c, raw, nil); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("handler not entered")
		}
	}
	select {
	case <-entered:
		t.Fatal("more than two active handlers")
	case <-time.After(30 * time.Millisecond):
	}
	// Close cancels active and queued channels, then Wait drains both classes.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { s.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handlers did not drain")
	}
	for _, c := range clients {
		c.Close()
	}
}

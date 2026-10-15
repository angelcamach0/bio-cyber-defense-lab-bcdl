//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type bridgeTestHandler func(context.Context, BridgeRequest, *os.File) (BridgeResponse, *os.File, error)

func (h bridgeTestHandler) HandleBridge(ctx context.Context, q BridgeRequest, f *os.File) (BridgeResponse, *os.File, error) {
	return h(ctx, q, f)
}

type bridgeTestAcknowledger struct {
	handler bridgeTestHandler
	ack     func(context.Context, BridgeRequest, func() error) error
}

func (h *bridgeTestAcknowledger) HandleBridge(ctx context.Context, q BridgeRequest, f *os.File) (BridgeResponse, *os.File, error) {
	return h.handler(ctx, q, f)
}
func (h *bridgeTestAcknowledger) AcknowledgeBridge(ctx context.Context, q BridgeRequest, w func() error) error {
	return h.ack(ctx, q, w)
}
func bridgeTestRequest(op string) BridgeRequest {
	q := BridgeRequest{SchemaVersion: 1, Operation: op, JobID: strings.Repeat("a", 16), UploadSHA256: strings.Repeat("b", 64), ExpectedProfileSHA256: strings.Repeat("c", 64)}
	if op == "submit" {
		q.ProcessedSHA256 = digest([]byte("synthetic bridge input"))
		q.ProcessedBytes = int64(len("synthetic bridge input"))
		q.OriginalName = "synthetic.fastq"
	}
	return q
}
func bridgeTestResponse(q BridgeRequest) BridgeResponse {
	return BridgeResponse{SchemaVersion: 1, JobID: q.JobID, UploadSHA256: q.UploadSHA256, ProfileSHA256: q.ExpectedProfileSHA256, StoreID: strings.Repeat("d", 32), LeaseID: strings.Repeat("e", 32), State: "executing", Manifest: emptyBridgeManifest()}
}
func bridgeTestReceipt(q BridgeRequest, data []byte) BridgeResponse {
	r := bridgeTestResponse(q)
	r.State = "committed"
	r.HasManifest = true
	r.ReceiptBytes = int64(len(data))
	r.ReceiptSHA256 = digest(data)
	r.Manifest = Manifest{SchemaVersion: 1, JobID: q.JobID, InputSHA256: q.UploadSHA256, StoreID: r.StoreID, LeaseID: r.LeaseID, PolicySHA256: strings.Repeat("f", 64), Files: map[string]FileRecord{"execution_receipt": {State: "verified", SHA256: r.ReceiptSHA256, Bytes: r.ReceiptBytes}}, ExecutionStatus: "failed", ReleaseStatus: "withheld", ErrorCode: "fixture_failed"}
	raw, _ := jsonBytes(r.Manifest)
	r.ManifestSHA256 = digest(raw)
	return r
}
func bridgeTestFile(t *testing.T, data []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private.bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
func bridgeTestStart(t *testing.T, cfg UnixServerConfig, h BridgeHandler) (*BridgeUnixServer, string) {
	t.Helper()
	if cfg.SocketPath == "" {
		cfg.SocketPath = filepath.Join(t.TempDir(), "private", "bridge.sock")
	}
	if cfg.AllowedUID == nil {
		uid := uint32(os.Geteuid())
		cfg.AllowedUID = &uid
	}
	s, err := ListenBridgeUnix(cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan error, 1)
	go func() { ended <- s.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.base.mu.Lock()
		started := s.base.started
		s.base.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bridge Serve startup timeout")
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
			t.Error("bridge Serve did not finish")
		}
	})
	return s, cfg.SocketPath
}
func bridgeTestEncoded(q BridgeRequest) []byte {
	raw, _ := json.Marshal(q)
	frame := make([]byte, len(raw)+4)
	binary.BigEndian.PutUint32(frame, uint32(len(raw)))
	copy(frame[4:], raw)
	return frame
}
func bridgeTestWireError(t *testing.T, c *net.UnixConn) {
	t.Helper()
	raw, f, err := bridgeReadFrame(c)
	if f != nil {
		f.Close()
		t.Fatal("error transferred FD")
	}
	if err != nil {
		return
	} // Closed channels are valid rejection too.
	var response BridgeResponse
	if strictJSON(raw, &response) != nil || response.ErrorCode == "" {
		t.Fatal("invalid input obtained non-error response")
	}
}

func TestBridgeRealSubmitStatusReceiptAndPrivateDescriptors(t *testing.T) {
	data := []byte("synthetic bridge input")
	receipt := []byte(`{"synthetic":true}`)
	var calls atomic.Int32
	_, socket := bridgeTestStart(t, UnixServerConfig{}, bridgeTestHandler(func(ctx context.Context, q BridgeRequest, f *os.File) (BridgeResponse, *os.File, error) {
		calls.Add(1)
		if q.Operation == "submit" {
			if bridgeCheckFile(f, MaxInputBytes, int64(len(data))) != nil {
				t.Error("submitted descriptor metadata invalid")
			}
			b := make([]byte, len(data))
			_, err := f.ReadAt(b, 0)
			if err != nil || digest(b) != q.ProcessedSHA256 {
				t.Error("input did not match separately supplied digest")
			}
		} else if f != nil {
			t.Error("non-submit handler got descriptor")
		}
		if q.Operation == "receipt" {
			return bridgeTestReceipt(q, receipt), bridgeTestFile(t, receipt), nil
		}
		return bridgeTestResponse(q), nil, nil
	}))
	input := bridgeTestFile(t, data)
	for _, op := range []string{"submit", "status", "cancel", "receipt"} {
		var f *os.File
		if op == "submit" {
			f = input
		}
		response, out, err := CallBridgeUnix(context.Background(), socket, bridgeTestRequest(op), f)
		if err != nil || response.ErrorCode != "" {
			t.Fatal(op, "roundtrip failed", err)
		}
		if op == "receipt" {
			if out == nil {
				t.Fatal("receipt descriptor missing")
			}
			b, err := io.ReadAll(out)
			out.Close()
			if err != nil || string(b) != string(receipt) {
				t.Fatal("receipt data mismatch")
			}
		} else if out != nil {
			out.Close()
			t.Fatal("unexpected returned descriptor")
		}
	}
	if calls.Load() != 4 {
		t.Fatal("unexpected dispatch count")
	}
	if _, err := input.Stat(); err != nil {
		t.Fatal("transport closed borrowed client descriptor")
	}
}

func TestBridgeRejectsUnsafeMissingExtraAndLateRightsBeforeDispatch(t *testing.T) {
	cases := []string{"missing", "extra", "late", "writable", "mode", "hardlink", "fifo", "wrong_size", "forbidden_status_fd", "truncated_control"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			_, socket := bridgeTestStart(t, UnixServerConfig{}, bridgeTestHandler(func(context.Context, BridgeRequest, *os.File) (BridgeResponse, *os.File, error) {
				calls.Add(1)
				return BridgeResponse{}, nil, nil
			}))
			q := bridgeTestRequest("submit")
			f := bridgeTestFile(t, []byte("synthetic bridge input"))
			switch name {
			case "writable":
				w, err := os.OpenFile(f.Name(), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer w.Close()
				f = w
			case "mode":
				if err := os.Chmod(f.Name(), 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.Name(), filepath.Join(filepath.Dir(f.Name()), "alias")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				path := filepath.Join(t.TempDir(), "pipe")
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
				fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				f = os.NewFile(uintptr(fd), "fifo")
				defer f.Close()
			case "wrong_size":
				q.ProcessedBytes++
			case "forbidden_status_fd":
				q = bridgeTestRequest("status")
			}
			c := unixTestDial(t, socket)
			frame := bridgeTestEncoded(q)
			control := syscall.UnixRights(int(f.Fd()))
			switch name {
			case "missing":
				c.Write(frame)
			case "late":
				c.Write(frame[:4])
				c.WriteMsgUnix(frame[4:], control, nil)
			case "extra":
				c.WriteMsgUnix(frame, syscall.UnixRights(int(f.Fd()), int(f.Fd())), nil)
			case "truncated_control":
				fds := make([]int, 20)
				for i := range fds {
					fds[i] = int(f.Fd())
				}
				c.WriteMsgUnix(frame, syscall.UnixRights(fds...), nil)
			default:
				c.WriteMsgUnix(frame, control, nil)
			}
			bridgeTestWireError(t, c)
			if calls.Load() != 0 {
				t.Fatal("invalid FD reached handler")
			}
		})
	}
}

func TestBridgeFragmentedFirstRightsAndStrictJSONTimeout(t *testing.T) {
	var calls atomic.Int32
	_, socket := bridgeTestStart(t, UnixServerConfig{RequestTimeout: 50 * time.Millisecond}, bridgeTestHandler(func(_ context.Context, q BridgeRequest, _ *os.File) (BridgeResponse, *os.File, error) {
		calls.Add(1)
		return bridgeTestResponse(q), nil, nil
	}))
	q := bridgeTestRequest("submit")
	f := bridgeTestFile(t, []byte("synthetic bridge input"))
	frame := bridgeTestEncoded(q)
	c := unixTestDial(t, socket)
	if _, _, err := c.WriteMsgUnix(frame[:1], syscall.UnixRights(int(f.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(frame[1:]); err != nil {
		t.Fatal(err)
	}
	raw, out, err := bridgeReadFrame(c)
	if out != nil {
		out.Close()
	}
	if err != nil {
		t.Fatal("fragmented frame rejected", err)
	}
	var r BridgeResponse
	if strictJSON(raw, &r) != nil || validateBridgeResponse(q, r) != nil {
		t.Fatal("fragmented response invalid")
	}
	c.Close()
	bad := []string{`{"schema_version":1}`, strings.Replace(string(frame[4:]), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1), strings.Replace(string(frame[4:]), `"operation"`, `"Operation"`, 1), string(frame[4:]) + `{}`}
	for _, body := range bad {
		conn := unixTestDial(t, socket)
		b := []byte(body)
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(len(b)))
		conn.WriteMsgUnix(append(header, b...), syscall.UnixRights(int(f.Fd())), nil)
		bridgeTestWireError(t, conn)
		conn.Close()
	}
	conn := unixTestDial(t, socket)
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, MaxFrameBytes+1)
	conn.Write(header)
	bridgeTestWireError(t, conn)
	conn.Close()
	slow := unixTestDial(t, socket)
	slow.Write([]byte{0})
	bridgeTestWireError(t, slow)
	slow.Close()
	r, out, err = CallBridgeUnix(context.Background(), socket, bridgeTestRequest("status"), nil)
	if out != nil {
		out.Close()
	}
	if err != nil || r.ErrorCode != "" {
		t.Fatal("valid request after rejection failed", err)
	}
	if calls.Load() != 2 {
		t.Fatal("bad JSON/timeout reached handler")
	}
}

func TestBridgePostDispatchBytesRightsHalfCloseAndDisconnectCancel(t *testing.T) {
	for _, fault := range []string{"bytes", "rights", "half_close", "disconnect"} {
		t.Run(fault, func(t *testing.T) {
			entered, stopped := make(chan struct{}), make(chan struct{})
			var ack atomic.Int32
			h := &bridgeTestAcknowledger{handler: func(ctx context.Context, q BridgeRequest, _ *os.File) (BridgeResponse, *os.File, error) {
				close(entered)
				<-ctx.Done()
				close(stopped)
				return bridgeTestResponse(q), nil, nil
			}, ack: func(context.Context, BridgeRequest, func() error) error { ack.Add(1); return nil }}
			_, socket := bridgeTestStart(t, UnixServerConfig{}, h)
			c := unixTestDial(t, socket)
			raw, _ := json.Marshal(bridgeTestRequest("status"))
			if err := bridgeWriteFrame(c, raw, nil); err != nil {
				t.Fatal(err)
			}
			unixTestAwait(t, entered)
			switch fault {
			case "bytes":
				c.Write([]byte{'x'})
			case "rights":
				f := bridgeTestFile(t, []byte("late"))
				c.WriteMsgUnix([]byte{'x'}, syscall.UnixRights(int(f.Fd())), nil)
			case "half_close":
				c.CloseWrite()
			case "disconnect":
				c.Close()
			}
			unixTestAwait(t, stopped)
			if ack.Load() != 0 {
				t.Fatal("late/canceled request acknowledged")
			}
		})
	}
}

func TestBridgeRealACKOnceFailureAndActiveMonitor(t *testing.T) {
	t.Run("one_actual_frame", func(t *testing.T) {
		second := make(chan error, 1)
		h := &bridgeTestAcknowledger{handler: func(_ context.Context, q BridgeRequest, _ *os.File) (BridgeResponse, *os.File, error) {
			return bridgeTestResponse(q), nil, nil
		}, ack: func(_ context.Context, _ BridgeRequest, write func() error) error {
			first := write()
			second <- write()
			return first
		}}
		_, socket := bridgeTestStart(t, UnixServerConfig{}, h)
		r, f, err := CallBridgeUnix(context.Background(), socket, bridgeTestRequest("status"), nil)
		if f != nil {
			f.Close()
		}
		if err != nil || r.ErrorCode != "" {
			t.Fatal(err)
		}
		if err := <-second; err == nil {
			t.Fatal("second ACK callback wrote again")
		}
	})
	t.Run("close_inside_ack", func(t *testing.T) {
		entered, observed := make(chan struct{}), make(chan error, 1)
		h := &bridgeTestAcknowledger{handler: func(_ context.Context, q BridgeRequest, _ *os.File) (BridgeResponse, *os.File, error) {
			return bridgeTestResponse(q), nil, nil
		}, ack: func(ctx context.Context, _ BridgeRequest, write func() error) error {
			close(entered)
			<-ctx.Done()
			err := write()
			observed <- err
			return err
		}}
		_, socket := bridgeTestStart(t, UnixServerConfig{}, h)
		c := unixTestDial(t, socket)
		raw, _ := json.Marshal(bridgeTestRequest("status"))
		bridgeWriteFrame(c, raw, nil)
		unixTestAwait(t, entered)
		c.Close()
		select {
		case err := <-observed:
			if err == nil {
				t.Fatal("closed peer accepted ACK")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("monitor stopped before ACK")
		}
	})
	t.Run("late_callback_rejected", func(t *testing.T) {
		late := make(chan func() error, 1)
		h := &bridgeTestAcknowledger{handler: func(_ context.Context, q BridgeRequest, _ *os.File) (BridgeResponse, *os.File, error) {
			return bridgeTestResponse(q), nil, nil
		}, ack: func(_ context.Context, _ BridgeRequest, write func() error) error { late <- write; return nil }}
		_, socket := bridgeTestStart(t, UnixServerConfig{}, h)
		_, f, err := CallBridgeUnix(context.Background(), socket, bridgeTestRequest("status"), nil)
		if f != nil {
			f.Close()
		}
		if err == nil {
			t.Fatal("missing callback fabricated frame")
		}
		if err := (<-late)(); err == nil {
			t.Fatal("callback escaped acknowledged lifetime")
		}
	})
}

func TestBridgeReceiptDigestAndUnexpectedOutputsFailClosed(t *testing.T) {
	for _, kind := range []string{"digest", "missing", "wrong_size", "unexpected_status", "handler_error", "response_cap"} {
		t.Run(kind, func(t *testing.T) {
			data := []byte("private synthetic receipt")
			op := "receipt"
			if kind == "unexpected_status" || kind == "handler_error" || kind == "response_cap" {
				op = "status"
			}
			_, socket := bridgeTestStart(t, UnixServerConfig{}, bridgeTestHandler(func(_ context.Context, q BridgeRequest, _ *os.File) (BridgeResponse, *os.File, error) {
				r := bridgeTestReceipt(q, data)
				var f *os.File
				if kind != "missing" {
					f = bridgeTestFile(t, data)
				}
				switch kind {
				case "digest":
					r.ReceiptSHA256 = digest([]byte("different"))
					x := r.Manifest.Files["execution_receipt"]
					x.SHA256 = r.ReceiptSHA256
					r.Manifest.Files["execution_receipt"] = x
					raw, _ := jsonBytes(r.Manifest)
					r.ManifestSHA256 = digest(raw)
				case "wrong_size":
					f = bridgeTestFile(t, append(data, 'x'))
				case "handler_error":
					return r, f, fail("private_secret_should_not_escape")
				case "response_cap":
					r = bridgeTestResponse(q)
					r.JobID = strings.Repeat("x", MaxFrameBytes+1)
				}
				return r, f, nil
			}))
			response, f, err := CallBridgeUnix(context.Background(), socket, bridgeTestRequest(op), nil)
			if f != nil {
				f.Close()
				t.Fatal("invalid output descriptor returned")
			}
			if err == nil && response.ErrorCode == "" {
				t.Fatal("invalid output accepted")
			}
			if strings.Contains(response.ErrorCode, "private_secret") {
				t.Fatal("handler details leaked")
			}
		})
	}
}

func TestBridgePeerDeadlineCancellationAndScopedConcurrency(t *testing.T) {
	t.Run("wrong_peer", func(t *testing.T) {
		uid := uint32(os.Geteuid() + 1)
		var calls atomic.Int32
		_, socket := bridgeTestStart(t, UnixServerConfig{AllowedUID: &uid}, bridgeTestHandler(func(context.Context, BridgeRequest, *os.File) (BridgeResponse, *os.File, error) {
			calls.Add(1)
			return BridgeResponse{}, nil, nil
		}))
		r, f, err := CallBridgeUnix(context.Background(), socket, bridgeTestRequest("status"), nil)
		if f != nil {
			f.Close()
		}
		if err == nil && r.ErrorCode == "" || calls.Load() != 0 {
			t.Fatal("wrong peer dispatched")
		}
	})
	t.Run("deadline", func(t *testing.T) {
		stopped := make(chan struct{})
		_, socket := bridgeTestStart(t, UnixServerConfig{RunTimeout: 40 * time.Millisecond}, bridgeTestHandler(func(ctx context.Context, q BridgeRequest, _ *os.File) (BridgeResponse, *os.File, error) {
			<-ctx.Done()
			close(stopped)
			return bridgeTestResponse(q), nil, nil
		}))
		_, f, err := CallBridgeUnix(context.Background(), socket, bridgeTestRequest("status"), nil)
		if f != nil {
			f.Close()
		}
		if err == nil {
			t.Fatal("run deadline returned success")
		}
		unixTestAwait(t, stopped)
	})
	t.Run("scoped", func(t *testing.T) {
		entered := make(chan string, 2)
		stopped := make(chan string, 2)
		s, socket := bridgeTestStart(t, UnixServerConfig{MaxConnections: 2}, bridgeTestHandler(func(ctx context.Context, q BridgeRequest, _ *os.File) (BridgeResponse, *os.File, error) {
			entered <- q.JobID
			<-ctx.Done()
			stopped <- q.JobID
			return bridgeTestResponse(q), nil, nil
		}))
		a, b := unixTestDial(t, socket), unixTestDial(t, socket)
		qa, qb := bridgeTestRequest("status"), bridgeTestRequest("status")
		qb.JobID = strings.Repeat("f", 16)
		ra, _ := json.Marshal(qa)
		rb, _ := json.Marshal(qb)
		bridgeWriteFrame(a, ra, nil)
		bridgeWriteFrame(b, rb, nil)
		<-entered
		<-entered
		a.Close()
		select {
		case id := <-stopped:
			if id != qa.JobID {
				t.Fatal("cancellation crossed connection")
			}
		case <-time.After(time.Second):
			t.Fatal("A not canceled")
		}
		select {
		case <-stopped:
			t.Fatal("B canceled by A")
		case <-time.After(20 * time.Millisecond):
		}
		s.Close()
		select {
		case id := <-stopped:
			if id != qb.JobID {
				t.Fatal("wrong remaining connection")
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not cancel B")
		}
	})
}

func TestBridgeRejectedRightsDoNotLeakInstalledDescriptors(t *testing.T) {
	_, socket := bridgeTestStart(t, UnixServerConfig{}, bridgeTestHandler(func(context.Context, BridgeRequest, *os.File) (BridgeResponse, *os.File, error) {
		t.Error("extra rights reached handler")
		return BridgeResponse{}, nil, nil
	}))
	f := bridgeTestFile(t, []byte("synthetic bridge input"))
	initial, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	frame := bridgeTestEncoded(bridgeTestRequest("submit"))
	for i := 0; i < 20; i++ {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Net: "unix", Name: socket})
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		c.WriteMsgUnix(frame, syscall.UnixRights(int(f.Fd()), int(f.Fd())), nil)
		bridgeTestWireError(t, c)
		c.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		now, err := os.ReadDir("/proc/self/fd")
		if err == nil && len(now) == len(initial) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("rejected SCM_RIGHTS descriptors remain installed")
}

//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// OwnerReadHandler must guard the actual synchronous delivery. This is a read
// guard, never the worker ACK interface or a Store acknowledgement.
type OwnerReadHandler interface {
	HandleOwnerRead(context.Context, OwnerReadRequest) (OwnerReadResponse, *os.File, error)
	DeliverOwnerRead(context.Context, OwnerReadRequest, OwnerReadResponse, *os.File, func() error) error
}

type OwnerReadClientConfig struct {
	SocketPath        string
	ExpectedBrokerUID uint32
}

type OwnerReadUnixServer struct {
	base      *UnixServer
	handler   OwnerReadHandler
	active    chan struct{}
	mu        sync.Mutex
	started   bool
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
}

func ListenOwnerReadUnix(cfg UnixServerConfig, handler OwnerReadHandler) (*OwnerReadUnixServer, error) {
	// The initial deployment is private and same UID. Cross-UID traversal and
	// socket ACLs need a separately implemented deployment policy.
	if handler == nil || cfg.AllowedUID == nil || *cfg.AllowedUID != uint32(os.Geteuid()) {
		return nil, fail("artifact_owner_read_config_invalid")
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 4
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 5 * time.Second
	}
	if cfg.RunTimeout == 0 {
		cfg.RunTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 5 * time.Second
	}
	if cfg.MaxConnections > 4 || cfg.RequestTimeout > 5*time.Second || cfg.RunTimeout > 30*time.Second || cfg.WriteTimeout > 5*time.Second {
		return nil, fail("artifact_owner_read_config_invalid")
	}
	base, err := ListenUnixServer(cfg, bridgeUnusedV1{})
	if err != nil {
		return nil, err
	}
	return &OwnerReadUnixServer{base: base, handler: handler, active: make(chan struct{}, 2)}, nil
}

// Close retains the first cleanup error across all callers and cancels only
// this listener's channels. Wait joins its handlers before broker teardown.
func (s *OwnerReadUnixServer) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.base.Close() })
	return s.closeErr
}

func (s *OwnerReadUnixServer) Wait() { s.wg.Wait() }

func (s *OwnerReadUnixServer) Serve(ctx context.Context) (result error) {
	if ctx == nil {
		return fail("artifact_server_context_invalid")
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fail("artifact_server_unavailable")
	}
	s.started = true
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	defer func() {
		if err := s.Close(); err != nil {
			result = err
		}
		s.Wait()
	}()
	b := s.base
	for {
		conn, err := b.listener.AcceptUnix()
		if err != nil {
			b.mu.Lock()
			closed := b.closed
			b.mu.Unlock()
			if closed || ctx.Err() != nil {
				return nil
			}
			return fail("artifact_socket_accept_failed")
		}
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			conn.Close()
			continue
		}
		select {
		case b.slots <- struct{}{}:
			connectionCtx, cancel := context.WithCancel(ctx)
			b.connections[conn] = cancel
			s.wg.Add(1)
			b.mu.Unlock()
			go s.serveConnection(connectionCtx, conn, cancel)
		default:
			b.mu.Unlock()
			conn.Close()
		}
	}
}

func (s *OwnerReadUnixServer) writeError(conn *net.UnixConn, code string) {
	if conn.SetWriteDeadline(time.Now().Add(s.base.config.WriteTimeout)) != nil {
		return
	}
	raw, err := json.Marshal(NewOwnerReadError(code))
	if err == nil {
		writeOwnerFrame(conn, raw, nil)
	}
}

func closeOwnerFiles(files []*os.File) {
	for _, f := range files {
		f.Close()
	}
}

// All frame bytes, including trailing bytes, are read with recvmsg. Rights may
// occur only with the first byte, never a later header or payload byte.
func readOwnerFrame(conn *net.UnixConn, maxFD int) (raw []byte, files []*os.File, result error) {
	keep := false
	var received []*os.File
	defer func() {
		if !keep {
			closeOwnerFiles(received)
		}
	}()
	first := true
	read := func(dst []byte) error {
		for len(dst) > 0 {
			control := make([]byte, syscall.CmsgSpace(16))
			n, count, flags, _, err := conn.ReadMsgUnix(dst, control)
			rights, parseErr := bridgeRights(control[:count])
			for _, f := range rights {
				syscall.CloseOnExec(int(f.Fd()))
			}
			files = append(files, rights...)
			received = files
			wasFirst := first
			first = false
			if err != nil || parseErr != nil || n <= 0 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || len(files) > maxFD || (!wasFirst && len(rights) > 0) {
				return fail("artifact_owner_read_frame_invalid")
			}
			dst = dst[n:]
		}
		return nil
	}
	var header [4]byte
	if err := read(header[:1]); err != nil {
		return nil, nil, err
	}
	if err := read(header[1:]); err != nil {
		return nil, nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameBytes {
		return nil, nil, fail("artifact_owner_read_frame_oversized")
	}
	raw = make([]byte, int(size))
	if err := read(raw); err != nil {
		return nil, nil, err
	}
	if !utf8.Valid(raw) {
		return nil, nil, fail("artifact_owner_read_frame_invalid")
	}
	keep = true
	return raw, files, nil
}

func writeOwnerFrame(conn *net.UnixConn, raw []byte, files []*os.File) error {
	if len(raw) == 0 || len(raw) > MaxFrameBytes || len(files) > 1 {
		return fail("artifact_owner_read_frame_oversized")
	}
	frame := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(raw)))
	copy(frame[4:], raw)
	var control []byte
	if len(files) == 1 {
		if files[0] == nil {
			return fail("artifact_owner_read_file_invalid")
		}
		control = syscall.UnixRights(int(files[0].Fd()))
	}
	// Send rights with exactly one byte, making the first-byte rule explicit.
	n, count, err := conn.WriteMsgUnix(frame[:1], control, nil)
	if err != nil || n != 1 || count != len(control) {
		return fail("artifact_owner_read_write_failed")
	}
	for offset := 1; offset < len(frame); {
		n, err = conn.Write(frame[offset:])
		if err != nil || n <= 0 {
			return fail("artifact_owner_read_write_failed")
		}
		offset += n
	}
	return nil
}

func ownerReadEnd(conn *net.UnixConn) error {
	var one [1]byte
	control := make([]byte, syscall.CmsgSpace(16))
	n, count, flags, _, err := conn.ReadMsgUnix(one[:], control)
	files, parseErr := bridgeRights(control[:count])
	closeOwnerFiles(files)
	// ReadMsgUnix wraps the stream's io.EOF in *net.OpError. Recognize that
	// causal EOF while still rejecting deadlines, resets, bytes and ancillary.
	if n != 0 || !errors.Is(err, io.EOF) || parseErr != nil || count != 0 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return fail("artifact_owner_read_trailing")
	}
	return nil
}

func (s *OwnerReadUnixServer) serveConnection(parent context.Context, conn *net.UnixConn, cancel context.CancelFunc) {
	b := s.base
	defer func() {
		cancel()
		conn.Close()
		b.mu.Lock()
		delete(b.connections, conn)
		b.mu.Unlock()
		<-b.slots
		s.wg.Done()
	}()
	stopParent := context.AfterFunc(parent, func() { conn.Close() })
	defer stopParent()
	uid, err := peerUID(conn)
	if err != nil || uid != *b.config.AllowedUID {
		s.writeError(conn, "artifact_peer_forbidden")
		return
	}
	if conn.SetReadDeadline(time.Now().Add(b.config.RequestTimeout)) != nil {
		return
	}
	raw, files, err := readOwnerFrame(conn, 0)
	defer closeOwnerFiles(files)
	var q OwnerReadRequest
	if err != nil || strictJSON(raw, &q) != nil || ValidateOwnerReadRequest(q) != nil {
		s.writeError(conn, "artifact_owner_read_request_invalid")
		return
	}
	if !unixChannelOpen(conn) {
		return
	}
	runCtx, stopRun := context.WithTimeout(parent, b.config.RunTimeout)
	defer stopRun()
	stopClose := context.AfterFunc(runCtx, func() { conn.Close() })
	defer stopClose()
	deadline, _ := runCtx.Deadline()
	if conn.SetReadDeadline(deadline) != nil {
		return
	}
	monitored := make(chan struct{})
	go func() { defer close(monitored); ownerReadEnd(conn); stopRun() }()
	defer func() { conn.SetReadDeadline(time.Now()); <-monitored }()
	select {
	case s.active <- struct{}{}:
		defer func() { <-s.active }()
	case <-runCtx.Done():
		return
	}
	r, out, err := s.handler.HandleOwnerRead(runCtx, q)
	if out != nil {
		defer out.Close()
	}
	if runCtx.Err() != nil || !unixChannelOpen(conn) {
		return
	}
	if err != nil {
		s.writeError(conn, "artifact_owner_read_handler_failed")
		return
	}
	if ValidateOwnerReadResponse(q, r) != nil {
		s.writeError(conn, "artifact_owner_read_response_invalid")
		return
	}
	if !r.HasReceipt && out != nil {
		s.writeError(conn, "artifact_owner_read_unexpected_fd")
		return
	}
	encoded, err := json.Marshal(r)
	if err != nil || len(encoded) > MaxFrameBytes {
		s.writeError(conn, "artifact_owner_read_response_oversized")
		return
	}
	var gate sync.Mutex
	active, called := true, false
	write := func() error {
		gate.Lock()
		defer gate.Unlock()
		if !active || called {
			return fail("artifact_owner_read_delivery_invalid")
		}
		called = true
		if runCtx.Err() != nil || !unixChannelOpen(conn) {
			return fail("artifact_owner_read_channel_closed")
		}
		if conn.SetWriteDeadline(time.Now().Add(b.config.WriteTimeout)) != nil {
			return fail("artifact_owner_read_write_failed")
		}
		var outputs []*os.File
		if r.HasReceipt {
			// Validate only after the core's fresh trusted-history guard. A stale
			// receipt cannot short-circuit that independent storage-fault check.
			// This is trusted broker storage, not client IO. A concurrent remote
			// cancellation must not hide an observed storage fault. The core
			// handles the typed fault under its still-held history locks.
			if err := checkOwnerReceipt(context.Background(), out, uint32(os.Geteuid()), r.Binding.Execution); err != nil {
				return &ownerReadFailure{storage: true, cause: err}
			}
			send, err := duplicateReadOnly(out)
			if err != nil {
				return err
			}
			defer send.Close()
			outputs = []*os.File{send}
		}
		return writeOwnerFrame(conn, encoded, outputs)
	}
	// No fallback write: a guard rejection or partial write cannot append a new
	// response. In particular, no transport error is an execution ACK failure.
	s.handler.DeliverOwnerRead(runCtx, q, r, out, write)
	gate.Lock()
	active = false
	gate.Unlock()
}

func ownerReceiptStat(f *os.File, uid uint32, size int64) (syscall.Stat_t, error) {
	var st syscall.Stat_t
	if f == nil || size < 0 || size > MaxBridgeReceiptBytes || syscall.Fstat(int(f.Fd()), &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Uid != uid || st.Size != size {
		return st, fail("artifact_owner_read_file_invalid")
	}
	flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFL, 0)
	fdflags, _, ce := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFD, 0)
	if e != 0 || ce != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY || fdflags&syscall.FD_CLOEXEC == 0 {
		return st, fail("artifact_owner_read_file_invalid")
	}
	return st, nil
}

func checkOwnerReceipt(ctx context.Context, f *os.File, brokerUID uint32, r BridgeResponse) error {
	before, err := ownerReceiptStat(f, brokerUID, r.ReceiptBytes)
	if err != nil || !hexID(r.ReceiptSHA256, 64) {
		return fail("artifact_owner_read_file_invalid")
	}
	if _, err = ReceiveInput(ctx, io.Discard, io.NewSectionReader(f, 0, r.ReceiptBytes+1), r.ReceiptBytes, r.ReceiptSHA256); err != nil {
		return fail("artifact_owner_read_receipt_invalid")
	}
	after, err := ownerReceiptStat(f, brokerUID, r.ReceiptBytes)
	if err != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return fail("artifact_owner_read_file_changed")
	}
	return nil
}

// Client metadata checks use the configured broker UID, including receipt FD
// ownership. They do not confuse the Results process UID with the producer UID.
func ownerClientDirectory(path string, uid uint32) (*os.File, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail("artifact_directory_unsafe")
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		child, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, fail("artifact_directory_unsafe")
		}
		fd = child
	}
	f := os.NewFile(uintptr(fd), "owner-reader-directory")
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&07777 != 0700 || st.Uid != uid {
		f.Close()
		return nil, fail("artifact_directory_unsafe")
	}
	return f, nil
}

func ownerClientSocket(dir *os.File, name string, uid uint32) (*os.File, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, unixPathFlag|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail("artifact_socket_unsafe")
	}
	f := os.NewFile(uintptr(fd), "owner-reader-socket")
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFSOCK || !privateSocket(st) || st.Uid != uid {
		f.Close()
		return nil, fail("artifact_socket_unsafe")
	}
	return f, nil
}

func QueryOwnerStatus(ctx context.Context, cfg OwnerReadClientConfig, q OwnerReadRequest) (OwnerReadResponse, error) {
	if q.Operation != "status" {
		return OwnerReadResponse{}, fail("artifact_owner_read_request_invalid")
	}
	r, f, err := callOwnerRead(ctx, cfg, q)
	if f != nil {
		f.Close()
		return OwnerReadResponse{}, fail("artifact_owner_read_unexpected_fd")
	}
	return r, err
}

func ReadOwnerReceipt(ctx context.Context, cfg OwnerReadClientConfig, q OwnerReadRequest) (OwnerReadResponse, *os.File, error) {
	if q.Operation != "receipt" {
		return OwnerReadResponse{}, nil, fail("artifact_owner_read_request_invalid")
	}
	return callOwnerRead(ctx, cfg, q)
}

func callOwnerRead(ctx context.Context, cfg OwnerReadClientConfig, q OwnerReadRequest) (OwnerReadResponse, *os.File, error) {
	var zero OwnerReadResponse
	if ctx == nil || ValidateOwnerReadRequest(q) != nil {
		return zero, nil, fail("artifact_owner_read_request_invalid")
	}
	path, name, err := unixName(cfg.SocketPath)
	if err != nil {
		return zero, nil, err
	}
	directory, err := ownerClientDirectory(path, cfg.ExpectedBrokerUID)
	if err != nil {
		return zero, nil, err
	}
	defer directory.Close()
	metadata, err := ownerClientSocket(directory, name, cfg.ExpectedBrokerUID)
	if err != nil {
		return zero, nil, err
	}
	defer metadata.Close()
	raw, err := json.Marshal(q)
	if err != nil || len(raw) > MaxFrameBytes {
		return zero, nil, fail("artifact_owner_read_request_invalid")
	}
	bounded, stop := context.WithTimeout(ctx, 40*time.Second)
	defer stop()
	connection, err := (&net.Dialer{}).DialContext(bounded, "unix", fdPath(directory)+"/"+name)
	if err != nil {
		return zero, nil, fail("artifact_client_connect_failed")
	}
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return zero, nil, fail("artifact_client_connect_failed")
	}
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil || uid != cfg.ExpectedBrokerUID {
		return zero, nil, fail("artifact_peer_forbidden")
	}
	stopClose := context.AfterFunc(bounded, func() { conn.Close() })
	defer stopClose()
	deadline, _ := bounded.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return zero, nil, fail("artifact_client_deadline_failed")
	}
	if err = writeOwnerFrame(conn, raw, nil); err != nil {
		return zero, nil, err
	}
	data, files, err := readOwnerFrame(conn, 1)
	keep := false
	defer func() {
		if !keep {
			closeOwnerFiles(files)
		}
	}()
	if err != nil {
		return zero, nil, err
	}
	var r OwnerReadResponse
	if strictJSON(data, &r) != nil || ValidateOwnerReadResponse(q, r) != nil {
		return zero, nil, fail("artifact_owner_read_response_invalid")
	}
	if ownerReadEnd(conn) != nil {
		return zero, nil, fail("artifact_owner_read_response_trailing")
	}
	if r.HasReceipt {
		if len(files) != 1 || checkOwnerReceipt(bounded, files[0], uid, r.Binding.Execution) != nil {
			return zero, nil, fail("artifact_owner_read_file_invalid")
		}
		keep = true
		return r, files[0], nil
	}
	if len(files) != 0 {
		return zero, nil, fail("artifact_owner_read_unexpected_fd")
	}
	return r, nil, nil
}

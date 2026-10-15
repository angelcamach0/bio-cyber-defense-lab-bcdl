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
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// BridgeHandler owns broker authority, admission and persistence. input is a
// borrowed descriptor valid until HandleBridge returns; a retained input must be
// duplicated. A returned output descriptor transfers ownership to the transport.
// Neither a frame nor an EOF is proof of provider quiescence.
type BridgeHandler interface {
	HandleBridge(context.Context, BridgeRequest, *os.File) (BridgeResponse, *os.File, error)
}

// BridgeAcknowledger wraps the actual bounded socket write, synchronously and at
// most once. Without this interface the generic transport claims no durable ACK.
type BridgeHandlerV2 interface {
	HandleBridgeV2(context.Context, BridgeRequestV2, *os.File) (BridgeResponse, *os.File, error)
}
type BridgeAcknowledgerV2 interface {
	AcknowledgeBridgeV2(context.Context, BridgeRequestV2, func() error) error
}

type BridgeAcknowledger interface {
	AcknowledgeBridge(context.Context, BridgeRequest, func() error) error
}

// BridgeUnixServer reuses v1's private descriptor-anchored socket lifetime and
// limits, but runs a separate FD-aware protocol. It never dispatches v1 requests.
type BridgeUnixServer struct {
	base      *UnixServer
	handler   BridgeHandler
	handlerV2 BridgeHandlerV2
	handlerV3 BridgeHandlerV3
	version   int
}
type bridgeUnusedV1 struct{}

func (bridgeUnusedV1) Handle(context.Context, Request) ([]byte, error) {
	return nil, fail("artifact_bridge_v1_forbidden")
}

func ListenBridgeUnix(config UnixServerConfig, handler BridgeHandler) (*BridgeUnixServer, error) {
	if handler == nil {
		return nil, fail("artifact_bridge_config_invalid")
	}
	base, err := ListenUnixServer(config, bridgeUnusedV1{})
	if err != nil {
		return nil, err
	}
	return &BridgeUnixServer{base: base, handler: handler, version: 1}, nil
}

// ListenBridgeUnixV2 selects a separate fixed codec; no per-frame fallback or
// version negotiation is permitted on this listener.
func ListenBridgeUnixV2(config UnixServerConfig, handler BridgeHandlerV2) (*BridgeUnixServer, error) {
	if handler == nil {
		return nil, fail("artifact_bridge_config_invalid")
	}
	base, err := ListenUnixServer(config, bridgeUnusedV1{})
	if err != nil {
		return nil, err
	}
	return &BridgeUnixServer{base: base, handlerV2: handler, version: 2}, nil
}
func (s *BridgeUnixServer) Close() error { return s.base.Close() }
func (s *BridgeUnixServer) Serve(ctx context.Context) error {
	if ctx == nil {
		return fail("artifact_server_context_invalid")
	}
	b := s.base
	b.mu.Lock()
	if b.closed || b.started {
		b.mu.Unlock()
		return fail("artifact_server_unavailable")
	}
	b.started = true
	b.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	for {
		conn, err := b.listener.AcceptUnix()
		if err != nil {
			b.mu.Lock()
			closed := b.closed
			b.mu.Unlock()
			if closed || ctx.Err() != nil {
				return nil
			}
			s.Close()
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
			b.mu.Unlock()
			go s.serveConnection(connectionCtx, conn, cancel)
		default:
			b.mu.Unlock()
			conn.Close()
		}
	}
}

// Read every byte using recvmsg, including fragmented headers/bodies and the
// trailing monitor. Ordinary Read would silently discard late ancillary rights.
// Rights are permitted only on the first received byte of a frame. Go's Linux
// UnixConn.ReadMsgUnix uses MSG_CMSG_CLOEXEC atomically; verify that property too.
func bridgeReadFrame(conn *net.UnixConn) (raw []byte, file *os.File, err error) {
	var rights []*os.File
	keep := false
	defer func() {
		if !keep {
			for _, f := range rights {
				f.Close()
			}
		}
	}()
	read := func(dst []byte, first *bool) error {
		for len(dst) > 0 {
			control := make([]byte, syscall.CmsgSpace(4*4))
			n, count, flags, _, readErr := conn.ReadMsgUnix(dst, control)
			received, parseErr := bridgeRights(control[:count])
			rights = append(rights, received...)
			hadFirst := *first
			*first = false
			if readErr != nil || parseErr != nil || flags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) != 0 || n <= 0 || len(rights) > 1 || (!hadFirst && len(received) > 0) {
				return fail("artifact_bridge_frame_invalid")
			}
			dst = dst[n:]
		}
		return nil
	}
	first := true
	var header [4]byte
	if err = read(header[:], &first); err != nil {
		return nil, nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameBytes {
		return nil, nil, fail("artifact_bridge_frame_oversized")
	}
	raw = make([]byte, int(size))
	if err = read(raw, &first); err != nil {
		return nil, nil, err
	}
	if !utf8.Valid(raw) {
		return nil, nil, fail("artifact_bridge_frame_invalid")
	}
	if len(rights) == 1 {
		file = rights[0]
	}
	keep = true
	return raw, file, nil
}
func bridgeRights(control []byte) ([]*os.File, error) {
	messages, err := syscall.ParseSocketControlMessage(control)
	var files []*os.File
	for _, m := range messages {
		if m.Header.Level != syscall.SOL_SOCKET || m.Header.Type != syscall.SCM_RIGHTS {
			err = fail("artifact_bridge_rights_invalid")
			continue
		}
		fds, e := syscall.ParseUnixRights(&m)
		if e != nil {
			err = fail("artifact_bridge_rights_invalid")
			continue
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "artifact-bridge-fd"))
		}
	}
	return files, err
}
func bridgeCheckFile(f *os.File, limit, size int64) error {
	if f == nil || size < 0 || size > limit || !safeInfo(f, false) {
		return fail("artifact_bridge_file_invalid")
	}
	info, err := f.Stat()
	if err != nil || info.Size() != size {
		return fail("artifact_bridge_file_invalid")
	}
	flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFL, 0)
	descriptor, _, ce := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFD, 0)
	if e != 0 || ce != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY || descriptor&syscall.FD_CLOEXEC == 0 {
		return fail("artifact_bridge_file_invalid")
	}
	return nil
}
func bridgeReadEnd(conn *net.UnixConn) error {
	var one [1]byte
	control := make([]byte, syscall.CmsgSpace(4*4))
	n, count, flags, _, err := conn.ReadMsgUnix(one[:], control)
	files, parseErr := bridgeRights(control[:count])
	for _, f := range files {
		f.Close()
	}
	if n != 0 || (err != nil && !errors.Is(err, io.EOF)) || parseErr != nil || count != 0 || flags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) != 0 {
		return fail("artifact_bridge_trailing")
	}
	return nil
}
func bridgeWriteFrame(conn *net.UnixConn, raw []byte, f *os.File) error {
	if len(raw) == 0 || len(raw) > MaxFrameBytes {
		return fail("artifact_bridge_frame_oversized")
	}
	frame := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(raw)))
	copy(frame[4:], raw)
	var control []byte
	if f != nil {
		control = syscall.UnixRights(int(f.Fd()))
	}
	n, count, err := conn.WriteMsgUnix(frame, control, nil)
	if err != nil || n <= 0 || count != len(control) {
		return fail("artifact_bridge_write_failed")
	}
	// Ancillary rights travel exactly once. A partial stream write may finish the
	// ordinary bytes, but must never resend the descriptor with the remainder.
	for n < len(frame) {
		written, err := conn.Write(frame[n:])
		if err != nil || written <= 0 {
			return fail("artifact_bridge_write_failed")
		}
		n += written
	}
	return nil
}
func (s *BridgeUnixServer) writeError(conn *net.UnixConn, code string) {
	conn.SetWriteDeadline(time.Now().Add(s.base.config.WriteTimeout))
	r := bridgeErrorResponse(code)
	r.SchemaVersion = s.version
	raw, err := json.Marshal(r)
	if err == nil {
		bridgeWriteFrame(conn, raw, nil)
	}
}
func (s *BridgeUnixServer) serveConnection(parent context.Context, conn *net.UnixConn, cancel context.CancelFunc) {
	if s.version == 3 {
		s.serveOwnerConnection(parent, conn, cancel)
		return
	}
	b := s.base
	defer func() {
		cancel()
		conn.Close()
		b.mu.Lock()
		delete(b.connections, conn)
		b.mu.Unlock()
		<-b.slots
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
	raw, input, err := bridgeReadFrame(conn)
	if input != nil {
		defer input.Close()
	}
	var q BridgeRequest
	var q2 BridgeRequestV2
	var decodeErr error
	if s.version == 2 {
		decodeErr = strictJSON(raw, &q2)
		if decodeErr == nil {
			decodeErr = validateBridgeRequestV2(q2)
		}
		q = q2.legacy()
	} else {
		decodeErr = strictJSON(raw, &q)
		if decodeErr == nil {
			decodeErr = validateBridgeRequest(q)
		}
	}
	if err != nil || decodeErr != nil {
		s.writeError(conn, "artifact_bridge_request_invalid")
		return
	}
	if q.Operation == "submit" {
		if bridgeCheckFile(input, MaxInputBytes, q.ProcessedBytes) != nil {
			s.writeError(conn, "artifact_bridge_file_invalid")
			return
		}
	} else if input != nil {
		s.writeError(conn, "artifact_bridge_unexpected_fd")
		return
	}
	// Reject already queued bytes/EOF before dispatch. Data racing later admission
	// cannot undo durable work; the monitor cancels context and fences the ACK.
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
	go func() { defer close(monitored); bridgeReadEnd(conn); stopRun() }()
	defer func() { conn.SetReadDeadline(time.Now()); <-monitored }()
	var response BridgeResponse
	var output *os.File
	var handlerErr error
	if s.version == 2 {
		response, output, handlerErr = s.handlerV2.HandleBridgeV2(runCtx, q2, input)
	} else {
		response, output, handlerErr = s.handler.HandleBridge(runCtx, q, input)
	}
	if output != nil {
		defer output.Close()
	}
	if runCtx.Err() != nil || !unixChannelOpen(conn) {
		return
	}
	if handlerErr != nil {
		s.writeError(conn, "artifact_bridge_handler_failed")
		return
	}
	var responseErr error
	if s.version == 2 {
		responseErr = validateBridgeResponseV2(q2, response)
	} else {
		responseErr = validateBridgeResponse(q, response)
	}
	if responseErr != nil {
		s.writeError(conn, "artifact_bridge_response_invalid")
		return
	}
	var send *os.File
	if q.Operation == "receipt" && response.ErrorCode == "" {
		if bridgeCheckFile(output, MaxBridgeReceiptBytes, response.ReceiptBytes) != nil {
			s.writeError(conn, "artifact_bridge_file_invalid")
			return
		}
		send, err = duplicateReadOnly(output)
		if err != nil {
			s.writeError(conn, "artifact_bridge_file_invalid")
			return
		}
		defer send.Close()
	} else if output != nil {
		s.writeError(conn, "artifact_bridge_unexpected_fd")
		return
	}
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > MaxFrameBytes {
		s.writeError(conn, "artifact_bridge_response_oversized")
		return
	}
	write := func() error {
		if runCtx.Err() != nil || !unixChannelOpen(conn) {
			return fail("artifact_bridge_ack_closed")
		}
		if conn.SetWriteDeadline(time.Now().Add(b.config.WriteTimeout)) != nil {
			return fail("artifact_bridge_write_failed")
		}
		return bridgeWriteFrame(conn, encoded, send)
	}
	var acknowledge func(context.Context, func() error) error
	if s.version == 2 {
		if a, ok := s.handlerV2.(BridgeAcknowledgerV2); ok {
			acknowledge = func(ctx context.Context, w func() error) error { return a.AcknowledgeBridgeV2(ctx, q2, w) }
		}
	} else if a, ok := s.handler.(BridgeAcknowledger); ok {
		acknowledge = func(ctx context.Context, w func() error) error { return a.AcknowledgeBridge(ctx, q, w) }
	}
	if acknowledge != nil {
		var callbackMu sync.Mutex
		active, called := true, false
		callback := func() error {
			callbackMu.Lock()
			defer callbackMu.Unlock()
			if !active || called {
				return fail("artifact_bridge_ack_invalid")
			}
			called = true
			return write()
		}
		acknowledge(runCtx, callback)
		callbackMu.Lock()
		active = false
		callbackMu.Unlock()
		return
	}
	write()
}

// CallBridgeUnix borrows input and returns an owned receipt FD only after the
// complete response, EOF, private metadata and bounded receipt hash agree. The
// caller closes that FD. No plaintext or receipt paths travel over this protocol.
func CallBridgeUnix(ctx context.Context, socket string, q BridgeRequest, input *os.File) (BridgeResponse, *os.File, error) {
	if validateBridgeRequest(q) != nil {
		return BridgeResponse{}, nil, fail("artifact_bridge_request_invalid")
	}
	return callBridgeUnix(ctx, socket, q, input, nil)
}

// CallBridgeUnixV2 requires an explicitly selected v2 listener and validates a v2
// response. The input and retained-receipt FD guarantees match the v1 client.
func CallBridgeUnixV2(ctx context.Context, socket string, q BridgeRequestV2, input *os.File) (BridgeResponse, *os.File, error) {
	if validateBridgeRequestV2(q) != nil {
		return BridgeResponse{}, nil, fail("artifact_bridge_request_invalid")
	}
	return callBridgeUnix(ctx, socket, q.legacy(), input, &q)
}
func callBridgeUnix(ctx context.Context, socket string, q BridgeRequest, input *os.File, q2 *BridgeRequestV2) (BridgeResponse, *os.File, error) {
	var response BridgeResponse
	if ctx == nil || validateBridgeRequest(q) != nil {
		return response, nil, fail("artifact_bridge_request_invalid")
	}
	var send *os.File
	var err error
	if q.Operation == "submit" {
		send, err = duplicateReadOnly(input)
		if err != nil {
			return response, nil, err
		}
		defer send.Close()
		if err = bridgeCheckFile(send, MaxInputBytes, q.ProcessedBytes); err != nil {
			return response, nil, err
		}
	} else if input != nil {
		return response, nil, fail("artifact_bridge_unexpected_fd")
	}
	path, name, err := unixName(socket)
	if err != nil {
		return response, nil, err
	}
	directory, err := unixExistingDirectory(path)
	if err != nil {
		return response, nil, err
	}
	defer directory.Close()
	metadata, stat, err := socketMetadata(directory, name)
	if err != nil {
		return response, nil, fail("artifact_socket_unsafe")
	}
	defer metadata.Close()
	if !privateSocket(stat) {
		return response, nil, fail("artifact_socket_unsafe")
	}
	var raw []byte
	if q2 != nil {
		raw, err = json.Marshal(*q2)
	} else {
		raw, err = json.Marshal(q)
	}
	if err != nil || len(raw) > MaxFrameBytes {
		return response, nil, fail("artifact_bridge_request_invalid")
	}
	// Validate our emitted bytes against the same strict wire parser too.
	var codecErr error
	if q2 != nil {
		var check BridgeRequestV2
		codecErr = strictJSON(raw, &check)
	} else {
		var check BridgeRequest
		codecErr = strictJSON(raw, &check)
	}
	if codecErr != nil {
		return response, nil, fail("artifact_bridge_request_invalid")
	}
	bounded, stop := context.WithTimeout(ctx, time.Hour)
	defer stop()
	connection, err := (&net.Dialer{}).DialContext(bounded, "unix", fdPath(directory)+"/"+name)
	if err != nil {
		return response, nil, fail("artifact_client_connect_failed")
	}
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return response, nil, fail("artifact_client_connect_failed")
	}
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil || uid != uint32(os.Geteuid()) {
		return response, nil, fail("artifact_peer_forbidden")
	}
	stopClose := context.AfterFunc(bounded, func() { conn.Close() })
	defer stopClose()
	deadline, _ := bounded.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return response, nil, fail("artifact_client_deadline_failed")
	}
	if err = bridgeWriteFrame(conn, raw, send); err != nil {
		return response, nil, err
	}
	data, output, err := bridgeReadFrame(conn)
	keep := false
	defer func() {
		if output != nil && !keep {
			output.Close()
		}
	}()
	if err != nil {
		return response, nil, err
	}
	responseErr := strictJSON(data, &response)
	if responseErr == nil {
		if q2 != nil {
			responseErr = validateBridgeResponseV2(*q2, response)
		} else {
			responseErr = validateBridgeResponse(q, response)
		}
	}
	if responseErr != nil {
		return response, nil, fail("artifact_bridge_response_invalid")
	}
	if err = bridgeReadEnd(conn); err != nil {
		return response, nil, err
	}
	if q.Operation == "receipt" && response.ErrorCode == "" {
		if err = bridgeCheckFile(output, MaxBridgeReceiptBytes, response.ReceiptBytes); err != nil {
			return response, nil, err
		}
		if _, err = ReceiveInput(bounded, io.Discard, io.NewSectionReader(output, 0, response.ReceiptBytes+1), response.ReceiptBytes, response.ReceiptSHA256); err != nil {
			return response, nil, fail("artifact_bridge_receipt_invalid")
		}
	} else if output != nil {
		return response, nil, fail("artifact_bridge_unexpected_fd")
	}
	keep = true
	return response, output, nil
}

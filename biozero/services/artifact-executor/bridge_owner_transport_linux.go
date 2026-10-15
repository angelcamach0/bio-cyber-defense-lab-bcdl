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
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	ownership "biozero/ownership-authority"
)

type BridgeHandlerV3 interface {
	HandleBridgeV3(context.Context, BridgeRequestV3, *os.File, *os.File) (BridgeResponseV3, *os.File, error)
}
type BridgeAcknowledgerV3 interface {
	AcknowledgeBridgeV3(context.Context, BridgeRequestV3, func() error) error
}

func ListenBridgeUnixV3(cfg UnixServerConfig, handler BridgeHandlerV3) (*BridgeUnixServer, error) {
	if handler == nil {
		return nil, fail("artifact_bridge_config_invalid")
	}
	base, e := ListenUnixServer(cfg, bridgeUnusedV1{})
	if e != nil {
		return nil, e
	}
	return &BridgeUnixServer{base: base, handlerV3: handler, version: 3}, nil
}

// This codec is separate from v1/v2's one-FD codec. Rights appear once, on the
// first frame byte only. Every received FD is closed on all rejection paths.
func ownerReadFrame(conn *net.UnixConn, maxFD int) (raw []byte, files []*os.File, err error) {
	keep := false
	defer func() {
		if !keep {
			for _, f := range files {
				f.Close()
			}
		}
	}()
	first := true
	read := func(dst []byte) error {
		for len(dst) > 0 {
			control := make([]byte, syscall.CmsgSpace(4*4))
			n, count, flags, _, e := conn.ReadMsgUnix(dst, control)
			rights, pe := bridgeRights(control[:count])
			files = append(files, rights...)
			wasFirst := first
			first = false
			if e != nil || pe != nil || n <= 0 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 || len(files) > maxFD || (!wasFirst && len(rights) > 0) {
				return fail("artifact_bridge_frame_invalid")
			}
			dst = dst[n:]
		}
		return nil
	}
	var header [4]byte
	if err = read(header[:1]); err != nil {
		return nil, files, err
	}
	if err = read(header[1:]); err != nil {
		return nil, files, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameBytes {
		return nil, files, fail("artifact_bridge_frame_oversized")
	}
	raw = make([]byte, int(size))
	if err = read(raw); err != nil {
		return nil, files, err
	}
	if !utf8.Valid(raw) {
		return nil, files, fail("artifact_bridge_frame_invalid")
	}
	keep = true
	return raw, files, nil
}
func ownerWriteFrame(conn *net.UnixConn, raw []byte, files []*os.File) error {
	if len(raw) < 1 || len(raw) > MaxFrameBytes || len(files) > 2 {
		return fail("artifact_bridge_frame_oversized")
	}
	frame := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(raw)))
	copy(frame[4:], raw)
	var control []byte
	if len(files) > 0 {
		fds := make([]int, len(files))
		for i, f := range files {
			if f == nil {
				return fail("artifact_bridge_file_invalid")
			}
			fds[i] = int(f.Fd())
		}
		control = syscall.UnixRights(fds...)
	}
	n, count, e := conn.WriteMsgUnix(frame, control, nil)
	if e != nil || n <= 0 || count != len(control) {
		return fail("artifact_bridge_write_failed")
	}
	for n < len(frame) {
		w, e := conn.Write(frame[n:])
		if e != nil || w <= 0 {
			return fail("artifact_bridge_write_failed")
		}
		n += w
	}
	return nil
}
func (s *BridgeUnixServer) writeOwnerError(conn *net.UnixConn, code string) {
	conn.SetWriteDeadline(time.Now().Add(s.base.config.WriteTimeout))
	raw, e := json.Marshal(bridgeErrorResponseV3(code))
	if e == nil {
		ownerWriteFrame(conn, raw, nil)
	}
}
func (s *BridgeUnixServer) serveOwnerConnection(parent context.Context, conn *net.UnixConn, cancel context.CancelFunc) {
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
	uid, e := peerUID(conn)
	if e != nil || uid != *b.config.AllowedUID {
		s.writeOwnerError(conn, "artifact_peer_forbidden")
		return
	}
	if conn.SetReadDeadline(time.Now().Add(b.config.RequestTimeout)) != nil {
		return
	}
	raw, inputs, e := ownerReadFrame(conn, 2)
	for _, f := range inputs {
		defer f.Close()
	}
	var q BridgeRequestV3
	if e != nil || strictJSON(raw, &q) != nil || validateBridgeRequestV3(q) != nil {
		s.writeOwnerError(conn, "artifact_bridge_request_invalid")
		return
	}
	var plain, acceptance *os.File
	if q.Operation == "submit" {
		if len(inputs) != 2 {
			s.writeOwnerError(conn, "artifact_bridge_file_invalid")
			return
		}
		plain, acceptance = inputs[0], inputs[1]
		if bridgeCheckFile(plain, MaxInputBytes, q.ProcessedBytes) != nil || bridgeCheckFile(acceptance, ownership.MaxAcceptanceBytes, q.AcceptanceBytes) != nil {
			s.writeOwnerError(conn, "artifact_bridge_file_invalid")
			return
		}
	} else if len(inputs) != 0 {
		s.writeOwnerError(conn, "artifact_bridge_unexpected_fd")
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
	go func() { defer close(monitored); bridgeReadEnd(conn); stopRun() }()
	defer func() { conn.SetReadDeadline(time.Now()); <-monitored }()
	r, out, e := s.handlerV3.HandleBridgeV3(runCtx, q, plain, acceptance)
	if out != nil {
		defer out.Close()
	}
	if runCtx.Err() != nil || !unixChannelOpen(conn) {
		return
	}
	if e != nil {
		s.writeOwnerError(conn, "artifact_bridge_handler_failed")
		return
	}
	if validateBridgeResponseV3(q, r) != nil {
		s.writeOwnerError(conn, "artifact_bridge_response_invalid")
		return
	}
	var send *os.File
	if q.Operation == "receipt" && r.Execution.ErrorCode == "" {
		if bridgeCheckFile(out, MaxBridgeReceiptBytes, r.Execution.ReceiptBytes) != nil {
			s.writeOwnerError(conn, "artifact_bridge_file_invalid")
			return
		}
		send, e = duplicateReadOnly(out)
		if e != nil {
			s.writeOwnerError(conn, "artifact_bridge_file_invalid")
			return
		}
		defer send.Close()
	} else if out != nil {
		s.writeOwnerError(conn, "artifact_bridge_unexpected_fd")
		return
	}
	encoded, e := json.Marshal(r)
	if e != nil || len(encoded) > MaxFrameBytes {
		s.writeOwnerError(conn, "artifact_bridge_response_oversized")
		return
	}
	write := func() error {
		if runCtx.Err() != nil || !unixChannelOpen(conn) {
			return fail("artifact_bridge_ack_closed")
		}
		if conn.SetWriteDeadline(time.Now().Add(b.config.WriteTimeout)) != nil {
			return fail("artifact_bridge_write_failed")
		}
		var files []*os.File
		if send != nil {
			files = []*os.File{send}
		}
		return ownerWriteFrame(conn, encoded, files)
	}
	if ack, ok := s.handlerV3.(BridgeAcknowledgerV3); ok {
		var gate sync.Mutex
		active, called := true, false
		callback := func() error {
			gate.Lock()
			defer gate.Unlock()
			if !active || called {
				return fail("artifact_bridge_ack_invalid")
			}
			called = true
			return write()
		}
		ack.AcknowledgeBridgeV3(runCtx, q, callback)
		gate.Lock()
		active = false
		gate.Unlock()
		return
	}
	write()
}
func CallBridgeUnixV3(ctx context.Context, socket string, q BridgeRequestV3, plain, acceptance *os.File) (BridgeResponseV3, *os.File, error) {
	var zero BridgeResponseV3
	if ctx == nil || validateBridgeRequestV3(q) != nil {
		return zero, nil, fail("artifact_bridge_request_invalid")
	}
	var sends []*os.File
	defer func() {
		for _, f := range sends {
			f.Close()
		}
	}()
	if q.Operation == "submit" {
		for i, source := range []*os.File{plain, acceptance} {
			f, e := duplicateReadOnly(source)
			if e != nil {
				return zero, nil, e
			}
			sends = append(sends, f)
			limit, size := MaxInputBytes, q.ProcessedBytes
			if i == 1 {
				limit, size = ownership.MaxAcceptanceBytes, q.AcceptanceBytes
			}
			if bridgeCheckFile(f, limit, size) != nil {
				return zero, nil, fail("artifact_bridge_file_invalid")
			}
		}
	} else if plain != nil || acceptance != nil {
		return zero, nil, fail("artifact_bridge_unexpected_fd")
	}
	dir, name, e := unixName(socket)
	if e != nil {
		return zero, nil, e
	}
	directory, e := unixExistingDirectory(dir)
	if e != nil {
		return zero, nil, e
	}
	defer directory.Close()
	metadata, st, e := socketMetadata(directory, name)
	if e != nil {
		return zero, nil, fail("artifact_socket_unsafe")
	}
	defer metadata.Close()
	if !privateSocket(st) {
		return zero, nil, fail("artifact_socket_unsafe")
	}
	raw, e := json.Marshal(q)
	var check BridgeRequestV3
	if e != nil || len(raw) > MaxFrameBytes || strictJSON(raw, &check) != nil {
		return zero, nil, fail("artifact_bridge_request_invalid")
	}
	bounded, stop := context.WithTimeout(ctx, time.Hour)
	defer stop()
	connection, e := (&net.Dialer{}).DialContext(bounded, "unix", fdPath(directory)+"/"+name)
	if e != nil {
		return zero, nil, fail("artifact_client_connect_failed")
	}
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return zero, nil, fail("artifact_client_connect_failed")
	}
	defer conn.Close()
	uid, e := peerUID(conn)
	if e != nil || uid != uint32(os.Geteuid()) {
		return zero, nil, fail("artifact_peer_forbidden")
	}
	stopClose := context.AfterFunc(bounded, func() { conn.Close() })
	defer stopClose()
	deadline, _ := bounded.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return zero, nil, fail("artifact_client_deadline_failed")
	}
	if e = ownerWriteFrame(conn, raw, sends); e != nil {
		return zero, nil, e
	}
	data, outputs, e := ownerReadFrame(conn, 1)
	keep := false
	defer func() {
		if !keep {
			for _, f := range outputs {
				f.Close()
			}
		}
	}()
	if e != nil {
		return zero, nil, e
	}
	var r BridgeResponseV3
	if strictJSON(data, &r) != nil || validateBridgeResponseV3(q, r) != nil {
		return zero, nil, fail("artifact_bridge_response_invalid")
	}
	if e = bridgeReadEnd(conn); e != nil {
		return zero, nil, e
	}
	if q.Operation == "receipt" && r.Execution.ErrorCode == "" {
		if len(outputs) != 1 || bridgeCheckFile(outputs[0], MaxBridgeReceiptBytes, r.Execution.ReceiptBytes) != nil {
			return zero, nil, fail("artifact_bridge_file_invalid")
		}
		if _, e = ReceiveInput(bounded, io.Discard, io.NewSectionReader(outputs[0], 0, r.Execution.ReceiptBytes+1), r.Execution.ReceiptBytes, r.Execution.ReceiptSHA256); e != nil {
			return zero, nil, fail("artifact_bridge_receipt_invalid")
		}
	} else if len(outputs) != 0 {
		return zero, nil, fail("artifact_bridge_unexpected_fd")
	}
	keep = true
	if len(outputs) == 1 {
		return r, outputs[0], nil
	}
	return r, nil, nil
}

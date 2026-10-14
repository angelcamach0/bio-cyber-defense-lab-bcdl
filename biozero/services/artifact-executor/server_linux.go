//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// UnixHandler is trusted keeper code. It validates lease/reference authority and
// performs durable Store ordering. Peer UID alone does not authorize a lease.
type UnixHandler interface {
	Handle(context.Context, Request) ([]byte, error)
}

// UnixAcknowledger may wrap the actual wire write in Store.Acknowledge. The
// callback must run synchronously, at most once, before this method returns.
// Without this optional interface the listener makes no durable ACK claim.
type UnixAcknowledger interface {
	Acknowledge(context.Context, Request, func() error) error
}

type UnixServerConfig struct {
	SocketPath     string
	AllowedUID     *uint32 // Required: UID zero is valid only when explicitly selected.
	MaxConnections int
	RequestTimeout time.Duration
	RunTimeout     time.Duration
	WriteTimeout   time.Duration
}

type UnixServer struct {
	mu                sync.Mutex
	listener          *net.UnixListener
	directory, socket *os.File
	name              string
	socketStat        syscall.Stat_t
	config            UnixServerConfig
	handler           UnixHandler
	slots             chan struct{}
	connections       map[*net.UnixConn]context.CancelFunc
	started, closed   bool
}

// Linux O_PATH has a stable ABI value, including architectures where syscall
// does not export its constant. It pins filesystem socket metadata, not sockfs.
const unixPathFlag = 0x200000

func unixName(path string) (string, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || path == "" {
		return "", "", fail("artifact_socket_config_invalid")
	}
	name := filepath.Base(absolute)
	if len(name) == 0 || len(name) > 64 || name == "." || name == ".." {
		return "", "", fail("artifact_socket_config_invalid")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return "", "", fail("artifact_socket_config_invalid")
		}
	}
	return filepath.Dir(absolute), name, nil
}
func socketMetadata(dir *os.File, name string) (*os.File, syscall.Stat_t, error) {
	var stat syscall.Stat_t
	fd, err := syscall.Openat(int(dir.Fd()), name, unixPathFlag|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, stat, err
	}
	f := os.NewFile(uintptr(fd), "artifact-socket-metadata")
	if syscall.Fstat(fd, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFSOCK || stat.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, stat, fail("artifact_socket_unsafe")
	}
	return f, stat, nil
}
func privateSocket(stat syscall.Stat_t) bool { return stat.Mode&07777 == 0600 && stat.Nlink == 1 }

func ListenUnixServer(config UnixServerConfig, handler UnixHandler) (*UnixServer, error) {
	if config.AllowedUID == nil || handler == nil {
		return nil, fail("artifact_socket_config_invalid")
	}
	uid := *config.AllowedUID
	config.AllowedUID = &uid // Caller cannot change policy through an alias.
	if config.MaxConnections == 0 {
		config.MaxConnections = 8
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 5 * time.Second
	}
	if config.RunTimeout == 0 {
		config.RunTimeout = 15 * time.Minute
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 5 * time.Second
	}
	if config.MaxConnections < 1 || config.MaxConnections > 32 || config.RequestTimeout <= 0 || config.RequestTimeout > 30*time.Second || config.RunTimeout <= 0 || config.RunTimeout > time.Hour || config.WriteTimeout <= 0 || config.WriteTimeout > 30*time.Second {
		return nil, fail("artifact_socket_config_invalid")
	}
	path, name, err := unixName(config.SocketPath)
	if err != nil {
		return nil, err
	}
	directory, err := openRoot(path)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			directory.Close()
		}
	}()
	// Do not adopt or remove an earlier socket, regular file, FIFO or symlink.
	fd, err := syscall.Openat(int(directory.Fd()), name, unixPathFlag|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err == nil {
		syscall.Close(fd)
		return nil, fail("artifact_socket_exists")
	}
	if err != syscall.ENOENT {
		return nil, fail("artifact_socket_unsafe")
	}
	address := fdPath(directory) + "/" + name
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		return nil, fail("artifact_socket_listen_failed")
	}
	listener.SetUnlinkOnClose(false)
	server := &UnixServer{listener: listener, directory: directory, name: name, config: config, handler: handler, slots: make(chan struct{}, config.MaxConnections), connections: make(map[*net.UnixConn]context.CancelFunc)}
	keep = true
	socket, stat, err := socketMetadata(directory, name)
	if err != nil {
		listener.Close()
		directory.Close()
		return nil, fail("artifact_socket_unsafe")
	}
	server.socket = socket
	server.socketStat = stat
	// chmod follows only the proc reference to the pinned socket inode.
	if os.Chmod(fdPath(socket), 0600) != nil || syscall.Fstat(int(socket.Fd()), &stat) != nil || !privateSocket(stat) || directory.Sync() != nil {
		server.Close()
		return nil, fail("artifact_socket_unsafe")
	}
	server.socketStat = stat
	return server, nil
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	var uid uint32
	var inner error
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fail("artifact_peer_unverified")
	}
	err = raw.Control(func(fd uintptr) {
		var cred *syscall.Ucred
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if inner == nil {
			uid = cred.Uid
		}
	})
	if err != nil || inner != nil {
		return 0, fail("artifact_peer_unverified")
	}
	return uid, nil
}

func (s *UnixServer) Serve(ctx context.Context) error {
	if ctx == nil {
		return fail("artifact_server_context_invalid")
	}
	s.mu.Lock()
	if s.closed || s.started {
		s.mu.Unlock()
		return fail("artifact_server_unavailable")
	}
	s.started = true
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || ctx.Err() != nil {
				return nil
			}
			s.Close()
			return fail("artifact_socket_accept_failed")
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		select {
		case s.slots <- struct{}{}:
			connectionCtx, cancel := context.WithCancel(ctx)
			s.connections[conn] = cancel
			s.mu.Unlock()
			go s.serveConnection(connectionCtx, conn, cancel)
		default:
			s.mu.Unlock()
			conn.Close()
		}
	}
}

func (s *UnixServer) serveConnection(parent context.Context, conn *net.UnixConn, cancel context.CancelFunc) {
	defer func() {
		cancel()
		conn.Close()
		s.mu.Lock()
		delete(s.connections, conn)
		s.mu.Unlock()
		<-s.slots
	}()
	stopParent := context.AfterFunc(parent, func() { conn.Close() })
	defer stopParent()
	conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))
	uid, err := peerUID(conn)
	if err != nil || uid != *s.config.AllowedUID {
		s.writeError(conn, "artifact_peer_forbidden")
		return
	}
	if conn.SetReadDeadline(time.Now().Add(s.config.RequestTimeout)) != nil {
		return
	}
	request, err := ReadRequest(conn)
	if err != nil {
		s.writeError(conn, requestErrorCode(err))
		return
	}
	runCtx, stopRun := context.WithTimeout(parent, s.config.RunTimeout)
	defer stopRun()
	stopClose := context.AfterFunc(runCtx, func() { conn.Close() })
	defer stopClose()
	deadline, _ := runCtx.Deadline()
	if conn.SetReadDeadline(deadline) != nil {
		return
	}
	// A client must keep both directions open. EOF includes a write-half-close.
	// Extra input may race dispatch; cancellation does not undo durable admission.
	monitored := make(chan error, 1)
	go func() {
		var extra [1]byte
		n, readErr := conn.Read(extra[:])
		if n > 0 {
			stopRun()
			monitored <- fail("artifact_request_trailing")
			return
		}
		if readErr == nil || !isTimeout(readErr) {
			stopRun()
		}
		monitored <- readErr
	}()
	// Monitoring continues through the real ACK callback, including any time
	// spent inside the trusted acknowledger. The local deadline only interrupts
	// the monitor at connection teardown; it is not a client half-close.
	defer func() { conn.SetReadDeadline(time.Now()); <-monitored }()
	response, handlerErr := s.handler.Handle(runCtx, request)
	if runCtx.Err() != nil {
		return
	}
	if !unixChannelOpen(conn) {
		stopRun()
		return
	}
	if conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout)) != nil {
		return
	}
	if handlerErr != nil {
		s.writeError(conn, "artifact_handler_failed")
		return
	}
	if len(response) == 0 || len(response) > MaxFrameBytes {
		s.writeError(conn, "artifact_response_oversized")
		return
	}
	// A peer can still close during this write. A successful kernel write is not
	// proof that a client received an ACK; Store retains committed custody.
	if acknowledger, ok := s.handler.(UnixAcknowledger); ok {
		var callbackMu sync.Mutex
		active, called := true, false
		write := func() error {
			callbackMu.Lock()
			defer callbackMu.Unlock()
			if !active || called {
				return fail("artifact_ack_invalid")
			}
			called = true
			if runCtx.Err() != nil || !unixChannelOpen(conn) {
				return fail("artifact_ack_channel_closed")
			}
			if conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout)) != nil {
				return fail("artifact_ack_write_failed")
			}
			if runCtx.Err() != nil {
				return fail("artifact_ack_channel_closed")
			}
			return WriteFrame(conn, response)
		}
		acknowledger.Acknowledge(runCtx, request, write)
		callbackMu.Lock()
		active = false
		callbackMu.Unlock()
		// Never append another response after a partial/ambiguous ACK write.
		return
	}
	WriteFrame(conn, response)
}
func isTimeout(err error) bool { var n net.Error; return errors.As(err, &n) && n.Timeout() }
func unixChannelOpen(conn *net.UnixConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	open := false
	err = raw.Control(func(fd uintptr) {
		var one [1]byte
		_, _, e := syscall.Recvfrom(int(fd), one[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		// syscall reports n=-1 on EAGAIN; the errno alone means no pending data.
		open = e == syscall.EAGAIN || e == syscall.EWOULDBLOCK
	})
	return err == nil && open
}
func requestErrorCode(err error) string {
	switch err.Error() {
	case "artifact_frame_invalid", "artifact_frame_oversized", "artifact_request_invalid":
		return err.Error()
	}
	return "artifact_request_invalid"
}
func (s *UnixServer) writeError(conn *net.UnixConn, code string) {
	conn.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))
	b, _ := json.Marshal(struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		ErrorCode     string `json:"error_code"`
	}{1, "failed", code})
	WriteFrame(conn, b)
}

// Close fences active channels and cancels their contexts without waiting for
// an uncooperative handler/provider. Only the exact socket created here may be
// removed. Same-UID/privileged directory writers remain trusted.
func (s *UnixServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.listener.Close()
	for conn, cancel := range s.connections {
		cancel()
		conn.Close()
	}
	var result error
	if s.socket != nil {
		current, stat, err := socketMetadata(s.directory, s.name)
		if err == nil {
			current.Close()
			if stat.Dev == s.socketStat.Dev && stat.Ino == s.socketStat.Ino && stat.Uid == s.socketStat.Uid && privateSocket(stat) {
				if syscall.Unlinkat(int(s.directory.Fd()), s.name) != nil || s.directory.Sync() != nil {
					result = fail("artifact_socket_cleanup_failed")
				}
			} else {
				result = fail("artifact_socket_changed")
			}
		} else if err != syscall.ENOENT {
			result = fail("artifact_socket_changed")
		}
		s.socket.Close()
	}
	s.directory.Close()
	return result
}

// CallUnix keeps the request channel open until one bounded response and EOF.
// The trusted socket directory/server must have the caller's UID and private
// modes. No CloseWrite or arbitrary file reference travels over this protocol.
func CallUnix(ctx context.Context, socket string, request Request) ([]byte, error) {
	if ctx == nil {
		return nil, fail("artifact_client_context_invalid")
	}
	path, name, err := unixName(socket)
	if err != nil {
		return nil, err
	}
	directory, err := unixExistingDirectory(path)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	metadata, stat, err := socketMetadata(directory, name)
	if err != nil {
		return nil, fail("artifact_socket_unsafe")
	}
	defer metadata.Close()
	if !privateSocket(stat) {
		return nil, fail("artifact_socket_unsafe")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, fail("artifact_request_invalid")
	}
	var frame bytes.Buffer
	if WriteFrame(&frame, raw) != nil {
		return nil, fail("artifact_request_invalid")
	}
	if _, err := ReadRequest(bytes.NewReader(frame.Bytes())); err != nil {
		return nil, err
	}
	bounded, stop := context.WithTimeout(ctx, time.Hour)
	defer stop()
	deadline, _ := bounded.Deadline()
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(bounded, "unix", fdPath(directory)+"/"+name)
	if err != nil {
		return nil, fail("artifact_client_connect_failed")
	}
	defer connection.Close()
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, fail("artifact_client_connect_failed")
	}
	uid, err := peerUID(conn)
	if err != nil || uid != uint32(os.Geteuid()) {
		return nil, fail("artifact_peer_forbidden")
	}
	stopClose := context.AfterFunc(bounded, func() { conn.Close() })
	defer stopClose()
	if conn.SetDeadline(deadline) != nil {
		return nil, fail("artifact_client_deadline_failed")
	}
	if WriteFrame(conn, raw) != nil {
		return nil, fail("artifact_client_write_failed")
	}
	response, err := readUnixFrame(conn)
	if err != nil {
		return nil, err
	}
	var extra [1]byte
	n, err := conn.Read(extra[:])
	if n != 0 || err != io.EOF {
		return nil, fail("artifact_response_trailing")
	}
	return response, nil
}
func readUnixFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, fail("artifact_response_invalid")
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxFrameBytes {
		return nil, fail("artifact_response_oversized")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fail("artifact_response_invalid")
	}
	return data, nil
}
func unixExistingDirectory(path string) (*os.File, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail("artifact_directory_unsafe")
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		child, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, fail("artifact_directory_unsafe")
		}
		fd = child
	}
	directory := os.NewFile(uintptr(fd), "artifact-client-directory")
	if !safeInfo(directory, true) {
		directory.Close()
		return nil, fail("artifact_directory_unsafe")
	}
	return directory, nil
}

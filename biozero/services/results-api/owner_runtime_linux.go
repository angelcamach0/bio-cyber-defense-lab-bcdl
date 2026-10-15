//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func selectOwnerResults(lookup func(string) (string, bool)) (bool, string, error) {
	protocol, _ := lookup("BIOZERO_RESULTS_PROTOCOL")
	path, present := lookup("BIOZERO_OWNER_RESULTS_CONFIG")
	switch protocol {
	case "", "legacy":
		if present {
			return true, "", ownerResultsError("owner_results_selector_invalid")
		}
		return false, "", nil
	case "owner-v1":
		if !present || !ownerResultsPath(path) {
			return true, "", ownerResultsError("owner_results_selector_invalid")
		}
		for _, key := range []string{"BIOZERO_DATA_DIR", "BIOZERO_RESULTS_ADDR", "BIOZERO_TLS_CERT", "BIOZERO_TLS_KEY", "BIOZERO_TLS_CA", "BIOZERO_RATE_LIMIT", "BIOZERO_SECURITY_MODE"} {
			if _, ok := lookup(key); ok {
				return true, "", ownerResultsError("owner_results_selector_mixed")
			}
		}
		return true, path, nil
	default:
		return true, "", ownerResultsError("owner_results_selector_invalid")
	}
}

// Called before any legacy environment handling, directory creation or handler
// registration. An owner configuration failure cannot enter the legacy route.
func ownerResultsMain() (bool, int) {
	handled, path, err := selectOwnerResults(os.LookupEnv)
	if !handled {
		return false, 0
	}
	if err != nil || len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "owner_results_start_failed")
		return true, 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := runOwnerResults(ctx, path); err != nil {
		fmt.Fprintln(os.Stderr, "owner_results_service_failed")
		return true, 1
	}
	return true, 0
}

type ownerResultsLimitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *ownerResultsLimitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

type ownerResultsLimitedListener struct {
	net.Listener
	slots chan struct{}
	once  sync.Once
	err   error
}

func (l *ownerResultsLimitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &ownerResultsLimitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}
func (l *ownerResultsLimitedListener) Close() error {
	l.once.Do(func() { l.err = l.Listener.Close() })
	return l.err
}

type ownerResultsService struct {
	server    *http.Server
	listener  *ownerResultsLimitedListener
	handler   *ownerResultsHandler
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	started   bool
	done      chan struct{}
	terminal  error
	closeOnce sync.Once
	closeErr  error
}

func newOwnerResultsService(ctx context.Context, listener net.Listener, m ownerResultsMaterial) (*ownerResultsService, error) {
	if ctx == nil || listener == nil || m.tls == nil || m.tls.MinVersion != tls.VersionTLS13 || m.tls.MaxVersion != tls.VersionTLS13 || m.tls.ClientAuth != tls.RequireAndVerifyClientCert {
		return nil, ownerResultsError("owner_results_service_invalid")
	}
	h, err := newOwnerResultsHandler(m)
	if err != nil {
		return nil, err
	}
	owned, cancel := context.WithCancel(ctx)
	l := &ownerResultsLimitedListener{Listener: listener, slots: make(chan struct{}, 4)}
	s := &ownerResultsService{listener: l, handler: h, ctx: owned, cancel: cancel, done: make(chan struct{})}
	s.server = &http.Server{Handler: h, TLSConfig: m.tls.Clone(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return owned }, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		if tc, ok := c.(*tls.Conn); ok {
			return context.WithValue(ctx, ownerResultsConnectionKey{}, tc)
		}
		return ctx
	}, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	return s, nil
}

func (s *ownerResultsService) Serve() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return ownerResultsError("owner_results_service_invalid")
	}
	s.started = true
	s.mu.Unlock()
	defer close(s.done)
	err := s.server.Serve(tls.NewListener(s.listener, s.server.TLSConfig))
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	s.mu.Lock()
	if s.terminal == nil {
		s.terminal = err
	}
	result := s.terminal
	s.mu.Unlock()
	return result
}

// Shutdown cancels only read contexts, stops admission and joins HTTP handlers
// before closing the authorization directory. It has no execution mutation RPC.
func (s *ownerResultsService) Shutdown(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.cancel()
		remember := func(err error) {
			if s.closeErr == nil && err != nil {
				s.closeErr = err
			}
		}
		remember(s.server.Shutdown(ctx))
		if s.closeErr != nil {
			s.server.Close()
			return
		}
		remember(s.listener.Close())
		s.mu.Lock()
		started := s.started
		s.mu.Unlock()
		if started {
			select {
			case <-s.done:
			case <-ctx.Done():
				remember(ownerResultsError("owner_results_shutdown_pending"))
				return
			}
		}
		s.mu.Lock()
		terminal := s.terminal
		s.mu.Unlock()
		remember(terminal)
		remember(s.handler.Close())
	})
	return s.closeErr
}

func runOwnerResults(ctx context.Context, path string) error {
	m, err := loadOwnerResultsConfig(ctx, path)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", m.config.Address)
	if err != nil {
		return ownerResultsError("owner_results_listen_failed")
	}
	s, err := newOwnerResultsService(ctx, listener, m)
	if err != nil {
		listener.Close()
		return err
	}
	return serveOwnerResults(ctx, s)
}

// Always join the goroutine launched here, including cancellation before its
// first instruction. Shutdown's started snapshot alone cannot establish that.
func serveOwnerResults(ctx context.Context, s *ownerResultsService) error {
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	var result error
	collected := false
	select {
	case result = <-served:
		collected = true
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(shutdown); result == nil {
		result = err
	}
	if !collected {
		if err := <-served; result == nil {
			result = err
		}
	}
	return result
}

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
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func selectOwnerGateway(lookup func(string) (string, bool)) (bool, string, error) {
	protocol, _ := lookup("BIOZERO_REVIEWER_PROTOCOL")
	path, present := lookup("BIOZERO_OWNER_REVIEWER_CONFIG")
	legacy, legacyPresent := lookup("BIOZERO_REVIEWER_CONFIG")
	_ = legacy
	switch protocol {
	case "", "legacy":
		if present {
			return true, "", errors.New("owner_gateway_selector_invalid")
		}
		return false, "", nil
	case "owner-v1":
		if !present || !filepath.IsAbs(path) || filepath.Clean(path) != path || legacyPresent {
			return true, "", errors.New("owner_gateway_selector_invalid")
		}
		return true, path, nil
	default:
		return true, "", errors.New("owner_gateway_selector_invalid")
	}
}

// This selection runs before legacy configuration or filesystem access.
func ownerGatewayMain() (bool, int) {
	handled, path, err := selectOwnerGateway(os.LookupEnv)
	if !handled {
		return false, 0
	}
	initialize := len(os.Args) == 2 && os.Args[1] == "--init-owner-gateway"
	if err != nil || !(len(os.Args) == 1 || initialize) {
		fmt.Fprintln(os.Stderr, "owner_gateway_start_failed")
		return true, 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err = runOwnerGateway(ctx, path, initialize); err != nil {
		fmt.Fprintln(os.Stderr, "owner_gateway_service_failed")
		return true, 1
	}
	return true, 0
}

type ogLimitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *ogLimitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }

type ogLimitedListener struct {
	net.Listener
	slots chan struct{}
	once  sync.Once
	err   error
}

func (l *ogLimitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			return &ogLimitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}
func (l *ogLimitedListener) Close() error {
	l.once.Do(func() { l.err = l.Listener.Close() })
	return l.err
}

type ownerGatewayService struct {
	gateway   *ownerGateway
	server    *http.Server
	listener  *ogLimitedListener
	mu        sync.Mutex
	started   bool
	terminal  error
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newOwnerGatewayService(ctx context.Context, listener net.Listener, m ownerGatewayMaterial, store ownerGatewayHTTPStore) (*ownerGatewayService, error) {
	if listener == nil || m.BrowserTLS == nil || m.BrowserTLS.MinVersion != tls.VersionTLS13 || m.BrowserTLS.MaxVersion != tls.VersionTLS13 || m.BrowserTLS.ClientAuth != tls.NoClientCert {
		return nil, errors.New("owner_gateway_service_invalid")
	}
	g, err := newOwnerGateway(ctx, m, store)
	if err != nil {
		return nil, err
	}
	l := &ogLimitedListener{Listener: listener, slots: make(chan struct{}, 8)}
	s := &ownerGatewayService{gateway: g, listener: l, done: make(chan struct{})}
	s.server = &http.Server{Handler: g, TLSConfig: m.BrowserTLS.Clone(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return g.serviceCtx }, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	return s, nil
}
func (s *ownerGatewayService) Serve() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("owner_gateway_serve_duplicate")
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
func (s *ownerGatewayService) Shutdown(ctx context.Context) error {
	s.closeOnce.Do(func() {
		remember := func(e error) {
			if s.closeErr == nil && e != nil {
				s.closeErr = e
			}
		}
		// Stopping is serialized against Intent+enqueue. Logout never takes this path.
		s.gateway.mu.Lock()
		s.gateway.stopping = true
		close(s.gateway.queue)
		s.gateway.cancel()
		s.gateway.mu.Unlock()
		httpErr := s.server.Shutdown(ctx)
		remember(httpErr)
		if httpErr != nil {
			remember(s.server.Close())
		}
		remember(s.listener.Close())
		s.mu.Lock()
		started := s.started
		s.mu.Unlock()
		if started {
			select {
			case <-s.done:
			case <-ctx.Done():
				remember(errors.New("owner_gateway_shutdown_pending"))
				return
			}
		}
		drained := make(chan struct{})
		go func() { s.gateway.workers.Wait(); close(drained) }()
		select {
		case <-drained:
		case <-ctx.Done():
			remember(errors.New("owner_gateway_shutdown_pending"))
			return
		}
		s.mu.Lock()
		remember(s.terminal)
		s.mu.Unlock()
		// A failed HTTP drain may leave a trusted history read blocked in a handler.
		// Do not close custody while such an authority can still be in use.
		if httpErr != nil {
			return
		}
		remember(s.gateway.store.Close())
		for _, reviewer := range s.gateway.material.Reviewers {
			if reviewer.Results != nil {
				remember(reviewer.Results.Close())
			}
		}
	})
	return s.closeErr
}
func serveOwnerGateway(ctx context.Context, s *ownerGatewayService) error {
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
	// Join the goroutine even if cancellation won before Serve entered.
	if !collected {
		if err := <-served; result == nil {
			result = err
		}
	}
	return result
}
func runOwnerGateway(ctx context.Context, path string, initialize bool) error {
	m, err := loadOwnerGatewayConfig(ctx, path)
	if err != nil {
		return err
	}
	if initialize {
		if err = initializeOwnerGatewayStore(ctx, m); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, `{"schema_version":1,"state":"initialized"}`)
		return nil
	}
	store, err := openOwnerGatewayStore(ctx, m)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", m.Config.ListenAddress)
	if err != nil {
		store.Close()
		return errors.New("owner_gateway_listen_failed")
	}
	service, err := newOwnerGatewayService(ctx, listener, m, store)
	if err != nil {
		listener.Close()
		store.Close()
		return err
	}
	fmt.Fprintln(os.Stdout, `{"schema_version":1,"state":"owner_gateway_ready"}`)
	return serveOwnerGateway(ctx, service)
}

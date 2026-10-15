//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const AuthorityServiceConfigLimit = 64 << 10
const AuthorityServiceShutdownBudget = 5 * time.Second
const authorityServiceConnections = 8

type AuthorityServiceAsset struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// All wire fields are mandatory. Load seals material in private memory; changing
// a loaded configuration is rejected rather than silently reloading any asset.
type AuthorityServiceConfig struct {
	SchemaVersion          int                   `json:"schema_version"`
	ListenAddress          string                `json:"listen_address"`
	StoreRoot              string                `json:"store_root"`
	Namespace              string                `json:"namespace"`
	AuthorityID            string                `json:"authority_id"`
	PublicKeyHex           string                `json:"public_key_hex"`
	PipelineMode           string                `json:"pipeline_mode"`
	ExecutionProfileSHA256 string                `json:"execution_profile_sha256"`
	SigningKey             AuthorityServiceAsset `json:"signing_key"`
	TLSCertificate         AuthorityServiceAsset `json:"tls_certificate"`
	TLSPrivateKey          AuthorityServiceAsset `json:"tls_private_key"`
	ClientCA               AuthorityServiceAsset `json:"client_ca"`
	Policy                 StorePolicy           `json:"policy"`
	ExpectedScope          AcceptanceScope       `json:"expected_scope"`
	loaded                 *authorityServiceMaterial
}

// Separate closed wire shape keeps private material out of both reflection
// validation and JSON. Ordinary marshaling of the public config omits loaded.
type authorityServiceWire struct {
	SchemaVersion          int                   `json:"schema_version"`
	ListenAddress          string                `json:"listen_address"`
	StoreRoot              string                `json:"store_root"`
	Namespace              string                `json:"namespace"`
	AuthorityID            string                `json:"authority_id"`
	PublicKeyHex           string                `json:"public_key_hex"`
	PipelineMode           string                `json:"pipeline_mode"`
	ExecutionProfileSHA256 string                `json:"execution_profile_sha256"`
	SigningKey             AuthorityServiceAsset `json:"signing_key"`
	TLSCertificate         AuthorityServiceAsset `json:"tls_certificate"`
	TLSPrivateKey          AuthorityServiceAsset `json:"tls_private_key"`
	ClientCA               AuthorityServiceAsset `json:"client_ca"`
	Policy                 StorePolicy           `json:"policy"`
	ExpectedScope          AcceptanceScope       `json:"expected_scope"`
}

type authorityServiceMaterial struct {
	configSHA string
	key       ed25519.PrivateKey
	pin       AuthorityPin
	tls       *tls.Config
}

func authorityServicePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && utf8.ValidString(path) && !strings.ContainsAny(path, "\x00\r\n")
}
func authorityServiceOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
func (c AuthorityServiceConfig) shape() error {
	if c.SchemaVersion != 1 || !authorityServicePath(c.StoreRoot) || !nameValid(c.Namespace) || !hexValue(c.PublicKeyHex, 64) {
		return fail("ownership_service_config_invalid")
	}
	host, port, err := net.SplitHostPort(c.ListenAddress)
	ip, ipErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || !ip.IsLoopback() || ip.Zone() != "" || ip.String() != host || portErr != nil || number < 0 || number > 65535 || strconv.Itoa(number) != port {
		return fail("ownership_service_address_invalid")
	}
	public, _ := hex.DecodeString(c.PublicKeyHex)
	pin := AuthorityPin{c.AuthorityID, ed25519.PublicKey(public), c.PipelineMode, c.ExecutionProfileSHA256}
	if pin.validate() != nil || c.Policy.validate() != nil {
		return fail("ownership_service_config_invalid")
	}
	if c.ExpectedScope != (AcceptanceScope{}) {
		identity, _ := json.Marshal((StoreConfig{Namespace: c.Namespace, Pin: pin, Policy: c.Policy}).identity())
		if c.ExpectedScope.validate() != nil || c.ExpectedScope.PolicySHA256 != digest(identity) {
			return fail("ownership_service_scope_invalid")
		}
	}
	for _, asset := range []AuthorityServiceAsset{c.SigningKey, c.TLSCertificate, c.TLSPrivateKey, c.ClientCA} {
		if !authorityServicePath(asset.Path) || !hexValue(asset.SHA256, 64) || authorityServiceOverlap(asset.Path, c.StoreRoot) {
			return fail("ownership_service_asset_invalid")
		}
	}
	return nil
}

func readAuthorityServicePath(ctx context.Context, path string, limit int64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || !authorityServicePath(path) {
		return nil, fail("ownership_service_file_invalid")
	}
	dir, err := storeRoot(filepath.Dir(path), false)
	if err != nil {
		return nil, fail("ownership_service_file_unsafe")
	}
	defer dir.Close()
	raw, err := storeRead(dir, filepath.Base(path), limit)
	if err != nil {
		return nil, fail("ownership_service_file_unsafe")
	}
	if ctx.Err() != nil {
		return nil, fail("ownership_service_cancelled")
	}
	return raw, nil
}
func readAuthorityServiceAsset(ctx context.Context, asset AuthorityServiceAsset, limit int64) ([]byte, error) {
	raw, err := readAuthorityServicePath(ctx, asset.Path, limit)
	if err != nil {
		return nil, err
	}
	if digest(raw) != asset.SHA256 {
		return nil, fail("ownership_service_asset_mismatch")
	}
	return raw, nil
}
func authorityPEMCertificates(raw []byte, limit int) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}
	for len(bytes.TrimSpace(raw)) != 0 {
		if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fail("ownership_service_tls_invalid")
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) > 16<<10 {
			return nil, fail("ownership_service_tls_invalid")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fail("ownership_service_tls_invalid")
		}
		certs = append(certs, cert)
		if len(certs) > limit {
			return nil, fail("ownership_service_tls_invalid")
		}
		raw = rest
	}
	if len(certs) == 0 {
		return nil, fail("ownership_service_tls_invalid")
	}
	return certs, nil
}
func loadAuthorityServiceMaterial(ctx context.Context, c AuthorityServiceConfig) (*authorityServiceMaterial, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fail("ownership_service_cancelled")
	}
	if err := c.shape(); err != nil {
		return nil, err
	}
	wire, _ := json.Marshal(c)
	configSHA := digest(wire)
	if c.loaded != nil {
		if c.loaded.configSHA != configSHA {
			return nil, fail("ownership_service_config_changed")
		}
		return c.loaded, nil
	}
	key, err := readAuthorityServiceAsset(ctx, c.SigningKey, 64)
	if err != nil {
		return nil, err
	}
	public, _ := hex.DecodeString(c.PublicKeyHex)
	pin := AuthorityPin{c.AuthorityID, ed25519.PublicKey(public), c.PipelineMode, c.ExecutionProfileSHA256}
	if len(key) != 64 || !bytes.Equal(ed25519.NewKeyFromSeed(key[:32]), key) || !bytes.Equal(key[32:], public) {
		return nil, fail("ownership_service_signing_key_invalid")
	}
	certPEM, err := readAuthorityServiceAsset(ctx, c.TLSCertificate, 64<<10)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readAuthorityServiceAsset(ctx, c.TLSPrivateKey, 64<<10)
	if err != nil {
		return nil, err
	}
	caPEM, err := readAuthorityServiceAsset(ctx, c.ClientCA, 64<<10)
	if err != nil {
		return nil, err
	}
	certs, err := authorityPEMCertificates(certPEM, 8)
	if err != nil {
		return nil, err
	}
	caCerts, err := authorityPEMCertificates(caPEM, 16)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || len(block.Headers) != 0 || (block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY") || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(bytes.TrimSpace(keyPEM), []byte("-----BEGIN "+block.Type+"-----")) {
		return nil, fail("ownership_service_tls_invalid")
	}
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fail("ownership_service_tls_invalid")
	}
	leaf := certs[0]
	rsaKey, ok := leaf.PublicKey.(*rsa.PublicKey)
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	now := time.Now()
	if !ok || rsaKey.N == nil || rsaKey.N.BitLen() < 2048 || rsaKey.N.BitLen() > 4096 || rsaKey.E != 65537 || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !serverAuth {
		return nil, fail("ownership_service_tls_invalid")
	}
	for _, cert := range append(certs, caCerts...) {
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return nil, fail("ownership_service_tls_invalid")
		}
	}
	pool := x509.NewCertPool()
	for _, cert := range caCerts {
		if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fail("ownership_service_tls_invalid")
		}
		pool.AddCert(cert)
	}
	serverCert.Leaf = leaf
	return &authorityServiceMaterial{configSHA, ed25519.PrivateKey(key), pin, &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}}, nil
}

// Load validates private anchored files and pins without creating a store or
// listener. All material is cached privately and never reread by Serve.
func LoadAuthorityServiceConfig(ctx context.Context, path string) (AuthorityServiceConfig, error) {
	var zero AuthorityServiceConfig
	raw, err := readAuthorityServicePath(ctx, path, AuthorityServiceConfigLimit)
	if err != nil {
		return zero, err
	}
	var wire authorityServiceWire
	if err = decodeStoreJSON(raw, &wire); err != nil {
		return zero, fail("ownership_service_config_invalid")
	}
	var config AuthorityServiceConfig
	if json.Unmarshal(raw, &config) != nil {
		return zero, fail("ownership_service_config_invalid")
	}
	if authorityServiceOverlap(path, config.StoreRoot) {
		return zero, fail("ownership_service_config_overlap")
	}
	config.loaded, err = loadAuthorityServiceMaterial(ctx, config)
	if err != nil {
		return zero, err
	}
	return config, nil
}

func (c AuthorityServiceConfig) storeConfig(m *authorityServiceMaterial) StoreConfig {
	return StoreConfig{Directory: c.StoreRoot, Namespace: c.Namespace, Pin: m.pin, SigningKey: m.key, Policy: c.Policy, ExpectedScope: c.ExpectedScope}
}

// InitializeAuthorityStore never starts ingress and never opens existing history.
// Its returned scope must be pinned externally before a separate service start.
func InitializeAuthorityStore(ctx context.Context, c AuthorityServiceConfig) (AcceptanceScope, error) {
	if c.ExpectedScope != (AcceptanceScope{}) {
		return AcceptanceScope{}, fail("ownership_service_scope_invalid")
	}
	m, err := loadAuthorityServiceMaterial(ctx, c)
	if err != nil {
		return AcceptanceScope{}, err
	}
	s, err := CreateStore(c.storeConfig(m))
	if err != nil {
		return AcceptanceScope{}, err
	}
	scope := s.Scope()
	if err = s.Close(); err != nil {
		return AcceptanceScope{}, err
	}
	return scope, nil
}

type authorityLimitedListener struct {
	net.Listener
	slots    chan struct{}
	done     chan struct{}
	once     sync.Once
	closeErr error
}
type authorityLimitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *authorityLimitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *authorityLimitedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &authorityLimitedConn{Conn: c, release: func() { <-l.slots }}, nil
}
func (l *authorityLimitedListener) Close() error {
	l.once.Do(func() { close(l.done); l.closeErr = l.Listener.Close() })
	return l.closeErr
}

type authorityTransportLog struct{}

func (authorityTransportLog) Write(p []byte) (int, error) {
	_, err := fmt.Fprintln(os.Stderr, "ownership_service_transport_error")
	return len(p), err
}

// AuthorityService retains any uncertain store custody. Shutdown never clears
// history, retries startup, or closes Store while a handler can still use it.
type AuthorityService struct {
	mu                        sync.Mutex
	shutdownGate              chan struct{}
	store                     *Store
	handler                   *AuthorityHTTPHandler
	server                    *http.Server
	listener                  *authorityLimitedListener
	cancel                    context.CancelFunc
	base                      context.Context
	started, stopping, closed bool
	serveDone                 chan struct{}
	terminalErr               error
}

func OpenAuthorityService(ctx context.Context, c AuthorityServiceConfig) (*AuthorityService, error) {
	if c.ExpectedScope == (AcceptanceScope{}) {
		return nil, fail("ownership_service_scope_invalid")
	}
	m, err := loadAuthorityServiceMaterial(ctx, c)
	if err != nil {
		return nil, err
	}
	s := &AuthorityService{serveDone: make(chan struct{}), shutdownGate: make(chan struct{}, 1)}
	s.base, s.cancel = context.WithCancel(ctx)
	s.store, err = OpenStore(c.storeConfig(m))
	if err != nil {
		s.cancel()
		return nil, err
	}
	cleanup := func(cause error) (*AuthorityService, error) {
		s.cancel()
		if s.handler != nil {
			s.handler.StopAdmission()
		}
		if s.store.Close() != nil {
			return s, cause
		}
		return nil, cause
	}
	s.handler, err = NewHTTPHandler(HTTPHandlerConfig{Store: s.store})
	if err != nil {
		return cleanup(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", c.ListenAddress)
	if err != nil {
		return cleanup(fail("ownership_service_listen_failed"))
	}
	s.listener = &authorityLimitedListener{Listener: listener, slots: make(chan struct{}, authorityServiceConnections), done: make(chan struct{})}
	s.server = &http.Server{Handler: s.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: m.tls.Clone(), TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ErrorLog: log.New(authorityTransportLog{}, "", 0), BaseContext: func(net.Listener) context.Context { return s.base }}
	return s, nil
}
func (s *AuthorityService) Addr() net.Addr {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}
func (s *AuthorityService) StoreScope() AcceptanceScope {
	if s == nil || s.store == nil {
		return AcceptanceScope{}
	}
	return s.store.Scope()
}
func (s *AuthorityService) stopAdmission() { s.handler.StopAdmission(); s.cancel(); s.listener.Close() }
func (s *AuthorityService) Serve(ctx context.Context) error {
	if s == nil || s.server == nil || ctx == nil {
		return fail("ownership_service_unavailable")
	}
	s.mu.Lock()
	if s.started || s.stopping || s.closed {
		s.mu.Unlock()
		return fail("ownership_service_unavailable")
	}
	s.started = true
	s.mu.Unlock()
	defer close(s.serveDone)
	stop := context.AfterFunc(ctx, s.stopAdmission)
	stopBase := context.AfterFunc(s.base, s.stopAdmission)
	defer stop()
	defer stopBase()
	err := s.server.Serve(tls.NewListener(s.listener, s.server.TLSConfig))
	cancelled := ctx.Err() != nil || s.base.Err() != nil
	s.stopAdmission()
	if err == nil || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) || cancelled {
		return nil
	}
	return fail("ownership_service_serve_failed")
}

// Shutdown uses a total budget of at most five seconds. One fifth is reserved
// for forced own-connection close and handler drain; expiry preserves custody.
func (s *AuthorityService) Shutdown(ctx context.Context) error {
	if s == nil || s.server == nil || ctx == nil {
		return fail("ownership_service_unavailable")
	}
	budget, cancel := context.WithTimeout(ctx, AuthorityServiceShutdownBudget)
	defer cancel()
	// A caller that never acquired shutdown ownership may time out without
	// changing the active shutdown's custody decision. It cannot block on a mutex.
	select {
	case s.shutdownGate <- struct{}{}:
		defer func() { <-s.shutdownGate }()
	case <-budget.Done():
		return fail("ownership_service_shutdown_wait_expired")
	}
	s.mu.Lock()
	if s.closed {
		err := s.terminalErr
		s.mu.Unlock()
		return err
	}
	s.stopping = true
	s.mu.Unlock()
	deadline, _ := budget.Deadline()
	remaining := time.Until(deadline)
	grace := remaining * 4 / 5
	s.stopAdmission()
	if err := s.listener.Close(); err != nil {
		s.remember(fail("ownership_service_close_failed"))
	}
	graceCtx, stopGrace := context.WithTimeout(budget, grace)
	shutdownErr := s.server.Shutdown(graceCtx)
	stopGrace()
	if shutdownErr != nil {
		if !errors.Is(shutdownErr, context.DeadlineExceeded) && !errors.Is(shutdownErr, context.Canceled) {
			s.remember(fail("ownership_service_close_failed"))
		}
		if s.server.Close() != nil {
			s.remember(fail("ownership_service_close_failed"))
		}
	}
	if err := s.handler.Wait(budget); err != nil {
		return s.remember(fail("ownership_service_pending"))
	}
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if started {
		select {
		case <-s.serveDone:
		case <-budget.Done():
			return s.remember(fail("ownership_service_pending"))
		}
	}
	s.mu.Lock()
	terminalErr := s.terminalErr
	s.mu.Unlock()
	if terminalErr != nil {
		return terminalErr
	}
	if err := s.store.Close(); err != nil {
		return s.remember(fail("ownership_service_pending"))
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return s.terminalErr
}
func (s *AuthorityService) remember(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminalErr == nil {
		s.terminalErr = err
	}
	return s.terminalErr
}

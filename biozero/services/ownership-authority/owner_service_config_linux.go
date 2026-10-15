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
	"strconv"
	"sync"
	"time"
)

const OwnerIngressServiceShutdownBudget = AuthorityServiceShutdownBudget

// OwnerIngressServiceConfig contains only public authority verification material
// and this transport endpoint's TLS assets. It cannot enroll signing/decrypt keys.
type OwnerIngressServiceConfig struct {
	SchemaVersion          int                   `json:"schema_version"`
	ListenAddress          string                `json:"listen_address"`
	StoreRoot              string                `json:"store_root"`
	Namespace              string                `json:"namespace"`
	AuthorityID            string                `json:"authority_id"`
	PublicKeyHex           string                `json:"public_key_hex"`
	PipelineMode           string                `json:"pipeline_mode"`
	ExecutionProfileSHA256 string                `json:"execution_profile_sha256"`
	ExpectedScope          AcceptanceScope       `json:"expected_scope"`
	Policy                 OwnerIngressPolicy    `json:"policy"`
	TLSCertificate         AuthorityServiceAsset `json:"tls_certificate"`
	TLSPrivateKey          AuthorityServiceAsset `json:"tls_private_key"`
	ClientCA               AuthorityServiceAsset `json:"client_ca"`
	loaded                 *ownerIngressServiceMaterial
}

// Separate closed shape prevents a private cache field from entering wire schema.
type ownerIngressServiceWire struct {
	SchemaVersion          int                   `json:"schema_version"`
	ListenAddress          string                `json:"listen_address"`
	StoreRoot              string                `json:"store_root"`
	Namespace              string                `json:"namespace"`
	AuthorityID            string                `json:"authority_id"`
	PublicKeyHex           string                `json:"public_key_hex"`
	PipelineMode           string                `json:"pipeline_mode"`
	ExecutionProfileSHA256 string                `json:"execution_profile_sha256"`
	ExpectedScope          AcceptanceScope       `json:"expected_scope"`
	Policy                 OwnerIngressPolicy    `json:"policy"`
	TLSCertificate         AuthorityServiceAsset `json:"tls_certificate"`
	TLSPrivateKey          AuthorityServiceAsset `json:"tls_private_key"`
	ClientCA               AuthorityServiceAsset `json:"client_ca"`
}
type ownerIngressServiceMaterial struct {
	configSHA string
	pin       AuthorityPin
	tls       *tls.Config
}

func (c OwnerIngressServiceConfig) shape() error {
	if c.SchemaVersion != 1 || !authorityServicePath(c.StoreRoot) || !nameValid(c.Namespace) || !hexValue(c.PublicKeyHex, 64) || c.ExpectedScope.validate() != nil || c.Policy.validate() != nil {
		return fail("ownership_ingress_service_config_invalid")
	}
	host, port, err := net.SplitHostPort(c.ListenAddress)
	ip, ipErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || !ip.IsLoopback() || ip.Zone() != "" || ip.String() != host || portErr != nil || number < 0 || number > 65535 || strconv.Itoa(number) != port {
		return fail("ownership_ingress_service_address_invalid")
	}
	public, _ := hex.DecodeString(c.PublicKeyHex)
	pin := AuthorityPin{c.AuthorityID, ed25519.PublicKey(public), c.PipelineMode, c.ExecutionProfileSHA256}
	if pin.validate() != nil {
		return fail("ownership_ingress_service_config_invalid")
	}
	for _, asset := range []AuthorityServiceAsset{c.TLSCertificate, c.TLSPrivateKey, c.ClientCA} {
		if !authorityServicePath(asset.Path) || !hexValue(asset.SHA256, 64) || authorityServiceOverlap(asset.Path, c.StoreRoot) {
			return fail("ownership_ingress_service_asset_invalid")
		}
	}
	return nil
}
func loadOwnerIngressMaterial(ctx context.Context, c OwnerIngressServiceConfig) (*ownerIngressServiceMaterial, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fail("ownership_ingress_service_cancelled")
	}
	if err := c.shape(); err != nil {
		return nil, err
	}
	wire, _ := json.Marshal(c)
	configSHA := digest(wire)
	if c.loaded != nil {
		if c.loaded.configSHA != configSHA {
			return nil, fail("ownership_ingress_service_config_changed")
		}
		return c.loaded, nil
	}
	public, _ := hex.DecodeString(c.PublicKeyHex)
	pin := AuthorityPin{c.AuthorityID, ed25519.PublicKey(public), c.PipelineMode, c.ExecutionProfileSHA256}
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
	return &ownerIngressServiceMaterial{configSHA, pin, &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}}, nil
}

// Load validates and caches private pinned assets, without creating/opening state
// or starting a listener. Serving never rereads key material from filesystem.
func LoadOwnerIngressServiceConfig(ctx context.Context, path string) (OwnerIngressServiceConfig, error) {
	var zero OwnerIngressServiceConfig
	raw, err := readAuthorityServicePath(ctx, path, AuthorityServiceConfigLimit)
	if err != nil {
		return zero, err
	}
	var wire ownerIngressServiceWire
	if decodeStoreJSON(raw, &wire) != nil {
		return zero, fail("ownership_ingress_service_config_invalid")
	}
	var c OwnerIngressServiceConfig
	if json.Unmarshal(raw, &c) != nil {
		return zero, fail("ownership_ingress_service_config_invalid")
	}
	if authorityServiceOverlap(path, c.StoreRoot) {
		return zero, fail("ownership_ingress_service_config_overlap")
	}
	c.loaded, err = loadOwnerIngressMaterial(ctx, c)
	if err != nil {
		return zero, err
	}
	return c, nil
}
func (c OwnerIngressServiceConfig) ingressConfig(m *ownerIngressServiceMaterial) OwnerIngressConfig {
	return OwnerIngressConfig{Directory: c.StoreRoot, Namespace: c.Namespace, Pin: m.pin, Scope: c.ExpectedScope, Policy: c.Policy}
}

// InitializeOwnerIngress creates only a new transport spool. The scope already
// belongs to the external authority; genesis never enrolls or changes that scope.
func InitializeOwnerIngress(ctx context.Context, c OwnerIngressServiceConfig) error {
	m, err := loadOwnerIngressMaterial(ctx, c)
	if err != nil {
		return err
	}
	s, err := CreateOwnerIngress(c.ingressConfig(m))
	if err != nil {
		return err
	}
	return s.Close()
}

type ownerIngressTransportLog struct{}

func (ownerIngressTransportLog) Write(p []byte) (int, error) {
	_, err := fmt.Fprintln(os.Stderr, "ownership_ingress_transport_error")
	return len(p), err
}

// OwnerIngressService drains only its own HTTP handlers/connections. Any terminal
// uncertainty keeps transport Store custody until this process actually exits.
type OwnerIngressService struct {
	mu                        sync.Mutex
	shutdownGate              chan struct{}
	store                     *OwnerIngressStore
	handler                   *OwnerIngressHandler
	server                    *http.Server
	listener                  *authorityLimitedListener
	cancel                    context.CancelFunc
	base                      context.Context
	started, stopping, closed bool
	serveDone                 chan struct{}
	terminalErr               error
}

func OpenOwnerIngressService(ctx context.Context, c OwnerIngressServiceConfig) (*OwnerIngressService, error) {
	if c.ExpectedScope == (AcceptanceScope{}) {
		return nil, fail("ownership_ingress_service_scope_invalid")
	}
	m, err := loadOwnerIngressMaterial(ctx, c)
	if err != nil {
		return nil, err
	}
	s := &OwnerIngressService{serveDone: make(chan struct{}), shutdownGate: make(chan struct{}, 1)}
	s.base, s.cancel = context.WithCancel(ctx)
	s.store, err = OpenOwnerIngress(c.ingressConfig(m))
	if err != nil {
		s.cancel()
		return nil, err
	}
	cleanup := func(cause error) (*OwnerIngressService, error) {
		s.cancel()
		if s.handler != nil {
			s.handler.StopAdmission()
		}
		if s.store.Close() != nil {
			return s, cause
		}
		return nil, cause
	}
	s.handler, err = NewOwnerIngressHandler(s.store)
	if err != nil {
		return cleanup(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", c.ListenAddress)
	if err != nil {
		return cleanup(fail("ownership_ingress_service_listen_failed"))
	}
	s.listener = &authorityLimitedListener{Listener: listener, slots: make(chan struct{}, authorityServiceConnections), done: make(chan struct{})}
	s.server = &http.Server{Handler: s.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: m.tls.Clone(), TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ErrorLog: log.New(ownerIngressTransportLog{}, "", 0), BaseContext: func(net.Listener) context.Context { return s.base }}
	return s, nil
}
func (s *OwnerIngressService) Addr() net.Addr {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}
func (s *OwnerIngressService) StoreScope() AcceptanceScope {
	if s == nil || s.store == nil {
		return AcceptanceScope{}
	}
	return s.store.config.Scope
}
func (s *OwnerIngressService) stopAdmission() {
	s.handler.StopAdmission()
	s.cancel()
	s.listener.Close()
}
func (s *OwnerIngressService) Serve(ctx context.Context) error {
	if s == nil || s.server == nil || ctx == nil {
		return fail("ownership_ingress_service_unavailable")
	}
	s.mu.Lock()
	if s.started || s.stopping || s.closed {
		s.mu.Unlock()
		return fail("ownership_ingress_service_unavailable")
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
	return fail("ownership_ingress_service_serve_failed")
}

// Shutdown uses a total budget of at most five seconds. One fifth is reserved
// for forced own-connection close and handler drain; expiry preserves custody.
func (s *OwnerIngressService) Shutdown(ctx context.Context) error {
	if s == nil || s.server == nil || ctx == nil {
		return fail("ownership_ingress_service_unavailable")
	}
	budget, cancel := context.WithTimeout(ctx, OwnerIngressServiceShutdownBudget)
	defer cancel()
	// A caller that never acquired shutdown ownership may time out without
	// changing the active shutdown's custody decision. It cannot block on a mutex.
	select {
	case s.shutdownGate <- struct{}{}:
		defer func() { <-s.shutdownGate }()
	case <-budget.Done():
		return fail("ownership_ingress_service_shutdown_wait_expired")
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
		s.remember(fail("ownership_ingress_service_close_failed"))
	}
	graceCtx, stopGrace := context.WithTimeout(budget, grace)
	shutdownErr := s.server.Shutdown(graceCtx)
	stopGrace()
	if shutdownErr != nil {
		if !errors.Is(shutdownErr, context.DeadlineExceeded) && !errors.Is(shutdownErr, context.Canceled) {
			s.remember(fail("ownership_ingress_service_close_failed"))
		}
		if s.server.Close() != nil {
			s.remember(fail("ownership_ingress_service_close_failed"))
		}
	}
	if err := s.handler.Wait(budget); err != nil {
		return s.remember(fail("ownership_ingress_service_pending"))
	}
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if started {
		select {
		case <-s.serveDone:
		case <-budget.Done():
			return s.remember(fail("ownership_ingress_service_pending"))
		}
	}
	s.mu.Lock()
	terminalErr := s.terminalErr
	s.mu.Unlock()
	if terminalErr != nil {
		return terminalErr
	}
	if err := s.store.Close(); err != nil {
		return s.remember(fail("ownership_ingress_service_pending"))
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return s.terminalErr
}
func (s *OwnerIngressService) remember(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminalErr == nil {
		s.terminalErr = err
	}
	return s.terminalErr
}

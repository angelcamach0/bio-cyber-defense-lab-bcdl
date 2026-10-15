//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

const PublicationServiceConfigLimit = 64 << 10
const PublicationServiceShutdownBudget = 5 * time.Second

type publicationServiceWire struct {
	SchemaVersion            int                   `json:"schema_version"`
	ListenAddress            string                `json:"listen_address"`
	StateDirectory           string                `json:"state_directory"`
	AuthorityID              string                `json:"authority_id"`
	PublicKeyHex             string                `json:"public_key_hex"`
	PipelineMode             string                `json:"pipeline_mode"`
	ExecutionProfileSHA256   string                `json:"execution_profile_sha256"`
	ExpectedAuthorityScope   AcceptanceScope       `json:"expected_authority_scope"`
	ExpectedPublisherScope   PublicationScope      `json:"expected_publisher_scope"`
	ProducerCredentialSHA256 []string              `json:"producer_credential_sha256"`
	TLSCertificate           AuthorityServiceAsset `json:"tls_certificate"`
	TLSPrivateKey            AuthorityServiceAsset `json:"tls_private_key"`
	ProducerCA               AuthorityServiceAsset `json:"producer_ca"`
}

// The unexported cache never participates in the closed public wire schema.
type PublicationServiceConfig struct {
	SchemaVersion            int                   `json:"schema_version"`
	ListenAddress            string                `json:"listen_address"`
	StateDirectory           string                `json:"state_directory"`
	AuthorityID              string                `json:"authority_id"`
	PublicKeyHex             string                `json:"public_key_hex"`
	PipelineMode             string                `json:"pipeline_mode"`
	ExecutionProfileSHA256   string                `json:"execution_profile_sha256"`
	ExpectedAuthorityScope   AcceptanceScope       `json:"expected_authority_scope"`
	ExpectedPublisherScope   PublicationScope      `json:"expected_publisher_scope"`
	ProducerCredentialSHA256 []string              `json:"producer_credential_sha256"`
	TLSCertificate           AuthorityServiceAsset `json:"tls_certificate"`
	TLSPrivateKey            AuthorityServiceAsset `json:"tls_private_key"`
	ProducerCA               AuthorityServiceAsset `json:"producer_ca"`
	loaded                   *publicationServiceMaterial
}
type publicationServiceMaterial struct {
	configSHA string
	pin       AuthorityPin
	tls       *tls.Config
}

func (c PublicationServiceConfig) transportConfig() OwnerIngressServiceConfig {
	return OwnerIngressServiceConfig{SchemaVersion: c.SchemaVersion, ListenAddress: c.ListenAddress, StoreRoot: c.StateDirectory, Namespace: "authorization-publication", AuthorityID: c.AuthorityID, PublicKeyHex: c.PublicKeyHex, PipelineMode: c.PipelineMode, ExecutionProfileSHA256: c.ExecutionProfileSHA256, ExpectedScope: c.ExpectedAuthorityScope, Policy: DefaultOwnerIngressPolicy(), TLSCertificate: c.TLSCertificate, TLSPrivateKey: c.TLSPrivateKey, ClientCA: c.ProducerCA}
}
func loadPublicationMaterial(ctx context.Context, c PublicationServiceConfig) (*publicationServiceMaterial, error) {
	if ctx == nil || ctx.Err() != nil || len(c.ProducerCredentialSHA256) < 1 || len(c.ProducerCredentialSHA256) > 16 {
		return nil, fail("ownership_publication_service_config_invalid")
	}
	if c.ExpectedPublisherScope != (PublicationScope{}) && c.ExpectedPublisherScope.validate() != nil {
		return nil, fail("ownership_publication_service_scope_invalid")
	}
	producers := append([]string(nil), c.ProducerCredentialSHA256...)
	sort.Strings(producers)
	for i, pin := range producers {
		if !hexValue(pin, 64) || i > 0 && pin == producers[i-1] {
			return nil, fail("ownership_publication_service_producer_invalid")
		}
	}
	if c.TLSCertificate.Path == c.TLSPrivateKey.Path || c.ProducerCA.Path == c.TLSPrivateKey.Path || c.ProducerCA.Path == c.TLSCertificate.Path {
		return nil, fail("ownership_publication_service_asset_invalid")
	}
	raw, _ := json.Marshal(c)
	hash := digest(raw)
	if c.loaded != nil {
		if c.loaded.configSHA != hash {
			return nil, fail("ownership_publication_service_config_changed")
		}
		return c.loaded, nil
	}
	// Reuse only the existing private asset/TLS parser. This helper opens no
	// ingress/store/socket and needs no signer, decrypt key or owner CA.
	transport, err := loadOwnerIngressMaterial(ctx, c.transportConfig())
	if err != nil {
		return nil, err
	}
	leaf := transport.tls.Certificates[0].Leaf
	for _, pin := range producers {
		if digest(leaf.Raw) == pin {
			return nil, fail("ownership_publication_service_key_role_invalid")
		}
	}
	serverKey := leaf.PublicKey.(*rsa.PublicKey)
	tlsConfig := transport.tls.Clone()
	tlsConfig.MaxVersion = tls.VersionTLS13
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return fail("ownership_publication_denied")
		}
		peer, ok := state.PeerCertificates[0].PublicKey.(*rsa.PublicKey)
		if !ok || peer.N == nil || peer.N.Cmp(serverKey.N) == 0 && peer.E == serverKey.E {
			return fail("ownership_publication_role_invalid")
		}
		return nil
	}
	return &publicationServiceMaterial{hash, transport.pin, tlsConfig}, nil
}
func LoadPublicationServiceConfig(ctx context.Context, path string) (PublicationServiceConfig, error) {
	var zero PublicationServiceConfig
	raw, err := readAuthorityServicePath(ctx, path, PublicationServiceConfigLimit)
	if err != nil {
		return zero, err
	}
	var wire publicationServiceWire
	if decodeStoreJSON(raw, &wire) != nil {
		return zero, fail("ownership_publication_service_config_invalid")
	}
	var c PublicationServiceConfig
	if json.Unmarshal(raw, &c) != nil || authorityServiceOverlap(path, c.StateDirectory) {
		return zero, fail("ownership_publication_service_config_invalid")
	}
	c.loaded, err = loadPublicationMaterial(ctx, c)
	if err != nil {
		return zero, err
	}
	return c, nil
}
func (c PublicationServiceConfig) storeConfig(m *publicationServiceMaterial) PublicationStoreConfig {
	return PublicationStoreConfig{Directory: c.StateDirectory, Pin: m.pin, AuthorityScope: c.ExpectedAuthorityScope, ExpectedPublisherScope: c.ExpectedPublisherScope, ProducerCredentialSHA256: append([]string(nil), c.ProducerCredentialSHA256...)}
}
func InitializePublicationStore(ctx context.Context, c PublicationServiceConfig) (PublicationScope, error) {
	if c.ExpectedPublisherScope != (PublicationScope{}) {
		return PublicationScope{}, fail("ownership_publication_service_scope_invalid")
	}
	m, err := loadPublicationMaterial(ctx, c)
	if err != nil {
		return PublicationScope{}, err
	}
	store, err := CreatePublicationStore(c.storeConfig(m))
	if err != nil {
		return PublicationScope{}, err
	}
	scope := store.Scope()
	if err = store.Close(); err != nil {
		return PublicationScope{}, err
	}
	return scope, nil
}

type PublicationService struct {
	mu                sync.Mutex
	store             *PublicationStore
	handler           *PublicationHTTPHandler
	listener          *authorityLimitedListener
	server            *http.Server
	base              context.Context
	cancel            context.CancelFunc
	started, stopping bool
	done              chan struct{}
	terminal          error
	closeOnce         sync.Once
	closeErr          error
}

func OpenPublicationService(ctx context.Context, c PublicationServiceConfig) (*PublicationService, error) {
	if c.ExpectedPublisherScope.validate() != nil {
		return nil, fail("ownership_publication_service_scope_invalid")
	}
	m, err := loadPublicationMaterial(ctx, c)
	if err != nil {
		return nil, err
	}
	s := &PublicationService{done: make(chan struct{})}
	s.base, s.cancel = context.WithCancel(ctx)
	s.store, err = OpenPublicationStore(c.storeConfig(m))
	if err != nil {
		s.cancel()
		return nil, err
	}
	cleanup := func(cause error) (*PublicationService, error) {
		s.cancel()
		if s.store.Close() != nil {
			return s, cause
		}
		return nil, cause
	}
	s.handler, err = NewPublicationHTTPHandler(s.store, m.pin, c.ExpectedAuthorityScope)
	if err != nil {
		return cleanup(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", c.ListenAddress)
	if err != nil {
		return cleanup(fail("ownership_publication_service_listen_failed"))
	}
	s.listener = &authorityLimitedListener{Listener: listener, slots: make(chan struct{}, 8), done: make(chan struct{})}
	s.server = &http.Server{Handler: s.handler, TLSConfig: m.tls.Clone(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return s.base }, ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
		if actual, ok := conn.(*tls.Conn); ok {
			return context.WithValue(ctx, publicationConnectionKey{}, actual)
		}
		return ctx
	}, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ErrorLog: log.New(authorityTransportLog{}, "", 0)}
	return s, nil
}
func (s *PublicationService) Addr() net.Addr {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}
func (s *PublicationService) Scope() PublicationScope {
	if s == nil || s.store == nil {
		return PublicationScope{}
	}
	return s.store.Scope()
}
func (s *PublicationService) InboxDirectory() string {
	if s == nil || s.store == nil {
		return ""
	}
	return s.store.InboxDirectory()
}
func (s *PublicationService) remember(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal == nil {
		s.terminal = err
	}
	return s.terminal
}
func (s *PublicationService) stopAdmission() {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	s.handler.StopAdmission()
	s.cancel()
	if err := s.listener.Close(); err != nil {
		s.remember(fail("ownership_publication_service_close_failed"))
	}
}
func (s *PublicationService) Serve(ctx context.Context) error {
	if s == nil || s.server == nil || ctx == nil {
		return fail("ownership_publication_service_unavailable")
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fail("ownership_publication_service_unavailable")
	}
	s.started = true
	s.mu.Unlock()
	defer close(s.done)
	stop := context.AfterFunc(ctx, s.stopAdmission)
	stopBase := context.AfterFunc(s.base, s.stopAdmission)
	defer stop()
	defer stopBase()
	err := s.server.Serve(tls.NewListener(s.listener, s.server.TLSConfig))
	s.mu.Lock()
	expected := s.stopping || ctx.Err() != nil || s.base.Err() != nil
	s.mu.Unlock()
	if err != nil && !expected {
		s.remember(fail("ownership_publication_service_serve_failed"))
	}
	s.stopAdmission()
	return s.remember(nil)
}
func (s *PublicationService) Shutdown(ctx context.Context) error {
	if s == nil || s.store == nil || ctx == nil {
		return fail("ownership_publication_service_unavailable")
	}
	s.closeOnce.Do(func() {
		remember := func(err error) {
			if s.closeErr == nil && err != nil {
				s.closeErr = err
			}
		}
		budget, cancel := context.WithTimeout(ctx, PublicationServiceShutdownBudget)
		defer cancel()
		// Startup cleanup may retain a Store before a complete listener exists.
		if s.server == nil {
			remember(s.store.Close())
			return
		}
		s.stopAdmission()
		deadline, _ := budget.Deadline()
		grace, stop := context.WithDeadline(budget, time.Now().Add(time.Until(deadline)*4/5))
		shutdownErr := s.server.Shutdown(grace)
		stop()
		if shutdownErr != nil {
			if !errors.Is(shutdownErr, context.DeadlineExceeded) && !errors.Is(shutdownErr, context.Canceled) {
				remember(fail("ownership_publication_service_close_failed"))
			}
			if err := s.server.Close(); err != nil {
				remember(fail("ownership_publication_service_close_failed"))
			}
		}
		if err := s.handler.Wait(budget); err != nil {
			remember(err)
			return
		}
		s.mu.Lock()
		started := s.started
		s.mu.Unlock()
		if started {
			select {
			case <-s.done:
			case <-budget.Done():
				remember(fail("ownership_publication_service_pending"))
				return
			}
		}
		remember(s.remember(nil))
		// Close only after real handler+Serve drain. Transport errors stay local,
		// while Store.Close itself retains uncertain durable custody.
		remember(s.store.Close())
	})
	return s.closeErr
}

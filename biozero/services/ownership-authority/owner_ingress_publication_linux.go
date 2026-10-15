//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const OwnerIngressPublicationHeadroom int64 = 3*clientStepLimit + 64

// Optional only for legacy transport-spool.v1. Measured trust is supplied by
// the trusted service loader; direct callers must measure CA bytes themselves.
type OwnerIngressPublicationConfig struct {
	Client      PublicationClientConfig
	TrustSHA256 string
}

type ownerIngressPublicationChild struct {
	operation                      *PublicationOperation
	live, constructing, finalizing bool
	originalCipher                 os.FileInfo
}

type ownerIngressPublication struct {
	root     *os.File
	client   *PublicationClient
	children map[string]*ownerIngressPublicationChild
	base     context.Context
	baseSet  bool
	closeErr error
}

func snapshotOwnerIngressPublication(c OwnerIngressConfig) (OwnerIngressConfig, *ownerIngressPublication, error) {
	if c.Publication == nil || !hexValue(c.Publication.TrustSHA256, 64) {
		return c, nil, fail("ownership_ingress_publication_config_invalid")
	}
	client, err := NewPublicationClient(c.Publication.Client)
	if err != nil {
		return c, nil, err
	}
	t, ok := client.transport.client.Transport.(*http.Transport)
	if !ok || t.TLSClientConfig == nil || len(t.TLSClientConfig.Certificates) != 1 || client.transport.pin.AuthorityID != c.Pin.AuthorityID ||
		hex.EncodeToString(client.transport.pin.PublicKey) != hex.EncodeToString(c.Pin.PublicKey) || client.transport.pin.PipelineMode != c.Pin.PipelineMode ||
		client.transport.pin.ExecutionProfileSHA256 != c.Pin.ExecutionProfileSHA256 || client.transport.scope != c.Scope {
		client.CloseIdleConnections()
		return c, nil, fail("ownership_ingress_publication_config_invalid")
	}
	// This transport owns DER, RSA and CA copies. No mutable caller material is
	// retained and its private key is never marshalled into identity metadata.
	cfg := OwnerIngressPublicationConfig{TrustSHA256: c.Publication.TrustSHA256, Client: PublicationClientConfig{
		Client: AuthorityClientConfig{BaseURL: client.transport.base, Certificate: t.TLSClientConfig.Certificates[0], RootCAs: t.TLSClientConfig.RootCAs.Clone(),
			ServerName: t.TLSClientConfig.ServerName, Pin: client.transport.pin, Scope: client.transport.scope}, ExpectedPublisherScope: client.scope}}
	c.Publication = &cfg
	return c, &ownerIngressPublication{client: client, children: map[string]*ownerIngressPublicationChild{}, base: context.Background()}, nil
}

func (p *ownerIngressPublication) context(c OwnerIngressConfig) []byte {
	raw, _ := json.Marshal(struct {
		Directory, Namespace string
		Pin                  AuthorityPin
		Scope                AcceptanceScope
		Policy               OwnerIngressPolicy
		Publication          struct {
			SchemaVersion                                     int
			Endpoint, ServerName, TrustSHA256, ProducerSHA256 string
			PublisherScope                                    PublicationScope
			Headroom                                          int64
		}
	}{Directory: c.Directory, Namespace: c.Namespace, Pin: c.Pin, Scope: c.Scope, Policy: c.Policy, Publication: struct {
		SchemaVersion                                     int
		Endpoint, ServerName, TrustSHA256, ProducerSHA256 string
		PublisherScope                                    PublicationScope
		Headroom                                          int64
	}{
		1, p.client.transport.base, c.Publication.Client.Client.ServerName, c.Publication.TrustSHA256, digest(p.client.transport.leaf.Raw), p.client.scope, OwnerIngressPublicationHeadroom}})
	return raw
}

func (s *OwnerIngressStore) ingressCharge() int64 {
	charge := s.config.Policy.MaxBodyBytes + StoreMetadataHeadroom
	if s.publication != nil {
		charge += OwnerIngressPublicationHeadroom
	}
	return charge
}
func (s *OwnerIngressStore) ingressDirectories() map[string]*os.File {
	out := map[string]*os.File{"": s.root, "uploads": s.uploads, "jobs": s.jobs, "acceptances": s.acceptances}
	if s.publication != nil {
		out["publication"] = s.publication.root
	}
	return out
}
func (s *OwnerIngressStore) setPublicationBase(ctx context.Context) error {
	if s.publication == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || s.inflight != 0 || s.publication.baseSet {
		return fail("ownership_ingress_publication_context_invalid")
	}
	s.publication.base = ctx
	s.publication.baseSet = true
	return nil
}
func (s *OwnerIngressStore) checkPublicationOwner(v VerifiedAcceptance) error {
	if s.publication == nil {
		return nil
	}
	if !publicationProducerDistinct(v, s.publication.client.transport.leaf) {
		return fail("ownership_ingress_publication_role_invalid")
	}
	return nil
}
func (s *OwnerIngressStore) publicationRootNames(missing bool) error {
	names, err := ownerReadNames(s.root, 8)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, n := range names {
		switch n {
		case "instance.lock", "uploads", "jobs", "acceptances", "publication", "ledger.json":
			seen[n] = true
		case "transaction.pending", "ledger.next":
			return fail("ownership_ingress_pending")
		default:
			return fail("ownership_ingress_history_invalid")
		}
	}
	for _, n := range []string{"instance.lock", "uploads", "jobs", "acceptances", "publication"} {
		if !seen[n] {
			return fail("ownership_ingress_history_invalid")
		}
	}
	if !missing && !seen["ledger.json"] {
		return fail("ownership_ingress_history_invalid")
	}
	return nil
}
func (s *OwnerIngressStore) publicationOperationConfig(e ownerIngressEntry) PublicationOperationConfig {
	return PublicationOperationConfig{Directory: filepath.Join(s.config.Directory, "publication", e.JobID), Client: s.config.Publication.Client,
		Acceptance: []byte(e.AcceptanceJSON), TrustSHA256: s.config.Publication.TrustSHA256}
}
func (s *OwnerIngressStore) expectedPublication(v VerifiedAcceptance) PublicationReceipt {
	b := v.Binding()
	return PublicationReceipt{SchemaVersion: 1, Domain: PublicationReceiptDomain, State: "published", PublisherScope: s.publication.client.scope, AuthorityScope: s.config.Scope,
		JobID: b.JobID, AcceptanceSHA256: v.SHA256(), CredentialSHA256: b.CredentialSHA256, ExecutionProfileSHA256: b.ExecutionProfileSHA256, PipelineMode: b.PipelineMode}
}
func (s *OwnerIngressStore) openPublicationChildren() error {
	for _, e := range s.data.Records {
		if e.State != "delivered" {
			continue
		}
		op, err := OpenPublicationOperation(s.publicationOperationConfig(e))
		s.publication.children[e.JobID] = &ownerIngressPublicationChild{operation: op}
		if err != nil || op == nil {
			return s.latch()
		}
	}
	return s.checkPublicationChildren()
}
func (s *OwnerIngressStore) checkPublicationChildren() error {
	names, err := ownerReadNames(s.publication.root, 64)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, n := range names {
		if !hexValue(n, 16) {
			return fail("ownership_ingress_publication_history_invalid")
		}
		seen[n] = true
	}
	for _, e := range s.data.Records {
		child := s.publication.children[e.JobID]
		if e.State != "authorizing" && e.State != "delivered" {
			if seen[e.JobID] || child != nil {
				return fail("ownership_ingress_publication_history_invalid")
			}
			continue
		}
		if child == nil {
			return fail("ownership_ingress_publication_history_invalid")
		}
		if !seen[e.JobID] {
			if e.State == "authorizing" && child.live && child.constructing && child.operation == nil {
				continue
			}
			return fail("ownership_ingress_publication_history_invalid")
		}
		delete(seen, e.JobID)
		if child.operation == nil {
			return fail("ownership_ingress_publication_history_invalid")
		}
		err = child.operation.Check()
		if err != nil {
			if err.Error() == "ownership_publication_operation_busy" && e.State == "authorizing" && child.live && !child.constructing {
				continue
			}
			return err
		}
		if e.State == "delivered" || child.finalizing {
			// No owner can start network IO for a finalizing/published child.
			receipt, err := child.operation.Receipt()
			if err != nil || receipt != s.expectedPublication(s.accepted[e.JobID]) {
				return fail("ownership_ingress_publication_receipt_invalid")
			}
		} else if !child.live {
			return fail("ownership_ingress_pending")
		}
	}
	if len(seen) != 0 {
		return fail("ownership_ingress_publication_history_invalid")
	}
	return nil
}

// publicationFiles retains v1's cache boundary. It adds a visibility barrier:
// authorizing jobs/sidecars can exist only during our mutex-held final publish,
// after the retained published receipt is validated.
func (s *OwnerIngressStore) publicationFiles() error {
	for kind, dir := range map[string]*os.File{"uploads": s.uploads, "jobs": s.jobs, "acceptances": s.acceptances} {
		names, err := ownerReadNames(dir, 128)
		if err != nil {
			return err
		}
		expected := map[string]ownerIngressEntry{}
		for _, e := range s.data.Records {
			if kind == "uploads" {
				expected[e.JobID+"_"+s.accepted[e.JobID].Binding().OriginalName] = e
				continue
			}
			child := s.publication.children[e.JobID]
			if e.State == "delivered" || e.State == "authorizing" && child != nil && child.finalizing {
				expected[e.JobID+".json"] = e
				if kind == "jobs" && e.State == "authorizing" {
					expected[e.JobID+".pending"] = e
				}
			}
		}
		seen := map[string]bool{}
		for _, name := range names {
			e, ok := expected[name]
			if !ok {
				return fail("ownership_ingress_history_invalid")
			}
			f, err := storeFile(dir, name, false)
			if err != nil {
				return err
			}
			info, err := storeSafeFile(f)
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			limit := int64(MaxAcceptanceBytes)
			if kind == "uploads" {
				limit = s.accepted[e.JobID].Binding().CiphertextBytes
			}
			if info.Size() < 0 || info.Size() > limit {
				return fail("ownership_ingress_history_invalid")
			}
			if kind == "uploads" && e.State != "reading" && info.Size() != e.ReceivedBytes {
				return fail("ownership_ingress_history_invalid")
			}
			if kind == "acceptances" {
				raw, err := storeRead(dir, name, MaxAcceptanceBytes)
				if err != nil || digest(raw) != digest([]byte(e.AcceptanceJSON)) {
					return fail("ownership_ingress_history_invalid")
				}
			}
			seen[name] = true
		}
		for name, e := range expected {
			if (kind == "uploads" && e.State != "reading" || kind != "uploads" && e.State == "delivered") && !seen[name] {
				return fail("ownership_ingress_history_invalid")
			}
		}
	}
	return nil
}

func ownerIngressSameCipher(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	y, yes := b.Sys().(*syscall.Stat_t)
	return ok && yes && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}
func (s *OwnerIngressStore) recheckPublicationCipher(v VerifiedAcceptance, original os.FileInfo) (retErr error) {
	if original == nil {
		return fail("ownership_ingress_history_invalid")
	}
	b := v.Binding()
	name := b.JobID + "_" + b.OriginalName
	f, err := storeFile(s.uploads, name, false)
	if err != nil {
		return err
	}
	defer func() {
		if e := f.Close(); e != nil && retErr == nil {
			retErr = e
		}
	}()
	before, err := storeSafeFile(f)
	if err != nil || before.Size() != b.CiphertextBytes || !ownerIngressSameCipher(original, before) {
		return fail("ownership_ingress_history_invalid")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, b.CiphertextBytes+1))
	after, statErr := storeSafeFile(f)
	if err != nil || statErr != nil || n != b.CiphertextBytes || !ownerIngressSameCipher(before, after) || hex.EncodeToString(h.Sum(nil)) != b.CiphertextSHA256 {
		return fail("ownership_ingress_history_invalid")
	}
	fresh, err := storeFile(s.uploads, name, false)
	if err != nil {
		return err
	}
	freshInfo, statErr := storeSafeFile(fresh)
	closeErr := fresh.Close()
	if statErr != nil || closeErr != nil || !ownerIngressSameCipher(after, freshInfo) {
		return fail("ownership_ingress_history_invalid")
	}
	return nil
}

// Caller owns ingress.mu and its inflight/body slot for the complete method.
// Network is strictly outside ingress.mu; source cancellation is service-owned.
func (s *OwnerIngressStore) publishIngressAcceptanceLocked(i int, entry ownerIngressEntry, v VerifiedAcceptance, original os.FileInfo) (OwnerUploadReceipt, error) {
	var zero OwnerUploadReceipt
	child := &ownerIngressPublicationChild{live: true, constructing: true, originalCipher: original}
	if s.recheckPublicationCipher(v, original) != nil {
		return zero, s.latch()
	}
	entry.State = "authorizing"
	// No child path exists until authorizing is durable. Register immediately after
	// the ledger transition while holding ingress.mu, before any other preflight.
	if err := s.replace(i, entry); err != nil {
		return zero, err
	}
	s.publication.children[entry.JobID] = child
	if s.point("publication_create") != nil {
		return zero, s.latch()
	}
	op, err := CreatePublicationOperation(s.publicationOperationConfig(entry))
	child.operation = op
	child.constructing = false
	if err != nil || op == nil {
		return zero, s.latch()
	}
	if s.point("publication_intent_durable") != nil {
		return zero, s.latch()
	}
	ctx, cancel := context.WithTimeout(s.publication.base, PublicationClientTimeout)
	s.mu.Unlock()
	receipt, err := op.Publish(ctx)
	if err != nil && ctx.Err() == nil && op.Check() == nil && op.State() == "publishing" {
		// Exactly one known read-only recovery; neither absence nor an invalid ACK
		// enables a second POST. No cold path calls this method.
		receipt, err = op.Recover(ctx)
	}
	cancel()
	s.mu.Lock()
	child.live = false
	child.finalizing = err == nil
	if err != nil {
		return zero, s.latch()
	}
	if receipt != s.expectedPublication(v) || s.preflight() != nil || s.recheckPublicationCipher(v, child.originalCipher) != nil {
		return zero, s.latch()
	}
	if s.point("publication_before_job") != nil {
		return zero, s.latch()
	}
	if err = s.publishFiles(entry, v); err != nil {
		return zero, s.latch()
	}
	entry.State = "delivered"
	if err = s.replace(i, entry); err != nil {
		return zero, err
	}
	child.finalizing = false
	return ownerReceipt(v), nil
}
func (s *OwnerIngressStore) closePublicationIngress() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.publication
	if p.closeErr != nil {
		return p.closeErr
	}
	if s.closed {
		return nil
	}
	remember := func(err error) error {
		if p.closeErr == nil {
			p.closeErr = err
		}
		return p.closeErr
	}
	if s.inflight != 0 {
		return remember(fail("ownership_ingress_pending"))
	}
	if err := s.preflight(); err != nil {
		return remember(err)
	}
	for _, child := range p.children {
		if child.operation == nil {
			return remember(s.latch())
		}
		if err := child.operation.Close(); err != nil {
			return remember(s.latch())
		}
	}
	p.client.CloseIdleConnections()
	for _, f := range []*os.File{p.root, s.acceptances, s.jobs, s.uploads, s.root, s.lock} {
		if s.point("close") != nil || f.Close() != nil {
			return remember(s.latch())
		}
	}
	if s.rawHeld {
		if syscall.Close(s.rawFD) != nil {
			return remember(s.latch())
		}
		s.rawHeld = false
	}
	s.closed = true
	return nil
}

// The server trust CA below is distinct from the receiver's dedicated ProducerCA.
// The receiver independently authenticates this exact producer leaf.
type OwnerIngressPublisherServiceConfig struct {
	BaseURL                string                `json:"base_url"`
	ServerName             string                `json:"server_name"`
	ExpectedPublisherScope PublicationScope      `json:"expected_publisher_scope"`
	ProducerTLSCertificate AuthorityServiceAsset `json:"producer_tls_certificate"`
	ProducerTLSPrivateKey  AuthorityServiceAsset `json:"producer_tls_private_key"`
	PublisherCA            AuthorityServiceAsset `json:"publisher_ca"`
}

func (c OwnerIngressServiceConfig) publisherShape() error {
	p := c.Publisher
	if c.SchemaVersion != 2 || p == nil || p.BaseURL == "" || p.ServerName == "" || p.ExpectedPublisherScope.validate() != nil {
		return fail("ownership_ingress_publication_config_invalid")
	}
	for _, a := range []AuthorityServiceAsset{p.ProducerTLSCertificate, p.ProducerTLSPrivateKey, p.PublisherCA} {
		if !authorityServicePath(a.Path) || !hexValue(a.SHA256, 64) || authorityServiceOverlap(a.Path, c.StoreRoot) {
			return fail("ownership_ingress_service_asset_invalid")
		}
	}
	return nil
}
func loadOwnerIngressPublisherMaterial(ctx context.Context, c OwnerIngressServiceConfig, m *ownerIngressServiceMaterial) (*OwnerIngressPublicationConfig, error) {
	p := c.Publisher
	certPEM, err := readAuthorityServiceAsset(ctx, p.ProducerTLSCertificate, 64<<10)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readAuthorityServiceAsset(ctx, p.ProducerTLSPrivateKey, 64<<10)
	if err != nil {
		return nil, err
	}
	caPEM, err := readAuthorityServiceAsset(ctx, p.PublisherCA, 64<<10)
	if err != nil {
		return nil, err
	}
	certs, err := authorityPEMCertificates(certPEM, 8)
	if err != nil {
		return nil, err
	}
	roots, err := authorityPEMCertificates(caPEM, 16)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || len(block.Headers) != 0 || (block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY") || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(bytes.TrimSpace(keyPEM), []byte("-----BEGIN "+block.Type+"-----")) {
		return nil, fail("ownership_service_tls_invalid")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fail("ownership_service_tls_invalid")
	}
	cert.Leaf = certs[0]
	producerKey, ok := cert.Leaf.PublicKey.(*rsa.PublicKey)
	serverKey, serverOK := m.tls.Certificates[0].Leaf.PublicKey.(*rsa.PublicKey)
	if !ok || !serverOK || producerKey.N == nil || serverKey.N == nil || producerKey.E == serverKey.E && producerKey.N.Cmp(serverKey.N) == 0 {
		return nil, fail("ownership_ingress_publication_role_invalid")
	}
	intermediates := x509.NewCertPool()
	for _, v := range certs[1:] {
		intermediates.AddCert(v)
	}
	// This negative check is local role separation only. Publisher's configured
	// ProducerCA, not this server-trust pool, decides remote producer admission.
	if _, err = cert.Leaf.Verify(x509.VerifyOptions{Roots: m.tls.ClientCAs, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		return nil, fail("ownership_ingress_publication_role_invalid")
	}
	pool := x509.NewCertPool()
	now := time.Now()
	for _, v := range roots {
		if !v.IsCA || !v.BasicConstraintsValid || v.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(v.NotBefore) || !now.Before(v.NotAfter) {
			return nil, fail("ownership_service_tls_invalid")
		}
		pool.AddCert(v)
	}
	for _, v := range certs {
		if now.Before(v.NotBefore) || !now.Before(v.NotAfter) {
			return nil, fail("ownership_service_tls_invalid")
		}
	}
	cfg := OwnerIngressPublicationConfig{TrustSHA256: digest(caPEM), Client: PublicationClientConfig{Client: AuthorityClientConfig{BaseURL: p.BaseURL, ServerName: p.ServerName, Certificate: cert, RootCAs: pool, Pin: m.pin, Scope: c.ExpectedScope}, ExpectedPublisherScope: p.ExpectedPublisherScope}}
	client, err := NewPublicationClient(cfg.Client)
	if err != nil {
		return nil, err
	}
	client.CloseIdleConnections()
	return &cfg, nil
}

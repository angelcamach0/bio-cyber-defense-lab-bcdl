//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type ingressPublicationEndpoint struct {
	mu          sync.Mutex
	posts, gets int
	mode        string
	receipt     PublicationReceipt
	hook        func(*http.Request)
}

func (x *ingressPublicationEndpoint) counts() (int, int) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.posts, x.gets
}
func ingressPublicationFixture(t *testing.T) (*OwnerIngressStore, OwnerIngressConfig, AcceptedBundle, *ingressPublicationEndpoint) {
	t.Helper()
	x := &ingressPublicationEndpoint{}
	client, _, _ := publicationClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		x.mu.Lock()
		if r.Method == http.MethodPost {
			x.posts++
		} else if r.Method == http.MethodGet {
			x.gets++
		} else {
			t.Error("unexpected method")
		}
		mode, receipt, hook := x.mode, x.receipt, x.hook
		x.mu.Unlock()
		if r.Method == http.MethodPost && digest(raw) != receipt.AcceptanceSHA256 || r.Method == http.MethodGet && len(raw) != 0 {
			t.Error("wrong canonical body")
		}
		if hook != nil {
			hook(r)
		}
		if mode == "drop" && r.Method == http.MethodPost {
			c, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			c.Close()
			return
		}
		if mode == "absent" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(receipt)
	}))
	bundle := ingressTestBundle(t, false)
	cfg := ingressTestConfig(t)
	client.Client.Scope = cfg.Scope
	chain := fixture(t).stateA.VerifiedChains[0]
	cfg.Publication = &OwnerIngressPublicationConfig{Client: client, TrustSHA256: digest(chain[len(chain)-1].Raw)}
	s, err := CreateOwnerIngress(cfg)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyAcceptance(bundle.Acceptance, cfg.Pin, cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	x.mu.Lock()
	x.receipt = s.expectedPublication(v)
	x.mu.Unlock()
	t.Cleanup(func() { ingressPublicationSimulateExit(s) })
	return s, cfg, bundle, x
}

// Descriptor release models only test process exit; it is not crash evidence.
func ingressPublicationSimulateExit(s *OwnerIngressStore) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.publication != nil {
		for _, child := range s.publication.children {
			if child.operation != nil {
				publicationOperationSimulateExit(child.operation)
			}
		}
		s.publication.client.CloseIdleConnections()
		if s.publication.root != nil {
			s.publication.root.Close()
		}
	}
	for _, f := range []*os.File{s.acceptances, s.jobs, s.uploads, s.root, s.lock} {
		if f != nil {
			f.Close()
		}
	}
	if s.rawHeld {
		syscall.Close(s.rawFD)
		s.rawHeld = false
	}
	s.closed = true
}

func TestOwnerIngressPublicationLegacyIdentityUnchanged(t *testing.T) {
	cfg := ingressTestConfig(t)
	raw, _ := json.Marshal(struct {
		Namespace string
		Pin       AuthorityPin
		Scope     AcceptanceScope
		Policy    OwnerIngressPolicy
	}{cfg.Namespace, cfg.Pin, cfg.Scope, cfg.Policy})
	s := ingressTestStore(t, cfg, true)
	if s.data.SchemaVersion != 1 || s.data.Domain != "biozero.ownership.transport-spool.v1" || s.data.ContextSHA256 != digest(raw) || s.ingressCharge() != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom {
		t.Fatal("legacy identity changed")
	}
	names, err := ownerReadNames(s.root, 8)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if name == "publication" {
			t.Fatal("legacy gained publication state")
		}
	}
	c, _ := ownerServiceFixture(t, cfg.Scope)
	wire, _ := json.Marshal(c)
	if bytes.Contains(wire, []byte("publisher")) {
		t.Fatal("legacy config bytes gained a field")
	}
	var closed ownerIngressServiceWire
	if decodeStoreJSON(wire, &closed) != nil {
		t.Fatal("legacy wire no longer closed compatible")
	}
}

func TestOwnerIngressPublicationGateBusyAndDuplicate(t *testing.T) {
	s, cfg, bundle, x := ingressPublicationFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var once sync.Once
	x.mu.Lock()
	x.hook = func(r *http.Request) {
		if r.Method == http.MethodPost {
			once.Do(func() { close(entered) })
			<-release
		}
	}
	x.mu.Unlock()
	done := make(chan error, 1)
	var receipt OwnerUploadReceipt
	go func() {
		var err error
		receipt, err = s.Accept(context.Background(), &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext)))
		done <- err
		close(done)
	}()
	defer func() {
		unblock()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("test publisher did not drain")
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher not entered")
	}
	job := x.receipt.JobID
	if _, err := os.Stat(filepath.Join(cfg.Directory, "jobs", job+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("job visible before published receipt")
	}
	observed := make(chan error, 1)
	go func() { _, err := s.Get(context.Background(), &fixture(t).stateA, job); observed <- err }()
	select {
	case err := <-observed:
		if err == nil || err.Error() != "ownership_ingress_pending" {
			t.Fatal("busy local child was not pending", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ingress mutex blocked behind publisher")
	}
	snap := s.Snapshot()
	if snap.Jobs != 1 || snap.Reading != 0 || snap.Authorizing != 1 || snap.Rejected != 0 || snap.ChargedBytes != cfg.Policy.MaxBodyBytes+StoreMetadataHeadroom+OwnerIngressPublicationHeadroom {
		t.Fatal("authorizing accounting", snap)
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("publish did not complete")
	}
	if receipt.State != "delivered" || receipt.AcceptanceSHA256 != x.receipt.AcceptanceSHA256 {
		t.Fatal("upload receipt binding")
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, "jobs", job+".json")); err != nil {
		t.Fatal(err)
	}
	before := s.Snapshot()
	got, err := s.Accept(context.Background(), &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, publicationNoRead{}, int64(len(bundle.Ciphertext)))
	if err != nil || got != receipt || s.Snapshot() != before {
		t.Fatal("duplicate changed retained delivery", err)
	}
	if p, g := x.counts(); p != 1 || g != 0 {
		t.Fatal("duplicate network", p, g)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenOwnerIngress(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ingressPublicationSimulateExit(reopened)
	got, err = reopened.Get(context.Background(), &fixture(t).stateA, job)
	if err != nil || got != receipt {
		t.Fatal("cold delivered read", err)
	}
	if p, g := x.counts(); p != 1 || g != 0 {
		t.Fatal("cold Open did network", p, g)
	}
}

type publicationNoRead struct{}

func (publicationNoRead) Read([]byte) (int, error) { panic("duplicate read ciphertext") }

func TestOwnerIngressPublicationLostResponseKnownGetOnly(t *testing.T) {
	s, _, bundle, x := ingressPublicationFixture(t)
	x.mu.Lock()
	x.mode = "drop"
	x.mu.Unlock()
	got, err := s.Accept(context.Background(), &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext)))
	if err != nil || got.State != "delivered" {
		t.Fatal("known GET failed", err)
	}
	if p, g := x.counts(); p != 1 || g != 1 {
		t.Fatal("expected one POST and one GET", p, g)
	}
}

func TestOwnerIngressPublicationUncertainNeverRejectOrReplay(t *testing.T) {
	s, cfg, bundle, x := ingressPublicationFixture(t)
	x.mu.Lock()
	x.mode = "absent"
	x.mu.Unlock()
	_, err := s.Accept(context.Background(), &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext)))
	if err == nil || !s.sticky || s.data.Records[0].State != "authorizing" || s.data.Records[0].ChargeBytes != s.ingressCharge() {
		t.Fatal("uncertainty lost", err)
	}
	if _, err = os.Stat(filepath.Join(cfg.Directory, "jobs", x.receipt.JobID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("uncertain job exposed")
	}
	if p, g := x.counts(); p != 1 || g != 1 {
		t.Fatal("wrong attempt counts", p, g)
	}
	before := fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))
	// Actual kernel flock, not a failure caused by the Store's sticky bool.
	lock, err := os.OpenFile(filepath.Join(cfg.Directory, "instance.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
		t.Fatal("uncertain ingress lock released")
	}
	lock.Close()
	ingressPublicationSimulateExit(s)
	cold, err := OpenOwnerIngress(cfg)
	defer ingressPublicationSimulateExit(cold)
	if err == nil || cold == nil || !cold.rawHeld {
		t.Fatal("cold uncertain history not retained", err)
	}
	if !bytes.Equal(before, fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))) {
		t.Fatal("cold mutated history")
	}
	if p, g := x.counts(); p != 1 || g != 1 {
		t.Fatal("cold replayed network", p, g)
	}
}

func TestOwnerIngressPublicationCipherChangedBeforeJobFences(t *testing.T) {
	s, cfg, bundle, x := ingressPublicationFixture(t)
	v, err := VerifyAcceptance(bundle.Acceptance, cfg.Pin, cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	x.mu.Lock()
	x.hook = func(r *http.Request) {
		if r.Method == http.MethodPost {
			changed := bytes.Clone(bundle.Ciphertext)
			changed[0] ^= 1
			if err := os.WriteFile(filepath.Join(cfg.Directory, "uploads", v.Binding().JobID+"_"+v.Binding().OriginalName), changed, 0600); err != nil {
				t.Error(err)
			}
		}
	}
	x.mu.Unlock()
	_, err = s.Accept(context.Background(), &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext)))
	if err == nil || !s.sticky || s.data.Records[0].State != "authorizing" {
		t.Fatal("changed ciphertext released", err)
	}
	if _, err = os.Stat(filepath.Join(cfg.Directory, "jobs", v.Binding().JobID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mutated ciphertext job visible")
	}
}

func TestOwnerIngressPublicationOutlivesRequestCancellation(t *testing.T) {
	s, _, bundle, x := ingressPublicationFixture(t)
	base, stop := context.WithCancel(context.Background())
	defer stop()
	if err := s.setPublicationBase(base); err != nil {
		t.Fatal(err)
	}
	request, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var hookOnce sync.Once
	x.mu.Lock()
	x.hook = func(r *http.Request) { hookOnce.Do(func() { close(entered) }); <-release }
	x.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := s.Accept(request, &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext)))
		done <- err
		close(done)
	}()
	defer func() {
		unblock()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("test publisher did not drain")
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher not reached")
	}
	cancel()
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("request cancelled authorized publication", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("publication did not finish")
	}
	if s.data.Records[0].State != "delivered" {
		t.Fatal("source-owned result not delivered")
	}
}

func TestOwnerIngressPublicationClosedWireV2(t *testing.T) {
	c, _ := ownerServiceFixture(t, AcceptanceScope{})
	c.SchemaVersion = 2
	c.Publisher = &OwnerIngressPublisherServiceConfig{BaseURL: "https://127.0.0.1:1", ServerName: "localhost", ExpectedPublisherScope: PublicationScope{strings.Repeat("7", 32), strings.Repeat("8", 64)}, ProducerTLSCertificate: c.TLSCertificate, ProducerTLSPrivateKey: c.TLSPrivateKey, PublisherCA: c.ClientCA}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var wire ownerIngressServiceWireV2
	if decodeStoreJSON(raw, &wire) != nil || !reflect.DeepEqual(wire.Publisher, *c.Publisher) {
		t.Fatal("valid closed wire rejected")
	}
	for _, kind := range []string{"null", "unknown", "missing", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			bad := bytes.Clone(raw)
			switch kind {
			case "null":
				pub, _ := json.Marshal(c.Publisher)
				bad = bytes.Replace(bad, pub, []byte("null"), 1)
			case "unknown":
				bad = bytes.Replace(bad, []byte(`"publisher":{`), []byte(`"publisher":{"unknown":0,`), 1)
			case "missing":
				bad = bytes.Replace(bad, []byte(`"server_name":"localhost",`), nil, 1)
			case "duplicate":
				bad = bytes.Replace(bad, []byte(`"server_name":"localhost"`), []byte(`"server_name":"localhost","server_name":"localhost"`), 1)
			}
			var out ownerIngressServiceWireV2
			if decodeStoreJSON(bad, &out) == nil {
				t.Fatal("nonclosed publisher accepted")
			}
		})
	}
	var legacy ownerIngressServiceWire
	if decodeStoreJSON(raw, &legacy) == nil {
		t.Fatal("legacy adopted publisher")
	}
}

func TestOwnerIngressPublicationSameBytesReplacementBeforeJobFences(t *testing.T) {
	s, cfg, bundle, x := ingressPublicationFixture(t)
	v, err := VerifyAcceptance(bundle.Acceptance, cfg.Pin, cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	var held *os.File
	var observed bool
	var observationMu sync.Mutex
	x.mu.Lock()
	x.hook = func(r *http.Request) {
		if r.Method != http.MethodPost {
			return
		}
		observationMu.Lock()
		defer observationMu.Unlock()
		path := filepath.Join(cfg.Directory, "uploads", v.Binding().JobID+"_"+v.Binding().OriginalName)
		var err error
		held, err = os.Open(path)
		if err != nil {
			t.Error(err)
			return
		}
		original, err := held.Stat()
		if err != nil {
			t.Error(err)
			return
		}
		if err = os.Remove(path); err != nil {
			t.Error(err)
			return
		}
		if err = os.WriteFile(path, bundle.Ciphertext, 0600); err != nil {
			t.Error(err)
			return
		}
		current, err := os.Stat(path)
		if err != nil {
			t.Error(err)
			return
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			return
		}
		// Positive preflight + exact bytes remove namespace/size/hash as confounders.
		observed = !os.SameFile(original, current) && bytes.Equal(raw, bundle.Ciphertext) && s.Healthy()
	}
	x.mu.Unlock()
	_, err = s.Accept(context.Background(), &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext)))
	observationMu.Lock()
	defer observationMu.Unlock()
	if held != nil {
		if closeErr := held.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	if !observed || err == nil || !s.sticky || s.data.Records[0].State != "authorizing" {
		t.Fatal("replacement original-inode fence not causal", observed, err)
	}
	if _, err = os.Stat(filepath.Join(cfg.Directory, "jobs", v.Binding().JobID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replacement exposed a job")
	}
}

func TestOwnerIngressPublicationActualPublisherServiceGate(t *testing.T) {
	cfg := ingressTestConfig(t)
	bundle := ingressTestBundle(t, false)
	f := fixture(t)
	pc, path, _ := publicationServiceFixture(t)
	pc.ExpectedAuthorityScope = cfg.Scope
	publicationWriteServiceFixture(t, path, pc)
	initConfig, err := LoadPublicationServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := InitializePublicationStore(context.Background(), initConfig)
	if err != nil {
		t.Fatal(err)
	}
	pc.ExpectedPublisherScope = scope
	publicationWriteServiceFixture(t, path, pc)
	liveConfig, err := LoadPublicationServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce, enteredOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	publisher, url := publicationRunService(t, liveConfig, func(service *PublicationService) {
		service.store.fault = func(point string) error {
			if point == "receipt_durable" {
				enteredOnce.Do(func() { close(entered) })
				<-release
			}
			return nil
		}
	})
	ca := f.stateA.VerifiedChains[0][len(f.stateA.VerifiedChains[0])-1]
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	cfg.Publication = &OwnerIngressPublicationConfig{TrustSHA256: digest(ca.Raw), Client: PublicationClientConfig{Client: AuthorityClientConfig{
		BaseURL: url, Certificate: tls.Certificate{Certificate: [][]byte{f.certB.Raw}, PrivateKey: f.keyB}, RootCAs: roots, ServerName: "localhost", Pin: cfg.Pin, Scope: cfg.Scope}, ExpectedPublisherScope: scope}}
	ingress, err := CreateOwnerIngress(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { unblock(); ingressPublicationSimulateExit(ingress) }()
	v, err := VerifyAcceptance(bundle.Acceptance, cfg.Pin, cfg.Scope)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ingress.Accept(context.Background(), &f.stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext)))
		done <- err
		close(done)
	}()
	defer func() {
		unblock()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("test publisher did not drain")
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("real publisher did not reach durable receipt barrier")
	}
	if _, err = os.Stat(filepath.Join(cfg.Directory, "jobs", v.Binding().JobID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("job visible before publisher return")
	}
	// Signed authorization may already authorize Results before publication ACK.
	actual, err := os.ReadFile(filepath.Join(publisher.InboxDirectory(), v.Binding().JobID+".json"))
	if err != nil || !bytes.Equal(actual, v.canonical) {
		t.Fatal("actual publisher inbox differs", err)
	}
	if !ingress.Healthy() {
		t.Fatal("known live publisher IO poisoned healthy ingress")
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("actual publisher response not drained")
	}
	receipt, err := publisher.store.Get(context.Background(), &f.stateB, v.Binding().JobID, v.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	child := ingress.publication.children[v.Binding().JobID]
	retained, err := child.operation.Receipt()
	if err != nil || retained != receipt {
		t.Fatal("sender receipt differs from real publisher", err)
	}
	if _, err = os.Stat(filepath.Join(cfg.Directory, "jobs", v.Binding().JobID+".json")); err != nil {
		t.Fatal("post-receipt job absent", err)
	}
	before := publicationTree(t, pc.StateDirectory)
	uploadReceipt, err := ingress.Accept(context.Background(), &f.stateA, bundle.Acceptance, bundle.KeyEnvelope, publicationNoRead{}, int64(len(bundle.Ciphertext)))
	if err != nil || uploadReceipt.AcceptanceSHA256 != v.SHA256() || !reflect.DeepEqual(before, publicationTree(t, pc.StateDirectory)) {
		t.Fatal("duplicate mutated real publisher", err)
	}
	snap, err := publisher.store.Snapshot()
	if err != nil || snap.RetainedJobs != 1 || snap.RetainedBytes != PublicationRunCharge {
		t.Fatal("real publisher charges", err, snap)
	}
}

func TestOwnerIngressPublicationProducerOwnerRejectedBeforeAdmission(t *testing.T) {
	s, _, _, x := ingressPublicationFixture(t)
	bundle := ingressTestBundle(t, true)
	_, err := s.Accept(context.Background(), &fixture(t).stateB, bundle.Acceptance, bundle.KeyEnvelope, publicationNoRead{}, int64(len(bundle.Ciphertext)))
	if err == nil || err.Error() != "ownership_ingress_publication_role_invalid" || s.Snapshot().Jobs != 0 {
		t.Fatal("producer owner admitted", err)
	}
	if p, g := x.counts(); p != 0 || g != 0 {
		t.Fatal("role denial contacted publisher", p, g)
	}
}

func TestOwnerIngressPublicationSnapshotsCallerTrust(t *testing.T) {
	s, cfg, bundle, x := ingressPublicationFixture(t)
	cfg.Publication.Client.Client.BaseURL = "https://127.0.0.1:1"
	cfg.Publication.Client.Client.Certificate.Certificate[0] = []byte("invalid")
	cfg.Publication.Client.Client.RootCAs = x509.NewCertPool()
	cfg.Publication.Client.Client.Pin.PublicKey = nil
	cfg.Publication.TrustSHA256 = strings.Repeat("f", 64)
	got, err := s.Accept(context.Background(), &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext)))
	if err != nil || got.State != "delivered" {
		t.Fatal("borrowed mutable caller trust", err)
	}
	if p, g := x.counts(); p != 1 || g != 0 {
		t.Fatal("snapshot did not use original endpoint", p, g)
	}
}

func TestOwnerIngressPublicationServiceConfigSeparateProducerAndCA(t *testing.T) {
	c, path := ownerServiceFixture(t, AcceptanceScope{})
	c.SchemaVersion = 2
	f := fixture(t)
	states, certs := publicationTLSLeaves(t, 1, f.keyB)
	ca := f.stateA.VerifiedChains[0][len(f.stateA.VerifiedChains[0])-1]
	writeAsset := func(name string, raw []byte) AuthorityServiceAsset {
		p := filepath.Join(filepath.Dir(path), name)
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return AuthorityServiceAsset{p, digest(raw)}
	}
	producerCA := states[0].VerifiedChains[0][len(states[0].VerifiedChains[0])-1]
	// The public producer chain is deliberately from a different CA than owners.
	producerPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: producerCA.Raw})...)
	c.Publisher = &OwnerIngressPublisherServiceConfig{BaseURL: "https://127.0.0.1:1", ServerName: "localhost", ExpectedPublisherScope: PublicationScope{strings.Repeat("7", 32), strings.Repeat("8", 64)},
		ProducerTLSCertificate: writeAsset("producer.crt", producerPEM), ProducerTLSPrivateKey: writeAsset("producer.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.keyB)})),
		PublisherCA: writeAsset("publisher-ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))}
	writeOwnerServiceFixture(t, path, c)
	loaded, err := LoadOwnerIngressServiceConfig(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(c.StoreRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("loader created state")
	}
	if loaded.loaded.publication.TrustSHA256 != c.Publisher.PublisherCA.SHA256 {
		t.Fatal("actual CA asset hash not retained")
	}
	if err = InitializeOwnerIngress(context.Background(), loaded); err != nil {
		t.Fatal(err)
	}
	s, err := OpenOwnerIngress(loaded.ingressConfig(loaded.loaded))
	if err != nil {
		t.Fatal(err)
	}
	defer ingressPublicationSimulateExit(s)
	if s.data.SchemaVersion != 2 || s.data.Domain != "biozero.ownership.transport-spool.v2" {
		t.Fatal("schema2 did not select new history")
	}
	// Same server RSA is forbidden even if the service has separate field names.
	changed := c
	group := *c.Publisher
	changed.Publisher = &group
	group.ProducerTLSCertificate = c.TLSCertificate
	group.ProducerTLSPrivateKey = c.TLSPrivateKey
	writeOwnerServiceFixture(t, path, changed)
	if _, err = LoadOwnerIngressServiceConfig(context.Background(), path); err == nil {
		t.Fatal("producer reused server key")
	}
	// Same owner CA is not a deployment of the dedicated producer role.
	group = *c.Publisher
	changed.Publisher = &group
	group.ProducerTLSCertificate = writeAsset("owner-ca-producer.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.certB.Raw}))
	writeOwnerServiceFixture(t, path, changed)
	if _, err = LoadOwnerIngressServiceConfig(context.Background(), path); err == nil {
		t.Fatal("producer authenticated by owner CA")
	}
}

func TestOwnerIngressPublicationColdFencesEachAuthorizingBoundary(t *testing.T) {
	for _, point := range []string{"publication_create", "publication_intent_durable", "publication_before_job"} {
		t.Run(point, func(t *testing.T) {
			s, cfg, bundle, x := ingressPublicationFixture(t)
			s.fault = func(p string) error {
				if p == point {
					return errors.New("causal publication barrier")
				}
				return nil
			}
			_, err := s.Accept(context.Background(), &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext)))
			if err == nil || !s.sticky || s.data.Records[0].State != "authorizing" {
				t.Fatal("barrier not retained", err)
			}
			job := s.data.Records[0].JobID
			if _, err = os.Stat(filepath.Join(cfg.Directory, "jobs", job+".json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("barrier exposed job")
			}
			posts, gets := x.counts()
			want := 0
			if point == "publication_before_job" {
				want = 1
			}
			if posts != want || gets != 0 {
				t.Fatal("wrong causal HTTP boundary", posts, gets)
			}
			before := publicationTree(t, cfg.Directory)
			ingressPublicationSimulateExit(s)
			cold, err := OpenOwnerIngress(cfg)
			defer ingressPublicationSimulateExit(cold)
			if err == nil || cold == nil || !cold.rawHeld {
				t.Fatal("cold pending parent custody released", err)
			}
			if !reflect.DeepEqual(before, publicationTree(t, cfg.Directory)) {
				t.Fatal("cold completion/replay changed files")
			}
			if p, g := x.counts(); p != posts || g != gets {
				t.Fatal("cold performed network", p, g)
			}
		})
	}
}

func TestOwnerIngressPublicationDeliveredBusyCannotMasqueradeLive(t *testing.T) {
	s, cfg, bundle, _ := ingressPublicationFixture(t)
	receipt, err := s.Accept(context.Background(), &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext)))
	if err != nil {
		t.Fatal(err)
	}
	child := s.publication.children[receipt.JobID]
	before := fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))
	child.operation.mu.Lock()
	observed := make(chan error, 1)
	go func() { _, err := s.Get(context.Background(), &fixture(t).stateA, receipt.JobID); observed <- err }()
	select {
	case err := <-observed:
		if err == nil {
			t.Error("busy delivered child accepted")
		}
	case <-time.After(time.Second):
		t.Error("busy delivered child blocked ingress")
	}
	child.operation.mu.Unlock()
	if !s.sticky || !bytes.Equal(before, fileBytes(t, filepath.Join(cfg.Directory, "ledger.json"))) {
		t.Fatal("busy delivered fault changed ledger or was not fenced")
	}
}

func TestOwnerIngressPublicationSourceShutdownDrainsAndKeepsFirstClose(t *testing.T) {
	s, cfg, bundle, x := ingressPublicationFixture(t)
	base, stop := context.WithCancel(context.Background())
	defer stop()
	if err := s.setPublicationBase(base); err != nil {
		t.Fatal(err)
	}
	entered, serverDone := make(chan struct{}), make(chan struct{})
	var enterOnce sync.Once
	x.mu.Lock()
	x.hook = func(r *http.Request) {
		enterOnce.Do(func() { close(entered) })
		<-r.Context().Done()
		close(serverDone)
	}
	x.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := s.Accept(context.Background(), &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext)))
		done <- err
		close(done)
	}()
	defer func() {
		stop()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("source cancellation did not drain publication")
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("publication not live")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- s.Close() }()
	var first error
	select {
	case first = <-closeDone:
		if first == nil || first.Error() != "ownership_ingress_pending" {
			t.Fatal("live Close lost pending", first)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind publication")
	}
	stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled publication delivered")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("source publication not joined")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("actual HTTP publication connection did not close")
	}
	if got := s.Close(); got != first {
		t.Fatal("repeat Close discarded first error", got, first)
	}
	if !s.rawHeld || s.inflight != 0 || s.data.Records[0].State != "authorizing" || s.data.Records[0].ChargeBytes != s.ingressCharge() {
		t.Fatal("shutdown changed retained custody")
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, "jobs", x.receipt.JobID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("shutdown exposed pending job")
	}
	if p, g := x.counts(); p != 1 || g != 0 {
		t.Fatal("shutdown automatically recovered/retried", p, g)
	}
}

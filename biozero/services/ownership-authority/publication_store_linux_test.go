//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func publicationStoreFixture(t *testing.T) (*PublicationStore, PublicationStoreConfig, []byte, *testFixture) {
	t.Helper()
	f, a, scope := acceptanceFixture(t, true)
	raw, _ := MarshalAcceptance(a)
	parent := t.TempDir()
	os.Chmod(parent, 0700)
	c := PublicationStoreConfig{Directory: filepath.Join(parent, "publisher"), Pin: f.pin, AuthorityScope: scope, ProducerCredentialSHA256: []string{digest(f.certB.Raw)}}
	s, e := CreatePublicationStore(c)
	if e != nil {
		t.Fatal(e)
	}
	c.ExpectedPublisherScope = s.Scope()
	t.Cleanup(func() { s.Close() })
	return s, c, raw, f
}
func publicationTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() {
			raw, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			r, _ := filepath.Rel(root, p)
			out[r] = digest(raw)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestPublicationStoreDurableIdentityDuplicateAndColdReadOnly(t *testing.T) {
	s, c, raw, f := publicationStoreFixture(t)
	ctx := context.Background()
	if _, e := CreatePublicationStore(PublicationStoreConfig{Directory: c.Directory, Pin: c.Pin, AuthorityScope: c.AuthorityScope, ProducerCredentialSHA256: c.ProducerCredentialSHA256}); e == nil {
		t.Fatal("adopted existing history")
	}
	if _, e := OpenPublicationStore(c); e == nil {
		t.Fatal("second writer acquired live lock")
	}
	got, e := s.Publish(ctx, &f.stateB, raw)
	if e != nil {
		t.Fatal(e)
	}
	if got.CredentialSHA256 != digest(f.certA.Raw) || got.PublisherScope != c.ExpectedPublisherScope || got.State != "published" {
		t.Fatal("identity/receipt mismatch")
	}
	before := publicationTree(t, c.Directory)
	var pretty bytes.Buffer
	json.Indent(&pretty, raw, "", "  ")
	duplicate, e := s.Publish(ctx, &f.stateB, pretty.Bytes())
	if e != nil || duplicate != got || !reflect.DeepEqual(before, publicationTree(t, c.Directory)) {
		t.Fatal("duplicate mutated or recharged", e)
	}
	snap, e := s.Snapshot()
	if e != nil || snap.RetainedJobs != 1 || snap.RetainedBytes != PublicationRunCharge {
		t.Fatal("promise not retained", snap, e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	cold, e := OpenPublicationStore(c)
	if e != nil {
		t.Fatal(e)
	}
	defer cold.Close()
	again, e := cold.Get(ctx, &f.stateB, got.JobID, got.AcceptanceSHA256)
	if e != nil || again != got || !reflect.DeepEqual(before, publicationTree(t, c.Directory)) {
		t.Fatal("cold Get mutated history", e)
	}
	if _, e = cold.Get(ctx, &f.stateA, got.JobID, got.AcceptanceSHA256); e == nil {
		t.Fatal("owner CN/serial substituted for producer leaf")
	}
}
func TestPublicationStoreInvalidInputsNeverPublishOrCharge(t *testing.T) {
	s, c, raw, f := publicationStoreFixture(t)
	before := publicationTree(t, c.Directory)
	for _, kind := range []string{"signature", "scope", "duplicate_json", "owner_role", "nil_state", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			input := append([]byte(nil), raw...)
			state := &f.stateB
			ctx := context.Background()
			switch kind {
			case "signature":
				input[20] ^= 1
			case "scope":
				var a SignedAcceptance
				json.Unmarshal(input, &a)
				a.Record.StoreID = strings.Repeat("9", 32)
				input = resignAcceptanceForTest(t, a, f.private)
			case "duplicate_json":
				input = append([]byte(`{"signature":"00",`), input[1:]...)
			case "owner_role":
				state = &f.stateA
			case "nil_state":
				state = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, e := s.Publish(ctx, state, input); e == nil {
				t.Fatal("invalid publication accepted")
			}
			if !reflect.DeepEqual(before, publicationTree(t, c.Directory)) {
				t.Fatal("invalid input changed authority")
			}
			if e := s.Check(); e != nil {
				t.Fatal("invalid caller poisoned store", e)
			}
		})
	}
}

func TestPublicationStoreProducerRoleDuplicateAndValidConflict(t *testing.T) {
	f, a, scope := acceptanceFixture(t, true)
	raw, _ := MarshalAcceptance(a)
	states, certs := publicationTLSLeaves(t, 1, f.keyB)
	parent := t.TempDir()
	os.Chmod(parent, 0700)
	c := PublicationStoreConfig{Directory: filepath.Join(parent, "publisher"), Pin: f.pin, AuthorityScope: scope, ProducerCredentialSHA256: []string{digest(f.certA.Raw), digest(f.certB.Raw), digest(certs[0].Raw)}}
	s, e := CreatePublicationStore(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	before := publicationTree(t, c.Directory)
	if _, e = s.Publish(context.Background(), &f.stateA, raw); e == nil || e.Error() != "ownership_publication_role_invalid" {
		t.Fatal("dedicated role became owner", e)
	}
	if !reflect.DeepEqual(before, publicationTree(t, c.Directory)) {
		t.Fatal("role rejection changed history")
	}
	first, e := s.Publish(context.Background(), &f.stateB, raw)
	if e != nil {
		t.Fatal(e)
	}
	before = publicationTree(t, c.Directory)
	second, e := s.Publish(context.Background(), &states[0], raw)
	if e != nil || second != first || !reflect.DeepEqual(before, publicationTree(t, c.Directory)) {
		t.Fatal("second pinned producer duplicated publication", e)
	}
	conflict := publicationSignedJob(t, f.stateA, f.certA, 0x1234567890abcdef, scope)
	if _, e = VerifyAcceptance(conflict, c.Pin, c.AuthorityScope); e != nil {
		t.Fatal("conflict fixture must be valid", e)
	}
	if _, e = s.Publish(context.Background(), &f.stateB, conflict); e == nil || !s.sticky {
		t.Fatal("valid conflicting signed acceptance not fenced")
	}
	if !bytes.Equal(fileBytes(t, filepath.Join(s.InboxDirectory(), first.JobID+".json")), raw) || !bytes.Equal(fileBytes(t, filepath.Join(c.Directory, "conflicting-acceptance.json")), conflict) {
		t.Fatal("conflict replaced or lost original signed facts")
	}
}

func TestPublicationStoreColdTamperRefusalKeepsCustody(t *testing.T) {
	for _, kind := range []string{"output", "intent", "receipt", "unknown_output", "unknown_operation", "missing_inbox", "paired_deletion", "catalogue_missing", "catalogue_corrupt", "catalogue_marker"} {
		t.Run(kind, func(t *testing.T) {
			s, c, raw, f := publicationStoreFixture(t)
			r, e := s.Publish(context.Background(), &f.stateB, raw)
			if e != nil {
				t.Fatal(e)
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "output":
				os.WriteFile(filepath.Join(s.InboxDirectory(), r.JobID+".json"), []byte("{}"), 0600)
			case "intent":
				os.WriteFile(filepath.Join(c.Directory, "operations", r.JobID, "intent.json"), []byte("{}"), 0600)
			case "receipt":
				os.WriteFile(filepath.Join(c.Directory, "operations", r.JobID, "published.json"), []byte("{}"), 0600)
			case "unknown_output":
				os.WriteFile(filepath.Join(s.InboxDirectory(), "unknown.json"), raw, 0600)
			case "unknown_operation":
				os.Mkdir(filepath.Join(c.Directory, "operations", "unknown"), 0700)
			case "missing_inbox":
				os.Rename(s.InboxDirectory(), filepath.Join(filepath.Dir(c.Directory), "retained-inbox"))
				os.Mkdir(s.InboxDirectory(), 0700)
			case "paired_deletion":
				if os.RemoveAll(filepath.Join(c.Directory, "operations", r.JobID)) != nil || os.Remove(filepath.Join(s.InboxDirectory(), r.JobID+".json")) != nil {
					t.Fatal("test removal failed")
				}
			case "catalogue_missing":
				os.Remove(filepath.Join(c.Directory, "catalogue.json"))
			case "catalogue_corrupt":
				os.WriteFile(filepath.Join(c.Directory, "catalogue.json"), []byte("{}"), 0600)
			case "catalogue_marker":
				os.WriteFile(filepath.Join(c.Directory, "catalogue.intent"), []byte("{}"), 0600)
			}
			before := publicationTree(t, c.Directory)
			if _, e = OpenPublicationStore(c); e == nil {
				t.Fatal("cold history adopted")
			}
			if _, e = OpenPublicationStore(c); e == nil || e.Error() != "ownership_publication_locked" {
				t.Fatal("cold history fault released lifetime lock", e)
			}
			if !reflect.DeepEqual(before, publicationTree(t, c.Directory)) {
				t.Fatal("cold history was repaired or deleted")
			}
		})
	}
}
func TestPublicationStoreStorageFaultsRetainRawLockAndVisibleAuthorization(t *testing.T) {
	for _, point := range []string{"catalogue_intent_durable", "catalogue_next_durable", "catalogue_renamed", "catalogue_marker_removed", "operation_created", "intent_durable", "output_staged", "output_linked", "output_link_synced", "output_unlinked", "output_durable", "receipt_durable"} {
		t.Run(point, func(t *testing.T) {
			s, c, raw, f := publicationStoreFixture(t)
			s.fault = func(p string) error {
				if p == point {
					return errors.New("injected storage failure")
				}
				return nil
			}
			if _, e := s.Publish(context.Background(), &f.stateB, raw); e == nil {
				t.Fatal("storage failure acknowledged")
			}
			first := s.Close()
			if first == nil || s.Close().Error() != first.Error() || !s.rawHeld {
				t.Fatal("uncertainty/first close error disappeared")
			}
			if _, e := OpenPublicationStore(c); e == nil {
				t.Fatal("uncertain writer lock released")
			}
			v, _ := VerifyAcceptance(raw, c.Pin, c.AuthorityScope)
			out := filepath.Join(s.InboxDirectory(), v.Binding().JobID+".json")
			info, e := os.Stat(out)
			if point == "output_linked" || point == "output_link_synced" {
				if e != nil || info.Sys().(*syscall.Stat_t).Nlink != 2 {
					t.Fatal("expected retained two-link window", e)
				}
			}
			if point == "output_unlinked" || point == "output_durable" || point == "receipt_durable" {
				if e != nil || info.Sys().(*syscall.Stat_t).Nlink != 1 || !bytes.Equal(fileBytes(t, out), raw) {
					t.Fatal("fully signed authorization disappeared before ACK", e)
				}
			}
		})
	}
}
func TestPublicationStoreTamperAndReplacementFenceBeforeRead(t *testing.T) {
	for _, kind := range []string{"output_bytes", "output_hardlink", "intent", "receipt", "unknown_output", "unknown_operation", "lock_replacement", "directory_replacement"} {
		t.Run(kind, func(t *testing.T) {
			s, c, raw, f := publicationStoreFixture(t)
			r, e := s.Publish(context.Background(), &f.stateB, raw)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "output_bytes":
				os.WriteFile(filepath.Join(s.InboxDirectory(), r.JobID+".json"), []byte("{}"), 0600)
			case "output_hardlink":
				os.Link(filepath.Join(s.InboxDirectory(), r.JobID+".json"), filepath.Join(filepath.Dir(c.Directory), "alias"))
			case "intent":
				os.WriteFile(filepath.Join(c.Directory, "operations", r.JobID, "intent.json"), []byte("{}"), 0600)
			case "receipt":
				os.WriteFile(filepath.Join(c.Directory, "operations", r.JobID, "published.json"), []byte("{}"), 0600)
			case "unknown_output":
				os.WriteFile(filepath.Join(s.InboxDirectory(), "unknown.json"), raw, 0600)
			case "unknown_operation":
				os.Mkdir(filepath.Join(c.Directory, "operations", "unrecognized"), 0700)
			case "lock_replacement":
				os.Rename(filepath.Join(c.Directory, "instance.lock"), filepath.Join(filepath.Dir(c.Directory), "old-lock"))
				os.WriteFile(filepath.Join(c.Directory, "instance.lock"), nil, 0600)
			case "directory_replacement":
				os.Rename(s.InboxDirectory(), filepath.Join(filepath.Dir(c.Directory), "old-inbox"))
				os.Mkdir(s.InboxDirectory(), 0700)
			}
			if _, e = s.Get(context.Background(), &f.stateB, r.JobID, r.AcceptanceSHA256); e == nil || !s.sticky {
				t.Fatal("storage change released receipt")
			}
			if e = s.Close(); e == nil || !s.rawHeld {
				t.Fatal("tamper released custody")
			}
		})
	}
}

// Use real TLS-verified leaves for aggregate per-owner capacity; these are
// protocol fixtures only, without scientific execution or deployed role claims.
func publicationQuotaOwners(t *testing.T, n int) ([]tls.ConnectionState, []*x509.Certificate) {
	return publicationTLSLeaves(t, n, fixture(t).keyA)
}
func publicationTLSLeaves(t *testing.T, n int, leafKey *rsa.PrivateKey) ([]tls.ConnectionState, []*x509.Certificate) {
	t.Helper()
	f := fixture(t)
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "quota-ca"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(der)
	clients := x509.NewCertPool()
	clients.AddCert(ca)
	roots := x509.NewCertPool()
	chain := f.stateA.VerifiedChains[0]
	roots.AddCert(chain[len(chain)-1])
	observed := make(chan tls.ConnectionState, n)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { observed <- *r.TLS; w.WriteHeader(204) }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients, Certificates: []tls.Certificate{{Certificate: [][]byte{f.certA.Raw}, PrivateKey: f.keyA}}}
	server.StartTLS()
	defer server.Close()
	states := []tls.ConnectionState{}
	certs := []*x509.Certificate{}
	for i := 0; i < n; i++ {
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 100)), Subject: pkix.Name{CommonName: "quota-owner"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		cert, _ := x509.ParseCertificate(der)
		tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: leafKey}}}}
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		resp, e := client.Get(server.URL)
		if e != nil {
			t.Fatal(e)
		}
		resp.Body.Close()
		tr.CloseIdleConnections()
		states = append(states, <-observed)
		certs = append(certs, cert)
	}
	return states, certs
}
func publicationSignedJob(t *testing.T, state tls.ConnectionState, cert *x509.Certificate, n int, scope AcceptanceScope) []byte {
	t.Helper()
	f := fixture(t)
	p, e := PrincipalFromTLS(&state)
	if e != nil {
		t.Fatal(e)
	}
	challenge, e := SignChallenge(f.private, f.pin, p, ChallengeInput{fmt.Sprintf("%016x", n), fmt.Sprintf("%064x", n), "synthetic.fastq", f.now, f.now.Add(5 * time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	cr, _ := MarshalChallenge(challenge)
	v, e := VerifyChallengeForClient(cr, f.pin, cert, f.now)
	if e != nil {
		t.Fatal(e)
	}
	body := bytes.Repeat([]byte("z"), 32)
	manifest, e := SignManifest(f.keyA, cert, v, ManifestInput{digest(body), int64(len(body)), strings.Repeat("4", 64)})
	if e != nil {
		t.Fatal(e)
	}
	mr, _ := MarshalManifest(manifest)
	binding, e := Finalize(context.Background(), &state, cr, mr, f.pin, bytes.NewReader(body), f.now)
	if e != nil {
		t.Fatal(e)
	}
	a, e := sealAcceptance(f.private, f.pin, scope, &state, cr, mr, binding, f.now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := MarshalAcceptance(a)
	return raw
}
func TestPublicationStoreMeasuredOwnerAndGlobalRetentionLimits(t *testing.T) {
	owners, certs := publicationQuotaOwners(t, 4)
	for _, mode := range []string{"owner20", "global64"} {
		t.Run(mode, func(t *testing.T) {
			s, c, _, f := publicationStoreFixture(t)
			limit := PublicationRunLimit
			if mode == "owner20" {
				limit = PublicationOwnerLimit
			}
			for i := 0; i < limit; i++ {
				owner := 0
				if mode == "global64" {
					owner = i % 4
				}
				raw := publicationSignedJob(t, owners[owner], certs[owner], i+1, c.AuthorityScope)
				if _, e := s.Publish(context.Background(), &f.stateB, raw); e != nil {
					t.Fatal(i, e)
				}
			}
			before := publicationTree(t, c.Directory)
			raw := publicationSignedJob(t, owners[0], certs[0], limit+1, c.AuthorityScope)
			if _, e := s.Publish(context.Background(), &f.stateB, raw); e == nil || e.Error() != "ownership_publication_quota" {
				t.Fatal("retained limit bypassed", e)
			}
			if !reflect.DeepEqual(before, publicationTree(t, c.Directory)) {
				t.Fatal("quota rejection changed history")
			}
			snap, e := s.Snapshot()
			if e != nil || snap.RetainedJobs != limit || snap.RetainedBytes != int64(limit)*PublicationRunCharge {
				t.Fatal("wrong retained promise", snap, e)
			}
		})
	}
}

func TestPublicationStoreProcessHelper(t *testing.T) {
	parent := os.Getenv("BIOZERO_PUBLICATION_HELPER_ROOT")
	if parent == "" {
		t.Skip("owned child only")
	}
	f, a, scope := acceptanceFixture(t, true)
	raw, _ := MarshalAcceptance(a)
	c := PublicationStoreConfig{Directory: filepath.Join(parent, "publisher"), Pin: f.pin, AuthorityScope: scope, ProducerCredentialSHA256: []string{digest(f.certB.Raw)}}
	s, e := CreatePublicationStore(c)
	if e != nil {
		t.Fatal(e)
	}
	c.ExpectedPublisherScope = s.Scope()
	b, _ := json.Marshal(c)
	if os.WriteFile(filepath.Join(parent, "config.json"), b, 0600) != nil {
		t.Fatal("helper config")
	}
	cut := os.Getenv("BIOZERO_PUBLICATION_HELPER_CUT")
	if cut != "" {
		s.fault = func(p string) error {
			if p == cut {
				return errors.New("owned death boundary")
			}
			return nil
		}
	}
	_, e = s.Publish(context.Background(), &f.stateB, raw)
	if cut == "" && e != nil || cut != "" && e == nil {
		t.Fatal("unexpected publication", e)
	}
	os.Exit(0) // No Close: the real kernel process boundary releases raw flock.
}
func TestPublicationStoreActualProcessDeathAndColdPartialRefusal(t *testing.T) {
	for _, cut := range []string{"", "catalogue_intent_durable", "catalogue_next_durable", "catalogue_renamed", "catalogue_marker_removed", "output_linked", "output_unlinked"} {
		t.Run("cut_"+cut, func(t *testing.T) {
			parent := t.TempDir()
			os.Chmod(parent, 0700)
			cmd := exec.Command(os.Args[0], "-test.run=^TestPublicationStoreProcessHelper$")
			cmd.Env = append(os.Environ(), "BIOZERO_PUBLICATION_HELPER_ROOT="+parent, "BIOZERO_PUBLICATION_HELPER_CUT="+cut)
			if out, e := cmd.CombinedOutput(); e != nil {
				t.Fatal(e, string(out))
			}
			var c PublicationStoreConfig
			if json.Unmarshal(fileBytes(t, filepath.Join(parent, "config.json")), &c) != nil {
				t.Fatal("helper config invalid")
			}
			before := publicationTree(t, c.Directory)
			cold, e := OpenPublicationStore(c)
			if cut != "" {
				if e == nil {
					cold.Close()
					t.Fatal("adopted partial journal")
				}
				if _, again := OpenPublicationStore(c); again == nil || again.Error() != "ownership_publication_locked" {
					t.Fatal("cold uncertain custody released its raw lifetime lock", again)
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				snap, e := cold.Snapshot()
				if e != nil || snap.RetainedJobs != 1 {
					t.Fatal("cold state lost", e)
				}
				if e = cold.Close(); e != nil {
					t.Fatal(e)
				}
			}
			if !reflect.DeepEqual(before, publicationTree(t, c.Directory)) {
				t.Fatal("cold Open mutated or repaired history")
			}
		})
	}
}

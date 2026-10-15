//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This helper extends the existing signed/encrypted synthetic protocol fixtures
// to a real TLS-observed alias. It creates no extra implementation or server
// beyond publicationTLSLeaves. Fixture owner aliases may use the fixture signing
// key; this is not a deployment of shared owner keys or a scientific acceptance.
func ingressPublicationFreshOwnerBundle(t *testing.T, cfg OwnerIngressConfig, state *tls.ConnectionState, leaf *x509.Certificate, key *rsa.PrivateKey) AcceptedBundle {
	t.Helper()
	f := fixture(t)
	owner, err := PrincipalFromTLS(state)
	if err != nil {
		t.Fatal(err)
	}
	job, err := storeRandom(8)
	if err != nil {
		t.Fatal(err)
	}
	token, err := storeRandom(32)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := SignChallenge(f.private, cfg.Pin, owner, ChallengeInput{job, token, "limit.fastq", f.now, f.now.Add(MaxChallengeLifetime)})
	if err != nil {
		t.Fatal(err)
	}
	challengeJSON, err := MarshalChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := EncryptForChallenge(challengeJSON, cfg.Pin, leaf, key, &payloadWorkerKey(t).PublicKey, []byte("authorizing limit"), f.now)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := Finalize(context.Background(), state, challengeJSON, payload.Manifest, cfg.Pin, bytes.NewReader(payload.Ciphertext), f.now)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := sealAcceptance(f.private, cfg.Pin, cfg.Scope, state, challengeJSON, payload.Manifest, binding, f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalAcceptance(accepted)
	if err != nil {
		t.Fatal(err)
	}
	return AcceptedBundle{Acceptance: raw, KeyEnvelope: payload.KeyEnvelope, Ciphertext: payload.Ciphertext}
}

type ingressPublicationLimitReader struct {
	reader *bytes.Reader
	calls  atomic.Int64
}

func (r *ingressPublicationLimitReader) Read(p []byte) (int, error) {
	r.calls.Add(1)
	return r.reader.Read(p)
}

func TestOwnerIngressPublicationAuthorizingEnforcesAdmissionLimits(t *testing.T) {
	for _, axis := range []string{"global_active", "principal_active"} {
		t.Run(axis, func(t *testing.T) {
			original, cfg, first, endpoint := ingressPublicationFixture(t)
			if err := original.Close(); err != nil {
				t.Fatal(err)
			}
			// Explicit fresh state, not a policy rewrite/adoption of existing state.
			cfg.Directory = filepath.Join(t.TempDir(), "limited-ingress")
			cfg.Policy.MaxActive = 2
			cfg.Policy.MaxPrincipalActive = 1
			f := fixture(t)
			secondState := &f.stateA
			second := ingressTestBundle(t, false)
			if axis == "global_active" {
				cfg.Policy.MaxActive = 1
				// This policy requires principal-active <= global-active. A distinct
				// CN ensures the second principal's own active counter is still zero,
				// leaving the global bound as the only active admission blocker.
				states, certs := publicationTLSLeaves(t, 1, f.keyA)
				secondState = &states[0]
				second = ingressPublicationFreshOwnerBundle(t, cfg, secondState, certs[0], f.keyA)
			}
			firstV, err := VerifyAcceptance(first.Acceptance, cfg.Pin, cfg.Scope)
			if err != nil {
				t.Fatal(err)
			}
			secondV, err := VerifyAcceptance(second.Acceptance, cfg.Pin, cfg.Scope)
			if err != nil {
				t.Fatal(err)
			}
			if firstV.Binding().JobID == secondV.Binding().JobID || firstV.Claims().Challenge.Claim.Nonce == secondV.Claims().Challenge.Claim.Nonce || firstV.SHA256() == secondV.SHA256() {
				t.Fatal("quota candidate was an idempotent duplicate")
			}
			ownerA, err := PrincipalFromTLS(&f.stateA)
			if err != nil {
				t.Fatal(err)
			}
			ownerB, err := PrincipalFromTLS(&f.stateB)
			if err != nil {
				t.Fatal(err)
			}
			principalA, err := quotaPrincipal(cfg.Namespace, ownerA)
			if err != nil {
				t.Fatal(err)
			}
			principalB, err := quotaPrincipal(cfg.Namespace, ownerB)
			if err != nil || principalA != principalB || ownerA.CredentialSHA256() == ownerB.CredentialSHA256() {
				t.Fatal("quota principal must follow namespace+CN, not exact owner leaf", err)
			}
			candidateOwner, err := PrincipalFromTLS(secondState)
			if err != nil {
				t.Fatal(err)
			}
			candidatePrincipal, err := quotaPrincipal(cfg.Namespace, candidateOwner)
			if err != nil || (candidatePrincipal == principalA) != (axis == "principal_active") {
				t.Fatal("active-axis control was confounded by quota principal", err)
			}
			store, err := CreateOwnerIngress(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ingressPublicationSimulateExit(store) })
			entered, release := make(chan struct{}), make(chan struct{})
			var enteredOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			endpoint.mu.Lock()
			endpoint.receipt = store.expectedPublication(firstV)
			endpoint.hook = func(r *http.Request) {
				if r.Method == http.MethodPost {
					enteredOnce.Do(func() { close(entered) })
					<-release
				}
			}
			endpoint.mu.Unlock()
			firstDone := make(chan error, 1)
			go func() {
				_, e := store.Accept(context.Background(), &f.stateA, first.Acceptance, first.KeyEnvelope, bytes.NewReader(first.Ciphertext), int64(len(first.Ciphertext)))
				firstDone <- e
				close(firstDone)
			}()
			defer func() {
				unblock()
				select {
				case <-firstDone:
				case <-time.After(4 * time.Second):
					t.Error("held publisher did not drain")
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("first job did not reach publisher response barrier")
			}
			before := store.Snapshot()
			if before.Jobs != 1 || before.Authorizing != 1 || before.Reading != 0 || before.ChargedBytes != store.ingressCharge() {
				t.Fatal("first job not authorizing under full permanent charge", before)
			}
			store.mu.Lock()
			firstPrincipal := store.data.Records[0].PrincipalSHA256
			firstState := store.data.Records[0].State
			store.mu.Unlock()
			if firstPrincipal != principalA || firstState != "authorizing" {
				t.Fatal("retained row does not use CN principal and authorizing phase")
			}
			history := publicationTree(t, cfg.Directory)
			candidateReader := &ingressPublicationLimitReader{reader: bytes.NewReader(second.Ciphertext)}
			rejected := make(chan error, 1)
			go func() {
				_, e := store.Accept(context.Background(), secondState, second.Acceptance, second.KeyEnvelope, candidateReader, int64(len(second.Ciphertext)))
				rejected <- e
				close(rejected)
			}()
			defer func() {
				unblock()
				select {
				case <-rejected:
				case <-time.After(4 * time.Second):
					t.Error("quota request did not drain")
				}
			}()
			select {
			case err := <-rejected:
				if err == nil || err.Error() != "ownership_ingress_quota" {
					t.Fatal("authorizing did not block the configured active limit", err)
				}
			case <-time.After(time.Second):
				t.Fatal("quota admission waited behind publisher network IO")
			}
			if candidateReader.calls.Load() != 0 || store.Snapshot() != before || !reflect.DeepEqual(history, publicationTree(t, cfg.Directory)) {
				t.Fatal("exceeded active limit read body, charged or changed history")
			}
			if posts, gets := endpoint.counts(); posts != 1 || gets != 0 {
				t.Fatal("quota rejection contacted publisher", posts, gets)
			}
			unblock()
			select {
			case err := <-firstDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("first publication did not finish")
			}
			// An explicit fresh attempt after the active slot is released is a
			// positive control for valid metadata/body, not an automatic retry.
			endpoint.mu.Lock()
			endpoint.hook = nil
			endpoint.receipt = store.expectedPublication(secondV)
			endpoint.mu.Unlock()
			positive := &ingressPublicationLimitReader{reader: bytes.NewReader(second.Ciphertext)}
			got, err := store.Accept(context.Background(), secondState, second.Acceptance, second.KeyEnvelope, positive, int64(len(second.Ciphertext)))
			if err != nil || got.AcceptanceSHA256 != secondV.SHA256() || positive.calls.Load() == 0 {
				t.Fatal("quota candidate was not valid after releasing active slot", err)
			}
			final := store.Snapshot()
			if final.Jobs != 2 || final.Authorizing != 0 || final.Delivered != 2 || final.ChargedBytes != 2*store.ingressCharge() {
				t.Fatal("explicit positive control accounting", final)
			}
			if posts, gets := endpoint.counts(); posts != 2 || gets != 0 {
				t.Fatal("positive control had unexpected publication attempts", posts, gets)
			}
		})
	}
}

func TestOwnerIngressPublicationColdChangedContextDoesNotAdopt(t *testing.T) {
	for _, changed := range []string{"authority_scope", "profile", "measured_ca"} {
		t.Run(changed, func(t *testing.T) {
			store, cfg, bundle, endpoint := ingressPublicationFixture(t)
			if _, err := store.Accept(context.Background(), &fixture(t).stateA, bundle.Acceptance, bundle.KeyEnvelope, bytes.NewReader(bundle.Ciphertext), int64(len(bundle.Ciphertext))); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			before := publicationTree(t, cfg.Directory)
			posts, gets := endpoint.counts()
			group := *cfg.Publication
			modified := cfg
			modified.Publication = &group
			switch changed {
			case "authority_scope":
				modified.Scope.StoreID = strings.Repeat("9", 32)
				group.Client.Client.Scope = modified.Scope
			case "profile":
				modified.Pin.ExecutionProfileSHA256 = strings.Repeat("e", 64)
				group.Client.Client.Pin = modified.Pin
			case "measured_ca":
				states, _ := publicationTLSLeaves(t, 1, fixture(t).keyA)
				chain := states[0].VerifiedChains[0]
				ca := chain[len(chain)-1]
				pool := x509.NewCertPool()
				pool.AddCert(ca)
				group.Client.Client.RootCAs = pool
				group.TrustSHA256 = digest(ca.Raw)
				if group.TrustSHA256 == cfg.Publication.TrustSHA256 {
					t.Fatal("CA identity did not change")
				}
			}
			// These are valid typed trust configurations; refusal must be the
			// retained ingress context, not a malformed client config/empty pool.
			client, err := NewPublicationClient(group.Client)
			if err != nil {
				t.Fatal(err)
			}
			client.CloseIdleConnections()
			cold, err := OpenOwnerIngress(modified)
			defer ingressPublicationSimulateExit(cold)
			if err == nil || err.Error() != "ownership_ingress_history_invalid" || cold == nil || !cold.rawHeld || !cold.sticky {
				t.Fatal("changed context adopted history or released acquired parent custody", err)
			}
			if !reflect.DeepEqual(before, publicationTree(t, cfg.Directory)) {
				t.Fatal("cold changed context mutated retained bytes/history")
			}
			// This observes HTTP application calls, not packet-level egress. Open
			// is filesystem-only; no child Publish/Recover is invoked in this path.
			if p, g := endpoint.counts(); p != posts || g != gets {
				t.Fatal("cold changed context made publication HTTP calls", p, g)
			}
			if _, statErr := os.Stat(filepath.Join(cfg.Directory, "jobs", store.data.Records[0].JobID+".json")); statErr != nil {
				t.Fatal("cold refusal removed retained job", statErr)
			}
		})
	}
}

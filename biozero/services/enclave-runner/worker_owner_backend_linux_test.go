//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	artifact "biozero/artifact-executor"
	ownership "biozero/ownership-authority"
)

type ownerWorkerCustodySpy struct {
	ownerWorkerCustodyAPI
	puts, lookups int
}

func (s *ownerWorkerCustodySpy) PutVerified(c context.Context, b OwnerWorkerBinding, a []byte) error {
	s.puts++
	return s.ownerWorkerCustodyAPI.PutVerified(c, b, a)
}
func (s *ownerWorkerCustodySpy) Lookup(j string) (OwnerWorkerBinding, bool, error) {
	s.lookups++
	return s.ownerWorkerCustodyAPI.Lookup(j)
}
func ownerWorkerGateBackend(t *testing.T, f *ownerWorkerTestFixture) (*ownerWorkerBackend, *ownerWorkerCustodySpy, *[3]int) {
	t.Helper()
	c, e := CreateOwnerWorkerCustody(context.Background(), filepath.Join(f.root, "worker-custody"), f.trust)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	spy := &ownerWorkerCustodySpy{ownerWorkerCustodyAPI: c}
	calls := new([3]int)
	b := &ownerWorkerBackend{material: ownerWorkerMaterial{trust: f.trust, key: f.workerKey, config: ownerWorkerConfig{UploadsDirectory: f.uploads, StageDirectory: filepath.Join(f.root, "stage-not-created"), TimeoutSeconds: 1}}, custody: spy, pending: map[string]OwnerWorkerBinding{}, stages: map[string]*VerifiedPlaintextStage{}, rejected: map[string]bool{}, stage: func(context.Context, string, string, []byte) (*VerifiedPlaintextStage, error) {
		calls[0]++
		return nil, errors.New("stage fixture boundary")
	}, call: func(context.Context, string, artifact.BridgeRequestV3, *os.File, *os.File) (artifact.BridgeResponseV3, *os.File, error) {
		calls[1]++
		return artifact.BridgeResponseV3{}, nil, errors.New("unexpected submit")
	}, publish: func(context.Context, ownerWorkerCache) error { calls[2]++; return nil }}
	return b, spy, calls
}
func TestOwnerWorkerCopiedCipherGetsRealBAcceptanceButFailsBeforeStageCustodySubmit(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	a := f.bundle(t, false, nil)
	other := f.bundle(t, true, &a)
	accepted, e := ownership.VerifyAcceptance(other.Acceptance, f.pin, f.scope)
	if e != nil || accepted.Binding().CredentialSHA256 != workerCustodyDigest(f.leafs[1].Raw) {
		t.Fatal("fixture did not obtain B's legitimate signed acceptance")
	}
	valid, e := verifyOwnerWorkerInput(context.Background(), a.Job, a.Acceptance, f.pin, f.scope, f.workerKey, f.uploads)
	if e != nil || !bytes.Equal(valid.Plaintext, a.Plaintext) {
		t.Fatal("positive actual AAD control failed", e)
	}
	clear(valid.Plaintext)
	if !bytes.Equal(a.Ciphertext, other.Ciphertext) || !bytes.Equal(a.Envelope, other.Envelope) {
		t.Fatal("fixture copied bytes changed")
	}
	before := f.store.Snapshot()
	ledgerPath := filepath.Join(f.root, "authority", "ledger.json")
	ledgerBefore, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	b, c, calls := ownerWorkerGateBackend(t, f)
	e = b.process(context.Background(), other.Job, other.Acceptance)
	if e == nil || e.Error() != "owner_worker_payload_authentication_failed" || calls[0] != 0 || calls[1] != 0 || calls[2] != 0 || c.puts != 0 {
		t.Fatal("B's copied payload reached plaintext/custody/Submit", e, *calls, c.puts)
	}
	bindings, e := c.Bindings()
	if e != nil || len(bindings) != 0 {
		t.Fatal("rejected GCM consumed verified custody", e)
	}
	if !reflect.DeepEqual(before, f.store.Snapshot()) {
		t.Fatal("worker rejection changed retained authority history/charge")
	}
	ledgerAfter, err := os.ReadFile(ledgerPath)
	if err != nil || !bytes.Equal(ledgerBefore, ledgerAfter) {
		t.Fatal("worker rejection changed physical authority ledger")
	}
	if raw, e := os.ReadFile(filepath.Join(f.uploads, other.Job.JobID+"_"+other.Job.OriginalName)); e != nil || !bytes.Equal(raw, a.Ciphertext) {
		t.Fatal("rejection altered original ciphertext")
	}
	if _, e := os.Stat(b.material.config.StageDirectory); !os.IsNotExist(e) {
		t.Fatal("rejection persisted plaintext")
	}
}
func TestOwnerWorkerVerificationGatesHaveValidUnshadowedControl(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	a := f.bundle(t, false, nil)
	cases := []struct {
		name, code string
		mutate     func(*ownerWorkerJob, *[]byte)
	}{
		{"job", "owner_worker_binding_mismatch", func(j *ownerWorkerJob, _ *[]byte) { j.JobID = strings.Repeat("9", 16) }},
		{"name", "owner_worker_binding_mismatch", func(j *ownerWorkerJob, _ *[]byte) { j.OriginalName = "other.fastq" }},
		{"hash", "owner_worker_binding_mismatch", func(j *ownerWorkerJob, _ *[]byte) { j.SHA256 = strings.Repeat("9", 64) }},
		{"size", "owner_worker_binding_mismatch", func(j *ownerWorkerJob, _ *[]byte) { j.SizeBytes++ }},
		{"algorithm", "owner_worker_binding_mismatch", func(j *ownerWorkerJob, _ *[]byte) { j.EncAlg = "aes-256-gcm+rsa-oaep-sha256" }},
		{"acceptance_hash", "owner_worker_binding_mismatch", func(j *ownerWorkerJob, _ *[]byte) { j.OwnershipAcceptanceSHA256 = strings.Repeat("9", 64) }},
		{"owner_header", "owner_worker_binding_mismatch", func(j *ownerWorkerJob, _ *[]byte) { j.ClientID = "other" }},
		{"envelope", "owner_worker_envelope_invalid", func(j *ownerWorkerJob, _ *[]byte) { j.EncKey = strings.Repeat("00", 256) }},
		{"ambiguous_acceptance", "owner_worker_acceptance_invalid", func(_ *ownerWorkerJob, r *[]byte) { *r = append(*r, []byte(" {}")...) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := a.Job
			raw := append([]byte(nil), a.Acceptance...)
			tc.mutate(&j, &raw)
			v, e := verifyOwnerWorkerInput(context.Background(), j, raw, f.pin, f.scope, f.workerKey, f.uploads)
			clear(v.Plaintext)
			if e == nil || e.Error() != tc.code {
				t.Fatal("gate not reached", e)
			}
		})
	}
	// Removing the input proves the envelope negative is before ciphertext IO,
	// while an unmodified envelope reaches the distinct ciphertext-read gate.
	path := filepath.Join(f.uploads, a.Job.JobID+"_"+a.Job.OriginalName)
	if e := os.Rename(path, path+".retained"); e != nil {
		t.Fatal(e)
	}
	j := a.Job
	j.EncKey = strings.Repeat("00", 256)
	if _, e := verifyOwnerWorkerInput(context.Background(), j, a.Acceptance, f.pin, f.scope, f.workerKey, f.uploads); e == nil || e.Error() != "owner_worker_envelope_invalid" {
		t.Fatal("bad envelope read unavailable body", e)
	}
	if _, e := verifyOwnerWorkerInput(context.Background(), a.Job, a.Acceptance, f.pin, f.scope, f.workerKey, f.uploads); e == nil || e.Error() != "owner_worker_ciphertext_invalid" {
		t.Fatal("positive envelope control shadowed", e)
	}
}
func TestOwnerWorkerPositiveCryptoAloneReachesStageBoundary(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	a := f.bundle(t, false, nil)
	b, c, calls := ownerWorkerGateBackend(t, f)
	e := b.process(context.Background(), a.Job, a.Acceptance)
	if e == nil || e.Error() != "owner_worker_stage_unavailable" || calls[0] != 1 || calls[1] != 0 || c.puts != 0 {
		t.Fatal("valid crypto did not reach exactly stage boundary", e, *calls, c.puts)
	}
	// Stage failure is an admission fence; it never becomes permission to submit.
	_ = b.process(context.Background(), a.Job, a.Acceptance)
	if calls[0] != 1 || calls[1] != 0 {
		t.Fatal("stage uncertainty retried")
	}
}
func TestOwnerWorkerCancellationAndRejectedCardinalityFence(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	a := f.bundle(t, false, nil)
	b, c, calls := ownerWorkerGateBackend(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := b.process(ctx, a.Job, a.Acceptance); e == nil || c.lookups != 0 || calls[0] != 0 {
		t.Fatal("cancelled worker entered custody")
	}
	for i := 0; i < 64; i++ {
		b.rejected[strings.Repeat("0", 14)+string("0123456789abcdef"[i/16])+string("0123456789abcdef"[i%16])] = true
	}
	if e := b.process(context.Background(), a.Job, a.Acceptance); e == nil || e.Error() != "owner_worker_rejection_budget" || len(b.rejected) != 64 || !b.admissionBlocked || calls[0] != 0 || c.puts != 0 {
		t.Fatal("rotating spool escaped cardinality fence", e)
	}
}
func TestOwnerWorkerKnownCustodyIgnoresMutableTerminalCacheAndDoesNotDecrypt(t *testing.T) {
	f := newOwnerWorkerTestFixture(t)
	a := f.bundle(t, false, nil)
	input, e := verifyOwnerWorkerInput(context.Background(), a.Job, a.Acceptance, f.pin, f.scope, f.workerKey, f.uploads)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(input.Plaintext)
	b, c, calls := ownerWorkerGateBackend(t, f)
	v := b.bindInput(input)
	if e = c.PutVerified(context.Background(), v, input.CanonicalAcceptance); e != nil {
		t.Fatal(e)
	}
	// Neither a forged result marker nor removal of ALL spool input can grant a
	// new Submit. Recovery uses private custody even if caller job fields lie.
	b.material.config.ResultsDirectory = filepath.Join(f.root, "results")
	if e = os.Mkdir(b.material.config.ResultsDirectory, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(b.material.config.ResultsDirectory, a.Job.JobID+".json"), []byte(`{"status":"succeeded","release_status":"evaluated_passed"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(f.uploads, a.Job.JobID+"_"+a.Job.OriginalName)); e != nil {
		t.Fatal(e)
	}
	var ops []string
	b.call = func(_ context.Context, _ string, q artifact.BridgeRequestV3, p, a *os.File) (artifact.BridgeResponseV3, *os.File, error) {
		ops = append(ops, q.Operation)
		if q.AcceptanceSHA256 != v.AcceptanceSHA256 || p != nil || a != nil {
			t.Fatal("recovery request changed owner or carried FD")
		}
		return artifact.BridgeResponseV3{}, nil, errors.New("query fixture unavailable")
	}
	forged := a.Job
	forged.Status = "succeeded"
	forged.SHA256 = strings.Repeat("9", 64)
	b.rejected[forged.JobID] = true
	b.admissionBlocked = true
	if e = b.process(context.Background(), forged, nil); e == nil || len(ops) != 1 || ops[0] != "status" || calls[0] != 0 || c.puts != 1 {
		t.Fatal("custody recovery trusted mutable metadata or retried", e, ops)
	}
}

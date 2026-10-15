//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

const clientStepLimit = 96 << 10

var clientStepNames = []string{"00-intent.json", "01-challenge.json", "02-prepared.json", "03-finalize.json", "04-accepted.json"}

// ClientOperationConfig is trusted local configuration. Roots, endpoint, external
// authority scope/pin and worker encryption key are provisioned by the caller.
// Directory is one new operation, never an automatically recycled workspace.
type ClientOperationConfig struct {
	Directory     string
	Client        AuthorityClientConfig
	EncryptionKey *rsa.PublicKey
	OriginalName  string
}

type clientOperationStep struct {
	SchemaVersion    int    `json:"schema_version"`
	Domain           string `json:"domain"`
	Sequence         int    `json:"sequence"`
	ContextSHA256    string `json:"context_sha256"`
	PreviousSHA256   string `json:"previous_sha256"`
	RequestID        string `json:"request_id"`
	ChallengeJSON    string `json:"challenge_json"`
	ManifestJSON     string `json:"manifest_json"`
	EnvelopeHex      string `json:"envelope_hex"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	CiphertextBytes  int64  `json:"ciphertext_bytes"`
	AcceptanceJSON   string `json:"acceptance_json"`
}

// ClientOperation retains encrypted input, original challenge/manifest bytes and
// a verified acceptance (canonical serialization when recovered through Get).
// It is not an execution queue. Open does no network IO. Recover only queries the
// already-known job. All methods serialize; a failed filesystem publication keeps
// a raw lifetime flock until actual process death, including loss of Go handles.
type ClientOperation struct {
	mu             sync.Mutex
	config         ClientOperationConfig
	client         *AuthorityClient
	leaf           *x509.Certificate
	key            *rsa.PrivateKey
	root, lock     *os.File
	rawFD          int
	rawHeld        bool
	hashes         map[string]string
	step           clientOperationStep
	contextSHA     string
	sticky, closed bool
	preparing      bool
	fault          func(string) error // Tests only; never configured by clients or ingress.
}

func CreateClientOperation(config ClientOperationConfig) (*ClientOperation, error) {
	return openClientOperation(config, true)
}
func OpenClientOperation(config ClientOperationConfig) (*ClientOperation, error) {
	return openClientOperation(config, false)
}

func openClientOperation(config ClientOperationConfig, create bool) (*ClientOperation, error) {
	if !filepath.IsAbs(config.Directory) || filepath.Clean(config.Directory) != config.Directory || !nameValid(config.OriginalName) || !payloadPublicKey(config.EncryptionKey) {
		return nil, fail("ownership_client_config_invalid")
	}
	client, err := NewAuthorityClient(config.Client)
	if err != nil {
		return nil, err
	}
	failClient := func(err error) (*ClientOperation, error) { client.CloseIdleConnections(); return nil, err }
	// Reparse copied key material; retained state must not alias mutable caller keys.
	if len(config.Client.Certificate.Certificate) == 0 {
		return failClient(fail("ownership_client_config_invalid"))
	}
	leaf, err := x509.ParseCertificate(append([]byte(nil), config.Client.Certificate.Certificate[0]...))
	if err != nil {
		return failClient(fail("ownership_client_config_invalid"))
	}
	key, ok := config.Client.Certificate.PrivateKey.(*rsa.PrivateKey)
	if !ok || key == nil || key.Validate() != nil {
		return failClient(fail("ownership_client_config_invalid"))
	}
	key, err = x509.ParsePKCS1PrivateKey(x509.MarshalPKCS1PrivateKey(key))
	if err != nil {
		return failClient(fail("ownership_client_config_invalid"))
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(config.EncryptionKey)
	if err != nil {
		return failClient(fail("ownership_client_config_invalid"))
	}
	pub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		return failClient(fail("ownership_client_config_invalid"))
	}
	config.EncryptionKey = pub.(*rsa.PublicKey)
	config.Client.Pin.PublicKey = append([]byte(nil), config.Client.Pin.PublicKey...)
	contextBytes, _ := json.Marshal(struct {
		Endpoint, ServerName, Authority, PublicKey, Mode, Profile, Store, Policy, Credential, EncryptionKey, OriginalName string
	}{config.Client.BaseURL, config.Client.ServerName, config.Client.Pin.AuthorityID, hex.EncodeToString(config.Client.Pin.PublicKey), config.Client.Pin.PipelineMode, config.Client.Pin.ExecutionProfileSHA256, config.Client.Scope.StoreID, config.Client.Scope.PolicySHA256, digest(leaf.Raw), digest(pubBytes), config.OriginalName})
	root, err := storeRoot(config.Directory, create)
	if err != nil {
		return failClient(err)
	}
	o := &ClientOperation{config: config, client: client, leaf: leaf, key: key, root: root, hashes: map[string]string{}, contextSHA: digest(contextBytes)}
	success := false
	defer func() {
		if !success {
			if !o.sticky {
				if o.rawHeld {
					syscall.Close(o.rawFD)
					o.rawHeld = false
				}
				if o.lock != nil {
					o.lock.Close()
				}
				root.Close()
			}
			client.CloseIdleConnections()
		}
	}()
	o.lock, err = storeFile(root, "instance.lock", create)
	if err != nil {
		return nil, fail("ownership_client_lock_unsafe")
	}
	info, err := o.lock.Stat()
	if err != nil || info.Size() != 0 {
		return nil, fail("ownership_client_lock_unsafe")
	}
	if syscall.Flock(int(o.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, fail("ownership_client_locked")
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, o.lock.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return nil, fail("ownership_client_lock_unsafe")
	}
	o.rawFD = int(fd)
	o.rawHeld = true
	if create {
		if o.lock.Sync() != nil || root.Sync() != nil {
			return nil, o.latch()
		}
		token, err := storeRandom(16)
		if err != nil {
			return nil, err
		}
		o.step = clientOperationStep{SchemaVersion: 1, Domain: "biozero.ownership.client-operation.v1", Sequence: -1, ContextSHA256: o.contextSHA, RequestID: token}
		next := o.step
		next.Sequence = 0
		if err = o.publish(next, nil); err != nil {
			return nil, err
		}
	} else {
		names, err := o.names()
		if err != nil {
			return nil, err
		}
		if len(names) < 2 {
			return nil, fail("ownership_client_history_unknown")
		}
		expected := map[string]bool{"instance.lock": true}
		for i, name := range clientStepNames {
			found := false
			for _, n := range names {
				if n == name {
					found = true
				}
			}
			if !found {
				break
			}
			raw, err := storeRead(root, name, clientStepLimit)
			if err != nil {
				return nil, err
			}
			var step clientOperationStep
			if err = strictJSON(raw, &step, clientStepLimit); err != nil {
				return nil, err
			}
			if err = o.validateStep(step, i); err != nil {
				return nil, err
			}
			o.step = step
			o.hashes[name] = digest(raw)
			expected[name] = true
		}
		if len(o.hashes) == 0 {
			return nil, fail("ownership_client_history_unknown")
		}
		if o.step.Sequence >= 2 {
			expected["ciphertext.bin"] = true
			raw, err := storeRead(root, "ciphertext.bin", MaxCiphertextBytes)
			if err != nil || digest(raw) != o.step.CiphertextSHA256 || int64(len(raw)) != o.step.CiphertextBytes {
				return nil, fail("ownership_client_payload_changed")
			}
			o.hashes["ciphertext.bin"] = digest(raw)
		}
		if len(expected) != len(names) {
			return nil, fail("ownership_client_history_unknown")
		}
		for _, n := range names {
			if !expected[n] {
				return nil, fail("ownership_client_history_unknown")
			}
		}
	}
	success = true
	return o, nil
}

func (o *ClientOperation) names() ([]string, error) {
	fd, err := syscall.Openat(int(o.root.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail("ownership_client_history_unknown")
	}
	f := os.NewFile(uintptr(fd), "ownership-client-scan")
	defer f.Close()
	entries, err := f.ReadDir(10)
	if err != nil && err != io.EOF || len(entries) > 8 {
		return nil, fail("ownership_client_history_unknown")
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}
func (o *ClientOperation) latch() error {
	o.sticky = true
	return fail("ownership_client_state_uncertain")
}
func (o *ClientOperation) point(name string) error {
	if o.fault != nil {
		return o.fault(name)
	}
	return nil
}
func (o *ClientOperation) preflight() error {
	if o.closed || o.sticky || o.root == nil || o.lock == nil {
		return fail("ownership_client_unavailable")
	}
	fresh, err := storeRoot(o.config.Directory, false)
	if err != nil {
		return o.latch()
	}
	a, e1 := fresh.Stat()
	fresh.Close()
	b, e2 := o.root.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(a, b) {
		return o.latch()
	}
	lock, err := storeFile(o.root, "instance.lock", false)
	if err != nil {
		return o.latch()
	}
	a, e1 = lock.Stat()
	lock.Close()
	b, e2 = o.lock.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(a, b) || a.Size() != 0 {
		return o.latch()
	}
	names, err := o.names()
	expectedCount := len(o.hashes) + 1
	if o.preparing {
		expectedCount++
	}
	if err != nil || len(names) != expectedCount {
		return o.latch()
	}
	for _, name := range names {
		if name == "instance.lock" {
			continue
		}
		if o.preparing && name == "prepare.intent" {
			raw, e := storeRead(o.root, name, 32)
			if e != nil || string(raw) != "preparing" {
				return o.latch()
			}
			continue
		}
		h, ok := o.hashes[name]
		if !ok {
			return o.latch()
		}
		limit := int64(clientStepLimit)
		if name == "ciphertext.bin" {
			limit = MaxCiphertextBytes
		}
		raw, err := storeRead(o.root, name, limit)
		if err != nil || digest(raw) != h {
			return o.latch()
		}
	}
	return nil
}

// publish is append-only. The marker precedes any new bytes. Unknown/partial
// phases are never adopted or removed on Open. As with Store, a crash after
// marker unlink but failed parent sync need not retain that marker universally.
func (o *ClientOperation) publish(next clientOperationStep, ciphertext []byte) error {
	if err := o.preflight(); err != nil {
		return err
	}
	raw, err := boundedJSON(next, clientStepLimit)
	if err != nil {
		return err
	}
	marker, err := storeFile(o.root, "client.intent", true)
	if err != nil {
		return o.latch()
	}
	write := func(f *os.File, data []byte) error {
		n, e := f.Write(data)
		if e == nil && n != len(data) {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = o.point("file_sync")
		}
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		return e
	}
	if write(marker, []byte(digest(raw))) != nil || o.root.Sync() != nil {
		return o.latch()
	}
	if ciphertext != nil {
		f, e := storeFile(o.root, "ciphertext.bin", true)
		if e != nil {
			return o.latch()
		}
		if write(f, ciphertext) != nil {
			return o.latch()
		}
	}
	f, err := storeFile(o.root, clientStepNames[next.Sequence], true)
	if err != nil {
		return o.latch()
	}
	if write(f, raw) != nil {
		return o.latch()
	}
	if o.point("directory_sync") != nil || o.root.Sync() != nil {
		return o.latch()
	}
	if o.point("intent_unlink") != nil || syscall.Unlinkat(int(o.root.Fd()), "client.intent") != nil || o.root.Sync() != nil {
		return o.latch()
	}
	o.step = next
	o.hashes[clientStepNames[next.Sequence]] = digest(raw)
	if ciphertext != nil {
		o.hashes["ciphertext.bin"] = digest(ciphertext)
	}
	return nil
}
func (o *ClientOperation) next(sequence int) clientOperationStep {
	s := o.step
	s.Sequence = sequence
	s.PreviousSHA256 = o.hashes[clientStepNames[sequence-1]]
	return s
}
func (o *ClientOperation) challenge(raw []byte) (VerifiedChallenge, error) {
	var signed SignedChallenge
	if err := strictJSON(raw, &signed, MaxChallengeBytes); err != nil {
		return VerifiedChallenge{}, err
	}
	issued, err := canonicalTime(signed.Claim.IssuedAt)
	if err != nil {
		return VerifiedChallenge{}, err
	}
	v, err := VerifyChallengeForClient(raw, o.config.Client.Pin, o.leaf, issued)
	if err != nil {
		return v, err
	}
	if v.Claims().OriginalName != o.config.OriginalName {
		return VerifiedChallenge{}, fail("ownership_client_history_mismatch")
	}
	return v, nil
}
func (o *ClientOperation) validateStep(s clientOperationStep, i int) error {
	if s.SchemaVersion != 1 || s.Domain != "biozero.ownership.client-operation.v1" || s.Sequence != i || s.ContextSHA256 != o.contextSHA || !hexValue(s.RequestID, 32) {
		return fail("ownership_client_history_mismatch")
	}
	if i == 0 {
		if s.PreviousSHA256 != "" {
			return fail("ownership_client_history_mismatch")
		}
	} else {
		if s.PreviousSHA256 != o.hashes[clientStepNames[i-1]] || s.RequestID != o.step.RequestID {
			return fail("ownership_client_history_mismatch")
		}
		// Earlier original facts cannot be changed by appending another phase.
		prior := o.step
		if i > 1 && s.ChallengeJSON != prior.ChallengeJSON || i > 2 && (s.ManifestJSON != prior.ManifestJSON || s.EnvelopeHex != prior.EnvelopeHex || s.CiphertextSHA256 != prior.CiphertextSHA256 || s.CiphertextBytes != prior.CiphertextBytes) {
			return fail("ownership_client_history_mismatch")
		}
	}
	if i < 1 {
		if s.ChallengeJSON != "" {
			return fail("ownership_client_history_mismatch")
		}
	} else {
		if _, err := o.challenge([]byte(s.ChallengeJSON)); err != nil {
			return err
		}
	}
	if i < 2 {
		if s.ManifestJSON != "" || s.EnvelopeHex != "" || s.CiphertextSHA256 != "" || s.CiphertextBytes != 0 {
			return fail("ownership_client_history_mismatch")
		}
	} else {
		v, err := o.challenge([]byte(s.ChallengeJSON))
		if err != nil {
			return err
		}
		if err = verifyClientManifest([]byte(s.ManifestJSON), v, o.leaf); err != nil {
			return err
		}
		var manifest SignedManifest
		if err = strictJSON([]byte(s.ManifestJSON), &manifest, MaxManifestBytes); err != nil {
			return err
		}
		env, err := hex.DecodeString(s.EnvelopeHex)
		if err != nil || len(env) < 256 || len(env) > 512 || digest(env) != manifest.Manifest.KeyEnvelopeSHA256 || s.CiphertextSHA256 != manifest.Manifest.CiphertextSHA256 || s.CiphertextBytes != manifest.Manifest.CiphertextBytes {
			return fail("ownership_client_history_mismatch")
		}
	}
	if i < 4 {
		if s.AcceptanceJSON != "" {
			return fail("ownership_client_history_mismatch")
		}
	} else {
		if err := o.matchAcceptance([]byte(s.AcceptanceJSON), s); err != nil {
			return err
		}
	}
	return nil
}
func (o *ClientOperation) matchAcceptance(raw []byte, s clientOperationStep) error {
	v, err := VerifyAcceptance(raw, o.config.Client.Pin, o.config.Client.Scope)
	if err != nil {
		return err
	}
	rec := v.Claims()
	ch, _ := MarshalChallenge(rec.Challenge)
	m, _ := MarshalManifest(rec.Manifest)
	stored, err := o.challenge([]byte(s.ChallengeJSON))
	if err != nil {
		return err
	}
	if !bytes.Equal(ch, stored.canonical) || digest(m) != digest([]byte(s.ManifestJSON)) || rec.Binding.CredentialSHA256 != digest(o.leaf.Raw) || rec.Binding.CiphertextSHA256 != s.CiphertextSHA256 || rec.Binding.CiphertextBytes != s.CiphertextBytes {
		return fail("ownership_client_acceptance_mismatch")
	}
	env, err := hex.DecodeString(s.EnvelopeHex)
	if err != nil || rec.Binding.KeyEnvelopeSHA256 != digest(env) {
		return fail("ownership_client_acceptance_mismatch")
	}
	return nil
}

// State returns a coarse local phase, never an execution/scientific verdict.
func (o *ClientOperation) State() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return "closed"
	}
	if o.sticky {
		return "unavailable"
	}
	return []string{"intent", "reserved", "prepared", "finalizing", "accepted"}[o.step.Sequence]
}
func (o *ClientOperation) JobID() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.step.ChallengeJSON == "" {
		return ""
	}
	v, err := o.challenge([]byte(o.step.ChallengeJSON))
	if err != nil {
		return ""
	}
	return v.Claims().JobID
}

// Reserve is an explicit idempotent action on the original durable request ID.
// Open never calls it. A caller recovering a lost reservation response must choose
// this operation explicitly; it cannot request a fresh identity in this workspace.
func (o *ClientOperation) Reserve(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.preflight(); err != nil {
		return err
	}
	if ctx == nil || ctx.Err() != nil {
		return fail("ownership_cancelled")
	}
	if o.step.Sequence != 0 {
		return fail("ownership_client_phase_invalid")
	}
	raw, err := o.client.Reserve(ctx, HTTPReserveRequest{1, o.step.RequestID, o.config.OriginalName})
	if err != nil {
		return err
	}
	if _, err = o.challenge(raw); err != nil {
		return err
	}
	next := o.next(1)
	next.ChallengeJSON = string(raw)
	return o.publish(next, nil)
}
func (o *ClientOperation) Prepare(ctx context.Context, plaintext []byte, now time.Time) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.preflight(); err != nil {
		return err
	}
	if ctx == nil || ctx.Err() != nil {
		return fail("ownership_cancelled")
	}
	if o.step.Sequence != 1 {
		return fail("ownership_client_phase_invalid")
	}
	if int64(len(plaintext)) > MaxPlaintextBytes {
		return fail("ownership_payload_invalid")
	}
	// Preserve a durable preparation marker BEFORE generating symmetric material.
	// publish already owns this marker, so prepare under a distinct retained fence.
	marker, err := storeFile(o.root, "prepare.intent", true)
	if err != nil {
		return o.latch()
	}
	if n, writeErr := marker.Write([]byte("preparing")); writeErr != nil || n != len("preparing") {
		marker.Close()
		return o.latch()
	}
	if marker.Sync() != nil {
		marker.Close()
		return o.latch()
	}
	if marker.Close() != nil || o.root.Sync() != nil {
		return o.latch()
	}
	o.preparing = true
	encrypted, err := EncryptForChallenge([]byte(o.step.ChallengeJSON), o.config.Client.Pin, o.leaf, o.key, o.config.EncryptionKey, plaintext, now)
	if err != nil {
		return o.latch()
	}
	if ctx.Err() != nil {
		return o.latch()
	}
	next := o.next(2)
	next.ManifestJSON = string(encrypted.Manifest)
	next.EnvelopeHex = hex.EncodeToString(encrypted.KeyEnvelope)
	next.CiphertextSHA256 = digest(encrypted.Ciphertext)
	next.CiphertextBytes = int64(len(encrypted.Ciphertext))
	if err = o.publish(next, encrypted.Ciphertext); err != nil {
		return err
	}
	if syscall.Unlinkat(int(o.root.Fd()), "prepare.intent") != nil || o.root.Sync() != nil {
		return o.latch()
	}
	o.preparing = false
	return nil
}
func (o *ClientOperation) Finalize(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.preflight(); err != nil {
		return err
	}
	if ctx == nil || ctx.Err() != nil {
		return fail("ownership_cancelled")
	}
	if o.step.Sequence != 2 {
		return fail("ownership_client_phase_invalid")
	}
	ciphertext, err := storeRead(o.root, "ciphertext.bin", MaxCiphertextBytes)
	if err != nil {
		return o.latch()
	}
	if err = o.publish(o.next(3), nil); err != nil {
		return err
	}
	raw, err := o.client.Finalize(ctx, []byte(o.step.ChallengeJSON), []byte(o.step.ManifestJSON), bytes.NewReader(ciphertext), o.step.CiphertextBytes)
	if err != nil {
		return err
	}
	if err = o.matchAcceptance(raw, o.step); err != nil {
		return err
	}
	next := o.next(4)
	next.AcceptanceJSON = string(raw)
	return o.publish(next, nil)
}

// Recover is query-only: no Reserve, encryption, Finalize or upload is invoked.
// A reserved/reading/rejected/unknown authority response remains retained and
// requires an explicit later operator decision; this method cannot resubmit it.
func (o *ClientOperation) Recover(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.preflight(); err != nil {
		return err
	}
	if ctx == nil || ctx.Err() != nil {
		return fail("ownership_cancelled")
	}
	if o.step.Sequence == 4 {
		return nil
	}
	if o.step.Sequence != 3 {
		return fail("ownership_client_phase_invalid")
	}
	ch, err := o.challenge([]byte(o.step.ChallengeJSON))
	if err != nil {
		return err
	}
	result, err := o.client.Get(ctx, ch.Claims().JobID)
	if err != nil {
		return err
	}
	if result.State != "accepted" || result.Acceptance == nil {
		return fail("ownership_client_authority_pending")
	}
	raw, err := MarshalAcceptance(*result.Acceptance)
	if err != nil {
		return err
	}
	if err = o.matchAcceptance(raw, o.step); err != nil {
		return err
	}
	next := o.next(4)
	next.AcceptanceJSON = string(raw)
	return o.publish(next, nil)
}
func (o *ClientOperation) Acceptance() ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.preflight(); err != nil {
		return nil, err
	}
	if o.step.Sequence != 4 {
		return nil, fail("ownership_client_phase_invalid")
	}
	return []byte(o.step.AcceptanceJSON), nil
}
func (o *ClientOperation) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	if err := o.preflight(); err != nil {
		return err
	}
	o.client.CloseIdleConnections()
	if o.point("close_root") != nil || o.root.Close() != nil {
		return o.latch()
	}
	if o.point("close_lock") != nil || o.lock.Close() != nil {
		return o.latch()
	}
	if o.rawHeld {
		if syscall.Close(o.rawFD) != nil {
			return o.latch()
		}
		o.rawHeld = false
	}
	o.closed = true
	return nil
}

//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
)

const clientDeliveryStepLimit = 96 << 10
const clientDeliveryReceiptLimit = 4096

var clientDeliveryStepNames = []string{"00-bundle.json", "01-delivering.json", "02-delivered.json"}

type clientDeliveryTrust struct {
	Endpoint              string `json:"endpoint"`
	ServerName            string `json:"server_name"`
	AuthorityID           string `json:"authority_id"`
	PublicKey             string `json:"public_key"`
	PipelineMode          string `json:"pipeline_mode"`
	ProfileSHA256         string `json:"profile_sha256"`
	AuthorityStoreID      string `json:"authority_store_id"`
	AuthorityPolicySHA256 string `json:"authority_policy_sha256"`
	CredentialSHA256      string `json:"credential_sha256"`
}
type clientDeliveryStep struct {
	SchemaVersion    int                 `json:"schema_version"`
	Domain           string              `json:"domain"`
	Sequence         int                 `json:"sequence"`
	Context          clientDeliveryTrust `json:"context"`
	ContextSHA256    string              `json:"context_sha256"`
	PreviousSHA256   string              `json:"previous_sha256"`
	JobID            string              `json:"job_id"`
	AcceptanceJSON   string              `json:"acceptance_json"`
	EnvelopeHex      string              `json:"envelope_hex"`
	CiphertextSHA256 string              `json:"ciphertext_sha256"`
	CiphertextBytes  int64               `json:"ciphertext_bytes"`
	Receipt          OwnerUploadReceipt  `json:"receipt"`
}

// ClientDelivery is an isolated append-only transport journal. It retains the
// accepted encrypted bundle, never plaintext or unwrapped keys. Delivered is a
// matching upload-service transport acknowledgement, not ownership, execution
// or scientific authority. A compromised upload service can fabricate that ACK.
// After intent publication, all recovery is GET-only. Raw flock custody survives
// sticky IO failure and lost Go handles until actual process exit.
type ClientDelivery struct {
	mu             sync.Mutex
	directory      string
	client         *AuthorityClient
	root, lock     *os.File
	rawFD          int
	rawHeld        bool
	hashes         map[string]string
	trust          clientDeliveryTrust
	contextSHA     string
	step           clientDeliveryStep
	expected       OwnerUploadReceipt
	sticky, closed bool
	fault          func(string) error // tests only; no configuration or wire fault controls
}

// CreateClientDelivery verifies the complete accepted bundle against external
// pin/scope, this exact TLS leaf, actual ciphertext and decoded envelope before
// creating one new private directory. Parent directories must already exist.
func CreateClientDelivery(ctx context.Context, directory string, config AuthorityClientConfig, bundle AcceptedBundle) (*ClientDelivery, error) {
	return openClientDelivery(ctx, directory, config, &bundle, true)
}

// OpenClientDelivery validates existing exact history without any network call.
// It neither creates nor adopts an incomplete or previously used directory.
func OpenClientDelivery(ctx context.Context, directory string, config AuthorityClientConfig) (*ClientDelivery, error) {
	return openClientDelivery(ctx, directory, config, nil, false)
}
func openClientDelivery(ctx context.Context, directory string, config AuthorityClientConfig, bundle *AcceptedBundle, create bool) (*ClientDelivery, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" {
		return nil, fail("ownership_delivery_config_invalid")
	}
	client, e := NewAuthorityClient(config)
	if e != nil {
		return nil, e
	}
	d := &ClientDelivery{directory: directory, client: client, rawFD: -1, hashes: map[string]string{}}
	d.trust = clientDeliveryTrust{client.base, config.ServerName, client.pin.AuthorityID, hex.EncodeToString(client.pin.PublicKey), client.pin.PipelineMode, client.pin.ExecutionProfileSHA256, client.scope.StoreID, client.scope.PolicySHA256, digest(client.leaf.Raw)}
	trustBytes, _ := json.Marshal(d.trust)
	d.contextSHA = digest(trustBytes)
	var ciphertext []byte
	if create {
		if bundle == nil || len(bundle.Acceptance) < 1 || len(bundle.Acceptance) > MaxAcceptanceBytes || len(bundle.KeyEnvelope) < 256 || len(bundle.KeyEnvelope) > 512 || len(bundle.Ciphertext) < 16 || int64(len(bundle.Ciphertext)) > MaxCiphertextBytes {
			client.CloseIdleConnections()
			return nil, fail("ownership_delivery_bundle_invalid")
		}
		copied := AcceptedBundle{Acceptance: append([]byte(nil), bundle.Acceptance...), KeyEnvelope: append([]byte(nil), bundle.KeyEnvelope...), Ciphertext: append([]byte(nil), bundle.Ciphertext...)}
		canonical, expected, e := d.verifyBundle(copied)
		if e != nil {
			client.CloseIdleConnections()
			return nil, e
		}
		d.expected = expected
		d.step = clientDeliveryStep{SchemaVersion: 1, Domain: "biozero.ownership.client-delivery.v1", Sequence: -1, Context: d.trust, ContextSHA256: d.contextSHA, JobID: expected.JobID, AcceptanceJSON: string(canonical), EnvelopeHex: hex.EncodeToString(copied.KeyEnvelope), CiphertextSHA256: expected.CiphertextSHA256, CiphertextBytes: expected.CiphertextBytes}
		ciphertext = copied.Ciphertext
	}
	root, e := storeRoot(directory, create)
	if e != nil {
		client.CloseIdleConnections()
		return nil, e
	}
	d.root = root
	success := false
	defer func() {
		if !success {
			client.CloseIdleConnections()
			if !d.sticky {
				if d.rawHeld {
					syscall.Close(d.rawFD)
					d.rawHeld = false
				}
				if d.lock != nil {
					d.lock.Close()
				}
				root.Close()
			}
		}
	}()
	d.lock, e = storeFile(root, "instance.lock", create)
	if e != nil {
		return nil, fail("ownership_delivery_lock_unsafe")
	}
	info, e := d.lock.Stat()
	if e != nil || info.Size() != 0 {
		return nil, fail("ownership_delivery_lock_unsafe")
	}
	if syscall.Flock(int(d.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, fail("ownership_delivery_locked")
	}
	raw, _, errno := syscall.Syscall(syscall.SYS_FCNTL, d.lock.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return nil, fail("ownership_delivery_lock_unsafe")
	}
	d.rawFD = int(raw)
	d.rawHeld = true
	if create {
		if d.lock.Sync() != nil || root.Sync() != nil {
			return d, d.latch()
		}
		next := d.step
		next.Sequence = 0
		if e = d.publish(next, ciphertext); e != nil {
			if d.sticky {
				return d, e
			}
			return nil, e
		}
	} else {
		if e = d.load(ctx); e != nil {
			return d, d.latch()
		}
	}
	success = true
	return d, nil
}
func (d *ClientDelivery) verifyBundle(bundle AcceptedBundle) ([]byte, OwnerUploadReceipt, error) {
	var zero OwnerUploadReceipt
	verified, e := VerifyAcceptance(bundle.Acceptance, d.client.pin, d.client.scope)
	if e != nil {
		return nil, zero, fail("ownership_delivery_acceptance_invalid")
	}
	binding := verified.Binding()
	if binding.CredentialSHA256 != d.trust.CredentialSHA256 || binding.ExecutionProfileSHA256 != d.trust.ProfileSHA256 || binding.PipelineMode != d.trust.PipelineMode || len(bundle.KeyEnvelope) < 256 || len(bundle.KeyEnvelope) > 512 || digest(bundle.KeyEnvelope) != binding.KeyEnvelopeSHA256 || int64(len(bundle.Ciphertext)) != binding.CiphertextBytes || len(bundle.Ciphertext) < 16 || int64(len(bundle.Ciphertext)) > MaxCiphertextBytes || digest(bundle.Ciphertext) != binding.CiphertextSHA256 {
		return nil, zero, fail("ownership_delivery_bundle_mismatch")
	}
	expected := OwnerUploadReceipt{SchemaVersion: 1, JobID: binding.JobID, AcceptanceSHA256: verified.SHA256(), CredentialSHA256: binding.CredentialSHA256, CiphertextSHA256: binding.CiphertextSHA256, CiphertextBytes: binding.CiphertextBytes, KeyEnvelopeSHA256: binding.KeyEnvelopeSHA256, State: "delivered"}
	return append([]byte(nil), verified.canonical...), expected, nil
}

func (d *ClientDelivery) names() ([]string, error) {
	fd, e := syscall.Openat(int(d.root.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("ownership_delivery_history_unknown")
	}
	f := os.NewFile(uintptr(fd), "ownership-delivery-scan")
	defer f.Close()
	entries, e := f.ReadDir(8)
	if e != nil && e != io.EOF || len(entries) > 6 {
		return nil, fail("ownership_delivery_history_unknown")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}
func (d *ClientDelivery) latch() error {
	d.sticky = true
	return fail("ownership_delivery_state_uncertain")
}
func (d *ClientDelivery) point(name string) error {
	if d.fault != nil {
		return d.fault(name)
	}
	return nil
}
func (d *ClientDelivery) preflight() error {
	if d.closed || d.sticky || d.root == nil || d.lock == nil || !d.rawHeld {
		return fail("ownership_delivery_unavailable")
	}
	fresh, e := storeRoot(d.directory, false)
	if e != nil {
		return d.latch()
	}
	a, e1 := fresh.Stat()
	fresh.Close()
	b, e2 := d.root.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(a, b) {
		return d.latch()
	}
	lock, e := storeFile(d.root, "instance.lock", false)
	if e != nil {
		return d.latch()
	}
	a, e1 = lock.Stat()
	lock.Close()
	b, e2 = d.lock.Stat()
	if e1 != nil || e2 != nil || !os.SameFile(a, b) || a.Size() != 0 {
		return d.latch()
	}
	names, e := d.names()
	if e != nil || len(names) != len(d.hashes)+1 {
		return d.latch()
	}
	for _, name := range names {
		if name == "instance.lock" {
			continue
		}
		expected, ok := d.hashes[name]
		if !ok {
			return d.latch()
		}
		limit := int64(clientDeliveryStepLimit)
		if name == "ciphertext.bin" {
			limit = MaxCiphertextBytes
		}
		raw, e := storeRead(d.root, name, limit)
		if e != nil || digest(raw) != expected {
			return d.latch()
		}
	}
	return nil
}
func (d *ClientDelivery) load(ctx context.Context) error {
	names, e := d.names()
	if e != nil {
		return e
	}
	expectedNames := map[string]bool{"instance.lock": true, "ciphertext.bin": true}
	ciphertext, e := storeRead(d.root, "ciphertext.bin", MaxCiphertextBytes)
	if e != nil {
		return e
	}
	for i, name := range clientDeliveryStepNames {
		found := false
		for _, n := range names {
			if n == name {
				found = true
			}
		}
		if !found {
			break
		}
		if ctx.Err() != nil {
			return fail("ownership_cancelled")
		}
		raw, e := storeRead(d.root, name, clientDeliveryStepLimit)
		if e != nil {
			return e
		}
		var step clientDeliveryStep
		if strictJSON(raw, &step, clientDeliveryStepLimit) != nil || step.SchemaVersion != 1 || step.Domain != "biozero.ownership.client-delivery.v1" || step.Sequence != i || step.Context != d.trust || step.ContextSHA256 != d.contextSHA {
			return fail("ownership_delivery_history_mismatch")
		}
		if i == 0 {
			if step.PreviousSHA256 != "" || step.Receipt != (OwnerUploadReceipt{}) {
				return fail("ownership_delivery_history_mismatch")
			}
			envelope, e := hex.DecodeString(step.EnvelopeHex)
			if e != nil {
				return e
			}
			canonical, expected, e := d.verifyBundle(AcceptedBundle{Acceptance: []byte(step.AcceptanceJSON), KeyEnvelope: envelope, Ciphertext: ciphertext})
			if e != nil || !bytes.Equal(canonical, []byte(step.AcceptanceJSON)) || step.JobID != expected.JobID || step.CiphertextSHA256 != expected.CiphertextSHA256 || step.CiphertextBytes != expected.CiphertextBytes {
				return fail("ownership_delivery_history_mismatch")
			}
			d.expected = expected
		} else {
			if step.PreviousSHA256 != d.hashes[clientDeliveryStepNames[i-1]] {
				return fail("ownership_delivery_history_mismatch")
			}
			prior := d.step
			prior.Sequence = step.Sequence
			prior.PreviousSHA256 = step.PreviousSHA256
			prior.Receipt = step.Receipt
			if prior != step {
				return fail("ownership_delivery_history_mismatch")
			}
			if i < 2 && step.Receipt != (OwnerUploadReceipt{}) || i == 2 && step.Receipt != d.expected {
				return fail("ownership_delivery_receipt_mismatch")
			}
		}
		d.step = step
		d.hashes[name] = digest(raw)
		expectedNames[name] = true
	}
	if _, ok := d.hashes[clientDeliveryStepNames[0]]; !ok {
		return fail("ownership_delivery_history_unknown")
	}
	if len(names) != len(expectedNames) {
		return fail("ownership_delivery_history_unknown")
	}
	for _, name := range names {
		if !expectedNames[name] {
			return fail("ownership_delivery_history_unknown")
		}
	}
	d.hashes["ciphertext.bin"] = digest(ciphertext)
	return nil
}

// publish appends one durable phase. The intent marker precedes any phase/body
// file. Unknown/partial files are retained and refused on Open, never repaired.
// As with ClientOperation, a crash after unlink and failed parent sync need not
// retain a marker universally; a complete delivering phase still forbids POST.
func (d *ClientDelivery) publish(next clientDeliveryStep, ciphertext []byte) error {
	if e := d.preflight(); e != nil {
		return e
	}
	raw, e := boundedJSON(next, clientDeliveryStepLimit)
	if e != nil {
		return e
	}
	marker, e := storeFile(d.root, "delivery.intent", true)
	if e != nil {
		return d.latch()
	}
	write := func(file *os.File, data []byte) error {
		n, e := file.Write(data)
		if e == nil && n != len(data) {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = d.point("file_sync")
		}
		if e == nil {
			e = file.Sync()
		}
		closeErr := file.Close()
		if e == nil {
			e = closeErr
		}
		return e
	}
	if write(marker, []byte(digest(raw))) != nil || d.point("marker_directory_sync") != nil || d.root.Sync() != nil {
		return d.latch()
	}
	if ciphertext != nil {
		file, e := storeFile(d.root, "ciphertext.bin", true)
		if e != nil {
			return d.latch()
		}
		if write(file, ciphertext) != nil {
			return d.latch()
		}
	}
	file, e := storeFile(d.root, clientDeliveryStepNames[next.Sequence], true)
	if e != nil {
		return d.latch()
	}
	if write(file, raw) != nil {
		return d.latch()
	}
	if d.point("directory_sync") != nil || d.root.Sync() != nil {
		return d.latch()
	}
	if d.point("intent_unlink") != nil || syscall.Unlinkat(int(d.root.Fd()), "delivery.intent") != nil || d.point("intent_directory_sync") != nil || d.root.Sync() != nil {
		return d.latch()
	}
	d.step = next
	d.hashes[clientDeliveryStepNames[next.Sequence]] = digest(raw)
	if ciphertext != nil {
		d.hashes["ciphertext.bin"] = digest(ciphertext)
	}
	return nil
}
func (d *ClientDelivery) next(sequence int) clientDeliveryStep {
	next := d.step
	next.Sequence = sequence
	next.PreviousSHA256 = d.hashes[clientDeliveryStepNames[sequence-1]]
	return next
}
func (d *ClientDelivery) parseReceipt(raw []byte) (OwnerUploadReceipt, error) {
	var receipt OwnerUploadReceipt
	if strictJSON(raw, &receipt, clientDeliveryReceiptLimit) != nil || receipt != d.expected {
		return OwnerUploadReceipt{}, fail("ownership_delivery_receipt_mismatch")
	}
	return receipt, nil
}

// Deliver sends at most one POST for this workspace, after durable delivering
// intent. A network, cancellation or receipt error retains that phase. Calling
// Deliver again cannot resend it; only Recover's known-job GET is permitted.
func (d *ClientDelivery) Deliver(ctx context.Context) (OwnerUploadReceipt, error) {
	var zero OwnerUploadReceipt
	if d == nil {
		return zero, fail("ownership_delivery_unavailable")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.preflight(); e != nil {
		return zero, e
	}
	if ctx == nil || ctx.Err() != nil {
		return zero, fail("ownership_cancelled")
	}
	if d.step.Sequence == 2 {
		return d.step.Receipt, nil
	}
	if d.step.Sequence != 0 {
		return zero, fail("ownership_delivery_phase_invalid")
	}
	ciphertext, e := storeRead(d.root, "ciphertext.bin", MaxCiphertextBytes)
	if e != nil || digest(ciphertext) != d.expected.CiphertextSHA256 || int64(len(ciphertext)) != d.expected.CiphertextBytes {
		return zero, d.latch()
	}
	envelope, e := hex.DecodeString(d.step.EnvelopeHex)
	if e != nil {
		return zero, d.latch()
	}
	acceptance := []byte(d.step.AcceptanceJSON)
	frame := make([]byte, 8+len(acceptance)+len(envelope))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(acceptance)))
	copy(frame[4:], acceptance)
	offset := 4 + len(acceptance)
	binary.BigEndian.PutUint32(frame[offset:offset+4], uint32(len(envelope)))
	copy(frame[offset+4:], envelope)
	if e = d.publish(d.next(1), nil); e != nil {
		return zero, e
	}
	bounded, cancel := context.WithTimeout(ctx, AuthorityClientTimeout)
	defer cancel()
	raw, e := d.client.call(bounded, "POST", "/v1/uploads", "application/octet-stream", io.MultiReader(bytes.NewReader(frame), bytes.NewReader(ciphertext)), int64(len(frame))+int64(len(ciphertext)), clientDeliveryReceiptLimit)
	if e != nil {
		return zero, fail("ownership_delivery_uncertain")
	}
	receipt, e := d.parseReceipt(raw)
	if e != nil {
		return zero, e
	}
	next := d.next(2)
	next.Receipt = receipt
	if e = d.publish(next, nil); e != nil {
		return zero, e
	}
	return receipt, nil
}

// Recover makes only a known-job GET, never a POST, re-encryption or new identity.
// Missing/rejected/other states and all ambiguous transport errors stay pending.
func (d *ClientDelivery) Recover(ctx context.Context) (OwnerUploadReceipt, error) {
	var zero OwnerUploadReceipt
	if d == nil {
		return zero, fail("ownership_delivery_unavailable")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.preflight(); e != nil {
		return zero, e
	}
	if ctx == nil || ctx.Err() != nil {
		return zero, fail("ownership_cancelled")
	}
	if d.step.Sequence == 2 {
		return d.step.Receipt, nil
	}
	if d.step.Sequence != 1 {
		return zero, fail("ownership_delivery_phase_invalid")
	}
	bounded, cancel := context.WithTimeout(ctx, AuthorityClientTimeout)
	defer cancel()
	raw, e := d.client.call(bounded, "GET", "/v1/uploads/"+d.step.JobID, "", nil, 0, clientDeliveryReceiptLimit)
	if e != nil {
		return zero, fail("ownership_delivery_pending")
	}
	receipt, e := d.parseReceipt(raw)
	if e != nil {
		return zero, e
	}
	next := d.next(2)
	next.Receipt = receipt
	if e = d.publish(next, nil); e != nil {
		return zero, e
	}
	return receipt, nil
}
func (d *ClientDelivery) State() string {
	if d == nil {
		return "unavailable"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return "closed"
	}
	if d.sticky {
		return "unavailable"
	}
	return []string{"prepared", "delivering", "delivered"}[d.step.Sequence]
}
func (d *ClientDelivery) JobID() string {
	if d == nil {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.step.JobID
}

// AcceptanceSHA256 returns the canonical verified acceptance identity after a
// complete local custody check. It is available before delivery and makes no
// assertion that a peer received the ciphertext.
func (d *ClientDelivery) AcceptanceSHA256() (string, error) {
	if d == nil {
		return "", fail("ownership_delivery_unavailable")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.preflight(); e != nil {
		return "", e
	}
	return d.expected.AcceptanceSHA256, nil
}
func (d *ClientDelivery) Receipt() (OwnerUploadReceipt, error) {
	if d == nil {
		return OwnerUploadReceipt{}, fail("ownership_delivery_unavailable")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.preflight(); e != nil {
		return OwnerUploadReceipt{}, e
	}
	if d.step.Sequence != 2 {
		return OwnerUploadReceipt{}, fail("ownership_delivery_phase_invalid")
	}
	return d.step.Receipt, nil
}
func (d *ClientDelivery) Close() error {
	if d == nil {
		return fail("ownership_delivery_unavailable")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	if e := d.preflight(); e != nil {
		return e
	}
	if d.step.Sequence == 1 {
		return fail("ownership_delivery_pending")
	}
	d.client.CloseIdleConnections()
	if d.point("close_root") != nil || d.root.Close() != nil {
		return d.latch()
	}
	if d.point("close_lock") != nil || d.lock.Close() != nil {
		return d.latch()
	}
	if d.rawHeld {
		if syscall.Close(d.rawFD) != nil {
			return d.latch()
		}
		d.rawHeld = false
	}
	d.closed = true
	return nil
}

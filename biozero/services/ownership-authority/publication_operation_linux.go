//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
)

var publicationOperationNames = []string{"00-intent.json", "01-publishing.json", "02-published.json"}

// TrustSHA256 is the measured CA asset identity supplied by a trusted loader.
// It is not learned from a peer. Directory names one new lifetime operation.
type PublicationOperationConfig struct {
	Directory   string
	Client      PublicationClientConfig
	Acceptance  []byte
	TrustSHA256 string
}

type publicationOperationTrust struct {
	Directory, Endpoint, ServerName, TrustSHA256, ProducerSHA256 string
	AuthorityID, PublicKey, PipelineMode, ProfileSHA256          string
	AuthorityScope                                               AcceptanceScope
	PublisherScope                                               PublicationScope
}

type publicationOperationStep struct {
	SchemaVersion  int                `json:"schema_version"`
	Domain         string             `json:"domain"`
	Sequence       int                `json:"sequence"`
	ContextSHA256  string             `json:"context_sha256"`
	PreviousSHA256 string             `json:"previous_sha256"`
	AcceptanceJSON string             `json:"acceptance_json"`
	Receipt        PublicationReceipt `json:"receipt"`
}

type publicationOperationPin struct {
	SHA256 string
	Info   os.FileInfo
}

// PublicationOperation has no automatic network recovery. Only a fresh hot
// instance can POST, after its publishing step is durable. Open is read-only;
// explicit Recover uses GET for the retained acceptance. A failed/uncertain
// Close retains the raw lifetime flock and its first error until process exit.
type PublicationOperation struct {
	mu                     sync.Mutex
	directory              string
	client                 *PublicationClient
	root, lock             *os.File
	lockInfo               os.FileInfo
	rawFD                  int
	rawHeld                bool
	pins                   map[string]publicationOperationPin
	step                   publicationOperationStep
	contextSHA, acceptance string
	expected               PublicationReceipt
	hot, sticky, closed    bool
	closeErr               error
	fault                  func(string) error // tests only; no wire/config fault controls
}

func CreatePublicationOperation(config PublicationOperationConfig) (*PublicationOperation, error) {
	return openPublicationOperation(config, true)
}

func OpenPublicationOperation(config PublicationOperationConfig) (*PublicationOperation, error) {
	return openPublicationOperation(config, false)
}

func openPublicationOperation(config PublicationOperationConfig, create bool) (*PublicationOperation, error) {
	if !filepath.IsAbs(config.Directory) || filepath.Clean(config.Directory) != config.Directory || config.Directory == "/" || !hexValue(config.TrustSHA256, 64) {
		return nil, fail("ownership_publication_operation_config_invalid")
	}
	client, err := NewPublicationClient(config.Client)
	if err != nil {
		return nil, err
	}
	v, err := VerifyAcceptance(config.Acceptance, client.transport.pin, client.transport.scope)
	if err != nil || !publicationProducerDistinct(v, client.transport.leaf) {
		client.CloseIdleConnections()
		return nil, fail("ownership_publication_operation_acceptance_invalid")
	}
	binding := v.Binding()
	trust := publicationOperationTrust{config.Directory, client.transport.base, config.Client.Client.ServerName, config.TrustSHA256,
		digest(client.transport.leaf.Raw), client.transport.pin.AuthorityID, hex.EncodeToString(client.transport.pin.PublicKey),
		client.transport.pin.PipelineMode, client.transport.pin.ExecutionProfileSHA256, client.transport.scope, client.scope}
	contextRaw, err := json.Marshal(trust)
	if err != nil {
		client.CloseIdleConnections()
		return nil, fail("ownership_publication_operation_config_invalid")
	}
	o := &PublicationOperation{directory: config.Directory, client: client, rawFD: -1, pins: map[string]publicationOperationPin{},
		contextSHA: digest(contextRaw), acceptance: string(v.canonical),
		expected: PublicationReceipt{SchemaVersion: 1, Domain: PublicationReceiptDomain, State: "published", PublisherScope: client.scope,
			AuthorityScope: client.transport.scope, JobID: binding.JobID, AcceptanceSHA256: v.SHA256(), CredentialSHA256: binding.CredentialSHA256,
			ExecutionProfileSHA256: binding.ExecutionProfileSHA256, PipelineMode: binding.PipelineMode}}
	o.step = publicationOperationStep{SchemaVersion: 1, Domain: "biozero.authorization-publication.operation.v1", Sequence: -1,
		ContextSHA256: o.contextSHA, AcceptanceJSON: o.acceptance}
	o.root, err = storeRoot(config.Directory, create)
	if err != nil {
		client.CloseIdleConnections()
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			client.CloseIdleConnections()
			if !o.sticky {
				if o.rawHeld {
					syscall.Close(o.rawFD)
					o.rawHeld = false
				}
				if o.lock != nil {
					o.lock.Close()
				}
				o.root.Close()
			}
		}
	}()
	o.lock, err = storeFile(o.root, "instance.lock", create)
	if err != nil {
		return nil, fail("ownership_publication_operation_lock_invalid")
	}
	o.lockInfo, err = storeSafeFile(o.lock)
	if err != nil || o.lockInfo.Size() != 0 {
		return nil, fail("ownership_publication_operation_lock_invalid")
	}
	if syscall.Flock(int(o.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, fail("ownership_publication_operation_locked")
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, o.lock.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return nil, fail("ownership_publication_operation_lock_invalid")
	}
	o.rawFD, o.rawHeld = int(fd), true
	if create {
		if o.lock.Sync() != nil || o.root.Sync() != nil {
			return o, o.latch()
		}
		next := o.step
		next.Sequence = 0
		if err = o.appendStep(next); err != nil {
			return o, err
		}
		o.hot = true
	} else if err = o.load(); err != nil {
		return o, o.latch()
	}
	success = true
	return o, nil
}

func (o *PublicationOperation) point(name string) error {
	if o.fault != nil {
		return o.fault(name)
	}
	return nil
}

func (o *PublicationOperation) latch() error {
	o.sticky = true
	return fail("ownership_publication_operation_uncertain")
}

func (o *PublicationOperation) names() ([]string, error) {
	// At most the lock and three complete steps. A transaction marker is never
	// healthy visible history and is retained on failure rather than removed.
	fd, err := syscall.Openat(int(o.root.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "ownership-publication-scan")
	defer f.Close()
	entries, err := f.ReadDir(6)
	if err != nil && err != io.EOF || len(entries) > 4 {
		return nil, fail("ownership_publication_operation_history_unknown")
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (o *PublicationOperation) read(name string) ([]byte, os.FileInfo, error) {
	f, err := storeFile(o.root, name, false)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	before, err := storeSafeFile(f)
	if err != nil || before.Size() < 1 || before.Size() > clientStepLimit {
		return nil, nil, fail("ownership_publication_operation_file_invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(f, clientStepLimit+1))
	if err != nil {
		return nil, nil, err
	}
	after, err := storeSafeFile(f)
	if err != nil || !storeInfoEqual(before, after) || int64(len(raw)) != before.Size() {
		return nil, nil, fail("ownership_publication_operation_file_invalid")
	}
	if err = o.point("read_path_guard"); err != nil {
		return nil, nil, err
	}
	current, err := storeFile(o.root, name, false)
	if err != nil {
		return nil, nil, err
	}
	named, namedErr := storeSafeFile(current)
	closeErr := current.Close()
	if namedErr != nil || closeErr != nil || !storeInfoEqual(after, named) {
		return nil, nil, fail("ownership_publication_operation_file_invalid")
	}
	return raw, after, nil
}

func (o *PublicationOperation) preflight() error {
	if o.closed || o.sticky || !o.rawHeld || o.root == nil || o.lock == nil {
		return fail("ownership_publication_operation_unavailable")
	}
	fresh, err := storeRoot(o.directory, false)
	if err != nil {
		return o.latch()
	}
	a, e1 := fresh.Stat()
	closeErr := fresh.Close()
	b, e2 := o.root.Stat()
	if e1 != nil || e2 != nil || closeErr != nil || o.point("preflight_close_root") != nil || !os.SameFile(a, b) {
		return o.latch()
	}
	lock, err := storeFile(o.root, "instance.lock", false)
	if err != nil {
		return o.latch()
	}
	a, err = storeSafeFile(lock)
	closeErr = lock.Close()
	if err != nil || closeErr != nil || o.point("preflight_close_lock") != nil || !storeInfoEqual(a, o.lockInfo) || a.Size() != 0 {
		return o.latch()
	}
	names, err := o.names()
	if err != nil || len(names) != len(o.pins)+1 {
		return o.latch()
	}
	for _, name := range names {
		if name == "instance.lock" {
			continue
		}
		pin, ok := o.pins[name]
		if !ok {
			return o.latch()
		}
		raw, info, err := o.read(name)
		if err != nil || digest(raw) != pin.SHA256 || !storeInfoEqual(info, pin.Info) {
			return o.latch()
		}
	}
	return nil
}

func (o *PublicationOperation) validateStep(step publicationOperationStep, sequence int) error {
	if step.SchemaVersion != 1 || step.Domain != "biozero.authorization-publication.operation.v1" || step.Sequence != sequence ||
		step.ContextSHA256 != o.contextSHA || step.AcceptanceJSON != o.acceptance ||
		sequence == 0 && step.PreviousSHA256 != "" || sequence > 0 && step.PreviousSHA256 != o.pins[publicationOperationNames[sequence-1]].SHA256 ||
		sequence < 2 && step.Receipt != (PublicationReceipt{}) || sequence == 2 && step.Receipt != o.expected {
		return fail("ownership_publication_operation_history_invalid")
	}
	return nil
}

func (o *PublicationOperation) load() error {
	names, err := o.names()
	if err != nil || len(names) < 2 {
		return fail("ownership_publication_operation_history_unknown")
	}
	expected := map[string]bool{"instance.lock": true}
	for i, name := range publicationOperationNames {
		present := false
		for _, n := range names {
			if n == name {
				present = true
			}
		}
		if !present {
			break
		}
		raw, info, err := o.read(name)
		if err != nil {
			return err
		}
		var step publicationOperationStep
		if strictJSON(raw, &step, clientStepLimit) != nil || o.validateStep(step, i) != nil {
			return fail("ownership_publication_operation_history_invalid")
		}
		o.step = step
		o.pins[name] = publicationOperationPin{digest(raw), info}
		expected[name] = true
	}
	if len(o.pins) == 0 || len(expected) != len(names) {
		return fail("ownership_publication_operation_history_unknown")
	}
	for _, name := range names {
		if !expected[name] {
			return fail("ownership_publication_operation_history_unknown")
		}
	}
	return o.preflight()
}

func (o *PublicationOperation) appendStep(next publicationOperationStep) error {
	if err := o.preflight(); err != nil {
		return err
	}
	if next.Sequence < 0 || next.Sequence > 2 || next.Sequence != o.step.Sequence+1 || o.validateStep(next, next.Sequence) != nil {
		return fail("ownership_publication_operation_phase_invalid")
	}
	raw, err := boundedJSON(next, clientStepLimit)
	if err != nil {
		return err
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
	marker, err := storeFile(o.root, "publication.intent", true)
	if err != nil {
		return o.latch()
	}
	if write(marker, []byte(digest(raw))) != nil || o.point("marker_directory_sync") != nil || o.root.Sync() != nil {
		return o.latch()
	}
	f, err := storeFile(o.root, publicationOperationNames[next.Sequence], true)
	if err != nil {
		return o.latch()
	}
	if write(f, raw) != nil || o.point("directory_sync") != nil || o.root.Sync() != nil {
		return o.latch()
	}
	if o.point("intent_unlink") != nil || syscall.Unlinkat(int(o.root.Fd()), "publication.intent") != nil ||
		o.point("intent_directory_sync") != nil || o.root.Sync() != nil {
		return o.latch()
	}
	stored, info, err := o.read(publicationOperationNames[next.Sequence])
	if err != nil || string(stored) != string(raw) {
		return o.latch()
	}
	o.pins[publicationOperationNames[next.Sequence]] = publicationOperationPin{digest(raw), info}
	o.step = next
	return nil
}

func (o *PublicationOperation) next(sequence int) publicationOperationStep {
	next := o.step
	next.Sequence = sequence
	next.PreviousSHA256 = o.pins[publicationOperationNames[sequence-1]].SHA256
	return next
}

func (o *PublicationOperation) Publish(ctx context.Context) (PublicationReceipt, error) {
	var zero PublicationReceipt
	if o == nil {
		return zero, fail("ownership_publication_operation_unavailable")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.preflight(); err != nil {
		return zero, err
	}
	if ctx == nil || ctx.Err() != nil {
		return zero, fail("ownership_cancelled")
	}
	if o.step.Sequence == 2 {
		return o.step.Receipt, nil
	}
	if !o.hot || o.step.Sequence != 0 {
		return zero, fail("ownership_publication_operation_phase_invalid")
	}
	o.hot = false
	if err := o.appendStep(o.next(1)); err != nil {
		return zero, err
	}
	receipt, err := o.client.Publish(ctx, []byte(o.acceptance))
	// A client cancellation never hides trusted custody changes observed after IO.
	if storageErr := o.preflight(); storageErr != nil {
		return zero, storageErr
	}
	if err != nil {
		return zero, err
	}
	if receipt != o.expected {
		return zero, fail("ownership_publication_operation_receipt_invalid")
	}
	next := o.next(2)
	next.Receipt = receipt
	if err = o.appendStep(next); err != nil {
		return zero, err
	}
	return receipt, nil
}

func (o *PublicationOperation) Recover(ctx context.Context) (PublicationReceipt, error) {
	var zero PublicationReceipt
	if o == nil {
		return zero, fail("ownership_publication_operation_unavailable")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.preflight(); err != nil {
		return zero, err
	}
	if ctx == nil || ctx.Err() != nil {
		return zero, fail("ownership_cancelled")
	}
	if o.step.Sequence == 2 {
		return o.step.Receipt, nil
	}
	if o.step.Sequence != 1 {
		return zero, fail("ownership_publication_operation_phase_invalid")
	}
	receipt, err := o.client.Get(ctx, []byte(o.acceptance))
	if storageErr := o.preflight(); storageErr != nil {
		return zero, storageErr
	}
	if err != nil {
		return zero, err
	}
	if receipt != o.expected {
		return zero, fail("ownership_publication_operation_receipt_invalid")
	}
	next := o.next(2)
	next.Receipt = receipt
	if err = o.appendStep(next); err != nil {
		return zero, err
	}
	return receipt, nil
}

func (o *PublicationOperation) Check() error {
	if o == nil {
		return fail("ownership_publication_operation_unavailable")
	}
	if !o.mu.TryLock() {
		return fail("ownership_publication_operation_busy")
	}
	defer o.mu.Unlock()
	return o.preflight()
}

func (o *PublicationOperation) State() string {
	if o == nil {
		return "unavailable"
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return "closed"
	}
	if o.sticky || o.step.Sequence < 0 || o.step.Sequence > 2 {
		return "unavailable"
	}
	return []string{"intent", "publishing", "published"}[o.step.Sequence]
}

func (o *PublicationOperation) Receipt() (PublicationReceipt, error) {
	var zero PublicationReceipt
	if o == nil {
		return zero, fail("ownership_publication_operation_unavailable")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.preflight(); err != nil {
		return zero, err
	}
	if o.step.Sequence != 2 {
		return zero, fail("ownership_publication_operation_phase_invalid")
	}
	return o.step.Receipt, nil
}

func (o *PublicationOperation) Close() error {
	if o == nil {
		return fail("ownership_publication_operation_unavailable")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closeErr != nil {
		return o.closeErr
	}
	if o.closed {
		return nil
	}
	remember := func(err error) error {
		if o.closeErr == nil {
			o.closeErr = err
		}
		return o.closeErr
	}
	if err := o.preflight(); err != nil {
		return remember(err)
	}
	o.client.CloseIdleConnections()
	if o.step.Sequence == 1 {
		return remember(fail("ownership_publication_operation_pending"))
	}
	if o.point("close_root") != nil || o.root.Close() != nil {
		return remember(o.latch())
	}
	if o.point("close_lock") != nil || o.lock.Close() != nil {
		return remember(o.latch())
	}
	if o.rawHeld {
		if o.point("close_raw") != nil || syscall.Close(o.rawFD) != nil {
			return remember(o.latch())
		}
		o.rawHeld = false
	}
	o.closed = true
	return nil
}

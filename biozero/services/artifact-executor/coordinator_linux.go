//go:build linux

package artifactexecutor

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
)

// Provider is configured by the trusted host, never selected by an RPC caller.
// Execute must supervise its actual kernel capsule and return Quiescent only
// after capsule wait has completed. An error or process ID is not that proof.
// No native/container implementation is implied by this interface.
type Provider interface {
	Execute(context.Context, *ScopedInput, *Exporter) ProviderCompletion
}

type ProviderCompletion struct {
	Outcome   Outcome
	Quiescent bool
	Err       error
}

// Exporter is a lease-scoped authority. Closing it waits for current exports
// and fences later calls, independently of whether a provider's producers died.
// Quiescence must still be established by the configured trusted keeper.
type Exporter struct {
	mu     sync.Mutex
	store  *Store
	lease  string
	ctx    context.Context
	closed bool
}

func (e *Exporter) Export(id, expectedSHA string, src io.Reader) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.ctx.Err() != nil {
		return fail("artifact_export_authority_closed")
	}
	return e.store.Export(e.ctx, e.lease, id, expectedSHA, src)
}

func (e *Exporter) close() {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
}

type activeExecution struct {
	lease  string
	cancel context.CancelFunc
	done   chan struct{}
}

// Coordinator composes bounded input references, the durable Store and a
// configured provider. RegisterInput is a trusted local method; it is absent
// from the Unix Request schema. Same-UID host/writer trust is still required.
type Coordinator struct {
	mu       sync.Mutex
	store    *Store
	registry *InputRegistry
	provider Provider
	active   *activeExecution
	closed   bool
}

type RegisteredExecution struct {
	LeaseID  string
	InputRef string
}

type ExecutionResponse struct {
	SchemaVersion   int       `json:"schema_version"`
	LeaseID         string    `json:"lease_id"`
	State           string    `json:"state"`
	ManifestSHA256  string    `json:"manifest_sha256"`
	CancelRequested bool      `json:"cancel_requested"`
	Manifest        *Manifest `json:"manifest,omitempty"`
}

func NewCoordinator(store *Store, registry *InputRegistry, provider Provider) (*Coordinator, error) {
	if store == nil || registry == nil || registry.store != store || provider == nil {
		return nil, fail("artifact_provider_unavailable")
	}
	return &Coordinator{store: store, registry: registry, provider: provider}, nil
}

func (c *Coordinator) latch(code string) error {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	return c.store.latch(code)
}

func (c *Coordinator) RegisterInput(ctx context.Context, jobID, originalSHA, processedSHA string, size int64, input *os.File) (RegisteredExecution, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || ctx.Err() != nil {
		return RegisteredExecution{}, fail("artifact_coordinator_unavailable")
	}
	lease, err := c.store.Reserve(jobID, originalSHA)
	if err != nil {
		return RegisteredExecution{}, err
	}
	ref, err := c.registry.Bind(ctx, lease, input, processedSHA, size)
	if err != nil {
		// No provider was called for this new reservation. Preserve the reservation
		// and stop admission; this is not a recovery of unknown older pending work.
		return RegisteredExecution{}, c.latch("artifact_input_registration_failed")
	}
	return RegisteredExecution{LeaseID: lease, InputRef: ref}, nil
}

func validCoordinatorRequest(q Request) bool {
	if q.SchemaVersion != 1 || !hexID(q.LeaseID, 32) {
		return false
	}
	switch q.Operation {
	case "run":
		return hexID(q.InputRef, 32)
	case "status", "cancel":
		return q.InputRef == ""
	default:
		return false
	}
}

func (c *Coordinator) Handle(ctx context.Context, q Request) ([]byte, error) {
	if !validCoordinatorRequest(q) || ctx.Err() != nil {
		return nil, fail("artifact_request_invalid")
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, fail("artifact_coordinator_unavailable")
	}
	switch q.Operation {
	case "run":
		return c.run(ctx, q)
	case "cancel":
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, fail("artifact_coordinator_unavailable")
		}
		requested := c.active != nil && c.active.lease == q.LeaseID
		if requested {
			c.active.cancel()
		}
		c.mu.Unlock()
		return c.response(q.LeaseID, requested)
	default:
		return c.response(q.LeaseID, false)
	}
}

func (c *Coordinator) run(ctx context.Context, q Request) ([]byte, error) {
	c.mu.Lock()
	if c.closed || c.active != nil {
		c.mu.Unlock()
		return nil, fail("artifact_execution_busy")
	}
	// Acquire requires the exact opaque pair and fences it before Begin. Invalid
	// guessed references cannot transition another reserved lease to executing.
	input, err := c.registry.Acquire(q.LeaseID, q.InputRef)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if err = c.store.Begin(q.LeaseID); err != nil {
		input.Close()
		c.mu.Unlock()
		return nil, err
	}
	work, cancel := context.WithCancel(ctx)
	active := &activeExecution{lease: q.LeaseID, cancel: cancel, done: make(chan struct{})}
	c.active = active
	c.mu.Unlock()
	defer func() {
		cancel()
		input.Close()
		c.mu.Lock()
		c.active = nil
		close(active.done)
		c.mu.Unlock()
	}()
	exporter := &Exporter{store: c.store, lease: q.LeaseID, ctx: work}
	// Panics remain an uncertain execution and cannot unlock admission or ACK.
	var completion ProviderCompletion
	func() {
		defer func() {
			if recover() != nil {
				completion = ProviderCompletion{Err: fail("artifact_provider_failed")}
			}
		}()
		completion = c.provider.Execute(work, input, exporter)
	}()
	exporter.close()
	if !completion.Quiescent {
		return nil, c.latch("artifact_provider_quiescence_unproven")
	}
	outcome := completion.Outcome
	if completion.Err != nil || work.Err() != nil {
		outcome.ExecutionStatus, outcome.ReleaseStatus = "failed", "withheld"
		outcome.ErrorCode = "artifact_provider_failed"
		if work.Err() != nil {
			outcome.ErrorCode = "artifact_cancelled"
		}
	}
	manifest, err := c.store.Prepare(q.LeaseID, outcome)
	if err != nil {
		return nil, err
	}
	// Only the host coordinator constructs this proof, after provider wait and
	// closure of all export callbacks. No wire field can supply any part of it.
	manifestBytes, err := jsonBytes(manifest)
	if err != nil {
		return nil, c.latch("artifact_manifest_invalid")
	}
	proof := Proof{SchemaVersion: 1, StoreID: manifest.StoreID, PolicySHA256: manifest.PolicySHA256,
		LeaseID: q.LeaseID, JobID: manifest.JobID, InputSHA256: manifest.InputSHA256,
		ManifestSHA256: digest(manifestBytes), CapsuleWaitFinished: true, ExportAuthorityClosed: true}
	if err = c.store.RecordQuiescence(q.LeaseID, proof); err != nil {
		return nil, err
	}
	if err = c.store.Commit(q.LeaseID); err != nil {
		return nil, err
	}
	return c.response(q.LeaseID, false)
}

func (c *Coordinator) response(lease string, cancelled bool) ([]byte, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if err := c.store.ready(); err != nil {
		return nil, err
	}
	record, err := c.store.record(lease)
	if err != nil {
		return nil, fail("artifact_lease_unavailable")
	}
	response := ExecutionResponse{SchemaVersion: 1, LeaseID: lease, State: record.State,
		ManifestSHA256: record.ManifestSHA256, CancelRequested: cancelled}
	if record.State == "committed" {
		dir, err := childDir(c.store.objects, lease, false)
		if err != nil {
			return nil, c.store.latch("artifact_history_missing")
		}
		defer dir.Close()
		raw, err := boundedRead(context.Background(), dir, "manifest.json", manifestLimit)
		var manifest Manifest
		if err != nil || digest(raw) != record.ManifestSHA256 || strictJSON(raw, &manifest) != nil || !c.store.matchManifest(lease, record, manifest) {
			return nil, c.store.latch("artifact_history_invalid")
		}
		response.Manifest = &manifest
	}
	data, err := json.Marshal(response)
	if err != nil || len(data) > MaxFrameBytes {
		return nil, fail("artifact_frame_oversized")
	}
	return data, nil
}

// Acknowledge is used by UnixServer's optional UnixAcknowledger interface. The
// supplied callback must be the actual bounded socket WriteFrame, not a marshal
// or queue notification. A lost write preserves committed charge and latches the
// Store; cancellation before callback makes no assertion of peer receipt.
func (c *Coordinator) Acknowledge(ctx context.Context, q Request, write func() error) error {
	if ctx.Err() != nil || write == nil || !validCoordinatorRequest(q) {
		return fail("artifact_ack_invalid")
	}
	c.store.mu.Lock()
	record, err := c.store.record(q.LeaseID)
	c.store.mu.Unlock()
	if err != nil {
		return fail("artifact_lease_unavailable")
	}
	callback := func() error {
		if ctx.Err() != nil {
			return fail("artifact_cancelled")
		}
		return write()
	}
	if record.State == "committed" {
		return c.store.Acknowledge(q.LeaseID, callback)
	}
	// A nonterminal status/cancel reply also fails closed if another operation
	// latched the Store after Handle built that snapshot. Hold the bounded wire
	// callback under the same lock, without nesting Store.Acknowledge.
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if err := c.store.ready(); err != nil {
		return err
	}
	current, err := c.store.record(q.LeaseID)
	if err != nil || current.State != record.State || current.ManifestSHA256 != record.ManifestSHA256 {
		return fail("artifact_status_changed")
	}
	return callback()
}

// Close cancels current work but does not close Store or pretend its capsule is
// gone. The owner must await provider completion before closing the lifetime
// flock. Unproven completion leaves durable pending history and full charges.
func (c *Coordinator) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.active != nil {
		c.active.cancel()
	}
	return nil
}

// Wait waits for the active trusted provider call and storage handling to
// return. It does not turn missing quiescence into proof. A timeout means the
// keeper still owns pending work; callers must not release its lifetime flock.
func (c *Coordinator) Wait(ctx context.Context) error {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	if active == nil {
		return nil
	}
	select {
	case <-active.done:
		return nil
	case <-ctx.Done():
		return fail("artifact_provider_wait_pending")
	}
}

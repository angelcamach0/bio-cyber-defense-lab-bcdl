//go:build linux

package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These are storage/channel composition tests with trusted synthetic providers.
// They do not establish a real namespace/Docker keeper or scientific acceptance.
type fixtureProvider func(context.Context, *ScopedInput, *Exporter) ProviderCompletion

func (f fixtureProvider) Execute(ctx context.Context, input *ScopedInput, exporter *Exporter) ProviderCompletion {
	return f(ctx, input, exporter)
}

func successfulFixtureProvider(ctx context.Context, input *ScopedInput, exporter *Exporter) ProviderCompletion {
	if _, err := input.CopyTo(ctx, io.Discard); err != nil {
		return ProviderCompletion{Quiescent: true, Err: err}
	}
	vcf := []byte("synthetic normalized VCF\n")
	if err := exporter.Export("normalized_vcf", digest(vcf), bytes.NewReader(vcf)); err != nil {
		return ProviderCompletion{Quiescent: true, Err: err}
	}
	return ProviderCompletion{Outcome: Outcome{"succeeded", "evaluated_passed", "", digest(vcf), digest(vcf)}, Quiescent: true}
}

func coordinatorFixture(t *testing.T, provider Provider) (*Coordinator, RegisteredExecution, *Store) {
	t.Helper()
	r, s, lease, file, data := registryFixture(t)
	ref, err := r.Bind(context.Background(), lease, file, digest(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordinator(s, r, provider)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, RegisteredExecution{LeaseID: lease, InputRef: ref}, s
}

func runRequest(input RegisteredExecution) Request {
	return Request{SchemaVersion: 1, Operation: "run", LeaseID: input.LeaseID, InputRef: input.InputRef}
}

func TestCoordinatorCommitsBeforeActualAcknowledgement(t *testing.T) {
	c, input, s := coordinatorFixture(t, fixtureProvider(successfulFixtureProvider))
	q := runRequest(input)
	raw, err := c.Handle(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	var response ExecutionResponse
	if json.Unmarshal(raw, &response) != nil || response.State != "committed" || response.Manifest == nil || response.Manifest.ReleaseStatus != "evaluated_passed" {
		t.Fatal("no committed manifest", string(raw))
	}
	if s.data.Records[input.LeaseID].ProofSHA256 == "" || s.data.Records[input.LeaseID].ManifestSHA256 != response.ManifestSHA256 {
		t.Fatal("reply preceded durable proof/commit")
	}
	called := 0
	if err := c.Acknowledge(context.Background(), q, func() error { called++; return nil }); err != nil || called != 1 {
		t.Fatal("real send callback not called exactly once", err)
	}
	if _, err := c.Handle(context.Background(), q); err == nil {
		t.Fatal("execution replay accepted")
	}
}

func TestCoordinatorLostAckRetainsCommittedCharge(t *testing.T) {
	c, input, s := coordinatorFixture(t, fixtureProvider(successfulFixtureProvider))
	q := runRequest(input)
	if _, err := c.Handle(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	before := s.Snapshot()
	if err := c.Acknowledge(context.Background(), q, func() error { return errors.New("synthetic socket write failure") }); err == nil {
		t.Fatal("lost ACK accepted")
	}
	after := s.Snapshot()
	if after.Healthy || before.ChargedBytes != after.ChargedBytes || after.RetainedOrReservedJobs != 1 || s.data.Records[input.LeaseID].State != "committed" {
		t.Fatal("lost ACK changed durable custody")
	}
}

func TestCoordinatorUnknownReferenceCannotConsumeLease(t *testing.T) {
	var calls atomic.Int32
	provider := fixtureProvider(func(ctx context.Context, input *ScopedInput, exporter *Exporter) ProviderCompletion {
		calls.Add(1)
		return successfulFixtureProvider(ctx, input, exporter)
	})
	c, input, s := coordinatorFixture(t, provider)
	q := runRequest(input)
	q.InputRef = strings.Repeat("0", 32)
	if _, err := c.Handle(context.Background(), q); err == nil {
		t.Fatal("unknown ref accepted")
	}
	if calls.Load() != 0 || s.data.Records[input.LeaseID].State != "reserved" {
		t.Fatal("unknown request changed execution")
	}
	if _, err := c.Handle(context.Background(), runRequest(input)); err != nil {
		t.Fatal("valid reserved lease lost", err)
	}
}

func TestCoordinatorUnprovenProviderAndPanicKeepReservation(t *testing.T) {
	for _, panicProvider := range []bool{false, true} {
		t.Run(map[bool]string{false: "unproven", true: "panic"}[panicProvider], func(t *testing.T) {
			provider := fixtureProvider(func(context.Context, *ScopedInput, *Exporter) ProviderCompletion {
				if panicProvider {
					panic("synthetic keeper failure")
				}
				return ProviderCompletion{Outcome: Outcome{"failed", "withheld", "artifact_provider_failed", "", ""}, Err: errors.New("synthetic wait unproven")}
			})
			c, input, s := coordinatorFixture(t, provider)
			before := s.Snapshot()
			if _, err := c.Handle(context.Background(), runRequest(input)); err == nil {
				t.Fatal("unproven keeper accepted")
			}
			after := s.Snapshot()
			if after.Healthy || before.ChargedBytes != after.ChargedBytes || s.data.Records[input.LeaseID].State != "executing" || s.data.Records[input.LeaseID].ProofSHA256 != "" {
				t.Fatal("uncertainty manufactured proof/release")
			}
		})
	}
}

func TestCoordinatorCancellationWaitsForKeeperAndWithholdsRelease(t *testing.T) {
	started, allowWait := make(chan struct{}), make(chan struct{})
	provider := fixtureProvider(func(ctx context.Context, _ *ScopedInput, _ *Exporter) ProviderCompletion {
		close(started)
		<-ctx.Done()
		<-allowWait
		return ProviderCompletion{Outcome: Outcome{"failed", "withheld", "artifact_cancelled", "", ""}, Quiescent: true}
	})
	c, input, s := coordinatorFixture(t, provider)
	done := make(chan error, 1)
	go func() { _, err := c.Handle(context.Background(), runRequest(input)); done <- err }()
	<-started
	q := Request{SchemaVersion: 1, Operation: "cancel", LeaseID: input.LeaseID}
	if _, err := c.Handle(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := c.Wait(waitCtx); err == nil {
		t.Fatal("pending keeper treated as finished")
	}
	if s.data.Records[input.LeaseID].State != "executing" {
		t.Fatal("cancel ack manufactured completion")
	}
	close(allowWait)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	raw, err := c.Handle(context.Background(), Request{SchemaVersion: 1, Operation: "status", LeaseID: input.LeaseID})
	var response ExecutionResponse
	if err != nil || json.Unmarshal(raw, &response) != nil || response.Manifest == nil || response.Manifest.ReleaseStatus != "withheld" {
		t.Fatal("cancelled result approved", err)
	}
}

func TestCoordinatorLateExportAuthorityIsFenced(t *testing.T) {
	var authority *Exporter
	provider := fixtureProvider(func(ctx context.Context, input *ScopedInput, exporter *Exporter) ProviderCompletion {
		authority = exporter
		return successfulFixtureProvider(ctx, input, exporter)
	})
	c, input, s := coordinatorFixture(t, provider)
	if _, err := c.Handle(context.Background(), runRequest(input)); err != nil {
		t.Fatal(err)
	}
	before := s.Snapshot()
	if err := authority.Export("variants_vcf", digest([]byte("late")), strings.NewReader("late")); err == nil {
		t.Fatal("closed lease export accepted")
	}
	if !s.Snapshot().Healthy || s.Snapshot().ChargedBytes != before.ChargedBytes {
		t.Fatal("late callback mutated committed custody")
	}
}

func TestCoordinatorRegistrationFailureRetainsQuotaWithoutTools(t *testing.T) {
	s, _, _ := openTest(t, 4)
	r, err := NewInputRegistry(s)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var calls atomic.Int32
	c, err := NewCoordinator(s, r, fixtureProvider(func(context.Context, *ScopedInput, *Exporter) ProviderCompletion {
		calls.Add(1)
		return ProviderCompletion{}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var file *os.File // Missing verified input cannot become execution authority.
	if _, err := c.RegisterInput(context.Background(), "0000000000000001", digest([]byte("encrypted")), digest([]byte("plaintext")), 9, file); err == nil {
		t.Fatal("missing input accepted")
	}
	if calls.Load() != 0 || s.Snapshot().Healthy || s.Snapshot().RetainedOrReservedJobs != 1 {
		t.Fatal("failed registration released charge or ran tools")
	}
}

func TestCoordinatorCanceledAckNeverCallsWireWriter(t *testing.T) {
	c, input, s := coordinatorFixture(t, fixtureProvider(successfulFixtureProvider))
	q := runRequest(input)
	if _, err := c.Handle(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := 0
	if err := c.Acknowledge(ctx, q, func() error { called++; return nil }); err == nil || called != 0 {
		t.Fatal("cancelled channel acknowledged")
	}
	if s.data.Records[input.LeaseID].State != "committed" || s.Snapshot().RetainedOrReservedJobs != 1 {
		t.Fatal("cancelled ACK discarded committed custody")
	}
}

func TestCoordinatorNonterminalAckCannotOutliveStoreLatch(t *testing.T) {
	c, input, s := coordinatorFixture(t, fixtureProvider(successfulFixtureProvider))
	q := Request{SchemaVersion: 1, Operation: "status", LeaseID: input.LeaseID}
	if _, err := c.Handle(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.latch("artifact_synthetic_persistence_failure")
	s.mu.Unlock()
	called := 0
	if err := c.Acknowledge(context.Background(), q, func() error { called++; return nil }); err == nil || called != 0 {
		t.Fatal("nonterminal status acknowledged after store became unavailable")
	}
}

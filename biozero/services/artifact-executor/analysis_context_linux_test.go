//go:build linux

package artifactexecutor

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestAnalysisFactsFollowOneShotVerifiedInput(t *testing.T) {
	r, _, lease, file, data := registryFixture(t)
	facts := AnalysisContext{OriginalName: "public-synthetic.fastq", ProcessedSizeBytes: int64(len(data)), Decrypted: true, SignatureValid: true}
	ref, err := r.BindWithAnalysis(context.Background(), lease, file, digest(data), int64(len(data)), facts)
	if err != nil {
		t.Fatal(err)
	}
	facts.OriginalName = "changed-after-registration"
	input, err := r.Acquire(lease, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if input.AnalysisContext == nil || input.AnalysisContext.OriginalName != "public-synthetic.fastq" || !input.AnalysisContext.SignatureValid || !input.AnalysisContext.Decrypted {
		t.Fatal("registered facts were lost or aliased")
	}
	// The trusted provider receives its own copy, not authority to mutate the
	// retained registration or enable a second acquisition.
	input.AnalysisContext.OriginalName = "provider-local-copy"
	if r.inputs[ref].analysis.OriginalName != "public-synthetic.fastq" {
		t.Fatal("provider mutated registration history")
	}
	if _, err := input.CopyTo(context.Background(), io.Discard); err != nil {
		t.Fatal("facts changed verified byte authority", err)
	}
	if _, err := r.Acquire(lease, ref); err == nil {
		t.Fatal("analysis registration allowed replay")
	}
}

func TestInvalidAnalysisFactsNeverReserveOrBind(t *testing.T) {
	mutations := map[string]func(*AnalysisContext){
		"changed_size":            func(c *AnalysisContext) { c.ProcessedSizeBytes++ },
		"negative_size":           func(c *AnalysisContext) { c.ProcessedSizeBytes = -1 },
		"name_limit":              func(c *AnalysisContext) { c.OriginalName = strings.Repeat("x", 4097) },
		"name_utf8":               func(c *AnalysisContext) { c.OriginalName = string([]byte{0xff}) },
		"decrypt_error_limit":     func(c *AnalysisContext) { c.DecryptionError = strings.Repeat("x", 129) },
		"signature_error_utf8":    func(c *AnalysisContext) { c.SignatureError = string([]byte{0xff}) },
		"contradictory_decrypt":   func(c *AnalysisContext) { c.Decrypted, c.DecryptionError = true, "failed" },
		"contradictory_signature": func(c *AnalysisContext) { c.SignatureValid, c.SignatureError = true, "failed" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r, s, lease, file, data := registryFixture(t)
			c, err := NewCoordinator(s, r, fixtureProvider(func(context.Context, *ScopedInput, *Exporter) ProviderCompletion {
				t.Fatal("invalid context reached provider")
				return ProviderCompletion{}
			}))
			if err != nil {
				t.Fatal(err)
			}
			facts := AnalysisContext{OriginalName: "synthetic.fastq", ProcessedSizeBytes: int64(len(data))}
			mutate(&facts)
			before := s.Snapshot()
			if _, err := c.RegisterInputWithAnalysis(context.Background(), strings.Repeat("a", 16), digest([]byte("ciphertext")), digest(data), int64(len(data)), file, facts); err == nil {
				t.Fatal("invalid context accepted by coordinator")
			}
			if _, err := r.BindWithAnalysis(context.Background(), lease, file, digest(data), int64(len(data)), facts); err == nil {
				t.Fatal("invalid context accepted by registry")
			}
			after := s.Snapshot()
			if before.ChargedBytes != after.ChargedBytes || before.RetainedOrReservedJobs != after.RetainedOrReservedJobs || len(r.inputs) != 0 {
				t.Fatal("invalid facts changed custody or consumed admission")
			}
		})
	}
}

func TestLegacyInputDoesNotSilentlyEnableAnalysis(t *testing.T) {
	r, _, lease, file, data := registryFixture(t)
	ref, err := r.Bind(context.Background(), lease, file, digest(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	input, err := r.Acquire(lease, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if input.AnalysisContext != nil {
		t.Fatal("legacy registration fabricated verifier facts")
	}
}

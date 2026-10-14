package artifactexecutor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func testPolicy(jobs int) Policy {
	p := DefaultPolicy()
	p.ExportBytes = 1024
	p.Jobs = jobs
	p.GlobalBytes = storeHeaderReserve + int64(jobs)*(p.ExportBytes+p.PublicationHeadroom)
	return p
}
func openTest(t *testing.T, jobs int) (*Store, string, Policy) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store")
	p := testPolicy(jobs)
	s, e := Open(context.Background(), path, p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, path, p
}
func reserveTest(t *testing.T, s *Store, n int) string {
	t.Helper()
	l, e := s.Reserve(fmt.Sprintf("%016x", n), digest([]byte("original-upload")))
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func prepareTest(t *testing.T, s *Store, n int) string {
	t.Helper()
	l := reserveTest(t, s, n)
	if e := s.Begin(l); e != nil {
		t.Fatal(e)
	}
	b := []byte("synthetic VCF\n")
	if e := s.Export(context.Background(), l, "normalized_vcf", digest(b), bytes.NewReader(b)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Prepare(l, Outcome{"succeeded", "evaluated_passed", "", digest(b), digest(b)}); e != nil {
		t.Fatal(e)
	}
	return l
}
func proofFor(s *Store, l string) Proof {
	r := s.data.Records[l]
	return Proof{1, s.data.StoreID, s.policySHA(), l, r.JobID, r.InputSHA256, r.ManifestSHA256, true, true}
}
func commitTest(t *testing.T, s *Store, n int) string {
	t.Helper()
	l := prepareTest(t, s, n)
	if e := s.RecordQuiescence(l, proofFor(s, l)); e != nil {
		t.Fatal(e)
	}
	if e := s.Commit(l); e != nil {
		t.Fatal(e)
	}
	return l
}
func TestCommitRetainsChargesAndImmutableBytesAcrossRestart(t *testing.T) {
	s, path, p := openTest(t, 1)
	l := commitTest(t, s, 1)
	before := s.Snapshot()
	if !before.Healthy || before.ChargedBytes <= storeHeaderReserve {
		t.Fatal("charge missing")
	}
	var ack bool
	if e := s.Acknowledge(l, func() error { ack = true; return nil }); e != nil || !ack {
		t.Fatal("ack missing")
	}
	raw, _ := os.ReadFile(filepath.Join(path, "objects", l, "normalized_vcf"))
	s.Close()
	s2, e := Open(context.Background(), path, p)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close()
	if s2.Snapshot() != before {
		t.Fatal("retention changed")
	}
	if _, e = s2.Reserve("0000000000000002", digest(nil)); e == nil {
		t.Fatal("terminal slot released")
	}
	after, _ := os.ReadFile(filepath.Join(path, "objects", l, "normalized_vcf"))
	if !bytes.Equal(raw, after) {
		t.Fatal("history changed")
	}
}
func TestPendingAndKeeperLostDenyRestartWithoutReexecution(t *testing.T) {
	for _, state := range []string{"reserved", "executing", "prepared", "proof_written"} {
		t.Run(state, func(t *testing.T) {
			s, path, p := openTest(t, 2)
			l := reserveTest(t, s, 1)
			if state != "reserved" {
				if e := s.Begin(l); e != nil {
					t.Fatal(e)
				}
			}
			if state == "prepared" || state == "proof_written" {
				b := []byte("x")
				if e := s.Export(context.Background(), l, "normalized_vcf", digest(b), bytes.NewReader(b)); e != nil {
					t.Fatal(e)
				}
				if _, e := s.Prepare(l, Outcome{"succeeded", "evaluated_passed", "", digest(b), digest(b)}); e != nil {
					t.Fatal(e)
				}
				if state == "proof_written" {
					if e := s.RecordQuiescence(l, proofFor(s, l)); e != nil {
						t.Fatal(e)
					}
				}
			}
			charge := s.Snapshot().ChargedBytes
			s.Close()
			s2, e := Open(context.Background(), path, p)
			if e != nil {
				t.Fatal(e)
			}
			defer s2.Close()
			if s2.Snapshot().Healthy || s2.Snapshot().ChargedBytes != charge {
				t.Fatal("pending unlocked")
			}
			if _, e = s2.Reserve("0000000000000002", digest(nil)); e == nil {
				t.Fatal("new work admitted")
			}
			if e = s2.Begin(l); e == nil {
				t.Fatal("work reexecuted")
			}
		})
	}
}
func TestParallelReservationsLinearizeQuota(t *testing.T) {
	s, _, _ := openTest(t, 3)
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for n := 1; n <= 20; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, e := s.Reserve(fmt.Sprintf("%016x", n), digest(nil))
			if e == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}(n)
	}
	wg.Wait()
	if success != 3 || s.Snapshot().RetainedOrReservedJobs != 3 {
		t.Fatal("quota race")
	}
}
func TestByteQuotaAndSingleActiveExecution(t *testing.T) {
	s, path, p := openTest(t, 3)
	s.Close()
	p.GlobalBytes = storeHeaderReserve + p.ExportBytes + p.PublicationHeadroom
	os.Remove(filepath.Join(path, "ledger.json"))
	s, e := Open(context.Background(), path, p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	reserveTest(t, s, 1)
	if _, e = s.Reserve("0000000000000002", digest(nil)); e == nil {
		t.Fatal("byte quota bypass")
	}
	s2, _, _ := openTest(t, 2)
	a := reserveTest(t, s2, 1)
	b := reserveTest(t, s2, 2)
	if e = s2.Begin(a); e != nil {
		t.Fatal(e)
	}
	if e = s2.Begin(b); e == nil {
		t.Fatal("two active executions")
	}
}
func TestSecondStoreLockAndPolicyChange(t *testing.T) {
	s, path, p := openTest(t, 2)
	if x, e := Open(context.Background(), path, p); e == nil {
		x.Close()
		t.Fatal("second writer")
	}
	reserveTest(t, s, 1)
	s.Close()
	p.Jobs = 1
	if x, e := Open(context.Background(), path, p); e == nil {
		x.Close()
		t.Fatal("policy silently adopted")
	}
}
func TestMissingHistoryNeverAdoptedOrDeleted(t *testing.T) {
	for _, which := range []string{"ledger", "artifact", "unknown", "unknown_directory"} {
		t.Run(which, func(t *testing.T) {
			s, path, p := openTest(t, 2)
			l := commitTest(t, s, 1)
			s.Close()
			tracked := filepath.Join(path, "objects", l, "normalized_vcf")
			raw, _ := os.ReadFile(tracked)
			switch which {
			case "ledger":
				os.Remove(filepath.Join(path, "ledger.json"))
			case "artifact":
				os.Remove(tracked)
			case "unknown":
				os.WriteFile(filepath.Join(path, "foreign"), []byte("keep"), 0600)
			case "unknown_directory":
				os.Mkdir(filepath.Join(path, "objects", "foreign"), 0700)
			}
			if x, e := Open(context.Background(), path, p); e == nil {
				x.Close()
				t.Fatal("unsafe history accepted")
			}
			if which != "artifact" {
				after, _ := os.ReadFile(tracked)
				if !bytes.Equal(after, raw) {
					t.Fatal("history deleted")
				}
			}
		})
	}
}
func TestExportAggregateExactAndPlusOne(t *testing.T) {
	for _, n := range []int{1024, 1025} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s, path, _ := openTest(t, 1)
			l := reserveTest(t, s, 1)
			s.Begin(l)
			b := bytes.Repeat([]byte("a"), n)
			e := s.Export(context.Background(), l, "normalized_vcf", digest(b), bytes.NewReader(b))
			if n == 1024 && e != nil {
				t.Fatal(e)
			}
			if n == 1025 {
				if e == nil || s.Snapshot().Healthy {
					t.Fatal("overflow accepted")
				}
				if _, e = os.Stat(filepath.Join(path, "objects", l, "normalized_vcf")); e == nil {
					t.Fatal("overflow published")
				}
			}
		})
	}
	s, _, _ := openTest(t, 1)
	l := reserveTest(t, s, 1)
	s.Begin(l)
	b := bytes.Repeat([]byte("b"), 600)
	if e := s.Export(context.Background(), l, "normalized_vcf", digest(b), bytes.NewReader(b)); e != nil {
		t.Fatal(e)
	}
	if e := s.Export(context.Background(), l, "variants_vcf", digest(b), bytes.NewReader(b)); e == nil {
		t.Fatal("multi-file aggregate overflow")
	}
}
func TestExportNamesCardinalityDigestAndNoClobber(t *testing.T) {
	s, path, _ := openTest(t, 1)
	l := reserveTest(t, s, 1)
	s.Begin(l)
	for _, name := range []string{"../../escape", "new_arbitrary_artifact", "manifest.json"} {
		if e := s.Export(context.Background(), l, name, digest(nil), bytes.NewReader(nil)); e == nil {
			t.Fatal("unknown name accepted")
		}
	}
	b := []byte("first")
	s.Export(context.Background(), l, "normalized_vcf", digest(b), bytes.NewReader(b))
	if e := s.Export(context.Background(), l, "normalized_vcf", digest([]byte("second")), strings.NewReader("second")); e == nil {
		t.Fatal("overwrite accepted")
	}
	raw, _ := os.ReadFile(filepath.Join(path, "objects", l, "normalized_vcf"))
	if !bytes.Equal(raw, b) {
		t.Fatal("artifact overwritten")
	}
	if e := s.Export(context.Background(), l, "variants_vcf", digest([]byte("wrong")), strings.NewReader("actual")); e == nil || s.Snapshot().Healthy {
		t.Fatal("digest mismatch accepted")
	}
}
func TestEvaluationAndQuiescenceMismatchWithholdCommit(t *testing.T) {
	for _, field := range []string{"store", "policy", "lease", "job", "input", "manifest", "wait", "authority"} {
		t.Run(field, func(t *testing.T) {
			s, _, _ := openTest(t, 1)
			l := prepareTest(t, s, 1)
			p := proofFor(s, l)
			switch field {
			case "store":
				p.StoreID = strings.Repeat("a", 32)
			case "policy":
				p.PolicySHA256 = digest(nil)
			case "lease":
				p.LeaseID = strings.Repeat("a", 32)
			case "job":
				p.JobID = "0000000000000002"
			case "input":
				p.InputSHA256 = digest(nil)
			case "manifest":
				p.ManifestSHA256 = digest(nil)
			case "wait":
				p.CapsuleWaitFinished = false
			case "authority":
				p.ExportAuthorityClosed = false
			}
			if e := s.RecordQuiescence(l, p); e == nil {
				t.Fatal("wrong proof accepted")
			}
			if e := s.Commit(l); e == nil {
				t.Fatal("release before quiescence")
			}
			if s.Snapshot().Healthy {
				t.Fatal("mismatch did not latch")
			}
		})
	}
	s, _, _ := openTest(t, 1)
	l := reserveTest(t, s, 1)
	s.Begin(l)
	b := []byte("observed")
	s.Export(context.Background(), l, "normalized_vcf", digest(b), bytes.NewReader(b))
	if _, e := s.Prepare(l, Outcome{"succeeded", "evaluated_passed", "", digest(b), digest([]byte("different evaluated"))}); e == nil {
		t.Fatal("evaluation mismatch")
	}
}
func TestPersistenceFaultsLatchAndPreserveInputs(t *testing.T) {
	for _, point := range []string{"write", "file_sync", "rename", "directory_sync"} {
		t.Run(point, func(t *testing.T) {
			s, path, p := openTest(t, 2)
			old, _ := os.ReadFile(filepath.Join(path, "ledger.json"))
			s.fault = func(x string) error {
				if x == point {
					return fmt.Errorf("synthetic fault")
				}
				return nil
			}
			if _, e := s.Reserve("0000000000000001", digest(nil)); e == nil {
				t.Fatal("fault ignored")
			}
			if s.Snapshot().Healthy {
				t.Fatal("no latch")
			}
			s.Close()
			reopened, e := Open(context.Background(), path, p)
			if e == nil {
				defer reopened.Close()
				if reopened.Snapshot().Healthy {
					t.Fatal("ambiguous restart admitted")
				}
			}
			if len(old) == 0 {
				t.Fatal("bad fixture")
			}
		})
	}
	for _, point := range []string{"link", "file_sync", "directory_sync"} {
		t.Run("export_"+point, func(t *testing.T) {
			s, _, _ := openTest(t, 1)
			l := reserveTest(t, s, 1)
			s.Begin(l)
			calls := 0
			s.fault = func(x string) error {
				if x == point {
					calls++
					if point == "link" || calls > 1 {
						return io.ErrClosedPipe
					}
				}
				return nil
			}
			if e := s.Export(context.Background(), l, "normalized_vcf", digest([]byte("x")), strings.NewReader("x")); e == nil || s.Snapshot().Healthy {
				t.Fatal("export fault ignored")
			}
		})
	}
}
func TestAcknowledgementAfterStorageFailureCannotApprove(t *testing.T) {
	s, path, p := openTest(t, 2)
	l := commitTest(t, s, 1)
	charge := s.Snapshot().ChargedBytes
	s.fault = func(x string) error {
		if x == "file_sync" {
			return io.ErrClosedPipe
		}
		return nil
	}
	s.Reserve("0000000000000002", digest(nil))
	called := false
	if e := s.Acknowledge(l, func() error { called = true; return nil }); e == nil || called {
		t.Fatal("ACK after latch")
	}
	if s.Snapshot().ChargedBytes < charge {
		t.Fatal("charge released")
	}
	s.Close()
	x, e := Open(context.Background(), path, p)
	if e == nil {
		x.Close()
	}
}
func TestLostAcknowledgementRetainsCommittedHistory(t *testing.T) {
	s, path, p := openTest(t, 1)
	l := commitTest(t, s, 1)
	before := s.Snapshot().ChargedBytes
	if e := s.Acknowledge(l, func() error { return io.ErrClosedPipe }); e == nil {
		t.Fatal("ACK failure hidden")
	}
	s.Close()
	x, e := Open(context.Background(), path, p)
	if e != nil {
		t.Fatal(e)
	}
	defer x.Close()
	if x.Snapshot().ChargedBytes != before {
		t.Fatal("lost ACK released usage")
	}
	if _, e = x.Reserve("0000000000000001", digest(nil)); e == nil {
		t.Fatal("lost ACK job rerun")
	}
}
func TestManifestCannotMutateLedgerByAlias(t *testing.T) {
	s, _, _ := openTest(t, 1)
	l := reserveTest(t, s, 1)
	if e := s.Begin(l); e != nil {
		t.Fatal(e)
	}
	b := []byte("observed")
	if e := s.Export(context.Background(), l, "normalized_vcf", digest(b), bytes.NewReader(b)); e != nil {
		t.Fatal(e)
	}
	m, e := s.Prepare(l, Outcome{"succeeded", "evaluated_passed", "", digest(b), digest(b)})
	if e != nil {
		t.Fatal(e)
	}
	m.Files["normalized_vcf"] = FileRecord{}
	if s.data.Records[l].Files["normalized_vcf"].SHA256 != digest(b) {
		t.Fatal("returned manifest aliases private ledger")
	}
}
func TestCancelledExportFailsClosed(t *testing.T) {
	s, _, _ := openTest(t, 1)
	l := reserveTest(t, s, 1)
	s.Begin(l)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := s.Export(ctx, l, "normalized_vcf", digest(nil), bytes.NewReader(nil)); e == nil || s.Snapshot().Healthy {
		t.Fatal("cancel ignored")
	}
}
func TestBoundedMetadataUnsafeFilesAndAncestors(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink", "ancestor", "sparse", "mode", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			s, path, p := openTest(t, 1)
			s.Close()
			ledgerPath := filepath.Join(path, "ledger.json")
			old, _ := os.ReadFile(ledgerPath)
			switch kind {
			case "fifo":
				os.Remove(ledgerPath)
				syscall.Mkfifo(ledgerPath, 0600)
			case "symlink":
				os.Remove(ledgerPath)
				target := filepath.Join(t.TempDir(), "target")
				os.WriteFile(target, old, 0600)
				os.Symlink(target, ledgerPath)
			case "ancestor":
				link := filepath.Join(t.TempDir(), "link")
				os.Symlink(filepath.Dir(path), link)
				path = filepath.Join(link, "store")
			case "sparse":
				f, _ := os.OpenFile(ledgerPath, os.O_WRONLY, 0600)
				f.Truncate(ledgerLimit + 1)
				f.Close()
			case "mode":
				os.Chmod(ledgerPath, 0644)
			case "hardlink":
				os.Link(ledgerPath, filepath.Join(t.TempDir(), "linked"))
			}
			if x, e := Open(context.Background(), path, p); e == nil {
				x.Close()
				t.Fatal("unsafe metadata admitted")
			}
		})
	}
}
func TestArtifactLinkUnsafeAndMissingDoesNotOverwrite(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "sparse", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			s, path, p := openTest(t, 1)
			l := commitTest(t, s, 1)
			s.Close()
			f := filepath.Join(path, "objects", l, "normalized_vcf")
			os.Remove(f)
			switch kind {
			case "symlink":
				os.Symlink("/dev/null", f)
			case "fifo":
				syscall.Mkfifo(f, 0600)
			case "sparse":
				x, _ := os.OpenFile(f, os.O_CREATE|os.O_WRONLY, 0600)
				x.Truncate(p.ExportBytes + 1)
				x.Close()
			case "corrupt":
				os.WriteFile(f, []byte("different"), 0600)
			}
			if x, e := Open(context.Background(), path, p); e == nil {
				x.Close()
				t.Fatal("unsafe artifact admitted")
			}
			if _, e := os.Lstat(f); e != nil {
				t.Fatal("unsafe history removed")
			}
		})
	}
}

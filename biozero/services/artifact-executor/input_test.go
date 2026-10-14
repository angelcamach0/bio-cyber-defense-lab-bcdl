package artifactexecutor

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestVerifiedInputTransferExactCeilingAndExtraByte(t *testing.T) {
	data := bytes.Repeat([]byte("a"), int(MaxInputBytes))
	for _, extra := range []bool{false, true} {
		source := data
		if extra {
			source = append(append([]byte{}, data...), byte('x'))
		}
		n, e := ReceiveInput(context.Background(), io.Discard, bytes.NewReader(source), MaxInputBytes, digest(data))
		if extra {
			if e == nil || n > MaxInputBytes {
				t.Fatal("input overflow accepted")
			}
		} else if e != nil || n != MaxInputBytes {
			t.Fatal("exact input rejected")
		}
	}
	if _, e := ReceiveInput(context.Background(), io.Discard, bytes.NewReader(nil), MaxInputBytes+1, digest(nil)); e == nil {
		t.Fatal("oversized declared body")
	}
	if _, e := ReceiveInput(context.Background(), io.Discard, bytes.NewReader([]byte("x")), 1, digest([]byte("y"))); e == nil {
		t.Fatal("hash from worker ignored")
	}
}
func TestQuiescencePublicationAndCommitFailureNeverACK(t *testing.T) {
	for _, point := range []string{"file_sync", "link", "directory_sync"} {
		t.Run("proof_"+point, func(t *testing.T) {
			s, path, p := openTest(t, 1)
			l := prepareTest(t, s, 1)
			charge := s.Snapshot().ChargedBytes
			s.fault = func(x string) error {
				if x == point {
					return io.ErrClosedPipe
				}
				return nil
			}
			if e := s.RecordQuiescence(l, proofFor(s, l)); e == nil {
				t.Fatal("proof failure hidden")
			}
			called := false
			s.Acknowledge(l, func() error { called = true; return nil })
			if called || s.Snapshot().ChargedBytes != charge {
				t.Fatal("proof failure released")
			}
			s.Close()
			if x, e := Open(context.Background(), path, p); e == nil {
				defer x.Close()
				if x.Snapshot().Healthy {
					t.Fatal("proof ambiguity admitted")
				}
			}
		})
	}
	t.Run("commit", func(t *testing.T) {
		s, _, _ := openTest(t, 1)
		l := prepareTest(t, s, 1)
		if e := s.RecordQuiescence(l, proofFor(s, l)); e != nil {
			t.Fatal(e)
		}
		s.fault = func(x string) error {
			if x == "rename" {
				return io.ErrClosedPipe
			}
			return nil
		}
		if e := s.Commit(l); e == nil {
			t.Fatal("commit fault hidden")
		}
		called := false
		s.Acknowledge(l, func() error { called = true; return nil })
		if called || s.Snapshot().Healthy {
			t.Fatal("commit ambiguity approved")
		}
	})
}

func TestEmptyFailureAndStatsCommitAllowNextJobWithoutScientificApproval(t *testing.T) {
	for _, outcome := range []Outcome{{"failed", "withheld", "invalid_input", "", ""}, {"incomplete", "withheld", "missing_tools", "", ""}, {"succeeded", "unassessed", "", "", ""}} {
		t.Run(outcome.ExecutionStatus, func(t *testing.T) {
			s, path, p := openTest(t, 2)
			l := reserveTest(t, s, 1)
			if e := s.Begin(l); e != nil {
				t.Fatal(e)
			}
			m, e := s.Prepare(l, outcome)
			if e != nil {
				t.Fatal(e)
			}
			if len(m.Files) != 0 || m.ReleaseStatus == "evaluated_passed" {
				t.Fatal("empty result approved")
			}
			if e = s.RecordQuiescence(l, proofFor(s, l)); e != nil {
				t.Fatal(e)
			}
			if e = s.Commit(l); e != nil {
				t.Fatal(e)
			}
			if e = s.Acknowledge(l, func() error { return nil }); e != nil {
				t.Fatal(e)
			}
			charge := s.Snapshot().ChargedBytes
			if charge <= storeHeaderReserve {
				t.Fatal("metadata released")
			}
			s.Close()
			s2, e := Open(context.Background(), path, p)
			if e != nil {
				t.Fatal(e)
			}
			defer s2.Close()
			next, e := s2.Reserve("0000000000000002", digest([]byte("new original")))
			if e != nil {
				t.Fatal(e)
			}
			if e = s2.Begin(next); e != nil {
				t.Fatal("previous failure blocked next job")
			}
			if s2.Snapshot().RetainedOrReservedJobs != 2 {
				t.Fatal("retained failed slot lost")
			}
		})
	}
}
func TestOutcomeTypeAndScientificDigestRules(t *testing.T) {
	outcomes := []Outcome{{"failed", "evaluated_passed", "invalid_input", "", ""}, {"incomplete", "evaluated_passed", "missing_tools", "", ""}, {"succeeded", "evaluated_passed", "", "", ""}, {"succeeded", "withheld", "", "", ""}, {"failed", "withheld", "free error with sensitive text", "", ""}, {"processed", "unassessed", "", "", ""}, {"succeeded", "unknown", "", "", ""}}
	for _, o := range outcomes {
		s, _, _ := openTest(t, 1)
		l := reserveTest(t, s, 1)
		s.Begin(l)
		if _, e := s.Prepare(l, o); e == nil {
			t.Fatal("unsafe outcome accepted")
		}
	}
	for _, release := range []string{"withheld", "unassessed"} {
		s, _, _ := openTest(t, 1)
		l := reserveTest(t, s, 1)
		s.Begin(l)
		b := []byte("observed")
		if e := s.Export(context.Background(), l, "normalized_vcf", digest(b), bytes.NewReader(b)); e != nil {
			t.Fatal(e)
		}
		o := Outcome{"succeeded", release, "evaluation_no_truth_matches", digest(b), digest(b)}
		m, e := s.Prepare(l, o)
		if e != nil {
			t.Fatal(e)
		}
		if m.ReleaseStatus != release {
			t.Fatal("storage promoted science")
		}
	}
}

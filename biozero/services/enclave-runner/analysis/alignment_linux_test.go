// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package analysis

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("private reader detail") }

func TestSAMRecordSemanticsAndLimits(t *testing.T) {
	// Flags are deliberately different: legacy counts records, not unique reads.
	raw := "@HD\tVN:1.6\nq\t0\ttarget\nq\t256\ttarget\nu\t4\t*\nincomplete\n"
	a, err := ParseSAM(strings.NewReader(raw), Limits{})
	if err != nil || a.TotalReads != 4 || a.MappedReads != 2 || a.Fraction != .5 || a.Targets["target"] != 2 {
		t.Fatal("legacy SAM counting changed", err)
	}
	exact := "q\t0\tt\n"
	for _, tc := range []struct {
		name, raw string
		limits    Limits
		code      Code
	}{
		{"exact_bytes", exact, Limits{SAMBytes: int64(len(exact))}, ""},
		{"over_bytes", exact + " ", Limits{SAMBytes: int64(len(exact))}, "alignment_stdout_limit"},
		{"exact_line", strings.Repeat("x", 16) + "\n", Limits{LineBytes: 16}, ""},
		{"over_line", strings.Repeat("x", 17) + "\n", Limits{LineBytes: 16}, "alignment_line_limit"},
		{"exact_records", exact + exact, Limits{Records: 2}, ""},
		{"over_records", exact + exact + exact, Limits{Records: 2}, "alignment_record_limit"},
		{"exact_target", "q\t0\tabc\n", Limits{TargetBytes: 3}, ""},
		{"over_target", "q\t0\tabcd\n", Limits{TargetBytes: 3}, "alignment_target_limit"},
		{"cardinality", "q\t0\ta\nq\t0\tb\n", Limits{Targets: 1}, "alignment_target_limit"},
		{"control_target", "q\t0\tx\x00z\n", Limits{}, "alignment_target_invalid"},
		{"invalid_config", exact, Limits{Records: -1}, "alignment_config_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSAM(strings.NewReader(tc.raw), tc.limits)
			if tc.code == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err != tc.code || got.TotalReads != 0 || got.MappedReads != 0 || len(got.Targets) != 0 {
				t.Fatal("limit retained partial metrics", err)
			}
		})
	}
	if _, err := ParseSAM(io.MultiReader(strings.NewReader(exact), brokenReader{}), Limits{}); err != Code("alignment_read_failed") {
		t.Fatal("reader diagnostic escaped")
	}
}

func supervisorFixture(t *testing.T, script string) (Supervisor, string, string) {
	t.Helper()
	root := t.TempDir()
	tool := filepath.Join(root, "minimap2")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	panel, content := filepath.Join(root, "panel.fa"), filepath.Join(root, "input.fastq")
	for _, p := range []string{panel, content} {
		if err := os.WriteFile(p, []byte("synthetic fixture, no biological input\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return Supervisor{Executable: tool, Timeout: time.Second}, panel, content
}

func TestSupervisorSuccessAndFailuresDiscardMetrics(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		code         Code
		limits       Limits
	}{
		{"success", "printf 'q\\t0\\ttarget\\n'\n", "", Limits{}},
		{"exit_failure", "printf 'q\\t0\\ttarget\\n'; printf 'private path /secret input' >&2; exit 7\n", "alignment_failed", Limits{}},
		{"stderr_exact", "printf 'q\\t0\\ttarget\\n'; printf 12345678 >&2\n", "", Limits{StderrBytes: 8}},
		{"stderr_over", "printf 'q\\t0\\ttarget\\n'; printf 123456789 >&2\n", "alignment_stderr_limit", Limits{StderrBytes: 8}},
		{"stdout_over", "printf 'q\\t0\\ttarget\\nq\\t0\\ttarget\\nq\\t0\\ttarget\\n'\n", "alignment_stdout_limit", Limits{SAMBytes: 20}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p, c := supervisorFixture(t, tc.script)
			s.Limits = tc.limits
			a, err := s.Align(context.Background(), p, c)
			if tc.code == "" {
				if err != nil || a.MappedReads != 1 || a.TotalReads != 1 {
					t.Fatal("success metrics lost", err)
				}
				return
			}
			if err != tc.code || a.TotalReads != 0 || a.MappedReads != 0 || len(a.Targets) != 0 {
				t.Fatal("failure retained metrics/diagnostics", err)
			}
		})
	}
}

func TestSupervisorTimeoutAndParentCancellation(t *testing.T) {
	for _, parentCancel := range []bool{false, true} {
		t.Run(fmt.Sprint(parentCancel), func(t *testing.T) {
			s, p, c := supervisorFixture(t, "printf 'q\\t0\\ttarget\\n'; sleep 3\n")
			s.Timeout = 40 * time.Millisecond
			ctx := context.Background()
			cancel := func() {}
			expected := Code("alignment_timed_out")
			if parentCancel {
				ctx, cancel = context.WithCancel(ctx)
				s.Timeout = time.Second
				time.AfterFunc(40*time.Millisecond, cancel)
				expected = "analysis_canceled"
			}
			defer cancel()
			start := time.Now()
			a, err := s.Align(ctx, p, c)
			if err != expected || a.TotalReads != 0 || time.Since(start) > 2*time.Second {
				t.Fatal("execution budget not enforced", err)
			}
		})
	}
}

func TestSupervisorStopsDescendantAfterLeaderExit(t *testing.T) {
	for _, cause := range []string{"line", "stderr"} {
		t.Run(cause, func(t *testing.T) {
			root := t.TempDir()
			marker := filepath.Join(root, "must-not-exist")
			emit := "printf 12345678901234567890"
			limits := Limits{LineBytes: 8}
			expected := Code("alignment_line_limit")
			if cause == "stderr" {
				emit += " >&2"
				limits = Limits{StderrBytes: 8}
				expected = "alignment_stderr_limit"
			}
			script := fmt.Sprintf("(sleep .03; %s; sleep .2; touch '%s') &\nexit 0\n", emit, marker)
			s, p, c := supervisorFixture(t, script)
			s.Limits = limits
			start := time.Now()
			a, err := s.Align(context.Background(), p, c)
			if err != expected || a.TotalReads != 0 || time.Since(start) > 2*time.Second {
				t.Fatal("descendant failure not bounded", err)
			}
			time.Sleep(300 * time.Millisecond)
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("descendant survived group cancellation")
			}
		})
	}
}

func TestSupervisorMissingInputsAndTool(t *testing.T) {
	s, p, c := supervisorFixture(t, "exit 0\n")
	if _, err := s.Align(context.Background(), "/missing", c); err != Code("alignment_panel_missing") {
		t.Fatal(err)
	}
	if _, err := s.Align(context.Background(), p, "/missing"); err != Code("alignment_content_missing") {
		t.Fatal(err)
	}
	s.Executable = "/missing-minimap2"
	if _, err := s.Align(context.Background(), p, c); err != Code("alignment_tool_missing") {
		t.Fatal(err)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package analysis

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Limits are trusted configuration; zero means the default, not unlimited.
// Smaller limits are useful for deterministic tests. Larger limits fail closed.
type Limits struct {
	SAMBytes                                              int64
	LineBytes, Records, Targets, TargetBytes, StderrBytes int
}

func DefaultLimits() Limits { return Limits{64 << 20, 1 << 20, 1000000, 128, 128, 64 << 10} }
func (l Limits) checked() (Limits, error) {
	d := DefaultLimits()
	if l.SAMBytes == 0 {
		l.SAMBytes = d.SAMBytes
	}
	if l.LineBytes == 0 {
		l.LineBytes = d.LineBytes
	}
	if l.Records == 0 {
		l.Records = d.Records
	}
	if l.Targets == 0 {
		l.Targets = d.Targets
	}
	if l.TargetBytes == 0 {
		l.TargetBytes = d.TargetBytes
	}
	if l.StderrBytes == 0 {
		l.StderrBytes = d.StderrBytes
	}
	if l.SAMBytes < 1 || l.SAMBytes > d.SAMBytes || l.LineBytes < 1 || l.LineBytes > d.LineBytes || l.Records < 1 || l.Records > d.Records || l.Targets < 1 || l.Targets > d.Targets || l.TargetBytes < 1 || l.TargetBytes > d.TargetBytes || l.StderrBytes < 1 || l.StderrBytes > d.StderrBytes {
		return Limits{}, Code("alignment_config_invalid")
	}
	return l, nil
}

// ParseSAM counts the same records as the existing worker: every non-header
// line counts, even an incomplete record; a third field other than * maps.
// Secondary/supplementary records are not deduplicated into unique reads.
// Any limit or read error discards all partial metrics.
func ParseSAM(reader io.Reader, limits Limits) (AlignmentStats, error) {
	l, err := limits.checked()
	if err != nil {
		return AlignmentStats{}, err
	}
	r := &io.LimitedReader{R: reader, N: l.SAMBytes + 1}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, min(64<<10, l.LineBytes+2)), l.LineBytes+2)
	a := AlignmentStats{Targets: map[string]int{}}
	for scanner.Scan() {
		if r.N == 0 {
			return AlignmentStats{}, Code("alignment_stdout_limit")
		}
		line := scanner.Text()
		if len(line) > l.LineBytes {
			return AlignmentStats{}, Code("alignment_line_limit")
		}
		if strings.HasPrefix(line, "@") {
			continue
		}
		a.TotalReads++
		if a.TotalReads > l.Records {
			return AlignmentStats{}, Code("alignment_record_limit")
		}
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) < 3 || fields[2] == "*" {
			continue
		}
		target := fields[2]
		if len(target) > l.TargetBytes {
			return AlignmentStats{}, Code("alignment_target_limit")
		}
		for _, c := range []byte(target) {
			if c < 33 || c > 126 {
				return AlignmentStats{}, Code("alignment_target_invalid")
			}
		}
		if _, exists := a.Targets[target]; !exists && len(a.Targets) >= l.Targets {
			return AlignmentStats{}, Code("alignment_target_limit")
		}
		a.MappedReads++
		a.Targets[target]++
	}
	if r.N == 0 {
		return AlignmentStats{}, Code("alignment_stdout_limit")
	}
	if scanner.Err() != nil {
		if errors.Is(scanner.Err(), bufio.ErrTooLong) {
			return AlignmentStats{}, Code("alignment_line_limit")
		}
		return AlignmentStats{}, Code("alignment_read_failed")
	}
	if a.TotalReads > 0 {
		a.Fraction = float64(a.MappedReads) / float64(a.TotalReads)
	}
	return a, nil
}

func validAlignment(a AlignmentStats) bool {
	d := DefaultLimits()
	if a.TotalReads < 0 || a.TotalReads > d.Records || a.MappedReads < 0 || a.MappedReads > a.TotalReads || len(a.Targets) > d.Targets || math.IsNaN(a.Fraction) || math.IsInf(a.Fraction, 0) {
		return false
	}
	n := 0
	for k, v := range a.Targets {
		if len(k) > d.TargetBytes || v < 1 || v > a.MappedReads {
			return false
		}
		for _, c := range []byte(k) {
			if c < 33 || c > 126 {
				return false
			}
		}
		n += v
	}
	return n == a.MappedReads
}

// Supervisor runs only the configured minimap2 executable with fixed arguments.
// It must run inside a capsule for namespace-wide cleanup/quiescence guarantees.
// Executable is trusted Go configuration, never a field in Request.
type Supervisor struct {
	Executable string
	Timeout    time.Duration
	Limits     Limits
}

type diagnosticCounter struct {
	mu       sync.Mutex
	n, max   int
	exceeded bool
	cancel   context.CancelFunc
}

func (c *diagnosticCounter) Write(b []byte) (int, error) {
	c.mu.Lock()
	if len(b) <= c.max-c.n {
		c.n += len(b)
		c.mu.Unlock()
		return len(b), nil
	}
	c.exceeded = true
	c.mu.Unlock()
	c.cancel()
	return 0, Code("alignment_stderr_limit")
}
func (c *diagnosticCounter) Exceeded() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.exceeded }

func (s Supervisor) Align(parent context.Context, panel, content string) (AlignmentStats, error) {
	l, err := s.Limits.checked()
	if err != nil {
		return AlignmentStats{}, err
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 600 * time.Second
	}
	if timeout < 0 || timeout > 600*time.Second {
		return AlignmentStats{}, Code("alignment_config_invalid")
	}
	if parent.Err() != nil {
		return AlignmentStats{}, Code("analysis_canceled")
	}
	if f, e := os.Stat(panel); e != nil || !f.Mode().IsRegular() {
		return AlignmentStats{}, Code("alignment_panel_missing")
	}
	if f, e := os.Stat(content); e != nil || !f.Mode().IsRegular() {
		return AlignmentStats{}, Code("alignment_content_missing")
	}
	executable := s.Executable
	if executable == "" {
		executable = "minimap2"
	}
	path, err := exec.LookPath(executable)
	if err != nil {
		return AlignmentStats{}, Code("alignment_tool_missing")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-a", panel, content)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	killGroup := func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	cmd.Cancel = func() error { killGroup(); return nil }
	cmd.WaitDelay = time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return AlignmentStats{}, Code("alignment_stdout_failed")
	}
	defer stdout.Close()
	stderr := &diagnosticCounter{max: l.StderrBytes, cancel: cancel}
	cmd.Stderr = stderr
	if cmd.Start() != nil {
		if parent.Err() != nil {
			return AlignmentStats{}, Code("analysis_canceled")
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return AlignmentStats{}, Code("alignment_timed_out")
		}
		return AlignmentStats{}, Code("alignment_start_failed")
	}
	watchDone := make(chan struct{})
	stopWatch := context.AfterFunc(ctx, func() { killGroup(); _ = stdout.Close(); close(watchDone) })
	stats, parseErr := ParseSAM(stdout, l)
	if parseErr != nil {
		cancel()
		killGroup()
		_ = stdout.Close()
	}
	waitErr := cmd.Wait()
	// Also stop members that closed their pipes but outlived their leader.
	killGroup()
	if !stopWatch() {
		<-watchDone
	}
	if stderr.Exceeded() {
		return AlignmentStats{}, Code("alignment_stderr_limit")
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return AlignmentStats{}, Code("alignment_timed_out")
	}
	if parent.Err() != nil {
		return AlignmentStats{}, Code("analysis_canceled")
	}
	if parseErr != nil {
		return AlignmentStats{}, parseErr
	}
	if waitErr != nil {
		return AlignmentStats{}, Code("alignment_failed")
	}
	return stats, nil
}

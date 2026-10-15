//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	artifact "biozero/artifact-executor"
)

// Keep ambiguous custody reachable in a long-lived embedding process. Raw
// custody descriptors remain authoritative even after Go handles are collected.
var ownerWorkerRetained *ownerWorkerBackend

func ownerWorkerNames(ctx context.Context, path string, limit int) ([]string, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ownerWorkerError("owner_worker_cancelled")
	}
	d, e := openWorkerStageDir(path)
	if e != nil {
		return nil, ownerWorkerError("owner_worker_directory_unavailable")
	}
	defer d.Close()
	entries, e := d.ReadDir(limit + 1)
	if e != nil && e != io.EOF || len(entries) > limit {
		return nil, ownerWorkerError("owner_worker_directory_budget")
	}
	names := make([]string, 0, len(entries))
	for _, v := range entries {
		names = append(names, v.Name())
	}
	sort.Strings(names)
	return names, nil
}
func newOwnerWorkerBackend(ctx context.Context, m ownerWorkerMaterial) (*ownerWorkerBackend, error) {
	// A staging launcher supplies its actual mounted path. An owner config must
	// select that same filesystem; direct launch still validates its own tmpfs.
	if stage := os.Getenv("BIOZERO_DECRYPT_DIR"); stage != "" && stage != m.config.StageDirectory {
		return nil, ownerWorkerError("owner_worker_stage_selection_invalid")
	}
	b := &ownerWorkerBackend{material: m, call: artifact.CallBridgeUnixV3, stage: StageVerifiedPlaintext, pending: map[string]OwnerWorkerBinding{}, stages: map[string]*VerifiedPlaintextStage{}, rejected: map[string]bool{}}
	for _, p := range []string{m.config.JobsDirectory, m.config.UploadsDirectory, m.config.AcceptancesDirectory, m.config.ResultsDirectory} {
		d, e := openWorkerStageDir(p)
		if e != nil {
			return nil, ownerWorkerError("owner_worker_directory_unavailable")
		}
		if e = d.Close(); e != nil {
			return nil, ownerWorkerError("owner_worker_directory_unavailable")
		}
	}
	if e := ValidateWorkerStageDirectory(ctx, m.config.StageDirectory); e != nil {
		return nil, ownerWorkerError("owner_worker_stage_configuration_invalid")
	}
	names, e := ownerWorkerNames(ctx, m.config.StageDirectory, 1)
	if e != nil {
		return nil, e
	}
	b.admissionBlocked = len(names) > 0
	custody, e := OpenOwnerWorkerCustody(ctx, m.config.CustodyDirectory, m.trust)
	b.custody = custody
	if e != nil {
		return b, e
	}
	bindings, e := custody.Bindings()
	if e != nil {
		return b, e
	}
	for _, v := range bindings {
		b.pending[v.JobID] = v
	}
	b.publish = func(ctx context.Context, c ownerWorkerCache) error {
		return ownerWorkerWriteCache(ctx, m.config.ResultsDirectory, c)
	}
	return b, nil
}

// tick always recovers durable owner bindings first. It never reads mutable
// result files to skip work; unknown job lifecycle/cache cannot authorize replay.
func (b *ownerWorkerBackend) tick(ctx context.Context) error {
	b.refresh(ctx)
	if b.sticky {
		return ownerWorkerError("owner_worker_unavailable")
	}
	if b.admissionBlocked || len(b.pending) > 0 {
		return nil
	}
	names, e := ownerWorkerNames(ctx, b.material.config.JobsDirectory, 128)
	if e != nil {
		b.admissionBlocked = true
		return e
	}
	for _, name := range names {
		if ctx.Err() != nil {
			return ownerWorkerError("owner_worker_cancelled")
		}
		if strings.HasSuffix(name, ".pending") && workerCustodyHex(strings.TrimSuffix(name, ".pending"), 16) {
			continue
		}
		if !strings.HasSuffix(name, ".json") || !workerCustodyHex(strings.TrimSuffix(name, ".json"), 16) {
			b.admissionBlocked = true
			return ownerWorkerError("owner_worker_job_layout_invalid")
		}
		job := strings.TrimSuffix(name, ".json")
		binding, found, e := b.custody.Lookup(job)
		if e != nil {
			b.sticky = true
			return e
		}
		if found {
			// Completed process-local entries need no new decrypt or submit. Startup
			// repopulates pending from ALL custody records regardless of job/cache data.
			if _, pending := b.pending[job]; pending {
				_ = b.finish(ctx, binding)
			}
			continue
		}
		if b.rejected[job] {
			continue
		}
		j, e := readOwnerWorkerJob(ctx, filepath.Join(b.material.config.JobsDirectory, name))
		if e != nil {
			// The ingress's exclusive link/unlink publication can briefly have nlink2.
			// Deferring metadata observation is not retrying execution or adopting work.
			continue
		}
		raw, e := readWorkerSnapshot(ctx, filepath.Join(b.material.config.AcceptancesDirectory, job+".json"), 64<<10, true)
		if e != nil {
			continue
		}
		if e = b.process(ctx, j, raw); e != nil {
			if b.sticky || len(b.pending) > 0 || b.admissionBlocked {
				return e
			}
			// Stable classification only; no raw error/path/input goes to process logs.
			fmt.Fprintln(os.Stderr, "owner_worker_input_rejected")
		}
		if len(b.pending) > 0 || b.admissionBlocked {
			return nil
		}
	}
	return nil
}
func runOwnerWorker(ctx context.Context, path string, args []string, out, stderr io.Writer) (code int, backend *ownerWorkerBackend) {
	flags := flag.NewFlagSet("worker owner-v1", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	init := flags.Bool("init-owner-worker", false, "initialize one new private owner custody only")
	if ctx == nil || flags.Parse(args) != nil || flags.NArg() != 0 || path == "" {
		fmt.Fprintln(stderr, "owner_worker_arguments_invalid")
		return 2, nil
	}
	m, e := loadOwnerWorkerConfig(ctx, path)
	if e != nil {
		fmt.Fprintln(stderr, "owner_worker_configuration_invalid")
		return 1, nil
	}
	if *init {
		custody, e := CreateOwnerWorkerCustody(ctx, m.config.CustodyDirectory, m.trust)
		if e != nil {
			fmt.Fprintln(stderr, "owner_worker_init_failed")
			return 1, &ownerWorkerBackend{custody: custody}
		}
		if e = custody.Close(); e != nil {
			fmt.Fprintln(stderr, "owner_worker_init_uncertain")
			return 1, &ownerWorkerBackend{custody: custody}
		}
		const initialized = "{\"schema_version\":1,\"state\":\"initialized\"}\n"
		if n, e := io.WriteString(out, initialized); e != nil || n != len(initialized) {
			fmt.Fprintln(stderr, "owner_worker_init_delivery_failed")
			return 1, nil
		}
		return 0, nil
	}
	b, e := newOwnerWorkerBackend(ctx, m)
	if e != nil {
		fmt.Fprintln(stderr, "owner_worker_start_failed")
		return 1, b
	}
	backend = b
	defer func() {
		if e := b.Close(); e != nil {
			fmt.Fprintln(stderr, "owner_worker_shutdown_pending")
			code = 1
		}
	}()
	const ready = "owner_worker_ready\n"
	if n, e := io.WriteString(out, ready); e != nil || n != len(ready) {
		fmt.Fprintln(stderr, "owner_worker_readiness_failed")
		return 1, b
	}
	ticker := time.NewTicker(time.Duration(m.config.PollMilliseconds) * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return 0, b
		}
		if e = b.tick(ctx); e != nil {
			if b.sticky {
				fmt.Fprintln(stderr, "owner_worker_custody_uncertain")
				return 1, b
			}
			if ctx.Err() == nil {
				fmt.Fprintln(stderr, "owner_worker_execution_pending")
			}
		}
		select {
		case <-ctx.Done():
			return 0, b
		case <-ticker.C:
		}
	}
}

// This selector executes before legacy configuration, job/result recovery or
// tools. Unknown/mixed owner settings never fall back to the old processing loop.
func runOwnerWorkerSelected() (bool, error) {
	protocol := os.Getenv("BIOZERO_WORKER_PROTOCOL")
	path := os.Getenv("BIOZERO_OWNER_WORKER_CONFIG")
	if protocol == "" || protocol == "legacy" {
		if path != "" {
			return true, ownerWorkerError("owner_worker_protocol_required")
		}
		for _, a := range os.Args[1:] {
			if strings.HasPrefix(a, "--init-owner-worker") {
				return true, ownerWorkerError("owner_worker_protocol_required")
			}
		}
		return false, nil
	}
	if protocol != "owner-v1" {
		return true, ownerWorkerError("owner_worker_protocol_invalid")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code, b := runOwnerWorker(ctx, path, os.Args[1:], os.Stdout, os.Stderr)
	ownerWorkerRetained = b
	if code != 0 {
		return true, ownerWorkerError("owner_worker_failed")
	}
	return true, nil
}

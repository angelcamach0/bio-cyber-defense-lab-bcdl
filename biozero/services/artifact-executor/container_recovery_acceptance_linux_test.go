//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// This is deliberately not a scientific pipeline. Its private marker is only a
// trigger for lifecycle faults; Docker wait/inspect and Store remain authorities.
const containerRecoveryPipeline = `import json, os, time
state={"ready":True,"pid":os.getpid()}
with open("/proc/self/status") as f:
 for line in f:
  key,_,value=line.partition(":")
  if key in ("CapEff","CapPrm","CapBnd","NoNewPrivs"): state[key]=value.strip()
with open("lifecycle-ready.json","x") as f:
 json.dump(state,f); f.flush(); os.fsync(f.fileno())
while True: time.sleep(0.05)
`

type containerRecoveryTracker struct {
	provider   *ContainerProvider
	calls      atomic.Int32
	mu         sync.Mutex
	completion ProviderCompletion
}

func (p *containerRecoveryTracker) Execute(ctx context.Context, input *ScopedInput, exporter *Exporter) ProviderCompletion {
	p.calls.Add(1)
	result := p.provider.Execute(ctx, input, exporter)
	p.mu.Lock()
	p.completion = result
	p.mu.Unlock()
	return result
}

type containerRecoveryRun struct {
	registered  RegisteredExecution
	coordinator *Coordinator
	registry    *InputRegistry
	store       *Store
	provider    *ContainerProvider
	tracked     *containerRecoveryTracker
	config      ContainerProviderConfig
}
type containerRecoveryIdentity struct {
	SchemaVersion int    `json:"schema_version"`
	Nonce         string `json:"nonce"`
	Store         string `json:"store"`
	Lease         string `json:"lease"`
	Image         string `json:"image"`
	ContainerID   string `json:"container_id"`
}

func containerRecoverySources(t *testing.T, repo string) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, rel := range []string{"biozero/services/artifact-executor/container_provider_linux.go", "biozero/services/artifact-executor/capsule/container_capsule.py", "biozero/services/artifact-executor/capsule/native_capsule.py", "biozero/services/artifact-executor/store.go", "biozero/services/artifact-executor/types.go", "biozero/services/artifact-executor/registry_linux.go", "biozero/services/artifact-executor/coordinator_linux.go", "biozero/services/artifact-executor/container_recovery_acceptance_linux_test.go", "biozero/bio/pipeline/resource_budget.py"} {
		raw, err := os.ReadFile(filepath.Join(repo, rel))
		if err != nil {
			t.Fatal(err)
		}
		result[rel] = digest(raw)
	}
	return result
}
func containerRecoveryConfig(t *testing.T, base string, timeout int) ContainerProviderConfig {
	t.Helper()
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	assets := filepath.Join(base, "assets")
	if err = os.Mkdir(assets, 0700); err != nil {
		t.Fatal(err)
	}
	pipeline := filepath.Join(assets, "pipeline.py")
	if err = os.WriteFile(pipeline, []byte(containerRecoveryPipeline), 0600); err != nil {
		t.Fatal(err)
	}
	budget, err := os.ReadFile(filepath.Join(repo, "biozero/bio/pipeline/resource_budget.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(assets, "resource_budget.py"), budget, 0600); err != nil {
		t.Fatal(err)
	}
	asset := func(rel string) PinnedAsset {
		path := filepath.Join(repo, rel)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return PinnedAsset{path, digest(raw)}
	}
	return ContainerProviderConfig{WorkspaceRoot: filepath.Join(base, "controls"), DockerCommand: []string{"/usr/bin/sudo", "-n", "/usr/bin/docker", "--host=unix:///var/run/docker.sock"}, ImageID: "sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d", Mode: "stats", Helper: asset("biozero/services/artifact-executor/capsule/container_capsule.py"), NativeHelper: asset("biozero/services/artifact-executor/capsule/native_capsule.py"), Pipeline: PinnedAsset{pipeline, digest([]byte(containerRecoveryPipeline))}, ResourceBudgetSHA256: digest(budget), TimeoutSeconds: timeout}
}
func containerRecoverySetup(t *testing.T, base string, timeout int) *containerRecoveryRun {
	t.Helper()
	cfg := containerRecoveryConfig(t, base, timeout)
	provider, err := NewContainerProvider(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(context.Background(), filepath.Join(base, "store"), NativeArtifactPolicy())
	if err != nil {
		provider.Close()
		t.Fatal(err)
	}
	registry, err := NewInputRegistry(store)
	if err != nil {
		store.Close()
		provider.Close()
		t.Fatal(err)
	}
	tracked := &containerRecoveryTracker{provider: provider}
	coordinator, err := NewCoordinator(store, registry, tracked)
	if err != nil {
		registry.Close()
		store.Close()
		provider.Close()
		t.Fatal(err)
	}
	run := &containerRecoveryRun{coordinator: coordinator, registry: registry, store: store, provider: provider, tracked: tracked, config: cfg}
	data := []byte("@lifecycle\nACGT\n+\nIIII\n")
	path := filepath.Join(base, "verified.fastq")
	if err = os.WriteFile(path, data, 0600); err != nil {
		run.close()
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		run.close()
		t.Fatal(err)
	}
	defer f.Close()
	run.registered, err = coordinator.RegisterInput(context.Background(), "0000000000000004", digest([]byte("synthetic original container lifecycle upload")), digest(data), int64(len(data)), f)
	if err != nil {
		run.close()
		t.Fatal(err)
	}
	return run
}
func (r *containerRecoveryRun) close() {
	r.coordinator.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if r.coordinator.Wait(ctx) == nil {
		r.registry.Close()
		r.provider.Close()
		r.store.Close()
	}
}
func containerRecoveryReady(t *testing.T, p *ContainerProvider, registered RegisteredExecution) (containerRecoveryIdentity, string) {
	t.Helper()
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		entries, _ := os.ReadDir(p.config.WorkspaceRoot)
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			anchor := filepath.Join(p.config.WorkspaceRoot, entry.Name())
			raw, err := os.ReadFile(filepath.Join(anchor, "container.json"))
			var id containerRecoveryIdentity
			if err != nil || strictJSON(raw, &id) != nil || id.SchemaVersion != 1 || !hexID(id.ContainerID, 64) || !hexID(id.Nonce, 32) || id.Lease != registered.LeaseID || id.Image != p.config.ImageID || entry.Name() != "capsule-"+id.Nonce {
				continue
			}
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			state, err := p.inspect(ctx, id.ContainerID)
			if err != nil || !p.validInspection(state, id.ContainerID, id.Nonce, id.Store, id.Lease, anchor) || state.Status != "running" || !state.Running || state.PID <= 0 {
				stop()
				continue
			}
			// Fixed test-only exec: no paths or commands supplied by RPC/client. Reading
			// readiness is not quiescence evidence, and is never done after keeper death.
			marker, err := p.docker(ctx, "exec", id.ContainerID, "/usr/bin/python3.12", "-I", "-B", "-S", "-c", "import pathlib,sys; sys.stdout.buffer.write(pathlib.Path('/workspace/lifecycle-ready.json').read_bytes())")
			stop()
			if err != nil {
				continue
			}
			var m struct {
				Ready      bool   `json:"ready"`
				PID        int    `json:"pid"`
				CapEff     string `json:"CapEff"`
				CapPrm     string `json:"CapPrm"`
				CapBnd     string `json:"CapBnd"`
				NoNewPrivs string `json:"NoNewPrivs"`
			}
			if strictJSON(marker, &m) == nil && m.Ready && m.PID > 1 && m.CapEff == "0000000000000000" && m.CapPrm == m.CapEff && m.CapBnd == m.CapEff && m.NoNewPrivs == "1" {
				return id, anchor
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("actual Docker lifecycle workload readiness unavailable; private history retained")
	return containerRecoveryIdentity{}, ""
}

// Emergency cleanup touches only the freshly identified capsule, retains its
// stopped object/history, and never makes the failed acceptance pass.
func containerRecoveryStopOwned(p *ContainerProvider, id containerRecoveryIdentity, anchor string) {
	ctx, stop := context.WithTimeout(context.Background(), 12*time.Second)
	defer stop()
	state, err := p.inspect(ctx, id.ContainerID)
	if err == nil && p.validInspection(state, id.ContainerID, id.Nonce, id.Store, id.Lease, anchor) && state.Running {
		p.docker(ctx, "kill", "--signal=KILL", id.ContainerID)
		p.docker(ctx, "wait", id.ContainerID)
	}
}

func TestContainerRecoveryActualAcceptance(t *testing.T) {
	if os.Getenv("BIOZERO_RUN_CONTAINER_RECOVERY_ACCEPTANCE") != "1" {
		t.Skip("opt-in actual local Docker lifecycle recovery; no model")
	}
	if runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64" {
		t.Fatal("unsupported acceptance architecture")
	}
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	evidence := os.Getenv("BIOZERO_CONTAINER_RECOVERY_EVIDENCE_DIR")
	if evidence == "" {
		evidence = filepath.Join(repo, ".biozero", "container-recovery-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	}
	if !filepath.IsAbs(evidence) || os.Mkdir(evidence, 0700) != nil {
		t.Fatal("evidence root must be new and absolute")
	}
	sources := containerRecoverySources(t, repo)
	for _, scenario := range []string{"cancel", "timeout", "keeper_kill"} {
		t.Run(scenario, func(t *testing.T) {
			base := filepath.Join(evidence, scenario)
			if err := os.Mkdir(base, 0700); err != nil {
				t.Fatal(err)
			}
			record := recoveryEvidence{SchemaVersion: 1, Case: scenario, Status: "running", Scope: "Actual pinned Docker/Coordinator/Store lifecycle with blocked stats fixture; no science, worker, protected entry, model, network or attestation.", SourceSHA256: sources}
			defer func() {
				record.Status = "passed"
				if t.Failed() {
					record.Status = "failed"
				}
				if err := recoveryPrivateJSON(filepath.Join(base, "acceptance.json"), record); err != nil {
					t.Error("private acceptance persistence failed", err)
				}
			}()
			if scenario == "keeper_kill" {
				containerRecoveryKilledKeeper(t, base, &record)
				return
			}
			timeout := 30
			if scenario == "timeout" {
				timeout = 8
			}
			run := containerRecoverySetup(t, base, timeout)
			defer run.close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := run.coordinator.Handle(ctx, runRequest(run.registered)); done <- err }()
			id, anchor := containerRecoveryReady(t, run.provider, run.registered)
			defer containerRecoveryStopOwned(run.provider, id, anchor)
			recoveryCheck(t, &record, "actual_blocked_workload_ready_caps0_nnp", true)
			recoveryFlockDenied(t, filepath.Join(base, "store"))
			recoveryCheck(t, &record, "live_lifetime_flock_denies_restart", true)
			run.store.mu.Lock()
			before := run.store.data.Records[run.registered.LeaseID]
			policy := run.store.data.Policy
			run.store.mu.Unlock()
			recoveryCheck(t, &record, "executing_full_reservation_before_termination", before.State == "executing" && before.Charge == policy.ExportBytes+policy.PublicationHeadroom && before.ProofSHA256 == "" && before.ManifestSHA256 == "")
			if scenario == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				recoveryCheck(t, &record, "coordinator_returns_after_authoritative_wait", err == nil)
			case <-time.After(45 * time.Second):
				t.Fatal("container lifecycle failed to terminate; private history retained")
			}
			run.tracked.mu.Lock()
			completion := run.tracked.completion
			run.tracked.mu.Unlock()
			recoveryCheck(t, &record, "provider_completion_real_quiescent_failure", completion.Quiescent && completion.Err != nil)
			run.store.mu.Lock()
			entry := run.store.data.Records[run.registered.LeaseID]
			run.store.mu.Unlock()
			recoveryCheck(t, &record, "failure_commit_has_postwait_proof", entry.State == "committed" && hexID(entry.ProofSHA256, 64) && entry.Charge > 0)
			object := filepath.Join(base, "store", "objects", run.registered.LeaseID)
			manifestRaw, manifestErr := os.ReadFile(filepath.Join(object, "manifest.json"))
			proofRaw, proofErr := os.ReadFile(filepath.Join(object, "proof.json"))
			var durableProof Proof
			proofDecode := strictJSON(proofRaw, &durableProof)
			recoveryCheck(t, &record, "proof_binds_exact_durable_manifest", manifestErr == nil && proofErr == nil && proofDecode == nil && digest(proofRaw) == entry.ProofSHA256 && digest(manifestRaw) == entry.ManifestSHA256 && durableProof.ManifestSHA256 == digest(manifestRaw) && durableProof.CapsuleWaitFinished && durableProof.ExportAuthorityClosed && durableProof.LeaseID == run.registered.LeaseID)

			raw, err := run.coordinator.response(run.registered.LeaseID, false)
			recoveryCheck(t, &record, "failure_manifest_readable", err == nil)
			var response ExecutionResponse
			err = json.Unmarshal(raw, &response)
			recoveryCheck(t, &record, "failed_withheld_empty_exports_never_approval", err == nil && response.Manifest != nil && response.Manifest.ExecutionStatus == "failed" && response.Manifest.ReleaseStatus == "withheld" && len(response.Manifest.Files) == 0)
			called := false
			canceled, stop := context.WithCancel(context.Background())
			stop()
			err = run.coordinator.Acknowledge(canceled, runRequest(run.registered), func() error { called = true; return nil })
			recoveryCheck(t, &record, "canceled_ack_callback_never_called", err != nil && !called)
			recoveryCheck(t, &record, "provider_invoked_once", run.tracked.calls.Load() == 1)
			anchors, err := os.ReadDir(run.config.WorkspaceRoot)
			recoveryCheck(t, &record, "controls_clean_after_verified_wait", err == nil && len(anchors) == 0)
			inspectCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			remaining, inspectErr := run.provider.docker(inspectCtx, "ps", "--all", "--no-trunc", "--filter", "id="+id.ContainerID, "--format", "{{.ID}}")
			stop()
			recoveryCheck(t, &record, "owned_capsule_removed_after_wait", inspectErr == nil && len(remaining) == 0)
			charge := run.store.Snapshot().ChargedBytes
			run.close()
			reopened, err := Open(context.Background(), filepath.Join(base, "store"), NativeArtifactPolicy())
			recoveryCheck(t, &record, "failed_commit_reopens_consistently", err == nil)
			defer reopened.Close()
			recoveryCheck(t, &record, "slot_charge_retained_across_restart", reopened.Snapshot().ChargedBytes == charge && reopened.Snapshot().RetainedOrReservedJobs == 1)
			registry, err := NewInputRegistry(reopened)
			recoveryCheck(t, &record, "fresh_registry_valid_after_failure_commit", err == nil)
			defer registry.Close()
			tracker := &containerRecoveryTracker{provider: run.provider}
			coordinator, err := NewCoordinator(reopened, registry, tracker)
			recoveryCheck(t, &record, "fresh_coordinator_valid", err == nil)
			defer coordinator.Close()
			_, err = coordinator.Handle(context.Background(), runRequest(run.registered))
			recoveryCheck(t, &record, "old_pair_cannot_reexecute", err != nil && tracker.calls.Load() == 0)
		})
	}
	t.Log("private Docker lifecycle acceptance root:", evidence)
}

func TestContainerRecoveryKeeperProcess(t *testing.T) {
	if os.Getenv("BIOZERO_CONTAINER_RECOVERY_CHILD") != "1" || os.Getenv("BIOZERO_RUN_CONTAINER_RECOVERY_ACCEPTANCE") != "1" {
		t.Skip("internal Docker keeper subprocess")
	}
	base := os.Getenv("BIOZERO_CONTAINER_RECOVERY_CHILD_DIR")
	if !filepath.IsAbs(base) {
		t.Fatal("invalid child destination")
	}
	run := containerRecoverySetup(t, base, 30)
	defer run.close()
	registration := struct {
		Registered RegisteredExecution     `json:"registered"`
		Config     ContainerProviderConfig `json:"config"`
	}{run.registered, run.config}
	if err := recoveryPrivateJSON(filepath.Join(base, "registration.json"), registration); err != nil {
		t.Fatal(err)
	}
	_, err := run.coordinator.Handle(context.Background(), runRequest(run.registered))
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("keeper workload unexpectedly completed before parent fault")
}
func containerRecoveryKilledKeeper(t *testing.T, base string, record *recoveryEvidence) {
	t.Helper()
	restore := recoverySubreaper(t)
	defer restore()
	log, err := os.OpenFile(filepath.Join(base, "keeper.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestContainerRecoveryKeeperProcess$", "-test.count=1", "-test.timeout=50s")
	// Preserve host SDK/Docker auth. Runtime Docker command independently clears
	// exactly the five local endpoint selectors; none of this env reaches tools.
	command.Env = append(os.Environ(), "BIOZERO_RUN_CONTAINER_RECOVERY_ACCEPTANCE=1", "BIOZERO_CONTAINER_RECOVERY_CHILD=1", "BIOZERO_CONTAINER_RECOVERY_CHILD_DIR="+base)
	command.Stdout = log
	command.Stderr = log
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	defer command.Process.Kill()
	var info struct {
		Registered RegisteredExecution     `json:"registered"`
		Config     ContainerProviderConfig `json:"config"`
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(base, "registration.json"))
		if err == nil && json.Unmarshal(raw, &info) == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	recoveryCheck(t, record, "keeper_registration_durable", hexID(info.Registered.LeaseID, 32))
	probe := &ContainerProvider{config: info.Config}
	id, anchor := containerRecoveryReady(t, probe, info.Registered)
	defer containerRecoveryStopOwned(probe, id, anchor)
	recoveryCheck(t, record, "actual_keeper_workload_ready", true)
	managed := containerRecoveryAttachTasks(command.Process.Pid, id.ContainerID)
	recoveryCheck(t, record, "capture_only_keeper_owned_attach_tasks", len(managed) > 0)
	recoveryFlockDenied(t, filepath.Join(base, "store"))
	recoveryCheck(t, record, "live_flock_denies_restart", true)
	beforeRaw, err := os.ReadFile(filepath.Join(base, "store/ledger.json"))
	recoveryCheck(t, record, "pending_ledger_readable", err == nil)
	var saved ledger
	err = strictJSON(beforeRaw, &saved)
	recoveryCheck(t, record, "pending_ledger_strict", err == nil)
	before := saved.Records[info.Registered.LeaseID]
	recoveryCheck(t, record, "pending_full_charge_without_proof", before.State == "executing" && before.ProofSHA256 == "" && before.ManifestSHA256 == "" && before.Charge == saved.Policy.ExportBytes+saved.Policy.PublicationHeadroom)
	recoveryCheck(t, record, "sigkill_only_spawned_keeper", command.Process.Kill() == nil)
	// No Wait, readiness probe or Docker cleanup intervenes before this gate.
	early, earlyErr := Open(context.Background(), filepath.Join(base, "store"), NativeArtifactPolicy())
	if earlyErr != nil {
		record.ImmediateRestart = "lifetime_flock_locked"
		recoveryCheck(t, record, "immediate_restart_denied_before_cleanup", earlyErr.Error() == "artifact_instance_locked")
	} else {
		snapshot := early.Snapshot()
		early.Close()
		record.ImmediateRestart = "durable_pending_unhealthy"
		recoveryCheck(t, record, "immediate_restart_denied_before_cleanup", !snapshot.Healthy && snapshot.RetainedOrReservedJobs == 1 && snapshot.ChargedBytes == storeHeaderReserve+before.Charge)
	}
	select {
	case err := <-finished:
		var exit *exec.ExitError
		recoveryCheck(t, record, "keeper_exit_sigkill", errors.As(err, &exit) && exit.Sys().(syscall.WaitStatus).Signaled() && exit.Sys().(syscall.WaitStatus).Signal() == syscall.SIGKILL)
	case <-time.After(6 * time.Second):
		t.Fatal("spawned keeper failed to exit")
	}
	waitCtx, stop := context.WithTimeout(context.Background(), 12*time.Second)
	defer stop()
	raw, err := probe.docker(waitCtx, "wait", id.ContainerID)
	code, parseErr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	state, inspectErr := probe.inspect(waitCtx, id.ContainerID)
	recoveryCheck(t, record, "eof_monitor_actual_pid1_exited_wait_inspect", err == nil && parseErr == nil && inspectErr == nil && probe.validInspection(state, id.ContainerID, id.Nonce, id.Store, id.Lease, anchor) && state.Status == "exited" && !state.Running && !state.Paused && !state.Restarting && !state.Dead && state.PID == 0 && state.ExitCode == code && code == 1)
	containerRecoveryReapAttach(t, managed)
	recoveryCheck(t, record, "captured_attach_processes_exited_reaped", true)
	// This observation does not give the dead keeper authority to manufacture proof.
	reopened, err := Open(context.Background(), filepath.Join(base, "store"), NativeArtifactPolicy())
	recoveryCheck(t, record, "pending_store_reopens_unhealthy", err == nil)
	defer reopened.Close()
	snapshot := reopened.Snapshot()
	recoveryCheck(t, record, "pending_slot_full_charge_retained", !snapshot.Healthy && snapshot.RetainedOrReservedJobs == 1 && snapshot.ChargedBytes == storeHeaderReserve+before.Charge)
	reopened.mu.Lock()
	current := reopened.data.Records[info.Registered.LeaseID]
	reopened.mu.Unlock()
	recoveryCheck(t, record, "no_proof_manifest_after_keeper_loss", current.State == "executing" && current.ProofSHA256 == "" && current.ManifestSHA256 == "")
	_, err = reopened.Reserve("0000000000000005", digest([]byte("other")))
	recoveryCheck(t, record, "new_admission_denied", err != nil)
	recoveryCheck(t, record, "pending_begin_denied_no_reexecution", reopened.Begin(info.Registered.LeaseID) != nil)
	called := false
	err = reopened.Acknowledge(info.Registered.LeaseID, func() error { called = true; return nil })
	recoveryCheck(t, record, "pending_ack_callback_never_called", err != nil && !called)
	_, err = NewInputRegistry(reopened)
	recoveryCheck(t, record, "registry_authority_not_recreated", err != nil)
	provider, err := NewContainerProvider(context.Background(), info.Config)
	if provider != nil {
		provider.Close()
	}
	recoveryCheck(t, record, "old_control_history_not_adopted", err != nil && err.Error() == "artifact_container_workspace_history_unknown")
	after, err := os.ReadFile(filepath.Join(base, "store/ledger.json"))
	recoveryCheck(t, record, "restart_does_not_rewrite_pending_history", err == nil && digest(after) == digest(beforeRaw))
	anchors, err := os.ReadDir(info.Config.WorkspaceRoot)
	recoveryCheck(t, record, "anchor_intent_id_retained", err == nil && len(anchors) == 1 && anchors[0].Name() == "capsule-"+id.Nonce)
	last, err := probe.inspect(waitCtx, id.ContainerID)
	recoveryCheck(t, record, "stopped_owned_container_retained_not_removed", err == nil && last.ID == id.ContainerID && last.Status == "exited" && last.PID == 0)
}

// Only descendants of the test's created keeper, with exact attach argv/ID, are
// captured. No host-wide PID search or signal is used. The temporary subreaper
// lets the test reap those known orphan CLIs after Docker has ended the capsule.
func containerRecoveryAttachTasks(keeper int, id string) []recoveryTask {
	var found []recoveryTask
	var walk func(int, int)
	walk = func(parent, depth int) {
		if depth > 4 {
			return
		}
		for _, pid := range recoveryChildren(parent) {
			task, err := recoveryReadTask(pid)
			if err == nil && recoveryHasArg(task, id) && recoveryHasArg(task, "start") && recoveryHasArg(task, "--attach") {
				found = append(found, task)
			}
			walk(pid, depth+1)
		}
	}
	walk(keeper, 0)
	return found
}
func containerRecoveryReapAttach(t *testing.T, tasks []recoveryTask) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for _, task := range tasks {
			if recoveryGone(task) {
				continue
			}
			var status syscall.WaitStatus
			_, err := syscall.Wait4(task.pid, &status, syscall.WNOHANG, nil)
			if err != nil && err != syscall.ECHILD {
				t.Fatal("captured attach reap failed")
			}
			if !recoveryGone(task) {
				all = false
			}
		}
		if all {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("captured keeper attach processes remain; scoped history retained")
}

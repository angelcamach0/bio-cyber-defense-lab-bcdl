//go:build linux

package artifactexecutor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Deliberately blocked trusted lifecycle workload, not the scientific pipeline.
// Its marker is readiness only; it never authorizes quiescence or recovery.
const recoveryPipeline = `import json, os, time
state={"ready":True,"pid":os.getpid()}
with open("/proc/self/status") as f:
 for line in f:
  key,_,value=line.partition(":")
  if key in ("CapEff","CapPrm","CapBnd","NoNewPrivs"): state[key]=value.strip()
with open("lifecycle-ready.json","x") as f:
 json.dump(state,f); f.flush(); os.fsync(f.fileno())
while True: time.sleep(0.05)
`

type recoveryTrackingProvider struct {
	native *NativeProvider
	calls  atomic.Int32
}

func (p *recoveryTrackingProvider) Execute(ctx context.Context, i *ScopedInput, e *Exporter) ProviderCompletion {
	p.calls.Add(1)
	return p.native.Execute(ctx, i, e)
}

type recoveryRun struct {
	registered  RegisteredExecution
	coordinator *Coordinator
	registry    *InputRegistry
	store       *Store
	provider    *NativeProvider
	tracked     *recoveryTrackingProvider
	config      NativeProviderConfig
}
type recoveryTask struct {
	pid   int
	start string
	cmd   []string
	pidfd int
}
type recoveryAssertion struct {
	Code   string `json:"code"`
	Passed bool   `json:"passed"`
}
type recoveryEvidence struct {
	SchemaVersion    int                 `json:"schema_version"`
	Case             string              `json:"case"`
	Status           string              `json:"status"`
	Scope            string              `json:"scope"`
	Assertions       []recoveryAssertion `json:"assertions"`
	SourceSHA256     map[string]string   `json:"source_sha256"`
	ImmediateRestart string              `json:"immediate_restart,omitempty"`
}

func recoveryCheck(t *testing.T, e *recoveryEvidence, code string, ok bool) {
	t.Helper()
	e.Assertions = append(e.Assertions, recoveryAssertion{code, ok})
	if !ok {
		t.Fatal(code)
	}
}
func recoveryPrivateJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	parent, err := unixExistingDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	nonce, err := token()
	if err != nil {
		return err
	}
	tmp := ".acceptance-" + nonce
	f, err := regular(parent, tmp, true)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Link(fdPath(parent)+"/"+tmp, fdPath(parent)+"/"+filepath.Base(path)); err != nil {
		return err
	}
	if err = syscall.Unlinkat(int(parent.Fd()), tmp); err != nil {
		return err
	}
	return parent.Sync()
}
func recoverySources(t *testing.T, repo string) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, rel := range []string{"biozero/services/artifact-executor/native_provider_linux.go", "biozero/services/artifact-executor/capsule/native_capsule.py", "biozero/services/artifact-executor/store.go", "biozero/services/artifact-executor/registry_linux.go", "biozero/services/artifact-executor/coordinator_linux.go", "biozero/services/artifact-executor/native_recovery_acceptance_linux_test.go", "biozero/bio/pipeline/resource_budget.py"} {
		b, err := os.ReadFile(filepath.Join(repo, rel))
		if err != nil {
			t.Fatal(err)
		}
		result[rel] = digest(b)
	}
	return result
}
func recoveryConfig(t *testing.T, base string, timeout int) NativeProviderConfig {
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
	if err = os.WriteFile(pipeline, []byte(recoveryPipeline), 0600); err != nil {
		t.Fatal(err)
	}
	budget, err := os.ReadFile(filepath.Join(repo, "biozero/bio/pipeline/resource_budget.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(assets, "resource_budget.py"), budget, 0600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(repo, "biozero/services/artifact-executor/capsule/native_capsule.py")
	raw, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	python, err := filepath.EvalSymlinks("/usr/bin/python3")
	if err != nil {
		t.Fatal(err)
	}
	// No namespace opt-in silently substitutes an unavailable interpreter/provider.
	probe := exec.Command(python, "-I", "-B", "-S", "-c", "import os,signal,sys; assert sys.version_info[:2]==(3,9); assert hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal')")
	probe.Env = []string{"PATH=/usr/bin", "LANG=C", "LC_ALL=C"}
	if err = probe.Run(); err != nil {
		t.Fatal("host Python3.9/pidfd capability unavailable")
	}
	return NativeProviderConfig{WorkspaceRoot: filepath.Join(base, "workspaces"), PythonPath: python, ToolPath: "/tmp/biozero-bio-tools-locked/bin:/usr/bin", Mode: "stats", Helper: PinnedAsset{helper, digest(raw)}, Pipeline: PinnedAsset{pipeline, digest([]byte(recoveryPipeline))}, ResourceBudgetSHA256: digest(budget), TimeoutSeconds: timeout}
}
func recoverySetup(t *testing.T, base string, timeout int) *recoveryRun {
	t.Helper()
	cfg := recoveryConfig(t, base, timeout)
	p, err := NewNativeProvider(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), filepath.Join(base, "store"), NativeArtifactPolicy())
	if err != nil {
		p.Close()
		t.Fatal(err)
	}
	r, err := NewInputRegistry(s)
	if err != nil {
		s.Close()
		p.Close()
		t.Fatal(err)
	}
	tracked := &recoveryTrackingProvider{native: p}
	c, err := NewCoordinator(s, r, tracked)
	if err != nil {
		r.Close()
		s.Close()
		p.Close()
		t.Fatal(err)
	}
	data := []byte("@lifecycle\nACGT\n+\nIIII\n")
	path := filepath.Join(base, "verified.fastq")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	registered, err := c.RegisterInput(context.Background(), "0000000000000001", digest([]byte("synthetic original lifecycle upload")), digest(data), int64(len(data)), f)
	if err != nil {
		t.Fatal(err)
	}
	return &recoveryRun{registered, c, r, s, p, tracked, cfg}
}
func (r *recoveryRun) close() {
	r.coordinator.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if r.coordinator.Wait(ctx) == nil {
		r.registry.Close()
		r.provider.Close()
		r.store.Close()
	}
}
func recoveryReadTask(pid int) (recoveryTask, error) {
	task := recoveryTask{pid: pid, pidfd: -1}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return task, err
	}
	end := strings.LastIndex(string(raw), ")")
	if end < 0 {
		return task, errors.New("task_stat_invalid")
	}
	fields := strings.Fields(string(raw)[end+1:])
	if len(fields) < 20 {
		return task, errors.New("task_stat_invalid")
	}
	task.start = fields[19]
	cmd, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return task, err
	}
	task.cmd = strings.Split(strings.TrimSuffix(string(cmd), "\x00"), "\x00")
	return task, nil
}
func recoveryChildren(pid int) []int {
	tasks, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	seen := map[int]bool{}
	var found []int
	for _, thread := range tasks {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", pid, thread.Name()))
		if err != nil {
			continue
		}
		for _, word := range strings.Fields(string(b)) {
			n, err := strconv.Atoi(word)
			if err == nil && !seen[n] {
				seen[n] = true
				found = append(found, n)
			}
		}
	}
	return found
}
func recoveryHasArg(task recoveryTask, arg string) bool {
	for _, value := range task.cmd {
		if value == arg {
			return true
		}
	}
	return false
}
func recoveryPin(task recoveryTask) (recoveryTask, error) {
	// Generic Linux syscall numbers for the explicitly accepted arm64/amd64 host.
	fd, _, errno := syscall.Syscall(434, uintptr(task.pid), 0, 0)
	if errno != 0 {
		return task, errno
	}
	task.pidfd = int(fd)
	current, err := recoveryReadTask(task.pid)
	if err != nil || current.start != task.start {
		syscall.Close(task.pidfd)
		task.pidfd = -1
		return task, errors.New("task_identity_changed")
	}
	return task, nil
}
func (task recoveryTask) signal(signal syscall.Signal) error {
	if task.pidfd < 0 {
		return errors.New("pidfd_missing")
	}
	_, _, errno := syscall.Syscall6(424, uintptr(task.pidfd), uintptr(signal), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func (task recoveryTask) close() {
	if task.pidfd >= 0 {
		syscall.Close(task.pidfd)
	}
}
func recoveryReady(t *testing.T, keeper int, cfg NativeProviderConfig) (recoveryTask, recoveryTask) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		for _, pid := range recoveryChildren(keeper) {
			helper, err := recoveryReadTask(pid)
			if err != nil || !recoveryHasArg(helper, cfg.Helper.Path) {
				continue
			}
			for _, child := range recoveryChildren(pid) {
				pipeline, err := recoveryReadTask(child)
				if err != nil || !recoveryHasArg(pipeline, cfg.Pipeline.Path) {
					continue
				}
				raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cwd/lifecycle-ready.json", child))
				if err != nil {
					continue
				}
				var marker map[string]any
				if json.Unmarshal(raw, &marker) != nil || marker["ready"] != true {
					continue
				}
				if marker["NoNewPrivs"] != "1" || marker["CapEff"] != "0000000000000000" || marker["CapPrm"] != "0000000000000000" || marker["CapBnd"] != "0000000000000000" {
					t.Fatal("lifecycle capsule capability boundary invalid")
				}
				helper, err = recoveryPin(helper)
				if err != nil {
					continue
				}
				pipeline, err = recoveryPin(pipeline)
				if err != nil {
					helper.close()
					continue
				}
				return helper, pipeline
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("actual native lifecycle readiness unavailable")
	return recoveryTask{}, recoveryTask{}
}
func recoveryGone(task recoveryTask) bool {
	current, err := recoveryReadTask(task.pid)
	return os.IsNotExist(err) || err == nil && current.start != task.start
}
func recoveryWaitGone(t *testing.T, tasks ...recoveryTask) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for _, task := range tasks {
			if !recoveryGone(task) {
				all = false
			}
		}
		if all {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("captured lifecycle processes remain")
}
func recoveryFlockDenied(t *testing.T, path string) {
	t.Helper()
	s, err := Open(context.Background(), path, NativeArtifactPolicy())
	if err == nil {
		s.Close()
		t.Fatal("live Store flock admitted second instance")
	}
	if err.Error() != "artifact_instance_locked" {
		t.Fatal("restart was not denied by lifetime flock", err)
	}
}

func TestNativeRecoveryActualAcceptance(t *testing.T) {
	if os.Getenv("BIOZERO_RUN_NATIVE_RECOVERY_ACCEPTANCE") != "1" {
		t.Skip("opt-in real kernel/keeper recovery; no model")
	}
	if runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64" {
		t.Fatal("unsupported pidfd acceptance architecture")
	}
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	evidence := os.Getenv("BIOZERO_NATIVE_RECOVERY_EVIDENCE_DIR")
	if evidence == "" {
		evidence = filepath.Join(repo, ".biozero", "native-recovery-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	}
	if !filepath.IsAbs(evidence) {
		t.Fatal("evidence root must be new and absolute")
	}
	if err = os.Mkdir(evidence, 0700); err != nil {
		t.Fatal("evidence root already exists/unavailable")
	}
	sources := recoverySources(t, repo)
	for _, scenario := range []string{"cancel", "timeout", "pid1_kill", "keeper_kill"} {
		t.Run(scenario, func(t *testing.T) {
			base := filepath.Join(evidence, scenario)
			if err = os.Mkdir(base, 0700); err != nil {
				t.Fatal(err)
			}
			record := recoveryEvidence{1, scenario, "running", "Actual NativeProvider/Store lifecycle with pinned blocked synthetic workload; no science, protected entry, worker, model, Docker or external attestation.", nil, sources, ""}
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
				recoveryKilledKeeper(t, base, &record)
				return
			}
			timeout := 30
			if scenario == "timeout" {
				timeout = 3
			}
			run := recoverySetup(t, base, timeout)
			defer run.close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := run.coordinator.Handle(ctx, runRequest(run.registered)); done <- err }()
			helper, pipeline := recoveryReady(t, os.Getpid(), run.config)
			defer helper.close()
			defer pipeline.close()
			defer func() {
				if !recoveryGone(helper) {
					helper.signal(syscall.SIGKILL)
				}
			}()
			recoveryCheck(t, &record, "actual_capsule_workload_ready_caps_zero_nnp", true)
			recoveryFlockDenied(t, filepath.Join(base, "store"))
			recoveryCheck(t, &record, "live_lifetime_flock_denies_restart", true)
			run.store.mu.Lock()
			before := run.store.data.Records[run.registered.LeaseID]
			run.store.mu.Unlock()
			recoveryCheck(t, &record, "executing_full_reservation_before_termination", before.State == "executing" && before.Charge == run.store.data.Policy.ExportBytes+run.store.data.Policy.PublicationHeadroom && before.ProofSHA256 == "")
			switch scenario {
			case "cancel":
				cancel()
			case "pid1_kill":
				recoveryCheck(t, &record, "pidfd_kill_verified_pid1", helper.signal(syscall.SIGKILL) == nil)
			}
			select {
			case err := <-done:
				recoveryCheck(t, &record, "coordinator_returned_after_authoritative_wait", err == nil)
			case <-time.After(10 * time.Second):
				t.Fatal("NativeProvider did not finish")
			}
			recoveryWaitGone(t, helper, pipeline)
			recoveryCheck(t, &record, "captured_tasks_disappeared", true)
			run.store.mu.Lock()
			entry := run.store.data.Records[run.registered.LeaseID]
			run.store.mu.Unlock()
			recoveryCheck(t, &record, "failed_execution_commit_has_real_quiescence_proof", entry.State == "committed" && hexID(entry.ProofSHA256, 64) && entry.Charge > 0)
			raw, err := run.coordinator.response(run.registered.LeaseID, false)
			recoveryCheck(t, &record, "failed_manifest_readable", err == nil)
			var response ExecutionResponse
			json.Unmarshal(raw, &response)
			recoveryCheck(t, &record, "failure_withheld_never_science_approval", response.Manifest != nil && response.Manifest.ExecutionStatus == "failed" && response.Manifest.ReleaseStatus == "withheld" && len(response.Manifest.Files) == 0)
			called := false
			canceled, stop := context.WithCancel(context.Background())
			stop()
			err = run.coordinator.Acknowledge(canceled, runRequest(run.registered), func() error { called = true; return nil })
			recoveryCheck(t, &record, "canceled_release_has_no_ack", err != nil && !called)
			recoveryCheck(t, &record, "native_provider_invoked_once", run.tracked.calls.Load() == 1)
			list, err := os.ReadDir(run.config.WorkspaceRoot)
			recoveryCheck(t, &record, "host_workspace_anchors_clean_after_wait", err == nil && len(list) == 0)
			charge := run.store.Snapshot().ChargedBytes
			run.close()
			reopened, err := Open(context.Background(), filepath.Join(base, "store"), NativeArtifactPolicy())
			recoveryCheck(t, &record, "failed_commit_reopens_consistently", err == nil)
			defer reopened.Close()
			recoveryCheck(t, &record, "retained_slot_charge_survive_restart", reopened.Snapshot().ChargedBytes == charge && reopened.Snapshot().RetainedOrReservedJobs == 1)
			registry, err := NewInputRegistry(reopened)
			recoveryCheck(t, &record, "fresh_registry_initializes_after_valid_failure_commit", err == nil)
			defer registry.Close()
			tracker := &recoveryTrackingProvider{native: run.provider}
			coordinator, err := NewCoordinator(reopened, registry, tracker)
			recoveryCheck(t, &record, "fresh_coordinator_initializes", err == nil)
			defer coordinator.Close()
			_, err = coordinator.Handle(context.Background(), runRequest(run.registered))
			recoveryCheck(t, &record, "old_run_pair_cannot_reexecute", err != nil && tracker.calls.Load() == 0)
		})
	}
	t.Log("private native lifecycle acceptance root:", evidence)
}

func TestNativeRecoveryKeeperProcess(t *testing.T) {
	if os.Getenv("BIOZERO_NATIVE_RECOVERY_CHILD") != "1" || os.Getenv("BIOZERO_RUN_NATIVE_RECOVERY_ACCEPTANCE") != "1" {
		t.Skip("internal keeper process")
	}
	base := os.Getenv("BIOZERO_NATIVE_RECOVERY_CHILD_DIR")
	if !filepath.IsAbs(base) {
		t.Fatal("child destination invalid")
	}
	run := recoverySetup(t, base, 30)
	defer run.close()
	registration := struct {
		Registered RegisteredExecution  `json:"registered"`
		Config     NativeProviderConfig `json:"config"`
	}{run.registered, run.config}
	if err := recoveryPrivateJSON(filepath.Join(base, "registration.json"), registration); err != nil {
		t.Fatal(err)
	}
	_, err := run.coordinator.Handle(context.Background(), runRequest(run.registered))
	if err != nil {
		t.Fatal(err)
	}
	// The parent must kill this real keeper before its pinned workload finishes.
	t.Fatal("keeper workload unexpectedly completed")
}

func recoverySubreaper(t *testing.T) func() {
	t.Helper()
	var old int32
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 37, uintptr(unsafe.Pointer(&old)), 0, 0, 0, 0)
	if errno != 0 {
		t.Fatal("subreaper read unavailable", errno)
	}
	_, _, errno = syscall.Syscall6(syscall.SYS_PRCTL, 36, 1, 0, 0, 0, 0)
	if errno != 0 {
		t.Fatal("subreaper unavailable", errno)
	}
	return func() { syscall.Syscall6(syscall.SYS_PRCTL, 36, uintptr(old), 0, 0, 0, 0) }
}
func recoveryKilledKeeper(t *testing.T, base string, record *recoveryEvidence) {
	t.Helper()
	restore := recoverySubreaper(t)
	defer restore()
	log, err := os.OpenFile(filepath.Join(base, "keeper.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestNativeRecoveryKeeperProcess$", "-test.count=1", "-test.timeout=40s")
	command.Env = []string{"PATH=/usr/bin", "LANG=C", "LC_ALL=C", "BIOZERO_RUN_NATIVE_RECOVERY_ACCEPTANCE=1", "BIOZERO_NATIVE_RECOVERY_CHILD=1", "BIOZERO_NATIVE_RECOVERY_CHILD_DIR=" + base}
	command.Stdout = log
	command.Stderr = log
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	defer func() { command.Process.Kill() }()
	var info struct {
		Registered RegisteredExecution  `json:"registered"`
		Config     NativeProviderConfig `json:"config"`
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		raw, readErr := os.ReadFile(filepath.Join(base, "registration.json"))
		if readErr == nil && json.Unmarshal(raw, &info) == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	recoveryCheck(t, record, "keeper_created_durable_registration", hexID(info.Registered.LeaseID, 32))
	helper, pipeline := recoveryReady(t, command.Process.Pid, info.Config)
	defer helper.close()
	defer pipeline.close()
	defer func() {
		if !recoveryGone(helper) {
			helper.signal(syscall.SIGKILL)
		}
	}()
	recoveryCheck(t, record, "keeper_capsule_ready_before_death", true)
	recoveryFlockDenied(t, filepath.Join(base, "store"))
	recoveryCheck(t, record, "restart_denied_while_keeper_capsule_alive", true)
	raw, err := os.ReadFile(filepath.Join(base, "store", "ledger.json"))
	recoveryCheck(t, record, "pending_ledger_readable_before_death", err == nil)
	var saved ledger
	err = strictJSON(raw, &saved)
	recoveryCheck(t, record, "pending_ledger_strict_before_death", err == nil)
	before := saved.Records[info.Registered.LeaseID]
	recoveryCheck(t, record, "pending_execution_has_full_charge_and_no_proof", before.State == "executing" && before.ProofSHA256 == "" && before.ManifestSHA256 == "" && before.Charge == saved.Policy.ExportBytes+saved.Policy.PublicationHeadroom)
	recoveryCheck(t, record, "kill_only_created_keeper", command.Process.Kill() == nil)
	// Try restart before observing keeper/capsule cleanup. A still-held flock
	// or unhealthy durable pending journal must fence admission immediately.
	early, earlyErr := Open(context.Background(), filepath.Join(base, "store"), NativeArtifactPolicy())
	if earlyErr != nil {
		record.ImmediateRestart = "lifetime_flock_locked"
		recoveryCheck(t, record, "immediate_restart_denied_before_observed_cleanup", earlyErr.Error() == "artifact_instance_locked")
	} else {
		snapshot := early.Snapshot()
		early.Close()
		record.ImmediateRestart = "durable_pending_unhealthy"
		recoveryCheck(t, record, "immediate_restart_denied_before_observed_cleanup", !snapshot.Healthy && snapshot.RetainedOrReservedJobs == 1 && snapshot.ChargedBytes == storeHeaderReserve+before.Charge)
	}
	select {
	case err := <-finished:
		var exit *exec.ExitError
		recoveryCheck(t, record, "keeper_exit_is_sigkill", errors.As(err, &exit) && exit.Sys().(syscall.WaitStatus).Signaled() && exit.Sys().(syscall.WaitStatus).Signal() == syscall.SIGKILL)
	case <-time.After(6 * time.Second):
		t.Fatal("keeper did not terminate")
	}
	// As a temporary subreaper, reap only the captured orphan PID1. Its exit is
	// cleanup observation, never a substitute for the missing durable proof.
	reapDeadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(reapDeadline) {
		var status syscall.WaitStatus
		pid, waitErr := syscall.Wait4(helper.pid, &status, syscall.WNOHANG, nil)
		if pid == helper.pid || waitErr == syscall.ECHILD && recoveryGone(helper) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	recoveryWaitGone(t, helper, pipeline)
	recoveryCheck(t, record, "pdeathsig_namespace_processes_disappear", true)
	reopened, err := Open(context.Background(), filepath.Join(base, "store"), NativeArtifactPolicy())
	recoveryCheck(t, record, "pending_store_reopens_only_unhealthy", err == nil)
	defer reopened.Close()
	snapshot := reopened.Snapshot()
	recoveryCheck(t, record, "restart_keeps_full_reservation_and_slot", !snapshot.Healthy && snapshot.RetainedOrReservedJobs == 1 && snapshot.ChargedBytes == storeHeaderReserve+before.Charge)
	reopened.mu.Lock()
	current := reopened.data.Records[info.Registered.LeaseID]
	reopened.mu.Unlock()
	recoveryCheck(t, record, "no_manifest_or_quiescence_proof_after_keeper_loss", current.State == "executing" && current.ProofSHA256 == "" && current.ManifestSHA256 == "")
	_, err = reopened.Reserve("0000000000000002", digest([]byte("other")))
	recoveryCheck(t, record, "new_admission_refused_without_recovery", err != nil)
	recoveryCheck(t, record, "pending_begin_refused_without_reexecution", reopened.Begin(info.Registered.LeaseID) != nil)
	called := false
	err = reopened.Acknowledge(info.Registered.LeaseID, func() error { called = true; return nil })
	recoveryCheck(t, record, "pending_run_cannot_ack", err != nil && !called)
	_, err = NewInputRegistry(reopened)
	recoveryCheck(t, record, "lost_registry_cannot_recreate_authority", err != nil)
	p, err := NewNativeProvider(context.Background(), info.Config)
	if p != nil {
		p.Close()
	}
	recoveryCheck(t, record, "unreconciled_workspace_not_silently_adopted", err != nil && err.Error() == "artifact_native_workspace_history_unknown")
	after, err := os.ReadFile(filepath.Join(base, "store", "ledger.json"))
	recoveryCheck(t, record, "restart_refusals_do_not_rewrite_pending_ledger", err == nil && digest(after) == digest(raw))
}

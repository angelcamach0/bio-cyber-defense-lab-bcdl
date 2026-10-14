//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Retaining the coordinator keeps Store/flock/provider/registry references alive
// after an uncertain failure. Persistent fixture roots are never auto-deleted.
var containerQuotaCustody struct {
	sync.Mutex
	coordinators []*Coordinator
}

const containerQuotaImageID = "sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d"

// This pinned synthetic stats fixture records actual kernel observations. It
// deletes only its own partial byte file or last two inode files to leave room
// for the failed execution receipt. No historical or host artifact is deleted.
const containerQuotaPipeline = `import argparse, errno, json, os, resource

parser = argparse.ArgumentParser()
parser.add_argument('input')
parser.add_argument('--out-dir', required=True)
parser.add_argument('--mode', required=True)
parser.add_argument('--reference')
args = parser.parse_args()
profile = '__PROFILE__'
assert args.mode == 'stats' and args.out_dir == '/workspace'
assert os.getcwd() == '/workspace'

def snapshot():
    value = os.statvfs('/workspace')
    return {'capacity_bytes': value.f_blocks * value.f_frsize,
            'free_bytes': value.f_bavail * value.f_frsize,
            'inode_units': value.f_files, 'free_inode_units': value.f_favail}

observed = {'profile': profile, 'before': snapshot(), 'errno': None,
            'saw_efbig': False, 'created_files': 0, 'deleted_for_receipt': [],
            'file_bytes': [], 'fsize': list(resource.getrlimit(resource.RLIMIT_FSIZE)),
            'cwd': os.getcwd(), 'cleanup_scope': 'only newly created fixture files'}
created = []
try:
    if profile == 'bytes':
        block = b'x' * (1 << 20)
        for index in range(3):
            name = 'byte-grow-%03d' % index
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(name)
            try:
                for step in range(63):
                    position = 0
                    while position < len(block):
                        count = os.write(fd, block[position:])
                        if count <= 0: raise RuntimeError('zero byte write')
                        position += count
            finally:
                os.close(fd)
    elif profile == 'inodes':
        for index in range(8192):
            name = 'inode-grow-%05d' % index
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(name)
            os.close(fd)
    else:
        raise RuntimeError('unknown fixed quota profile')
except OSError as error:
    observed['errno'] = error.errno
    observed['saw_efbig'] = error.errno == errno.EFBIG
    observed['at_limit'] = snapshot()
    observed['created_files'] = len(created)
    observed['file_bytes'] = [os.stat(name).st_size for name in created] if profile == 'bytes' else []
    if error.errno == errno.ENOSPC:
        if profile == 'bytes' and len(created) == 3:
            partial = created[-1]
            if os.stat(partial).st_size < 63 << 20:
                os.unlink(partial)
                observed['deleted_for_receipt'].append(partial)
        elif profile == 'inodes':
            for name in created[-2:]:
                os.unlink(name)
                observed['deleted_for_receipt'].append(name)
observed['after_private_cleanup'] = snapshot()
print(json.dumps({'schema_version': 1, 'mode': 'stats', 'pipeline_status': 'failed',
                  'outputs': {}, 'quota_observation': observed}, separators=(',', ':')))
raise SystemExit(1)
`

type containerQuotaSnapshot struct {
	CapacityBytes  int64 `json:"capacity_bytes"`
	FreeBytes      int64 `json:"free_bytes"`
	InodeUnits     int64 `json:"inode_units"`
	FreeInodeUnits int64 `json:"free_inode_units"`
}

type containerQuotaObservation struct {
	Profile             string                 `json:"profile"`
	Before              containerQuotaSnapshot `json:"before"`
	AtLimit             containerQuotaSnapshot `json:"at_limit"`
	AfterPrivateCleanup containerQuotaSnapshot `json:"after_private_cleanup"`
	Errno               int                    `json:"errno"`
	SawEFBIG            bool                   `json:"saw_efbig"`
	CreatedFiles        int64                  `json:"created_files"`
	DeletedForReceipt   []string               `json:"deleted_for_receipt"`
	FileBytes           []int64                `json:"file_bytes"`
	FSIZE               []int64                `json:"fsize"`
	Cwd                 string                 `json:"cwd"`
	CleanupScope        string                 `json:"cleanup_scope"`
}

type containerQuotaReceipt struct {
	SchemaVersion      int    `json:"schema_version"`
	CapsuleKind        string `json:"capsule_kind"`
	InputSHA256        string `json:"input_sha256"`
	InputBytes         int64  `json:"input_bytes"`
	NativeHelperSHA256 string `json:"native_helper_sha256"`
	SourcePins         map[string]struct {
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	} `json:"source_pins"`
	Mode         string          `json:"mode"`
	Evaluation   json.RawMessage `json:"evaluation"`
	CapsuleState struct {
		PID         int64    `json:"pid"`
		UID         int64    `json:"uid"`
		GID         int64    `json:"gid"`
		EUID        int64    `json:"euid"`
		EGID        int64    `json:"egid"`
		CapInh      string   `json:"CapInh"`
		CapPrm      string   `json:"CapPrm"`
		CapEff      string   `json:"CapEff"`
		CapBnd      string   `json:"CapBnd"`
		CapAmb      string   `json:"CapAmb"`
		NoNewPrivs  string   `json:"NoNewPrivs"`
		Interfaces  []string `json:"interfaces"`
		RLIMITFSIZE []int64  `json:"rlimit_fsize"`
		RootStatFS  struct {
			Flags int64 `json:"flags"`
		} `json:"root_statfs"`
		WorkspaceStatFS struct {
			Magic         int64 `json:"filesystem_magic"`
			CapacityBytes int64 `json:"capacity_bytes"`
			InodeUnits    int64 `json:"inode_units"`
		} `json:"workspace_statfs"`
		Cgroup map[string]string `json:"cgroup"`
	} `json:"capsule_state"`
	Pipeline struct {
		Returncode int `json:"returncode"`
		Payload    struct {
			SchemaVersion int                       `json:"schema_version"`
			Mode          string                    `json:"mode"`
			Status        string                    `json:"pipeline_status"`
			Observation   containerQuotaObservation `json:"quota_observation"`
		} `json:"payload"`
	} `json:"pipeline"`
}

func containerQuotaWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal("private quota evidence write failed", err, closeErr)
	}
}

func containerQuotaRead(t *testing.T, path string, limit int64) []byte {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > limit {
		t.Fatal("unsafe quota evidence", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || int64(len(raw)) != info.Size() {
		t.Fatal("quota evidence read changed", err)
	}
	return raw
}

func containerQuotaRun(t *testing.T, profile string) {
	t.Helper()
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	base := os.Getenv("BIOZERO_CONTAINER_QUOTA_EVIDENCE_DIR")
	if base == "" {
		base = filepath.Join(repo, ".biozero", "container-quota-"+profile+"-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	} else {
		base = filepath.Join(base, profile)
	}
	if !filepath.IsAbs(base) || os.Mkdir(base, 0700) != nil {
		t.Fatal("quota evidence root must be new and absolute; parent must exist")
	}
	assets := filepath.Join(base, "assets")
	if err := os.Mkdir(assets, 0700); err != nil {
		t.Fatal(err)
	}
	asset := func(path string) PinnedAsset {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return PinnedAsset{Path: path, SHA256: digest(data)}
	}
	pipeline := []byte(strings.ReplaceAll(containerQuotaPipeline, "__PROFILE__", profile))
	pipelinePath := filepath.Join(assets, "pipeline.py")
	containerQuotaWrite(t, pipelinePath, pipeline)
	budgetRaw, err := os.ReadFile(filepath.Join(repo, "biozero/bio/pipeline/resource_budget.py"))
	if err != nil {
		t.Fatal(err)
	}
	containerQuotaWrite(t, filepath.Join(assets, "resource_budget.py"), budgetRaw)
	cfg := ContainerProviderConfig{WorkspaceRoot: filepath.Join(base, "controls"),
		DockerCommand: []string{"/usr/bin/sudo", "-n", "/usr/bin/docker", "--host=unix:///var/run/docker.sock"},
		ImageID:       containerQuotaImageID, Mode: "stats", TimeoutSeconds: 60,
		Helper:       asset(filepath.Join(repo, "biozero/services/artifact-executor/capsule/container_capsule.py")),
		NativeHelper: asset(filepath.Join(repo, "biozero/services/artifact-executor/capsule/native_capsule.py")),
		Pipeline:     asset(pipelinePath), ResourceBudgetSHA256: digest(budgetRaw)}
	preflight, _ := jsonBytes(map[string]any{"schema_version": 1, "phase": "prepared_not_executed", "profile": profile,
		"image_id": cfg.ImageID, "pipeline_sha256": cfg.Pipeline.SHA256, "resource_budget_sha256": cfg.ResourceBudgetSHA256,
		"container_helper_sha256": cfg.Helper.SHA256, "native_helper_sha256": cfg.NativeHelper.SHA256})
	containerQuotaWrite(t, filepath.Join(base, "prepared.json"), preflight)
	provider, err := NewContainerProvider(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var store *Store
	var registry *InputRegistry
	var coordinator *Coordinator
	var observed *containerAcceptanceObserver
	t.Cleanup(func() {
		if coordinator != nil {
			coordinator.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			err := coordinator.Wait(ctx)
			cancel()
			observed.mu.Lock()
			completion := observed.completion
			observed.mu.Unlock()
			if err != nil || !completion.Quiescent {
				containerQuotaCustody.Lock()
				containerQuotaCustody.coordinators = append(containerQuotaCustody.coordinators, coordinator)
				containerQuotaCustody.Unlock()
				t.Error("quota fixture uncertain; persistent evidence and keeper custody retained")
				return
			}
		}
		if registry != nil {
			registry.Close()
		}
		provider.Close()
		if store != nil {
			store.Close()
		}
	})
	storeRoot := filepath.Join(base, "store")
	store, err = Open(context.Background(), storeRoot, NativeArtifactPolicy())
	if err != nil {
		t.Fatal(err)
	}
	registry, err = NewInputRegistry(store)
	if err != nil {
		t.Fatal(err)
	}
	observed = &containerAcceptanceObserver{provider: provider}
	coordinator, err = NewCoordinator(store, registry, observed)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("@synthetic-quota-" + profile + "\nACGT\n+\nIIII\n")
	inputPath := filepath.Join(base, "verified.fastq")
	containerQuotaWrite(t, inputPath, plaintext)
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	job := "0000000000000011"
	if profile == "inodes" {
		job = "0000000000000012"
	}
	originalSHA := digest([]byte("synthetic original quota upload placeholder " + profile))
	registered, err := coordinator.RegisterInput(context.Background(), job, originalSHA, digest(plaintext), int64(len(plaintext)), input)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	started := time.Now()
	responseRaw, err := coordinator.Handle(ctx, runRequest(registered))
	var response ExecutionResponse
	if err != nil || json.Unmarshal(responseRaw, &response) != nil || response.SchemaVersion != 1 || response.LeaseID != registered.LeaseID || response.State != "committed" || response.Manifest == nil {
		t.Fatal("quota failure did not retain committed custody", err)
	}
	observed.mu.Lock()
	completion := observed.completion
	observed.mu.Unlock()
	if completion.Err != nil || !completion.Quiescent {
		t.Fatal("Docker wait/inspect completion not authoritative", completion.Err)
	}
	m := response.Manifest
	if m.ExecutionStatus != "failed" || m.ReleaseStatus != "withheld" || m.ErrorCode != "capsule_pipeline_failed" || m.ObservedSHA256 != "" || m.EvaluatedSHA256 != "" || len(m.Files) != 1 || m.InputSHA256 != originalSHA {
		t.Fatal("quota failure advertised approval or lost original digest")
	}
	metadata, exists := m.Files["execution_receipt"]
	if !exists {
		t.Fatal("quota failure lost private execution receipt")
	}
	object := filepath.Join(storeRoot, "objects", registered.LeaseID)
	receiptRaw := containerQuotaRead(t, filepath.Join(object, "execution_receipt"), 16<<20)
	var receipt containerQuotaReceipt
	if digest(receiptRaw) != metadata.SHA256 || int64(len(receiptRaw)) != metadata.Bytes || json.Unmarshal(receiptRaw, &receipt) != nil {
		t.Fatal("quota receipt bytes/hash/type mismatch")
	}
	if receipt.SchemaVersion != 1 || receipt.CapsuleKind != "docker" || receipt.Mode != "stats" || receipt.InputSHA256 != digest(plaintext) || receipt.InputBytes != int64(len(plaintext)) || receipt.NativeHelperSHA256 != cfg.NativeHelper.SHA256 || !bytes.Equal(bytes.TrimSpace(receipt.Evaluation), []byte("null")) || receipt.Pipeline.Returncode != 1 || receipt.Pipeline.Payload.SchemaVersion != 1 || receipt.Pipeline.Payload.Mode != "stats" || receipt.Pipeline.Payload.Status != "failed" {
		t.Fatal("quota private execution context mismatch")
	}
	if len(receipt.SourcePins) != 2 || receipt.SourcePins["pipeline"].SHA256 != cfg.Pipeline.SHA256 || receipt.SourcePins["resource_budget"].SHA256 != cfg.ResourceBudgetSHA256 {
		t.Fatal("quota fixture or real resource module source pins changed")
	}
	state := receipt.CapsuleState
	zero := func(value string) bool { return value != "" && strings.Trim(value, "0") == "" }
	if state.PID != 1 || state.UID != 1000 || state.GID != 1000 || state.EUID != 1000 || state.EGID != 1000 || !zero(state.CapEff) || !zero(state.CapPrm) || !zero(state.CapInh) || !zero(state.CapBnd) || !zero(state.CapAmb) || state.NoNewPrivs != "1" || !equalStrings(state.Interfaces, []string{"lo"}) || len(state.RLIMITFSIZE) != 2 || state.RLIMITFSIZE[0] != 64<<20 || state.RLIMITFSIZE[1] != 64<<20 || state.RootStatFS.Flags&1 == 0 || state.WorkspaceStatFS.Magic != 0x01021994 || state.WorkspaceStatFS.CapacityBytes != 128<<20 || state.WorkspaceStatFS.InodeUnits != 4096 {
		t.Fatal("quota kernel state did not show the configured Docker boundary")
	}
	cpuParts := strings.Fields(state.Cgroup["cpu.max"])
	quota, period := int64(0), int64(0)
	if len(cpuParts) == 2 {
		quota, _ = strconv.ParseInt(cpuParts[0], 10, 64)
		period, _ = strconv.ParseInt(cpuParts[1], 10, 64)
	}
	if state.Cgroup["membership"] != "0::/" || state.Cgroup["memory.max"] != "536870912" || state.Cgroup["memory.swap.max"] != "0" || state.Cgroup["pids.max"] != "128" || quota <= 0 || quota != period {
		t.Fatal("quota fixture has unexpected actual cgroup limits")
	}
	q := receipt.Pipeline.Payload.Observation
	if q.Profile != profile || q.Errno != 28 || q.SawEFBIG || q.Cwd != "/workspace" || q.CleanupScope != "only newly created fixture files" || len(q.FSIZE) != 2 || q.FSIZE[0] != 64<<20 || q.FSIZE[1] != 64<<20 {
		t.Fatal("quota exhaustion was not exact ENOSPC under private FSIZE/workspace")
	}
	for _, snapshot := range []containerQuotaSnapshot{q.Before, q.AtLimit, q.AfterPrivateCleanup} {
		if snapshot.CapacityBytes != 128<<20 || snapshot.InodeUnits != 4096 {
			t.Fatal("quota capacity changed during fixture")
		}
	}
	if profile == "bytes" {
		if q.CreatedFiles != 3 || len(q.FileBytes) != 3 || q.FileBytes[0] != 63<<20 || q.FileBytes[1] != 63<<20 || q.FileBytes[2] < 0 || q.FileBytes[2] >= 63<<20 || q.AtLimit.FreeBytes != 0 || q.AtLimit.FreeInodeUnits <= 0 || len(q.DeletedForReceipt) != 1 || q.DeletedForReceipt[0] != "byte-grow-002" || q.AfterPrivateCleanup.FreeBytes <= q.AtLimit.FreeBytes {
			t.Fatal("aggregate byte exhaustion/partial-only cleanup not demonstrated")
		}
	} else {
		if q.CreatedFiles <= 0 || q.CreatedFiles >= 8192 || len(q.FileBytes) != 0 || q.AtLimit.FreeInodeUnits != 0 || q.AtLimit.FreeBytes <= 0 || len(q.DeletedForReceipt) != 2 || q.AfterPrivateCleanup.FreeInodeUnits < 2 || q.AfterPrivateCleanup.FreeBytes <= 0 {
			t.Fatal("inode exhaustion while bytes remained/own-file cleanup not demonstrated")
		}
		for _, name := range q.DeletedForReceipt {
			if !strings.HasPrefix(name, "inode-grow-") {
				t.Fatal("inode cleanup touched a nonfixture name")
			}
		}
	}
	manifestRaw := containerQuotaRead(t, filepath.Join(object, "manifest.json"), manifestLimit)
	proofRaw := containerQuotaRead(t, filepath.Join(object, "proof.json"), proofLimit)
	historyRaw := containerQuotaRead(t, filepath.Join(storeRoot, "ledger.json"), ledgerLimit)
	var proof Proof
	var history ledger
	if strictJSON(proofRaw, &proof) != nil || strictJSON(historyRaw, &history) != nil || digest(manifestRaw) != response.ManifestSHA256 || !proof.CapsuleWaitFinished || !proof.ExportAuthorityClosed || proof.ManifestSHA256 != response.ManifestSHA256 || proof.StoreID != m.StoreID || proof.PolicySHA256 != m.PolicySHA256 || proof.LeaseID != registered.LeaseID || proof.JobID != job || proof.InputSHA256 != originalSHA {
		t.Fatal("quota custody lacks post-Wait bound proof/manifest")
	}
	entry, exists := history.Records[registered.LeaseID]
	if !exists || len(history.Records) != 1 || entry.State != "committed" || entry.Charge <= metadata.Bytes || entry.ManifestSHA256 != digest(manifestRaw) || entry.ProofSHA256 != digest(proofRaw) || len(entry.Files) != 1 || entry.InputSHA256 != originalSHA {
		t.Fatal("quota terminal slot/charge/receipt custody not retained")
	}
	acked := false
	if err := coordinator.Acknowledge(ctx, runRequest(registered), func() error { acked = true; return nil }); err != nil || !acked {
		t.Fatal("failed/withheld storage ACK did not follow commitment", err)
	}
	afterACK := containerQuotaRead(t, filepath.Join(storeRoot, "ledger.json"), ledgerLimit)
	if !bytes.Equal(afterACK, historyRaw) {
		t.Fatal("failure ACK changed retained charge/history")
	}
	anchors, err := os.ReadDir(cfg.WorkspaceRoot)
	if err != nil || len(anchors) != 0 {
		t.Fatal("Docker quota run left host control anchors", err)
	}
	err = filepath.WalkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && (strings.HasPrefix(entry.Name(), "byte-grow-") || strings.HasPrefix(entry.Name(), "inode-grow-")) {
			return fail("quota_generated_file_escaped_to_host")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	inputAfter, err := os.ReadFile(inputPath)
	if err != nil || !bytes.Equal(inputAfter, plaintext) {
		t.Fatal("quota run changed original plaintext fixture", err)
	}
	acceptance, err := jsonBytes(map[string]any{"schema_version": 1, "status": "passed", "profile": profile,
		"observed_utc": time.Now().UTC().Format(time.RFC3339Nano), "seconds": time.Since(started).Seconds(),
		"image_id": cfg.ImageID, "source_sha256": map[string]string{"container_helper": cfg.Helper.SHA256,
			"native_helper": cfg.NativeHelper.SHA256, "pipeline_fixture": cfg.Pipeline.SHA256,
			"resource_budget": cfg.ResourceBudgetSHA256, "test": asset(filepath.Join(repo, "biozero/services/artifact-executor/container_quota_acceptance_linux_test.go")).SHA256},
		"kernel_observation": q, "receipt_sha256": digest(receiptRaw), "manifest_sha256": digest(manifestRaw),
		"proof_sha256": digest(proofRaw), "ledger_sha256": digest(historyRaw), "retained_charge": entry.Charge,
		"execution_status": m.ExecutionStatus, "release_status": m.ReleaseStatus, "export_count": len(m.Files),
		"docker_wait_inspect_finished": completion.Quiescent, "host_generated_quota_files": 0,
		"private_only": true, "model_external_network_image_build_executed": false,
		"ack_scope": "local failed-custody callback; no scientific approval or Unix/TLS integration claim"})
	if err != nil {
		t.Fatal(err)
	}
	containerQuotaWrite(t, filepath.Join(base, "acceptance.json"), acceptance)
	t.Logf("actual Docker %s ENOSPC: capacity=%d inode_units=%d created_files=%d; failed/withheld private receipt, positive retained charge and post-Wait proof; no model/external network/image build", profile, q.AtLimit.CapacityBytes, q.AtLimit.InodeUnits, q.CreatedFiles)
}

func TestContainerQuotaActualBytes(t *testing.T) {
	if os.Getenv("BIOZERO_RUN_CONTAINER_QUOTA_ACCEPTANCE") != "1" {
		t.Skip("opt-in real Docker aggregate byte quota acceptance")
	}
	containerQuotaRun(t, "bytes")
}

func TestContainerQuotaActualInodes(t *testing.T) {
	if os.Getenv("BIOZERO_RUN_CONTAINER_QUOTA_ACCEPTANCE") != "1" {
		t.Skip("opt-in real Docker inode-unit quota acceptance")
	}
	containerQuotaRun(t, "inodes")
}

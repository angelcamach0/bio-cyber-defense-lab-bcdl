//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func containerGolden() (*ContainerProvider, containerInspection) {
	p := &ContainerProvider{config: ContainerProviderConfig{ImageID: "sha256:" + strings.Repeat("a", 64), Helper: PinnedAsset{Path: "/private/helpers/container_capsule.py"}, NativeHelper: PinnedAsset{Path: "/private/helpers/native_capsule.py"}, Pipeline: PinnedAsset{Path: "/private/pipeline/pipeline.py"}, Reference: PinnedAsset{Path: "/private/reference.fa"}, Evaluator: PinnedAsset{Path: "/private/evaluator/evaluate_variants.py"}, Truth: PinnedAsset{Path: "/private/truth.vcf"}}}
	v := containerInspection{ID: strings.Repeat("b", 64), Image: p.config.ImageID, Nonce: strings.Repeat("c", 32), Store: strings.Repeat("d", 32), Lease: strings.Repeat("e", 32), Status: "created", User: "1000:1000", WorkingDir: "/workspace", Entrypoint: []string{"/usr/bin/python3.12"}, Cmd: []string{"-I", "-B", "-S", "/run/biozero/helpers/container_capsule.py"}, Env: containerEnvironment(), ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, NetworkMode: "none", IPCMode: "private", CgroupnsMode: "private", RestartPolicy: "no", Memory: 536870912, MemorySwap: 536870912, PidsLimit: 128, NanoCPUs: 1000000000, ShmSize: 65536, Mounts: p.mounts("/private/control"), Tmpfs: map[string]string{"/workspace": containerTmpfs}, Ulimits: []containerUlimit{{Name: "fsize", Soft: 64 << 20, Hard: 64 << 20}}}
	return p, v
}

func TestContainerInspectionRejectsAuthorityAndResourceChanges(t *testing.T) {
	p, v := containerGolden()
	if !p.validInspection(v, v.ID, v.Nonce, v.Store, v.Lease, "/private/control") {
		t.Fatal("fixed capsule inspection rejected")
	}
	mutations := map[string]func(*containerInspection){
		"image":         func(v *containerInspection) { v.Image = "sha256:" + strings.Repeat("f", 64) },
		"id":            func(v *containerInspection) { v.ID = strings.Repeat("f", 64) },
		"nonce":         func(v *containerInspection) { v.Nonce = strings.Repeat("f", 32) },
		"lease":         func(v *containerInspection) { v.Lease = strings.Repeat("f", 32) },
		"store":         func(v *containerInspection) { v.Store = strings.Repeat("f", 32) },
		"root_user":     func(v *containerInspection) { v.User = "0" },
		"entrypoint":    func(v *containerInspection) { v.Entrypoint = []string{"/bin/sh"} },
		"command":       func(v *containerInspection) { v.Cmd = []string{"-c", "true"} },
		"workdir":       func(v *containerInspection) { v.WorkingDir = "/tmp" },
		"root_rw":       func(v *containerInspection) { v.ReadonlyRootfs = false },
		"privileged":    func(v *containerInspection) { v.Privileged = true },
		"capadd":        func(v *containerInspection) { v.CapAddCount = 1 },
		"capdrop":       func(v *containerInspection) { v.CapDrop = []string{} },
		"nnp":           func(v *containerInspection) { v.SecurityOpt = []string{} },
		"host_network":  func(v *containerInspection) { v.NetworkMode = "host" },
		"host_pid":      func(v *containerInspection) { v.PIDMode = "host" },
		"host_ipc":      func(v *containerInspection) { v.IPCMode = "host" },
		"host_userns":   func(v *containerInspection) { v.UsernsMode = "host" },
		"cgroup":        func(v *containerInspection) { v.CgroupnsMode = "host" },
		"restart":       func(v *containerInspection) { v.RestartPolicy = "always" },
		"memory":        func(v *containerInspection) { v.Memory = 0 },
		"swap":          func(v *containerInspection) { v.MemorySwap = -1 },
		"pids":          func(v *containerInspection) { v.PidsLimit = 0 },
		"cpu":           func(v *containerInspection) { v.NanoCPUs = 0 },
		"devices":       func(v *containerInspection) { v.DeviceCount = 1 },
		"ports":         func(v *containerInspection) { v.PortCount = 1 },
		"shared_memory": func(v *containerInspection) { v.ShmSize = 64 << 20 },
		"image_volume":  func(v *containerInspection) { v.VolumeCount = 1 },
		"extra_env":     func(v *containerInspection) { v.Env = append(v.Env, "SECRET_TOKEN=synthetic-canary") },
		"duplicate_env": func(v *containerInspection) { v.Env[0] = v.Env[1] },
		"proxy":         func(v *containerInspection) { v.Env[4] = "HTTP_PROXY=http://unexpected.invalid" },
		"writable_bind": func(v *containerInspection) { v.Mounts[0].RW = true },
		"extra_bind": func(v *containerInspection) {
			v.Mounts = append(v.Mounts, containerMount{"/var/run/docker.sock", "/docker.sock", "bind", false, "rprivate"})
		},
		"missing_bind":      func(v *containerInspection) { v.Mounts = v.Mounts[1:] },
		"duplicate_bind":    func(v *containerInspection) { v.Mounts = append(v.Mounts, v.Mounts[0]) },
		"wrong_bind_source": func(v *containerInspection) { v.Mounts[0].Source = "/private/other.py" },
		"workspace":         func(v *containerInspection) { v.Tmpfs["/workspace"] = "size=1g" },
		"extra_tmpfs":       func(v *containerInspection) { v.Tmpfs["/scratch"] = "size=1g" },
		"missing_fsize":     func(v *containerInspection) { v.Ulimits = nil },
		"raised_fsize":      func(v *containerInspection) { v.Ulimits[0].Hard = 128 << 20 },
		"duplicate_fsize":   func(v *containerInspection) { v.Ulimits = append(v.Ulimits, v.Ulimits[0]) },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			_, candidate := containerGolden()
			change(&candidate)
			if p.validInspection(candidate, v.ID, v.Nonce, v.Store, v.Lease, "/private/control") {
				t.Fatal("changed capsule authority/resource accepted")
			}
		})
	}
}

func TestContainerCommandAndMountSourcesCannotSelectRemoteOrInjectCSV(t *testing.T) {
	for _, command := range [][]string{{"/usr/bin/docker", "--host=unix:///var/run/docker.sock"}, {"/usr/bin/sudo", "-n", "/usr/bin/docker", "--host=unix:///var/run/docker.sock"}} {
		if !validDockerCommand(command) {
			t.Fatal("trusted local command rejected")
		}
	}
	for _, command := range [][]string{{"/bin/sh", "-c", "docker"}, {"docker"}, {"/usr/bin/docker", "--host=tcp://remote.invalid:2375"}, {"/usr/bin/docker", "--context", "other"}, {"/usr/bin/sudo", "-S", "/usr/bin/docker", "--host=unix:///var/run/docker.sock"}} {
		if validDockerCommand(command) {
			t.Fatal("remote/arbitrary CLI selector accepted")
		}
	}
	if !safeContainerSource("/private/source with spaces.py") {
		t.Fatal("ordinary canonical source rejected")
	}
	for _, path := range []string{"", "relative.py", "/private/../source.py", "/private/source,readonly=false", "/private/\"source.py", "/private/a\x00b", "/private/a\nb"} {
		if safeContainerSource(path) {
			t.Fatal("unsafe mount CSV source accepted")
		}
	}
}

func TestContainerIntentIsPrivateDurableAndNeverClobbered(t *testing.T) {
	dir, err := openRoot(filepath.Join(t.TempDir(), "anchor"))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	intent := map[string]any{"schema_version": 1, "nonce": strings.Repeat("a", 32)}
	if err := writeContainerRecord(dir, "intent.json", intent); err != nil {
		t.Fatal(err)
	}
	before, err := boundedRead(context.Background(), dir, "intent.json", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeContainerRecord(dir, "intent.json", map[string]any{"wrong": true}); err == nil {
		t.Fatal("retained intent overwritten")
	}
	after, err := boundedRead(context.Background(), dir, "intent.json", 4096)
	if err != nil || string(before) != string(after) {
		t.Fatal("failed overwrite changed intent")
	}
}

type containerAcceptanceObserver struct {
	provider   *ContainerProvider
	mu         sync.Mutex
	completion ProviderCompletion
}

func (p *containerAcceptanceObserver) Execute(ctx context.Context, input *ScopedInput, exporter *Exporter) ProviderCompletion {
	done := p.provider.Execute(ctx, input, exporter)
	p.mu.Lock()
	p.completion = done
	p.mu.Unlock()
	return done
}

func TestContainerProviderActualSyntheticUnix(t *testing.T) {
	if os.Getenv("BIOZERO_RUN_CONTAINER_PROVIDER_ACCEPTANCE") != "1" {
		t.Skip("opt-in real Docker capsule, Unix channel and synthetic pipeline")
	}
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	base := os.Getenv("BIOZERO_CONTAINER_PROVIDER_EVIDENCE_DIR")
	if base == "" {
		base = filepath.Join(repo, ".biozero", "container-provider-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	}
	if !filepath.IsAbs(base) || os.Mkdir(base, 0700) != nil {
		t.Fatal("container evidence directory must be new and absolute")
	}
	asset := func(path string) PinnedAsset {
		path = filepath.Join(repo, path)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return PinnedAsset{path, digest(data)}
	}
	cfg := ContainerProviderConfig{WorkspaceRoot: filepath.Join(base, "controls"), DockerCommand: []string{"/usr/bin/sudo", "-n", "/usr/bin/docker", "--host=unix:///var/run/docker.sock"}, ImageID: "sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d", Mode: "variants", Helper: asset("biozero/services/artifact-executor/capsule/container_capsule.py"), NativeHelper: asset("biozero/services/artifact-executor/capsule/native_capsule.py"), Pipeline: asset("biozero/bio/pipeline/pipeline.py"), ResourceBudgetSHA256: asset("biozero/bio/pipeline/resource_budget.py").SHA256, Reference: asset("biozero/bio/fixtures/variant-smoke/reference.fa"), Evaluator: asset("biozero/bio/benchmarks/evaluate_variants.py"), Truth: asset("biozero/bio/fixtures/variant-smoke/expected.vcf"), TimeoutSeconds: 120}
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
		provider.Close()
		store.Close()
		t.Fatal(err)
	}
	observed := &containerAcceptanceObserver{provider: provider}
	coordinator, err := NewCoordinator(store, registry, observed)
	if err != nil {
		registry.Close()
		provider.Close()
		store.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		coordinator.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		if coordinator.Wait(ctx) != nil {
			t.Error("container coordinator still pending; private evidence retained")
			return
		}
		registry.Close()
		provider.Close()
		store.Close()
	})
	plaintext, err := os.ReadFile(filepath.Join(repo, "biozero/bio/fixtures/variant-smoke/reads.fastq"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "verified.fastq")
	if err := os.WriteFile(path, plaintext, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	registered, err := coordinator.RegisterInput(context.Background(), "0000000000000003", digest([]byte("synthetic encrypted upload placeholder")), digest(plaintext), int64(len(plaintext)), input)
	if err != nil {
		t.Fatal(err)
	}
	audit := &nativeWireAudit{Coordinator: coordinator, storeRoot: filepath.Join(base, "store")}
	_, socket := unixTestStart(t, UnixServerConfig{SocketPath: filepath.Join(base, "channel", "keeper.sock")}, audit)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	raw, err := CallUnix(ctx, socket, runRequest(registered))
	var response ExecutionResponse
	if err != nil || json.Unmarshal(raw, &response) != nil || response.Manifest == nil || response.Manifest.ExecutionStatus != "succeeded" || response.Manifest.ReleaseStatus != "evaluated_passed" {
		observed.mu.Lock()
		completion := observed.completion
		observed.mu.Unlock()
		t.Fatalf("actual container did not pass: transport=%v provider=%v quiescent=%v", err, completion.Err, completion.Quiescent)
	}
	m := response.Manifest
	if len(m.Files) != 4 || m.ObservedSHA256 != m.EvaluatedSHA256 || m.ObservedSHA256 != m.Files["normalized_vcf"].SHA256 || audit.runWrites.Load() != 1 {
		t.Fatal("container exact VCF/export/commit-before-write mismatch")
	}
	receiptRaw, err := os.ReadFile(filepath.Join(base, "store", "objects", registered.LeaseID, "execution_receipt"))
	if err != nil || digest(receiptRaw) != m.Files["execution_receipt"].SHA256 {
		t.Fatal("container receipt custody mismatch", err)
	}
	var receipt struct {
		Evaluation struct {
			Returncode int `json:"returncode"`
			Payload    struct {
				TP        int     `json:"tp"`
				FP        int     `json:"fp"`
				FN        int     `json:"fn"`
				Status    string  `json:"evaluation_status"`
				Precision float64 `json:"precision"`
				Recall    float64 `json:"recall"`
			} `json:"payload"`
		} `json:"evaluation"`
	}
	if json.Unmarshal(receiptRaw, &receipt) != nil || receipt.Evaluation.Returncode != 0 || receipt.Evaluation.Payload.TP != 3 || receipt.Evaluation.Payload.FP != 0 || receipt.Evaluation.Payload.FN != 0 || receipt.Evaluation.Payload.Status != "passed" || receipt.Evaluation.Payload.Precision != 1 || receipt.Evaluation.Payload.Recall != 1 {
		t.Fatal("actual container evaluator did not demonstrate exact three-SNP science")
	}
	anchors, err := os.ReadDir(cfg.WorkspaceRoot)
	if err != nil || len(anchors) != 0 {
		t.Fatal("container metadata anchors remain after proved cleanup", err)
	}
	t.Log("actual pinned Docker capsule, readonly FD handoff, wait/inspect then export, exact three-SNP receipt and commit-before-Unix-reply; worker TLS/crypto integration remains pending")
}

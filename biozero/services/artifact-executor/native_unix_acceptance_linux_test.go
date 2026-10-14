//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type nativeWireProvider struct {
	provider  *NativeProvider
	calls     atomic.Int32
	quiescent atomic.Bool
}

func (p *nativeWireProvider) Execute(ctx context.Context, input *ScopedInput, exporter *Exporter) ProviderCompletion {
	p.calls.Add(1)
	completion := p.provider.Execute(ctx, input, exporter)
	p.quiescent.Store(completion.Quiescent)
	return completion
}

// This observer wraps the actual socket-write callback, not a simulated ACK.
// The files are new private acceptance fixtures; no production history is changed.
// Failed acceptance keeps uncertain keeper custody until process exit; durable
// pending history and the fixture remain for operator review.
var nativeWireUncertainCustody struct {
	sync.Mutex
	coordinators []*Coordinator
}

type nativeWireAudit struct {
	*Coordinator
	storeRoot string
	runWrites atomic.Int32
}

func (a *nativeWireAudit) Acknowledge(ctx context.Context, q Request, write func() error) error {
	return a.Coordinator.Acknowledge(ctx, q, func() error {
		if q.Operation == "run" {
			data, err := os.ReadFile(filepath.Join(a.storeRoot, "ledger.json"))
			var history ledger
			if err != nil || strictJSON(data, &history) != nil {
				return fail("acceptance_ledger_unreadable_at_ack")
			}
			record, present := history.Records[q.LeaseID]
			if !present || record.State != "committed" || record.Charge <= 0 || len(record.Files) != 4 {
				return fail("acceptance_storage_not_committed_at_ack")
			}
			root := filepath.Join(a.storeRoot, "objects", q.LeaseID)
			manifest, err := os.ReadFile(filepath.Join(root, "manifest.json"))
			if err != nil || digest(manifest) != record.ManifestSHA256 {
				return fail("acceptance_manifest_not_retained_at_ack")
			}
			proofBytes, err := os.ReadFile(filepath.Join(root, "proof.json"))
			var proof Proof
			if err != nil || digest(proofBytes) != record.ProofSHA256 || strictJSON(proofBytes, &proof) != nil || !proof.CapsuleWaitFinished || !proof.ExportAuthorityClosed {
				return fail("acceptance_quiescence_not_retained_at_ack")
			}
			a.runWrites.Add(1)
		}
		return write()
	})
}

func TestNativeProviderActualUnixCommitBeforeReplyAndReplay(t *testing.T) {
	if os.Getenv("BIOZERO_RUN_NATIVE_UNIX_ACCEPTANCE") != "1" {
		t.Skip("opt-in actual native capsule and Unix client acceptance")
	}
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	asset := func(relative string) PinnedAsset {
		path := filepath.Join(repo, relative)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return PinnedAsset{Path: path, SHA256: digest(data)}
	}
	base, err := os.MkdirTemp("", "biozero-native-unix-")
	if err != nil {
		t.Fatal(err)
	} // Opt-in evidence is not automatically deleted.
	if destination := os.Getenv("BIOZERO_NATIVE_UNIX_EVIDENCE_DIR"); destination != "" {
		if !filepath.IsAbs(destination) || os.Mkdir(destination, 0700) != nil {
			t.Fatal("Unix evidence directory must be new and absolute")
		}
		base = destination
	}
	python, err := filepath.EvalSymlinks("/usr/bin/python3")
	if err != nil {
		t.Fatal(err)
	}
	config := NativeProviderConfig{WorkspaceRoot: filepath.Join(base, "workspaces"), PythonPath: python,
		ToolPath: "/tmp/biozero-bio-tools-locked/bin:/usr/bin", Mode: "variants", TimeoutSeconds: 120,
		Helper:   asset("biozero/services/artifact-executor/capsule/native_capsule.py"),
		Pipeline: asset("biozero/bio/pipeline/pipeline.py"), ResourceBudgetSHA256: asset("biozero/bio/pipeline/resource_budget.py").SHA256,
		Reference: asset("biozero/bio/fixtures/variant-smoke/reference.fa"),
		Evaluator: asset("biozero/bio/benchmarks/evaluate_variants.py"), Truth: asset("biozero/bio/fixtures/variant-smoke/expected.vcf")}
	provider, err := NewNativeProvider(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	var store *Store
	var registry *InputRegistry
	var coordinator *Coordinator
	var counted *nativeWireProvider
	t.Cleanup(func() {
		uncertain := false
		if coordinator != nil {
			coordinator.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := coordinator.Wait(ctx)
			cancel()
			uncertain = err != nil || (counted.calls.Load() > 0 && !counted.quiescent.Load())
			if uncertain {
				nativeWireUncertainCustody.Lock()
				nativeWireUncertainCustody.coordinators = append(nativeWireUncertainCustody.coordinators, coordinator)
				nativeWireUncertainCustody.Unlock()
				t.Error("uncertain execution: fixture and keeper custody retained; no cleanup permission")
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
	counted = &nativeWireProvider{provider: provider}
	coordinator, err = NewCoordinator(store, registry, counted)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := os.ReadFile(filepath.Join(repo, "biozero/bio/fixtures/variant-smoke/reads.fastq"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(base, "verified.fastq")
	if err := os.WriteFile(inputPath, plaintext, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	registered, err := coordinator.RegisterInput(context.Background(), "0000000000000002", digest([]byte("synthetic original encrypted upload placeholder")), digest(plaintext), int64(len(plaintext)), input)
	if err != nil {
		t.Fatal(err)
	}
	audit := &nativeWireAudit{Coordinator: coordinator, storeRoot: storeRoot}
	_, socket := unixTestStart(t, UnixServerConfig{SocketPath: filepath.Join(base, "channel", "keeper.sock")}, audit)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status := Request{SchemaVersion: 1, Operation: "status", LeaseID: registered.LeaseID}
	raw, err := CallUnix(ctx, socket, status)
	var before ExecutionResponse
	if err != nil || json.Unmarshal(raw, &before) != nil || before.SchemaVersion != 1 || before.LeaseID != registered.LeaseID || before.State != "reserved" || before.Manifest != nil || counted.calls.Load() != 0 {
		t.Fatal("reserved status unexpectedly ran or released execution", err)
	}
	raw, err = CallUnix(ctx, socket, runRequest(registered))
	var response ExecutionResponse
	if err != nil || json.Unmarshal(raw, &response) != nil || response.SchemaVersion != 1 || response.LeaseID != registered.LeaseID || response.State != "committed" || response.Manifest == nil {
		t.Fatal("actual native Unix run did not return committed manifest", err)
	}
	m := response.Manifest
	if m.ExecutionStatus != "succeeded" || m.ReleaseStatus != "evaluated_passed" || len(m.Files) != 4 || m.ObservedSHA256 != m.EvaluatedSHA256 || m.ObservedSHA256 != m.Files["normalized_vcf"].SHA256 || audit.runWrites.Load() != 1 || counted.calls.Load() != 1 {
		t.Fatal("actual science, retained VCF or commit-before-wire-write mismatch")
	}
	receiptBytes, err := os.ReadFile(filepath.Join(storeRoot, "objects", registered.LeaseID, "execution_receipt"))
	var receipt struct {
		SchemaVersion int `json:"schema_version"`
		Evaluation    struct {
			Returncode int `json:"returncode"`
			Payload    struct {
				Status    string  `json:"evaluation_status"`
				TP        int     `json:"tp"`
				FP        int     `json:"fp"`
				FN        int     `json:"fn"`
				Precision float64 `json:"precision"`
				Recall    float64 `json:"recall"`
			} `json:"payload"`
		} `json:"evaluation"`
	}
	if err != nil || digest(receiptBytes) != m.Files["execution_receipt"].SHA256 || json.Unmarshal(receiptBytes, &receipt) != nil || receipt.SchemaVersion != 1 || receipt.Evaluation.Returncode != 0 || receipt.Evaluation.Payload.Status != "passed" || receipt.Evaluation.Payload.TP != 3 || receipt.Evaluation.Payload.FP != 0 || receipt.Evaluation.Payload.FN != 0 || receipt.Evaluation.Payload.Precision != 1 || receipt.Evaluation.Payload.Recall != 1 {
		t.Fatal("retained evaluator did not independently show TP3/FP0/FN0/precision1/recall1", err)
	}
	statusRaw, err := CallUnix(ctx, socket, status)
	var after ExecutionResponse
	if err != nil || json.Unmarshal(statusRaw, &after) != nil || after.SchemaVersion != 1 || after.LeaseID != registered.LeaseID || after.ManifestSHA256 != response.ManifestSHA256 || after.State != "committed" || after.Manifest == nil {
		t.Fatal("committed status did not retain exact manifest", err)
	}
	originalManifest, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	statusManifest, err := json.Marshal(after.Manifest)
	if err != nil || !bytes.Equal(originalManifest, statusManifest) {
		t.Fatal("status changed the complete retained manifest", err)
	}
	ledgerBefore, err := os.ReadFile(filepath.Join(storeRoot, "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	replayRaw, err := CallUnix(ctx, socket, runRequest(registered))
	var replay struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		ErrorCode     string `json:"error_code"`
	}
	if err != nil || json.Unmarshal(replayRaw, &replay) != nil || replay.SchemaVersion != 1 || replay.Status != "failed" || replay.ErrorCode != "artifact_handler_failed" {
		t.Fatal("replayed input reference was not explicitly rejected", err)
	}
	ledgerAfter, err := os.ReadFile(filepath.Join(storeRoot, "ledger.json"))
	if err != nil || string(ledgerBefore) != string(ledgerAfter) || counted.calls.Load() != 1 || audit.runWrites.Load() != 1 {
		t.Fatal("replay changed retained history, repeated provider or acknowledged release")
	}
	anchors, err := os.ReadDir(config.WorkspaceRoot)
	if err != nil || len(anchors) != 0 {
		t.Fatal("native Unix run retained workspace anchors", err)
	}
	t.Log("actual native capsule plus Unix client: storage/proof before socket reply, exact retained science, status continuity and replay rejection; TLS/signature/decryption worker entry remains untested")
}

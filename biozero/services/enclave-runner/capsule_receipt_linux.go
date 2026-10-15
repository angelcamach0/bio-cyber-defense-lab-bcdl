//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"

	artifact "biozero/artifact-executor"
	"biozero/enclave-runner/analysis"
)

type capsuleSourcePin struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type capsuleReceiptFacts struct {
	JobID, UploadSHA256, ProfileSHA256, ProcessedSHA256 string
	ProcessedBytes                                      int64
	AnalysisContext                                     artifact.AnalysisContext
	Mode, CapsuleKind                                   string
	ExpectedSourcePins                                  map[string]capsuleSourcePin
}
type capsuleReceiptProjection struct {
	PipelineOutput, ScientificEvaluation json.RawMessage
	Detection                            *detectionResult
	PipelineError, Status, ReleaseStatus string
	ArtifactExecution                    *artifactExecution
}
type receiptOutcome struct {
	ExecutionStatus string `json:"execution_status"`
	ReleaseStatus   string `json:"release_status"`
	ErrorCode       string `json:"error_code"`
	ObservedSHA256  string `json:"observed_sha256"`
	EvaluatedSHA256 string `json:"evaluated_sha256"`
}
type receiptCapture struct {
	Returncode *int            `json:"returncode"`
	Payload    json.RawMessage `json:"payload"`
	RawStdout  string          `json:"raw_stdout"`
	RawStderr  string          `json:"raw_stderr"`
	ErrorCode  string          `json:"error_code,omitempty"`
}

var receiptCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var receiptPath = regexp.MustCompile(`/[^\s"'<>]*`)

func receiptInvalid() error           { return errors.New("capsule_receipt_invalid") }
func receiptDigest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// Token validation precedes every typed conversion. Go's default decoder accepts
// case aliases, duplicate keys, invalid UTF-8 and numeric overflow into interfaces.
func receiptJSON(ctx context.Context, raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, receiptInvalid()
	}
	if _, err := validateMetadataJSON(ctx, raw, nil); err != nil {
		return nil, receiptInvalid()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil {
		return nil, receiptInvalid()
	}
	var finite func(any) bool
	finite = func(v any) bool {
		switch x := v.(type) {
		case json.Number:
			n, e := x.Float64()
			return e == nil && !math.IsInf(n, 0) && !math.IsNaN(n)
		case map[string]any:
			for _, v := range x {
				if !finite(v) {
					return false
				}
			}
		case []any:
			for _, v := range x {
				if !finite(v) {
					return false
				}
			}
		}
		return true
	}
	if !finite(value) {
		return nil, receiptInvalid()
	}
	return value, nil
}

// Exact typed shape, including required nested fields. RawMessage is an explicit
// extensible boundary, not an exception to duplicate/depth/finite validation.
func receiptShape(raw []byte, typ reflect.Type) error {
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if typ.Kind() == reflect.Ptr {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		return receiptShape(raw, typ.Elem())
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return receiptInvalid()
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil {
			return receiptInvalid()
		}
		allowed := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := f.Tag.Get("json")
			k := strings.Split(tag, ",")[0]
			allowed[k] = true
			v, ok := object[k]
			if !ok {
				if !strings.Contains(tag, ",omitempty") {
					return receiptInvalid()
				}
				continue
			}
			if receiptShape(v, f.Type) != nil {
				return receiptInvalid()
			}
		}
		for k := range object {
			if !allowed[k] {
				return receiptInvalid()
			}
		}
	case reflect.Map:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil {
			return receiptInvalid()
		}
		for _, v := range object {
			if receiptShape(v, typ.Elem()) != nil {
				return receiptInvalid()
			}
		}
	case reflect.Slice, reflect.Array:
		var array []json.RawMessage
		if json.Unmarshal(raw, &array) != nil || array == nil {
			return receiptInvalid()
		}
		if typ.Kind() == reflect.Array && len(array) != typ.Len() {
			return receiptInvalid()
		}
		for _, v := range array {
			if receiptShape(v, typ.Elem()) != nil {
				return receiptInvalid()
			}
		}
	default:
		if json.Unmarshal(raw, reflect.New(typ).Interface()) != nil {
			return receiptInvalid()
		}
	}
	return nil
}
func receiptDecode(ctx context.Context, raw []byte, out any) error {
	if _, err := receiptJSON(ctx, raw); err != nil {
		return err
	}
	if receiptShape(raw, reflect.TypeOf(out).Elem()) != nil || json.Unmarshal(raw, out) != nil {
		return receiptInvalid()
	}
	return nil
}
func receiptObject(raw []byte, required, optional []string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, receiptInvalid()
	}
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if _, ok := m[k]; !ok {
			return nil, receiptInvalid()
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return nil, receiptInvalid()
		}
	}
	return m, nil
}
func receiptString(raw []byte) (string, error) {
	var s string
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &s) != nil {
		return "", receiptInvalid()
	}
	return s, nil
}
func receiptInt(raw []byte) (int64, error) {
	var n int64
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &n) != nil {
		return 0, receiptInvalid()
	}
	return n, nil
}
func receiptEqual(a, b any) bool { return reflect.DeepEqual(a, b) }
func receiptContextValid(c artifact.AnalysisContext, size int64) bool {
	return size >= 0 && size <= 25<<20 && c.ProcessedSizeBytes == size && utf8.ValidString(c.OriginalName) && len(c.OriginalName) <= 4096 && utf8.ValidString(c.DecryptionError) && len(c.DecryptionError) <= 128 && utf8.ValidString(c.SignatureError) && len(c.SignatureError) <= 128 && !(c.Decrypted && c.DecryptionError != "") && !(c.SignatureValid && c.SignatureError != "")
}
func validateReceiptPins(ctx context.Context, raw []byte, f capsuleReceiptFacts) (bool, bool, error) {
	var pins map[string]capsuleSourcePin
	if receiptDecode(ctx, raw, &pins) != nil || !receiptEqual(pins, f.ExpectedSourcePins) {
		return false, false, receiptInvalid()
	}
	required := map[string]int64{"pipeline": 4 << 20, "resource_budget": 4 << 20, "analysis_executable": 4 << 20, "analysis_rules": 64 << 10}
	allowed := map[string]int64{}
	for k, v := range required {
		allowed[k] = v
	}
	allowed["analysis_panel"] = 32 << 20
	// Stats may carry a pinned reference, but only variants may configure truth/evaluation.
	allowed["reference"] = 32 << 20
	if f.Mode == "variants" {
		required["reference"] = 32 << 20
		allowed["reference"] = 32 << 20
		allowed["evaluator"] = 4 << 20
		allowed["truth"] = 32 << 20
	} else if f.Mode != "stats" {
		return false, false, receiptInvalid()
	}
	for k := range required {
		if _, ok := pins[k]; !ok {
			return false, false, receiptInvalid()
		}
	}
	for k, v := range pins {
		limit, ok := allowed[k]
		if !ok || !artifactHex(v.SHA256, 64) || v.Bytes < 0 || v.Bytes > limit {
			return false, false, receiptInvalid()
		}
	}
	_, panel := pins["analysis_panel"]
	_, eval := pins["evaluator"]
	_, truth := pins["truth"]
	_, reference := pins["reference"]
	if eval != truth || eval && !reference {
		return false, false, receiptInvalid()
	}
	return panel, eval, nil
}
func decodeReceiptCapture(ctx context.Context, raw []byte, limit int, allowIncomplete bool) (receiptCapture, error) {
	var c receiptCapture
	if receiptDecode(ctx, raw, &c) != nil {
		return c, receiptInvalid()
	}
	if len(c.RawStdout) > limit || len(c.RawStderr) > 3*(64<<10) {
		return c, receiptInvalid()
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	if c.Returncode == nil {
		if len(fields) != 5 {
			return c, receiptInvalid()
		}
		if !allowIncomplete || !receiptCode.MatchString(c.ErrorCode) || !bytes.Equal(bytes.TrimSpace(c.Payload), []byte("null")) || c.RawStdout != "" || c.RawStderr != "" {
			return c, receiptInvalid()
		}
		return c, nil
	}
	if len(fields) != 4 || c.ErrorCode != "" {
		return c, receiptInvalid()
	}
	a, e := receiptJSON(ctx, c.Payload)
	if e != nil {
		return c, e
	}
	if _, ok := a.(map[string]any); !ok {
		return c, receiptInvalid()
	}
	b, e := receiptJSON(ctx, []byte(c.RawStdout))
	if e != nil || !receiptEqual(a, b) {
		return c, receiptInvalid()
	}
	return c, nil
}

// Kernel fields remain private. This checks the recorded shape/observations; it
// does not replace provider Wait, export fencing or the Store's custody proof.
func validateReceiptState(ctx context.Context, raw []byte, kind string) error {
	keys := []string{"pid", "uid", "gid", "rlimit_fsize", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "namespaces"}
	if kind == "docker" {
		keys = append(keys, "euid", "egid", "mounts", "interfaces", "root_statfs", "workspace_statfs", "cgroup", "workspace_directory")
	} else if kind != "native" {
		return receiptInvalid()
	}
	m, e := receiptObject(raw, keys, nil)
	if e != nil {
		return e
	}
	uid := int64(0)
	if kind == "docker" {
		uid = 1000
	}
	for k, want := range map[string]int64{"pid": 1, "uid": uid, "gid": uid} {
		n, e := receiptInt(m[k])
		if e != nil || n != want {
			return receiptInvalid()
		}
	}
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		s, e := receiptString(m[k])
		if e != nil || s != "0000000000000000" {
			return receiptInvalid()
		}
	}
	if value, e := receiptString(m["NoNewPrivs"]); e != nil || value != "1" {
		return receiptInvalid()
	}
	var limits [2]int64
	if receiptDecode(ctx, m["rlimit_fsize"], &limits) != nil || limits != [2]int64{64 << 20, 64 << 20} {
		return receiptInvalid()
	}
	ns, e := receiptObject(m["namespaces"], []string{"user", "mnt", "pid", "net"}, nil)
	if e != nil {
		return e
	}
	for k, v := range ns {
		s, e := receiptString(v)
		if e != nil || !regexp.MustCompile(`^`+k+`:\[[0-9]+\]$`).MatchString(s) {
			return receiptInvalid()
		}
	}
	if kind == "native" {
		return nil
	}
	for _, k := range []string{"euid", "egid"} {
		n, e := receiptInt(m[k])
		if e != nil || n != 1000 {
			return receiptInvalid()
		}
	}
	var interfaces []string
	if receiptDecode(ctx, m["interfaces"], &interfaces) != nil || !receiptEqual(interfaces, []string{"lo"}) {
		return receiptInvalid()
	}
	type mount struct {
		Mountpoint   string   `json:"mountpoint"`
		Options      []string `json:"options"`
		Filesystem   string   `json:"filesystem"`
		SuperOptions []string `json:"super_options"`
		Optional     []string `json:"optional"`
	}
	var mounts []mount
	if receiptDecode(ctx, m["mounts"], &mounts) != nil || len(mounts) == 0 || len(mounts) > 4096 {
		return receiptInvalid()
	}
	type fs struct {
		Magic    int64 `json:"filesystem_magic"`
		Block    int64 `json:"block_bytes"`
		Capacity int64 `json:"capacity_bytes"`
		Inodes   int64 `json:"inode_units"`
		Free     int64 `json:"free_inode_units"`
		Flags    int64 `json:"flags"`
	}
	var root, work fs
	if receiptDecode(ctx, m["root_statfs"], &root) != nil || receiptDecode(ctx, m["workspace_statfs"], &work) != nil || root.Flags&1 != 1 || work.Magic != 0x1021994 || work.Capacity != 128<<20 || work.Inodes != 4096 || work.Flags&1 != 0 {
		return receiptInvalid()
	}
	type dir struct {
		UID   int  `json:"uid"`
		GID   int  `json:"gid"`
		Mode  int  `json:"mode"`
		Empty bool `json:"empty"`
	}
	var directory dir
	if receiptDecode(ctx, m["workspace_directory"], &directory) != nil || directory != (dir{1000, 1000, 0700, true}) {
		return receiptInvalid()
	}
	type cg struct {
		Membership string `json:"membership"`
		Namespace  string `json:"namespace"`
		Memory     string `json:"memory.max"`
		Swap       string `json:"memory.swap.max"`
		PIDs       string `json:"pids.max"`
		CPU        string `json:"cpu.max"`
	}
	var group cg
	if receiptDecode(ctx, m["cgroup"], &group) != nil || group.Membership != "0::/" || !regexp.MustCompile(`^cgroup:\[[0-9]+\]$`).MatchString(group.Namespace) || group.Memory != "536870912" || group.Swap != "0" || group.PIDs != "128" {
		return receiptInvalid()
	}
	cpu := strings.Fields(group.CPU)
	if len(cpu) != 2 || cpu[0] != cpu[1] || !regexp.MustCompile(`^[1-9][0-9]{0,18}$`).MatchString(cpu[0]) {
		return receiptInvalid()
	}
	return nil
}

// ProjectCapsuleReceipt reads only the held receipt. It never opens a capsule
// pathname and never reruns tools. The caller retains FD/custody authority.
func ProjectCapsuleReceipt(ctx context.Context, reader io.Reader, r artifact.BridgeResponse, f capsuleReceiptFacts) (capsuleReceiptProjection, error) {
	var zero capsuleReceiptProjection
	if !artifactHex(f.JobID, 16) || !artifactHex(f.UploadSHA256, 64) || !artifactHex(f.ProfileSHA256, 64) || !artifactHex(f.ProcessedSHA256, 64) || !receiptContextValid(f.AnalysisContext, f.ProcessedBytes) || (f.CapsuleKind != "native" && f.CapsuleKind != "docker") || (f.Mode != "stats" && f.Mode != "variants") {
		return zero, receiptInvalid()
	}
	m := r.Manifest
	if r.SchemaVersion != 2 || r.State != "committed" || !r.HasManifest || r.ErrorCode != "" || r.CancelRequested || m.Files == nil || len(m.Files) > 4 || r.JobID != f.JobID || r.UploadSHA256 != f.UploadSHA256 || r.ProfileSHA256 != f.ProfileSHA256 || !artifactHex(r.StoreID, 32) || !artifactHex(r.LeaseID, 32) || m.SchemaVersion != 1 || m.StoreID != r.StoreID || m.LeaseID != r.LeaseID || m.JobID != r.JobID || m.InputSHA256 != f.UploadSHA256 || !artifactHex(m.PolicySHA256, 64) {
		return zero, receiptInvalid()
	}
	manifestBytes, e := json.Marshal(m)
	if e != nil || receiptDigest(manifestBytes) != r.ManifestSHA256 {
		return zero, receiptInvalid()
	}
	binding := artifactExecution{1, f.ProfileSHA256, r.StoreID, r.LeaseID, r.ManifestSHA256, r.ReceiptSHA256, r.ReceiptBytes, map[string]artifactFile{}}
	for id, file := range m.Files {
		if file.State != "verified" {
			return zero, receiptInvalid()
		}
		binding.Files[id] = artifactFile{file.SHA256, file.Bytes}
	}
	b, _ := json.Marshal(binding)
	if _, e := validateArtifactExecution(b, m.ExecutionStatus, m.ReleaseStatus); e != nil {
		return zero, receiptInvalid()
	}
	out := capsuleReceiptProjection{Status: m.ExecutionStatus, ReleaseStatus: m.ReleaseStatus, PipelineError: m.ErrorCode, ArtifactExecution: &binding}
	if r.ReceiptSHA256 == "" {
		if reader != nil || m.ExecutionStatus != "failed" || m.ReleaseStatus != "withheld" || !receiptCode.MatchString(m.ErrorCode) || m.ObservedSHA256 != "" || m.EvaluatedSHA256 != "" {
			return zero, receiptInvalid()
		}
		return out, nil
	}
	if reader == nil {
		return zero, receiptInvalid()
	}
	var buffer bytes.Buffer
	chunk := make([]byte, 32<<10)
	for {
		if ctx.Err() != nil {
			return zero, errors.New("capsule_receipt_cancelled")
		}
		n, e := reader.Read(chunk)
		if n > 0 {
			if int64(buffer.Len()+n) > r.ReceiptBytes {
				return zero, receiptInvalid()
			}
			buffer.Write(chunk[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return zero, errors.New("capsule_receipt_read_failed")
		}
		if n == 0 {
			return zero, errors.New("capsule_receipt_read_failed")
		}
	}
	raw := buffer.Bytes()
	if int64(len(raw)) != r.ReceiptBytes || receiptDigest(raw) != r.ReceiptSHA256 {
		return zero, receiptInvalid()
	}
	if _, e := receiptJSON(ctx, raw); e != nil {
		return zero, e
	}
	keys := []string{"schema_version", "input_sha256", "input_bytes", "source_pins", "mode", "capsule_state", "workspace_policy", "outcome", "pipeline", "evaluation", "scope", "analysis_capture", "analysis_context"}
	if f.CapsuleKind == "docker" {
		keys = append(keys, "capsule_kind", "native_helper_sha256", "keeper_monitor")
	}
	fields, e := receiptObject(raw, keys, nil)
	if e != nil {
		return zero, e
	}
	version, e := receiptInt(fields["schema_version"])
	if e != nil || version != 2 {
		return zero, receiptInvalid()
	}
	input, e := receiptString(fields["input_sha256"])
	if e != nil || input != f.ProcessedSHA256 {
		return zero, receiptInvalid()
	}
	size, e := receiptInt(fields["input_bytes"])
	if e != nil || size != f.ProcessedBytes {
		return zero, receiptInvalid()
	}
	mode, e := receiptString(fields["mode"])
	if e != nil || mode != f.Mode {
		return zero, receiptInvalid()
	}
	scope, e := receiptString(fields["scope"])
	if e != nil || scope != "synthetic normalized allele presence; no biological accuracy claim" {
		return zero, receiptInvalid()
	}
	if f.CapsuleKind == "docker" {
		kind, e := receiptString(fields["capsule_kind"])
		pin, pe := receiptString(fields["native_helper_sha256"])
		monitor, me := receiptString(fields["keeper_monitor"])
		if e != nil || kind != "docker" || pe != nil || !artifactHex(pin, 64) || me != nil || monitor != "active; EOF/error is cancellation, never proof" {
			return zero, receiptInvalid()
		}
	}
	var contextFacts artifact.AnalysisContext
	if receiptDecode(ctx, fields["analysis_context"], &contextFacts) != nil || contextFacts != f.AnalysisContext {
		return zero, receiptInvalid()
	}
	panel, evaluator, e := validateReceiptPins(ctx, fields["source_pins"], f)
	if e != nil {
		return zero, e
	}
	type workspace struct {
		Filesystem string `json:"filesystem"`
		Bytes      int64  `json:"bytes"`
		Inodes     int    `json:"nr_inodes"`
		FileBytes  int64  `json:"file_bytes"`
	}
	var work workspace
	if receiptDecode(ctx, fields["workspace_policy"], &work) != nil || work != (workspace{"tmpfs", 128 << 20, 4096, 64 << 20}) || validateReceiptState(ctx, fields["capsule_state"], f.CapsuleKind) != nil {
		return zero, receiptInvalid()
	}
	var outcome receiptOutcome
	if receiptDecode(ctx, fields["outcome"], &outcome) != nil || outcome != (receiptOutcome{m.ExecutionStatus, m.ReleaseStatus, m.ErrorCode, m.ObservedSHA256, m.EvaluatedSHA256}) {
		return zero, receiptInvalid()
	}
	pipe, e := decodeReceiptCapture(ctx, fields["pipeline"], 1<<20, false)
	if e != nil {
		return zero, e
	}
	pipeline, pipeStatus, e := projectReceiptPipeline(ctx, pipe, f, m)
	if e != nil {
		return zero, e
	}
	out.PipelineOutput = pipeline
	wanted := receiptOutcome{ExecutionStatus: pipeStatus, ReleaseStatus: "unassessed"}
	if pipeStatus != "succeeded" {
		wanted.ReleaseStatus = "withheld"
		wanted.ErrorCode = "capsule_pipeline_" + pipeStatus
	}
	if pipeStatus == "succeeded" && f.Mode == "variants" {
		if len(m.Files) != 4 || !artifactHex(m.ObservedSHA256, 64) || m.Files["normalized_vcf"].SHA256 != m.ObservedSHA256 {
			return zero, receiptInvalid()
		}
		wanted.ObservedSHA256 = m.ObservedSHA256
		if evaluator {
			eval, e := decodeReceiptCapture(ctx, fields["evaluation"], 1<<20, false)
			if e != nil {
				return zero, e
			}
			projected, passed, e := projectReceiptEvaluation(ctx, eval)
			if e != nil {
				return zero, e
			}
			out.ScientificEvaluation = projected
			if m.EvaluatedSHA256 != m.ObservedSHA256 {
				return zero, receiptInvalid()
			}
			wanted.EvaluatedSHA256 = m.EvaluatedSHA256
			if passed {
				wanted.ReleaseStatus = "evaluated_passed"
			} else {
				wanted.ReleaseStatus = "withheld"
				wanted.ErrorCode = "capsule_science_failed"
			}
		} else if !bytes.Equal(bytes.TrimSpace(fields["evaluation"]), []byte("null")) {
			return zero, receiptInvalid()
		}
	} else {
		if len(m.Files) != 1 || m.ObservedSHA256 != "" || m.EvaluatedSHA256 != "" || !bytes.Equal(bytes.TrimSpace(fields["evaluation"]), []byte("null")) {
			return zero, receiptInvalid()
		}
	}
	detection, analysisError, e := projectReceiptAnalysis(ctx, fields["analysis_capture"], f.AnalysisContext, panel)
	if e != nil {
		return zero, e
	}
	out.Detection = detection
	if analysisError != "" {
		wanted.ExecutionStatus = "failed"
		wanted.ReleaseStatus = "withheld"
		wanted.ErrorCode = analysisError
	}
	if wanted != outcome {
		return zero, receiptInvalid()
	}
	if out.Detection != nil && validateReceiptDetectionPipeline(ctx, *out.Detection, pipe.Payload) != nil {
		return zero, receiptInvalid()
	}
	return out, nil
}

// Remove dead namespace locations from diagnostic text as well as explicit path
// fields. Retained files are identified by the manifest's opaque artifact IDs.
func receiptProjectValue(v any) any {
	switch x := v.(type) {
	case string:
		return receiptPath.ReplaceAllString(x, "[capsule-path]")
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = receiptProjectValue(v)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, v := range x {
			if !strings.ContainsAny(k, "/\\") {
				out[k] = receiptProjectValue(v)
			}
		}
		return out
	}
	return v
}
func projectReceiptPipeline(ctx context.Context, c receiptCapture, f capsuleReceiptFacts, m artifact.Manifest) (json.RawMessage, string, error) {
	required := []string{"schema_version", "pipeline", "mode", "pipeline_status", "timestamp", "input", "output_dir", "stages", "outputs", "errors", "warnings", "tools"}
	optional := []string{"pipeline", "timestamp", "input", "output_dir", "stages", "outputs", "errors", "warnings", "tools", "resource_budget", "read_count", "avg_read_length", "line_count", "byte_count", "sha256", "reference_sha256", "variant_count", "error", "versions", "fastp"}
	fields, e := receiptObject(c.Payload, required, optional)
	if e != nil {
		return nil, "", e
	}
	version, e := receiptInt(fields["schema_version"])
	mode, me := receiptString(fields["mode"])
	status, se := receiptString(fields["pipeline_status"])
	code, ok := map[string]int{"succeeded": 0, "failed": 1, "incomplete": 2}[status]
	if e != nil || version != 1 || me != nil || mode != f.Mode || se != nil || !ok || c.Returncode == nil || *c.Returncode != code {
		return nil, "", receiptInvalid()
	}
	if name, e := receiptString(fields["pipeline"]); e != nil || name != "python-wrapper" {
		return nil, "", receiptInvalid()
	}
	if status == "succeeded" {
		for _, key := range []string{"read_count", "avg_read_length", "line_count", "byte_count", "sha256"} {
			if _, ok := fields[key]; !ok {
				return nil, "", receiptInvalid()
			}
		}
		if f.Mode == "variants" {
			for _, key := range []string{"reference_sha256", "variant_count"} {
				if _, ok := fields[key]; !ok {
					return nil, "", receiptInvalid()
				}
			}
		}
	}
	for _, key := range []string{"read_count", "avg_read_length", "line_count", "byte_count", "variant_count"} {
		if value, ok := fields[key]; ok {
			n, e := receiptInt(value)
			if e != nil || n < 0 || (key == "byte_count" && n != f.ProcessedBytes) {
				return nil, "", receiptInvalid()
			}
		}
	}
	for key, want := range map[string]string{"sha256": f.ProcessedSHA256, "reference_sha256": f.ExpectedSourcePins["reference"].SHA256} {
		if value, ok := fields[key]; ok {
			s, e := receiptString(value)
			if e != nil || s != want || !artifactHex(s, 64) {
				return nil, "", receiptInvalid()
			}
		}
	}
	for _, key := range []string{"pipeline", "timestamp", "input", "error"} {
		if value, ok := fields[key]; ok {
			if _, e := receiptString(value); e != nil {
				return nil, "", e
			}
		}
	}
	if value, ok := fields["output_dir"]; ok && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		if _, e := receiptString(value); e != nil {
			return nil, "", e
		}
	}
	if value, ok := fields["warnings"]; ok {
		var warnings []string
		if receiptDecode(ctx, value, &warnings) != nil || len(warnings) > 1<<20 {
			return nil, "", receiptInvalid()
		}
	}
	if value, ok := fields["tools"]; ok {
		var tools map[string]bool
		if receiptDecode(ctx, value, &tools) != nil {
			return nil, "", receiptInvalid()
		}
	}
	if value, ok := fields["versions"]; ok {
		var versions map[string]string
		if receiptDecode(ctx, value, &versions) != nil {
			return nil, "", receiptInvalid()
		}
	}
	if value, ok := fields["stages"]; ok {
		type stage struct {
			Name       string `json:"name"`
			Status     string `json:"status"`
			Returncode *int   `json:"returncode,omitempty"`
			ErrorCode  string `json:"error_code,omitempty"`
		}
		var stages []stage
		if receiptDecode(ctx, value, &stages) != nil || len(stages) > 4096 {
			return nil, "", receiptInvalid()
		}

		var rawStages []map[string]json.RawMessage
		json.Unmarshal(value, &rawStages)
		completed := map[string]bool{}
		for i, s := range stages {
			if s.Name == "" || completed[s.Name] || s.Status != "succeeded" && s.Status != "failed" && s.Status != "incomplete" {
				return nil, "", receiptInvalid()
			}
			if v, ok := rawStages[i]["returncode"]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				return nil, "", receiptInvalid()
			}
			if status == "succeeded" && (s.Status != "succeeded" || s.Returncode != nil && *s.Returncode != 0) {
				return nil, "", receiptInvalid()
			}
			completed[s.Name] = true
		}
		if status == "succeeded" && (!completed["validate_fastq"] || f.Mode == "stats" && !completed["fastq_stats"] || f.Mode == "variants" && !completed["vcf_check"]) {
			return nil, "", receiptInvalid()
		}

	}
	if value, ok := fields["errors"]; ok {
		type pipelineError struct {
			Stage   string `json:"stage"`
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		var faults []pipelineError
		if receiptDecode(ctx, value, &faults) != nil || len(faults) > 4096 || status == "succeeded" && len(faults) > 0 {
			return nil, "", receiptInvalid()
		}
	}
	if value, ok := fields["resource_budget"]; ok {
		type budget struct {
			File        int64  `json:"file_bytes"`
			Reference   int64  `json:"reference_bytes"`
			Input       int64  `json:"expanded_input_bytes"`
			Stdout      int64  `json:"tool_stdout_bytes"`
			Stderr      int64  `json:"tool_stderr_bytes"`
			Enforcement string `json:"file_enforcement"`
			Aggregate   string `json:"workspace_aggregate_enforcement"`
			Group       string `json:"group_mode"`
		}
		var b budget
		if receiptDecode(ctx, value, &b) != nil || b.File != 64<<20 || b.Reference != 32<<20 || b.Input != 25<<20 || b.Stdout != 64<<10 || b.Stderr != 64<<10 || b.Enforcement != "kernel_rlimit_fsize" || b.Aggregate != "pending" || b.Group != "shared" {
			return nil, "", receiptInvalid()
		}
	}
	value, _ := receiptJSON(ctx, c.Payload)
	projected := receiptProjectValue(value).(map[string]any)
	delete(projected, "input")
	delete(projected, "output_dir")
	delete(projected, "outputs")
	if source, ok := fields["outputs"]; ok {
		outputs, e := receiptObject(source, nil, []string{"alignment_sam", "alignment_bam", "variants_vcf", "variants_vcf_index", "normalized_vcf", "fastp_summary"})
		if e != nil {
			return nil, "", e
		}
		retained := map[string]any{}
		for key, value := range outputs {
			if key == "fastp_summary" {
				v, e := receiptJSON(ctx, value)
				if e != nil {
					return nil, "", e
				}
				if _, ok := v.(map[string]any); !ok {
					return nil, "", receiptInvalid()
				}
				retained[key] = receiptProjectValue(v)
				continue
			}
			if _, e := receiptString(value); e != nil {
				return nil, "", e
			}
			if _, ok := m.Files[key]; ok {
				retained[key] = key
			}
		}
		if f.Mode == "variants" && status == "succeeded" {
			for _, id := range []string{"normalized_vcf", "variants_vcf", "variants_vcf_index"} {
				if _, ok := retained[id]; !ok {
					return nil, "", receiptInvalid()
				}
			}
		}
		projected["outputs"] = retained
	} else if f.Mode == "variants" && status == "succeeded" {
		return nil, "", receiptInvalid()
	}
	data, e := json.Marshal(projected)
	if e != nil || len(data) > 1<<20 {
		return nil, "", receiptInvalid()
	}
	return data, status, nil
}
func projectReceiptEvaluation(ctx context.Context, c receiptCapture) (json.RawMessage, bool, error) {
	fields, e := receiptObject(c.Payload, []string{"evaluation_status"}, []string{"tp", "fp", "fn", "precision", "recall", "unexpected", "missing", "scope", "error"})
	if e != nil {
		return nil, false, e
	}
	status, e := receiptString(fields["evaluation_status"])
	if e != nil || c.Returncode == nil || (status != "passed" && status != "failed") || *c.Returncode != map[string]int{"passed": 0, "failed": 1}[status] {
		return nil, false, receiptInvalid()
	}
	output := map[string]any{"evaluation_status": status}
	_, hasError := fields["error"]
	if hasError {
		if status != "failed" || len(fields) != 2 {
			return nil, false, receiptInvalid()
		}
		message, e := receiptString(fields["error"])
		if e != nil {
			return nil, false, e
		}
		output["error"] = receiptProjectValue(message)
	} else {
		counts := map[string]int64{}
		for _, key := range []string{"tp", "fp", "fn"} {
			n, e := receiptInt(fields[key])
			if e != nil || n < 0 {
				return nil, false, receiptInvalid()
			}
			counts[key] = n
			output[key] = n
		}
		for _, key := range []string{"precision", "recall"} {
			value, ok := fields[key]
			if !ok {
				return nil, false, receiptInvalid()
			}
			var number *float64
			if json.Unmarshal(value, &number) != nil {
				return nil, false, receiptInvalid()
			}
			den := counts["tp"] + counts["fp"]
			if key == "recall" {
				den = counts["tp"] + counts["fn"]
			}
			if den < 0 || (den == 0 && number != nil) || (den > 0 && (number == nil || *number != float64(counts["tp"])/float64(den))) {
				return nil, false, receiptInvalid()
			}
			output[key] = number
		}
		for _, key := range []string{"unexpected", "missing"} {
			var entries []json.RawMessage
			if receiptDecode(ctx, fields[key], &entries) != nil {
				return nil, false, receiptInvalid()
			}
			want := counts["fp"]
			if key == "missing" {
				want = counts["fn"]
			}
			if int64(len(entries)) != want {
				return nil, false, receiptInvalid()
			}
			output[key+"_count"] = len(entries)
		}
		scope, e := receiptString(fields["scope"])
		if e != nil || scope != "normalized allele presence; no genotype or clinical validation" {
			return nil, false, receiptInvalid()
		}
		output["scope"] = scope
		if status == "passed" && (counts["tp"] <= 0 || counts["fp"] != 0 || counts["fn"] != 0) {
			return nil, false, receiptInvalid()
		}
	}
	data, e := json.Marshal(output)
	return data, status == "passed", e
}
func projectReceiptAnalysis(ctx context.Context, raw []byte, facts artifact.AnalysisContext, panel bool) (*detectionResult, string, error) {
	capture, e := decodeReceiptCapture(ctx, raw, 64<<10, true)
	if e != nil {
		return nil, "", e
	}
	if capture.Returncode == nil {
		switch capture.ErrorCode {
		case "capsule_analysis_request_limit", "capsule_capture_limit", "capsule_json_invalid", "capsule_analysis_stdin_failed", "capsule_analysis_start_failed":
		default:
			return nil, "", receiptInvalid()
		}
		return nil, capture.ErrorCode, nil
	}
	var response analysis.Response
	if receiptDecode(ctx, capture.Payload, &response) != nil || response.SchemaVersion != 1 || response.Warnings == nil || len(response.Warnings) != 0 {
		return nil, "capsule_analysis_invalid", nil
	}
	if response.Status == "failed" {
		if *capture.Returncode != 1 || response.Detection != nil || !receiptCode.MatchString(response.ErrorCode) {
			return nil, "capsule_analysis_invalid", nil
		}
		return nil, "capsule_analysis_failed", nil
	}
	if response.Status != "succeeded" || *capture.Returncode != 0 || response.ErrorCode != "" || response.Detection == nil {
		return nil, "capsule_analysis_invalid", nil
	}
	d := response.Detection
	if !finiteReceipt(d.Score) || d.Score < 0 || d.Score > 1 || (d.Verdict != "low" && d.Verdict != "medium" && d.Verdict != "high") || len(d.Reasons) > 7 {
		return nil, "capsule_analysis_invalid", nil
	}
	reasons := map[string]bool{"suspicious_filename": true, "file_size_exceeded": true, "decryption_failed": true, "signature_invalid": true, "critical_pipeline_warnings": true, "low_quality_reads": true, "threat_panel_hit": true}
	seen := map[string]bool{}
	for _, reason := range d.Reasons {
		if !reasons[reason] || seen[reason] {
			return nil, "capsule_analysis_invalid", nil
		}
		seen[reason] = true
	}
	reason := "no suspicious indicators"
	if len(d.Reasons) > 0 {
		reason = d.Reasons[0]
	}
	if d.Reason != reason {
		return nil, "capsule_analysis_invalid", nil
	}
	s := d.Signals
	if s.Integrity.SignatureValid != facts.SignatureValid || s.Integrity.Decrypted != facts.Decrypted || s.Pipeline.ReadCount < 0 || s.Pipeline.AvgReadLength < 0 || s.Warnings.Critical < 0 || s.Warnings.Warn < 0 || s.Warnings.Info < 0 || s.Warnings.Critical > 1<<20 || s.Warnings.Warn > 1<<20 || s.Warnings.Info > 1<<20 || s.Fastp != nil && !finiteReceipt(s.Fastp.Q30Rate) || panel != (s.Alignment != nil) {
		return nil, "capsule_analysis_invalid", nil
	}
	if a := s.Alignment; a != nil {
		if a.TotalReads < 0 || a.TotalReads > 1000000 || a.MappedReads < 0 || a.MappedReads > a.TotalReads || len(a.Targets) > 128 {
			return nil, "capsule_analysis_invalid", nil
		}
		fraction := 0.0
		if a.TotalReads > 0 {
			fraction = float64(a.MappedReads) / float64(a.TotalReads)
		}
		if a.Fraction != fraction {
			return nil, "capsule_analysis_invalid", nil
		}
		total := 0
		for name, n := range a.Targets {
			if len(name) == 0 || len(name) > 128 || n <= 0 || n > a.MappedReads {
				return nil, "capsule_analysis_invalid", nil
			}
			for _, c := range name {
				if c < 33 || c > 126 {
					return nil, "capsule_analysis_invalid", nil
				}
			}
			total += n
		}
		if total != a.MappedReads {
			return nil, "capsule_analysis_invalid", nil
		}
	}
	data, e := json.Marshal(d)
	if e != nil {
		return nil, "", receiptInvalid()
	}
	var projected detectionResult
	if json.Unmarshal(data, &projected) != nil {
		return nil, "", receiptInvalid()
	}
	return &projected, "", nil
}
func finiteReceipt(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func validateReceiptDetectionPipeline(ctx context.Context, d detectionResult, raw []byte) error {
	var pipe map[string]json.RawMessage
	json.Unmarshal(raw, &pipe)
	var signals analysis.Signals
	b, _ := json.Marshal(d.Signals)
	if json.Unmarshal(b, &signals) != nil {
		return receiptInvalid()
	}
	read, length := int64(0), int64(0)
	if v, ok := pipe["read_count"]; ok {
		read, _ = receiptInt(v)
	}
	if v, ok := pipe["avg_read_length"]; ok {
		length, _ = receiptInt(v)
	}
	if int64(signals.Pipeline.ReadCount) != read || int64(signals.Pipeline.AvgReadLength) != length {
		return receiptInvalid()
	}
	var warnings []string
	if v, ok := pipe["warnings"]; ok {
		if json.Unmarshal(v, &warnings) != nil {
			return receiptInvalid()
		}
	}
	critical, warn, info := 0, 0, 0
	for _, s := range warnings {
		u := strings.ToLower(s)
		switch {
		case strings.Contains(u, "error") || strings.Contains(u, "failed") || strings.Contains(u, "fatal"):
			critical++
		case strings.Contains(u, "warn"):
			warn++
		default:
			info++
		}
	}
	if signals.Warnings != (analysis.WarningSummary{Critical: critical, Warn: warn, Info: info}) {
		return receiptInvalid()
	}
	var outputs map[string]json.RawMessage
	json.Unmarshal(pipe["outputs"], &outputs)
	var fastp struct {
		Summary map[string]struct {
			Q30Rate *float64 `json:"q30_rate"`
		} `json:"summary"`
	}
	json.Unmarshal(outputs["fastp_summary"], &fastp)
	var q *float64
	for _, key := range []string{"after_filtering", "before_filtering"} {
		if part, ok := fastp.Summary[key]; ok && part.Q30Rate != nil {
			q = part.Q30Rate
			break
		}
	}
	if (q != nil) != (signals.Fastp != nil) || q != nil && *q != signals.Fastp.Q30Rate {
		return receiptInvalid()
	}
	return nil
}

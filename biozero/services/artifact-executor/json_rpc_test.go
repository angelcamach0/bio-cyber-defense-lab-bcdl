package artifactexecutor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictLedgerJSONRejectsAmbiguousAndIncomplete(t *testing.T) {
	for _, kind := range []string{"duplicate", "alias", "unknown", "null_scalar", "null_records", "null_policy", "null_array_element", "trailing", "deep", "missing", "invalid_state", "reserved_contradiction"} {
		t.Run(kind, func(t *testing.T) {
			s, path, p := openTest(t, 1)
			reserveTest(t, s, 1)
			b, _ := os.ReadFile(filepath.Join(path, "ledger.json"))
			s.Close()
			v := string(b)
			switch kind {
			case "duplicate":
				v = strings.Replace(v, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
			case "alias":
				v = strings.Replace(v, `"schema_version":1`, `"Schema_Version":1`, 1)
			case "unknown":
				v = strings.Replace(v, `"schema_version":1`, `"schema_version":1,"extra":false`, 1)
			case "null_scalar":
				v = strings.Replace(v, `"schema_version":1`, `"schema_version":null`, 1)
			case "null_records":
				start := strings.Index(v, `"records":`)
				v = v[:start] + `"records":null}`
			case "null_policy":
				var m map[string]any
				json.Unmarshal(b, &m)
				m["policy"] = nil
				z, _ := json.Marshal(m)
				v = string(z)
			case "null_array_element":
				v = strings.Replace(v, `"normalized_vcf"`, `null`, 1)
			case "trailing":
				v += "{}"
			case "deep":
				v = strings.Repeat(`[`, 66) + v + strings.Repeat(`]`, 66)
			case "missing":
				v = strings.Replace(v, `"schema_version":1,`, "", 1)
			case "invalid_state":
				v = strings.Replace(v, `"state":"reserved"`, `"state":"succeeded"`, 1)
			case "reserved_contradiction":
				v = strings.Replace(v, `"proof_sha256":""`, `"proof_sha256":"`+digest(nil)+`"`, 1)
			}
			os.WriteFile(filepath.Join(path, "ledger.json"), []byte(v), 0600)
			if x, e := Open(context.Background(), path, p); e == nil {
				x.Close()
				t.Fatal("invalid ledger accepted")
			}
		})
	}
}
func frame(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if e := WriteFrame(&out, b); e != nil {
		t.Fatal(e)
	}
	return out.Bytes()
}
func TestUnixRequestFramesAreBoundedAndScoped(t *testing.T) {
	valid := `{"schema_version":1,"operation":"run","lease_id":"` + strings.Repeat("a", 32) + `","input_ref":"` + strings.Repeat("b", 32) + `"}`
	q, e := ReadRequest(bytes.NewReader(frame(t, []byte(valid))))
	if e != nil || q.Operation != "run" {
		t.Fatal("valid rejected")
	}
	for _, bad := range []string{strings.Replace(valid, `"run"`, `"shell"`, 1), strings.Replace(valid, `"input_ref"`, `"path"`, 1), strings.Replace(valid, `"schema_version":1`, `"schema_version":null`, 1), strings.Replace(valid, `"schema_version":1`, `"Schema_Version":1`, 1), strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1), strings.Replace(valid, `"input_ref":"`+strings.Repeat("b", 32)+`"`, `"input_ref":"../../input"`, 1), valid + `{}`, strings.Replace(valid, `"run"`, `"proof"`, 1)} {
		if _, e := ReadRequest(bytes.NewReader(frame(t, []byte(bad)))); e == nil {
			t.Fatal("invalid request accepted")
		}
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxFrameBytes+1)
	if _, e := ReadRequest(bytes.NewReader(header[:])); e == nil {
		t.Fatal("huge frame accepted")
	}
	if _, e := ReadRequest(bytes.NewReader([]byte{0, 0, 0, 1})); e == nil {
		t.Fatal("truncated frame")
	}
	if e := WriteFrame(io.Discard, make([]byte, MaxFrameBytes+1)); e == nil {
		t.Fatal("outbound huge frame")
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > 2 {
		b = b[:2]
	}
	return w.Buffer.Write(b)
}
func TestFrameShortWritesAndExactCeiling(t *testing.T) {
	w := &shortWriter{}
	b := bytes.Repeat([]byte("x"), MaxFrameBytes)
	if e := WriteFrame(w, b); e != nil {
		t.Fatal(e)
	}
	if w.Len() != MaxFrameBytes+4 || !bytes.Equal(w.Bytes()[4:], b) {
		t.Fatal("partial write lost bytes")
	}
}
func TestErrorCodesNeverIncludePrivateTokensOrPaths(t *testing.T) {
	s, path, _ := openTest(t, 1)
	l := reserveTest(t, s, 1)
	s.Begin(l)
	e := s.Export(context.Background(), l, "../../private", digest(nil), bytes.NewReader(nil))
	if e == nil || strings.Contains(e.Error(), path) || strings.Contains(e.Error(), l) || strings.Contains(e.Error(), "../../private") {
		t.Fatal("error leaks metadata")
	}
}
func TestDirectoryCardinalityBound(t *testing.T) {
	s, path, p := openTest(t, 1)
	s.Close()
	for n := 0; n < 140; n++ {
		os.WriteFile(filepath.Join(path, strings.Repeat("x", n+1)), nil, 0600)
	}
	if x, e := Open(context.Background(), path, p); e == nil {
		x.Close()
		t.Fatal("unbounded directory accepted")
	}
}

func TestStrictDepthExactBoundary(t *testing.T) {
	for _, depth := range []int{64, 65} {
		d := json.NewDecoder(strings.NewReader(strings.Repeat("[", depth) + "true" + strings.Repeat("]", depth)))
		d.UseNumber()
		_, e := scanJSON(d, 0)
		if (e == nil) != (depth == 64) {
			t.Fatal("depth boundary")
		}
	}
}
func TestPolicyRejectsInvalidAndUnreviewedGrowth(t *testing.T) {
	for _, mutate := range []func(*Policy){func(p *Policy) { p.GlobalBytes = -1 }, func(p *Policy) { p.GlobalBytes = (1 << 30) + 1 }, func(p *Policy) { p.ExportBytes = (64 << 20) + 1 }, func(p *Policy) { p.Jobs = 65 }, func(p *Policy) { p.PublicationHeadroom = 0 }, func(p *Policy) { p.ArtifactIDs = []string{"normalized_vcf", "normalized_vcf"} }, func(p *Policy) { p.ArtifactIDs = []string{"../path"} }, func(p *Policy) { p.ArtifactIDs = []string{"variants_vcf"} }} {
		p := DefaultPolicy()
		mutate(&p)
		if s, e := Open(context.Background(), filepath.Join(t.TempDir(), "root"), p); e == nil {
			s.Close()
			t.Fatal("invalid policy")
		}
	}
}

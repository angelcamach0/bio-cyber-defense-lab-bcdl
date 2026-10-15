//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package receiptprojection

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func policyFixture(mode string) Policy {
	p := Policy{SchemaVersion: 1, ProfileSHA256: strings.Repeat("a", 64), PipelineMode: mode, CapsuleKind: "native", SourcePins: map[string]SourcePin{}}
	for _, name := range []string{"pipeline", "resource_budget", "analysis_executable", "analysis_rules"} {
		p.SourcePins[name] = SourcePin{SHA256: strings.Repeat("b", 64), Bytes: 1}
	}
	if mode == "variants" {
		for _, name := range []string{"reference", "evaluator", "truth"} {
			p.SourcePins[name] = SourcePin{SHA256: strings.Repeat("c", 64), Bytes: 1}
		}
	}
	return p
}

func TestParsePolicyExternalProfileAndScientificSources(t *testing.T) {
	for _, mode := range []string{"stats", "variants"} {
		for _, kind := range []string{"native", "docker"} {
			p := policyFixture(mode)
			p.CapsuleKind = kind
			raw, _ := json.Marshal(p)
			if _, err := ParsePolicy(context.Background(), raw, p.ProfileSHA256, mode); err != nil {
				t.Fatalf("valid %s/%s: %v", mode, kind, err)
			}
			if _, err := ParsePolicy(context.Background(), raw, strings.Repeat("f", 64), mode); err == nil {
				t.Fatal("policy enrolled its own producer profile")
			}
		}
	}
	p := policyFixture("variants")
	for _, source := range []string{"pipeline", "resource_budget", "analysis_executable", "analysis_rules", "reference", "evaluator", "truth"} {
		t.Run("required_"+source, func(t *testing.T) {
			q := policyFixture("variants")
			delete(q.SourcePins, source)
			raw, _ := json.Marshal(q)
			if _, e := ParsePolicy(context.Background(), raw, p.ProfileSHA256, "variants"); e == nil {
				t.Fatal("missing scientific source accepted")
			}
		})
	}
	for source, limit := range map[string]int64{"pipeline": 1 << 20, "resource_budget": 1 << 20, "analysis_executable": 4 << 20, "analysis_rules": 64 << 10, "reference": 32 << 20, "evaluator": 1 << 20, "truth": 8 << 20, "analysis_panel": 32 << 20} {
		t.Run("limit_"+source, func(t *testing.T) {
			q := policyFixture("variants")
			q.SourcePins[source] = SourcePin{SHA256: strings.Repeat("b", 64), Bytes: limit}
			raw, _ := json.Marshal(q)
			if _, e := ParsePolicy(context.Background(), raw, p.ProfileSHA256, "variants"); e != nil {
				t.Fatal("bounded source rejected", e)
			}
			q.SourcePins[source] = SourcePin{SHA256: strings.Repeat("b", 64), Bytes: limit + 1}
			raw, _ = json.Marshal(q)
			if _, e := ParsePolicy(context.Background(), raw, p.ProfileSHA256, "variants"); e == nil {
				t.Fatal("oversize source accepted")
			}
		})
	}
}

func TestParsePolicyClosedPrivateMetadata(t *testing.T) {
	p := policyFixture("stats")
	raw, _ := json.Marshal(p)
	text := string(raw)
	for name, bad := range map[string][]byte{
		"duplicate":      []byte(strings.Replace(text, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)),
		"case":           []byte(strings.Replace(text, `"schema_version"`, `"Schema_Version"`, 1)),
		"missing_bytes":  []byte(strings.Replace(text, `,"bytes":1`, ``, 1)),
		"nested_unknown": []byte(strings.Replace(text, `"bytes":1`, `"bytes":1,"path":"/private"`, 1)),
		"null_pin":       []byte(strings.Replace(text, `"analysis_rules":{`, `"analysis_rules":null,"unknown":{`, 1)),
		"null_pins":      []byte(strings.Replace(text, `"source_pins":{`, `"source_pins":null,"unknown":{`, 1)),
		"negative":       []byte(strings.Replace(text, `"bytes":1`, `"bytes":-1`, 1)),
		"invalid_hash":   []byte(strings.Replace(text, strings.Repeat("b", 64), strings.Repeat("B", 64), 1)),
		"fraction":       []byte(strings.Replace(text, `"bytes":1`, `"bytes":1.5`, 1)),
		"trailing":       append(append([]byte{}, raw...), []byte(` {}`)...),
		"invalid_utf8":   []byte(strings.Replace(text, `"native"`, "\"nat"+string([]byte{0xff})+"ive\"", 1)),
		"oversize":       []byte(strings.Repeat(" ", 64<<10) + text),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePolicy(context.Background(), bad, p.ProfileSHA256, "stats"); err == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}

func TestDecodeClosedJSONRequiresNestedConfiguration(t *testing.T) {
	type nested struct {
		UID uint32 `json:"uid"`
	}
	type config struct {
		Reader nested               `json:"reader"`
		Pins   map[string]SourcePin `json:"pins"`
	}
	valid := []byte(`{"reader":{"uid":0},"pins":{"source":{"sha256":"x","bytes":0}}}`)
	var c config
	if DecodeClosedJSON(context.Background(), valid, &c) != nil {
		t.Fatal("explicit zero required field rejected")
	}
	for _, bad := range []string{
		`{"reader":{},"pins":{}}`,
		`{"reader":{"uid":null},"pins":{}}`,
		`{"reader":{"uid":0},"pins":{"source":{"sha256":"x"}}}`,
		`{"reader":{"uid":0},"pins":null}`,
		`{"reader":{"uid":0,"UID":0},"pins":{}}`,
		`{"reader":{"uid":0},"pins":{},"x":1}`,
		`{"reader":{"uid":0},"pins":{},"reader":{"uid":0}}`,
		strings.Repeat("[", 70) + "0" + strings.Repeat("]", 70),
	} {
		if DecodeClosedJSON(context.Background(), []byte(bad), &c) == nil {
			t.Fatal("open or incomplete config accepted", bad)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var nilConfig *config
	for _, out := range []any{nil, nilConfig, c} {
		if DecodeClosedJSON(context.Background(), valid, out) == nil {
			t.Fatal("invalid output accepted")
		}
	}
	if DecodeClosedJSON(nil, valid, &c) == nil || DecodeClosedJSON(cancelled, valid, &c) == nil {
		t.Fatal("missing/cancelled context accepted")
	}
}

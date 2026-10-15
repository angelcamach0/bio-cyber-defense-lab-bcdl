//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package receiptprojection

import (
	"context"
	"errors"
	"reflect"
)

// Policy is operator configuration shared by the worker and Results. Its source
// pins describe the producer profile; a receipt cannot enroll its own sources.
// Callers read and measure one anchored snapshot before parsing these bytes.
type Policy struct {
	SchemaVersion int                  `json:"schema_version"`
	ProfileSHA256 string               `json:"profile_sha256"`
	PipelineMode  string               `json:"pipeline_mode"`
	CapsuleKind   string               `json:"capsule_kind"`
	SourcePins    map[string]SourcePin `json:"source_pins"`
}

// DecodeClosedJSON validates exact field names and required nested fields before
// conversion. Unknown/duplicate keys, invalid UTF-8, null scalar/map values,
// trailing JSON, excessive depth and nonfinite numbers are rejected. The caller
// must bound raw before calling; this helper never reads files or authorizes IO.
func DecodeClosedJSON(ctx context.Context, raw []byte, out any) error {
	t := reflect.TypeOf(out)
	if ctx == nil || ctx.Err() != nil || t == nil || t.Kind() != reflect.Ptr || reflect.ValueOf(out).IsNil() {
		return receiptInvalid()
	}
	return receiptDecode(ctx, raw, out)
}

// ParsePolicy preserves the worker's source allowlist and byte limits. It has no
// filesystem or execution authority and never derives expected facts from a
// capsule receipt or a mutable result cache.
func ParsePolicy(ctx context.Context, raw []byte, profile, mode string) (Policy, error) {
	var p Policy
	invalid := errors.New("projection_policy_invalid")
	if len(raw) == 0 || len(raw) > 64<<10 || !ArtifactHex(profile, 64) || DecodeClosedJSON(ctx, raw, &p) != nil || p.SchemaVersion != 1 || p.ProfileSHA256 != profile || p.PipelineMode != mode || (mode != "stats" && mode != "variants") || (p.CapsuleKind != "native" && p.CapsuleKind != "docker") {
		return Policy{}, invalid
	}
	required := map[string]int64{"pipeline": 1 << 20, "resource_budget": 1 << 20, "analysis_executable": 4 << 20, "analysis_rules": 64 << 10}
	optional := map[string]int64{"reference": 32 << 20, "analysis_panel": 32 << 20}
	if mode == "variants" {
		required["reference"], required["evaluator"], required["truth"] = 32<<20, 1<<20, 8<<20
	}
	for name, pin := range p.SourcePins {
		limit, ok := required[name]
		if !ok {
			limit, ok = optional[name]
		}
		if !ok || !ArtifactHex(pin.SHA256, 64) || pin.Bytes < 0 || pin.Bytes > limit {
			return Policy{}, invalid
		}
	}
	for name := range required {
		if _, ok := p.SourcePins[name]; !ok {
			return Policy{}, invalid
		}
	}
	return p, nil
}

// SPDX-License-Identifier: AGPL-3.0-only
package analysis

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// uniqueJSON rejects duplicate keys at every depth, excessive nesting and trailing
// values. Case-sensitive field validation occurs separately at typed boundaries.
func uniqueJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return Code("analysis_request_invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 32 {
			return Code("analysis_request_invalid")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := t.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return err
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return Code("analysis_request_invalid")
					}
					seen[s] = true
					if err := visit(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := visit(depth + 1); err != nil {
						return err
					}
				}
			default:
				return Code("analysis_request_invalid")
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return Code("analysis_request_invalid")
	}
	return nil
}

func exactObject(raw []byte, keys []string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil || len(m) != len(keys) {
		return nil, Code("analysis_request_invalid")
	}
	for _, k := range keys {
		v, ok := m[k]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, Code("analysis_request_invalid")
		}
	}
	return m, nil
}

func DecodeRequest(reader io.Reader) (Request, error) {
	b, err := io.ReadAll(io.LimitReader(reader, MaxJSONBytes+1))
	if err != nil {
		return Request{}, Code("analysis_request_read_failed")
	}
	if len(b) > MaxJSONBytes {
		return Request{}, Code("analysis_request_limit")
	}
	if uniqueJSON(b) != nil {
		return Request{}, Code("analysis_request_invalid")
	}
	// Pipeline may be null (legacy missing metrics), but the field is required.
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil || len(raw) != 3 || raw["schema_version"] == nil || raw["context"] == nil || raw["pipeline"] == nil {
		return Request{}, Code("analysis_request_invalid")
	}
	if _, err := exactObject(raw["context"], []string{"original_name", "processed_size_bytes", "decrypted", "decryption_error", "signature_valid", "signature_error"}); err != nil {
		return Request{}, err
	}
	pipeline := bytes.TrimSpace(raw["pipeline"])
	if !bytes.Equal(pipeline, []byte("null")) && (len(pipeline) == 0 || pipeline[0] != '{') {
		return Request{}, Code("analysis_request_invalid")
	}
	var request Request
	if json.Unmarshal(b, &request) != nil || request.SchemaVersion != 1 || bytes.Equal(bytes.TrimSpace(raw["schema_version"]), []byte("null")) {
		return Request{}, Code("analysis_request_invalid")
	}
	if err := validateContext(request.Context); err != nil {
		return Request{}, err
	}
	return request, nil
}

func validateContext(facts Context) error {
	if facts.ProcessedSizeBytes < 0 || len(facts.OriginalName) > 4096 || len(facts.DecryptionError) > 4096 || len(facts.SignatureError) > 4096 {
		return Code("analysis_context_invalid")
	}
	return nil
}

// LoadRulesStrict is for the pinned CLI. Unlike LoadRules, every diagnostic is
// fatal. It additionally rejects duplicate/unknown/case-alias rule fields.
func LoadRulesStrict(path string) (Rules, error) {
	b, err := readRulesBytes(path)
	if err != nil {
		return Rules{}, err
	}
	if uniqueJSON(b) != nil {
		return Rules{}, Code("rules_parse_error")
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil || raw == nil {
		return Rules{}, Code("rules_parse_error")
	}
	allowed := map[string]bool{}
	for _, k := range []string{"max_size_bytes", "suspicious_name_patterns", "high_score", "low_score", "threat_panel_fasta", "threat_min_reads", "threat_min_fraction", "fastp_min_q30", "critical_warning_score_boost", "high_threshold", "medium_threshold"} {
		allowed[k] = true
	}
	for k, v := range raw {
		if !allowed[k] || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return Rules{}, Code("rules_parse_error")
		}
	}
	var r Rules
	if json.Unmarshal(b, &r) != nil || !finiteRules(r) {
		return Rules{}, Code("rules_parse_error")
	}
	return ApplyRuleDefaults(r), nil
}

func EncodeResponse(response Response) ([]byte, error) {
	b, err := json.Marshal(response)
	if err != nil {
		return nil, Code("analysis_response_invalid")
	}
	if len(b)+1 > MaxJSONBytes {
		return nil, Code("analysis_response_limit")
	}
	return append(b, '\n'), nil
}

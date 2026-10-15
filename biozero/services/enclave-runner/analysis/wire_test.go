// SPDX-License-Identifier: AGPL-3.0-only
package analysis

import (
	"encoding/json"
	"strings"
	"testing"
)

const goodRequest = `{"schema_version":1,"context":{"original_name":"synthetic.fastq","processed_size_bytes":1,"decrypted":true,"decryption_error":"","signature_valid":true,"signature_error":""},"pipeline":{}}`

func TestStrictRequestBoundary(t *testing.T) {
	for _, raw := range []string{goodRequest, goodRequest + strings.Repeat(" ", MaxJSONBytes-len(goodRequest)), strings.Replace(goodRequest, `"pipeline":{}`, `"pipeline":null`, 1)} {
		if _, err := DecodeRequest(strings.NewReader(raw)); err != nil {
			t.Fatal("valid request rejected", err)
		}
	}
	bad := []string{
		goodRequest + "{}", goodRequest + strings.Repeat(" ", MaxJSONBytes-len(goodRequest)+1),
		strings.Replace(goodRequest, `"schema_version":1`, `"schema_version":true`, 1),
		strings.Replace(goodRequest, `"schema_version":1`, `"schema_version":null`, 1),
		strings.Replace(goodRequest, `"schema_version":1`, `"schema_version":1.0`, 1),
		strings.Replace(goodRequest, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		strings.Replace(goodRequest, `"schema_version":1`, `"Schema_Version":1`, 1),
		strings.Replace(goodRequest, `"decrypted":true`, `"decrypted":null`, 1),
		strings.Replace(goodRequest, `"decrypted":true`, `"decrypted":1`, 1),
		strings.Replace(goodRequest, `"signature_error":""`, `"signature_error":"","path":"/sensitive"`, 1),
		strings.Replace(goodRequest, `"processed_size_bytes":1`, `"processed_size_bytes":-1`, 1),
		strings.Replace(goodRequest, `"pipeline":{}`, `"pipeline":{"a":{"b":1,"b":2}}`, 1),
		strings.Replace(goodRequest, `"pipeline":{}`, `"pipeline":[]`, 1),
		strings.Replace(goodRequest, `"pipeline":{}`, `"pipeline":`+strings.Repeat(`{"n":`, 34)+`0`+strings.Repeat(`}`, 34), 1),
		strings.Replace(goodRequest, `"context":{`, `"context":{"Original_Name":"alias",`, 1),
		strings.Replace(goodRequest, `"pipeline":{}`, `"pipeline":{},"content_path":"/sensitive"`, 1),
	}
	for i, raw := range bad {
		if _, err := DecodeRequest(strings.NewReader(raw)); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
}

func TestBoundedResponseWorstTargetsAndNoTruncation(t *testing.T) {
	a := AlignmentStats{TotalReads: 128, MappedReads: 128, Targets: map[string]int{}}
	for i := 0; i < 128; i++ {
		key := string(rune(33+i%90)) + string(rune(33+i/90)) + strings.Repeat(`"`, 126)
		a.Targets[key] = 1
	}
	r := DefaultRules()
	r.ThreatPanelFasta = "trusted"
	result, err := Score(Context{}, r, nil, &a)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncodeResponse(Response{SchemaVersion: 1, Status: "succeeded", Warnings: []string{}, Detection: &result})
	if err != nil || len(b) > MaxJSONBytes || !json.Valid(b) {
		t.Fatal("maximum valid targets exceed wire budget")
	}
	if _, err := EncodeResponse(Response{ErrorCode: strings.Repeat("x", MaxJSONBytes)}); err != Code("analysis_response_limit") {
		t.Fatal("response truncated or unbounded")
	}
}

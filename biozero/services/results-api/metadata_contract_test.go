package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// These coordinator-owned vectors freeze the cross-service contract separately
// from either implementation. Parser validity never grants authorization/science.
func TestSharedMetadataContract(t *testing.T) {
	data, err := os.ReadFile("../../docs/security/metadata-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		SchemaVersion int `json:"schema_version"`
		Cases         []struct {
			Name  string `json:"name"`
			Kind  string `json:"kind"`
			JSON  string `json:"json"`
			Valid bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &contract); err != nil || contract.SchemaVersion != 1 || len(contract.Cases) != 54 {
		t.Fatalf("invalid shared contract: %v", err)
	}
	for _, c := range contract.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var err error
			switch c.Kind {
			case "job":
				_, err = parseJob([]byte(c.JSON))
			case "result":
				_, err = parseResult([]byte(c.JSON))
			default:
				t.Fatal("unknown contract record kind")
			}
			if (err == nil) != c.Valid {
				t.Fatalf("expected valid=%v, got %v", c.Valid, err)
			}
		})
	}
}

func TestForeignOwnedMetadataAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("The fixture requires root to isolate UID rejection from read permissions; normal service tests stay non-root")
	}
	path := filepath.Join(t.TempDir(), "foreign.json")
	if err := os.WriteFile(path, []byte(`{"job_id":"abcd1234","status":"uploaded"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, -1); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != 65534 {
		t.Fatal("foreign-owner fixture not established")
	}
	if _, err := readRecord(path, maxJobBytes); err == nil || isMissingRecord(err) {
		t.Fatal("foreign owned metadata accepted or misclassified as missing")
	}
}

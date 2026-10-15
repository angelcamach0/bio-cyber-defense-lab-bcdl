//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicationCommandArgumentsAreClosed(t *testing.T) {
	for _, args := range [][]string{nil, {"--unknown"}, {"--config"}, {"--config", "/not/read", "extra"}} {
		var out, err bytes.Buffer
		code, service := run(context.Background(), args, &out, &err)
		if code != 2 || service != nil || out.Len() != 0 || err.String() != "ownership_publication_arguments_invalid\n" {
			t.Fatal("arguments accepted or diagnostic leaked")
		}
	}
}
func TestPublicationCommandInvalidConfigDoesNotInitialize(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"signing_key":"not-allowed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, err bytes.Buffer
	code, service := run(context.Background(), []string{"--config", path, "--init-store"}, &out, &err)
	if code != 1 || service != nil || out.Len() != 0 || err.String() != "ownership_publication_config_invalid\n" {
		t.Fatal("configuration fallback or leak")
	}
	names, readErr := os.ReadDir(root)
	if readErr != nil || len(names) != 1 {
		t.Fatal("invalid config initialized state")
	}
}

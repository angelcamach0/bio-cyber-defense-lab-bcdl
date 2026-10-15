//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOwnerUploadRuntimeRejectsArgumentsWithoutLegacyFallback(t *testing.T) {
	for _, args := range [][]string{{"--unexpected"}, {"--init-owner-ingress", "extra"}, nil} {
		var out, stderr bytes.Buffer
		code, service := runOwnerUpload(context.Background(), args, "", &out, &stderr)
		if code == 0 || service != nil || out.Len() != 0 || !strings.Contains(stderr.String(), "arguments_invalid") {
			t.Fatal("runtime accepted invalid arguments")
		}
	}
}
func TestOwnerUploadSelectorProcessHelper(t *testing.T) {
	if os.Getenv("BIOZERO_OWNER_SELECTOR_HELPER") != "1" {
		t.Skip("owned selector process helper")
	}
	if os.Getenv("BIOZERO_OWNER_SELECTOR_INIT") == "1" {
		os.Args = []string{os.Args[0], "--init-owner-ingress=false"}
	} else {
		os.Args = []string{os.Args[0]}
	}
	if !dispatchOwnerUpload() {
		os.Exit(94)
	}
}
func TestOwnerUploadSelectorRejectsUnknownBeforeLegacyState(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"unknown", "owner missing config", "legacy init flag"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "must-remain-absent")
			protocol := "owner-v1"
			initFlag := "0"
			if kind == "unknown" {
				protocol = "unrecognized"
			}
			if kind == "legacy init flag" {
				protocol = "legacy"
				initFlag = "1"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestOwnerUploadSelectorProcessHelper$")
			cmd.Env = append(os.Environ(), "BIOZERO_OWNER_SELECTOR_HELPER=1", "BIOZERO_OWNER_SELECTOR_INIT="+initFlag, "BIOZERO_UPLOAD_PROTOCOL="+protocol, "BIOZERO_OWNER_UPLOAD_CONFIG=", "BIOZERO_DATA_DIR="+root)
			out, err := cmd.CombinedOutput()
			if err == nil || ctx.Err() != nil || !bytes.Contains(out, []byte("ownership_ingress_")) {
				t.Fatal("selector did not fail closed", err, string(out))
			}
			if _, err = os.Stat(root); !os.IsNotExist(err) {
				t.Fatal("selector initialized legacy state")
			}
			if bytes.Contains(out, []byte(root)) {
				t.Fatal("selector leaked paths")
			}
		})
	}
}

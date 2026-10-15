// SPDX-License-Identifier: AGPL-3.0-only
// capsule-analysis is a local pinned executable, not a network service.
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"biozero/enclave-runner/analysis"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout)
	stop()
	os.Exit(code)
}

func safePath(path string) bool {
	return len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func run(ctx context.Context, args []string, input io.Reader, output io.Writer) int {
	fail := func(code string) int {
		return emit(output, analysis.Response{SchemaVersion: 1, Status: "failed", ErrorCode: code, Warnings: []string{}}, 1)
	}
	// Exact argv is supplied by trusted host configuration; stdin cannot select
	// paths, rules, limits, executable names or additional command arguments.
	if len(args) != 6 || args[0] != "--rules" || args[2] != "--panel" || args[4] != "--content" || !safePath(args[1]) || (args[3] != "" && !safePath(args[3])) || !safePath(args[5]) {
		return fail("analysis_config_invalid")
	}
	rules, err := analysis.LoadRulesStrict(args[1])
	if err != nil {
		return fail(stableCode(err))
	}
	// Preserve the configured presence of detection. Host argv may remap a
	// nonempty panel path, but cannot enable or disable that analysis silently.
	if (rules.ThreatPanelFasta == "") != (args[3] == "") {
		return fail("analysis_panel_config_mismatch")
	}
	// File contents never choose the capsule's path mapping.
	rules.ThreatPanelFasta = args[3]
	request, err := analysis.DecodeRequest(input)
	if err != nil {
		return fail(stableCode(err))
	}
	detection, err := analysis.Evaluate(ctx, request.Context, rules, request.Pipeline, args[5])
	if err != nil {
		return fail(stableCode(err))
	}
	return emit(output, analysis.Response{SchemaVersion: 1, Status: "succeeded", Warnings: []string{}, Detection: &detection}, 0)
}

func stableCode(err error) string {
	if code, ok := err.(analysis.Code); ok {
		return string(code)
	}
	return "analysis_failed"
}

func emit(output io.Writer, response analysis.Response, exit int) int {
	b, err := analysis.EncodeResponse(response)
	if err != nil {
		b = []byte("{\"schema_version\":1,\"status\":\"failed\",\"error_code\":\"analysis_response_limit\",\"warnings\":[],\"detection\":null}\n")
		exit = 1
	}
	n, err := output.Write(b)
	if err != nil || n != len(b) {
		return 1
	}
	return exit
}

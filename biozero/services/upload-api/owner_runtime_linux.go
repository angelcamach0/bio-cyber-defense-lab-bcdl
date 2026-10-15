//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	ownership "biozero/ownership-authority"
)

// Uncertain transport custody remains anchored until real process death.
var ownerUploadCustody *ownership.OwnerIngressService

func runOwnerUpload(ctx context.Context, args []string, path string, out, stderr io.Writer) (int, *ownership.OwnerIngressService) {
	flags := flag.NewFlagSet("upload-api owner-v1", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	initialize := flags.Bool("init-owner-ingress", false, "create a fresh transport spool only")
	if ctx == nil || flags.Parse(args) != nil || flags.NArg() != 0 || path == "" {
		fmt.Fprintln(stderr, "ownership_ingress_arguments_invalid")
		return 2, nil
	}
	config, err := ownership.LoadOwnerIngressServiceConfig(ctx, path)
	if err != nil {
		fmt.Fprintln(stderr, "ownership_ingress_config_invalid")
		return 1, nil
	}
	if *initialize {
		if err = ownership.InitializeOwnerIngress(ctx, config); err != nil {
			fmt.Fprintln(stderr, "ownership_ingress_init_failed")
			return 1, nil
		}
		raw, _ := json.Marshal(struct {
			SchemaVersion int    `json:"schema_version"`
			State         string `json:"state"`
		}{1, "initialized"})
		if n, e := fmt.Fprintln(out, string(raw)); e != nil || n != len(raw)+1 {
			fmt.Fprintln(stderr, "ownership_ingress_init_delivery_failed")
			return 1, nil
		}
		return 0, nil
	}
	service, err := ownership.OpenOwnerIngressService(ctx, config)
	if err != nil {
		fmt.Fprintln(stderr, "ownership_ingress_start_failed")
		return 1, service
	}
	const ready = "ownership_ingress_ready\n"
	if n, e := io.WriteString(out, ready); e != nil || n != len(ready) {
		fmt.Fprintln(stderr, "ownership_ingress_readiness_failed")
		_ = service.Shutdown(context.Background())
		return 1, service
	}
	serveErr := service.Serve(ctx)
	if err = service.Shutdown(context.Background()); err != nil {
		fmt.Fprintln(stderr, "ownership_ingress_pending")
		return 1, service
	}
	if serveErr != nil {
		fmt.Fprintln(stderr, "ownership_ingress_serve_failed")
		return 1, service
	}
	return 0, service
}

// dispatchOwnerUpload executes before all legacy setup. Unknown selectors and
// owner configuration errors cannot initialize, serve or fall back to legacy.
func dispatchOwnerUpload() bool {
	protocol := os.Getenv("BIOZERO_UPLOAD_PROTOCOL")
	if protocol == "" || protocol == "legacy" {
		for _, arg := range os.Args[1:] {
			if arg == "--init-owner-ingress" || strings.HasPrefix(arg, "--init-owner-ingress=") {
				fmt.Fprintln(os.Stderr, "ownership_ingress_protocol_required")
				os.Exit(2)
			}
		}
		return false
	}
	if protocol != "owner-v1" {
		fmt.Fprintln(os.Stderr, "ownership_ingress_protocol_invalid")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code, service := runOwnerUpload(ctx, os.Args[1:], os.Getenv("BIOZERO_OWNER_UPLOAD_CONFIG"), os.Stdout, os.Stderr)
	ownerUploadCustody = service
	stop()
	if code != 0 {
		os.Exit(code)
	}
	return true
}

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
	"syscall"

	ownership "biozero/ownership-authority"
)

// Retain uncertain service custody until actual process exit. No retry or
// historical adoption is attempted after any startup/shutdown failure.
var serviceCustody *ownership.AuthorityService

func run(ctx context.Context, args []string, stdout, stderr io.Writer) (int, *ownership.AuthorityService) {
	flags := flag.NewFlagSet("ownership-authority", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "private absolute configuration path")
	initialize := flags.Bool("init-store", false, "create fresh genesis only; emit external scope and exit")
	if ctx == nil || flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" {
		fmt.Fprintln(stderr, "ownership_service_arguments_invalid")
		return 2, nil
	}
	config, err := ownership.LoadAuthorityServiceConfig(ctx, *path)
	if err != nil {
		fmt.Fprintln(stderr, "ownership_service_config_invalid")
		return 1, nil
	}
	if *initialize {
		scope, err := ownership.InitializeAuthorityStore(ctx, config)
		if err != nil {
			fmt.Fprintln(stderr, "ownership_service_init_failed")
			return 1, nil
		}
		raw, _ := json.Marshal(scope)
		if n, writeErr := fmt.Fprintln(stdout, string(raw)); writeErr != nil || n != len(raw)+1 {
			fmt.Fprintln(stderr, "ownership_service_scope_delivery_failed")
			return 1, nil
		}
		return 0, nil
	}
	service, err := ownership.OpenAuthorityService(ctx, config)
	if err != nil {
		fmt.Fprintln(stderr, "ownership_service_start_failed")
		return 1, service
	}
	if n, writeErr := fmt.Fprintln(stdout, "ownership_service_ready"); writeErr != nil || n != len("ownership_service_ready\n") {
		fmt.Fprintln(stderr, "ownership_service_readiness_failed")
		service.Shutdown(context.Background())
		return 1, service
	}
	serveErr := service.Serve(ctx)
	if err = service.Shutdown(context.Background()); err != nil {
		fmt.Fprintln(stderr, "ownership_service_pending")
		return 1, service
	}
	if serveErr != nil {
		fmt.Fprintln(stderr, "ownership_service_serve_failed")
		return 1, service
	}
	return 0, service
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code, service := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	serviceCustody = service
	stop()
	os.Exit(code)
}

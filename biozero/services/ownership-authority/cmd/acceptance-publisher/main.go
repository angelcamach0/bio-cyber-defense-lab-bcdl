//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	ownership "biozero/ownership-authority"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// Uncertain publication custody remains reachable until actual process exit.
var serviceCustody *ownership.PublicationService

func run(ctx context.Context, args []string, stdout, stderr io.Writer) (int, *ownership.PublicationService) {
	flags := flag.NewFlagSet("acceptance-publisher", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "private absolute configuration path")
	initialize := flags.Bool("init-store", false, "create fresh publication genesis and print its external scope")
	if ctx == nil || flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" {
		fmt.Fprintln(stderr, "ownership_publication_arguments_invalid")
		return 2, nil
	}
	config, err := ownership.LoadPublicationServiceConfig(ctx, *path)
	if err != nil {
		fmt.Fprintln(stderr, "ownership_publication_config_invalid")
		return 1, nil
	}
	if *initialize {
		scope, err := ownership.InitializePublicationStore(ctx, config)
		if err != nil {
			fmt.Fprintln(stderr, "ownership_publication_init_failed")
			return 1, nil
		}
		raw, _ := json.Marshal(scope)
		if n, err := fmt.Fprintln(stdout, string(raw)); err != nil || n != len(raw)+1 {
			fmt.Fprintln(stderr, "ownership_publication_scope_delivery_failed")
			return 1, nil
		}
		return 0, nil
	}
	service, err := ownership.OpenPublicationService(ctx, config)
	if err != nil {
		fmt.Fprintln(stderr, "ownership_publication_start_failed")
		return 1, service
	}
	if n, err := fmt.Fprintln(stdout, "ownership_publication_ready"); err != nil || n != len("ownership_publication_ready\n") {
		fmt.Fprintln(stderr, "ownership_publication_readiness_failed")
		service.Shutdown(context.Background())
		return 1, service
	}
	serveErr := service.Serve(ctx)
	closeErr := service.Shutdown(context.Background())
	if closeErr != nil {
		fmt.Fprintln(stderr, "ownership_publication_pending")
		return 1, service
	}
	if serveErr != nil {
		fmt.Fprintln(stderr, "ownership_publication_serve_failed")
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

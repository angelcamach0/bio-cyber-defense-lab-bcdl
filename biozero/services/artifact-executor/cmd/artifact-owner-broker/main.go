//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	artifact "biozero/artifact-executor"
)

var custody *artifact.BrokerService

func run(ctx context.Context, args []string, out, stderr io.Writer) (int, *artifact.BrokerService) {
	flags := flag.NewFlagSet("artifact-owner-broker", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "private fixed configuration")
	profileOnly := flags.Bool("print-profile", false, "verify assets and print owner profile without state")
	initialize := flags.Bool("init-owner-broker", false, "create new empty Store and owner journal, never serve")
	if ctx == nil || flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" || (*profileOnly && *initialize) {
		fmt.Fprintln(stderr, "artifact_owner_service_arguments_invalid")
		return 2, nil
	}
	c, e := artifact.LoadOwnerBrokerServiceConfig(ctx, *path)
	if e != nil {
		fmt.Fprintln(stderr, "artifact_owner_service_config_invalid")
		return 1, nil
	}
	if *profileOnly {
		profile, e := artifact.OwnerBrokerServiceProfile(ctx, c)
		if e != nil {
			fmt.Fprintln(stderr, "artifact_owner_service_profile_failed")
			return 1, nil
		}
		if n, e := fmt.Fprintln(out, profile); e != nil || n != len(profile)+1 {
			return 1, nil
		}
		return 0, nil
	}
	var service *artifact.BrokerService
	if *initialize {
		service, e = artifact.InitializeOwnerBrokerService(ctx, c)
	} else {
		service, e = artifact.OpenOwnerBrokerService(ctx, c)
	}
	if e != nil {
		fmt.Fprintln(stderr, "artifact_owner_service_start_failed")
		return 1, service
	}
	var serveErr error
	if !*initialize {
		serveErr = service.Serve(ctx)
	}
	budget, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if e = service.Shutdown(budget); e != nil {
		fmt.Fprintln(stderr, "artifact_owner_service_pending")
		return 1, service
	}
	if serveErr != nil {
		fmt.Fprintln(stderr, "artifact_owner_service_serve_failed")
		return 1, service
	}
	if *initialize {
		const message = "{\"schema_version\":1,\"state\":\"initialized\"}\n"
		if n, e := io.WriteString(out, message); e != nil || n != len(message) {
			return 1, service
		}
	}
	return 0, service
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code, service := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	custody = service
	stop()
	os.Exit(code)
}

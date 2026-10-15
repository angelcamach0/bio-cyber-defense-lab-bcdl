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

// Keep any uncertain startup/shutdown custody reachable for the whole process
// lifetime. Exiting does not erase durable pending history or authorize retry.
var serviceCustody *artifact.BrokerService

func run(ctx context.Context, args []string, stdout, stderr io.Writer) (int, *artifact.BrokerService) {
	flags := flag.NewFlagSet("artifact-broker", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "private absolute configuration path")
	printProfile := flags.Bool("print-profile", false, "verify configuration/assets and print only the computed profile")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *configPath == "" {
		fmt.Fprintln(stderr, "artifact_service_arguments_invalid")
		return 2, nil
	}
	cfg, err := artifact.LoadBrokerServiceConfig(ctx, *configPath)
	if err != nil {
		fmt.Fprintln(stderr, "artifact_service_config_invalid")
		return 1, nil
	}
	if *printProfile {
		profile, err := artifact.BrokerServiceProfile(ctx, cfg)
		if err != nil {
			fmt.Fprintln(stderr, "artifact_service_profile_failed")
			return 1, nil
		}
		if _, err = fmt.Fprintln(stdout, profile); err != nil {
			return 1, nil
		}
		return 0, nil
	}
	service, err := artifact.OpenBrokerService(ctx, cfg)
	if err != nil {
		fmt.Fprintln(stderr, "artifact_service_start_failed")
		return 1, service
	}
	serveErr := service.Serve(ctx)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err = service.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintln(stderr, "artifact_service_pending")
		return 1, service
	}
	if serveErr != nil {
		fmt.Fprintln(stderr, "artifact_service_serve_failed")
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

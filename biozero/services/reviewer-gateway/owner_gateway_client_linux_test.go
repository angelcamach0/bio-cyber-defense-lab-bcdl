//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ownership "biozero/ownership-authority"
)

// Real authority/client crypto and real upload-side mTLS, with an intentional
// protocol-fixture upload failure. This is not capsule/scientific acceptance.
func TestOwnerGatewayClientBusyReleaseAndUncertainCommitAxes(t *testing.T) {
	f := ogNewConfigFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	upload := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/uploads" {
			http.Error(w, "fixture", 404)
			return
		}
		if _, err := ownership.PrincipalFromTLS(r.TLS); err != nil {
			http.Error(w, "fixture", 403)
			return
		}
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		http.Error(w, "fixture delivery response unavailable", 503)
	}))
	upload.TLS = f.serverTLS.Clone()
	upload.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	upload.StartTLS()
	defer upload.Close()
	f.config.UploadURL = upload.URL
	ogWriteConfig(t, f.path, f.config)
	m, err := loadOwnerGatewayConfig(context.Background(), f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer ogCloseMaterial(m)
	s := ogRegistryOpen(t, m)
	row, _, err := s.Intent(context.Background(), "a", "synthetic", strings.Repeat("1", 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Execute(ctx, row.RunID) }()
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("upload barrier never reached: %v", err)
	case <-ctx.Done():
		t.Fatal("upload barrier timeout")
	}
	start := time.Now()
	pending, err := s.Run(context.Background(), "a", row.RunID)
	if err != nil || pending.Phase != "delivering" || pending.AcceptanceSHA256 == "" {
		t.Fatal("local operation summary unavailable", pending.Phase, err)
	}
	called := false
	if err = s.GuardRun(context.Background(), "a", pending, func() error { called = true; return nil }); err == nil || called || s.sticky {
		t.Fatal("busy custody released report or poisoned history", err)
	}
	if err = s.GuardRunCurrent(context.Background(), "a", row.RunID, func(current ownerGatewayRun) error {
		if current.RunID != row.RunID || current.Phase != "delivering" {
			t.Fatal("local identity changed")
		}
		return nil
	}); err != nil {
		t.Fatal("bounded local summary denied", err)
	}
	if _, fresh, err := s.Intent(context.Background(), "b", "synthetic", strings.Repeat("2", 32)); err != nil || !fresh {
		t.Fatal("slow peer blocked second admission", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("registry waited on upstream client mutex")
	}
	close(release)
	released = true
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("failed delivery reported success")
		}
	case <-ctx.Done():
		t.Fatal("Execute did not join")
	}
	pending, err = s.Run(context.Background(), "a", row.RunID)
	if err != nil || pending.Phase != "delivering" || pending.ErrorCode != "owner_gateway_operation_uncertain" || pending.Commit != nil {
		t.Fatal("uncertain transport relabeled", err)
	}
	committed := ogProtocolResult(pending)
	observed, err := s.ObserveResult(context.Background(), row.RunID, committed)
	if err != nil || observed.Commit == nil || observed.Phase != "delivering" || observed.ErrorCode != pending.ErrorCode {
		t.Fatal("Results observation erased transport uncertainty", err)
	}
	if _, err = s.ObserveResult(context.Background(), row.RunID, ogPendingResult(pending)); err == nil || s.sticky {
		t.Fatal("stale concurrent pending observation poisoned custody")
	}
	if _, err = s.ObserveResult(context.Background(), row.RunID, committed); err != nil {
		t.Fatal("equal committed observation not idempotent", err)
	}
	if s.ledger.RetainedBytes != 2*ownerGatewayRunCharge || len(s.ledger.Runs) != 2 {
		t.Fatal("terminal observation refunded retained promises")
	}
	first := s.Close()
	if first == nil || first.Error() != "ownership_delivery_pending" {
		t.Fatal("uncertain delivery Close reported healthy", first)
	}
	if again := s.Close(); again == nil || again.Error() != first.Error() {
		t.Fatal("first shutdown error disappeared", again)
	}
}

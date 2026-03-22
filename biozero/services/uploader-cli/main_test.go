package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchResultsSendsClientIDHeader(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Client-Id"); got != "researcher-1" {
			t.Fatalf("expected X-Client-Id header researcher-1, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer server.Close()

	status, payload, err := fetchResults(server.Client(), server.URL+"/results", "job-123", "researcher-1")
	if err != nil {
		t.Fatalf("fetchResults returned error: %v", err)
	}
	if status != "pending" {
		t.Fatalf("expected status pending, got %q", status)
	}
	if payload != "" {
		t.Fatalf("expected empty payload for pending response, got %q", payload)
	}
}

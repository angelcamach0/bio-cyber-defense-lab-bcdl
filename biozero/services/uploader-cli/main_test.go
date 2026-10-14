package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPollingDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"status":"running"}`) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, _, err := pollResults(ctx, server.Client(), server.URL, "abcd1234", time.Millisecond, 2)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
func TestPollingDeadlineCancelsHTTPRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, _, err := pollResults(ctx, server.Client(), server.URL, "abcd1234", time.Millisecond, 2)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
func TestPollingTerminalCodes(t *testing.T) {
	for status, expected := range map[string]int{"succeeded": 0, "incomplete": 2, "processed": 2, "rejected": 3, "failed": 3, "timed_out": 4} {
		t.Run(status, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"status":%q,"data":{"status":%q}}`, status, status)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, _, err := pollResults(ctx, server.Client(), server.URL, "abcd1234", time.Millisecond, 2)
			if err != nil {
				t.Fatal(err)
			}
			code, terminal := terminalExitCode(got)
			if code != expected || !terminal {
				t.Fatal(got, code)
			}
		})
	}
}
func TestForbiddenDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(403) }))
	defer server.Close()
	_, _, err := pollResults(context.Background(), server.Client(), server.URL, "abcd1234", time.Millisecond, 5)
	if err == nil || calls.Load() != 1 {
		t.Fatal(err, calls.Load())
	}
}
func TestUnknownStatusFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"status":"banana"}`) }))
	defer server.Close()
	_, _, err := pollResults(context.Background(), server.Client(), server.URL, "abcd1234", time.Millisecond, 2)
	if err == nil {
		t.Fatal("unknown status accepted")
	}
}

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func verifiedRequest(owner string, serial int64) *http.Request {
	r := httptest.NewRequest("GET", "/results/abcd1234", nil)
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: owner}}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	return r
}
func apiFixture(t *testing.T) (string, string, http.Handler) {
	t.Helper()
	root := t.TempDir()
	jobs := filepath.Join(root, "jobs")
	results := filepath.Join(root, "results")
	os.Mkdir(jobs, 0700)
	os.Mkdir(results, 0700)
	data, _ := json.Marshal(jobRecord{JobID: "abcd1234", Status: "uploaded", ClientID: "researcher-a", ClientCertSerial: "1"})
	os.WriteFile(filepath.Join(jobs, "abcd1234.json"), data, 0600)
	return jobs, results, newResultsHandler(jobs, results, newRateLimiter(100, time.Minute))
}
func TestAuthorizationRequiresCertificateAndOwner(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	job := jobRecord{ClientID: "researcher-a", ClientCertSerial: "1"}
	a := verifiedRequest("researcher-a", 1)
	if !authorizedJob(a, job) {
		t.Fatal("owner denied")
	}
	for _, r := range []*http.Request{verifiedRequest("researcher-b", 2), verifiedRequest("researcher-b", 1), httptest.NewRequest("GET", "/", nil)} {
		r.Header.Set("X-Client-Id", "researcher-a")
		if authorizedJob(r, job) {
			t.Fatal("non-owner permitted")
		}
	}
	a.TLS.VerifiedChains = nil
	if authorizedJob(a, job) {
		t.Fatal("unverified certificate permitted")
	}
	a = verifiedRequest("researcher-a", 1)
	job.ClientCertSerial = ""
	if authorizedJob(a, job) {
		t.Fatal("TLS job without binding used header fallback")
	}
}
func TestResultsExposeSavedStatusesAndLegacy(t *testing.T) {
	for _, status := range []string{"succeeded", "incomplete", "rejected", "failed", "timed_out", "processed"} {
		t.Run(status, func(t *testing.T) {
			_, results, h := apiFixture(t)
			data, _ := json.Marshal(map[string]string{"job_id": "abcd1234", "status": status})
			os.WriteFile(filepath.Join(results, "abcd1234.json"), data, 0600)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, verifiedRequest("researcher-a", 1))
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			var response resultResponse
			json.Unmarshal(w.Body.Bytes(), &response)
			expected := status
			if status == "processed" {
				expected = "incomplete"
				if response.LegacyStatus != "processed" || response.ErrorCode != "legacy_result_unverified" {
					t.Fatal(response)
				}
			}
			if response.Status != expected {
				t.Fatal(response)
			}
		})
	}
}
func TestResultsDenyBAndReportCorruption(t *testing.T) {
	jobs, results, h := apiFixture(t)
	os.WriteFile(filepath.Join(results, "abcd1234.json"), []byte(`{"job_id":"abcd1234","status":"succeeded"}`), 0600)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, verifiedRequest("researcher-b", 2))
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	os.WriteFile(filepath.Join(results, "abcd1234.json"), []byte("broken"), 0600)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, verifiedRequest("researcher-a", 1))
	if w.Code != 500 {
		t.Fatal(w.Code)
	}
	os.WriteFile(filepath.Join(jobs, "abcd1234.json"), []byte("broken"), 0600)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, verifiedRequest("researcher-a", 1))
	if w.Code != 500 {
		t.Fatal(w.Code)
	}
}
func TestProtectedServerRequiresCompleteTLS(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	for _, cfg := range [][3]string{{"", "", ""}, {"cert", "key", ""}, {"cert", "", "ca"}} {
		if validateServerSecurity(cfg[0], cfg[1], cfg[2]) == nil {
			t.Fatal("incomplete TLS accepted")
		}
	}
	if validateServerSecurity("cert", "key", "ca") != nil {
		t.Fatal("complete configuration rejected")
	}
}
func TestPendingAndTerminalJobStates(t *testing.T) {
	for _, status := range []string{"uploaded", "running", "failed", "rejected", "timed_out"} {
		t.Run(status, func(t *testing.T) {
			jobs, _, h := apiFixture(t)
			job := jobRecord{JobID: "abcd1234", Status: status, ClientID: "researcher-a", ClientCertSerial: "1", ErrorCode: "failure_reason"}
			data, _ := json.Marshal(job)
			os.WriteFile(filepath.Join(jobs, "abcd1234.json"), data, 0600)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, verifiedRequest("researcher-a", 1))
			var response resultResponse
			json.Unmarshal(w.Body.Bytes(), &response)
			if w.Code != 200 || response.Status != status {
				t.Fatal(w.Code, response)
			}
		})
	}
}
func TestResultReadErrorDoesNotBecomePending(t *testing.T) {
	_, results, h := apiFixture(t)
	os.Mkdir(filepath.Join(results, "abcd1234.json"), 0700)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, verifiedRequest("researcher-a", 1))
	if w.Code != 500 {
		t.Fatal(w.Code, w.Body.String())
	}
}

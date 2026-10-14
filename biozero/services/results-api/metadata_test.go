package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func completeResult(t *testing.T, status string) []byte {
	t.Helper()
	b, err := json.Marshal(resultRecord{SchemaVersion: 1, JobID: "abcd1234", Status: status})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func writeFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func requestCode(t *testing.T, h http.Handler, req *http.Request, status int, code string) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != status {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if code != "" {
		var e errorResponse
		if json.Unmarshal(w.Body.Bytes(), &e) != nil || e.Code != code {
			t.Fatalf("wrong error: %s", w.Body.String())
		}
	}
}
func TestHTTPUnsafeMetadataAndNextValidRequest(t *testing.T) {
	for _, kind := range []string{"job", "result"} {
		for _, fault := range []string{"fifo", "symlink_final", "symlink_parent", "symlink_ancestor", "directory", "permissions", "sticky", "sparse_oversize"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				jobs, results, h := apiFixture(t)
				authJobs := jobs
				writeFixture(t, filepath.Join(results, "abcd1234.json"), completeResult(t, "succeeded"))
				dir := jobs
				cap := maxJobBytes
				if kind == "result" {
					dir = results
					cap = maxResultBytes
				}
				path := filepath.Join(dir, "abcd1234.json")
				saved, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "fifo":
					os.Remove(path)
					if err := syscall.Mkfifo(path, 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink_final":
					os.Remove(path)
					target := filepath.Join(t.TempDir(), "private.json")
					writeFixture(t, target, saved)
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				case "symlink_parent":
					real := dir + "-real"
					if err := os.Rename(dir, real); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(real, dir); err != nil {
						t.Fatal(err)
					}
					defer func() { os.Remove(dir); os.Rename(real, dir) }()
				case "symlink_ancestor":
					real := filepath.Dir(dir)
					alias := filepath.Join(t.TempDir(), "alias")
					if err := os.Symlink(real, alias); err != nil {
						t.Fatal(err)
					}
					if kind == "job" {
						authJobs = filepath.Join(alias, "jobs")
						h = newResultsHandler(authJobs, results, newRateLimiter(0, time.Minute))
					} else {
						h = newResultsHandler(jobs, filepath.Join(alias, "results"), newRateLimiter(0, time.Minute))
					}
				case "directory":
					os.Remove(path)
					if err := os.Mkdir(path, 0600); err != nil {
						t.Fatal(err)
					}
				case "permissions":
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				case "sticky":
					if err := os.Chmod(path, 0600|os.ModeSticky); err != nil {
						t.Fatal(err)
					}
				case "sparse_oversize":
					f, err := os.OpenFile(path, os.O_WRONLY, 0600)
					if err != nil {
						t.Fatal(err)
					}
					if err = f.Truncate(cap + 1); err != nil {
						t.Fatal(err)
					}
					f.Close()
				}
				if kind == "result" {
					requestCode(t, h, verifiedRequest("researcher-b", 2), 403, "forbidden")
				}
				requestCode(t, h, verifiedRequest("researcher-a", 1), 500, kind+"_read_failed")
				if authorizedForJob(verifiedRequest("researcher-a", 1), authJobs, "abcd1234") && kind == "job" {
					t.Fatal("unsafe job authorized")
				}
				// Reset request paths and restore an ordinary record; faults cannot poison later requests.
				if fault == "symlink_parent" {
					real := dir + "-real"
					os.Remove(dir)
					os.Rename(real, dir)
				}
				if fault != "symlink_ancestor" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					writeFixture(t, path, saved)
				}
				h = newResultsHandler(jobs, results, newRateLimiter(0, time.Minute))
				requestCode(t, h, verifiedRequest("researcher-a", 1), 200, "")
			})
		}
	}
}
func TestHTTPStrictContractsAndCompatibility(t *testing.T) {
	valid := string(completeResult(t, "succeeded"))
	cases := []struct{ kind, data string }{
		{"job", `{"job_id":"abcd1234","status":"uploaded","client_id":"a","client_id":"b"}`},
		{"job", `{"job_id":"abcd1234","status":"uploaded","Client_id":"researcher-a"}`},
		{"job", `{"job_id":"abcd1234","status":"uploaded","client_cert_serial":null}`},
		{"job", `{"job_id":"abcd1234","status":"alien"}`},
		{"job", `{"job_id":"abcd1234","status":"uploaded","size_bytes":"1"}`},
		{"result", strings.TrimSuffix(valid, "}") + `,"status":"failed"}`},
		{"result", strings.Replace(valid, `"status"`, `"Status"`, 1)},
		{"result", valid + ` {}`},
		{"result", `{"schema_version":1,"job_id":"abcd1234","status":"succeeded"}`},
		{"result", strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1)},
		{"result", strings.Replace(valid, `"schema_version":1`, `"schema_version":null`, 1)},
		{"result", strings.Replace(valid, `"detection":{"score":0,"reason":""}`, `"detection":{"Score":0,"reason":""}`, 1)},
		{"result", strings.Replace(valid, `"detection":{"score":0,"reason":""}`, `"detection":{"score":0}`, 1)},
		{"result", strings.TrimSuffix(valid, "}") + `,"pipeline_output":{"x":1,"x":2}}`},
		{"result", strings.TrimSuffix(valid, "}") + `,"scientific_evaluation":{"x":` + strings.Repeat("[", 64) + `0` + strings.Repeat("]", 64) + `}}`},
		{"result", `{"job_id":"abcd1234","status":"succeeded"}`},
		{"result", strings.Replace(valid, `"job_id":"abcd1234"`, `"job_id":"ffff1234"`, 1)},
	}
	for i, c := range cases {
		t.Run(c.kind+"/"+big.NewInt(int64(i)).String(), func(t *testing.T) {
			jobs, results, h := apiFixture(t)
			path := filepath.Join(results, "abcd1234.json")
			if c.kind == "job" {
				path = filepath.Join(jobs, "abcd1234.json")
			}
			writeFixture(t, path, []byte(c.data))
			requestCode(t, h, verifiedRequest("researcher-a", 1), 500, c.kind+"_record_invalid")
			if c.kind == "job" && authorizedForJob(verifiedRequest("researcher-a", 1), jobs, "abcd1234") {
				t.Fatal("invalid job authorized")
			}
		})
	}
	for _, data := range []string{`{"job_id":"abcd1234","status":"processed"}`, string(completeResult(t, "processed")), strings.TrimSuffix(valid, "}") + `,"pipeline_output":{"output_dir":null},"scientific_evaluation":{"x":1,"X":2,"optional":null}}`} {
		_, results, h := apiFixture(t)
		writeFixture(t, filepath.Join(results, "abcd1234.json"), []byte(data))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, verifiedRequest("researcher-a", 1))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var r resultResponse
		json.Unmarshal(w.Body.Bytes(), &r)
		if strings.Contains(data, `"processed"`) && (r.Status != "incomplete" || r.LegacyStatus != "processed" || r.ErrorCode != "legacy_result_unverified") {
			t.Fatal(r)
		}
	}
}

func mtlsFixture(t *testing.T, h http.Handler) (*httptest.Server, *http.Client, *http.Client) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	mux := http.NewServeMux()
	mux.Handle("/results/", h)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	s := httptest.NewUnstartedServer(mux)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	s.StartTLS()
	t.Cleanup(s.Close)
	serverPool := x509.NewCertPool()
	serverPool.AddCert(s.Certificate())
	client := func(owner string, serial int64) *http.Client {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: owner}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, cert, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: serverPool, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: time.Second}
	}
	return s, client("researcher-a", 1), client("researcher-b", 2)
}
func TestTLSFIFORequestsReturnWithoutBlockingHealth(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	for _, kind := range []string{"job", "result"} {
		t.Run(kind, func(t *testing.T) {
			jobs, results, h := apiFixture(t)
			path := filepath.Join(results, "abcd1234.json")
			if kind == "job" {
				path = filepath.Join(jobs, "abcd1234.json")
				os.Remove(path)
			}
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			server, a, b := mtlsFixture(t, h)
			check := func(client *http.Client, route string, status int) {
				t.Helper()
				resp, err := client.Get(server.URL + route)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != status {
					t.Fatalf("%d %s %v", resp.StatusCode, body, err)
				}
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				resp, err := a.Get(server.URL + "/results/abcd1234")
				if err != nil {
					t.Error(err)
					return
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != 500 || !strings.Contains(string(body), kind+"_read_failed") {
					t.Error(resp.StatusCode, string(body))
				}
			}()
			check(a, "/health", 200)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("FIFO request blocked")
			}
			if kind == "result" {
				check(b, "/results/abcd1234", 403)
			}
			os.Remove(path)
			if kind == "job" {
				data, _ := json.Marshal(jobRecord{JobID: "abcd1234", Status: "uploaded", ClientID: "researcher-a", ClientCertSerial: "1"})
				writeFixture(t, path, data)
			} else {
				writeFixture(t, path, completeResult(t, "succeeded"))
			}
			check(a, "/results/abcd1234", 200)
		})
	}
}

func TestAuthorizationMetadataFailureIsClosed(t *testing.T) {
	jobs, _, _ := apiFixture(t)
	for _, data := range []string{`{"job_id":"ffff1234","status":"uploaded","client_id":"researcher-a","client_cert_serial":"1"}`, `{"job_id":"abcd1234","status":"uploaded","client_cert_serial":"1","client_cert_serial":"2"}`} {
		writeFixture(t, filepath.Join(jobs, "abcd1234.json"), []byte(data))
		if authorizedForJob(verifiedRequest("researcher-a", 1), jobs, "abcd1234") {
			t.Fatal("mismatched or duplicate ownership metadata authorized")
		}
	}
	if authorizedForJob(verifiedRequest("researcher-a", 1), jobs, "../abcd1234") {
		t.Fatal("invalid ID authorized")
	}
}

func TestHTTPMetadataDepthBoundaryAndRequiredFields(t *testing.T) {
	for _, depth := range []int{64, 65} {
		_, results, h := apiFixture(t)
		// Root object + pipeline object + nested arrays total depth.
		raw := strings.TrimSuffix(string(completeResult(t, "succeeded")), "}") + `,"pipeline_output":{"x":` + strings.Repeat("[", depth-2) + `null` + strings.Repeat("]", depth-2) + `}}`
		writeFixture(t, filepath.Join(results, "abcd1234.json"), []byte(raw))
		status, code := 200, ""
		if depth == 65 {
			status, code = 500, "result_record_invalid"
		}
		requestCode(t, h, verifiedRequest("researcher-a", 1), status, code)
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(completeResult(t, "succeeded"), &fields)
	for _, required := range []string{"schema_version", "security_mode", "pipeline_mode", "job_id", "status", "processed_at", "upload_sha256", "processed_sha256", "size_bytes", "decrypted", "signature_valid", "release_status", "detection"} {
		t.Run(required, func(t *testing.T) {
			_, results, h := apiFixture(t)
			copyFields := make(map[string]json.RawMessage)
			for k, v := range fields {
				copyFields[k] = v
			}
			delete(copyFields, required)
			raw, _ := json.Marshal(copyFields)
			writeFixture(t, filepath.Join(results, "abcd1234.json"), raw)
			requestCode(t, h, verifiedRequest("researcher-a", 1), 500, "result_record_invalid")
		})
	}
}

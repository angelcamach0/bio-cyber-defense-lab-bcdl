// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func smallAdmissionPolicy() admissionPolicy {
	p := defaultAdmissionPolicy(1024)
	p.GlobalJobs = 4
	p.PrincipalJobs = 2
	p.GlobalBytes = 1 << 20
	p.PrincipalBytes = 512 << 10
	return p
}
func admissionFixture(t *testing.T, p admissionPolicy) (*uploadAdmissionHandler, string) {
	t.Helper()
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	root := t.TempDir()
	store, err := openAdmissionStore(root, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return &uploadAdmissionHandler{store: store, limiter: newRateLimiter(1000, time.Minute)}, root
}
func serveAdmission(t *testing.T, h http.Handler, r *http.Request, want int, code string) string {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != want || code != "" && body["code"] != code {
		t.Fatalf("response %d %s; want %d %s", w.Code, w.Body.String(), want, code)
	}
	return body["job_id"]
}
func setPrincipal(r *http.Request, cn string, serial int64) {
	c := &x509.Certificate{Subject: pkix.Name{CommonName: cn}, SerialNumber: big.NewInt(serial)}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}, VerifiedChains: [][]*x509.Certificate{{c}}}
}
func readTestLedger(t *testing.T, s *admissionStore) admissionLedger {
	t.Helper()
	v, e := s.load()
	if e != nil {
		t.Fatal(e)
	}
	return v
}

func TestAdmissionPolicyStrictEnvironment(t *testing.T) {
	names := []string{"BIOZERO_ADMISSION_GLOBAL_JOBS", "BIOZERO_ADMISSION_PRINCIPAL_JOBS", "BIOZERO_ADMISSION_GLOBAL_BYTES", "BIOZERO_ADMISSION_PRINCIPAL_BYTES", "BIOZERO_ADMISSION_ACTIVE_UPLOADS", "BIOZERO_ADMISSION_PRINCIPAL_ACTIVE_UPLOADS", "BIOZERO_MAX_UPLOAD_BYTES", "BIOZERO_ADMISSION_FREE_SPACE_FLOOR"}
	for _, name := range names {
		for _, value := range []string{"", "0", "-1", "not-a-number", "9223372036854775808"} {
			t.Run(name+"/"+value, func(t *testing.T) {
				t.Setenv(name, value)
				if _, e := admissionPolicyFromEnv(); e == nil {
					t.Fatal("invalid config fell back")
				}
			})
		}
	}
	p := smallAdmissionPolicy()
	p.MaxBodyBytes = math.MaxInt64
	if p.validate() == nil {
		t.Fatal("overflow accepted")
	}
}
func TestAdmissionRetainedQuotaVerifiedPrincipalAndRenewal(t *testing.T) {
	p := smallAdmissionPolicy()
	p.PrincipalJobs = 1
	h, root := admissionFixture(t, p)
	id := serveAdmission(t, h, multipartUpload(t, nil), 200, "")
	path := filepath.Join(root, "jobs", id+".json")
	b, _ := os.ReadFile(path)
	var job jobRecord
	json.Unmarshal(b, &job)
	job.Status = "rejected"
	b, _ = json.MarshalIndent(job, "", "  ")
	os.WriteFile(path, b, 0600)
	r := multipartUpload(t, nil)
	setPrincipal(r, "researcher-a", 900)
	r.Header.Set("X-Client-Id", "researcher-b")
	r.Header.Set("X-Forwarded-For", "192.0.2.99")
	serveAdmission(t, h, r, 429, "quota_exceeded")
	r = multipartUpload(t, map[string]string{"client_id": "researcher-b"})
	setPrincipal(r, "researcher-b", 2)
	serveAdmission(t, h, r, 200, "")
	if len(readTestLedger(t, h.store).Entries) != 2 {
		t.Fatal("terminal or serial renewal reset charges")
	}
	h.store.Close()
	store, e := openAdmissionStore(root, p)
	if e != nil || !store.healthy() {
		t.Fatal("restart failed", e)
	}
	defer store.Close()
	h.store = store
	r = multipartUpload(t, nil)
	setPrincipal(r, "researcher-a", 901)
	serveAdmission(t, h, r, 429, "quota_exceeded")
	assertUploadEntries(t, filepath.Join(root, "uploads"), 2)
}
func TestAdmissionGlobalAndByteQuota(t *testing.T) {
	for _, kind := range []string{"global_jobs", "global_bytes", "principal_bytes"} {
		t.Run(kind, func(t *testing.T) {
			p := smallAdmissionPolicy()
			reserve := p.MaxBodyBytes + admissionHeadroom
			switch kind {
			case "global_jobs":
				p.GlobalJobs = 2
				p.PrincipalJobs = 2
			case "global_bytes":
				p.GlobalBytes = 2 * reserve
				p.PrincipalBytes = p.GlobalBytes
			case "principal_bytes":
				p.PrincipalBytes = reserve
			}
			h, _ := admissionFixture(t, p)
			serveAdmission(t, h, multipartUpload(t, nil), 200, "")
			if kind != "principal_bytes" {
				r := multipartUpload(t, nil)
				setPrincipal(r, "researcher-b", 2)
				serveAdmission(t, h, r, 200, "")
			}
			r := multipartUpload(t, nil)
			if kind != "principal_bytes" {
				setPrincipal(r, "researcher-c", 3)
			}
			serveAdmission(t, h, r, 429, "quota_exceeded")
		})
	}
}
func TestAdmissionConcurrentLastJobHasOneWinner(t *testing.T) {
	p := smallAdmissionPolicy()
	p.GlobalJobs = 1
	p.PrincipalJobs = 1
	p.ActiveUploads = 1
	p.PrincipalActiveUploads = 1
	h, _ := admissionFixture(t, p)
	start := make(chan struct{})
	codes := make(chan int, 12)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		r := multipartUpload(t, nil)
		setPrincipal(r, fmt.Sprintf("researcher-%d", i), int64(i+1))
		wg.Add(1)
		go func() { defer wg.Done(); <-start; w := httptest.NewRecorder(); h.ServeHTTP(w, r); codes <- w.Code }()
	}
	close(start)
	wg.Wait()
	close(codes)
	winners := 0
	for c := range codes {
		if c == 200 {
			winners++
		} else if c != 429 {
			t.Fatalf("unexpected response %d", c)
		}
	}
	if winners != 1 || len(readTestLedger(t, h.store).Entries) != 1 {
		t.Fatal("concurrent over-admission", winners)
	}
}

type gatedBody struct {
	ready, release chan struct{}
	once           sync.Once
	reader         io.Reader
}

func (b *gatedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.ready); <-b.release })
	return b.reader.Read(p)
}
func (*gatedBody) Close() error { return nil }
func TestAdmissionReservationBeforeBodyAndActiveLimits(t *testing.T) {
	h, _ := admissionFixture(t, smallAdmissionPolicy())
	r := multipartUpload(t, nil)
	g := &gatedBody{ready: make(chan struct{}), release: make(chan struct{}), reader: r.Body}
	r.Body = g
	done := make(chan int, 1)
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, r); done <- w.Code }()
	select {
	case <-g.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("body never read")
	}
	defer func() {
		select {
		case <-g.release:
		default:
			close(g.release)
		}
	}()
	ledger := readTestLedger(t, h.store)
	for _, entry := range ledger.Entries {
		if entry.State != "reserved" || entry.ChargedBytes != h.store.policy.MaxBodyBytes+admissionHeadroom {
			t.Fatal("read before durable full reserve")
		}
	}
	serveAdmission(t, h, multipartUpload(t, nil), 429, "upload_concurrency_exceeded")
	b, e := h.store.reserve("researcher-b", "2")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.store.reserve("researcher-c", "3"); e == nil || e.Error() != "upload_concurrency_exceeded" {
		t.Fatal("global active limit", e)
	}
	if e = h.store.abort(b); e != nil {
		t.Fatal(e)
	}
	close(g.release)
	if <-done != 200 {
		t.Fatal("admitted upload failed")
	}
	if len(readTestLedger(t, h.store).Entries) != 1 {
		t.Fatal("aborted active charge retained")
	}
}

type unreadBody struct{ reads int }

func (b *unreadBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("body must not be read")
}
func (*unreadBody) Close() error { return nil }
func TestAdmissionIdentityAndQuotaDenyBeforeBody(t *testing.T) {
	p := smallAdmissionPolicy()
	p.PrincipalJobs = 1
	h, _ := admissionFixture(t, p)
	b := &unreadBody{}
	r := multipartUpload(t, nil)
	r.TLS = nil
	r.Body = b
	serveAdmission(t, h, r, 403, "identity_invalid")
	if b.reads != 0 || len(readTestLedger(t, h.store).Entries) != 0 {
		t.Fatal("unauthenticated body or reservation")
	}
	serveAdmission(t, h, multipartUpload(t, nil), 200, "")
	r = multipartUpload(t, nil)
	r.Body = b
	serveAdmission(t, h, r, 429, "quota_exceeded")
	if b.reads != 0 {
		t.Fatal("quota rejection read body")
	}
}
func TestAdmissionInstanceLockAndPolicyPin(t *testing.T) {
	p := smallAdmissionPolicy()
	h, root := admissionFixture(t, p)
	if other, e := openAdmissionStore(root, p); e == nil {
		other.Close()
		t.Fatal("second uploader accepted")
	}
	before, _ := os.ReadFile(filepath.Join(root, "admission", "ledger.json"))
	h.store.Close()
	p.PrincipalJobs = 1
	if changed, e := openAdmissionStore(root, p); e == nil {
		changed.Close()
		t.Fatal("policy changed without adoption")
	}
	after, _ := os.ReadFile(filepath.Join(root, "admission", "ledger.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("policy rejection mutated ledger")
	}
}
func TestAdmissionFreeSpaceSubtractsOutstandingReservations(t *testing.T) {
	p := defaultAdmissionPolicy(8 << 20)
	var fs syscall.Statfs_t
	root := t.TempDir()
	if e := syscall.Statfs(root, &fs); e != nil {
		t.Fatal(e)
	}
	available := int64(fs.Bavail) * fs.Bsize
	p.FreeSpaceFloor = available - (p.MaxBodyBytes+admissionHeadroom)*3/2
	if p.FreeSpaceFloor <= 0 {
		t.Skip("filesystem too small for floor test")
	}
	s, e := openAdmissionStore(root, p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.reserve("researcher-a", "1"); e != nil {
		t.Fatal("first reservation", e)
	}
	if _, e = s.reserve("researcher-b", "2"); e == nil || e.Error() != "storage_free_space_low" {
		t.Fatal("pending reservation ignored by floor", e)
	}
}
func TestAdmissionLedgerRequiredTypesAndTotals(t *testing.T) {
	for _, fault := range []string{"alias", "duplicate", "null_scalar", "null_entries", "missing_policy", "missing_entry_field", "oversubscribed"} {
		t.Run(fault, func(t *testing.T) {
			h, root := admissionFixture(t, smallAdmissionPolicy())
			entry, e := h.store.reserve("researcher-a", "1")
			if e != nil {
				t.Fatal(e)
			}
			ledger := readTestLedger(t, h.store)
			raw, _ := json.MarshalIndent(ledger, "", "  ")
			switch fault {
			case "alias":
				raw = bytes.Replace(raw, []byte(`"schema_version"`), []byte(`"Schema_Version"`), 1)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"schema_version": 1`), []byte(`"schema_version": 1, "schema_version": 1`), 1)
			case "null_scalar":
				raw = bytes.Replace(raw, []byte(`"charged_bytes": 132096`), []byte(`"charged_bytes": null`), 1)
			case "null_entries":
				var v map[string]any
				json.Unmarshal(raw, &v)
				v["entries"] = nil
				raw, _ = json.Marshal(v)
			case "missing_policy":
				var v map[string]any
				json.Unmarshal(raw, &v)
				delete(v, "policy")
				raw, _ = json.Marshal(v)
			case "missing_entry_field":
				var v map[string]any
				json.Unmarshal(raw, &v)
				delete(v["entries"].(map[string]any)[entry.JobID].(map[string]any), "certificate_serial")
				raw, _ = json.Marshal(v)
			case "oversubscribed":
				for i := 0; i < 3; i++ {
					x := entry
					x.JobID = fmt.Sprintf("%016x", i+1)
					ledger.Entries[x.JobID] = x
				}
				raw, _ = json.Marshal(ledger)
			}
			h.store.Close()
			if e = os.WriteFile(filepath.Join(root, "admission", "ledger.json"), raw, 0600); e != nil {
				t.Fatal(e)
			}
			s, e := openAdmissionStore(root, smallAdmissionPolicy())
			if e == nil {
				s.Close()
				t.Fatal("invalid authoritative ledger accepted", fault)
			}
		})
	}
}
func TestAdmissionMissingLedgerNeverImportsExistingData(t *testing.T) {
	for _, dir := range []string{"uploads", "jobs"} {
		t.Run(dir, func(t *testing.T) {
			root := t.TempDir()
			os.Mkdir(filepath.Join(root, dir), 0700)
			path := filepath.Join(root, dir, "historical")
			os.WriteFile(path, []byte("keep"), 0600)
			s, e := openAdmissionStore(root, smallAdmissionPolicy())
			if e == nil {
				s.Close()
				t.Fatal("missing ledger imported")
			}
			b, _ := os.ReadFile(path)
			if string(b) != "keep" {
				t.Fatal("history deleted")
			}
			if _, e = os.Stat(filepath.Join(root, "admission", "ledger.json")); !os.IsNotExist(e) {
				t.Fatal("baseline ledger invented")
			}
		})
	}
}
func TestAdmissionUnsafeNamespaceAndLedger(t *testing.T) {
	for _, fault := range []string{"ancestor_symlink", "staging_symlink", "ledger_symlink", "ledger_fifo", "ledger_mode", "ledger_sparse", "unknown_file"} {
		t.Run(fault, func(t *testing.T) {
			h, root := admissionFixture(t, smallAdmissionPolicy())
			h.store.Close()
			path := filepath.Join(root, "admission", "ledger.json")
			switch fault {
			case "ancestor_symlink":
				real := root + "-real"
				if e := os.Rename(root, real); e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { os.RemoveAll(real) })
				os.Symlink(real, root)
			case "staging_symlink":
				os.Remove(filepath.Join(root, "uploads", admissionStageName))
				os.Symlink(t.TempDir(), filepath.Join(root, "uploads", admissionStageName))
			case "ledger_symlink":
				b, _ := os.ReadFile(path)
				other := filepath.Join(t.TempDir(), "ledger")
				os.WriteFile(other, b, 0600)
				os.Remove(path)
				os.Symlink(other, path)
			case "ledger_fifo":
				os.Remove(path)
				syscall.Mkfifo(path, 0600)
			case "ledger_mode":
				os.Chmod(path, 0644)
			case "ledger_sparse":
				os.Truncate(path, maxAdmissionLedgerBytes+1)
			case "unknown_file":
				os.WriteFile(filepath.Join(root, "admission", "unowned"), []byte("keep"), 0600)
			}
			start := time.Now()
			s, e := openAdmissionStore(root, smallAdmissionPolicy())
			if e == nil {
				s.Close()
				t.Fatal("unsafe namespace accepted")
			}
			if time.Since(start) > time.Second {
				t.Fatal("unsafe object blocked")
			}
		})
	}
}
func TestAdmissionPublishedChargesSurviveMissingHistory(t *testing.T) {
	h, root := admissionFixture(t, smallAdmissionPolicy())
	id := serveAdmission(t, h, multipartUpload(t, nil), 200, "")
	ledger := readTestLedger(t, h.store)
	h.store.Close()
	os.Remove(filepath.Join(root, "jobs", id+".json"))
	for _, entry := range ledger.Entries {
		os.Remove(filepath.Join(root, "uploads", entry.PayloadName))
	}
	before, _ := os.ReadFile(filepath.Join(root, "admission", "ledger.json"))
	s, e := openAdmissionStore(root, smallAdmissionPolicy())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.healthy() {
		t.Fatal("lost history reset charge")
	}
	after, _ := os.ReadFile(filepath.Join(root, "admission", "ledger.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("committed charge released")
	}
}

// Helper is killed by its parent at a real durable transition; no pipeline runs.
func TestAdmissionCrashHelper(t *testing.T) {
	root := os.Getenv("BIOZERO_ADMISSION_CRASH_ROOT")
	if root == "" {
		return
	}
	phase := os.Getenv("BIOZERO_ADMISSION_CRASH_PHASE")
	os.Setenv("BIOZERO_SECURITY_MODE", "protected")
	s, e := openAdmissionStore(root, smallAdmissionPolicy())
	if e != nil {
		t.Fatal(e)
	}
	stop := func() {
		fmt.Println("READY")
		for {
			time.Sleep(time.Second)
		}
	}
	if phase == "reserved" {
		if _, e = s.reserve("researcher-a", "1"); e != nil {
			t.Fatal(e)
		}
		stop()
	}
	s.failpoint = func(name string) error {
		if name == phase {
			stop()
		}
		return nil
	}
	h := &uploadAdmissionHandler{store: s, limiter: newRateLimiter(1000, time.Minute)}
	h.ServeHTTP(httptest.NewRecorder(), multipartUpload(t, nil))
	t.Fatal("failpoint not reached")
}
func TestAdmissionRealCrashRecoveryTransitions(t *testing.T) {
	for _, phase := range []string{"reserved", "payload_created_before_identity", "prepared_before_publication", "payload_published", "job_published", "committed_before_ack"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestAdmissionCrashHelper$")
			cmd.Env = append(os.Environ(), "BIOZERO_ADMISSION_CRASH_ROOT="+root, "BIOZERO_ADMISSION_CRASH_PHASE="+phase)
			stdout, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			ready := make(chan string, 1)
			go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
			select {
			case line := <-ready:
				if line != "READY\n" {
					t.Fatal("child not ready", line, stderr.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("child did not reach durable transition")
			}
			if e = cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			cmd.Wait()
			before, _ := os.ReadFile(filepath.Join(root, "admission", "ledger.json"))
			s, e := openAdmissionStore(root, smallAdmissionPolicy())
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			ambiguous := phase == "payload_created_before_identity" || phase == "payload_published"
			if ambiguous {
				if s.healthy() {
					t.Fatal("ambiguous crash acknowledged")
				}
				after, _ := os.ReadFile(filepath.Join(root, "admission", "ledger.json"))
				if !bytes.Equal(before, after) {
					t.Fatal("ambiguous reservation changed")
				}
				h := &uploadAdmissionHandler{store: s, limiter: newRateLimiter(1000, time.Minute)}
				serveAdmission(t, h, multipartUpload(t, nil), 503, "admission_state_unavailable")
				return
			}
			if !s.healthy() {
				t.Fatal("known transition did not recover")
			}
			ledger := readTestLedger(t, s)
			if phase == "job_published" || phase == "committed_before_ack" {
				if len(ledger.Entries) != 1 {
					t.Fatal("lost ack released charge")
				}
				for _, entry := range ledger.Entries {
					if entry.State != "committed" || entry.ChargedBytes != int64(len(uploadTestPayload))+admissionHeadroom {
						t.Fatal("publication recovery failed")
					}
				}
				assertUploadEntries(t, filepath.Join(root, "jobs"), 1)
				assertUploadEntries(t, filepath.Join(root, "uploads"), 1)
			} else {
				if len(ledger.Entries) != 0 {
					t.Fatal("never-published reservation not cleaned")
				}
				assertUploadEntries(t, filepath.Join(root, "uploads"), 0)
			}
			assertUploadEntries(t, filepath.Join(root, "uploads", admissionStageName), 0)
			assertUploadEntries(t, filepath.Join(root, "jobs", admissionStageName), 0)
		})
	}
}
func TestAdmissionStorageFailureStickyAndRecoverable(t *testing.T) {
	for _, phase := range []string{"ledger_before_write", "ledger_after_write", "stage_cleanup_after_sync", "committed_before_ack"} {
		t.Run(phase, func(t *testing.T) {
			h, root := admissionFixture(t, smallAdmissionPolicy())
			once := false
			h.store.failpoint = func(name string) error {
				if name == phase && !once {
					once = true
					return errors.New("private path secret")
				}
				return nil
			}
			r := multipartUpload(t, nil)
			if phase == "stage_cleanup_after_sync" {
				r.Header.Set("X-Content-SHA256", "bad")
			}
			serveAdmission(t, h, r, 503, "admission_state_unavailable")
			if h.store.healthy() {
				t.Fatal("storage failure did not latch")
			}
			serveAdmission(t, h, multipartUpload(t, nil), 503, "admission_state_unavailable")
			h.store.Close()
			s, e := openAdmissionStore(root, smallAdmissionPolicy())
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			if !s.healthy() {
				t.Fatal("unambiguous recovery failed")
			}
			n := 0
			if phase == "committed_before_ack" {
				n = 1
			}
			if len(readTestLedger(t, s).Entries) != n {
				t.Fatal("unexpected recovered charges")
			}
		})
	}
}
func TestAdmissionStageIdentityMismatchNeverDeletesForeignFile(t *testing.T) {
	h, root := admissionFixture(t, smallAdmissionPolicy())
	entry, e := h.store.reserve("researcher-a", "1")
	if e != nil {
		t.Fatal(e)
	}
	f, e := h.store.beginPayload(entry)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	path := filepath.Join(root, "uploads", admissionStageName, entry.JobID, "payload.part")
	os.Rename(path, path+"-original")
	os.WriteFile(path, []byte("FOREIGN"), 0600)
	os.Remove(path + "-original")
	if e = h.store.abort(entry); e == nil || h.store.healthy() {
		t.Fatal("inode mismatch released charge")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "FOREIGN" {
		t.Fatal("foreign file removed")
	}
	if len(readTestLedger(t, h.store).Entries) != 1 {
		t.Fatal("ambiguous charge lost")
	}
}
func multipartParts(t *testing.T, parts [][3]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for _, p := range parts {
		var out io.Writer
		var e error
		if p[1] != "" {
			out, e = w.CreateFormFile(p[0], p[1])
		} else {
			out, e = w.CreateFormField(p[0])
		}
		if e != nil {
			t.Fatal(e)
		}
		io.WriteString(out, p[2])
	}
	w.Close()
	r := httptest.NewRequest("POST", "/upload", &body)
	r.Header.Set("Content-Type", w.FormDataContentType())
	setPrincipal(r, "researcher-a", 1)
	return r
}
func TestStreamingMultipartRejectsMalformedAndCleansOwnedStages(t *testing.T) {
	for _, kind := range []string{"unknown", "duplicate_field", "duplicate_file", "file_field", "missing_file", "field_total", "truncated", "cancelled", "chunked_wire_cap", "form_owner_mismatch"} {
		t.Run(kind, func(t *testing.T) {
			p := smallAdmissionPolicy()
			if kind == "field_total" {
				p.MaxBodyBytes = 100000
			}
			h, root := admissionFixture(t, p)
			parts := [][3]string{{"file", "reads.fastq", string(uploadTestPayload)}}
			want, code := 400, "invalid_form"
			switch kind {
			case "unknown":
				parts = append(parts, [3]string{"evil", "", "secret"})
			case "duplicate_field":
				parts = append(parts, [3]string{"sig", "", "one"}, [3]string{"sig", "", "two"})
			case "duplicate_file":
				parts = append(parts, [3]string{"file", "other", "x"})
			case "file_field":
				parts = append(parts, [3]string{"sig", "wrong", "x"})
			case "missing_file":
				parts = [][3]string{{"sig", "", "x"}}
				code = "missing_file"
			case "field_total":
				parts = append(parts, [3]string{"sig", "", strings.Repeat("x", 65536)}, [3]string{"enc_alg", "", "a"})
				want, code = 413, "metadata_too_large"
			case "form_owner_mismatch":
				parts = append(parts, [3]string{"client_id", "", "researcher-b"})
				want, code = 403, "identity_invalid"
			case "chunked_wire_cap":
				parts[0][2] = strings.Repeat("x", 2000)
				want, code = 413, "payload_too_large"
			case "cancelled":
				code = "upload_cancelled"
			}
			r := multipartParts(t, parts)
			if kind == "chunked_wire_cap" {
				r.ContentLength = -1
			}
			if kind == "truncated" {
				b, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(b[:len(b)-40]))
				r.ContentLength = -1
			}
			if kind == "cancelled" {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			serveAdmission(t, h, r, want, code)
			if !h.store.healthy() || len(readTestLedger(t, h.store).Entries) != 0 {
				t.Fatal("rejection poisoned admission")
			}
			assertUploadEntries(t, filepath.Join(root, "jobs"), 0)
			assertUploadEntries(t, filepath.Join(root, "uploads"), 0)
			assertUploadEntries(t, filepath.Join(root, "uploads", admissionStageName), 0)
			assertUploadEntries(t, filepath.Join(root, "jobs", admissionStageName), 0)
			serveAdmission(t, h, multipartUpload(t, nil), 200, "")
		})
	}
}

func TestAdmissionConcurrentLatchPreventsDelayedSuccessAck(t *testing.T) {
	h, _ := admissionFixture(t, smallAdmissionPolicy())
	ready, release := make(chan struct{}), make(chan struct{})
	var failSave atomic.Bool
	h.store.failpoint = func(name string) error {
		if name == "ack_before_lock" {
			close(ready)
			<-release
		}
		if name == "ledger_before_write" && failSave.Load() {
			return errors.New("storage failure")
		}
		return nil
	}
	a := multipartUpload(t, nil)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, a); done <- w }()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("A never reached committed acknowledgement")
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	ledger := readTestLedger(t, h.store)
	if len(ledger.Entries) != 1 {
		t.Fatal("A not persisted before ACK")
	}
	failSave.Store(true)
	b := multipartUpload(t, nil)
	setPrincipal(b, "researcher-b", 2)
	serveAdmission(t, h, b, 503, "admission_state_unavailable")
	close(release)
	w := <-done
	if w.Code != 503 || strings.Contains(w.Body.String(), `"job_id"`) {
		t.Fatal("success leaked after authoritative latch", w.Code, w.Body.String())
	}
	if len(readTestLedger(t, h.store).Entries) != 1 {
		t.Fatal("unacknowledged committed input lost charge")
	}
}

func TestAdmissionPublicationNeverClobbersExistingJob(t *testing.T) {
	h, root := admissionFixture(t, smallAdmissionPolicy())
	var conflict string
	h.store.failpoint = func(name string) error {
		if name == "prepared_before_publication" {
			ledger := readTestLedger(t, h.store)
			for id := range ledger.Entries {
				conflict = filepath.Join(root, "jobs", id+".json")
			}
			if err := os.WriteFile(conflict, []byte("FOREIGN ORIGINAL"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	serveAdmission(t, h, multipartUpload(t, nil), 503, "admission_state_unavailable")
	data, _ := os.ReadFile(conflict)
	if string(data) != "FOREIGN ORIGINAL" {
		t.Fatal("publication clobbered an existing job")
	}
	if h.store.healthy() || len(readTestLedger(t, h.store).Entries) != 1 {
		t.Fatal("publication ambiguity released quota")
	}
	assertUploadEntries(t, filepath.Join(root, "uploads"), 1)
}
func TestAdmissionRecoveryRejectsOwnerRelabelWithoutResettingQuota(t *testing.T) {
	h, root := admissionFixture(t, smallAdmissionPolicy())
	id := serveAdmission(t, h, multipartUpload(t, nil), 200, "")
	path := filepath.Join(root, "jobs", id+".json")
	raw, _ := os.ReadFile(path)
	var job jobRecord
	json.Unmarshal(raw, &job)
	job.ClientID = "researcher-b"
	raw, _ = json.MarshalIndent(job, "", "  ")
	os.WriteFile(path, raw, 0600)
	before, _ := os.ReadFile(filepath.Join(root, "admission", "ledger.json"))
	h.store.Close()
	store, err := openAdmissionStore(root, smallAdmissionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.healthy() {
		t.Fatal("mutable owner trusted for quota recovery")
	}
	after, _ := os.ReadFile(filepath.Join(root, "admission", "ledger.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("relabel reset original quota")
	}
}

func TestAdmissionDirectoryCreationRetriesParentDurability(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	rootInfo, _ := os.Stat(root)
	rootStat, _ := infoSysStat(rootInfo)
	target := filepath.Join(root, "created", "leaf")
	failed := false
	retries := 0
	syncParent := func(fd int) error {
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Dev == rootStat.Dev && st.Ino == rootStat.Ino {
			retries++
			if !failed {
				failed = true
				return errors.New("parent fsync failed after mkdir")
			}
		}
		return syscall.Fsync(fd)
	}
	if directory, err := secureDirectoryWithSync(target, true, true, syncParent); err == nil {
		directory.Close()
		t.Fatal("acknowledged unsynced parent")
	}
	if _, err := os.Stat(filepath.Join(root, "created")); err != nil {
		t.Fatal("test did not create before sync failure", err)
	}
	directory, err := secureDirectoryWithSync(target, true, true, syncParent)
	if err != nil {
		t.Fatal(err)
	}
	directory.Close()
	if retries != 2 {
		t.Fatal("existing ancestor skipped fsync retry", retries)
	}
	parent, err := secureDirectory(root, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	calls := 0
	childSync := func(fd int) error {
		calls++
		if calls == 1 {
			return errors.New("parent sync failure")
		}
		return syscall.Fsync(fd)
	}
	if child, err := secureChildDirectoryWithSync(parent, "child", true, childSync); err == nil {
		child.Close()
		t.Fatal("child accepted unsynced parent")
	}
	child, err := secureChildDirectoryWithSync(parent, "child", true, childSync)
	if err != nil {
		t.Fatal(err)
	}
	child.Close()
	if calls != 2 {
		t.Fatal("existing child skipped retry")
	}
}

func TestAdmissionReservedContradictionCannotGrandfatherOrphan(t *testing.T) {
	h, root := admissionFixture(t, smallAdmissionPolicy())
	entry, err := h.store.reserve("researcher-a", "1")
	if err != nil {
		t.Fatal(err)
	}
	ledger := readTestLedger(t, h.store)
	entry.PayloadName = entry.JobID + "_orphan"
	ledger.Entries[entry.JobID] = entry
	orphan := filepath.Join(root, "uploads", entry.PayloadName)
	if err = os.WriteFile(orphan, []byte("RETAIN UNKNOWN"), 0600); err != nil {
		t.Fatal(err)
	}
	h.store.Close()
	raw, _ := json.MarshalIndent(ledger, "", "  ")
	ledgerPath := filepath.Join(root, "admission", "ledger.json")
	os.WriteFile(ledgerPath, raw, 0600)
	store, err := openAdmissionStore(root, smallAdmissionPolicy())
	if err == nil {
		store.Close()
		t.Fatal("contradictory reserved orphan accepted")
	}
	after, _ := os.ReadFile(ledgerPath)
	if !bytes.Equal(raw, after) {
		t.Fatal("contradiction released charged entry")
	}
	data, _ := os.ReadFile(orphan)
	if string(data) != "RETAIN UNKNOWN" {
		t.Fatal("unknown input deleted")
	}
}
func TestAdmissionOwnedPartialBodyRecoversWithoutOrphan(t *testing.T) {
	h, root := admissionFixture(t, smallAdmissionPolicy())
	entry, err := h.store.reserve("researcher-a", "1")
	if err != nil {
		t.Fatal(err)
	}
	file, err := h.store.beginPayload(entry)
	if err != nil {
		t.Fatal(err)
	}
	file.Write([]byte("PARTIAL"))
	file.Sync()
	file.Close()
	h.store.Close()
	store, err := openAdmissionStore(root, smallAdmissionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if !store.healthy() || len(readTestLedger(t, store).Entries) != 0 {
		t.Fatal("owned never-published partial body not recovered")
	}
	assertUploadEntries(t, filepath.Join(root, "uploads", admissionStageName), 0)
	assertUploadEntries(t, filepath.Join(root, "jobs", admissionStageName), 0)
	assertUploadEntries(t, filepath.Join(root, "uploads"), 0)
}

type rejectTailBody struct {
	prefix    *strings.Reader
	tailReads int
}

func (body *rejectTailBody) Read(buffer []byte) (int, error) {
	if body.prefix.Len() > 0 {
		return body.prefix.Read(buffer)
	}
	body.tailReads++
	return 0, errors.New("unread remainder should not be drained")
}
func (*rejectTailBody) Close() error { return nil }
func TestStreamingUnknownPartRejectsWithoutDrainingRemainder(t *testing.T) {
	h, _ := admissionFixture(t, smallAdmissionPolicy())
	body := &rejectTailBody{prefix: strings.NewReader("--test-boundary\r\nContent-Disposition: form-data; name=\"unknown\"\r\n\r\n")}
	request := httptest.NewRequest("POST", "/upload", nil)
	request.Body = body
	request.ContentLength = -1
	request.Header.Set("Content-Type", "multipart/form-data; boundary=test-boundary")
	setPrincipal(request, "researcher-a", 1)
	serveAdmission(t, h, request, 400, "invalid_form")
	if body.tailReads != 0 {
		t.Fatal("rejected part drained unread remainder", body.tailReads)
	}
	if len(readTestLedger(t, h.store).Entries) != 0 {
		t.Fatal("safe rejection retained reservation")
	}
}

func TestAdmissionLegacyStagingNeverAdopted(t *testing.T) {
	h, root := admissionFixture(t, smallAdmissionPolicy())
	h.store.Close()
	legacy := filepath.Join(root, "admission", "staging")
	if err := os.Mkdir(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(legacy, "legacy-payload")
	os.WriteFile(keep, []byte("PRESERVE"), 0600)
	ledgerPath := filepath.Join(root, "admission", "ledger.json")
	before, _ := os.ReadFile(ledgerPath)
	store, err := openAdmissionStore(root, smallAdmissionPolicy())
	if err == nil {
		store.Close()
		t.Fatal("legacy stage silently adopted")
	}
	after, _ := os.ReadFile(ledgerPath)
	data, _ := os.ReadFile(keep)
	if !bytes.Equal(before, after) || string(data) != "PRESERVE" {
		t.Fatal("legacy stage or charge modified")
	}
}
func TestAdmissionSplitStageUnknownAndMissingLedgerFailClosed(t *testing.T) {
	for _, parent := range []string{"uploads", "jobs"} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/missing=%v", parent, missing), func(t *testing.T) {
				h, root := admissionFixture(t, smallAdmissionPolicy())
				h.store.Close()
				unknown := filepath.Join(root, parent, admissionStageName, "untracked")
				os.Mkdir(unknown, 0700)
				path := filepath.Join(unknown, "keep")
				os.WriteFile(path, []byte("UNKNOWN"), 0600)
				ledgerPath := filepath.Join(root, "admission", "ledger.json")
				before, _ := os.ReadFile(ledgerPath)
				if missing {
					os.Remove(ledgerPath)
				}
				store, err := openAdmissionStore(root, smallAdmissionPolicy())
				if missing {
					if err == nil {
						store.Close()
						t.Fatal("missing ledger reset nonempty stage")
					}
					if _, err = os.Stat(ledgerPath); !os.IsNotExist(err) {
						t.Fatal("new ledger fabricated")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					defer store.Close()
					if store.healthy() {
						t.Fatal("unknown stage accepted")
					}
					after, _ := os.ReadFile(ledgerPath)
					if !bytes.Equal(before, after) {
						t.Fatal("charge changed on unknown stage")
					}
				}
				data, _ := os.ReadFile(path)
				if string(data) != "UNKNOWN" {
					t.Fatal("unknown staged data deleted")
				}
			})
		}
	}
}

// Explicit mount regression: standard suites skip it; the container invocation
// supplies three distinct bind mounts and executes the real handler/recovery.
func TestAdmissionDistinctBindMountPublicationAndRecovery(t *testing.T) {
	root := os.Getenv("BIOZERO_ADMISSION_MOUNT_ROOT")
	if root == "" {
		t.Skip("requires three explicit bind mounts")
	}
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	store, err := openAdmissionStore(root, smallAdmissionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	mountID := func(file *os.File) string {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", file.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "mnt_id:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:"))
			}
		}
		t.Fatal("mount ID missing")
		return ""
	}
	ids := map[string]bool{}
	for _, file := range []*os.File{store.dir, store.uploads, store.jobs} {
		ids[mountID(file)] = true
	}
	if len(ids) != 3 {
		store.Close()
		t.Fatal("test did not use distinct bind mounts")
	}
	handler := &uploadAdmissionHandler{store: store, limiter: newRateLimiter(1000, time.Minute)}
	jobID := serveAdmission(t, handler, multipartUpload(t, nil), 200, "")
	ledger := readTestLedger(t, store)
	if len(ledger.Entries) != 1 || ledger.Entries[jobID].State != "committed" {
		t.Fatal("bind mount publication not committed")
	}
	assertUploadEntries(t, filepath.Join(root, "uploads", admissionStageName), 0)
	assertUploadEntries(t, filepath.Join(root, "jobs", admissionStageName), 0)
	store.Close()
	store, err = openAdmissionStore(root, smallAdmissionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if !store.healthy() || len(readTestLedger(t, store).Entries) != 1 {
		t.Fatal("bind mount restart lost retained input")
	}
	for _, parent := range []string{"uploads", "jobs"} {
		assertUploadEntries(t, filepath.Join(root, parent), 1)
	}
}

func TestAdmissionSplitCleanupChecksBothInodesBeforeDeleting(t *testing.T) {
	h, root := admissionFixture(t, smallAdmissionPolicy())
	var id string
	h.store.failpoint = func(name string) error {
		if name != "prepared_before_publication" {
			return nil
		}
		ledger := readTestLedger(t, h.store)
		for jobID := range ledger.Entries {
			id = jobID
		}
		path := filepath.Join(root, "jobs", admissionStageName, id, "job.part")
		if err := os.Rename(path, path+"-original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("FOREIGN JOB"), 0600); err != nil {
			t.Fatal(err)
		}
		os.Remove(path + "-original")
		return errors.New("interrupted before publication")
	}
	serveAdmission(t, h, multipartUpload(t, nil), 503, "admission_state_unavailable")
	ledgerPath := filepath.Join(root, "admission", "ledger.json")
	before, _ := os.ReadFile(ledgerPath)
	h.store.Close()
	store, err := openAdmissionStore(root, smallAdmissionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.healthy() {
		t.Fatal("foreign job stage released charge")
	}
	original, _ := os.ReadFile(filepath.Join(root, "uploads", admissionStageName, id, "payload.part"))
	foreign, _ := os.ReadFile(filepath.Join(root, "jobs", admissionStageName, id, "job.part"))
	after, _ := os.ReadFile(ledgerPath)
	if !bytes.Equal(original, uploadTestPayload) || string(foreign) != "FOREIGN JOB" || !bytes.Equal(before, after) {
		t.Fatal("one stage deleted before both identities were validated")
	}
}

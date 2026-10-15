//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// OwnerIngressPolicy budgets a separate transport spool. Its full maximum body
// promise plus metadata headroom is charged permanently per admitted job. The
// authority's reservation remains separate; transport never refunds/transfers it.
type OwnerIngressPolicy struct {
	MaxJobs             int64 `json:"max_jobs"`
	MaxPrincipalJobs    int64 `json:"max_principal_jobs"`
	MaxBytes            int64 `json:"max_bytes"`
	MaxPrincipalBytes   int64 `json:"max_principal_bytes"`
	MaxActive           int64 `json:"max_active"`
	MaxPrincipalActive  int64 `json:"max_principal_active"`
	MaxBodyBytes        int64 `json:"max_body_bytes"`
	FreeSpaceFloorBytes int64 `json:"free_space_floor_bytes"`
}

func DefaultOwnerIngressPolicy() OwnerIngressPolicy {
	p := DefaultStorePolicy()
	return OwnerIngressPolicy{int64(p.MaxJobs), int64(p.MaxPrincipalJobs), p.MaxBytes, p.MaxPrincipalBytes, int64(p.MaxActive), int64(p.MaxPrincipalActive), p.MaxBodyBytes, p.FreeSpaceFloorBytes}
}
func (p OwnerIngressPolicy) validate() error {
	if p.MaxJobs < 1 || p.MaxJobs > 64 || p.MaxPrincipalJobs < 1 || p.MaxPrincipalJobs > 64 || p.MaxActive < 1 || p.MaxActive > 64 || p.MaxPrincipalActive < 1 || p.MaxPrincipalActive > 64 {
		return fail("ownership_ingress_policy_invalid")
	}
	return (StorePolicy{int(p.MaxJobs), int(p.MaxPrincipalJobs), p.MaxBytes, p.MaxPrincipalBytes, int(p.MaxActive), int(p.MaxPrincipalActive), p.MaxBodyBytes, p.FreeSpaceFloorBytes, 300}).validate()
}

type OwnerIngressConfig struct {
	Directory, Namespace string
	Pin                  AuthorityPin
	Scope                AcceptanceScope
	Policy               OwnerIngressPolicy
	Publication          *OwnerIngressPublicationConfig
}
type ownerIngressEntry struct {
	JobID            string `json:"job_id"`
	AcceptanceSHA256 string `json:"acceptance_sha256"`
	CredentialSHA256 string `json:"credential_sha256"`
	PrincipalSHA256  string `json:"principal_sha256"`
	AcceptanceJSON   string `json:"acceptance_json"`
	EnvelopeHex      string `json:"envelope_hex"`
	State            string `json:"state"`
	ChargeBytes      int64  `json:"charge_bytes"`
	ReceivedBytes    int64  `json:"received_bytes"`
}
type ownerIngressLedger struct {
	SchemaVersion int                 `json:"schema_version"`
	Domain        string              `json:"domain"`
	ContextSHA256 string              `json:"context_sha256"`
	Records       []ownerIngressEntry `json:"records"`
}
type OwnerIngressSnapshot struct {
	Jobs, Reading, Authorizing, Delivered, Rejected int
	ChargedBytes                                    int64
	Sticky                                          bool
}

// OwnerIngressStore is transport state, never owner/execution authority. Only the
// independently signed acceptance and external pin/scope authenticate ownership.
// Its unsigned ledger cannot protect against a compromised upload/host writer.
type OwnerIngressStore struct {
	mu                                     sync.Mutex
	config                                 OwnerIngressConfig
	root, lock, uploads, jobs, acceptances *os.File
	rawFD                                  int
	rawHeld                                bool
	sticky, closed                         bool
	inflight                               int
	data                                   ownerIngressLedger
	ledgerSHA                              string
	accepted                               map[string]VerifiedAcceptance
	fault                                  func(string) error
	publication                            *ownerIngressPublication
}

func CreateOwnerIngress(c OwnerIngressConfig) (*OwnerIngressStore, error) {
	return openOwnerIngress(c, true)
}
func OpenOwnerIngress(c OwnerIngressConfig) (*OwnerIngressStore, error) {
	return openOwnerIngress(c, false)
}
func openOwnerIngress(c OwnerIngressConfig, create bool) (out *OwnerIngressStore, outErr error) {
	if !authorityServicePath(c.Directory) || !nameValid(c.Namespace) || c.Pin.validate() != nil || c.Scope.validate() != nil || c.Policy.validate() != nil {
		return nil, fail("ownership_ingress_config_invalid")
	}
	var publication *ownerIngressPublication
	if c.Publication != nil {
		var err error
		c, publication, err = snapshotOwnerIngressPublication(c)
		if err != nil {
			return nil, err
		}
	}
	c.Pin.PublicKey = append(ed25519.PublicKey(nil), c.Pin.PublicKey...)
	raw, _ := json.Marshal(struct {
		Namespace string
		Pin       AuthorityPin
		Scope     AcceptanceScope
		Policy    OwnerIngressPolicy
	}{c.Namespace, c.Pin, c.Scope, c.Policy})
	if publication != nil {
		raw = publication.context(c)
	}
	root, err := storeRoot(c.Directory, create)
	if err != nil {
		return nil, err
	}
	s := &OwnerIngressStore{config: c, root: root, accepted: map[string]VerifiedAcceptance{}, data: ownerIngressLedger{1, "biozero.ownership.transport-spool.v1", digest(raw), []ownerIngressEntry{}}}
	if publication != nil {
		s.publication = publication
		s.data.SchemaVersion = 2
		s.data.Domain = "biozero.ownership.transport-spool.v2"
	}
	ok := false
	defer func() {
		if !ok && s.publication != nil && s.rawHeld {
			s.latch()
			out = s // retain all uncertain constructor children, never adopt or reset
		}
		if !ok && !s.sticky {
			s.releaseFailedOpen()
		}
	}()
	s.lock, err = storeFile(root, "instance.lock", create)
	if err != nil {
		return nil, fail("ownership_ingress_lock_invalid")
	}
	info, err := s.lock.Stat()
	if err != nil || info.Size() != 0 {
		return nil, fail("ownership_ingress_lock_invalid")
	}
	if syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, fail("ownership_ingress_locked")
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, s.lock.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return nil, fail("ownership_ingress_lock_invalid")
	}
	s.rawFD = int(fd)
	s.rawHeld = true
	if create {
		if s.lock.Sync() != nil || root.Sync() != nil {
			return nil, s.latch()
		}
	}
	for name, target := range map[string]**os.File{"uploads": &s.uploads, "jobs": &s.jobs, "acceptances": &s.acceptances} {
		if create {
			if syscall.Mkdirat(int(root.Fd()), name, 0700) != nil || root.Sync() != nil {
				return nil, s.latch()
			}
		}
		d, e := storeRoot(filepath.Join(c.Directory, name), false)
		if e != nil {
			return nil, fail("ownership_ingress_layout_invalid")
		}
		*target = d
	}
	if s.publication != nil {
		if create {
			if syscall.Mkdirat(int(root.Fd()), "publication", 0700) != nil || root.Sync() != nil {
				return nil, s.latch()
			}
		}
		s.publication.root, err = storeRoot(filepath.Join(c.Directory, "publication"), false)
		if err != nil {
			return nil, s.latch()
		}
	}
	if create {
		if err = s.save(s.data); err != nil {
			return nil, err
		}
	} else {
		if err = s.rootNames(false); err != nil {
			return nil, err
		}
		raw, err := storeRead(root, "ledger.json", StoreLedgerLimit)
		if err != nil {
			return nil, err
		}
		var ledger ownerIngressLedger
		if decodeStoreJSON(raw, &ledger) != nil || ledger.SchemaVersion != s.data.SchemaVersion || ledger.Domain != s.data.Domain || ledger.ContextSHA256 != s.data.ContextSHA256 || int64(len(ledger.Records)) > c.Policy.MaxJobs {
			return nil, fail("ownership_ingress_history_invalid")
		}
		for _, e := range ledger.Records {
			if _, exists := s.accepted[e.JobID]; exists {
				return nil, fail("ownership_ingress_history_invalid")
			}
			v, err := s.verifyEntry(e)
			if err != nil {
				return nil, err
			}
			s.accepted[e.JobID] = v
			if e.State == "reading" || s.publication != nil && e.State == "authorizing" {
				return nil, fail("ownership_ingress_pending")
			}
		}
		if err = s.checkBudget(ledger); err != nil {
			return nil, err
		}
		s.data = ledger
		s.ledgerSHA = digest(raw)
		if s.publication != nil {
			if err = s.openPublicationChildren(); err != nil {
				return nil, err
			}
		}
		if err = s.preflight(); err != nil {
			return nil, err
		}
	}
	ok = true
	return s, nil
}
func (s *OwnerIngressStore) checkBudget(ledger ownerIngressLedger) error {
	var jobs, active, charged int64
	principals := map[string][3]int64{}
	for _, e := range ledger.Records {
		jobs++
		charged += e.ChargeBytes
		a := principals[e.PrincipalSHA256]
		a[0]++
		a[1] += e.ChargeBytes
		if e.State == "reading" || s.publication != nil && e.State == "authorizing" {
			active++
			a[2]++
		}
		principals[e.PrincipalSHA256] = a
	}
	p := s.config.Policy
	if jobs > p.MaxJobs || active > p.MaxActive || charged > p.MaxBytes {
		return fail("ownership_ingress_history_invalid")
	}
	for _, a := range principals {
		if a[0] > p.MaxPrincipalJobs || a[1] > p.MaxPrincipalBytes || a[2] > p.MaxPrincipalActive {
			return fail("ownership_ingress_history_invalid")
		}
	}
	return nil
}

func (s *OwnerIngressStore) releaseFailedOpen() {
	for _, f := range []*os.File{s.uploads, s.jobs, s.acceptances, s.root, s.lock} {
		if f != nil {
			f.Close()
		}
	}
	if s.rawHeld {
		syscall.Close(s.rawFD)
		s.rawHeld = false
	}
}
func (s *OwnerIngressStore) latch() error {
	s.sticky = true
	return fail("ownership_ingress_uncertain")
}
func (s *OwnerIngressStore) point(name string) error {
	if s.fault != nil {
		return s.fault(name)
	}
	return nil
}
func ownerReadNames(root *os.File, limit int) ([]string, error) {
	fd, e := syscall.Openat(int(root.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("ownership_ingress_history_invalid")
	}
	f := os.NewFile(uintptr(fd), "owner-ingress-scan")
	defer f.Close()
	entries, e := f.ReadDir(limit + 1)
	if e != nil && e != io.EOF || len(entries) > limit {
		return nil, fail("ownership_ingress_history_invalid")
	}
	out := make([]string, 0, len(entries))
	for _, v := range entries {
		out = append(out, v.Name())
	}
	return out, nil
}
func (s *OwnerIngressStore) rootNames(missingLedger bool) error {
	if s.publication != nil {
		return s.publicationRootNames(missingLedger)
	}
	names, err := ownerReadNames(s.root, 8)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, n := range names {
		switch n {
		case "instance.lock", "uploads", "jobs", "acceptances", "ledger.json":
			seen[n] = true
		case "transaction.pending", "ledger.next":
			return fail("ownership_ingress_pending")
		default:
			return fail("ownership_ingress_history_invalid")
		}
	}
	if !seen["instance.lock"] || !seen["uploads"] || !seen["jobs"] || !seen["acceptances"] || (!missingLedger && !seen["ledger.json"]) {
		return fail("ownership_ingress_history_invalid")
	}
	return nil
}
func (s *OwnerIngressStore) verifyEntry(e ownerIngressEntry) (VerifiedAcceptance, error) {
	v, err := VerifyAcceptance([]byte(e.AcceptanceJSON), s.config.Pin, s.config.Scope)
	if err == nil {
		err = s.checkPublicationOwner(v)
	}
	if err != nil {
		return v, fail("ownership_ingress_history_invalid")
	}
	b := v.Binding()
	env, err := hex.DecodeString(e.EnvelopeHex)
	if err != nil || len(env) < 256 || len(env) > 512 || digest(env) != b.KeyEnvelopeSHA256 || e.JobID != b.JobID || e.AcceptanceSHA256 != v.SHA256() || e.CredentialSHA256 != b.CredentialSHA256 || !hexValue(e.PrincipalSHA256, 64) || e.ChargeBytes != s.ingressCharge() || e.ReceivedBytes < 0 || e.ReceivedBytes > b.CiphertextBytes || b.CiphertextBytes > s.config.Policy.MaxBodyBytes {
		return v, fail("ownership_ingress_history_invalid")
	}
	var certBytes []byte
	certBytes, err = hex.DecodeString(v.Claims().CredentialDER)
	if err != nil {
		return v, fail("ownership_ingress_history_invalid")
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return v, fail("ownership_ingress_history_invalid")
	}
	q, err := quotaPrincipalCN(s.config.Namespace, cert.Subject.CommonName)
	if err != nil || q != e.PrincipalSHA256 {
		return v, fail("ownership_ingress_history_invalid")
	}
	switch e.State {
	case "reading", "rejected":
	case "authorizing":
		if s.publication == nil || e.ReceivedBytes != b.CiphertextBytes {
			return v, fail("ownership_ingress_history_invalid")
		}
	case "delivered":
		if e.ReceivedBytes != b.CiphertextBytes {
			return v, fail("ownership_ingress_history_invalid")
		}
	default:
		return v, fail("ownership_ingress_history_invalid")
	}
	return v, nil
}
func (s *OwnerIngressStore) preflight() error {
	if s.closed || s.sticky {
		return fail("ownership_ingress_unavailable")
	}
	for name, f := range s.ingressDirectories() {
		path := s.config.Directory
		if name != "" {
			path = filepath.Join(path, name)
		}
		fresh, e := storeRoot(path, false)
		if e != nil {
			return s.latch()
		}
		a, e1 := fresh.Stat()
		closeErr := fresh.Close()
		b, e2 := f.Stat()
		if e1 != nil || e2 != nil || s.publication != nil && closeErr != nil || !os.SameFile(a, b) {
			return s.latch()
		}
	}
	if s.rootNames(s.ledgerSHA == "") != nil {
		return s.latch()
	}
	lock, e := storeFile(s.root, "instance.lock", false)
	if e != nil {
		return s.latch()
	}
	a, e1 := lock.Stat()
	closeErr := lock.Close()
	b, e2 := s.lock.Stat()
	if e1 != nil || e2 != nil || s.publication != nil && closeErr != nil || a.Size() != 0 || !os.SameFile(a, b) {
		return s.latch()
	}
	raw, e := storeRead(s.root, "ledger.json", StoreLedgerLimit)
	if s.ledgerSHA == "" {
		if !os.IsNotExist(e) {
			return s.latch()
		}
	} else if e != nil || digest(raw) != s.ledgerSHA {
		return s.latch()
	}
	if err := s.files(); err != nil {
		return s.latch()
	}
	if s.publication != nil && s.checkPublicationChildren() != nil {
		return s.latch()
	}
	return nil
}
func (s *OwnerIngressStore) files() error {
	if s.publication != nil {
		return s.publicationFiles()
	}
	// The worker's lifecycle job JSON remains a cache. Do not treat its strings as
	// ownership authority or read ciphertext merely to authorize a GET receipt.
	for kind, dir := range map[string]*os.File{"uploads": s.uploads, "jobs": s.jobs, "acceptances": s.acceptances} {
		names, err := ownerReadNames(dir, 128)
		if err != nil {
			return err
		}
		expected := map[string]ownerIngressEntry{}
		for _, e := range s.data.Records {
			v := s.accepted[e.JobID]
			name := e.JobID + ".json"
			if kind == "uploads" {
				name = e.JobID + "_" + v.Binding().OriginalName
			}
			if e.State != "rejected" || kind == "uploads" {
				expected[name] = e
				if kind == "jobs" && e.State == "reading" {
					expected[e.JobID+".pending"] = e
				}
			}
		}
		seen := map[string]bool{}
		for _, name := range names {
			e, ok := expected[name]
			if !ok {
				return fail("ownership_ingress_history_invalid")
			}
			f, err := storeFile(dir, name, false)
			if err != nil {
				return err
			}
			info, err := f.Stat()
			f.Close()
			if err != nil {
				return err
			}
			limit := int64(MaxAcceptanceBytes)
			if kind == "uploads" {
				limit = s.accepted[e.JobID].Binding().CiphertextBytes
			}
			if info.Size() < 0 || info.Size() > limit {
				return fail("ownership_ingress_history_invalid")
			}
			seen[name] = true
			if kind == "uploads" && e.State != "reading" && info.Size() != e.ReceivedBytes {
				return fail("ownership_ingress_history_invalid")
			}
			if kind == "acceptances" {
				raw, err := storeRead(dir, name, MaxAcceptanceBytes)
				if err != nil || digest(raw) != digest([]byte(e.AcceptanceJSON)) {
					return fail("ownership_ingress_history_invalid")
				}
			}
		}
		for name, e := range expected {
			if e.State != "reading" && !seen[name] {
				return fail("ownership_ingress_history_invalid")
			}
		}
	}
	return nil
}
func (s *OwnerIngressStore) save(next ownerIngressLedger) error {
	if err := s.preflight(); err != nil {
		return err
	}
	raw, err := boundedJSON(next, StoreLedgerLimit)
	if err != nil {
		return s.latch()
	}
	write := func(name string, data []byte) error {
		f, e := storeFile(s.root, name, true)
		if e != nil {
			return e
		}
		n, e := f.Write(data)
		if e == nil && n != len(data) {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = s.point(name + "_sync")
		}
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		return e
	}
	marker, _ := json.Marshal(struct{ Previous, Next string }{s.ledgerSHA, digest(raw)})
	if write("transaction.pending", marker) != nil || s.root.Sync() != nil || write("ledger.next", raw) != nil {
		return s.latch()
	}
	if s.point("ledger_rename") != nil || syscall.Renameat(int(s.root.Fd()), "ledger.next", int(s.root.Fd()), "ledger.json") != nil || s.root.Sync() != nil {
		return s.latch()
	}
	if s.point("intent_unlink") != nil || syscall.Unlinkat(int(s.root.Fd()), "transaction.pending") != nil || s.root.Sync() != nil {
		return s.latch()
	}
	s.data = next
	s.ledgerSHA = digest(raw)
	return nil
}
func (s *OwnerIngressStore) replace(i int, e ownerIngressEntry) error {
	next := s.data
	next.Records = append([]ownerIngressEntry(nil), s.data.Records...)
	next.Records[i] = e
	return s.save(next)
}
func ownerReceipt(v VerifiedAcceptance) OwnerUploadReceipt {
	b := v.Binding()
	return OwnerUploadReceipt{1, b.JobID, v.SHA256(), b.CredentialSHA256, b.CiphertextSHA256, b.CiphertextBytes, b.KeyEnvelopeSHA256, "delivered"}
}
func (s *OwnerIngressStore) Snapshot() OwnerIngressSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := OwnerIngressSnapshot{Sticky: s.sticky}
	for _, e := range s.data.Records {
		v.Jobs++
		v.ChargedBytes += e.ChargeBytes
		switch e.State {
		case "reading":
			v.Reading++
		case "authorizing":
			v.Authorizing++
		case "rejected":
			v.Rejected++
		case "delivered":
			v.Delivered++
		}
	}
	return v
}
func (s *OwnerIngressStore) Healthy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.preflight() == nil
}
func (s *OwnerIngressStore) find(job string) int {
	for i, e := range s.data.Records {
		if e.JobID == job {
			return i
		}
	}
	return -1
}
func (s *OwnerIngressStore) Get(ctx context.Context, state *tls.ConnectionState, job string) (OwnerUploadReceipt, error) {
	var z OwnerUploadReceipt
	p, err := PrincipalFromTLS(state)
	if err != nil {
		return z, err
	}
	if ctx == nil || ctx.Err() != nil {
		return z, fail("ownership_cancelled")
	}
	if !hexValue(job, 16) {
		return z, fail("ownership_ingress_job_invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return z, fail("ownership_cancelled")
	}
	i := s.find(job)
	if i < 0 || s.data.Records[i].CredentialSHA256 != p.CredentialSHA256() {
		return z, fail("ownership_denied")
	}
	if err = s.preflight(); err != nil {
		return z, err
	}
	if s.data.Records[i].State != "delivered" {
		return z, fail("ownership_ingress_pending")
	}
	return ownerReceipt(s.accepted[job]), nil
}

// Accept verifies signed metadata and the actual TLS owner before Reader.Read.
// It commits its full local promise before the first ciphertext read. Pending or
// rejected entries never admit another body; exact delivered replay reads none.
func (s *OwnerIngressStore) Accept(ctx context.Context, state *tls.ConnectionState, rawAcceptance, envelope []byte, reader io.Reader, bodyBytes int64) (OwnerUploadReceipt, error) {
	var zero OwnerUploadReceipt
	p, err := PrincipalFromTLS(state)
	if err != nil {
		return zero, err
	}
	if ctx == nil || ctx.Err() != nil {
		return zero, fail("ownership_cancelled")
	}
	v, err := VerifyAcceptance(rawAcceptance, s.config.Pin, s.config.Scope)
	if err != nil {
		return zero, err
	}
	b := v.Binding()
	if err = s.checkPublicationOwner(v); err != nil {
		return zero, err
	}
	if p.CredentialSHA256() != b.CredentialSHA256 {
		return zero, fail("ownership_denied")
	}
	if len(envelope) < 256 || len(envelope) > 512 || digest(envelope) != b.KeyEnvelopeSHA256 || bodyBytes != b.CiphertextBytes || bodyBytes > s.config.Policy.MaxBodyBytes || reader == nil {
		return zero, fail("ownership_ingress_payload_invalid")
	}
	principal, err := quotaPrincipal(s.config.Namespace, p)
	if err != nil {
		return zero, err
	}
	s.mu.Lock()
	if ctx.Err() != nil {
		s.mu.Unlock()
		return zero, fail("ownership_cancelled")
	}
	if err = s.preflight(); err != nil {
		s.mu.Unlock()
		return zero, err
	}
	i := s.find(b.JobID)
	if i >= 0 {
		old := s.data.Records[i]
		if old.CredentialSHA256 != p.CredentialSHA256() || old.AcceptanceSHA256 != v.SHA256() {
			s.mu.Unlock()
			return zero, fail("ownership_ingress_conflict")
		}
		if old.State != "delivered" {
			s.mu.Unlock()
			return zero, fail("ownership_ingress_pending")
		}
		s.mu.Unlock()
		return ownerReceipt(v), nil
	}
	var jobs, pjobs, active, pactive, charged, pcharged int64
	for _, e := range s.data.Records {
		jobs++
		charged += e.ChargeBytes
		if e.State == "reading" || s.publication != nil && e.State == "authorizing" {
			active++
		}
		if e.PrincipalSHA256 == principal {
			pjobs++
			pcharged += e.ChargeBytes
			if e.State == "reading" || s.publication != nil && e.State == "authorizing" {
				pactive++
			}
		}
	}
	promise := s.ingressCharge()
	pol := s.config.Policy
	if jobs >= pol.MaxJobs || pjobs >= pol.MaxPrincipalJobs || active >= pol.MaxActive || pactive >= pol.MaxPrincipalActive || charged+promise > pol.MaxBytes || pcharged+promise > pol.MaxPrincipalBytes {
		s.mu.Unlock()
		return zero, fail("ownership_ingress_quota")
	}
	available, e := storeAvailable(s.root)
	if e != nil || available < uint64(pol.FreeSpaceFloorBytes+charged+promise+2*StoreLedgerLimit) {
		s.mu.Unlock()
		return zero, fail("ownership_ingress_capacity")
	}
	entry := ownerIngressEntry{b.JobID, v.SHA256(), b.CredentialSHA256, principal, string(rawAcceptance), hex.EncodeToString(envelope), "reading", promise, 0}
	next := s.data
	next.Records = append(append([]ownerIngressEntry(nil), s.data.Records...), entry)
	s.accepted[b.JobID] = v
	if err = s.save(next); err != nil {
		s.mu.Unlock()
		return zero, err
	}
	i = len(s.data.Records) - 1
	s.inflight++
	file, err := storeFile(s.uploads, b.JobID+"_"+b.OriginalName, true)
	if err != nil {
		s.inflight--
		e := s.latch()
		s.mu.Unlock()
		return zero, e
	}
	// Persist the new directory entry before reading any ciphertext. File.Sync
	// alone does not make the pathname durable across a crash.
	if err = s.uploads.Sync(); err != nil {
		_ = file.Close()
		s.inflight--
		e := s.latch()
		s.mu.Unlock()
		return zero, e
	}
	s.mu.Unlock()
	hash := sha256.New()
	buf := make([]byte, 64<<10)
	var received int64
	var readErr error
	seenEOF := false
	for received < bodyBytes {
		if ctx.Err() != nil {
			readErr = ctx.Err()
			break
		}
		want := int64(len(buf))
		if bodyBytes-received < want {
			want = bodyBytes - received
		}
		n, e := reader.Read(buf[:want])
		if n < 0 || int64(n) > want {
			readErr = io.ErrUnexpectedEOF
			break
		}
		if n > 0 {
			count, we := file.Write(buf[:n])
			if we != nil || count != n {
				readErr = fail("ownership_ingress_storage_failed")
				break
			}
			hash.Write(buf[:n])
			received += int64(n)
		}
		if e == io.EOF {
			seenEOF = true
			if received != bodyBytes {
				readErr = io.ErrUnexpectedEOF
			}
			break
		}
		if e != nil || n == 0 {
			if e == nil {
				e = io.ErrNoProgress
			}
			readErr = e
			break
		}
	}
	if readErr == nil && received == bodyBytes && !seenEOF {
		n, e := reader.Read(buf[:1])
		if n != 0 || e != io.EOF {
			readErr = io.ErrUnexpectedEOF
		}
	}
	if readErr == nil && (hex.EncodeToString(hash.Sum(nil)) != b.CiphertextSHA256 || ctx.Err() != nil) {
		readErr = fail("ownership_ingress_payload_invalid")
	}
	syncErr := file.Sync()
	var originalCipher os.FileInfo
	var cipherStatErr error
	if s.publication != nil && syncErr == nil {
		originalCipher, cipherStatErr = storeSafeFile(file)
	}
	closeErr := file.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { s.inflight-- }()
	if syncErr != nil || closeErr != nil || cipherStatErr != nil || readErr != nil && readErr.Error() == "ownership_ingress_storage_failed" {
		return zero, s.latch()
	}
	if err = s.preflight(); err != nil {
		return zero, err
	}
	entry.ReceivedBytes = received
	if ctx.Err() != nil && readErr == nil {
		readErr = ctx.Err()
	}
	if readErr != nil {
		entry.State = "rejected"
		if s.replace(i, entry) != nil {
			return zero, s.latch()
		}
		return zero, fail("ownership_ingress_payload_invalid")
	}
	if s.publication != nil {
		return s.publishIngressAcceptanceLocked(i, entry, v, originalCipher)
	}
	// Sidecar is signed owner context, NOT execution proof. Job JSON is only a
	// future lifecycle cache; old workers must reject this owner-v1 algorithm.
	if err = s.publishFiles(entry, v); err != nil {
		return zero, s.latch()
	}
	entry.State = "delivered"
	if err = s.replace(i, entry); err != nil {
		return zero, err
	}
	return ownerReceipt(v), nil
}

// ownerPublishExclusive uses linkat's no-overwrite publication followed by
// removal of our private staging name. A crash between them retains two links
// and reading history, which cold Open refuses without repair. Unlike frozen
// syscall.SYS_RENAMEAT2, SYS_LINKAT is available on Linux amd64 as well as ARM64.
func ownerPublishExclusive(dir *os.File, old, new string) error {
	a, e := syscall.BytePtrFromString(old)
	if e != nil {
		return e
	}
	b, e := syscall.BytePtrFromString(new)
	if e != nil {
		return e
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, dir.Fd(), uintptr(unsafe.Pointer(a)), dir.Fd(), uintptr(unsafe.Pointer(b)), 0, 0)
	if errno != 0 {
		return errno
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	if err := syscall.Unlinkat(int(dir.Fd()), old); err != nil {
		return err
	}
	return dir.Sync()
}
func (s *OwnerIngressStore) publishFiles(entry ownerIngressEntry, v VerifiedAcceptance) error {
	write := func(dir *os.File, name string, data []byte) error {
		f, e := storeFile(dir, name, true)
		if e != nil {
			return e
		}
		n, e := f.Write(data)
		if e == nil && n != len(data) {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = s.point("publish_file_sync")
		}
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e == nil {
			e = dir.Sync()
		}
		return e
	}
	if err := write(s.acceptances, entry.JobID+".json", []byte(entry.AcceptanceJSON)); err != nil {
		return err
	}
	b := v.Binding()
	job := struct {
		JobID                     string `json:"job_id"`
		Status                    string `json:"status"`
		UploadedAt                string `json:"uploaded_at"`
		OriginalName              string `json:"original_name"`
		SizeBytes                 int64  `json:"size_bytes"`
		SHA256                    string `json:"sha256"`
		ClientID                  string `json:"client_id"`
		EncAlg                    string `json:"enc_alg"`
		EncKey                    string `json:"enc_key"`
		OwnershipVersion          int    `json:"ownership_version"`
		OwnershipAcceptanceSHA256 string `json:"ownership_acceptance_sha256"`
	}{b.JobID, "uploaded", time.Now().UTC().Format(time.RFC3339), b.OriginalName, b.CiphertextBytes, b.CiphertextSHA256, "", EncryptionAlgorithm, entry.EnvelopeHex, 1, v.SHA256()}
	raw, e := boundedJSON(job, 64<<10)
	if e != nil {
		return e
	}
	if e = write(s.jobs, b.JobID+".pending", raw); e != nil {
		return e
	}
	if e = ownerPublishExclusive(s.jobs, b.JobID+".pending", b.JobID+".json"); e != nil {
		return e
	}
	return s.jobs.Sync()
}
func (s *OwnerIngressStore) deliver(ctx context.Context, receipt OwnerUploadReceipt, write func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.preflight(); err != nil {
		return err
	}
	if ctx == nil || ctx.Err() != nil {
		return fail("ownership_cancelled")
	}
	i := s.find(receipt.JobID)
	if i < 0 || s.data.Records[i].State != "delivered" || s.data.Records[i].AcceptanceSHA256 != receipt.AcceptanceSHA256 {
		return fail("ownership_ingress_pending")
	}
	if err := write(); err != nil {
		return s.latch()
	}
	return nil
}
func (s *OwnerIngressStore) Close() error {
	if s != nil && s.publication != nil {
		return s.closePublicationIngress()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.sticky {
		return fail("ownership_ingress_unavailable")
	}
	if s.inflight != 0 {
		return fail("ownership_ingress_pending")
	}
	if err := s.preflight(); err != nil {
		return err
	}
	for _, f := range []*os.File{s.acceptances, s.jobs, s.uploads, s.root, s.lock} {
		if s.point("close") != nil || f.Close() != nil {
			return s.latch()
		}
	}
	if s.rawHeld {
		if syscall.Close(s.rawFD) != nil {
			return s.latch()
		}
		s.rawHeld = false
	}
	s.closed = true
	return nil
}

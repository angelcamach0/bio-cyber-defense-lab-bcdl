//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const publicationIntentLimit = 2*MaxAcceptanceBytes + (4 << 10)
const PublicationRunCharge int64 = publicationIntentLimit + MaxAcceptanceBytes + PublicationResponseLimit

type publicationGenesis struct {
	SchemaVersion int              `json:"schema_version"`
	Domain        string           `json:"domain"`
	Scope         PublicationScope `json:"scope"`
}
type publicationIntent struct {
	SchemaVersion            int              `json:"schema_version"`
	Domain                   string           `json:"domain"`
	PublisherScope           PublicationScope `json:"publisher_scope"`
	ProducerCredentialSHA256 string           `json:"producer_credential_sha256"`
	ProducerCredentialDER    string           `json:"producer_credential_der"`
	AcceptanceJSON           string           `json:"acceptance_json"`
	RetainedBytes            int64            `json:"retained_bytes"`
}
type publicationFilePin struct {
	info os.FileInfo
	sha  string
}
type publicationRow struct {
	dir                     os.FileInfo
	intent, receipt, output publicationFilePin
	record                  publicationIntent
	result                  PublicationReceipt
}
type PublicationSnapshot struct {
	RetainedJobs  int
	RetainedBytes int64
}

// PublicationStore owns authorization metadata only. It cannot execute work,
// mint acceptance signatures, query an authority or read a ciphertext spool.
// All partial history is retained and refused on cold Open; no repair is implicit.
type PublicationStore struct {
	mu                            sync.Mutex
	config                        PublicationStoreConfig
	root, operations, inbox, lock *os.File
	rawFD                         int
	rawHeld, sticky, closed       bool
	closeErr                      error
	scope                         PublicationScope
	genesis                       publicationFilePin
	cataloguePin                  publicationFilePin
	catalogue                     publicationCatalogue
	rows                          map[string]publicationRow
	fault                         func(string) error
}

func CreatePublicationStore(c PublicationStoreConfig) (*PublicationStore, error) {
	return openPublicationStore(c, true)
}
func OpenPublicationStore(c PublicationStoreConfig) (*PublicationStore, error) {
	return openPublicationStore(c, false)
}

func publicationDirectory(parent *os.File, name string) (*os.File, error) {
	fd, e := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("ownership_publication_history_invalid")
	}
	f := os.NewFile(uintptr(fd), "publication-directory")
	info, e := f.Stat()
	st, ok := storeStat(info)
	if e != nil || !ok || !info.IsDir() || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 {
		f.Close()
		return nil, fail("ownership_publication_history_invalid")
	}
	return f, nil
}
func publicationRead(dir *os.File, name string, limit int64) ([]byte, publicationFilePin, error) {
	f, e := storeFile(dir, name, false)
	if e != nil {
		return nil, publicationFilePin{}, e
	}
	defer f.Close()
	before, e := storeSafeFile(f)
	if e != nil || before.Size() < 1 || before.Size() > limit {
		return nil, publicationFilePin{}, fail("ownership_publication_history_invalid")
	}
	raw, e := io.ReadAll(io.NewSectionReader(f, 0, limit+1))
	after, ae := storeSafeFile(f)
	if e != nil || ae != nil || !storeInfoEqual(before, after) || int64(len(raw)) != before.Size() {
		return nil, publicationFilePin{}, fail("ownership_publication_history_invalid")
	}
	current, e := storeFile(dir, name, false)
	if e != nil {
		return nil, publicationFilePin{}, e
	}
	named, ne := storeSafeFile(current)
	ce := current.Close()
	if ne != nil || ce != nil || !storeInfoEqual(after, named) {
		return nil, publicationFilePin{}, fail("ownership_publication_history_invalid")
	}
	return raw, publicationFilePin{after, digest(raw)}, nil
}
func publicationWrite(dir *os.File, name string, raw []byte) error {
	f, e := storeFile(dir, name, true)
	if e != nil {
		return e
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
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

func openPublicationStore(c PublicationStoreConfig, create bool) (*PublicationStore, error) {
	if !authorityServicePath(c.Directory) || c.Pin.validate() != nil || c.AuthorityScope.validate() != nil || len(c.ProducerCredentialSHA256) < 1 || len(c.ProducerCredentialSHA256) > 16 {
		return nil, fail("ownership_publication_config_invalid")
	}
	if !create && c.ExpectedPublisherScope.validate() != nil {
		return nil, fail("ownership_publication_scope_invalid")
	}
	if create && c.ExpectedPublisherScope != (PublicationScope{}) {
		return nil, fail("ownership_publication_scope_invalid")
	}
	c.Pin.PublicKey = append(ed25519.PublicKey(nil), c.Pin.PublicKey...)
	c.ProducerCredentialSHA256 = append([]string(nil), c.ProducerCredentialSHA256...)
	sort.Strings(c.ProducerCredentialSHA256)
	for i, p := range c.ProducerCredentialSHA256 {
		if !hexValue(p, 64) || i > 0 && p == c.ProducerCredentialSHA256[i-1] {
			return nil, fail("ownership_publication_config_invalid")
		}
	}
	parent, e := storeRoot(filepath.Dir(c.Directory), false)
	if e != nil {
		return nil, e
	}
	if e = parent.Close(); e != nil {
		return nil, e
	}
	raw, _ := json.Marshal(struct {
		Directory, Authority, Key, Mode, Profile string
		Scope                                    AcceptanceScope
		Producers                                []string
		Global, Owner                            int
		Charge                                   int64
		CatalogueDomain                          string
		CatalogueLimit                           int
		RoleRule                                 string
	}{c.Directory, c.Pin.AuthorityID, hex.EncodeToString(c.Pin.PublicKey), c.Pin.PipelineMode, c.Pin.ExecutionProfileSHA256, c.AuthorityScope, c.ProducerCredentialSHA256, PublicationRunLimit, PublicationOwnerLimit, PublicationRunCharge, publicationCatalogueDomain, publicationCatalogueLimit, "distinct-leaf-and-rsa-key.v1"})
	policy := digest(raw)
	root, e := storeRoot(c.Directory, create)
	if e != nil {
		return nil, e
	}
	s := &PublicationStore{config: c, root: root, rows: map[string]publicationRow{}}
	ok := false
	validatedCustody := false
	defer func() {
		if !ok && (create || validatedCustody) && s.rawHeld {
			s.sticky = true
		}
		if !ok && !s.sticky {
			for _, f := range []*os.File{s.operations, s.inbox, s.lock, s.root} {
				if f != nil {
					f.Close()
				}
			}
			if s.rawHeld {
				syscall.Close(s.rawFD)
				s.rawHeld = false
			}
		}
	}()
	s.lock, e = storeFile(root, "instance.lock", create)
	if e != nil {
		return nil, e
	}
	info, e := s.lock.Stat()
	if e != nil || info.Size() != 0 {
		return nil, fail("ownership_publication_lock_invalid")
	}
	if syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, fail("ownership_publication_locked")
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, s.lock.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return nil, fail("ownership_publication_lock_invalid")
	}
	s.rawFD = int(fd)
	s.rawHeld = true
	if create {
		if s.lock.Sync() != nil || root.Sync() != nil {
			return nil, s.latch()
		}
		id, e := storeRandom(16)
		if e != nil {
			return nil, s.latch()
		}
		s.scope = PublicationScope{id, policy}
		for _, name := range []string{"operations", "inbox"} {
			if syscall.Mkdirat(int(root.Fd()), name, 0700) != nil || root.Sync() != nil {
				return nil, s.latch()
			}
		}
		g, _ := json.Marshal(publicationGenesis{1, "biozero.authorization-publication.genesis.v1", s.scope})
		if publicationWrite(root, "genesis.json", g) != nil {
			return nil, s.latch()
		}
		catalogue, _ := json.Marshal(publicationCatalogue{1, publicationCatalogueDomain, s.scope, []publicationCatalogueEntry{}})
		if publicationWrite(root, "catalogue.json", catalogue) != nil {
			return nil, s.latch()
		}
	} else {
		g, _, e := publicationRead(root, "genesis.json", 4096)
		if e != nil {
			return nil, e
		}
		var header publicationGenesis
		if strictJSON(g, &header, 4096) != nil || header.SchemaVersion != 1 || header.Domain != "biozero.authorization-publication.genesis.v1" || header.Scope.validate() != nil || header.Scope != c.ExpectedPublisherScope || header.Scope.PolicySHA256 != policy {
			return nil, fail("ownership_publication_scope_invalid")
		}
		s.scope = header.Scope
		validatedCustody = true
	}
	s.operations, e = publicationDirectory(root, "operations")
	if e != nil {
		return nil, e
	}
	s.inbox, e = publicationDirectory(root, "inbox")
	if e != nil {
		return nil, e
	}
	_, s.genesis, e = publicationRead(root, "genesis.json", 4096)
	if e != nil {
		return nil, e
	}
	if e = s.loadCatalogue(); e != nil {
		return nil, e
	}
	for _, entry := range s.catalogue.Records {
		job := entry.JobID
		row, e := s.readRow(job)
		if e != nil {
			return nil, e
		}
		s.rows[job] = row
	}
	if e = s.preflight(); e != nil {
		return nil, e
	}
	ok = true
	return s, nil
}

func (s *PublicationStore) Scope() PublicationScope { return s.scope }
func (s *PublicationStore) InboxDirectory() string  { return filepath.Join(s.config.Directory, "inbox") }
func (s *PublicationStore) point(name string) error {
	if s.fault != nil {
		return s.fault(name)
	}
	return nil
}
func (s *PublicationStore) latch() error {
	s.sticky = true
	return fail("ownership_publication_uncertain")
}

func (s *PublicationStore) AuthorizeProducer(state *tls.ConnectionState) error {
	if s == nil || state == nil || state.Version != tls.VersionTLS13 {
		return fail("ownership_publication_denied")
	}
	p, e := PrincipalFromTLS(state)
	if e != nil {
		return fail("ownership_publication_denied")
	}
	now := time.Now()
	for _, chain := range state.VerifiedChains {
		for _, c := range chain {
			if c == nil || now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
				return fail("ownership_publication_denied")
			}
		}
	}
	for _, expected := range s.config.ProducerCredentialSHA256 {
		if expected == p.CredentialSHA256() {
			return nil
		}
	}
	return fail("ownership_publication_denied")
}
func (s *PublicationStore) receipt(v VerifiedAcceptance) PublicationReceipt {
	b := v.Binding()
	return PublicationReceipt{1, PublicationReceiptDomain, "published", s.scope, s.config.AuthorityScope, b.JobID, v.SHA256(), b.CredentialSHA256, b.ExecutionProfileSHA256, b.PipelineMode}
}
func (s *PublicationStore) readRow(job string) (publicationRow, error) {
	var row publicationRow
	dir, e := publicationDirectory(s.operations, job)
	if e != nil {
		return row, e
	}
	defer dir.Close()
	row.dir, e = dir.Stat()
	if e != nil {
		return row, e
	}
	names, e := ownerReadNames(dir, 2)
	sort.Strings(names)
	if e != nil || !reflect.DeepEqual(names, []string{"intent.json", "published.json"}) {
		return row, fail("ownership_publication_history_invalid")
	}
	raw, pin, e := publicationRead(dir, "intent.json", publicationIntentLimit)
	if e != nil {
		return row, e
	}
	row.intent = pin
	if strictJSON(raw, &row.record, publicationIntentLimit) != nil || row.record.SchemaVersion != 1 || row.record.Domain != "biozero.authorization-publication.intent.v1" || row.record.PublisherScope != s.scope || row.record.RetainedBytes != PublicationRunCharge {
		return row, fail("ownership_publication_history_invalid")
	}
	allowed := false
	for _, p := range s.config.ProducerCredentialSHA256 {
		allowed = allowed || p == row.record.ProducerCredentialSHA256
	}
	if !allowed {
		return row, fail("ownership_publication_history_invalid")
	}
	v, e := VerifyAcceptance([]byte(row.record.AcceptanceJSON), s.config.Pin, s.config.AuthorityScope)
	if e != nil || v.Binding().JobID != job || !bytes.Equal(v.canonical, []byte(row.record.AcceptanceJSON)) {
		return row, fail("ownership_publication_history_invalid")
	}
	encoded := row.record.ProducerCredentialDER
	if len(encoded) < 2 || len(encoded) > 2*(16<<10) || len(encoded)%2 != 0 || !hexValue(encoded, len(encoded)) {
		return row, fail("ownership_publication_history_invalid")
	}
	der, _ := hex.DecodeString(encoded)
	producer, _, e := rsaLeaf(&x509.Certificate{Raw: der})
	if e != nil || digest(producer.Raw) != row.record.ProducerCredentialSHA256 || !publicationProducerDistinct(v, producer) {
		return row, fail("ownership_publication_history_invalid")
	}
	raw, row.receipt, e = publicationRead(dir, "published.json", PublicationResponseLimit)
	if e != nil {
		return row, e
	}
	if strictJSON(raw, &row.result, PublicationResponseLimit) != nil || row.result != s.receipt(v) {
		return row, fail("ownership_publication_history_invalid")
	}
	raw, row.output, e = publicationRead(s.inbox, job+".json", MaxAcceptanceBytes)
	if e != nil || !bytes.Equal(raw, v.canonical) {
		return row, fail("ownership_publication_history_invalid")
	}
	return row, nil
}

func publicationSameFile(dir *os.File, name string, limit int64, pin publicationFilePin) bool {
	raw, fresh, e := publicationRead(dir, name, limit)
	return e == nil && digest(raw) == pin.sha && storeInfoEqual(pin.info, fresh.info)
}
func (s *PublicationStore) preflight() error {
	if s == nil || s.closed || s.sticky || s.root == nil {
		return fail("ownership_publication_unavailable")
	}
	fresh, e := storeRoot(s.config.Directory, false)
	if e != nil {
		return s.latch()
	}
	a, e1 := fresh.Stat()
	ce := fresh.Close()
	b, e2 := s.root.Stat()
	if e1 != nil || ce != nil || e2 != nil || !os.SameFile(a, b) {
		return s.latch()
	}
	names, e := ownerReadNames(s.root, 5)
	sort.Strings(names)
	if e != nil || !reflect.DeepEqual(names, []string{"catalogue.json", "genesis.json", "inbox", "instance.lock", "operations"}) {
		return s.latch()
	}
	for name, old := range map[string]*os.File{"operations": s.operations, "inbox": s.inbox} {
		f, e := publicationDirectory(s.root, name)
		if e != nil {
			return s.latch()
		}
		a, e1 = f.Stat()
		ce = f.Close()
		b, e2 = old.Stat()
		if e1 != nil || ce != nil || e2 != nil || !os.SameFile(a, b) {
			return s.latch()
		}
	}
	lock, e := storeFile(s.root, "instance.lock", false)
	if e != nil {
		return s.latch()
	}
	a, e1 = lock.Stat()
	ce = lock.Close()
	b, e2 = s.lock.Stat()
	if e1 != nil || ce != nil || e2 != nil || !os.SameFile(a, b) || a.Size() != 0 {
		return s.latch()
	}
	if !publicationSameFile(s.root, "genesis.json", 4096, s.genesis) {
		return s.latch()
	}
	if !s.catalogueMatchesRows() {
		return s.latch()
	}
	operations, e := ownerReadNames(s.operations, PublicationRunLimit)
	if e != nil || len(operations) != len(s.rows) {
		return s.latch()
	}
	outputs, e := ownerReadNames(s.inbox, PublicationRunLimit)
	if e != nil || len(outputs) != len(s.rows) {
		return s.latch()
	}
	for _, name := range outputs {
		if len(name) != 21 || name[16:] != ".json" {
			return s.latch()
		}
		if _, ok := s.rows[name[:16]]; !ok {
			return s.latch()
		}
	}
	owners := map[string]int{}
	for _, job := range operations {
		row, ok := s.rows[job]
		if !ok {
			return s.latch()
		}
		dir, e := publicationDirectory(s.operations, job)
		if e != nil {
			return s.latch()
		}
		info, e := dir.Stat()
		names, ne := ownerReadNames(dir, 2)
		sort.Strings(names)
		valid := e == nil && os.SameFile(info, row.dir) && ne == nil && reflect.DeepEqual(names, []string{"intent.json", "published.json"}) && publicationSameFile(dir, "intent.json", publicationIntentLimit, row.intent) && publicationSameFile(dir, "published.json", PublicationResponseLimit, row.receipt) && publicationSameFile(s.inbox, job+".json", MaxAcceptanceBytes, row.output)
		ce = dir.Close()
		if !valid || ce != nil {
			return s.latch()
		}
		owners[row.result.CredentialSHA256]++
		if owners[row.result.CredentialSHA256] > PublicationOwnerLimit {
			return s.latch()
		}
	}
	return nil
}
func (s *PublicationStore) Check() error { s.mu.Lock(); defer s.mu.Unlock(); return s.preflight() }
func (s *PublicationStore) Snapshot() (PublicationSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.preflight(); e != nil {
		return PublicationSnapshot{}, e
	}
	return PublicationSnapshot{len(s.rows), int64(len(s.rows)) * PublicationRunCharge}, nil
}

// Publish performs one local durable transaction. A fully verified immutable
// inbox file may authorize its owner before the final journal marker/HTTP ACK.
// Failure in that window fences this writer, never retroactively revokes that
// signed authorization or grants execution/scientific approval.
func (s *PublicationStore) Publish(ctx context.Context, state *tls.ConnectionState, raw []byte) (PublicationReceipt, error) {
	var zero PublicationReceipt
	if s.AuthorizeProducer(state) != nil {
		return zero, fail("ownership_publication_denied")
	}
	if ctx == nil || ctx.Err() != nil {
		return zero, fail("ownership_publication_cancelled")
	}
	v, e := VerifyAcceptance(raw, s.config.Pin, s.config.AuthorityScope)
	if e != nil {
		return zero, fail("ownership_publication_acceptance_invalid")
	}
	b := v.Binding()
	producer, _ := PrincipalFromTLS(state)
	if !publicationProducerDistinct(v, producer.leaf) {
		return zero, fail("ownership_publication_role_invalid")
	}
	canonical := append([]byte(nil), v.canonical...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e = s.preflight(); e != nil {
		return zero, e
	}
	if ctx.Err() != nil {
		return zero, fail("ownership_publication_cancelled")
	}
	if row, ok := s.rows[b.JobID]; ok {
		if row.result.AcceptanceSHA256 != v.SHA256() {
			_ = publicationWrite(s.root, "conflicting-acceptance.json", canonical)
			return zero, s.latch()
		}
		return row.result, nil
	}
	count := 0
	for _, row := range s.rows {
		if row.result.CredentialSHA256 == b.CredentialSHA256 {
			count++
		}
	}
	if len(s.rows) >= PublicationRunLimit || count >= PublicationOwnerLimit {
		return zero, fail("ownership_publication_quota")
	}
	intent := publicationIntent{1, "biozero.authorization-publication.intent.v1", s.scope, producer.CredentialSHA256(), hex.EncodeToString(producer.leaf.Raw), string(canonical), PublicationRunCharge}
	ir, e := boundedJSON(intent, publicationIntentLimit)
	if e != nil {
		return zero, e
	}
	if e = s.reserveCatalogue(publicationCatalogueEntry{b.JobID, v.SHA256(), b.CredentialSHA256, producer.CredentialSHA256(), PublicationRunCharge}); e != nil {
		return zero, e
	}
	if syscall.Mkdirat(int(s.operations.Fd()), b.JobID, 0700) != nil || s.operations.Sync() != nil {
		return zero, s.latch()
	}
	if s.point("operation_created") != nil {
		return zero, s.latch()
	}
	dir, e := publicationDirectory(s.operations, b.JobID)
	if e != nil {
		return zero, s.latch()
	}
	defer dir.Close()
	if publicationWrite(dir, "intent.json", ir) != nil || s.point("intent_durable") != nil {
		return zero, s.latch()
	}
	pending := b.JobID + ".pending"
	if publicationWrite(s.inbox, pending, canonical) != nil || s.point("output_staged") != nil {
		return zero, s.latch()
	}
	old, _ := syscall.BytePtrFromString(pending)
	dest, _ := syscall.BytePtrFromString(b.JobID + ".json")
	_, _, errno := syscall.Syscall6(syscall.SYS_LINKAT, s.inbox.Fd(), uintptr(unsafe.Pointer(old)), s.inbox.Fd(), uintptr(unsafe.Pointer(dest)), 0, 0)
	if errno != 0 || s.point("output_linked") != nil {
		return zero, s.latch()
	}
	if s.inbox.Sync() != nil || s.point("output_link_synced") != nil {
		return zero, s.latch()
	}
	if syscall.Unlinkat(int(s.inbox.Fd()), pending) != nil || s.point("output_unlinked") != nil {
		return zero, s.latch()
	}
	if s.inbox.Sync() != nil || s.point("output_durable") != nil {
		return zero, s.latch()
	}
	result := s.receipt(v)
	rr, _ := json.Marshal(result)
	if publicationWrite(dir, "published.json", rr) != nil || s.point("receipt_durable") != nil {
		return zero, s.latch()
	}
	row, e := s.readRow(b.JobID)
	if e != nil {
		return zero, s.latch()
	}
	s.rows[b.JobID] = row
	if e = s.preflight(); e != nil {
		return zero, e
	}
	return result, nil
}
func (s *PublicationStore) Get(ctx context.Context, state *tls.ConnectionState, job, hash string) (PublicationReceipt, error) {
	var zero PublicationReceipt
	if s.AuthorizeProducer(state) != nil {
		return zero, fail("ownership_publication_denied")
	}
	if ctx == nil || ctx.Err() != nil || !hexValue(job, 16) || !hexValue(hash, 64) {
		return zero, fail("ownership_publication_request_invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.preflight(); e != nil {
		return zero, e
	}
	row, ok := s.rows[job]
	if !ok || row.result.AcceptanceSHA256 != hash {
		return zero, fail("ownership_publication_not_found")
	}
	v, e := VerifyAcceptance([]byte(row.record.AcceptanceJSON), s.config.Pin, s.config.AuthorityScope)
	if e != nil {
		return zero, s.latch()
	}
	producer, _ := PrincipalFromTLS(state)
	if !publicationProducerDistinct(v, producer.leaf) {
		return zero, fail("ownership_publication_role_invalid")
	}
	return row.result, nil
}
func (s *PublicationStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closeErr != nil {
		return s.closeErr
	}
	if s.closed {
		return s.closeErr
	}
	if s.sticky {
		s.closeErr = fail("ownership_publication_uncertain")
		return s.closeErr
	}
	if e := s.preflight(); e != nil {
		s.closeErr = e
		return e
	}
	for _, f := range []*os.File{s.operations, s.inbox, s.root, s.lock} {
		if e := f.Close(); e != nil {
			s.closeErr = e
			s.sticky = true
			return e
		}
	}
	if s.rawHeld {
		if e := syscall.Close(s.rawFD); e != nil {
			s.closeErr = e
			s.sticky = true
			return e
		}
		s.rawHeld = false
	}
	s.closed = true
	return nil
}

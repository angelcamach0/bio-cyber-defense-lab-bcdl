//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	StoreLedgerLimit            = 8 << 20
	StoreMetadataHeadroom int64 = 131072
	storeLedgerDomain           = "biozero.ownership.store.v1"
)

// StorePolicy is fixed at genesis. Charges are full body reservations plus
// metadata headroom and survive acceptance/rejection; no TTL or refund exists.
type StorePolicy struct {
	MaxJobs             int   `json:"max_jobs"`
	MaxPrincipalJobs    int   `json:"max_principal_jobs"`
	MaxBytes            int64 `json:"max_bytes"`
	MaxPrincipalBytes   int64 `json:"max_principal_bytes"`
	MaxActive           int   `json:"max_active"`
	MaxPrincipalActive  int   `json:"max_principal_active"`
	MaxBodyBytes        int64 `json:"max_body_bytes"`
	FreeSpaceFloorBytes int64 `json:"free_space_floor_bytes"`
	ChallengeTTLSeconds int64 `json:"challenge_ttl_seconds"`
}

func DefaultStorePolicy() StorePolicy {
	return StorePolicy{64, 16, 512 << 20, 128 << 20, 2, 1, 25 << 20, 128 << 20, 300}
}
func (p StorePolicy) validate() error {
	charge := p.MaxBodyBytes + StoreMetadataHeadroom
	if p.MaxBodyBytes < 16 || p.MaxBodyBytes > MaxCiphertextBytes || p.MaxJobs < 1 || p.MaxJobs > 64 || p.MaxPrincipalJobs < 1 || p.MaxPrincipalJobs > p.MaxJobs ||
		p.MaxBytes < charge || p.MaxBytes > 64*(MaxCiphertextBytes+StoreMetadataHeadroom) || p.MaxPrincipalBytes < charge || p.MaxPrincipalBytes > p.MaxBytes ||
		p.MaxActive < 1 || p.MaxActive > p.MaxJobs || p.MaxPrincipalActive < 1 || p.MaxPrincipalActive > p.MaxActive || p.MaxPrincipalActive > p.MaxPrincipalJobs ||
		p.FreeSpaceFloorBytes < 0 || p.FreeSpaceFloorBytes > 1<<40 || p.ChallengeTTLSeconds < 1 || p.ChallengeTTLSeconds > 300 {
		return fail("ownership_policy_invalid")
	}
	return nil
}

type StoreConfig struct {
	Directory     string
	Namespace     string
	Pin           AuthorityPin
	SigningKey    ed25519.PrivateKey
	Policy        StorePolicy
	ExpectedScope AcceptanceScope
}

// Identity serialization order is part of PolicySHA256: namespace, authority,
// externally pinned key ID, mode/profile and every numeric policy field.
type storeIdentity struct {
	Namespace              string      `json:"namespace"`
	AuthorityID            string      `json:"authority_id"`
	KeyID                  string      `json:"key_id"`
	PipelineMode           string      `json:"pipeline_mode"`
	ExecutionProfileSHA256 string      `json:"execution_profile_sha256"`
	Policy                 StorePolicy `json:"policy"`
}

func (c StoreConfig) identity() storeIdentity {
	return storeIdentity{c.Namespace, c.Pin.AuthorityID, digest(c.Pin.PublicKey), c.Pin.PipelineMode, c.Pin.ExecutionProfileSHA256, c.Policy}
}
func (c StoreConfig) validate() error {
	if !nameValid(c.Namespace) {
		return fail("ownership_namespace_invalid")
	}
	if err := c.Pin.validate(); err != nil {
		return err
	}
	if err := c.Policy.validate(); err != nil {
		return err
	}
	if len(c.SigningKey) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(c.SigningKey[:32]), c.SigningKey) || !bytes.Equal(c.SigningKey.Public().(ed25519.PublicKey), c.Pin.PublicKey) {
		return fail("ownership_signing_key_invalid")
	}
	return nil
}

type storeEntry struct {
	RequestID        string `json:"request_id"`
	PrincipalSHA256  string `json:"principal_sha256"`
	CredentialSHA256 string `json:"credential_sha256"`
	CertificateDER   string `json:"certificate_der"`
	State            string `json:"state"`
	ChargeBytes      int64  `json:"charge_bytes"`
	ChallengeJSON    string `json:"challenge_json"`
	ManifestJSON     string `json:"manifest_json"`
	AcceptanceJSON   string `json:"acceptance_json"`
	FailureCode      string `json:"failure_code"`
}
type storeLedger struct {
	SchemaVersion int           `json:"schema_version"`
	Domain        string        `json:"domain"`
	StoreID       string        `json:"store_id"`
	Identity      storeIdentity `json:"identity"`
	Records       []storeEntry  `json:"records"`
}
type signedStoreLedger struct {
	Ledger    storeLedger `json:"ledger"`
	Signature string      `json:"signature"`
}

// StoreRecord contains copies of owner-authorized protocol DTOs, never the
// private ledger, quota principal or persisted certificate bytes.
type StoreRecord struct {
	State       string
	Challenge   SignedChallenge
	Acceptance  *SignedAcceptance
	FailureCode string
}
type StoreSnapshot struct {
	Jobs         int
	ChargedBytes int64
	Active       int
	Reading      int
	Accepted     int
	Rejected     int
	Sticky       bool
}
type Store struct {
	mu             sync.Mutex
	root, lock     *os.File
	ledgerFile     *os.File
	rawLockFD      int
	rawLockHeld    bool
	config         StoreConfig
	scope          AcceptanceScope
	data           storeLedger
	ledgerSHA      string
	sticky, closed bool
	inflight       int
	fault          func(string) error // Test-only fault injection, never configured by ingress.
	available      func(*os.File) (uint64, error)
}

func (s *Store) Scope() AcceptanceScope { s.mu.Lock(); defer s.mu.Unlock(); return s.scope }
func (s *Store) Healthy() bool          { s.mu.Lock(); defer s.mu.Unlock(); return s.preflight() == nil }
func (s *Store) Snapshot() StoreSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := storeCounts(s.data.Records, "")
	v.Sticky = s.sticky
	return v
}
func storeCounts(rows []storeEntry, principal string) StoreSnapshot {
	v := StoreSnapshot{}
	for _, r := range rows {
		if principal != "" && r.PrincipalSHA256 != principal {
			continue
		}
		v.Jobs++
		v.ChargedBytes += r.ChargeBytes
		switch r.State {
		case "reserved":
			v.Active++
		case "reading":
			v.Active++
			v.Reading++
		case "accepted":
			v.Accepted++
		case "rejected":
			v.Rejected++
		}
	}
	return v
}
func (s *Store) point(name string) error {
	if s.fault != nil {
		return s.fault(name)
	}
	return nil
}
func (s *Store) latch(code string) error { s.sticky = true; return fail(code) }
func (s *Store) ready() error {
	if s.closed || s.sticky || s.root == nil || s.lock == nil {
		return fail("ownership_store_unavailable")
	}
	return nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.sticky {
		return fail("ownership_store_unavailable")
	}
	if s.inflight != 0 {
		return fail("ownership_reading_pending")
	}
	if s.ledgerSHA != "" {
		if err := s.preflight(); err != nil {
			return err
		}
	}
	if s.ledgerFile != nil {
		if s.point("close_ledger") != nil || s.ledgerFile.Close() != nil {
			return s.latch("ownership_store_close_failed")
		}
	}
	if s.root != nil {
		if s.point("close_root") != nil || s.root.Close() != nil {
			return s.latch("ownership_store_close_failed")
		}
	}
	if s.lock != nil {
		if s.point("close_lock") != nil || s.lock.Close() != nil {
			return s.latch("ownership_store_close_failed")
		}
	}
	if s.rawLockHeld {
		if s.point("close_raw_lock") != nil || syscall.Close(s.rawLockFD) != nil {
			return s.latch("ownership_store_close_failed")
		}
		s.rawLockHeld = false
	}
	s.closed = true
	return nil
}

func CreateStore(config StoreConfig) (*Store, error) { return openStore(config, true) }
func OpenStore(config StoreConfig) (*Store, error)   { return openStore(config, false) }
func openStore(config StoreConfig, create bool) (*Store, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	identityJSON, _ := json.Marshal(config.identity())
	policySHA := digest(identityJSON)
	if create {
		if config.ExpectedScope != (AcceptanceScope{}) {
			return nil, fail("ownership_scope_invalid")
		}
	} else if !hexValue(config.ExpectedScope.StoreID, 32) || config.ExpectedScope.PolicySHA256 != policySHA {
		return nil, fail("ownership_scope_invalid")
	}
	config.SigningKey = append(ed25519.PrivateKey(nil), config.SigningKey...)
	config.Pin.PublicKey = append(ed25519.PublicKey(nil), config.Pin.PublicKey...)
	root, err := storeRoot(config.Directory, create)
	if err != nil {
		return nil, err
	}
	s := &Store{root: root, config: config, available: storeAvailable}
	success := false
	defer func() {
		if !success {
			s.Close()
		}
	}()
	s.lock, err = storeFile(root, "instance.lock", create)
	if err != nil {
		return nil, fail("ownership_lock_unsafe")
	}
	info, err := s.lock.Stat()
	if err != nil || info.Size() != 0 {
		return nil, fail("ownership_lock_unsafe")
	}
	if syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, fail("ownership_instance_locked")
	}
	// A raw CLOEXEC duplicate has no os.File finalizer. Ambiguous writers keep
	// this lifetime authority until real process death, even if Store is GC'd.
	dup, _, errno := syscall.Syscall(syscall.SYS_FCNTL, s.lock.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return nil, fail("ownership_lock_unsafe")
	}
	s.rawLockFD = int(dup)
	s.rawLockHeld = true
	if create {
		if s.lock.Sync() != nil || root.Sync() != nil {
			return nil, fail("ownership_directory_sync_failed")
		}
		id, err := storeRandom(16)
		if err != nil {
			return nil, err
		}
		s.scope = AcceptanceScope{StoreID: id, PolicySHA256: policySHA}
		s.data = storeLedger{1, storeLedgerDomain, id, config.identity(), []storeEntry{}}
		if err = s.save(s.data); err != nil {
			return nil, err
		}
	} else {
		s.scope = config.ExpectedScope
		if err = s.checkNames(false); err != nil {
			return nil, err
		}
		raw, err := storeRead(root, "ledger.json", StoreLedgerLimit)
		if err != nil {
			return nil, fail("ownership_ledger_unavailable")
		}
		if err = s.load(raw); err != nil {
			return nil, err
		}
		s.ledgerSHA = digest(raw)
		s.ledgerFile, err = storeFile(root, "ledger.json", false)
		if err != nil {
			return nil, err
		}
	}
	success = true
	return s, nil
}

func storeRandom(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fail("ownership_random_failed")
	}
	return hex.EncodeToString(b), nil
}
func quotaPrincipal(namespace string, owner Principal) (string, error) {
	return quotaPrincipalCN(namespace, owner.CommonName())
}
func quotaPrincipalCN(namespace, cn string) (string, error) {
	if cn == "" || len(cn) > 256 || !utf8.ValidString(cn) {
		return "", fail("ownership_quota_principal_invalid")
	}
	for _, r := range cn {
		if r < 32 || r == 127 {
			return "", fail("ownership_quota_principal_invalid")
		}
	}
	return digest([]byte("biozero.ownership.quota.v1\x00" + namespace + "\x00" + cn)), nil
}

func (s *Store) checkNames(allowMissingLedger bool) error {
	names, err := storeNames(s.root)
	if err != nil {
		return err
	}
	ledger, lock := false, false
	for _, name := range names {
		switch name {
		case "instance.lock":
			lock = true
		case "ledger.json":
			ledger = true
		case "ledger.next", "transaction.pending":
			return fail("ownership_store_pending")
		default:
			return fail("ownership_history_unknown")
		}
	}
	if !lock || (!ledger && !allowMissingLedger) {
		return fail("ownership_ledger_unavailable")
	}
	return nil
}
func (s *Store) preflight() error {
	if err := s.ready(); err != nil {
		return err
	}
	currentRoot, err := storeRoot(s.config.Directory, false)
	if err != nil {
		return s.latch("ownership_store_changed")
	}
	rootInfo, rootErr := s.root.Stat()
	currentRootInfo, currentRootErr := currentRoot.Stat()
	currentRoot.Close()
	if rootErr != nil || currentRootErr != nil || !os.SameFile(rootInfo, currentRootInfo) {
		return s.latch("ownership_store_changed")
	}
	if err := s.checkNames(s.ledgerSHA == ""); err != nil {
		return s.latch("ownership_store_changed")
	}
	lock, err := storeFile(s.root, "instance.lock", false)
	if err != nil {
		return s.latch("ownership_store_changed")
	}
	old, oldErr := storeSafeFile(s.lock)
	current, currentErr := storeSafeFile(lock)
	lock.Close()
	if oldErr != nil || currentErr != nil || !os.SameFile(old, current) || current.Size() != 0 {
		return s.latch("ownership_store_changed")
	}
	raw, err := storeRead(s.root, "ledger.json", StoreLedgerLimit)
	if s.ledgerSHA == "" {
		if !errors.Is(err, os.ErrNotExist) {
			return s.latch("ownership_store_changed")
		}
	} else if err != nil || digest(raw) != s.ledgerSHA {
		return s.latch("ownership_store_changed")
	}
	if s.ledgerSHA != "" {
		current, err := storeFile(s.root, "ledger.json", false)
		if err != nil {
			return s.latch("ownership_store_changed")
		}
		a, e1 := storeSafeFile(s.ledgerFile)
		b, e2 := storeSafeFile(current)
		current.Close()
		if e1 != nil || e2 != nil || !os.SameFile(a, b) {
			return s.latch("ownership_store_changed")
		}
	}
	return nil
}

func (s *Store) save(next storeLedger) error {
	if err := s.preflight(); err != nil {
		return err
	}
	canonical, err := json.Marshal(next)
	if err != nil {
		return s.latch("ownership_ledger_write_failed")
	}
	envelope := signedStoreLedger{next, hex.EncodeToString(ed25519.Sign(s.config.SigningKey, canonical))}
	raw, err := json.Marshal(envelope)
	if err != nil || len(raw) > StoreLedgerLimit {
		return s.latch("ownership_ledger_oversized")
	}
	marker, err := storeFile(s.root, "transaction.pending", true)
	if err != nil {
		return s.latch("ownership_transaction_failed")
	}
	intent, _ := json.Marshal(struct {
		StoreID        string `json:"store_id"`
		PreviousSHA256 string `json:"previous_sha256"`
		NextSHA256     string `json:"next_sha256"`
	}{s.scope.StoreID, s.ledgerSHA, digest(raw)})
	err = s.point("marker_write")
	if err == nil {
		_, err = marker.Write(intent)
	}
	if err == nil {
		err = s.point("marker_sync")
	}
	if err == nil {
		err = marker.Sync()
	}
	closeErr := marker.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = s.point("marker_parent_sync")
	}
	if err == nil {
		err = s.root.Sync()
	}
	if err != nil {
		return s.latch("ownership_transaction_failed")
	}
	temp, err := storeFile(s.root, "ledger.next", true)
	if err != nil {
		return s.latch("ownership_transaction_failed")
	}
	err = s.point("write")
	if err == nil {
		var n int
		n, err = temp.Write(raw)
		if n != len(raw) && err == nil {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = s.point("file_sync")
	}
	if err == nil {
		err = temp.Sync()
	}
	if err == nil {
		err = s.point("file_close")
	}
	closeErr = temp.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = s.point("rename")
	}
	if err == nil {
		err = syscall.Renameat(int(s.root.Fd()), "ledger.next", int(s.root.Fd()), "ledger.json")
	}
	if err == nil {
		err = s.point("parent_sync")
	}
	if err == nil {
		err = s.root.Sync()
	}
	if err != nil {
		return s.latch("ownership_transaction_failed")
	}
	if err = s.point("marker_unlink"); err == nil {
		err = syscall.Unlinkat(int(s.root.Fd()), "transaction.pending")
	}
	if err == nil {
		err = s.point("marker_remove_sync")
	}
	if err == nil {
		err = s.root.Sync()
	}
	if err != nil {
		return s.latch("ownership_transaction_failed")
	}
	anchor, err := storeFile(s.root, "ledger.json", false)
	if err != nil {
		return s.latch("ownership_store_changed")
	}
	if s.ledgerFile != nil {
		if s.ledgerFile.Close() != nil {
			anchor.Close()
			return s.latch("ownership_store_close_failed")
		}
	}
	s.ledgerFile = anchor
	s.data = next
	s.ledgerSHA = digest(raw)
	return nil
}

func (s *Store) load(raw []byte) error {
	var env signedStoreLedger
	if err := decodeStoreJSON(raw, &env); err != nil {
		return err
	}
	canonical, _ := json.Marshal(env.Ledger)
	if !hexValue(env.Signature, 128) {
		return fail("ownership_ledger_signature_invalid")
	}
	sig, _ := hex.DecodeString(env.Signature)
	if !ed25519.Verify(s.config.Pin.PublicKey, canonical, sig) {
		return fail("ownership_ledger_signature_invalid")
	}
	d := env.Ledger
	if d.SchemaVersion != 1 || d.Domain != storeLedgerDomain || d.StoreID != s.scope.StoreID || d.Identity != s.config.identity() || len(d.Records) > 64 {
		return fail("ownership_ledger_identity_invalid")
	}
	seenJobs := map[string]bool{}
	seenRequests := map[string]bool{}
	seenNonces := map[string]bool{}
	for _, r := range d.Records {
		if !hexValue(r.RequestID, 32) || !hexValue(r.PrincipalSHA256, 64) || !hexValue(r.CredentialSHA256, 64) || r.ChargeBytes != s.config.Policy.MaxBodyBytes+StoreMetadataHeadroom || len(r.CertificateDER) > 32<<10 || len(r.CertificateDER)%2 != 0 || !hexValue(r.CertificateDER, len(r.CertificateDER)) {
			return fail("ownership_ledger_record_invalid")
		}
		der, e := hex.DecodeString(r.CertificateDER)
		if e != nil {
			return fail("ownership_ledger_record_invalid")
		}
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return fail("ownership_ledger_record_invalid")
		}
		leaf, _, e := rsaLeaf(cert)
		if e != nil || digest(der) != r.CredentialSHA256 {
			return fail("ownership_ledger_record_invalid")
		}
		principal, e := quotaPrincipalCN(s.config.Namespace, leaf.Subject.CommonName)
		if e != nil || principal != r.PrincipalSHA256 {
			return fail("ownership_ledger_record_invalid")
		}
		var ch SignedChallenge
		if strictJSON([]byte(r.ChallengeJSON), &ch, MaxChallengeBytes) != nil {
			return fail("ownership_ledger_record_invalid")
		}
		issued, e := canonicalTime(ch.Claim.IssuedAt)
		if e != nil {
			return fail("ownership_ledger_record_invalid")
		}
		expires, e := canonicalTime(ch.Claim.ExpiresAt)
		if e != nil || expires.Sub(issued) != time.Duration(s.config.Policy.ChallengeTTLSeconds)*time.Second {
			return fail("ownership_ledger_record_invalid")
		}
		verified, e := verifyChallenge([]byte(r.ChallengeJSON), s.config.Pin, r.CredentialSHA256, issued)
		if e != nil {
			return fail("ownership_ledger_record_invalid")
		}
		canonicalChallenge, _ := MarshalChallenge(ch)
		if string(canonicalChallenge) != r.ChallengeJSON {
			return fail("ownership_ledger_record_invalid")
		}
		requestKey := r.PrincipalSHA256 + "/" + r.RequestID
		if seenJobs[ch.Claim.JobID] || seenRequests[requestKey] || seenNonces[ch.Claim.Nonce] {
			return fail("ownership_ledger_record_invalid")
		}
		seenJobs[ch.Claim.JobID] = true
		seenRequests[requestKey] = true
		seenNonces[ch.Claim.Nonce] = true
		if r.State == "reserved" {
			if r.ManifestJSON != "" || r.AcceptanceJSON != "" || r.FailureCode != "" {
				return fail("ownership_ledger_record_invalid")
			}
		} else {
			manifest, e := storedManifest([]byte(r.ManifestJSON), verified, leaf.PublicKey.(*rsa.PublicKey))
			if e != nil || manifest.manifest.CiphertextBytes > s.config.Policy.MaxBodyBytes {
				return fail("ownership_ledger_record_invalid")
			}
			switch r.State {
			case "reading":
				return fail("ownership_store_pending")
			case "accepted":
				if r.FailureCode != "" {
					return fail("ownership_ledger_record_invalid")
				}
				accepted, e := VerifyAcceptance([]byte(r.AcceptanceJSON), s.config.Pin, s.scope)
				if e != nil {
					return fail("ownership_ledger_record_invalid")
				}
				b := accepted.Binding()
				if b.ChallengeSHA256 != verified.SHA256() || b.ManifestSHA256 != digest(manifest.canonical) || b.CredentialSHA256 != r.CredentialSHA256 {
					return fail("ownership_ledger_record_invalid")
				}
			case "rejected":
				if r.AcceptanceJSON != "" || !storeFailureValid(r.FailureCode) {
					return fail("ownership_ledger_record_invalid")
				}
			default:
				return fail("ownership_ledger_record_invalid")
			}
		}
	}
	all := storeCounts(d.Records, "")
	p := s.config.Policy
	if all.Jobs > p.MaxJobs || all.ChargedBytes > p.MaxBytes || all.Active > p.MaxActive {
		return fail("ownership_ledger_quota_invalid")
	}
	for _, r := range d.Records {
		one := storeCounts(d.Records, r.PrincipalSHA256)
		if one.Jobs > p.MaxPrincipalJobs || one.ChargedBytes > p.MaxPrincipalBytes || one.Active > p.MaxPrincipalActive {
			return fail("ownership_ledger_quota_invalid")
		}
	}
	s.data = d
	return nil
}

func storeFailureValid(code string) bool {
	if len(code) < 1 || len(code) > 64 {
		return false
	}
	for _, r := range code {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// Historical records are verified as historical facts, never promoted into an
// authenticated Principal. Only PrincipalFromTLS creates that capability.
func storedManifest(raw []byte, v VerifiedChallenge, key *rsa.PublicKey) (VerifiedManifest, error) {
	var zero VerifiedManifest
	var signed SignedManifest
	if err := strictJSON(raw, &signed, MaxManifestBytes); err != nil {
		return zero, err
	}
	if err := validateManifest(signed.Manifest, v); err != nil {
		return zero, err
	}
	if !hexValue(signed.Signature, key.Size()*2) {
		return zero, fail("ownership_signature_invalid")
	}
	sig, _ := hex.DecodeString(signed.Signature)
	canonical, _ := json.Marshal(signed.Manifest)
	sum := sha256.Sum256(canonical)
	if rsa.VerifyPSS(key, crypto.SHA256, sum[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {
		return zero, fail("ownership_signature_invalid")
	}
	envelope, _ := MarshalManifest(signed)
	return VerifiedManifest{signed.Manifest, envelope, true}, nil
}
func (s *Store) next() storeLedger {
	next := s.data
	next.Records = append([]storeEntry{}, s.data.Records...)
	return next
}
func (s *Store) ack() error {
	if s.point("ack") != nil {
		return s.latch("ownership_ack_failed")
	}
	return nil
}

func (s *Store) Reserve(state *tls.ConnectionState, requestID, originalName string, now time.Time) (SignedChallenge, error) {
	var zero SignedChallenge
	owner, err := PrincipalFromTLS(state)
	if err != nil {
		return zero, err
	}
	principal, err := quotaPrincipal(s.config.Namespace, owner)
	if err != nil {
		return zero, err
	}
	if !hexValue(requestID, 32) || !nameValid(originalName) || now.IsZero() || now.Nanosecond() != 0 {
		return zero, fail("ownership_request_invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = s.preflight(); err != nil {
		return zero, err
	}
	for _, r := range s.data.Records {
		if r.PrincipalSHA256 == principal && r.RequestID == requestID {
			var ch SignedChallenge
			_ = strictJSON([]byte(r.ChallengeJSON), &ch, MaxChallengeBytes)
			if r.CredentialSHA256 != owner.credential || ch.Claim.OriginalName != originalName {
				return zero, fail("ownership_request_conflict")
			}
			if err = s.ack(); err != nil {
				return zero, err
			}
			return ch, nil
		}
	}
	p := s.config.Policy
	charge := p.MaxBodyBytes + StoreMetadataHeadroom
	all := storeCounts(s.data.Records, "")
	one := storeCounts(s.data.Records, principal)
	if all.Jobs >= p.MaxJobs || one.Jobs >= p.MaxPrincipalJobs || all.ChargedBytes > p.MaxBytes-charge || one.ChargedBytes > p.MaxPrincipalBytes-charge || all.Active >= p.MaxActive || one.Active >= p.MaxPrincipalActive {
		return zero, fail("ownership_quota_exceeded")
	}
	available, err := s.available(s.root)
	if err != nil {
		return zero, fail("ownership_capacity_unavailable")
	}
	// Conservative sensor: all retained promises remain subtracted because this
	// library cannot prove how much ciphertext another ingress has materialized.
	required := uint64(p.FreeSpaceFloorBytes + all.ChargedBytes + charge + 2*StoreLedgerLimit)
	if available < required {
		return zero, fail("ownership_free_space_floor")
	}
	job, err := storeRandom(8)
	if err != nil {
		return zero, err
	}
	nonce, err := storeRandom(32)
	if err != nil {
		return zero, err
	}
	for _, r := range s.data.Records {
		var prior SignedChallenge
		_ = strictJSON([]byte(r.ChallengeJSON), &prior, MaxChallengeBytes)
		if prior.Claim.JobID == job || prior.Claim.Nonce == nonce {
			return zero, fail("ownership_random_collision")
		}
	}
	ch, err := SignChallenge(s.config.SigningKey, s.config.Pin, owner, ChallengeInput{job, nonce, originalName, now, now.Add(time.Duration(p.ChallengeTTLSeconds) * time.Second)})
	if err != nil {
		return zero, err
	}
	raw, _ := MarshalChallenge(ch)
	next := s.next()
	next.Records = append(next.Records, storeEntry{requestID, principal, owner.credential, hex.EncodeToString(owner.leaf.Raw), "reserved", charge, string(raw), "", "", ""})
	if err = s.save(next); err != nil {
		return zero, err
	}
	if err = s.ack(); err != nil {
		return zero, err
	}
	return ch, nil
}

func (s *Store) Get(state *tls.ConnectionState, jobID string) (StoreRecord, error) {
	var zero StoreRecord
	owner, err := PrincipalFromTLS(state)
	if err != nil {
		return zero, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = s.preflight(); err != nil {
		return zero, err
	}
	for _, r := range s.data.Records {
		var ch SignedChallenge
		_ = strictJSON([]byte(r.ChallengeJSON), &ch, MaxChallengeBytes)
		if ch.Claim.JobID != jobID {
			continue
		}
		if r.CredentialSHA256 != owner.credential {
			return zero, fail("ownership_denied")
		}
		out := StoreRecord{State: r.State, Challenge: ch, FailureCode: r.FailureCode}
		if r.State == "accepted" {
			a, err := s.acceptedDTO(r)
			if err != nil {
				return zero, s.latch("ownership_store_changed")
			}
			out.Acceptance = &a
		}
		if err = s.ack(); err != nil {
			return zero, err
		}
		return out, nil
	}
	return zero, fail("ownership_denied")
}

func (s *Store) Finalize(ctx context.Context, state *tls.ConnectionState, rawChallenge, rawManifest []byte, reader io.Reader, now time.Time) (SignedAcceptance, error) {
	var zero SignedAcceptance
	started := time.Now()
	owner, err := PrincipalFromTLS(state)
	if err != nil {
		return zero, err
	}
	if ctx == nil || ctx.Err() != nil {
		return zero, fail("ownership_cancelled")
	}
	var candidate SignedChallenge
	if err = strictJSON(rawChallenge, &candidate, MaxChallengeBytes); err != nil {
		return zero, err
	}
	s.mu.Lock()
	if err = s.preflight(); err != nil {
		s.mu.Unlock()
		return zero, err
	}
	if ctx.Err() != nil {
		s.mu.Unlock()
		return zero, fail("ownership_cancelled")
	}
	index := -1
	for i, r := range s.data.Records {
		var ch SignedChallenge
		_ = strictJSON([]byte(r.ChallengeJSON), &ch, MaxChallengeBytes)
		if ch.Claim.JobID == candidate.Claim.JobID {
			index = i
			break
		}
	}
	if index < 0 {
		s.mu.Unlock()
		return zero, fail("ownership_denied")
	}
	row := s.data.Records[index]
	if row.CredentialSHA256 != owner.credential {
		s.mu.Unlock()
		return zero, fail("ownership_denied")
	}
	if row.ChallengeJSON != string(rawChallenge) {
		s.mu.Unlock()
		return zero, fail("ownership_request_conflict")
	}
	if row.State != "reserved" {
		if row.ManifestJSON != string(rawManifest) {
			s.mu.Unlock()
			return zero, fail("ownership_request_conflict")
		}
		switch row.State {
		case "accepted":
			out, e := s.acceptedDTO(row)
			if e != nil {
				err = s.latch("ownership_store_changed")
				s.mu.Unlock()
				return zero, err
			}
			err = s.ack()
			s.mu.Unlock()
			if err != nil {
				return zero, err
			}
			return out, nil
		case "rejected":
			s.mu.Unlock()
			return zero, fail(row.FailureCode)
		default:
			s.mu.Unlock()
			return zero, fail("ownership_reading_pending")
		}
	}
	verified, err := VerifyChallenge(rawChallenge, s.config.Pin, owner, now)
	if err != nil {
		s.mu.Unlock()
		return zero, err
	}
	manifest, err := VerifyManifest(rawManifest, verified, owner)
	if err != nil {
		s.mu.Unlock()
		return zero, err
	}
	if manifest.manifest.CiphertextBytes > s.config.Policy.MaxBodyBytes {
		s.mu.Unlock()
		return zero, fail("ownership_manifest_body_limit")
	}
	if reader == nil {
		s.mu.Unlock()
		return zero, fail("ownership_ciphertext_reader_invalid")
	}
	next := s.next()
	next.Records[index].State = "reading"
	next.Records[index].ManifestJSON = string(rawManifest)
	if err = s.save(next); err != nil {
		s.mu.Unlock()
		return zero, err
	}
	s.inflight++
	s.mu.Unlock()
	readAt := now.Add(time.Since(started))
	measured, readErr := Finalize(ctx, state, rawChallenge, rawManifest, s.config.Pin, reader, readAt)
	if readErr == nil {
		s.point("before_seal")
		if ctx.Err() != nil {
			readErr = fail("ownership_cancelled")
		}
	}
	decisionAt := now.Add(time.Since(started))
	var accepted SignedAcceptance
	if readErr == nil {
		accepted, readErr = sealAcceptance(s.config.SigningKey, s.config.Pin, s.scope, state, rawChallenge, rawManifest, measured, decisionAt)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { s.inflight-- }()
	if err = s.ready(); err != nil {
		return zero, err
	}
	if err = s.preflight(); err != nil {
		return zero, err
	}
	if readErr == nil {
		s.point("before_accept")
		if ctx.Err() != nil {
			readErr = fail("ownership_cancelled")
		}
	}
	next = s.next()
	if readErr != nil {
		code := readErr.Error()
		if !storeFailureValid(code) {
			code = "ownership_finalize_failed"
		}
		next.Records[index].State = "rejected"
		next.Records[index].FailureCode = code
		if err = s.save(next); err != nil {
			return zero, err
		}
		return zero, fail(code)
	}
	raw, err := MarshalAcceptance(accepted)
	if err != nil {
		return zero, s.latch("ownership_acceptance_invalid")
	}
	next.Records[index].State = "accepted"
	next.Records[index].AcceptanceJSON = string(raw)
	if err = s.save(next); err != nil {
		return zero, err
	}
	if err = s.ack(); err != nil {
		return zero, err
	}
	return accepted, nil
}

func (s *Store) acceptedDTO(row storeEntry) (SignedAcceptance, error) {
	var out SignedAcceptance
	if _, err := VerifyAcceptance([]byte(row.AcceptanceJSON), s.config.Pin, s.scope); err != nil {
		return out, err
	}
	if err := strictJSON([]byte(row.AcceptanceJSON), &out, MaxAcceptanceBytes); err != nil {
		return SignedAcceptance{}, err
	}
	return out, nil
}

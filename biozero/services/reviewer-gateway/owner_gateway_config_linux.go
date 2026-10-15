//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	projection "biozero/enclave-runner/receiptprojection"
	ownership "biozero/ownership-authority"
)

const ogConfigLimit int64 = 1 << 20
const ogCertificateLimit int64 = 256 << 10
const ogKeyLimit int64 = 32 << 10
const ogPolicyLimit int64 = 64 << 10
const ogPreparedLimit int64 = 10 << 20
const ogUILimit int64 = 256 << 10

func ogConfigError(code string) error  { return errors.New(code) }
func ogConfigDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func ogConfigPath(path string) bool {
	return utf8.ValidString(path) && filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsAny(path, "\x00\r\n")
}
func ogConfigOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// All ancestors are pinned without following symlinks. Assets and state live
// in private same-UID directories in this first native deployment policy.
func ogOpenPrivateDir(path string) (*os.File, error) {
	if !ogConfigPath(path) {
		return nil, ogConfigError("owner_gateway_directory_invalid")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ogConfigError("owner_gateway_directory_invalid")
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		child, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, ogConfigError("owner_gateway_directory_invalid")
		}
		fd = child
	}
	f := os.NewFile(uintptr(fd), "owner-gateway-directory")
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&07777 != 0700 {
		f.Close()
		return nil, ogConfigError("owner_gateway_directory_invalid")
	}
	return f, nil
}

func ogReadPrivateFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || !ogConfigPath(path) || limit < 1 {
		return nil, ogConfigError("owner_gateway_file_invalid")
	}
	dir, err := ogOpenPrivateDir(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := syscall.Openat(int(dir.Fd()), filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ogConfigError("owner_gateway_file_invalid")
	}
	f := os.NewFile(uintptr(fd), "owner-gateway-private-file")
	defer f.Close()
	valid := func(st syscall.Stat_t) bool {
		return st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1 && st.Size > 0 && st.Size <= limit
	}
	var before, after syscall.Stat_t
	if syscall.Fstat(fd, &before) != nil || !valid(before) {
		return nil, ogConfigError("owner_gateway_file_invalid")
	}
	raw, err := io.ReadAll(io.NewSectionReader(f, 0, limit+1))
	if err != nil || syscall.Fstat(fd, &after) != nil || !valid(after) || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(len(raw)) != before.Size || ctx.Err() != nil {
		return nil, ogConfigError("owner_gateway_file_invalid")
	}
	return raw, nil
}

func ogLoopbackAddress(address string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	number, parseErr := strconv.Atoi(port)
	ip := net.ParseIP(host)
	if err != nil || parseErr != nil || port == "" || strings.Trim(port, "0123456789") != "" || number < 0 || number > 65535 || ip == nil || !ip.IsLoopback() {
		return "", 0, ogConfigError("owner_gateway_address_invalid")
	}
	return host, number, nil
}

func ogGatewayOrigin(raw string, loopback bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "\x00\r\n") {
		return nil, ogConfigError("owner_gateway_origin_invalid")
	}
	if loopback {
		if _, _, err := ogLoopbackAddress(u.Host); err != nil {
			return nil, err
		}
	}
	return u, nil
}

type ogMeasuredAsset struct {
	SHA256 string
	Raw    []byte
}

func ogReadAsset(ctx context.Context, asset ownerGatewayAsset, limit int64, cache map[string]ogMeasuredAsset) ([]byte, error) {
	if previous, ok := cache[asset.Path]; ok {
		if previous.SHA256 != asset.SHA256 || int64(len(previous.Raw)) > limit {
			return nil, ogConfigError("owner_gateway_asset_invalid")
		}
		return previous.Raw, nil
	}
	if !projection.ArtifactHex(asset.SHA256, 64) {
		return nil, ogConfigError("owner_gateway_asset_invalid")
	}
	raw, err := ogReadPrivateFile(ctx, asset.Path, limit)
	if err != nil || ogConfigDigest(raw) != asset.SHA256 {
		return nil, ogConfigError("owner_gateway_asset_invalid")
	}
	cache[asset.Path] = ogMeasuredAsset{asset.SHA256, raw}
	return raw, nil
}

func ogReadCA(ctx context.Context, asset ownerGatewayAsset, cache map[string]ogMeasuredAsset) (*x509.CertPool, error) {
	raw, err := ogReadAsset(ctx, asset, ogCertificateLimit, cache)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, ogConfigError("owner_gateway_ca_invalid")
	}
	return pool, nil
}

func ogReadPair(ctx context.Context, certAsset, keyAsset ownerGatewayAsset, cache map[string]ogMeasuredAsset) (tls.Certificate, *x509.Certificate, error) {
	var zero tls.Certificate
	if certAsset.Path == keyAsset.Path {
		return zero, nil, ogConfigError("owner_gateway_tls_invalid")
	}
	certRaw, err := ogReadAsset(ctx, certAsset, ogCertificateLimit, cache)
	if err != nil {
		return zero, nil, err
	}
	keySource, err := ogReadAsset(ctx, keyAsset, ogKeyLimit, cache)
	if err != nil {
		return zero, nil, err
	}
	keyRaw := append([]byte(nil), keySource...)
	defer clear(keyRaw)
	pair, err := tls.X509KeyPair(certRaw, keyRaw)
	if err != nil || len(pair.Certificate) < 1 || len(pair.Certificate) > 8 {
		return zero, nil, ogConfigError("owner_gateway_tls_invalid")
	}
	for _, der := range pair.Certificate {
		if len(der) > 16<<10 {
			return zero, nil, ogConfigError("owner_gateway_tls_invalid")
		}
		if _, e := x509.ParseCertificate(der); e != nil {
			return zero, nil, ogConfigError("owner_gateway_tls_invalid")
		}
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return zero, nil, ogConfigError("owner_gateway_tls_invalid")
	}
	public, ok := leaf.PublicKey.(*rsa.PublicKey)
	now := time.Now()
	if !ok || public.N == nil || public.N.BitLen() < 2048 || public.N.BitLen() > 4096 || public.E != 65537 || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return zero, nil, ogConfigError("owner_gateway_tls_invalid")
	}
	pair.Leaf = leaf
	return pair, leaf, nil
}

func ogPublicKeySHA(key any) (string, error) {
	raw, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", ogConfigError("owner_gateway_key_invalid")
	}
	return ogConfigDigest(raw), nil
}

// Material uses one measured snapshot per asset. Display and browser admission
// settings are excluded from ContextSHA256, while ConfigSHA256 retains them.
func loadOwnerGatewayConfig(ctx context.Context, path string) (ownerGatewayMaterial, error) {
	var zero ownerGatewayMaterial
	raw, err := ogReadPrivateFile(ctx, path, ogConfigLimit)
	if err != nil {
		return zero, err
	}
	var cfg ownerGatewayConfig
	if projection.DecodeClosedJSON(ctx, raw, &cfg) != nil || cfg.SchemaVersion != 1 || cfg.Protocol != "owner-v1" || cfg.ExpectedUID != uint32(os.Geteuid()) || !ogConfigPath(cfg.StateDirectory) || len(cfg.Reviewers) < 1 || len(cfg.Reviewers) > 100 || len(cfg.Experiments) < 1 || len(cfg.Experiments) > 16 || len(cfg.UIAssets) != 3 {
		return zero, ogConfigError("owner_gateway_config_invalid")
	}
	_, listenPort, err := ogLoopbackAddress(cfg.ListenAddress)
	if err != nil {
		return zero, err
	}
	origin, err := ogGatewayOrigin(cfg.PublicOrigin, false)
	if err != nil {
		return zero, err
	}
	originHost := origin.Hostname()
	originPort, err := strconv.Atoi(origin.Port())
	if err != nil || originPort != listenPort || (originHost != "localhost" && (net.ParseIP(originHost) == nil || !net.ParseIP(originHost).IsLoopback())) {
		return zero, ogConfigError("owner_gateway_origin_invalid")
	}
	for _, endpoint := range []string{cfg.AuthorityURL, cfg.UploadURL, cfg.ResultsURL} {
		if _, err := ogGatewayOrigin(endpoint, true); err != nil {
			return zero, err
		}
	}
	for _, name := range []string{cfg.AuthorityServerName, cfg.UploadServerName, cfg.ResultsServerName} {
		if name == "" || len(name) > 253 || strings.ContainsAny(name, "\x00\r\n/\\ ") || net.ParseIP(name) == nil && strings.Contains(name, ":") {
			return zero, ogConfigError("owner_gateway_server_name_invalid")
		}
	}
	if !projection.ArtifactHex(cfg.AuthorityID, 32) || !projection.ArtifactHex(cfg.PublicKeyHex, 64) || !projection.ArtifactHex(cfg.ExecutionProfileSHA256, 64) || !projection.ArtifactHex(cfg.ExpectedScope.StoreID, 32) || !projection.ArtifactHex(cfg.ExpectedScope.PolicySHA256, 64) || (cfg.PipelineMode != "variants" && cfg.PipelineMode != "stats") {
		return zero, ogConfigError("owner_gateway_config_invalid")
	}
	uiNames := []string{"index.html", "app.js", "styles.css"}
	for _, name := range uiNames {
		if _, ok := cfg.UIAssets[name]; !ok {
			return zero, ogConfigError("owner_gateway_ui_invalid")
		}
	}
	privatePaths := map[string]bool{}
	for _, asset := range append([]ownerGatewayAsset{cfg.BrowserTLSPrivateKey}, func() []ownerGatewayAsset {
		keys := []ownerGatewayAsset{}
		for _, r := range cfg.Reviewers {
			keys = append(keys, r.TLSPrivateKey)
		}
		return keys
	}()...) {
		if privatePaths[asset.Path] {
			return zero, ogConfigError("owner_gateway_asset_roles_invalid")
		}
		privatePaths[asset.Path] = true
	}
	publicAssets := []ownerGatewayAsset{cfg.BrowserTLSCertificate, cfg.AuthorityCA, cfg.UploadCA, cfg.ResultsCA, cfg.WorkerEncryptionPublicKey, cfg.ProjectionPolicy, {Path: path}}
	for _, r := range cfg.Reviewers {
		publicAssets = append(publicAssets, r.TLSCertificate)
	}
	for _, e := range cfg.Experiments {
		publicAssets = append(publicAssets, e.Input, e.Reference)
	}
	protectedPaths := map[string]bool{}
	for _, asset := range publicAssets {
		if privatePaths[asset.Path] {
			return zero, ogConfigError("owner_gateway_asset_roles_invalid")
		}
		protectedPaths[asset.Path] = true
	}
	uiPaths := map[string]bool{}
	for _, asset := range cfg.UIAssets {
		if privatePaths[asset.Path] || protectedPaths[asset.Path] || uiPaths[asset.Path] {
			return zero, ogConfigError("owner_gateway_asset_roles_invalid")
		}
		uiPaths[asset.Path] = true
	}
	assets := []ownerGatewayAsset{cfg.BrowserTLSCertificate, cfg.BrowserTLSPrivateKey, cfg.AuthorityCA, cfg.UploadCA, cfg.ResultsCA, cfg.WorkerEncryptionPublicKey, cfg.ProjectionPolicy, {Path: path}}
	for _, asset := range cfg.UIAssets {
		assets = append(assets, asset)
	}
	for _, r := range cfg.Reviewers {
		assets = append(assets, r.TLSCertificate, r.TLSPrivateKey)
	}
	for _, e := range cfg.Experiments {
		assets = append(assets, e.Input, e.Reference)
	}
	for _, asset := range assets {
		if !ogConfigPath(asset.Path) || ogConfigOverlap(cfg.StateDirectory, asset.Path) {
			return zero, ogConfigError("owner_gateway_config_overlap")
		}
	}
	// State may be a future exclusive genesis, but its parent is already private.
	parent, err := ogOpenPrivateDir(filepath.Dir(cfg.StateDirectory))
	if err != nil {
		return zero, err
	}
	parent.Close()
	cache := map[string]ogMeasuredAsset{}
	defer func() {
		for path := range privatePaths {
			if measured, ok := cache[path]; ok {
				clear(measured.Raw)
			}
		}
	}()
	browserPair, browserLeaf, err := ogReadPair(ctx, cfg.BrowserTLSCertificate, cfg.BrowserTLSPrivateKey, cache)
	if err != nil {
		return zero, err
	}
	serverUsage := false
	for _, usage := range browserLeaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverUsage = true
		}
	}
	if !serverUsage || browserLeaf.IsCA || browserLeaf.VerifyHostname(origin.Hostname()) != nil {
		return zero, ogConfigError("owner_gateway_tls_invalid")
	}
	browserKeySHA, err := ogPublicKeySHA(browserLeaf.PublicKey)
	if err != nil {
		return zero, err
	}
	authorityCA, err := ogReadCA(ctx, cfg.AuthorityCA, cache)
	if err != nil {
		return zero, err
	}
	uploadCA, err := ogReadCA(ctx, cfg.UploadCA, cache)
	if err != nil {
		return zero, err
	}
	resultsCA, err := ogReadCA(ctx, cfg.ResultsCA, cache)
	if err != nil {
		return zero, err
	}
	encryptionRaw, err := ogReadAsset(ctx, cfg.WorkerEncryptionPublicKey, ogPolicyLimit, cache)
	if err != nil {
		return zero, err
	}
	block, rest := pem.Decode(encryptionRaw)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 || len(block.Headers) != 0 {
		return zero, ogConfigError("owner_gateway_encryption_key_invalid")
	}
	var parsed any
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(block.Bytes)
		if err == nil {
			parsed = cert.PublicKey
		}
	default:
		return zero, ogConfigError("owner_gateway_encryption_key_invalid")
	}
	encryption, ok := parsed.(*rsa.PublicKey)
	if err != nil || !ok || encryption.N == nil || encryption.N.Sign() <= 0 || encryption.N.BitLen() < 2048 || encryption.N.BitLen() > 4096 || encryption.E != 65537 {
		return zero, ogConfigError("owner_gateway_encryption_key_invalid")
	}
	encryptionSHA, err := ogPublicKeySHA(encryption)
	if err != nil || encryptionSHA == browserKeySHA {
		return zero, ogConfigError("owner_gateway_key_roles_invalid")
	}
	policyRaw, err := ogReadAsset(ctx, cfg.ProjectionPolicy, ogPolicyLimit, cache)
	if err != nil {
		return zero, err
	}
	policy, err := projection.ParsePolicy(ctx, policyRaw, cfg.ExecutionProfileSHA256, cfg.PipelineMode)
	if err != nil {
		return zero, ogConfigError("owner_gateway_policy_invalid")
	}
	public, _ := hex.DecodeString(cfg.PublicKeyHex)
	pin := ownership.AuthorityPin{AuthorityID: cfg.AuthorityID, PublicKey: ed25519.PublicKey(public), PipelineMode: cfg.PipelineMode, ExecutionProfileSHA256: cfg.ExecutionProfileSHA256}
	m := ownerGatewayMaterial{Config: cfg, ConfigSHA256: ogConfigDigest(raw), Pin: pin, Policy: policy, EncryptionKey: encryption, BrowserTLS: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{browserPair}, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}, Reviewers: map[string]ownerGatewayReviewer{}, Experiments: map[string]ownerGatewayExperiment{}, UI: map[string][]byte{}}
	success := false
	defer func() {
		if !success {
			for _, r := range m.Reviewers {
				r.Results.Close()
			}
		}
	}()
	usedLeaf, usedKey := map[string]bool{}, map[string]bool{browserKeySHA: true, encryptionSHA: true}
	for _, r := range cfg.Reviewers {
		if !safeID.MatchString(r.ID) || len(r.Label) > 256 || !utf8.ValidString(r.Label) || !projection.ArtifactHex(r.AccessCodeSHA256, 64) || !projection.ArtifactHex(r.CredentialSHA256, 64) {
			return zero, ogConfigError("owner_gateway_reviewer_invalid")
		}
		if _, ok := m.Reviewers[r.ID]; ok {
			return zero, ogConfigError("owner_gateway_reviewer_invalid")
		}
		pair, leaf, err := ogReadPair(ctx, r.TLSCertificate, r.TLSPrivateKey, cache)
		if err != nil {
			return zero, err
		}
		fingerprint := ogConfigDigest(leaf.Raw)
		keySHA, err := ogPublicKeySHA(leaf.PublicKey)
		if err != nil || fingerprint != r.CredentialSHA256 || usedLeaf[fingerprint] || usedKey[keySHA] {
			return zero, ogConfigError("owner_gateway_key_roles_invalid")
		}
		authority := ownership.AuthorityClientConfig{BaseURL: cfg.AuthorityURL, Certificate: pair, RootCAs: authorityCA, ServerName: cfg.AuthorityServerName, Pin: pin, Scope: cfg.ExpectedScope}
		upload := authority
		upload.BaseURL = cfg.UploadURL
		upload.RootCAs = uploadCA
		upload.ServerName = cfg.UploadServerName
		for _, config := range []ownership.AuthorityClientConfig{authority, upload} {
			client, e := ownership.NewAuthorityClient(config)
			if e != nil {
				return zero, ogConfigError("owner_gateway_reviewer_invalid")
			}
			client.CloseIdleConnections()
		}
		resultConfig := authority
		resultConfig.BaseURL = cfg.ResultsURL
		resultConfig.RootCAs = resultsCA
		resultConfig.ServerName = cfg.ResultsServerName
		results, err := newOwnerGatewayResultsClient(resultConfig, policy, fingerprint)
		if err != nil {
			return zero, err
		}
		hash, _ := hex.DecodeString(r.AccessCodeSHA256)
		var access [32]byte
		copy(access[:], hash)
		m.Reviewers[r.ID] = ownerGatewayReviewer{Config: r, CredentialSHA256: fingerprint, AccessSHA256: access, AuthorityConfig: authority, UploadConfig: upload, Results: results}
		usedLeaf[fingerprint], usedKey[keySHA] = true, true
	}
	for _, e := range cfg.Experiments {
		if !safeID.MatchString(e.ID) || e.Scope != "synthetic" || e.Label == "" || len(e.Label) > 256 || !utf8.ValidString(e.Label) || e.OriginalName == "" || len(e.OriginalName) > 256 || !utf8.ValidString(e.OriginalName) || strings.ContainsAny(e.OriginalName, "\x00\r\n/") {
			return zero, ogConfigError("owner_gateway_experiment_invalid")
		}
		if _, ok := m.Experiments[e.ID]; ok {
			return zero, ogConfigError("owner_gateway_experiment_invalid")
		}
		input, err := ogReadAsset(ctx, e.Input, ogPreparedLimit, cache)
		if err != nil {
			return zero, err
		}
		reference, err := ogReadAsset(ctx, e.Reference, ogPreparedLimit, cache)
		if err != nil {
			return zero, err
		}
		if pin, has := policy.SourcePins["reference"]; has && (ogConfigDigest(reference) != pin.SHA256 || int64(len(reference)) != pin.Bytes) {
			return zero, ogConfigError("owner_gateway_reference_invalid")
		}
		m.Experiments[e.ID] = ownerGatewayExperiment{Config: e, Input: input, InputSHA256: ogConfigDigest(input), InputBytes: int64(len(input)), ReferenceSHA256: ogConfigDigest(reference), ReferenceBytes: int64(len(reference))}
	}
	for _, name := range uiNames {
		body, err := ogReadAsset(ctx, cfg.UIAssets[name], ogUILimit, cache)
		if err != nil {
			return zero, err
		}
		m.UI[name] = body
	}
	m.ContextSHA256, err = ogMaterialContext(m, cfg)
	if err != nil || ctx.Err() != nil {
		return zero, ogConfigError("owner_gateway_config_invalid")
	}
	for id, reviewer := range m.Reviewers {
		reviewer.Results.contextSHA = m.ContextSHA256
		reviewer.Results.reviewerID = id
		for experimentID, e := range m.Experiments {
			reviewer.Results.experiments[experimentID] = ogResultsExperiment{Name: e.Config.OriginalName, InputSHA256: e.InputSHA256, ReferenceSHA256: e.ReferenceSHA256, InputBytes: e.InputBytes, ReferenceBytes: e.ReferenceBytes}
		}
	}
	success = true
	return m, nil
}

func ogMaterialContext(m ownerGatewayMaterial, cfg ownerGatewayConfig) (string, error) {
	type reviewerTrust struct{ ID, CredentialSHA256 string }
	type experimentTrust struct {
		ID, Scope, OriginalName, InputSHA256, ReferenceSHA256 string
		InputBytes, ReferenceBytes                            int64
	}
	reviewers := []reviewerTrust{}
	experiments := []experimentTrust{}
	for id, r := range m.Reviewers {
		reviewers = append(reviewers, reviewerTrust{id, r.CredentialSHA256})
	}
	for id, e := range m.Experiments {
		experiments = append(experiments, experimentTrust{id, e.Config.Scope, e.Config.OriginalName, e.InputSHA256, e.ReferenceSHA256, e.InputBytes, e.ReferenceBytes})
	}
	sort.Slice(reviewers, func(i, j int) bool { return reviewers[i].ID < reviewers[j].ID })
	sort.Slice(experiments, func(i, j int) bool { return experiments[i].ID < experiments[j].ID })
	keySHA, err := ogPublicKeySHA(m.EncryptionKey)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		Domain, StateDirectory                                                                        string
		AuthorityURL, UploadURL, ResultsURL, AuthorityServerName, UploadServerName, ResultsServerName string
		AuthorityCASHA256, UploadCASHA256, ResultsCASHA256, EncryptionKeySHA256                       string
		AuthorityID, PublicKeyHex, ProfileSHA256, Mode                                                string
		Scope                                                                                         ownership.AcceptanceScope
		Policy                                                                                        projection.Policy
		Reviewers                                                                                     []reviewerTrust
		Experiments                                                                                   []experimentTrust
	}{"biozero.gateway.owner.context.v1", cfg.StateDirectory, cfg.AuthorityURL, cfg.UploadURL, cfg.ResultsURL, cfg.AuthorityServerName, cfg.UploadServerName, cfg.ResultsServerName, cfg.AuthorityCA.SHA256, cfg.UploadCA.SHA256, cfg.ResultsCA.SHA256, keySHA, cfg.AuthorityID, cfg.PublicKeyHex, cfg.ExecutionProfileSHA256, cfg.PipelineMode, cfg.ExpectedScope, m.Policy, reviewers, experiments})
	if err != nil {
		return "", ogConfigError("owner_gateway_context_invalid")
	}
	return ogConfigDigest(raw), nil
}

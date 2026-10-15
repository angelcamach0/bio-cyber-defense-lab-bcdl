//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	projection "biozero/enclave-runner/receiptprojection"
	ownership "biozero/ownership-authority"
)

const ownerResultsMetadataLimit int64 = 64 << 10
const ownerResultsResponseLimit = 16 << 20

type ownerResultsAsset struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// The first native policy uses private same-UID files and sockets. It does not
// establish role isolation or authorize cross-UID permissions or ACL changes.
type ownerResultsConfig struct {
	SchemaVersion          int                       `json:"schema_version"`
	Protocol               string                    `json:"protocol"`
	Address                string                    `json:"address"`
	AcceptancesDirectory   string                    `json:"acceptances_directory"`
	ExpectedAcceptancesUID uint32                    `json:"expected_acceptances_uid"`
	ReaderSocket           string                    `json:"reader_socket"`
	ExpectedBrokerUID      uint32                    `json:"expected_broker_uid"`
	AuthorityID            string                    `json:"authority_id"`
	PublicKeyHex           string                    `json:"public_key_hex"`
	PipelineMode           string                    `json:"pipeline_mode"`
	ExecutionProfileSHA256 string                    `json:"execution_profile_sha256"`
	ExpectedScope          ownership.AcceptanceScope `json:"expected_scope"`
	TLSCertificate         ownerResultsAsset         `json:"tls_certificate"`
	TLSPrivateKey          ownerResultsAsset         `json:"tls_private_key"`
	ClientCA               ownerResultsAsset         `json:"client_ca"`
	ProjectionPolicy       ownerResultsAsset         `json:"projection_policy"`
}

type ownerResultsMaterial struct {
	config ownerResultsConfig
	pin    ownership.AuthorityPin
	policy projection.Policy
	tls    *tls.Config
}

func ownerResultsError(code string) error { return errors.New(code) }
func ownerResultsDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func ownerResultsPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsAny(path, "\x00\r\n")
}

func ownerResultsSocketPath(path string) bool {
	if !ownerResultsPath(path) {
		return false
	}
	name := filepath.Base(path)
	if len(name) < 1 || len(name) > 64 || name == "." || name == ".." {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func ownerResultsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// Every directory component is opened without symlink traversal; the final
// directory is pinned and private. No directory is created by owner Results.
func ownerResultsDirectory(path string, uid uint32) (*os.File, error) {
	if !ownerResultsPath(path) {
		return nil, ownerResultsError("owner_results_directory_invalid")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ownerResultsError("owner_results_directory_invalid")
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		child, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, ownerResultsError("owner_results_directory_invalid")
		}
		fd = child
	}
	f := os.NewFile(uintptr(fd), "owner-results-directory")
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&07777 != 0700 {
		f.Close()
		return nil, ownerResultsError("owner_results_directory_invalid")
	}
	return f, nil
}

func ownerResultsReadAt(ctx context.Context, dir *os.File, name string, uid uint32) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || dir == nil || name == "" || filepath.Base(name) != name {
		return nil, ownerResultsError("owner_results_metadata_invalid")
	}
	var directoryStat syscall.Stat_t
	if syscall.Fstat(int(dir.Fd()), &directoryStat) != nil || directoryStat.Uid != uid || directoryStat.Mode&syscall.S_IFMT != syscall.S_IFDIR || directoryStat.Mode&07777 != 0700 {
		return nil, ownerResultsError("owner_results_directory_invalid")
	}
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ownerResultsError("owner_results_metadata_unavailable")
	}
	f := os.NewFile(uintptr(fd), "owner-results-metadata")
	defer f.Close()
	var before, after syscall.Stat_t
	valid := func(st syscall.Stat_t) bool {
		return st.Uid == uid && st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Mode&07777 == 0600 && st.Nlink == 1 && st.Size > 0 && st.Size <= ownerResultsMetadataLimit
	}
	if syscall.Fstat(fd, &before) != nil || !valid(before) {
		return nil, ownerResultsError("owner_results_metadata_invalid")
	}
	raw, err := io.ReadAll(io.NewSectionReader(f, 0, ownerResultsMetadataLimit+1))
	if err != nil || syscall.Fstat(fd, &after) != nil || !valid(after) || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(len(raw)) != before.Size || ctx.Err() != nil {
		return nil, ownerResultsError("owner_results_metadata_invalid")
	}
	return raw, nil
}

func ownerResultsReadPath(ctx context.Context, path string) ([]byte, error) {
	if !ownerResultsPath(path) {
		return nil, ownerResultsError("owner_results_config_invalid")
	}
	dir, err := ownerResultsDirectory(filepath.Dir(path), uint32(os.Geteuid()))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return ownerResultsReadAt(ctx, dir, filepath.Base(path), uint32(os.Geteuid()))
}

func loadOwnerResultsConfig(ctx context.Context, path string) (ownerResultsMaterial, error) {
	var zero ownerResultsMaterial
	raw, err := ownerResultsReadPath(ctx, path)
	if err != nil {
		return zero, err
	}
	var c ownerResultsConfig
	if projection.DecodeClosedJSON(ctx, raw, &c) != nil || c.SchemaVersion != 1 || c.Protocol != "owner-v1" || c.ExpectedAcceptancesUID != uint32(os.Geteuid()) || c.ExpectedBrokerUID != uint32(os.Geteuid()) || !ownerResultsPath(c.AcceptancesDirectory) || !ownerResultsSocketPath(c.ReaderSocket) || !projection.ArtifactHex(c.AuthorityID, 32) || !projection.ArtifactHex(c.ExecutionProfileSHA256, 64) || !projection.ArtifactHex(c.ExpectedScope.StoreID, 32) || !projection.ArtifactHex(c.ExpectedScope.PolicySHA256, 64) || (c.PipelineMode != "stats" && c.PipelineMode != "variants") {
		return zero, ownerResultsError("owner_results_config_invalid")
	}
	host, port, err := net.SplitHostPort(c.Address)
	portNumber, portErr := strconv.Atoi(port)
	ip := net.ParseIP(host)
	if err != nil || portErr != nil || portNumber < 0 || portNumber > 65535 || port == "" || strings.Trim(port, "0123456789") != "" || len(c.Address) > 256 || strings.ContainsAny(c.Address, "\x00\r\n") || ip == nil || !ip.IsLoopback() {
		return zero, ownerResultsError("owner_results_config_invalid")
	}
	pub, err := hex.DecodeString(c.PublicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize || hex.EncodeToString(pub) != c.PublicKeyHex {
		return zero, ownerResultsError("owner_results_config_invalid")
	}
	assets := []ownerResultsAsset{c.TLSCertificate, c.TLSPrivateKey, c.ClientCA, c.ProjectionPolicy}
	for _, a := range append(assets, ownerResultsAsset{Path: path}) {
		if !ownerResultsPath(a.Path) || ownerResultsOverlap(c.AcceptancesDirectory, a.Path) || ownerResultsOverlap(filepath.Dir(c.ReaderSocket), a.Path) {
			return zero, ownerResultsError("owner_results_config_overlap")
		}
	}
	if ownerResultsOverlap(c.AcceptancesDirectory, filepath.Dir(c.ReaderSocket)) {
		return zero, ownerResultsError("owner_results_config_overlap")
	}
	for i, a := range assets {
		for _, b := range assets[:i] {
			if a.Path == b.Path {
				return zero, ownerResultsError("owner_results_config_overlap")
			}
		}
	}
	readAsset := func(a ownerResultsAsset) ([]byte, error) {
		b, e := ownerResultsReadPath(ctx, a.Path)
		if e != nil || !projection.ArtifactHex(a.SHA256, 64) || ownerResultsDigest(b) != a.SHA256 {
			return nil, ownerResultsError("owner_results_asset_invalid")
		}
		return b, nil
	}
	certRaw, err := readAsset(c.TLSCertificate)
	if err != nil {
		return zero, err
	}
	keyRaw, err := readAsset(c.TLSPrivateKey)
	if err != nil {
		return zero, err
	}
	defer clear(keyRaw)
	certificate, err := tls.X509KeyPair(certRaw, keyRaw)
	if err != nil {
		return zero, ownerResultsError("owner_results_tls_invalid")
	}
	caRaw, err := readAsset(c.ClientCA)
	if err != nil {
		return zero, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caRaw) {
		return zero, ownerResultsError("owner_results_tls_invalid")
	}
	policyRaw, err := readAsset(c.ProjectionPolicy)
	if err != nil {
		return zero, err
	}
	policy, err := projection.ParsePolicy(ctx, policyRaw, c.ExecutionProfileSHA256, c.PipelineMode)
	if err != nil {
		return zero, ownerResultsError("owner_results_policy_invalid")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	return ownerResultsMaterial{c, ownership.AuthorityPin{AuthorityID: c.AuthorityID, PublicKey: ed25519.PublicKey(pub), PipelineMode: c.PipelineMode, ExecutionProfileSHA256: c.ExecutionProfileSHA256}, policy, tlsConfig}, nil
}

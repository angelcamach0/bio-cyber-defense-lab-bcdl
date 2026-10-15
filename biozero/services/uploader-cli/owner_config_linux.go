//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"unicode/utf8"

	ownership "biozero/ownership-authority"
)

type ownerAsset struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type ownerCLIConfig struct {
	SchemaVersion          int                       `json:"schema_version"`
	AuthorityURL           string                    `json:"authority_url"`
	AuthorityServerName    string                    `json:"authority_server_name"`
	UploadURL              string                    `json:"upload_url"`
	UploadServerName       string                    `json:"upload_server_name"`
	TLSCertificate         ownerAsset                `json:"tls_certificate"`
	TLSPrivateKey          ownerAsset                `json:"tls_private_key"`
	AuthorityCA            ownerAsset                `json:"authority_ca"`
	UploadCA               ownerAsset                `json:"upload_ca"`
	EncryptionPublicKey    ownerAsset                `json:"encryption_public_key"`
	AuthorityID            string                    `json:"authority_id"`
	PublicKeyHex           string                    `json:"public_key_hex"`
	PipelineMode           string                    `json:"pipeline_mode"`
	ExecutionProfileSHA256 string                    `json:"execution_profile_sha256"`
	ExpectedScope          ownership.AcceptanceScope `json:"expected_scope"`
	OriginalName           string                    `json:"original_name"`
}
type ownerCLIMaterial struct {
	config            ownerCLIConfig
	configSHA         string
	authority, upload ownership.AuthorityClientConfig
	encryption        *rsa.PublicKey
}

func ownerError(code string) error { return errors.New(code) }
func ownerHex(v string, n int) bool {
	if len(v) != n {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func ownerDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func ownerPath(s string) bool {
	return filepath.IsAbs(s) && s != "/" && filepath.Clean(s) == s && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}
func ownerOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// openOwnerFile walks every ancestor with openat/O_NOFOLLOW and opens only a
// bounded private regular file. It does not follow links or block on a FIFO.
func openOwnerFile(path string) (*os.File, error) {
	if !ownerPath(path) {
		return nil, ownerError("owner_file_unsafe")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ownerError("owner_file_unsafe")
	}
	for i, name := range parts {
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, e := syscall.Openat(fd, name, flags, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, ownerError("owner_file_unsafe")
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "owner-private-input"), nil
}
func ownerFileStat(f *os.File) (*syscall.Stat_t, error) {
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return nil, ownerError("owner_file_unsafe")
	}
	return &st, nil
}
func readOwnerFile(path string, limit int64) ([]byte, error) {
	f, err := openOwnerFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := ownerFileStat(f)
	if err != nil {
		return nil, err
	}
	if before.Size < 0 || before.Size > limit {
		return nil, ownerError("owner_file_oversized")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ownerError("owner_file_read_failed")
	}
	after, err := ownerFileStat(f)
	if err != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Nlink != after.Nlink || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(len(raw)) != before.Size {
		return nil, ownerError("owner_file_changed")
	}
	return raw, nil
}

// Every configuration field is required, exact-case and non-null. This scanner
// precedes typed decoding so duplicate keys and JSON null cannot become defaults.
func scanOwnerConfig(d *json.Decoder, t reflect.Type, depth int) error {
	if depth > 32 {
		return ownerError("owner_config_invalid")
	}
	tok, err := d.Token()
	if err != nil || tok == nil {
		return ownerError("owner_config_invalid")
	}
	switch t.Kind() {
	case reflect.Struct:
		if tok != json.Delim('{') {
			return ownerError("owner_config_invalid")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fields[f.Tag.Get("json")] = f.Type
		}
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			name, ok := key.(string)
			field, known := fields[name]
			if e != nil || !ok || !known || seen[name] {
				return ownerError("owner_config_invalid")
			}
			seen[name] = true
			if scanOwnerConfig(d, field, depth+1) != nil {
				return ownerError("owner_config_invalid")
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') || len(seen) != len(fields) {
			return ownerError("owner_config_invalid")
		}
	case reflect.String:
		if _, ok := tok.(string); !ok {
			return ownerError("owner_config_invalid")
		}
	case reflect.Int, reflect.Int64:
		n, ok := tok.(json.Number)
		if !ok {
			return ownerError("owner_config_invalid")
		}
		if _, e := n.Int64(); e != nil {
			return ownerError("owner_config_invalid")
		}
	default:
		return ownerError("owner_config_invalid")
	}
	return nil
}
func decodeOwnerJSON(raw []byte, out any) error {
	if !utf8.Valid(raw) {
		return ownerError("owner_config_invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if scanOwnerConfig(d, reflect.TypeOf(out).Elem(), 0) != nil {
		return ownerError("owner_config_invalid")
	}
	if _, err := d.Token(); err != io.EOF {
		return ownerError("owner_config_invalid")
	}
	if json.Unmarshal(raw, out) != nil {
		return ownerError("owner_config_invalid")
	}
	return nil
}
func loadOwnerConfig(path string) (ownerCLIMaterial, error) {
	var out ownerCLIMaterial
	raw, err := readOwnerFile(path, 64<<10)
	if err != nil {
		return out, err
	}
	if !utf8.Valid(raw) {
		return out, ownerError("owner_config_invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if scanOwnerConfig(d, reflect.TypeOf(ownerCLIConfig{}), 0) != nil {
		return out, ownerError("owner_config_invalid")
	}
	if _, e := d.Token(); e != io.EOF {
		return out, ownerError("owner_config_invalid")
	}
	var cfg ownerCLIConfig
	if json.Unmarshal(raw, &cfg) != nil || cfg.SchemaVersion != 1 || cfg.OriginalName == "" || len(cfg.OriginalName) > 256 || !utf8.ValidString(cfg.OriginalName) || !ownerHex(cfg.PublicKeyHex, 64) {
		return out, ownerError("owner_config_invalid")
	}
	asset := func(a ownerAsset, limit int64) ([]byte, error) {
		if !ownerHex(a.SHA256, 64) {
			return nil, ownerError("owner_asset_invalid")
		}
		b, e := readOwnerFile(a.Path, limit)
		if e != nil || ownerDigest(b) != a.SHA256 {
			return nil, ownerError("owner_asset_invalid")
		}
		return b, nil
	}
	cert, err := asset(cfg.TLSCertificate, 256<<10)
	if err != nil {
		return out, err
	}
	key, err := asset(cfg.TLSPrivateKey, 32<<10)
	if err != nil {
		return out, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return out, ownerError("owner_tls_invalid")
	}
	pool := func(a ownerAsset) (*x509.CertPool, error) {
		b, e := asset(a, 256<<10)
		if e != nil {
			return nil, e
		}
		p := x509.NewCertPool()
		if !p.AppendCertsFromPEM(b) {
			return nil, ownerError("owner_ca_invalid")
		}
		return p, nil
	}
	authorityCA, err := pool(cfg.AuthorityCA)
	if err != nil {
		return out, err
	}
	uploadCA, err := pool(cfg.UploadCA)
	if err != nil {
		return out, err
	}
	encryption, err := asset(cfg.EncryptionPublicKey, 64<<10)
	if err != nil {
		return out, err
	}
	block, rest := pem.Decode(encryption)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return out, ownerError("owner_encryption_key_invalid")
	}
	var public any
	switch block.Type {
	case "PUBLIC KEY":
		public, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		var c *x509.Certificate
		c, err = x509.ParseCertificate(block.Bytes)
		if err == nil {
			public = c.PublicKey
		}
	default:
		err = ownerError("owner_encryption_key_invalid")
	}
	encryptionKey, ok := public.(*rsa.PublicKey)
	if err != nil || !ok || encryptionKey.N == nil || encryptionKey.N.Sign() <= 0 || encryptionKey.N.BitLen() < 2048 || encryptionKey.N.BitLen() > 4096 || encryptionKey.E != 65537 {
		return out, ownerError("owner_encryption_key_invalid")
	}
	pub, _ := hex.DecodeString(cfg.PublicKeyHex)
	pin := ownership.AuthorityPin{AuthorityID: cfg.AuthorityID, PublicKey: ed25519.PublicKey(pub), PipelineMode: cfg.PipelineMode, ExecutionProfileSHA256: cfg.ExecutionProfileSHA256}
	a := ownership.AuthorityClientConfig{BaseURL: cfg.AuthorityURL, Certificate: pair, RootCAs: authorityCA, ServerName: cfg.AuthorityServerName, Pin: pin, Scope: cfg.ExpectedScope}
	u := a
	u.BaseURL = cfg.UploadURL
	u.RootCAs = uploadCA
	u.ServerName = cfg.UploadServerName
	for _, clientCfg := range []ownership.AuthorityClientConfig{a, u} {
		c, e := ownership.NewAuthorityClient(clientCfg)
		if e != nil {
			return out, ownerError("owner_client_config_invalid")
		}
		c.CloseIdleConnections()
	}
	// Exclude the signing key as recipient before any reservation or input read.
	if len(pair.Certificate) == 0 {
		return out, ownerError("owner_tls_invalid")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return out, ownerError("owner_tls_invalid")
	}
	signing, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || signing.N.Cmp(encryptionKey.N) == 0 && signing.E == encryptionKey.E {
		return out, ownerError("owner_encryption_key_not_separate")
	}
	return ownerCLIMaterial{cfg, ownerDigest(raw), a, u, encryptionKey}, nil
}

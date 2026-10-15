//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

const AuthorityClientTimeout = 45 * time.Second

type AuthorityClientConfig struct {
	BaseURL     string
	Certificate tls.Certificate
	RootCAs     *x509.CertPool
	ServerName  string
	Pin         AuthorityPin
	Scope       AcceptanceScope
}

// AuthorityClient is a one-call transport, not a journal or retry coordinator.
// The caller must persist intent before Reserve/Finalize. After uncertainty use
// Get; never automatically resend ciphertext or create a new reservation.
type AuthorityClient struct {
	base   string
	client *http.Client
	leaf   *x509.Certificate
	pin    AuthorityPin
	scope  AcceptanceScope
	now    func() time.Time
}

func NewAuthorityClient(config AuthorityClientConfig) (*AuthorityClient, error) {
	u, err := url.Parse(config.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fail("ownership_client_origin_invalid")
	}
	if config.RootCAs == nil || len(config.RootCAs.Subjects()) == 0 || config.Pin.validate() != nil || config.Scope.validate() != nil || strings.ContainsAny(config.ServerName, "\x00\r\n/") {
		return nil, fail("ownership_client_config_invalid")
	}
	chain := config.Certificate.Certificate
	if len(chain) < 1 || len(chain) > 8 {
		return nil, fail("ownership_client_certificate_invalid")
	}
	copyCert := tls.Certificate{Certificate: make([][]byte, len(chain)), SupportedSignatureAlgorithms: append([]tls.SignatureScheme(nil), config.Certificate.SupportedSignatureAlgorithms...)}
	for i, der := range chain {
		if len(der) < 1 || len(der) > 16<<10 {
			return nil, fail("ownership_client_certificate_invalid")
		}
		copyCert.Certificate[i] = append([]byte(nil), der...)
	}
	leaf, pub, err := rsaLeaf(&x509.Certificate{Raw: copyCert.Certificate[0]})
	if err != nil {
		return nil, fail("ownership_client_certificate_invalid")
	}
	key, ok := config.Certificate.PrivateKey.(*rsa.PrivateKey)
	if !ok || key == nil || key.N == nil || key.D == nil || key.N.Cmp(pub.N) != 0 || key.E != pub.E || key.D.BitLen() > 4096 || len(key.Primes) < 2 || len(key.Primes) > 5 {
		return nil, fail("ownership_client_key_invalid")
	}
	for _, prime := range key.Primes {
		if prime == nil || prime.Sign() <= 0 || prime.BitLen() > 4096 {
			return nil, fail("ownership_client_key_invalid")
		}
	}
	if key.Validate() != nil {
		return nil, fail("ownership_client_key_invalid")
	}
	copyKey, err := x509.ParsePKCS1PrivateKey(x509.MarshalPKCS1PrivateKey(key))
	if err != nil {
		return nil, fail("ownership_client_key_invalid")
	}
	copyCert.PrivateKey = copyKey
	copyCert.Leaf = leaf
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fail("ownership_client_certificate_invalid")
	}
	config.Pin.PublicKey = append(ed25519.PublicKey(nil), config.Pin.PublicKey...)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: config.RootCAs.Clone(), ServerName: config.ServerName, Certificates: []tls.Certificate{copyCert}, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableKeepAlives: true, DisableCompression: true, MaxConnsPerHost: 4, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	client := &http.Client{Transport: transport, Timeout: AuthorityClientTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return fail("ownership_client_redirect_denied") }}
	return &AuthorityClient{strings.TrimSuffix(config.BaseURL, "/"), client, leaf, config.Pin, config.Scope, time.Now}, nil
}

func (c *AuthorityClient) CloseIdleConnections() {
	if c != nil && c.client != nil {
		c.client.CloseIdleConnections()
	}
}
func (c *AuthorityClient) call(ctx context.Context, method, path, contentType string, body io.Reader, size int64, limit int) ([]byte, error) {
	if c == nil || c.client == nil || ctx == nil || ctx.Err() != nil {
		return nil, fail("ownership_client_cancelled")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, fail("ownership_client_request_invalid")
	}
	req.ContentLength = size
	req.GetBody = nil
	req.Close = true
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fail("ownership_client_cancelled")
		}
		return nil, fail("ownership_client_transport_failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fail("ownership_client_http_rejected")
	}
	if resp.ProtoMajor != 1 || resp.ProtoMinor != 1 || resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 || len(resp.Header.Values("Content-Encoding")) != 0 {
		return nil, fail("ownership_client_response_invalid")
	}
	if resp.ContentLength > int64(limit) {
		return nil, fail("ownership_client_response_oversized")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if len(raw) > limit {
		return nil, fail("ownership_client_response_oversized")
	}
	if err != nil || ctx.Err() != nil {
		return nil, fail("ownership_client_response_failed")
	}
	return raw, nil
}

// Reserve makes exactly one HTTP call. Persist request ID, credential and name
// first; repeat only under an explicit caller recovery policy using that intent.
func (c *AuthorityClient) Reserve(ctx context.Context, request HTTPReserveRequest) ([]byte, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return nil, fail("ownership_client_cancelled")
	}
	if request.SchemaVersion != 1 || !hexValue(request.RequestID, 32) || !nameValid(request.OriginalName) {
		return nil, fail("ownership_client_request_invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, AuthorityClientTimeout)
	defer cancel()
	body, _ := json.Marshal(request)
	raw, err := c.call(ctx, http.MethodPost, "/v1/reservations", "application/json", bytes.NewReader(body), int64(len(body)), MaxChallengeBytes)
	if err != nil {
		return nil, err
	}
	verified, err := VerifyChallengeForClient(raw, c.pin, c.leaf, c.now())
	if err != nil || verified.claim.OriginalName != request.OriginalName {
		return nil, fail("ownership_client_challenge_invalid")
	}
	return raw, nil
}

// Get makes exactly one HTTP call. Historical acceptance is validated without a
// caller-selected clock; current owner identity still must be the exact leaf.
func (c *AuthorityClient) Get(ctx context.Context, jobID string) (HTTPJobResponse, error) {
	var zero HTTPJobResponse
	if c == nil || ctx == nil || ctx.Err() != nil {
		return zero, fail("ownership_client_cancelled")
	}
	if !hexValue(jobID, 16) {
		return zero, fail("ownership_client_job_invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, AuthorityClientTimeout)
	defer cancel()
	raw, err := c.call(ctx, http.MethodGet, "/v1/jobs/"+jobID, "", nil, 0, HTTPResponseLimit)
	if err != nil {
		return zero, err
	}
	response, err := decodeAuthorityClientJob(raw)
	if err != nil {
		return zero, err
	}
	if response.SchemaVersion != 1 || response.Challenge.Claim.JobID != jobID || response.Challenge.Claim.CredentialSHA256 != digest(c.leaf.Raw) {
		return zero, fail("ownership_client_job_invalid")
	}
	challengeRaw, err := MarshalChallenge(response.Challenge)
	if err != nil {
		return zero, fail("ownership_client_job_invalid")
	}
	issued, err := canonicalTime(response.Challenge.Claim.IssuedAt)
	if err != nil {
		return zero, fail("ownership_client_job_invalid")
	}
	// A signed historical challenge is a DTO, not a fresh acceptance capability.
	if _, err = VerifyChallengeForClient(challengeRaw, c.pin, c.leaf, issued); err != nil {
		return zero, fail("ownership_client_challenge_invalid")
	}
	switch response.State {
	case "reserved", "reading":
		if response.Acceptance != nil || response.FailureCode != "" {
			return zero, fail("ownership_client_job_invalid")
		}
	case "rejected":
		if response.Acceptance != nil || !storeFailureValid(response.FailureCode) {
			return zero, fail("ownership_client_job_invalid")
		}
	case "accepted":
		if response.Acceptance == nil || response.FailureCode != "" {
			return zero, fail("ownership_client_job_invalid")
		}
		acceptanceRaw, err := MarshalAcceptance(*response.Acceptance)
		if err != nil {
			return zero, fail("ownership_client_acceptance_invalid")
		}
		accepted, err := VerifyAcceptance(acceptanceRaw, c.pin, c.scope)
		if err != nil {
			return zero, fail("ownership_client_acceptance_invalid")
		}
		binding := accepted.Binding()
		if binding.JobID != jobID || binding.CredentialSHA256 != digest(c.leaf.Raw) || binding.ChallengeSHA256 != digest(challengeRaw) {
			return zero, fail("ownership_client_acceptance_invalid")
		}
	default:
		return zero, fail("ownership_client_job_invalid")
	}
	return response, nil
}

// Finalize makes exactly one HTTP call, after local identity/signature/size/hash
// checks. The caller must durably record this intent before invoking it. It is a
// fresh operation: after uncertain delivery or expiry recover with Get, not a
// ciphertext resend. A generic Reader cannot be interrupted inside Read; checks
// occur between bounded chunks. Up to 25 MiB ciphertext is buffered in memory.
func (c *AuthorityClient) Finalize(ctx context.Context, rawChallenge, rawManifest []byte, reader io.Reader, ciphertextBytes int64) ([]byte, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return nil, fail("ownership_client_cancelled")
	}
	ctx, cancel := context.WithTimeout(ctx, AuthorityClientTimeout)
	defer cancel()
	challenge, err := VerifyChallengeForClient(rawChallenge, c.pin, c.leaf, c.now())
	if err != nil {
		return nil, fail("ownership_client_challenge_invalid")
	}
	manifest, err := clientManifest(rawManifest, challenge, c.leaf)
	if err != nil {
		return nil, fail("ownership_client_manifest_invalid")
	}
	if reader == nil || ciphertextBytes != manifest.manifest.CiphertextBytes || ciphertextBytes < 16 || ciphertextBytes > MaxCiphertextBytes {
		return nil, fail("ownership_client_ciphertext_invalid")
	}
	ciphertext, err := readAuthorityClientCiphertext(ctx, reader, ciphertextBytes)
	if err != nil {
		return nil, err
	}
	if digest(ciphertext) != manifest.manifest.CiphertextSHA256 {
		return nil, fail("ownership_client_ciphertext_invalid")
	}
	if _, err = VerifyChallengeForClient(rawChallenge, c.pin, c.leaf, c.now()); err != nil {
		return nil, fail("ownership_client_challenge_invalid")
	}
	header := make([]byte, 4, HTTPFrameOverhead)
	binary.BigEndian.PutUint32(header, uint32(len(rawChallenge)))
	header = append(header, rawChallenge...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(rawManifest)))
	header = append(header, length...)
	header = append(header, rawManifest...)
	body := io.MultiReader(bytes.NewReader(header), bytes.NewReader(ciphertext))
	raw, err := c.call(ctx, http.MethodPost, "/v1/finalizations", "application/octet-stream", body, int64(len(header))+ciphertextBytes, MaxAcceptanceBytes)
	if err != nil {
		return nil, err
	}
	accepted, err := VerifyAcceptance(raw, c.pin, c.scope)
	if err != nil {
		return nil, fail("ownership_client_acceptance_invalid")
	}
	b := accepted.Binding()
	if b.ChallengeSHA256 != challenge.SHA256() || b.ManifestSHA256 != digest(manifest.canonical) || b.CredentialSHA256 != digest(c.leaf.Raw) || b.JobID != challenge.claim.JobID {
		return nil, fail("ownership_client_acceptance_invalid")
	}
	return raw, nil
}

// verifyClientManifest validates retained signed metadata without inventing a
// TLS Principal. It is historical verification only; fresh callers separately
// verify the challenge's current acceptance window.
func verifyClientManifest(raw []byte, challenge VerifiedChallenge, leaf *x509.Certificate) error {
	_, err := clientManifest(raw, challenge, leaf)
	return err
}
func clientManifest(raw []byte, challenge VerifiedChallenge, leaf *x509.Certificate) (VerifiedManifest, error) {
	actual, key, err := rsaLeaf(leaf)
	if err != nil {
		return VerifiedManifest{}, err
	}
	if !challenge.valid || challenge.claim.CredentialSHA256 != digest(actual.Raw) {
		return VerifiedManifest{}, fail("ownership_client_manifest_invalid")
	}
	return storedManifest(raw, challenge, key)
}

func readAuthorityClientCiphertext(ctx context.Context, reader io.Reader, size int64) ([]byte, error) {
	raw := make([]byte, 0, int(size))
	buffer := make([]byte, 64<<10)
	for int64(len(raw)) < size {
		if ctx.Err() != nil {
			return nil, fail("ownership_client_cancelled")
		}
		remaining := size - int64(len(raw))
		want := int64(len(buffer))
		if remaining < want {
			want = remaining
		}
		n, err := reader.Read(buffer[:want])
		if n < 0 || int64(n) > want {
			return nil, fail("ownership_client_ciphertext_invalid")
		}
		raw = append(raw, buffer[:n]...)
		if err == io.EOF {
			if int64(len(raw)) != size {
				return nil, fail("ownership_client_ciphertext_invalid")
			}
			if ctx.Err() != nil {
				return nil, fail("ownership_client_cancelled")
			}
			return raw, nil
		}
		if err != nil || n == 0 {
			return nil, fail("ownership_client_ciphertext_invalid")
		}
	}
	if ctx.Err() != nil {
		return nil, fail("ownership_client_cancelled")
	}
	n, err := reader.Read(buffer[:1])
	if n != 0 || err != io.EOF {
		return nil, fail("ownership_client_ciphertext_invalid")
	}
	if ctx.Err() != nil {
		return nil, fail("ownership_client_cancelled")
	}
	return raw, nil
}

func decodeAuthorityClientJob(raw []byte) (HTTPJobResponse, error) {
	var out HTTPJobResponse
	if len(raw) == 0 || len(raw) > HTTPResponseLimit || !utf8.Valid(raw) {
		return out, fail("ownership_client_response_invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return out, fail("ownership_client_response_invalid")
	}
	fields := map[string]reflect.Type{"schema_version": reflect.TypeOf(int(0)), "state": reflect.TypeOf(""), "challenge": reflect.TypeOf(SignedChallenge{}), "acceptance": reflect.TypeOf(SignedAcceptance{}), "failure_code": reflect.TypeOf("")}
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		name, ok := key.(string)
		t, known := fields[name]
		if e != nil || !ok || !known || seen[name] {
			return out, fail("ownership_client_response_invalid")
		}
		seen[name] = true
		if scanValue(d, t, 1) != nil {
			return out, fail("ownership_client_response_invalid")
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || !seen["schema_version"] || !seen["state"] || !seen["challenge"] {
		return out, fail("ownership_client_response_invalid")
	}
	if _, err = d.Token(); err != io.EOF {
		return out, fail("ownership_client_response_invalid")
	}
	if json.Unmarshal(raw, &out) != nil {
		return out, fail("ownership_client_response_invalid")
	}
	return out, nil
}

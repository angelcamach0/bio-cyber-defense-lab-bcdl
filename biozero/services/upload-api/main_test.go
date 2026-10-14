package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestUploadIdentityUsesVerifiedCN(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	for _, supplied := range []string{"", "researcher-a", "researcher-b"} {
		r := httptest.NewRequest("POST", "/upload", strings.NewReader(url.Values{"client_id": {supplied}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Client-Id", "researcher-b")
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: "researcher-a"}}
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		owner, err := uploadIdentity(r)
		if supplied == "researcher-b" {
			if err == nil {
				t.Fatal("claimed other owner")
			}
		} else if err != nil || owner != "researcher-a" {
			t.Fatal(owner, err)
		}
	}
}
func TestUploadIdentityRejectsUnverifiedAndHeaders(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	r := httptest.NewRequest("POST", "/upload", nil)
	r.Header.Set("X-Client-Id", "researcher-a")
	if _, err := uploadIdentity(r); err == nil {
		t.Fatal("header accepted without mTLS")
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "researcher-a"}}}}
	if _, err := uploadIdentity(r); err == nil {
		t.Fatal("unverified peer accepted")
	}
}
func TestProtectedTLSConfig(t *testing.T) {
	t.Setenv("BIOZERO_SECURITY_MODE", "protected")
	if validateServerSecurity("", "", "") == nil || validateServerSecurity("cert", "key", "") == nil {
		t.Fatal("incomplete TLS accepted")
	}
	if validateServerSecurity("cert", "key", "ca") != nil {
		t.Fatal("complete TLS rejected")
	}
}

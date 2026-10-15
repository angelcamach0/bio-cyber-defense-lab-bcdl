// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func acceptanceFixture(t *testing.T, historical bool) (*testFixture, SignedAcceptance, AcceptanceScope) {
	t.Helper()
	original := fixture(t)
	copyFixture := *original
	f := &copyFixture
	if historical {
		f.now = f.now.Add(-30 * time.Minute)
	}
	body := bytes.Repeat([]byte("x"), 32)
	raw, manifest, _ := signed(t, f, body)
	binding, err := Finalize(context.Background(), &f.stateA, raw, manifest, f.pin, bytes.NewReader(body), f.now)
	if err != nil {
		t.Fatal(err)
	}
	scope := AcceptanceScope{strings.Repeat("5", 32), strings.Repeat("6", 64)}
	accepted, err := sealAcceptance(f.private, f.pin, scope, &f.stateA, raw, manifest, binding, f.now.Add(time.Second+123*time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	return f, accepted, scope
}
func resignAcceptanceForTest(t *testing.T, a SignedAcceptance, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := boundedJSON(a.Record, MaxAcceptanceBytes)
	if err != nil {
		t.Fatal(err)
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(key, raw))
	raw, err = MarshalAcceptance(a)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestAcceptanceHistoricalDecisionDoesNotReexpire(t *testing.T) {
	f, a, scope := acceptanceFixture(t, true)
	raw, err := MarshalAcceptance(a)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := PrincipalFromTLS(&f.stateA)
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := MarshalChallenge(a.Record.Challenge)
	if _, err = VerifyChallenge(challenge, f.pin, owner, time.Now()); err == nil {
		t.Fatal("test requires original challenge already expired")
	}
	v, err := VerifyAcceptance(raw, f.pin, scope)
	if err != nil {
		t.Fatal(err)
	}
	if v.Binding() != a.Record.Binding || v.SHA256() != digest(raw) {
		t.Fatal("original historical binding changed")
	}
	aad, err := CanonicalAADFromAcceptance(v)
	if err != nil {
		t.Fatal(err)
	}
	acceptedAt, _ := acceptanceTime(a.Record.AcceptedAt)
	original, err := VerifyChallenge(challenge, f.pin, owner, acceptedAt)
	if err != nil {
		t.Fatal(err)
	}
	want, err := CanonicalAAD(original)
	if err != nil || !bytes.Equal(aad, want) {
		t.Fatal("historical AAD mismatch", err)
	}
	claims := v.Claims()
	claims.Binding.JobID = strings.Repeat("f", 16)
	claims.Challenge.Claim.Nonce = strings.Repeat("f", 64)
	if v.Binding() != a.Record.Binding || v.Claims().Challenge.Claim.Nonce != a.Record.Challenge.Claim.Nonce {
		t.Fatal("claims exposed mutable verified state")
	}
	if _, err = CanonicalAADFromAcceptance(VerifiedAcceptance{}); err == nil {
		t.Fatal("zero verified value accepted")
	}
}
func TestAcceptanceExternalScopeAndAuthorityRequired(t *testing.T) {
	f, a, scope := acceptanceFixture(t, false)
	raw, _ := MarshalAcceptance(a)
	cases := []struct {
		name  string
		pin   AuthorityPin
		scope AcceptanceScope
	}{
		{"scope_missing", f.pin, AcceptanceScope{}},
		{"store_changed", f.pin, AcceptanceScope{strings.Repeat("7", 32), scope.PolicySHA256}},
		{"policy_changed", f.pin, AcceptanceScope{scope.StoreID, strings.Repeat("7", 64)}},
		{"pin_missing", AuthorityPin{}, scope},
	}
	wrongKey := f.pin
	wrongKey.PublicKey = make([]byte, ed25519.PublicKeySize)
	cases = append(cases, struct {
		name  string
		pin   AuthorityPin
		scope AcceptanceScope
	}{"external_key_changed", wrongKey, scope})
	wrongProfile := f.pin
	wrongProfile.ExecutionProfileSHA256 = strings.Repeat("8", 64)
	cases = append(cases, struct {
		name  string
		pin   AuthorityPin
		scope AcceptanceScope
	}{"external_profile_changed", wrongProfile, scope})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyAcceptance(raw, tc.pin, tc.scope); err == nil {
				t.Fatal("external expectation ignored")
			}
		})
	}
}
func TestAcceptanceSignedInconsistentFactsRejected(t *testing.T) {
	f, a, scope := acceptanceFixture(t, false)
	changes := map[string]func(*AcceptanceRecord){
		"schema":                          func(r *AcceptanceRecord) { r.SchemaVersion = 2 },
		"domain":                          func(r *AcceptanceRecord) { r.Domain = ChallengeDomain },
		"authority":                       func(r *AcceptanceRecord) { r.AuthorityID = strings.Repeat("7", 32) },
		"key_id":                          func(r *AcceptanceRecord) { r.KeyID = strings.Repeat("7", 64) },
		"store":                           func(r *AcceptanceRecord) { r.StoreID = strings.Repeat("7", 32) },
		"policy":                          func(r *AcceptanceRecord) { r.PolicySHA256 = strings.Repeat("7", 64) },
		"time_before_issue":               func(r *AcceptanceRecord) { r.AcceptedAt = f.now.Add(-time.Second).Format(time.RFC3339Nano) },
		"time_at_expiry":                  func(r *AcceptanceRecord) { r.AcceptedAt = r.Challenge.Claim.ExpiresAt },
		"time_noncanonical":               func(r *AcceptanceRecord) { r.AcceptedAt = f.now.Format("2006-01-02T15:04:05+00:00") },
		"credential_other_same_cn_serial": func(r *AcceptanceRecord) { r.CredentialDER = hex.EncodeToString(f.certB.Raw) },
		"credential_invalid_der":          func(r *AcceptanceRecord) { r.CredentialDER = "aa" },
		"credential_odd_hex":              func(r *AcceptanceRecord) { r.CredentialDER = "aaa" },
		"challenge_signature":             func(r *AcceptanceRecord) { r.Challenge.Signature = strings.Repeat("0", 128) },
		"client_signature":                func(r *AcceptanceRecord) { r.Manifest.Signature = strings.Repeat("0", 512) },
		"binding_job":                     func(r *AcceptanceRecord) { r.Binding.JobID = strings.Repeat("7", 16) },
		"binding_owner":                   func(r *AcceptanceRecord) { r.Binding.CredentialSHA256 = digest(f.certB.Raw) },
		"binding_nonce":                   func(r *AcceptanceRecord) { r.Binding.Nonce = strings.Repeat("7", 64) },
		"binding_input_hash":              func(r *AcceptanceRecord) { r.Binding.CiphertextSHA256 = strings.Repeat("7", 64) },
		"binding_input_bytes":             func(r *AcceptanceRecord) { r.Binding.CiphertextBytes++ },
		"binding_envelope":                func(r *AcceptanceRecord) { r.Binding.KeyEnvelopeSHA256 = strings.Repeat("7", 64) },
		"binding_manifest":                func(r *AcceptanceRecord) { r.Binding.ManifestSHA256 = strings.Repeat("7", 64) },
		"binding_aad":                     func(r *AcceptanceRecord) { r.Binding.AADSHA256 = strings.Repeat("7", 64) },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			changed := a
			mutate(&changed.Record)
			raw := resignAcceptanceForTest(t, changed, f.private)
			if _, err := VerifyAcceptance(raw, f.pin, scope); err == nil {
				t.Fatal("signed inconsistent facts accepted")
			}
		})
	}
}
func TestAcceptanceStrictWireAndOuterTamper(t *testing.T) {
	f, a, scope := acceptanceFixture(t, false)
	raw, _ := MarshalAcceptance(a)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	without := map[string]json.RawMessage{"record": fields["record"]}
	missing, _ := json.Marshal(without)
	cases := map[string][]byte{
		"outer_signature": bytes.Replace(raw, []byte(a.Signature), []byte(strings.Repeat("0", 128)), 1),
		"duplicate":       append([]byte(`{"signature":"`+a.Signature+`",`), raw[1:]...),
		"case_alias":      bytes.Replace(raw, []byte(`"record"`), []byte(`"Record"`), 1),
		"null":            bytes.Replace(raw, []byte(`"record":{`), []byte(`"record":null,"extra":{`), 1),
		"unknown":         append([]byte(`{"extra":1,`), raw[1:]...),
		"trailing":        append(append([]byte{}, raw...), []byte(` {}`)...),
		"missing":         missing,
		"oversize":        bytes.Repeat([]byte(" "), MaxAcceptanceBytes+1),
		"invalid_utf8":    append([]byte{255}, raw...),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyAcceptance(b, f.pin, scope); err == nil {
				t.Fatal("unsafe wire accepted")
			}
		})
	}
}
func TestAcceptanceSealRequiresMeasuredFactsAndRealIdentity(t *testing.T) {
	f := fixture(t)
	body := bytes.Repeat([]byte("x"), 32)
	raw, manifest, _ := signed(t, f, body)
	measured, err := Finalize(context.Background(), &f.stateA, raw, manifest, f.pin, bytes.NewReader(body), f.now)
	if err != nil {
		t.Fatal(err)
	}
	scope := AcceptanceScope{strings.Repeat("5", 32), strings.Repeat("6", 64)}
	altered := measured
	altered.CiphertextSHA256 = strings.Repeat("7", 64)
	corruptKey := append(ed25519.PrivateKey{}, f.private...)
	corruptKey[len(corruptKey)-1] ^= 1
	for _, tc := range []struct {
		name    string
		state   *tls.ConnectionState
		binding Binding
		key     ed25519.PrivateKey
		at      time.Time
	}{
		{"other_leaf", &f.stateB, measured, f.private, f.now},
		{"nil_tls", nil, measured, f.private, f.now},
		{"unmeasured_binding", &f.stateA, altered, f.private, f.now},
		{"key_seed_public_mismatch", &f.stateA, measured, corruptKey, f.now},
		{"time_at_expiry", &f.stateA, measured, f.private, f.now.Add(5 * time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sealAcceptance(tc.key, f.pin, scope, tc.state, raw, manifest, tc.binding, tc.at); err == nil {
				t.Fatal("unsafe seal accepted")
			}
		})
	}
}

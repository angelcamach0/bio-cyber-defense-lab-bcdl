//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"crypto/x509"
	"encoding/hex"
)

// Distinct certificate fingerprints alone do not separate key capabilities:
// a renewed/aliased leaf can carry the same RSA key. Reparse both DER values.
func publicationProducerDistinct(v VerifiedAcceptance, producer *x509.Certificate) bool {
	if !v.valid || producer == nil {
		return false
	}
	leaf, key, e := rsaLeaf(producer)
	if e != nil {
		return false
	}
	der, e := hex.DecodeString(v.record.CredentialDER)
	if e != nil {
		return false
	}
	_, owner, e := rsaLeaf(&x509.Certificate{Raw: der})
	return e == nil && digest(leaf.Raw) != v.Binding().CredentialSHA256 && (key.E != owner.E || key.N.Cmp(owner.N) != 0)
}

const PublicationReceiptDomain = "biozero.authorization-publication.v1"
const PublicationResponseLimit = 8 << 10
const PublicationRunLimit = 64
const PublicationOwnerLimit = 20

// PublicationScope is supplied through trusted initialization, never learned
// from an untrusted HTTP receipt. It identifies a particular retained history.
type PublicationScope struct {
	PublisherID  string `json:"publisher_id"`
	PolicySHA256 string `json:"policy_sha256"`
}

func (s PublicationScope) validate() error {
	if !hexValue(s.PublisherID, 32) || !hexValue(s.PolicySHA256, 64) {
		return fail("ownership_publication_scope_invalid")
	}
	return nil
}

// A publication receipt proves local durable publication acknowledgement only.
// It never approves execution, scientific release, or downstream peer receipt.
type PublicationReceipt struct {
	SchemaVersion          int              `json:"schema_version"`
	Domain                 string           `json:"domain"`
	State                  string           `json:"state"`
	PublisherScope         PublicationScope `json:"publisher_scope"`
	AuthorityScope         AcceptanceScope  `json:"authority_scope"`
	JobID                  string           `json:"job_id"`
	AcceptanceSHA256       string           `json:"acceptance_sha256"`
	CredentialSHA256       string           `json:"credential_sha256"`
	ExecutionProfileSHA256 string           `json:"execution_profile_sha256"`
	PipelineMode           string           `json:"pipeline_mode"`
}

type PublicationClientConfig struct {
	Client                 AuthorityClientConfig
	ExpectedPublisherScope PublicationScope
}

// Only an explicitly pinned service producer can relay signed authorization.
// Its identity is separate from the owner authenticated inside the acceptance.
type PublicationStoreConfig struct {
	Directory                string
	Pin                      AuthorityPin
	AuthorityScope           AcceptanceScope
	ExpectedPublisherScope   PublicationScope
	ProducerCredentialSHA256 []string
}

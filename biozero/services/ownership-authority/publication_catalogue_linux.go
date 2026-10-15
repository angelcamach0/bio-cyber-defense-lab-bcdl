//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"encoding/json"
	"syscall"
)

const publicationCatalogueLimit = 1 << 20
const publicationCatalogueDomain = "biozero.authorization-publication.catalogue.v1"

type publicationCatalogueEntry struct {
	JobID                    string `json:"job_id"`
	AcceptanceSHA256         string `json:"acceptance_sha256"`
	CredentialSHA256         string `json:"credential_sha256"`
	ProducerCredentialSHA256 string `json:"producer_credential_sha256"`
	RetainedBytes            int64  `json:"retained_bytes"`
}
type publicationCatalogue struct {
	SchemaVersion  int                         `json:"schema_version"`
	Domain         string                      `json:"domain"`
	PublisherScope PublicationScope            `json:"publisher_scope"`
	Records        []publicationCatalogueEntry `json:"records"`
}

func (s *PublicationStore) loadCatalogue() error {
	raw, pin, e := publicationRead(s.root, "catalogue.json", publicationCatalogueLimit)
	if e != nil {
		return e
	}
	var c publicationCatalogue
	if len(raw) > publicationCatalogueLimit || decodeStoreJSON(raw, &c) != nil || c.SchemaVersion != 1 || c.Domain != publicationCatalogueDomain || c.PublisherScope != s.scope || c.Records == nil || len(c.Records) > PublicationRunLimit {
		return fail("ownership_publication_history_invalid")
	}
	seen := map[string]bool{}
	owners := map[string]int{}
	for _, entry := range c.Records {
		allowed := false
		for _, p := range s.config.ProducerCredentialSHA256 {
			allowed = allowed || p == entry.ProducerCredentialSHA256
		}
		if !hexValue(entry.JobID, 16) || !hexValue(entry.AcceptanceSHA256, 64) || !hexValue(entry.CredentialSHA256, 64) || !allowed || entry.CredentialSHA256 == entry.ProducerCredentialSHA256 || entry.RetainedBytes != PublicationRunCharge || seen[entry.JobID] {
			return fail("ownership_publication_history_invalid")
		}
		seen[entry.JobID] = true
		owners[entry.CredentialSHA256]++
		if owners[entry.CredentialSHA256] > PublicationOwnerLimit {
			return fail("ownership_publication_history_invalid")
		}
	}
	s.catalogue = c
	s.cataloguePin = pin
	return nil
}

// The independent catalogue is the durable witness of retained jobs/charges.
// Deleting both a job directory and its inbox copy cannot reduce cold counts.
// It does not provide antirollback against a consistent malicious host snapshot.
func (s *PublicationStore) catalogueMatchesRows() bool {
	if len(s.catalogue.Records) != len(s.rows) || !publicationSameFile(s.root, "catalogue.json", publicationCatalogueLimit, s.cataloguePin) {
		return false
	}
	for _, entry := range s.catalogue.Records {
		row, ok := s.rows[entry.JobID]
		if !ok || row.result.AcceptanceSHA256 != entry.AcceptanceSHA256 || row.result.CredentialSHA256 != entry.CredentialSHA256 || row.record.ProducerCredentialSHA256 != entry.ProducerCredentialSHA256 || row.record.RetainedBytes != entry.RetainedBytes {
			return false
		}
	}
	return true
}

// Intent and the full replacement are synced before rename; the root directory
// is synced after rename and after retiring only this exact transaction marker.
// Cold Open never completes, deletes or adopts a leftover marker/replacement.
func (s *PublicationStore) reserveCatalogue(entry publicationCatalogueEntry) error {
	next := s.catalogue
	next.Records = append(append([]publicationCatalogueEntry{}, s.catalogue.Records...), entry)
	raw, e := boundedJSON(next, publicationCatalogueLimit)
	if e != nil {
		return s.latch()
	}
	marker, _ := json.Marshal(struct {
		PreviousSHA256 string `json:"previous_sha256"`
		NextSHA256     string `json:"next_sha256"`
	}{s.cataloguePin.sha, digest(raw)})
	if publicationWrite(s.root, "catalogue.intent", marker) != nil || s.point("catalogue_intent_durable") != nil {
		return s.latch()
	}
	if publicationWrite(s.root, "catalogue.next", raw) != nil || s.point("catalogue_next_durable") != nil {
		return s.latch()
	}
	if syscall.Renameat(int(s.root.Fd()), "catalogue.next", int(s.root.Fd()), "catalogue.json") != nil || s.root.Sync() != nil || s.point("catalogue_renamed") != nil {
		return s.latch()
	}
	if syscall.Unlinkat(int(s.root.Fd()), "catalogue.intent") != nil || s.root.Sync() != nil || s.point("catalogue_marker_removed") != nil {
		return s.latch()
	}
	if e = s.loadCatalogue(); e != nil {
		return s.latch()
	}
	return nil
}

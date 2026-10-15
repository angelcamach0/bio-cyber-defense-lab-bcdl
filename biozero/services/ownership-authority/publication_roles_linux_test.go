//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPublicationRolesRejectSameKeyDifferentLeafBeforeIO(t *testing.T) {
	f := fixture(t)
	states, certs := publicationTLSLeaves(t, 1, f.keyA)
	if digest(certs[0].Raw) == digest(f.certA.Raw) {
		t.Fatal("alias fixture requires distinct certificates")
	}
	var hits atomic.Int32
	config, raw, _ := publicationClientFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	config.Client.Certificate = tls.Certificate{Certificate: [][]byte{certs[0].Raw}, PrivateKey: f.keyA}
	client, e := NewPublicationClient(config)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	for _, method := range []string{"POST", "GET"} {
		var err error
		if method == "POST" {
			_, err = client.Publish(context.Background(), raw)
		} else {
			_, err = client.Get(context.Background(), raw)
		}
		if err == nil || hits.Load() != 0 {
			t.Fatal("same-key certificate alias reached publisher", method, err, hits.Load())
		}
	}
	parent := t.TempDir()
	os.Chmod(parent, 0700)
	directory := filepath.Join(parent, "sender")
	if _, e := CreatePublicationOperation(PublicationOperationConfig{Directory: directory, Client: config, Acceptance: raw, TrustSHA256: strings.Repeat("9", 64)}); e == nil {
		t.Fatal("same-key sender adopted")
	}
	if _, e := os.Lstat(directory); !os.IsNotExist(e) {
		t.Fatal("rejected role created filesystem custody", e)
	}
	receiver, e := CreatePublicationStore(PublicationStoreConfig{Directory: filepath.Join(parent, "receiver"), Pin: config.Client.Pin, AuthorityScope: config.Client.Scope, ProducerCredentialSHA256: []string{digest(certs[0].Raw), digest(f.certB.Raw)}})
	if e != nil {
		t.Fatal(e)
	}
	defer receiver.Close()
	before := publicationTree(t, receiver.config.Directory)
	if _, e := receiver.Publish(context.Background(), &states[0], raw); e == nil || e.Error() != "ownership_publication_role_invalid" {
		t.Fatal("receiver accepted alias owner key as service role", e)
	}
	if !reflect.DeepEqual(before, publicationTree(t, receiver.config.Directory)) || receiver.Check() != nil {
		t.Fatal("role rejection published, charged or poisoned custody")
	}
	receipt, e := receiver.Publish(context.Background(), &f.stateB, raw)
	if e != nil {
		t.Fatal(e)
	}
	before = publicationTree(t, receiver.config.Directory)
	if _, e = receiver.Get(context.Background(), &states[0], receipt.JobID, receipt.AcceptanceSHA256); e == nil || e.Error() != "ownership_publication_role_invalid" {
		t.Fatal("raw receiver GET accepted alias owner key", e)
	}
	if got, e := receiver.Get(context.Background(), &f.stateB, receipt.JobID, receipt.AcceptanceSHA256); e != nil || got != receipt {
		t.Fatal("matching dedicated producer GET failed", e)
	}
	if !reflect.DeepEqual(before, publicationTree(t, receiver.config.Directory)) {
		t.Fatal("GET changed retained history")
	}
}

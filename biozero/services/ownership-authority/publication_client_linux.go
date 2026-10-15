//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
package ownership

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

const PublicationClientTimeout = 30 * time.Second

// PublicationClient relays already-signed authorization through a dedicated
// producer identity. Its private transport cannot be used by callers to reserve,
// finalize, deliver an upload or access execution. The caller retains durable
// intent before Publish; uncertainty permits Get, never an automatic POST retry.
type PublicationClient struct {
	transport *AuthorityClient
	scope     PublicationScope
}

func NewPublicationClient(config PublicationClientConfig) (*PublicationClient, error) {
	if config.ExpectedPublisherScope.validate() != nil {
		return nil, fail("ownership_publication_client_config_invalid")
	}
	// Reuse the existing certificate/key/CA/pin snapshot validation and copying.
	// This object remains private; publication has its own closed wire policy.
	transport, err := NewAuthorityClient(config.Client)
	if err != nil {
		return nil, err
	}
	httpTransport, ok := transport.client.Transport.(*http.Transport)
	if !ok || httpTransport.TLSClientConfig == nil {
		transport.CloseIdleConnections()
		return nil, fail("ownership_publication_client_config_invalid")
	}
	httpTransport.TLSClientConfig.MinVersion = tls.VersionTLS13
	httpTransport.TLSClientConfig.MaxVersion = tls.VersionTLS13
	transport.client.Timeout = PublicationClientTimeout
	return &PublicationClient{transport: transport, scope: config.ExpectedPublisherScope}, nil
}

func (c *PublicationClient) CloseIdleConnections() {
	if c != nil {
		c.transport.CloseIdleConnections()
	}
}

// Publish makes exactly one POST with the verified canonical representation.
// Equivalent JSON whitespace shares the same identity and transmitted bytes.
func (c *PublicationClient) Publish(ctx context.Context, rawAcceptance []byte) (PublicationReceipt, error) {
	return c.request(ctx, http.MethodPost, rawAcceptance)
}

// Get makes exactly one bodyless GET for this verified signed acceptance. It
// neither discovers unknown jobs nor supplies caller-selected binding fields.
func (c *PublicationClient) Get(ctx context.Context, rawAcceptance []byte) (PublicationReceipt, error) {
	return c.request(ctx, http.MethodGet, rawAcceptance)
}

func (c *PublicationClient) request(ctx context.Context, method string, rawAcceptance []byte) (PublicationReceipt, error) {
	var zero PublicationReceipt
	if c == nil || c.transport == nil || c.transport.client == nil || ctx == nil || ctx.Err() != nil {
		return zero, fail("ownership_publication_client_cancelled")
	}
	ctx, cancel := context.WithTimeout(ctx, PublicationClientTimeout)
	defer cancel()
	v, err := VerifyAcceptance(rawAcceptance, c.transport.pin, c.transport.scope)
	if err != nil || ctx.Err() != nil {
		return zero, fail("ownership_publication_client_acceptance_invalid")
	}
	binding := v.Binding()
	if !publicationProducerDistinct(v, c.transport.leaf) {
		return zero, fail("ownership_publication_client_role_invalid")
	}
	path := "/v1/acceptances/" + binding.JobID + "/" + v.SHA256()
	var body io.Reader
	var size int64
	if method == http.MethodPost {
		body = bytes.NewReader(v.canonical)
		size = int64(len(v.canonical))
	}
	request, err := http.NewRequestWithContext(ctx, method, c.transport.base+path, body)
	if err != nil {
		return zero, fail("ownership_publication_client_request_invalid")
	}
	request.ContentLength = size
	request.GetBody = nil
	request.Close = true
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.transport.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return zero, fail("ownership_publication_client_unavailable")
	}
	if response == nil || response.Body == nil {
		return zero, fail("ownership_publication_client_response_invalid")
	}
	defer response.Body.Close()
	contentType := response.Header.Values("Content-Type")
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 1 || response.ProtoMinor != 1 ||
		response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.Version != tls.VersionTLS13 || len(response.TLS.VerifiedChains) == 0 ||
		len(contentType) != 1 || contentType[0] != "application/json" || len(response.Header.Values("Content-Encoding")) != 0 ||
		response.Uncompressed || len(response.TransferEncoding) != 0 && (len(response.TransferEncoding) != 1 || response.TransferEncoding[0] != "chunked") || len(response.Trailer) != 0 ||
		len(response.Header.Values("Trailer")) != 0 || response.ContentLength > PublicationResponseLimit {
		return zero, fail("ownership_publication_client_response_invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, PublicationResponseLimit+1))
	if err != nil || ctx.Err() != nil || len(raw) == 0 || len(raw) > PublicationResponseLimit ||
		response.ContentLength >= 0 && int64(len(raw)) != response.ContentLength || len(response.Trailer) != 0 {
		return zero, fail("ownership_publication_client_response_invalid")
	}
	var receipt PublicationReceipt
	if strictJSON(raw, &receipt, PublicationResponseLimit) != nil || receipt.SchemaVersion != 1 || receipt.Domain != PublicationReceiptDomain ||
		receipt.State != "published" || receipt.PublisherScope != c.scope || receipt.AuthorityScope != c.transport.scope ||
		receipt.JobID != binding.JobID || receipt.AcceptanceSHA256 != v.SHA256() || receipt.CredentialSHA256 != binding.CredentialSHA256 ||
		receipt.ExecutionProfileSHA256 != binding.ExecutionProfileSHA256 || receipt.PipelineMode != binding.PipelineMode {
		return zero, fail("ownership_publication_client_receipt_invalid")
	}
	return receipt, nil
}

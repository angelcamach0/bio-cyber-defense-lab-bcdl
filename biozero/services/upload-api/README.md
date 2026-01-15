# upload-api (MVP)

Accepts file uploads and writes job metadata for the runner to process.

## Endpoints
- `POST /upload` (multipart form, field `file`, optional `client_id`)
- `GET /health`

## Security metadata
When the client provides encryption/signing metadata, the API records:
- `enc_alg`, `enc_key`, `sig_alg`, `sig`
- mTLS client certificate subject/issuer/serial (when enabled)

## Config
- `BIOZERO_UPLOAD_ADDR` (default `:8081`)
- `BIOZERO_DATA_DIR` (default `./data`)
- `BIOZERO_MAX_UPLOAD_BYTES` (default `26214400`)
- `BIOZERO_RATE_LIMIT` (requests per minute, default `60`)
- `BIOZERO_TLS_CERT` (PEM cert path, enables TLS when set)
- `BIOZERO_TLS_KEY` (PEM key path)
- `BIOZERO_TLS_CA` (PEM CA bundle, enables mTLS when set)

## Run
```bash
go run ./main.go
```

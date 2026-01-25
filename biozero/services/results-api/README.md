# results-api (MVP)

Serves processed results for a given job ID.

## Endpoints
- `GET /results/{job_id}`
- `GET /health`

## Response shape
`GET /results/{job_id}` returns `status` and, when processed, a raw `data` payload
containing the stored result JSON (including detection and pipeline output).

Example (abridged):
```json
{
  "status": "processed",
  "data": {
    "job_id": "d846d14ae9491894",
    "status": "processed",
    "detection": {
      "verdict": "low"
    }
  }
}
```

## Config
- `BIOZERO_RESULTS_ADDR` (default `:8082`)
- `BIOZERO_DATA_DIR` (default `./data`)
- `BIOZERO_RATE_LIMIT` (requests per minute, default `120`)
- `BIOZERO_TLS_CERT` (PEM cert path, enables TLS when set)
- `BIOZERO_TLS_KEY` (PEM key path)
- `BIOZERO_TLS_CA` (PEM CA bundle, enables mTLS when set)

## Authorization
- mTLS enabled: client cert serial must match the job record.
- Non-mTLS: `X-Client-Id` must match the job record.

## Run
```bash
go run ./main.go
```

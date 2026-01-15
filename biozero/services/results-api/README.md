# results-api (MVP)

Serves processed results for a given job ID.

## Endpoints
- `GET /results/{job_id}`
- `GET /health`

## Response shape
`GET /results/{job_id}` returns `job`, `result`, and `inputs` so the UI can display provenance.

Example (abridged):
```json
{
  "job": {
    "id": "d846d14ae9491894",
    "status": "completed"
  },
  "inputs": {
    "mode": "default",
    "reference": {
      "id": "bundled",
      "hash": "sha256:...",
      "version": "v1"
    },
    "rules": {
      "id": "bundled",
      "hash": "sha256:...",
      "version": "v1"
    }
  },
  "result": {
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

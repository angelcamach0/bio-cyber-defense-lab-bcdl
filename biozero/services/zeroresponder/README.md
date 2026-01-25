# zeroresponder (MVP)

Simple webhook listener that logs response actions and writes blocklist/revocation/quarantine files.

## Endpoints
- `POST /alert` (JSON payload)
- `GET /health`

When `BIOZERO_WEBHOOK_SECRET` is set, callers must include `X-Webhook-Secret`.

## Config
- `BIOZERO_RESPONDER_ADDR` (default `:8090`)
- `BIOZERO_DATA_DIR` (default `./data`)
- `BIOZERO_WEBHOOK_SECRET` (optional shared secret)
- `BIOZERO_ALERT_MAX_BYTES` (default `1048576`)

## Example alert
```json
{
  "alert_id": "ALERT-001",
  "source": "siem",
  "severity": "high",
  "timestamp": "2026-01-12T00:00:00Z",
  "indicators": {
    "ip": "10.1.2.3",
    "job_id": "abcd1234",
    "cert_serial": "01"
  },
  "actions": ["block_ip", "revoke_cert", "quarantine"]
}
```

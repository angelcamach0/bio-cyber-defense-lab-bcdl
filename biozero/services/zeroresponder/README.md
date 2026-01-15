# zeroresponder (MVP)

Simple webhook listener that logs response actions and writes blocklist/revocation/quarantine files.

## Endpoints
- `POST /alert` (JSON payload)
- `GET /health`

## Config
- `BIOZERO_RESPONDER_ADDR` (default `:8090`)
- `BIOZERO_DATA_DIR` (default `./data`)
- `BIOZERO_WEBHOOK_SECRET` (optional shared secret)

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

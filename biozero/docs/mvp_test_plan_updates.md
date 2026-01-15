# MVP Test Plan Updates

These tests align with the new MVP code path.

## T-7.1 - Upload API accepts file
- Steps: POST /upload with client_id and file.
- Expected: HTTP 200 with job_id.
- Actual Result: Upload succeeded; job_id `d846d14ae9491894`.
- PASS/FAIL: PASS
- Evidence: `biozero/docs/evidence/LOG_30_uploader_cli.txt`

## T-7.2 - Runner processes job
- Steps: Wait for runner output file.
- Expected: results/{job_id}.json created with status=processed.
- Actual Result: results returned with `status=processed`, pipeline output JSON, and tool outputs.
- PASS/FAIL: PASS
- Evidence: `biozero/docs/evidence/LOG_30_uploader_cli.txt`

## T-7.3 - Results API returns processed status
- Steps: GET /results/{job_id} with X-Client-Id.
- Expected: status=processed and JSON payload.
- Actual Result: Processed JSON returned in CLI output.
- PASS/FAIL: PASS
- Evidence: `biozero/docs/evidence/LOG_30_uploader_cli.txt`

## T-7.4 - mTLS denies unauthenticated client
- Steps: Call APIs without client cert when mTLS enabled.
- Expected: TLS handshake failure.
- Actual Result: TLS handshake failed with `alert certificate required`.
- PASS/FAIL: PASS
- Evidence: `biozero/docs/evidence/LOG_31_tls_fail.txt`

## T-7.5 - Encrypted upload decrypts in runner
- Steps: CLI upload with --server-cert.
- Expected: results include decrypted=true.
- Actual Result: results show `decrypted: true`.
- PASS/FAIL: PASS
- Evidence: `biozero/docs/evidence/LOG_30_uploader_cli.txt`

## T-7.6 - Signed upload verifies in runner
- Steps: CLI upload with --sign-key and runner has signer cert.
- Expected: signature_valid=true.
- Actual Result: results show `signature_valid: true`.
- PASS/FAIL: PASS
- Evidence: `biozero/docs/evidence/LOG_30_uploader_cli.txt`

## T-7.7 - Results authZ enforcement
- Steps: GET /results/{job_id} with wrong X-Client-Id.
- Expected: HTTP 403.
- Actual Result: Not executed in this run.
- PASS/FAIL: PENDING
- Evidence: N/A

## T-7.8 - ZeroResponder accepts alert
- Steps: POST /alert with X-Webhook-Secret and alert payload.
- Expected: HTTP 200 and actions logged.
- Actual Result: HTTP 200 with action records; actions log populated.
- PASS/FAIL: PASS
- Evidence: `biozero/docs/evidence/IMG_35_zeroresponder_response.txt`, `biozero/docs/evidence/LOG_34_zeroresponder_actions.log`

## T-7.9 - UI homepage loads
- Steps: GET `http://localhost:8080/`
- Expected: HTML payload for UI homepage.
- Actual Result: HTML payload returned.
- PASS/FAIL: PASS
- Evidence: `biozero/docs/evidence/IMG_36_ui_homepage.html`

## T-7.10 - UI health proxy to Upload API
- Steps: GET `http://localhost:8080/api/health/upload`
- Expected: `ok`
- Actual Result: 502 Bad Gateway.
- PASS/FAIL: FAIL
- Evidence: `biozero/docs/evidence/LOG_36_ui_health_upload.txt`

## T-7.11 - Detection signals populated
- Steps: Run uploader CLI and inspect results JSON.
- Expected: `detection` includes `verdict`, `reasons`, and `signals` (alignment, warnings, integrity).
- Actual Result: detection includes verdict + signals in latest run (job_id `b2aacf0dfd25d15a`).
- PASS/FAIL: PASS
- Evidence: `biozero/infra/compose/output5.txt`

## Notes
- Pipeline ran with tools enabled inside the container; `bcftools` reported a call warning
  (see `LOG_30_uploader_cli.txt` warnings field).

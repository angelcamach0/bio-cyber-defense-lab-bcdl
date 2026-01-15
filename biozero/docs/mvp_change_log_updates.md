# MVP Change Log Updates

These entries supplement the PDF change log with the MVP code and security work.

## CHG-010 - MVP Core Services (Upload/Results/Runner/CLI)
- Description: Implemented Go-based upload API, results API, enclave runner, and uploader CLI.
- Risk Level: Medium
- Acceptance Criteria:
  - Upload API accepts files and returns a job ID.
  - Runner produces a result JSON for each job.
  - Results API returns pending/processed status.
- Evidence: (to capture) LOG_30, IMG_30

## CHG-011 - mTLS + Client-Side Crypto
- Description: Added optional mTLS, client-side encryption (AES-GCM + RSA-OAEP), and signing (RSA-PSS).
- Risk Level: Medium
- Acceptance Criteria:
  - mTLS denies clients without a valid cert.
  - Encrypted payloads decrypt in runner.
  - Signed payloads verify successfully in runner.
- Evidence: (to capture) LOG_31, IMG_31, CONF_10

## CHG-012 - PKI Helper + Compose Orchestration
- Description: Added PKI generation script and Docker Compose stack for MVP services.
- Risk Level: Low
- Acceptance Criteria:
  - PKI script generates CA/server/client/signer certs.
  - Compose stack launches all services with shared data volume.
- Evidence: (to capture) LOG_32, IMG_32

## CHG-013 - Pipeline Stub + AuthZ/Validation
- Description: Added pipeline stub, request validation, rate limiting, and results authorization checks.
- Risk Level: Medium
- Acceptance Criteria:
  - Pipeline emits JSON stats per payload.
  - Upload rejects missing client_id and hash mismatches.
  - Results require matching client identity.
- Evidence: (to capture) LOG_33, IMG_33

## CHG-014 - ZeroResponder MVP
- Description: Added webhook responder to log actions and produce blocklist/revocation/quarantine files.
- Risk Level: Low
- Acceptance Criteria:
  - /alert accepts payloads with shared secret.
  - Action records are written to actions.log.
- Evidence: (to capture) LOG_34, IMG_35

## CHG-015 - UI Proxy + PKI SAN Alignment
- Description: Updated Nginx proxy SSL name handling and PKI SANs for service hostnames to support mTLS proxy health checks.
- Risk Level: Low
- Acceptance Criteria:
  - UI proxy can reach Upload/Results APIs over TLS using service DNS names.
  - Health endpoints return OK via `/api/health/*` once certs are regenerated.
- Evidence: LOG_36, run_output.txt (post-regeneration)

## CHG-016 - Detection Engine Logic Upgrade
- Description: Expanded detection logic to include pipeline signals, warning severity, crypto integrity, and threat-panel alignment scoring.
- Risk Level: Medium
- Acceptance Criteria:
  - Results include detection verdict + signals (alignment, fastp q30, warning summary).
  - Detection score increases on threat-panel hits, signature failures, or critical warnings.
- Evidence: output5.txt (detection verdict + signals), LOG_30_uploader_cli.txt (baseline)

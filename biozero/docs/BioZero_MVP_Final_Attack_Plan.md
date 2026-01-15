# BioZero MVP Final Attack Plan

This plan consolidates the blueprint and the consolidated attack plan into one execution-ready
document. It is scoped for the Proxmox Ubuntu VM, Docker Compose deployment, and the current
BioZero repo structure.

## Scope & Environment
- Local MVP running in Docker Compose inside a Proxmox Ubuntu VM.
- Services: Go APIs + runner + simulator, Python pipeline, static HTML/JS UI.
- Zero-trust baseline already implemented (mTLS, client identity).

## Priority Order
1) Datastore + job queue  
2) Detection engine logic  
3) SIEM/SOC stub + automated response  
4) UI upgrades  
5) Simulated adversary (valid FASTQ)  
6) Pipeline warnings schema  
7) AuthZ negative test (403)

## Locked Decisions
### Identity & AuthZ
- **Rule:** mTLS cert serial wins; headers ignored if cert present.
- If no client cert, fall back to `X-Client-Id`.
- All reads require tenant match (`jobs.client_id`), and if `jobs.client_cert_serial` exists it must
  match the caller cert.

### Reference Inputs Dual-Mode
- **Mode A (default):** FASTQ only; use bundled reference inputs (`reference.fa` + `rules.json`).
- **Mode B (override):** client may supply optional job-scoped reference inputs (reference and/or rules).
- Detection logic must not fork; only the per-job input selection changes.
- Input selection must be deterministic per job and recorded in metadata (mode + identifiers + hashes/versions).
- Overrides are immutable once processing starts, size-bounded, and audited.

### Job IDs
- Keep existing **hex string** IDs; DB uses `TEXT`.

### Retention
- **Soft delete only** (add `deleted_at`), no hard deletes in MVP.

### SIEM Stub
- Default: JSONL events at `/data/events/events.jsonl`.

### Queue Failure Strategy
- Redis + Asynq preferred, max retry 5, exponential backoff, final state `quarantined`.
- Fallback: Postgres-only queue with `UPDATE ... WHERE status='queued'`.

## Phase 1 — Datastore + Job Queue
### Compose changes
Add to `biozero/infra/compose/docker-compose.yml`:
- `postgres` + `redis` services
- `DATABASE_URL`, `REDIS_ADDR` env vars for upload/results/runner
- Keep `/data` volume and add `/data/events` for telemetry

### Schema (Postgres)
Create migrations under `biozero/infra/db/migrations/`:
- `client_credentials` (bind cert serial to client_id)
- `jobs` (status, retention, retry_count, input_mode, reference_id, reference_hash, reference_version, rules_id, rules_hash, rules_version)
  - `input_mode` enum: `default` | `override` (default `default`)
  - reference/rules identifiers are simple `TEXT` columns; hashes are `sha256:<hex>` strings
- `results` (JSONB outputs, warnings, detection)
- `audit_events` (append-only)

### Upload API
File: `biozero/services/upload-api/main.go`
- Replace JSON writes with DB insert.
- Store upload to `/data/uploads/<job_id>_<sanitized>`.
- If override inputs are provided, persist references + hashes/versions in job columns and write to a job-scoped workspace directory.
- Enforce immutable override inputs once processing begins; reject changes after status transitions from `queued`.
- Enforce size bounds on reference/rules uploads.
- Enqueue job via Redis.
- Emit audit events: `UPLOAD_ACCEPTED`, `JOB_ENQUEUED`, `REFERENCE_OVERRIDE_ACCEPTED`.

### Enclave Runner
File: `biozero/services/enclave-runner/main.go`
- Replace directory scan with queue consumer.
- Atomic claim guard on `jobs.status`.
- Resolve effective inputs per job (default vs override) before running pipeline/scoring; do not fork detection logic.
- Write `results` row, update job status, emit `JOB_STARTED`, `JOB_COMPLETED`, `JOB_FAILED`.
- Quarantine on final failure.

### Results API
File: `biozero/services/results-api/main.go`
- Replace filesystem reads with DB queries.
- Add endpoints:
  - `GET /jobs?limit=25`
  - `GET /results/{job_id}`
  - `GET /results/{job_id}/download?type=json|vcf|fastp_html`
- Include effective reference/rules metadata in results responses for UI display (mode + identifiers + hashes/versions).
- Emit audit events: `RESULT_VIEWED`, `RESULT_DOWNLOADED`, `AUTHZ_DENY`.

## Phase 2 — Detection Engine Logic
File: `biozero/services/enclave-runner/main.go`
- Replace heuristic scoring with hybrid signals:
  - Threat-panel alignment (minimap2 against small FASTA)
  - FASTQ quality signals (fastp)
  - Variant count anomalies
  - Pipeline warnings severity
  - Crypto/integrity failures
- Output JSON schema in `results.detection_json`.

## Phase 3 — SIEM/SOC Stub + Response
Files: `biozero/services/enclave-runner/main.go`, `biozero/services/zeroresponder/main.go`
- Emit JSONL telemetry to `/data/events/events.jsonl`.
- Add `EventSink` abstraction for File/Syslog later.
- If verdict high, call ZeroResponder and log `ALERT_SENT`.

## Phase 4 — UI Upgrades
Files: `biozero/ui/index.html`, `biozero/ui/app.js`
- Add job history panel.
- Format results (status, detection verdict, integrity, pipeline stats).
- Warnings panel (grouped by severity).
- Download/export buttons for JSON/VCF/fastp HTML.
- Add optional "Advanced" inputs for reference/rules override.
- Display mode (Default/Override) + reference/rules identifiers on results and history views for reproducibility.

## Phase 5 — Simulated Adversary
File: `biozero/simulated-adversary/main.go`
- Generate **valid FASTQ** (4 lines/read, quality length equals sequence length).
- Modes: benign (random GC balance), threat (motif injection).

## Phase 6 — Pipeline Warnings Schema
File: `biozero/bio/pipeline/pipeline.py`
- Convert raw warning strings into structured items:
  - `severity`: critical/warn/info
  - `tool`, `category`, `message`, `raw`
- Add summary counts to results.

## Phase 7 — AuthZ Negative Test (403)
File: `biozero/docs/mvp_test_plan_updates.md`
- Upload as client A.
- Fetch as client B → expect 403.
- Verify `AUTHZ_DENY` audit event.

## Acceptance Criteria (High-Level)
- DB + queue replace JSON file polling.
- End-to-end processing with auditable state transitions.
- Detection output enriched and structured.
- UI reflects detection + warnings + download capability.
- SOC stub emits telemetry and triggers response on high risk.

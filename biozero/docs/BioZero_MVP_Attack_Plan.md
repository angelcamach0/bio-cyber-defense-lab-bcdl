# BioZero MVP — Consolidated Attack Plan (.md)

This document consolidates **all decisions, gap closures, data models, and implementation sequencing**
for the BioZero MVP. It is written to be **terminal-first**, **Codex-friendly**, and aligned with your
existing repository, security behavior, and sustainment mindset.

---

## 0. Scope & Assumptions

- Local MVP running in **Docker Compose** inside an **Ubuntu VM (Proxmox)**  
- Services:
  - Go: `upload-api`, `results-api`, `enclave-runner`, `simulated-adversary`
  - Python: bioinformatics pipeline
  - Static HTML/JS UI
- Zero-trust baseline already exists (mTLS, cert parsing, client identity)
- Goal: replace file-based stubs with **realistic, auditable, production-shaped logic**

Priority order implemented here:

1. Datastore + job queue  
2. Detection engine logic  
3. SIEM/SOC stub + response  
4. UI upgrades  
5. Simulated adversary (valid FASTQ)  
6. Pipeline warnings schema  
7. AuthZ negative test (403)

---

## 1. Locked Design Decisions (No Ambiguity)

### 1.1 Tenant Identity & AuthZ Rule (mTLS + client_id)

**Rule:**  
**mTLS certificate serial wins.**  
If a verified client certificate is present, identity is derived from it and **headers are ignored**.  
If no peer certificate exists (dev mode), fall back to `X-Client-Id`.

**Why:**  
X.509 client certificates are the strongest identity signal and should override all headers.

**Implementation contract (all APIs):**
- If `r.TLS.PeerCertificates` exists:
  - `cert_serial := r.TLS.PeerCertificates[0].SerialNumber.String()`
  - `client_id := SELECT client_id FROM client_credentials WHERE cert_serial=$1 AND disabled_at IS NULL`
  - If not found → **403**
- Else:
  - `client_id := r.Header.Get("X-Client-Id")`
  - If empty → **401 / 403**

**AuthZ for reads:**  
`jobs.client_id` **must equal** derived `client_id`.  
If `jobs.client_cert_serial` is set, it **must match** the caller’s cert serial.

---

### 1.2 Job ID Type

**Decision:** keep existing **hex string job IDs**.

- DB column type: `TEXT`
- No refactor risk
- Optional later upgrade to ULID (sortable) without schema change

---

### 1.3 Deletion & Retention

**Decision:** soft delete only.

- Add `deleted_at TIMESTAMPTZ NULL`
- UI hides deleted jobs
- No hard deletes in MVP (audit trail preserved)

---

### 1.4 SIEM Stub Output

**Default:** JSONL events written to shared volume  
`/data/events/events.jsonl`

Optional later:
- Syslog sink
- Fluent Bit / Filebeat
- Wazuh / OpenSearch

---

### 1.5 Queue Failure Strategy

**Preferred:** Redis + Asynq

- `MaxRetry = 5`
- Exponential backoff
- Final failure → `quarantined`

Fallback:
- Postgres-only queue using atomic `UPDATE ... WHERE status='queued'`

---

## 2. Core Data Model (Postgres)

### 2.1 client_credentials (Tenant Binding)

```sql
CREATE TABLE client_credentials (
  client_id     TEXT PRIMARY KEY,
  cert_serial   TEXT UNIQUE,
  cert_subject  TEXT,
  cert_issuer   TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  disabled_at   TIMESTAMPTZ NULL
);
```

---

### 2.2 jobs

```sql
CREATE TABLE jobs (
  job_id              TEXT PRIMARY KEY,
  client_id           TEXT NOT NULL,
  client_cert_serial  TEXT NULL,

  status              TEXT NOT NULL,
  uploaded_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at        TIMESTAMPTZ NULL,

  original_name       TEXT NOT NULL,
  size_bytes          BIGINT,
  sha256              TEXT,

  retry_count         INT NOT NULL DEFAULT 0,
  last_error          TEXT,

  deleted_at          TIMESTAMPTZ NULL
);

CREATE INDEX jobs_client_uploaded_idx ON jobs(client_id, uploaded_at DESC);
CREATE INDEX jobs_status_idx ON jobs(status);
```

---

### 2.3 results

```sql
CREATE TABLE results (
  job_id           TEXT PRIMARY KEY REFERENCES jobs(job_id),

  status           TEXT NOT NULL,
  pipeline_output  JSONB,
  pipeline_error   TEXT,

  detection_json   JSONB NOT NULL,
  warnings_json    JSONB NOT NULL,

  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

### 2.4 audit_events (Append-only)

```sql
CREATE TABLE audit_events (
  event_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
  event_type   TEXT NOT NULL,
  service      TEXT NOT NULL,
  job_id       TEXT NULL,
  client_id    TEXT NULL,
  cert_serial  TEXT NULL,
  details      JSONB
);
```

---

## 3. Datastore + Job Queue (Phase 1)

### 3.1 Docker Compose

Add services:
- `postgres`
- `redis`
- `migrator` (one-shot)

Shared volumes:
- `/data`
- `/data/events`

Env vars:
- `DATABASE_URL`
- `REDIS_ADDR`
- `BIOZERO_DATA_DIR=/data`

---

### 3.2 Upload API (`upload-api/main.go`)

Replace JSON file writes with:

1. Derive tenant identity (mTLS first)
2. Insert `jobs` row (`status='queued'`)
3. Store upload at:
   - `/data/uploads/<job_id>_<sanitized>`
4. Enqueue job (`process_job(job_id)`)
5. Emit audit events:
   - `UPLOAD_ACCEPTED`
   - `JOB_ENQUEUED`

Return:
```json
{ "job_id": "...", "status": "queued" }
```

---

### 3.3 Enclave Runner (`enclave-runner/main.go`)

Replace directory polling with queue consumer.

**Atomic claim guard:**
```sql
UPDATE jobs
SET status='running'
WHERE job_id=$1 AND status='queued';
```

If rows affected == 0 → skip (already claimed).

On success:
- write results row
- update job to `processed`

On final failure:
- status → `quarantined`
- increment retry_count
- emit `JOB_QUARANTINED`

---

### 3.4 Results API (`results-api/main.go`)

Replace filesystem reads with DB queries.

Endpoints:
- `GET /jobs?limit=25`
- `GET /results/{job_id}`
- `GET /results/{job_id}/download?type=json|vcf|html`

Enforce:
- mTLS serial → client_id mapping
- client_id match on all reads

Emit audit events:
- `JOB_LIST_VIEWED`
- `RESULT_VIEWED`
- `RESULT_DOWNLOADED`
- `AUTHZ_DENY`

---

## 4. Detection Engine Logic (Phase 2)

Replace heuristic stub with **hybrid scoring**:

Signals:
- Threat-panel alignment (minimap2 vs small FASTA)
- FASTQ quality anomalies
- Variant count anomalies
- Pipeline warnings (see §6)
- Crypto/integrity failures

Detection output schema:
```json
{
  "score": 0.92,
  "verdict": "high",
  "reasons": ["threat_panel_hit"],
  "signals": {
    "alignment": { "threat_reads": 412, "total_reads": 2000 },
    "warnings": { "critical": 0, "warn": 2 }
  }
}
```

High score triggers SOC workflow.

---

## 5. SIEM / SOC Stub (Phase 3)

### 5.1 Event Schema

```json
{
  "ts": "2026-01-13T12:00:00Z",
  "service": "enclave-runner",
  "event_type": "DETECTION_HIGH",
  "severity": "high",
  "job_id": "...",
  "client_id": "...",
  "details": { "score": 0.92 }
}
```

### 5.2 Sinks
- JSONL file (default)
- Syslog (optional env toggle)

### 5.3 Automated Response
If `verdict == high`:
- emit event
- call ZeroResponder
- audit `ALERT_SENT`

---

## 6. UI Upgrades (Phase 4)

UI panels:
- Job history table
- Result summary
- Detection verdict
- Warnings panel (grouped by severity)
- Artifact downloads

API support already covered in Phase 1.

---

## 7. Simulated Adversary (Phase 5)

Replace random bytes with **valid FASTQ generator**:

- 4-line FASTQ records
- Quality string length == sequence length
- Modes:
  - `benign`: random GC-balanced reads
  - `threat`: motif injection at fixed rate

Optional:
- shell out to `art_illumina` if installed

---

## 8. Pipeline Warnings Schema (Phase 6)

Structured warnings instead of raw strings.

Severity mapping:
- exit code != 0 → `critical`
- `[E::]` or `Error:` → `critical`
- `[W::]` or `Warning:` → `warn`
- else → `info`

Example:
```json
{
  "summary": { "critical": 0, "warn": 2, "info": 1 },
  "items": [
    {
      "tool": "bcftools",
      "severity": "warn",
      "category": "VCF_HEADER",
      "message": "FILTER not defined",
      "raw": "[W::vcf_parse] FILTER not defined"
    }
  ]
}
```

---

## 9. AuthZ Negative Test (Phase 7)

Test script:
1. Upload job as client A
2. Fetch result as client B
3. Expect **403**
4. Verify `AUTHZ_DENY` audit event exists

---

## 10. Terminal-First Build Order

1. Compose Postgres + Redis + migrations  
2. Upload API → DB + queue  
3. Enclave runner → queue consumer + atomic claim  
4. Results API → DB + AuthZ preserved  
5. Job list endpoint + rate limit + audit  
6. Detection engine logic  
7. SIEM stub + responder  
8. UI upgrades  
9. Simulated adversary FASTQ  
10. Warnings schema + 403 tests  

---

## End State

At completion, BioZero is no longer a demo scaffold but a **credible sustainment system**:
- Deterministic identity
- Tenant isolation
- Auditable state transitions
- Real detection signals
- Failure containment
- SOC-ready telemetry

This is exactly the shape a **Junior Sustainment Cyber Security Test Engineer** would be expected to build, test, and defend.

# BioZero MVP — Missing Pieces Blueprint (implementation‑ready + web‑researched)

**Assumptions:** local Docker Compose, Go services, Python pipeline, static HTML/JS UI, running inside an Ubuntu VM on Proxmox.

**Priority order:** **(3) datastore+queue → (1) detection engine → (2) SIEM stub+response → (7) UI upgrades → (5) simulated adversary → (6) pipeline warnings → (4) AuthZ 403 test**.

---

## 3) Persistent datastore + job queue (replace JSON files)

### MVP goals
- Replace `data/jobs/*.json` + `data/results/*.json` polling with:
  - DB as source of truth (jobs/results/audit)
  - queue for dispatch (at‑least‑once)
- Keep uploads/artifacts on disk volume; DB stores metadata + file paths.

### Recommended tools / libs
- **PostgreSQL** (persistence) + **Redis** (queue) in Compose.
- Queue option A (fastest MVP in Go): **Asynq** (Redis‑backed distributed task queue). citeturn0search16turn0search12
- Queue option B (lower‑level): **Redis Streams + consumer groups** (at‑least‑once + recovery). citeturn0search9turn0search17
- Go DB: `pgx/v5` (or `database/sql` + pgx)
- Migrations: `golang-migrate/migrate` or `pressly/goose`

### Compose changes
Edit `biozero/infra/compose/docker-compose.yml`:
- Add services:
  - `postgres` (volume + healthcheck)
  - `redis` (volume + healthcheck)
- Add env vars to `upload-api`, `results-api`, `enclave-runner`:
  - `DATABASE_URL=postgres://biozero:biozero@postgres:5432/biozero?sslmode=disable`
  - `REDIS_ADDR=redis:6379`
  - `BIOZERO_DATA_DIR=/data` (shared volume)

### Minimal Postgres schema
Create migrations in `biozero/infra/db/migrations/0001_init.sql`.

**jobs** (tenant‑scoped)
- `job_id` (PK, UUID/ULID)
- `client_id` (TEXT)
- `status` (TEXT: `queued|running|processed|failed|quarantined`)
- `original_name`, `content_type`, `size_bytes`, `sha256`
- `upload_path` (TEXT)
- crypto metadata: `enc_alg`, `enc_key`, `sig_alg`, `sig`
- mTLS metadata: `client_cert_serial`, `client_cert_subject`, `client_cert_issuer`
- `created_at`, `updated_at`

**results**
- `job_id` (PK/FK)
- `status`, `processed_at`, `processed_sha256`
- `pipeline_json` (JSONB)
- `warnings_json` (JSONB) *(see item 6)*
- `detection_json` (JSONB) *(see item 1)*
- `artifacts_json` (JSONB) *(paths for VCF/fastp html/etc)*
- `error` (TEXT)

**audit_events** (append‑only)
- `event_id` (PK)
- `ts`, `event_type`, `severity`
- `job_id` (nullable)
- `actor_client_id` (nullable), `actor_cert_serial` (nullable)
- `source` (upload-api/results-api/enclave-runner/ui)
- `details` (JSONB)

**Why:** Postgres + concurrency‑safe claims are a common queue-ish pattern; `SKIP LOCKED` is widely used when you want DB‑backed work claiming. citeturn0search14

### Queue design (choose one)

#### Option A — Asynq (recommended MVP)
- Upload API enqueues task type `process_job` with payload `{job_id}`.
- Enclave Runner runs Asynq worker:
  - set job `running`
  - run pipeline + detection
  - write results
  - set job `processed` (or `failed`)
- Asynq gives retries/timeouts/scheduling with minimal code. citeturn0search16turn0search12

#### Option B — Redis Streams (if you want primitives)
- Stream: `biozero:jobs`, group: `enclave-runners`.
- Producer: `XADD biozero:jobs * job_id <id>`
- Worker: `XREADGROUP ... STREAMS biozero:jobs >` then `XACK`.
- Recovery: pending + auto-claim for crashed workers (at‑least‑once). citeturn0search9turn0search17

### Service integration (file paths you listed)

#### `biozero/services/upload-api/main.go`
Replace “write job JSON file” with:
- Save upload to `/data/uploads/<job_id>_<sanitized>`
- `INSERT INTO jobs (...) VALUES (...)`
- enqueue `<job_id>` in Redis (Asynq or Streams)
- `INSERT INTO audit_events` for:
  - `UPLOAD_ACCEPTED`, `JOB_ENQUEUED`

Return:
```json
{"job_id":"...","status":"queued"}
```

#### `biozero/services/enclave-runner/main.go`
Replace directory scan loop with:
- queue consumer loop
- DB status transitions `queued → running → processed|failed`
- write `results` row (JSONB)
- write audit events `JOB_STARTED`, `JOB_COMPLETED`, `JOB_FAILED`

#### `biozero/services/results-api/main.go`
Replace “read results JSON file” with:
- `SELECT ... FROM results JOIN jobs ... WHERE job_id=? AND client_id=?`
- implement AuthZ (item 4)

Add endpoints needed for UI upgrades (item 7):
- `GET /jobs?limit=50&status=processed`
- `GET /results/{job_id}/download?type=json|vcf|fastp_html`

### SQLite fallback (if Postgres/Redis feels heavy today)
- Persist to SQLite file: `/data/biozero.db`.
- Keep same schema (JSONB → TEXT JSON).
- Replace queue with DB polling:
  - `UPDATE jobs SET status='running' WHERE job_id=? AND status='queued'` (check rows=1)
- Later swap to Postgres/Redis without changing UI/API.

### Security notes (zero‑trust, RBAC/ABAC)
- Tenant boundary = `client_id`; every query filters by it.
- Bind identity:
  - Prefer mTLS → store cert serial and require it on reads.
  - Demo fallback: `X-Client-Id` header.
- Audit everything security-relevant (upload, deny, alert trigger).

---

## 1) Real bio‑threat detection engine logic (replace heuristic stub)

**Target:** `biozero/services/enclave-runner/main.go` (replace `scoreDetection`).

### MVP detection strategy (realistic + easy to implement via terminal)
Use a **hybrid scoring** model:
1) **QC signals** (fastp summary if present)
2) **Threat panel alignment** (minimap2 against a small curated FASTA)
3) **Pipeline anomalies** (variant counts + warnings severity)
4) **Crypto/integrity** (signature invalid, decrypt error)

Minimap2 is a standard CLI aligner and already in your wrapper. citeturn2search0turn2search3

### Data model (store in `results.detection_json`)
```json
{
  "score": 0.92,
  "verdict": "high",
  "reasons": ["threat_panel_hit"],
  "signals": {
    "alignment": {"threat_reads": 413, "total_reads": 2000, "targets": [{"id":"THREAT_A", "reads": 390}]},
    "fastp": {"q30_rate": 0.88},
    "variants": {"count": 12},
    "integrity": {"signature_valid": true, "decrypted": false},
    "warnings": {"critical": 0, "warn": 2}
  }
}
```

### Rules (extend `biozero/bio/reference-db/rules.json`)
Add:
- `threat_panel_fasta` (default `biozero/bio/reference-db/threat_panel.fa`)
- `threat_min_reads` (e.g., 50)
- `threat_min_fraction` (e.g., 0.02)
- `fastp_min_q30` (e.g., 0.75)
- `critical_warning_score_boost` (e.g., 0.2)
- `high_threshold` (e.g., 0.8)

### Implementation steps in `enclave-runner/main.go`
- Parse pipeline JSON and extract:
  - `read_count`, `avg_read_length`
  - `fastp_summary` (if present)
  - `outputs.variants_vcf` (if present)
  - structured warnings (after item 6)
- Add function:
  - `evaluateThreat(contentPath, pipelineJSON, rules) -> detection_json`
- Threat panel pass:
  - If `threat_panel.fa` exists: run `minimap2 -a threat_panel.fa <fastq>` and count mapped reads per reference (RNAME != `*`).
- Score:
  - baseline 0.1
  - +0.6 if threat hit thresholds met
  - +0.2 if signature invalid
  - +0.2 if critical warnings
  - clamp 0..1
- Store evidence in DB and emit event (item 2).

### Optional future ideas (not needed for MVP)
- **Kraken2** (k‑mer taxonomic classification) citeturn2search1turn2search15
- **Mash** (MinHash sketches for similarity checks) citeturn2search2

---

## 2) SOC/SIEM integration + automated response (stub now, drop‑in later)

### Constraint
Stub integration locally with a clean interface; plan for future Wazuh/OpenSearch drop‑in.

### Event schema (JSONL)
Emit one line per event:
```json
{"ts":"...","service":"enclave-runner","event_type":"DETECTION_HIGH","severity":"high","job_id":"...","client_id":"...","cert_serial":"...","details":{"score":0.92,"reasons":["threat_panel_hit"]}}
```

### Interface (Go)
Create `biozero/services/shared/telemetry/sink.go`:
- `type EventSink interface { Emit(ctx context.Context, ev Event) error }`
Implement:
- `FileSink` → `/data/events/events.jsonl`
- `SyslogSink` → TCP/UDP syslog
  - Wazuh can collect syslog from endpoints that can’t run an agent. citeturn0search11
- `HTTPSink` → POST to a local collector (optional)

### Future drop‑in plan
- Wazuh ↔ OpenSearch integration exists (later). citeturn0search15turn0search19
- Keep your JSON fields stable so you can map to OpenSearch later.

### Automated response workflow (MVP)
Where: enclave-runner after scoring
- If `score >= high_threshold` OR `signature_valid == false` OR warnings include `critical`:
  1) emit event `DETECTION_HIGH`
  2) call `zeroresponder` `/alert` (already exists)
  3) write `audit_events` row `ALERT_SENT`

### (Optional) OpenTelemetry later
If you want “standard observability plumbing,” align with OTel logs concepts, but don’t deploy a collector now. citeturn1search3turn1search7

---

## 7) UI upgrades (job history, formatted results, warnings, export)

**Targets:** `biozero/ui/app.js` + `biozero/ui/index.html`

### Backend endpoints to add (Results API)
- `GET /jobs?limit=25` → last jobs for this `client_id`
- `GET /results/{job_id}` → current result/status
- `GET /results/{job_id}/download?type=json|vcf|fastp_html` → artifacts

### UI changes (vanilla JS)
- **Job history panel**
  - fetch `/api/jobs` on load
  - render list w/ status badge + score
- **Formatted results view**
  - cards: Status, Detection, Integrity, Pipeline stats
- **Warnings panel**
  - group by severity/category (depends on item 6)
  - filters: critical/warn/info
- **Download/export**
  - buttons: Download JSON, Download VCF (if exists), Copy summary
- **Polling**
  - stop polling once `processed|failed`
  - show last updated timestamp

---

## 5) Simulated adversary → valid FASTQ (replace random bytes)

**Target:** `biozero/simulated-adversary/main.go`

### Requirements
- Produce syntactically valid FASTQ: 4 lines/read, quality length == sequence length. citeturn1search4turn1search16

### MVP implementation (Go‑native generator, always available)
Flags:
- `--out`, `--reads`, `--length`, `--mode benign|threat`, `--motif`, `--seed`

Logic:
- Generate sequences with A/C/G/T (optionally GC target)
- If `mode=threat`, inject motif into a fraction of reads
- Quality string: constant `'I'` (high) or random phred+33 chars

### Optional realism via ART (if installed)
- ART generates synthetic reads and outputs FASTQ, based on real error models. citeturn1search5turn1search17
- In Go: if `art_illumina` exists, shell out; else fallback to native generator.

---

## 6) Pipeline warnings handling (bcftools warnings categorization)

**Target:** `biozero/bio/pipeline/pipeline.py`

### Goal
Replace string warnings with structured objects + summary counts.

Output contract:
```json
{"warnings":[{"source":"bcftools","severity":"warn","category":"VCF_HEADER_TAG","message":"tag not defined","raw":"..."}],
 "warnings_summary":{"critical":0,"warn":2,"info":1}}
```

### Practical steps
- Capture stderr from fastp/minimap2/samtools/bcftools.
- Also capture `mpileup` stderr (currently discarded).
- Split stderr by line; map via regex → category + severity.
- Use bcftools FAQ patterns as anchors for categorization (e.g., header/tag/field mismatches). citeturn1search6

Suggested categories:
- `VCF_HEADER_TAG`, `FORMAT_MISMATCH`, `IO`, `PLOIDY`, `TOOL_MISSING`, `ALIGNMENT_QUALITY`

Severity:
- tool exit != 0 → `critical`
- line contains `[E::` or `Error:` → `critical`
- line contains `[W::` or `Warning:` → `warn`
- else `info`

---

## 4) AuthZ negative test (403) — implement + validate

### Correct behavior
- Only the uploader’s tenant/client can read results.
- Mismatch client identity → **403 Forbidden**.
- Emit `AUTHZ_DENY` audit event.

### Implement (Results API)
For `GET /results/{job_id}` and `/download`:
1) determine caller identity:
   - prefer mTLS cert serial
   - demo fallback: `X-Client-Id`
2) fetch job row
3) compare:
   - `job.client_id == caller_client_id`
   - (optional strong bind) `job.client_cert_serial == caller_cert_serial`
4) if mismatch: return 403 + write audit event

### Validate (terminal)
Upload as A; read as B:
```bash
curl -sk -H "X-Client-Id: researcher-2" https://localhost:8082/results/<JOB_ID> -i
# expect HTTP/1.1 403 Forbidden
```
If using mTLS:
```bash
curl -sk --cert clientB.crt --key clientB.key https://localhost:8082/results/<JOB_ID> -i
# expect 403
```

---

## “Most implementable” choices (given your constraints)
- **DB:** Postgres + `pgx`
- **Queue:** Asynq (fastest to implement) citeturn0search16turn0search12
- **Detection:** minimap2 threat panel + multi-signal scoring citeturn2search0turn2search3
- **SIEM stub:** JSONL file sink + optional syslog sink (future Wazuh/OpenSearch) citeturn0search11turn0search15
- **Adversary:** Go FASTQ generator + optional ART shell‑out citeturn1search4turn1search5
- **Warnings:** structured regex categorization (bcftools FAQ patterns) citeturn1search6
- **AuthZ test:** curl 403 negative test + audit event


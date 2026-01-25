# BioZero: Integrated Bio-Cyber Defense Lab

## Mission
BioZero is a secure, zero-trust, cloud-native platform for genomic data processing, bio-threat detection, and adversary simulation, integrated with a SOC and automated incident response engine.

## Core Subsystems
1. **PKI & Identity Layer**
2. **Zero-Trust Genomic Data Platform**
3. **Bio-Threat Detection Engine (BCTDS)**
4. **Bio-Inspired Adversary Simulation**
5. **ZeroSentinel SOC / SIEM**
6. **ZeroResponder Automated Incident Response**

## High-Level Architecture
- Upload API → Encrypted Storage → Enclave Runner → Results API  
- Threat Engine produces signature & anomaly-based scoring  
- Simulation layer generates evolving adversary behavior  
- Logs flow into SIEM  
- Automated response engine triggers containment actions  

## Roadmap
- Phase 1: MVP (upload → process → result)
- Phase 2: PKI + mTLS + encryption CLI
- Phase 3: Enclave integration
- Phase 4: Threat detection engine
- Phase 5: Bio-inspired adversary simulation
- Phase 6: SOC + automated response
- Phase 7: Documentation + demo

## Status
MVP services, PKI tooling, and pipeline stub are implemented.
Next step: Run the stack end-to-end, capture evidence, and expand SIEM + real pipeline.

## Current Components (MVP)
- Upload API: `biozero/services/upload-api`
- Results API: `biozero/services/results-api`
- Enclave Runner: `biozero/services/enclave-runner`
- Uploader CLI: `biozero/services/uploader-cli`
- Pipeline Wrapper: `biozero/bio/pipeline/pipeline.py`
- Detection Rules: `biozero/bio/reference-db/rules.json`
- Demo Reference: `biozero/bio/reference-db/reference.fa`
- Adversary Simulator: `biozero/simulated-adversary`
- ZeroResponder: `biozero/services/zeroresponder`
- PKI Helper: `biozero/infra/PKI/gen-pki.sh`
- Compose Stack: `biozero/infra/compose/docker-compose.yml`

## How Components Communicate
- Uploader CLI encrypts/signs a file (optional) and uploads it to Upload API.
- Upload API stores the upload, writes a job record, and records client cert metadata.
- Enclave Runner polls job records, verifies signatures, decrypts payloads (if configured),
  runs the pipeline wrapper, applies detection rules, and writes results.
- Results API serves pending/processed status and enforces client identity checks.
- Adversary Simulator triggers uploader-cli to generate benign/suspicious traffic.
- ZeroResponder receives alert webhooks and logs response actions to files.

## Run (Docker Compose)
1) Generate PKI assets:
```bash
cd "biozero/infra/PKI"
chmod +x ./gen-pki.sh
bash ./gen-pki.sh ./pki
```
2) Start services:
```bash
cd "biozero/infra/compose"
sudo docker compose up --build -d
```
3) Open the UI:
```
http://localhost:8080
```
4) Run the MVP test harness:
```bash
cd "biozero/infra/compose"
sudo ./run_mvp_tests.sh
```

## Run (Manual, without Docker)
Open four terminals in these directories:
```bash
cd "biozero/services/upload-api" && BIOZERO_DATA_DIR=./data go run ./main.go
cd "biozero/services/results-api" && BIOZERO_DATA_DIR=./data go run ./main.go
cd "biozero/services/enclave-runner" && BIOZERO_DATA_DIR=./data go run ./main.go
cd "biozero/services/zeroresponder" && BIOZERO_DATA_DIR=./data go run ./main.go
```

## Test (CLI)
Upload with encryption + signing + mTLS:
```bash
cd "biozero/services/uploader-cli"
go run ./main.go --file /path/to/sample.fastq \
  --client-id researcher-1 \
  --mtls-cert ../infra/PKI/pki/client.crt \
  --mtls-key ../infra/PKI/pki/client.key \
  --ca-cert ../infra/PKI/pki/ca.crt \
  --server-cert ../infra/PKI/pki/server.crt \
  --sign-key ../infra/PKI/pki/signer.key
```

Trigger ZeroResponder:
```bash
curl -s -X POST http://localhost:8090/alert \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: ${BIOZERO_WEBHOOK_SECRET:-}" \
  -d '{"alert_id":"ALERT-001","source":"siem","severity":"high","timestamp":"2026-01-12T00:00:00Z","indicators":{"ip":"10.1.2.3","job_id":"abcd1234","cert_serial":"01"},"actions":["block_ip","revoke_cert","quarantine"]}'
```

## Evidence Capture
Use the supplemental logs to track MVP artifacts:
- `biozero/docs/mvp_change_log_updates.md`
- `biozero/docs/mvp_test_plan_updates.md`
- `biozero/docs/mvp_evidence_log_updates.md`

## UI (Website)
See `biozero/ui/README.md` for UI-specific run steps and notes about the Nginx proxy.

## Flow Guide
See `biozero/docs/PROJECT_FLOW_GUIDE.md` for a Mermaid flow chart, pipeline explanation, and real‑world use cases.

## License
This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See `LICENSE` and `NOTICE`.

## Proxmox VM Usage (Pull + Run)
1) Install dependencies (inside the VM):
```bash
sudo apt update
sudo apt install -y git docker.io python3 fastp minimap2 bcftools samtools
```
2) Clone the repo:
```bash
git clone https://github.com/<you>/<repo>.git
cd "Bio-Cyber Defense Lab (BCDL)"
```
3) Generate PKI and run Compose:
```bash
cd biozero/infra/PKI
bash ./gen-pki.sh ./pki
cd ../compose
sudo docker compose up --build -d
```
4) Run uploader CLI test:
```bash
cd ../../services/uploader-cli
go run ./main.go --file /path/to/sample.fastq --client-id researcher-1 \
  --upload-url https://localhost:8081/upload \
  --results-url https://localhost:8082/results \
  --mtls-cert ../../infra/PKI/pki/client.crt \
  --mtls-key ../../infra/PKI/pki/client.key \
  --ca-cert ../../infra/PKI/pki/ca.crt \
  --server-cert ../../infra/PKI/pki/server.crt \
  --sign-key ../../infra/PKI/pki/signer.key
```

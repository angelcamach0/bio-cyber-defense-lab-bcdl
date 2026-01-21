#!/usr/bin/env bash
set -euo pipefail
# MVP test harness: spins up compose stack, uploads a sample, and captures evidence.

BASE_DIR="/home/acamacho/TopDawgProjects/BioZeroRelated/Bio-Cyber Defense Lab (BCDL)/biozero"
COMPOSE_DIR="$BASE_DIR/infra/compose"
EVIDENCE_DIR="$BASE_DIR/docs/evidence"

mkdir -p "$EVIDENCE_DIR"

RUN_LOG="$EVIDENCE_DIR/run_output.txt"
: > "$RUN_LOG"
WEBHOOK_SECRET="${BIOZERO_WEBHOOK_SECRET:-}"

log_step() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$RUN_LOG"
}

log_step "Starting MVP test run"

log_step "Ensuring sample FASTQ exists"
if [[ ! -f "$EVIDENCE_DIR/sample.fastq" ]]; then
  cat > "$EVIDENCE_DIR/sample.fastq" <<'FASTQ'
@read1
ACGTACGTACGT
+
FFFFFFFFFFFF
@read2
ACGTACGTACGTACGT
+
FFFFFFFFFFFFFFFF
@read3
ACGTACGT
+
FFFFFFFF
FASTQ
fi

log_step "Starting compose stack"
cd "$COMPOSE_DIR"
docker compose up --build -d | tee -a "$RUN_LOG"

log_step "Encrypted + signed upload via uploader-cli container"
docker run --rm --network host \
  -v "/home/acamacho/TopDawgProjects/BioZeroRelated/Bio-Cyber Defense Lab (BCDL)":/work \
  -w "/work/biozero/services/uploader-cli" \
  golang:1.22-alpine \
  go run ./main.go \
  --file "/work/biozero/docs/evidence/sample.fastq" \
  --client-id researcher-1 \
  --upload-url https://localhost:8081/upload \
  --results-url https://localhost:8082/results \
  --mtls-cert /work/biozero/infra/PKI/pki/client.crt \
  --mtls-key /work/biozero/infra/PKI/pki/client.key \
  --ca-cert /work/biozero/infra/PKI/pki/ca.crt \
  --server-cert /work/biozero/infra/PKI/pki/server.crt \
  --sign-key /work/biozero/infra/PKI/pki/signer.key \
  | tee "$EVIDENCE_DIR/LOG_30_uploader_cli.txt" | tee -a "$RUN_LOG"

log_step "mTLS negative test (no client cert)"
set +e
curl -vk https://localhost:8081/health 2>&1 | tee "$EVIDENCE_DIR/LOG_31_tls_fail.txt" | tee -a "$RUN_LOG"
set -e

log_step "ZeroResponder alert test"
if [[ -n "$WEBHOOK_SECRET" ]]; then
  curl -s -X POST http://localhost:8090/alert \
    -H "Content-Type: application/json" \
    -H "X-Webhook-Secret: ${WEBHOOK_SECRET}" \
    -d '{"alert_id":"ALERT-001","source":"siem","severity":"high","timestamp":"2026-01-13T00:00:00Z","indicators":{"ip":"10.1.2.3","job_id":"abcd1234","cert_serial":"01"},"actions":["block_ip","revoke_cert","quarantine"]}' \
    | tee "$EVIDENCE_DIR/IMG_35_zeroresponder_response.txt" | tee -a "$RUN_LOG"
else
  curl -s -X POST http://localhost:8090/alert \
    -H "Content-Type: application/json" \
    -d '{"alert_id":"ALERT-001","source":"siem","severity":"high","timestamp":"2026-01-13T00:00:00Z","indicators":{"ip":"10.1.2.3","job_id":"abcd1234","cert_serial":"01"},"actions":["block_ip","revoke_cert","quarantine"]}' \
    | tee "$EVIDENCE_DIR/IMG_35_zeroresponder_response.txt" | tee -a "$RUN_LOG"
fi

log_step "UI smoke test (fetch homepage)"
curl -s http://localhost:8080/ | tee "$EVIDENCE_DIR/IMG_36_ui_homepage.html" | tee -a "$RUN_LOG"

log_step "UI health proxy check"
curl -s http://localhost:8080/api/health/upload | tee "$EVIDENCE_DIR/LOG_36_ui_health_upload.txt" | tee -a "$RUN_LOG"

log_step "Collecting enclave-runner logs"
set +e
docker compose logs enclave-runner --tail 50 | tee "$EVIDENCE_DIR/LOG_30_runner.log" | tee -a "$RUN_LOG"
set -e

log_step "Collecting zeroresponder actions log"
set +e
docker compose exec -T zeroresponder sh -c "cat /data/actions/actions.log" | tee "$EVIDENCE_DIR/LOG_34_zeroresponder_actions.log" | tee -a "$RUN_LOG"
set -e

log_step "Test run complete"

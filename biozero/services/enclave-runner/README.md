# enclave-runner (MVP)

Polls job records, verifies optional signatures, decrypts encrypted payloads, applies a simple
rule set, and writes results.

## Config
- `BIOZERO_DATA_DIR` (default `./data`)
- `BIOZERO_RULES_PATH` (default `../../bio/reference-db/rules.json`)
- `BIOZERO_POLL_SECONDS` (default `2`)
- `BIOZERO_PRIVATE_KEY` (RSA private key for decrypting payloads)
- `BIOZERO_SIGNER_CERT` (client cert for verifying payload signatures)
- `BIOZERO_DECRYPT_DIR` (default `./data/decrypted`)
- `BIOZERO_PIPELINE_PATH` (default `../../bio/pipeline/pipeline.py`)
- `BIOZERO_REFERENCE_PATH` (optional reference genome for alignment/variant steps)
- `BIOZERO_PIPELINE_TIMEOUT` (default `10m`)
- `BIOZERO_JOB_KEY` (optional 32-byte key, base64 or hex, to unwrap `enc_key`)

## Output
- Results include `upload_sha256`, `processed_sha256`, `pipeline_output`, `decrypted`, and signature status fields.

## Run
```bash
go run ./main.go
```

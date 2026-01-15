# PKI helpers

This folder contains local PKI helpers to generate a CA, server cert, client cert, and signer cert for the MVP.

## Generate certificates
```bash
chmod +x ./gen-pki.sh
bash ./gen-pki.sh ./pki
```

Note: If service hostnames change, re-run `gen-pki.sh` so the server cert SAN list stays in sync.

Outputs (under `./pki`):
- `ca.crt`, `ca.key`
- `server.crt`, `server.key`
- `client.crt`, `client.key`
- `signer.crt`, `signer.key`

## Use with services
Upload API and Results API:
- `BIOZERO_TLS_CERT=./pki/server.crt`
- `BIOZERO_TLS_KEY=./pki/server.key`
- `BIOZERO_TLS_CA=./pki/ca.crt`

Uploader CLI:
- `--mtls-cert ./pki/client.crt --mtls-key ./pki/client.key --ca-cert ./pki/ca.crt`
- `--server-cert ./pki/server.crt --sign-key ./pki/signer.key`

Enclave runner:
- `BIOZERO_PRIVATE_KEY=./pki/server.key`
- `BIOZERO_SIGNER_CERT=./pki/signer.crt`

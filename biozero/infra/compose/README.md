# Compose (MVP)

Runs upload-api, results-api, and enclave-runner with shared data volume and PKI mounts.

## Prereqs
Generate certs first:
```bash
cd "../PKI"
chmod +x ./gen-pki.sh
bash ./gen-pki.sh ./pki
```

## Run
```bash
docker compose up --build
```

## Notes
- APIs listen on 8081 and 8082 with mTLS enabled.
- Update PKI paths if you store certs elsewhere.
- Rebuild the stack after regenerating PKI assets so Nginx picks up new certs.
- Containers run as root to avoid volume permission issues with the named data volume.

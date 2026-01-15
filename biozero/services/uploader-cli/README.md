# uploader-cli (MVP)

Uploads a file to the upload API and polls the results API until processing completes.

## Run
```bash
go run ./main.go --file /path/to/sample.fastq --client-id researcher-1
```

## Security options
- `--mtls-cert` / `--mtls-key`: client cert/key for mTLS
- `--ca-cert`: CA bundle to validate server certs
- `--server-cert`: encrypt payload using the server's public cert (RSA)
- `--sign-key`: sign payload using a client private key (RSA)

## Flags
- `--upload-url` (default `http://localhost:8081/upload`)
- `--results-url` (default `http://localhost:8082/results`)
- `--client-id` (optional)
- `--poll-seconds` (default `2`)

# BioZero UI (local demo)

## Run with Compose
Start the full stack, then open:
- http://localhost:8080

The UI proxies through Nginx to the APIs and handles mTLS on your behalf.

## Notes
- If PKI certs are regenerated, rebuild the UI container so Nginx reloads the updated certs.
- Health checks are available via `/api/health/*` through the UI proxy.

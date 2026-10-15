# BioZero UI

## Owner-v1 review UI

[`owner-v1/`](owner-v1/index.html) contains the three same-origin assets served
from pinned snapshots by the [owner Gateway](../services/reviewer-gateway/README.md).
Use its explicit protocol/configuration and HTTPS origin; browser requests go to
the Gateway rather than a shared proxy identity or backend API. The legacy demo
below is a separate interface.

Sign in, choose a prepared synthetic experiment and execute once. The UI creates
a request nonce per explicit click, polls its operation, then queries only the
persisted signed job. Lost POST responses are recovered through history without
automatic submission retry. Pending/`needs_operator` preserve history; logout
does not cancel authorized durable work.

Session/poll generations after asynchronous boundaries prevent an older
response from populating a newer session. Server epoch/Store guards protect the
actual output as well. Cookies are Secure/HttpOnly/SameSiteStrict; access codes
are cleared after sign-in and no credentials/bundles are stored in localStorage.
Separate simultaneous reviewers require separate browser profiles; automatic
identity synchronization across every open tab is not implemented.

The typed report distinguishes execution from scientific release. TP/FP/FN are
shown only when present, with actual precision/recall; null displays **Sin
evaluar**, not zero. Variants approval applies only to synthetic normalized
allele presence. Successful stats displays **Sin evaluación científica**, FASTQ
statistics scope and no fabricated evaluation/count cards. Neither establishes
clinical accuracy. Raw captures, local paths, target lists, vectors and key
bundles are excluded.

[Real Firefox evidence](../docs/evidence/20261015-owner-gateway/public/README.md)
compares the complete real UI response with the original renderer argument and
visible metrics/status/scope, checks 390px layout and releases a delayed real
HTTPS response after changing reviewer. It uses private NSS trust without TLS
bypass or fabricated responses. Profiles/screenshots stay private. See the
[runbook](../docs/runbooks/reproduce.md) and
[security contract](../docs/security/ownership-gateway-contract.md) for reproduction,
configured limits, explicit signed-inbox fixture provisioning and remaining gates.

## Legacy local demo

### Run with Compose
Start the full stack, then open:
- http://localhost:8080

The UI proxies through Nginx to the APIs and handles mTLS on your behalf.

### Notes
- If PKI certs are regenerated, rebuild the UI container so Nginx reloads the updated certs.
- Health checks are available via `/api/health/*` through the UI proxy.

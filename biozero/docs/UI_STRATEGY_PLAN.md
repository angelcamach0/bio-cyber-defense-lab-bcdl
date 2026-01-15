# BioZero UI Strategy Plan

## Goal
Create a simple, local-hosted HTML UI that demonstrates the BioZero MVP flow: upload → process → results → alert response. The UI must be interactive, safe for demo use, and easy to run locally.

## Backbone Alignment
- **Zero-trust principles**: UI never bypasses identity checks; Nginx proxy enforces TLS/mTLS and forwards client identity.
- **Phase mapping**:
  - Phase 1: Upload → process → result UI flow (MVP validation)
  - Phase 2: PKI + mTLS via proxy and cert-bound requests
  - Phase 3: Enclave runner pipeline outputs visualized in UI
  - Phase 4: Detection score + warnings shown in UI
  - Phase 6: ZeroResponder alert trigger + action feedback

## Scope (Phase 1 UI)
- Upload a FASTQ file and show job ID
- Poll results and render pipeline output, detection score, and crypto status
- Trigger a ZeroResponder alert and display action logs
- Display service health indicators
- Provide a proxy-only UI (no direct browser mTLS)

## Key Endpoints (Current)
- Upload API: `POST /upload` on `https://localhost:8081/upload`
- Results API: `GET /results/{job_id}` on `https://localhost:8082/results/{job_id}`
- ZeroResponder: `POST /alert` on `http://localhost:8090/alert`
- Health checks:
  - Upload API: `GET /health`
  - Results API: `GET /health`
  - ZeroResponder: `GET /health`

## UI Interaction Flow
1) User selects FASTQ file and clicks Upload
2) UI sends multipart form to Upload API (include `client_id` field)
3) UI receives job ID and starts polling Results API
4) UI renders JSON (pipeline output, detection, crypto status)
5) UI optionally triggers ZeroResponder alert and shows response
6) UI health panel reflects proxy connectivity

## Security & Hosting Strategy
### Local Hosting (Demo)
- **Option A (simple)**: Static files served by `python3 -m http.server` (no mTLS)
- **Option B (secure)**: Nginx reverse proxy (TLS termination, optional mTLS)

### Recommended Demo Stack
- **Nginx** as front door
  - TLS termination with local certs
  - Rate limiting
  - Reverse proxy to Upload/Results/ZeroResponder
  - Optional mTLS for advanced demo
- **Docker Compose** to run APIs and Nginx together

## Proposed Nginx Setup
- `https://localhost` serves UI
- `/api/upload` → Upload API
- `/api/results/{job_id}` → Results API
- `/api/alert` → ZeroResponder
 - `/api/health/*` → Service health endpoints

### Nginx Features
- TLS 1.2+ only
- Strict ciphers
- Basic rate limiting
- Optional client certificate auth
 - mTLS upstream to Upload/Results APIs

## UI Architecture
- Single static HTML + JS file
- No framework required (vanilla JS)
- Use fetch API + polling loop
- Render JSON in readable sections
- Compute and send `X-Content-SHA256` header via Web Crypto
- Nginx reverse proxy handles TLS + mTLS to backend APIs

## Data to Display
- Job ID + status
- Decryption status + signature validity
- Pipeline stats
- Detection score + reason
- fastp summary (if present)
- minimap2 alignment summary (if present)
- Warnings array (e.g., bcftools call warnings)
- Health checks and API availability

## Future Enhancements
- Add results download button
- Simple charts for read count / GC content
- Integrate SIEM (display alerts + response history)

## Implementation Plan
1) Create `ui/` directory with `index.html`, `app.js`, `styles.css`
2) Add a lightweight local server (optional Python or Nginx)
3) Wire frontend to `/api/*` endpoints (proxy handles CORS)
4) Add a Compose profile for UI + Nginx
5) Document how to run and test UI
6) Add UI smoke tests to `run_mvp_tests.sh`

## Required Headers / Inputs
- Upload API requires `client_id` (form field or `X-Client-Id` header)
- Upload API validates `X-Content-SHA256` when present
- Results API auth uses `X-Client-Id` when mTLS is not used
- ZeroResponder can require `X-Webhook-Secret`

## UI File Locations (Implemented)
- UI HTML: `biozero/ui/index.html`
- UI JS: `biozero/ui/app.js`
- UI CSS: `biozero/ui/styles.css`
- Nginx proxy config: `biozero/ui/nginx.conf`
- UI container: `biozero/ui/Dockerfile`

## Testing Plan
- Upload test FASTQ via UI
- Confirm job ID and results update
- Trigger ZeroResponder alert
- Validate error handling (no cert, wrong job ID)
- Confirm UI proxy health endpoints return OK

## Risks / Considerations
- Browsers do not handle mTLS well for local demo; use proxy or dev mode
- CORS must be handled by proxy or server
- Keep PKI keys out of any public hosting
 - UI proxy health endpoints can return 502 if upstream TLS/mTLS is misconfigured

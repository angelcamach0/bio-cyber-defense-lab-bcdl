# Reviewer gateway

A Go standard-library browser entry for **real executions of prepared synthetic experiments**. Reviewers sign in, select an allowlisted experiment, submit its encrypted/signed input, and inspect their own job and scientific report. This service does not implement arbitrary uploads, command execution, alert response, production identity federation or clinical validation.

## Run and configure

The server requires `BIOZERO_REVIEWER_CONFIG` pointing to a private JSON file. Run as a non-root user. Provide a private `0700` registry directory; its atomic run registry is written as `0600`. UI assets may be served directly from the configured `ui_dir`, or by a same-origin front end which routes **only to this gateway**. Browser traffic must not bypass it to the backend APIs.

```json
{
  "listen_address": ":8083",
  "public_origin": "https://localhost:8083",
  "tls_cert": "/pki/server.crt",
  "tls_key": "/pki/server.key",
  "allow_insecure_loopback": false,
  "upload_url": "https://upload-api:8081/upload",
  "results_url": "https://results-api:8082/results",
  "ca_cert": "/pki/ca.crt",
  "encryption_cert": "/pki/decrypt.crt",
  "signing_key": "/pki/signer.key",
  "run_registry_path": "/state/runs.json",
  "ui_dir": "/ui",
  "reviewers": [
    {
      "id": "reviewer-a",
      "principal": "researcher-a",
      "cert": "/pki/researcher-a.crt",
      "key": "/pki/researcher-a.key",
      "access_code_sha256": "REPLACE_WITH_HASH_FROM_ADMIN_PROVISIONING",
      "enabled": true
    }
  ],
  "experiments": [
    {
      "id": "variant-smoke",
      "label": "Three known synthetic SNPs",
      "file": "/fixtures/reads.fastq",
      "reference": "/fixtures/reference.fa",
      "scope": "synthetic"
    }
  ]
}
```

The placeholder deliberately cannot authenticate. Use the repository's `infra/compose/prepare-reviewers.py` for private provisioning. Each access code is 32 random bytes encoded as unpadded URL-safe base64; the configuration stores **SHA-256 of the encoded string**. These are high-entropy administrative access codes, not human passwords. Do not publish invitations or include them in run evidence. Code hashes, private certificates and configuration are mounted only in the gateway; CA/decryption private keys are not needed there.

Enabled and disabled account configuration is read at startup. Change it and restart to apply revocation/rotation; all in-memory sessions expire on restart. Keep disabled identities in configuration while their runs remain in the registry. Account deletion, certificate expiry and certificate rotation need a deliberate migration of historical ownership: Results API continues to enforce the original certificate serial.

Prepared files and references must be regular, non-symlink files of at most 10 MiB each. Their contents/hashes are frozen at gateway startup. The gateway submits only the input file; the worker's independently configured reference and evaluator must match the prepared protocol. An approval requires the processed-input and evaluated-reference hashes to match the hashes stored in that run's durable registry.

Normal operation is HTTPS. Local HTTP test mode requires `allow_insecure_loopback: true`, a literal loopback listen IP, and an exactly matching HTTP `public_origin`. It uses a distinct `bz_local_session` cookie and must not be described as remote-access protection. The TLS configuration uses `__Host-bz_session` with Secure, HttpOnly, SameSite=Strict, Path=/ and no Domain.

## API

| Endpoint | Authentication and behavior |
| --- | --- |
| `POST /api/sign-in` | JSON `{id, access_code}`; exact Origin/Host, 4 KiB limit, rate limit; creates a new random session and revokes any previous session of that reviewer |
| `GET /api/session` | Session required; returns `{reviewer, csrf_token}` |
| `GET /api/experiments` | Session required; safe catalog with IDs, labels, scope and hashes, never local paths |
| `POST /api/experiments/{id}/runs` | Session, exact Origin, `X-CSRF-Token`, JSON `{}` and quotas required; returns 202 `{job_id, experiment_id}` |
| `GET /api/runs` | Only the authenticated reviewer's durable run records |
| `GET /api/results/{job_id}` | Gateway ownership first, then Results API ownership using that reviewer's fixed mTLS transport; safe typed report DTO |
| `POST /api/sign-out` | Session, Origin and CSRF required; revokes session and expires cookie |
| `GET /health` | Gateway liveness only; scientific readiness explicitly unverified |

No caller-supplied filename, client ID, principal, reference, URL, command or scope is accepted. Unknown JSON fields are rejected for sign-in/run requests. There is no CORS opt-in. Every non-GET request requires the configured exact Origin; `null` and missing Origin fail. Session cookies are opaque, server-side records store only their hashes, idle expiry is 30 minutes and absolute expiry is 8 hours. CSRF tokens are separate random values associated with each session. Login requires JSON, so foreign browser forms/preflight do not create sessions.

Login is limited to 10 attempts per peer IP/minute; run submission to 5 per reviewer/minute; result polling to 120 per reviewer/minute. Only one active run per reviewer and two globally are admitted, with 20 total runs per reviewer in the retained fixture registry. A completed run frees its active slot when its result is retrieved. These quotas are intentionally small for one synthetic worker. They are not a distributed scheduler or durable rolling-rate policy.

Nginx must preserve the configured browser Host including its port (`proxy_set_header Host $http_host`). Do not infer trusted origin from forwarded headers. The gateway uses a separate immutable HTTP client/transport per principal, retains TLS verification, and denies redirects. It never installs a shared browser proxy certificate as a job owner.

## Durable ownership and failure handling

The registry records reviewer ID, backend principal, job ID, experiment ID, creation, completion, input hash and reference hash. Updates use a private temporary file, file sync, rename and parent-directory sync. Session tokens/CSRF/access codes are never persisted there.

If upload succeeds but registry persistence fails, the browser receives 503, the provisional in-memory mapping is removed and the gateway becomes unhealthy. The upstream job may still execute privately; it is not released or presented as approved. If persisting completion fails, the previous record is restored and the same latch applies. Further run submissions/listing/result releases return 503 until an operator repairs state and restarts. The healthy check is repeated under the registry mutex at submission admission, submission commit, history release and every result release. Commit and response emission are serialized with failures: a request already sent upstream may finish privately, but if another request activated the latch before its release boundary it returns 503, makes no further registry update and cannot implicitly recover the gateway even if the filesystem has become writable again. Responses emitted before the latch remain historical results; the gateway cannot retract bytes already sent. Logout still works. Restart invalidates sessions but restores successfully persisted run ownership.

## Execution versus scientific release

Reports show execution and scientific evaluation separately. `succeeded` alone does not approve science. The gateway accepts `evaluated_passed` only with successful execution, positive TP, zero FP/FN, precision/recall 1, evaluator exit 0, required provenance hashes, and matching processed-input/reference hashes. An unsupported approval is downgraded to `withheld` with `gateway_evidence_mismatch`.

The report DTO excludes key/signature records, local paths, raw stderr/error messages, arbitrary metrics maps and artifact URLs. It includes typed statuses, digest evidence, crypto outcome booleans, pipeline counts/stage codes and scientific counts/provenance. The browser uses text escaping and distinguishes withheld/unassessed reports from approved synthetic results. The UI session-generation guard prevents late responses from an older reviewer from populating a newer reviewer's workspace.

Session-race acceptance covers explicit A/logout/B transitions within a page and
initial recovery losing to explicit sign-in intent. A browser profile shares its
session cookie across tabs; separate simultaneous reviewer accounts require
separate browser profiles. Automatic identity synchronization of every open tab
is not implemented or claimed by these checks.

## Verification and limits

```bash
go test -race ./...
go vet ./...
```

Eight tests with negative subcases cover sessions, Origin/Host, CSRF, expiration, logout, disabled accounts, rate limits, registry recovery/failure (including an approved upstream response blocked while another request triggers the persistence latch), typed DTO rejection, unsupported scientific approval, and concurrent A/B requests over real local mTLS. The mock upstream verifies the uploaded RSA-PSS signature and decrypts the AES-GCM/RSA-OAEP payload to the prepared input. It does **not** substitute for the real worker/variant pipeline; the Compose reviewer harness must demonstrate that integration separately.

The gateway is a trusted credential holder and can act for every configured reviewer if compromised. The host operator and Docker administrators remain trusted. Access codes are reusable until configuration rotation/restart; there is no MFA, mail delivery or self-service recovery. Sessions/rate state and admission reservations are process-local; run ownership is persistent. Certificate rotation, multiple gateway instances/workers and crash recovery of in-flight submissions require additional design. No deployment, hardware enclave, clinical accuracy or external-lab readiness is inferred from unit tests.

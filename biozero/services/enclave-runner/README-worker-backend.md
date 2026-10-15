# Protected worker to capsule broker

This integration connects one protected worker to the fixed-profile v2 Unix/FD
broker. The worker verifies an anchored ciphertext snapshot, verifies RSA-PSS over
that same snapshot and authenticates AES-256-GCM after RSA-OAEP key unwrapping.
Optional encrypted key envelopes still require the configured job key. Original
upload hash/size are unchanged; processed plaintext hash/size are separate facts.

Verified plaintext is staged only in a checked 32 MiB, 4096 inode-unit private
tmpfs. Durable worker custody is recorded before the first Submit. Pipeline,
scientific evaluator and alignment/detection execute inside the provider capsule.
The worker projects its result from the confirmed retained receipt and never opens
capsule-produced paths or invokes those tools on this route.

Fresh protected native25-check and three-service Compose30-check runs passed,
with independent retained-evidence readback78/35. Both use the native capsule
provider. Separate [protected Docker acceptance](../../docs/evidence/20261015-protected-docker-capsule-worker/public/README.md)
passed57actual assertions and52independent retained-state checks, using the same
production binaries and actual Docker capsules. [Earlier acceptance and source pins](../../docs/evidence/20261015-protected-capsule-worker/public/README.md)
distinguish runtime evidence from component tests, later documentation, production
deployment and cross-host reproducibility.
See [current gates](../../docs/requirements-and-gates.md) for remaining scope.

## Fixed operator configuration

The process entry defaults to `BIOZERO_EXECUTION_BACKEND=capsule`. Configure all
of these values before starting it:

- `BIOZERO_ARTIFACT_SOCKET`: absolute private broker socket path.
- `BIOZERO_ARTIFACT_PROFILE_SHA256`: the profile printed by the same broker binary
  and configuration that will serve this socket.
- `BIOZERO_ARTIFACT_PROJECTION_POLICY`: absolute path to a private `0600`,
  single-link, current-UID JSON document, bounded to 64 KiB.
- `BIOZERO_PIPELINE_MODE`: `stats` or `variants`, matching the profile and policy.
- `BIOZERO_DECRYPT_DIR`: the prepared bounded tmpfs directory; see
  [the native launcher](cmd/worker-scope/README.md).
- `BIOZERO_WORKER_CUSTODY_DIR`: private durable directory, defaulting to
  `worker-custody` under `BIOZERO_DATA_DIR`. Preserve it across restarts.

PKI, data, security-event and optional job-key settings retain their protected
entry roles. The capsule route does not load host-side pipeline/rules/evaluator
selectors. Compose grants no Docker socket, Store mount or provider command
authority. The native launcher retains access to the trusted host filesystem tree;
its configuration does not confer authority to open Store paths, but it does not
isolate host files or hostile same-UID writers. See the launcher's explicit scope.

The projection document has exactly five required fields:

```json
{
  "schema_version": 1,
  "profile_sha256": "<64 lowercase hexadecimal characters>",
  "pipeline_mode": "variants",
  "capsule_kind": "native",
  "source_pins": {
    "pipeline": {"sha256": "<64 lowercase hex>", "bytes": 1},
    "resource_budget": {"sha256": "<64 lowercase hex>", "bytes": 1},
    "reference": {"sha256": "<64 lowercase hex>", "bytes": 1},
    "evaluator": {"sha256": "<64 lowercase hex>", "bytes": 1},
    "truth": {"sha256": "<64 lowercase hex>", "bytes": 1},
    "analysis_executable": {"sha256": "<64 lowercase hex>", "bytes": 1},
    "analysis_rules": {"sha256": "<64 lowercase hex>", "bytes": 1},
    "analysis_panel": {"sha256": "<64 lowercase hex>", "bytes": 1}
  }
}
```

Replace every placeholder and example byte count with verified assets from the
selected broker configuration. The operator must supply that correspondence; the
worker cannot derive configuration from its digest. `capsule_kind` may be `docker`
for that fixed provider. Stats omits evaluator/truth; unused reference/panel pins
are omitted. Unknown fields, extra pin names, missing members, alias/duplicate
keys, nulls, oversized assets and mismatched profile/mode are rejected. This
document grants no authority to choose executables or routes for individual jobs.

The earlier execution profile remains only as explicit
`BIOZERO_EXECUTION_BACKEND=legacy`, with all capsule settings absent. The original
native/Compose harnesses select that profile explicitly while their existing
acceptance is retained. Missing or broken capsule configuration never falls back
to it. The native staging launcher accepts the capsule profile only.

## Recovery and private result references

[Worker custody](README-worker-custody.md) binds immutable job metadata, original
upload digest, plaintext facts and exact analysis context to the selected profile.
The metadata fingerprint excludes only status, start time and lifecycle errors.
Only its digest is retained, not signatures or encrypted key envelopes. This does
not complete the separate immutable-principal ownership requirement TM02.

A running job or existing custody binding only queries status and receipt. It
never decrypts again or resubmits. A lost response, generic handler error,
unavailable broker or uncertain durable state keeps the job running without a
terminal result. Pending work blocks admission of another plaintext input. Every
retained binding is queried again after restart; a missing local binding for a
previously running job also requires operator reconciliation.
Unreadable, unsafe or mismatched metadata under an otherwise valid job filename
also fences new admission. Known committed receipts and terminal results can still
recover; the worker does not delete or silently adopt the ambiguous file.

The live stage remains linked and reachable until confirmed committed readback.
Transport failure is not a termination proof. Process exit closes descriptors
without deleting unknown names. A stage left by another worker process is never
adopted or removed automatically; it can continue to block new admission even
after a prior result is recovered. Namespace/tmpfs destruction has its own runtime
scope and does not authorize journal deletion, refunds or another execution.

Confirmed receipt projection retains execution/scientific/detection data allowed
by the result contract. Raw command captures and capsule paths are excluded.
Variant output names become artifact IDs; these references are not file paths or
an artifact-download endpoint. Detection targets stay in the owner's private
result. A genuinely empty failed commit carries no invented evaluation/detection.
Its required detection envelope says `detection_unavailable`.

Optional `artifact_execution` binds the private result to profile, Store, lease,
manifest, receipt and bounded file hashes/sizes. Result publication failure can
recover the same committed objects without executing again. An oversized result
becomes failed/withheld while preserving original input provenance and this
artifact binding. References do not themselves approve scientific release.

## Executed verification and remaining scope

Component tests cover anchored verification, pre-custody rejection,
fingerprints, strict projection policy, query-only recovery, uncertain responses,
publication failure and admission fencing. The final backend race scope passed
14top-level functions and34subcases; full make passed263Python (261passed/two
opt-ins skipped) and eight Go modules' test/vet. Stage/launcher file tests distinguish
real inode/FD behavior from namespace/mount acceptance.

Actual native25-check and Compose30-check runs established TLS, signature/
decryption, repeated three-SNP science, provenance hashes, A/B denial, unsigned
rejection before custody, invalid FASTQ withheld and worker clean-stop/lost-
publication recovery without reexecution. Original failed startup evidence remains
preserved. These runs do not establish crash recovery or broker/capsule cancellation.
Image dependency/build closure, actual integrated crash/cancel/lost-ACK fault
reconciliation, principal quotas/retention and broader project gates remain open.

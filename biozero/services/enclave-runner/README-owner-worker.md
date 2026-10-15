# Explicit owner-v1 worker

This worker entry verifies signed ownership, actual ciphertext/envelope and GCM
AAD before staging or broker V3 admission. It uses the shared receipt projector
for execution/scientific-release checks. The source and component tests do not
establish a new real provider acceptance or close TM02. See the
[execution contract](../../docs/security/ownership-execution-contract.md).

## Selection and private configuration

Set `BIOZERO_WORKER_PROTOCOL=owner-v1` and
`BIOZERO_OWNER_WORKER_CONFIG` to the absolute private configuration path. Selection
precedes legacy config, recovery and tools. Unknown protocols fail closed; an
owner config or init flag with an absent/legacy selector is rejected. With no
owner settings, the consciously selected legacy route keeps its existing behavior.
There is no fallback after an owner configuration or execution error.

Configuration is closed JSON, bounded 64 KiB, regular single-link current-UID
mode 0600, with anchored no-follow ancestry. All fields below are required:

| Fields | Values |
| --- | --- |
| `schema_version`, `protocol` | `1`, `owner-v1` |
| `socket` | Absolute clean path of the separately configured V3 broker socket |
| `jobs_directory`, `uploads_directory`, `acceptances_directory` | Dedicated owner ingress paths; read-only to the worker in a restricted deployment |
| `results_directory`, `stage_directory`, `custody_directory` | Separate private writable locations; stage must meet the verified tmpfs contract |
| `authority_id`, `public_key_hex` | External 32-hex authority ID and 64-hex Ed25519 public key |
| `pipeline_mode`, `execution_profile_sha256` | `stats` or `variants`; exact 64-hex owner broker profile |
| `expected_scope` | Exactly `{store_id,policy_sha256}`, externally pinned authority genesis |
| `decryption_key`, `projection_policy` | Each exactly `{path,sha256}`; private hash-pinned assets |
| `poll_milliseconds`, `timeout_seconds` | 100–60000 ms; 1–600 s |

The six state roots must be pairwise disjoint, absolute and clean. None may cover
config, socket or assets. The RSA key is 2048–4096 bits with exponent 65537;
PKCS1/PKCS8 private PEM is loaded once. The projection policy fixes profile, mode,
provider kind and pipeline/resource/analysis/source hashes; already hash-checked
bytes are parsed without reopening the asset. Neither file contains authority
signing material. Do not give the worker a Docker socket, provider authority or
artifact Store mount.

The SHA of **all original config bytes** is part of custody trust. Preserve those
bytes: even reformatting or changing polling/timeout changes the required context.
There is no automatic config migration or permission to replace retained custody.

## Explicit genesis and start

Build the worker and launcher explicitly from this module when creating a new
verified binary inventory:

```sh
CGO_ENABLED=0 go build -o /absolute/private/bin/enclave-runner .
CGO_ENABLED=0 go build -o /absolute/private/bin/worker-scope ./cmd/worker-scope
```

First provision the [owner broker profile and authority scope](../artifact-executor/README-owner-broker.md).
Freeze matching worker config/policy, prepare private ingress/results paths and
initialize only the new custody root:

```sh
BIOZERO_WORKER_PROTOCOL=owner-v1 \
BIOZERO_OWNER_WORKER_CONFIG=/absolute/private/owner-worker.json \
/absolute/private/bin/enclave-runner --init-owner-worker
```

Initialization verifies config/assets and creates one new owner journal; it does
not stage plaintext, start tools or serve jobs. Existing roots are rejected.
Normal execution opens that established history. For the native staging profile:

```sh
BIOZERO_WORKER_PROTOCOL=owner-v1 \
BIOZERO_OWNER_WORKER_CONFIG=/absolute/private/owner-worker.json \
/absolute/private/bin/worker-scope \
  --worker /absolute/private/bin/enclave-runner \
  --worker-sha256 WORKER_BINARY_SHA256 \
  --tmpfs /absolute/private/worker-plaintext
```

The config's `stage_directory` must equal this exact tmpfs path. The launcher
forces `BIOZERO_DECRYPT_DIR`; the owner runtime checks equality when present.
[Launcher requirements](cmd/worker-scope/README.md) include UID/GID 1000 and actual
user/mount/network namespace capability. Direct service/container launch must
provide the same verified 32 MiB, 4096-inode-unit private tmpfs with
`noexec,nosuid,nodev`; the worker never silently substitutes a host directory.
The broker must already be serving the matching V3 profile/scope.

## Custody, recovery and output

Canonical signed acceptance is retained separately from processed facts in
`acceptances/<sha>.json`; the owner journal never imports legacy records.
At most 64 bindings and 64 KiB per acceptance are retained, with a 1 MiB journal
and one replacement. This is logical metadata accounting, not a disk quota.
Uncertain publication retains markers/files and a raw lifetime flock; Close or GC
does not release a sticky writer. No history is repaired, deleted or refunded.

GCM failure occurs before Stage, custody Put or Submit. A successful stage is
retained if custody/transport is uncertain. Existing bindings recover by broker
status/receipt only, even if spool input is missing or mutable job/cache fields
claim completion. A missing broker record does not authorize another Submit.
Unknown predecessor plaintext blocks fresh admission and is not adopted/deleted.
Cancellation closes the current channel; provider completion is not inferred.

Committed status and actual receipt are projected with matching owner/context/
source facts before releasing this process's stage. The bounded owner result
cache is observability only and is not a legacy `resultRecord` or an owner Results
API. Its status cannot authorize execution or user result release. Legacy
protected-rejection SOC outbox behavior does not automatically run in this loop.
The process also caps rejected-job identities; this is not durable client quota.

See the execution contract for pending Results/Gateway, deployed isolation,
physical quotas, attestation and lifecycle/uncertainty gates. Preserve failed
runs and source-specific evidence; earlier V2 native/Docker receipts do not prove
V3 acceptance.

## Source-specific native evidence

[Retained owner execution](../../docs/evidence/20261015-owner-worker-execution/public/README.md)
passed53native controls and96independent public-key-only readback controls. It
covers two three-SNP inputs, invalid FASTQ withheld, and copied ciphertext with B's
legitimate acceptance rejected without new execution state. Old weaker/failed
attempts and all charges remain. This does not close Results/Gateway, owner-V3
lifecycle fault, deployed isolation or full physical quota gates.

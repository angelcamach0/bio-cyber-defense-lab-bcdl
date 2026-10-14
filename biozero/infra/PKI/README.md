# Local milestone PKI and runtime preparation

This PKI is a fresh, short-lived fixture for reproducible experiments with synthetic data. It creates separate researcher A/B identities, independent upload/results/gateway TLS keys, and a separate payload decryption key. It never overwrites an existing destination, including an empty directory. If generation fails, inspect the partial output and select a new destination; do not overwrite keys associated with existing jobs.

## Prepare from the repository root

```bash
bash biozero/infra/PKI/gen-pki.sh
bash biozero/infra/PKI/prepare-runtime.sh
export BIOZERO_UID="$(id -u)"
export BIOZERO_GID="$(id -g)"
docker compose -f biozero/infra/compose/docker-compose.yml config
```

Run these commands as a non-root host user. `gen-pki.sh` defaults to its own `pki/` directory, independent of the current working directory. An explicit new destination is supported, including paths with spaces. `prepare-runtime.sh` defaults to `infra/compose/data/`; it does not replace data and refuses symlink or foreign-owned target directories. Bind mounts set `create_host_path: false`, so missing setup fails instead of creating root-owned folders.

For custom destinations, set `BIOZERO_PKI_PATH` and `BIOZERO_DATA_PATH` to absolute paths before running Compose. The PKI and data files must be owned by the UID/GID used by Compose. Default Compose UID/GID is 1000:1000; export your actual values rather than relying on the default. No service requires host root, Docker socket access, or privileged mode.

## Material layout

| Directory | Material | Consumer |
| --- | --- | --- |
| `authorities/` | CA certificate/private key and issuance serial | Local issuer only; never mounted in a service |
| `clients/` | `researcher-a.crt/key`, `researcher-b.crt/key`, `ca.crt`, `decrypt.crt`, `signer.key` | Individual CLI test clients; never mounted in a service |
| `runtime/upload/` | Upload TLS certificate/key and CA certificate | Upload API only |
| `runtime/results/` | Results TLS certificate/key and CA certificate | Results API only |
| `runtime/worker/` | Payload `decrypt.key` and public `signer.crt` | Worker only |
| `runtime/gateway/` | Gateway TLS key, A/B client identities, fixture signer key, CA/encryption public certificates | Reviewer gateway only |

A/B certificates have distinct serials, key pairs and common names (`researcher-a` and `researcher-b`). Their CN is the protected-mode `client_id`; form/header claims cannot establish identity. Server certificates are valid for localhost, 127.0.0.1 and their own service hostname. The payload signer has code-signing purpose, so it cannot serve as an mTLS client credential. The CA lasts 30 days; issued certificates last 7 days. Generate a new fixture before expiry; this is not a rotation mechanism for persistent deployments.

The CLI uses:

```text
--client-id researcher-a
--mtls-cert <pki>/clients/researcher-a.crt
--mtls-key <pki>/clients/researcher-a.key
--ca-cert <pki>/clients/ca.crt
--server-cert <pki>/clients/decrypt.crt
--sign-key <pki>/clients/signer.key
```

The legacy CLI flag `--server-cert` selects the encryption public key. TLS verification still uses `--ca-cert`; encryption and TLS now use different private keys. Researcher B uses its own certificate/key and `--client-id researcher-b`.

## Runtime boundaries

Upload API writes uploads/jobs; Results API reads jobs/results; the worker reads uploads and writes jobs/results/artifacts. Results API has no uploads mount. Worker decryption uses a 32 MiB tmpfs with cleanup after processing; pipeline scratch uses a bounded tmpfs, and approved output artifacts persist in the worker-only artifacts bind. APIs, worker and UI have read-only root filesystems, dropped capabilities, no-new-privileges and CPU/memory/PID limits. Limits are provisional budgets for the small synthetic experiment, not measurements of Oracle capacity. Host ports bind only to 127.0.0.1. The worker has no network interface beyond loopback; API/gateway use a project-scoped bridge with loopback port bindings. The optional static UI and simulation responder use separate bridges. These networks do not enforce egress denial; see [network decision](../../docs/decisions/002-local-container-network.md).

The static UI has no PKI/data mounts or backend proxy. `/api/upload`, `/api/results/*` and `/api/alert` return 403. UI `/health` reports UI liveness and explicitly unverified backend readiness; `/api/health/*` returns 503. This static nginx service is an optional `static-ui` profile and has no reviewer API identity. The default browser entry is the HTTPS reviewer gateway on port 8083, with distinct sessions and A/B mTLS transports; see [gateway configuration](../../services/reviewer-gateway/README.md). Backend readiness must be tested with authenticated CLI probes; a rendered homepage does not validate scientific outputs.

ZeroResponder is an opt-in `simulation` Compose profile, has only its actions directory, and cannot change firewalls, host configuration or certificate trust. It writes simulation records. Enabling the profile is not evidence of real blocking, quarantine or revocation. Alert authentication and its negative tests must pass before enabling it.

## Validation

```bash
bash biozero/infra/PKI/test-pki.sh
```

This generates disposable keys outside the repository and checks A/B identities, certificate chains and TLS purposes, service hostname rejection, refusing overwrite, private-key modes, minimal runtime material and runtime preparation. It prints no private-key contents. Static YAML checks are not substitutes for `docker compose config`, `nginx -t`, container startup and A/B end-to-end authorization tests. Validate only the enabled profiles; the gateway serves its own UI without nginx. The real four-service reviewer run passed 30 assertions, including HTTPS/mTLS, A/B denial, restart ownership, revocation, scientific release and container controls. This does not validate the optional nginx or responder profiles.

## Scope and remaining risks

Containers and filesystem roles are not hardware enclaves. There is no demonstrated TEE, remote attestation, confidential-computing guarantee against the host operator, or enforced certificate revocation here. The host user and Docker administrators can access local fixture material. The demo trusts one client-held signing key for both researchers; it verifies payload integrity under that fixture, not a distinct per-user scientific endorsement. Jobs remain a shared writer boundary between upload and worker; concurrent processing, transactional persistence and tamper-resistant provenance require additional work. Sensitive human genomic data is outside this synthetic milestone's acceptance scope.

Compose controls use the official [service configuration reference](https://docs.docker.com/reference/compose-file/services/). Full image digest pinning and measured resource budgets remain follow-up work.

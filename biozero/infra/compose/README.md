# Compose reviewer experiment

The default four-service profile runs prepared synthetic variant experiments through
an HTTPS reviewer gateway, individual mTLS identities and one worker without a
network. Execution success and scientific release are separate report fields.

## Prepare a local demo

Run from the repository root as the non-root runtime user. Use fresh destinations;
PKI and reviewer provisioning refuse replacement. Docker socket permission or a
noninteractive sudo prefix is needed on the host, never inside a service.

```bash
bash biozero/infra/PKI/gen-pki.sh biozero/infra/PKI/pki
bash biozero/infra/PKI/prepare-runtime.sh biozero/infra/compose/data
python3 biozero/infra/compose/prepare-reviewers.py --out .biozero/reviewer-config
export BIOZERO_UID="$(id -u)"
export BIOZERO_GID="$(id -g)"
docker --host=unix:///var/run/docker.sock compose -f biozero/infra/compose/docker-compose.yml config --quiet
docker --host=unix:///var/run/docker.sock compose -f biozero/infra/compose/docker-compose.yml up --build -d
```

Open https://localhost:8083. Trust the disposable public demo CA in your local
client for this local experiment; preserve TLS verification. Retrieve reviewer-a
or reviewer-b and its code privately from .biozero/reviewer-config/invitations.json.
Do not commit, print in shared logs, or publish invitations, cookies or keys.
The configuration stores only code hashes and is mounted read-only in the gateway.
Reviewer codes are high-entropy access codes, not human passwords.

The default reference, input catalogue and truth are the deterministic three-SNP
fixture. The worker uses variants mode and the independent evaluator by default.
Select variant-smoke for a known-answer run, or invalid-fastq for the agreed failure.
A succeeded job without evaluated_passed remains scientifically unassessed or withheld.
For a transport-only run, explicitly choose BIOZERO_PIPELINE_MODE=stats; that does
not approve the scientific experiment. Explicit empty BIOZERO_EVALUATOR_PATH and
BIOZERO_TRUTH_PATH disable optional scientific evaluation together.

Custom PKI/data/config/reference paths must be absolute and exist before Compose.
The generator supplies role-specific runtime keys; no service receives the CA
private key, and the gateway does not receive the worker decryption private key.
The gateway is a trusted holder of both reviewer TLS identities and the synthetic
fixture signer key. Read [its configuration and limits](../../services/reviewer-gateway/README.md).

## Repeat the integration verification

```bash
python3 -B biozero/infra/compose/run_reviewer_experiment.py
```

The command creates its own fresh private runtime, builds the images, starts a
unique project on loopback ports and removes only that project in a finally block.
If the host needs sudo, pass --docker-command 'sudo -n docker --host=unix:///var/run/docker.sock'.
It clears Docker endpoint/context/TLS selectors for commands while preserving
registry credentials, proxy settings and certificate trust. Existing images can
be selected with --skip-build --image-prefix biozero-review after a verified build.

The executed ARM run passed 30 assertions: health and missing-certificate TLS
rejection, sessions/Origin/CSRF, real encrypted/signed submissions, two exact
three-SNP evaluations, A/B denial on gateway and backend, immutable hashes,
malformed FASTQ withholding, restart ownership, logout revocation and non-root
read-only/scoped container controls. Evidence is under
biozero/docs/evidence/20261014T141041-019709Z-reviewer-compose/public/ with SHA256SUMS.
Share only public/. Credentials, registry, raw data and diagnostics remain private.
HTTP session-flow checks alone do not prove browser rendering. The separate
20261014T150658-139518Z-reviewer-compose/public/ run passed31 total assertions,
including23 real Firefox/TLS/UI/late-response checks, zero JavaScript errors and
four screenshots. TLS stayed verified; its project cleanup passed.

## Browser acceptance setup

The opt-in browser checks require Python 3.10+, Playwright 1.64.0, its patched
Firefox build (157.0, revision 1555), and NSS certutil. Use an isolated environment:

```bash
python3.11 -m venv .biozero/browser
.biozero/browser/bin/python -m pip install --require-hashes -r biozero/infra/bootstrap/browser-linux-aarch64-py311.requirements.txt
.biozero/browser/bin/python -m playwright install firefox
.biozero/browser/bin/python -B biozero/infra/compose/run_reviewer_experiment.py --browser
```

The wheel lock is for CPython 3.11/Linux ARM64, matching the executed host setup;
do not use it as a cross-platform lock. Playwright browser versions are coupled to the Python package. Browser/system
dependencies must be installed for the host; see [official browser setup](https://playwright.dev/python/docs/browsers).
On this RHEL 9.8 ARM host the Ubuntu 24.04 ARM Firefox fallback actually launched;
RHEL is not an officially supported Playwright platform. Observed prerequisites
include nss-tools, gtk3, libX11/libXcomposite/libXdamage/libXrandr, mesa-libgbm,
alsa-lib, libXt/libXScrnSaver, pango/cairo, dbus-glib and fonts. A browser download
alone does not establish runtime compatibility.

The harness imports only the disposable demo CA into a temporary Firefox NSS
profile. A separate profile without that CA must reject TLS. System/user trust
stores are unchanged and ignore_https_errors stays false. Screenshots are
allowlisted public artifacts; invitations, cookies, profiles and diagnostics
remain private. Browser checks exercise the actual UI, scientific release,
owner isolation, invalid input and delayed responses across A/logout/B.
The recorded --browser run passed these controls for local Firefox157; other
browsers, production identity and external deployment are not covered.

## Network and profiles

Published ports bind explicitly to 127.0.0.1. The service bridge permits fixed
backend communication but does not enforce egress denial. Docker 29.9.0 did not
publish ports for the earlier internal-only bridge; that failed run is preserved.
See [the observed network decision](../../docs/decisions/002-local-container-network.md).
The worker retains network_mode=none and a bounded plaintext tmpfs.

The old nginx static UI is optional --profile static-ui; it has no API identity
and blocks upload/results/alerts. ZeroResponder is optional --profile simulation
and writes simulation records only. Neither optional profile was part of the
30-assertion reviewer run. External publishing, Oracle deployment, production
identity/key management, queues and measured concurrency remain separate gates.

## Security event simulation profile

The worker now mounts a private `security-events/` outbox, while retaining network
none and no responder secret. Prepare the new directory with the current runtime
script. Updated PKI generation creates `runtime/responder/` containing only its
server certificate/key. The optional simulation profile requires a private
`BIOZERO_WEBHOOK_SECRET` (32 to512 bytes) and uses HTTPS. The host port is
`BIOZERO_RESPONDER_PORT`, default8090, bound only to127.0.0.1. Do not print an expanded
Compose configuration containing that secret.

The separate [SOC harness](../soc/README.md) validates a retained real native
worker event and builds only this responder. Run
`python3 -B biozero/infra/soc/run_container_response.py --help` for private parent/event
arguments. Receipt `20261014T165334-020175Z-soc-container/public/` passed13 controls
and cleanup, with verified TLS, authentication, private durable idempotent receipts,
minimal mounts, limits and loopback publishing. It executes no pipeline/model.
The current four-service run separately passed30 controls in
`20261014T164550-385353Z-reviewer-compose/public/`, including the exact outbox mount.
Both receipts are independently reviewed; the earlier mount-verifier failure is
preserved in STATUS. There is no automatic relay service or effective containment.

## Active cancellation and explicit committed-broker recovery

These are separate opt-in local Linux ARM64 scenarios. Use host UID/EUID/GID 1000,
the exact cached image
`sha256:1ca8e95c2f5679ab2001f856549c634f0b9daeeeb1492b8610814b96cf30fa7d`,
and the six existing verified
service executables. Check their hashes and production-source correspondence
against their build receipt before reuse. Neither command builds or pulls an
image, compiles acceptance service binaries, downloads data or runs a model.
The broker-recovery scenario additionally requires Python os.pidfd_open and
kernel pidfd support; it fails explicitly if that capability is unavailable.
Host/daemon and cooperative same-UID trust remain part of the boundary.

```sh
python3 biozero/infra/compose/run_capsule_cancellation.py \
  --run-dir "$PWD/.biozero/active-cancel-NEW" \
  --binaries-dir /absolute/existing/verified/bin

python3 biozero/infra/compose/run_broker_recovery.py \
  --run-dir "$PWD/.biozero/committed-broker-recovery-NEW" \
  --binaries-dir /absolute/existing/verified/bin
```

Each command requires a new private root and selects the real Docker capsule
provider with the fixed cached image. Source, configuration/profile, executable
and supplied-input pins belong to that run. Existing failed attempts, stopped
application objects, retained history and charges are preserved. Do not reset,
adopt or refund history to admit a replacement execution.

### Active cancellation

The protected entry still uses individual mTLS, signing and encryption. A
separately pinned lifecycle pipeline reads the verified input, writes a bounded
private readiness marker and waits with a finite deadline. It intentionally
produces no scientific result. The harness reads the marker through the exact
inspected capsule PID's proc root, using no-follow bounded regular-file checks
and matching Docker identity before/after; it does not exec another process
inside the capsule.

Before Cancel, the runner requires the active Store record's complete reservation,
linked broker journal, verified worker custody and absence of a terminal result.
It preserves the ORIGINAL bytes of all three metadata files as private 0600
checkpoints, with bounded no-follow reads, stable metadata, hashes, file fsync,
readback equality to the validated JSON states and directory fsync. It rechecks
all three current files immediately before sending the real V2 Cancel frame.
This makes the reservation-to-commit transition auditable without reconstructing
an earlier state after the event.

Cancel is a local operator action on the existing broker channel, not a public
cancellation API or a new client authorization capability. Submit remains open;
neither request is half-closed. The gate is a complete Cancel send after actual
activity, followed before the provider deadline by failed/withheld status,
artifact_cancelled, zero retained exports and a proof created after provider
wait/export closure. The observed 17-check run also received CancelRequested=true;
ACK observation is recorded separately and is not inferred from request_sent.
The contract permits a raced/missing ACK only when the independent causal final
state is verified. No Submit is retried to obtain a better transport result.

The terminal manifest/proof and its one slot/actual metadata charge remain
retained; terminal failure is not a refund. Scientific evaluation and pipeline
outputs are absent, detection is unavailable, and no scientific approval follows.
The unchanged custody retains the original ciphertext and verified plaintext
hashes separately. A/B result authorization remains enforced.

### Broker death after commit

The fixed proxy holds the real completed Submit response only AFTER receiving
its full upstream frame and EOF. With that worker response still held, the
operator fixture pins the known live broker process/socket, exact executable and
configuration, fixed profile and complete committed history. It SIGKILLs only
that child and requires Wait=-9. Starting the same binary/configuration without
socket reconciliation returns 1 with the actual generic message
artifact_service_start_failed. This observation does not establish a specific
internal error code.

The explicit operator procedure may retire ONLY the previously pinned socket
for this fresh owned fixture. It requires pidfd-confirmed death, refusal of new
connections to that socket, unchanged complete committed Store/journal/custody,
valid artifacts/proofs/accounting, an empty provider workspace and the actual
negative startup result. It checks identities again immediately before unlink
and synchronizes the parent directory. It does not remove a ledger, workspace,
anchor, plaintext file, retained object or charge. Directory/socket descriptors
and pidfd checks do not remove the cooperative-host assumption: unlinkat itself
is not an atomic inode-conditional operation against a malicious same-UID writer.

Starting the same broker again creates a verified replacement socket at the
same path/profile. Only then does the proxy discard the held downstream response;
the worker recovers through real status/receipt queries using the same lease,
artifacts, proof, scientific result and charge. Recorded process exits are -9
for the killed broker, 1 for the unreconciled startup and 0 for the recovered
broker after clean shutdown. All created processes are waited and logs retained.
The proxy remains held throughout the outage, so this does not demonstrate worker
query retries during broker unavailability or an upstream ACK-write failure.

The broker run passed 31 controls, the newer physical-checkpoint cancellation run
passed 17, and the positive default Docker baseline passed 57. Their respective
receipts retain their exact source snapshots; a change to one runner is not
silently attributed to an earlier run. Independent readbacks passed 48/49/52 respectively; final make passed 294 Python
cases (292 passed, two helper opt-ins skipped) and eight Go modules test/vet. See
the [public bundle and exact source delta](../../docs/evidence/20261015-broker-cancel-recovery/public/README.md).

These checks do not establish pending-execution/plaintext reconciliation, broker
death while a capsule is active, capsule death, a production stale-socket repair
service, immutable ownership, full image/build closure, clinical accuracy or the
complete lifecycle gate. Unknown pending history still blocks restart; no
implicit cleanup, replay or quota release is authorized.

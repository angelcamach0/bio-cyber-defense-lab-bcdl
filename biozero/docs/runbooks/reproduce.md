# Reproduce the synthetic milestone

## Local native profile

Use Linux, Go 1.22+, Python 3.9+, OpenSSL, Git, curl, and make. Run `make bio-tools`
to install micromamba 2.9.0 and tools into `.biozero/` without a system-wide install.
The explicit lock fixes the Linux ARM64 packages. x86_64 has a versioned
specification but has not been validated here. Preserve inherited proxy and CA
trust; keep TLS verification enabled.

```bash
make bio-tools
make test
bash biozero/infra/PKI/test-pki.sh
make experiment
```

The native profile starts upload/results APIs and one worker on temporary
loopback ports with individual mTLS identities. The CLI encrypts with the worker
public key and signs with the client-held demo signing key. The worker validates
before analysis, returns terminal states, and cleans plaintext. The evaluator
checks variant presence separately.

Acceptance: three expected SNPs, zero extras/omissions, identical normalized
calls in two runs; B cannot read A's results with a forged header; invalid FASTQ
fails for its format; no certificate fails TLS; unsigned input is rejected before
analysis; original upload hashes are preserved.

## Evidence

Each run creates a new directory in `biozero/docs/evidence/` and exits nonzero on
failure. Its manifest records revision, dirty flag, source hashes, architecture,
versions, safe configuration, input hashes, cases and outcomes. Metrics and VCFs
record independent scientific evaluation. `public/` has an explicit allowlist
and checksums. Share that subdirectory only. Private credentials/runtime records
and diagnostic logs remain outside it.
Public VCFs are derived normalized allele-presence records, not full raw VCFs.
Their derivation JSON records source/reference/export hashes and allele agreement;
genotype, quality, filters, annotations, sample names and commands are omitted.
Original VCFs remain outside public/. Earlier raw exports contain local paths and
must not be published.

`make science` records sequential pipeline elapsed time and maximum child RSS in
Linux KiB. It does not measure total service RAM or concurrency capacity. The
fixture evaluates allele presence for simple synthetic SNPs, not genotype,
indel, whole-genome or clinical accuracy.

## Failure diagnosis

- Missing tools: run bootstrap or select an existing `BIOZERO_TOOLS_PREFIX`.
- `pipeline_start_failed`: inspect execution permissions/interpreter availability.
- `incomplete`: inspect mandatory dependencies/reference and stage error codes.
- `rejected`: inspect protected integrity/signing/encryption requirements.
- `timed_out`: inspect the execution budget; terminal errors must not poll forever.
- Preserve failed evidence and create a new run after correcting its cause.

The supervisor stops only sessions it created, including separate child groups.
SIGINT/SIGTERM handled by the worker preserve cancellation and clean plaintext.
Abrupt termination is recovered as an interrupted job on restart.

## Separate Compose profile

See [PKI setup](../../infra/PKI/README.md). Generate fresh PKI, prepare runtime
directories, select the actual non-root UID/GID, and set Compose paths. The
configuration restricts interfaces/resources and mounts service-specific keys.
The default HTTPS reviewer gateway executes prepared synthetic experiments with
individual sessions and mTLS transports; the old nginx UI is an optional restricted
profile. ZeroResponder remains optional simulation.

Run python3 -B biozero/infra/compose/run_reviewer_experiment.py for the real four-service
Compose verification. A fresh ARM --browser run passed 31 assertions including scientific
release, cross-client denial, restart/relogin, revocation and container controls.
Public evidence: biozero/docs/evidence/20261014T150658-139518Z-reviewer-compose/public/.
The opt-in browser setup is in [Compose README](../../infra/compose/README.md).
Real Firefox157 passed23 UI/TLS/session-race checks with four screenshots and
zero JavaScript errors. These results cover this local Firefox profile only.
Optional nginx/responder and Oracle deployment remain unverified.
Native success alone does not prove the container profile.

Lía independently reproduced the native milestone from another temporary Git
checkout; see evidence/20261014T150823-057533Z-independent-checkout/public/.
The snapshot provenance records127 hashes/modes and the older native manifest's
119/127 Unicode-filename limitation. The current runner uses Git's NUL output.

## Regulatory resource preflight

Use make regulatory-tools and make regulatory-preflight to recreate the measured
CPU-only Python 3.11/Torch environment from exact ARM package/wheel artifacts.
The default probe preserves Torch's initial motor while requesting Sei's fbgemm
qconfig. It exercises a small untrained Conv1d+Linear, never a trained checkpoint.
See [SCI01](../research/2026-10-14-regulatory-feasibility.md) for actual results,
forced-engine failure, provenance and remaining trained-model/biological gates.

## CI

Local/CI share `make test`, `make science`, and `make experiment`. The prepared
workflow uses a standard public-repository ARM64 runner, read-only token permissions
and public synthetic evidence only. Hosted workflow execution is pending.
Runner policy: [GitHub documentation](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

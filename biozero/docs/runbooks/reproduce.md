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
Optional nginx and Oracle deployment remain unverified. The later responder
simulation receipt is described below; it does not establish effective response.
Native success alone does not prove the container profile.

The native milestone was independently reproduced from another temporary Git
checkout; see evidence/20261014T150823-057533Z-independent-checkout/public/.
The snapshot provenance records127 hashes/modes and the older native manifest's
119/127 Unicode-filename limitation. The current runner uses Git's NUL output.

## Regulatory resource preflight

Use make regulatory-tools and make regulatory-preflight to recreate the measured
CPU-only Python 3.11/Torch environment from exact ARM package/wheel artifacts.
The default probe preserves Torch's initial quantized engine while requesting Sei's fbgemm
qconfig. It exercises a small untrained Conv1d+Linear, never a trained checkpoint.
See [SCI01](../research/2026-10-14-regulatory-feasibility.md) for actual results,
forced-engine failure, provenance and remaining trained-model/biological gates.

## CI

Local/CI share `make test`, `make science`, and `make experiment-soc`. The prepared
workflow uses a standard public-repository ARM64 runner, read-only token permissions
and public synthetic evidence only. Hosted run38587738514 passed these commands
for implementation commit a27221c6f2174ea9d116779fcd47c88f9794dddb via the PR merge
revision. Its downloaded artifact/checksums and fresh native metrics were checked;
see evidence/20261014T151621-665108Z-hosted-ci/public/hosted-ci.json.
The workflow does not run the separately recorded local Compose/Firefox suite.
Runner policy: [GitHub documentation](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

## Security event acceptance

`make experiment-soc` includes the original synthetic milestone and real protected
worker rejection/outbox/HTTPS-relay/responder acceptance. Native receipt
`evidence/20261014T165148-344656Z/public/` passed22 assertions. The new four-service
container receipt `evidence/20261014T164550-385353Z-reviewer-compose/public/`
passed30 controls with a private outbox mount and worker network none.

To verify the optional responder container using that retained native event:

```bash
python3 -B biozero/infra/soc/run_container_response.py \
  --source-manifest /absolute/path/to/native-run/manifest.json \
  --event /absolute/path/to/native-run/private/data/security-events/evt-ID.json
```

Pass `--docker-command 'sudo -n docker --host=unix:///var/run/docker.sock'` only if
the local daemon requires that authorized prefix. The harness builds and runs
only ZeroResponder in a unique project, verifies the passed native parent/result
and event hashes, TLS/authentication/restart receipts, scoped keys and container
controls, and removes its own project. It runs no pipeline or trained model.
The executed receipt `evidence/20261014T165334-020175Z-soc-container/public/`
passed13 assertions and cleanup. Share public/ only; secrets and source linkage
remain private. No live firewall, certificate or quarantine action is implemented.

## Metadata and lifecycle acceptance

`make experiment-soc` now also enables `--metadata-faults`. With existing locked
tools, run:

```bash
make experiment-soc BIOZERO_TOOLS_PREFIX=/absolute/path/to/verified-tools
```

The fresh native runtime tests exact projected metadata admission/terminal
readability, one byte over/cleanup, nine unsafe spool fixtures, owner-before-result
denial and continued new worker progress. Faults are created in fresh paths and
removed only by matching inode/device; originals are retained. Public reports
contain fixed observations, never sentinels/raw metadata/credentials. Receipt
`evidence/20261014T175423-175221Z/public/` passed53 checks with8 checksums.
Separate rebuilt Compose `evidence/20261014T175423-180461Z-reviewer-compose/public/`
passed30 controls and cleanup; it did not repeat Firefox. Shared54-case vectors
run in both Go modules under `make test`; foreign UID fixtures skip for non-root
and have a separate root-only receipt, not a root-service deployment. See the
[metadata contract](../security/metadata-contract.md) for limits and residual gates.

## Retained-input and command-output acceptance

`make experiment-soc` now selects `--soc --metadata-faults --output-cases
--admission-cases`. Use an existing verified prefix rather than acquiring tools
again for a documentation/evidence review:

```bash
make experiment-soc BIOZERO_TOOLS_PREFIX=/absolute/path/to/verified-tools
```

The additional native cases exercise principal/global retained-job accounting,
terminal charges across uploader restart, second-instance exclusion and
missing/corrupt-ledger startup failure. Protected uploads also exercise excessive
pipeline/evaluator output, cleanup of descendants/plaintext and preservation of
crypto/hash/ownership while science remains withheld. See the
[admission contract](../security/admission-contract.md) for exact policy,
streaming/ledger boundaries and separate serialized-result limits.

Pre-correction receipt `evidence/20261014T190933-375408Z/public/` passed78 checks;
local `make test` passed 86 Python tests/seven Go modules for that working-tree
snapshot. The related Compose run
`evidence/20261014T190933-378316Z-reviewer-compose/public/` failed after 10 checks
at prepared submission and cleaned up. Publication across separate bind mounts
returned `EXDEV` despite equal device IDs. The correction stages payload/job data
inside each destination mount and keeps admission's ledger/lock separate; it
is now covered by the fresh source-specific acceptance below. Legacy admission staging fails closed without
silent adoption. Do not call the failed run
passed or apply its earlier native PASS to a corrected source automatically.
Those failures justified one new acceptance snapshot; they are not relabeled.

Corrected receipt `evidence/20261014T192150-539678Z/public/` passed 78/78.
Rebuilt four-service `evidence/20261014T192150-561120Z-reviewer-compose/public/`
passed 30/30 and scoped cleanup; fresh `make test` passed 86 Python tests/seven
Go modules. The separate actual three-bind-mount publication/restart receipt
`evidence/20261014T192234-593374Z-admission-mount/public/` covers only that storage
regression, without TLS/inference. The browser and optional responder profile
retain their earlier separate source receipts; they were not repeated here.
Final independent review approved 32 selected exports. Native's seven hash
differences were docs-only; Compose matched 34 runtime hashes/five checksums.
This local record was written before publication/new hosted CI; consult the
live PR for the subsequent head/checks. Preserve every dated source snapshot
instead of applying old PASS/CI to later changes.

The input ledger retains charges; there is no automatic quota release on worker
completion, TTL, eviction or policy reset. Missing/corrupt accounting over existing
data must fail closed rather than create an empty baseline. Do not delete a ledger
or change a pinned policy to unblock admission. Default retained-job caps are
64 global/16 per-CN, input-charge caps 512/128 MiB and active streams two/one;
the free-space floor is a 128 MiB sensor. Certificate renewal shares its CN quota
but does not override the certificate-serial authorization of existing jobs.
Artifact/reference copies,
results/events/receipts/registry totals, cache and retention remain outside this
input/capture subgate; a free-space sensor is not a hard disk quota.

## Biological-source review without another acquisition

Review the recorded [small-source acquisition](../../research/regulatory/small-source-acquisition.json),
[structure](../../research/regulatory/small-source-structure.json) and
[primary-source investigation](../research/2026-10-14-small-caqtl-sources.md).
They establish cached source bytes/digests and descriptive structure, not prediction
cases. The gzip (10,497,915 bytes) plus README (5,043 bytes) fit the 50 MiB dataset budget;
the retained dataset charge is 10,512,921 bytes including the earlier control.
Do not reset the ledger or download the 35.6 GB archive. Checkpoint accounting is a
separate preserved ledger; no new model execution is part of this review.

Before scoring, review and freeze exact header/dictionary mapping, GRCh37-to-hg38 and
REF/ALT/strand correspondence, focal peaks/context, ties/duplicates, splits and
training overlap. Freeze normalization and selection, then obtain the actual
ten-locus adapter receipt before 100 separate evaluation loci. CRC-checked 297,308
source rows and technical SNVs are descriptive denominators, not completed cases.
Zero biological loci have been inferred. The exact Synapse/DARTv2 access403 remains;
the small Zenodo source is a separately reviewed alternative.

## Explicit owner-v1 native execution

Follow [worker configuration](../../services/enclave-runner/README-owner-worker.md)
and [broker genesis](../../services/artifact-executor/README-owner-broker.md).
Pin the broker profile before authority genesis, then provision its exact scope;
initialize fresh broker and worker custody explicitly. Preserve exact worker config
bytes across Open. Historical protocols and Results/Gateway remain separate.

With UID/GID1000, compatible Linux namespaces and an existing verified tool prefix:

```sh
python3 -B biozero/infra/native/run_owner_worker.py   --run-dir /absolute/private/new-owner-acceptance   --tools-prefix /absolute/existing-tool-prefix
```

The run directory must be new. Eight executables are built offline, including the
independent payload inspector. No tools/images/models/data are downloaded. Private
short-path runtime roots, bins, synthetic credentials, ledgers, journals, receipts
and logs remain retained; only owned Popen processes receive signals and Wait.
No Results API is launched and the worker cache is not release authority.

After a fixture-only correction, explicit `--reuse-build-report /absolute/private/original/report.json`
can verify/copy the original eight bins into a new run. It requires identical
complete initial/final Go/module inventories, exact hashes/sizes/UID/mode/link
counts and stable source metadata before/after copy. Original build logs, report
SHA, dirty commit and failed status stay recorded. Failure does not fall back to
compilation. This never adopts old stores, journals, stages or execution history.
A production/source change needs its own build and acceptance.

The [recorded owner acceptance](../evidence/20261015-owner-worker-execution/public/README.md)
passed53native controls and96independent readback controls; final local make has
one test-only keyed-literal delta from the runtime snapshot. This is same-host
synthetic SNP presence, not owner Compose/browser/cloud/image reproduction or
clinical accuracy. Old interrupted/failed acceptance directories stay preserved.
V3 lifecycle faults and full Results/Gateway/deployed isolation remain pending.


## Owner-v1 HTTPS Results acceptance

Follow the [Results/reader contract](../security/ownership-results-contract.md).
The separate `cmd/artifact-owner-read-broker` wrapper seals both listeners in its
producer profile; initialize fresh authority genesis, broker and worker histories.
Results configuration includes only TLS, external authorization pin/scope, signed
inbox, reader and projection policy, without legacy spool/Store or decrypt/signing
keys. The first native policy requires the same UID and private directories.

```sh
python3 -B biozero/infra/native/run_owner_worker.py \
  --results \
  --run-dir /absolute/private/new-owner-results-acceptance \
  --tools-prefix /absolute/existing-tool-prefix
```

The opt-in builds nine executables offline and verifies real mTLS, protected
three-SNP/invalid science, independent dedicated receipt FD readback and HTTPS
projection, owner/signature/job/cache negatives and unchanged five-history
snapshots/charges after clean Wait. Cache substitutions happen only after stopping
the worker publisher. An explicit `--reuse-build-report` may verify/copy exactly
nine Results binaries with identical Go/module inputs into fresh state after a
harness-only correction; the historical eight-worker-binary set is incompatible.
No fallback compilation, history adoption/reset/refund or deletion is permitted.

The [retained Results evidence](../evidence/20261015-owner-results/public/README.md)
records83 native controls, separate independent/race/make checks, exact source
attribution and original failed attempts. Native same-UID acceptance is separate
from component RST/EIO/stale-guard fixtures, maximum load, deployed isolation,
Gateway/UI and complete V3 lifecycle/reconciliation acceptance.

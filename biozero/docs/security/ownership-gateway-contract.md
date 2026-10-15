# Owner-v1 Gateway and browser contract

This contract covers the explicitly selected owner-v1 reviewer Gateway and its
three-asset browser UI. It extends the [ownership decision](../decisions/004-authenticated-ownership.md),
[durable client](ownership-client-contract.md), [delivery](ownership-delivery-contract.md)
and [Results/reader contract](ownership-results-contract.md). The
[requirements](../requirements-and-gates.md) and [threat model](threat-model.md)
retain the wider project and deployment gates.

## Trust and selection

The operator, host, Gateway and configured individual reviewer keys are trusted.
Administrative access codes grant browser access to this custodian; they are not
cryptographic delegation from a browser. Exact leaf fingerprints authorize
upstream work. Reviewer labels, certificate CN/serial and forwarded headers do
not grant ownership. Compromise of the Gateway can expose all configured
reviewer capabilities.

`BIOZERO_REVIEWER_PROTOCOL=owner-v1` and `BIOZERO_OWNER_REVIEWER_CONFIG` select the
new route before legacy reads or directory creation. Unknown/mixed selection or
invalid owner configuration fails without legacy fallback. `--init-owner-gateway`
creates exclusive fresh state; default serve validates existing history. It does
not adopt legacy registries, shared signer/nil-AAD submissions or legacy Results
DTOs. The [reviewer README](../../services/reviewer-gateway/README.md) lists exact
configuration fields and the separate legacy interface.

The [config loader](../../services/reviewer-gateway/owner_gateway_config_linux.go)
uses a closed schema, bounded measured assets, no-follow traversal and private
current-UID directories/files. State cannot overlap assets. Fixed HTTPS origins,
server names, CA pins, exact reviewer leaf/key pairs, recipient public key,
external authority pin/scope, mode/profile and projection policy are loaded once.
The first native listener is loopback TLS1.3/HTTP1.1 and uses the current UID.
Browser, reviewer and recipient public-key roles cannot be reused.

The complete config hash differs from the durable execution context. The latter
binds state, backend trust, authorization, reviewer IDs/fingerprints and prepared
input/reference facts; it excludes display/access-code/admission/UI settings.
A changed execution context cannot relabel prior history. Produce the execution
profile before authority genesis, then supply the external genesis scope. Scope
is not fed back into that producer profile hash.

Prepared input/reference plaintext is legitimately held by the Gateway as an
operator snapshot. The Gateway needs no worker decrypt key, authority signing
key, Store/spool mount or broker socket. Results trusts its own separate signed
inbox and dedicated read channel. The native fixture explicitly provisions
already-signed acceptance into that inbox; an automatic/deployed publisher and
its constrained identity/writes/failure lifecycle remain unverified.

## Durable mutation and recovery

Before upstream mutation, an intent records immutable reviewer/credential,
experiment/input/reference/context, request nonce, run identity and retained-byte
promise. Duplicate reviewer/request/experiment returns the existing run before
queue-capacity checks; a changed experiment conflicts. No duplicate reservation,
encryption, finalization, upload or charge is inferred from a lost browser reply.
Only a fresh intent from this process may dispatch.

The server owns a 150s operation context, independent of browser cancellation or
logout. Mutations use the shared durable ClientOperation/ClientDelivery APIs:
reservation, one owner-AAD preparation, finalization, verified acceptance and
transport delivery. Each component retains its own intent before uncertain
network attempts. RunView exposes the job ID only after signed acceptance has
been durably bound.

Operation/transport `phase` and Results `commit` are separate axes. A committed
observation never upgrades an uncertain delivery to delivered, clears its error,
refunds retention or proves peer receipt. Upload transport ACK is not scientific
approval. Browser response failure is not an execution ACK.

Cold Open validates child state and sidecars without dispatching, reserving,
preparing, finalizing, delivering or invoking recovery. Cold/error nonterminal
runs remain `needs_operator`; a known signed job may be queried read-only when
custody is valid. Unknown/torn directories or incompatible child states reject
without reset, adoption, relabeling, hidden GC or refund.

`ClientOperation.Check` and `ClientDelivery.Check` inspect custody without network
or phase advancement and use nonblocking mutex acquisition. Busy is temporary,
not checked health, absence or storage corruption. Gateway checks must not wait
behind a child's potentially 45s upstream mutation while holding shared
authority. This does not promise a hard kernel-filesystem deadline.

## Session and release boundary

Cookies are Secure/HttpOnly/SameSiteStrict, with exact Host/Origin, separate CSRF,
bounded sessions/rate maps and a fingerprint-bound session epoch. Private output
holds session mutex → Store mutex through the actual bounded write. Current-run
responses are built under that guard; Results is released against the exact
observed row after local commit persistence. A replaced/expired session cannot
release an earlier owner's private body.

The healthy original registry and signed acceptance authorize the exact
reviewer/job before any Results request. The individual mTLS client checks the
closed Results DTO against acceptance, input, ciphertext, mode/profile and
projection policy. A commit is persisted before release, and a conflicting
terminal observation fences local authority. Unknown/foreign runs or jobs return
404 without a private tuple or upstream discovery query; storage faults remain
503 rather than becoming evidence of absence.

Browser read/write cancellation and disconnects stay local: they do not poison,
reserve, cancel, reconcile, refund or ACK broker execution. Genuine local history
faults fence Gateway admission/release and preserve custody. Shutdown stops
admission/dispatch, cancels owned contexts, joins HTTP/Serve and operation
workers, then closes healthy custody/transports. The first close error persists;
an uncertain delivering child or incomplete drain does not release lifetime raw
locks to make shutdown appear successful.

The browser DTO is a typed subset of authenticated Results, not an offline
signature/attestation proof. It carries acceptance and opaque custody hashes,
selected pipeline counts/hashes/stage codes, aggregate detection categories and
scientific metrics. Raw captures, paths, target lists, signals/vectors, cipher/key
bundles and arbitrary diagnostics are excluded. Evaluator error text becomes
`scientific_evaluation_failed`; no legacy evaluator provenance is fabricated.

`pending/withheld`, failed/incomplete/succeeded execution and
`evaluated_passed/withheld/unassessed` release stay distinct. Stats succeeds
unassessed without variant evaluation or alignment. Null precision/recall is
rendered as “Sin evaluar”; missing counts never become zero. Synthetic normalized
SNP allele presence does not validate genotypes, indels, WGS or clinical accuracy.

UI session/poll generations guard asynchronous rendering, including initial
session recovery and delayed prior-owner replies. Separate simultaneous
reviewers need separate browser profiles. Automatic synchronization of identity
across every open tab, MFA, self-service recovery and certificate migration are
not established.

## Bounds and evidence

| Resource | Implemented bound |
| --- | --- |
| Browser connections / handlers | 8 / 4 |
| Sessions / login peer-rate entries | 100 / 1024 |
| Session expiration | 30min idle / 8h absolute |
| Login / new run / poll rates | 10 per real peer IP / 5 per reviewer / 120 per reviewer per minute |
| Active operations | 2 global / 1 reviewer; 150s owned budget |
| Retained runs | 64 global / 20 reviewer; noncommitted promises also restrict admission |
| Registry / replacement | 1MiB each |
| Signed acceptance sidecars | Up to 64 × 64KiB |
| Logical retained promise per run | `2*(10MiB+16) + 8*96KiB + 64KiB` |
| JSON POST / configured headers | 4096 bytes / 16KiB |
| POST body / final write callback | 5s / 5s |
| Results body / client timeout | 16MiB / 30s |
| Config / cert and CA / private key | 1MiB / 256KiB / 32KiB |
| Recipient public key and policy / UI asset | 64KiB / 256KiB |
| Prepared inputs / experiments | 10MiB per input/reference; up to 16 pairs |

The logical promise includes two encrypted copies and client metadata. It is not
physical allocated bytes, RSS or an available-space guarantee. Component resource
checks and small native runs do not establish simultaneous maximum-load behavior
or arbitrary kernel I/O deadlines.

The [public evidence](../evidence/20261015-owner-gateway/public/README.md) separates
variants 116/116 from stats 67/67 and the 824-control retained-evidence audit.
Each native run records seven own service instances Wait0, including Gateway
restart, plus private Firefox cleanup and history/charge checks. The runs share
10 executable byte pins and 188 Go/module inputs; their full source snapshots
differ by one Python fixture file that derives stats rules without a panel.
Original variants 36/37, stats setup 9/9 followed by config failure, and failed
build preparation remain failed receipts, not successful science.

Build provenance is nine verified original executables plus one rebuilt Gateway.
The original build pinned Go executable/version and build metadata, but not the
entire historical GOROOT/compiler or external certified FIPS source tree. Later
closure checks measure/recheck current selected inputs and permit only the exact
standard-library FIPS version identified in that metadata; they do not establish
historical tree immutability or FIPS certification of BioZero. All ten are not
claimed to have been compiled from the final snapshot.

Same-host/same-UID native acceptance is separate from component RST/EIO/guard
fixtures, Docker/Compose owner execution, maximum load, deployed role/key/mount/
network isolation, multi-worker/instance admission and complete active-job V3
failure/recovery. Legacy interface weaknesses and these remaining requirements
keep TM-02 open globally. See the [runbook](../runbooks/reproduce.md) for exact
cached-tool commands and [STATUS](../STATUS.md) for source-specific checks/CI.

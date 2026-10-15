# Authenticated ownership across upload, execution and release

Date: 2026-10-15. Status: selected direction; implementation in progress.
Source: TM-02 in the threat model and the required per-client authorization gate.
This decision does not mark TM-02 complete or change existing deployed interfaces.

## Problem and required guarantee

Current Results API authorization reads client_id and certificate serial from
mutable jobs JSON. A writer with access to that spool and a valid second client
credential can change the first job's owner without changing signed ciphertext.
The result reader then returns raw result JSON after matching only its job ID.
A separate immutable owner record alone would leave two substitutions open:
replaying captured ciphertext/encryption metadata as a new second-client job, and
copying first-client result data into the second job while relabeling its ID.

The protected path must deny all three substitutions through both direct client
and reviewer gateway access. The guarantee includes a compromised upload service
or a writer confined to the upload/job/result spool, plus a valid other client
credential. Host/root, CA, ownership authority, execution broker/coordinator,
worker/verifier, Results API and reviewer gateway remain trusted unless a separate
threat model removes that trust. Worker/Results remain trusted for plaintext
handling and projection; owner authority stays outside their writable state.
Container mounts or the same host UID alone do not establish this separation.
Availability and trustworthy science against a compromised execution authority
are separate requirements; an owner signature is not a scientific approval.

## Observed baseline

A private synthetic fixture copied the current Results API sources at 77a4e03
and exercised the actual handler over HTTPS/mTLS with two CA-verified client
certificates. In one case, the second client received 403 before the mutable
owner fields changed and 200 afterward, while result bytes stayed unchanged.
In the second case, changing only a copied result's job ID released the first
client's synthetic marker to the second, despite its original certificate serial
and upload hash remaining in that result. Both controlled cases reproduced the
weakness; neither is a passing security rejection test or a remote attack.
No genomic analysis or deployment ran. The retained private summary SHA-256 is
`cc7b7b6de84f5e1fdfd447b85fa27ea9ab325f0057fd06a5c8e51e1906152387`.
A full ciphertext replay through the worker was not executed by this fixture;
the current nil-AAD calls and resulting protocol gap were separately inspected.

## Selected trust boundary

Introduce a separate ownership/admission authority with its own mTLS endpoint,
private signing key and durable registry outside upload/worker writable mounts.
Clients contact it directly for Reserve and Finalize; the upload service is a
transport and mutable lifecycle writer, never an authority for caller identity.
An RPC that accepts owner/CN/serial assertions from upload is forbidden. A signing
key or shared authorization secret held by upload would preserve the original
attack and does not implement this decision.

The authority derives identity only from the verified TLS client leaf/chain.
Its public key, authority identity, accepted mode and execution profile are pinned
by trusted configuration. A key named inside an incoming object does not become
trusted. Authorization binds the exact client leaf fingerprint; certificate
rotation/enrollment requires a separate explicit procedure, not a same-CN fallback.
Principal quota aggregation remains within the configured CA/enrollment namespace;
serial changes must not create fresh independent quota buckets.

## Required protocol and immutable facts

1. Reserve authenticates mTLS and durably reserves principal/global slots and
   conservative input/body/metadata bytes before any large body is read. The
   authority generates an unpredictable job ID and fresh nonce; callers cannot
   choose another job's identity. The immutable signed challenge binds authority,
   job, nonce, client credential, original filename, encryption algorithm, pipeline
   mode and fixed execution profile, plus its short acceptance window.
2. The client verifies that challenge against the external authority pin and its
   own credential. It uses the exact canonical challenge context as AES-GCM AAD.
   Its individual mTLS RSA key signs a domain-separated manifest binding that
   context to ciphertext SHA-256, exact ciphertext bytes and wrapped-key envelope
   SHA-256. The shared demo signer is not authority for this protocol.
3. Finalize derives the same client identity from its own real mTLS connection,
   validates challenge and client signature before reading ciphertext, then
   measures actual bounded ciphertext bytes/hash. It must not sign a checksum
   declaration supplied by the upload service. The eventual file transport must
   verify regular read-only descriptor provenance and bounds; a generic Reader
   helper is not a filesystem or deadline authority.
4. The authority seals the original owner/job/nonce binding once, with a durable
   accepted time and exact verified manifest/input facts. A conflicting finalize
   cannot overwrite it. A lost response permits exact readback, never a second
   creation or a changed owner. Challenge freshness controls initial acceptance;
   it does not retrospectively expire accepted historical execution or custody.
5. Worker verification obtains that accepted authoritative binding before decrypt
   or execution. It checks the actual input/envelope and reconstructs the exact
   AAD for GCM authentication. Re-signing captured first-client ciphertext with
   a second valid key does not authenticate it under the second job's AAD.
6. The broker validates the same accepted job/input/profile binding before first
   execution admission and during recovery. Its retained manifest/receipt ties
   execution facts and exports to that authority record. Existing committed
   journal history is never silently relabeled or upgraded.
7. Results authenticates the reader against the immutable owner before reading
   private outputs, then projects from a confirmed broker receipt/manifest through
   a fixed trusted reader channel, or verifies the complete response against a
   separately authenticated final record. Comparing mutable result strings for
   job ID/upload hash is insufficient. Mutable jobs/results become lifecycle
   caches or notifications, never release or ownership authority.

The initial protocol component uses fixed version/domain separation, bounded
strict JSON and a pinned Ed25519 authority signature; client proof is RSA-PSS with
SHA-256 and the same verified 2048–4096-bit leaf key. It has no legacy/demo parser
fallback. Exact serializations and algorithm names belong to its versioned source
contract, not loosely equivalent JSON or caller-selected algorithms.

## Persistence, budgets and migration gates

Reserve must retain its maximum charge across crash, transport loss, partial
publication, ambiguous fsync/close and unknown execution state. The authoritative
registry must enforce bounded records, cardinality and replacement overhead with
exclusive writer locking, no-follow anchored files and explicit durable ordering.
Retention or a terminal status is not permission to refund unknown reservations.
A pure signature/Reader implementation does not establish these properties.

The Linux library Store now implements exclusive fresh genesis, externally pinned
StoreID/policy, pre-body reservations and signed strict ledger transactions.
Exact accepted retries preserve original signed bytes without reading a new body.
Reading or retained transaction evidence blocks cold Open; unknown history is not
adopted. Full charges and slots survive rejection, acceptance and process death.
A sticky live writer retains a raw CLOEXEC flock descriptor until actual process
exit, including when Go handles are lost. See the
[Store contract](../../services/ownership-authority/README.md) for budgets and
the intent-unlink/parent-sync crash boundary. A separate Linux HTTPS/mTLS service
now exposes Reserve/Finalize/readback with pinned private configuration, bounded
ingress and delivery-failure fencing. Actual TCP RST, writer exclusion, confirmed
process death and cold replay are verified locally; the separately compiled CLI
passes explicit genesis and two clean serving restarts. Deployed key/mount
isolation and end-to-end consumers remain to be constructed.

Acceptance time records the verified decision, after elapsed preparation and
reading, within the challenge and leaf validity windows. Signing/commit follow
and are not asserted to finish before expiry. Historical verification requires
the external pin and Store scope and revalidates the original leaf, challenge,
manifest and every binding field; it has no caller-selected historical clock.

The existing upload admission contract reserves before body reads. Integration
must preserve that invariant while moving owner authority outside upload. It must
not let upload pick an arbitrary principal for fresh quota. Client/gateway shared
accounting and certificate renewal need causal tests on the integrated route.

Old jobs without an authenticated authority record are unverified on the new
protected path. Never enroll them from jobs.ClientID, the reader's certificate,
worker custody or a guessed public key. Explicit reviewed migration and retention
must preserve originals and historical charges. Do not rewrite accepted fixtures
or claim their old results demonstrate the new protocol.

## Deliverables and acceptance dependencies

| Deliverable | Required evidence | Status |
| --- | --- | --- |
| Cryptographic protocol component | Real TLS identities; strict parser boundaries; same-leaf signatures; ciphertext exact/+1 checks; invalid authorization rejected before Reader.Read; altered AAD fails actual GCM Open | Verified protocol/authority; explicit CLI/upload and worker/V3 broker have separate retained acceptance; Results remains pending |
| Durable authority Reserve/Finalize/readback | Actual restart and injected transaction failures; retained charges; immutable owner; concurrent final-slot/duplicate-finalize behavior; no implicit legacy adoption | Linux Store and HTTPS/mTLS authority implemented; local RST/death/replay and separately compiled CLI verified; deployed isolation and consumers pending |
| Client and gateway integration | Both use direct authenticated authority sessions, per-client signing and exact context-bound encryption; shared admission and cross-client replay denied | Shared client and direct CLI/upload preserve authoritative ID with retained acceptance; Gateway/shared-route acceptance pending |
| Worker and broker integration | Accepted owner/context checked before crypto/execution; actual ciphertext rebinding rejected; recovery keeps original registry/lease/charges | Explicit owner worker/V3 broker native53 and independent96; query-only recovery component tested; actual V3 fault/restart acceptance still pending |
| Result delivery and release | Direct and gateway owner reassignment denied; relabeled private result cannot be released; trusted receipt projection and nonowner denial before private read | Pending |
| Reproducible protected acceptance | Pinned services, local/Compose crypto/science/lifecycle regressions, independent retained-evidence review and source-specific CI | Owner native53/independent96 verified; original eight builds reused after exact checks; owner Compose/lifecycle/deployed acceptance remains pending |

The [durable client component](../security/ownership-client-contract.md) now
persists original operation identity before Reserve, exact encrypted payload before
Finalize and its own finalizing intent before the network call. Recovery only
queries the known job; ambiguous preparation/IO is retained. It fixes the actual
OAEP44/empty-label envelope and mandatory GCM AAD framing for consumers. This does
not activate historical clients automatically. The explicit owner CLI/upload now
preserves the signed job ID; the gateway still persists runs after upload and
requires its own adapter.
Local unit/process tests are not deployed key isolation or protected execution.

A component milestone cannot close the requirement. The complete gate needs the
same-job owner rewrite, cross-owner new-job ciphertext replay and result relabel
negative cases, alongside successful owner execution/readback and fault recovery.
No raw DNA, private results, credentials, case identifiers or ownership registry
entries belong in public evidence; publish reviewed aggregate verdicts and hashes.

## Explicit owner-v1 delivery increment

The direct CLI and separate upload service preserve the authority-signed job ID
and retain full local transport promises before ciphertext reads. A lost reply
recovers only by known-job GET. The transport receipt cannot replace signed owner
context or a committed execution receipt. Configuration includes external public
pin/scope and TLS assets; it has no signing/decrypt-key enrollment field. See the
[delivery contract](../security/ownership-delivery-contract.md) and
[source-bound acceptance](../evidence/20261015-owner-upload-delivery/public/README.md).
The [owner execution contract](../security/ownership-execution-contract.md) now
records independent worker/broker binding and private receipt projection. Gateway,
authoritative Results release and deployed isolation remain required. The historical protocol is explicitly selected separately.

## Owner execution increment

The explicit worker/V3 broker route passed [native53 and independent96 controls](../evidence/20261015-owner-worker-execution/public/README.md).
The worker verifies actual envelope/body/AAD before Stage/custody/Submit; broker
verifies signed canonical acceptance on a second FD before Reserve, trusting the
worker for authenticated plaintext facts. Fresh B acceptance over copied A bytes
was delivered and rejected without new execution state. Existing Results/Gateway
routes remain outside this verified scope. The complete substitution/release and
V3 fault gates above remain open; historical failures and charges are preserved.


## Owner Results increment

The separately selected owner-v1 Results endpoint now verifies the actual live TLS
leaf against external signed-acceptance pin/scope/job/profile before any broker
query. Its dedicated socket exposes status/receipt only, with no worker mutation
or ACK authority. Full status/receipt bindings must agree before shared receipt
projection. Actual [native83 and independent readback](../evidence/20261015-owner-results/public/README.md)
cover the same retained science, equal-label distinct-leaf denial and cache/signature/
job substitution negatives. The [contract](../security/ownership-results-contract.md)
separates local reader failure from trusted-storage custody fencing. The first
native policy remains same UID; Gateway, deployed isolation and integrated V3
fault/reconciliation scope still prevent closing TM02.

# Signed authorization publication contract

This increment provides a separate authorization publisher and durable sending
operation with canonical Upload schema2 integration. Fresh native CLI/Gateway
acceptance passed310 variants and216stats controls. Earlier [Gateway evidence](../evidence/20261015-owner-gateway/public/README.md)
explicitly used fixture provisioning; these components do not relabel it as an
automated deployed path. The [requirements](../requirements-and-gates.md) remain
the completion criteria.

The publisher relays an already-signed acceptance into its own authorization
inbox. Its configuration does not enroll authority signing, reviewer or decrypt
keys, a worker spool, artifact Store or execution socket. Native same-UID host
access is trusted; this configuration boundary is not deployed filesystem
isolation. Results keeps its existing
[read-only authorization and receipt boundary](ownership-results-contract.md).
The canonical producer is Upload, covering both direct CLI and Gateway
submissions with the same publication policy.

## Identity and protocol

Publication uses a dedicated service client certificate, separate from the
owner leaf inside the signed acceptance. The receiver requires verified TLS1.3,
HTTP/1.1, an explicitly configured producer CA and an exact allowed leaf DER
fingerprint. Its handler compares the actual connection with request TLS state
and rechecks certificate validity before reading the body. Forwarded identity,
certificate CN and serial cannot substitute for this check. A producer leaf
cannot publish its own acceptance as an owner. Distinct certificates carrying
the same RSA public key also fail this role boundary. The receiver retains the
actual producer DER fingerprint and public-key binding in its private intent for
cold validation. It is a relay capability for
valid signed records within one externally pinned authority/scope/mode/profile,
not permission to create ownership or approve execution.

Both methods use `/v1/acceptances/{job16}/{canonical_acceptance_sha256}`. POST has
one canonical signed acceptance, at most64KiB, with exact JSON content type;
GET is bodyless and names a previously known acceptance. The handler verifies
the signature and complete external binding before any mutation. A successful
response is one closed, at-most8KiB receipt binding the publisher's external
genesis scope, authority scope, job, canonical acceptance hash, owner credential,
mode/profile and `published` state. HTTP200 is used for both first publication
and exact duplicate. There is no list, discovery, arbitrary path, execution,
cancel, ACK or certificate enrollment method.

The client snapshots private key/certificate/CA material through the existing
validated transport constructor and exposes only Publish/Get/Close. It has its
own TLS1.3 maximum, HTTP1.1, closed receipt/content/encoding validation, no
redirects, four connections and30s deadline. It canonicalizes verified bytes
consistently for the path and POST. Each invocation makes at most one call;
`GetBody` is disabled and failed publication never triggers a POST retry.

## Receiver history and resource promises

Initialization creates a new private root and returns its external publisher
scope. Serving opens only matching existing history, with one raw lifetime
flock. Config pins state path, authority public verification material, authority
scope, mode/profile, sorted producer identities and resource policy. Changed
scope/context, unknown files and partial history reject without adoption.

The bounded global `catalogue.json` permanently records job, acceptance hash,
owner, first producer and retained charge. Its transaction marker and full
replacement precede rename and directory sync. The new catalogue promise is
durable before creating any per-job intent or output. Cold Open checks every
catalogued job against its retained operation and inbox copy. Deleting both of
those copies cannot silently reduce the reconstructed count. Consistent rollback
of the entire trusted host history is not prevented by this local witness.

Each job retains an immutable intent and published receipt under `operations/`;
its canonical signed output lives under `inbox/`. Files are private current-UID
regular0600/single-link snapshots with no-follow traversal and stable FD/pathname
identity and content checks. Directories are0700. Metadata never authorizes
executing work: only the authority-signed acceptance binds the owner.

The receiver reserves at most64 jobs globally and20 per owner leaf, including
retained or uncertain work. There is no expiry, refund, hidden GC or automatic
repair. A per-job logical promise covers a bounded intent,64KiB output and8KiB
receipt. The catalogue has a separate1MiB bound plus one1MiB replacement and a
small transaction marker; those global metadata bounds are separate from the
per-job charge. Physical filesystem allocation, inode quotas and maximum-load
behavior require their own acceptance. The HTTP service bounds eight connections,
four handlers,16KiB headers and5s body/final-write deadlines.

Exact duplicate publication returns the same retained receipt without modifying
files or adding a charge, including through another allowed producer. A valid
conflicting acceptance for the same job preserves both signed facts and fences
the receiver. Invalid signatures or unauthorized producers neither publish nor
poison healthy local custody.

## Visibility, acknowledgement and failure

An output is staged and fsynced, linked without overwrite, the inbox directory
is synced, the staging name is unlinked and that directory synced again. The
two-link interval is deliberately not readable by current Results, which requires
one link. A complete signed output with one link may authorize its exact owner
before the receiver persists its final private receipt or emits HTTP response.
Publisher acknowledgement does not define the start of authorization and does
not establish that any downstream peer received a response.

A fault after output visibility preserves the signed output, intent, catalogue
charge and raw receiver lock. Cold partial/torn history does not resume, erase
or republish anything. Once genesis and external scope identify retained custody,
a subsequent structural/storage failure keeps the raw lock until process death.
Already-valid signed files remain independently verifiable by Results; publisher
ACK loss does not create a global Results health dependency or revoke ownership.
A failed producer response write stays local after durable publication.

The sender writes an immutable intent before any POST and a publishing step
before its sole attempted POST. Only a fresh hot operation may start it. Cold
Open performs no network work. An unknown response remains publishing; explicit
recovery uses GET for that exact retained acceptance. Absence does not permit
resending or creating a new reservation. A verified published receipt is retained
before returning success. Check uses nonblocking mutex acquisition; busy is a
temporary condition, not healthy custody or corruption. Storage failures take
precedence over request cancellation. Pending/faulted Close retains raw custody
and its first error.

The sender context binds directory, endpoint, server name, producer leaf, external
authority and publisher scopes, acceptance and the trusted loader's measured CA
asset hash. That loader must actually verify the CA bytes: a caller-supplied hash
alone is not a measurement. Its three retained96KiB journal-step bounds and small
marker need explicit Upload accounting in addition to existing ingress headroom.

## Canonical Upload integration

Upload schema2 requires a dedicated producer certificate/key, receiver server CA
asset and external publisher scope. Schema1 retains its historical closed wire
shape, state context and charge. A schema2 service creates a fresh transport-spool
v2 root; it never migrates or adopts schema1 history. The loader measures the CA
asset bytes and rejects producer reuse of the Upload server key or owner CA.
Each signed submission also rejects producer/owner RSA key aliases.

The permanent Upload promise adds three96KiB publication journal steps plus a
64-byte marker to the previous body and metadata allowance. Both `reading` and
`authorizing` consume active admission slots. After hashing and syncing the
ciphertext, Upload captures the original FD identity before Close, persists
`authorizing`, and creates the child sender journal before its only POST. Network
IO runs outside the ingress mutex under a service-owned30s context. Request
cancellation does not cancel already-authorized publication; service shutdown
cancels and drains it.

An ambiguous response permits at most one hot GET for that known acceptance,
within the same deadline. No POST fallback, rejected-state conversion or refund
follows. Only the exact retained published receipt, fresh child history and a
fresh ciphertext inode/metadata/hash check permit signed-sidecar and lifecycle
job visibility. Replacing ciphertext with equal bytes on a new inode fails this
check. Publication authorizes metadata; copied ciphertext may publish under its
new signed owner and still fail the worker's GCM check without execution.

A live registered authorizing child may report temporary busy while its network
operation owns its own mutex. Delivered, unknown or unregistered busy children
fence ingress. Cold Open performs no network, rejects reading/authorizing before
opening children, retains the raw parent lock and never completes pending work.
Only already-delivered children are opened and matched to exact published receipts.
Pending Close preserves the first error and custody. This is component behavior;
native CLI/Gateway/scientific acceptance has separate source-bound receipts below.

## Evidence scope

Earlier receiver/client/service component race checks passed28 principal tests
and128 subtests. A separate sender race run passed11 principal tests and21 subtests.
The two source snapshots differ by the sender files. Tests use real TLS and
signed protocol fixtures, actual retained limits, response loss/RST and process
death/readback; no genomic execution is attributed to these component counts.
Process-death helpers exit without Close at controlled boundaries; they do not
prove arbitrary asynchronous interruption during every filesystem syscall.

The canonical Upload integration focused race run passed15 principal tests and7
subtests, including an actual PublicationService/Store/HTTP receipt barrier. The
subsequent full ownership-authority module race run passed156 principal tests
and583 subtests, with unchanged source hashes; it also covers historical schema1
and authority/client/service behavior. These are overlapping component scopes,
not additive native scientific/browser acceptance counts. Two v2-only temporary
descriptor Close-error guards were added between the focused and full runs.

The earlier catalogue decoder failure is preserved as failed evidence. The
receiver now uses the existing closed bounded ledger decoder, whose collection
support is capped at64 entries. Unknown/torn namespace, paired deletion, changed
snapshots, ambiguous publication and exact duplicate controls remain separate
from hosted CI or native scientific/browser acceptance.

Results currently requires its inbox UID equal to its own effective UID and
private0700/0600 permissions. Same-UID native automation cannot establish deployed
role separation. Different UIDs/read-only mounts require a separately versioned,
measured deployment policy; no chmod/ACL broadening is implicit here. Actual all-entry native acceptance now covers automatic publication for CLI and
Gateway, real Firefox, authority-signed acceptance and retained receipt
projection, and clean receiver/source
restarts. Three positive variant inputs, one invalid input and copied ciphertext
retain five publication promises; stats retains three. Each run joined eleven
service instances with Wait0 and unchanged publication history. Negative Results
controls use a separate fixture inbox after original Results Wait0 on the same
endpoint/TLS identity; they never mutate or restore the primary publisher inbox.
See the [aggregate and pins](../evidence/20261015-owner-publisher/public/README.md).
Physical/principal resource closure, deployed isolation, maximum-load acceptance,
active V3 faults/operator reconciliation and TM02 remain open.

# Owner-bound broker V3

`cmd/artifact-owner-broker` is a separately selected host service around the
existing Store, coordinator and configured native/Docker provider. It verifies
historical signed acceptance independently and binds owner and processed-context
facts to durable execution. It does not authorize a live Results reader or attest
a worker/host. Implementation/component tests are not new actual provider
acceptance. See the [execution contract](../../docs/security/ownership-execution-contract.md).

## Configuration and profile genesis

Build this command explicitly from the artifact-executor module:

```sh
CGO_ENABLED=0 go build -o /absolute/private/bin/artifact-owner-broker ./cmd/artifact-owner-broker
```

The closed private JSON config has exactly these required fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | `1` |
| `execution` | Complete existing [`BrokerServiceConfig`](README-service.md), including unused explicit empty fields |
| `authority_id` | Externally provisioned 32-hex authority ID |
| `public_key_hex` | Externally provisioned 64-hex Ed25519 public key |
| `expected_scope` | Exactly `{store_id,policy_sha256}`, external authority genesis |

Config is bounded 64 KiB, current-UID regular single-link mode 0600, with anchored
no-follow ancestry. Engine assets, executable/tool paths, mode/provider, policy,
UID and state roots keep their existing fixed-service validation. No private
Ed25519 signing key or RSA payload-decryption key is required by this broker.
Native requires a pinned helper and safe Python/tools. Docker requires the
allowlisted local daemon command, exact cached image ID and both helper pins;
requests cannot pick commands, mounts, images or new policies. No image is pulled
or built by service startup.

The owner profile hashes the domain `biozero.owner-broker.profile.v1`, protocol
version 3, existing engine-profile SHA, authority ID and public key. The engine
profile includes the same running service executable, complete execution config,
asset pins and fixed Store policy. Thus compute and serve with the same binary.
Authority scope is excluded from the profile to avoid a genesis dependency cycle;
it is still mandatory and matched in the V3 journal before serving.

Provision in this order:

1. Freeze binaries, public authority pin and complete execution config. Use new,
   separate Store/journal roots and existing validated parent directories.
2. Set `expected_scope` to `{"store_id":"","policy_sha256":""}` only while computing
   the profile.
   Run `artifact-owner-broker --config /absolute/private/broker.json --print-profile`.
   This validates assets/profile without state, provider, socket or Docker access.
3. Configure and explicitly initialize the authority with that exact profile and
   mode. Retain its externally pinned Store/policy scope; insert it into the broker
   config. Recompute the profile and require equality. Serving/init reject empty
   scope. Do not change other engine/pin fields or adopt another authority scope.
4. Initialize new broker history, then serve it using the same config/binary:

```sh
/absolute/private/bin/artifact-owner-broker \
  --config /absolute/private/broker.json --init-owner-broker
/absolute/private/bin/artifact-owner-broker \
  --config /absolute/private/broker.json
```

Initialization creates a new Store and separate owner journal without executing a
provider or opening a listener. Serving requires existing matching history and
opens its socket last. It cannot silently initialize missing history or import
V1/V2 journals. Configure worker/ingress/clients with the same authority scope and
profile; see the [worker recipe](../enclave-runner/README-owner-worker.md).

## V3 transport and retained facts

The Unix channel authenticates its configured peer UID and permits eight
connections, with fixed request/write bounds and separately bounded execution.
Strict JSON frames are at most 64 KiB with four-byte big-endian framing.
Submit carries exactly two read-only SCM_RIGHTS FDs: plaintext, canonical signed
acceptance. Plaintext is at most 25 MiB; acceptance at most 64 KiB. Hash/length,
regular/private/single-link metadata and exact FD cardinality are verified.
Status/receipt/cancel carry zero FDs and require acceptance SHA, with zero
processed/context query fields. There is no fallback to V2.

Broker verifies signature, external scope/profile, canonical acceptance bytes,
job/original-upload identity and credential; it preserves the signed envelope
hash. Actual OAEP/GCM decryption is the trusted worker's preceding responsibility.
Processed input/context is separately retained from the original ciphertext SHA.
It must match name/size and report successful decryption/signature with no crypto
errors. Canonical acceptance sidecars, owner bindings and contexts are committed
with the existing job-to-lease binding. Exact replays cannot change these facts.
A sidecar without corresponding history or a leftover publication is uncertainty,
not a fresh baseline.

The journal is at most 1 MiB; at most 64 acceptance sidecars of at most 64 KiB
plus one bounded pending publication are retained. Private metadata readers
reject symlinks, wrong modes/owners, extra links, ambiguous JSON and unknown names.
Lifetime raw lock authority survives uncertain Close/GC until process death.
These metadata bounds and the existing managed Store accounting are not a full
physical host or per-principal quota. No retention/refund/adoption is implemented.

V3 responses contain owner facts from the journal and the unchanged schema-2
execution response. A receipt operation returns the bounded read-only receipt FD
(up to 16 MiB), measured against committed SHA/length. Worker uses the shared
projector; Store commitment alone does not prove scientific approval. This socket
also permits Submit/cancel and must not be granted to a future Results service.
A dedicated receipt/status-only reader channel remains a separate requirement.

## Lifecycle and scope

SIGINT/SIGTERM stops channels and requests cancellation; the service waits for
broker/provider completion before closing healthy authority. Pending work,
failed ACK, unsafe socket or storage/provider uncertainty produces an error and
retains history/charges. Process exit is not permission to delete a stale socket,
replay a Submit, refund storage or adopt workspace remnants. Explicit operator
reconciliation and separate fault acceptance are still required.

Preserve old V2 receipts as historical evidence. New V3 native/Compose/Docker
acceptance, deployed key/mount/network isolation, Results/Gateway ownership,
full image/tool build closure, physical quotas, hostile-host resistance and
hardware attestation are not established merely by this command or its tests.

## Source-specific native evidence

[Retained owner execution](../../docs/evidence/20261015-owner-worker-execution/public/README.md)
passed53native controls and96independent public-key-only readback controls. It
covers two three-SNP inputs, invalid FASTQ withheld, and copied ciphertext with B's
legitimate acceptance rejected without new execution state. Old weaker/failed
attempts and all charges remain. This does not close Results/Gateway, owner-V3
lifecycle fault, deployed isolation or full physical quota gates.

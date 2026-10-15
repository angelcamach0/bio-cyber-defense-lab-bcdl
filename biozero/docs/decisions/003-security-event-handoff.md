# Decision 003: durable local events before response enforcement

Date: 2026-10-14.

The original platform roadmap includes SOC telemetry and effective response.
The existing ZeroResponder stub could accept unauthenticated alerts when its
optional secret was unset and return success despite failed artifact writes.
Its block/revocation/quarantine lists did not demonstrate enforced actions.

We first establish a verified boundary from real protected-worker rejections to
durable, authenticated simulation receipts. This is a prerequisite; it does not
remove effective containment from the roadmap or represent production readiness.
No other host, network or account is targeted by the acceptance experiments.

## Chosen behavior

- The worker retains network isolation and no responder secret. It writes minimal
  local events only after a persisted protected security rejection; a separate
  relay owns HTTPS delivery and the shared secret.
- Results are the recovery source. Every worker cycle reconciles terminal results
  for missing events without reexecuting analysis. Outbox failures remain visible
  and retryable; they cannot promote scientific release or erase a result.
- Events retain immutable IDs/timestamps. Publication is file fsync, no-clobber
  hardlink and directory fsync on a local Linux filesystem. Consumers retain
  events and receipts; there is no automatic retention or disk quota yet.
- HTTPS verifies CA and hostname and refuses redirects. The responder secret is
  mandatory. Source is a validated claim of a secret holder, not an attested
  per-source identity. Non-loopback responder listeners require TLS.
- A responder receipt atomically holds the full request and all simulated actions.
  Exact retries return the same receipt across restart; conflicting reuse is 409.
  Persistence ambiguity latches admission/health unavailable, requiring operator
  repair and restart. Success explicitly says simulation and enforced=false.
- The responder writes no effective lists, changes no job state and performs no
  firewall or certificate revocation operations. The relay records a delivery
  only after a valid matching acknowledgment and its own durable local receipt.

## Limits and next requirements

This is at-least-once transport with idempotent response, not a distributed
exactly-once transaction or multi-worker queue. Local storage, the host and the
configured UID remain trusted. There is no independent tamper-evident audit store,
separate source identity, long-running relay service, global storage quota,
production SIEM integration, live containment or revocation checking. A privileged
writer or secret holder can forge claims within those trust boundaries.

Before live response, freeze harmless laboratory scenarios, target scope,
authorization/policy and rollback; prove actual containment and availability on
isolated disposable fixtures. Before publishing beyond loopback, resolve the
admission/storage, metadata integrity, key lifecycle and queue findings in the
[threat model](../security/threat-model.md). Keep real-world response and deployment
pending until those acceptance receipts exist.

The [event contract](../security/event-contract.md) defines the wire/storage
boundary; [SOC reproduction](../../infra/soc/README.md) defines commands. Only
executed receipts establish acceptance, and older four-service/browser receipts
do not prove this new path.

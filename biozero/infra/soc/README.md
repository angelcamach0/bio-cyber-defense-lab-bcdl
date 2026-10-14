# Local security events and simulated response

The protected worker writes a minimal private outbox for eight security rejection
codes. A separate one-shot Python relay sends one retained event over verified
HTTPS to ZeroResponder. The responder records simulated actions; it does not
block traffic, revoke trust or quarantine running jobs.

Read the [event contract](../../docs/security/event-contract.md) and
[threat model](../../docs/security/threat-model.md) before changing the boundary.
The relay authenticates possession of one shared secret, not a hardware-attested
source identity. An operator/compromised process with that secret can impersonate
the claimed source. Production identity, quotas/retention and live response remain
separate roadmap work.

## Reproduce the acceptance experiment

```bash
make experiment-soc BIOZERO_TOOLS_PREFIX=/absolute/path/to/locked/bio-tools
```

This runs the native synthetic success/failure experiment plus the actual worker
outbox, terminal-result recovery, TLS/authentication, durable simulation receipt,
responder restart/replay, changed-payload conflict, strict input and absence of
effective action artifacts. Native execution does not establish container network
isolation; the earlier Compose evidence covers its own worker/image snapshot.
Share only the new run's `public/` artifacts. Runtime keys, secrets, events,
receipts, raw results and diagnostics remain private.

## Deliver one retained event

```bash
python3 -B biozero/infra/soc/relay.py \
  --event /private/security-events/evt-IDENTIFIER.json \
  --endpoint https://127.0.0.1:8090/alert \
  --ca /private/pki/clients/ca.crt \
  --secret-file /private/webhook-secret \
  --receipts /private/security-deliveries
```

The secret file contains the exact ASCII secret, without a newline, with mode
0600; do not supply it in CLI arguments or publish it. Events are regular mode
0600 files with bounded exact schemas. Delivery receipts are mode 0600 in a mode
0700 directory. Events are retained even when transport or receipt storage fails.
The relay refuses redirects and HTTP, checks response digest/target and explicit
`enforced: false`, and acknowledges locally only after receipt persistence.
Retries still contact the responder and verify its durable idempotent response.

The optional Compose `simulation` profile now requires a secret and its scoped
TLS role. Generate fresh PKI with the updated generator before using that profile.
Set `BIOZERO_WEBHOOK_SECRET` privately (at least 32 bytes); never log Compose's
expanded configuration when it contains a secret. Worker outbox storage is mounted
separately and the worker retains `network_mode: none`. There is no continuously
running relay service or production SOC yet. Use the one-shot relay explicitly.

No automatic deletion, exactly-once distributed delivery, lease/queue, disk quota,
independent audit store, firewall integration or certificate revocation checker
is provided by this block. Operator repairs and retention must preserve receipt
integrity; idempotency requires retaining the responder's receipt.

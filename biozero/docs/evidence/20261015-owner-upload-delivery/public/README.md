# Owner-v1 delivery evidence —2026-10-15

The direct CLI and separate upload spool retain the authority-signed job ID.
Delivered means transport, not execution or scientific release. Full TM02,
worker/broker/Results/gateway integration and deployed isolation remain open.

Corrected focused checks passed ingress/delivery26 principal/109 subcases,
CLI11/18, selector2/3 and worker rejection1/2. Full race passed146 principal/543
subcases across three modules, including four authority-command tests; ten
explicit opt-in/helper tests were skipped. There were136 repository Go/module
inputs unchanged in focused/race/runtime. The standalone inspector is included
in that inventory but is compiled only by runtime acceptance.

Fresh native acceptance built four exact pinned executables and passed27controls:
real TLS1.3/mTLS with separate EKUs, trusted genesis scope, original signed ID,
exact ciphertext/OAEP envelope, independent GCM inspection under signed AAD with
changed-AAD rejection, A200/B403, and cold CLI query-only recovery. The owned relay
received upstream200 completely, then cut the downstream connection before HTTP
response bytes. Its observed CLI methods were exactly POST then GET. This is
client response loss; it does not prove upload ACK-write failure. A separate unit
fixture exercised actual upstream TCP RST/delegated write failure, sticky lock,
SIGKILL/Wait and cold replay. Those unit temporary directories were framework
cleaned; retained logs/pins do not make them retained runtime workspaces.

The real runtime acceptance retains its private binaries, synthetic credentials,
client journals, ciphertext, authority and upload ledgers and original logs.
Independent retained-evidence review passed57 controls using public-key-only
signature checks, source/binary/receipt/accounting/history readback; it did not
rerun acceptance or open private keys/plaintext. Both services exited zero on
SIGTERM/Wait with identical retained history. Each
single-record store kept exactly26,345,472 charged bytes; that is its logical
maximum-body promise plus metadata, not physical disk usage. No histories or
charges were reset/refunded and no unknown work was removed.

Final make passed294Python cases (292passed/two kernel opt-ins skipped) and
ordinary test/vet in nine Go modules. Its474-file snapshot is identical to the
runtime acceptance snapshot. Four status/requirements/decision/threat documents
and this public bundle were updated afterward; production/tests/reproduction
sources remain identical. No Docker/image build, capsule analysis, biological
model/dataset acquisition, deployment or scientific recomputation ran.

Failed/weaker attempts remain retained. Initial focused used a barrier on the
whole HTTP body, accidentally stopping metadata rather than ciphertext; the
corrected helper passes exactly the frame metadata before the causal barrier.
Initial make inherited the capture runner's077 umask, so two historical0644
negative fixtures became0600; correcting only the child mask to022 restored the
intended negatives. Source and original stdout/stderr hashes for all attempts
are in summary.json; no runtime source changed for that orchestration correction.

This allowlist contains only this README, summary.json, test-source-pins.json and
SHA256SUMS. Raw logs, private keys/configuration/paths, runtime IDs, DNA and result
rows are excluded. Test receipts are source-specific. See the
[delivery contract](../../../security/ownership-delivery-contract.md).

To reproduce on a prepared Linux host with local Go/OpenSSL and no downloads:

```sh
python3 -B biozero/infra/native/run_owner_upload.py \
  --run-dir /absolute/private/new-evidence --ack-loss
```

The parent must already exist. Keep the new root/private records intact, including
failed attempts. This uses synthetic inputs and same-host/same-UID fixture trust;
it establishes no production key/mount isolation or image dependency closure.

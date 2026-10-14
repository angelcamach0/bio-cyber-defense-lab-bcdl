# Execution status and scientific acceptance

Protected mode is the default. Complete TLS/mTLS is mandatory for APIs; verified
client CN and serial determine ownership. The worker requires signed, coherently
encrypted data and verifies the original upload hash before invoking analysis.
The signing key shared by demo clients is a fixture assumption, not a production
key-management policy.

`uploaded` and `running` are nonterminal. Terminal results are `succeeded`,
`incomplete`, `rejected`, `failed`, and `timed_out`. `succeeded` means required
pipeline stages and artifacts exist; a separate evaluator checks scientific
acceptance. Stats and variants have different mandatory outputs. Incomplete
dependencies, invalid input, cryptographic rejection and timeout remain distinct.

Historical `processed` is served as incomplete with `legacy_result_unverified`.
This preserves the record without granting it unmeasured scientific acceptance.
Original upload hashes/sizes remain unchanged; derived hashes are separate.
Interrupted running work becomes an explicit failure that requires resubmission.
The filesystem implementation supports one worker. Multiple workers require a
verified claim/lease or queue mechanism before being enabled.

The browser proxy certificate cannot identify individual users. Browser upload
and results access therefore remain restricted while CLI client isolation is
tested. User sign-in and principal propagation are a separate implementation gate.

CLI exit codes: 0 succeeded, 2 incomplete/historical, 3 failed/rejected,
4 timed out, 1 configuration/transport/protocol. The total wait deadline bounds
polling. No terminal state is presented as pending indefinitely.

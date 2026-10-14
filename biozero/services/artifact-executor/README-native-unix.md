# Actual native capsule over the Unix channel

Observed locally on2026-10-14, Linux ARM64 UID/GID1000, compatible host Python3.9
and the locked bioinformatics tools. The opt-in test composes the actual Unix
client/listener, Coordinator, InputRegistry, NativeProvider and durable Store.
It extends the [local provider acceptance](README-native.md); it still does not
install the provider in enclave-runner or exercise TLS/signature/decryption entry.
Original-upload identity is a synthetic placeholder, with separately verified
plaintext bytes. Peer UID is local host authentication, not tenant attestation.

## Executed assertions

Before execution, a real status request returns the registered lease in reserved
state without a manifest or provider invocation. A real run request executes the
three-SNP fixture inside the native capsule and returns a committed manifest.
An observer wraps the actual socket-write callback inside Coordinator.Acknowledge:
the private ledger is already committed, its charge is positive, four exports
exist, and retained manifest/proof hashes agree before the callback writes.
The proof reports capsule wait finished and export authority closed. The client
must read the full bounded frame and EOF; a marshal or local callback alone does
not count as a reply.

The retained execution_receipt's actual bytes match the manifest hash and contain
evaluation exit0/status passed, TP3/FP0/FN0 and precision/recall1. Observed, evaluated
and retained normalized VCF digests agree. Response schema/lease are checked; a
later status returns the same complete canonical manifest. Replaying the old
run/reference yields the server's sanitized artifact_handler_failed response,
not internal diagnostics. Provider invocation remains one, the ledger stays
byte-identical and no additional release write occurs. Host workspace anchors
are empty after the successful authoritative wait.

The final strengthened test passed with the race detector: body0.48s, Go1.505s.
Private root: `.biozero/native-unix-strengthened-acceptance-20261014/`.
Execution receipt SHA:
`548b0e1a5eb2ebcc1e6827862483006d2614d2ee7176b8f20021e49af23bb995`.
Private acceptance inventory SHA:
`9ccc7236543a22221911923f539d741cc89d93984fa6f2a71a32de177c434e51`.
Test source SHA:
`7ba285629c5f333ff272bf6a3f6b49454e303cb1465ac657cd20ebead47432fe`.
The inventory retains source hashes and all eight stored-file hashes. It is not
an externally attested receipt or a public export of raw pipeline data.

## Preserved failures and custody

The first test failed before provider execution because it used the storage
strictJSON parser for a response DTO with optional/pointer fields. The acceptance
decoder was corrected without changing runtime parsing or weakening storage
guards. Independent review also corrected the expected sanitized replay code.
That failed private root and its diagnostic remain retained. A subsequent passing
test predates the final explicit evaluator/status assertions and retains that
narrower scope in its own inventory; it is not promoted to the final source.

Opt-in fixtures are persistent private directories. Cleanup first cancels and
waits for the coordinator, then checks the real provider's Quiescent completion.
If that remains uncertain, the test fails while retaining keeper references,
Store/flock and evidence until process exit. It does not delete the fixture or
treat Coordinator.Wait alone as proof of capsule death. This branch is a guard,
not an independently injected uncertainty acceptance case. Provider crash and
restart observations are documented separately in README-native-recovery.md.

## Reproduction and limits

From the artifact-executor module on the prepared compatible host:

```sh
BIOZERO_RUN_NATIVE_UNIX_ACCEPTANCE=1 go test -race \
  -run '^TestNativeProviderActualUnixCommitBeforeReplyAndReplay$' -v -count=1
```

BIOZERO_NATIVE_UNIX_EVIDENCE_DIR selects a new absolute private directory; existing
destinations are refused. Otherwise an enduring private temporary fixture is
created. Default suites skip this opt-in and cannot establish actual capsule/wire
acceptance. The profile requires its real kernel/interpreter/tools and fails when
they are unavailable. It does not silently choose a weaker provider.

No protected worker integration, Docker capsule, clinical/genotype/indel/WGS
accuracy, authenticated immutable ownership, complete storage retention or
production deployment is established by this synthetic local channel test.

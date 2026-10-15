# Admission, retained inputs and command-output budgets

Date: 2026-10-14. Source: TM-01 and the adopted platform roadmap.
Implemented subgate; executed acceptance and remaining limits are recorded below.

## Scope and identity

All UploadAPI clients, including CLI and reviewer gateway, share durable global
and principal accounting for pending/retained inputs plus job-metadata headroom.
Worker terminal status and gateway registry loss do not release retained charges.
Principal is the canonical CN of a verified certificate in the configured CA
namespace. Renewal/serial changes share its quota; serial remains audited and
used for existing authorization. Check form client_id against that CN after
parsing; headers/IP/forwarding claims cannot select another quota. Protected
rate limiting uses the verified principal. Demo uses one unauthenticated bucket.

This is a TM-01 subgate, not a complete disk quota. SAM/BAM/BCF/VCF/reference
copies, result/event/receipt/registry totals, caches and operator retention still
need controls. Output-capture limits below do not bound those artifacts. Shared
host/UID remains trusted; TM-02 immutable owner provenance is not completed here.

## Policy

| Setting | Default | Meaning |
| --- | ---: | --- |
| BIOZERO_ADMISSION_GLOBAL_JOBS | 64 | Pending plus retained jobs |
| BIOZERO_ADMISSION_PRINCIPAL_JOBS | 16 | Same count per verified CN |
| BIOZERO_ADMISSION_GLOBAL_BYTES | 536870912 | Pending plus retained input charge |
| BIOZERO_ADMISSION_PRINCIPAL_BYTES | 134217728 | Same charge per CN |
| BIOZERO_ADMISSION_ACTIVE_UPLOADS | 2 | Global simultaneous body readers |
| BIOZERO_ADMISSION_PRINCIPAL_ACTIVE_UPLOADS | 1 | Same limit per CN |
| BIOZERO_ADMISSION_FREE_SPACE_FLOOR | 134217728 | Free-space sensor floor |
| BIOZERO_MAX_UPLOAD_BYTES | 26214400 | Whole multipart body cap |

Parse settings strictly; invalid/overflowing/nonpositive or unsupported values
fail startup. This first store pins its policy in the ledger: any change, including
lower limits, fails startup without rewriting charges/data. Reviewed policy
migration is pending. No automatic TTL/eviction/reset exists. Reserve
maximum body bytes plus 2x65536 job bytes before reading, including chunked bodies.
This is a conservative input accounting charge, not a hard physical ceiling on
all copies during concurrent worker replacements. Shrink to actual payload bytes plus that metadata headroom only after temporary
data is removed durably. A failed/below-floor sensor denies writes, but cannot
prevent other writers consuming disk; it is not a hard filesystem quota.

## Stream and store

Verify TLS identity and reserve active/jobs/bytes capacity before body reads.
A denied handler does not read the body; transport buffering is a separate issue.
Stream one file and only client_id, enc_alg, enc_key, sig_alg and sig fields.
Reject duplicates/unknown parts, multiple/missing files, more than seven parts
and aggregate field values over65536 bytes. Bound the whole body and its read
deadline. Preserve the exact projected lifecycle check/hash/size/crypto. Streaming
avoids ParseMultipartForm buffering/external temp files; multipart MIME headers
still have library allocations, so total request RAM is not claimed as64KiB.

Upload alone mounts <data>/admission: ledger.json and instance.lock. Payload and
job staging are private .biozero-admission-staging/<job-ID>/ directories within
the uploads and jobs mounts, respectively, with payload.part and job.part.
Directory0700/files0600/current UID, bounded regular-file no-follow
descriptor access, strict case-sensitive JSON without duplicate/null/unknown
fields or unsupported versions. Each hardlink publication stays within its own
destination mount. Equal filesystem device IDs alone do not establish that a
hardlink can cross separate bind mounts. Hold
nonblocking exclusive flock for the uploader's lifetime; a second instance fails.
A mutex serializes durable accounting, not whole body streams. A RAM counter
alone is never authoritative for stored usage or restart.

1. Persist unique job-ID/principal/audit-identity and maximum-byte reservation
   before reading or creating payload data.
2. Stream/hash into exclusive private staging; check sync/close/parent durability.
3. Persist prepared fixed hash/size/metadata/filenames before publication.
4. Publish payload/job from its respective staging without clobber, sync, remove
   both staging directories durably and commit
   accounting before200. Ambiguous write/rename/sync/close failures retain charge
   and latch admission/health503, including already-in-flight commit/ACK paths.

Restart takes the instance lock, validates ledger/published records and reconciles
stages. Committed or possibly published work stays charged despite lost response
or gateway registry. Do not reconstruct principals from mutable job owners.
Only exact tracked temporaries proven never published may be removed by safe
descriptor/inode identity and directory sync before releasing charge. Time/PID
expiry cannot establish this. Missing/corrupt ledger over existing data, unknown
files, contradictory provenance or ambiguous publication fail closed; never
create an empty baseline or delete historical inputs. The prior admission/staging
layout is unsupported and fails closed without migration. Explicit legacy adoption
and retention tools remain pending.

## Worker command/result limits

Pipeline/evaluator stdout each cap at1048576 bytes; stderr and optional alignment
stderr cap at65536. The first excess byte latches failure and cancels/kills the
retained process group, including descendants holding pipes after leader exit.
Truncated JSON is never accepted. Pipeline uses pipeline_output_limit; evaluation
uses evaluation_output_limit and withholds science. An observed overflow takes
precedence over concurrent cancellation/timeout; absent overflow the existing
shutdown/deadline contracts apply. Alignment scanner errors kill children before
waiting on unread pipes; total SAM bytes and target-map size remain unbounded.
Alignment is optional detection; its warning alone does not withhold independent
variant evaluation. Capturing at the worker boundary also does not bound memory
that the Python wrapper may use while collecting its own tool output.

Final serialized results must fit the existing16777216-byte reader cap. Oversized
derived output becomes a small schema1 failed/withheld result_metadata_too_large
envelope retaining identity/time, upload/processed hashes, size and established
crypto flags. Oversized derived fields are not persisted. This explicit resource
failure is different from silently truncating a successful result or limiting
only the job's diagnostic copy.

## Required acceptance

Small real quotas: exact/+1 jobs/bytes, principal isolation/renewal, CLI/gateway
shared accounting, chunked bodies, denied body unread, concurrent last-slot
requests, slow/cancelled streams and durable cleanup. Restart/second instance,
strict ledger/path/UID/policy, and failpoints around each transaction stage must
preserve originals and charge; no200 with absent accounting. Include published
work whose client never received ACK. Preserve ambiguous charges on failure.

Output tests: exact/+1 stdout/stderr, concurrent captures, valid JSON followed
by excess, scientific withholding, actual leader-exit/descendant survival check,
serialized result exact/+1, readable/provenance-preserving fallback. Rebuild
services and preserve scientific/crypto/ownership/TM-03 acceptance. Public proof
contains fixed cases/counts/codes/hashes, never raw ledger/principals/private
paths/credentials/payloads/sentinels. Record dated receipts before claiming PASS.

## Executed acceptance and scope

Corrected native receipt [192150-539678Z](../evidence/20261014T192150-539678Z/public/manifest.json)
passed78 checks, including15 real HTTPS admission checks and10 command-output
checks. Small global/per-CN retained-job quotas denied new input after actual
terminal rejection and restart; another principal retained its independent slot.
Missing/corrupt ledger copies refused startup without changing original inputs
or creating an empty baseline. A second uploader was excluded. Output-overflow
jobs preserved original/processed hashes and established crypto, withheld partial
JSON, killed the descendant and removed decrypted plaintext before acceptance.
The public export has ten verified checksums; raw responses and ledgers stay private.

Rebuilt [Compose receipt](../evidence/20261014T192150-561120Z-reviewer-compose/public/manifest.json)
passed30 checks plus cleanup: real gateway HTTPS/mTLS submissions, repeated
synthetic science, owner denial, restart/relogin and exact narrow container mounts.
It is a gateway integration, not an additional small-quota last-slot test shared
with a concurrent CLI client. Both interfaces call the same admission handler;
the native run tests direct/CLI uploads, and unit tests cover quota/renewal/races.

The first pre-fix native78 receipt remains historical. The corresponding Compose
run failed after ten controls: cross-mount hardlinks returned EXDEV despite equal
device IDs. Staging was split into destination-local directories; no wider mount
or copied payload was introduced. [Distinct-mount regression](../evidence/20261014T192234-593374Z-admission-mount/public/mount-regression.json)
records an executed real Docker handler/restart test and eight source hashes;
it does not establish TLS or scientific inference by itself. The native/Compose
receipts above establish the corrected candidate's integration separately.

Fresh make test passed86 Python cases and test/vet across seven Go modules.
Corrected upload test/race/vet checks passed, including six actual SIGKILL
transitions and the split-stage cleanup regression. Worker tests cover
exact/+1 captures, leader-exit descendants, withholding and serialized-result
fallback; its race run passed. The explicit mount test skips in ordinary/hosted
Go suites and was run separately in the cited Docker regression.

These receipts verify the described input/output controls. Physical artifact
quotas/retention, policy migration, immutable authenticated ownership, queue/
leases and production storage remain pending. A gate-wide claim requires its
remaining acceptance, including shared-interface quota exhaustion, to be demonstrated.

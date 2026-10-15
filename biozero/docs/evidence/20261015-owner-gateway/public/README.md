# Owner-v1 Gateway and Firefox acceptance

Actual native synthetic variants passed **116/116** controls; separate stats
passed **67/67**. Independent offline retained-evidence readback passed
**824/824**. Component race counts in summary.json have separate scope and
must not be added to native controls.

Browser execution traversed Gateway → authority → upload → protected worker →
V3 broker/capsule → dedicated receipt reader → Results → Gateway → Firefox.
Signed acceptance, receipt/proof, typed projection and actual rendered metrics
were compared. A/B denials, copied-ciphertext AAD rejection, invalid FASTQ,
post-worker cache substitution, signed-inbox negatives, Gateway restart/relogin
and unchanged retained history/charges were exercised. Each run joined seven
own service instances with Wait0; browser shutdown was checked separately.

Two valid variants runs each observed TP3/FP0/FN0 and1,171mapped SAM records;
invalid input stayed failed/withheld. Stats succeeded/unassessed with no variant
assessment or scientific metric cards. Neither mode establishes clinical,
genotype, indel, WGS or novelty claims.

Both snapshots contain548sources and188Go/module inputs and use the same ten
binary bytes. Their sole source difference is the stats fixture's private rules
derivation in run_owner_worker.py. Nine executables retain the original build
provenance; only Gateway was recompiled after the opaque404 correction. The
historical complete GOROOT/FIPS source closure was not measured; later hashing
does not prove its historical immutability or certify BioZero. These are native
receipts, not reproducible-image or cross-host evidence. Later docs are separate.

The fixture explicitly provisions an already-signed acceptance into Results'
authorization inbox. An autonomous deployed publisher, separate role UIDs/keys/
mounts/network, maximum-load and physical quotas, active-job failure/recovery and
the remaining TM02/project requirements remain open. Configured limits are not
maximum-load acceptance. Original failed attempts remain failed and retained;
summary.json records their hashes and causes. Auditor implementation failures
are separately retained and do not relabel native outcomes.

Only this four-file aggregate allowlist is public: README.md, summary.json,
pins.json and SHA256SUMS. No private raw receipts, identities, keys, runtime
paths, screenshots, DNA, targets, vectors or weights are exported.

See [Gateway contract](../../../security/ownership-gateway-contract.md),
[reproduction](../../../runbooks/reproduce.md) and
[requirements](../../../requirements-and-gates.md).

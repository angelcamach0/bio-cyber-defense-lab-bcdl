# BZ-EXP-001 synthetic variant validation

Executed 2026-10-14 on RHEL 9.8 aarch64. Source branch
`biozero/reproducible-milestone`, base revision b873193, local modifications
identified by per-file hashes in the run manifest.

## Protocol and acceptance

Use the versioned fixture in `biozero/bio/fixtures/variant-smoke`: deterministic
6 kb synthetic reference, 1,171 reads of 150 bases, three expected SNPs and an
invalid FASTQ. The fixture generator, manifest and evaluator define the answer
set and metrics. Evaluate all returned alleles; no silent filtering.

Two independent variant pipelines must yield the expected normalized allele set
with TP=3, FP=0, FN=0. Invalid FASTQ must fail the validation stage. Protected
integration additionally requires owner A/B isolation, original upload hashes,
client certificates, and rejection of unsigned data before invoking analysis.

## Observed results

The scientific repeat passed: three expected SNPs, zero extra/missing alleles and
equal callsets. The invalid input failed for its FASTQ structure. The environment
was recreated using an explicit 39-package Linux ARM64 lock; minimap2 2.31,
SAMtools/BCFtools 1.24 and Go 1.26.7 were observed.

The native protected run passed ten assertions: two successful signed/encrypted
uploads, two cross-client denials, two original-digest checks, variant comparison
and repeat, format-specific invalid-input failure, missing-certificate TLS denial,
and unsigned rejection before analysis.

The first integrated attempt failed because the rewritten pipeline lacked its
execution permission. That failed run was retained, the permission corrected and
the next runs passed. Startup errors now have a specific error code. Shutdown and
timeout tests verify child cleanup. None of the failed runs were relabeled PASS.

## Reproduction and evidence

```bash
make bio-tools
make test
make science
make experiment
```

Current native bundle: `biozero/docs/evidence/20261014T150910-330979Z/public/`.
It passed ten assertions and contains the manifest, metrics, derived allele-only
VCFs, derivation digests and checksums. Public VCFs preserve exactly the normalized
alleles used by the evaluator; sample names, tool commands, local paths, genotype,
quality, filters and annotations are omitted. Original VCFs and raw runtime
records remain outside the public allowlist. Four export tests cover gzip,
multiallelic records, path removal, reference mismatch and unsafe contig names.

The earlier `20261014T130244-777191Z` and `20261014T135932-793305Z` bundles are
historical executions, retained intact. Their raw public VCF copies contain local
paths in tool headers/sample names and must not be published. The new export
does not alter or relabel those runs. The independent scientific
report is in `biozero/docs/evidence/science/bz-exp001-9w5o8ngx/evidence.json`.

The scientific repeat measured about 0.919 s and 0.879 s with maximum child RSS
39,756 KiB while other checks also ran. These are local observations, not a
hardware-normalized performance comparison or total service-memory estimate.

## Limits and next action

Allele presence for three synthetic SNPs does not establish genotype/indel/WGS
accuracy, biological interpretation, clinical validity, or scientific novelty.
Native checks do not verify container isolation, an Oracle deployment or a
hardware enclave. The separate four-service reviewer Compose run
`20261014T150658-139518Z-reviewer-compose/public/` passed 31 assertions with real
signed/encrypted submissions, per-reviewer identity, backend ownership, withheld
invalid input and container controls. Its real Firefox run passed 23 browser checks: verified TLS, 3-SNP report,
invalid input withheld, A/B denial, desktop/mobile layout and delayed session
callbacks; zero JavaScript errors. Four public screenshots were inspected.
The native experiment was independently repeated in another checkout; evidence
`20261014T150823-057533Z-independent-checkout/public/` records the exact snapshot
and its original manifest limitations.
Next: finish hosted CI and publication, then advance the bounded
regulatory biological protocol according to permitted data access and resources.

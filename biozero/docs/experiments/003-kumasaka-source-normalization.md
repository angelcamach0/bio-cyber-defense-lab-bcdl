# SCI02 Kumasaka source normalization contract

Date: 2026-10-14.

**Decision:** the acquired Kumasaka source can support a prospective, descriptive
LCL transfer pilot under the rules below. This approves the source dictionary and
normalization design; it does not approve generated cases or report biological
results. Mapping assets, sequence receipts, implementation tests, a reviewed
normalization ledger and the frozen 110-case selection must pass before inference.
The existing SCI02 model, tracks, score and metrics remain fixed. SCI01's measured
economic no-go for the current quantized backend remains a separate decision.

## Pinned inputs and independently observed structure

The [author deposit](https://zenodo.org/records/1405945), DOI
10.5281/zenodo.1405945, is the 2018 version of processed ATAC data. Cached official
metadata declares open access and `cc-by-4.0`; retain attribution to Kumasaka,
Knights and Gaffney. This source is not established as a copy of DART African
caQTL v2. The file body stays in private research storage.

| Input | Observed identity |
| --- | --- |
| `lead_caQTL_variants.tsv.gz` | 10,497,915 bytes; SHA256 `b7a1e169153eff1fbf700270260bc7225f0c4585b1066ab2e2a65583c33a5d2e`; publisher MD5 `4b05a81465935729056828712e3e2fcf` |
| `README.txt` | 5,043 bytes; SHA256 `a3a7255678894553c3bc9ea99a1bc814a9d2104521f5d62e417e0a0ddebc18dd` |
| Frozen `baseline-protocol.json` | SHA256 `8c3f80a5b59eb3d165764bb5596e1b0451248bd2b0641d430fa6378b73a9126c` |

Independent review rehashed the cached gzip and streamed its table, without
creating a plaintext copy or running predictions. Its exact header is:

```text
Peak Chr Pos RsID Ref Alt AF Inside_Peak P_Lead Beta SE Log10_BF
```

There are 297,308 source rows. Restricting only to `Inside_Peak=1` and distinct
single A/C/G/T alleles yields 156,731 distinct source loci: no repeated rows or
loci associated with multiple focal peaks in that subset. Of those loci, 15,257
are on source chromosomes 8/9. There are 169 focal peaks with multiple eligible
lead SNVs. These counts precede tie exclusions, mapping, sequence verification
and final selection; they are not counts of accepted biological cases.

## Reviewed source dictionary

The [author README](https://zenodo.org/api/records/1405945/files/README.txt/content)
defines the following correspondence. Preserve the raw header and every raw value;
the aliases describe this exact file rather than a permissive parser for other
datasets.

| Actual column | Dictionary meaning / normalized use |
| --- | --- |
| `Peak` | Focal phenotype identifier; join to the peak table by exact ID |
| `Chr`, `Pos` | GRCh37 chromosome and one-based variant position |
| `RsID` | Alias of `Rs_ID`; annotation, never a substitute for coordinates/alleles |
| `Ref` | Alias of biallelic `Allele_0`; source reference/other allele |
| `Alt` | Alias of biallelic `Allele_1`; source effect allele |
| `AF` | Source effect-allele frequency |
| `Inside_Peak` | Alias of categorical `Var_Loc`: 0 outside, 1 focal, 2 another peak |
| `P_Lead` | Conditional lead-variant probability; retain as metadata |
| `Beta`, `SE` | Effect for source `Alt`, and its standard error |
| `Log10_BF` | Association evidence metadata |

Corroboration at PHM commit `09f70244f02c56e457b16d930c9006fcd4e03629`:
[bayeslm.c](https://github.com/natsuhiko/PHM/blob/09f70244f02c56e457b16d930c9006fcd4e03629/src/bayeslm.c)
copies VCF POS without shifting, preserves biallelic REF/ALT and assigns location
1 to the focal peak; [getLogBF.c](https://github.com/natsuhiko/PHM/blob/09f70244f02c56e457b16d930c9006fcd4e03629/src/getLogBF.c)
computes the regression slope from dosage/phenotype covariance. The
[VCF specification](https://samtools.github.io/hts-specs/VCFv4.5.pdf) defines POS
as one-based. Independent investigator reuse in the
[Context-TFs notebook](https://github.com/DeplanckeLab/Context-TFs/blob/1b7b889e2173063321bd3902a72f945c5fc82eac/Pre_processing_Kumasaka_et_al_tables_step1.ipynb)
uses these actual names, focal-peak SNVs and positive Beta as ALT-more-accessible.
The exact script exporting this 12-column table was not located. Its dictionary
mapping is supported by these convergent primary sources, not by an observed
export trace. Reference-base checks remain mandatory.

## Eligibility and multiplicity, fixed before predictions

Assign an immutable origin ID from the one-based data-row number, excluding the
header, and the pinned source digest. Validate types, enum values and strict
autosomal contigs; do not silently coerce invalid values. Initially admit only
`Inside_Peak=1`, distinct biallelic A/C/G/T SNVs, finite Beta and finite positive
SE. Preserve the source effect even when exactly zero. No Beta-magnitude, sign,
P_Lead, P_caQTL, AF or predicted-score threshold is applied.

Reject all focal peaks with more than one eligible lead SNV. The observed 169
such peaks require rejection of their rows, not merely rejection of 169 rows.
Count source rows, affected peaks and reasons separately. Retain a guard that
rejects all rows of a SNP associated with multiple focal peaks; this guard found
zero instances in the focal-SNV subset above. Reject ambiguous duplicate peak
metadata and conflicting/repeated case identities. Never average multiple Betas,
choose the largest effect or retain the best-scoring association.

Join each remaining row to its focal peak. Keep original/mapped peak intervals,
peak ID, P_caQTL if supplied, raw variant/effect and every exclusion. The lead
table covers the study's peaks and does not itself establish that every row is
a confidently causal QTL. The pilot measures agreement with reported association
effects; it does not validate causal variants or distal regulatory interactions.

## GRCh37 to hg38: coordinates, alleles and phenotype identity

Acquire and hash the author `peaks.bed.gz` and official
[hg19ToHg38 chain](https://hgdownload.soe.ucsc.edu/goldenPath/hg19/liftOver/hg19ToHg38.over.chain.gz)
under the existing 50 MiB dataset ledger. Inspect their actual schemas/headers
before admitting rows. The README declares GRCh37 peaks and consistent IDs.
[BED conventions](https://genome.ucsc.edu/FAQ/FAQformat.html#format1) are
zero-based, half-open. PHM's inspected peak-membership code uses inclusive
comparisons against VCF POS: do not copy that comparison into a BED parser.
Validate membership with `q=Pos-1` and `left <= q < right`; exclude and report any
source location/membership conflict rather than repair coordinates to admit it.

The [chain specification](https://www.genome.ucsc.edu/goldenPath/help/chain.html)
defines zero-based, half-open blocks. Confirm actual chain headers place hg19
on `t` and hg38 on `q`; do not infer direction from the filename alone. Require
one unique mapping for the SNV and full focal peak, with complete ungapped,
contiguous coverage, the same chain/chromosome/strand, and source/mapped SNV
containment in the respective focal intervals. Reject gaps, split peaks,
ambiguous mappings and noncanonical/interchromosomal targets. A one-base mapped
position alone does not verify a mapped phenotype interval. Restrict both source
and target to the same chromosome, 8 or 9, prospectively. Record chain ID, block
coordinates, orientation and mapping/containment evidence.

For `qStrand=-`, transform coordinates to the target's forward strand using the
chromosome size, and complement both source alleles. This renames biological
alleles and does **not** negate Beta. Obtain a verified source reference base at
`[Pos-1,Pos)` and require exact agreement with source `Ref`. Fetch target forward
DNA at `[q38-2048,q38+2048)`, exactly 4,096 A/C/G/T bases, with no padding. The
variant's target reference is DNA index 2048. Verify returned genome, chromosome,
interval and length, and retain response and uppercase-DNA digests/provenance.
Record focal-peak coverage within the input window; the score predicts a
central-base accessibility probability, not integrated accessibility over an
entire focal peak.

Support target-reference changes only for these verified biallelic SNVs:

| Target forward reference | Final REF / ALT | Raw effect alleles supplied to adapter |
| --- | --- | --- |
| Oriented source Ref | Oriented Ref / oriented Alt | E=oriented Alt, O=oriented Ref |
| Oriented source Alt | Oriented Alt / oriented Ref | E=oriented Alt (final REF), O=oriented Ref (final ALT) |
| Neither allele | Reject | No inferred effect orientation |

This reference swap is an established limited recovery in official
[Picard LiftoverVcf documentation](https://gatk.broadinstitute.org/hc/en-us/articles/360050815392-LiftoverVcf-Picard),
which also warns that allele-specific annotations require correction. BioZero
does not invoke Picard here or infer that it normalizes Beta. Preserve BetaRAW
and the explicit transformed E/O pair; `normalize_effect` performs exactly one
conversion to final ALT-minus-REF, negating only for E=final REF. SE remains
unchanged. Preserve AF as **source** AF; if deriving final-ALT AF for a swapped
site it is `1-source_AF`, with the transformation recorded. No source confidence
interval is present; invent none. Reject source-REF mismatches, third alleles and
unresolved orientation. Preserve original, complemented and swapped states so
the reviewer can reconstruct the conversion without a second sign flip.

## Bounded presample, then frozen 10 + 100

This pilot uses a prospective fixed resource presample, not uniform coverage of
all source loci. Freeze its definition and receipt before sequence API requests:

1. Complete source eligibility, tie exclusions, peak joins, chain checks and the
   chromosome restriction without any predictions or target-reference relabeling.
2. Rank technically mapped rows by SHA256 of UTF-8 newline-joined fields:
   `SCI02-KUMASAKA-PREPOOL-v1`, the existing protocol seed, source SHA256,
   `origin_row_id`, `hg38`, mapped chromosome, decimal mapped one-based position,
   oriented source Ref, oriented source Alt. Break ties by immutable origin ID.
   Freeze the first 256 rows, or the complete pool if fewer exist, with its digest.
   This key has a separate domain from the final protocol rank key.
3. Obtain source-base and target-window receipts for **all** fixed precandidates.
   Retain unavailable, mismatched and invalid candidates with stable reasons.
   Do not replenish from outside 256. Request sequentially at no more than one
   hit per second, respecting [UCSC API conditions](https://genome.ucsc.edu/goldenPath/help/api.html).
   Stop on an access denial/challenge; record affected unattempted rows as pending.
4. Normalize verified E/O against the observed target REF, preserve all
   precandidate outcomes, and independently review the resulting source ledger.
   The provisional key cannot masquerade as the final key: a reference swap
   changes the final canonical REF/ALT and hence its rank hash.
5. Apply the existing protocol's final deterministic hash and greedy disjoint
   complete-window selection to the normalized pool. Freeze **all 110** descriptors
   and their DNA hashes before the first biological prediction. First ten are
   adapter; next 100 are evaluation. If fewer than 110 pass, report pending
   feasibility and the exact shortfall; no automatic expansion or substitute data.
6. After freezing, retain failed/unavailable slots and never replace them.
   Evaluation requires the existing passed biological ten-case adapter receipt;
   an instrumentation control cannot provide that receipt.

HTTP response bodies, failures/partial reads and metadata acquisitions remain
charged to the dataset ledger. Independently cap each response, use verified TLS
and bounded timeouts, and stop before a read would exceed the aggregate ceiling.
With 256 candidates, at most 512 normal sequence requests are planned; no raw
genotypes, full reference, individual-level counts or further caQTL distributions
are needed. The acquisition record reported 10,512,921 dataset bytes charged before the peak/chain
acquisitions. `peaks.bed.gz` is publicly listed as 10,705,038 bytes, publisher MD5
`edfc80787bd9efb90ea6c259de14d70f`; actual SHA/size and chain receipts remain required.
Do not treat publisher checksums or estimated transfer size as verified bodies.

## Context, model split and interpretation

The [primary study](https://doi.org/10.1038/s41588-018-0278-6) measures accessibility
across 100 GBR LCLs, aligned to GRCh37; its separate GM12878 experiment was excluded
from QTL mapping. The fixed nine GM12878 ATAC tracks are a related LCL context,
so their mean ALT-minus-REF probability delta is a defensible **descriptive
transfer baseline**, with population, individual genotype, neighboring haplotype
and assay differences explicitly retained. It is not measured GM12878 QTL truth,
an African population result, a calibrated Beta estimate or clinical evidence.

The [original Sei Methods](https://doi.org/10.1038/s41588-022-01102-2) and pinned
[train.yml](https://github.com/FunctionLab/sei-framework/blob/1e16bff9b1618af7065a23f82c4a3bb82aaeb689/train/train.yml)
reserve hg38 chr8/9 for test, chr10 for validation, with labels based on central
base overlap. The prospective chr8/9 filter reduces known overlap with the
original backbone's training partition. Complete rank-64 head training,
calibration and fine-tuning history is still unknown: label these chromosomes
`original_Sei_test_partition`, never `rank64_verified_heldout`. Disjoint input
windows and unique focal peaks do not establish LD or statistical independence.

Keep strict FP32 rank64, projection=false, canonical both-strands averaging and
all nine pinned tracks. Primary mathematical-sign agreement includes exact zeros;
secondary agreement excludes only exact-zero experimental effects. Spearman uses
average tied ranks and is null for insufficient/constant inputs. Preserve SE and
all denominators; do not add uncertainty thresholds, outcome exclusions, track
selection, Beta MAE or 61-class substitutes after seeing predictions. Any measured
association is exploratory; results and negative findings must describe this
frozen source/context/sampling scope.

## Evidence scope and remaining gates

This review inspected cached source bytes and primary documentation only; it did
not acquire dataset/model artifacts, generate cases or run inference. Remaining
checks cover citations, evidence labels, bounded reads and provenance, together
with tests of effect swaps, minus-strand mapping, peak boundaries, ambiguous/gapped
chains, tie exclusions and no-replenishment.

Before biology: pin/hash peak and chain bodies; check actual peak schema and
membership; freeze the presample; acquire/account all bounded sequence outcomes;
review the normalized source/permission receipt; freeze the complete 110;
validate all ten adapter outcomes. No biological completion follows from this
document or from a successful model-load/control run.

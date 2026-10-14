# SCI02: biological regulatory baseline protocol draft

Date: 2026-10-14. Science reviewer: Vera. Coordinator: Chiquis.
Status: head/context/score/selection configuration and offline adapter implemented;
one instrumentation control executed; no biological dataset or effects evaluated.

## Why this follows SCI01

The rank-64 trained checkpoint loaded and ran within the resource budget. On the
same single synthetic pair, FP32 took 11.27 s and QNNPACK took 18.77 s; the prior
default quantized engine took 77.84 s. The first quantized pass therefore did not
support an economical recomputation gate in the measured configuration. Preserve
this provisional negative finding; do not manufacture a need for reruns.

The next useful experiment is a reproducible FP32 comparison with actual measured
regulatory effects. It must keep numerical agreement separate from biological
agreement. [SCI01 aggregate evidence](../../research/regulatory/runtime-feasibility.json).

## Candidate and conditions to freeze before scoring

Candidate: DART-Eval African caQTLs on GRCh38, lymphoblastoid accessibility, with
a corresponding Sei GM12878 ATAC-seq track from the 21,907-output head. Vera checked
the pinned target annotations contain GM12878 ATAC-seq/DNase entries. This remains
a proposed match until exact assay, allele orientation, track and data terms are
recorded. [DART-Eval methods/data](https://openreview.net/pdf?id=qR0x6H5WUX) and
[official task 5](https://github.com/kundajelab/DART-Eval#task-5-chromatin-activity-variant-effect-prediction).

Choose track or predefined aggregation by assay correspondence before predictions;
never choose it using the best observed correlation. The 61 projected sequence
classes from SCI01 are not experimental ATAC/DNase labels. Freeze dataset version,
download digest, permitted usage, genome assembly, exact track index, preprocessing,
effect definition, split and scientific acceptance before the larger evaluation.

## Adapter preflight: ten loci

1. Obtain permitted public data and document its version/terms; no paid API or
   large reference download is assumed by this proposal.
2. Validate locus/REF/ALT/build/effect orientation, duplicates and missing values.
3. Obtain real 4,096-base reference windows with verified alleles; do not pad
   shorter processed sequences arbitrarily. Mutate only the agreed allele.
4. Run FP32 with one thread, batch one, both strands and strict pinned state dicts.
5. Define the biological score and compatible metrics. Model probabilities and
   QTL effect estimates do not automatically share units; unscaled MAE would be
   misleading. Report numerical repeat stability separately.
6. Count every submitted locus, including invalid/unavailable results, and record
   elapsed time, RSS, provenance, scope and failure causes.

## Conditional pilot: one hundred biological pairs

Proceed only after the adapter passes the predefined controls. Fix selection and
strata before looking at predictions; separate development/evaluation by locus,
check training overlap and correlated regions, and report appropriate uncertainty
for a small pilot. Significant QTL association is not proof of causal mechanism.

The primary deliverable is the FP32 baseline versus measured effects. Consider a
smaller model separately if it fits the experiment; reducing the head rank does
not reduce the trunk and cannot be assumed to improve runtime. Reopen selective
recomputation only after a representative pass is measurably cheaper and a gate
can satisfy both quality and total-time acceptance. No trained gate is authorized
by a synthetic disagreement alone.

## Completion evidence

The data/track protocol, input and software digests, complete case ledger, scores,
repeat checks, metrics with denominators, timing/RSS and limits must support the
claim made. A protocol, a passing resource probe or 100 synthetic pairs cannot
mark this biological experiment completed.

## Source/access preflight observed 2026-10-14

Vera verified `Afr.CaQTLS.tsv`, Synapse `syn60756043` version 2 (modified
2026-05-19; file handle 173808988). Anonymous version metadata succeeded, but
file and filehandles endpoints returned HTTP 403. Actual TSV bytes, header,
size and SHA256 remain unverified. Acquisition requires authorized Synapse access
or an exact authorized copy, within a 50 MiB budget; do not bypass access control.
[Pinned metadata](https://repo-prod.prod.sagebase.org/repo/v1/entity/syn60756043/version/2).
The official paper declares CC BY 4.0 for African caQTL data in appendix C.4.
[Conference paper](https://papers.nips.cc/paper_files/paper/2024/file/71998bfc3217ffe1cca1ee084dfadadd-Paper-Datasets_and_Benchmarks_Track.pdf).

The DART-Eval loader at commit `af2a86d666c35304257c2fa7e15180e1fbcabb01`
allows allele2 to match REF. Confirm the effect allele before expressing beta
as ALT minus REF; do not assume allele1 is REF. Reject both-allele mismatch and
incomplete windows rather than copying the original loader's substitutions or
zero padding. Expected columns in code are not a verified TSV v2 header.
[Pinned loader](https://github.com/kundajelab/DART-Eval/blob/af2a86d666c35304257c2fa7e15180e1fbcabb01/src/dnalm_bench/task_2_5_single/components.py).

A public UCSC hg38 control window (chr1, zero-based [1000000,1004096)) returned
4,096 A/C/G/T bases; uppercase DNA SHA256
`99279a104d299f7fe1f147072c631b3041d0c27464dac169966a99eb5b70e439`.
This proves window retrieval only, not a real variant's REF agreement.
[Control request](https://api.genome.ucsc.edu/getData/sequence?genome=hg38;chrom=chr1;start=1000000;end=1004096),
[coordinate convention](https://genome.ucsc.edu/goldenPath/help/api.html).
For a one-based variant position p, use q=p-1 and [q-2048,q+2048).

Nine candidate GM12878 ATAC-seq track IDs in pinned annotations are 59676,
59678, 61819, 61820, 61821, 61822, 65259, 65260 and 65262. Freeze an exact
assay-matched aggregation before predictions. Ten adapter loci and one hundred
separate evaluation loci cannot yet be fixed without the authorized table and
effect dictionary. No biological inference ran during this access preflight.

## Implemented adapter and instrumentation evidence

[baseline-protocol.json](../../research/regulatory/baseline-protocol.json) was
frozen before predictions (SHA2568c3f80a5b59eb3d165764bb5596e1b0451248bd2b0641d430fa6378b73a9126c).
It fixes the nine ID-to-index mappings, probability-delta mean, raw effect-allele
conversion, zero/tie metrics and deterministic technical selection. Rank by the
fixed SHA key, greedily admit disjoint 4,096-base windows, freeze the first 10 and
next 100 before predictions, and retain failed slots without replacements.
The exact source filters/schema/effect dictionary still require the actual table.
Disjoint windows do not establish LD independence or 100 independent observations.

[biological_adapter.py](../../research/regulatory/biological_adapter.py) verifies
source bytes, permitted/reviewed semantics, complete windows and full frozen case
payloads. Changing beta, E/O or provenance without changing the reviewed
normalization is rejected. Hundred-locus execution requires a passed biological
ten-locus receipt with matching dataset/protocol/weights/selection. Unknown
prerequisites remain pending. Atomic private per-row progress preserves completed
cases on failure; input validation and model inference are separate states.

Twenty adapter tests and three acquisition-boundary tests passed. One UCSC public
reference/artificial-C-to-G control passed actual cached FP32 head loading,
finite 21,907 probabilities, both strands and exact repeat. Measurement 11.348 s;
repeat 11.378 s; self RSS 927,031,296 bytes. It has no measured effect and cannot
count among the ten/hundred biological loci. The [public runtime receipt](../../research/regulatory/adapter-control-runtime.json)
omits DNA/vectors; full reports remain private. See the
[adapter commands](../../research/regulatory/README.md) for reconstruction.

Vera checked an [author-linked AFGR distribution](https://github.com/smontgomlab/AFGR/blob/26ddc2b02e0735065c140690f6765b05bccfdb5b/README.md).
Its archive declares35,612,374,185 bytes; no individual small file was verified.
The response body was not downloaded. The author-linked source does not prove
an exact copy of the DART v2 table or its terms. A
[primary preprocessing notebook](https://github.com/kundajelab/chrombpnet-figures/blob/3a81c09e9cc4f9945d553ce5619da3bc1088106b/src/figures_factory/Fig6/preprocessing/format_af_caqtls.ipynb)
documents allele2/allele1 effects for its own output; it does not establish which
flips are already applied to the unread DART v2 bytes.

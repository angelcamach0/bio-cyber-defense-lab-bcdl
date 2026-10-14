# BZ-EXP-001: deterministic variant smoke experiment

This fixture contains a generated, nonrepetitive 6,000-base reference and one
synthetic haploid sample with three homozygous SNP sites. There are 1,171
error-free single-end reads of 150 bases, alternating orientation, with roughly
30x internal coverage. The truth positions are 1001, 2501 and 4501 (VCF one-based).
The sequence generator has a fixed seed; `manifest.json` pins input hashes.
There are no patient data, genome assembly identifiers, or external datasets.

The acceptance criterion is TP=3, FP=0, FN=0 and identical normalized allele
sets from two independent successful variant runs. The deliberately truncated
`invalid.fastq` must exit 1 with `pipeline_status=failed` and `invalid_input`.
An unavailable required variant tool must exit 2 (`incomplete`), never succeed.
This checks orchestration and SNP presence on this fixture only. It does not
validate genotype, indel detection, noisy sequencing, human genomes or diagnosis.

Run from the repository root after installing minimap2, SAMtools and BCFtools:

The complete experiment, including both runs, evaluation, failure case and
version/resource evidence, can be executed with one command:

```bash
python3 biozero/bio/benchmarks/run_variant_smoke.py --out-dir /tmp/biozero-science
```

For the individual steps:

```bash
python3 biozero/bio/pipeline/pipeline.py biozero/bio/fixtures/variant-smoke/reads.fastq --mode variants --reference biozero/bio/fixtures/variant-smoke/reference.fa --out-dir /tmp/biozero-exp001-a > /tmp/biozero-exp001-a.json
python3 biozero/bio/pipeline/pipeline.py biozero/bio/fixtures/variant-smoke/reads.fastq --mode variants --reference biozero/bio/fixtures/variant-smoke/reference.fa --out-dir /tmp/biozero-exp001-b > /tmp/biozero-exp001-b.json
python3 biozero/bio/benchmarks/evaluate_variants.py --reference biozero/bio/fixtures/variant-smoke/reference.fa --expected biozero/bio/fixtures/variant-smoke/expected.vcf --observed /actual/run-a/variants.vcf --repeat /actual/run-b/variants.vcf
python3 biozero/bio/pipeline/pipeline.py biozero/bio/fixtures/variant-smoke/invalid.fastq --mode stats
```

Replace the two `/actual/...` paths with `outputs.normalized_vcf` in the run
JSON. Every run gets a fresh child directory under `--out-dir`. Preserve both
JSON results, artifact hashes, evaluator output, tool versions, CPU architecture,
elapsed time and peak RSS. An empty valid VCF can represent a completed pipeline;
it will fail this scientific experiment because the expected SNPs are missing.

`stats` is the CLI default and validates FASTQ/counts without external tools.
It makes no variant-analysis claim. Variant execution checks every stage and
required artifact, including reference/BAM/VCF indexes. mpileup is materialized
before calling so its exit status and timeout cannot be hidden by a downstream
process. fastp preprocessing is not part of this fixed smoke protocol.

Tests without external bioinformatics tools:

```bash
python3 -m unittest discover -s biozero/bio/pipeline -p 'test_*.py'
python3 -m unittest discover -s biozero/bio/benchmarks -p 'test_*.py'
```

Generate the exact fixture again with `python3 biozero/bio/fixtures/variant-smoke/generate.py`.

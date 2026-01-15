# pipeline (MVP wrapper)

This directory holds the MVP pipeline wrapper used by the enclave runner.

## Scripts
- `pipeline.py`: Python wrapper that runs basic FASTQ stats and uses external tools when available.
- `pipeline.sh`: legacy stub retained for reference.

## Tool support
The wrapper will run:
- `fastp` for FASTQ QC (if installed)
- `minimap2` for alignment (if installed and reference provided)
- `bcftools` + `samtools` for variant calling (if installed and reference provided)

If tools are missing, the wrapper still emits JSON with warnings and basic stats.

## Usage
```bash
./pipeline.py /path/to/input.fastq --reference /path/to/reference.fa
```

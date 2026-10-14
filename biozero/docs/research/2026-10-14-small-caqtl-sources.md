# SCI02: small public caQTL source preflight

Date: 2026-10-14; final HEAD observations checked by 18:29 UTC. Researcher: Nora;
coordinator: Chiquis. Status: source metadata/access investigation, not a biological
experiment. Nora acquired no dataset bodies or models, generated no normalized
cases, changed no frozen protocol, and ran no inference. A subsequent acquisition
must have its own receipt; this document does not establish dataset integrity.

## 1. Kumasaka/Knights/Gaffney: lead caQTL variants

The [author record](https://zenodo.org/records/1405945), DOI
10.5281/zenodo.1405945, is a concrete alternative to the inaccessible DART table.
Its [public API](https://zenodo.org/api/records/1405945) returned HTTP 200 and
declared `access_right: open`, license `cc-by-4.0`, and publication date 2018-08-30.
The candidate is the individual file, not the entire 22.1 GB record.

| Observed/published field | Value |
| --- | --- |
| File | `lead_caQTL_variants.tsv.gz` |
| Requested and final HEAD URL | https://zenodo.org/api/records/1405945/files/lead_caQTL_variants.tsv.gz/content |
| HEAD status / Content-Length | 200 / 10,497,915 bytes |
| Content-Type | `application/octet-stream` |
| Content-Encoding / Accept-Ranges / ETag | All absent in the observed response |
| Last-Modified | Thu, 08 Jan 2026 07:38:10 GMT |
| API-published MD5 | `4b05a81465935729056828712e3e2fcf` |

MD5 above is publisher metadata, not a digest computed over acquired bytes.
HEAD establishes current response metadata, not a complete successful GET.

The [README](https://zenodo.org/api/records/1405945/files/README.txt/content)
returned 200; 5,043 bytes were read as source documentation. Computed SHA256:
`a3a7255678894553c3bc9ea99a1bc814a9d2104521f5d62e417e0a0ddebc18dd`.
Its publisher MD5 is `ef718ea6b0c2c598fb3c8737f417f41d`. The dictionary defines
`Chr`/`Pos` as GRCh37; `Allele_0` as REF and `Allele_1` as ALT for biallelic
variants; `Beta` as the effect of `Allele_1`; and `SE` as its standard error.
`Peak` can repeat for tied lead variants. `Var_Loc` distinguishes outside peaks
(0), inside the focal peak (1), and inside another peak (2). These are verified
documentation definitions, not a verified header or a count of eligible rows.

The [primary publication](https://doi.org/10.1038/s41588-018-0278-6), read through
[official article XML](https://www.ebi.ac.uk/europepmc/webservices/rest/PMC6330062/fullTextXML)
(200; 136,571 bytes), describes 100 GBR lymphoblastoid cell lines and GRCh37
alignment. An additional GM12878 ATAC experiment was explicitly excluded from
QTL mapping. Thus the table's measured effects are population LCL effects, not
GM12878-specific truth. The paper distinguishes local and distal regulation;
the candidate's focal peak must remain associated with each variant/effect.

**Pending compatibility decisions:** real header/full-file digest, coordinate
convention, biallelic SNV eligibility, GRCh37-to-hg38 mapping with allele/strand
checks, and local peak correspondence. Neither changing a build label nor using
the same rsID verifies a mapping. Review any `Var_Loc=1` filter before prediction;
the current variant-centered 4,096-base score does not automatically represent
effects at distal peaks. Freeze a deterministic rule for multiple peaks/ties and
duplicate loci, preserve exclusions and source SE, and verify training overlap.
The nine GM12878 ATAC tracks require explicit context review before adoption.

## 2. Tehranchi et al.: shared caQTL supplement

The [primary figures/data index](https://elifesciences.org/articles/39595/figures)
identifies supplementary file 2, DOI 10.7554/eLife.39595.024, as shared caQTLs.
[Official article XML](https://www.ebi.ac.uk/europepmc/webservices/rest/PMC6335058/fullTextXML)
returned 200; 304,926 article bytes were read. It records CC-BY-4.0 and marks
supplement 2 as local-data, without an observed license exception. The study
measures pooled ATAC in LCLs from ten populations, not only GM12878.

| Observed field | Value |
| --- | --- |
| Requested and final HEAD URL | https://cdn.elifesciences.org/articles/39595/elife-39595-supp2-v1.txt |
| HEAD status / Content-Length | 200 / 4,484,914 bytes |
| Content-Type / Content-Encoding | `text/plain` / absent |
| Accept-Ranges | `bytes` (advertised; no range GET tested) |
| ETag | `"22ac67b6b044326827520440471445ad"` (not treated as a verified digest) |
| Last-Modified | Wed, 22 May 2019 08:44:57 GMT |

Dataset bytes/header, build, numerical effect and exact effect-allele orientation
remain unread/unverified. An author-linked
[cisVar configuration](https://raw.githubusercontent.com/tehranchi/cisVar/1d7a3bd4a9124d553954121e506ccdb03951b0ee/pipeline/cisvar_config.json)
uses hg19; that is supporting code context, not proof of this supplement's build.
Pre/post ATAC frequency or open/closed allele descriptions do not prove a signed
continuous Beta column. This file is not established as a copy of DART v2.
Supplement 1 XLSX separately returned HEAD 200, length 11,137,826 bytes; its body
was not read and it is not an additional approved acquisition.

## Access methods, boundaries and next action

Python `urllib.request.urlopen(Request(url, method='HEAD'), timeout=20)` used
normal redirect handling and TLS verification. Final URLs equaled requested URLs;
intermediate redirect histories were not retained. No dataset body was read.
Earlier web-rendered eLife/PMC pages presented browser challenges; official
public article APIs and editorial metadata were used without bypassing them.
No Synapse 403 or signed Dropbox denial was retried, and no credentials were sought.

Kumasaka is the stronger **metadata candidate**, because its dictionary explicitly
orients Beta. Both individual files fit the 50 MiB transfer ceiling by published
size; that does not approve their decoded size, schema or scientific compatibility.
Chiquis plans one bounded acquisition of the Kumasaka file plus README with a
dataset ledger preserving the prior 4,251-byte UCSC control charge. Acquisition,
digest verification and bounded decoding must precede header/schema approval.
Keep the [SCI02 protocol](../experiments/002-regulatory-biological-baseline.md)
and [frozen configuration](../../research/regulatory/baseline-protocol.json)
unchanged until source normalization, build/context/peak semantics, selection and
training-overlap review are frozen. Retain the first ten biological adapter slots,
then 100 separate evaluation slots, all failures and the original denominators.

## Subsequent root acquisition and schema review

After the preflight above, Root reported acquiring the complete 10,497,915-byte
gzip and 5,043-byte README, matching their published MD5s. Dataset SHA256:
`b7a1e169153eff1fbf700270260bc7225f0c4585b1066ab2e2a65583c33a5d2e`.
Nora independently checked the cached README's size/SHA256/MD5; all matched above.
The private dataset ledger reports 10,512,921 charged bytes under 50 MiB, preserving
the prior 4,251-byte UCSC charge. This is separate from the checkpoint ledger.
Root read this exact 12-column gzip header, without a biological inference:
`Peak Chr Pos RsID Ref Alt AF Inside_Peak P_Lead Beta SE Log10_BF`.
It differs from README names `Rs_ID`, `Allele_0`, `Allele_1`, and `Var_Loc`.
**Proposed correspondence, not an approved alias/freeze:** `RsID`→`Rs_ID`,
`Ref`→`Allele_0`, `Alt`→`Allele_1`, `Inside_Peak`→`Var_Loc`.

Static primary-code inspection at PHM commit `09f70244f02c56e457b16d930c9006fcd4e03629`
found [bayeslm.c](https://github.com/natsuhiko/PHM/blob/09f70244f02c56e457b16d930c9006fcd4e03629/src/bayeslm.c)
copies VCF POS unchanged, retains REF/ALT for biallelic variants, uses allele-1
dosage for regression, and assigns location 1 to the focal peak and 2 to another
peak (zero initialized otherwise). [getLogBF.c](https://github.com/natsuhiko/PHM/blob/09f70244f02c56e457b16d930c9006fcd4e03629/src/getLogBF.c)
calculates Beta as covariance of dosage/phenotype divided by dosage variance.
[VCF specifies one-based POS](https://samtools.github.io/hts-specs/VCFv4.5.pdf).
These corroborate the intended coordinate/effect/enum semantics; the exact script
exporting the acquired 12-column table was not located, so its transformation is pending.

Independent primary-author reuse in the [Context-TFs notebook](https://github.com/DeplanckeLab/Context-TFs/blob/1b7b889e2173063321bd3902a72f945c5fc82eac/Pre_processing_Kumasaka_et_al_tables_step1.ipynb)
(commit `1b7b889e2173063321bd3902a72f945c5fc82eac`, source cells 7–10 and 35) filters
`Inside_Peak==1`/single-base `Ref`/`Alt` and interprets positive Beta as ALT more
accessible. Only code cells were inspected; embedded outputs were not inspected.
Their zero-collapse rule must not replace SCI02's exact-zero metrics. Keep location
as a categorical integer, not a Boolean; review unexpected values and ties explicitly.
This evidence supports a reviewed mapping proposal, not row-level validation,
GRCh37→hg38 normalization, track compatibility, frozen selection or biological completion.
Root subsequently reported a complete CRC-checked decode under a 512 MiB expansion
cap and 8,192-byte line cap: 297,308 rows / 29,004,438 decoded bytes, zero column/type
errors; location counts 0:78,801, 1:171,528, 2:46,979. Source aggregates include
226,346 technical SNV rows, 199,326 unique loci, 11,000 loci with multiple peaks,
277,128 peaks and 8,442 peaks with multiple lead rows; Beta/SE were finite and SE positive.
These are coordinator-reported source counts, not counts of approved prediction cases.

## Original Sei training split: evidence and limit

The [original Methods](https://doi.org/10.1038/s41588-022-01102-2), read through
[official XML](https://www.ebi.ac.uk/europepmc/webservices/rest/PMC9279145/fullTextXML)
(200; 121,898 bytes), reserve hg38 chr8/chr9 for test and chr10 for validation;
other chromosomes supply on-the-fly training, excluding ENCODE blacklist regions.
[train.yml](https://github.com/FunctionLab/sei-framework/blob/1e16bff9b1618af7065a23f82c4a3bb82aaeb689/train/train.yml)
at commit `1e16bff9b1618af7065a23f82c4a3bb82aaeb689` confirms these holdouts,
hg38, length 4,096, 21,907 targets and center bin [2048,2049]. Its 2,380 bytes have
SHA256 `c82d2388e613fdffbeda6de3e5ae9c0aa486df5b91db7e9148112e976a18a3df`.
The [pinned Sei-LLRA README](https://github.com/kostkalab/seillra/blob/217469410410e07b6663372da847426ffd172855/README.md)
describes post-hoc low-rank heads. This does not establish a complete training,
calibration or fine-tuning history for each cached component. Record original
chromosome membership after validated mapping; do not call the present pool or
rank-64 evaluation held-out solely from the original paper's split. Any holdout
filter must precede frozen selection; no chromosome filtering or inference ran here.

# SCI02 biological execution: completed adapter and evaluation evidence

Prepared 2026-10-14 by Nora; coordinator/writer of execution receipts: Chiquis.
This document distinguishes retained execution evidence, descriptive metrics and
reviewed aggregate exports. The exporter tests and both real exports have
completed, and both reviewed JSONs are integrated locally. External publication
and fresh hosted CI remain pending.
The source/reference stages and frozen selection are recorded in
[checkpoint004](004-kumasaka-prepool-evidence.md) and
[contract003](003-kumasaka-source-normalization.md). No protocol, cases, slots,
weights, measurements or metric definitions were changed for this export work.

## Source, prospective split and scientific scope

The source is Kumasaka/Knights/Gaffney's [public deposit](https://zenodo.org/records/1405945),
declared CC-BY-4.0: 100 GBR population lymphoblastoid cell lines, not the inaccessible
DART African caQTL table and not measured GM12878-specific QTL truth. The original
source uses GRCh37. Reviewed mapping, verified hg19 source bases and full hg38
reference windows precede the frozen 110-case selection.

The fixed head averages ALT-minus-REF probability deltas from nine GM12878 ATAC
tracks, using FP32 rank64, the upstream forward/reverse-complement average, batch1,
thread1 and no sequence-class projection. This is a descriptive transfer baseline.
Central-base peak probability and population peak-level association Beta do not
have an established common scale; raw MAE is **not calculated**. Biological accuracy,
causality and clinical usefulness are not approved by runtime checks or an exit0.

Source outcomes, tie exclusions and the prospective 256-candidate resource
presample are retained. All 512 fixed reference queries were accounted before
independent input review. Selection110 was fixed before predictions: first ten
adapter slots, then 100 different evaluation slots, with complete disjoint
4,096-base windows. Failures retain their original slots; no replacements or
post-prediction reselection are permitted. Disjoint windows do not establish LD
or statistical independence.

Chr8/9 are the [original Sei test chromosomes](https://doi.org/10.1038/s41588-022-01102-2).
The rank64 head's complete training/calibration/fine-tuning history remains unknown;
the pilot cannot claim `rank64_verified_heldout`. All actual selected cases map
on `+`, have no reference swap and nonzero source Beta. Minus mapping, swaps and
exact-zero rules are covered separately by synthetic tests, not these observations.

## Completed adapter10: observed input/runtime PASS

The original ledger SHA is
`db834741dd57f9107301d2081434329e5400c346fc4605d6dab45ee8a4a1bab5`;
report SHA is `83452f1450ce12f46e9c2d5d8adbd6cf18835531de156569c1149dac89e70987`.
Observed counts: submitted10, input-validated10, inferred10, rejected0 and pending0.
Input validation and inference are successive stages; they are not summed into
20 cases. All ten full-head outputs were finite and repeated identically under
the trusted writer; the private receipt retains nine-track probabilities, not
the complete head tensors. PASS denotes input/runtime acceptance without an
accuracy threshold. Adapter sign agreement5/10 and Spearman0.6 are descriptive
preflight observations, not a criterion for changing the subsequent100 cases.
All ten source SEs were preserved; no confidence intervals were supplied or invented.

Controller elapsed247.425s; worker peak RSS932,831,232B and watchdog peak933,007,360B.
The120-second timeout applies per loading/warmup/measurement/repeat event. Memory
monitoring uses the50ms RSS watchdog and worker self-reported peak, not a kernel
allocation cap. This biological head run does not revise SCI01's earlier,
comparable synthetic FP32/QNNPACK economic no-go for its measured configuration.

## Completed evaluation100: observed input/runtime PASS

Original100 ledger SHA:
`dac53b27f517ca7a511a49e5c0ea84120a174766d1f7a67704e2e321820ae3c9`.
After independent receipt-binder review, its derivative SHA is
`904236014cac74d617b2937a08e51a3cfbd3bf0851cc13ef9232d40ce7c1841f`.
Binding retained every case and its order. The actual evaluation ran offline on
the same retained execution handle93610 and terminated with exit0. The terminal
private report SHA is
`570d94443fc79ce9b695ee7ed874306f01b6579e5cd680060ec9bc5eff743999`.
Observed counts are submitted100, validated100, inferred100, rejected0 and pending0;
all100 outputs are finite and repeat-identical. Independent read-only review
verified the bound ledger against the original100 cases, without changes or
replacements. Nora did not restart inference or use partial values to adjust it.

Primary sign agreement is61/100 (0.61), and Spearman correlation is
0.1840864086408641 over100 effect/prediction pairs. A separate stdlib oracle used
pairwise comparisons to calculate average tied ranks and covariance; it exactly
matched these aggregates and the earlier adapter5/10 and0.6. Neither100-case
vector contains mathematical zeros, so secondary nonzero-effect sign agreement
also uses61/100. All100 source SEs are retained; supplied confidence intervals0.
Raw MAE remains not calculated because probability deltas and population Beta
have no established common scale. No significance, LD independence, causality,
clinical validation or verified rank64 training holdout is asserted.

Controller elapsed2280.947179593s; primary inference sum1132.767800271s and repeat
sum1132.541552313s. Worker peak RSS939,098,112B; watchdog peak939,290,624B. The
120-second limit remains per model event and the3GiB ceiling remains a watchdog
policy, not a kernel allocation cap. The observed runtime PASS does not set an
accuracy threshold, justify a track change or reverse SCI01's economic no-go.
The association is reported descriptively; scientific feasibility remains pending
and `biological_accuracy_approved` and `rank64_verified_heldout` remain false.

## Public runtime exporter: tested boundary and local integration

[biological_runtime_export.py](../../research/regulatory/biological_runtime_export.py)
accepts a private prefix, ledger/report paths and their exact SHA256s. It uses
bounded, no-follow `private_file` reads and `validate_ledger`, then checks complete
biological adapter10/evaluation100 status, frozen parents, configuration, supervisor,
every original record/effect/slot, source uncertainty presence and repeat flag.
Nine finite probabilities, exact ALT-minus-REF deltas and the writer's `math.fsum`
mean must agree; all aggregate metrics are recomputed and compared with JSON types
preserved. Evaluation also revalidates the pinned adapter report and its retained
content-addressed original ten-case ledger. Version1 accepts the locked observed
Python3.11.17/Torch2.14.1+cpu/aarch64 configuration.

Output uses an explicit allowlist of protocol, parent/validator hashes, technique,
stage counts, aggregate metrics, summarized times and RSS. It contains no DNA,
loci, alleles, case/origin IDs, individual scores/probabilities, raw rows, private
paths or copied diagnostics. It makes no namespace-isolation or attestation claim
from report fields. Partial/failed/mutated/nonfinite reports return a stable
failure code without a public success receipt. Export reads inputs and prints
JSON; it does not execute models, fetch data, overwrite inputs or publish externally.

The retained reproduction command produces an adapter candidate in ignored
private staging; it does not publish or replace the integrated aggregates:

```sh
python3 -B biozero/research/regulatory/biological_runtime_export.py \
  --prefix .biozero/regulatory-assets \
  --ledger .biozero/regulatory-assets/datasets/kumasaka-adapter-ledger-db834741dd57f9107301d2081434329e5400c346fc4605d6dab45ee8a4a1bab5.json \
  --ledger-sha256 db834741dd57f9107301d2081434329e5400c346fc4605d6dab45ee8a4a1bab5 \
  --report .biozero/regulatory-assets/biological-adapter-a1778b06f5d14ec195fc0b8bb81be780.json \
  --report-sha256 83452f1450ce12f46e9c2d5d8adbd6cf18835531de156569c1149dac89e70987 \
  > .biozero/biological-adapter-public-candidate.json
```

The [exporter tests](../../research/regulatory/test_biological_runtime_export.py) use
synthetic reports/ledgers only: privacy canaries, partial/failure/type/configuration
mutations, original effects/slots, vector math, invented uncertainty, forged metrics,
supervisor/timing, path/hash boundaries and full prior-adapter checks. They were
authored during the active evaluation, then Chiquis ran all13 successfully after
its terminal receipt (3.020s). Chiquis also executed both real exports. Nora's
independent review checked their counts, metrics, parents, technique and timing
against the retained private receipts and the unchanged bound/original cases.

Reviewed aggregate JSONs now integrated locally with identical candidate bytes:

| Local aggregate receipt | Bytes | SHA256 |
| --- | ---: | --- |
| [adapter10](../../research/regulatory/adapter-biological-runtime.json) | 4723 | f45e781380d5d296cf72937168d0789a3a6fc58f32a342b91ecbe93a7f44ca83 |
| [evaluation100](../../research/regulatory/evaluation-biological-runtime.json) | 4897 | a562223e4c3c8ec811da9fc9a7cc267e12602fc1bcac849a077191bf304decf3 |

The original private candidates remain regular600 files with one link; the two
integrated aggregates are regular644 files with one link. Nora verified their
exact bytes and hashes against the reviewed candidates. Schema and string checks found
no DNA, loci, alleles, case/origin IDs, individual vectors or private paths. Their
scientific approval flags remain false. Raw source/reference data, original
ledgers, per-case inference records, complete private reports and model weights
remain outside these aggregate exports. Local integration has completed;
external publication and new hosted CI have not occurred at this checkpoint.
This receipt/export acceptance does not assert native-provider, Go keeper,
namespace-lifecycle or kernel-quota acceptance.

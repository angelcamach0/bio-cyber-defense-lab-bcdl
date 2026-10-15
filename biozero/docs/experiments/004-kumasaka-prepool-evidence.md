# SCI02 source, reference and biological adapter evidence

Observed 2026-10-14 in the managed ARM64 workspace. Sections preserve successive
checkpoints, including the completed biological adapter, the evaluation launch
with results pending, and the later verified terminal100 result below. The
preparation sections were originally recorded as an uncommitted local checkpoint
above published head `57013e76831184bcd6a1153b33ebb5acb40f1ec5`. The dated
publication/CI checkpoint below supersedes that earlier state. The source-normalization
policy is [contract003](003-kumasaka-source-normalization.md); the model/head,
tracks, seed and score remain in the unchanged frozen baseline protocol.

## Actual preparation and denominators

The frozen `prepare_precandidates` was executed on the pinned private
lead, peak and official chain files. Both tables were completely CRC-decoded
through bounded reads, with private-file checks and two compressed-byte hashes.
The chain parser loaded 1,278 chains and 53,950 blocks with its required SHA pin.

| Boundary | Observed |
| --- | ---: |
| Lead rows | 297,308 |
| Peak rows | 277,128 |
| Initially eligible focal biallelic SNV rows | 156,731 |
| Focal peaks with multiple eligible lead variants | 169 |
| Rows excluded for those ties | 338 |
| Focal SNP loci associated with multiple focal peaks | 0 |
| Duplicate peak IDs | 0 |
| Technically mapped rows before resource presampling | 15,182 |
| Frozen precandidates | 256 |
| Excluded source rows | 282,126 |
| Mapped source rows outside the fixed presample | 14,926 |
| Sequence API requests during preparation | 0 |
| Biological loci predicted | 0 |

All 297,308 source outcomes and 277,128 peak outcomes are retained in a private
qualification archive. The three source status counts partition the entire
source. Diagnostic reasons can overlap and do not form a second partition:
8 ambiguous mappings, 34 gapped intervals, 129 source SNP/peak membership
conflicts, 70,962 non-biallelic-SNV rows, 125,780 non-focal rows and 141,474 rows
outside chr8/9. No effect magnitude or prediction was used to choose candidates.
Optional annotation state counts were empty for the actual pinned source.

The source and peak tables expanded to 29,004,438 and 24,305,809 bytes including
headers: 53,310,247 aggregate bytes. Their compressed sum was 21,202,953 bytes.
Table caps are aggregate 50 MiB compressed and 512 MiB expanded; the chain has
separate 8 MiB compressed and 64 MiB expanded caps. The complete preparation and
qualification serialization took 39.447 seconds, with observed maximum process
RSS 1,480,212 Linux KiB. This run additionally used a 3 GiB address-space ceiling
and 120-second alarm; this does not measure model inference memory or time.

## Immutable private receipts

| Artifact | SHA256 | Bytes |
| --- | --- | ---: |
| Lead gzip | b7a1e169153eff1fbf700270260bc7225f0c4585b1066ab2e2a65583c33a5d2e | 10,497,915 |
| Peak gzip | 1c626aea07016c98fac06dd413fa6cb75df1b035a8bb867785eb0e17ca267885 | 10,705,038 |
| Official hg19ToHg38 chain gzip | 5c0598e500ceb5a78c73086929e8ef993aec309bcafb595139b53d440b125a1d | 227,698 |
| Canonical frozen prepool | 417e7cf550909d4cdbd1dc9d6960356c47f5f06e43efa1890420a83e19f22e7f | 512,689 |
| Complete qualification JSONL gzip | 7fe82991b030a21ce877ec218242d97be914259f1cb30e07c8bc4c26cc8dd977 | 54,339,925 |

The prepool freezes every selected row, oriented source alleles, full peak/SNP
mapping, source effects and annotations, rank key, policy, asset hashes and
producer hashes before reference queries. It is not the final 110-case selection.
Minus-strand mapping complements E/O without negating Beta; target-reference
swaps cannot be resolved until the actual hg38 window is verified.

Producer `kumasaka_normalization.py`:
`c1fdc2cab3d566695dcd0249f13467e39c2ac8cf3fa5435954425c8576faa542`.
Chain parser `lift_chain.py`:
`3941be80eb56570ff13ab18d53313ebcde68a2b053a8cea9ea1d4553b5325171`.
Private preparation metadata is `.biozero/kumasaka-prepool-preparation.json`.
Raw rows, DNA, qualification archive and prepool remain ignored private assets.

## Persistent acquisition history

The immutable control-baseline receipt was explicitly migrated after checking
the known 4,251-byte response, fixed coordinates and DNA pin. The dataset ledger
remained byte-identical:
`dcc77757bd6df34f9b41e17b8593268807fd5dfbb4a775d63af4afd981fa8223`.
Its charge is 21,445,657 bytes, with nine HTTP exchanges and four verified attempts.
The control receipt SHA is
`b250c3c6c10febe8eaa7d8e1014fc77178db50ad412b600f44803b02bee5a461`.
Both acquisition entrypoints now reject reduced totals against retained pins and
baseline proof, unsafe/oversized/weakly typed histories, unresolved attempts,
and existing mapping/reference data without a ledger. Removing a cached control
does not erase its historical charge. There is no budget reset, automatic legacy
zero baseline or refund of failed read reservations. This protects trusted
research history, not a host actor rewriting all ledgers and immutable receipts.

## Next executable gate

After independent review of the current producer, frozen prepool and orchestration,
cached-only inspection uses:

```sh
python3 biozero/research/regulatory/prepare_reference_pool.py \
  --prefix .biozero/regulatory-assets \
  --prepool-sha256 417e7cf550909d4cdbd1dc9d6960356c47f5f06e43efa1890420a83e19f22e7f
```

Explicit acquisition adds `--fetch`. This prepares only the fixed group's
hg19 single-base and hg38 4,096-base references. Its immutable request plan is
saved before any GET; response/error bodies share the same 50 MiB dataset ledger,
with bounded verified HTTPS, no redirects, a 900-second phase deadline and no
automatic retries. Calls respect the recommended one-per-second cadence in the
[official UCSC API conditions](https://genome.ucsc.edu/goldenPath/help/api.html).
An access denial/challenge stops further requests and preserves every unattempted
slot. There is no expansion beyond the frozen 256.

The resulting reference pool remains explicitly pending scientific review.
Independent review must verify source REF, target central REF, strand/peak math,
single E/O conversion, context and all denominators. Only then can the final
deterministic 110 complete disjoint windows be frozen: ten adapter cases followed
by 100 evaluation cases. Every later failure retains its original slot. Neither
this evidence nor the prior artificial control establishes biological accuracy,
causality, clinical usefulness, rank64 training exclusion or economic feasibility.

## Subsequent reference acquisition

After independent pre-reference and request-orchestration reviews,
the bounded request plan was executed. All **512** GET responses were verified
and all **256** fixed candidates normalized; no replacement, retry, denial or
phase stop occurred. The prospective plan was published under the same ledger
flock before acquisition, and each attempt retains its plan SHA. A prior cached-only
run preserved 256 pending outcomes, nine HTTP exchanges and the old charge; its
receipt remains separate from this completed acquisition.

Request plan SHA:
`c68741351262abb84305dc00f33abdc00ae69a04bddc440938770f3059754794`.
Reference pool SHA:
`a97378f088e4df99249a7c6d81187658a9597feadad968864577ec3b8dc82797`;
3,235,023 private bytes. Private summary:
`.biozero/reference-pool-acquisition.json`. The dataset ledger now retains
22,575,143 charged bytes and 521 HTTP exchanges, exactly nine earlier exchanges
plus 512 reference queries. Model/checkpoint accounting was not changed.

The earlier independent pre-reference review verified the entire qualification gzip CRC
(227,453,968 expanded bytes), all 256 rank keys and chain mappings, exact journal
bindings, and samples of 16 original variant and 16 original peak rows. Among
15,257 initially eligible chr8/9 source rows, 24 tie exclusions, nine source/peak
membership conflicts, eight ambiguous mappings and 34 gapped mappings leave
15,182 mapped rows. The presample contains 152 chr8 and 104 chr9 cases, all mapped
in orientation `+`; minus-strand behavior is currently covered by synthetic tests.

The reference pool retains every receipt, raw source provenance and outcome
privately. Independent reference/input review and the final 110-case freeze are
still required. `freeze_biological_selection.py` requires that review's pinned
receipt and checks the complete source prepool's order and denominator; a truncated
110-row pool cannot assert that all 256 slots were accounted. Biological prediction
count remains **zero** at this checkpoint.

## Execution resource scope

The phase A pipeline limits are frozen and tested separately. The
current wrapper was run with locked tools: `make science
BIOZERO_TOOLS_PREFIX=/tmp/biozero-bio-tools-locked` recovered the same three synthetic
SNPs twice (TP3/FP0/FN0) and rejected the controlled invalid input. Receipt:
`biozero/docs/evidence/science/bz-exp001-7ur5_oht/evidence.json`. An earlier call using
the absent default tool prefix failed prerequisites and is retained at
`bz-exp001-egvfswcm`; it did not approve science. No new full TLS/Compose/browser
acceptance is claimed here. Aggregate workspace and retained export implementation
remain in the [artifact contract](../security/artifact-workspace-contract.md).

## Reviewed input freeze and completed biological adapter

After acquisition, independent review verified all 512 cached response bodies,
their hashes, exact genome/coordinates/URLs, one verified attempt per response,
and the prospective request-plan binding. All 256 normalized candidates matched
the source, reference and effect-orientation rules. The reviewed input receipt
is `dd8232c2a9d28a067edc4d435690536a4672e02dd6b4c83b5a3d46295fa294f0`.
It approves source/reference inputs only, not predictive accuracy or exclusion
from rank64 training. Dataset history was unchanged during offline review.

The final 110 windows were frozen from the complete ordered 256-candidate
denominator. Independent review reproduced the ordering and greedy disjoint
selection, and checked all 5,995 selected-window pairs. One overlapping candidate
was excluded before the first110; no effect magnitude or prediction influenced
selection. The split was fixed before inference: ten adapter cases, then100
evaluation cases. All110 have `+` source mapping, no target-reference swap and
nonzero source Beta; minus-strand/swap/zero behavior remains synthetic-test scope.

| Frozen private document | SHA256 |
| --- | --- |
| Selection110 | c664d2139de4b2111675cb483009ad7eed1163a9a47c4e907284e4326a2a4a56 |
| Normalization256 | ceb8f334fff48d00a97d7af54b7269b5b77a922aa7597d0cbb0798829e5057c5 |
| Original adapter10 ledger | db834741dd57f9107301d2081434329e5400c346fc4605d6dab45ee8a4a1bab5 |
| Original evaluation100 ledger | dac53b27f517ca7a511a49e5c0ea84120a174766d1f7a67704e2e321820ae3c9 |

The ten-case group contains seven chr8/three chr9 and five positive/five negative
effects; the100 group contains58chr8/42chr9 and46positive/54negative effects.
These are technical windows from a GBR population LCL caQTL study transferred
descriptively to the fixed GM12878 ATAC head. Disjoint windows do not establish
LD independence. Chr8/9 selection reduces known original Sei backbone training
overlap; it does not establish the rank64 head's training/calibration exclusion.

The actual adapter10 was executed using the locked Python3.11.17/Torch2.14.1
CPU environment inside a user/network namespace with only loopback. No datasets
or weights were downloaded during inference. The pinned source, fixed FP32
rank64 head, full21,907 outputs, nine GM12878 ATAC tracks, both-strand upstream
forward, batch1 and thread1 were unchanged; projection remained disabled.

All10 cases completed measurement and repeat. Outputs were finite in[0,1] and
all head outputs repeated identically. The original private report is
`.biozero/regulatory-assets/biological-adapter-a1778b06f5d14ec195fc0b8bb81be780.json`,
23,193 bytes, SHA256
`83452f1450ce12f46e9c2d5d8adbd6cf18835531de156569c1149dac89e70987`.
Controller elapsed247.425s; worker peak RSS932,831,232bytes, watchdog peak
933,007,360bytes. Measurement times were11.294–11.633s/pair; repeats
11.292–11.877s/pair. The120-second deadline applies separately to each model
loading/warmup/measurement/repeat event, not the whole ten-case run.

The adapter's descriptive sign agreement was5/10 and Spearman0.6 on10 cases.
There was no accuracy threshold for adapter PASS: PASS denotes input/runtime
checks. All10 supplied source standard errors; no source confidence intervals
were present or invented. Raw MAE against source Beta was not calculated because
the model probability delta and source effect are not on an established common
scale. Scientific feasibility remains pending, and no100-case biological result
is claimed at this checkpoint. This head/input run does not revise the earlier
comparable61-class FP32/QNNPACK cost finding.

Before binding evaluation, independent review found that the first receipt binder accepted
altered parent/configuration metadata and missing prediction vectors. The binder
was corrected to require the pinned original ten-case ledger, its frozen parents,
source commit, ACGT/both-strand configuration, ready flag and supervisor success;
each record must match its original normalized effect/slot and have nine finite,
bounded probabilities, exact ALT-minus-REF deltas and the writer's mean score.
Seven mutation/contract tests passed, and the actual report passes these checks.
The report is evidence under a trusted host/writer, not external attestation or
proof of retained full-head tensors. Binding creates a derivative100 ledger
without changing cases/order or overwriting the original ledger.

Fresh local `make test` at this checkpoint passed197Python tests (144regulatory)
and test/vet checks in eight Go modules; simulated-adversary has no Go tests.
The artifact-executor library is included in those local checks. Its providers,
authenticated RPC server and worker integration remain pending. No new hosted
CI, full TLS/Compose/browser acceptance or100-case inference is asserted here.

## Evaluation launch after receipt review

Independent validation rejected12/12 receipt mutations, passed7/7 binder tests, and
verified the real report against the original private ten-case parent. Both
parent validation and the bound100-case validation were ready, with cases/order
unchanged. `attach_adapter_receipt.py` was then run with the explicit pinned
adapter and evaluation ledgers. The immutable derivative100 ledger SHA is
`904236014cac74d617b2937a08e51a3cfbd3bf0851cc13ef9232d40ce7c1841f`.
The original100 ledger remains unchanged. Binding is not inference.

At approximately21:50UTC, the actual100-case evaluation started in a
user/network namespace using the same locked environment and frozen protocol.
The private launch handoff is `.biozero/kumasaka-evaluation-live-handoff.json`;
it records the execution session, source hashes and fixed parents. The private
outer summary is `.biozero/kumasaka-evaluation-execution.json`. Poll the retained
handle rather than relaunching the model or treating a progress file as liveness.
The controller preserves original slots and completed progress if execution
fails. Results and scientific feasibility remain pending at this launch
checkpoint; a later terminal receipt must establish actual completion.

## Subsequent terminal evaluation and local aggregate integration

The same retained handle93610 subsequently terminated with exit0; no inference
was restarted and no cases were replaced. The terminal private report SHA is
`570d94443fc79ce9b695ee7ed874306f01b6579e5cd680060ec9bc5eff743999`.
All100 original slots were validated and inferred, with rejected0, pending0,
finite outputs and identical repeats. Independent review confirmed that the bound
ledger still contains the original100 cases in the same order.

Descriptive primary and secondary sign agreement are61/100; average-tied-rank
Spearman correlation is0.1840864086408641 over100 pairs. An independent stdlib
oracle exactly reproduced these metrics. All100 source SEs were retained, with
zero supplied confidence intervals. MAE was not calculated because source Beta
and model probability deltas have no established common scale. Controller elapsed
2280.947s; worker peak RSS939,098,112bytes and watchdog peak939,290,624bytes.
PASS denotes input/runtime acceptance. Scientific feasibility and biological
accuracy approval remain pending; training holdout and LD independence are not
established, and the earlier comparable economic no-go is unchanged.

The reviewed adapter10/evaluation100 aggregate JSONs are now integrated locally,
with exact bytes matching their private staging candidates. External publication
and fresh hosted CI remain pending. Raw data, per-case records, private reports
and weights are excluded from these aggregate exports. The preceding pending
sections preserve their historical checkpoint scope. See
[completed evaluation and export evidence005](005-biological-evaluation.md)
for frozen parent/report hashes, public aggregate links, privacy checks and limits.

## Subsequent verified publication and hosted CI, 2026-10-14

The reviewed59-file source/aggregate snapshot was published as
[28918a9](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/commit/28918a96484dcb2a015c71540f853d29e34a9836)
to [draft PR21](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/pull/21).
Independent readback verified its head and open/draft/unmerged state, and
[hosted ARM CI run38651583022](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38651583022)
with [job116151397770](https://github.com/angelcamach0/bio-cyber-defense-lab-bcdl/actions/runs/38651583022/job/116151397770)
completed successfully. Checkout used merge ref
`e56751a6e481d29fc4f09546212567bcd802a01b` into unchanged main.

CI logs confirm231 Python cases (229passed/two kernel skips), eight Go module
test/vet checks, PKI, synthetic scientific repeat and78 protected native
assertions. CI did not execute the biological100 model, the new native-provider/
helper kernel opt-ins, Compose or Firefox. Local100 measurements and subsequent
standalone native Unix/lifecycle acceptance keep their separate evidence and
source scopes. The new Unix/recovery tests were not part of this published
snapshot. Publication is to the draft branch, with no main merge or deployment.
The earlier pending-publication notes remain historical; these documentation
updates await their own commit. See [evidence005](005-biological-evaluation.md)
for aggregate privacy, descriptive metrics and unchanged scientific limits.

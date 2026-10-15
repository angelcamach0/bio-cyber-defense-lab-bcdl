# Extracted worker detection

This Linux Go package extracts detection/scoring from `../main.go` without
changing that worker or installing a new execution path. It does not verify
cryptography, authorize a tenant, evaluate variant accuracy or permit release.
`Context` contains facts established by the protected host before capsule entry.
Context names/error text and private paths are never copied into `Result`.

```go
result, err := analysis.Evaluate(ctx, facts, rules, pipelineJSON, privateFASTQPath)
```

`Rules` preserves the existing JSON names and defaults: HighScore0.9,
LowScore0.1, ThreatMinReads50, ThreatMinFraction0.02, FastpMinQ300.75,
CriticalWarningScoreBoost0.2, HighThreshold0.8 and MediumThreshold0.5.
Zero values in these fields receive defaults. MaxSizeBytes, filename tokens and
panel have no invented defaults. HighScore remains unused by scoring, as before.
`LoadRules` retains legacy read/parse fallback with a separate stable diagnostic;
`LoadRulesStrict` treats that diagnostic as fatal, bounds the file to64KiB and
rejects duplicate/unknown/case-alias/null rule fields. It reads source bytes once.
The host must separately hash/pin and protect its configured sources.
The CLI additionally requires panel presence to agree between rules and trusted
argv; it remaps a configured nonempty panel path without disabling detection.

`Score` contains the pure calculation and typed signals with the existing JSON
shape. Filename, size, decryption/signature, critical-warning, Q30 and panel-hit
boosts retain their existing order and values, score clamping and inclusive
verdict thresholds. Pipeline count has priority over the alignment denominator;
alignment count is a fallback only when pipeline count is zero. Q30 prefers
after-filtering over before-filtering, and zero Q30 does not trigger its boost.
Warnings still classify by error/failed/fatal, then warn, then informational.
Other pipeline fields are ignored. The package preserves best-effort empty
metrics for malformed pipeline JSON; the CLI accepts only valid object/null JSON.
Nonfinite Q30/rules fail explicitly rather than yielding unencodable results.

`ParseSAM` is pure streaming input processing. Its counters describe SAM records,
not deduplicated biological reads: every non-header line increments TotalReads,
even an incomplete record; a third field other than `*` increments MappedReads.
Secondary/supplementary records retain their historical counting behavior.
Changing those definitions needs a separate methodological review.

The trusted `Supervisor` has a default600-second deadline, constrained by earlier
parent cancellation. It invokes only `minimap2 -a PANEL CONTENT` without a shell.
The executable comes from trusted Go configuration/PATH, never stdin. Limits:

| Quantity | Maximum |
| --- | ---: |
| Total SAM stdout, including headers/delimiters |64MiB |
| One scanner line, excluding its line ending |1MiB |
| Non-header records |1,000,000 |
| Distinct targets |128 |
| Target name |128 printable ASCII bytes |
| Stderr |64KiB |

Zero limit fields select defaults; trusted callers may only reduce limits.
The parser stores one bounded line and bounded target counts; stderr is counted,
never retained or logged. Group cancellation kills descendants on timeout,
parent cancellation or output failure, including when the leader already exited.
A context callback closes stdout to unblock a held pipe, and WaitDelay bounds
stderr-pipe teardown. The configured capsule's PID namespace supervisor remains
responsible for authoritative namespace-wide quiescence and custody.

Intentional failure change: missing inputs/tools, process failure, timeout,
cancellation, parsing/read errors or budget excess return a stable error with
zero partial metrics. The previous worker could use accumulated SAM metrics after
an alignment process failed. The new boundary cannot represent that failed
alignment as completed detection. Raw stderr/paths are never error codes.
No success result is truncated to fit a wire budget.

Tests are scoped to pure scoring/parsing, strict configuration/JSON/privacy, and
small synthetic shell producers. They do not exercise a real minimap2 build,
capsule kernel boundaries, host crypto, protected-worker integration or science.
Observed2026-10-15UTC after coordinated CPU release: the analysis package's11
top-level tests with25 subcases passed ordinarily(0.783s) and with Go's race
detector(1.850s). The CLI's separate4 tests/11 subcases passed too, including
the corrected panel-presence guard and nonempty host-to-capsule path mapping. Explicit
`go vet ./analysis ./cmd/capsule-analysis` exited0. Commands used GOMAXPROCS1,
GOTOOLCHAIN=local, GOPROXY=off and GOSUMDB=off; no dependency/network acquisition.
These tests do not launch a standalone compiled CLI binary. Vale subsequently
read the corrected panel guard without rerunning tests and identified no further
blocker. Package/CLI integration into the worker or capsule remains separate.

## Subsequent compiled-binary checkpoint

Root recorded two Linux/ARM64 builds on2026-10-15UTC with separate initially empty
GOCACHE directories, Go1.26.7(Red Hat1.26.7-2.el9_8), CGO_ENABLED0,
GOTOOLCHAIN=local, GOENV=off, empty GOFLAGS, GOPROXY/GOSUMDB=off,
`-trimpath -buildvcs=false -ldflags=-buildid=` and GOMAXPROCS1.
Both exited0(14.839s/13.929s). Nora independently read both ELF binaries:
3,565,542 bytes each, ARM64 machine183, byte-identical SHA256
`cb95d52dcf6c601039a4f801fd4b1ca02fa16a8c89b7a87706ffbc553fd1edf6`.
The private build receipt SHA256 is
`1dcd571b5daf550fde94156d8fe420decd31760cbdd93a106f77ab01e3714edf`.
Readback verified all11 recorded source/go.mod pins and the local Go executable
hash. This proves local binary repeatability in one toolchain/environment;
initial cache state is recorded execution evidence, not independently recreated.
There is no cross-host, second-toolchain, AMD64 or OCI-image reproduction claim.

Root also executed that standalone CLI with real minimap2 2.31-r1302 against
the public variant-smoke reads/reference and synthetic rules/context. The output
records1,171 mapped SAM records out of1,171 total, one target, score0.9/high and
threat_panel_hit. These are record metrics, not unique-read or biological-accuracy
claims. Nora independently matched the private output to its aggregate summary,
binary/tool/rules/input/reference pins and source; no alignment was rerun.
Summary SHA256:
`b6f8fbdb9da354f9ee5fa47d2f2085aa5f1676eb230a2d57e216b3bf9bfcd696`.
Evidence remains under ignored
`.biozero/analysis-repro-build-20261015T002250.270419Z/`; target names and raw
output remain private. Caller crypto facts were synthetic. No broker, capsule,
protected-worker TLS/signature/decryption, image or biological model was exercised
by that CLI acceptance. Pinning/integrating the binary into those paths remains
the next step; these local receipts have not become hosted-CI evidence.

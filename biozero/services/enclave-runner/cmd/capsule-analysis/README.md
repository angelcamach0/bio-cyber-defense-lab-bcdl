# Pinned capsule analysis CLI

This executable is a local capsule component. The existing worker remains
unchanged. It exposes no RPC, arbitrary command selection or user-supplied paths.
The host must pin this executable, rules, panel and source context before use;
the CLI does not attest those pins itself.

Exact trusted argv order:

```text
capsule-analysis --rules /run/biozero/rules.json --panel /run/biozero/panel.fa --content /workspace/input.fastq
```

All three pairs are required. Paths must be absolute and clean. Panel presence
must agree between rules and argv: `--panel` may be empty only if
Rules.ThreatPanelFasta is empty, and a configured panel requires a nonempty argv
path. Either mismatch fails with `analysis_panel_config_mismatch` before tools.
Only a nonempty rules path may be remapped to a nonempty capsule path; argv
cannot silently enable or disable configured detection.
Only these argv values can choose rules/panel/content. The CLI never obtains
them from stdin, and never accepts executable/limit flags. Its inherited PATH
must be the capsule's fixed trusted tool path. Rules failures are fatal before
tools; valid zero-valued rules receive the existing defaults.

Stdin is one UTF-8 JSON value, at most65,536 bytes including whitespace:

```json
{"schema_version":1,"context":{"original_name":"synthetic.fastq","processed_size_bytes":17,"decrypted":true,"decryption_error":"","signature_valid":true,"signature_error":""},"pipeline":{"read_count":3,"avg_read_length":100,"warnings":[]}}
```

All top/context fields are required, with exact spelling/types and no extras or
nulls. Pipeline is an object or null, with its full valid content passed to the
existing metric extraction. Duplicate keys anywhere, trailing values, invalid
UTF-8, nesting beyond32, negative processed size, or context strings over4096
bytes fail. Crypto flags/errors are protected-host facts, not self-authentication.
The stdin schema has no FASTQ/path-selection, source-pin, command or release
authority fields. Incidental path strings inside ignored pipeline metadata do
not select files or get copied into detection output.

Stdout is exactly one bounded typed JSON response plus newline, at most65,536
bytes. The CLI writes no stderr diagnostics, usage text, paths or input content.
On success, exit0:

```json
{"schema_version":1,"status":"succeeded","error_code":"","warnings":[],"detection":{"score":0.1,"reason":"no suspicious indicators","verdict":"low","signals":{"warnings":{"critical":0,"warn":0,"info":0},"integrity":{"signature_valid":true,"decrypted":true},"pipeline":{"read_count":3,"avg_read_length":100}}}}
```

On failure, exit1:

```json
{"schema_version":1,"status":"failed","error_code":"rules_read_error","warnings":[],"detection":null}
```

Errors are stable categories for config, request, rules, metric, alignment or
response failure. Diagnostic text never fills error_code. Oversized responses
produce a small failed envelope, never an accepted JSON prefix. Output write
failure exits1 without attempting a second response. `succeeded` means detection
completed; it provides no accuracy/scientific approval or release permission.
Configured alignment failure discards every partial metric. See the
[package scope and bounds](../../analysis/README.md).

Reproduction command from the enclave-runner module:

```sh
CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -buildvcs=false \
  -ldflags=-buildid= -o /absolute/private/destination/capsule-analysis ./cmd/capsule-analysis
```

Use an explicitly pinned Go toolchain and GOOS/GOARCH; hash the resulting binary
and record sources/build configuration. Go module dependencies are stdlib only;
this creates no image-build claim. The subsequent local builds below also fixed
GOENV=off, empty GOFLAGS, GOMAXPROCS1 and GOPROXY/GOSUMDB=off.
Observed2026-10-15UTC after the panel-presence correction:
the CLI core's4 tests/11 subcases passed ordinarily(0.024s) and with the race
detector(1.041s). These include both incoherences, both-empty configuration and
nonempty remapping through a synthetic shell alignment producer. The analysis
package's11 tests/25 subcases passed separately(0.783s/1.850s). Explicit scoped go vet
exited0. Tests invoke `run` with synthetic streams and paths; they do not launch a
standalone compiled CLI binary. That source/test checkpoint used no model, real
alignment, Docker/image build or network operation. Its scope remains distinct
from the subsequent standalone execution below.

## Subsequent actual binary and alignment

The private build receipt recorded two independent-cache builds with the same local
Go1.26.7(Red Hat1.26.7-2.el9_8) toolchain on Linux/ARM64. Both exited0 and produced
byte-identical3,565,542-byte ELF binaries with SHA256:
`cb95d52dcf6c601039a4f801fd4b1ca02fa16a8c89b7a87706ffbc553fd1edf6`.
Receipt SHA256:
`1dcd571b5daf550fde94156d8fe420decd31760cbdd93a106f77ab01e3714edf`.
Independent readback verified byte equality, both hashes/sizes, all11 source/go.mod
pins and the current Go executable hash by reading existing files, without a
build rerun. This is same-environment binary repeatability; cross-host/toolchain,
AMD64 and bit-identical OCI reconstruction remain untested.

The compiled CLI was then run with actual minimap2 2.31-r1302 and the public
variant-smoke fixture, synthetic rules and synthetic caller crypto facts.
Observed:1,171 mapped/1,171 total SAM records, one target, score0.9/high with
threat_panel_hit. Readback matched private output aggregates and all binary,
source, minimap2, rules, input and reference pins without repeating execution.
Summary SHA256:
`b6f8fbdb9da354f9ee5fa47d2f2085aa5f1676eb230a2d57e216b3bf9bfcd696`.
Private evidence root:
`.biozero/analysis-repro-build-20261015T002250.270419Z/`.
No target names, raw alignment output or FASTQ are exported here. SAM counts do
not establish unique-read counts or biological accuracy. This acceptance did not
exercise broker/capsule/worker integration, TLS or real crypto verification, and
did not build an image or execute a model. The binary now has a measured local
pin; integration and its own acceptance remain next steps.

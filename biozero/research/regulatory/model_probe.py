#!/usr/bin/env python3
"""Offline trained Sei-LLRA runtime probe; synthetic pairs are not biology evidence.

Only manually verified checkpoints are loaded. FP32 and quantized CPU execute
in separate supervised processes. The pinned upstream forward is reused with
locally assembled modules; factories, downloads and torch.compile are disabled.
"""
import argparse
import collections.abc
import importlib
import importlib.machinery
import json
import math
import os
from pathlib import Path
import platform
import resource
import selectors
import signal
import subprocess
import sys
import time
import threading
import types
import uuid

from checkpoint_fetch import SOURCE_COMMIT, atomic_json, load_manifest, verify_file

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MAX_RSS = 3 << 30
MAX_INPUT_SECONDS = 120
MAX_PROTOCOL_BYTES = 16 << 20
SEED = 20261014


class ProbeError(RuntimeError):
    pass


def verify_source(source):
    source = Path(source).resolve()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(source), *args], text=True, timeout=10).strip()
    if git("rev-parse", "HEAD") != SOURCE_COMMIT:
        raise ProbeError("source cache is not at the approved Sei-LLRA commit")
    if git("config", "--get", "remote.origin.url") != "https://github.com/kostkalab/seillra.git":
        raise ProbeError("source cache origin differs from the approved repository")
    if git("status", "--porcelain", "--untracked-files=no"):
        raise ProbeError("pinned source has tracked modifications")
    # Avoid executing package initializers/factories. Relevant modules and data
    # must be tracked at this commit, and namespace initializers must stay absent.
    for relative in ("dist/seillra/src/sei_parts.py", "dist/seillra/src/model_wrappers.py",
                     "dist/seillra/dat/config.yaml", "dist/seillra/dat/histone_inds.npy",
                     "dist/seillra/dat/seqclass.names", "dist/seillra/dat/target.names"):
        git("ls-files", "--error-unmatch", relative)
    for relative in ("dist/seillra/src/__init__.py", "dist/seillra/dat/__init__.py"):
        if (source / relative).exists():
            raise ProbeError("unexpected source namespace initializer")
    return source


def local_parts(source):
    """Import public pinned modules while making every factory inaccessible."""
    sys.dont_write_bytecode = True
    base = source / "dist" / "seillra"
    for name, directory in (("seillra", base), ("seillra.src", base / "src")):
        module = types.ModuleType(name)
        module.__path__ = [str(directory)]
        module.__spec__ = importlib.machinery.ModuleSpec(name, loader=None, is_package=True)
        module.__spec__.submodule_search_locations = module.__path__
        sys.modules[name] = module
    factories = types.ModuleType("seillra.src.get_models")
    def blocked(*unused_args, **unused_kwargs):
        raise ProbeError("network/model factories are disabled in this offline probe")
    for name in ("get_sei_head_llra", "get_sei_projection", "get_sei_trunk"):
        setattr(factories, name, blocked)
    sys.modules[factories.__name__] = factories
    parts = importlib.import_module("seillra.src.sei_parts")
    wrappers = importlib.import_module("seillra.src.model_wrappers")
    return parts, wrappers


def verified_paths(prefix, variant):
    manifest = load_manifest()
    required = ("trunk_fp32", "head64_fp32", "projection_fp32") if variant == "fp32" else ("trunk_cpu", "head64_cpu", "projection_fp32")
    entries = {entry["component"]: entry for entry in manifest["files"]}
    paths = {}
    for component in required:
        entry = entries[component]
        path = Path(prefix) / "checkpoints" / entry["filename"]
        if not verify_file(path, entry):
            raise ProbeError("required checkpoint is absent or differs from the approved size/SHA256: " + component)
        paths[component] = path
    return paths, {component: entries[component]["sha256"] for component in required}


def construct_model(torch, parts, wrappers, paths, variant):
    def load(module, path):
        state = torch.load(path, map_location="cpu", weights_only=True)
        if not isinstance(state, collections.abc.Mapping):
            raise ProbeError("checkpoint is not a state_dict mapping")
        module.load_state_dict(state, strict=True)
        del state
        return module.eval()
    trunk = parts.SeiTrunk(sequence_length=4096).eval()
    head = parts.SeiHeadLLRA(k=64).eval()
    if variant == "fp32":
        trunk = load(trunk, paths["trunk_fp32"])
        head = load(head, paths["head64_fp32"])
    else:
        from torch.ao.quantization import QConfigMapping, get_default_qconfig
        from torch.ao.quantization.quantize_fx import prepare_fx, convert_fx
        # Upstream initializes the spline tensor using this exact input shape
        # before FX conversion. eval mode is required by current FX fusion.
        trunk(torch.zeros(1, 4, 4096))
        mapping = QConfigMapping().set_global(get_default_qconfig("fbgemm"))
        trunk = convert_fx(prepare_fx(trunk, mapping, (torch.zeros(1, 4, 4096),)))
        trunk = load(trunk, paths["trunk_cpu"])
        head = convert_fx(prepare_fx(head, mapping, (torch.zeros(1, 15360),)))
        head = parts.QuantizedSeiHead(load(head, paths["head64_cpu"]))
    projection = load(parts.SeiProjection(), paths["projection_fp32"])
    projection.set_mode("variant")
    # Bypass the upstream constructor because it invokes downloading factories.
    # Its exact pinned forward performs both strands and variant normalization.
    model = wrappers.Sei_LLRA.__new__(wrappers.Sei_LLRA)
    torch.nn.Module.__init__(model)
    model.trunk, model.head, model.proj = trunk, head, projection
    model.projection, model.mode, model.compile = True, "variant", False
    model.quant = "CPU" if variant == "cpu" else None
    model.device = torch.device("cpu")
    return model.eval()


def event(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def worker(args):
    event({"event": "phase", "phase": "loading"})
    source = verify_source(args.source)
    paths, pins = verified_paths(args.prefix, args.variant)
    import torch
    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)
    torch.manual_seed(SEED)
    initial_engine = torch.backends.quantized.engine
    if args.engine != "current":
        if args.engine not in torch.backends.quantized.supported_engines:
            raise ProbeError("requested quantization engine is unavailable")
        torch.backends.quantized.engine = args.engine
    parts, wrappers = local_parts(source)
    generator = torch.Generator(device="cpu").manual_seed(SEED)
    pairs = []
    input_digest = __import__("hashlib").sha256()
    for index in range(args.pairs):
        bases = torch.randint(0, 4, (4096,), generator=generator)
        reference = torch.nn.functional.one_hot(bases, num_classes=4).T.to(torch.float32).unsqueeze(0).contiguous()
        alternate = reference.clone()
        position = 2048 + index % 31
        base = int(bases[position])
        alternate[0, base, position] = 0
        alternate[0, (base + 1) % 4, position] = 1
        input_digest.update(reference.numpy().tobytes())
        input_digest.update(alternate.numpy().tobytes())
        pairs.append((reference, alternate))
    started = time.monotonic()
    with torch.inference_mode():
        model = construct_model(torch, parts, wrappers, paths, args.variant)
        load_seconds = time.monotonic() - started
        quantized_types = sorted(set(type(module).__module__ + "." + type(module).__name__
                                   for module in model.modules()
                                   if ".quantized." in type(module).__module__))
        records = []
        checks = {"finite": True, "repeat_identical": True, "shape_1x61": True,
                  "one_hot_1x4x4096": True, "batch_one": True}
        if args.variant == "cpu":
            checks["quantized_conv1d_present"] = any(name.rsplit(".",1)[-1] in ("Conv1d","ConvReLU1d") for name in quantized_types)
            checks["quantized_linear_present"] = any(name.rsplit(".",1)[-1] in ("Linear","LinearReLU") for name in quantized_types)
        def infer(pair, phase, index):
            event({"event": "phase", "phase": phase, "pair_index": index})
            start = time.monotonic()
            output = model(pair)
            elapsed = time.monotonic() - start
            if not isinstance(output, tuple) or len(output) != 2:
                raise ProbeError("canonical variant wrapper returned an unexpected output")
            for value in output:
                checks["finite"] = checks["finite"] and bool(torch.isfinite(value).all())
                checks["shape_1x61"] = checks["shape_1x61"] and list(value.shape) == [1, 61]
            return output, elapsed
        _, warmup_seconds = infer(pairs[0], "warmup", 0)
        for index, pair in enumerate(pairs):
            checks["one_hot_1x4x4096"] = checks["one_hot_1x4x4096"] and all(
                list(value.shape) == [1, 4, 4096] and bool((value.sum(dim=1) == 1).all()) for value in pair)
            output, elapsed = infer(pair, "measure", index)
            repeated, repeat_seconds = infer(pair, "repeat", index)
            checks["repeat_identical"] = checks["repeat_identical"] and all(torch.equal(a, b) for a, b in zip(output, repeated))
            reference, alternate = output
            delta = alternate - reference
            records.append({"pair_index": index, "seconds": elapsed, "repeat_seconds": repeat_seconds,
                            "ref_projection": reference[0].tolist(), "alt_projection": alternate[0].tolist(),
                            "variant_delta": delta[0].tolist()})
    maximum = max([load_seconds, warmup_seconds] + [duration for record in records for duration in (record["seconds"], record["repeat_seconds"])])
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    checks["rss_within_ceiling"] = peak <= args.max_rss_bytes
    checks["phase_within_time_budget"] = maximum <= args.seconds_per_input
    report = {"schema_version": 1, "variant": args.variant,
              "status": "passed" if all(checks.values()) else "failed", "checks": checks,
              "trained_weights_loaded": True, "strict_state_dict": True, "weights_only": True,
              "source_commit": SOURCE_COMMIT, "checkpoint_sha256": pins,
              "python": platform.python_version(), "torch": torch.__version__, "architecture": platform.machine(),
              "initial_engine": initial_engine, "effective_engine": torch.backends.quantized.engine,
              "qconfig": "fbgemm" if args.variant == "cpu" else None,
              "quantized_operator_types": quantized_types,
              "seed": SEED, "threads": 1, "batch": 1, "input_shape": [1, 4, 4096],
              "input_sha256": input_digest.hexdigest(), "pairs": args.pairs,
              "channel_order": ["A","C","G","T"], "reverse_complement": "canonical torch.flip over channel and length axes",
              "fx_adaptations": ["eval before current FX fusion", "tuple example inputs"] if args.variant == "cpu" else [],
              "load_seconds": load_seconds, "warmup_seconds": warmup_seconds,
              "peak_rss_bytes": peak, "records": records,
              "scope": "Seeded synthetic mutation pairs; trained-weight compatibility and resource/numeric observations only; biological validation pending."}
    event({"event": "report", "report": report})
    return 0 if report["status"] == "passed" else 1


def process_rss(pid):
    try:
        for line in Path("/proc/{}/status".format(pid)).read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        return 0
    return 0


def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def supervise(command, pairs, rss_limit=MAX_RSS, seconds_per_input=MAX_INPUT_SECONDS):
    if sys.platform != "linux" or not 0 < rss_limit <= MAX_RSS or not 0 < seconds_per_input <= MAX_INPUT_SECONDS or pairs not in (1, 10, 100):
        raise ProbeError("unsupported resource budget or platform")
    env = os.environ.copy()
    env.update(OMP_NUM_THREADS="1", MKL_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", NUMEXPR_NUM_THREADS="1",
               CUDA_VISIBLE_DEVICES="", PYTHONDONTWRITEBYTECODE="1")
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        total = math.ceil(seconds_per_input * (2 * pairs + 2)) + 1
        resource.setrlimit(resource.RLIMIT_CPU, (total, total))
    started = time.monotonic()
    previous_term = None
    if threading.current_thread() is threading.main_thread():
        previous_term = signal.getsignal(signal.SIGTERM)
        def terminate(unused_signum, unused_frame):
            raise ProbeError("probe controller received SIGTERM")
        signal.signal(signal.SIGTERM, terminate)
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=env, start_new_session=True, preexec_fn=limits)
    except BaseException:
        if previous_term is not None:
            signal.signal(signal.SIGTERM, previous_term)
        raise
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffer, diagnostic = bytearray(), bytearray()
    phase_deadline = started + seconds_per_input
    total_deadline = started + seconds_per_input * (2 * pairs + 2) + 1
    phases, peak, report, failure = 0, 0, None, None
    received = 0
    try:
        while selector.get_map():
            now = time.monotonic()
            peak = max(peak, process_rss(process.pid))
            if peak > rss_limit:
                failure = "rss_ceiling_exceeded"
                break
            if now > min(phase_deadline, total_deadline):
                failure = "phase_deadline_exceeded"
                break
            for key, _ in selector.select(timeout=0.05):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                received += len(data)
                if received > MAX_PROTOCOL_BYTES:
                    failure = "worker_output_ceiling_exceeded"
                    break
                if key.data == "stderr":
                    if len(diagnostic) < 65536:
                        diagnostic.extend(data[:65536-len(diagnostic)])
                    continue
                buffer.extend(data)
                while b"\n" in buffer:
                    line, _, rest = buffer.partition(b"\n")
                    buffer = bytearray(rest)
                    try:
                        message = json.loads(line)
                    except (ValueError, UnicodeDecodeError):
                        failure = "worker_protocol_invalid"
                        break
                    if message.get("event") == "phase":
                        phases += 1
                        if phases > 2 * pairs + 2 or message.get("phase") not in ("loading", "warmup", "measure", "repeat"):
                            failure = "worker_phase_protocol_invalid"
                            break
                        phase_deadline = time.monotonic() + seconds_per_input
                    elif message.get("event") == "report" and report is None:
                        report = message.get("report")
                    else:
                        failure = "worker_protocol_invalid"
                        break
                if failure:
                    break
            if failure:
                break
        if failure:
            stop_group(process)
        else:
            process.wait(timeout=min(5, max(0.001, total_deadline-time.monotonic())))
    except BaseException:
        stop_group(process)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if previous_term is not None:
            signal.signal(signal.SIGTERM, previous_term)
    elapsed = time.monotonic() - started
    if failure is None and (process.returncode != 0 or not isinstance(report, dict)):
        failure = "worker_failed_or_report_missing"
    if failure is None and (report.get("peak_rss_bytes", rss_limit+1) > rss_limit or report.get("status") != "passed"):
        failure = "worker_resource_or_checks_failed"
    if failure:
        return {"status": "failed", "error_code": failure, "returncode": process.returncode,
                "seconds": elapsed, "watchdog_peak_rss_bytes": peak,
                "diagnostic_type": "worker stderr present" if diagnostic else None,
                "partial_report": report}
    report["supervisor"] = {"returncode": process.returncode, "seconds": elapsed,
                            "watchdog_peak_rss_bytes": peak, "rss_ceiling_bytes": rss_limit,
                            "seconds_per_phase": seconds_per_input,
                            "memory_enforcement": "50 ms RSS watchdog plus self-reported peak; not RLIMIT_AS or a kernel allocation cap",
                            "cpu_time_total_limit_seconds": math.ceil(seconds_per_input * (2 * pairs + 2)) + 1}
    return report


def numeric_comparison(reports):
    if any(report.get("status") != "passed" for report in reports.values()) or set(reports) != {"fp32", "cpu"}:
        return {"status": "pending", "reason": "both verified model variants must execute successfully"}
    baseline, quantized = reports["fp32"], reports["cpu"]
    if baseline["input_sha256"] != quantized["input_sha256"]:
        raise ProbeError("model variants used different synthetic inputs")
    if baseline["pairs"] != quantized["pairs"] or len(baseline["records"]) != baseline["pairs"] or len(quantized["records"]) != quantized["pairs"]:
        raise ProbeError("model variants contain unequal or incomplete pair records")
    differences = {name: [] for name in ("ref_projection", "alt_projection", "variant_delta")}
    for index,(first, second) in enumerate(zip(baseline["records"], quantized["records"])):
        if first["pair_index"] != index or second["pair_index"] != index:
            raise ProbeError("model pair ordering differs")
        for name in differences:
            if len(first[name]) != len(second[name]):
                raise ProbeError("model output dimensions disagree")
            differences[name].extend(abs(a-b) for a, b in zip(first[name], second[name]))
    return {"status": "measured", "pairs": baseline["pairs"],
            "differences": {name: {"maximum_absolute": max(values), "mean_absolute": math.fsum(values)/len(values)}
                            for name, values in differences.items()},
            "scope": "Numerical differences on synthetic input only; no biological accuracy or selective recomputation claim."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=ROOT / ".biozero" / "regulatory-assets")
    parser.add_argument("--source", type=Path, default=ROOT / ".biozero" / "seillra")
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--variant", choices=("fp32", "cpu", "both"), default="both")
    parser.add_argument("--pairs", type=int, choices=(1, 10, 100), default=1)
    parser.add_argument("--engine", default="current", choices=("current", "x86", "qnnpack", "fbgemm", "onednn"))
    parser.add_argument("--max-rss-bytes", type=int, default=MAX_RSS)
    parser.add_argument("--seconds-per-input", type=float, default=MAX_INPUT_SECONDS)
    parser.add_argument("--run", action="store_true", help="Explicitly load verified local trained weights; never downloads")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "pending", "trained_weights_loaded": False,
                          "network_access_performed": False, "scientific_feasibility": "pending",
                          "reason": "explicit --run required after manual checkpoint verification"}, indent=2))
        return 0
    if args.worker:
        try:
            return worker(args)
        except Exception as exc:
            event({"event": "report", "report": {"status": "failed", "error_type": type(exc).__name__,
                  "reason": str(exc)[:512], "scientific_feasibility": "pending"}})
            return 1
    if sys.platform != "linux":
        raise ProbeError("RSS supervision requires Linux /proc")
    variants = ("fp32", "cpu") if args.variant == "both" else (args.variant,)
    reports = {}
    for variant in variants:
        command = [str(args.python), str(Path(__file__).resolve()), "--worker", "--run",
                   "--source", str(args.source.resolve()), "--prefix", str(args.prefix.resolve()),
                   "--variant", variant, "--pairs", str(args.pairs), "--engine", args.engine,
                   "--max-rss-bytes", str(args.max_rss_bytes), "--seconds-per-input", str(args.seconds_per_input)]
        reports[variant] = supervise(command, args.pairs, args.max_rss_bytes, args.seconds_per_input)
    report = {"schema_version": 1, "experiment": "SCI01-trained-weight-synthetic-runtime",
              "status": "passed" if all(value["status"] == "passed" for value in reports.values()) else "failed",
              "source_commit": SOURCE_COMMIT, "variants": reports, "numeric_comparison": numeric_comparison(reports),
              "scientific_feasibility": "pending", "network_access_performed": False,
              "scope": "Runtime/checkpoint/resource probe on seeded synthetic pairs; not a 100-pair biological benchmark."}
    args.prefix.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(args.prefix, 0o700)
    destination = args.prefix / ("model-probe-" + uuid.uuid4().hex + ".json")
    atomic_json(destination, report)
    # Prediction arrays stay in the private report; never print checkpoint data.
    print(json.dumps({"status": report["status"], "report": str(destination),
                      "variants": {key: value["status"] for key, value in reports.items()},
                      "numeric_comparison": report["numeric_comparison"], "scientific_feasibility": "pending"}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProbeError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__, "scientific_feasibility": "pending"}))
        raise SystemExit(1)

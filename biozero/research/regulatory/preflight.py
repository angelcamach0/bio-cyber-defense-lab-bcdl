#!/usr/bin/env python3
"""Offline synthetic CPU quantization probe; never loads a trained checkpoint."""
import argparse
import copy
import datetime
import importlib
import importlib.metadata
import io
import json
import os
import platform
import sys
from pathlib import Path


def _read_int(path):
    try:
        value = Path(path).read_text().strip()
        return int(value) if value != "max" else None
    except (OSError, ValueError):
        return None


def runtime_metadata():
    memory = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                memory = int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    limit = _read_int("/sys/fs/cgroup/memory.max")
    if limit is None:
        limit = _read_int("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    # A huge v1 sentinel is not a meaningful container limit.
    limits = [x for x in (memory, limit) if x is not None and 0 < x < 2 ** 60]
    cpu_quota = None
    try:
        quota, period = Path("/sys/fs/cgroup/cpu.max").read_text().split()
        if quota != "max":
            cpu_quota = int(quota) / int(period)
    except (OSError, ValueError, ZeroDivisionError):
        pass
    try:
        torch_version = importlib.metadata.version("torch")
    except importlib.metadata.PackageNotFoundError:
        torch_version = None
    return {
        "python": platform.python_version(),
        "python_version_info": list(sys.version_info[:3]),
        "architecture": platform.machine(),
        "platform": platform.platform(),
        "logical_cpu_count": os.cpu_count(),
        "cpu_quota_cores": cpu_quota,
        "host_memory_bytes": memory,
        "cgroup_memory_limit_bytes": limit,
        "effective_memory_ceiling_bytes": min(limits) if limits else None,
        "torch_distribution_version": torch_version,
    }


def synthetic_probe(torch, engine, qconfig_backend="fbgemm"):
    from torch.ao.quantization import QConfigMapping, get_default_qconfig
    from torch.ao.quantization.quantize_fx import convert_fx, prepare_fx

    class TinyModel(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.conv = torch.nn.Conv1d(4, 8, kernel_size=3, padding=1)
            self.relu = torch.nn.ReLU()
            self.flatten = torch.nn.Flatten()
            self.linear = torch.nn.Linear(8 * 32, 6)

        def forward(self, value):
            return self.linear(self.flatten(self.relu(self.conv(value))))

    previous_engine = torch.backends.quantized.engine
    previous_threads = torch.get_num_threads()
    try:
        torch.backends.quantized.engine = engine
        torch.set_num_threads(1)
        with torch.random.fork_rng(devices=[]), torch.inference_mode():
            torch.manual_seed(20261014)
            model = TinyModel().eval()
            sample = torch.linspace(-1.0, 1.0, 4 * 4 * 32).reshape(4, 4, 32)
            baseline = model(sample)
            mapping = QConfigMapping().set_global(get_default_qconfig(qconfig_backend))

            def converted():
                prepared = prepare_fx(copy.deepcopy(model), mapping, (sample,))
                prepared(sample)
                return convert_fx(prepared)

            quantized = converted()
            output = quantized(sample)
            repeated = quantized(sample)
            buffer = io.BytesIO()
            torch.save(quantized.state_dict(), buffer)
            payload_bytes = buffer.tell()
            buffer.seek(0)
            restored = converted()
            restored.load_state_dict(torch.load(buffer, map_location="cpu", weights_only=True))
            restored_output = restored(sample)
            quantized_types = sorted(set(
                type(module).__module__ + "." + type(module).__name__
                for module in quantized.modules()
                if ".quantized." in type(module).__module__
            ))
            conv_seen = any(name.rsplit(".", 1)[-1] in ("Conv1d", "ConvReLU1d") for name in quantized_types)
            linear_seen = any("Linear" in name for name in quantized_types)
            checks = {
                "input_finite": bool(torch.isfinite(sample).all()),
                "fp32_output_finite": bool(torch.isfinite(baseline).all()),
                "quantized_output_finite": bool(torch.isfinite(output).all()),
                "restored_output_finite": bool(torch.isfinite(restored_output).all()),
                "repeat_identical": bool(torch.equal(output, repeated)),
                "state_dict_roundtrip_identical": bool(torch.equal(output, restored_output)),
                "quantized_conv1d_present": conv_seen,
                "quantized_linear_present": linear_seen,
                "output_shape_expected": list(output.shape) == [4, 6],
            }
            return {
                "status": "passed" if all(checks.values()) else "failed",
                "seed": 20261014,
                "threads": 1,
                "input_shape": list(sample.shape),
                "output_shape": list(output.shape),
                "checks": checks,
                "quantized_module_types": quantized_types,
                "serialized_synthetic_state_dict_bytes": payload_bytes,
                "max_abs_difference_from_synthetic_fp32": float((output - baseline).abs().max()),
                "scope": "Tiny untrained Conv1d + Linear only; no checkpoint or scientific accuracy validation.",
            }
    finally:
        torch.backends.quantized.engine = previous_engine
        torch.set_num_threads(previous_threads)


def build_report(metadata=None, torch_loader=None, engine="current", qconfig_backend="fbgemm"):
    metadata = runtime_metadata() if metadata is None else metadata
    report = {
        "schema_version": 1,
        "experiment": "SCI01-offline-synthetic-preflight",
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "runtime": metadata,
        "requested_engine": engine,
        "requested_qconfig_backend": qconfig_backend,
        "network_access_performed": False,
        "trained_weights_loaded": False,
        "checkpoint_compatibility": "pending",
        "scientific_feasibility": "pending",
        "synthetic_probe": {"status": "pending"},
    }
    if tuple(metadata["python_version_info"][:2]) < (3, 10):
        report["reason"] = "Python >= 3.10 required for the pinned Sei-LLRA source annotations."
        return report
    try:
        torch = (torch_loader or (lambda: importlib.import_module("torch")))()
    except ImportError as exc:
        report["reason"] = "Torch unavailable; synthetic execution is pending."
        report["diagnostic"] = str(exc)
        return report
    except Exception as exc:
        report["reason"] = "Torch import failed; synthetic execution is pending."
        report["diagnostic"] = "{}: {}".format(type(exc).__name__, exc)
        return report
    report["torch_imported_version"] = str(torch.__version__)
    engines = list(torch.backends.quantized.supported_engines)
    report["supported_quantized_engines"] = engines
    report["initial_quantized_engine"] = torch.backends.quantized.engine
    effective_engine = torch.backends.quantized.engine if engine == "current" else engine
    report["effective_quantized_engine"] = effective_engine
    try:
        qconfig = torch.ao.quantization.get_default_qconfig(qconfig_backend)
        report["requested_qconfig"] = str(qconfig)
    except Exception as exc:
        report["reason"] = "Requested qconfig unavailable; real-model compatibility remains pending."
        report["diagnostic"] = "{}: {}".format(type(exc).__name__, exc)
        return report
    if effective_engine not in engines or effective_engine == "none":
        report["reason"] = "Requested engine is not executable according to this Torch build."
        return report
    try:
        report["synthetic_probe"] = synthetic_probe(torch, effective_engine, qconfig_backend)
    except Exception as exc:
        report["synthetic_probe"] = {
            "status": "failed", "diagnostic": "{}: {}".format(type(exc).__name__, exc)
        }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    parser.add_argument("--engine", default="current", help="current preserves Torch's default, as pinned Sei does")
    parser.add_argument("--qconfig", default="fbgemm", help="Observer configuration; separate from the execution engine")
    args = parser.parse_args()
    report = build_report(engine=args.engine, qconfig_backend=args.qconfig)
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(serialized)
    else:
        print(serialized, end="")
    # Pending is informative, never reported as a synthetic pass.
    return 1 if report["synthetic_probe"]["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())

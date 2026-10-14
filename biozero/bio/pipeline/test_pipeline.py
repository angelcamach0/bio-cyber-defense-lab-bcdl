# SPDX-License-Identifier: AGPL-3.0-only
import argparse
import contextlib
import importlib.util
import io
import gzip
import hashlib
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("biozero_pipeline", HERE / "pipeline.py")
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.input = self.directory / "input.fastq"
        self.input.write_text("@read\nACGT\n+\nIIII\n")
        self.reference = self.directory / "ref.fa"
        self.reference.write_text(">synthetic\nACGT\n")

    def args(self, mode="variants"):
        return argparse.Namespace(input=str(self.input), reference=str(self.reference),
                                  out_dir=str(self.directory), mode=mode)

    def test_stats_requires_no_bioinformatics_tools(self):
        with patch.object(pipeline.shutil, "which", side_effect=AssertionError("not needed")):
            report, status = pipeline.execute(self.args("stats"))
        self.assertEqual(status, 0)
        self.assertEqual(report["pipeline_status"], "succeeded")
        self.assertEqual(report["read_count"], 1)
        self.assertNotIn("variants_vcf", report["outputs"])

    def test_invalid_fastq_emits_stable_json(self):
        for data in ("", "@x\nACGT\n+\n", "x\nACGT\n+\nIIII\n",
                     "@x\nACGT\n+\nIII\n", "@x\nACXT\n+\nIIII\n",
                     "@x\nACGT\n+x2\nIIII\n"):
            with self.subTest(data=data):
                self.input.write_text(data)
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured):
                    status = pipeline.main([str(self.input), "--mode", "stats"])
                report = json.loads(captured.getvalue())
                self.assertEqual(status, 1)
                self.assertEqual(report["pipeline_status"], "failed")
                self.assertEqual(report["errors"][0]["code"], "invalid_input")

    def test_variants_missing_tool_is_incomplete(self):
        with patch.object(pipeline.shutil, "which", return_value=None), patch.object(pipeline, "run_cmd") as run:
            report, status = pipeline.execute(self.args())
        run.assert_not_called()
        self.assertEqual(status, 2)
        self.assertEqual(report["pipeline_status"], "incomplete")
        self.assertEqual(report["errors"][0]["code"], "missing_tool")

    def fake_tools(self, failed_stage=None, omit_artifact=False):
        self.commands = []

        def run(cmd, stdout_path=None, timeout_seconds=600):
            self.commands.append(cmd)
            action = cmd[1]
            if action == failed_stage:
                return subprocess.CompletedProcess(cmd, 9, "", "upstream failure")
            if omit_artifact:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if stdout_path:
                Path(stdout_path).write_text("SAM artifact\n")
            if action == "faidx":
                Path(cmd[2] + ".fai").write_text("synthetic\t4\t11\t4\t5\n")
            if "-o" in cmd:
                output = Path(cmd[cmd.index("-o") + 1])
                output.write_text("#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n")
            if action == "index":
                Path(cmd[2] + (".bai" if cmd[0] == "samtools" else ".csi")).write_text("index\n")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return run

    def test_upstream_failure_never_calls_or_releases_vcf(self):
        with patch.object(pipeline.shutil, "which", side_effect=lambda name: name), \
             patch.object(pipeline, "run_cmd", side_effect=self.fake_tools("mpileup")):
            report, status = pipeline.execute(self.args())
        self.assertEqual(status, 1)
        self.assertEqual(report["pipeline_status"], "failed")
        self.assertEqual(report["errors"][0]["stage"], "mpileup")
        self.assertFalse(any(command[1] == "call" for command in self.commands))
        self.assertNotIn("variants_vcf", report["outputs"])

    def test_index_failure_is_not_success(self):
        with patch.object(pipeline.shutil, "which", side_effect=lambda name: name), \
             patch.object(pipeline, "run_cmd", side_effect=self.fake_tools("index")):
            report, status = pipeline.execute(self.args())
        self.assertEqual(status, 1)
        self.assertEqual(report["errors"][0]["stage"], "bam_index")
        self.assertFalse(any(command[1] == "mpileup" for command in self.commands))

    def test_zero_exit_missing_output_rejected(self):
        with patch.object(pipeline.shutil, "which", side_effect=lambda name: name), \
             patch.object(pipeline, "run_cmd", side_effect=self.fake_tools(omit_artifact=True)):
            report, status = pipeline.execute(self.args())
        self.assertEqual(status, 1)
        self.assertEqual(report["errors"][0]["code"], "missing_output")

    def test_new_run_directory_cannot_reuse_old_outputs(self):
        with patch.object(pipeline.shutil, "which", side_effect=lambda name: name), \
             patch.object(pipeline, "run_cmd", side_effect=self.fake_tools()):
            first, code = pipeline.execute(self.args())
            second, code2 = pipeline.execute(self.args())
        self.assertEqual((code, code2), (0, 0))
        self.assertNotEqual(first["output_dir"], second["output_dir"])
        self.assertEqual(first["variant_count"], 0)

    def test_expanded_fastq_line_limit_without_newline(self):
        compressed = self.directory / "huge.fastq.gz"
        with gzip.open(compressed, "wb") as stream:
            stream.write(b"@" + b"X" * 200000)
        with patch.dict(os.environ, {"BIOZERO_PIPELINE_MAX_BYTES": "1024"}):
            with self.assertRaisesRegex(ValueError, "expanded FASTQ"):
                pipeline.fastq_stats(compressed)

    def test_reference_size_cap_prevents_all_tool_calls(self):
        with patch.dict(os.environ, {"BIOZERO_PIPELINE_MAX_REFERENCE_BYTES": "4"}), \
             patch.object(pipeline.shutil, "which", side_effect=lambda name: name), \
             patch.object(pipeline, "run_cmd") as run:
            report, status = pipeline.execute(self.args())
        run.assert_not_called()
        self.assertEqual(status, 1)
        self.assertEqual(report["errors"][0]["code"], "reference_size_limit")
        self.assertNotIn("variants_vcf", report["outputs"])

    def test_cli_invalid_budget_fails_as_json_before_tools(self):
        for name, value in (("BIOZERO_TOOL_STDERR_BYTES", "0"), ("BIOZERO_PIPELINE_MAX_BYTES", "no")):
            completed = subprocess.run([sys.executable, str(HERE / "pipeline.py"), str(self.input), "--mode", "variants"],
                env=dict(os.environ, **{name: value}), capture_output=True, text=True, timeout=5)
            self.assertEqual(completed.returncode, 1)
            report = json.loads(completed.stdout)
            self.assertEqual(report["errors"][0]["code"], "resource_config_invalid")
            self.assertEqual(report["outputs"], {})

    def test_real_cli_records_kernel_limit_stats_compatible(self):
        completed = subprocess.run([sys.executable, str(HERE / "pipeline.py"), str(self.input), "--mode", "stats"],
                                   capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["resource_budget"]["file_enforcement"], "kernel_rlimit_fsize")
        self.assertEqual(report["resource_budget"]["workspace_aggregate_enforcement"], "pending")
        self.assertEqual(report["read_count"], 1)

    def test_sort_temp_prefix_is_inside_own_workspace(self):
        with patch.object(pipeline.shutil, "which", side_effect=lambda name: name), \
             patch.object(pipeline, "run_cmd", side_effect=self.fake_tools()):
            report, status = pipeline.execute(self.args())
        self.assertEqual(status, 0)
        sort = next(command for command in self.commands if command[1] == "sort")
        self.assertEqual(Path(sort[sort.index("-T") + 1]).parent, Path(report["output_dir"]))

    def test_actual_tool_overflow_fails_even_after_output_and_exit_zero(self):
        tools = self.directory / "tools"
        tools.mkdir()
        marker = self.directory / "later-stage"
        code = ("#!" + sys.executable + "\nimport os,sys,pathlib\n"
                "if sys.argv[1]=='faidx':\n pathlib.Path(sys.argv[2]+'.fai').write_text('index')\n os.write(2,b'X'*65537)\n"
                "else:\n pathlib.Path(" + repr(str(marker)) + ").write_text('CALLED')\n")
        for name in ("minimap2", "samtools", "bcftools"):
            tool = tools / name
            tool.write_text(code)
            tool.chmod(0o700)
        command = [sys.executable, str(HERE / "pipeline.py"), str(self.input), "--mode", "variants",
                   "--reference", str(self.reference), "--out-dir", str(self.directory)]
        completed = subprocess.run(command, env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ.get("PATH", "")),
                                   capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["pipeline_status"], "failed")
        self.assertEqual(report["errors"][0]["code"], "tool_output_limit")
        self.assertEqual(report["outputs"], {})
        self.assertFalse(marker.exists())
        self.assertEqual(report["resource_budget"]["file_enforcement"], "kernel_rlimit_fsize")

    def test_corrupt_deflate_emits_invalid_input_json_without_tools(self):
        corrupt = self.directory / "corrupt.fastq.gz"
        # GZIP magic and header are valid; DEFLATE's reserved block type is not.
        corrupt.write_bytes(bytes.fromhex("1f8b0800000000000003") + b"\x07" + bytes(8))
        args = self.args()
        args.input = str(corrupt)
        with patch.object(pipeline.shutil, "which", side_effect=AssertionError("tools must not be resolved")), \
             patch.object(pipeline, "run_cmd") as run:
            report, status = pipeline.execute(args)
        run.assert_not_called()
        self.assertEqual((status, report["errors"][0]["code"]), (1, "invalid_input"))
        completed = subprocess.run([sys.executable, str(HERE / "pipeline.py"), str(corrupt), "--mode", "variants",
                                   "--reference", str(self.reference)], capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 1)
        report = json.loads(completed.stdout)
        self.assertEqual(report["pipeline_status"], "failed")
        self.assertEqual(report["errors"][0]["code"], "invalid_input")
        self.assertEqual(report["outputs"], {})
        self.assertEqual(report["tools"], {})
        self.assertNotIn("Traceback", completed.stderr)

    def test_reference_copy_exact_and_one_extra_byte(self):
        for size in (64, 65):
            with self.subTest(size=size):
                source = self.directory / ("reference-" + str(size))
                destination = self.directory / ("copied-" + str(size))
                original = b"A" * size
                source.write_bytes(original)
                if size == 64:
                    digest = pipeline.copy_reference(source, destination, 64)
                    self.assertEqual(destination.read_bytes(), original)
                    self.assertEqual(digest, hashlib.sha256(original).hexdigest())
                else:
                    with self.assertRaises(pipeline.BudgetError) as raised:
                        pipeline.copy_reference(source, destination, 64)
                    self.assertEqual(raised.exception.code, "reference_size_limit")
                    self.assertLessEqual(destination.stat().st_size, 64)
                self.assertEqual(source.read_bytes(), original)

    def test_complete_fastq_exact_and_one_extra_byte(self):
        original = self.input.read_bytes()
        for limit in (len(original), len(original) - 1):
            with self.subTest(limit=limit), patch.dict(os.environ, {"BIOZERO_PIPELINE_MAX_BYTES": str(limit)}):
                if limit == len(original):
                    self.assertEqual(pipeline.fastq_stats(self.input), (1, 4, 4))
                else:
                    with self.assertRaisesRegex(ValueError, "expanded FASTQ"):
                        pipeline.fastq_stats(self.input)
                completed = subprocess.run([sys.executable, str(HERE / "pipeline.py"), str(self.input), "--mode", "stats"],
                                           capture_output=True, text=True, timeout=5)
                report = json.loads(completed.stdout)
                self.assertEqual(completed.returncode, 0 if limit == len(original) else 1)
                self.assertEqual(report["pipeline_status"], "succeeded" if limit == len(original) else "failed")
        self.assertEqual(self.input.read_bytes(), original)

    def test_real_child_timeout_is_collected(self):
        result = pipeline.run_cmd([sys.executable, "-c", "import time; time.sleep(5)"], timeout_seconds=0.05)
        self.assertEqual(result.returncode, 124)


if __name__ == "__main__":
    unittest.main()

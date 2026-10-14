# SPDX-License-Identifier: AGPL-3.0-only
import argparse
import contextlib
import importlib.util
import io
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

    def test_real_child_timeout_is_collected(self):
        result = pipeline.run_cmd([sys.executable, "-c", "import time; time.sleep(5)"], timeout_seconds=0.05)
        self.assertEqual(result.returncode, 124)


if __name__ == "__main__":
    unittest.main()

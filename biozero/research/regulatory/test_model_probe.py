"""Real subprocess budget controls, offline source and incomplete-asset checks.

These tests do not load trained checkpoints and do not assert model compatibility.
"""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location("model_probe",HERE/"model_probe.py")
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProcessBudgetTests(unittest.TestCase):
    def test_real_sleep_exceeds_phase_deadline(self):
        script="import json,time;print(json.dumps({'event':'phase','phase':'loading'}),flush=True);time.sleep(5)"
        started=time.monotonic()
        result=probe.supervise([sys.executable,"-u","-c",script],1,seconds_per_input=0.1)
        self.assertEqual(result["status"],"failed")
        self.assertEqual(result["error_code"],"phase_deadline_exceeded")
        self.assertLess(time.monotonic()-started,2)

    def test_real_allocation_exceeds_rss_ceiling(self):
        script="import json,time;print(json.dumps({'event':'phase','phase':'loading'}),flush=True);x=bytearray(64*1024*1024);time.sleep(5)"
        result=probe.supervise([sys.executable,"-u","-c",script],1,rss_limit=32<<20,seconds_per_input=2)
        self.assertEqual(result["status"],"failed")
        self.assertEqual(result["error_code"],"rss_ceiling_exceeded")
        self.assertGreater(result["watchdog_peak_rss_bytes"],32<<20)

    def test_missing_worker_report_is_not_approved(self):
        result=probe.supervise([sys.executable,"-c","pass"],1,seconds_per_input=1)
        self.assertEqual(result["status"],"failed")
        self.assertEqual(result["error_code"],"worker_failed_or_report_missing")

    def test_unbounded_phase_protocol_is_rejected(self):
        script="import json,time\nfor i in range(8): print(json.dumps({'event':'phase','phase':'loading'}),flush=True)\ntime.sleep(5)"
        result=probe.supervise([sys.executable,"-u","-c",script],1,seconds_per_input=1)
        self.assertEqual(result["error_code"],"worker_phase_protocol_invalid")

    def test_controller_interrupt_kills_its_worker_group(self):
        self.check_controller_signal(signal.SIGINT)

    def test_controller_sigterm_kills_its_worker_group(self):
        self.check_controller_signal(signal.SIGTERM)

    def check_controller_signal(self, selected_signal):
        with tempfile.TemporaryDirectory() as root:
            marker=Path(root)/"started"
            escaped=Path(root)/"escaped"
            child="import pathlib,time;pathlib.Path({!r}).write_text('started');time.sleep(1);pathlib.Path({!r}).write_text('escaped');time.sleep(5)".format(str(marker),str(escaped))
            controller="import sys;sys.path.insert(0,{!r});import model_probe;model_probe.supervise({!r},1,seconds_per_input=5)".format(str(HERE),[sys.executable,"-u","-c",child])
            process=subprocess.Popen([sys.executable,"-c",controller],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:
                deadline=time.monotonic()+3
                while not marker.exists() and time.monotonic()<deadline:
                    time.sleep(0.01)
                self.assertTrue(marker.exists())
                process.send_signal(selected_signal)
                process.communicate(timeout=3)
                self.assertNotEqual(process.returncode,0)
                time.sleep(1.1)
                self.assertFalse(escaped.exists())
            finally:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGKILL)
                    process.communicate(timeout=3)

    def test_incomplete_checkpoints_are_rejected_without_torch_load(self):
        with tempfile.TemporaryDirectory() as root:
            checkpoints=Path(root)/"checkpoints";checkpoints.mkdir()
            (checkpoints/"trunk-fp32.pth").write_bytes(b"incomplete")
            with self.assertRaises(probe.ProbeError):
                probe.verified_paths(root,"fp32")

    def test_numeric_comparison_rejects_incomplete_pairs(self):
        record={"pair_index":0,"ref_projection":[1.0],"alt_projection":[2.0],"variant_delta":[1.0]}
        baseline={"status":"passed","input_sha256":"same","pairs":1,"records":[record]}
        incomplete={"status":"passed","input_sha256":"same","pairs":1,"records":[]}
        with self.assertRaises(probe.ProbeError):
            probe.numeric_comparison({"fp32":baseline,"cpu":incomplete})

    def test_budget_cannot_exceed_authorized_ceiling(self):
        for settings in ({"rss_limit":probe.MAX_RSS+1},{"seconds_per_input":121}):
            with self.subTest(settings=settings),self.assertRaises(probe.ProbeError):
                probe.supervise([sys.executable,"-c","pass"],1,**settings)


if __name__=="__main__":
    unittest.main()

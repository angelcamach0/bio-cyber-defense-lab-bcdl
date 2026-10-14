"""Verify cleanup of a worker's own session including a separate child group."""
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('run_experiment', pathlib.Path(__file__).with_name('run_experiment.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CleanupTest(unittest.TestCase):
    def test_cleanup_separate_child_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = pathlib.Path(tmp) / 'child.pid'
            code = ('import pathlib,subprocess,sys,time; '
                    'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],process_group=0); '
                    'pathlib.Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(60)')
            # Python 3.9 on RHEL does not expose process_group; use POSIX preexec.
            code = code.replace('process_group=0', 'preexec_fn=__import__("os").setpgrp')
            process = subprocess.Popen([sys.executable, '-c', code, str(marker)], start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(marker.exists())
                child = int(marker.read_text())
                runner.stop_processes([process])
                self.assertIsNotNone(process.poll())
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    stat = pathlib.Path(f'/proc/{child}/stat')
                    if not stat.exists() or stat.read_text().rsplit(')', 1)[1].split()[0] == 'Z':
                        break
                    time.sleep(0.05)
                else:
                    self.fail('tool child survived cleanup')
            finally:
                runner.stop_processes([process])


if __name__ == '__main__':
    unittest.main()

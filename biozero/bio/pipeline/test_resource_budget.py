# SPDX-License-Identifier: AGPL-3.0-only
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from resource_budget import Budget, BudgetError, bounded_command

HERE = Path(__file__).resolve().parent


class BudgetTests(unittest.TestCase):
    def test_config_strict_and_overflow(self):
        names = ("BIOZERO_PIPELINE_MAX_FILE_BYTES", "BIOZERO_PIPELINE_MAX_REFERENCE_BYTES",
                 "BIOZERO_PIPELINE_MAX_BYTES", "BIOZERO_TOOL_STDOUT_BYTES",
                 "BIOZERO_TOOL_STDERR_BYTES", "BIOZERO_PIPELINE_TIMEOUT_SECONDS")
        for name in names:
            for bad in ("", "0", "-1", "oops", "9223372036854775808", " 1", "+1"):
                with self.subTest(name=name, value=bad), patch.dict(os.environ, {name: bad}):
                    with self.assertRaises(BudgetError):
                        Budget.from_env()
        with patch.dict(os.environ, {"BIOZERO_PIPELINE_MAX_FILE_BYTES": "1024"}):
            with self.assertRaises(BudgetError):
                Budget.from_env()

    def test_binary_capture_exact_and_extra_stdout_stderr(self):
        for stream in (1, 2):
            for count in (1024, 1025):
                result = bounded_command([sys.executable, "-c", f"import os;os.write({stream},b'X'*{count})"],
                                         budget=Budget(stdout_bytes=1024, stderr_bytes=1024))
                data = result.stdout if stream == 1 else result.stderr
                self.assertEqual(len(data), 1024)
                self.assertEqual(result.error_code, "" if count == 1024 else "tool_output_limit")
                self.assertEqual(result.returncode, 0 if count == 1024 else 125)

    def test_two_pipes_are_drained_without_deadlock(self):
        result = bounded_command([sys.executable, "-c",
            "import os\nfor i in range(32):\n os.write(1,b'A'*1024);os.write(2,b'B'*1024)"],
            budget=Budget(stdout_bytes=32768, stderr_bytes=32768))
        self.assertEqual((result.returncode, len(result.stdout), len(result.stderr)), (0, 32768, 32768))

    def test_closed_pipes_do_not_disable_timeout(self):
        before = time.monotonic()
        result = bounded_command([sys.executable, "-c", "import os,time;os.close(1);os.close(2);time.sleep(5)"], timeout_seconds=0.05)
        self.assertEqual((result.returncode, result.error_code), (124, "timeout"))
        self.assertLess(time.monotonic() - before, 2)

    def test_stdout_file_no_clobber_and_private_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sam"
            result = bounded_command([sys.executable, "-c", "print('SAM')"], stdout_path=path)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            again = bounded_command([sys.executable, "-c", "print('REPLACED')"], stdout_path=path)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(path.read_text(), "SAM\n")

    def test_cwd_and_all_temp_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            script = "import os,json;print(json.dumps([os.getcwd(),os.environ['TMPDIR'],os.environ['TMP'],os.environ['TEMP']]))"
            result = bounded_command([sys.executable, "-c", script], cwd=temp)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout), [temp] * 4)

    def execute_private_wrapper(self, code, args=(), env=None):
        command = [sys.executable, "-c", "import sys;sys.path.insert(0,sys.argv.pop(1));" + code, str(HERE), *map(str, args)]
        return subprocess.run(command, capture_output=True, text=True,
                              env=dict(os.environ, **(env or {})), timeout=5)

    def test_kernel_fsize_write_and_sparse_truncate(self):
        for action in ("write", "truncate"):
            with tempfile.TemporaryDirectory() as temp:
                script = """
import os,errno,json,resource
from resource_budget import Budget,apply_kernel_file_limit
apply_kernel_file_limit(Budget(file_bytes=4096))
p=os.path.join(sys.argv[1],'artifact')
with open(p,'wb') as f:
 if sys.argv[2]=='write': f.write(b'x'*4096);f.flush()
 else: f.truncate(4096)
 exact=os.stat(p).st_size
try:
 with open(p,'ab') as f:
  if sys.argv[2]=='write': f.write(b'x');f.flush()
  else: f.truncate(4097)
except OSError as e:
 print(json.dumps({'exact':exact,'after':os.stat(p).st_size,'errno':e.errno,'limits':resource.getrlimit(resource.RLIMIT_FSIZE)}))
else: raise SystemExit(8)
"""
                result = self.execute_private_wrapper(script, (temp, action))
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report, {"exact": 4096, "after": 4096, "errno": errno.EFBIG, "limits": [4096, 4096]})

    def test_kernel_hard_limit_inherited_and_cannot_raise(self):
        code = """
import json,subprocess
from resource_budget import Budget,apply_kernel_file_limit
apply_kernel_file_limit(Budget(file_bytes=4096))
child='import resource,json; print(json.dumps(resource.getrlimit(resource.RLIMIT_FSIZE))); resource.setrlimit(resource.RLIMIT_FSIZE,(8192,8192))'
p=subprocess.run([sys.executable,'-c',child],capture_output=True,text=True)
print(json.dumps({'limits':json.loads(p.stdout),'code':p.returncode}))
"""
        result = self.execute_private_wrapper(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"limits": [4096, 4096], "code": 1})

    def test_kernel_sigxfsz_child_is_explicit_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            code = """
import json,signal
from resource_budget import Budget,apply_kernel_file_limit,bounded_command
apply_kernel_file_limit(Budget(file_bytes=4096))
child="import signal;signal.signal(signal.SIGXFSZ,signal.SIG_DFL);open(__import__('sys').argv[1],'wb').write(b'x'*4097)"
p=bounded_command([sys.executable,'-c',child,sys.argv[1]])
print(json.dumps({'code':p.returncode,'error':p.error_code}))
"""
            result = self.execute_private_wrapper(code, (Path(temp) / "artifact",))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {"code": 125, "error": "artifact_file_limit"})

    def test_owned_and_shared_cleanup_kills_leader_exit_descendant(self):
        for mode in ("owned", "shared"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                pidpath, marker = Path(temp) / "pid", Path(temp) / "marker"
                code = """
import json,os,time
from resource_budget import own_job_group,bounded_command
before=os.getpgrp();own_job_group();after=os.getpgrp()
child="import os,sys,time;pid=os.fork();"+"\\nif pid==0:\\n open(sys.argv[1],'w').write(str(os.getpid()));time.sleep(0.7);open(sys.argv[2],'w').write('ALIVE');os._exit(0)\\nelse: os._exit(0)"
p=bounded_command([sys.executable,'-c',child,sys.argv[1],sys.argv[2]],timeout_seconds=0.15)
print(json.dumps({'code':p.returncode,'error':p.error_code,'before':before,'after':after,'pid':os.getpid()}))
"""
                result = self.execute_private_wrapper(code, (pidpath, marker), {"BIOZERO_PIPELINE_GROUP_MODE": mode})
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual((report["code"], report["error"]), (124, "timeout"))
                if mode == "owned":
                    self.assertEqual(report["after"], report["pid"])
                else:
                    self.assertEqual(report["before"], report["after"])
                pid = int(pidpath.read_text())
                self.assertFalse(Path(f"/proc/{pid}").exists(), "descendant not killed/reaped")
                time.sleep(0.75)
                self.assertFalse(marker.exists())

    def test_shared_cleanup_preserves_unrelated_same_group_sibling(self):
        # The outer test is the parent of both; shared cleanup must not infer
        # ownership from PGID and kill the unrelated sibling or this parent.
        sibling = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(5)"])
        self.addCleanup(lambda: (sibling.kill(), sibling.wait()) if sibling.poll() is None else None)
        code = """
import json,os
from resource_budget import own_job_group,bounded_command
own_job_group()
p=bounded_command([sys.executable,'-c','import time;time.sleep(5)'],timeout_seconds=0.05)
print(json.dumps({'code':p.returncode}))
"""
        result = self.execute_private_wrapper(code, env={"BIOZERO_PIPELINE_GROUP_MODE": "shared"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"code": 124})
        self.assertIsNone(sibling.poll())

    def test_tool_inherits_job_pgid_without_new_session(self):
        code = """
import json,os
from resource_budget import own_job_group,bounded_command
own_job_group()
p=bounded_command([sys.executable,'-c','import os;print(os.getpgrp())'])
print(json.dumps({'parent':os.getpgrp(),'child':int(p.stdout)}))
"""
        result = self.execute_private_wrapper(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["parent"], report["child"])


if __name__ == "__main__":
    unittest.main()

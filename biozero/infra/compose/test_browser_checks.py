"""Offline contract/privacy tests; these do not replace real browser evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("browser_checks",HERE/"browser_checks.py")
browser=importlib.util.module_from_spec(spec)
spec.loader.exec_module(browser)


class BrowserContractTests(unittest.TestCase):
    def test_only_https_loopback_origin(self):
        self.assertEqual(browser.check_origin("https://127.0.0.1:8083"),"https://127.0.0.1:8083")
        for value in ("http://127.0.0.1:8083","https://outside.example","https://secret@localhost:8083","https://localhost:8083/path"):
            with self.subTest(value=value),self.assertRaises(browser.BrowserFailure):
                browser.check_origin(value)

    def test_launch_retains_tls_and_disables_os_root_import(self):
        options=browser.launch_options("/private/profile")
        self.assertIs(options["ignore_https_errors"],False)
        self.assertIs(options["firefox_user_prefs"]["security.enterprise_roots.enabled"],False)
        self.assertEqual(options["user_data_dir"],"/private/profile")

    def test_profile_initializes_only_private_nss_and_demo_ca(self):
        with tempfile.TemporaryDirectory() as root,patch.object(browser.subprocess,"run") as run:
            ca=Path(root)/"ca.crt";ca.write_text("public demo CA")
            profile=browser.make_profile(root,ca)
            self.assertEqual(profile.stat().st_mode&0o777,0o700)
            commands=[call.args[0] for call in run.call_args_list]
            self.assertEqual(commands[0][:3],["certutil","-N","--empty-password"])
            self.assertIn("sql:"+str(profile),commands[0])
            self.assertIn("C,,",commands[1])
            self.assertEqual(commands[1][-1],str(ca.resolve()))

    def test_invitations_must_stay_inside_private_with_private_permissions(self):
        origin="https://localhost:8083"
        with tempfile.TemporaryDirectory() as root:
            private=Path(root)/"private";private.mkdir(mode=0o700)
            path=private/"invitations.json"
            rows=[{"id":"reviewer-"+suffix,"access_code":suffix*43,"origin":origin} for suffix in ("a","b")]
            path.write_text(json.dumps(rows));path.chmod(0o600)
            self.assertEqual(set(browser.read_invitations(path,origin,private)),{"reviewer-a","reviewer-b"})
            path.chmod(0o644)
            with self.assertRaises(browser.BrowserFailure):
                browser.read_invitations(path,origin,private)
            path.chmod(0o600)
            with self.assertRaises(browser.BrowserFailure):
                browser.read_invitations(path,origin,Path(root)/"other")

    def test_public_failure_report_does_not_include_raw_exception_or_codes(self):
        with tempfile.TemporaryDirectory() as root:
            public,private=Path(root)/"public",Path(root)/"private"
            public.mkdir();private.mkdir()
            report=browser.run_browser_checks("https://remote.example",private/"invitations.json",private/"ca.crt",public,private)
            self.assertEqual(report["status"],"failed")
            self.assertEqual(report["error_code"],"browser_origin_must_be_https_loopback")
            text=(public/browser.REPORT_FILE).read_text()
            self.assertNotIn("Traceback",text)
            self.assertNotIn("access_code",text)
            self.assertTrue((private/"browser-diagnostics.txt").is_file())
            self.assertEqual((private/"browser-diagnostics.txt").stat().st_mode&0o777,0o600)


if __name__=="__main__":
    unittest.main()

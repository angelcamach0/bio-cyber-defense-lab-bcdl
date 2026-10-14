#!/usr/bin/env python3
"""Real Firefox reviewer checks with private NSS trust and delayed real responses.

No fake API responses, TLS bypass, server startup, dependency install, cookie
export, or invitation logging. Call before the owning harness cleans its stack.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import traceback
from urllib.parse import urlsplit

SCREENSHOTS = (
    "browser-valid-desktop.png", "browser-valid-mobile.png",
    "browser-invalid-desktop.png", "browser-session-isolation.png",
    "browser-failure.png",
)
REPORT_FILE = "browser-checks.json"

# Holds only the next matching response, after Firefox's real verified fetch.
# Bodies/cookies are not replaced. All test hooks live in browser memory.
FETCH_GATES = r"""
(() => {
  const realFetch = window.fetch.bind(window);
  const gates = new Map();
  window.__biozeroBrowserGate = {
    arm(tag, path, method = 'GET') {
      if (gates.has(tag)) throw new Error('duplicate test gate');
      gates.set(tag, {path, method, claimed: false, ready: false, expired: false, delivered: false});
    },
    info(tag) { const g = gates.get(tag); return g ? {ready:g.ready, expired:g.expired, status:g.status, error:g.error, body:g.body} : null; },
    release(tag) { const g = gates.get(tag); if (!g || !g.resolve) throw new Error('test gate not ready'); clearTimeout(g.timer); g.delivered=true; g.resolve(g.response); }
  };
  window.fetch = async (...args) => {
    const first = args[0];
    const path = new URL(typeof first === 'string' ? first : first.url, location.href).pathname;
    const method = (args[1]?.method || first?.method || 'GET').toUpperCase();
    const entry = [...gates.values()].find(g => !g.claimed && g.path === path && g.method === method);
    if (!entry) return realFetch(...args);
    entry.claimed = true;
    try {
      const response = await realFetch(...args);
      entry.response = response;
      entry.status = response.status;
      try { entry.body = await response.clone().json(); } catch (_) { entry.body = null; }
      return await new Promise(resolve => {
        entry.resolve = resolve;
        entry.ready = true;
        entry.timer = setTimeout(() => { entry.expired=true; entry.delivered=true; resolve(response); }, 20000);
      });
    } catch (error) { entry.error = error.name; entry.ready=true; throw error; }
  };
})();
"""

SNAPSHOT = """() => ({
  identity: document.getElementById('identityLabel').textContent,
  workspaceHidden: document.getElementById('workspace').hidden,
  reportHidden: document.getElementById('reportPanel').hidden,
  message: document.getElementById('statusMessage').textContent,
  jobs: [...document.getElementById('runSelect').options].map(o=>o.value),
  jobLabel: document.getElementById('jobLabel').textContent,
  runDisabled: document.getElementById('runBtn').disabled,
  viewDisabled: document.getElementById('viewRunBtn').disabled,
  signInDisabled: document.getElementById('signInBtn').disabled,
  sessionGeneration, pollingGeneration
})"""


class BrowserFailure(RuntimeError):
    pass


def check_origin(origin):
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or parsed.hostname not in ("localhost", "127.0.0.1")
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise BrowserFailure("browser_origin_must_be_https_loopback")
    return origin


def read_invitations(path, origin, private_dir):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise BrowserFailure("invitations_must_remain_private")
    if not path.resolve().is_relative_to(Path(private_dir).resolve()):
        raise BrowserFailure("invitations_outside_private_directory")
    rows = json.loads(path.read_text())
    indexed = {row.get("id"): row for row in rows if isinstance(row, dict)}
    for reviewer in ("reviewer-a", "reviewer-b"):
        row = indexed.get(reviewer, {})
        if row.get("origin") != origin or not isinstance(row.get("access_code"), str) or len(row["access_code"]) < 32:
            raise BrowserFailure("browser_invitation_contract_invalid")
    return indexed


def write_json(path, value, private=False):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    Path(path).chmod(0o600 if private else 0o644)


def make_profile(private_dir, ca_path=None):
    root = Path(private_dir) / "browser-profiles"
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    profile = Path(tempfile.mkdtemp(prefix="firefox-nss-", dir=root))
    database = "sql:" + str(profile)
    subprocess.run(["certutil", "-N", "--empty-password", "-d", database], check=True,
                   capture_output=True, timeout=15)
    if ca_path is not None:
        subprocess.run(["certutil", "-A", "-n", "BioZero demo root", "-t", "C,,", "-d", database,
                        "-i", str(Path(ca_path).resolve())], check=True, capture_output=True, timeout=15)
    return profile


def launch_options(profile):
    return {"user_data_dir": str(profile), "headless": True, "ignore_https_errors": False,
            "viewport": {"width": 1440, "height": 1000},
            "firefox_user_prefs": {"security.enterprise_roots.enabled": False,
                                   "datareporting.policy.dataSubmissionEnabled": False,
                                   "toolkit.telemetry.enabled": False}}


def _arm(page, tag, path, method="GET"):
    page.evaluate("({tag,path,method})=>window.__biozeroBrowserGate.arm(tag,path,method)",
                  {"tag": tag, "path": path, "method": method})


def _gate(page, tag):
    page.wait_for_function("tag=>window.__biozeroBrowserGate.info(tag)?.ready", arg=tag, timeout=15000)
    state = page.evaluate("tag=>window.__biozeroBrowserGate.info(tag)", tag)
    if state.get("expired") or state.get("error"):
        raise BrowserFailure("delayed_real_response_gate_failed")
    return state


def _release(page, tag):
    state = _gate(page, tag)
    page.evaluate("tag=>window.__biozeroBrowserGate.release(tag)", tag)
    return state


def _workspace(page, reviewer):
    page.wait_for_function("reviewer=>!document.getElementById('workspace').hidden && document.getElementById('identityLabel').textContent === 'Reviewer '+reviewer",
                           arg=reviewer, timeout=20000)
    page.wait_for_function("!document.getElementById('signInBtn').disabled", timeout=20000)


def _login(page, invitation):
    page.locator("#loginPanel").wait_for(state="visible", timeout=15000)
    page.wait_for_function("!document.getElementById('signInBtn').disabled", timeout=15000)
    page.locator("#reviewerId").fill(invitation["id"])
    page.locator("#accessCode").fill(invitation["access_code"])
    page.locator("#signInBtn").click()
    _workspace(page, invitation["id"])


def _logout(page):
    page.locator("#signOutBtn").click()
    page.locator("#loginPanel").wait_for(state="visible", timeout=15000)
    page.wait_for_function("!document.getElementById('signInBtn').disabled", timeout=15000)
    if page.locator("#runSelect option").count() or page.locator("#jobLabel").text_content():
        raise BrowserFailure("logout_retained_owner_data")


def _get(page, path):
    return page.evaluate("""async path => {
      const response=await fetch(path,{credentials:'same-origin'});
      return {status:response.status,body:await response.json()};
    }""", path)


def _finished(page, status, release):
    page.wait_for_function("({status,release})=>!document.getElementById('reportPanel').hidden && document.getElementById('executionStatus').textContent===status && document.getElementById('scientificStatus').textContent===release",
                          arg={"status": status, "release": release}, timeout=60000)
    page.wait_for_function("!document.getElementById('runBtn').disabled", timeout=15000)
    return page.evaluate("JSON.parse(document.getElementById('executionReport').textContent)")


def _run(page, experiment, status, release):
    page.locator("#experimentSelect").select_option(experiment)
    page.locator("#runBtn").click()
    report = _finished(page, status, release)
    label = page.locator("#jobLabel").text_content()
    job = label.split(" · ")[-1]
    return job, report


def _screenshot(page, filename, public_dir, invitations):
    if filename not in SCREENSHOTS:
        raise BrowserFailure("screenshot_not_allowlisted")
    if page.locator("#accessCode").input_value():
        raise BrowserFailure("screenshot_access_code_field_not_cleared")
    text = page.locator("body").inner_text()
    if any(row["access_code"] in text for row in invitations.values()):
        raise BrowserFailure("screenshot_contains_private_code")
    path = Path(public_dir) / filename
    page.screenshot(path=str(path), full_page=True, mask=[page.locator("#accessCode")])
    path.chmod(0o644)
    return {"file": filename, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "viewport": page.viewport_size}


def run_browser_checks(origin, invitations_path, ca_path, public_dir, private_dir):
    """Return a safe report; raw driver diagnostics and profiles stay private."""
    report = {"status": "failed", "checks": [], "screenshots": [], "report_file": REPORT_FILE,
              "javascript_error_count": 0, "browser": "Firefox", "tls_verified": False,
              "scope": "Real synthetic reviewer execution and delayed-response isolation in Firefox; no clinical validation."}
    public, private = Path(public_dir), Path(private_dir)
    profiles, contexts, active_page, invitations, errors = [], [], None, {}, []
    def record(name, passed, details=None):
        report["checks"].append({"name": name, "passed": bool(passed), "details": details or {}})
        if not passed:
            raise BrowserFailure(name)
    try:
        check_origin(origin)
        if public.is_symlink() or private.is_symlink() or public.resolve().is_relative_to(private.resolve()) or private.resolve().is_relative_to(public.resolve()):
            raise BrowserFailure("browser_public_private_paths_overlap")
        public.mkdir(parents=True, exist_ok=True, mode=0o755)
        private.mkdir(parents=True, exist_ok=True, mode=0o700)
        private.chmod(0o700)
        invitations = read_invitations(invitations_path, origin, private)
        ca = Path(ca_path)
        if ca.is_symlink() or not ca.is_file():
            raise BrowserFailure("browser_demo_ca_unavailable")
        if shutil.which("certutil") is None:
            raise BrowserFailure("browser_certutil_unavailable")
        from playwright.sync_api import sync_playwright, Error as PlaywrightError
        with sync_playwright() as playwright:
            # Control: service rejection without the custom CA must be a TLS
            # issuer error, not a refused connection. A trusted load follows.
            profile = make_profile(private)
            profiles.append(profile)
            untrusted = playwright.firefox.launch_persistent_context(**launch_options(profile))
            contexts.append(untrusted)
            control_page = untrusted.pages[0] if untrusted.pages else untrusted.new_page()
            rejected = False
            try:
                control_page.goto(origin + "/health", timeout=15000)
            except PlaywrightError as exc:
                rejected = any(code in str(exc) for code in ("SEC_ERROR_UNKNOWN_ISSUER", "SEC_ERROR_UNTRUSTED", "SSL_ERROR_UNKNOWN_CA"))
            record("firefox_untrusted_demo_ca_rejected", rejected)
            untrusted.close()
            contexts.remove(untrusted)
            profile = make_profile(private, ca)
            profiles.append(profile)
            context = playwright.firefox.launch_persistent_context(**launch_options(profile))
            contexts.append(context)
            report["browser_version"] = context.browser.version if context.browser else "persistent-context"
            watched_pages = set()
            def watch(page):
                if id(page) in watched_pages:
                    return
                watched_pages.add(id(page))
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("console", lambda entry: errors.append(entry.text) if entry.type == "error" else None)
            context.on("page", watch)
            page = context.pages[0] if context.pages else context.new_page()
            watch(page)
            active_page = page
            page.add_init_script(FETCH_GATES)
            response = page.goto(origin + "/health", timeout=15000)
            record("firefox_demo_ca_https_verified", response is not None and response.status == 200)
            report["tls_verified"] = True
            report["trust"] = {"private_profile_demo_ca_only_added": True, "system_roots_imported": False,
                               "ignore_https_errors": False, "demo_ca_sha256": hashlib.sha256(ca.read_bytes()).hexdigest()}
            page.goto(origin, wait_until="domcontentloaded", timeout=20000)
            _login(page, invitations["reviewer-a"])
            record("ui_reviewer_a_signed_in", page.locator("#identityLabel").text_content() == "Reviewer reviewer-a")
            options = page.locator("#experimentSelect option").evaluate_all("nodes=>nodes.map(n=>n.value)")
            record("ui_prepared_catalog_available", set(options) == {"variant-smoke", "invalid-fastq"})
            job_a, _ = _run(page, "variant-smoke", "succeeded", "evaluated_passed")
            evaluation = json.loads(page.locator("#evaluationReport").text_content())
            record("ui_real_three_snp_evaluation", evaluation.get("evaluation_status") == "passed"
                   and (evaluation.get("tp"), evaluation.get("fp"), evaluation.get("fn")) == (3, 0, 0)
                   and page.locator("#releaseBadge").text_content() == "Evaluation passed",
                   {"tp": evaluation.get("tp"), "fp": evaluation.get("fp"), "fn": evaluation.get("fn")})
            a_jobs = set(page.locator("#runSelect option").evaluate_all("nodes=>nodes.map(n=>n.value)"))
            a_jobs.add(job_a)
            report["screenshots"].append(_screenshot(page, SCREENSHOTS[0], public, invitations))
            page.set_viewport_size({"width": 390, "height": 844})
            record("ui_mobile_viewport_no_horizontal_overflow", page.evaluate("document.documentElement.scrollWidth<=window.innerWidth"))
            report["screenshots"].append(_screenshot(page, SCREENSHOTS[1], public, invitations))
            page.set_viewport_size({"width": 1440, "height": 1000})
            _logout(page)
            record("ui_logout_clears_workspace", page.locator("#workspace").is_hidden())
            _login(page, invitations["reviewer-b"])
            b_jobs = set(page.locator("#runSelect option").evaluate_all("nodes=>nodes.map(n=>n.value)"))
            record("ui_reviewer_b_history_isolated", not (a_jobs & b_jobs))
            foreign = _get(page, "/api/results/" + job_a)
            record("browser_b_cannot_read_a", foreign["status"] == 404, {"http_status": foreign["status"]})
            job_b, _ = _run(page, "invalid-fastq", "failed", "withheld")
            invalid = _get(page, "/api/results/" + job_b)["body"]
            stages = invalid.get("data", {}).get("pipeline_output", {}).get("errors", [])
            record("ui_b_malformed_fastq_withheld", invalid.get("status") == "failed"
                   and invalid.get("data", {}).get("release_status") == "withheld"
                   and any(row.get("stage") == "validate_fastq" and row.get("code") == "invalid_input" for row in stages)
                   and page.locator("#releaseBadge").text_content() == "Release withheld")
            report["screenshots"].append(_screenshot(page, SCREENSHOTS[2], public, invitations))
            _logout(page)
            _login(page, invitations["reviewer-a"])

            # History success and a real foreign-result error both arrive after
            # logout/login. The latter covers the view handler's catch/finally.
            _arm(page, "history-a", "/api/runs")
            page.evaluate("void refreshRuns()")
            record("delayed_a_history_is_real", _gate(page, "history-a")["status"] == 200)
            page.evaluate("job=>{const option=document.createElement('option');option.value=job;option.textContent='adversarial foreign run';document.getElementById('runSelect').append(option);document.getElementById('runSelect').value=job;}", job_b)
            _arm(page, "view-a-error", "/api/results/" + job_b)
            page.locator("#viewRunBtn").click()
            record("delayed_a_view_error_is_real", _gate(page, "view-a-error")["status"] == 404)

            # A second tab begins actual session recovery as A. It is held until
            # the explicit B sign-in is pending, to exercise intent ordering.
            recovery = context.new_page()
            # One init script gives deterministic order; Playwright does not
            # guarantee order between context and page init scripts.
            recovery.add_init_script(FETCH_GATES + "\nwindow.__biozeroBrowserGate.arm('initial-a-session','/api/session','GET');")
            recovery.goto(origin, wait_until="domcontentloaded", timeout=20000)
            recovered = _gate(recovery, "initial-a-session")
            record("delayed_initial_session_is_a", recovered["status"] == 200 and recovered["body"].get("reviewer") == "reviewer-a")
            _logout(page)
            _login(page, invitations["reviewer-b"])
            before = page.evaluate(SNAPSHOT)
            _release(page, "history-a")
            page.wait_for_timeout(200)
            record("stale_a_history_cannot_populate_b", page.evaluate(SNAPSHOT) == before)
            _release(page, "view-a-error")
            page.wait_for_timeout(200)
            record("stale_a_view_error_cannot_interrupt_b", page.evaluate(SNAPSHOT) == before)

            _arm(recovery, "signin-b", "/api/sign-in", "POST")
            recovery.locator("#reviewerId").fill("reviewer-b")
            recovery.locator("#accessCode").fill(invitations["reviewer-b"]["access_code"])
            recovery.locator("#signInBtn").click()
            record("delayed_b_signin_is_real", _gate(recovery, "signin-b")["status"] == 200)
            pending = recovery.evaluate(SNAPSHOT)
            _release(recovery, "initial-a-session")
            recovery.wait_for_timeout(200)
            record("stale_session_recovery_loses_to_signin_intent", recovery.evaluate(SNAPSHOT) == pending)
            _release(recovery, "signin-b")
            _workspace(recovery, "reviewer-b")
            active_page = page = recovery
            record("recovery_tab_commits_only_b", page.locator("#identityLabel").text_content() == "Reviewer reviewer-b")

            # The old A start callback is released while B has its own genuine
            # request pending. It must not increment polling or re-enable B's
            # buttons through old catch/finally paths.
            _logout(page)
            _login(page, invitations["reviewer-a"])
            page.locator("#experimentSelect").select_option("variant-smoke")
            _arm(page, "start-a", "/api/experiments/variant-smoke/runs", "POST")
            page.locator("#runBtn").click()
            started_a = _gate(page, "start-a")
            record("delayed_a_start_is_real", started_a["status"] == 202 and bool(started_a["body"].get("job_id")))
            a_jobs.add(started_a["body"]["job_id"])
            _logout(page)
            _login(page, invitations["reviewer-b"])
            page.locator("#experimentSelect").select_option("invalid-fastq")
            _arm(page, "start-b", "/api/experiments/invalid-fastq/runs", "POST")
            page.locator("#runBtn").click()
            record("delayed_b_start_is_real", _gate(page, "start-b")["status"] == 202)
            busy = page.evaluate(SNAPSHOT)
            _release(page, "start-a")
            page.wait_for_timeout(200)
            record("stale_a_start_cannot_interrupt_busy_b", page.evaluate(SNAPSHOT) == busy and busy["runDisabled"])
            _release(page, "start-b")
            _finished(page, "failed", "withheld")
            rows = set(page.locator("#runSelect option").evaluate_all("nodes=>nodes.map(n=>n.value)"))
            record("b_remains_owner_after_all_late_callbacks", not (a_jobs & rows)
                   and page.locator("#identityLabel").text_content() == "Reviewer reviewer-b")
            report["screenshots"].append(_screenshot(page, SCREENSHOTS[3], public, invitations))
            record("no_javascript_errors", not errors, {"count": len(errors)})
            _logout(page)
            context.close()
            contexts.remove(context)
            report["status"] = "passed"
    except Exception as exc:
        report["error_code"] = str(exc) if isinstance(exc, BrowserFailure) else "browser_" + type(exc).__name__
        if private.is_dir():
            diagnostics = private / "browser-diagnostics.txt"
            diagnostics.write_text(traceback.format_exc(), encoding="utf-8")
            diagnostics.chmod(0o600)
        if active_page is not None and public.is_dir() and invitations:
            try:
                active_page.evaluate("document.getElementById('accessCode').value=''")
                report["screenshots"].append(_screenshot(active_page, SCREENSHOTS[4], public, invitations))
            except Exception:
                pass
    finally:
        report["javascript_error_count"] = len(errors)
        for context in contexts:
            try:
                context.close()
            except Exception:
                pass
        for profile in profiles:
            shutil.rmtree(profile, ignore_errors=True)
        if public.is_dir() and not public.is_symlink():
            write_json(public / REPORT_FILE, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--invitations", type=Path, required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--private-dir", type=Path, required=True)
    args = parser.parse_args()
    report = run_browser_checks(args.origin, args.invitations, args.ca, args.public_dir, args.private_dir)
    print(json.dumps({"status": report["status"], "report_file": report["report_file"],
                      "checks": len(report["checks"]), "error_code": report.get("error_code")}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

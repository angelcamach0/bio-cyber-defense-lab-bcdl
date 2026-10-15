#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Private, opt-in Firefox driver for the real owner-v1 Gateway UI.

The caller owns all services. This module never installs tools, starts services,
exports cookies, fabricates responses or disables certificate verification.
Only the supplied private directory receives driver evidence and screenshots.
Use the cached /tmp/biozero-browser/bin/python environment.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import threading
import time
from urllib.parse import quote, urlsplit


_FIREFOX = Path.home() / ".cache/ms-playwright/firefox-1555/firefox/firefox"
_DRIVER = None
_DRIVER_USERS = 0
_DRIVER_THREAD = None
_LIMIT = 16 << 20
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")


class OwnerGatewayBrowserError(RuntimeError):
    """Fixed error code; raw browser diagnostics stay in private evidence."""


# Every gate retains the original Firefox Response after its verified native
# fetch completed. No replacement body, status, certificate or cookie is used.
# Render tracking wraps the real renderer without modifying its input or DOM.
_PROBE = r"""
(() => {
  const nativeFetch = window.fetch.bind(window);
  const gates = new Map();
  const copy = value => JSON.parse(JSON.stringify(value));
  const probe = window.__ownerGatewayBrowserProbe = {
    rendered: null, renders: [], installed: false, uiResponses: [], sequence: 0,
    // Manual harness reads still use Firefox's native verified fetch. They are
    // explicitly excluded from the application-response/render attribution.
    helperFetch: (...args) => nativeFetch(...args),
    arm(tag,path) {
      if (gates.has(tag)) throw new Error('gate_duplicate');
      gates.set(tag,{path,claimed:false,ready:false,expired:false,delivered:false});
    },
    info(tag) {
      const g=gates.get(tag);
      return g ? {ready:g.ready,expired:g.expired,delivered:g.delivered,status:g.status,
                  body:g.body,error:g.error} : null;
    },
    release(tag) {
      const g=gates.get(tag);
      if (!g || !g.resolve || !g.ready || g.delivered) throw new Error('gate_unavailable');
      clearTimeout(g.timer);g.delivered=true;g.resolve(g.response);
    }
  };
  async function boundedJSON(response) {
    const reader=response.body.getReader(),decoder=new TextDecoder('utf-8',{fatal:true});
    let text='',total=0;
    for (;;) {
      const {value,done}=await reader.read();if(done)break;
      total+=value.length;
      if(total>16777216){await reader.cancel();throw new Error('response_bound');}
      text+=decoder.decode(value,{stream:true});
    }
    text+=decoder.decode();return JSON.parse(text);
  }
  window.fetch = async (...args) => {
    const request=args[0], options=args[1]||{};
    const url=new URL(typeof request==='string'?request:request.url,location.href);
    const path=url.pathname,method=(options.method||request?.method||'GET').toUpperCase();
    const gate=[...gates.values()].find(g=>!g.claimed&&g.path===path&&method==='GET');
    if (gate) gate.claimed=true;
    try {
      const response=await nativeFetch(...args);
      let payload;
      if (url.origin===location.origin&&/^\/api\/results\/[a-f0-9]{16}$/.test(path)&&method==='GET') {
        payload=await boundedJSON(response.clone());
        probe.uiResponses.push({sequence:++probe.sequence,path,status:response.status,payload,claimed:false});
        if(probe.uiResponses.length>8)probe.uiResponses.shift();
      }
      if (!gate) return response;
      gate.response=response;gate.status=response.status;
      gate.body=payload===undefined?await boundedJSON(response.clone()):payload;
      return await new Promise(resolve=>{
        gate.resolve=resolve;gate.ready=true;
        gate.timer=setTimeout(()=>{gate.expired=true;gate.delivered=true;resolve(response)},26000);
      });
    } catch(error) {if(gate){gate.ready=true;gate.error=error.name;}throw error;}
  };
  document.addEventListener('DOMContentLoaded',()=>{
    if (typeof window.showResult!=='function') return;
    const render=window.showResult;
    window.showResult=function(result) {
      const argument=copy(result);
      const source=[...probe.uiResponses].reverse().find(row=>!row.claimed&&row.status===200&&
        row.path==='/api/results/'+argument.job_id&&JSON.stringify(row.payload)===JSON.stringify(argument));
      const value=render.call(this,result);
      if(source)source.claimed=true;
      const row={job_id:result.job_id,status:result.status,release_status:result.release_status,
                 execution_state:result.execution_state,session_generation:sessionGeneration,
                 poll_generation:pollGeneration};
      probe.rendered={...row,argument,source:source?copy(source):null};
      probe.renders.push(row);
      if (probe.renders.length>256) probe.renders.shift();
      return value;
    };
    probe.installed=true;
  },{once:true});
})();
"""

_FETCH = r"""async ({method,path,body,headers}) => {
  const target=new URL(path,location.href);
  if (target.origin!==location.origin) throw new Error('same_origin_only');
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),35000);
  try {
    const values={'Content-Type':'application/json',...headers};
    if (method!=='GET' && method!=='HEAD' && !Object.keys(values).some(k=>k.toLowerCase()==='x-csrf-token')) {
      if (typeof session!=='undefined'&&session) values['X-CSRF-Token']=session.csrf_token;
    }
    const options={method,headers:values,credentials:'same-origin',cache:'no-store',
                   redirect:'error',signal:controller.signal};
    if (method!=='GET'&&method!=='HEAD') options.body=JSON.stringify(body===null?{}:body);
    const response=await window.__ownerGatewayBrowserProbe.helperFetch(target.href,options);
    const reader=response.body?.getReader();let total=0;const chunks=[];
    if (reader) for (;;) {
      const {value,done}=await reader.read();if(done)break;
      total+=value.length;
      if(total>16777216){await reader.cancel();throw new Error('response_bound');}
      chunks.push(value);
    }
    let text='';for(const chunk of chunks) for(let i=0;i<chunk.length;i+=8192)
      text+=String.fromCharCode(...chunk.subarray(i,i+8192));
    return {status:response.status,body:btoa(text)};
  } finally {clearTimeout(timer);}
}"""


def _private_root(path):
    path = Path(path)
    if not path.is_absolute() or Path(os.path.abspath(path)) != path or path == Path("/"):
        raise OwnerGatewayBrowserError("browser_private_path_invalid")
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=current)
            os.close(current)
            current = child
        os.mkdir(path.name, 0o700, dir_fd=current)
        descriptor = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=current)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise OwnerGatewayBrowserError("browser_private_directory_unsafe")
        finally:
            os.close(descriptor)
    finally:
        os.close(current)
    return path


def _write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _json(path, value):
    _write(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def _acquire_driver():
    global _DRIVER, _DRIVER_USERS, _DRIVER_THREAD
    thread = threading.get_ident()
    if _DRIVER is not None and thread != _DRIVER_THREAD:
        raise OwnerGatewayBrowserError("browser_sync_thread_changed")
    if _DRIVER is None:
        from playwright.sync_api import sync_playwright
        _DRIVER = sync_playwright().start()
        _DRIVER_THREAD = thread
    _DRIVER_USERS += 1
    return _DRIVER


def _release_driver():
    global _DRIVER, _DRIVER_USERS, _DRIVER_THREAD
    _DRIVER_USERS -= 1
    if _DRIVER_USERS == 0:
        driver, _DRIVER = _DRIVER, None
        _DRIVER_THREAD = None
        driver.stop()


def _profile_processes(profile):
    """Observe only exact-profile Firefox roots and their current descendants."""
    wanted = str(profile).encode()
    rows = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != os.geteuid():
                continue
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            arguments = (entry / "cmdline").read_bytes().split(b"\0")
            rows[int(entry.name)] = (int(fields[1]), fields[19], wanted in arguments)
        except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
            continue
    owned = {pid for pid, (_, _, matches) in rows.items() if matches}
    while True:
        extended = owned | {pid for pid, (parent, _, _) in rows.items() if parent in owned}
        if extended == owned:
            break
        owned = extended
    return {pid: rows[pid][1] for pid in owned}


def _process_exists(pid, started):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return fields[19] == started
    except (FileNotFoundError, ProcessLookupError, IndexError):
        return False


def _same_json(left, right):
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same_json(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_json(a, b) for a, b in zip(left, right))
    return left == right


class OwnerGatewayBrowser:
    def __init__(self, origin, ca_path, private_dir, reviewers):
        parsed = urlsplit(origin)
        if (parsed.scheme != "https" or parsed.hostname not in ("127.0.0.1", "::1", "localhost")
                or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
                or not parsed.port):
            raise OwnerGatewayBrowserError("browser_origin_invalid")
        if not isinstance(reviewers, dict) or not reviewers or any(
                not isinstance(key, str) or not isinstance(row, dict) or not isinstance(row.get("access_code"), str)
                for key, row in reviewers.items()):
            raise OwnerGatewayBrowserError("browser_reviewers_invalid")
        self.origin, self.ca_path = origin, Path(ca_path)
        self.private_dir, self.reviewers = Path(private_dir), dict(reviewers)
        self.context = self.page = self.driver = self.profile = None
        self.current_reviewer = self.last_request_id = self.last_run_id = None
        self._counter = 0
        self._diagnostics = []
        self._closed = False
        self._driver_acquired = False
        self._root_ready = False
        self._close_error = None
        self._owned = {}
        self.controls = {}

    def _retain(self, label, value):
        self._counter += 1
        name = f"{self._counter:04d}-{label}.json"
        _json(self.private_dir / name, value)
        return name

    def _profile(self, name, trusted):
        profile = self.private_dir / name
        profile.mkdir(mode=0o700)
        database = "sql:" + str(profile)
        commands = [["certutil", "-N", "--empty-password", "-d", database]]
        if trusted:
            commands.append(["certutil", "-A", "-n", "Owner acceptance root", "-t", "C,,",
                             "-d", database, "-i", str(self.ca_path)])
        for index, command in enumerate(commands):
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       timeout=15, umask=0o077, check=False)
            _write(self.private_dir / f"{name}-certutil-{index}.stdout", completed.stdout)
            _write(self.private_dir / f"{name}-certutil-{index}.stderr", completed.stderr)
            if completed.returncode:
                raise OwnerGatewayBrowserError("browser_trust_initialization_failed")
        return profile

    def _launch(self, profile):
        return self.driver.firefox.launch_persistent_context(
            user_data_dir=str(profile), executable_path=str(_FIREFOX), headless=True,
            ignore_https_errors=False, viewport={"width": 1440, "height": 1000},
            firefox_user_prefs={"security.enterprise_roots.enabled": False,
                                "datareporting.policy.dataSubmissionEnabled": False,
                                "toolkit.telemetry.enabled": False})

    def __enter__(self):
        try:
            self.private_dir = _private_root(self.private_dir)
            self._root_ready = True
            info = self.ca_path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not _FIREFOX.is_file() or shutil.which("certutil") is None:
                raise OwnerGatewayBrowserError("browser_cached_dependencies_unavailable")
            self.driver = _acquire_driver()
            self._driver_acquired = True
            untrusted_profile = self._profile("untrusted-profile", False)
            untrusted = self._launch(untrusted_profile)
            untrusted_owned = _profile_processes(untrusted_profile)
            self._owned.update(untrusted_owned)
            try:
                if not untrusted_owned:
                    raise OwnerGatewayBrowserError("browser_profile_process_unobserved")
                probe = untrusted.pages[0] if untrusted.pages else untrusted.new_page()
                rejected = False
                try:
                    probe.goto(self.origin + "/health", timeout=15000)
                except Exception as error:
                    self._retain("untrusted-tls-control", {"diagnostic": str(error)})
                    rejected = any(code in str(error) for code in (
                        "SEC_ERROR_UNKNOWN_ISSUER", "SEC_ERROR_UNTRUSTED", "SSL_ERROR_UNKNOWN_CA"))
                if not rejected:
                    raise OwnerGatewayBrowserError("browser_untrusted_ca_control_failed")
                self.controls["untrusted_ca_rejected"] = True
            finally:
                untrusted.close()
            self.profile = self._profile("trusted-profile", True)
            self.context = self._launch(self.profile)
            self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
            self.page.set_default_timeout(20000)
            self.page.set_default_navigation_timeout(20000)
            self.page.add_init_script(_PROBE)
            self.page.on("pageerror", lambda error: self._diagnostics.append({"kind": "pageerror", "message": str(error)}))
            self.page.on("console", lambda entry: self._diagnostics.append({"kind": "console", "message": entry.text}) if entry.type == "error" else None)
            response = self.page.goto(self.origin + "/health", timeout=15000)
            if response is None or response.status != 200:
                raise OwnerGatewayBrowserError("browser_trusted_https_control_failed")
            self.page.goto(self.origin, wait_until="domcontentloaded")
            self.page.wait_for_function("window.__ownerGatewayBrowserProbe?.installed")
            self.controls["trusted_ca_verified"] = True
            trusted_owned = _profile_processes(self.profile)
            self._owned.update(trusted_owned)
            if not trusted_owned:
                raise OwnerGatewayBrowserError("browser_profile_process_unobserved")
            self._retain("runtime", {"firefox_binary_sha256": hashlib.sha256(_FIREFOX.read_bytes()).hexdigest(),
                                     "ca_sha256": hashlib.sha256(self.ca_path.read_bytes()).hexdigest(),
                                     "ignore_https_errors": False, "system_roots_imported": False,
                                     "owned_processes": self._owned})
            return self
        except BaseException:
            self.close()
            raise

    def login(self, reviewer_id):
        row = self.reviewers.get(reviewer_id)
        if row is None:
            raise OwnerGatewayBrowserError("browser_reviewer_unknown")
        if self.page.locator("#workspace").is_visible():
            self.logout()
        self.page.locator("#login").wait_for(state="visible")
        self.page.locator("#reviewer").fill(reviewer_id)
        self.page.locator("#access-code").fill(row["access_code"])
        with self.page.expect_response(lambda response: response.url == self.origin + "/api/sign-in" and response.request.method == "POST") as pending:
            self.page.locator("#sign-in").click()
        response = pending.value
        raw = response.body()
        self._retain("ui-sign-in", {"status": response.status, "body_base64": base64.b64encode(raw).decode()})
        if response.status != 200:
            raise OwnerGatewayBrowserError("browser_login_failed")
        self.page.wait_for_function("id=>!document.getElementById('workspace').hidden&&document.getElementById('greeting').textContent==='Experimentos · '+id", arg=reviewer_id)
        self.page.locator("#catalog article button").first.wait_for(state="visible")
        self.page.wait_for_function("!document.getElementById('sign-in').disabled")
        if self.page.locator("#access-code").input_value():
            raise OwnerGatewayBrowserError("browser_access_code_not_cleared")
        self.current_reviewer = reviewer_id
        return {"ui_login": True, "access_code_cleared": True}

    def logout(self):
        if self.page.locator("#workspace").is_visible():
            with self.page.expect_response(lambda response: response.url == self.origin + "/api/sign-out" and response.request.method == "POST") as pending:
                self.page.locator("#sign-out").click()
            response = pending.value
            self._retain("ui-sign-out", {"status": response.status})
            # Another same-reviewer login may have revoked this context's old
            # epoch. The real UI still clears locally on its observed401.
            if response.status not in (200, 401):
                raise OwnerGatewayBrowserError("browser_logout_failed")
        self.page.locator("#login").wait_for(state="visible")
        if not self.page.locator("#workspace").is_hidden() or not self.page.locator("#result").is_hidden():
            raise OwnerGatewayBrowserError("browser_logout_private_view_visible")
        self.current_reviewer = None

    def call(self, method, path, body=None, headers=None):
        method = method.upper()
        parsed = urlsplit(path)
        if (method not in {"GET", "POST", "HEAD"} or not path.startswith("/") or path.startswith("//")
                or parsed.scheme or parsed.netloc or parsed.fragment):
            raise OwnerGatewayBrowserError("browser_call_same_origin_required")
        headers = dict(headers or {})
        if any(key.lower() in {"host", "origin", "cookie", "connection", "content-length"} for key in headers):
            raise OwnerGatewayBrowserError("browser_forbidden_header_not_testable")
        result = self.page.evaluate(_FETCH, {"method": method, "path": path, "body": body, "headers": headers})
        raw = base64.b64decode(result["body"], validate=True)
        if len(raw) > _LIMIT:
            raise OwnerGatewayBrowserError("browser_response_bound")
        self._retain("browser-fetch", {"method": method, "path": path, "status": result["status"],
                                       "body_base64": result["body"]})
        return result["status"], raw

    def start(self, experiment_id):
        status, raw = self.call("GET", "/api/experiments")
        rows = json.loads(raw)
        matching = [row for row in rows if row.get("id") == experiment_id]
        if status != 200 or len(matching) != 1:
            raise OwnerGatewayBrowserError("browser_experiment_unknown")
        label = matching[0]["label"]
        cards = self.page.locator("#catalog article").filter(has=self.page.get_by_role("heading", name=label, exact=True))
        if cards.count() != 1:
            raise OwnerGatewayBrowserError("browser_experiment_card_ambiguous")
        path = "/api/experiments/" + quote(experiment_id, safe="") + "/runs"
        with self.page.expect_response(lambda response: response.url == self.origin + path and response.request.method == "POST") as pending:
            cards.locator("button").click()
        response = pending.value
        request_body = json.loads(response.request.post_data)
        row = json.loads(response.body())
        self._retain("ui-run-post", {"status": response.status, "request": request_body, "response": row})
        if (response.status != 202 or set(request_body) != {"request_id"}
                or not _HEX32.fullmatch(request_body["request_id"])
                or not _HEX16.fullmatch(row.get("run_id", ""))
                or row.get("request_id") != request_body["request_id"] or row.get("experiment_id") != experiment_id):
            raise OwnerGatewayBrowserError("browser_run_post_contract_invalid")
        self.last_request_id, self.last_run_id = request_body["request_id"], row["run_id"]
        return row

    def screenshot(self, label):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label) or self.page.locator("#access-code").input_value():
            raise OwnerGatewayBrowserError("browser_screenshot_invalid")
        path = self.private_dir / f"{label}.png"
        if path.exists():
            raise OwnerGatewayBrowserError("browser_screenshot_exists")
        # Reserve exclusive0600 before the driver opens the same trusted path.
        _write(path, b"")
        self.page.screenshot(path=str(path), full_page=True, mask=[self.page.locator("#access-code")])
        path.chmod(0o600)
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "viewport": self.page.viewport_size}

    def wait_rendered(self, job_id, status, release):
        if not _HEX16.fullmatch(job_id):
            raise OwnerGatewayBrowserError("browser_job_invalid")
        self.page.wait_for_function("""({job,status,release})=>{
          const p=window.__ownerGatewayBrowserProbe,rendered=p?.rendered;
          return rendered?.job_id===job&&rendered.status===status&&rendered.release_status===release&&
            rendered.execution_state==='committed'&&!document.getElementById('result').hidden&&
            document.getElementById('result-content').textContent.includes('Ejecución: '+status+' · Liberación: '+release);
        }""", arg={"job": job_id, "status": status, "release": release}, timeout=180000)
        observation = self.page.evaluate("window.__ownerGatewayBrowserProbe.rendered")
        result, source = observation.get("argument"), observation.get("source")
        if (not isinstance(result, dict) or not isinstance(source, dict) or source.get("status") != 200
                or source.get("path") != "/api/results/" + job_id or type(source.get("sequence")) is not int
                or not _same_json(result, source.get("payload"))
                or (result.get("job_id"), result.get("status"), result.get("release_status"), result.get("execution_state"))
                != (job_id, status, release, "committed")):
            raise OwnerGatewayBrowserError("browser_full_renderer_argument_mismatch")
        dom = self.page.locator("#result-content").evaluate("""node=>({
          text:node.textContent,badge:node.querySelector('.badge')?.textContent,
          metrics:[...node.querySelectorAll('.metric')].map(metric=>({
            value:metric.querySelector('strong')?.textContent,
            label:[...metric.childNodes].filter(child=>child.nodeType===Node.TEXT_NODE).map(child=>child.textContent).join('').trim()
          }))
        })""")
        expected = {}
        evaluation = result.get("scientific_evaluation")
        if evaluation is not None:
            if not isinstance(evaluation, dict):
                raise OwnerGatewayBrowserError("browser_evaluation_shape_invalid")
            for name, label in (("tp", "Verdaderos positivos"), ("fp", "Falsos positivos"),
                                ("fn", "Falsos negativos")):
                value = evaluation.get(name)
                if type(value) in (int, float):
                    expected[label] = str(value)
            for name, label in (("precision", "Precisión"), ("recall", "Recall")):
                value = evaluation.get(name)
                if value is None:
                    expected[label] = "Sin evaluar"
                elif type(value) in (int, float):
                    # Use the browser's real scalar-to-text convention, matching
                    # textContent assignment without rounding or invented zeros.
                    expected[label] = self.page.evaluate("value=>String(value)", value)
                else:
                    raise OwnerGatewayBrowserError("browser_evaluation_metric_invalid")
        actual = {row["label"]: row["value"] for row in dom["metrics"]}
        if len(actual) != len(dom["metrics"]) or actual != expected:
            raise OwnerGatewayBrowserError("browser_rendered_scientific_metrics_mismatch")
        mode = (result.get("pipeline_output") or {}).get("mode")
        if mode == "stats":
            scope = "Alcance: estadísticas FASTQ de datos sintéticos, sin evaluación científica de variantes. No establece precisión clínica."
            if evaluation is not None or dom["metrics"]:
                raise OwnerGatewayBrowserError("browser_stats_fabricated_evaluation")
        elif mode == "variants":
            scope = "Alcance: presencia de alelos en datos sintéticos. No valida genotipos, genomas completos ni precisión clínica."
        else:
            raise OwnerGatewayBrowserError("browser_rendered_mode_missing")
        expected_badge = ("Validación sintética aprobada" if release == "evaluated_passed" else
                          "Sin evaluación científica" if release == "unassessed" else "Resultado retenido")
        if scope not in dom["text"] or dom["badge"] != expected_badge:
            raise OwnerGatewayBrowserError("browser_rendered_scientific_scope_mismatch")
        self._retain("rendered-ui-response-and-argument", {"observation": observation, "dom": dom})
        label = f"rendered-{len([p for p in self.private_dir.iterdir() if p.name.startswith('rendered-')]):03d}"
        screenshot = self.screenshot(label)
        return {"full_renderer_argument_equals_real_ui_response": True,
                "manual_harness_reads_excluded_from_attribution": True,
                "terminal_execution_rendered": True, "scientific_release_rendered": True,
                "rendered_metric_count": len(actual), "scientific_metrics_match_renderer_argument": True,
                "scientific_scope_matches_mode": True, "screenshot": screenshot}

    def mobile_layout(self):
        previous = self.page.viewport_size
        try:
            self.page.set_viewport_size({"width": 390, "height": 844})
            fits = self.page.evaluate("document.documentElement.scrollWidth<=window.innerWidth")
            if not fits:
                raise OwnerGatewayBrowserError("browser_mobile_horizontal_overflow")
            return {"no_horizontal_overflow": True, "screenshot": self.screenshot("mobile-layout")}
        finally:
            self.page.set_viewport_size(previous)

    def privacy_gate(self, job_id, other_reviewer_id):
        if not _HEX16.fullmatch(job_id) or other_reviewer_id == self.current_reviewer:
            raise OwnerGatewayBrowserError("browser_privacy_gate_invalid")
        with self.page.expect_response(lambda response: response.url == self.origin + "/api/runs" and response.request.method == "GET") as pending:
            self.page.locator("#refresh").click()
        response = pending.value
        rows = json.loads(response.body())
        indices = [index for index, row in enumerate(rows) if row.get("job_id") == job_id]
        if response.status != 200 or len(indices) != 1:
            raise OwnerGatewayBrowserError("browser_privacy_source_run_missing")
        self.page.wait_for_function("count=>document.querySelectorAll('#history .run').length===count", arg=len(rows))
        tag = f"isolation-{self._counter}"
        path = "/api/results/" + job_id
        self.page.evaluate("({tag,path})=>window.__ownerGatewayBrowserProbe.arm(tag,path)", {"tag": tag, "path": path})
        self.page.locator("#history .run").nth(indices[0]).locator("button").click()
        self.page.wait_for_function("tag=>window.__ownerGatewayBrowserProbe.info(tag)?.ready", arg=tag, timeout=20000)
        held = self.page.evaluate("tag=>window.__ownerGatewayBrowserProbe.info(tag)", tag)
        if held.get("expired") or held.get("error") or held.get("status") != 200 or held.get("body", {}).get("job_id") != job_id:
            raise OwnerGatewayBrowserError("browser_delayed_real_response_missing")
        self._retain("delayed-real-response", held)
        before = self.page.evaluate("sessionGeneration")
        self.logout()
        self.login(other_reviewer_id)
        changed = self.page.evaluate("sessionGeneration")
        self.page.evaluate("tag=>window.__ownerGatewayBrowserProbe.release(tag)", tag)
        self.page.evaluate("()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))")
        after = self.page.evaluate("""()=>({generation:sessionGeneration,greeting:document.getElementById('greeting').textContent,
          hidden:document.getElementById('result').hidden,renders:window.__ownerGatewayBrowserProbe.renders})""")
        crossed = [row for row in after["renders"] if row["job_id"] == job_id and row["session_generation"] >= changed]
        if changed <= before or after["generation"] != changed or crossed or not after["hidden"] or after["greeting"] != "Experimentos · " + other_reviewer_id:
            raise OwnerGatewayBrowserError("browser_delayed_response_crossed_session")
        self._retain("session-isolation", after)
        return {"held_response_was_real_https_200": True, "session_generation_advanced": True,
                "old_response_not_rendered_in_new_session": True,
                "screenshot": self.screenshot("session-isolation")}

    def close(self):
        if self._closed:
            if self._close_error is not None:
                raise self._close_error
            return
        self._closed = True
        failure = None
        try:
            if self.profile is not None:
                self._owned.update(_profile_processes(self.profile))
            if self.context is not None:
                self.context.close()
        except BaseException as error:
            failure = error
        finally:
            try:
                if self._driver_acquired:
                    _release_driver()
                    self._driver_acquired = False
            except BaseException as error:
                if failure is None:
                    failure = error
            deadline = time.monotonic() + 10
            remaining = dict(self._owned)
            while remaining and time.monotonic() < deadline:
                remaining = {pid: started for pid, started in remaining.items() if _process_exists(pid, started)}
                if remaining:
                    time.sleep(0.05)
            if self._root_ready:
                self._retain("browser-close", {"processes_observed": len(self._owned), "remaining_processes": remaining,
                                               "context_close_completed": failure is None, "diagnostics": self._diagnostics,
                                               "close_error": None if failure is None else str(failure)})
            self.controls["own_processes_exited"] = not remaining and failure is None and bool(self._owned)
            if failure is not None or remaining:
                self._close_error = OwnerGatewayBrowserError("browser_shutdown_failed")
                raise self._close_error from failure

    def __exit__(self, kind, error, trace):
        try:
            if error is not None and self.page is not None:
                self._retain("browser-failure", {"type": kind.__name__, "diagnostic": str(error)})
        finally:
            self.close()
        return False

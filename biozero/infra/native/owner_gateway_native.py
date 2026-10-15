#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded real HTTPS session and projection comparison for owner native runs.

The caller owns services and evidence. This module does not start services,
retry uncertain operations, follow redirects, execute science or export secrets.
HTTP requests exercise the browser protocol; they do not establish UI rendering.
"""

import http.client
import http.cookiejar
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import threading
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request


_REQUEST_LIMIT = 4096
_RESPONSE_LIMIT = 16 << 20
_TIMEOUT = 40
_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_HEX16 = re.compile(r"[0-9a-f]{16}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class OwnerGatewayNativeError(RuntimeError):
    """Fixed local failure code; no key, cookie, access code or header content."""


def _exact_json(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError("duplicate JSON field")
            result[name] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def _private_root(path):
    path = Path(path)
    if not path.is_absolute() or Path(os.path.abspath(path)) != path or path == Path("/"):
        raise OwnerGatewayNativeError("gateway_http_private_path_invalid")
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
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(descriptor)
            raise OwnerGatewayNativeError("gateway_http_private_directory_unsafe")
        return path, descriptor
    finally:
        os.close(current)


class GatewayHTTPSession:
    def __init__(self, origin, ca_path, private_dir, reviewers):
        try:
            parsed = urlsplit(origin)
            valid = (parsed.scheme == "https" and parsed.hostname in ("127.0.0.1", "::1", "localhost")
                     and not parsed.username and not parsed.password and not parsed.path
                     and not parsed.query and not parsed.fragment and parsed.port)
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise OwnerGatewayNativeError("gateway_http_origin_invalid")
        if not isinstance(reviewers, dict) or not reviewers or any(
                not isinstance(key, str) or not isinstance(row, dict)
                or not isinstance(row.get("access_code"), str) for key, row in reviewers.items()):
            raise OwnerGatewayNativeError("gateway_http_reviewers_invalid")
        self.origin, self.ca_path, self.private_dir = origin, Path(ca_path), Path(private_dir)
        self.reviewers = {key: dict(row) for key, row in reviewers.items()}
        self.current_reviewer = self.last_request_id = self.last_run_id = self.csrf = None
        self.cookies = http.cookiejar.CookieJar()
        self._host, self._port = parsed.hostname, parsed.port
        self._context = self._directory = None
        self._counter = 0
        self._closed = False

    def __enter__(self):
        if self._closed or self._directory is not None:
            raise OwnerGatewayNativeError("gateway_http_session_state_invalid")
        context = ssl.create_default_context(cafile=str(self.ca_path))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["http/1.1"])
        self.private_dir, self._directory = _private_root(self.private_dir)
        self._context = context
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def close(self):
        if not self._closed:
            self._closed = True
            self.cookies.clear()
            self.csrf = self.current_reviewer = None
            self.reviewers.clear()
            self._context = None
            if self._directory is not None:
                os.close(self._directory)
                self._directory = None

    def _retain(self, name, raw):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self._directory)
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(self._directory)

    def call(self, method, path, body=None, headers=None):
        if self._closed or self._directory is None:
            raise OwnerGatewayNativeError("gateway_http_session_closed")
        method = method.upper()
        parsed = urlsplit(path)
        if (method not in {"GET", "POST", "HEAD"} or not path.startswith("/") or path.startswith("//")
                or parsed.scheme or parsed.netloc or parsed.fragment or any(ord(ch) < 32 for ch in path)):
            raise OwnerGatewayNativeError("gateway_http_same_origin_required")
        custom = dict(headers or {})
        lowered = [key.lower() for key in custom]
        if len(set(lowered)) != len(lowered) or any(
                key in {"host", "origin", "cookie", "connection", "content-length", "transfer-encoding"}
                for key in lowered):
            raise OwnerGatewayNativeError("gateway_http_forbidden_header")
        values = {"Accept": "application/json", "Connection": "close"}
        if method == "POST":
            values.update({"Origin": self.origin, "Content-Type": "application/json"})
            if self.csrf and "x-csrf-token" not in lowered:
                values["X-CSRF-Token"] = self.csrf
            raw_body = body if isinstance(body, bytes) else json.dumps(
                {} if body is None else body, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        else:
            if body is not None:
                raise OwnerGatewayNativeError("gateway_http_get_body_invalid")
            raw_body = None
        if len(raw_body or b"") > _REQUEST_LIMIT:
            raise OwnerGatewayNativeError("gateway_http_request_bound")
        # Replace headers case-insensitively without manufacturing duplicates.
        for name, value in custom.items():
            for existing in list(values):
                if existing.lower() == name.lower():
                    del values[existing]
            values[name] = value
        request = Request(self.origin + path, data=raw_body, headers=values, method=method)
        self.cookies.add_cookie_header(request)
        connection = http.client.HTTPSConnection(self._host, self._port, timeout=_TIMEOUT,
                                                  context=self._context)
        response = None
        expired = threading.Event()
        live_socket = [None]

        def abort():
            expired.set()
            # HTTPConnection detaches its socket for Connection: close while
            # HTTPResponse still reads its file object. Retain that same socket
            # so a slow response cannot escape the total request deadline.
            sock = live_socket[0] or connection.sock
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()

        timer = threading.Timer(_TIMEOUT, abort)
        timer.daemon = True
        started = time.monotonic()
        timer.start()
        try:
            connection.connect()
            live_socket[0] = connection.sock
            if expired.is_set():
                raise OwnerGatewayNativeError("gateway_http_timeout")
            if connection.sock.version() != "TLSv1.3" or connection.sock.selected_alpn_protocol() != "http/1.1":
                raise OwnerGatewayNativeError("gateway_http_tls_invalid")
            connection.sock.settimeout(max(0.001, _TIMEOUT - (time.monotonic() - started)))
            connection.request(method, path, body=raw_body, headers=dict(request.header_items()))
            response = connection.getresponse()
            if response.version != 11:
                raise OwnerGatewayNativeError("gateway_http_version_invalid")
            if response.getheader("Content-Encoding") not in (None, ""):
                raise OwnerGatewayNativeError("gateway_http_response_encoding_invalid")
            declared = response.getheader("Content-Length")
            if declared is not None and (not declared.isdecimal() or int(declared) > _RESPONSE_LIMIT):
                raise OwnerGatewayNativeError("gateway_http_response_bound")
            chunks, count = [], 0
            while True:
                chunk = response.read1(min(65536, _RESPONSE_LIMIT + 1 - count))
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
                if count > _RESPONSE_LIMIT:
                    raise OwnerGatewayNativeError("gateway_http_response_bound")
            if expired.is_set() or time.monotonic() - started > _TIMEOUT:
                raise OwnerGatewayNativeError("gateway_http_timeout")
            raw = b"".join(chunks)
            if method != "HEAD" and declared is not None and len(raw) != int(declared):
                raise OwnerGatewayNativeError("gateway_http_response_incomplete")
            status = response.status
            # Cookie extraction consumes only response headers in memory.
            self.cookies.extract_cookies(response, request)
            self._counter += 1
            prefix = f"{self._counter:04d}-http"
            metadata = {"method": method, "path": path, "status": status, "tls": "TLSv1.3",
                        "response_bytes": len(raw)}
            self._retain(prefix + ".json", json.dumps(metadata, sort_keys=True).encode() + b"\n")
            self._retain(prefix + ".body", raw)
            return status, raw
        finally:
            timer.cancel()
            if response is not None:
                response.close()
            connection.close()

    def login(self, reviewer_id):
        row = self.reviewers.get(reviewer_id)
        if row is None:
            raise OwnerGatewayNativeError("gateway_http_reviewer_unknown")
        # A new login is an explicit user action, never an automatic retry.
        self.csrf = self.current_reviewer = None
        self.cookies.clear()
        status, raw = self.call("POST", "/api/sign-in", {"id": reviewer_id, "access_code": row["access_code"]})
        result = _exact_json(raw)
        if (status != 200 or not isinstance(result, dict) or set(result) != {"reviewer", "csrf_token"}
                or result["reviewer"] != reviewer_id or not isinstance(result["csrf_token"], str)
                or re.fullmatch(r"[A-Za-z0-9_-]{43}", result["csrf_token"]) is None
                or not any(cookie.name == "__Host-bz_session" and cookie.secure and cookie.path == "/"
                           for cookie in self.cookies)):
            raise OwnerGatewayNativeError("gateway_http_login_failed")
        self.current_reviewer, self.csrf = reviewer_id, result["csrf_token"]
        return {"http_login": True}

    def start(self, experiment_id):
        if not isinstance(experiment_id, str) or not _ID.fullmatch(experiment_id):
            raise OwnerGatewayNativeError("gateway_http_experiment_invalid")
        self.last_request_id = secrets.token_hex(16)
        self.last_run_id = None
        status, raw = self.call("POST", "/api/experiments/" + quote(experiment_id, safe="") + "/runs",
                                {"request_id": self.last_request_id})
        row = _exact_json(raw)
        fields = {"schema_version", "domain", "run_id", "request_id", "job_id", "experiment_id",
                  "phase", "error_code", "needs_operator"}
        if (status != 202 or not isinstance(row, dict) or set(row) != fields
                or type(row["schema_version"]) is not int or row["schema_version"] != 1
                or row["domain"] != "biozero.gateway.owner.v1" or not isinstance(row["run_id"], str)
                or not _HEX16.fullmatch(row["run_id"]) or row["request_id"] != self.last_request_id
                or row["experiment_id"] != experiment_id or type(row["needs_operator"]) is not bool):
            raise OwnerGatewayNativeError("gateway_http_start_contract_invalid")
        self.last_run_id = row["run_id"]
        return row


def _same_json(left, right):
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return math.isfinite(left) and math.isfinite(right) and left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same_json(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_json(a, b) for a, b in zip(left, right))
    return left == right


def gateway_projection_matches(gateway, direct, run_id, experiment_id):
    """Compare the exact Go browser allowlist to the same direct Results DTO.

    This is a comparison of observed projections, not an ownership verifier or
    independent scientific evaluator. Direct Results remains privately retained.
    """
    try:
        return _gateway_projection_matches(gateway, direct, run_id, experiment_id)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False


def _gateway_projection_matches(gateway, direct, run_id, experiment_id):
    common = {"schema_version", "job_id", "acceptance_sha256", "execution_state", "status",
              "release_status", "error_code", "pipeline_output", "scientific_evaluation",
              "detection", "artifact_execution"}
    if (not isinstance(gateway, dict) or not isinstance(direct, dict)
            or set(gateway) != common | {"domain", "run_id", "experiment_id"}
            or set(direct) != common | {"domain", "upload_sha256", "processed_sha256", "pipeline_mode"}
            or type(direct["schema_version"]) is not int or direct["schema_version"] != 1
            or direct["domain"] != "biozero.results.owner.v1"
            or not isinstance(run_id, str) or not _HEX16.fullmatch(run_id)
            or not isinstance(experiment_id, str) or not _ID.fullmatch(experiment_id)
            or not isinstance(direct["job_id"], str) or not _HEX16.fullmatch(direct["job_id"])
            or any(not isinstance(direct[name], str) or not _HEX64.fullmatch(direct[name])
                   for name in ("acceptance_sha256", "upload_sha256", "processed_sha256"))
            or direct["pipeline_mode"] not in {"variants", "stats"}):
        return False
    if (direct["execution_state"] not in {"reserved", "executing", "prepared", "committed"}
            or direct["status"] not in {"pending", "succeeded", "failed", "incomplete"}
            or direct["release_status"] not in {"withheld", "unassessed", "evaluated_passed"}
            or not isinstance(direct["error_code"], str)
            or direct["error_code"] and not _CODE.fullmatch(direct["error_code"])):
        return False
    expected = {name: direct[name] for name in common}
    expected.update(domain="biozero.gateway.owner.v1", run_id=run_id, experiment_id=experiment_id)
    pipeline = direct["pipeline_output"]
    if pipeline is not None:
        if not isinstance(pipeline, dict) or not isinstance(pipeline["stages"], list):
            return False
        view = {key: pipeline[key] for key in ("schema_version", "mode", "pipeline_status")}
        if (type(view["schema_version"]) is not int or view["schema_version"] != 1
                or view["mode"] != direct["pipeline_mode"]
                or view["pipeline_status"] not in {"succeeded", "failed", "incomplete"}):
            return False
        for key in ("read_count", "avg_read_length", "line_count", "byte_count", "variant_count"):
            if key in pipeline:
                if type(pipeline[key]) is not int or pipeline[key] < 0:
                    return False
                view[key] = pipeline[key]
        for key in ("sha256", "reference_sha256"):
            if pipeline.get(key):
                if not isinstance(pipeline[key], str) or not _HEX64.fullmatch(pipeline[key]):
                    return False
                view[key] = pipeline[key]
        view["stages"] = []
        for stage in pipeline["stages"]:
            if not isinstance(stage, dict) or stage["status"] not in {"succeeded", "failed", "incomplete"}:
                return False
            item = {"status": stage["status"]}
            if stage.get("error_code"):
                if not isinstance(stage["error_code"], str) or not _CODE.fullmatch(stage["error_code"]):
                    return False
                item["error_code"] = stage["error_code"]
            view["stages"].append(item)
        expected["pipeline_output"] = view
    evaluation = direct["scientific_evaluation"]
    if evaluation is not None:
        if not isinstance(evaluation, dict) or evaluation["evaluation_status"] not in {"passed", "failed"}:
            return False
        view = {"evaluation_status": evaluation["evaluation_status"],
                "precision": evaluation.get("precision"), "recall": evaluation.get("recall")}
        for key in ("tp", "fp", "fn", "unexpected_count", "missing_count"):
            if key in evaluation:
                if type(evaluation[key]) is not int or evaluation[key] < 0:
                    return False
                view[key] = evaluation[key]
        for key in ("precision", "recall"):
            if view[key] is not None and (type(view[key]) not in (int, float) or not math.isfinite(view[key])):
                return False
        if evaluation.get("scope"):
            if not isinstance(evaluation["scope"], str):
                return False
            view["scope"] = evaluation["scope"]
        if "error" in evaluation:
            if not isinstance(evaluation["error"], str):
                return False
            if evaluation["error"]:
                view["error"] = "scientific_evaluation_failed"
        expected["scientific_evaluation"] = view
    detection = direct["detection"]
    if detection is not None:
        if (not isinstance(detection, dict) or type(detection["score"]) not in (int, float)
                or not math.isfinite(detection["score"]) or not 0 <= detection["score"] <= 1
                or detection.get("verdict") not in {"low", "medium", "high"}
                or not isinstance(detection.get("reasons", []), list)
                or any(not isinstance(reason, str) for reason in detection.get("reasons", []))):
            return False
        expected["detection"] = {"score": detection["score"], "verdict": detection["verdict"],
                                 "reasons": detection.get("reasons", [])}
    artifact = direct["artifact_execution"]
    if artifact is not None:
        if (not isinstance(artifact, dict) or set(artifact) != {"schema_version", "profile_sha256", "store_id", "lease_id",
                                                            "manifest_sha256", "receipt_sha256", "receipt_bytes", "files"}
                or not isinstance(artifact["files"], dict)):
            return False
        if (type(artifact["schema_version"]) is not int or artifact["schema_version"] != 1
                or type(artifact["receipt_bytes"]) is not int or not 0 <= artifact["receipt_bytes"] <= _RESPONSE_LIMIT
                or any(not isinstance(artifact[key], str) or not _HEX64.fullmatch(artifact[key])
                       for key in ("profile_sha256", "manifest_sha256"))
                or any(not isinstance(artifact[key], str) or re.fullmatch(r"[0-9a-f]{32}", artifact[key]) is None
                       for key in ("store_id", "lease_id"))
                or not isinstance(artifact["receipt_sha256"], str)
                or artifact["receipt_sha256"] and not _HEX64.fullmatch(artifact["receipt_sha256"])):
            return False
        for name, entry in artifact["files"].items():
            if (name not in {"execution_receipt", "normalized_vcf", "variants_vcf", "variants_vcf_index"}
                    or not isinstance(entry, dict) or set(entry) != {"sha256", "bytes"}
                    or not isinstance(entry["sha256"], str) or not _HEX64.fullmatch(entry["sha256"])
                    or type(entry["bytes"]) is not int or entry["bytes"] < 0):
                return False
    return _same_json(gateway, expected)

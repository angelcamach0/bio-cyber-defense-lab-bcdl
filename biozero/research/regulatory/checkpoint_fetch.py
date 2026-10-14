#!/usr/bin/env python3
"""Explicit, bounded, verified private checkpoint acquisition; never auto-downloads.

The persistent budget counts observed response body bytes plus reservations
that may survive interrupted reads. Each reservation is reconciled to the
actual returned byte count after a successful read. TLS/HTTP framing and
buffers outside this client are not a measured wire counter. No retries, TLS bypass, package install, or checkpoint loading occurs.
"""
import argparse
import contextlib
import fcntl
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import signal
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_TRANSFER = 1 << 30
MAX_HTML = 64 << 10
CHUNK = 1 << 20
FILE_DEADLINE_SECONDS = 180
HERE = Path(__file__).resolve().parent
SOURCE_COMMIT = "217469410410e07b6663372da847426ffd172855"
CATALOG_SHA256 = "6c436349a46ef4eb2a2f49229e3ddc83e642813965a14d4c16aa0045ce25d920"


class FetchError(RuntimeError):
    pass


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".verified-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class TransferLedger:
    """One process owns the ledger; failed/interrupted attempts retain charges."""
    def __init__(self, prefix, limit=MAX_TRANSFER):
        if not 0 < limit <= MAX_TRANSFER:
            raise FetchError("transfer budget may not exceed 1 GiB")
        self.prefix = Path(prefix)
        self.prefix.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.prefix.is_symlink():
            raise FetchError("private prefix must not be a symlink")
        os.chmod(self.prefix, 0o700)
        self.path = self.prefix / "transfer-ledger.json"
        self.lock = open(self.prefix / "transfer-ledger.lock", "a+")
        os.chmod(self.prefix / "transfer-ledger.lock", 0o600)
        fcntl.flock(self.lock, fcntl.LOCK_EX)
        self.data = {"schema_version": 1, "limit_bytes": limit,
                     "charged_bytes": 0, "body_bytes_observed": 0,
                     "http_exchanges": 0, "attempts": [], "accounting":
                     "actual response-body bytes plus conservative unreconciled read reservations; not a TLS wire counter"}
        try:
            if self.path.exists():
                existing = json.loads(self.path.read_text())
                required = (existing.get("schema_version") == 1 and
                            existing.get("limit_bytes") == limit and
                            isinstance(existing.get("charged_bytes"), int) and
                            0 <= existing["charged_bytes"] <= limit and
                            isinstance(existing.get("body_bytes_observed"), int) and
                            0 <= existing["body_bytes_observed"] <= existing["charged_bytes"])
                if not required:
                    raise FetchError("persistent ledger is incompatible or invalid; refusing reset")
                self.data = existing
            else:
                self.save()
        except Exception:
            self.close()
            raise

    def save(self):
        atomic_json(self.path, self.data)

    def charge(self, count, kind="body"):
        if count < 0 or self.data["charged_bytes"] + count > self.data["limit_bytes"]:
            raise FetchError("persistent transfer budget exhausted")
        self.data["charged_bytes"] += count
        if kind == "exchange":
            self.data["http_exchanges"] += 1
        self.save()

    def observed(self, count, reserved):
        if not 0 <= count <= reserved:
            raise FetchError("response exceeded its reserved byte count")
        self.data["body_bytes_observed"] += count
        self.data["charged_bytes"] -= reserved - count
        self.save()

    def interrupted(self, observed):
        # Returned fragments are known to have transferred; the rest of the
        # reserved window remains conservative because a failing socket read
        # may have consumed bytes that were never returned to this process.
        self.data["body_bytes_observed"] += observed
        self.save()

    def close(self):
        if not self.lock.closed:
            fcntl.flock(self.lock, fcntl.LOCK_UN)
            self.lock.close()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


def allowed_url(value):
    parsed = urllib.parse.urlsplit(value)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise FetchError("download URL must use HTTPS without credentials")
    allowed = host in ("drive.google.com", "drive.usercontent.google.com", "googleusercontent.com") or host.endswith(".googleusercontent.com")
    if not allowed or parsed.fragment:
        raise FetchError("download destination is outside the Google Drive allowlist")
    return value


@contextlib.contextmanager
def deadline_alarm(seconds):
    if not hasattr(signal, "setitimer"):
        raise FetchError("hard download deadline requires a POSIX alarm")
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    if previous_timer != (0.0, 0.0):
        raise FetchError("another real-time alarm is active")
    def expired(unused_signum, unused_frame):
        raise FetchError("per-file download deadline exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


class ConfirmForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"action": attrs.get("action", ""), "method": attrs.get("method", "get").lower(), "fields": {}}
        elif tag == "input" and self.current is not None and attrs.get("type", "").lower() == "hidden":
            name, value = attrs.get("name", ""), attrs.get("value", "")
            if len(name) > 64 or len(value) > 2048:
                raise FetchError("confirmation field too large")
            if name:
                self.current["fields"][name] = value

    def handle_endtag(self, tag):
        if tag == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None


def confirmation_url(html, base_url, drive_id):
    if len(html) > MAX_HTML:
        raise FetchError("confirmation HTML exceeds 64 KiB")
    parser = ConfirmForm()
    parser.feed(html.decode("utf-8", errors="strict"))
    for form in parser.forms:
        fields = form["fields"]
        if form["method"] != "get" or fields.get("id") != drive_id or not fields.get("confirm"):
            continue
        action = allowed_url(urllib.parse.urljoin(base_url, form["action"]))
        parsed = urllib.parse.urlsplit(action)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        query.update(fields)
        return allowed_url(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), "")))
    raise FetchError("Google Drive response has no supported bounded confirmation form")


class BoundedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, client):
        self.client = client

    def http_error_302(self, request, response, code, message, headers):
        location = headers.get("Location")
        if not location:
            response.close()
            raise FetchError("redirect has no destination")
        target = allowed_url(urllib.parse.urljoin(request.full_url, location))
        self.client.redirects += 1
        if self.client.redirects > 4:
            response.close()
            raise FetchError("too many download redirects")
        # The standard redirect handler reads an unbounded body. This handler
        # closes immediately; no redirect body is consumed and no retry occurs.
        response.close()
        return self.client.open(target, request.get_method())

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


class DownloadClient:
    def __init__(self, ledger, deadline, opener=None):
        self.ledger, self.deadline = ledger, deadline
        self.redirects = 0
        context = ssl.create_default_context()
        self.opener = opener or urllib.request.build_opener(
            BoundedRedirect(self), urllib.request.HTTPSHandler(context=context))

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise FetchError("per-file download deadline exceeded")
        return remaining

    def open(self, url, method="GET"):
        allowed_url(url)
        self.ledger.data["http_exchanges"] += 1
        self.ledger.save()
        request = urllib.request.Request(url, method=method, headers={
            "User-Agent": "BioZero-SCI01-private-research/1", "Accept-Encoding": "identity"})
        try:
            response = self.opener.open(request, timeout=min(30, self.remaining()))
        except urllib.error.HTTPError as exc:
            # Error body reads are accounted exactly, bounded, and never retried.
            try:
                self.bounded_html(exc)
            finally:
                exc.close()
            raise FetchError("HTTP request failed without retry") from None
        allowed_url(response.geturl())
        if response.headers.get("Content-Encoding", "identity").lower() != "identity":
            response.close()
            raise FetchError("compressed transfer encoding is unsupported")
        return response

    def read(self, response, size):
        self.remaining()
        self.ledger.charge(size)
        # Reserve/persist one window before network I/O, then accumulate short
        # TLS records in memory. Two ledger writes per window, not per fragment.
        read = getattr(response, "read1", response.read)
        data = bytearray()
        try:
            while len(data) < size:
                self.remaining()
                part = read(size - len(data))
                if not part:
                    break
                if len(part) > size - len(data):
                    raise FetchError("response exceeded reserved read window")
                data.extend(part)
        except BaseException:
            self.ledger.interrupted(len(data))
            raise
        self.ledger.observed(len(data), size)
        return bytes(data)

    def bounded_html(self, response):
        data = bytearray()
        while len(data) <= MAX_HTML:
            part = self.read(response, min(8192, MAX_HTML + 1 - len(data)))
            if not part:
                return bytes(data)
            data.extend(part)
        raise FetchError("confirmation HTML exceeds 64 KiB")


def verify_file(path, entry):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size != entry["size_bytes"]:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(CHUNK), b""):
            digest.update(part)
    return digest.hexdigest() == entry["sha256"]


def load_manifest(path=HERE / "checkpoints.json"):
    manifest = json.loads(Path(path).read_text())
    if manifest.get("schema_version") != 1 or manifest.get("source_commit") != SOURCE_COMMIT:
        raise FetchError("checkpoint manifest/source revision is unsupported")
    entries = manifest.get("files", [])
    names = set()
    for entry in entries:
        filename = entry.get("filename", "")
        if (Path(filename).name != filename or filename in (".","..") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",filename) or filename in names or
                not isinstance(entry.get("size_bytes"), int) or not 0 < entry["size_bytes"] <= MAX_TRANSFER or
                not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")) or
                not re.fullmatch(r"[A-Za-z0-9_-]{10,100}", entry.get("drive_id", ""))):
            raise FetchError("invalid checkpoint manifest entry")
        names.add(filename)
    if not entries or sum(entry["size_bytes"] for entry in entries) != manifest.get("total_checkpoint_bytes"):
        raise FetchError("checkpoint manifest total is inconsistent")
    catalog = [{key: entry[key] for key in ("component","drive_id","size_bytes","sha256")}
               for entry in sorted(entries,key=lambda item:item["component"])]
    digest = hashlib.sha256(json.dumps(catalog,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    if digest != CATALOG_SHA256:
        raise FetchError("checkpoint catalog differs from the five approved pins")
    return manifest


def fetch_file(entry, prefix, ledger, client_factory=DownloadClient):
    weights = Path(prefix) / "checkpoints"
    weights.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = weights / entry["filename"]
    if verify_file(destination, entry):
        return {"component": entry["component"], "status": "verified_cached", "size_bytes": entry["size_bytes"], "sha256": entry["sha256"]}
    if destination.exists():
        raise FetchError("existing checkpoint failed verification; refusing overwrite")
    attempt = {"component": entry["component"], "started_unix": time.time(), "status": "started"}
    ledger.data["attempts"].append(attempt)
    ledger.save()
    temporary = None
    try:
        with deadline_alarm(FILE_DEADLINE_SECONDS):
            client = client_factory(ledger, time.monotonic() + FILE_DEADLINE_SECONDS)
            url = "https://drive.google.com/uc?" + urllib.parse.urlencode({"export": "download", "id": entry["drive_id"]})
            # Explicit HEAD checks are subject to the same redirect/deadline and
            # shared budget. GET still independently verifies MIME and payload.
            with client.open(url, "HEAD") as head:
                length = head.headers.get("Content-Length")
                if head.headers.get_content_type() != "text/html" and length is not None and int(length) != entry["size_bytes"]:
                    raise FetchError("HEAD size disagrees with pinned checkpoint")
            response = client.open(url)
            if response.headers.get_content_type() == "text/html":
                with response:
                    html = client.bounded_html(response)
                    url = confirmation_url(html, response.geturl(), entry["drive_id"])
                response = client.open(url)
            with response:
                if response.headers.get_content_type() == "text/html":
                    client.bounded_html(response)
                    raise FetchError("confirmation did not yield a checkpoint")
                length = response.headers.get("Content-Length")
                if length is not None and int(length) != entry["size_bytes"]:
                    raise FetchError("GET size disagrees with pinned checkpoint")
                descriptor, temporary = tempfile.mkstemp(prefix=".unverified-", dir=weights)
                digest, count = hashlib.sha256(), 0
                with os.fdopen(descriptor, "wb") as stream:
                    while count <= entry["size_bytes"]:
                        part = client.read(response, min(CHUNK, entry["size_bytes"] + 1 - count))
                        if not part:
                            break
                        count += len(part)
                        if count > entry["size_bytes"]:
                            raise FetchError("checkpoint exceeds pinned size")
                        stream.write(part)
                        digest.update(part)
                    if count != entry["size_bytes"] or digest.hexdigest() != entry["sha256"]:
                        raise FetchError("checkpoint size/SHA256 verification failed")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, destination)
                temporary = None
            attempt.update(status="verified", completed_unix=time.time(), size_bytes=count, sha256=digest.hexdigest())
            ledger.save()
            return {"component": entry["component"], "status": "verified", "size_bytes": count, "sha256": digest.hexdigest()}
    except Exception as exc:
        attempt.update(status="failed", completed_unix=time.time(), error_type=type(exc).__name__)
        ledger.save()
        raise
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=HERE.parents[2] / ".biozero" / "regulatory-assets")
    parser.add_argument("--manifest", type=Path, default=HERE / "checkpoints.json")
    parser.add_argument("--only", help="Comma-separated component names; default all five")
    parser.add_argument("--download", action="store_true", help="Explicitly perform network acquisition")
    args = parser.parse_args()
    manifest = load_manifest(args.manifest)
    components = args.only.split(",") if args.only else [entry["component"] for entry in manifest["files"]]
    entries = [entry for entry in manifest["files"] if entry["component"] in components]
    if set(components) != {entry["component"] for entry in entries}:
        parser.error("unknown checkpoint component")
    if not args.download:
        print(json.dumps({"status": "not_downloaded", "components": components,
                          "expected_bytes": sum(entry["size_bytes"] for entry in entries),
                          "network_access_performed": False, "usage": manifest["usage"]}, indent=2))
        return 0
    results = []
    with TransferLedger(args.prefix) as ledger:
        for entry in entries:
            results.append(fetch_file(entry, args.prefix, ledger))
        print(json.dumps({"status": "verified", "results": results,
                          "charged_bytes": ledger.data["charged_bytes"],
                          "body_bytes_observed": ledger.data["body_bytes_observed"],
                          "usage": manifest["usage"]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FetchError, OSError, ValueError, urllib.error.HTTPError) as exc:
        # No URL/query/cookie/credentials are printed on error.
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        raise SystemExit(1)

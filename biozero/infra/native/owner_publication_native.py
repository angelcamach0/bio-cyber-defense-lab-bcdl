# SPDX-License-Identifier: AGPL-3.0-only
"""PRIVATE integration draft; never executed as native acceptance by its author.

No build/install/Popen, automatic publication, repair, or scientific computation.
All commands, owned processes, HTTP, evidence writes and assertions go through
the existing run_owner_worker tools namespace. Importing this module has no IO.
"""

import copy
import http.client
import os
from pathlib import Path
import re
import ssl
import stat


RUN_CHARGE = (2 * (64 << 10) + (4 << 10)) + (64 << 10) + (8 << 10)
STEP_LIMIT = 96 << 10
STEP_NAMES = ("00-intent.json", "01-publishing.json", "02-published.json")
RECEIPT_KEYS = {"schema_version", "domain", "state", "publisher_scope", "authority_scope",
                "job_id", "acceptance_sha256", "credential_sha256", "execution_profile_sha256", "pipeline_mode"}


def _identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _directory(path, private=True):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.abspath(path) or path == Path("/"):
        raise ValueError("publication evidence path is not absolute and normalized")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                          os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
        info = os.fstat(fd)
        if private and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("publication evidence directory is not private")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(path, limit):
    """Bounded FD snapshot plus final pathname identity; never follows symlinks."""
    path = Path(path)
    parent = _directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_uid != os.geteuid() or before.st_nlink != 1 or not 0 <= before.st_size <= limit):
                raise ValueError("publication evidence file is not bounded/private/regular")
            chunks, count = [], 0
            while True:
                raw = os.read(fd, min(65536, limit + 1 - count))
                if not raw:
                    break
                count += len(raw)
                if count > limit:
                    raise ValueError("publication evidence exceeds bound")
                chunks.append(raw)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if count != before.st_size or _identity(before) != _identity(os.fstat(fd)) or _identity(before) != _identity(named):
                raise ValueError("publication evidence changed during read")
            return b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


class PublicationNative:
    """Injected tools: command/openssl/start/request/private_json/private_bytes/
    check/tree_hashes/asset/exact_json/compact/sha/free_port/wait_for.

    start owns all child registration/Wait/error attribution. The caller must
    start publisher before Upload and stop/drain Upload before publisher. This
    helper does not stop/restart processes or relabel their failures.
    """

    def __init__(self, tools, *, runtime, bins, pki, evidence, logs, authority_id,
                 public_key_hex, mode, profile, authority_scope, used_ports=()):
        required = ("command", "openssl", "start", "request", "private_json", "private_bytes", "check",
                    "tree_hashes", "asset", "exact_json", "compact", "sha", "free_port", "wait_for")
        self.t = {key: tools[key] if isinstance(tools, dict) else getattr(tools, key) for key in required}
        if any(not callable(value) for value in self.t.values()):
            raise ValueError("publication tools must be callables")
        self.runtime, self.bins, self.pki, self.evidence, self.logs = map(Path, (runtime, bins, pki, evidence, logs))
        for path in (self.runtime, self.bins, self.pki, self.evidence, self.logs):
            fd = _directory(path)
            os.close(fd)
        if (mode not in ("variants", "stats") or re.fullmatch("[0-9a-f]{64}", profile) is None
                or re.fullmatch("[0-9a-f]{64}", public_key_hex) is None
                or re.fullmatch("[0-9a-f]{32}", authority_id) is None):
            raise ValueError("publication external authority pin invalid")
        self._scope(authority_scope, "store_id")
        self.authority_id, self.public_key_hex, self.mode, self.profile = authority_id, public_key_hex, mode, profile
        self.authority_scope = copy.deepcopy(authority_scope)
        self.state = self.runtime / "publisher-state"
        self.primary_inbox = self.state / "inbox"
        self.config_path = self.runtime / "config/publisher.json"
        self.genesis_config_path = self.runtime / "config/publisher-genesis.json"
        self.used_ports, self.observed, self.sequence = set(used_ports), {}, 0
        self.config = self.scope = self.port = self.context = self.producer_der = self.producer_sha = None
        self.upload_publisher = None

    @staticmethod
    def _scope(value, field):
        if (not isinstance(value, dict) or set(value) != {field, "policy_sha256"}
                or not isinstance(value[field], str) or re.fullmatch("[0-9a-f]{32}", value[field]) is None
                or not isinstance(value["policy_sha256"], str) or re.fullmatch("[0-9a-f]{64}", value["policy_sha256"]) is None):
            raise ValueError("publication external scope invalid")

    def _digest(self, raw):
        import hashlib
        return hashlib.sha256(raw).hexdigest()

    def _check(self, name, passed, observed=None):
        # Existing harness check persists before raising, retaining failures.
        self.t["check"]("publisher_" + name, passed, observed)

    def _private(self, path, raw):
        self.t["private_bytes"](path, raw)
        return path

    def _public(self, certificate, label):
        _, raw = self.t["openssl"]("publisher-public-" + label, "x509", "-in", certificate, "-pubkey", "-noout")
        return raw

    def _issue(self, role, issuer, serial, server=False, subject=None):
        pki, op = self.pki, self.t["openssl"]
        op(role + "-key", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", pki / (role + ".key"))
        op(role + "-csr", "req", "-new", "-sha256", "-key", pki / (role + ".key"), "-out", pki / (role + ".csr"),
           "-subj", "/CN=" + (subject or role))
        extension = ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage="
                     + ("serverAuth\nsubjectAltName=IP:127.0.0.1\n" if server else "clientAuth\n"))
        self._private(pki / (role + ".ext"), extension.encode())
        op(role + "-cert", "x509", "-req", "-sha256", "-in", pki / (role + ".csr"), "-CA", pki / (issuer + ".crt"),
           "-CAkey", pki / (issuer + ".key"), "-set_serial", str(serial), "-days", "2",
           "-extfile", pki / (role + ".ext"), "-out", pki / (role + ".crt"))
        op(role + "-purpose", "verify", "-CAfile", pki / (issuer + ".crt"), "-purpose",
           "sslserver" if server else "sslclient", pki / (role + ".crt"))
        wrong, _ = op(role + "-other-purpose", "verify", "-CAfile", pki / (issuer + ".crt"), "-purpose",
                      "sslclient" if server else "sslserver", pki / (role + ".crt"), expected=None)
        self._check("separate_eku_" + role, wrong != 0)

    def prepare(self):
        """After authority genesis, before Upload genesis; fails on existing root."""
        if (self.config is not None or self.state.exists() or self.state.is_symlink()
                or self.config_path.exists() or self.config_path.is_symlink()
                or self.genesis_config_path.exists() or self.genesis_config_path.is_symlink()):
            raise ValueError("publication helper cannot adopt existing state")
        op, pki = self.t["openssl"], self.pki
        if any((pki / (role + suffix)).exists() or (pki / (role + suffix)).is_symlink()
               for role in ("producer-ca", "upload-producer", "rogue-producer", "publisher")
               for suffix in (".key", ".crt", ".csr", ".ext")):
            raise ValueError("publication PKI output already exists")
        _, signing_der = op("publisher-external-signing-pin", "pkey", "-pubin", "-in", pki / "signing.pub", "-outform", "DER")
        self._check("actual_signature_verifier_external_pin", len(signing_der) == 44
                    and signing_der[:12].hex() == "302a300506032b6570032100" and signing_der[-32:].hex() == self.public_key_hex)
        op("producer-ca-key", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", pki / "producer-ca.key")
        op("producer-ca-cert", "req", "-new", "-x509", "-sha256", "-key", pki / "producer-ca.key", "-out", pki / "producer-ca.crt",
           "-days", "2", "-subj", "/CN=owner-publication-producer-ca", "-addext", "basicConstraints=critical,CA:TRUE",
           "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        self._issue("upload-producer", "producer-ca", 701, subject="upload-publication-producer")
        self._issue("rogue-producer", "producer-ca", 701, subject="upload-publication-producer")
        self._issue("publisher", "ca", 702, server=True)
        self.producer_der = ssl.PEM_cert_to_DER_cert(_read(pki / "upload-producer.crt", 32 << 10).decode())
        self.producer_sha = self._digest(self.producer_der)
        _, good_labels = op("producer-labels", "x509", "-in", pki / "upload-producer.crt", "-noout", "-subject", "-serial")
        _, rogue_labels = op("rogue-producer-labels", "x509", "-in", pki / "rogue-producer.crt", "-noout", "-subject", "-serial")
        roles = ("upload-producer", "rogue-producer", "publisher", "owner-a", "owner-b", "upload", "authority", "results")
        if (pki / "gateway.crt").exists():
            roles += ("gateway",)
        public = {role: self._public(pki / (role + ".crt"), role) for role in roles}
        for role in ("recipient", "signing"):
            path = pki / ("signing.pem" if role == "signing" else "recipient.key")
            _, raw = op("publisher-keyrole-" + role, "pkey", "-in", path, "-pubout")
            public[role] = raw
        ca_public = self._public(pki / "ca.crt", "owner-ca")
        producer_ca_public = self._public(pki / "producer-ca.crt", "producer-ca")
        self._check("producer_issuer_and_all_private_key_roles_distinct", len(set(public.values())) == len(public)
                    and producer_ca_public != ca_public and producer_ca_public not in public.values()
                    and ca_public not in public.values() and good_labels == rogue_labels,
                    {"key_roles": len(public), "producer_cn_serial_equal": good_labels == rogue_labels})
        # Assert actual different issuer, not a renamed copy of the owner CA.
        owner_trust, _ = op("producer-reject-owner-issuer", "verify", "-CAfile", pki / "ca.crt", pki / "upload-producer.crt", expected=None)
        producer_trust, _ = op("owner-reject-producer-issuer", "verify", "-CAfile", pki / "producer-ca.crt", pki / "owner-a.crt", expected=None)
        self._check("actual_issuer_separation", owner_trust != 0 and producer_trust != 0)
        self.port = self.t["free_port"]()
        while self.port in self.used_ports:
            self.port = self.t["free_port"]()
        a = self.t["asset"]
        self.config = {"schema_version": 1, "listen_address": "127.0.0.1:" + str(self.port), "state_directory": str(self.state),
                       "authority_id": self.authority_id, "public_key_hex": self.public_key_hex, "pipeline_mode": self.mode,
                       "execution_profile_sha256": self.profile, "expected_authority_scope": self.authority_scope,
                       "expected_publisher_scope": {"publisher_id": "", "policy_sha256": ""},
                       "producer_credential_sha256": [self.producer_sha], "tls_certificate": a(pki / "publisher.crt"),
                       "tls_private_key": a(pki / "publisher.key"), "producer_ca": a(pki / "producer-ca.crt")}
        self.t["private_json"](self.genesis_config_path, self.config)
        _, raw = self.t["command"]("publisher-genesis", [self.bins / "acceptance-publisher", "--config", self.genesis_config_path, "--init-store"])
        self.scope = self.t["exact_json"](raw)
        self._scope(self.scope, "publisher_id")
        self._check("external_scope_from_actual_genesis", raw == self.t["compact"](self.scope) + b"\n")
        self._private(self.evidence / "publisher-genesis-scope.json", raw)
        self.config["expected_publisher_scope"] = self.scope
        self.t["private_json"](self.config_path, self.config)
        self.upload_publisher = {"base_url": "https://127.0.0.1:" + str(self.port), "server_name": "127.0.0.1",
                                 "expected_publisher_scope": self.scope, "producer_tls_certificate": a(pki / "upload-producer.crt"),
                                 "producer_tls_private_key": a(pki / "upload-producer.key"), "publisher_ca": a(pki / "ca.crt")}
        self.context = self.client_context("upload-producer")
        self._genesis()
        self._check("empty_genesis_catalogue_no_fixture_inbox_writes", self.catalogue()["records"] == [] and not list((self.state / "inbox").iterdir()))
        return {"upload_publisher": copy.deepcopy(self.upload_publisher), "results_inbox": self.primary_inbox,
                "publisher_scope": copy.deepcopy(self.scope), "port": self.port, "config_path": self.config_path}

    def client_context(self, role):
        ctx = ssl.create_default_context(cafile=str(self.pki / "ca.crt"))
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(["http/1.1"])
        if role is not None:
            ctx.load_cert_chain(self.pki / (role + ".crt"), self.pki / (role + ".key"))
        return ctx

    def start(self, name="acceptance-publisher"):
        if self.config is None:
            raise ValueError("publication helper requires explicit genesis")
        proc = self.t["start"](name, [self.bins / "acceptance-publisher", "--config", self.config_path])
        self.t["wait_for"](lambda: b"ownership_publication_ready\n" in (self.logs / (name + ".stdout")).read_bytes())
        code, raw, version = self.t["request"](self.port, self.context, "GET", "/healthz")
        self._private(self.evidence / (name + "-health.body"), raw)
        self._check(name + "_actual_producer_mtls_health", code == 200 and version == "TLSv1.3"
                    and self.t["exact_json"](raw) == {"status": "publication_alive"})
        return proc

    def _genesis(self):
        value = self.t["exact_json"](_read(self.state / "genesis.json", 4096))
        if value != {"schema_version": 1, "domain": "biozero.authorization-publication.genesis.v1", "scope": self.scope}:
            raise ValueError("publication genesis differs from externally pinned scope")

    def catalogue(self):
        self._genesis()
        value = self.t["exact_json"](_read(self.state / "catalogue.json", 1 << 20))
        if (set(value) != {"schema_version", "domain", "publisher_scope", "records"} or type(value["schema_version"]) is not int
                or value["schema_version"] != 1 or value["domain"] != "biozero.authorization-publication.catalogue.v1"
                or value["publisher_scope"] != self.scope or not isinstance(value["records"], list) or len(value["records"]) > 64):
            raise ValueError("publication catalogue invalid")
        seen, owners = set(), {}
        for row in value["records"]:
            if (set(row) != {"job_id", "acceptance_sha256", "credential_sha256", "producer_credential_sha256", "retained_bytes"}
                    or re.fullmatch("[0-9a-f]{16}", row["job_id"]) is None or row["job_id"] in seen
                    or any(re.fullmatch("[0-9a-f]{64}", row[k]) is None for k in ("acceptance_sha256", "credential_sha256"))
                    or row["producer_credential_sha256"] != self.producer_sha or row["credential_sha256"] == self.producer_sha
                    or type(row["retained_bytes"]) is not int or row["retained_bytes"] != RUN_CHARGE):
                raise ValueError("publication catalogue row invalid")
            seen.add(row["job_id"])
            owners[row["credential_sha256"]] = owners.get(row["credential_sha256"], 0) + 1
        if any(count > 20 for count in owners.values()):
            raise ValueError("publication per-owner retained count exceeds bound")
        return value

    def _expected_receipt(self, job, raw, binding):
        return {"schema_version": 1, "domain": "biozero.authorization-publication.v1", "state": "published",
                "publisher_scope": self.scope, "authority_scope": self.authority_scope, "job_id": job,
                "acceptance_sha256": self._digest(raw), "credential_sha256": binding["credential_sha256"],
                "execution_profile_sha256": self.profile, "pipeline_mode": self.mode}

    def observe(self, job, canonical_signed, uploadroot):
        """Positive assertion only: never creates/repairs source or receiver files.

        Call after actual Upload delivered, including copied-cipher B: successful
        publication is authorization metadata, not successful GCM or execution.
        """
        if not isinstance(canonical_signed, bytes) or not 0 < len(canonical_signed) <= 64 << 10:
            raise ValueError("publication observation needs bounded canonical signed bytes")
        if re.fullmatch("[0-9a-f]{16}", job) is None:
            raise ValueError("publication observation job invalid")
        raw, root, compact, parse = canonical_signed, Path(uploadroot), self.t["compact"], self.t["exact_json"]
        signed = parse(raw)
        if set(signed) != {"record", "signature"} or compact(signed) != raw:
            raise ValueError("publication observation acceptance is not exact canonical representation")
        record, binding = signed["record"], signed["record"]["binding"]
        owner_der = bytes.fromhex(record["credential_der"])
        if (type(record["schema_version"]) is not int or record["schema_version"] != 1
                or record["domain"] != "biozero.ownership.acceptance.v1"
                or binding["job_id"] != job or binding["authority_id"] != self.authority_id
                or record["authority_id"] != self.authority_id or record["store_id"] != self.authority_scope["store_id"]
                or record["policy_sha256"] != self.authority_scope["policy_sha256"] or binding["pipeline_mode"] != self.mode
                or binding["execution_profile_sha256"] != self.profile or binding["credential_sha256"] != self._digest(owner_der)
                or binding["credential_sha256"] == self.producer_sha):
            raise ValueError("publication observation signed external binding differs")
        # Actual retained Ed25519 acceptance signature; production also validates
        # nested challenge/manifest and historical semantics independently.
        prefix = "publication-%03d-%s" % (self.sequence, job)
        self.sequence += 1
        message = self._private(self.evidence / (prefix + ".record"), compact(record))
        signature = self._private(self.evidence / (prefix + ".signature"), bytes.fromhex(signed["signature"]))
        self.t["openssl"](prefix + "-signature", "pkeyutl", "-verify", "-pubin", "-inkey", self.pki / "signing.pub",
                          "-rawin", "-in", message, "-sigfile", signature)
        owner_path = self._private(self.evidence / (prefix + ".owner.der"), owner_der)
        _, owner_key = self.t["openssl"](prefix + "-owner-public", "x509", "-inform", "DER", "-in", owner_path, "-pubkey", "-noout")
        producer_key = self._public(self.pki / "upload-producer.crt", prefix + "-producer")
        expected = self._expected_receipt(job, raw, binding)
        inbox = _read(self.state / "inbox" / (job + ".json"), 64 << 10)
        source_sidecar = _read(root / "acceptances" / (job + ".json"), 64 << 10)
        # Upload sidecar is currently canonical but compare exact bytes to catch
        # a future silent representation change, rather than recanonicalizing.
        self._check(prefix + "_automatic_inbox_exact_source_no_copy", inbox == source_sidecar == raw and owner_key != producer_key)
        receiver = self.state / "operations" / job
        intent = parse(_read(receiver / "intent.json", 132 << 10))
        receipt = parse(_read(receiver / "published.json", 8 << 10))
        expected_intent = {"schema_version": 1, "domain": "biozero.authorization-publication.intent.v1",
                           "publisher_scope": self.scope, "producer_credential_sha256": self.producer_sha,
                           "producer_credential_der": self.producer_der.hex(), "acceptance_json": raw.decode(), "retained_bytes": RUN_CHARGE}
        self._check(prefix + "_receiver_full_producer_leaf_binding", intent == expected_intent
                    and receipt == expected and set(receipt) == RECEIPT_KEYS
                    and {p.name for p in receiver.iterdir()} == {"intent.json", "published.json"})
        catalogue = self.catalogue()
        expected_row = {"job_id": job, "acceptance_sha256": expected["acceptance_sha256"],
                        "credential_sha256": binding["credential_sha256"], "producer_credential_sha256": self.producer_sha,
                        "retained_bytes": RUN_CHARGE}
        self._check(prefix + "_catalogue_same_authority_owner_producer_charge", [r for r in catalogue["records"] if r["job_id"] == job] == [expected_row])
        operation = root / "publication" / job
        if {p.name for p in operation.iterdir()} != {"instance.lock", *STEP_NAMES} or _read(operation / "instance.lock", 0) != b"":
            raise ValueError("publication source history has unknown/missing entries")
        # Go struct field names/order below are the actual private operation
        # context marshaling schema, not guessed public protocol field names.
        trust = {"Directory": str(operation), "Endpoint": self.upload_publisher["base_url"], "ServerName": "127.0.0.1",
                 "TrustSHA256": self.upload_publisher["publisher_ca"]["sha256"], "ProducerSHA256": self.producer_sha,
                 "AuthorityID": self.authority_id, "PublicKey": self.public_key_hex, "PipelineMode": self.mode,
                 "ProfileSHA256": self.profile, "AuthorityScope": self.authority_scope, "PublisherScope": self.scope}
        context_sha, previous = self._digest(compact(trust)), ""
        zero = {"schema_version": 0, "domain": "", "state": "", "publisher_scope": {"publisher_id": "", "policy_sha256": ""},
                "authority_scope": {"store_id": "", "policy_sha256": ""}, "job_id": "", "acceptance_sha256": "",
                "credential_sha256": "", "execution_profile_sha256": "", "pipeline_mode": ""}
        steps = []
        for sequence, name in enumerate(STEP_NAMES):
            step_raw = _read(operation / name, STEP_LIMIT)
            step = parse(step_raw)
            wanted = {"schema_version": 1, "domain": "biozero.authorization-publication.operation.v1", "sequence": sequence,
                      "context_sha256": context_sha, "previous_sha256": previous, "acceptance_json": raw.decode(),
                      "receipt": expected if sequence == 2 else zero}
            self._check(prefix + "_source_step_" + str(sequence), step == wanted)
            previous = self._digest(step_raw)
            steps.append({"name": name, "sha256": previous, "bytes": len(step_raw)})
        code, body, version = self.t["request"](self.port, self.context, "GET", "/v1/acceptances/" + job + "/" + expected["acceptance_sha256"])
        self._private(self.evidence / (prefix + ".get.body"), body)
        self._check(prefix + "_known_get_same_exact_receipt", code == 200 and version == "TLSv1.3" and len(body) <= 8 << 10 and parse(body) == expected)
        value = {"receipt": expected, "source_steps": steps, "receiver_intent_sha256": self._digest(compact(intent)),
                 "source_operation_context_sha256": context_sha, "retained_bytes": RUN_CHARGE}
        if job in self.observed and self.observed[job] != value:
            raise ValueError("publication observation changed previously known job")
        self.observed[job] = value
        self.t["private_json"](self.evidence / (prefix + ".observation.json"), value)
        return copy.deepcopy(value)

    def known_duplicate_and_role_controls(self, job, canonical_signed):
        """Explicit fixture intent, one duplicate POST, then real TLS role denial.

        The automatic original publication must already have been observed. This
        never repairs an absent row and never discovers a job from HTTP history.
        """
        if job not in self.observed or self._digest(canonical_signed) != self.observed[job]["receipt"]["acceptance_sha256"]:
            raise ValueError("duplicate control requires a known observed signed intent")
        prefix = "publication-controls-%03d" % self.sequence
        self.sequence += 1
        before = self._tree(self.state)
        route = "/v1/acceptances/" + job + "/" + self._digest(canonical_signed)
        self.t["private_json"](self.evidence / (prefix + "-intent.json"),
                               {"scope": "fixture duplicate only; original automatic source observed", "method": "POST",
                                "route": route, "body_sha256": self._digest(canonical_signed)})
        code, raw, version = self.t["request"](self.port, self.context, "POST", route, canonical_signed, {"Content-Type": "application/json"})
        self._private(self.evidence / (prefix + "-duplicate.body"), raw)
        self._check(prefix + "_duplicate_exact_receipt_no_new_charge", code == 200 and version == "TLSv1.3"
                    and self.t["exact_json"](raw) == self.observed[job]["receipt"] and before == self._tree(self.state))
        rogue_code, rogue_raw, rogue_tls = self.t["request"](self.port, self.client_context("rogue-producer"), "GET", "/healthz")
        self._private(self.evidence / (prefix + "-rogue.body"), rogue_raw)
        self._check(prefix + "_same_issuer_cn_serial_different_leaf_denied", rogue_code == 403 and rogue_tls == "TLSv1.3"
                    and self.t["exact_json"](rogue_raw) == {"error": "ownership_publication_denied"})
        for role in ("owner-a", "owner-b", None):
            denied = False
            try:
                self.t["request"](self.port, self.client_context(role), "GET", "/healthz")
            except (OSError, http.client.HTTPException):
                denied = True
            self._check(prefix + "_untrusted_issuer_tls_denied_" + (role or "anonymous"), denied)
        self._check(prefix + "_all_controls_preserve_primary_history", before == self._tree(self.state))

    def _tree(self, root):
        root = Path(root)
        fd = _directory(root)
        os.close(fd)
        paths = list(root.rglob("*"))
        if len(paths) > 2048:
            raise ValueError("publication retained history exceeds fixture bound")
        result = {}
        for path in sorted(paths):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                fd = _directory(path)
                os.close(fd)
            elif stat.S_ISREG(info.st_mode):
                raw = _read(path, 1 << 20)
                result[str(path.relative_to(root))] = {"sha256": self._digest(raw), "bytes": len(raw), "metadata": list(_identity(path.lstat()))}
            else:
                raise ValueError("publication retained history contains nonregular entry")
        if self.t["tree_hashes"](root) != {name: item["sha256"] for name, item in result.items()}:
            raise ValueError("publication retained tree changed across independent reads")
        return result

    def snapshot(self, uploadroot, label="retained"):
        """Exact source/receiver metadata and logical charges; no request count claim.

        Call after every admitted job, including execution-rejected copied B, has
        reached durable source delivery. Compare again after clean owned Wait.
        """
        root = Path(uploadroot)
        catalogue = self.catalogue()
        rows = {row["job_id"]: row for row in catalogue["records"]}
        self._check(label + "_all_catalogue_jobs_observed", set(rows) == set(self.observed))
        self._check(label + "_exact_receiver_namespaces", {p.name for p in (self.state / "operations").iterdir()} == set(rows)
                    and {p.name for p in (self.state / "inbox").iterdir()} == {job + ".json" for job in rows}
                    and {p.name for p in self.state.iterdir()} == {"instance.lock", "genesis.json", "catalogue.json", "operations", "inbox"})
        ledger_raw = _read(root / "ledger.json", 1 << 20)
        ledger = self.t["exact_json"](ledger_raw)
        by_job = {row["job_id"]: row for row in ledger["records"]}
        self._check(label + "_source_delivery_and_publication_complete", len(by_job) == len(ledger["records"])
                    and set(by_job) == set(rows) and all(row["state"] == "delivered" for row in by_job.values())
                    and {p.name for p in (root / "publication").iterdir()} == set(rows))
        for job, row in by_job.items():
            expected = self.observed[job]["receipt"]
            self._check(label + "_source_retained_binding_" + job,
                        row["acceptance_sha256"] == expected["acceptance_sha256"]
                        and row["credential_sha256"] == expected["credential_sha256"]
                        and self._digest(row["acceptance_json"].encode()) == expected["acceptance_sha256"]
                        and type(row["charge_bytes"]) is int and row["charge_bytes"] > 0)
        self._check(label + "_source_sidecar_exact_namespace", {p.name for p in (root / "acceptances").iterdir()} == {job + ".json" for job in rows})
        owners = {}
        for row in rows.values():
            owners[row["credential_sha256"]] = owners.get(row["credential_sha256"], 0) + 1
        result = {"publisher": self._tree(self.state), "source_publication": self._tree(root / "publication"),
                  "source_ledger_sha256": self._digest(ledger_raw), "source_sidecars": self._tree(root / "acceptances"),
                  "catalogue": catalogue, "retained_jobs": len(rows), "per_owner_retained_jobs": owners,
                  "retained_bytes": sum(row["retained_bytes"] for row in rows.values()), "run_charge": RUN_CHARGE,
                  "source_upload_logical_charge": sum(row["charge_bytes"] for row in by_job.values()),
                  "authority_charge_scope": "separate; compare in main harness, never equate with schema2 Upload",
                  "request_count_scope": "not measured by snapshot; no automatic retry claim"}
        self.t["private_json"](self.evidence / ("publisher-" + label + ".json"), result)
        return result

    def assert_unchanged(self, before, uploadroot, label):
        after = self.snapshot(uploadroot, label)
        self._check(label + "_history_and_charges_unchanged", before == after)
        return after

    def negative_results_config(self, primary_config, known_acceptances, label="negative-results"):
        """Dedicated Results authorization fixture ONLY, never publisher output.

        Returns config/env using the SAME endpoint and TLS identity. Caller must
        first cleanly stop/Wait primary Results, retain both config hashes and
        start a new owned negative Results instance. Existing Gateway URL/trust/
        sessions/registry stay intact, allowing its real 403-upstream->503 check.
        Never call this fixture autonomous positive authorization publication.
        """
        if re.fullmatch("[a-z0-9-]{1,40}", label) is None:
            raise ValueError("negative Results fixture name invalid")
        if primary_config["acceptances_directory"] != str(self.primary_inbox):
            raise ValueError("negative Results config must derive from original automatic-inbox config")
        match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", primary_config["address"])
        if match is None or not 1 <= int(match[1]) <= 65535:
            raise ValueError("negative Results fixture requires original literal loopback endpoint")
        inbox = self.runtime / (label + "-inbox")
        inbox.mkdir(mode=0o700, exist_ok=False)
        for job, raw in known_acceptances.items():
            if job not in self.observed or self._digest(raw) != self.observed[job]["receipt"]["acceptance_sha256"]:
                raise ValueError("negative Results fixture may copy only previously observed authorization")
            self._private(inbox / (job + ".json"), raw)
        port = int(match[1])
        config = copy.deepcopy(primary_config)
        config["acceptances_directory"] = str(inbox)
        path = self.runtime / "config" / (label + ".json")
        self.t["private_json"](path, config)
        self.t["private_json"](self.evidence / (label + "-scope.json"),
                               {"scope": "fixture-only signed inbox; no positive automatic provisioning; no primary publisher mutation",
                                "copied_known_jobs": sorted(known_acceptances), "primary_publisher_inbox": str(self.primary_inbox),
                                "requires_original_results_clean_wait_before_start": True,
                                "same_listen_and_tls_identity": True,
                                "original_config_sha256": self._digest(self.t["compact"](primary_config)),
                                "negative_config_sha256": self._digest(self.t["compact"](config))})
        return {"config": config, "config_path": path, "inbox": inbox, "port": port,
                "env": {"BIOZERO_RESULTS_PROTOCOL": "owner-v1", "BIOZERO_OWNER_RESULTS_CONFIG": str(path)}}

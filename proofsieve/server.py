"""Loopback HTTP API and bundled application assets."""

import io
import hmac
import json
import logging
import re
import secrets
import sqlite3
import threading
import time
from contextlib import ExitStack
from datetime import datetime, timezone
from http.client import LineTooLong
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl

from .evidence import rule_version
from .guard import (
    DEFAULT_ENDPOINT,
    DEFAULT_RULE,
    MAX_BODY_BYTES,
    Guard,
    ReadOnlyEndpointError,
    _OPERATION,
    load_json,
    validate_endpoint,
)
from .odrl import compile_policy
from .openapi import verification_document
from .paths import ROOT


MAX_TEST_BODY_BYTES = 2 * MAX_BODY_BYTES + 1024  # Space for the rule-test envelope.
MAX_CONNECTIONS = 16
MAX_HEADER_BYTES = 16 * 1024
MAX_REQUEST_TARGET_BYTES = 4 * 1024
REQUEST_TIMEOUT = 5
SECURITY_AUDIT = logging.getLogger("proofsieve.security")
_SIGNED_CREDENTIAL_DEMOS = {
    "eudi-pid-sd-jwt": "/verify/demo/eudi-sd-jwt",
    "eudi-pid-mdoc": "/verify/demo/eudi-mdoc",
}
_PATH = re.compile(r"/[A-Za-z0-9._/-]*")
_QUERY = re.compile(r"(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*")
_INVALID_HEADER_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_RULE_ETAG = re.compile(r'"[0-9a-f]{64}"')


class DeadlineReader(io.RawIOBase):
    """Use one read deadline across the request line, headers and body."""

    def __init__(self, connection, timeout):
        super().__init__()
        self.connection = connection
        self.deadline = time.monotonic() + timeout

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Zeitlimit für die HTTP-Anfrage überschritten.")
        self.connection.settimeout(remaining)
        return self.connection.recv_into(buffer)


class HeaderReader:
    """Limit aggregate header input before the standard library parses it."""

    def __init__(self, source):
        self.source = source
        self.remaining = MAX_HEADER_BYTES

    def readline(self, limit):
        line = self.source.readline(min(limit, self.remaining + 1))
        self.remaining -= len(line)
        if self.remaining < 0:
            raise LineTooLong("header block")
        return line


class LoopbackHTTPServer(ThreadingHTTPServer):
    request_queue_size = 32

    def __init__(self, address, handler, bind_and_activate=True, *, max_connections=MAX_CONNECTIONS):
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler, bind_and_activate=bind_and_activate)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def admin_endpoint(query):
    if not query:
        return DEFAULT_ENDPOINT
    pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=1, errors="strict")
    if len(pairs) != 1 or pairs[0][0] != "endpoint":
        raise ValueError("Der einzige erlaubte Query-Parameter ist endpoint.")
    return validate_endpoint(pairs[0][1])


def load_credential_examples(directory):
    examples = []
    checks = {}
    for path in sorted(directory.glob("*.json")):
        example = load_json(path.read_bytes())
        example_id = example["id"]
        if example_id != path.stem or not re.fullmatch(r"[a-z0-9-]+", example_id):
            raise ValueError(f"Ungültige Credential-Beispiel-ID in {path.name}.")
        field = example["check"]["field"]
        policy = {
            **DEFAULT_RULE["policy"],
            "uid": f"urn:proofsieve:example:{example_id}",
            "permission": [{
                "target": f"urn:proofsieve:demo:{example_id}",
                "action": "use",
                "constraint": [{
                    "leftOperand": f"field:{field}",
                    "operator": "eq",
                    "rightOperand": example["check"]["expected"],
                }],
            }],
        }
        check = compile_policy(policy)
        if not check(example["input"]) or check({**example["input"], field: example["check"]["negative"]}):
            raise ValueError(f"Sollwert oder Gegenprobe passt nicht zu {path.name}.")
        examples.append(example)
        checks[f"/examples/credentials/{example_id}/check"] = check
    return examples, checks


class Handler(BaseHTTPRequestHandler):
    server_version = "ProofSieve"
    timeout = REQUEST_TIMEOUT
    redirects = {
        "/": "/apps/",
        "/apps": "/apps/",
        "/apps/guard": "/apps/guard/",
        "/apps/builder": "/apps/builder/",
        "/apps/lab": "/apps/lab/",
        "/apps/api-docs": "/apps/api-docs/",
        "/ui": "/apps/guard/",
        "/ui/": "/apps/guard/",
        "/ui/index.html": "/apps/guard/",
        "/ui/examples.html": "/apps/lab/",
    }
    content_types = {
        ".html": "text/html; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".txt": "text/plain; charset=utf-8",
        ".json": "application/json",
    }
    static = {
        "/apps/": "apps/index.html",
        "/apps/guard/": "apps/guard/index.html",
        "/apps/builder/": "apps/builder/index.html",
        "/apps/lab/": "apps/lab/index.html",
        "/apps/api-docs/": "apps/api-docs/index.html",
        **{
            f"/{file}": file
            for file in (
                "apps/workspace.css",
                "apps/api-docs/api-docs.js",
                "apps/api-docs/swagger-language.js",
                "apps/api-docs/api-docs.css",
                "apps/api-docs/vendor/swagger-ui-bundle.js",
                "apps/api-docs/vendor/swagger-ui-bundle.js.LICENSE.txt",
                "apps/api-docs/vendor/swagger-ui.css",
                "apps/shared/form.css",
                "apps/shared/i18n.js",
                "apps/shared/language.css",
                "apps/guard/guard.js",
                "apps/guard/guard.css",
                "apps/guard/access.css",
                "apps/guard/access.js",
                "apps/guard/odrl-graph.js",
                "apps/guard/odrl-graph.css",
                "apps/guard/rule-tester.js",
                "apps/guard/rule-tester.css",
                "apps/builder/builder.js",
                "apps/builder/builder.css",
                "apps/lab/app.js",
                "apps/lab/model.js",
                "apps/lab/presentation.js",
                "apps/lab/styles.css",
            )
        },
        **{
            f"/examples/{path.name}": f"examples/{path.name}"
            for path in (ROOT / "examples").glob("*.json")
        },
    }

    def log_message(self, format, *args):
        # Requests may contain evidence. Suppress the default request-line log.
        pass

    def audit_security_event(self, event, status, *, endpoint=None, revision=None):
        if self.access_policy is None:
            return
        path = self.request_path
        resource = {
            "/auth/me": "identity",
            "/openapi.json": "api_description",
            "/admin/rule": "rule",
            "/admin/test-rule": "rule_preview",
            "/evidence": "evidence",
        }.get(path, "verification" if path == "/verify" or path.startswith("/verify/") else "other")
        entry = {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "method": self.command,
            "resource": resource,
            "status": status,
        }
        principal = getattr(self, "principal", None)
        if principal is not None:
            entry.update(actor=principal.id, role=principal.role)
        if endpoint is not None:
            entry["endpoint"] = endpoint
        if revision is not None:
            entry["ruleVersion"] = revision
        SECURITY_AUDIT.info("%s", json.dumps(entry, separators=(",", ":")))

    def setup(self):
        super().setup()
        self.rfile.close()
        self.rfile = io.BufferedReader(DeadlineReader(self.connection, self.timeout))

    def parse_request(self):
        # BaseHTTPRequestHandler normalizes initial double slashes in self.path.
        # Validate the raw request target and use that exact target for dispatch.
        source = self.rfile
        try:
            self.rfile = HeaderReader(source)
            if not super().parse_request():
                return False
        finally:
            self.rfile = source
        self.close_connection = True
        parts = self.requestline.split(" ")
        if self.request_version not in ("HTTP/1.0", "HTTP/1.1"):
            self.request_version = "HTTP/1.0"  # HTTP/0.9 otherwise suppresses response headers.
            self.reply_json(400, {"error": "Nur HTTP/1.0 und HTTP/1.1 werden unterstützt."})
            return False
        target = parts[1] if len(parts) == 3 else ""
        if len(target) > MAX_REQUEST_TARGET_BYTES:
            self.reply_json(414, {"error": "HTTP-Anfrageziel ist zu lang."})
            return False
        path, _, query = target.partition("?")
        if (parts != [self.command, target, self.request_version]
                or self.raw_requestline != self.requestline.encode("iso-8859-1") + b"\r\n"
                or not _PATH.fullmatch(path)
                or "//" in path or any(part in (".", "..") for part in path.split("/"))
                or not _QUERY.fullmatch(query)):
            self.reply_json(400, {"error": "Ungültiges HTTP-Anfrageziel."})
            return False
        self.request_path = path
        self.request_query = query
        if self.headers.defects or any(_INVALID_HEADER_VALUE.search(value) for _, value in self.headers.raw_items()):
            self.reply_json(400, {"error": "Ungültige HTTP-Header."})
            return False
        lengths = self.headers.get_all("Content-Length", [])
        if (self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Expect")
                or len(lengths) > 1 or (lengths and not re.fullmatch(r"[0-9]{1,20}", lengths[0]))):
            self.reply_json(400, {"error": "Ungültige HTTP-Nachrichtenlänge oder Übertragungskodierung."})
            return False
        self.content_length = int(lengths[0]) if lengths else None
        if self.command == "GET" and self.content_length not in (None, 0):
            self.reply_json(400, {"error": "GET akzeptiert keinen Anfrageinhalt."})
            return False
        if self.command not in ("GET", "POST", "PUT"):
            self.reply_json(405, {"error": "Erlaubte Methoden sind GET, POST und PUT."})
            return False
        return True

    def reply(self, status, body, content_type="application/json", *, location=None, etag=None, retry_after=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        policy = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        if getattr(self, "request_path", None) == "/apps/api-docs/":
            policy += "; img-src 'self' data:; connect-src 'self'"
        self.send_header("Content-Security-Policy", policy)
        self.send_header("Referrer-Policy", "no-referrer")
        if content_type.startswith("text/html;"):
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        if location is not None:
            self.send_header("Location", location)
        if etag is not None:
            self.send_header("ETag", etag)
        if retry_after is not None:
            self.send_header("Retry-After", str(retry_after))
        if status == 405:
            self.send_header("Allow", "GET, POST, PUT")
        if status == 401:
            self.send_header("WWW-Authenticate", 'Bearer realm="ProofSieve"')
        try:
            self.connection.settimeout(self.timeout)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Live tests cancel the previous request as soon as the input changes.
            pass

    def reply_json(self, status, value, *, etag=None, retry_after=None):
        self.reply(status, json.dumps(value, ensure_ascii=True).encode("utf-8"), etag=etag, retry_after=retry_after)

    def accept_local_request(self, require_same_origin=True):
        port = self.server.server_port
        origins = {f"{host}:{port}": f"http://{host}:{port}" for host in ("127.0.0.1", "localhost")}
        proxy_origin = getattr(self.server, "proxy_origin", None)
        if proxy_origin is not None:
            origins = {proxy_origin.removeprefix("https://"): proxy_origin}
        host = self.headers.get_all("Host", [])
        origin = self.headers.get_all("Origin", [])
        fetch_site = self.headers.get_all("Sec-Fetch-Site", [])
        valid_host = len(host) == 1 and host[0] in origins
        if valid_host and origins[host[0]] == proxy_origin:
            path = self.request_path
            valid_host = not self.request_query and (
                (self.command == "GET" and path == "/openapi.json")
                or (self.command == "POST" and self.public_verification_path(path))
            )
        valid_context = len(origin) <= 1 and len(fetch_site) <= 1
        if valid_host and valid_context and require_same_origin:
            valid_context = (not origin or origin == [origins[host[0]]]) and (
                not fetch_site or fetch_site[0] in ("none", "same-origin")
            )
        if not valid_host or not valid_context:
            self.audit_security_event("request_origin_rejected", 403)
            self.reply_json(403, {"error": "Nur lokale Anfragen vom selben Ursprung sind erlaubt."})
            return False
        return True

    def public_verification_path(self, path):
        return (path == "/verify" or path.startswith("/verify/")) and (
            path not in self.server.guard.demos and path not in self.server.credential_checks
        )

    def read_json(self, max_bytes=MAX_BODY_BYTES, *, with_raw=False):
        if len(self.headers.get_all("Content-Type", [])) != 1 or self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type muss application/json sein.")
        size = self.content_length
        if size is None:
            raise ValueError("Ein eindeutiger Content-Length ist erforderlich.")
        if not 0 < size <= max_bytes:
            raise ValueError(f"Der JSON-Body ist leer oder größer als {max_bytes // 1024} KiB.")
        data = self.rfile.read(size)
        if len(data) != size:
            raise ValueError("Der JSON-Body ist unvollständig.")
        parsed = load_json(data)
        return (parsed, data) if with_raw else parsed

    def read_verification_request(self, *, allow_operation):
        request, raw = self.read_json(with_raw=True)
        if isinstance(request, dict) and request.keys() == {"data"}:
            return request["data"], None, raw
        if (allow_operation and isinstance(request, dict) and request.keys() == {"data", "operationId"}
                and isinstance(request["operationId"], str)):
            return request["data"], request["operationId"], raw
        if not allow_operation:
            raise ValueError("Der Request muss genau das Feld data enthalten.")
        raise ValueError("Der Request braucht data und optional eine operationId als Text.")

    def if_match_version(self):
        revisions = self.headers.get_all("If-Match", [])
        if not revisions:
            return None
        if len(revisions) != 1 or not _RULE_ETAG.fullmatch(revisions[0].strip()):
            raise ValueError("If-Match braucht genau einen ETag der Regel.")
        return revisions[0].strip()[1:-1]

    @property
    def access_policy(self):
        return getattr(self.server, "access_policy", None)

    def require_access(self, *, admin=False, global_admin=False, endpoint=None):
        if self.access_policy is None:
            return True
        principal = self.access_policy.authenticate(self.headers)
        if principal is None:
            if self.headers.get_all("Authorization") or self.request_path not in ("/auth/me", "/openapi.json"):
                self.audit_security_event("authentication_rejected", 401)
            self.reply_json(401, {"error": "Authentifizierung erforderlich.", "code": "unauthenticated"})
            return False
        self.principal = principal
        if ((admin or global_admin) and principal.role != "admin"
                or global_admin and principal.endpoints != ("*",)):
            return self.forbid_access()
        return endpoint is None or self.require_endpoint(endpoint)

    def forbid_access(self):
        self.audit_security_event("authorization_rejected", 403)
        self.reply_json(403, {"error": "Zugriff verweigert.", "code": "forbidden"})
        return False

    def require_endpoint(self, endpoint):
        if self.access_policy is None or self.principal.allows(endpoint):
            return True
        return self.forbid_access()

    def visible_endpoints(self, endpoints):
        if self.access_policy is None:
            return endpoints
        return [endpoint for endpoint in endpoints if self.principal.allows(endpoint)]

    def admin_details(self, details):
        guard = self.server.guard
        return {
            **details,
            "endpoints": self.visible_endpoints(details["endpoints"]),
            "capabilities": {
                "decision": guard.evidence is not None,
                "verification": guard.registry is not None and self.principal.endpoints == ("*",),
            },
        }

    def editor_token(self):
        secret = self.server.guard.token
        if self.access_policy is None:
            return secret
        return hmac.digest(secret.encode(), self.principal.id.encode(), "sha256").hex()

    def show_access(self):
        if not self.require_access():
            return
        if self.access_policy is None:
            self.reply_json(200, {"enabled": False})
            return
        principal = self.principal
        details = {"enabled": True, "id": principal.id, "role": principal.role,
                   "endpoints": self.visible_endpoints(self.server.guard.endpoints()),
                   "allEndpoints": principal.endpoints == ("*",)}
        if principal.role == "admin":
            details.update(grants=list(principal.endpoints), csrfToken=self.editor_token())
        self.audit_security_event("identity_confirmed", 200)
        self.reply_json(200, details)

    def accept_editor_token(self):
        supplied = self.headers.get_all("X-ProofSieve-Token", [])
        if len(supplied) != 1 or not secrets.compare_digest(supplied[0].encode(), self.editor_token().encode()):
            self.audit_security_event("editor_token_rejected", 403)
            self.reply_json(403, {"error": "Der Editor-Token fehlt oder ist ungültig."})
            return False
        return True

    def post_rule_test(self):
        if not self.require_access(admin=True):
            return
        try:
            endpoint = None
            if self.access_policy is not None:
                if not self.request_query:
                    raise ValueError("Die Regelvorschau braucht einen Prüfendpunkt.")
                endpoint = admin_endpoint(self.request_query)
                if not self.require_endpoint(endpoint):
                    return
            if not self.accept_editor_token():
                return
            payload = self.read_json(MAX_TEST_BODY_BYTES)
            if not isinstance(payload, dict) or payload.keys() != {"rule", "data"}:
                raise ValueError("Der Test braucht genau die Felder rule und data.")
            result = self.server.guard.preview(payload["rule"], payload["data"], endpoint)
        except (ValueError, TimeoutError) as exc:
            self.reply_json(400, {"error": str(exc)})
        except ImportError:
            self.reply_json(503, {"error": "Der konfigurierte Prüfadapter ist nicht installiert."})
        else:
            self.reply_json(200, result)

    def do_GET(self):
        path, query = self.request_path, self.request_query
        if not self.accept_local_request(require_same_origin=path in {"/admin/rule", "/auth/me", "/openapi.json", "/evidence"}):
            return
        if path == "/apps/api-docs/" and query:
            self.reply_json(400, {"error": "Die API-Konsole akzeptiert keine URL-Parameter."})
            return
        if path in self.redirects:
            self.reply(303, b"", location=self.redirects[path])
        elif path == "/auth/me":
            self.show_access()
        elif path == "/admin/rule":
            if not self.require_access(admin=True):
                return
            guard = self.server.guard
            try:
                endpoint = admin_endpoint(query)
            except ValueError as exc:
                self.reply_json(400, {"error": str(exc)})
                return
            if not self.require_endpoint(endpoint):
                return
            details = guard.describe(endpoint)
            if details is None:
                self.reply_json(404, {"error": "Unbekannter Prüfendpunkt."})
            else:
                self.reply_json(200, {**self.admin_details(details), "csrfToken": self.editor_token()},
                                etag=f'"{rule_version(details["rule"])}"')
        elif path == "/examples/credentials.json":
            examples = []
            for sample in self.server.credential_examples:
                endpoint = _SIGNED_CREDENTIAL_DEMOS.get(sample["id"])
                demo = self.server.guard.demos.get(endpoint, {})
                if demo.get("credentialExamples"):
                    sample = {**sample, "signedDemoEndpoint": endpoint}
                examples.append(sample)
            self.reply_json(200, examples)
        elif path == "/evidence" and getattr(self.server, "evidence_export", False):
            self.get_evidence_export(query)
        elif path == "/openapi.json":
            if not self.require_access():
                return
            try:
                spec = load_json((ROOT / "openapi.json").read_bytes())
                guard = self.server.guard
                with guard.lock:
                    profiles = guard.verification_profiles()
                    bundles = {name: guard.bundle_inputs(name) for name, profile in profiles.items()
                               if profile[0] == "bundle"}
                visible = self.visible_endpoints(profiles)
                on_proxy = getattr(self.server, "proxy_origin", None) == f"https://{self.headers['Host']}"
                if on_proxy:
                    visible = [endpoint for endpoint in visible if self.public_verification_path(endpoint)]
                spec = verification_document(spec, {endpoint: profiles[endpoint] for endpoint in visible},
                                             protected=self.access_policy is not None, demos=guard.demos,
                                             forwarding=guard.forwarding, bundles=bundles,
                                             evidence_export=getattr(self.server, "evidence_export", False) and not on_proxy)
            except (OSError, ValueError, KeyError, TypeError):
                self.reply_json(500, {"error": "Die OpenAPI-Beschreibung konnte nicht geladen werden."})
            else:
                self.audit_security_event("identity_confirmed", 200)
                self.reply_json(200, spec)
        elif path in self.static:
            file = ROOT / self.static[path]
            try:
                data = file.read_bytes()
            except FileNotFoundError:
                self.reply_json(404, {"error": "Datei nicht gefunden."})
            else:
                self.reply(200, data, self.content_types[file.suffix])
        else:
            self.reply_json(404, {"error": "Unbekannter Pfad."})

    def get_evidence_export(self, query):
        from .evidence import EvidenceExportError

        if not self.require_access():
            return
        try:
            pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=3, errors="strict")
            fields = dict(pairs)
            if (len(fields) != len(pairs) or fields.keys() not in (
                    {"endpoint", "operationId"}, {"endpoint", "operationId", "decisionId"})
                    or not _OPERATION.fullmatch(fields["operationId"])):
                raise ValueError("Der Export erfordert endpoint, operationId und optional decisionId.")
            endpoint = validate_endpoint(fields["endpoint"])
            decision_id = fields.get("decisionId")
            if decision_id is not None and not re.fullmatch(
                    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", decision_id):
                raise ValueError("Ungültige decisionId.")
        except ValueError as exc:
            self.reply_json(400, {"error": str(exc)})
            return
        if not self.require_endpoint(endpoint):
            return
        try:
            bundle = self.server.guard.evidence.export(
                endpoint=endpoint, caller=self.principal.id, operation_id=fields["operationId"], decision_id=decision_id,
            )
        except (OSError, sqlite3.Error, EvidenceExportError):
            self.audit_security_event("evidence_export_unavailable", 503, endpoint=endpoint)
            self.reply_json(503, {"error": "Der Prüfnachweis ist nicht verfügbar.", "code": "evidence_unavailable"})
            return
        if bundle is None:
            self.reply_json(404, {"error": "Kein passender Prüfnachweis.", "code": "evidence_not_found"})
        else:
            self.audit_security_event("evidence_exported", 200, endpoint=endpoint)
            self.reply_json(200, bundle)

    def do_PUT(self):
        if not self.accept_local_request():
            return
        path, query = self.request_path, self.request_query
        if path != "/admin/rule":
            self.reply_json(404, {"error": "Unbekannter Pfad."})
            return
        if not self.require_access(admin=True):
            return
        guard = self.server.guard
        try:
            endpoint = admin_endpoint(query)
            if not self.require_endpoint(endpoint) or not self.accept_editor_token():
                return
            preconditions = self.headers.get_all("If-None-Match", [])
            if preconditions and (len(preconditions) != 1 or preconditions[0].strip() != "*"):
                raise ValueError("Als If-None-Match ist nur * erlaubt.")
            revision = self.if_match_version()
            if revision is not None and preconditions:
                raise ValueError("If-Match und If-None-Match dürfen nicht gemeinsam vorkommen.")
            rule = self.read_json()
            details = guard.update(
                rule, endpoint, create_only=bool(preconditions),
                if_match=revision,
                manage_trust=self.access_policy is None or self.principal.endpoints == ("*",),
            )
        except (ValueError, TimeoutError) as exc:
            self.reply_json(400, {"error": str(exc)})
        except ReadOnlyEndpointError as exc:
            self.reply_json(403, {"error": str(exc)})
        except PermissionError:
            self.forbid_access()
        except ImportError:
            self.reply_json(503, {"error": "Der konfigurierte Prüfadapter ist nicht installiert."})
        except OSError:
            self.audit_security_event("rule_change_failed", 500, endpoint=endpoint)
            self.reply_json(500, {"error": "Die Regel konnte nicht gespeichert werden."})
        else:
            if details is None:
                self.audit_security_event("rule_change_conflict", 412, endpoint=endpoint)
                if revision is not None:
                    self.reply_json(412, {"error": "Die gespeicherte Regel wurde geändert.",
                                          "code": "rule_version_conflict"})
                else:
                    self.reply_json(412, {"error": "Der Prüfendpunkt existiert bereits."})
            else:
                revision = rule_version(details["rule"])
                self.audit_security_event("rule_changed", 200, endpoint=endpoint, revision=revision)
                self.reply_json(200, self.admin_details(details), etag=f'"{revision}"')

    def do_POST(self):
        if not self.accept_local_request():
            return
        endpoint = self.request_path
        if endpoint == "/admin/test-rule":
            self.post_rule_test()
            return
        guard = self.server.guard
        sample_check = self.server.credential_checks.get(endpoint)
        if sample_check is not None:
            if not self.require_access(global_admin=True):
                return
        elif endpoint == "/verify" or endpoint.startswith("/verify/"):
            if not self.require_access(endpoint=endpoint):
                return
        if sample_check is None and not guard.has_endpoint(endpoint):
            self.reply_json(404, {"error": "Unbekannter Prüfendpunkt."})
            return
        try:
            data, operation_id, raw = self.read_verification_request(allow_operation=sample_check is None)
            if endpoint in guard.wallet_endpoints:
                status, result = self.server.wallet.handle(guard, endpoint, self.principal.id, operation_id, data)
                if status == 429:
                    self.audit_security_event("wallet_rate_limited", 429, endpoint=endpoint)
                    self.reply_json(status, result, retry_after=result["retryAfterSeconds"])
                    return
            elif sample_check is None:
                caller = self.principal.id if self.access_policy is not None else None
                status, result = guard.verify(data, endpoint, operation_id=operation_id, caller=caller,
                                              request_body=raw, if_match=self.if_match_version())
            else:
                if not isinstance(data, dict):
                    raise ValueError("ODRL erwartet ein JSON-Objekt als data.")
                status, result = 200, sample_check(data)
        except (ValueError, TimeoutError) as exc:
            self.reply_json(400, {"error": str(exc)})
        else:
            if status >= 500:
                self.audit_security_event("verification_indeterminate", status, endpoint=endpoint)
            self.reply_json(status, result)


def serve(port, state, *, socket_path=None, access_policy=None, registry=None, evidence=None, forwarding=None, wallet=None,
          evidence_export=False,
          proxy_origin=None, proxy_socket=None, proxy_gid=None):
    if socket_path is not None and access_policy is None:
        raise ValueError("Ein Unix-Socket erfordert --auth-config.")
    if (registry is not None or evidence is not None or forwarding or wallet is not None) and access_policy is None:
        raise ValueError("Prüfadapter und Nachweisspeicher erfordern --auth-config.")
    if evidence_export and (evidence is None or access_policy is None):
        raise ValueError("Nachweisexport braucht Zugriffsschutz und einen Nachweisspeicher.")
    if (proxy_origin is not None or proxy_socket is not None) and (
        not proxy_origin or proxy_socket is None or socket_path is None
        or proxy_socket.resolve() == socket_path.resolve()
    ):
        raise ValueError("Der HTTPS-Proxy braucht --proxy-origin und zwei getrennte Unix-Sockets.")
    if proxy_gid is not None and (proxy_origin is None or proxy_gid < 0):
        raise ValueError("--proxy-gid erfordert --proxy-origin und eine gültige Gruppen-ID.")
    demos = load_json((ROOT / "examples" / "signed" / "guard.json").read_bytes())
    guard = Guard(state, demos, evidence=evidence, registry=registry, forwarding=forwarding,
                  wallet_endpoints=wallet.endpoints if wallet is not None else ())
    examples, checks = load_credential_examples(ROOT / "examples" / "credentials")
    if socket_path is None:
        listener = LoopbackHTTPServer(("127.0.0.1", port), Handler)
    else:
        from .unix_socket import open_private_socket

        listener = open_private_socket(LoopbackHTTPServer, socket_path, port, Handler)
    with ExitStack() as listeners:
        server = listeners.enter_context(listener)
        configured = [(server, None)]
        proxy = None
        if proxy_socket is not None:
            proxy = listeners.enter_context(
                open_private_socket(LoopbackHTTPServer, proxy_socket, port, Handler, proxy_gid=proxy_gid)
            )
            configured.append((proxy, proxy_origin))
        for target, origin in configured:
            target.guard = guard
            target.wallet = wallet
            target.evidence_export = evidence_export and origin is None
            target.access_policy = access_policy
            target.proxy_origin = origin
            target.credential_examples = examples
            target.credential_checks = checks
        if proxy is not None:
            worker = threading.Thread(target=proxy.serve_forever, daemon=True)
            worker.start()
        print(f"ProofSieve läuft auf http://127.0.0.1:{server.server_port}/apps/", flush=True)
        try:
            server.serve_forever()
        finally:
            if proxy is not None:
                proxy.shutdown()
                worker.join()

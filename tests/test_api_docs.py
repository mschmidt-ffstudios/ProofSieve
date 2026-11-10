"""Exercise API documentation and its authorization boundary over HTTP."""

import hashlib
import http.client
import json
import secrets
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from proofsieve.access import AccessPolicy
from proofsieve.evidence import EvidenceStore
from proofsieve.guard import DEFAULT_RULE, Guard
from proofsieve.paths import ROOT
from proofsieve.server import Handler, LoopbackHTTPServer


DOCS = "/apps/api-docs/"
SPEC = "/openapi.json"
PROXY_HOST = "proofsieve.example.test"
ORDER = "/verify/order"
PRIVATE = "/verify/order/private"
SIGNED = "/verify/demo/eudi-sd-jwt"
MDOC = "/verify/demo/eudi-mdoc"
SAMPLE_CHECK = "/examples/credentials/eudi-pid-sd-jwt/check"
FACTS = {"data": {"status": "active"}}


class ApiDocsTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="proofsieve-api-docs-")
        self.addCleanup(directory.cleanup)
        work = Path(directory.name)
        config = work / "access.json"
        grants = {
            "operator": ("admin", ["*"]),
            "scoped-admin": ("admin", [ORDER]),
            "orders": ("verifier", [ORDER]),
            "legacy": ("verifier", ["/verify"]),
            "signed": ("verifier", [SIGNED]),
            "mdoc": ("verifier", [MDOC]),
        }
        self.tokens = {user: secrets.token_urlsafe(32) for user in grants}
        config.write_text(json.dumps({
            "version": 1,
            "principals": [
                {"id": user, "role": role, "endpoints": endpoints,
                 "tokenSha256": hashlib.sha256(self.tokens[user].encode("ascii")).hexdigest()}
                for user, (role, endpoints) in grants.items()
            ],
        }), encoding="utf-8")
        config.chmod(0o600)
        access = AccessPolicy.load(config)
        demos = json.loads((ROOT / "examples/signed/guard.json").read_text(encoding="utf-8"))
        guard = Guard(work / "rules.json", demos, evidence=EvidenceStore(work / "audit.db"))
        guard.update({**DEFAULT_RULE, "responseMode": "decision"}, ORDER)
        guard.update(DEFAULT_RULE, PRIVATE)
        self.operator = self.start_listener(guard, access)
        self.proxy = self.start_listener(guard, access, origin=f"https://{PROXY_HOST}")

    def start_listener(self, guard, access, *, origin=None):
        server = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
        server.guard = guard
        server.access_policy = access
        server.credential_checks = {SAMPLE_CHECK: lambda data: True}
        server.proxy_origin = origin
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def request(self, path, *, method="GET", user=None, proxy=False, headers=None, payload=None):
        request_headers = {"Host": PROXY_HOST} if proxy else {}
        if user:
            request_headers["Authorization"] = f"Bearer {self.tokens[user]}"
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
            payload = json.dumps(payload).encode("utf-8")
        request_headers.update(headers or {})
        server = self.proxy if proxy else self.operator
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        try:
            connection.request(method, path, body=payload, headers=request_headers)
            with connection.getresponse() as response:
                return response.status, response.headers, response.read()
        finally:
            connection.close()

    def get_spec(self, **options):
        status, headers, raw = self.request(SPEC, **options)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get_content_type(), "application/json")
        self.assertEqual(headers["Cache-Control"], "no-store")
        return json.loads(raw)

    def test_docs_and_vendored_assets_are_operator_only(self):
        assets = {
            DOCS: "text/html",
            f"{DOCS}api-docs.js": "text/javascript",
            f"{DOCS}swagger-language.js": "text/javascript",
            f"{DOCS}api-docs.css": "text/css",
            f"{DOCS}vendor/swagger-ui-bundle.js": "text/javascript",
            f"{DOCS}vendor/swagger-ui.css": "text/css",
        }
        for path, media_type in assets.items():
            with self.subTest(path=path):
                status, headers, raw = self.request(path)
                self.assertEqual(status, 200)
                self.assertEqual(headers.get_content_type(), media_type)
                self.assertTrue(raw)
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(self.request(path, user="operator", proxy=True)[0], 403)
        self.assertEqual(self.request(f"{DOCS}vendor/missing.js")[0], 404)

    def test_protected_spec_contains_only_granted_routes(self):
        for proxy in (False, True):
            with self.subTest(proxy=proxy):
                status, headers, _ = self.request(SPEC, proxy=proxy)
                self.assertEqual(status, 401)
                self.assertIn("Bearer", headers["WWW-Authenticate"])
                self.assertEqual(self.request(f"{SPEC}?token={self.tokens['orders']}", proxy=proxy)[0],
                                 403 if proxy else 401)
                self.assertEqual(self.request(SPEC, user="orders", proxy=proxy,
                                              headers={"Origin": "https://foreign.example"})[0], 403)
                for role in ("orders", "scoped-admin"):
                    spec = self.get_spec(user=role, proxy=proxy)
                    self.assertEqual(set(spec["paths"]), {ORDER})
                    self.assertEqual(spec["security"], [{"bearerAuth": []}])
                    self.assertNotIn(self.tokens[role], json.dumps(spec))
                self.assertEqual(set(self.get_spec(user="legacy", proxy=proxy)["paths"]), {"/verify"})
        operator_paths = self.get_spec(user="operator")["paths"]
        self.assertEqual(set(operator_paths), {"/verify", ORDER, PRIVATE, SIGNED, MDOC})
        proxy_paths = self.get_spec(user="operator", proxy=True)["paths"]
        self.assertEqual(set(proxy_paths), {"/verify", ORDER, PRIVATE})
        self.assertEqual(self.get_spec(user="signed", proxy=True)["paths"], {})

    def test_signed_demo_examples_are_runnable_on_the_live_clock(self):
        for endpoint, user, expiry in ((SIGNED, "signed", "2029-09-01T23:33:20Z"),
                                       (MDOC, "mdoc", "2031-01-01T00:00:00Z")):
            with self.subTest(endpoint=endpoint):
                paths = self.get_spec(user=user)["paths"]
                self.assertEqual(set(paths), {endpoint})
                examples = paths[endpoint]["post"]["requestBody"]["content"]["application/json"]["examples"]
                self.assertIn(expiry, examples["original"]["description"])
                status, _, body = self.request(endpoint, method="POST", user=user, payload=examples["original"]["value"])
                self.assertEqual((status, json.loads(body)), (200, True))
                status, _, body = self.request(endpoint, method="POST", user=user, payload=examples["tampered"]["value"])
                self.assertEqual((status, json.loads(body)["code"]), (403, "credential_rejected"))

    def test_request_schema_matches_endpoint_mode(self):
        paths = self.get_spec(user="operator")["paths"]
        for path in ("/verify", ORDER, PRIVATE, SIGNED):
            with self.subTest(path=path):
                operation = paths[path]["post"]
                schema = operation["requestBody"]["content"]["application/json"]["schema"]
                decision = path == ORDER
                self.assertEqual(set(schema["required"]), {"data", "operationId"} if decision else {"data"})
                self.assertEqual("operationId" in schema["properties"], decision)
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(schema["properties"]["data"]["type"], "string" if path == SIGNED else "object")
                self.assertEqual("503" in operation["responses"], decision)
        order = {**FACTS, "operationId": "PO-1042"}
        status, _, raw = self.request(ORDER, method="POST", user="orders", payload=order)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["operationId"], "PO-1042")
        self.assertEqual(self.request(ORDER, method="POST", user="orders", payload=FACTS)[0], 400)
        self.assertEqual(self.request("/verify", method="POST", user="legacy", payload=order)[0], 400)
        self.assertEqual(self.request(SAMPLE_CHECK, method="POST", user="operator", payload=order)[0], 400)

    def test_unprotected_operator_spec_does_not_require_a_bearer(self):
        self.operator.access_policy = None
        spec = self.get_spec()
        self.assertNotIn("security", spec)
        self.assertIn("/verify", spec["paths"])
        self.assertNotIn("401", spec["paths"]["/verify"]["post"]["responses"])

    def test_security_audit_preserves_actors_and_outcomes_without_credentials(self):
        self.operator.evidence_export = True
        operation = "private-order-reference"
        raw_claim = "synthetic-sensitive-claim"
        with self.assertLogs("proofsieve.security", level="INFO") as captured:
            self.assertEqual(self.request("/auth/me")[0], 401)  # Normal discovery challenge.
            self.assertEqual(self.request("/auth/me?query-secret", headers={
                "Authorization": "Bearer invalid-token-secret",
            })[0], 401)
            self.assertEqual(self.request(ORDER, method="POST", user="orders", payload=FACTS,
                                          headers={"Origin": "https://foreign-origin-secret.example"})[0], 403)
            self.assertEqual(self.request("/admin/rule", user="orders")[0], 403)
            status, _, raw = self.request("/auth/me", user="operator")
            self.assertEqual(status, 200)
            csrf = json.loads(raw)["csrfToken"]
            admin_rule = f"/admin/rule?endpoint={PRIVATE}"
            self.assertEqual(self.request(admin_rule, method="PUT", user="operator", payload=DEFAULT_RULE,
                                          headers={"X-ProofSieve-Token": "invalid-editor-secret"})[0], 403)
            status, saved_headers, _ = self.request(admin_rule, method="PUT", user="operator", payload=DEFAULT_RULE,
                                                    headers={"X-ProofSieve-Token": csrf})
            self.assertEqual(status, 200)
            self.assertEqual(self.request(admin_rule, method="PUT", user="operator", payload=DEFAULT_RULE,
                                          headers={"X-ProofSieve-Token": csrf, "If-Match": '"' + "0" * 64 + '"'})[0], 412)
            status, _, raw = self.request(ORDER, method="POST", user="orders", payload={
                "data": {"status": "active", "claim": raw_claim}, "operationId": operation,
            })
            self.assertEqual(status, 200)
            decision = json.loads(raw)["decisionId"]
            export = f"/evidence?endpoint={ORDER}&operationId={operation}&decisionId={decision}"
            self.assertEqual(self.request(export, user="orders")[0], 200)

        entries = [json.loads(record.getMessage()) for record in captured.records]
        self.assertEqual([(event["event"], event["status"], event.get("actor")) for event in entries], [
            ("authentication_rejected", 401, None),
            ("request_origin_rejected", 403, None),
            ("authorization_rejected", 403, "orders"),
            ("identity_confirmed", 200, "operator"),
            ("editor_token_rejected", 403, "operator"),
            ("rule_changed", 200, "operator"),
            ("rule_change_conflict", 412, "operator"),
            ("evidence_exported", 200, "orders"),
        ])
        self.assertEqual(entries[5]["ruleVersion"], saved_headers["ETag"].strip('"'))
        self.assertEqual(entries[5]["endpoint"], PRIVATE)
        self.assertEqual(entries[7]["endpoint"], ORDER)
        self.assertTrue(all(datetime.fromisoformat(event["timestamp"]).tzinfo == timezone.utc for event in entries))
        for secret in (*self.tokens.values(), csrf, decision, operation, raw_claim, "query-secret",
                       "invalid-token-secret", "invalid-editor-secret", "foreign-origin-secret"):
            self.assertNotIn(secret, "\n".join(captured.output))

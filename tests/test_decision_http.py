"""Integration tests for operation-bound decisions and the proxy boundary."""

import hashlib
import http.client
import json
import secrets
import tempfile
import threading
import unittest
from pathlib import Path

from proofsieve.access import AccessPolicy
from proofsieve.evidence import EvidenceStore
from proofsieve.guard import DEFAULT_RULE, Guard
from proofsieve.server import Handler, LoopbackHTTPServer


class DecisionHTTPTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        policy_file = work / "auth.json"
        self.tokens = {user: secrets.token_urlsafe(32) for user in ("operator", "portal", "other")}
        grants = {"operator": ["*"], "portal": ["/verify/orders"], "other": ["/verify"]}
        policy_file.write_text(json.dumps({
            "version": 1,
            "principals": [
                {"id": user, "role": "admin" if user == "operator" else "verifier",
                 "endpoints": grants[user], "tokenSha256": hashlib.sha256(token.encode("ascii")).hexdigest()}
                for user, token in self.tokens.items()
            ],
        }), encoding="utf-8")
        policy_file.chmod(0o600)
        self.server = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(self.server.server_close)
        self.server.access_policy = AccessPolicy.load(policy_file)
        self.server.guard = Guard(work / "state.json", {}, evidence=EvidenceStore(work / "evidence.db"))
        self.server.guard.update({**DEFAULT_RULE, "responseMode": "decision"}, "/verify/orders")
        self.server.credential_checks = {}
        thread = threading.Thread(target=self.server.serve_forever, daemon=True, kwargs={"poll_interval": 0.01})
        thread.start()
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, *, user=None, body=None, host=None, origin=None):
        headers = {}
        if user:
            headers["Authorization"] = f"Bearer {self.tokens[user]}"
        if host:
            headers["Host"] = host
        if origin:
            headers["Origin"] = origin
        if body is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(body).encode("utf-8")
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers)
            with connection.getresponse() as reply:
                return reply.status, json.loads(reply.read())
        finally:
            connection.close()

    def test_order_requires_identity_grant_and_operation_id(self):
        route = "/verify/orders"
        data = {"data": {"status": "active"}}
        order = {**data, "operationId": "PO-1042"}
        self.assertEqual(self.request("POST", route, body=order)[0], 401)
        self.assertEqual(self.request("POST", route, user="other", body=order)[0], 403)
        self.assertEqual(self.request("POST", route, user="portal", body=data)[0], 400)
        self.assertEqual(self.request("POST", route, user="portal", body={**order, "operationId": None})[0], 400)
        status, result = self.request("POST", route, user="portal", body=order)
        self.assertEqual((status, result["outcome"], result["operationId"]), (200, "allow", "PO-1042"))
        self.assertIn("decisionId", result)
        self.assertEqual(self.request("POST", "/verify", user="other", body=data), (200, True))
        self.assertEqual(self.request("POST", "/verify", user="other", body=order)[0], 400)

    def test_proxy_host_is_api_only(self):
        host = "api.example.test"
        self.assertEqual(self.request("GET", "/admin/rule", user="operator")[0], 200)
        self.server.proxy_origin = f"https://{host}"
        for path in ("/auth/me", "/admin/rule", "/apps/guard/"):
            self.assertEqual(self.request("GET", path, user="operator", host=host)[0], 403)
        self.assertEqual(self.request("GET", "/admin/rule", user="operator")[0], 403)
        self.assertEqual(self.request("GET", "/openapi.json", user="portal", host=host)[0], 200)
        self.assertEqual(self.request("GET", "/openapi.json", user="portal", host=host,
                                      origin="https://elsewhere.example.test")[0], 403)
        body = {"data": {"status": "active"}, "operationId": "PO-1042"}
        self.assertEqual(self.request("POST", "/verify/orders", user="portal", host=host,
                                      origin=f"https://{host}", body=body)[0], 200)
        self.assertEqual(self.request("POST", "/verify/orders?unsupported=1", user="portal", host=host, body=body)[0], 403)

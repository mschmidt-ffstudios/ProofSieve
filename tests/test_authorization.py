"""Exercise access control against an actual authenticated HTTP listener."""

import hashlib
import http.client
import json
import re
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode

from proofsieve.guard import DEFAULT_RULE


ALPHA = "/verify/alpha"
BETA = "/verify/beta"
NEW_ALPHA = "/verify/alpha-new"
SD_JWT = "/verify/demo/eudi-sd-jwt"
MDOC = "/verify/demo/eudi-mdoc"
SAMPLE_CHECK = "/examples/credentials/eudi-pid-sd-jwt/check"
FACTS = {"data": {"status": "active"}}


def for_endpoint(path, endpoint):
    return f"{path}?{urlencode({'endpoint': endpoint})}"


class AuthorizationTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="proofsieve-auth-test-")
        self.addCleanup(directory.cleanup)
        work = Path(directory.name)
        self.state = work / "rules.json"
        self.state.write_text(json.dumps({
            "version": 1,
            "rules": {endpoint: DEFAULT_RULE for endpoint in ("/verify", ALPHA, BETA)},
        }), encoding="utf-8")
        grants = {
            "operator": ("admin", ["*"]),
            "alpha-admin": ("admin", [ALPHA, NEW_ALPHA]),
            "alpha-verifier": ("verifier", [ALPHA]),
            "beta-verifier": ("verifier", [BETA]),
            "jwt-verifier": ("verifier", [SD_JWT]),
        }
        self.tokens = {identifier: secrets.token_urlsafe(32) for identifier in grants}
        config = work / "access.json"
        config.write_text(json.dumps({
            "version": 1,
            "principals": [
                {
                    "id": identifier,
                    "role": role,
                    "endpoints": endpoints,
                    "tokenSha256": hashlib.sha256(self.tokens[identifier].encode("ascii")).hexdigest(),
                }
                for identifier, (role, endpoints) in grants.items()
            ],
        }), encoding="utf-8")
        config.chmod(0o600)
        self.log = work / "server.log"
        with self.log.open("wb") as log:
            process = subprocess.Popen(
                [sys.executable, "-m", "proofsieve", "--port", "0", "--state", str(self.state),
                 "--auth-config", str(config)],
                stdout=log, stderr=subprocess.STDOUT,
            )
        self.addCleanup(self.stop, process)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            output = self.log.read_text(encoding="utf-8")
            match = re.search(r"http://127\.0\.0\.1:(\d+)/apps/", output)
            if match:
                self.port = int(match.group(1))
                return
            if process.poll() is not None:
                break
            time.sleep(0.03)
        self.fail(f"The authenticated server did not start:\n{output}")

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)

    def request(self, method, path, *, user=None, body=None, headers=()):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.putrequest(method, path)
            if user:
                connection.putheader("Authorization", f"Bearer {self.tokens[user]}")
            for name, value in headers:
                connection.putheader(name, value)
            if body is None:
                connection.endheaders()
            else:
                payload = json.dumps(body).encode("utf-8")
                connection.putheader("Content-Type", "application/json")
                connection.putheader("Content-Length", str(len(payload)))
                connection.endheaders(payload)
            with connection.getresponse() as response:
                if response.status == 401:
                    self.assertTrue(response.getheader("WWW-Authenticate", "").startswith("Bearer "))
                raw = response.read()
                value = json.loads(raw) if response.headers.get_content_type() == "application/json" else raw
                return response.status, value
        finally:
            connection.close()

    def editor_token(self, user="operator", endpoint=ALPHA):
        status, rule = self.request("GET", for_endpoint("/admin/rule", endpoint), user=user)
        self.assertEqual(status, 200)
        return ("X-ProofSieve-Token", rule["csrfToken"])

    def test_public_shell_and_private_api_are_distinct(self):
        self.assertEqual(self.request("GET", "/apps/guard/")[0], 200)
        for method, path, body in (
            ("GET", "/auth/me", None),
            ("GET", "/admin/rule", None),
            ("GET", "/openapi.json", None),
            ("POST", ALPHA, FACTS),
            ("POST", SAMPLE_CHECK, {"data": {"vct": "urn:eudi:pid:de:1"}}),
        ):
            with self.subTest(method=method, path=path):
                status, reply = self.request(method, path, body=body)
                self.assertEqual(status, 401)
                self.assertNotIn("csrfToken", reply)

    def test_bad_duplicate_and_query_tokens_cannot_authenticate(self):
        unknown = secrets.token_urlsafe(32)
        self.assertEqual(self.request("POST", ALPHA, body=FACTS,
                                     headers=(("Authorization", f"Bearer {unknown}"),))[0], 401)
        self.assertEqual(self.request("POST", ALPHA, body=FACTS, user="alpha-verifier",
                                     headers=(("Authorization", f"Bearer {unknown}"),))[0], 401)
        self.assertEqual(self.request("GET", f"/auth/me?token={self.tokens['alpha-verifier']}")[0], 401)
        self.assertFalse(any(token in self.log.read_text(encoding="utf-8")
                             for token in (*self.tokens.values(), unknown)))

    def test_verifiers_can_use_only_their_own_exact_paths(self):
        for allowed, denied, user in ((ALPHA, BETA, "alpha-verifier"), (BETA, ALPHA, "beta-verifier")):
            with self.subTest(user=user):
                self.assertEqual(self.request("POST", allowed, user=user, body=FACTS), (200, True))
                status, reply = self.request("POST", denied, user=user, body=FACTS)
                self.assertEqual(status, 403)
                self.assertEqual(self.request("POST", "/verify/guessed", user=user, body=FACTS), (status, reply))
                self.assertEqual(self.request("POST", allowed + "/child", user=user, body=FACTS)[0], 403)
        self.assertEqual(self.request("POST", "/verify/%61lpha", user="alpha-verifier", body=FACTS)[0], 400)
        self.assertIn(self.request("POST", for_endpoint(BETA, ALPHA), user="alpha-verifier", body=FACTS)[0], (400, 403))

    def test_credential_rejection_occurs_after_endpoint_access(self):
        status, reply = self.request("POST", SD_JWT, user="jwt-verifier", body={"data": "bad"})
        self.assertEqual((status, reply["stage"]), (403, "credential"))
        status, reply = self.request("POST", MDOC, user="jwt-verifier", body={"data": "bad"})
        self.assertEqual(status, 403)
        self.assertNotIn("stage", reply)

    def test_auth_me_and_openapi_filter_endpoints(self):
        for user, role, allowed in (("alpha-verifier", "verifier", ALPHA),
                                    ("beta-verifier", "verifier", BETA),
                                    ("alpha-admin", "admin", ALPHA)):
            with self.subTest(user=user):
                status, identity = self.request("GET", "/auth/me", user=user)
                self.assertEqual(status, 200)
                self.assertTrue(identity["enabled"])
                self.assertEqual((identity["id"], identity["role"], identity["allEndpoints"]), (user, role, False))
                self.assertEqual(identity["endpoints"], [allowed])
                status, spec = self.request("GET", "/openapi.json", user=user)
                self.assertEqual(status, 200)
                self.assertEqual(set(spec["paths"]), {allowed})
        status, identity = self.request("GET", "/auth/me", user="operator")
        self.assertEqual(status, 200)
        self.assertTrue(identity["allEndpoints"])
        self.assertIn(ALPHA, identity["endpoints"])
        self.assertIn(BETA, identity["endpoints"])
        self.assertNotIn("tokenSha256", identity)
        _, verifier = self.request("GET", "/auth/me", user="alpha-verifier")
        self.assertNotIn("csrfToken", verifier)
        self.assertNotIn("tokenSha256", verifier)

    def test_verifier_cannot_read_edit_preview_or_bypass_via_sample_checks(self):
        route = for_endpoint("/admin/rule", ALPHA)
        csrf = self.editor_token()
        user = "alpha-verifier"
        original = self.state.read_bytes()
        self.assertEqual(self.request("GET", route, user=user)[0], 403)
        self.assertEqual(self.request("PUT", route, user=user, body=DEFAULT_RULE, headers=(csrf,))[0], 403)
        self.assertEqual(self.request("POST", for_endpoint("/admin/test-rule", ALPHA), user=user,
                                     body={"rule": DEFAULT_RULE, **FACTS}, headers=(csrf,))[0], 403)
        sample = {"data": {"vct": "urn:eudi:pid:de:1"}}
        self.assertEqual(self.request("POST", SAMPLE_CHECK, user=user, body=sample)[0], 403)
        self.assertEqual(self.request("POST", SAMPLE_CHECK, user="operator", body=sample), (200, True))
        self.assertEqual(self.state.read_bytes(), original)

    def test_admin_scope_and_editor_token_control_state_changes(self):
        user = "alpha-admin"
        alpha = for_endpoint("/admin/rule", ALPHA)
        beta = for_endpoint("/admin/rule", BETA)
        status, details = self.request("GET", alpha, user=user)
        self.assertEqual(status, 200)
        self.assertEqual(details["endpoints"], [ALPHA])
        csrf = ("X-ProofSieve-Token", details["csrfToken"])
        original = self.state.read_bytes()
        self.assertEqual(self.request("GET", beta, user=user)[0], 403)
        self.assertEqual(self.request("PUT", beta, user=user, body=DEFAULT_RULE, headers=(csrf,))[0], 403)
        self.assertEqual(self.request("PUT", alpha, user=user, body=DEFAULT_RULE)[0], 403)
        self.assertEqual(self.request("PUT", alpha, body=DEFAULT_RULE, headers=(csrf,))[0], 401)
        self.assertEqual(self.request("PUT", alpha, user=user, body=DEFAULT_RULE,
                                      headers=(self.editor_token(),))[0], 403)
        self.assertEqual(self.state.read_bytes(), original)
        new = for_endpoint("/admin/rule", NEW_ALPHA)
        status, details = self.request("PUT", new, user=user, body=DEFAULT_RULE,
                                       headers=(csrf, ("If-None-Match", "*")))
        self.assertEqual(status, 200)
        self.assertEqual(set(details["endpoints"]), {ALPHA, NEW_ALPHA})
        self.assertEqual(self.request("POST", NEW_ALPHA, user=user, body=FACTS), (200, True))
        self.assertEqual(self.request("POST", NEW_ALPHA, user="alpha-verifier", body=FACTS)[0], 403)

    def test_preview_scope_read_only_and_cross_origin(self):
        user = "alpha-admin"
        csrf = self.editor_token(user)
        payload = {"rule": DEFAULT_RULE, **FACTS}
        alpha = for_endpoint("/admin/test-rule", ALPHA)
        beta = for_endpoint("/admin/test-rule", BETA)
        original = self.state.read_bytes()
        status, result = self.request("POST", alpha, user=user, body=payload, headers=(csrf,))
        self.assertEqual(status, 200)
        self.assertTrue(result["valid"])
        self.assertEqual(self.request("POST", beta, user=user, body=payload, headers=(csrf,))[0], 403)
        self.assertEqual(self.request("POST", "/admin/test-rule", user=user, body=payload, headers=(csrf,))[0], 400)
        self.assertEqual(self.request("POST", alpha, user=user, body=payload)[0], 403)
        self.assertEqual(self.request("POST", alpha, user=user, body=payload,
                                     headers=(csrf, ("Origin", "https://other.example")))[0], 403)
        route = for_endpoint("/admin/rule", SD_JWT)
        status, details = self.request("GET", route, user="operator")
        self.assertEqual(status, 200)
        self.assertTrue(details["readOnly"])
        self.assertEqual(self.request("PUT", route, user="operator", body=details["rule"],
                                     headers=(("X-ProofSieve-Token", details["csrfToken"]),))[0], 403)
        self.assertEqual(self.state.read_bytes(), original)

    def test_private_socket_requires_authentication_configuration(self):
        socket_path = self.state.with_name("guard.sock")
        result = subprocess.run(
            [sys.executable, "-m", "proofsieve", "--port", "24180", "--socket", str(socket_path),
             "--state", str(self.state)], capture_output=True, timeout=3, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"--auth-config", result.stderr)
        self.assertFalse(socket_path.exists())

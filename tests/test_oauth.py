"""Validate OAuth grants, Keycloak token claims, and JWKS lifecycle."""

import base64
import hashlib
import json
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from proofsieve.access import AccessPolicy
from proofsieve.oauth import JWKS_REFRESH_INTERVAL, JWKS_TTL, MAX_JWKS_BYTES, MAX_TOKEN_LIFETIME


ISSUER = "https://auth.example.test/realms/proofsieve"
AUDIENCE = "proofsieve-api"
CLIENT = "supplier-portal"
SUBJECT = "service-account-uuid"
ENDPOINT = "/verify/supplier-orders"
ROLE = "verify-supplier-orders"
OPAQUE = "A" * 43


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def uint(number):
    return b64(number.to_bytes((number.bit_length() + 7) // 8, "big"))


def jwk(key, kid):
    numbers = key.public_key().public_numbers()
    return {"kty": "RSA", "alg": "RS256", "kid": kid, "use": "sig", "n": uint(numbers.n), "e": uint(numbers.e)}


class JWKSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        if self.server.status == 302:
            self.send_header("Location", self.server.redirect)
        self.end_headers()
        if getattr(self.server, "trickle", False):
            try:
                for _ in range(30):
                    self.wfile.write(b" ")
                    time.sleep(0.02)
            except OSError:
                pass
            return
        self.wfile.write(self.server.body)

    def log_message(self, *_):
        pass


class OAuthAccessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwks = {"keys": [jwk(cls.key, "key-1")]}

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "access.json"
        self.config = {
            "version": 2,
            "principals": [{
                "id": "operator", "role": "admin", "endpoints": ["*"],
                "tokenSha256": hashlib.sha256(OPAQUE.encode("ascii")).hexdigest(),
            }],
            "oauth": {
                "issuer": ISSUER, "audience": AUDIENCE,
                "serviceAccounts": [{"id": CLIENT, "clientId": CLIENT, "subject": SUBJECT, "grants": {ROLE: ENDPOINT}}],
            },
        }

    def load(self, config=None):
        self.path.write_text(json.dumps(self.config if config is None else config), encoding="utf-8")
        self.path.chmod(0o600)
        return AccessPolicy.load(self.path)

    def token(self, *, key=None, kid="key-1", jose=None, raw_payload=None, **claims):
        now = int(time.time())
        payload = {
            "iss": self.config["oauth"]["issuer"], "aud": [AUDIENCE, "account"], "typ": "Bearer",
            "azp": CLIENT, "sub": SUBJECT, "iat": now - 5, "exp": now + 60,
            "resource_access": {AUDIENCE: {"roles": [ROLE]}},
        }
        payload.update(claims)
        header = {"alg": "RS256", "typ": "JWT", "kid": kid, **(jose or {})}
        data = b64(json.dumps(header).encode()) + "." + b64(raw_payload or json.dumps(payload).encode())
        signature = (key or self.key).sign(data.encode(), padding.PKCS1v15(), hashes.SHA256())
        return data + "." + b64(signature)

    @staticmethod
    def authenticate(policy, *tokens):
        headers = Message()
        for token in tokens:
            headers.add_header("Authorization", "Bearer " + token)
        return policy.authenticate(headers)

    def test_registered_service_account_requires_a_signed_exact_grant(self):
        policy = self.load()
        with patch("proofsieve.oauth._fetch_jwks", return_value=self.jwks) as fetch:
            principal = self.authenticate(policy, self.token())
            self.assertEqual((principal.id, principal.role, principal.endpoints), (CLIENT, "verifier", (ENDPOINT,)))
            self.assertTrue(principal.allows(ENDPOINT))
            self.assertFalse(principal.allows(ENDPOINT + "/another"))
            self.assertFalse(principal.allows("/admin/rule"))
            for access in ({}, {"other-client": {"roles": [ROLE]}}, {AUDIENCE: {"roles": ["admin"]}}):
                token = self.token(aud=AUDIENCE, resource_access=access)
                self.assertEqual(self.authenticate(policy, token).endpoints, ())
            self.assertEqual(self.authenticate(policy, OPAQUE).role, "admin")
            fetch.assert_called_once_with(ISSUER + "/protocol/openid-connect/certs")

    def test_bad_claims_are_rejected_before_jwks_lookup(self):
        now = int(time.time())
        for claims in (
            {"iss": "https://other.example.test/realms/proofsieve"}, {"aud": "some-other-api"},
            {"aud": [AUDIENCE, 1]}, {"aud": {"any": AUDIENCE}}, {"typ": "ID"}, {"sub": "human-user"},
            {"azp": "other-client"}, {"sub": []}, {"azp": {}}, {"cnf": {"jkt": "bound-key"}},
            {"exp": now - 1}, {"iat": now + 60}, {"nbf": now + 60}, {"iat": None}, {"exp": True},
            {"exp": now + MAX_TOKEN_LIFETIME * 2},
        ):
            with self.subTest(claims=claims), patch("proofsieve.oauth._fetch_jwks") as fetch:
                self.assertIsNone(self.authenticate(self.load(), self.token(**claims)))
                fetch.assert_not_called()

    def test_confused_algorithms_and_untrusted_headers_are_rejected(self):
        bad_tokens = (
            self.token(jose={"alg": "none"}), self.token(jose={"alg": "HS256"}),
            self.token(jose={"typ": "at+jwt"}), self.token(jose={"jku": "https://malicious.invalid/keys"}),
            self.token(jose={"x5c": ["fake"]}), self.token(jose={"crit": ["test"]}),
            self.token(raw_payload=b'{"iss":"test","iss":"test"}'),
            self.token() + "=", "A" * (13 * 1024),
        )
        with patch("proofsieve.oauth._fetch_jwks") as fetch:
            for token in bad_tokens:
                self.assertIsNone(self.authenticate(self.load(), token))
            fetch.assert_not_called()

    def test_signature_role_and_duplicate_authorization_are_validated(self):
        policy = self.load()
        good = self.token()
        with patch("proofsieve.oauth._fetch_jwks", return_value=self.jwks):
            for token in (
                self.token(key=self.rotated), self.token(resource_access=None),
                self.token(resource_access={AUDIENCE: {"roles": ROLE}}),
                self.token(resource_access={AUDIENCE: {"roles": [ROLE, []]}}),
            ):
                self.assertIsNone(self.authenticate(policy, token))
            self.assertIsNone(self.authenticate(policy, good, good))
            self.assertIsNone(self.authenticate(policy, OPAQUE, good))

    def test_new_kid_refreshes_and_does_not_use_expired_cache_on_outage(self):
        policy = self.load()
        old, new = self.token(), self.token(key=self.rotated, kid="_key-2")
        with patch("proofsieve.oauth._fetch_jwks", side_effect=[
            self.jwks, {"keys": [jwk(self.rotated, "_key-2")]}, OSError("Keycloak offline"),
        ]) as fetch, patch("proofsieve.oauth.time.monotonic", return_value=100.0) as clock:
            self.assertIsNotNone(self.authenticate(policy, old))
            self.assertIsNone(self.authenticate(policy, new))
            clock.return_value += JWKS_REFRESH_INTERVAL + 1
            self.assertIsNotNone(self.authenticate(policy, new))
            self.assertIsNone(self.authenticate(policy, old))
            clock.return_value += JWKS_TTL + 1
            self.assertIsNone(self.authenticate(policy, new))
            self.assertIsNone(self.authenticate(policy, new))
            self.assertEqual(fetch.call_count, 3)

    def test_refresh_shares_inflight_fetch_without_delaying_fresh_cached_keys(self):
        policy = self.load()
        old, new = self.token(), self.token(key=self.rotated, kid="key-2")
        started, release = threading.Event(), threading.Event()

        def rotated_keyset():
            started.set()
            if not release.wait(5):
                raise TimeoutError
            return {"keys": [jwk(self.rotated, "key-2")]}

        with (patch("proofsieve.oauth._fetch_jwks") as fetch,
              patch("proofsieve.oauth.time.monotonic", return_value=100.0) as clock,
              ThreadPoolExecutor(max_workers=3) as pool):
            fetch.return_value = self.jwks
            self.assertIsNotNone(self.authenticate(policy, old))
            fetch.side_effect = lambda _url: rotated_keyset()
            clock.return_value += JWKS_REFRESH_INTERVAL + 1
            first = pool.submit(self.authenticate, policy, new)
            try:
                self.assertTrue(started.wait(2))
                second = pool.submit(self.authenticate, policy, new)
                cached = pool.submit(self.authenticate, policy, old)
                self.assertIsNotNone(cached.result(timeout=1))
                self.assertEqual(fetch.call_count, 2)
            finally:
                release.set()
            self.assertIsNotNone(first.result(timeout=2))
            self.assertIsNotNone(second.result(timeout=2))
            self.assertEqual(fetch.call_count, 2)

    def test_invalid_keysets_do_not_supply_keys(self):
        duplicate = jwk(self.key, "key-1")
        for keys in (
            [duplicate, duplicate], [{**duplicate, "alg": "RS512"}], [{**duplicate, "n": "AQ"}],
            [{**duplicate, "e": "="}], [{**duplicate, "use": "enc"}], ["malformed"],
        ):
            with self.subTest(keys=len(keys)), patch("proofsieve.oauth._fetch_jwks", return_value={"keys": keys}):
                self.assertIsNone(self.authenticate(self.load(), self.token()))

    def test_configuration_rejects_unsafe_issuer_and_unbounded_identity(self):
        for issuer in (
            "http://auth.example.test/realms/proofsieve", "https://user@auth.example.test/realms/proofsieve",
            "https://auth.example.test/realms/proofsieve/", "https://auth.example.test/a/../realms/proofsieve",
            "https://auth.example.test:66000/realms/proofsieve", "https://auth.example.test/realms/proofsieve#",
        ):
            with self.subTest(issuer=issuer):
                config = deepcopy(self.config)
                config["oauth"]["issuer"] = issuer
                with self.assertRaises(ValueError):
                    self.load(config)
        for field, value in (("id", "operator"), ("subject", ""), ("grants", {ROLE: "*"})):
            with self.subTest(field=field):
                config = deepcopy(self.config)
                config["oauth"]["serviceAccounts"][0][field] = value
                with self.assertRaises(ValueError):
                    self.load(config)
        config = deepcopy(self.config)
        config["oauth"]["serviceAccounts"].append(config["oauth"]["serviceAccounts"][0])
        with self.assertRaises(ValueError):
            self.load(config)

    def test_loopback_jwks_http_requires_opt_in_and_disables_redirects(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), JWKSHandler) as server:
            server.status = 200
            server.requests = []
            server.body = json.dumps(self.jwks).encode()
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                origin = f"http://127.0.0.1:{server.server_port}"
                self.config["oauth"]["issuer"] = origin + "/realms/proofsieve"
                with self.assertRaises(ValueError):
                    self.load()
                self.config["oauth"]["allowLoopbackHttp"] = True
                self.assertIsNotNone(self.authenticate(self.load(), self.token()))
                server.status = 302
                server.redirect = origin + "/redirect"
                server.body = b""
                self.assertIsNone(self.authenticate(self.load(), self.token()))
                self.assertEqual(server.requests, ["/realms/proofsieve/protocol/openid-connect/certs"] * 2)
                server.status = 200
                server.trickle = True
                with patch("proofsieve.oauth.JWKS_TIMEOUT", 0.15):
                    start = time.monotonic()
                    self.assertIsNone(self.authenticate(self.load(), self.token()))
                    self.assertLess(time.monotonic() - start, 0.45)
            finally:
                server.shutdown()
                thread.join(timeout=2)

    def test_jwks_response_is_size_limited(self):
        response = type("Response", (), {})()
        response.status = 200
        response.headers = Message()
        response.headers["Content-Type"] = "application/json"
        with patch("proofsieve.oauth.http.client.HTTPSConnection") as factory:
            context = factory.return_value.getresponse.return_value
            context.__enter__.return_value = response
            bytes_read = 0

            def read(size):
                nonlocal bytes_read
                bytes_read += size
                return b" " * size

            response.read1 = read
            self.assertIsNone(self.authenticate(self.load(), self.token()))
            self.assertEqual(bytes_read, MAX_JWKS_BYTES + 1)
            factory.return_value.close.assert_called_once()

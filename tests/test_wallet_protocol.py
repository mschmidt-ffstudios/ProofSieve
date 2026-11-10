import base64
import hashlib
import ipaddress
import json
import os
import ssl
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from proofsieve.wallet import load_wallet_verification
from proofsieve.wallet_protocol import (
    CredoWalletConnector, WalletConnector, WalletRejected, WalletUnavailable, load_wallet_connector,
)
from tests.test_external_checks import make_certificate


TOKEN = "test-wallet-connector-token"
CLIENT_ID = "x509_hash:" + "A" * 43
NONCE = "n" * 43
TRANSACTION = "t" * 43
PUBLIC_ORIGIN = "https://wallet.example.test"
REQUEST_URI = PUBLIC_ORIGIN + "/wallet/request.jwt/" + "r" * 43
PRESENTATION_PATH = f"/ui/presentations/{TRANSACTION}"
SD_JWT_PATH = "/utilities/validations/sdJwtVc"
MDOC_PATH = "/utilities/validations/msoMdoc/deviceResponse"
CREDO_PATH = "/internal/proofsieve/wallet/transactions"
CREDO_REQUEST_URI = PUBLIC_ORIGIN + "/oid4vp/proofsieve/authorization-requests/a8eb354a-8d16-4692-8d1c-0792e7c9c37e"
ISSUER_CHAIN = "operator-pinned issuer"


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def authorization_uri(request_uri=REQUEST_URI, **extra):
    parameters = {"client_id": CLIENT_ID, "request_uri": request_uri, "request_uri_method": "get"}
    return "haip-vp://?" + urlencode({**parameters, **extra})


class WalletProtocolTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        folder = Path(directory.name)
        self.folder = folder
        ca = folder / "ca.pem"
        key_file = folder / "key.pem"
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = make_certificate("Wallet protocol test", key, ca=True, ip=ipaddress.ip_address("127.0.0.1"))
        self.issuer_key = key
        self.issuer_certificate = certificate
        ca.write_bytes(certificate.public_bytes(Encoding.PEM))
        key_file.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ca, key_file)
        self.received = []
        self.responses = []
        test = self

        class Handler(BaseHTTPRequestHandler):
            def send_fixture(self):
                content = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                test.received.append((self.command, self.path, dict(self.headers.items()), content))
                status, body, headers = test.responses.pop(0)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)

            do_GET = send_fixture
            do_POST = send_fixture

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 2)
        self.addCleanup(server.shutdown)
        environment = patch.dict(os.environ, {"WALLET_PROTOCOL_TEST_TOKEN": TOKEN})
        environment.start()
        self.addCleanup(environment.stop)
        self.config = {
            "url": f"https://127.0.0.1:{server.server_port}",
            "allowedNetworks": ["127.0.0.1/32"],
            "bearerEnv": "WALLET_PROTOCOL_TEST_TOKEN",
            "caFile": str(ca),
            "publicOrigin": PUBLIC_ORIGIN,
            "clientId": CLIENT_ID,
        }
        self.connector = load_wallet_connector(self.config)
        self.profile = SimpleNamespace(
            dcql_query={"credentials": [{"id": "credential", "format": "dc+sd-jwt"}]},
            issuer_chain=ISSUER_CHAIN, intended_use_id="wallet-demo", format="dc+sd-jwt",
            issuer="https://issuer.example.test",
            project=Mock(return_value={"ageOver18": True}),
        )

    def reply(self, payload, *, status=200, headers=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("ascii")
        self.responses.append((status, body, headers or {}))

    def initialization(self, *, transaction=TRANSACTION, request_uri=REQUEST_URI, auth_uri=None, extra=None):
        auth_uri = authorization_uri(request_uri) if auth_uri is None else auth_uri
        payload = {"transaction_id": transaction, "client_id": CLIENT_ID, "request_uri": request_uri,
                   "request_uri_method": "get", "authorization_request_uri": auth_uri}
        self.reply({**payload, **(extra or {})}, headers={
            "Transaction-Id": transaction, "Authorization-Request-Uri": auth_uri,
        })

    def result(self):
        return self.connector.result(transaction_id=TRANSACTION, profile=self.profile, nonce=NONCE)

    def sd_jwt_presentation(self):
        disclosure = b64url(b'["secret-salt","ageOver18",true]')
        claims = {"iss": self.profile.issuer, "vct": "urn:proofsieve:pid", "exp": int(time.time()) + 300}
        payload = {**claims, "_sd": [b64url(hashlib.sha256(disclosure.encode("ascii")).digest())]}
        leaf = self.issuer_certificate.public_bytes(Encoding.DER)
        header = {"alg": "ES256", "typ": "dc+sd-jwt", "x5c": [base64.b64encode(leaf).decode("ascii")]}
        message = ".".join(b64url(json.dumps(value).encode("ascii")) for value in (header, payload))
        signature = self.issuer_key.sign(message.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(signature)
        raw = b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        # The test bridge owns holder verification. ProofSieve verifies the exact issuer portion.
        return f"{message}.{raw}~{disclosure}~x.y.z", {**claims, "ageOver18": True}

    def test_starts_bound_by_reference_haip_request(self):
        self.initialization()
        result = self.connector.start(profile=self.profile, nonce=NONCE)
        self.assertEqual(result.transaction_id, TRANSACTION)
        self.assertEqual(result.authorization_request_uri, authorization_uri())
        method, path, headers, body = self.received[0]
        self.assertEqual((method, path), ("POST", "/ui/presentations/v2"))
        self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(json.loads(body), {
            "dcql_query": self.profile.dcql_query, "nonce": NONCE, "jar_mode": "by_reference",
            "request_uri_method": "get", "authorization_request_scheme": "haip-vp", "profile": "haip",
            "response_mode": "direct_post.jwt", "issuer_chain": ISSUER_CHAIN, "intended_use_id": "wallet-demo",
        })

    def test_rejects_unbound_or_unsafe_initialization(self):
        for name, options in {
            "origin": {"request_uri": REQUEST_URI.replace("wallet.example.test", "other.example.test")},
            "route": {"request_uri": REQUEST_URI.replace("/wallet/", "/other/")},
            "auth_scheme": {"auth_uri": authorization_uri().replace("haip-vp:", "openwallet:")},
            "extra_param": {"auth_uri": authorization_uri(extra="1")},
            "duplicate_param": {"auth_uri": authorization_uri() + "&client_id=other"},
            "header_mismatch": {"extra": {"transaction_id": "b" * 43}},
            "path_injection": {"transaction": "../" + TRANSACTION},
        }.items():
            with self.subTest(name=name), self.assertRaises(WalletUnavailable):
                self.initialization(**options)
                self.connector.start(profile=self.profile, nonce=NONCE)
        self.assertEqual(len(self.received), 7)

    def test_retrieves_then_validates_bound_sd_jwt_on_same_pinned_host(self):
        token = "issuer.header.signature~disclosure~holder.header.signature"
        self.reply({"vp_token": {"credential": [token]}})
        claims = {"age_equal_or_over": {"18": True}, "iss": "https://issuer.example.test"}
        self.reply(claims)
        self.assertEqual(self.result(), {"ageOver18": True})
        self.assertEqual([(r[0], r[1]) for r in self.received], [("GET", PRESENTATION_PATH), ("POST", SD_JWT_PATH)])
        self.assertTrue(all(r[2]["Authorization"] == f"Bearer {TOKEN}" for r in self.received))
        self.assertEqual(self.received[1][2]["Content-Type"], "application/x-www-form-urlencoded")
        self.assertEqual(parse_qs(self.received[1][3].decode()), {
            "sd_jwt_vc": [token], "nonce": [NONCE], "audience": [CLIENT_ID], "issuer_chain": [ISSUER_CHAIN],
        })
        self.profile.project.assert_called_once_with(claims, presentation=token)

    def test_retrieves_submitted_mdoc_before_projection(self):
        token = "aW50ZXJuYWw"
        self.profile.format = "mso_mdoc"
        self.reply({"vp_token": {"credential": [token]}})
        verified = [{"docType": "example", "attributes": {"example": {"age_over_18": True}}}]
        self.reply(verified)
        self.assertEqual(self.result(), {"ageOver18": True})
        self.assertEqual([(r[0], r[1]) for r in self.received], [("GET", PRESENTATION_PATH), ("POST", MDOC_PATH)])
        self.assertEqual(parse_qs(self.received[1][3].decode()), {
            "device_response": [token], "issuer_chain": [ISSUER_CHAIN],
        })
        self.profile.project.assert_called_once_with(verified, presentation=token)

    def test_pending_error_malformed_and_unknown_never_validate(self):
        self.reply({"error": "PresentationNotSubmitted"}, status=400)
        self.assertIsNone(self.result())
        self.reply({}, status=404)
        with self.assertRaises(WalletUnavailable):
            self.result()
        self.reply({"error": "InvalidResponseCode"}, status=400)
        with self.assertRaises(WalletUnavailable):
            self.result()
        self.reply({"error": "access_denied"})
        with self.assertRaises(WalletRejected):
            self.result()
        self.reply(b'{"vp_token": {"credential": ["a.b.c~x.y.z"], "credential": ["x"]}}')
        with self.assertRaises(WalletUnavailable):
            self.result()
        self.reply({"vp_token": {"other": ["a.b.c~x.y.z"]}})
        with self.assertRaises(WalletUnavailable):
            self.result()
        self.reply({"vp_token": {"credential": ["a.b.c~"]}})
        with self.assertRaises(WalletRejected):
            self.result()
        self.assertEqual([r[0] for r in self.received], ["GET"] * 7)
        self.profile.project.assert_not_called()

    def test_rejects_utility_failure_and_propagates_indeterminate_status(self):
        wallet = {"vp_token": {"credential": ["a.b.c~x.y.z"]}}
        self.reply(wallet)
        self.reply({}, status=400)
        with self.assertRaises(WalletRejected):
            self.result()
        self.reply(wallet)
        self.reply({}, status=302, headers={"Location": "https://other.example.test/"})
        with self.assertRaises(WalletUnavailable):
            self.result()
        self.reply(wallet)
        self.reply({"status": "not verifiable"})
        self.profile.project.side_effect = WalletUnavailable()
        with self.assertRaises(WalletUnavailable):
            self.result()
        self.assertEqual([(r[0], r[1]) for r in self.received],
                         [("GET", PRESENTATION_PATH), ("POST", SD_JWT_PATH)] * 3)

    def test_refuses_arbitrary_configured_routes_and_untrusted_tls(self):
        for overrides in (
            {"url": self.config["url"] + "/api"}, {"publicOrigin": PUBLIC_ORIGIN + "/wallet"},
            {"clientId": "x509_san_dns:wallet.example.test"}, {"allowedNetworks": ["10.0.0.0/8"]},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                load_wallet_connector({**self.config, **overrides})
        without_ca = {key: value for key, value in self.config.items() if key != "caFile"}
        with self.assertRaises(WalletUnavailable):
            load_wallet_connector(without_ca).start(profile=self.profile, nonce=NONCE)
        self.assertEqual([], self.received)

    def test_credo_starts_bound_transaction_and_uses_configured_wallet_origin(self):
        connector = load_wallet_connector({**self.config, "kind": "credo"})
        self.reply({"transaction_id": TRANSACTION, "nonce": NONCE, "client_id": CLIENT_ID,
                    "request_uri": CREDO_REQUEST_URI})
        result = connector.start(profile=self.profile, nonce=NONCE)
        self.assertEqual(result.transaction_id, TRANSACTION)
        self.assertEqual(result.authorization_request_uri, authorization_uri(CREDO_REQUEST_URI))
        method, path, headers, body = self.received[0]
        self.assertEqual((method, path), ("POST", CREDO_PATH))
        self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")
        self.assertEqual(json.loads(body), {
            "dcql_query": self.profile.dcql_query, "nonce": NONCE,
            "issuer_chain": ISSUER_CHAIN, "intended_use_id": "wallet-demo",
        })

    def test_credo_refuses_unsafe_request_uris_and_unbound_initialization(self):
        connector = load_wallet_connector({**self.config, "kind": "credo"})
        good = {"transaction_id": TRANSACTION, "nonce": NONCE, "client_id": CLIENT_ID,
                "request_uri": CREDO_REQUEST_URI}
        for change in (
            {"request_uri": CREDO_REQUEST_URI.replace("wallet.example.test", "other.example.test")},
            {"request_uri": CREDO_REQUEST_URI.replace("/oid4vp/", "/other/")},
            {"request_uri": CREDO_REQUEST_URI.replace("/authorization-requests/", "/authorize/")},
            {"request_uri": CREDO_REQUEST_URI + "?nonce=changed"},
            {"request_uri": CREDO_REQUEST_URI + "/../callback"},
            {"nonce": "wrong"}, {"client_id": CLIENT_ID + "X"}, {"transaction_id": "../" + TRANSACTION},
        ):
            with self.subTest(change=change), self.assertRaises(WalletUnavailable):
                self.reply({**good, **change})
                connector.start(profile=self.profile, nonce=NONCE)

    def test_credo_projects_verified_sd_jwt_and_mdoc_from_bound_result(self):
        connector = load_wallet_connector({**self.config, "kind": "credo"})
        common = {"transaction_id": TRANSACTION, "nonce": NONCE, "client_id": CLIENT_ID, "state": "verified"}
        sd_jwt, sd_jwt_claims = self.sd_jwt_presentation()
        mdoc_claims = [{"docType": "type", "attributes": {"ns": {"ageOver18": True}}}]
        cases = (
            ("dc+sd-jwt", sd_jwt, {"ageOver18": False}, sd_jwt_claims),
            ("mso_mdoc", "aW50ZXJuYWw", mdoc_claims, mdoc_claims),
        )
        for fmt, token, bridge_claims, expected in cases:
            with self.subTest(format=fmt):
                self.profile.format = fmt
                self.reply({**common, "format": fmt, "presentation": token, "verified": bridge_claims})
                self.assertEqual(
                    connector.result(transaction_id=TRANSACTION, profile=self.profile, nonce=NONCE),
                    {"ageOver18": True},
                )
                self.profile.project.assert_called_with(expected, presentation=token)
        self.assertEqual(self.profile.project.call_count, 2)
        self.assertEqual([(method, path) for method, path, _, _ in self.received],
                         [("GET", f"{CREDO_PATH}/{TRANSACTION}")] * 2)

    def test_credo_does_not_accept_issuer_unbound_disclosure_even_when_bridge_says_verified(self):
        connector = load_wallet_connector({**self.config, "kind": "credo"})
        original, claims = self.sd_jwt_presentation()
        issuer_jws, _disclosure, holder_jws = original.split("~")
        replaced = b64url(b'["secret-salt","ageOver18",false]')
        for candidate in (replaced, b64url(b'["\xf2secret","ageOver18",true]')):
            with self.subTest(candidate=candidate):
                self.reply({
                    "transaction_id": TRANSACTION, "nonce": NONCE, "client_id": CLIENT_ID, "state": "verified",
                    "format": "dc+sd-jwt", "presentation": f"{issuer_jws}~{candidate}~{holder_jws}",
                    "verified": {key: value for key, value in claims.items() if key != "ageOver18"},
                })
                with self.assertRaisesRegex(WalletRejected, "wallet_presentation_validation_failed"):
                    connector.result(transaction_id=TRANSACTION, profile=self.profile, nonce=NONCE)
        self.profile.project.assert_not_called()

    def test_credo_distinguishes_pending_rejected_and_untrustworthy_results(self):
        connector = load_wallet_connector({**self.config, "kind": "credo"})
        pending = {"transaction_id": TRANSACTION, "nonce": NONCE, "client_id": CLIENT_ID, "state": "pending"}
        rejected = {**pending, "state": "rejected"}
        verified = {**pending, "state": "verified", "format": "dc+sd-jwt", "presentation": "a.b.c~x.y.z", "verified": {}}

        def result():
            return connector.result(transaction_id=TRANSACTION, profile=self.profile, nonce=NONCE)

        self.reply(pending)
        self.assertIsNone(result())
        self.reply(rejected)
        with self.assertRaises(WalletRejected):
            result()
        for payload in (
            {**pending, "nonce": "wrong"}, {**rejected, "transaction_id": "wrong"},
            {**rejected, "client_id": CLIENT_ID + "X"}, {**rejected, "verified": {}},
            {**verified, "format": "mso_mdoc"}, {**verified, "verified": []},
            {**verified, "presentation": "a.b.c~"}, {**verified, "state": "unknown"},
        ):
            with self.subTest(payload=payload), self.assertRaises(WalletUnavailable):
                self.reply(payload)
                result()
        self.reply({}, status=503)
        with self.assertRaises(WalletUnavailable):
            result()
        self.profile.project.assert_not_called()

    def test_wallet_connector_kind_is_explicit_and_legacy_default_is_unchanged(self):
        explicit = load_wallet_connector({**self.config, "kind": "eudi"})
        self.assertIs(type(explicit), type(self.connector))
        with self.assertRaises(ValueError):
            load_wallet_connector({**self.config, "kind": "unrecognized"})

    def test_config_loads_credo_and_eudi_side_by_side(self):
        config = self.folder / "wallet.json"
        profile = {
            "format": "dc+sd-jwt", "credentialType": "urn:eudi:pid:1",
            "issuer": "https://issuer.example.test",
            "issuerChainPem": Path(self.config["caFile"]).read_text(encoding="ascii"),
            "intendedUseId": "wallet-demo",
            "claims": {"status": {"path": ["status"], "type": "string"}},
            "status": {"mode": "not-required"},
        }
        config.write_text(json.dumps({
            "version": 1,
            "connectors": {"reference": self.config, "credo": {**self.config, "kind": "credo"}},
            "endpoints": {
                "/verify/eudi": {"connector": "reference", "profile": profile},
                "/verify/credo": {"connector": "credo", "profile": profile},
            },
        }), encoding="utf-8")
        config.chmod(0o600)
        binding = load_wallet_verification(config, self.folder / "sessions.db")
        eudi = binding.endpoints["/verify/eudi"]
        credo = binding.endpoints["/verify/credo"]
        self.assertIs(type(eudi.connector), WalletConnector)
        self.assertIs(type(credo.connector), CredoWalletConnector)
        self.assertEqual(eudi.profile.version, credo.profile.version)
        self.assertNotEqual(eudi.version, credo.version)
        self.assertEqual((binding.sessions.recent_per_caller, binding.sessions.retained_per_caller), (16, 500))

        config_values = json.loads(config.read_text(encoding="utf-8"))
        config_values["sessionLimits"] = {"recentPerCaller": 3, "retainedPerCaller": 10}
        config.write_text(json.dumps(config_values), encoding="utf-8")
        binding = load_wallet_verification(config, self.folder / "sessions.db")
        self.assertEqual((binding.sessions.recent_per_caller, binding.sessions.retained_per_caller), (3, 10))
        for limits in ({"recentPerCaller": True}, {"retainedPerCaller": 2501}, {"unknown": 1}, []):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                config_values["sessionLimits"] = limits
                config.write_text(json.dumps(config_values), encoding="utf-8")
                load_wallet_verification(config, self.folder / "sessions.db")

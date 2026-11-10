import http.client
import ipaddress
import json
import os
import ssl
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID

from proofsieve.forwarding import ForwardingUnavailable, load_forwarding


TOKEN = "demo-forwarding-test-token"
SOURCE = "/verify/orders"
BODY = b'{ "order": "123", "facts": { "status": "approved" } }\n'


class ForwardingTransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        self.config = folder / "forwarding.json"
        self.ca = folder / "certificate.pem"
        private_key = folder / "key.pem"
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ProofSieve forwarding test")])
        certificate = (x509.CertificateBuilder()
                       .subject_name(name)
                       .issuer_name(name)
                       .public_key(key.public_key())
                       .serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(days=1))
                       .not_valid_after(now + timedelta(days=1))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                       .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                                      critical=False)
                       .sign(key, hashes.SHA256()))
        self.ca.write_bytes(certificate.public_bytes(Encoding.PEM))
        private_key.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.ca, private_key)

        self.received = []
        self.response_status = 202
        self.hold_response = None
        test = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                test.received.append((self.path, self.headers, self.rfile.read(int(self.headers["Content-Length"]))))
                if test.hold_response is not None:
                    test.hold_response.wait(timeout=4)
                if test.response_status is not None:
                    self.send_response(test.response_status)
                    self.send_header("Location", "/unexpected-redirect")
                    self.send_header("Content-Length", "1000000")
                    self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 2)
        self.addCleanup(server.shutdown)
        self.url = f"https://127.0.0.1:{server.server_port}/internal/order"
        environment = patch.dict(os.environ, {"FORWARDING_TEST_TOKEN": TOKEN})
        environment.start()
        self.addCleanup(environment.stop)

    def write_config(self, endpoint=SOURCE, **overrides):
        settings = {"url": self.url, "allowedNetworks": ["127.0.0.1/32"],
                    "bearerEnv": "FORWARDING_TEST_TOKEN", "caFile": str(self.ca), "timeoutSeconds": 1}
        settings.update(overrides)
        self.config.write_text(json.dumps({"version": 1, "endpoints": {endpoint: settings}}), encoding="utf-8")
        self.config.chmod(0o600)
        return self.config

    def test_posts_exact_bytes_and_only_service_headers(self):
        target = load_forwarding(self.write_config())[SOURCE]
        with patch.object(http.client.HTTPResponse, "read", side_effect=AssertionError("Forwarding read the response body")):
            self.assertEqual(202, target.send(BODY, "decision-123"))
        self.assertEqual(1, len(self.received))
        path, headers, body = self.received[0]
        self.assertEqual("/internal/order", path)
        self.assertEqual(BODY, body)
        self.assertEqual("application/json", headers["Content-Type"])
        self.assertEqual(f"Bearer {TOKEN}", headers["Authorization"])
        self.assertEqual("decision-123", headers["Idempotency-Key"])
        self.assertNotIn("Cookie", headers)

    def test_reports_redirect_without_following_it(self):
        self.response_status = 307
        target = load_forwarding(self.write_config())[SOURCE]
        self.assertEqual(307, target.send(BODY, "decision-123"))
        self.assertEqual(["/internal/order"], [path for path, *_ in self.received])

    def test_missing_terminal_status_is_unknown_and_does_not_retry(self):
        self.response_status = None
        target = load_forwarding(self.write_config())[SOURCE]
        with self.assertRaises(ForwardingUnavailable):
            target.send(BODY, "decision-123")
        self.assertEqual(1, len(self.received))

    def test_response_header_deadline_does_not_retry(self):
        self.response_status = None
        self.hold_response = threading.Event()
        self.addCleanup(self.hold_response.set)
        target = load_forwarding(self.write_config())[SOURCE]
        started = time.monotonic()
        with self.assertRaises(ForwardingUnavailable):
            target.send(BODY, "decision-123")
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(1, len(self.received))

    def test_untrusted_certificate_blocks_post(self):
        config = self.write_config()
        document = json.loads(config.read_text(encoding="utf-8"))
        del document["endpoints"][SOURCE]["caFile"]
        config.write_text(json.dumps(document), encoding="utf-8")
        target = load_forwarding(config)[SOURCE]
        with self.assertRaises(ForwardingUnavailable):
            target.send(BODY, "decision-123")
        self.assertEqual([], self.received)

    def test_requires_private_file_and_refuses_symlink(self):
        config = self.write_config()
        symlink = config.with_name("symlink.json")
        symlink.symlink_to(config)
        with self.assertRaises(ValueError):
            load_forwarding(symlink)
        config.chmod(0o640)
        with self.assertRaises(ValueError):
            load_forwarding(config)

    def test_rejects_wildcards_unpinned_destinations_and_missing_token(self):
        for changes in ({"endpoint": "/verify/*"}, {"url": self.url.replace("https://", "http://")},
                        {"url": self.url + "?unexpected=1"}, {"allowedNetworks": ["10.0.0.0/8"]},
                        {"bearerEnv": "FORWARDING_TEST_TOKEN_MISSING"}, {"headers": {"Cookie": "caller"}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                load_forwarding(self.write_config(**changes))
        self.assertEqual([], self.received)

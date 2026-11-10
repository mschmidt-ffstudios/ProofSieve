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
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from proofsieve.checks import CheckRegistry, CheckUnavailable, load_check_registry


DOCUMENT = b'{"order":"ORDER-1042","amount":800}'


def base64_text(raw):
    return base64.b64encode(raw).decode("ascii")


def make_certificate(label, key, *, issuer=None, issuer_key=None, ca=False, expired=False, ip=None,
                     timestamping=False):
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
    builder = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer.subject if issuer is not None else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now + timedelta(days=-1 if expired else 2))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ip is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip)]), critical=False)
    if timestamping:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    return builder.sign(issuer_key or key, hashes.SHA256())


def pem(certificate):
    return certificate.public_bytes(Encoding.PEM).decode("ascii")


def signer_config(signer_id, certificate, kind="local", **options):
    return {"id": signer_id, "kind": kind, "certificatePem": pem(certificate), **options}


def proof(signer_id, key, document=DOCUMENT):
    return {"signer": signer_id, "signature": base64_text(key.sign(document, ec.ECDSA(hashes.SHA256())))}


class StubConnector:
    def __init__(self, kind, respond):
        self.kind = kind
        self.profile_version = "test-v1"
        self.respond = respond
        self.requests = []

    def post(self, body, media_type, accept, *, deadline):
        self.requests.append((body, media_type, accept))
        return self.respond(body)


class ExternalCheckTests(unittest.TestCase):
    def setUp(self):
        self.keys = {name: ec.generate_private_key(ec.SECP256R1()) for name in ("alice", "ben", "cem")}
        self.certificates = {name: make_certificate(name, key) for name, key in self.keys.items()}

    def test_local_threshold_uses_distinct_signers_and_identical_document(self):
        profile = {"threshold": 2, "signers": [
            signer_config(name, cert) for name, cert in self.certificates.items()
        ]}
        verify = CheckRegistry().compile(profile)
        alice = proof("alice", self.keys["alice"])
        ben = proof("ben", self.keys["ben"])
        other_order = proof("cem", self.keys["cem"], b'{"order":"ORDER-1043","amount":800}')
        allowed = verify({"document": base64_text(DOCUMENT), "proofs": [alice, ben, other_order]})
        self.assertEqual(allowed.outcome, "passed")
        self.assertEqual(allowed.facts, {
            "validSignerCount": 2, "requiredSignerCount": 2, "thresholdMet": True,
            "documentSha256": hashlib.sha256(DOCUMENT).hexdigest(),
        })
        self.assertEqual(allowed.evidence[-1]["reason"], "signature_invalid")
        rejected = verify({"document": base64_text(DOCUMENT), "proofs": [alice, other_order]})
        self.assertEqual(rejected.outcome, "failed")
        self.assertEqual(rejected.facts["validSignerCount"], 1)
        with self.assertRaisesRegex(ValueError, "distinct"):
            verify({"document": base64_text(DOCUMENT), "proofs": [alice, alice]})

    def test_local_expired_certificate_is_refused(self):
        certificate = make_certificate("expired", self.keys["alice"], expired=True)
        verify = CheckRegistry().compile({"threshold": 1, "signers": [signer_config("alice", certificate)]})
        result = verify({"document": base64_text(DOCUMENT), "proofs": [proof("alice", self.keys["alice"])]})
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.evidence[0]["reason"], "signer_certificate_outside_validity")

    def test_same_key_with_second_identity_is_rejected_at_configuration(self):
        alternative_certificate = make_certificate("ben", self.keys["alice"])
        with self.assertRaisesRegex(ValueError, "distinct ids and public keys"):
            CheckRegistry().compile({"threshold": 2, "signers": [
                signer_config("alice", self.certificates["alice"]),
                signer_config("ben", alternative_certificate),
            ]})

    def test_document_bypass_and_unconfigured_connector_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unconfigured connector"):
            CheckRegistry().compile({"threshold": 1, "signers": [
                signer_config("alice", self.certificates["alice"], "dss",
                              connector="unconfigured", format="pades"),
            ]})
        verify = CheckRegistry().compile({"threshold": 1, "signers": [
            signer_config("alice", self.certificates["alice"]),
        ]})
        for payload in ({"thresholdMet": True}, {"document": "ZX==", "proofs": []},
                        {"document": base64_text(DOCUMENT), "proofs": [{"signer": "other"}]}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                verify(payload)

    def test_external_report_binding_nonce_and_provenance(self):
        first_reply = None

        def respond(raw):
            nonlocal first_reply
            sent = json.loads(raw)
            self.assertEqual(sent["format"], "cades-detached")
            self.assertEqual(sent["documentSha256"], hashlib.sha256(DOCUMENT).hexdigest())
            self.assertEqual(sent["signatureSha256"], hashlib.sha256(b"CMS signature").hexdigest())
            self.assertEqual(sent["certificateSha256"], self.certificates["alice"].fingerprint(hashes.SHA256()).hex())
            if first_reply is None:
                first_reply = json.dumps({key: sent[key] for key in (
                    "version", "nonce", "documentSha256", "certificateSha256", "signatureSha256"
                )} | {"verdict": "passed", "reportId": "report-123"}).encode()
            return first_reply

        connector = StubConnector("dss", respond)
        verify = CheckRegistry({"dss": connector}).compile({"threshold": 1, "signers": [
            signer_config("alice", self.certificates["alice"], "dss", connector="dss", format="cades-detached")
        ]})
        payload = {"document": base64_text(DOCUMENT),
                   "proofs": [{"signer": "alice", "signature": base64_text(b"CMS signature")}]}
        result = verify(payload)
        self.assertEqual(result.outcome, "passed")
        self.assertEqual(result.evidence, ({"signer": "alice", "kind": "dss", "format": "cades-detached", "outcome": "passed",
                                            "reason": "connector_verdict", "connector": "dss",
                                            "connectorProfile": "test-v1", "reportId": "report-123"},))
        replay = verify(payload)
        self.assertEqual(replay.outcome, "indeterminate")
        self.assertEqual(replay.evidence[0]["reason"], "connector_response_mismatch")
        self.assertNotIn("reportId", replay.evidence[0])

    def test_extended_format_proof_shapes_and_timestamp_facts(self):
        def echo(raw):
            sent = json.loads(raw)
            bindings = {key: value for key, value in sent.items() if key not in {"format", "document", "signature"}}
            return json.dumps({**bindings, "verdict": "passed", "reportId": "fixture"}).encode()

        connector = StubConnector("dss", echo)
        registry = CheckRegistry({"dss": connector})
        tsa = make_certificate("tsa", self.keys["alice"], timestamping=True)
        timestamp_config = signer_config("alice", tsa, "dss", connector="dss", format="rfc3161")
        for fmt in ("xades-detached", "jades-detached", "cbades-detached", "asic-s", "asic-e", "rfc3161"):
            embedded = fmt.startswith("asic-")
            signer = timestamp_config if fmt == "rfc3161" else signer_config(
                "alice", self.certificates["alice"], "dss", connector="dss", format=fmt
            )
            verify = registry.compile({"threshold": 1, "signers": [signer]})
            bare = {"signer": "alice"}
            signed = {**bare, "signature": base64_text(b"proof")}
            with self.subTest(format=fmt):
                with self.assertRaises(ValueError):
                    verify({"document": base64_text(DOCUMENT), "proofs": [signed if embedded else bare]})
                result = verify({"document": base64_text(DOCUMENT), "proofs": [bare if embedded else signed]})
                request = json.loads(connector.requests[-1][0])
                self.assertEqual(request["format"], fmt)
                self.assertEqual("signatureSha256" in request, not embedded)
                self.assertEqual(result.outcome, "passed")
                if fmt == "rfc3161":
                    self.assertEqual(result.facts, {
                        "timestampVerified": True, "documentSha256": hashlib.sha256(DOCUMENT).hexdigest(),
                    })
                else:
                    self.assertEqual(result.facts["validSignerCount"], 1)

        with self.assertRaisesRegex(ValueError, "timestamp signing"):
            registry.compile({"threshold": 1, "signers": [
                {**timestamp_config, "certificatePem": pem(self.certificates["alice"])},
            ]})
        with self.assertRaisesRegex(ValueError, "exactly one timestamp authority"):
            registry.compile({"threshold": 2, "signers": [
                timestamp_config, signer_config("ben", self.certificates["ben"]),
            ]})

    def test_optional_third_dependency_failure_does_not_erase_two_confirmed_signers(self):
        def unavailable(_body):
            raise CheckUnavailable("connector_unavailable")

        verify = CheckRegistry({"dss": StubConnector("dss", unavailable)}).compile({"threshold": 2, "signers": [
            signer_config("alice", self.certificates["alice"]),
            signer_config("ben", self.certificates["ben"]),
            signer_config("cem", self.certificates["cem"], "dss", connector="dss", format="pades"),
        ]})
        alice = proof("alice", self.keys["alice"])
        ben = proof("ben", self.keys["ben"])
        cem = {"signer": "cem"}
        self.assertEqual(verify({"document": base64_text(DOCUMENT), "proofs": [alice, ben, cem]}).outcome,
                         "passed")
        self.assertEqual(verify({"document": base64_text(DOCUMENT), "proofs": [alice, cem]}).outcome,
                         "indeterminate")
        self.assertEqual(verify({"document": base64_text(DOCUMENT), "proofs": [cem]}).outcome,
                         "failed")

    def test_ocsp_checks_signature_binding_and_freshness_after_local_signature(self):
        ca_key = ec.generate_private_key(ec.SECP256R1())
        issuer = make_certificate("offline test CA", ca_key, ca=True)
        certificate = make_certificate("alice", self.keys["alice"], issuer=issuer, issuer_key=ca_key)
        other = make_certificate("ben", self.keys["ben"], issuer=issuer, issuer_key=ca_key)
        status = ocsp.OCSPCertStatus.GOOD
        stale = wrong_nonce = wrong_cert = wrong_key = False

        def respond(raw):
            request = ocsp.load_der_ocsp_request(raw)
            self.assertEqual(request.serial_number, certificate.serial_number)
            nonce = request.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
            now = datetime.now(timezone.utc)
            response = (ocsp.OCSPResponseBuilder()
                    .add_response(cert=other if wrong_cert else certificate, issuer=issuer,
                                  algorithm=hashes.SHA256(), cert_status=status,
                                  this_update=now - timedelta(days=2 if stale else 0, seconds=2),
                                  next_update=now + timedelta(hours=1),
                                  revocation_time=now if status is ocsp.OCSPCertStatus.REVOKED else None,
                                  revocation_reason=None)
                    .responder_id(ocsp.OCSPResponderEncoding.HASH, issuer)
                    .add_extension(x509.OCSPNonce(b"x" * 24 if wrong_nonce else nonce), critical=False)
                    .sign(ca_key, hashes.SHA256()))
            encoded = response.public_bytes(Encoding.DER)
            if wrong_key:
                signature = response.signature
                invalid_signature = signature[:-1] + bytes([signature[-1] ^ 1])
                encoded = encoded.replace(signature, invalid_signature, 1)
            return encoded

        connector = StubConnector("ocsp", respond)
        verify = CheckRegistry({"status": connector}).compile({"threshold": 1, "signers": [
            signer_config("alice", certificate, "ocsp", connector="status", issuerCertificatePem=pem(issuer))
        ]})
        valid = {"document": base64_text(DOCUMENT), "proofs": [proof("alice", self.keys["alice"])]}
        invalid = {"document": base64_text(DOCUMENT), "proofs": [proof("alice", self.keys["ben"])]}
        self.assertEqual(verify(invalid).evidence[0]["reason"], "signature_invalid")
        self.assertFalse(connector.requests)
        self.assertEqual(verify(valid).outcome, "passed")
        status = ocsp.OCSPCertStatus.REVOKED
        self.assertEqual(verify(valid).evidence[0]["reason"], "certificate_revoked")
        status = ocsp.OCSPCertStatus.UNKNOWN
        self.assertEqual(verify(valid).outcome, "indeterminate")
        status = ocsp.OCSPCertStatus.GOOD
        stale = True
        self.assertEqual(verify(valid).evidence[0]["reason"], "status_response_stale")
        stale, wrong_nonce = False, True
        self.assertEqual(verify(valid).evidence[0]["reason"], "status_response_mismatch")
        wrong_nonce, wrong_cert = False, True
        self.assertEqual(verify(valid).evidence[0]["reason"], "status_response_mismatch")
        wrong_cert, wrong_key = False, True
        self.assertEqual(verify(valid).evidence[0]["reason"], "status_response_invalid")
        malformed = x509.DuplicateExtension("duplicate nonce", x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"))
        with patch("proofsieve.checks._ocsp_reply", side_effect=malformed):
            result = verify(valid)
            self.assertEqual((result.outcome, result.evidence[0]["reason"]),
                             ("indeterminate", "status_response_invalid"))

    def test_connector_configuration_rejects_network_escape_and_public_files(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TEST_DSS_AUTH": "x" * 32}):
            path = Path(directory) / "connectors.json"
            config = {"kind": "dss", "url": "https://127.0.0.1:9090/validate",
                      "allowedNetworks": ["127.0.0.1/32"], "bearerEnv": "TEST_DSS_AUTH"}

            def write(values):
                path.write_text(json.dumps({"version": 1, "connectors": {"validation": values}}))

            write(config)
            path.chmod(0o600)
            self.assertIsInstance(load_check_registry(path), CheckRegistry)
            for update in ({"url": "http://127.0.0.1/validate"},
                           {"url": "https://127.0.0.1/../validate"},
                           {"url": "https://127.0.0.1/validate?other=1"},
                           {"url": "https://127.0.0.1/validate#frag"},
                           {"allowedNetworks": ["10.0.0.1/32"]},
                           {"allowedNetworks": ["0.0.0.0/0"]}, {"bearerEnv": None}):
                write(config | update)
                with self.subTest(update=update), self.assertRaises(ValueError):
                    load_check_registry(path)
            write(config)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private operator file"):
                load_check_registry(path)

    def test_https_transport_authenticates_peer_and_does_not_follow_redirects(self):
        token = "test-connector-token-with-sufficient-length"
        observed = []
        mode = "valid"

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                observed.append((self.path, self.headers.get("Authorization")))
                if mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", "/other")
                    self.end_headers()
                    return
                if mode == "slow-headers":
                    try:
                        self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                        for _ in range(12):
                            time.sleep(0.15)
                            self.connection.sendall(b"x")
                    except OSError:
                        pass
                    return
                sent = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                response = json.dumps({
                    key: sent[key] for key in ("version", "nonce", "documentSha256", "certificateSha256")
                } | {"verdict": "passed", "reportId": "test-report"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                if mode == "ambiguous-length":
                    self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *_args):
                pass

        host_ip = ipaddress.ip_address("127.0.0.1")
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca = make_certificate("transport CA", ca_key, ca=True)
        tls_key = ec.generate_private_key(ec.SECP256R1())
        tls = make_certificate("transport", tls_key, issuer=ca, issuer_key=ca_key, ip=host_ip)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TEST_DSS_AUTH": token}):
            config_path, ca_path, cert_path, key_path = [
                Path(directory) / name for name in ("registry.json", "ca.pem", "cert.pem", "key.pem")
            ]
            ca_path.write_text(pem(ca))
            cert_path.write_text(pem(tls))
            key_path.write_bytes(tls_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            with ThreadingHTTPServer((str(host_ip), 0), Handler) as server:
                server.socket = context.wrap_socket(server.socket, server_side=True)
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                try:
                    config = {"kind": "dss", "url": f"https://{host_ip}:{server.server_port}/verify",
                              "allowedNetworks": ["127.0.0.1/32"], "bearerEnv": "TEST_DSS_AUTH",
                              "timeoutSeconds": 1}
                    profile = {"threshold": 1, "signers": [
                        signer_config("alice", self.certificates["alice"], "dss", connector="dss", format="pades")
                    ]}
                    payload = {"document": base64_text(DOCUMENT), "proofs": [{"signer": "alice"}]}

                    def load(settings):
                        config_path.write_text(json.dumps({"version": 1, "connectors": {"dss": settings}}))
                        config_path.chmod(0o600)
                        return load_check_registry(config_path).compile(profile)

                    self.assertEqual(load(config)(payload).evidence[0]["reason"], "connector_unavailable")
                    self.assertFalse(observed)
                    verify = load(config | {"caFile": str(ca_path)})
                    self.assertEqual(verify(payload).outcome, "passed")
                    for invalid in ("redirect", "ambiguous-length"):
                        mode = invalid
                        with self.subTest(mode=mode):
                            outcome = verify(payload)
                            self.assertEqual(outcome.outcome, "indeterminate")
                            self.assertEqual(outcome.evidence[0]["reason"], "connector_response_invalid")
                    mode = "slow-headers"
                    start = time.monotonic()
                    self.assertEqual(verify(payload).evidence[0]["reason"], "connector_unavailable")
                    self.assertLess(time.monotonic() - start, 1.75)
                    self.assertEqual(observed, [("/verify", "Bearer " + token)] * 4)
                finally:
                    server.shutdown()
                    worker.join()


if __name__ == "__main__":
    unittest.main()

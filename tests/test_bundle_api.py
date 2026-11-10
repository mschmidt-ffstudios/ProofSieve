"""Exercise cryptographically verified proof bundles and export over the Guard API."""

import base64
import hashlib
import http.client
import json
import secrets
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofsieve.access import AccessPolicy
from proofsieve.evidence import EvidenceStore, verify_evidence_export
from proofsieve.guard import DEFAULT_RULE, Guard
from proofsieve.server import Handler, LoopbackHTTPServer


ENDPOINT = "/verify/business-order"
OPERATION = "order-1042"
ISSUER = "https://issuer.example.test"
CONTEXT = "https://www.w3.org/ns/credentials/v2"


def encode(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sign(key, kind, payload):
    signing_input = ".".join(encode(json.dumps(part, separators=(",", ":")).encode())
                             for part in ({"alg": "ES256", "typ": kind}, payload))
    r, s = utils.decode_dss_signature(key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return signing_input + "." + encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def pem(key):
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


class BundleAPITest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        work = Path(directory.name)
        self.tokens = {name: secrets.token_urlsafe(32) for name in ("caller", "another", "other", "admin")}
        auth = work / "auth.json"
        auth.write_text(json.dumps({"version": 1, "principals": [
            {"id": name, "role": "admin" if name == "admin" else "verifier",
             "tokenSha256": hashlib.sha256(token.encode()).hexdigest(),
             "endpoints": ["/verify" if name == "other" else ENDPOINT]}
            for name, token in self.tokens.items()
        ]}))
        auth.chmod(0o600)
        self.store = EvidenceStore(work / "evidence.db")
        self.guard = Guard(work / "rules.json", {}, evidence=self.store)
        self.org_key, self.mandate_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
        self.rule = {
            **DEFAULT_RULE,
            "responseMode": "decision",
            "policy": {
                **DEFAULT_RULE["policy"],
                "permission": [{**DEFAULT_RULE["policy"]["permission"][0], "constraint": [
                    {"leftOperand": "field:org_status", "operator": "eq", "rightOperand": "active"},
                    {"leftOperand": "field:mandate_amount", "operator": "lteq", "rightOperand": 10_000},
                ]}],
            },
            "bundle": {
                "items": {
                    "org": {
                        "credential": {"format": "sd-jwt", "issuer": ISSUER, "publicKeyPem": pem(self.org_key)},
                        "credentialType": "urn:example:organization",
                        "fields": ["organization", "status"],
                    },
                    "mandate": {
                        "credential": {
                            "format": "jwt-vc", "issuer": ISSUER, "publicKeyPem": pem(self.mandate_key),
                            "credentialType": "PurchaseMandate", "contexts": [CONTEXT],
                            "claims": {
                                "organization": {"path": ["organization"], "type": "string"},
                                "operation": {"path": ["operation"], "type": "string"},
                                "amount": {"path": ["amount"], "type": "integer"},
                            },
                        },
                        "fields": ["organization", "operation", "amount"],
                    },
                },
                "bindings": [["org_organization", "mandate_organization"], ["mandate_operation", "$operationId"]],
            },
        }
        self.guard.update(self.rule, ENDPOINT)
        self.server = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
        self.server.access_policy = AccessPolicy.load(auth)
        self.server.guard = self.guard
        self.server.credential_checks = {}
        self.server.evidence_export = True
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)

    def proofs(self, *, amount=9_999, company="company-A", operation=OPERATION, org_type="urn:example:organization"):
        organization = sign(self.org_key, "dc+sd-jwt", {
            "iss": ISSUER, "vct": org_type, "exp": int(time.time()) + 300,
            "organization": "company-A", "status": "active", "private": "demo-only-secret-claim",
        }) + "~"
        mandate = sign(self.mandate_key, "vc+jwt", {
            "@context": [CONTEXT], "type": ["VerifiableCredential", "PurchaseMandate"], "issuer": ISSUER,
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": {"organization": company, "operation": operation, "amount": amount},
        })
        return {"org": organization, "mandate": mandate}

    def request(self, path, body=None, user="caller"):
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if user:
            headers["Authorization"] = f"Bearer {self.tokens[user]}"
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request("POST" if body is not None else "GET", path,
                               json.dumps(body) if body is not None else None, headers)
            with connection.getresponse() as reply:
                return reply.status, json.loads(reply.read())
        finally:
            connection.close()

    def verify(self, proofs, *, operation=OPERATION):
        return self.request(ENDPOINT, {"data": proofs, "operationId": operation})

    def test_verified_items_must_bind_to_each_other_and_the_operation(self):
        valid = self.proofs()
        for proof, operation, expected in (
            (valid, OPERATION, "policy_allowed"),
            (self.proofs(amount=10_001), OPERATION, "policy_denied"),
            (self.proofs(company="company-B"), OPERATION, "check_failed"),
            (self.proofs(org_type="urn:example:other"), OPERATION, "check_failed"),
            (valid, "another-order", "check_failed"),
            ({**valid, "mandate": {"amount": 1}}, OPERATION, "check_failed"),
        ):
            with self.subTest(operation=operation, expected=expected):
                status, decision = self.verify(proof, operation=operation)
                self.assertEqual((status, decision["reason"]), (200, expected))
                self.assertEqual(decision["valid"], expected == "policy_allowed")
        self.assertEqual(self.verify({"org": valid["org"]})[0], 400)
        with self.assertRaisesRegex(ValueError, "linked to the operation"):
            self.guard.update({**self.rule, "bundle": {
                **self.rule["bundle"], "bindings": [["org_organization", "mandate_organization"]],
            }}, ENDPOINT)

    def test_export_requires_original_caller_and_verifies_against_pinned_key(self):
        _, decision = self.verify(self.proofs())
        path = "/evidence?" + urlencode({"endpoint": ENDPOINT, "operationId": OPERATION,
                                         "decisionId": decision["decisionId"]})
        self.assertEqual(self.request(path, user=None)[0], 401)
        self.assertEqual(self.request(path, user="other")[0], 403)
        self.assertEqual(self.request(path, user="another")[0], 404)
        self.assertEqual(self.request(path + "&operationId=other")[0], 400)
        status, result = self.request(path)
        self.assertEqual(status, 200)
        self.assertTrue(verify_evidence_export(result, public_key=self.store.export_public_key))
        self.assertEqual(result["decisions"][0]["decisionId"], decision["decisionId"])
        self.assertEqual(
            {check["item"]: check["format"] for check in result["decisions"][0]["checks"]
             if check["kind"] == "bundle_item"},
            {"org": "dc+sd-jwt", "mandate": "jwt-vc"},
        )
        self.assertNotIn("demo-only-secret-claim", json.dumps(result))
        self.assertNotIn("company-A", json.dumps(result))
        result["decisions"][0]["outcome"] = "deny"
        self.assertFalse(verify_evidence_export(result, public_key=self.store.export_public_key))
        _, spec = self.request("/openapi.json")
        self.assertIn("get", spec["paths"]["/evidence"])
        operation = spec["paths"][ENDPOINT]["post"]
        fields = operation["requestBody"]["content"]["application/json"]["schema"]["properties"]["data"]
        self.assertEqual(set(fields["required"]), {"org", "mandate"})
        self.assertFalse(fields["additionalProperties"])

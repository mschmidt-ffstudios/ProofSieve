import base64
import copy
import json
import random
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofsieve.guard import Guard, ReadOnlyEndpointError, preview_rule


SD_JWT = "/verify/demo/eudi-sd-jwt"
MDOC = "/verify/demo/eudi-mdoc"
FIXTURES = Path(__file__).resolve().parents[1] / "examples" / "signed" / "guard.json"


class SignedCredentialsTest(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name) / "rules.json"
        self.demos = json.loads(FIXTURES.read_text(encoding="utf-8"))
        self.guard = Guard(self.state, self.demos)
        clock = patch("proofsieve.guard.datetime")
        self.clock = clock.start()
        self.addCleanup(clock.stop)
        self.clock.now.return_value = datetime(2026, 11, 6, tzinfo=timezone.utc)

    def sample(self, endpoint, case="valid"):
        return self.demos[endpoint]["credentialExamples"][case]

    def assert_credential_denied(self, data, endpoint, reason=None):
        status, body = self.guard.verify(data, endpoint)
        self.assertEqual(status, 403)
        self.assertEqual(body["stage"], "credential")
        self.assertEqual(body["code"], "credential_rejected")
        if reason:
            self.assertIn(reason, body["error"])

    def test_originals_and_tampered_samples(self):
        for endpoint, reason in ((SD_JWT, "disclosure"), (MDOC, "signature")):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.guard.verify(self.sample(endpoint), endpoint), (200, True))
                self.assert_credential_denied(self.sample(endpoint, "tampered"), endpoint, reason)

    def test_historical_upstream_mdoc_vector_still_verifies_at_its_fixture_date(self):
        historical = json.loads(FIXTURES.with_name("mdoc-upstream.json").read_text(encoding="utf-8"))
        guard = Guard(self.state, {MDOC: historical})
        self.assertEqual(guard.verify(historical["credentialExamples"]["valid"], MDOC), (200, True))
        self.assertEqual(guard.verify(historical["credentialExamples"]["tampered"], MDOC)[0], 403)

    def test_seeded_signature_mutations_are_rejected(self):
        generator = random.Random(1042)
        jwt, disclosures = self.sample(SD_JWT).split("~", 1)
        header, claims, signature = jwt.split(".")
        jwt_signature = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        encoded_mdoc = self.sample(MDOC)
        mdoc = cbor2.loads(base64.urlsafe_b64decode(encoded_mdoc + "=" * (-len(encoded_mdoc) % 4)))
        mdoc_signature = mdoc["issuerAuth"][3]
        for _ in range(128):
            for endpoint, original in ((SD_JWT, jwt_signature), (MDOC, mdoc_signature)):
                changed = bytearray(original)
                changed[generator.randrange(len(changed))] ^= 1 << generator.randrange(8)
                if endpoint == SD_JWT:
                    mutated = base64.urlsafe_b64encode(changed).decode().rstrip("=")
                    specimen = f"{header}.{claims}.{mutated}~{disclosures}"
                else:
                    mdoc["issuerAuth"][3] = bytes(changed)
                    specimen = base64.urlsafe_b64encode(cbor2.dumps(mdoc)).decode().rstrip("=")
                self.assert_credential_denied(specimen, endpoint)

    def test_preview_traces_only_verified_claims(self):
        for endpoint in (SD_JWT, MDOC):
            with self.subTest(endpoint=endpoint):
                rule = self.demos[endpoint]["rule"]
                accepted = preview_rule(rule, self.sample(endpoint))
                self.assertTrue(accepted["credentialVerified"])
                self.assertTrue(accepted["trace"]["matched"])
                denied = preview_rule(rule, self.sample(endpoint, "tampered"))
                self.assertEqual(denied["stage"], "credential")
                self.assertFalse(denied["credentialVerified"])
                self.assertNotIn("trace", denied)
                self.assertFalse(self.state.exists())

    def test_caller_supplied_claims_cannot_bypass_crypto(self):
        self.assert_credential_denied({"vct": "urn:eudi:pid:de:1", "family_name": "Mustermann"}, SD_JWT)
        self.assert_credential_denied({"docType": "eu.europa.ec.eudi.pid.1", "issuing_country": "GR"}, MDOC)
        self.assertEqual(self.guard.verify({"status": "active"}), (200, True))

    def test_valid_signed_token_without_policy_claim_is_denied_by_odrl(self):
        parts = self.sample(SD_JWT).split("~")
        parts.pop(-2)  # Omit the family_name disclosure without changing the signed issuer JWT.
        self.assertEqual(self.guard.verify("~".join(parts), SD_JWT), (403, False))

    def test_unauthenticated_mdoc_item_is_rejected_before_odrl(self):
        data = self.sample(MDOC)
        document = cbor2.loads(base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)))
        items = document["nameSpaces"]["eu.europa.ec.eudi.pid.1"]
        for index, encoded in enumerate(items):
            item = cbor2.loads(encoded.value)
            if item["elementIdentifier"] == "issuing_country":
                item["elementValue"] = "DE"
                items[index] = cbor2.CBORTag(24, cbor2.dumps(item))
                break
        raw = base64.urlsafe_b64encode(cbor2.dumps(document)).decode().rstrip("=")
        self.assert_credential_denied(raw, MDOC, "digest")

    def test_pinned_key_is_used_instead_of_credential_key_material(self):
        key = ec.generate_private_key(ec.SECP256R1()).public_key()
        pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        for endpoint in (SD_JWT, MDOC):
            with self.subTest(endpoint=endpoint):
                rule = copy.deepcopy(self.demos[endpoint]["rule"])
                rule["credential"]["publicKeyPem"] = pem
                self.guard.update(rule, "/verify/wrong-key")
                self.assert_credential_denied(self.sample(endpoint), "/verify/wrong-key", "signature")

    def test_demo_routes_are_read_only_and_separate_from_persisted_rules(self):
        self.assertTrue(self.guard.describe(MDOC)["readOnly"])
        with self.assertRaises(ReadOnlyEndpointError):
            self.guard.update(self.demos[MDOC]["rule"], MDOC)
        self.assertFalse(self.state.exists())
        self.guard.update(self.demos[MDOC]["rule"], "/verify/customer-mdoc")
        self.assertNotIn(MDOC, json.loads(self.state.read_text())["rules"])
        self.assertEqual(Guard(self.state, self.demos).verify(self.sample(MDOC), "/verify/customer-mdoc"), (200, True))

    def test_signed_validity_window_is_enforced(self):
        self.clock.now.return_value = datetime(2040, 1, 1, tzinfo=timezone.utc)
        self.assert_credential_denied(self.sample(SD_JWT), SD_JWT, "expired")
        self.assert_credential_denied(self.sample(MDOC), MDOC, "validity")

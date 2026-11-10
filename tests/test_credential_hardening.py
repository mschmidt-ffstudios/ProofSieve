import base64
import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from proofsieve.mdoc import verify_mdoc
from proofsieve.sd_jwt import verify_sd_jwt


NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)
ISSUER = "https://issuer.example.invalid"
DOC_TYPE = "org.example.supplier"
FOREIGN_NAMESPACE = "org.example.other"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign(private_key, message):
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class CredentialHardeningTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())

    def sd_jwt(self, payload, *, key=None, extra_header=None):
        header = {"alg": "ES256", "typ": "dc+sd-jwt", **(extra_header or {})}
        claims = {"iss": ISSUER, "vct": DOC_TYPE, "exp": int(NOW.timestamp()) + 3600, **payload}
        encoded_claims = json.dumps(claims).encode()
        return self.sd_jwt_raw(encoded_claims, header, key or self.key)

    def sd_jwt_raw(self, claims, header, key):
        message = f"{b64url(json.dumps(header).encode())}.{b64url(claims)}"
        return f"{message}.{b64url(sign(key, message.encode()))}~"

    def verify_jwt(self, token):
        return verify_sd_jwt(token, self.key.public_key(), issuer=ISSUER, now=NOW)

    def mdoc(self, *, validity=None, extra_digests=None, relocate_role=False):
        def item(digest_id, name, value):
            return cbor2.CBORTag(24, cbor2.dumps({
                "digestID": digest_id,
                "random": bytes([digest_id]) * 16,
                "elementIdentifier": name,
                "elementValue": value,
            }))

        namespaces = {
            DOC_TYPE: [item(0, "role", b"admin"), item(1, "docType", "org.example.fake")],
            FOREIGN_NAMESPACE: [item(0, "role", "admin")],
        }
        digest_table = {
            namespace: {index: hashlib.sha256(cbor2.dumps(entry)).digest()
                        for index, entry in enumerate(entries)}
            for namespace, entries in namespaces.items()
        }
        mso = {
            "version": "1.0",
            "digestAlgorithm": "SHA-256",
            "valueDigests": {**digest_table, **(extra_digests or {})},
            "docType": DOC_TYPE,
            "validityInfo": validity or {"signed": NOW, "validFrom": NOW, "validUntil": NOW + timedelta(hours=1)},
        }
        protected = cbor2.dumps({1: -7})
        payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso)))
        signature = sign(self.key, cbor2.dumps(["Signature1", protected, b"", payload]))
        if relocate_role:
            namespaces[DOC_TYPE][0] = namespaces[FOREIGN_NAMESPACE][0]
        return b64url(cbor2.dumps({"issuerAuth": [protected, {}, payload, signature], "nameSpaces": namespaces}))

    def test_sd_jwt_rejects_unpaired_surrogates_and_accepts_valid_unicode(self):
        for claims in ({"subject": "\ud800"}, {"\udfff": "example"}, {"nested": [{"key": "\ud800"}]}):
            with self.subTest(claims=claims), self.assertRaisesRegex(ValueError, "invalid Unicode"):
                self.verify_jwt(self.sd_jwt(claims))
        self.assertEqual(self.verify_jwt(self.sd_jwt({"subject": "Grüße 🌍"}))["subject"], "Grüße 🌍")

    def test_sd_jwt_rejects_numeric_rounding_and_preserves_integral_exponents(self):
        claims = {"iss": ISSUER, "vct": DOC_TYPE, "exp": int(NOW.timestamp()) + 3600, "score": "NUMBER"}
        header = {"alg": "ES256", "typ": "dc+sd-jwt"}
        for text in ("17.99999999999999999999", "1e-999", "9" * 513):
            raw = json.dumps(claims).replace('"NUMBER"', text).encode()
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "invalid or ambiguous JSON"):
                self.verify_jwt(self.sd_jwt_raw(raw, header, self.key))
        raw = json.dumps(claims).replace('"NUMBER"', "1e25").encode()
        score = self.verify_jwt(self.sd_jwt_raw(raw, header, self.key))["score"]
        self.assertIs(type(score), int)
        self.assertEqual(score, 10 ** 25)

    def test_sd_jwt_uses_pinned_key_and_rejects_holder_proof(self):
        other_key = ec.generate_private_key(ec.SECP256R1())
        injected = self.sd_jwt({}, key=other_key, extra_header={"x5c": ["untrusted"]})
        with self.assertRaisesRegex(ValueError, "issuer signature is invalid"):
            self.verify_jwt(injected)
        issuer_credential = self.sd_jwt({})
        with self.assertRaisesRegex(ValueError, "without a holder proof"):
            self.verify_jwt(issuer_credential + "header.payload.signature")

    def test_mdoc_rejects_invalid_undisclosed_digest_tables(self):
        for entries in ({0: b"short"}, {True: b"x" * 32}, [], {}):
            with self.subTest(entries=entries), self.assertRaisesRegex(ValueError, "signed namespace digest table"):
                raw = self.mdoc(extra_digests={"org.example.undisclosed": entries})
                verify_mdoc(raw, self.key.public_key(), now=NOW)

    def test_mdoc_rejects_contradictory_validity_and_naive_clock(self):
        for validity in (
            {"signed": NOW, "validFrom": NOW - timedelta(hours=1), "validUntil": NOW + timedelta(hours=1)},
            {"signed": NOW, "validFrom": NOW, "validUntil": NOW},
        ):
            with self.subTest(validity=validity), self.assertRaisesRegex(ValueError, "signed mdoc validity interval"):
                verify_mdoc(self.mdoc(validity=validity), self.key.public_key(), now=NOW)
        with self.assertRaisesRegex(ValueError, "verification time must have a time zone"):
            verify_mdoc(self.mdoc(), self.key.public_key(), now=NOW.replace(tzinfo=None))

    def test_mdoc_does_not_promote_foreign_namespace_or_coerce_role(self):
        claims = verify_mdoc(self.mdoc(), self.key.public_key(), now=NOW)
        self.assertEqual(claims["docType"], DOC_TYPE)
        self.assertNotIn("role", claims)
        self.assertEqual(claims["nameSpaces"][DOC_TYPE]["role"], "YWRtaW4")
        self.assertEqual(claims["nameSpaces"][FOREIGN_NAMESPACE]["role"], "admin")
        with self.assertRaisesRegex(ValueError, "does not match the signed MSO"):
            verify_mdoc(self.mdoc(relocate_role=True), self.key.public_key(), now=NOW)

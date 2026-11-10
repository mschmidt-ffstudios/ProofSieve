"""Verify trusted wallet projection and independent signed status checks."""

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import time
import unittest
import zlib

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from proofsieve.wallet_profile import WalletStatusUnavailable, compile_wallet_profile


_ISSUER = "https://issuer.example.test"
_STATUS_URI = "https://issuer.example.test/status"
_TYPE = "urn:eudi:pid:1"
_MDOC_TYPE = "eu.europa.ec.eudi.pid.1"


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _signature(key, message):
    r, s = utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _jwt(key, claims):
    header = _b64(json.dumps({"alg": "ES256", "typ": "statuslist+jwt"}).encode("ascii"))
    payload = _b64(json.dumps(claims).encode("ascii"))
    message = f"{header}.{payload}".encode("ascii")
    return message + b"." + _b64(_signature(key, message)).encode("ascii")


def _cwt(key, claims, kind):
    header = cbor2.dumps({1: -7, 16: "application/" + kind + "+cwt"})
    payload = cbor2.dumps(claims)
    signature = _signature(key, cbor2.dumps(["Signature1", header, b"", payload]))
    return cbor2.dumps(cbor2.CBORTag(18, [header, {}, payload, signature]))


def _mdoc(status):
    mso = cbor2.dumps({"docType": _MDOC_TYPE, "status": status})
    payload = cbor2.dumps(cbor2.CBORTag(24, mso))
    auth = cbor2.CBORTag(18, [cbor2.dumps({1: -7}), {}, payload, b"issuer signature verified by adapter"])
    return _b64(cbor2.dumps({"documents": [{"docType": _MDOC_TYPE, "issuerSigned": {"issuerAuth": auth}}]}))


class WalletProfileTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.file = Path(directory.name) / "status"
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "ProofSieve test issuer")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(self.key.public_key()).serial_number(1)
                       .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                       .sign(self.key, hashes.SHA256()))
        self.config = {
            "format": "dc+sd-jwt", "issuer": _ISSUER, "credentialType": _TYPE,
            "issuerChainPem": certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "intendedUseId": "age-check",
            "claims": {
                "adult": {"path": ["age_equal_or_over", "18"], "type": "boolean"},
                "country": {"path": ["nationalities", 0], "type": "string"},
            },
            "status": {"mode": "not-required"},
        }
        self.disclosed = {"iss": _ISSUER, "vct": _TYPE, "age_equal_or_over": {"18": True},
                          "nationalities": ["DE"], "irrelevant": "private"}
        self.now = int(time.time())

    def write_status(self, value):
        self.file.write_bytes(value)
        self.file.chmod(0o600)

    def strict_profile(self, mode):
        config = deepcopy(self.config)
        if mode == "cwt-file":
            config = self.mdoc_config()
        config["status"] = {
            "mode": mode, "uri": _STATUS_URI, "file": str(self.file), "maxAgeSeconds": 60,
            "publicKeyPem": self.key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii"),
        }
        return compile_wallet_profile(config)

    def mdoc_config(self):
        config = deepcopy(self.config)
        del config["issuer"]
        config.update(format="mso_mdoc", credentialType=_MDOC_TYPE,
                      claims={"adult": {"path": [_MDOC_TYPE, "age_over_18"], "type": "boolean"}})
        return config

    def mdoc_result(self):
        return [{"docType": _MDOC_TYPE, "attributes": {_MDOC_TYPE: {"age_over_18": True, "unused": "private"}}}]

    def test_dcql_and_projection_use_only_typed_configured_claims(self):
        profile = compile_wallet_profile(self.config)
        self.assertEqual(profile.dcql_query, {"credentials": [{
            "id": "credential", "format": "dc+sd-jwt", "meta": {"vct_values": [_TYPE]},
            "require_cryptographic_holder_binding": True,
            "claims": [{"path": ["age_equal_or_over", "18"]}, {"path": ["nationalities", 0]}],
        }]})
        self.assertEqual(profile.project(self.disclosed), {"adult": True, "country": "DE"})
        self.assertNotEqual(profile.version, compile_wallet_profile({**self.config, "intendedUseId": "other"}).version)
        for updates in ({"iss": "another"}, {"vct": "other"}, {"nationalities": []},
                        {"age_equal_or_over": {"18": 1}}, {"age_equal_or_over": {"18": "true"}}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                profile.project(self.disclosed | updates)

    def test_mdoc_requires_one_matching_document_and_configured_namespace(self):
        profile = compile_wallet_profile(self.mdoc_config())
        self.assertEqual(profile.dcql_query["credentials"][0]["meta"], {"doctype_value": _MDOC_TYPE})
        self.assertEqual(profile.project(self.mdoc_result()), {"adult": True})
        for reply in ([], self.mdoc_result() * 2, [{"docType": _MDOC_TYPE, "attributes": {"other": {}}}],
                      [{"docType": "unexpected", "attributes": {_MDOC_TYPE: {"age_over_18": True}}}]):
            with self.subTest(reply=reply), self.assertRaises(ValueError):
                profile.project(reply)

    def test_explicit_profile_trust_requirements(self):
        for key in ("issuerChainPem", "intendedUseId", "status", "issuer"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                compile_wallet_profile({k: v for k, v in self.config.items() if k != key})
        with self.assertRaises(ValueError):
            compile_wallet_profile({**self.config, "issuerChainPem": "not a certificate"})
        with self.assertRaises(ValueError):
            compile_wallet_profile({**self.config, "status": {"mode": "upstream-verified"}})

    def test_jwt_status_checks_pinned_uri_signature_freshness_and_bit(self):
        profile = self.strict_profile("jwt-file")
        result = {**self.disclosed, "status": {"status_list": {"uri": _STATUS_URI, "idx": 3}}}
        claims = {"sub": _STATUS_URI, "iat": self.now - 1, "exp": self.now + 60,
                  "status_list": {"bits": 1, "lst": _b64(zlib.compress(b"\x00"))}}
        with self.assertRaises(WalletStatusUnavailable):
            profile.project(result)
        self.write_status(_jwt(self.key, claims))
        self.assertEqual(profile.project(result), {"adult": True, "country": "DE"})
        with self.assertRaisesRegex(ValueError, "reference"):
            profile.project(self.disclosed | {"status": {"status_list": {"uri": _ISSUER, "idx": 3}}})
        with self.assertRaisesRegex(ValueError, "reference"):
            profile.project(self.disclosed)
        for changes in ({"sub": _ISSUER}, {"iat": self.now - 90}, {"exp": self.now - 1},
                        {"ttl": 1}, {"nbf": self.now + 60}):
            self.write_status(_jwt(self.key, claims | changes))
            with self.subTest(changes=changes), self.assertRaises(WalletStatusUnavailable):
                profile.project(result)
        self.write_status(_jwt(ec.generate_private_key(ec.SECP256R1()), claims))
        with self.assertRaises(WalletStatusUnavailable):
            profile.project(result)
        self.write_status(_jwt(self.key, claims | {"status_list": {"bits": 1, "lst": _b64(zlib.compress(b"\x08"))}}))
        with self.assertRaisesRegex(ValueError, "not valid"):
            profile.project(result)

    def test_mdoc_status_verifies_cwt_bit_and_identifier_lists(self):
        profile = self.strict_profile("cwt-file")
        base_claims = {2: _STATUS_URI, 6: self.now - 1, 4: self.now + 60}
        for mechanism, path, value, revocation_data in (
            ("status_list", "idx", 3, ({65533: {"bits": 1, "lst": zlib.compress(b"\x00")}},
                                       {65533: {"bits": 1, "lst": zlib.compress(b"\x08")}})),
            ("identifier_list", "id", "example", ({65530: {"identifiers": {"other": {}}}},
                                                 {65530: {"identifiers": {"example": {}}}})),
        ):
            kind = "statuslist" if mechanism == "status_list" else "identifierlist"
            presentation = _mdoc({mechanism: {"uri": _STATUS_URI, path: value}})
            for revoked, additional in enumerate(revocation_data):
                with self.subTest(kind=kind, revoked=revoked):
                    self.write_status(_cwt(self.key, base_claims | additional, kind))
                    if revoked:
                        with self.assertRaisesRegex(ValueError, "not valid"):
                            profile.project(self.mdoc_result(), presentation=presentation)
                    else:
                        self.assertEqual(profile.project(self.mdoc_result(), presentation=presentation), {"adult": True})
            self.write_status(_cwt(ec.generate_private_key(ec.SECP256R1()), base_claims | revocation_data[0], kind))
            with self.assertRaises(WalletStatusUnavailable):
                profile.project(self.mdoc_result(), presentation=presentation)
        self.write_status(cbor2.dumps(cbor2.CBORTag(18, True)))
        with self.assertRaises(WalletStatusUnavailable):
            profile.project(self.mdoc_result(), presentation=_mdoc({"status_list": {"uri": _STATUS_URI, "idx": 3}}))
        with self.assertRaises(ValueError):
            profile.project(self.mdoc_result(), presentation="not-valid-cbor")


if __name__ == "__main__":
    unittest.main()

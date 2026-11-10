"""Native W3C VC profiles verify actual issuer signatures before projecting facts."""

import base64
import hashlib
import json
import unittest
from copy import deepcopy

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from proofsieve.vc_inputs import compile_vc_credential


_CONTEXTS = ["https://www.w3.org/ns/credentials/v2", "https://vocab.example.test/membership/v1"]
_ISSUER = "https://issuer.example.test"
_METHOD = _ISSUER + "#vc-key"
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _pem(key):
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _proof_value(data):
    number = int.from_bytes(data, "big")
    encoded = []
    while number:
        number, digit = divmod(number, 58)
        encoded.append(_BASE58[digit])
    return "z" + "1" * (len(data) - len(data.lstrip(b"\0"))) + "".join(reversed(encoded))


def _jws(key, vc, *, headers=None, encoded=None):
    protected = {"alg": "ES256", "typ": "vc+jwt", "cty": "vc"} if headers is None else headers
    payload = json.dumps(vc, ensure_ascii=False).encode("utf-8") if encoded is None else encoded
    signing_input = f"{_b64(json.dumps(protected).encode())}.{_b64(payload)}"
    r, s = utils.decode_dss_signature(key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return f"{signing_input}.{_b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def _di(key, vc, *, updates=None):
    options = {
        "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "assertionMethod", "verificationMethod": _METHOD,
        "created": "2025-01-01T00:00:00Z", "@context": vc["@context"],
    }
    options.update(updates or {})
    digest = hashlib.sha256(rfc8785.dumps(options)).digest() + hashlib.sha256(rfc8785.dumps(vc)).digest()
    return {**vc, "proof": {**options, "proofValue": _proof_value(key.sign(digest))}}


class NativeVcInputsTest(unittest.TestCase):
    def setUp(self):
        self.jwt_key = ec.generate_private_key(ec.SECP256R1())
        self.di_key = ed25519.Ed25519PrivateKey.generate()
        self.document = {
            "@context": _CONTEXTS[:], "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": _ISSUER, "validFrom": "2025-01-01T00:00:00Z", "validUntil": "2090-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "urn:member:123", "membership": {"active": True, "level": 2},
                "clubs": ["workshop"], "private": "excluded",
            },
        }
        self.jwt_config = {
            "format": "jwt-vc", "issuer": _ISSUER, "publicKeyPem": _pem(self.jwt_key.public_key()),
            "credentialType": "MembershipCredential", "contexts": _CONTEXTS[:],
            "claims": {
                "active": {"path": ["membership", "active"], "type": "boolean"},
                "level": {"path": ["membership", "level"], "type": "integer"},
                "club": {"path": ["clubs", 0], "type": "string"},
            },
        }
        self.di_config = {
            **self.jwt_config, "format": "vc-data-integrity", "publicKeyPem": _pem(self.di_key.public_key()),
            "verificationMethod": _METHOD,
        }
        self.jwt = compile_vc_credential(self.jwt_config)
        self.di = compile_vc_credential(self.di_config)

    def test_jwt_verifies_signature_and_projects_only_the_configured_facts(self):
        token = _jws(self.jwt_key, self.document)
        self.assertEqual(self.jwt(token), {"active": True, "level": 2, "club": "workshop"})
        header, _, signature = token.split(".")
        changed = deepcopy(self.document)
        changed["credentialSubject"]["membership"]["active"] = False
        tampered = f"{header}.{_b64(json.dumps(changed).encode())}.{signature}"
        with self.assertRaisesRegex(ValueError, "signature"):
            self.jwt(tampered)
        with self.assertRaisesRegex(ValueError, "signature"):
            self.jwt(_jws(ec.generate_private_key(ec.SECP256R1()), self.document))
        for typ in ("JWT", "vp+jwt", "dc+sd-jwt"):
            with self.subTest(typ=typ), self.assertRaisesRegex(ValueError, "protected header"):
                self.jwt(_jws(self.jwt_key, self.document, headers={"alg": "ES256", "typ": typ}))

    def test_jwt_rejects_unsigned_or_ambiguous_semantics_even_with_trusted_key(self):
        for changes in (
            {"issuer": "https://foreign.example.test"},
            {"type": ["VerifiableCredential", "DifferentCredential"]},
            {"@context": list(reversed(_CONTEXTS))},
            {"@context": _CONTEXTS + ["https://foreign.example.test"]},
            {"credentialSubject": {"@context": "https://foreign.example.test"}},
            {"validFrom": "2025-01-01T00:00:00+00:60"},
            {"validFrom": "2100-01-01T00:00:00Z"},
            {"validUntil": "2025-01-02T00:00:00Z"},
            {"credentialSchema": {"id": "http://127.0.0.1/schema", "type": "JsonSchema"}},
            {"credentialStatus": {"id": "https://foreign.example.test/status"}},
            {"credentialSubject": {"membership": {"active": 1, "level": 2}, "clubs": ["workshop"]}},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.jwt(_jws(self.jwt_key, self.document | changes))
        duplicate = json.dumps(self.document).replace('"active": true', '"active": false, "active": true')
        with self.assertRaises(ValueError):
            self.jwt(_jws(self.jwt_key, self.document, encoded=duplicate.encode()))

    def test_data_integrity_checks_the_entire_document_and_assertion(self):
        signed = _di(self.di_key, self.document)
        self.assertEqual(self.di(signed), {"active": True, "level": 2, "club": "workshop"})
        changed = deepcopy(signed)
        changed["credentialSubject"]["membership"]["active"] = False
        with self.assertRaisesRegex(ValueError, "signature"):
            self.di(changed)
        for updates in (
            {"proofPurpose": "authentication"}, {"cryptosuite": "eddsa-rdfc-2022"},
            {"verificationMethod": _ISSUER + "#other"}, {"@context": _CONTEXTS[:1]},
            {"expires": "2025-02-01T00:00:00Z"}, {"challenge": "foreign-session"},
        ):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                self.di(_di(self.di_key, self.document, updates=updates))
        signed["proof"] = [signed["proof"]]
        with self.assertRaises(ValueError):
            self.di(signed)

    def test_published_w3c_jcs_vector_verifies_independently_of_test_signer(self):
        # W3C Data Integrity EdDSA Cryptosuites v1.0, Appendix B.3 (Examples 30 and 39).
        # https://www.w3.org/TR/2025/REC-vc-di-eddsa-20250515/#representation-eddsa-jcs-2022
        multikey = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
        method = f"did:key:{multikey}#{multikey}"
        issuer = "https://vc.example/issuers/5678"
        contexts = [_CONTEXTS[0], "https://www.w3.org/ns/credentials/examples/v2"]
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex("b00d8d938e7f773d51565aad36a623f5344f7f5d1960f9cf3e8e12620ea2810f")
        )
        verify = compile_vc_credential({
            "format": "vc-data-integrity", "issuer": issuer, "publicKeyPem": _pem(public_key),
            "credentialType": "AlumniCredential", "contexts": contexts, "verificationMethod": method,
            "claims": {"alumni": {"path": ["alumniOf"], "type": "string"}},
        })
        document = {
            "@context": contexts, "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "name": "Alumni Credential", "description": "A minimum viable example of an Alumni Credential.",
            "issuer": issuer, "validFrom": "2023-01-01T00:00:00Z",
            "credentialSubject": {"id": "did:example:abcdefgh", "alumniOf": "The School of Examples"},
            "proof": {
                "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
                "created": "2023-02-24T23:36:38Z", "verificationMethod": method,
                "proofPurpose": "assertionMethod", "@context": contexts,
                "proofValue": "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX",
            },
        }
        self.assertEqual(verify(document), {"alumni": "The School of Examples"})

    def test_both_formats_enforce_signed_related_resource_pins(self):
        identifier = "https://vocab.example.test/membership/schema-v1.json"
        content = b'{"type":"object"}'
        for alg in ("sha256", "sha384"):
            sri = alg + "-" + base64.b64encode(hashlib.new(alg, content).digest()).decode("ascii")
            reference = {"id": identifier, "digestSRI": sri, "mediaType": "application/schema+json"}
            pin = {**reference, "contentBase64": base64.b64encode(content).decode("ascii")}
            for config, signer in (
                (self.jwt_config, lambda doc: _jws(self.jwt_key, doc)),
                (self.di_config, lambda doc: _di(self.di_key, doc)),
            ):
                with self.subTest(alg=alg, format=config["format"]):
                    verify = compile_vc_credential(config | {"resourcePins": [pin]})
                    signed = signer(self.document | {"relatedResource": [reference]})
                    self.assertEqual(verify(signed), {"active": True, "level": 2, "club": "workshop"})
                    for wrong in (
                        {"id": identifier.replace("schema-v1", "schema-v2")},
                        {"digestSRI": sri.replace(sri[-2], "X", 1)},
                        {"mediaType": "text/plain"},
                    ):
                        with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, "resource"):
                            verify(signer(self.document | {"relatedResource": [reference | wrong]}))
                    with self.assertRaisesRegex(ValueError, "resource"):
                        verify(signer(self.document))
                    with self.assertRaisesRegex(ValueError, "resource"):
                        compile_vc_credential(config)(signed)
                    tampered = {**pin, "contentBase64": base64.b64encode(b'{"type":"string"}').decode("ascii")}
                    with self.assertRaisesRegex(ValueError, "configured bytes"):
                        compile_vc_credential(config | {"resourcePins": [tampered]})
                    with self.assertRaisesRegex(ValueError, "Duplicate"):
                        compile_vc_credential(config | {"resourcePins": [pin, pin]})


if __name__ == "__main__":
    unittest.main()

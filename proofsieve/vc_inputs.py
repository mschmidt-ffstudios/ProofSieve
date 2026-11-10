"""Verify the pinned W3C VC JWS and EdDSA Data Integrity profiles."""

import base64
import binascii
import hashlib
import hmac
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

import rfc8785
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from .sd_jwt import _decode, _json


_VCDM_V2 = "https://www.w3.org/ns/credentials/v2"
_VC_TYPE = "VerifiableCredential"
_JWT = "jwt-vc"
_DATA_INTEGRITY = "vc-data-integrity"
_CRYPTOSUITE = "eddsa-jcs-2022"
_MAX_INPUT = 96 * 1024
_MAX_DEPTH = 48
_MAX_ITEMS = 4096
_MAX_RESOURCE_BYTES = 12 * 1024
_ABSOLUTE_IRI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[!-~]{1,512}")
_DATETIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", re.ASCII)
_PEM = re.compile(r"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?")
_FACT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
_PATH_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}")
_SCALARS = {"string", "boolean", "integer", "number"}
_REQUIRED_VC = {"@context", "type", "issuer", "validFrom", "credentialSubject"}
_OPTIONAL_VC = {"id", "name", "description", "validUntil", "relatedResource"}
_REQUIRED_PROOF = {"type", "cryptosuite", "proofPurpose", "verificationMethod", "proofValue"}
_OPTIONAL_PROOF = {"@context", "created", "expires"}
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_DIGIT = {symbol: index for index, symbol in enumerate(_BASE58)}
_SRI = re.compile(r"(sha256|sha384)-[A-Za-z0-9+/]+={0,2}")
_MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*")


def _iri(value):
    return type(value) is str and _ABSOLUTE_IRI.fullmatch(value) is not None


def _contexts(raw):
    if type(raw) is str:
        raw = [raw]
    if (type(raw) is not list or not 1 <= len(raw) <= 8 or raw[0] != _VCDM_V2
            or not all(_https_context(value) for value in raw) or len(raw) != len(set(raw))):
        raise ValueError("VC needs an ordered, explicit W3C v2 HTTPS context list.")
    return tuple(raw)


def _https_context(value):
    if not _iri(value) or re.search(r"[\\<>\x22{}|^\x60]", value):
        return False
    try:
        parts = urlsplit(value)
        return parts.scheme == "https" and bool(parts.hostname) and parts.username is None and not parts.fragment
    except ValueError:
        return False


def _date(value):
    if type(value) is not str or not _DATETIME.fullmatch(value):
        raise ValueError("VC timestamp needs a date, time and explicit time zone.")
    if not value.endswith("Z"):
        hours, minutes = int(value[-5:-3]), int(value[-2:])
        if hours > 14 or minutes > 59 or (hours == 14 and minutes):
            raise ValueError("VC timestamp time zone is invalid.")
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else ""))
    except ValueError:
        raise ValueError("VC timestamp is invalid.") from None


def _validate_values(root):
    # Bound native objects before canonicalization and reject nested JSON-LD aliasing.
    pending = [(root, 0)]
    count = 0
    size = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > _MAX_ITEMS or depth > _MAX_DEPTH:
            raise ValueError("VC is too large or deeply nested.")
        if type(value) is dict:
            if len(value) > _MAX_ITEMS:
                raise ValueError("VC is too large.")
            for key, item in value.items():
                if type(key) is not str or (key.startswith("@") and depth):
                    raise ValueError("VC contains a nested JSON-LD keyword or invalid property.")
                pending.extend(((key, depth + 1), (item, depth + 1)))
        elif type(value) is list:
            if len(value) > _MAX_ITEMS:
                raise ValueError("VC is too large.")
            pending.extend((item, depth + 1) for item in value)
        elif type(value) is str:
            if len(value) > _MAX_INPUT:
                raise ValueError("VC is too large.")
            try:
                size += len(value.encode("utf-8"))
            except UnicodeEncodeError:
                raise ValueError("VC contains an invalid Unicode string.") from None
            if size > _MAX_INPUT:
                raise ValueError("VC is too large.")
        elif type(value) not in (int, float, bool, type(None)) or (
            type(value) is float and not math.isfinite(value)
        ):
            raise ValueError("VC contains an unsupported JSON value.")


def _signature_bytes(value):
    if type(value) is not str or not 65 <= len(value) <= 89 or not value.startswith("z"):
        raise ValueError("Data Integrity needs a base58-btc multibase proof value.")
    number = 0
    encoded = value[1:]
    try:
        for symbol in encoded:
            number = 58 * number + _BASE58_DIGIT[symbol]
    except KeyError:
        raise ValueError("Invalid base58-btc proof value.") from None
    leading_zeroes = len(encoded) - len(encoded.lstrip("1"))
    decoded = b"\0" * leading_zeroes + number.to_bytes((number.bit_length() + 7) // 8, "big")
    if len(decoded) != 64:
        raise ValueError("Invalid Ed25519 proof size.")
    return decoded


def _verified_jwt(raw, key):
    if type(raw) is not str or not 1 <= len(raw) <= _MAX_INPUT or raw.count(".") != 2:
        raise ValueError("JWT-VC needs a bounded compact JWS.")
    header_b64, payload_b64, signature_b64 = raw.split(".")
    header = _json(header_b64)
    if (type(header) is not dict or header.get("alg") != "ES256" or header.get("typ") != "vc+jwt"
            or header.keys() - {"alg", "typ", "cty", "kid"} or header.get("cty", "vc") != "vc"
            or ("kid" in header and (type(header["kid"]) is not str or not 1 <= len(header["kid"]) <= 512))):
        raise ValueError("JWT-VC needs an ES256 vc+jwt protected header.")
    signature = _decode(signature_b64)
    if len(signature) != 64:
        raise ValueError("Invalid ES256 signature size.")
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    _decode(payload_b64)  # Establish ASCII and canonical base64url before creating the signing input.
    try:
        key.verify(der, f"{header_b64}.{payload_b64}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError("Invalid JWT-VC issuer signature.") from None
    payload = _json(payload_b64)
    _validate_values(payload)
    return payload


def _verified_data_integrity(raw, key, method, *, now):
    if type(raw) is not dict:
        raise ValueError("Data Integrity VC needs a JSON object.")
    proof = raw.get("proof")
    if (type(proof) is not dict or not _REQUIRED_PROOF <= proof.keys()
            or proof.keys() - _REQUIRED_PROOF - _OPTIONAL_PROOF
            or proof["type"] != "DataIntegrityProof" or proof["cryptosuite"] != _CRYPTOSUITE
            or proof["proofPurpose"] != "assertionMethod" or proof["verificationMethod"] != method):
        raise ValueError("Data Integrity VC needs one pinned eddsa-jcs-2022 issuer assertion.")
    if len(raw) > len(_REQUIRED_VC | _OPTIONAL_VC) + 1:
        raise ValueError("Data Integrity VC contains unsupported credential features.")
    document = {name: value for name, value in raw.items() if name != "proof"}
    options = {name: value for name, value in proof.items() if name != "proofValue"}
    if "@context" in options and options["@context"] != document.get("@context"):
        # A standalone proof profile requires the complete context to be signed, not an unsigned suffix.
        raise ValueError("Data Integrity proof context differs from the credential context.")
    _validate_values(document)
    _validate_values(options)
    created = _date(options["created"]) if "created" in options else None
    expires = _date(options["expires"]) if "expires" in options else None
    if (created is not None and created > now) or (expires is not None and now >= expires):
        raise ValueError("Data Integrity proof is outside its validity period.")
    try:
        proof_hash = hashlib.sha256(rfc8785.dumps(options)).digest()
        document_hash = hashlib.sha256(rfc8785.dumps(document)).digest()
    except rfc8785.CanonicalizationError:
        raise ValueError("Data Integrity VC cannot be canonicalized with RFC 8785.") from None
    try:
        key.verify(_signature_bytes(proof["proofValue"]), proof_hash + document_hash)
    except InvalidSignature:
        raise ValueError("Invalid Data Integrity issuer signature.") from None
    return document


@dataclass(frozen=True)
class _Claim:
    fact: str
    path: tuple
    kind: str

    def extract(self, subject):
        value = subject
        for step in self.path:
            if type(step) is str and type(value) is dict and step in value:
                value = value[step]
            elif type(step) is int and type(value) is list and step < len(value):
                value = value[step]
            else:
                raise ValueError("A configured VC subject claim is missing.")
        value_type = type(value)
        if (
            (self.kind == "string" and value_type is str and len(value) <= 4096)
            or (self.kind == "boolean" and value_type is bool)
            or (self.kind == "integer" and value_type is int)
            or (self.kind == "number" and value_type in (int, float))
        ):
            return value
        raise ValueError("A configured VC subject claim has the wrong type.")


def _compile_claims(entries):
    if type(entries) is not dict or not 1 <= len(entries) <= 32:
        raise ValueError("VC profile needs one to 32 explicitly mapped subject claims.")
    claims = []
    for fact, entry in entries.items():
        if (type(fact) is not str or not _FACT.fullmatch(fact) or type(entry) is not dict
                or entry.keys() != {"path", "type"} or type(entry["type"]) is not str
                or entry["type"] not in _SCALARS or type(entry["path"]) is not list
                or not 1 <= len(entry["path"]) <= 8):
            raise ValueError("Invalid VC claim mapping.")
        path = tuple(entry["path"])
        if type(path[0]) is not str or any(not (
            (type(part) is str and _PATH_KEY.fullmatch(part)) or (type(part) is int and 0 <= part <= 31)
        ) for part in path):
            raise ValueError("Invalid VC subject claim path.")
        claims.append(_Claim(fact, path, entry["type"]))
    return tuple(claims)


def _resource_identity(entry):
    identifier = entry["id"]
    sri = entry["digestSRI"]
    media_type = entry.get("mediaType")
    if (not _iri(identifier) or type(sri) is not str or len(sri) > 80 or not _SRI.fullmatch(sri)
            or ("mediaType" in entry and (type(media_type) is not str
                                         or len(media_type) > 128 or not _MEDIA_TYPE.fullmatch(media_type)))):
        raise ValueError("VC related resources require an exact IRI, SHA-256 or SHA-384 SRI and optional media type.")
    return identifier, (sri, media_type)


def _compile_resource_pins(entries):
    if type(entries) is not list or not 1 <= len(entries) <= 4:
        raise ValueError("VC resourcePins needs one to four approved resources.")
    pins = {}
    required = {"id", "digestSRI", "contentBase64"}
    for entry in entries:
        if type(entry) is not dict or not required <= entry.keys() or entry.keys() - required - {"mediaType"}:
            raise ValueError("Invalid VC resource pin.")
        identifier, identity = _resource_identity(entry)
        if identifier in pins:
            raise ValueError("Duplicate VC resource pin.")
        content = entry["contentBase64"]
        if type(content) is not str or not 1 <= len(content) <= 4 * (_MAX_RESOURCE_BYTES // 3):
            raise ValueError("VC resource content exceeds the Base64 pin limit.")
        try:
            raw = base64.b64decode(content, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("VC resource content is not standard Base64.") from None
        if not raw or base64.b64encode(raw).decode("ascii") != content:
            raise ValueError("VC resource content needs canonical standard Base64.")
        sri, _ = identity
        alg = sri.split("-", 1)[0]
        expected = alg + "-" + base64.b64encode(hashlib.new(alg, raw).digest()).decode("ascii")
        if not hmac.compare_digest(expected, sri):
            raise ValueError("VC resource digest does not match the configured bytes.")
        pins[identifier] = identity
    return pins


def _verify_resources(document, pins):
    if not pins and "relatedResource" not in document:
        return
    resources = document.get("relatedResource")
    if type(resources) is dict:
        resources = [resources]
    if type(resources) is not list or not pins or len(resources) != len(pins):
        raise ValueError("Signed VC resources do not match the configured pins.")
    required = {"id", "digestSRI"}
    seen = set()
    for entry in resources:
        if type(entry) is not dict or not required <= entry.keys() or entry.keys() - required - {"mediaType"}:
            raise ValueError("Unsupported signed VC relatedResource.")
        identifier, identity = _resource_identity(entry)
        if identifier in seen or pins.get(identifier) != identity:
            raise ValueError("Signed VC resource identity or digest does not match the configured pin.")
        seen.add(identifier)


def _verified_facts(document, *, issuer, credential_type, contexts, claims, resource_pins, now):
    if (type(document) is not dict or not _REQUIRED_VC <= document.keys()
            or document.keys() - _REQUIRED_VC - _OPTIONAL_VC):
        raise ValueError("VC contains missing fields or unsupported credential features.")
    if _contexts(document["@context"]) != contexts:
        raise ValueError("VC context does not match the configured allowlist.")
    types = document["type"]
    if type(types) is not list or len(types) != 2 or _VC_TYPE not in types or credential_type not in types:
        raise ValueError("VC type does not match the configured credential type.")
    actual_issuer = document["issuer"]
    if type(actual_issuer) is dict:
        actual_issuer = actual_issuer.get("id")
    if actual_issuer != issuer:
        raise ValueError("VC issuer does not match the configured issuer.")
    if _date(document["validFrom"]) > now or ("validUntil" in document and now >= _date(document["validUntil"])):
        raise ValueError("VC is outside its validity period.")
    subject = document["credentialSubject"]
    if type(subject) is not dict or not subject or ("id" in subject and not _iri(subject["id"])):
        raise ValueError("VC needs one credentialSubject object.")
    if "id" in document and not _iri(document["id"]):
        raise ValueError("Invalid VC identifier.")
    _verify_resources(document, resource_pins)
    return {claim.fact: claim.extract(subject) for claim in claims}


def compile_vc_credential(config):
    """Compile an operator-approved issuer, format, type and literal subject claim mapping."""
    if type(config) is not dict or config.get("format") not in (_JWT, _DATA_INTEGRITY):
        raise ValueError("VC format must be jwt-vc or vc-data-integrity.")
    fmt = config["format"]
    required = {"format", "issuer", "publicKeyPem", "credentialType", "contexts", "claims"}
    if fmt == _DATA_INTEGRITY:
        required.add("verificationMethod")
    if not required <= config.keys() or config.keys() - required - {"resourcePins"}:
        raise ValueError("VC profile contains missing or unsupported fields.")
    issuer, credential_type, pem = (config[name] for name in ("issuer", "credentialType", "publicKeyPem"))
    if (not _iri(issuer) or type(credential_type) is not str or credential_type == _VC_TYPE
            or not (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", credential_type) or _iri(credential_type))
            or type(pem) is not str or len(pem) > 1024 or not _PEM.fullmatch(pem)):
        raise ValueError("VC profile needs an exact issuer, credential type and public PEM key.")
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, UnsupportedAlgorithm):
        raise ValueError("Invalid pinned VC public key.") from None
    method = config.get("verificationMethod")
    if fmt == _DATA_INTEGRITY:
        if not isinstance(key, ed25519.Ed25519PublicKey) or not _iri(method):
            raise ValueError("Data Integrity needs an Ed25519 key and exact verification method.")
    elif not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("JWT-VC needs a pinned P-256 key.")
    contexts = _contexts(config["contexts"])
    claims = _compile_claims(config["claims"])
    resource_pins = _compile_resource_pins(config["resourcePins"]) if "resourcePins" in config else {}

    def verify(raw):
        now = datetime.now(timezone.utc)
        document = (_verified_jwt(raw, key) if fmt == _JWT
                    else _verified_data_integrity(raw, key, method, now=now))
        return _verified_facts(document, issuer=issuer, credential_type=credential_type,
                               contexts=contexts, claims=claims, resource_pins=resource_pins, now=now)

    return verify

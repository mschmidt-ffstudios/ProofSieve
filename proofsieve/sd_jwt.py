"""Verify the issuer-signed part of an SD-JWT VC using a configured key.

This profile implements compact issuer credentials (RFC 9901) with ES256
and SHA-256 disclosures. It does not authenticate the holder.
"""

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .json_numbers import bounded_int, finite_float


_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")
_SURROGATE = re.compile(r"[\ud800-\udfff]")
_RESERVED = {"_sd", "_sd_alg", "..."}
_PLAIN_CLAIMS = {"iss", "nbf", "exp", "iat", "aud", "cnf", "vct", "vct#integrity", "aka_vcts", "status"}
_HEADERS = {"alg", "typ", "kid", "x5c"}
_MAX_TOKEN_LENGTH = 96 * 1024
_MAX_DISCLOSURES = 256
_MAX_DEPTH = 48


def _invalid(reason):
    return ValueError(f"SD-JWT: {reason}.")


def _encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(text):
    if not isinstance(text, str) or not _BASE64URL.fullmatch(text):
        raise _invalid("invalid base64url component")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except binascii.Error as exc:
        raise _invalid("invalid base64url component") from exc
    if _encode(data) != text:
        raise _invalid("non-canonical base64url component")
    return data


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def _json(text):
    raw = _decode(text)
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=finite_float,
            parse_float=finite_float,
            parse_int=bounded_int,
        )
    except (ValueError, RecursionError) as exc:
        raise _invalid("invalid or ambiguous JSON") from exc

    # JSON escape sequences can produce lone surrogates despite a valid UTF-8 envelope.
    pending = [decoded]
    while pending:
        value = pending.pop()
        if isinstance(value, str) and _SURROGATE.search(value):
            raise _invalid("invalid Unicode in JSON")
        if isinstance(value, dict):
            pending.extend(value)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return decoded


def _verified_payload(jws, public_key):
    parts = jws.split(".")
    if len(parts) != 3:
        raise _invalid("expected a compact issuer JWS")
    encoded_header, encoded_payload, encoded_signature = parts
    header = _json(encoded_header)
    if not isinstance(header, dict) or header.get("alg") != "ES256" or header.get("typ") != "dc+sd-jwt":
        raise _invalid("expected a dc+sd-jwt header with ES256")
    # Only the configured key is used. kid and x5c are advisory here.
    if header.keys() - _HEADERS:
        raise _invalid("unsupported JOSE header parameter")
    signature = _decode(encoded_signature)
    if len(signature) != 64:
        raise _invalid("issuer signature has an invalid length")
    signing_input = f"{encoded_header}.{encoded_payload}"
    if not signing_input.isascii():
        raise _invalid("invalid issuer JWS encoding")
    der_signature = utils.encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    try:
        public_key.verify(der_signature, signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise _invalid("issuer signature is invalid") from exc
    payload = _json(encoded_payload)
    if not isinstance(payload, dict):
        raise _invalid("issuer payload must be an object")
    return payload


class _Disclosures:
    def __init__(self, encoded_disclosures):
        self.pending = {}
        self.seen_digests = set()
        self.seen_salts = set()
        for encoded in encoded_disclosures:
            disclosure = _json(encoded)
            if not isinstance(disclosure, list) or len(disclosure) not in (2, 3):
                raise _invalid("disclosure must have two or three elements")
            salt = disclosure[0]
            if not isinstance(salt, str) or not salt or salt in self.seen_salts:
                raise _invalid("invalid or repeated disclosure salt")
            self.seen_salts.add(salt)
            digest = _encode(hashlib.sha256(encoded.encode("ascii")).digest())
            if digest in self.pending:
                raise _invalid("repeated disclosure")
            self.pending[digest] = disclosure

    def take(self, digest, size):
        if not isinstance(digest, str) or len(digest) != 43 or len(_decode(digest)) != 32:
            raise _invalid("invalid disclosure digest")
        if digest in self.seen_digests:
            raise _invalid("repeated disclosure digest")
        self.seen_digests.add(digest)
        disclosure = self.pending.pop(digest, None)
        if disclosure is not None and len(disclosure) != size:
            raise _invalid("disclosure does not match its digest location")
        return disclosure

    def expand(self, value, depth=0, allow_disclosure=True):
        if depth > _MAX_DEPTH:
            raise _invalid("claims exceed the supported nesting depth")
        if isinstance(value, dict):
            return self.expand_object(value, depth, allow_disclosure)
        if isinstance(value, list):
            result = []
            for item in value:
                if isinstance(item, dict) and item.keys() == {"..."}:
                    if not allow_disclosure:
                        raise _invalid("a reserved claim contains a disclosure reference")
                    disclosure = self.take(item["..."], 2)
                    if disclosure is None:
                        continue
                    item = disclosure[1]
                result.append(self.expand(item, depth + 1, allow_disclosure))
            return result
        return value

    def expand_object(self, value, depth, allow_disclosure):
        if "..." in value or (depth and "_sd_alg" in value):
            raise _invalid("reserved disclosure key in an invalid location")
        result = {}
        for name, item in value.items():
            if name not in _RESERVED:
                can_disclose = allow_disclosure and (depth != 0 or name not in _PLAIN_CLAIMS)
                result[name] = self.expand(item, depth + 1, can_disclose)
        references = value.get("_sd", [])
        if not isinstance(references, list) or ("_sd" in value and not allow_disclosure):
            raise _invalid("invalid object disclosure references")
        for digest in references:
            disclosure = self.take(digest, 3)
            if disclosure is None:
                continue
            _, name, item = disclosure
            if not isinstance(name, str) or name in _RESERVED or name in result:
                raise _invalid("disclosure would overwrite a claim or use a reserved name")
            if depth == 0 and name in _PLAIN_CLAIMS:
                raise _invalid("a reserved claim cannot be selectively disclosed")
            result[name] = self.expand(item, depth + 1)
        return result


def _validate_dates(claims, now):
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise _invalid("verification time must have a time zone")
    dates = {}
    for field in ("exp", "nbf", "iat"):
        if field in claims:
            value = claims[field]
            if type(value) not in (int, float):
                raise _invalid(f"{field} must be a NumericDate")
            dates[field] = value
    if "exp" not in dates:
        raise _invalid("the exp claim is required")
    timestamp = now.timestamp()
    if timestamp >= dates["exp"]:
        raise _invalid("credential has expired")
    if "nbf" in dates and timestamp < dates["nbf"]:
        raise _invalid("credential is not valid yet")
    if "iat" in dates and timestamp < dates["iat"]:
        raise _invalid("issuer timestamp is in the future")


def verify_sd_jwt(raw: str, public_key, *, issuer: str, now: datetime) -> dict:
    """Return authenticated issuer claims and disclosures, or raise ValueError."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise _invalid("the configured issuer key must be a P-256 public key")
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_TOKEN_LENGTH:
        raise _invalid("expected a compact issuer credential within the size limit")
    if not raw.endswith("~"):
        raise _invalid("expected an issuer credential ending in ~ without a holder proof")
    issuer_jws, *encoded_disclosures = raw[:-1].split("~", _MAX_DISCLOSURES + 1)
    if len(encoded_disclosures) > _MAX_DISCLOSURES:
        raise _invalid("too many disclosures")
    payload = _verified_payload(issuer_jws, public_key)
    if not isinstance(issuer, str) or not issuer or payload.get("iss") != issuer:
        raise _invalid("issuer does not match the configured issuer")
    vct = payload.get("vct")
    if not isinstance(vct, str) or not vct or any(character.isspace() for character in vct):
        raise _invalid("expected a signed credential type in vct")
    if payload.get("_sd_alg", "sha-256") != "sha-256":
        raise _invalid("only SHA-256 disclosures are supported")
    if "aud" in payload:
        raise _invalid("audience-restricted credentials require an audience profile")
    disclosures = _Disclosures(encoded_disclosures)
    claims = disclosures.expand(payload)
    if disclosures.pending:
        raise _invalid("a disclosure is not bound to the signed claims")
    _validate_dates(claims, now)
    return claims

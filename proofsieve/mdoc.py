"""Verify mdoc IssuerSigned data against a configured document signer key."""

import base64
import binascii
from datetime import date, datetime
import hashlib
from io import BytesIO
import math
import re

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


_MAX_INPUT = 96 * 1024
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+={0,2}")
_ISSUER_FIELDS = {"issuerAuth", "nameSpaces"}
_ITEM_FIELDS = {"digestID", "random", "elementIdentifier", "elementValue"}
_SHA256_SIZE = hashlib.sha256().digest_size


def _encode_base64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_base64url(raw):
    if not isinstance(raw, str) or len(raw) > _MAX_INPUT or not _BASE64URL.fullmatch(raw):
        raise ValueError("mdoc input must be base64url-encoded IssuerSigned CBOR.")
    unpadded = raw.rstrip("=")
    padded = unpadded + "=" * (-len(unpadded) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except binascii.Error as exc:
        raise ValueError("Invalid mdoc base64url input.") from exc
    if raw not in (unpadded, padded) or _encode_base64url(decoded) != unpadded:
        raise ValueError("Invalid mdoc base64url input.")
    return decoded


def _deny_reference(*_):
    raise ValueError("CBOR reference tags are unsupported.")


def _decoder(stream):
    return cbor2.CBORDecoder(
        stream,
        read_size=1,
        max_depth=24,
        allow_indefinite=False,
        allow_duplicate_keys=False,
        semantic_decoders=dict.fromkeys((25, 28, 29, 256), _deny_reference),
    )


def _decode(data):
    stream = BytesIO(data)
    value = _decoder(stream).decode()
    if stream.tell() != len(data):
        raise ValueError("Unexpected bytes after mdoc CBOR value.")
    return value


def _container_size(stream, major_type, limit):
    header = stream.read(1)
    if not header or header[0] >> 5 != major_type:
        raise ValueError("Unexpected mdoc CBOR container.")
    length = header[0] & 31
    if 24 <= length <= 27:
        width = 1 << (length - 24)
        size = stream.read(width)
        if len(size) != width:
            raise ValueError("Incomplete mdoc CBOR container.")
        length = int.from_bytes(size, "big")
    elif length >= 28:
        raise ValueError("Indefinite or invalid mdoc CBOR container.")
    if not 1 <= length <= limit:
        raise ValueError("Invalid mdoc CBOR container size.")
    return length


def _read_issuer_signed(data):
    stream = BytesIO(data)
    decoder = _decoder(stream)
    issuer_signed = {}
    for _ in range(_container_size(stream, 5, len(_ISSUER_FIELDS))):
        field = decoder.decode()
        if type(field) is not str or field not in _ISSUER_FIELDS or field in issuer_signed:
            raise ValueError("Invalid or duplicate mdoc IssuerSigned field.")
        if field == "issuerAuth":
            issuer_signed[field] = decoder.decode()
            continue

        namespaces = {}
        for _ in range(_container_size(stream, 5, 32)):
            namespace = decoder.decode()
            if type(namespace) is not str or not namespace or namespace in namespaces:
                raise ValueError("Invalid or duplicate mdoc namespace.")
            items = []
            for _ in range(_container_size(stream, 4, 256)):
                start = stream.tell()
                item = decoder.decode()
                # An MSO digest covers the exact tag-24 wrapper, including its original encoding.
                items.append((item, data[start:stream.tell()]))
            namespaces[namespace] = items
        issuer_signed[field] = namespaces
    if issuer_signed.keys() != _ISSUER_FIELDS or stream.tell() != len(data):
        raise ValueError("Invalid mdoc IssuerSigned structure.")
    return issuer_signed


def _embedded_cbor(value):
    if not isinstance(value, cbor2.CBORTag) or value.tag != 24 or type(value.value) is not bytes:
        raise ValueError("Expected tag 24 containing an mdoc CBOR byte string.")
    return _decode(value.value)


def _verify_issuer_auth(value, public_key):
    if isinstance(value, cbor2.CBORTag) and value.tag == 18:
        value = value.value
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        raise ValueError("mdoc issuerAuth must contain a COSE_Sign1 structure.")
    protected, unprotected, payload, signature = value
    if not (
        type(protected) is bytes and type(unprotected) in (dict, cbor2.frozendict)
        and type(payload) is bytes and type(signature) is bytes and len(signature) == 64
    ):
        raise ValueError("Invalid mdoc COSE_Sign1 fields.")
    header = _decode(protected)
    if (
        type(header) is not dict or type(header.get(1)) is not int or header[1] != -7
        or not header.keys().isdisjoint(unprotected)
        or any(type(label) not in (int, str) for label in (*header, *unprotected))
        or 2 in header or 2 in unprotected
    ):
        raise ValueError("mdoc requires protected COSE ES256 without unsupported critical headers.")
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("mdoc requires a configured P-256 issuer key.")

    der_signature = utils.encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    message = cbor2.dumps(["Signature1", protected, b"", payload])
    try:
        public_key.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("mdoc issuerAuth signature does not match the configured issuer key.") from exc
    return _embedded_cbor(_decode(payload))


def _validate_mso(mso, now):
    if type(mso) is not dict or mso.get("version") != "1.0" or mso.get("digestAlgorithm") != "SHA-256":
        raise ValueError("mdoc requires Mobile Security Object version 1.0 with SHA-256.")
    doc_type = mso.get("docType")
    validity = mso.get("validityInfo")
    digests = mso.get("valueDigests")
    if not isinstance(doc_type, str) or not doc_type or type(validity) is not dict or type(digests) is not dict:
        raise ValueError("Missing mdoc document type, validity or element digests.")
    signed, start, end = (validity.get(key) for key in ("signed", "validFrom", "validUntil"))
    if not all(isinstance(value, datetime) and value.utcoffset() is not None for value in (signed, start, end)):
        raise ValueError("Invalid signed mdoc validity timestamps.")
    if not signed <= start < end:
        raise ValueError("Invalid signed mdoc validity interval.")
    if not start <= now <= end:
        raise ValueError("mdoc Mobile Security Object is outside its signed validity period.")
    if not digests or any(
        type(namespace) is not str or not namespace or type(entries) is not dict or not entries
        or any(type(index) is not int or index < 0 or type(digest) is not bytes or len(digest) != _SHA256_SIZE
               for index, digest in entries.items())
        for namespace, entries in digests.items()
    ):
        raise ValueError("Invalid mdoc signed namespace digest table.")
    return doc_type, digests


def _json_value(value):
    if value is None or type(value) in (str, bool, int) or (type(value) is float and math.isfinite(value)):
        return value
    if isinstance(value, date):
        return value.isoformat()
    if type(value) is bytes:
        return _encode_base64url(value)
    if type(value) is list:
        return [_json_value(item) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: _json_value(item) for key, item in value.items()}
    raise ValueError("Unsupported CBOR value in a verified mdoc claim.")


def _verify_namespace(items, expected):
    if expected is None:
        raise ValueError("Missing signed mdoc namespace digests.")
    used_ids = set()
    claims = {}
    for tag, encoded in items:
        item = _embedded_cbor(tag)
        if type(item) is not dict or item.keys() != _ITEM_FIELDS:
            raise ValueError("Invalid mdoc IssuerSignedItem.")
        digest_id = item["digestID"]
        name = item["elementIdentifier"]
        salt = item["random"]
        if (
            type(digest_id) is not int or digest_id < 0 or digest_id in used_ids
            or type(name) is not str or not name or name in claims
            or type(salt) is not bytes or len(salt) < 16
        ):
            raise ValueError("Invalid or duplicate mdoc IssuerSignedItem identifier or salt.")
        if expected.get(digest_id) != hashlib.sha256(encoded).digest():
            raise ValueError("mdoc issuer-signed element digest does not match the signed MSO.")
        used_ids.add(digest_id)
        claims[name] = item["elementValue"]
    return claims


def verify_mdoc(raw: str, public_key, *, now: datetime) -> dict:
    """Return issuer-verified data from an mdoc IssuerSigned object."""
    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("mdoc verification time must have a time zone.")
    try:
        issuer_signed = _read_issuer_signed(_decode_base64url(raw))
        mso = _verify_issuer_auth(issuer_signed["issuerAuth"], public_key)
        doc_type, digests = _validate_mso(mso, now)
        namespaces = {
            namespace: _verify_namespace(items, digests.get(namespace))
            for namespace, items in issuer_signed["nameSpaces"].items()
        }
        claims = {"docType": doc_type, "nameSpaces": _json_value(namespaces)}
    except (cbor2.CBORDecodeError, UnicodeError, OverflowError, RecursionError) as exc:
        raise ValueError("Invalid or unsupported mdoc CBOR encoding.") from exc

    claims.update({
        name: value
        for name, value in namespaces.get(doc_type, {}).items()
        if name not in claims and type(value) in (str, bool, int, float)
    })
    return claims

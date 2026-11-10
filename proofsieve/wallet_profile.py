"""Operator-owned wallet trust settings and verified fact projection."""

import math
import re
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .access import _read_config
from .evidence import rule_version
from .mdoc import _decode as _decode_cbor, _embedded_cbor
from .sd_jwt import _decode, _json
from .wallet_protocol import WalletUnavailable, _MAX_PRESENTATION


_SD_JWT = "dc+sd-jwt"
_MDOC = "mso_mdoc"
_FACT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
_CLAIM = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}")
_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+?-----END CERTIFICATE-----")
_FIELD_TYPES = {"boolean", "integer", "number", "string"}
_MAX_STATUS_BYTES = 1024 * 1024


class WalletStatusUnavailable(WalletUnavailable):
    """The configured status source could not establish a current status."""


def _status_bits(encoded, index, bits):
    decompressor = zlib.decompressobj()
    values = decompressor.decompress(encoded, _MAX_STATUS_BYTES + 1)
    if (not decompressor.eof or decompressor.unused_data or len(values) > _MAX_STATUS_BYTES
            or index >= len(values) * (8 // bits)):
        raise ValueError("Invalid status list length or index.")
    byte, position = divmod(index, 8 // bits)
    return (values[byte] >> (position * bits)) & ((1 << bits) - 1)


def _verify_es256(key, signed, signature):
    if type(signature) is not bytes or len(signature) != 64:
        raise ValueError("Unexpected status list signature size.")
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    key.verify(der, signed, ec.ECDSA(hashes.SHA256()))


def _check_status_time(iat, exp, ttl, nbf, now, max_age):
    if (type(iat) is not int or type(exp) is not int or not now - max_age <= iat <= now < exp
            or (ttl is not None and (type(ttl) is not int or not 0 < ttl or now >= iat + ttl))
            or (nbf is not None and (type(nbf) is not int or now < nbf))):
        raise ValueError("Status list does not satisfy the freshness policy.")


def _status_reference(status, uri, *, cwt, identifier_list=False):
    key, field = ("identifier_list", "id") if identifier_list else ("status_list", "idx")
    entry = status.get(key) if type(status) is dict else None
    allowed = {"uri", field, "certificate"} if cwt else {"uri", field}
    if (type(entry) is not dict or not {"uri", field} <= entry.keys()
            or entry.keys() - allowed or entry["uri"] != uri):
        raise ValueError("Credential lacks the configured status list reference.")
    if "certificate" in entry and (type(entry["certificate"]) is not bytes or not 1 <= len(entry["certificate"]) <= 4096):
        raise ValueError("Credential status certificate is malformed.")
    value = entry[field]
    if ((type(value) is int and (identifier_list or value >= 0))
            or (identifier_list and type(value) is str and 1 <= len(value) <= 256)):
        return value
    raise ValueError("Credential status reference is malformed.")


def _mdoc_status(presentation, credential_type):
    try:
        return _read_mdoc_status(presentation, credential_type)
    except cbor2.CBORDecodeError as exc:
        raise ValueError("Malformed mdoc CBOR for status verification.") from exc


def _read_mdoc_status(presentation, credential_type):
    if type(presentation) is not str or len(presentation) > _MAX_PRESENTATION:
        raise ValueError("Invalid mdoc DeviceResponse for status verification.")
    unpadded = presentation.rstrip("=")
    if presentation not in (unpadded, unpadded + "=" * (-len(unpadded) % 4)):
        raise ValueError("Invalid mdoc DeviceResponse padding.")
    response = _decode_cbor(_decode(unpadded))
    docs = response.get("documents") if type(response) is dict else None
    if type(docs) is not list or len(docs) != 1:
        raise ValueError("Expected one mdoc DeviceResponse document for status verification.")
    doc = docs[0]
    if type(doc) is not dict or doc.get("docType") != credential_type:
        raise ValueError("Unexpected mdoc document for status verification.")
    signed = doc.get("issuerSigned")
    auth = signed.get("issuerAuth") if type(signed) is dict else None
    if isinstance(auth, cbor2.CBORTag) and auth.tag == 18:
        auth = auth.value
    if type(auth) not in (list, tuple) or len(auth) != 4 or type(auth[2]) is not bytes:
        raise ValueError("Missing mdoc issuer authentication for status verification.")
    mso = _embedded_cbor(_decode_cbor(auth[2]))
    if type(mso) is not dict or mso.get("docType") != credential_type:
        raise ValueError("Unexpected mdoc type for status verification.")
    return mso.get("status")


@dataclass(frozen=True)
class _StatusFile:
    mode: str
    uri: str
    file: Path
    key: ec.EllipticCurvePublicKey = field(repr=False)
    max_age: int

    def require_valid(self, status):
        cwt = self.mode == "cwt-file"
        identifier_list = cwt and type(status) is dict and "identifier_list" in status
        if identifier_list and "status_list" in status:
            raise ValueError("Credential contains conflicting status references.")
        ref = _status_reference(status, self.uri, cwt=cwt, identifier_list=identifier_list)
        try:
            now = int(time.time())
            if self.mode == "jwt-file":
                value = self.read_jwt(ref, now=now)
            else:
                value = self.read_cwt(ref, identifier_list=identifier_list, now=now)
        except (OSError, ValueError, InvalidSignature, zlib.error, cbor2.CBORDecodeError) as exc:
            raise WalletStatusUnavailable("No valid fresh signed wallet status list is available.") from exc
        if value != 0:
            raise ValueError("Credential status is not valid.")

    def read_jwt(self, index, *, now):
        header_b64, payload_b64, signature_b64 = _read_config(self.file).decode("ascii").strip().split(".")
        header = _json(header_b64)
        if (type(header) is not dict or header.get("alg") != "ES256"
                or header.get("typ") != "statuslist+jwt" or header.keys() - {"alg", "typ", "kid"}):
            raise ValueError("Unexpected status list JWS header.")
        _verify_es256(self.key, f"{header_b64}.{payload_b64}".encode("ascii"), _decode(signature_b64))
        payload = _json(payload_b64)
        if type(payload) is not dict or payload.get("sub") != self.uri:
            raise ValueError("Status list does not bind to the configured URI.")
        _check_status_time(payload.get("iat"), payload.get("exp"), payload.get("ttl"),
                           payload.get("nbf"), now, self.max_age)
        status = payload.get("status_list")
        if (type(status) is not dict or type(status.get("bits")) is not int
                or status["bits"] not in (1, 2, 4, 8)):
            raise ValueError("Invalid status list bit width.")
        return _status_bits(_decode(status.get("lst")), index, status["bits"])

    def read_cwt(self, ref, *, identifier_list, now):
        cose = _decode_cbor(_read_config(self.file))
        if (not isinstance(cose, cbor2.CBORTag) or cose.tag != 18
                or type(cose.value) not in (list, tuple) or len(cose.value) != 4):
            raise ValueError("Expected a tagged COSE_Sign1 status list.")
        protected, unprotected, payload, signature = cose.value
        if (type(protected) is not bytes or type(payload) is not bytes
                or type(unprotected) not in (dict, cbor2.frozendict)):
            raise ValueError("Malformed COSE_Sign1 status list.")
        header = _decode_cbor(protected)
        media_type = "application/identifierlist+cwt" if identifier_list else "application/statuslist+cwt"
        if (type(header) is not dict or type(header.get(1)) is not int or header[1] != -7
                or header.get(16) != media_type or 2 in header or {1, 2, 16} & unprotected.keys()
                or not header.keys().isdisjoint(unprotected)):
            raise ValueError("Unexpected COSE status list header.")
        _verify_es256(self.key, cbor2.dumps(["Signature1", protected, b"", payload]), signature)
        claims = _decode_cbor(payload)
        if type(claims) is not dict or claims.get(2) != self.uri:
            raise ValueError("Status list does not bind to the configured URI.")
        _check_status_time(claims.get(6), claims.get(4), claims.get(65534), claims.get(5), now, self.max_age)
        status = claims.get(65530 if identifier_list else 65533)
        if type(status) is not dict or (65533 if identifier_list else 65530) in claims:
            raise ValueError("Missing or conflicting CWT status payload.")
        if identifier_list:
            identifiers = status.get("identifiers")
            if (type(identifiers) is not dict
                    or any(type(i) not in (str, int) or info != {} for i, info in identifiers.items())):
                raise ValueError("Invalid CWT identifier list.")
            return int(ref in identifiers)
        if type(status.get("bits")) is not int or status["bits"] != 1 or type(status.get("lst")) is not bytes:
            raise ValueError("Invalid one-bit mdoc status list.")
        return _status_bits(status["lst"], ref, 1)


def _compile_status(config, fmt):
    if config == {"mode": "not-required"}:
        return None
    mode = "jwt-file" if fmt == _SD_JWT else "cwt-file"
    if (type(config) is not dict or config.get("mode") != mode
            or config.keys() != {"mode", "uri", "file", "publicKeyPem", "maxAgeSeconds"}):
        raise ValueError("Use explicit not-required status or a configured signed status file for the format.")
    uri = config["uri"]
    from .guard import validate_result_url

    validate_result_url(uri, "status.uri")
    if not uri or urlsplit(uri).fragment:
        raise ValueError("Status list needs a pinned HTTPS URI without a fragment.")
    file = config["file"]
    age = config["maxAgeSeconds"]
    pem = config["publicKeyPem"]
    if (type(file) is not str or len(file) > 4096 or "\0" in file or not Path(file).is_absolute()
            or type(age) is not int or not 1 <= age <= 86_400
            or type(pem) is not str or len(pem) > 1024):
        raise ValueError("Status list needs an absolute file path, public key and bounded max age.")
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("Invalid status-list public key.") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("The status-list signer must be a configured P-256 public key.")
    return _StatusFile(mode, uri, Path(file), key, age)


@dataclass(frozen=True)
class _Claim:
    fact: str
    path: tuple
    kind: str

    def read(self, claims):
        value = claims
        for part in self.path:
            if type(part) is str and type(value) is dict and part in value:
                value = value[part]
            elif type(part) is int and type(value) is list and part < len(value):
                value = value[part]
            else:
                raise ValueError("A required wallet claim is missing.")
        valid = {
            "boolean": type(value) is bool,
            "integer": type(value) is int,
            "number": type(value) in (int, float) and (type(value) is int or math.isfinite(value)),
            "string": type(value) is str and len(value) <= 4096,
        }
        if not valid[self.kind]:
            raise ValueError("A required wallet claim has the wrong type.")
        return value


@dataclass(frozen=True)
class WalletProfile:
    format: str
    credential_type: str
    issuer_chain: str = field(repr=False)
    intended_use_id: str
    version: str
    issuer: str | None
    _claims: tuple[_Claim, ...] = field(repr=False)
    _status: _StatusFile | None = field(repr=False)

    @property
    def status_mode(self):
        return "not-required" if self._status is None else self._status.mode

    @property
    def dcql_query(self):
        meta = ({"vct_values": [self.credential_type]} if self.format == _SD_JWT
                else {"doctype_value": self.credential_type})
        return {"credentials": [{
            "id": "credential", "format": self.format, "meta": meta,
            "require_cryptographic_holder_binding": True,
            "claims": [{"path": list(claim.path)} for claim in self._claims],
        }]}

    def project(self, result, *, presentation=None):
        """Accept utility results only after the authenticated presentation transaction."""
        if self.format == _SD_JWT:
            if (type(result) is not dict or result.get("iss") != self.issuer
                    or result.get("vct") != self.credential_type):
                raise ValueError("Verified wallet issuer or credential type does not match.")
            if self._status is not None:
                self._status.require_valid(result.get("status"))
            claims = result
        else:
            if (type(result) is not list or len(result) != 1 or type(result[0]) is not dict
                    or result[0].keys() != {"docType", "attributes"}
                    or result[0]["docType"] != self.credential_type or type(result[0]["attributes"]) is not dict):
                raise ValueError("Verified wallet response needs exactly one matching mdoc.")
            if self._status is not None:
                self._status.require_valid(_mdoc_status(presentation, self.credential_type))
            claims = result[0]["attributes"]
        return {claim.fact: claim.read(claims) for claim in self._claims}


def _compile_claims(entries, fmt):
    if type(entries) is not dict or not 1 <= len(entries) <= 32:
        raise ValueError("A wallet profile needs one to 32 explicitly mapped claims.")
    claims = []
    for fact, entry in entries.items():
        if (type(fact) is not str or not _FACT.fullmatch(fact) or type(entry) is not dict
                or entry.keys() != {"path", "type"} or type(entry["type"]) is not str
                or entry["type"] not in _FIELD_TYPES or type(entry["path"]) is not list
                or not 1 <= len(entry["path"]) <= 8):
            raise ValueError("Invalid wallet claim mapping.")
        path = tuple(entry["path"])
        if any(not ((type(part) is str and _CLAIM.fullmatch(part))
                    or (type(part) is int and 0 <= part <= 31)) for part in path):
            raise ValueError("Invalid wallet claim path.")
        if type(path[0]) is not str or (fmt == _MDOC and (len(path) != 2 or type(path[1]) is not str)):
            raise ValueError("mdoc claim paths need a namespace and an element.")
        claims.append(_Claim(fact, path, entry["type"]))
    if len({claim.path for claim in claims}) != len(claims):
        raise ValueError("Wallet claim paths must be unique.")
    return tuple(claims)


def compile_wallet_profile(config):
    if type(config) is not dict or config.get("format") not in (_SD_JWT, _MDOC):
        raise ValueError("Wallet profile format must be dc+sd-jwt or mso_mdoc.")
    fmt = config["format"]
    required = {"format", "credentialType", "issuerChainPem", "intendedUseId", "claims", "status"}
    if config.keys() != required | ({"issuer"} if fmt == _SD_JWT else set()):
        raise ValueError("Wallet profile contains missing or unsupported fields.")
    credential_type, chain, use = (config[key] for key in ("credentialType", "issuerChainPem", "intendedUseId"))
    if (type(credential_type) is not str or not re.fullmatch(r"[!-~]{1,512}", credential_type)
            or type(use) is not str or not re.fullmatch(r"[!-~]{1,128}", use)
            or type(chain) is not str or not 1 <= len(chain) <= 24_576):
        raise ValueError("Wallet profile needs a type, intended use and bounded PEM issuer trust.")
    chain = chain.strip()
    certificates = _CERTIFICATE.findall(chain)
    if not 1 <= len(certificates) <= 8 or _CERTIFICATE.sub("", chain).strip():
        raise ValueError("Wallet issuer trust must contain only PEM certificates.")
    try:
        x509.load_pem_x509_certificates(chain.encode("ascii"))
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("Invalid configured wallet issuer certificate chain.") from exc
    issuer = config.get("issuer")
    if fmt == _SD_JWT and (type(issuer) is not str or not re.fullmatch(r"[!-~]{1,512}", issuer)):
        raise ValueError("SD-JWT wallet profiles require an exact issuer identifier.")
    return WalletProfile(fmt, credential_type, chain, use, rule_version(config), issuer,
                         _compile_claims(config["claims"], fmt), _compile_status(config["status"], fmt))

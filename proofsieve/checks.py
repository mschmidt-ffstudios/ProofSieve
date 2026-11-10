"""Validate document signatures with operator-selected, typed checks."""

import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import stat
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, SignatureAlgorithmOID


_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}")
_REPORT_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_HOST_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")
_PATH = re.compile(r"/[a-zA-Z0-9_./~-]*")
_TOKEN = re.compile(r"[a-zA-Z0-9_.~+/-]{16,2048}={0,2}")
_PEM = re.compile(r"-----BEGIN CERTIFICATE-----\r?\n(?:[a-zA-Z0-9+/=]+\r?\n)+-----END CERTIFICATE-----\r?\n?")
_CONNECTOR_KINDS = {"dss", "remote", "ocsp"}
_EMBEDDED_FORMATS = {"pades", "asic-s", "asic-e"}
_TIMESTAMP_FORMAT = "rfc3161"
_FORMATS = _EMBEDDED_FORMATS | {
    "cades-detached", "xades-detached", "jades-detached", "cbades-detached", _TIMESTAMP_FORMAT,
}
_OUTCOMES = {"passed", "failed", "indeterminate"}
_MAX_SIGNERS = 8
_MAX_DOCUMENT = 64 * 1024
_MAX_SIGNATURE = 32 * 1024
_MAX_RESPONSE = 32 * 1024
_MAX_REGISTRY = 64 * 1024
_MAX_CHECK_SECONDS = 12
_OCSP_MAX_AGE = timedelta(days=1)
_SKEW = timedelta(seconds=30)
_RSA_OCSP = {
    SignatureAlgorithmOID.RSA_WITH_SHA256,
    SignatureAlgorithmOID.RSA_WITH_SHA384,
    SignatureAlgorithmOID.RSA_WITH_SHA512,
}
_EC_OCSP = {
    SignatureAlgorithmOID.ECDSA_WITH_SHA256,
    SignatureAlgorithmOID.ECDSA_WITH_SHA384,
    SignatureAlgorithmOID.ECDSA_WITH_SHA512,
}


class CheckUnavailable(Exception):
    """A dependency did not provide a trustworthy check result."""


@dataclass(frozen=True)
class CheckResult:
    outcome: str
    facts: dict
    evidence: tuple[dict, ...]


def _is_id(value):
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _is_kind(value, allowed):
    return isinstance(value, str) and value in allowed


def _decode(value, limit):
    if not isinstance(value, str) or not value or len(value) > 4 * ((limit + 2) // 3):
        raise ValueError("Document or signature has an invalid Base64 size.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("Document or signature must use standard Base64.") from exc
    if len(decoded) > limit or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("Document or signature must use bounded canonical Base64.")
    return decoded


def _certificate(value):
    if not isinstance(value, str) or len(value) > 16 * 1024 or not _PEM.fullmatch(value):
        raise ValueError("Expected exactly one PEM certificate.")
    return x509.load_pem_x509_certificate(value.encode("ascii"))


def _certificate_live(certificate, now):
    return certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc


def _extension(certificate, kind):
    try:
        return certificate.extensions.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return None
    except (x509.DuplicateExtension, x509.UnsupportedGeneralNameType) as exc:
        raise ValueError("The signer certificate has malformed extensions.") from exc


def _supported_key(key):
    return ((isinstance(key, rsa.RSAPublicKey) and 2048 <= key.key_size <= 4096)
            or (isinstance(key, ec.EllipticCurvePublicKey)
                and isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1))))


def _verify_signature(key, signature, payload, algorithm):
    if isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, payload, padding.PKCS1v15(), algorithm)
    else:
        key.verify(signature, payload, ec.ECDSA(algorithm))


def _pem_fingerprint(certificate):
    return certificate.fingerprint(hashes.SHA256()).hex()


def _key_fingerprint(certificate):
    return hashlib.sha256(certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).digest()


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, context, timeout):
        super().__init__(host, port=port, context=context, timeout=timeout)
        self._pinned_ip = ip

    def connect(self):
        deadline = time.monotonic() + self.timeout
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            raw.settimeout(_remaining(deadline))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _interrupt(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("External verification timed out.")
    return remaining


@dataclass(frozen=True)
class _Connector:
    kind: str
    profile_version: str
    host: str
    port: int
    ip: str
    path: str
    context: ssl.SSLContext
    timeout: int
    token: str | None = field(repr=False)

    def post(self, body, media_type, accept, *, deadline):
        headers = {"Content-Type": media_type, "Accept": accept, "Connection": "close"}
        if self.token is not None:
            headers["Authorization"] = "Bearer " + self.token
        deadline = min(deadline, time.monotonic() + self.timeout)
        connection = None
        try:
            connection = _PinnedConnection(self.host, self.port, self.ip, self.context, _remaining(deadline))
            connection.connect()
            # Bound the entire request and response, including slowly delivered headers.
            timeout = _remaining(deadline)
            connection.sock.settimeout(timeout)
            timer = threading.Timer(timeout, _interrupt, args=(connection.sock,))
            timer.daemon = True
            timer.start()
            try:
                connection.request("POST", self.path, body=body, headers=headers)
                with connection.getresponse() as response:
                    _remaining(deadline)
                    return self._read_response(response, accept, deadline=deadline)
            finally:
                timer.cancel()
        except (OSError, http.client.HTTPException) as exc:
            raise CheckUnavailable("connector_unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _read_response(response, accept, *, deadline):
        headers = response.headers
        if (response.status != 200 or len(headers.get_all("Content-Type", [])) != 1
                or headers.get_content_type() != accept or headers.get_all("Content-Encoding", [])):
            raise CheckUnavailable("connector_response_invalid")
        lengths = headers.get_all("Content-Length", [])
        transfer = headers.get_all("Transfer-Encoding", [])
        if transfer or len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,6}", lengths[0]):
            raise CheckUnavailable("connector_response_invalid")
        length = int(lengths[0])
        if not 0 < length <= _MAX_RESPONSE:
            raise CheckUnavailable("connector_response_invalid")
        payload = response.read(length)
        _remaining(deadline)
        if len(payload) != length:
            raise CheckUnavailable("connector_response_invalid")
        return payload


def _tls_endpoint(value, networks):
    if not isinstance(value, str) or len(value) > 1024 or not value.startswith("https://"):
        raise ValueError("Connector URL must be an absolute HTTPS URL.")
    url = urlsplit(value)
    host = url.hostname
    if (not host or url.username is not None or url.password is not None or url.port == 0
            or url.query or url.fragment or not _PATH.fullmatch(url.path)
            or set(url.path.split("/")) & {".", ".."}
            or re.search(r"[^\x21-\x7e]|[\\%?#]", value)):
        raise ValueError("Connector URL must identify a fixed HTTPS route.")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        if len(host) > 253 or not all(_HOST_LABEL.fullmatch(label) for label in host.split(".")):
            raise ValueError("Connector URL has an invalid hostname.") from None
        try:
            addresses = {ipaddress.ip_address(item[4][0])
                         for item in socket.getaddrinfo(host, url.port or 443, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise ValueError("Connector hostname cannot be resolved.") from exc
    if not addresses or any(
            ip.is_unspecified or ip.is_link_local or ip.is_multicast or ip.is_reserved and not ip.is_loopback
            or getattr(ip, "ipv4_mapped", None) is not None
            or not any(ip in network for network in networks) for ip in addresses):
        raise ValueError("Connector resolved outside its allowed networks.")
    # Keep the verified address fixed until the next explicit configuration load.
    ip = min(addresses, key=lambda address: (address.version, int(address)))
    return host, url.port or 443, str(ip), url.path


def _connector(config):
    if (type(config) is not dict or not {"kind", "url", "allowedNetworks"} <= config.keys()
            or config.keys() - {"kind", "url", "allowedNetworks", "caFile", "bearerEnv", "timeoutSeconds",
                               "profileVersion"}
            or not _is_kind(config["kind"], _CONNECTOR_KINDS)):
        raise ValueError("Connector requires kind, url and allowedNetworks.")
    kind = config["kind"]
    version = config.get("profileVersion", "v1")
    if not _is_id(version):
        raise ValueError("Invalid connector profile version.")
    values = config["allowedNetworks"]
    if type(values) is not list or not 1 <= len(values) <= 8 or not all(isinstance(x, str) for x in values):
        raise ValueError("Connector needs one to eight explicit allowed networks.")
    networks = [ipaddress.ip_network(value, strict=True) for value in values]
    if any(network.prefixlen < (8 if network.version == 4 else 32) for network in networks):
        raise ValueError("Connector network is too broad.")
    host, port, ip, path = _tls_endpoint(config["url"], networks)
    timeout = config.get("timeoutSeconds", 3)
    if type(timeout) is not int or not 1 <= timeout <= 10:
        raise ValueError("Connector timeout must be an integer from 1 to 10 seconds.")
    cafile = config.get("caFile")
    if "caFile" in config and (not isinstance(cafile, str) or not Path(cafile).is_absolute()):
        raise ValueError("Connector CA path must be absolute.")
    try:
        context = ssl.create_default_context(cafile=cafile)
    except OSError as exc:
        raise ValueError("Connector CA could not be loaded.") from exc
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    token = None
    if kind != "ocsp" or "bearerEnv" in config:
        name = config.get("bearerEnv")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name):
            raise ValueError("Remote verification requires a connector token environment variable name.")
        token = os.environ.get(name)
        if token is None or not _TOKEN.fullmatch(token):
            raise ValueError("Connector token is missing or invalid.")
    return _Connector(kind, version, host, port, ip, path, context, timeout, token)


def load_check_registry(path):
    """Load an opt-in connector registry from a protected operator file."""
    from .guard import load_json

    path = Path(path)
    expected = path.lstat()
    if not stat.S_ISREG(expected.st_mode):
        raise ValueError("Connector configuration must be a private operator file.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if (not os.path.samestat(expected, info) or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or hasattr(os, "geteuid") and info.st_uid != os.geteuid()):
            raise ValueError("Connector configuration must be a private operator file.")
        raw = file.read(_MAX_REGISTRY + 1)
    if len(raw) > _MAX_REGISTRY:
        raise ValueError("Connector configuration is too large.")
    config = load_json(raw)
    if (type(config) is not dict or config.keys() != {"version", "connectors"}
            or type(config["version"]) is not int or config["version"] != 1
            or type(config["connectors"]) is not dict or len(config["connectors"]) > 16
            or not all(_is_id(name) for name in config["connectors"])):
        raise ValueError("Invalid connector registry version or configuration.")
    return CheckRegistry({name: _connector(value) for name, value in config["connectors"].items()})


@dataclass(frozen=True)
class _Signer:
    id: str
    kind: str
    certificate: x509.Certificate
    format: str
    connector: _Connector | None
    connector_id: str | None
    issuer: x509.Certificate | None


def _compile_signer(config, connectors):
    required = {"id", "kind", "certificatePem"}
    if (type(config) is not dict or not required <= config.keys() or not _is_id(config["id"])
            or not _is_kind(config["kind"], _CONNECTOR_KINDS | {"local"})):
        raise ValueError("Each signer needs an id, check kind and pinned certificate.")
    kind = config["kind"]
    connector = connector_id = issuer = None
    profile_format = "raw"
    if kind != "local":
        required.add("connector")
        connector_id = config.get("connector")
        connector = connectors.get(connector_id) if _is_id(connector_id) else None
        if connector is None or connector.kind != kind:
            raise ValueError("Signer references an unconfigured connector or a different connector kind.")
    if kind == "ocsp":
        required.add("issuerCertificatePem")
        issuer = _certificate(config.get("issuerCertificatePem"))
    elif kind in {"dss", "remote"}:
        required.add("format")
        profile_format = config.get("format")
        if not _is_kind(profile_format, _FORMATS | ({"raw"} if kind == "remote" else set())):
            raise ValueError("External document format is unsupported.")
    if config.keys() != required:
        raise ValueError("Invalid or unexpected signer configuration fields.")
    certificate = _certificate(config["certificatePem"])
    constraints = _extension(certificate, x509.BasicConstraints)
    usage = _extension(certificate, x509.KeyUsage)
    if (constraints is not None and constraints.ca or usage is not None
            and not (usage.digital_signature or usage.content_commitment)):
        raise ValueError("Signer certificate must be an end-entity signing certificate.")
    if profile_format == _TIMESTAMP_FORMAT:
        try:
            extended_usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        except x509.ExtensionNotFound:
            raise ValueError("RFC 3161 requires a certificate restricted to timestamp signing.") from None
        if not extended_usage.critical or list(extended_usage.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
            raise ValueError("RFC 3161 requires a certificate restricted to timestamp signing.")
    if kind in {"local", "ocsp"} and not _supported_key(certificate.public_key()):
        raise ValueError("Local signing key must use an approved RSA or NIST EC key.")
    if issuer is not None:
        authority = _extension(issuer, x509.BasicConstraints)
        issuer_usage = _extension(issuer, x509.KeyUsage)
        if (authority is None or not authority.ca or issuer_usage is not None and not issuer_usage.key_cert_sign
                or not _supported_key(issuer.public_key())):
            raise ValueError("OCSP issuer must be a CA with an approved signing key.")
        try:
            certificate.verify_directly_issued_by(issuer)
        except (InvalidSignature, UnsupportedAlgorithm, ValueError) as exc:
            raise ValueError("Signer certificate does not chain directly to the configured OCSP issuer.") from exc
    return _Signer(config["id"], kind, certificate, profile_format, connector, connector_id, issuer)


def _proofs(data, signers):
    if (type(data) is not dict or data.keys() != {"document", "proofs"}
            or type(data["proofs"]) is not list or len(data["proofs"]) > len(signers)):
        raise ValueError("Document checks require a Base64 document and a list of signer proofs.")
    document = _decode(data["document"], _MAX_DOCUMENT)
    proofs = {}
    for proof in data["proofs"]:
        if type(proof) is not dict or not _is_id(proof.get("signer")):
            raise ValueError("Each proof requires a configured signer id.")
        signer_id = proof["signer"]
        if signer_id in proofs or signer_id not in signers:
            raise ValueError("Proof signers must be distinct and configured.")
        if signers[signer_id].format in _EMBEDDED_FORMATS:
            if proof.keys() != {"signer"}:
                raise ValueError("Embedded proofs take the signature from the submitted document or container.")
            proofs[signer_id] = None
        else:
            if proof.keys() != {"signer", "signature"}:
                raise ValueError("Detached proofs require a signer id and Base64 signature.")
            proofs[signer_id] = _decode(proof["signature"], _MAX_SIGNATURE)
    return document, proofs


def _remote_check(signer, document, digest, signature, deadline):
    from .guard import load_json

    context = {"version": 1, "nonce": secrets.token_urlsafe(24), "documentSha256": digest,
               "certificateSha256": _pem_fingerprint(signer.certificate)}
    payload = {"format": signer.format, "document": base64.b64encode(document).decode("ascii")}
    if signature is not None:
        context["signatureSha256"] = hashlib.sha256(signature).hexdigest()
        payload["signature"] = base64.b64encode(signature).decode("ascii")
    raw = signer.connector.post(json.dumps({**context, **payload}, separators=(",", ":")).encode(),
                                "application/json", "application/json", deadline=deadline)
    try:
        reply = load_json(raw)
    except ValueError as exc:
        raise CheckUnavailable("connector_response_invalid") from exc
    if (type(reply) is not dict or reply.keys() != context.keys() | {"verdict", "reportId"}
            or type(reply["version"]) is not int or not _is_kind(reply["verdict"], _OUTCOMES)
            or not isinstance(reply["reportId"], str) or not _REPORT_ID.fullmatch(reply["reportId"])):
        raise CheckUnavailable("connector_response_invalid")
    if any(reply[key] != value for key, value in context.items()):
        raise CheckUnavailable("connector_response_mismatch")
    return reply["verdict"], "connector_verdict", reply["reportId"]


def _status_request(signer, nonce):
    return (ocsp.OCSPRequestBuilder().add_certificate(signer.certificate, signer.issuer, hashes.SHA256())
            .add_extension(x509.OCSPNonce(nonce), critical=False).build())


def _ocsp_reply(signer, request, raw, nonce, now):
    reply = ocsp.load_der_ocsp_response(raw)
    if reply.response_status is not ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise CheckUnavailable("status_unavailable")
    records = tuple(reply.responses)
    if len(records) != 1:
        raise CheckUnavailable("status_response_mismatch")
    record = records[0]
    if (record.serial_number != request.serial_number
            or record.issuer_key_hash != request.issuer_key_hash or record.issuer_name_hash != request.issuer_name_hash
            or not isinstance(record.hash_algorithm, hashes.SHA256)):
        raise CheckUnavailable("status_response_mismatch")
    if reply.responder_name is not None:
        responder_matches = reply.responder_name == signer.issuer.subject
    else:
        sha1_request = (ocsp.OCSPRequestBuilder()
                        .add_certificate(signer.certificate, signer.issuer, hashes.SHA1()).build())
        responder_matches = reply.responder_key_hash == sha1_request.issuer_key_hash
    key = signer.issuer.public_key()
    algorithms = _RSA_OCSP if isinstance(key, rsa.RSAPublicKey) else _EC_OCSP
    if not responder_matches or reply.signature_algorithm_oid not in algorithms:
        raise CheckUnavailable("status_signature_invalid")
    _verify_signature(key, reply.signature, reply.tbs_response_bytes, reply.signature_hash_algorithm)
    try:
        response_nonce = reply.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    except x509.ExtensionNotFound as exc:
        raise CheckUnavailable("status_response_mismatch") from exc
    if not secrets.compare_digest(response_nonce, nonce):
        raise CheckUnavailable("status_response_mismatch")
    if (any(ext.critical for ext in reply.extensions) or any(ext.critical for ext in reply.single_extensions)):
        raise CheckUnavailable("status_response_invalid")
    if (not _certificate_live(signer.issuer, now) or not _certificate_live(signer.issuer, reply.produced_at_utc)
            or not now - _OCSP_MAX_AGE <= reply.produced_at_utc <= now + _SKEW
            or not now - _OCSP_MAX_AGE <= record.this_update_utc <= min(now, reply.produced_at_utc) + _SKEW
            or record.next_update_utc is None or record.next_update_utc < max(now, record.this_update_utc)):
        raise CheckUnavailable("status_response_stale")
    return record.certificate_status


def _status_check(signer, now, deadline):
    nonce = secrets.token_bytes(24)
    request = _status_request(signer, nonce)
    raw = signer.connector.post(request.public_bytes(Encoding.DER), "application/ocsp-request",
                                "application/ocsp-response", deadline=deadline)
    try:
        status = _ocsp_reply(signer, request, raw, nonce, now)
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, x509.DuplicateExtension,
            x509.UnsupportedGeneralNameType) as exc:
        raise CheckUnavailable("status_response_invalid") from exc
    if status is ocsp.OCSPCertStatus.GOOD:
        return "passed", "signature_and_status_confirmed", None
    if status is ocsp.OCSPCertStatus.REVOKED:
        return "failed", "certificate_revoked", None
    return "indeterminate", "certificate_status_unknown", None


def _check_signer(signer, document, digest, signature, now, deadline):
    if signer.kind in {"dss", "remote"}:
        return _remote_check(signer, document, digest, signature, deadline)
    if not _certificate_live(signer.certificate, now):
        return "failed", "signer_certificate_outside_validity", None
    try:
        _verify_signature(signer.certificate.public_key(), signature, document, hashes.SHA256())
    except InvalidSignature:
        return "failed", "signature_invalid", None
    if signer.kind == "ocsp":
        return _status_check(signer, now, deadline)
    return "passed", "signature_confirmed", None


class CheckRegistry:
    def __init__(self, connectors=None):
        self._connectors = dict(connectors or {})

    def compile(self, profile):
        if (type(profile) is not dict or profile.keys() != {"threshold", "signers"}
                or type(profile["signers"]) is not list or not 1 <= len(profile["signers"]) <= _MAX_SIGNERS
                or type(profile["threshold"]) is not int or not 1 <= profile["threshold"] <= len(profile["signers"])):
            raise ValueError("Verification requires a valid threshold and one to eight configured signers.")
        signers = {}
        keys = set()
        for config in profile["signers"]:
            signer = _compile_signer(config, self._connectors)
            fingerprint = _key_fingerprint(signer.certificate)
            if signer.id in signers or fingerprint in keys:
                raise ValueError("Verification signers must have distinct ids and public keys.")
            signers[signer.id] = signer
            keys.add(fingerprint)
        threshold = profile["threshold"]
        timestamp = any(signer.format == _TIMESTAMP_FORMAT for signer in signers.values())
        if timestamp and len(signers) != 1:
            raise ValueError("An RFC 3161 profile requires exactly one timestamp authority.")

        def verify(data):
            document, proofs = _proofs(data, signers)
            digest = hashlib.sha256(document).hexdigest()
            now = datetime.now(timezone.utc)
            deadline = time.monotonic() + _MAX_CHECK_SECONDS
            evidence = []
            for signer in signers.values():
                report = None
                if signer.id not in proofs:
                    outcome, reason = "failed", "proof_missing"
                else:
                    try:
                        outcome, reason, report = _check_signer(signer, document, digest, proofs[signer.id], now, deadline)
                    except CheckUnavailable as exc:
                        outcome, reason = "indeterminate", str(exc)
                record = {"signer": signer.id, "kind": signer.kind, "format": signer.format,
                          "outcome": outcome, "reason": reason}
                if signer.connector_id is not None:
                    record["connector"] = signer.connector_id
                    record["connectorProfile"] = signer.connector.profile_version
                if report is not None:
                    record["reportId"] = report
                evidence.append(record)
            confirmed = sum(record["outcome"] == "passed" for record in evidence)
            uncertain = sum(record["outcome"] == "indeterminate" for record in evidence)
            met = confirmed >= threshold
            outcome = "passed" if met else ("indeterminate" if confirmed + uncertain >= threshold else "failed")
            if timestamp:
                facts = {"timestampVerified": met, "documentSha256": digest}
            else:
                facts = {"validSignerCount": confirmed, "requiredSignerCount": threshold,
                         "thresholdMet": met, "documentSha256": digest}
            return CheckResult(outcome, facts, tuple(evidence))

        return verify

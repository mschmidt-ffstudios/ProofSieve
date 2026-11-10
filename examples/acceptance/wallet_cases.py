"""Build synthetic credentials and answer signed OpenID4VP requests for acceptance tests."""

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
import secrets
import ssl
import struct
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlsplit

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier


ISSUER = "https://issuer.example.test"
VCT = "urn:eudi:pid:1"
DOC_TYPE = "eu.europa.ec.eudi.pid.1"
SURNAME = "Mustermann"
MAX_RESPONSE = 512 * 1024
CREDO_ADVISORY_CASES = ("pex-downgrade", "unbound-disclosure")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def cert(name, key, *, signer=None, san=(), ca=False, use=None):
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
                         x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer, signer_key = signer if signer else (None, key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=10))
        .not_valid_after(now + timedelta(days=3))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=ca,
                crl_sign=ca, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_key.public_key()), critical=False)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(list(san)), critical=False)
    if use:
        builder = builder.add_extension(x509.ExtendedKeyUsage([use]), critical=False)
    return builder.sign(signer_key, hashes.SHA256())


def initialize(directory, host):
    os.umask(0o077)
    directory.mkdir(mode=0o700, exist_ok=False)
    try:
        host_identity = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        host_identity = x509.DNSName(host)
    issuer_ca_key = new_key()
    issuer_ca = cert("ProofSieve synthetic issuer CA", issuer_ca_key, ca=True)
    tls_ca_key = new_key()
    tls_ca = cert("ProofSieve synthetic TLS CA", tls_ca_key, ca=True)
    issuer_key, verifier_key, tls_key = new_key(), new_key(), new_key()
    issuer = cert(
        "ProofSieve synthetic PID issuer", issuer_key, signer=(issuer_ca, issuer_ca_key),
        san=(x509.DNSName(urlsplit(ISSUER).hostname), x509.UniformResourceIdentifier(ISSUER)),
        use=ObjectIdentifier("1.0.18013.5.1.2"),
    )
    verifier = cert("ProofSieve synthetic reader", verifier_key, signer=(issuer_ca, issuer_ca_key),
                    san=(host_identity,))
    tls = cert("ProofSieve synthetic HTTPS", tls_key, signer=(tls_ca, tls_ca_key),
               san=(host_identity,), use=ExtendedKeyUsageOID.SERVER_AUTH)
    for name, certificate in (
        ("issuer-ca", issuer_ca), ("issuer", issuer), ("verifier", verifier), ("tls-ca", tls_ca), ("tls", tls),
    ):
        (directory / f"{name}.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    for name, key in (("issuer", issuer_key), ("verifier", verifier_key), ("tls", tls_key)):
        (directory / f"{name}-key.pem").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
    (directory / "metadata.json").write_bytes(json_bytes({
        "clientId": "x509_hash:" + b64(verifier.fingerprint(hashes.SHA256())),
        "issuer": ISSUER, "vct": VCT, "docType": DOC_TYPE, "namespace": DOC_TYPE, "surname": SURNAME,
    }) + b"\n")


def origin(url):
    parts = urlsplit(url)
    require(parts.scheme in {"http", "https"} and parts.hostname and parts.username is None
            and parts.password is None and not parts.fragment, "Unexpected request URL")
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


def request(url, expected_origin, *, context=None, headers=None, body=None):
    require(origin(url) == expected_origin, "Request escaped its configured origin")
    scheme, host, port = expected_origin
    parts = urlsplit(url)
    require(parts.path.startswith("/") and not parts.path.startswith("//"), "Invalid HTTP request path")
    if scheme == "https":
        require(context is not None, "TLS trust is required")
        connection = http.client.HTTPSConnection(host, port, timeout=10, context=context)
    else:
        require(host in {"127.0.0.1", "::1", "localhost"}, "Plain HTTP requires loopback")
        connection = http.client.HTTPConnection(host, port, timeout=10)
    try:
        target = parts.path + ("?" + parts.query if parts.query else "")
        connection.request("GET" if body is None else "POST", target, body=body, headers=headers or {})
        with connection.getresponse() as reply:
            content = reply.read(MAX_RESPONSE + 1)
            require(len(content) <= MAX_RESPONSE, "HTTP response exceeded the acceptance limit")
            return reply.status, content
    finally:
        connection.close()


def sign_es256(key, data):
    r, s = utils.decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def jwk(public_key):
    point = public_key.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64(point.x.to_bytes(32, "big")),
            "y": b64(point.y.to_bytes(32, "big"))}


def jwt(header, claims, key):
    data = ".".join(b64(json_bytes(part)) for part in (header, claims))
    return data + "." + b64(sign_es256(key, data.encode("ascii")))


def request_object(uri, wallet_origin, context, verifier):
    query = urlsplit(uri)
    require(query.scheme in {"haip-vp", "openid4vp"} and not query.netloc and not query.path,
            "Expected a wallet authorization URI")
    parameters = parse_qs(query.query, strict_parsing=True, max_num_fields=4)
    client_id = "x509_hash:" + b64(verifier.fingerprint(hashes.SHA256()))
    require(parameters.get("client_id") == [client_id], "Unexpected wallet client ID")
    request_uris = parameters.get("request_uri", [])
    require(len(request_uris) == 1, "Expected a single Request Object URI")
    status, body = request(request_uris[0], wallet_origin, context=context,
                           headers={"Accept": "application/oauth-authz-req+jwt"})
    require(status == 200, f"Request Object returned HTTP {status}")
    header, payload, signature = body.decode("ascii").split(".")
    raw = unb64(signature)
    require(len(raw) == 64 and json.loads(unb64(header)).get("alg") == "ES256",
            "Unexpected Request Object signature algorithm")
    encoded_signature = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    verifier.public_key().verify(encoded_signature, f"{header}.{payload}".encode("ascii"), ec.ECDSA(hashes.SHA256()))
    claims = json.loads(unb64(payload))
    require(claims["client_id"] == client_id and claims["response_mode"] == "direct_post.jwt"
            and origin(claims["response_uri"]) == wallet_origin,
            "Request Object did not use the configured encrypted wallet response")
    require(isinstance(claims["nonce"], str) and isinstance(claims["state"], str)
            and len(claims["nonce"]) >= 16 and len(claims["state"]) >= 16,
            "Wallet request must bind state and nonce")
    return claims


def issue_sd_jwt(issuer_key, issuer_cert, holder, surname):
    now = int(time.time())
    disclosure = b64(json_bytes([secrets.token_urlsafe(16), "family_name", surname]))
    issuer_token = jwt(
        {"typ": "dc+sd-jwt", "alg": "ES256",
         "x5c": [base64.b64encode(issuer_cert.public_bytes(serialization.Encoding.DER)).decode("ascii")]},
        {"iss": ISSUER, "vct": VCT, "iat": now, "nbf": now - 30, "exp": now + 300,
         "_sd_alg": "sha-256", "_sd": [b64(hashlib.sha256(disclosure.encode("ascii")).digest())],
         "cnf": {"jwk": jwk(holder.public_key())}},
        issuer_key,
    )
    return f"{issuer_token}~{disclosure}~"


def bind_sd_jwt(disclosed, holder, *, audience, nonce):
    return disclosed + jwt(
        {"typ": "kb+jwt", "alg": "ES256"},
        {"iat": int(time.time()), "aud": audience, "nonce": nonce,
         "sd_hash": b64(hashlib.sha256(disclosed.encode("ascii")).digest())},
        holder,
    )


def tagged(value):
    return cbor2.CBORTag(24, cbor2.dumps(value))


def cose_sign(key, payload, *, headers=None, detached=False):
    protected = cbor2.dumps({1: -7})
    return [protected, headers or {}, None if detached else payload,
            sign_es256(key, cbor2.dumps(["Signature1", protected, b"", payload]))]


def issue_mdoc(issuer_key, issuer_cert, device, surname):
    item = tagged({"random": secrets.token_bytes(16), "digestID": 0,
                   "elementIdentifier": "family_name", "elementValue": surname})
    now = datetime.now(timezone.utc)
    times = {
        field: cbor2.CBORTag(0, instant.strftime("%Y-%m-%dT%H:%M:%SZ"))
        for field, instant in (("signed", now - timedelta(seconds=10)),
                               ("validFrom", now - timedelta(seconds=5)),
                               ("validUntil", now + timedelta(minutes=8)))
    }
    point = device.public_key().public_numbers()
    mso = {
        "version": "1.0", "digestAlgorithm": "SHA-256", "docType": DOC_TYPE,
        "valueDigests": {DOC_TYPE: {0: hashlib.sha256(cbor2.dumps(item)).digest()}},
        "deviceKeyInfo": {"deviceKey": {1: 2, -1: 1, -2: point.x.to_bytes(32, "big"), -3: point.y.to_bytes(32, "big")}},
        "validityInfo": times,
    }
    issuer_auth = cose_sign(issuer_key, cbor2.dumps(tagged(mso)),
                            headers={33: issuer_cert.public_bytes(serialization.Encoding.DER)})
    return {"nameSpaces": {DOC_TYPE: [item]}, "issuerAuth": issuer_auth}


def bind_mdoc(issuer_signed, device, claims, nonce, recipient):
    thumbprint = hashlib.sha256(json.dumps(
        {key: recipient[key] for key in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True
    ).encode("ascii")).digest()
    handover = hashlib.sha256(cbor2.dumps([claims["client_id"], nonce, thumbprint, claims["response_uri"]])).digest()
    transcript = [None, None, ["OpenID4VPHandover", handover]]
    namespaces = tagged({})
    device_auth = cbor2.dumps(tagged(["DeviceAuthentication", transcript, DOC_TYPE, namespaces]))
    document = {
        "docType": DOC_TYPE,
        "issuerSigned": issuer_signed,
        "deviceSigned": {"nameSpaces": namespaces,
                         "deviceAuth": {"deviceSignature": cose_sign(device, device_auth, detached=True)}},
    }
    return b64(cbor2.dumps({"version": "1.0", "documents": [document], "status": 0}))


def encryption_key(claims):
    metadata = claims["client_metadata"]
    encryption = metadata.get("encrypted_response_enc_values_supported") or ["A128GCM"]
    keys = [key for key in metadata["jwks"]["keys"] if key.get("kty") == "EC" and key.get("crv") == "P-256"
            and key.get("use", "enc") == "enc" and key.get("alg", "ECDH-ES") == "ECDH-ES"]
    require(len(keys) == 1 and encryption[0] in {"A128GCM", "A192GCM", "A256GCM"},
            "Expected one compatible ECDH-ES response encryption key")
    return keys[0], encryption[0]


def jwe(recipient, encryption, party_v, response):
    ephemeral = new_key()
    public_key = ec.EllipticCurvePublicNumbers(
        int.from_bytes(unb64(recipient["x"]), "big"), int.from_bytes(unb64(recipient["y"]), "big"), ec.SECP256R1(),
    ).public_key()
    length = {"A128GCM": 16, "A192GCM": 24, "A256GCM": 32}[encryption]
    header = {"alg": "ECDH-ES", "enc": encryption, "epk": jwk(ephemeral.public_key())}
    if party_v:
        header["apv"] = b64(party_v)
    if "kid" in recipient:
        header["kid"] = recipient["kid"]
    def sized(value):
        return struct.pack(">I", len(value)) + value
    other = sized(encryption.encode("ascii")) + sized(b"") + sized(party_v) + struct.pack(">I", length * 8)
    key = ConcatKDFHash(algorithm=hashes.SHA256(), length=length, otherinfo=other).derive(
        ephemeral.exchange(ec.ECDH(), public_key)
    )
    protected = b64(json_bytes(header))
    iv = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(iv, json_bytes(response), protected.encode("ascii"))
    return ".".join((protected, "", b64(iv), b64(ciphertext[:-16]), b64(ciphertext[-16:])))


@dataclass(frozen=True)
class WalletTarget:
    origin: tuple
    tls: ssl.SSLContext
    verifier: x509.Certificate
    adapter: str

    @classmethod
    def from_files(cls, url, ca, verifier, adapter):
        wallet_origin = origin(url)
        parts = urlsplit(url)
        require(wallet_origin[0] == "https" and not parts.path and not parts.query,
                "The wallet target must be an HTTPS origin")
        return cls(wallet_origin, ssl.create_default_context(cafile=str(ca)),
                   x509.load_pem_x509_certificate(verifier.read_bytes()), adapter)


@dataclass(frozen=True)
class SyntheticCredential:
    format: str
    holder: ec.EllipticCurvePrivateKey
    issuer_signed: str | dict

    @classmethod
    def issue(cls, format_name, directory, surname):
        holder = new_key()
        issuer_cert = x509.load_pem_x509_certificate((directory / "issuer.pem").read_bytes())
        issuer_key = serialization.load_pem_private_key((directory / "issuer-key.pem").read_bytes(), password=None)
        if format_name == "dc+sd-jwt":
            issuer_signed = issue_sd_jwt(issuer_key, issuer_cert, holder, surname)
        else:
            require(format_name == "mso_mdoc", "Expected a supported acceptance credential")
            issuer_signed = issue_mdoc(issuer_key, issuer_cert, holder, surname)
        return cls(format_name, holder, issuer_signed)

    def bind(self, claims, nonce, recipient):
        if self.format == "dc+sd-jwt":
            return bind_sd_jwt(self.issuer_signed, self.holder, audience=claims["client_id"], nonce=nonce)
        return bind_mdoc(self.issuer_signed, self.holder, claims, nonce, recipient)


def present(target, uri, credential, *, wrong_nonce, observed_nonces, check_credo_envelope=False,
            credo_advisory_case=None):
    if credo_advisory_case is not None:
        require(credo_advisory_case in CREDO_ADVISORY_CASES and target.adapter == "credo"
                and credential.format == "dc+sd-jwt" and not wrong_nonce,
                "The Credo advisory cases require a current SD-JWT challenge")
    claims = request_object(uri, target.origin, target.tls, target.verifier)
    recipient, encryption = encryption_key(claims)
    [query] = claims["dcql_query"]["credentials"]
    metadata, claim_path = (
        ({"vct_values": [VCT]}, ["family_name"])
        if credential.format == "dc+sd-jwt"
        else ({"doctype_value": DOC_TYPE}, [DOC_TYPE, "family_name"])
    )
    require(query["format"] == credential.format and query["meta"] == metadata
            and [claim["path"] for claim in query["claims"]] == [claim_path],
            "The Request Object requested a different credential profile")
    challenge = claims["nonce"]
    require(challenge not in observed_nonces, "A wallet challenge was reused")
    observed_nonces.add(challenge)
    nonce = secrets.token_urlsafe(32) if wrong_nonce else challenge
    require(not wrong_nonce or nonce != challenge, "The negative fixture must use a wrong nonce")
    if credo_advisory_case == "unbound-disclosure":
        # Bind the holder proof to the altered bytes and current challenge.
        # The extra disclosure is absent from the issuer's signed digest set.
        unmatched = b64(json_bytes([secrets.token_urlsafe(16), "unmatched_claim", True]))
        disclosed = f"{credential.issuer_signed}{unmatched}~"
        presentation = bind_sd_jwt(disclosed, credential.holder, audience=claims["client_id"], nonce=nonce)
    else:
        presentation = credential.bind(claims, nonce, recipient)
    party_v = (b"" if target.adapter == "eudi-reference" and credential.format == "dc+sd-jwt"
               else challenge.encode("ascii"))
    payload = {"state": claims["state"], "vp_token": {query["id"]: [presentation]}}
    if credo_advisory_case == "pex-downgrade":
        payload["vp_token"] = presentation
        payload["presentation_submission"] = {
            "id": "legacy-submission",
            "definition_id": "legacy-definition",
            "descriptor_map": [{"id": query["id"], "path": "$", "format": "vc+sd-jwt"}],
        }
    response = jwe(recipient, encryption, party_v, payload)

    def submit(envelope):
        status, _ = request(
            claims["response_uri"], target.origin, context=target.tls,
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            body=urlencode({"response": envelope}).encode("ascii"),
        )
        return status

    if check_credo_envelope:
        # The invalid protected header retains the compact envelope's form.
        malformed = b64(b"not a JSON protected header") + "." + response.split(".", 1)[1]
        require(submit(malformed) == 400, "Credo did not reject the malformed envelope before verification")
    status = submit(response)
    rejected = wrong_nonce or credo_advisory_case is not None
    require((400 <= status < 500) if rejected else (200 <= status < 300),
            f"Wallet returned unexpected HTTP {status}")
    if check_credo_envelope or credo_advisory_case is not None:
        require(submit(response) == 409, "Credo accepted a replayed wallet callback")
    return status


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate private synthetic wallet acceptance fixtures")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    initialize(args.directory, args.host)

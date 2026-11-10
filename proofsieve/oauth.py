"""Validate RS256 Keycloak service-account access tokens."""

import base64
import binascii
import http.client
import re
import socket
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .access import MAX_GRANTS, MAX_PRINCIPALS, Principal, _IDENTITY
from .guard import load_json, validate_endpoint


MAX_TOKEN_BYTES = 12 * 1024
MAX_TOKEN_LIFETIME = 15 * 60
CLOCK_SKEW = 30
MAX_JWKS_BYTES = 256 * 1024
MAX_JWKS_KEYS = 32
JWKS_TTL = 5 * 60
JWKS_REFRESH_INTERVAL = 2
JWKS_TIMEOUT = 3

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", re.ASCII)
_KID = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._:-]{0,127}", re.ASCII)
_ISSUER = re.compile(r"(?:https|http)://(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::[1-9][0-9]{0,4})?"
                     r"(?:/[A-Za-z0-9_.~-]+)*/realms/[A-Za-z0-9_.~-]+", re.ASCII)
_B64 = re.compile(r"[A-Za-z0-9_-]+", re.ASCII)
_JWT_BEARER = re.compile(r"(?i:Bearer) +([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)", re.ASCII)
_OPTIONS = {"issuer", "audience", "serviceAccounts"}


def _decode(component):
    if not isinstance(component, str) or not _B64.fullmatch(component):
        raise ValueError("Ungültige Base64url-Kodierung.")
    try:
        decoded = base64.urlsafe_b64decode(component + "=" * (-len(component) % 4))
    except binascii.Error as exc:
        raise ValueError("Ungültige Base64url-Kodierung.") from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != component:
        raise ValueError("Nicht kanonische Base64url-Kodierung.")
    return decoded


def _name(value):
    return isinstance(value, str) and bool(_NAME.fullmatch(value))


def _key_url(issuer, allow_http):
    if not isinstance(issuer, str) or len(issuer) > 512 or not _ISSUER.fullmatch(issuer):
        raise ValueError("oauth.issuer muss eine vollständige Keycloak-Realm-URL sein.")
    url = urlsplit(issuer)
    if (url.port == 0 or any(segment in {".", ".."} for segment in url.path.split("/"))
            or url.scheme != "https" and not (allow_http and url.hostname in {"127.0.0.1", "::1"})):
        raise ValueError("oauth.issuer braucht HTTPS. Explizite Loopback-Tests dürfen HTTP verwenden.")
    return issuer + "/protocol/openid-connect/certs"


def _interrupt(connection_socket):
    try:
        connection_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _read_jwks(response):
    headers = response.headers
    if (response.status != 200 or len(headers.get_all("Content-Type", [])) != 1
            or headers.get_content_type() not in {"application/jwk-set+json", "application/json"}
            or headers.get_all("Content-Encoding", [])):
        raise ValueError("Unerwartete Antwort vom Keycloak-Schlüsselendpunkt.")
    body = bytearray()
    while len(body) <= MAX_JWKS_BYTES:
        chunk = response.read1(min(16 * 1024, MAX_JWKS_BYTES + 1 - len(body)))
        if not chunk:
            if response.length in {None, 0}:
                return load_json(body)
            break
        body.extend(chunk)
    raise ValueError("Die Keycloak-Schlüsselantwort ist unvollständig oder überschreitet ein Limit.")


def _fetch_jwks(url):
    target = urlsplit(url)
    connection_type = http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(target.netloc, timeout=JWKS_TIMEOUT)
    deadline = time.monotonic() + JWKS_TIMEOUT
    try:
        connection.connect()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Der Keycloak-Schlüsselabruf hat das Zeitlimit überschritten.")
        connection.sock.settimeout(remaining)
        timer = threading.Timer(remaining, _interrupt, args=(connection.sock,))
        timer.daemon = True
        timer.start()
        try:
            connection.request("GET", target.path, headers={"Accept": "application/jwk-set+json, application/json"})
            with connection.getresponse() as response:
                keys = _read_jwks(response)
            if time.monotonic() >= deadline:
                raise TimeoutError("Der Keycloak-Schlüsselabruf hat das Zeitlimit überschritten.")
            return keys
        finally:
            timer.cancel()
    finally:
        connection.close()


def _signature_keys(document):
    records = document.get("keys") if type(document) is dict else None
    if type(records) is not list or not 1 <= len(records) <= MAX_JWKS_KEYS:
        raise ValueError("Der Keycloak-Schlüsselsatz ist ungültig.")
    keys = {}
    for record in records:
        if type(record) is not dict:
            raise ValueError("Der Keycloak-Schlüsselsatz ist ungültig.")
        if (record.get("kty") != "RSA" or record.get("alg", "RS256") != "RS256"
                or record.get("use", "sig") != "sig" or record.get("key_ops", ["verify"]) != ["verify"]):
            continue
        kid = record.get("kid")
        if not isinstance(kid, str) or not _KID.fullmatch(kid) or kid in keys:
            raise ValueError("Doppelte oder ungültige Keycloak-Schlüssel-ID.")
        modulus, exponent = _decode(record.get("n")), _decode(record.get("e"))
        if not 256 <= len(modulus) <= 512 or not 1 <= len(exponent) <= 4 or not modulus[0] or not exponent[0]:
            raise ValueError("Der RSA-Signaturschlüssel erfüllt das Profil nicht.")
        n = int.from_bytes(modulus, "big")
        e = int.from_bytes(exponent, "big")
        if not 2048 <= n.bit_length() <= 4096 or n % 2 != 1 or e < 3 or e % 2 != 1:
            raise ValueError("Der RSA-Signaturschlüssel erfüllt das Profil nicht.")
        keys[kid] = rsa.RSAPublicNumbers(e, n).public_key()
    if not keys:
        raise ValueError("Der Keycloak-Schlüsselsatz enthält keine RS256-Signaturschlüssel.")
    return keys


class _KeyCache:
    def __init__(self, url):
        self.url = url
        self.keys = {}
        self.expires = 0.0
        self.next_refresh = 0.0
        self.lock = threading.Lock()
        self.pending_refresh = None

    def get(self, kid):
        with self.lock:
            now = time.monotonic()
            if now < self.expires and kid in self.keys:
                return self.keys[kid]
            pending = self.pending_refresh
            if pending is None:
                if now < self.next_refresh:
                    return None
                self.pending_refresh = threading.Event()

        if pending is not None:
            if not pending.wait(JWKS_TIMEOUT):
                return None
            with self.lock:
                return self.keys.get(kid) if time.monotonic() < self.expires else None

        keys = None
        try:
            keys = _signature_keys(_fetch_jwks(self.url))
        except (OSError, http.client.HTTPException, ValueError, UnsupportedAlgorithm):
            pass
        finally:
            with self.lock:
                now = time.monotonic()
                if keys is not None:
                    self.keys = keys
                    self.expires = now + JWKS_TTL
                self.next_refresh = now + JWKS_REFRESH_INTERVAL
                self.pending_refresh.set()
                self.pending_refresh = None
        return keys.get(kid) if keys is not None else None


@dataclass(frozen=True)
class _ServiceAccount:
    id: str
    grants: dict[str, str]


class OAuthAccess:
    def __init__(self, issuer, audience, accounts, key_url):
        self.issuer = issuer
        self.audience = audience
        self.accounts = accounts
        self.keys = _KeyCache(key_url)

    @classmethod
    def load(cls, config, opaque_ids):
        if type(config) is not dict or config.keys() not in (_OPTIONS, _OPTIONS | {"allowLoopbackHttp"}):
            raise ValueError("oauth braucht issuer, audience und serviceAccounts.")
        issuer, audience, accounts = config["issuer"], config["audience"], config["serviceAccounts"]
        allow_http = config.get("allowLoopbackHttp", False)
        if type(allow_http) is not bool or not _name(audience):
            raise ValueError("oauth.audience muss eine Client-ID und allowLoopbackHttp ein Boolean sein.")
        url = _key_url(issuer, allow_http)
        if type(accounts) is not list or not 1 <= len(accounts) <= MAX_PRINCIPALS:
            raise ValueError("Ungültige Anzahl an oauth.serviceAccounts.")
        identities = {}
        ids = set(opaque_ids)
        for account in accounts:
            if type(account) is not dict or account.keys() != {"id", "clientId", "subject", "grants"}:
                raise ValueError("Ein oauth.serviceAccount braucht id, clientId, subject und grants.")
            identifier, client, subject, grants = (
                account[field] for field in ("id", "clientId", "subject", "grants")
            )
            if (not isinstance(identifier, str) or not _IDENTITY.fullmatch(identifier)
                    or not _name(client) or not _name(subject)):
                raise ValueError("Ungültige Service-Account-Kennung.")
            if identifier in ids or (client, subject) in identities:
                raise ValueError("Service-Account-Identitäten müssen eindeutig sein.")
            if type(grants) is not dict or len(grants) > MAX_GRANTS or not all(_name(role) for role in grants):
                raise ValueError("Ungültige OAuth-Rollenzuordnung.")
            identities[client, subject] = _ServiceAccount(
                identifier, {role: validate_endpoint(endpoint) for role, endpoint in grants.items()},
            )
            ids.add(identifier)
        return cls(issuer, audience, identities, url)

    def _claims(self, payload):
        if (type(payload) is not dict or payload.get("iss") != self.issuer or payload.get("typ") != "Bearer"
                or "cnf" in payload):
            return None
        audience = payload.get("aud")
        if audience != self.audience and not (
            type(audience) is list and all(isinstance(item, str) for item in audience) and self.audience in audience
        ):
            return None
        client, subject = payload.get("azp"), payload.get("sub")
        if not _name(client) or not _name(subject):
            return None
        return self.accounts.get((client, subject))

    @staticmethod
    def _current(payload):
        issued, expiry = payload.get("iat"), payload.get("exp")
        not_before = payload.get("nbf", issued)
        now = time.time()
        return (
            all(type(value) is int for value in (issued, expiry, not_before))
            and 0 <= issued <= now + CLOCK_SKEW
            and now < expiry <= issued + MAX_TOKEN_LIFETIME
            and 0 <= not_before < expiry and not_before <= now + CLOCK_SKEW
            and issued < expiry
        )

    def authenticate(self, header):
        if len(header) > MAX_TOKEN_BYTES:
            return None
        token = _JWT_BEARER.fullmatch(header)
        if token is None:
            return None
        encoded_header, encoded_payload, encoded_signature = token.groups()
        try:
            jose = load_json(_decode(encoded_header))
            if (type(jose) is not dict or jose.keys() != {"typ", "alg", "kid"} or jose["typ"] != "JWT"
                    or jose["alg"] != "RS256" or not isinstance(jose["kid"], str) or not _KID.fullmatch(jose["kid"])):
                return None
            payload = load_json(_decode(encoded_payload))
            account = self._claims(payload)
            if account is None or not self._current(payload):
                return None
            signature = _decode(encoded_signature)
            key = self.keys.get(jose["kid"])
            if key is None:
                return None
            signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
            key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            if not self._current(payload):
                return None
            access = payload.get("resource_access", {})
            if type(access) is not dict:
                return None
            resource = access.get(self.audience, {})
            roles = resource.get("roles", []) if type(resource) is dict else None
            if type(roles) is not list or not all(isinstance(role, str) for role in roles):
                return None
            endpoints = tuple(dict.fromkeys(account.grants[role] for role in roles if role in account.grants))
            return Principal(account.id, "verifier", endpoints)
        except (ValueError, InvalidSignature, UnsupportedAlgorithm):
            return None

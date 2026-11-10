"""Authenticate access tokens and enforce exact endpoint grants."""

import hashlib
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from .guard import load_json, validate_endpoint


MAX_CONFIG_BYTES = 256 * 1024
MAX_PRINCIPALS = 128
MAX_GRANTS = 128
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
# A 32-byte token has two zero pad bits in its last base64url character.
_BEARER = re.compile(r"(?i:Bearer) +([A-Za-z0-9_-]{42}[AEIMQUYcgkosw048])", re.ASCII)


@dataclass(frozen=True)
class Principal:
    id: str
    role: str
    endpoints: tuple[str, ...]

    def allows(self, endpoint: str) -> bool:
        if self.role == "admin" and self.endpoints == ("*",):
            try:
                validate_endpoint(endpoint)
            except ValueError:
                return False
            return True
        return endpoint in self.endpoints


def _read_config(path: Path) -> bytes:
    expected = path.lstat()
    if not stat.S_ISREG(expected.st_mode):
        raise ValueError("Die Zugriffskonfiguration muss eine reguläre Datei sein.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        actual = os.fstat(fd)
        if not stat.S_ISREG(actual.st_mode) or not os.path.samestat(expected, actual):
            raise ValueError("Die Zugriffskonfiguration wurde beim Öffnen verändert.")
        if hasattr(os, "geteuid") and (actual.st_uid != os.geteuid() or actual.st_mode & 0o077):
            raise ValueError("Die Zugriffskonfiguration darf nur dem Prozessnutzer zugänglich sein.")
        with os.fdopen(fd, "rb", closefd=False) as config:
            data = config.read(MAX_CONFIG_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_CONFIG_BYTES:
        raise ValueError("Die Zugriffskonfiguration überschreitet das Größenlimit.")
    return data


def _parse_principal(record) -> tuple[bytes, Principal]:
    if type(record) is not dict or record.keys() != {"id", "role", "tokenSha256", "endpoints"}:
        raise ValueError("Ein Zugriffseintrag braucht id, role, tokenSha256 und endpoints.")
    identity, role, digest, endpoints = (record[key] for key in ("id", "role", "tokenSha256", "endpoints"))
    if not isinstance(identity, str) or not _IDENTITY.fullmatch(identity):
        raise ValueError("Ungültige ID in der Zugriffskonfiguration.")
    if role not in ("admin", "verifier"):
        raise ValueError("Eine Zugriffsrolle muss admin oder verifier sein.")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ValueError("Ein Zugriffseintrag braucht einen SHA-256-Digest in Kleinschreibung.")
    if type(endpoints) is not list or not 1 <= len(endpoints) <= MAX_GRANTS:
        raise ValueError("Ein Zugriffseintrag braucht eine begrenzte Liste erlaubter Prüfendpunkte.")
    if endpoints != ["*"] or role != "admin":
        for endpoint in endpoints:
            validate_endpoint(endpoint)
        if len(set(endpoints)) != len(endpoints):
            raise ValueError("Prüfendpunkte dürfen je Zugriffseintrag nur einmal vorkommen.")
    return bytes.fromhex(digest), Principal(identity, role, tuple(endpoints))


class AccessPolicy:
    def __init__(self, entries: tuple[tuple[bytes, Principal], ...], oauth=None):
        self._entries = entries
        self._oauth = oauth

    @classmethod
    def load(cls, path: Path) -> "AccessPolicy":
        raw = _read_config(path)
        try:
            document = load_json(raw)
        except ValueError:
            raise ValueError("Ungültiges JSON in der Zugriffskonfiguration.") from None
        schemas = {1: {"version", "principals"}, 2: {"version", "principals", "oauth"}}
        version = document.get("version") if type(document) is dict else None
        if type(version) is not int or document.keys() != schemas.get(version):
            raise ValueError("Die Zugriffskonfiguration braucht Version 1 mit principals oder Version 2 mit principals und oauth.")
        records = document["principals"]
        if type(records) is not list or not 1 <= len(records) <= MAX_PRINCIPALS:
            raise ValueError("Ungültige Anzahl von Zugriffseinträgen.")
        entries = tuple(_parse_principal(record) for record in records)
        if not any(principal.role == "admin" for _, principal in entries):
            raise ValueError("Die Zugriffskonfiguration braucht mindestens einen Admin.")
        if (len({digest for digest, _ in entries}) != len(entries)
                or len({principal.id for _, principal in entries}) != len(entries)):
            raise ValueError("IDs und Token-Digests müssen eindeutig sein.")
        if version == 2:
            from .oauth import OAuthAccess

            oauth = OAuthAccess.load(document["oauth"], {principal.id for _, principal in entries})
            return cls(entries, oauth)
        return cls(entries)

    def authenticate(self, headers) -> Principal | None:
        values = headers.get_all("Authorization", [])
        if len(values) != 1 or not isinstance(values[0], str):
            return None
        match = _BEARER.fullmatch(values[0])
        if not match:
            return self._oauth.authenticate(values[0]) if self._oauth is not None else None
        supplied = hashlib.sha256(match[1].encode("ascii")).digest()
        authenticated = None
        for expected, principal in self._entries:
            if secrets.compare_digest(supplied, expected):
                authenticated = principal
        return authenticated

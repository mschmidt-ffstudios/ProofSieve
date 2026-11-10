"""Durable, data-minimized records of live verification decisions."""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .wallet_sessions import COMPLETION_RECOVERY_SECONDS, SessionConflict


_APPLICATION_ID = 0x50535645
_MAX_FORWARDING_RESERVATIONS = 100_000
_MAX_EXPORTED_DECISIONS = 32
_MAX_EXPORT_BYTES = 256 * 1024
_MAX_CHECKS_BYTES = 16 * 1024
_MAX_CHECKS = 16
_EXPORT_DOMAIN = b"ProofSieve evidence export v1\x00"
_CANONICALIZATION = "proofsieve-json-v1"
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_ENDPOINT = re.compile(r"/verify(?:/[A-Za-z0-9_-]+)*")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\+00:00")
_DECISION_OUTCOMES = {"allow", "deny", "indeterminate"}
_DELIVERY_STATES = {"pending", "delivered", "rejected", "unknown"}
WALLET_EVIDENCE_INTERRUPTED = "wallet_evidence_interrupted"
_RETIRED_WALLET_DECISION = object()
_PROVENANCE_FIELDS = (
    "kind", "outcome", "reason", "item", "signer", "connector", "connectorProfile", "adapter", "profileVersion",
)
_CREDENTIAL_FORMATS = {
    "sd-jwt": "dc+sd-jwt",
    "mdoc": "mso_mdoc",
    "jwt-vc": "jwt-vc",
    "vc-data-integrity": "vc-data-integrity",
}
_PROVENANCE_FORMATS = {
    *_CREDENTIAL_FORMATS.values(), "bundle", "document", "raw", "pades",
    "cades-detached", "xades-detached", "jades-detached", "cbades-detached", "asic-s", "asic-e", "rfc3161",
}


def canonical_bytes(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def rule_version(rule):
    return hashlib.sha256(canonical_bytes(rule)).hexdigest()


def _base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value, size):
    if type(value) is not str or len(value) != (size * 8 + 5) // 6 or not _B64URL.fullmatch(value):
        raise ValueError("Invalid evidence signature encoding.")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != size or _base64url(raw) != value:
        raise ValueError("Invalid evidence signature encoding.")
    return raw


def verify_evidence_export(bundle, *, public_key):
    """Check a portable evidence export against an independently pinned public key."""
    try:
        if (type(bundle) is not dict or bundle.keys() != {"version", "scope", "decisions", "truncated", "integrity"}
                or type(bundle["version"]) is not int or bundle["version"] != 1):
            return False
        public_bytes = _decode_base64url(public_key, 32)
        integrity = bundle["integrity"]
        if (type(integrity) is not dict
                or integrity.keys() != {"algorithm", "canonicalization", "keyId", "publicKey", "signature"}
                or integrity["algorithm"] != "Ed25519" or integrity["canonicalization"] != _CANONICALIZATION
                or integrity["publicKey"] != public_key
                or integrity["keyId"] != hashlib.sha256(public_bytes).hexdigest()):
            return False
        signature = _decode_base64url(integrity["signature"], 64)
        if len(canonical_bytes(bundle)) > _MAX_EXPORT_BYTES:
            return False
        payload = {key: value for key, value in bundle.items() if key != "integrity"}
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, _EXPORT_DOMAIN + canonical_bytes(payload))
    except (InvalidSignature, TypeError, ValueError, RecursionError):
        return False
    return True


class ForwardingConflict(ValueError):
    """The operation identifier already belongs to another input."""


class ForwardingEvidenceExpired(ValueError):
    """A delivery remains reserved after its approval left evidence retention."""


class EvidenceExportError(ValueError):
    """Stored evidence is invalid or exceeds the export bounds."""


@dataclass(frozen=True)
class ForwardingReservation:
    id: str
    state: str
    upstream_status: int | None
    acquired: bool = False


class EvidenceStore:
    def __init__(self, path: Path, *, retention_days=30):
        if type(retention_days) is not int or not 1 <= retention_days <= 365:
            raise ValueError("Die Aufbewahrungsdauer muss zwischen 1 und 365 Tagen liegen.")
        if not path.is_absolute():
            path = path.absolute()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise ValueError("Das Nachweisverzeichnis muss dem Dienst gehören und Modus 0700 haben.")
        path = path.parent.resolve() / path.name
        flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(path, flags, 0o600)
        try:
            file = os.fstat(descriptor)
            if not stat.S_ISREG(file.st_mode) or file.st_uid != os.geteuid() or file.st_mode & 0o077:
                raise ValueError("Die Nachweisdatei muss eine private reguläre Datei des Dienstes sein.")
        finally:
            os.close(descriptor)
        self.path = path
        self.retention = timedelta(days=retention_days)
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            identity = db.execute("PRAGMA application_id").fetchone()[0]
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if (identity, version) == (0, 0):
                if db.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone() is not None:
                    raise ValueError("Die angegebene Datenbank gehört nicht zu ProofSieve.")
                db.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                db.execute("PRAGMA user_version = 1")
            elif (identity, version) != (_APPLICATION_ID, 1):
                raise ValueError("Die Version der Nachweisdatenbank wird nicht unterstützt.")
            db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
            db.execute("INSERT OR IGNORE INTO settings VALUES ('requestMacKey', ?)", (secrets.token_bytes(32),))
            db.execute("INSERT OR IGNORE INTO settings VALUES ('exportEd25519Key', ?)", (secrets.token_bytes(32),))
            db.execute("""CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY, decided_at TEXT NOT NULL, endpoint TEXT NOT NULL,
                caller TEXT NOT NULL, operation_id TEXT NOT NULL, rule_version TEXT NOT NULL,
                input_mac TEXT NOT NULL, outcome TEXT NOT NULL, reason TEXT NOT NULL, checks TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS decisions_time ON decisions (decided_at)")
            db.execute("""CREATE INDEX IF NOT EXISTS decisions_operation
                ON decisions (caller, endpoint, operation_id, decided_at, id)""")
            db.execute("""CREATE TABLE IF NOT EXISTS wallet_completion_commits (
                id TEXT PRIMARY KEY, committed_at REAL NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS wallet_commits_time ON wallet_completion_commits (committed_at)")
            # Keep reservations independent of decision retention to prevent a later replay.
            db.execute("""CREATE TABLE IF NOT EXISTS forwarding (
                id TEXT UNIQUE NOT NULL, decision_id TEXT NOT NULL, endpoint TEXT NOT NULL,
                caller TEXT NOT NULL, operation_id TEXT NOT NULL, input_mac TEXT NOT NULL,
                reserved_at TEXT NOT NULL, completed_at TEXT, upstream_status INTEGER,
                state TEXT NOT NULL CHECK (state IN ('pending', 'delivered', 'rejected', 'unknown')),
                PRIMARY KEY (endpoint, caller, operation_id)
            )""")
            self.key = db.execute("SELECT value FROM settings WHERE key = 'requestMacKey'").fetchone()[0]
            if type(self.key) is not bytes or len(self.key) != 32:
                raise ValueError("Der Schlüssel für den Nachweisfingerabdruck ist ungültig.")
            signing_key = db.execute("SELECT value FROM settings WHERE key = 'exportEd25519Key'").fetchone()[0]
            if type(signing_key) is not bytes or len(signing_key) != 32:
                raise ValueError("Der Signaturschlüssel für Nachweisexporte ist ungültig.")
            self._export_key = Ed25519PrivateKey.from_private_bytes(signing_key)
            public_key = self._export_key.public_key().public_bytes_raw()
            self.export_public_key = _base64url(public_key)
            self._export_key_id = hashlib.sha256(public_key).hexdigest()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=1)
        try:
            db.execute("PRAGMA trusted_schema = OFF")
            db.execute("PRAGMA secure_delete = ON")
        except sqlite3.Error:
            db.close()
            raise
        return db

    def _wallet_decision_id(self, scope, session, kind):
        binding = canonical_bytes([kind, *scope, session])
        return str(uuid.UUID(bytes=hmac.digest(self.key, binding, "sha256")[:16], version=4))

    def record(self, *, endpoint, caller, operation_id, data, version, outcome, reason, checks,
               wallet_session=None, expiry_replay_deadline=None):
        scope = (endpoint, caller, operation_id)
        if wallet_session is None:
            decision_id = str(uuid.uuid4())
            replay_deadline = None
        elif expiry_replay_deadline is None:
            decision_id = self._wallet_decision_id(scope, wallet_session.id, "wallet-completion")
            replay_deadline = wallet_session.created_at + COMPLETION_RECOVERY_SECONDS
        else:
            decision_id = self._wallet_decision_id(scope, wallet_session.id, "wallet-expiry")
            replay_deadline = expiry_replay_deadline
        fingerprint = self._input_mac(*scope, data)
        fields = (*scope, version, fingerprint, outcome, reason, canonical_bytes(checks).decode("ascii"))
        existing = self._insert_decision(decision_id, fields, wallet_replay_deadline=replay_deadline)
        if existing is _RETIRED_WALLET_DECISION and expiry_replay_deadline is not None:
            raise SessionConflict("The signed wallet expiry decision can no longer be written.")
        if existing is not None and (wallet_session is None or existing != fields):
            raise sqlite3.IntegrityError("Evidence decision identifier conflicts with another decision.")
        return decision_id

    def recover_wallet_completion(self, *, endpoint, caller, operation_id, version, session, started_at,
                                  fingerprint, check):
        """Record a missing completion as indeterminate, or recognize its existing decision."""
        scope = (endpoint, caller, operation_id)
        decision_id = self._wallet_decision_id(scope, session, "wallet-completion")
        fields = (*scope, version, fingerprint, "indeterminate", WALLET_EVIDENCE_INTERRUPTED,
                  canonical_bytes((check,)).decode("ascii"))
        existing = self._insert_decision(
            decision_id, fields, wallet_replay_deadline=started_at + COMPLETION_RECOVERY_SECONDS,
        )
        if existing is _RETIRED_WALLET_DECISION:
            return None
        if existing is None or existing == fields:
            return decision_id
        if existing[:5] != fields[:5]:
            raise sqlite3.IntegrityError("Wallet completion evidence does not match the sealed receipt.")
        return None

    def _insert_decision(self, decision_id, fields, *, wallet_replay_deadline=None):
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            now = datetime.now(timezone.utc)
            floor = self._prune_decisions(db, now)
            existing = db.execute(
                """SELECT endpoint, caller, operation_id, rule_version, input_mac, outcome, reason, checks
                   FROM decisions WHERE id = ?""", (decision_id,),
            ).fetchone()
            if existing is not None:
                return existing
            # Keep the existing floor and marker timestamp convention so older
            # completion receipts retain the same recovery boundary.
            marker_time = (None if wallet_replay_deadline is None
                           else wallet_replay_deadline - COMPLETION_RECOVERY_SECONDS)
            if marker_time is not None and (
                marker_time <= floor or db.execute(
                    "SELECT 1 FROM wallet_completion_commits WHERE id = ?", (decision_id,),
                ).fetchone() is not None
            ):
                return _RETIRED_WALLET_DECISION
            db.execute("INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (decision_id, now.isoformat(timespec="microseconds"), *fields))
            if marker_time is not None:
                db.execute("INSERT INTO wallet_completion_commits VALUES (?, ?)",
                           (decision_id, max(now.timestamp(), marker_time)))

    def _prune_decisions(self, db, now):
        cutoff = (now - self.retention).isoformat(timespec="microseconds")
        db.execute("DELETE FROM decisions WHERE decided_at < ?", (cutoff,))
        # A forward clock step can purge history before a subsequent clock correction.
        # Keep the recovery boundary monotonic even when older exports have expired.
        db.execute("""INSERT INTO settings VALUES ('walletRecoveryFloor', ?)
                      ON CONFLICT(key) DO UPDATE SET value = MAX(value, excluded.value)""",
                   (now.timestamp() - COMPLETION_RECOVERY_SECONDS,))
        floor, = db.execute("SELECT value FROM settings WHERE key = 'walletRecoveryFloor'").fetchone()
        db.execute("DELETE FROM wallet_completion_commits WHERE committed_at <= ?", (floor,))
        return floor

    def _input_mac(self, endpoint, caller, operation_id, data):
        binding = canonical_bytes([endpoint, caller, operation_id, data])
        return hmac.digest(self.key, binding, "sha256").hex()

    def export(self, *, endpoint, caller, operation_id, decision_id=None):
        """Return a bounded signed snapshot for one exact authenticated operation."""
        if not (
            type(endpoint) is str and len(endpoint) <= 128 and _ENDPOINT.fullmatch(endpoint)
            and type(caller) is str and _LABEL.fullmatch(caller)
            and type(operation_id) is str and _LABEL.fullmatch(operation_id)
            and (decision_id is None or type(decision_id) is str and _LABEL.fullmatch(decision_id))
        ):
            raise ValueError("Ungültiger Geltungsbereich für den Nachweisexport.")
        cutoff = (datetime.now(timezone.utc) - self.retention).isoformat(timespec="microseconds")
        operation = (caller, endpoint, operation_id)
        condition = "AND d.id = ?" if decision_id is not None else ""
        selection = (decision_id,) if decision_id is not None else ()
        with closing(self.connect()) as db:
            rows = db.execute(
                f"""SELECT d.id, d.decided_at, d.rule_version, d.input_mac, d.outcome, d.reason,
                          CASE WHEN length(CAST(d.checks AS BLOB)) <= ? THEN d.checks END,
                          f.id, f.state, f.reserved_at, f.completed_at, f.upstream_status
                   FROM decisions d
                   LEFT JOIN forwarding f ON f.decision_id = d.id AND f.caller = d.caller
                     AND f.endpoint = d.endpoint AND f.operation_id = d.operation_id AND f.input_mac = d.input_mac
                   WHERE d.caller = ? AND d.endpoint = ? AND d.operation_id = ? AND d.decided_at >= ?
                     {condition}
                   ORDER BY d.decided_at DESC, d.id DESC LIMIT ?""",
                (_MAX_CHECKS_BYTES, *operation, cutoff, *selection, _MAX_EXPORTED_DECISIONS + 1),
            ).fetchall()
        if not rows:
            return None
        payload = {
            "version": 1,
            "scope": {"caller": caller, "endpoint": endpoint, "operationId": operation_id},
            "decisions": [self._export_decision(row, operation) for row in rows[:_MAX_EXPORTED_DECISIONS]],
            "truncated": len(rows) > _MAX_EXPORTED_DECISIONS,
        }
        signature = self._export_key.sign(_EXPORT_DOMAIN + canonical_bytes(payload))
        bundle = {**payload, "integrity": {
            "algorithm": "Ed25519", "canonicalization": _CANONICALIZATION,
            "keyId": self._export_key_id, "publicKey": self.export_public_key, "signature": _base64url(signature),
        }}
        if len(canonical_bytes(bundle)) > _MAX_EXPORT_BYTES:
            raise EvidenceExportError("Der Nachweisexport überschreitet das Größenlimit.")
        return bundle

    def _export_decision(self, row, operation):
        (identifier, decided_at, version, fingerprint, outcome, reason, raw_checks,
         delivery_id, state, reserved_at, completed_at, upstream_status) = row
        try:
            checks = json.loads(raw_checks)
        except (ValueError, TypeError, RecursionError):
            raise EvidenceExportError("Die gespeicherten Prüfmetadaten können nicht exportiert werden.") from None
        if (type(checks) is not list or len(checks) > _MAX_CHECKS
                or any(type(check) is not dict for check in checks)
                or type(fingerprint) is not str or not _SHA256.fullmatch(fingerprint)
                or any(type(value) is not str or not _LABEL.fullmatch(value)
                       for value in (identifier, version, reason))
                or outcome not in _DECISION_OUTCOMES
                or type(decided_at) is not str or not _UTC_TIMESTAMP.fullmatch(decided_at)):
            raise EvidenceExportError("Die gespeicherten Nachweismetadaten sind ungültig.")
        decision = {
            "decisionId": identifier, "decidedAt": decided_at, "ruleVersion": version,
            "inputFingerprint": fingerprint, "outcome": outcome, "reason": reason,
            "checks": [self._export_check(check, operation) for check in checks],
        }
        if delivery_id is not None:
            if (type(delivery_id) is not str or not _LABEL.fullmatch(delivery_id)
                    or state not in _DELIVERY_STATES
                    or type(reserved_at) is not str or not _UTC_TIMESTAMP.fullmatch(reserved_at)
                    or (completed_at is not None and (type(completed_at) is not str
                                                       or not _UTC_TIMESTAMP.fullmatch(completed_at)))
                    or (upstream_status is not None and (type(upstream_status) is not int
                                                        or not 200 <= upstream_status <= 599))):
                raise EvidenceExportError("Die gespeicherten Zustellmetadaten sind ungültig.")
            delivery = {"id": delivery_id, "state": state, "reservedAt": reserved_at}
            if completed_at is not None:
                delivery["completedAt"] = completed_at
            if upstream_status is not None:
                delivery["upstreamStatus"] = upstream_status
            decision["delivery"] = delivery
        return decision

    def _export_check(self, check, operation):
        # The signed bundle carries provenance labels rather than the unchecked input or upstream reports.
        provenance = {}
        for field in _PROVENANCE_FIELDS:
            value = check.get(field)
            if type(value) is str and _LABEL.fullmatch(value):
                provenance[field] = value
        format_name = check.get("format")
        if "format" not in check and type(check.get("kind")) is str:
            # Standalone credential checks record the adapter ID as their kind.
            format_name = _CREDENTIAL_FORMATS.get(check["kind"])
        if type(format_name) is str:
            format_name = _CREDENTIAL_FORMATS.get(format_name, format_name)
            if format_name in _PROVENANCE_FORMATS:
                provenance["format"] = format_name
        report_id = check.get("reportId")
        if type(report_id) is str and _LABEL.fullmatch(report_id):
            binding = canonical_bytes(["proofsieve-report-id-v1", *operation, report_id])
            provenance["reportFingerprint"] = hmac.digest(self.key, binding, "sha256").hex()
        return provenance

    def reserve_forwarding(self, *, decision_id, endpoint, caller, operation_id, data):
        """Commit the sole delivery reservation for an approved operation before sending."""
        scope = (endpoint, caller, operation_id)
        fingerprint = self._input_mac(*scope, data)
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            decision = db.execute(
                """SELECT input_mac FROM decisions WHERE id = ? AND endpoint = ?
                   AND caller = ? AND operation_id = ? AND outcome = 'allow'""",
                (decision_id, *scope),
            ).fetchone()
            if decision is None or not hmac.compare_digest(decision[0], fingerprint):
                raise ValueError("Die Freigabe passt nicht zur Weiterleitungsanfrage.")
            previous = self._find_forwarding(db, scope, fingerprint)
            if previous is not None:
                _, reservation = previous
                return reservation
            return self._insert_forwarding(db, decision_id, scope, fingerprint)

    def record_forwarding_approval(self, *, endpoint, caller, operation_id, data, version, reason, checks):
        """Atomically record approval and reserve delivery, or return the original approval."""
        scope = (endpoint, caller, operation_id)
        fingerprint = self._input_mac(*scope, data)
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            now = datetime.now(timezone.utc)
            self._prune_decisions(db, now)
            previous = self._find_forwarding(db, scope, fingerprint)
            if previous is not None:
                decision_id, reservation = previous
                approval = db.execute(
                    """SELECT rule_version, reason FROM decisions WHERE id = ? AND endpoint = ?
                       AND caller = ? AND operation_id = ? AND input_mac = ? AND outcome = 'allow'""",
                    (decision_id, *scope, fingerprint),
                ).fetchone()
                if approval is None:
                    raise ForwardingEvidenceExpired("Der ursprüngliche Weiterleitungsnachweis ist abgelaufen.")
                return decision_id, *approval, reservation

            decision_id = str(uuid.uuid4())
            fields = (*scope, version, fingerprint, "allow", reason, canonical_bytes(checks).decode("ascii"))
            db.execute("INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (decision_id, now.isoformat(timespec="microseconds"), *fields))
            reservation = self._insert_forwarding(db, decision_id, scope, fingerprint)
            return decision_id, version, reason, reservation

    @staticmethod
    def _find_forwarding(db, scope, fingerprint):
        previous = db.execute(
            """SELECT decision_id, id, state, upstream_status, input_mac FROM forwarding
               WHERE endpoint = ? AND caller = ? AND operation_id = ?""", scope,
        ).fetchone()
        if previous is None:
            return None
        decision_id, delivery_id, state, upstream_status, previous_fingerprint = previous
        if not hmac.compare_digest(previous_fingerprint, fingerprint):
            raise ForwardingConflict("Die Vorgangsreferenz ist bereits an andere Eingabedaten gebunden.")
        return decision_id, ForwardingReservation(delivery_id, state, upstream_status)

    @staticmethod
    def _insert_forwarding(db, decision_id, scope, fingerprint):
        latest = db.execute("SELECT MAX(rowid) FROM forwarding").fetchone()[0]
        if latest is not None and latest >= _MAX_FORWARDING_RESERVATIONS:
            raise OSError("Das Weiterleitungsjournal hat seine Kapazitätsgrenze erreicht.")
        delivery_id = str(uuid.uuid4())
        reserved_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        db.execute(
            """INSERT INTO forwarding (id, decision_id, endpoint, caller, operation_id, input_mac, reserved_at, state)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')""",
            (delivery_id, decision_id, *scope, fingerprint, reserved_at),
        )
        return ForwardingReservation(delivery_id, "pending", None, acquired=True)

    def finish_forwarding(self, delivery_id, *, state, upstream_status=None):
        """Finalize a pending attempt. An interrupted attempt stays reserved."""
        if not (
            (state == "unknown" and upstream_status is None)
            or (state == "delivered" and type(upstream_status) is int and 200 <= upstream_status < 300)
            or (state == "rejected" and type(upstream_status) is int and 300 <= upstream_status < 600)
        ):
            raise ValueError("Der Zustellstatus passt nicht zur Antwort des Zieldienstes.")
        completed_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        with closing(self.connect()) as db, db:
            updated = db.execute(
                """UPDATE forwarding SET state = ?, upstream_status = ?, completed_at = ?
                   WHERE id = ? AND state = 'pending'""",
                (state, upstream_status, completed_at, delivery_id),
            )
            if updated.rowcount != 1:
                raise ValueError("Die Weiterleitung ist nicht offen.")
        return ForwardingReservation(delivery_id, state, upstream_status)

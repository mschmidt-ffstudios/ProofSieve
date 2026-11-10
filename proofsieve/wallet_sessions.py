"""Private, single-use journal for operation-bound wallet presentations."""

import math
import os
import re
import secrets
import sqlite3
import stat
import time
from contextlib import closing
from dataclasses import dataclass, replace
from pathlib import Path


_APPLICATION_ID = 0x50535753
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_ENDPOINT = re.compile(r"/verify(?:/[A-Za-z0-9_-]+)*")
_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{43}")
_OPAQUE_ID = re.compile(r"[A-Za-z0-9._~-]{1,256}")
_RULE_VERSION = re.compile(r"[0-9a-f]{64}")
_FORMATS = {"dc+sd-jwt", "mso_mdoc"}
_STATUS_MODES = {"not-required", "jwt-file", "cwt-file"}
_MAX_RETENTION = 2_592_000
COMPLETION_RECOVERY_SECONDS = 86_400
_SESSION_COLUMNS = (
    "id, nonce, caller, endpoint, operation_id, adapter, format, rule_version, profile_version, "
    "created_at, expires_at, transaction_id, state, closed_by_expiry"
)


class SessionUnavailable(ValueError):
    """A session is missing, expired or outside the exact operation binding."""


class SessionConflict(ValueError):
    """A session, operation or upstream response has already been reserved."""


class SessionCapacity(ValueError):
    """The bounded session journal cannot accept another reservation."""


class SessionQuota(ValueError):
    def __init__(self, retry_after):
        super().__init__("The caller's wallet session quota is full.")
        self.retry_after = retry_after


@dataclass(frozen=True)
class WalletSession:
    id: str
    nonce: str
    caller: str
    endpoint: str
    operation_id: str
    adapter: str
    format: str
    rule_version: str
    profile_version: str
    created_at: float
    expires_at: float
    transaction_id: str | None
    state: str
    closed_by_expiry: bool = False


@dataclass(frozen=True)
class CompletionReceipt:
    fingerprint: str
    status_mode: str


def _matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _private_path(path, *, create=True):
    path = Path(path).absolute()
    if create:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        raise ValueError("Wallet session storage requires an owner-only directory.")
    path = path.parent.resolve() / path.name
    access = os.O_CREAT | os.O_RDWR if create else os.O_RDONLY
    descriptor = os.open(path, access | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError("Wallet session storage requires a private regular file.")
    finally:
        os.close(descriptor)
    return path


def pending_wallet_receipts(path):
    path = _private_path(path, create=False)
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)) as db:
        db.execute("PRAGMA trusted_schema = OFF")
        if (db.execute("PRAGMA application_id").fetchone()[0],
                db.execute("PRAGMA user_version").fetchone()[0]) != (_APPLICATION_ID, 1):
            raise ValueError("Unsupported wallet session journal.")
        if db.execute("""SELECT 1 FROM sqlite_schema
                         WHERE type = 'table' AND name = 'wallet_completion_receipts'""").fetchone() is None:
            return []
        rows = db.execute(
            """SELECT s.caller, s.endpoint, s.operation_id, s.created_at + ?
               FROM wallet_completion_receipts r JOIN wallet_sessions s ON s.id = r.session_id
               WHERE s.created_at > ? ORDER BY s.created_at""",
            (COMPLETION_RECOVERY_SECONDS, time.time() - COMPLETION_RECOVERY_SECONDS),
        ).fetchall()
    return [{"caller": caller, "endpoint": endpoint, "operationId": operation, "recoverUntilEpoch": deadline}
            for caller, endpoint, operation, deadline in rows]


class WalletSessions:
    """Reserve one presentation per caller, endpoint and operation within retention."""

    def __init__(self, path, *, lifetime_seconds=300, retention_seconds=86_400,
                 max_sessions=10_000, max_recent_per_caller=16, max_retained_per_caller=500, clock=time.time):
        if not (
            type(lifetime_seconds) is int and 1 <= lifetime_seconds <= 900
            and type(retention_seconds) is int and lifetime_seconds <= retention_seconds <= _MAX_RETENTION
            and type(max_sessions) is int and 1 <= max_sessions <= 100_000
            and type(max_recent_per_caller) is int and 1 <= max_recent_per_caller <= 64
            and type(max_retained_per_caller) is int and 1 <= max_retained_per_caller <= 2_500
        ):
            raise ValueError("Wallet session limits are invalid.")
        self.path = _private_path(path)
        self.lifetime = lifetime_seconds
        self.retention = retention_seconds
        self.capacity = max_sessions
        self.retained_per_caller = min(max_retained_per_caller, max_sessions)
        self.recent_per_caller = min(max_recent_per_caller, self.retained_per_caller)
        self.clock = clock
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            identity = db.execute("PRAGMA application_id").fetchone()[0]
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if (identity, version) == (0, 0):
                if db.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone() is not None:
                    raise ValueError("The database is not a wallet session journal.")
                db.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                db.execute("PRAGMA user_version = 1")
            elif (identity, version) != (_APPLICATION_ID, 1):
                raise ValueError("Unsupported wallet session journal.")
            db.execute("""CREATE TABLE IF NOT EXISTS wallet_sessions (
                id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE,
                caller TEXT NOT NULL, endpoint TEXT NOT NULL, operation_id TEXT NOT NULL,
                adapter TEXT NOT NULL, format TEXT NOT NULL, rule_version TEXT NOT NULL,
                profile_version TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
                transaction_id TEXT,
                state TEXT NOT NULL CHECK (state IN ('creating', 'bound', 'claimed', 'consumed', 'failed')),
                UNIQUE (caller, endpoint, operation_id),
                UNIQUE (adapter, transaction_id)
            )""")
            # Keep the v1 table and its original state values readable by rc11.
            columns = {row[1] for row in db.execute("PRAGMA table_info(wallet_sessions)")}
            if "closed_by_expiry" not in columns:
                db.execute("""ALTER TABLE wallet_sessions ADD COLUMN closed_by_expiry
                              INTEGER NOT NULL DEFAULT 0 CHECK (closed_by_expiry IN (0, 1))""")
            db.execute("CREATE INDEX IF NOT EXISTS wallet_sessions_expiry ON wallet_sessions (expires_at)")
            db.execute("""CREATE TABLE IF NOT EXISTS wallet_completion_receipts (
                session_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, status_mode TEXT NOT NULL
            )""")
            # An older release can prune a session without its additive receipt.
            db.execute("""DELETE FROM wallet_completion_receipts WHERE NOT EXISTS (
                SELECT 1 FROM wallet_sessions WHERE id = wallet_completion_receipts.session_id
            )""")
            self._prune(db, self.clock())

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=1)
        try:
            db.execute("PRAGMA trusted_schema = OFF")
            db.execute("PRAGMA secure_delete = ON")
            db.execute("PRAGMA synchronous = FULL")
        except sqlite3.Error:
            db.close()
            raise
        return db

    def _prune(self, db, now):
        db.execute("""DELETE FROM wallet_completion_receipts WHERE session_id IN (
            SELECT id FROM wallet_sessions WHERE created_at <= ?
        )""", (now - COMPLETION_RECOVERY_SECONDS,))
        db.execute("""DELETE FROM wallet_sessions WHERE expires_at <= ? AND NOT EXISTS (
            SELECT 1 FROM wallet_completion_receipts WHERE session_id = wallet_sessions.id
        )""", (now - self.retention,))

    def _check_caller_quota(self, db, caller, now):
        retained, recent = db.execute(
            "SELECT COUNT(*), COALESCE(SUM(expires_at > ?), 0) FROM wallet_sessions WHERE caller = ?",
            (now, caller),
        ).fetchone()
        deadlines = []
        if retained >= self.retained_per_caller:
            evicts_at, = db.execute(
                """SELECT MAX(s.expires_at + ?, CASE WHEN r.session_id IS NULL THEN 0 ELSE s.created_at + ? END)
                   AS evicts_at FROM wallet_sessions s
                   LEFT JOIN wallet_completion_receipts r ON r.session_id = s.id
                   WHERE s.caller = ? ORDER BY evicts_at LIMIT 1 OFFSET ?""",
                (self.retention, COMPLETION_RECOVERY_SECONDS, caller, retained - self.retained_per_caller),
            ).fetchone()
            deadlines.append(evicts_at)
        if recent >= self.recent_per_caller:
            expires, = db.execute(
                """SELECT expires_at FROM wallet_sessions WHERE caller = ? AND expires_at > ?
                   ORDER BY expires_at LIMIT 1 OFFSET ?""",
                (caller, now, recent - self.recent_per_caller),
            ).fetchone()
            deadlines.append(expires)
        if deadlines:
            retry_after = min(_MAX_RETENTION, max(1, math.ceil(max(deadlines) - now)))
            raise SessionQuota(retry_after)

    def create(self, *, caller, endpoint, operation_id, adapter, format, rule_version, profile_version):
        if not (
            _matches(_IDENTITY, caller) and _matches(_ENDPOINT, endpoint) and len(endpoint) <= 128
            and _matches(_REFERENCE, operation_id) and _matches(_IDENTITY, adapter)
            and type(format) is str and format in _FORMATS
            and _matches(_RULE_VERSION, rule_version) and _matches(_REFERENCE, profile_version)
        ):
            raise ValueError("Invalid wallet session binding.")
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            now = self.clock()
            self._prune(db, now)
            operation = (caller, endpoint, operation_id)
            if db.execute(
                "SELECT 1 FROM wallet_sessions WHERE caller = ? AND endpoint = ? AND operation_id = ?",
                operation,
            ).fetchone() is not None:
                raise SessionConflict("The operation already has a wallet session.")
            if db.execute("SELECT COUNT(*) FROM wallet_sessions").fetchone()[0] >= self.capacity:
                raise SessionCapacity("The wallet session journal is full.")
            self._check_caller_quota(db, caller, now)
            session = WalletSession(
                secrets.token_urlsafe(32), secrets.token_urlsafe(32), caller, endpoint, operation_id, adapter,
                format, rule_version, profile_version, now, now + self.lifetime, None, "creating",
            )
            db.execute(
                """INSERT INTO wallet_sessions (
                    id, nonce, caller, endpoint, operation_id, adapter, format, rule_version,
                    profile_version, created_at, expires_at, state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session.id, session.nonce, caller, endpoint, operation_id, adapter, format, rule_version,
                 profile_version, session.created_at, session.expires_at, session.state),
            )
        return session

    def bind(self, session_id, *, transaction_id):
        if not _matches(_OPAQUE_ID, transaction_id):
            raise ValueError("Invalid wallet verifier transaction identifier.")
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            session = self._find(db, session_id, self.clock())
            if session.state != "creating":
                raise SessionConflict("The wallet transaction has already been assigned.")
            try:
                db.execute(
                    "UPDATE wallet_sessions SET transaction_id = ?, state = 'bound' WHERE id = ?",
                    (transaction_id, session_id),
                )
            except sqlite3.IntegrityError:
                raise SessionConflict("The wallet verifier transaction has already been assigned.") from None
        return replace(session, transaction_id=transaction_id, state="bound")

    def get(self, session_id, *, caller, endpoint, operation_id):
        with closing(self._connect()) as db:
            return self._find(db, session_id, self.clock(), (caller, endpoint, operation_id))

    def get_for_completion(self, session_id, *, caller, endpoint, operation_id):
        if not _matches(_SESSION_ID, session_id):
            raise SessionUnavailable("The wallet session is unavailable.")
        with closing(self._connect()) as db, db:
            db.execute("BEGIN")
            now = self.clock()
            row = db.execute(
                "SELECT fingerprint, status_mode FROM wallet_completion_receipts WHERE session_id = ?", (session_id,),
            ).fetchone()
            receipt = CompletionReceipt(*row) if row is not None else None
            valid_after = -math.inf if receipt is not None else now - self.retention
            session = self._find(db, session_id, valid_after, (caller, endpoint, operation_id))
            if receipt is not None and session.created_at + COMPLETION_RECOVERY_SECONDS <= now:
                raise SessionUnavailable("The wallet completion recovery window has ended.")
            if (receipt is None and session.expires_at <= now and not session.closed_by_expiry
                    and session.state not in ("bound", "claimed")):
                raise SessionUnavailable("The wallet session is unavailable.")
            return session, receipt

    def close_expired(self, session):
        operation = (session.caller, session.endpoint, session.operation_id)
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            now = self.clock()
            current = self._find(db, session.id, now - self.retention, operation)
            if (
                current.adapter != session.adapter or current.transaction_id != session.transaction_id
                or current.rule_version != session.rule_version or current.profile_version != session.profile_version
            ):
                raise SessionConflict("The wallet transaction no longer matches its configuration.")
            if current.closed_by_expiry:
                return
            if current.expires_at > now or current.state not in ("bound", "claimed"):
                raise SessionUnavailable("The wallet session is unavailable.")
            db.execute(
                "UPDATE wallet_sessions SET state = 'consumed', closed_by_expiry = 1 WHERE id = ?", (current.id,),
            )

    def claim(self, session_id, *, caller, endpoint, operation_id, transaction_id, rule_version, profile_version,
              receipt=None):
        if receipt is not None and (not isinstance(receipt, CompletionReceipt)
                                    or not _matches(_RULE_VERSION, receipt.fingerprint)
                                    or receipt.status_mode not in _STATUS_MODES):
            raise ValueError("Invalid wallet completion receipt.")
        state = "claimed" if receipt is None else "consumed"
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            session = self._find(db, session_id, self.clock(), (caller, endpoint, operation_id))
            if session.state != "bound":
                raise SessionConflict("The wallet session is not available for a first attempt.")
            if (
                session.transaction_id != transaction_id
                or session.rule_version != rule_version
                or session.profile_version != profile_version
            ):
                raise SessionConflict("The wallet transaction no longer matches its configuration.")
            db.execute("UPDATE wallet_sessions SET state = ? WHERE id = ?", (state, session_id))
            if receipt is not None:
                db.execute("INSERT INTO wallet_completion_receipts VALUES (?, ?, ?)",
                           (session_id, receipt.fingerprint, receipt.status_mode))
        return replace(session, state=state)

    def finish(self, session_id, *, state):
        if state not in ("consumed", "failed"):
            raise ValueError("Invalid final wallet session state.")
        if not _matches(_SESSION_ID, session_id):
            raise SessionUnavailable("The wallet session is unavailable.")
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            if state == "consumed":
                update = db.execute(
                    """UPDATE wallet_sessions SET state = 'consumed'
                       WHERE id = ? AND state = 'claimed' AND expires_at > ?""",
                    (session_id, self.clock()),
                )
            else:
                update = db.execute(
                    """UPDATE wallet_sessions SET state = 'failed'
                       WHERE id = ? AND state IN ('creating', 'bound', 'claimed')""",
                    (session_id,),
                )
            if update.rowcount != 1:
                raise SessionConflict("The wallet session cannot be finalized.")

    def acknowledge_completion(self, session_id):
        with closing(self._connect()) as db, db:
            return db.execute("DELETE FROM wallet_completion_receipts WHERE session_id = ?", (session_id,)).rowcount == 1

    @staticmethod
    def _find(db, session_id, valid_after, operation=None):
        if _matches(_SESSION_ID, session_id):
            row = db.execute(
                f"SELECT {_SESSION_COLUMNS} FROM wallet_sessions WHERE id = ? AND expires_at > ?",
                (session_id, valid_after),
            ).fetchone()
            if row is not None:
                session = WalletSession(*row[:-1], closed_by_expiry=bool(row[-1]))
                if operation is None or (session.caller, session.endpoint, session.operation_id) == operation:
                    return session
        raise SessionUnavailable("The wallet session is unavailable.")

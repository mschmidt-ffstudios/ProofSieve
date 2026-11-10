"""Bind a trusted wallet verifier's result to one ProofSieve operation."""

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .access import _read_config
from .evidence import WALLET_EVIDENCE_INTERRUPTED, rule_version
from .guard import MAX_ENDPOINTS, _OPERATION, load_json, validate_endpoint
from .wallet_profile import WalletProfile, compile_wallet_profile
from .wallet_protocol import WalletConnector, WalletRejected, WalletUnavailable, load_wallet_connector
from .wallet_sessions import (
    CompletionReceipt, SessionCapacity, SessionConflict, SessionQuota, SessionUnavailable, WalletSessions,
)


_CONNECTOR_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_SESSION_LIMITS = {"recentPerCaller": "max_recent_per_caller", "retainedPerCaller": "max_retained_per_caller"}


@dataclass(frozen=True)
class WalletEndpoint:
    adapter: str
    connector: WalletConnector
    profile: WalletProfile
    version: str


class WalletVerification:
    def __init__(self, sessions, endpoints):
        self.sessions = sessions
        self.endpoints = dict(endpoints)

    def handle(self, guard, endpoint, caller, operation_id, data):
        if not isinstance(operation_id, str) or not _OPERATION.fullmatch(operation_id):
            raise ValueError("Eine gültige operationId ist erforderlich.")
        if not isinstance(data, dict):
            raise ValueError("Eine Wallet-Aktion als JSON-Objekt ist erforderlich.")
        binding = self.endpoints[endpoint]
        version = guard.wallet_rule_version(endpoint)
        try:
            if data == {"action": "start"}:
                return self.start(endpoint, caller, operation_id, binding, version)
            if data.keys() == {"action", "sessionId"} and data["action"] == "complete":
                return self.complete(guard, endpoint, caller, operation_id, binding, version, data["sessionId"])
        except SessionUnavailable:
            return 404, {"code": "wallet_session_unavailable", "error": "Die Wallet-Sitzung ist nicht verfügbar."}
        except SessionConflict:
            return 409, {"code": "wallet_session_conflict", "error": "Die Wallet-Sitzung kann nicht verwendet werden."}
        except SessionQuota as exc:
            return 429, {"code": "wallet_rate_limited", "error": "Das Wallet-Limit für dieses Konto ist erreicht.",
                         "retryAfterSeconds": exc.retry_after}
        except (WalletUnavailable, SessionCapacity, OSError, sqlite3.Error):
            return 503, {"code": "wallet_unavailable", "error": "Die Wallet-Prüfung ist vorübergehend nicht verfügbar."}
        raise ValueError("Erlaubte Wallet-Aktionen sind start und complete mit sessionId.")

    def start(self, endpoint, caller, operation_id, binding, version):
        session = self.sessions.create(
            caller=caller, endpoint=endpoint, operation_id=operation_id, adapter=binding.adapter,
            format=binding.profile.format, rule_version=version, profile_version=binding.version,
        )
        try:
            transaction = binding.connector.start(profile=binding.profile, nonce=session.nonce)
            session = self.sessions.bind(session.id, transaction_id=transaction.transaction_id)
        except WalletRejected:
            self.sessions.finish(session.id, state="failed")
            raise WalletUnavailable() from None
        except (WalletUnavailable, SessionUnavailable, SessionConflict):
            self.sessions.finish(session.id, state="failed")
            raise
        return 201, {
            "state": "pending", "sessionId": session.id, "operationId": operation_id,
            "authorizationRequestUri": transaction.authorization_request_uri,
            "expiresAt": datetime.fromtimestamp(session.expires_at, timezone.utc).isoformat(),
        }

    def complete(self, guard, endpoint, caller, operation_id, binding, version, session_id):
        operation = {"caller": caller, "endpoint": endpoint, "operation_id": operation_id}
        session, receipt = self.sessions.get_for_completion(session_id, **operation)
        if receipt is not None:
            return self._recover_completion(guard, session, receipt)
        if (session.adapter != binding.adapter or session.rule_version != version
                or session.profile_version != binding.version):
            raise SessionConflict()
        if session.closed_by_expiry or self.sessions.clock() >= session.expires_at:
            return self._record_completion(guard, session, binding, None, expired=True)
        if session.state != "bound":
            raise SessionConflict()
        try:
            claims = binding.connector.result(
                transaction_id=session.transaction_id, profile=binding.profile, nonce=session.nonce,
            )
        except WalletRejected:
            claims = None
        except WalletUnavailable:
            if self.sessions.clock() >= session.expires_at:
                return self._record_completion(guard, session, binding, None, expired=True)
            raise
        else:
            if claims is None:
                if self.sessions.clock() >= session.expires_at:
                    return self._record_completion(guard, session, binding, None, expired=True)
                return 202, {"state": "pending", "operationId": operation_id}
        fingerprint = guard.evidence._input_mac(endpoint, caller, operation_id, claims)
        try:
            self.sessions.claim(
                session.id, **operation, transaction_id=session.transaction_id,
                rule_version=version, profile_version=binding.version,
                receipt=CompletionReceipt(fingerprint, binding.profile.status_mode),
            )
        except (SessionUnavailable, SessionConflict):
            if self.sessions.clock() >= session.expires_at:
                return self._record_completion(guard, session, binding, None, expired=True)
            raise
        status, result = self._record_completion(guard, session, binding, claims)
        if status != 503 or "decisionId" in result:
            self.sessions.acknowledge_completion(session.id)
        return status, result

    def _recover_completion(self, guard, session, receipt):
        check = {
            "kind": "wallet_presentation", "outcome": "indeterminate", "reason": WALLET_EVIDENCE_INTERRUPTED,
            "adapter": session.adapter, "format": session.format, "profileVersion": session.profile_version,
            "statusMode": receipt.status_mode,
        }
        try:
            decision_id = guard.evidence.recover_wallet_completion(
                endpoint=session.endpoint, caller=session.caller, operation_id=session.operation_id,
                version=session.rule_version, session=session.id, started_at=session.created_at,
                fingerprint=receipt.fingerprint, check=check,
            )
        except (OSError, sqlite3.Error):
            return 503, {"error": "Der Nachweisspeicher ist nicht verfügbar.", "code": "evidence_unavailable"}
        acknowledged = self.sessions.acknowledge_completion(session.id)
        if not acknowledged or decision_id is None:
            raise SessionConflict()
        return 503, {
            "valid": False, "outcome": "indeterminate", "reason": WALLET_EVIDENCE_INTERRUPTED,
            "decisionId": decision_id, "operationId": session.operation_id, "ruleVersion": session.rule_version,
        }

    def _record_completion(self, guard, session, binding, claims, *, expired=False):
        if expired:
            self.sessions.close_expired(session)
        check = {
            "kind": "wallet_presentation",
            "outcome": "indeterminate" if expired else ("failed" if claims is None else "passed"),
            "adapter": session.adapter, "format": session.format, "profileVersion": session.profile_version,
            "statusMode": binding.profile.status_mode,
        }
        if expired:
            check["reason"] = "wallet_expired"
        return guard.verify_wallet(
            session.endpoint, session.caller, session.operation_id, session.rule_version, claims, check,
            wallet_session=session,
            expiry_replay_deadline=session.expires_at + self.sessions.retention if expired else None,
        )


def load_wallet_verification(config_path, sessions_path):
    config = load_json(_read_config(Path(config_path)))
    required = {"version", "connectors", "endpoints"}
    if (type(config) is not dict or not required <= config.keys() or config.keys() - required - {"sessionLimits"}
            or type(config["version"]) is not int or config["version"] != 1
            or type(config["connectors"]) is not dict or not 1 <= len(config["connectors"]) <= 16
            or type(config["endpoints"]) is not dict or not 1 <= len(config["endpoints"]) <= MAX_ENDPOINTS):
        raise ValueError("Wallet-Konfiguration braucht version, connectors und endpoints.")
    limits = config.get("sessionLimits", {})
    if type(limits) is not dict or limits.keys() - _SESSION_LIMITS.keys():
        raise ValueError("Wallet sessionLimits accepts recentPerCaller and retainedPerCaller.")
    connectors = {}
    for identifier, settings in config["connectors"].items():
        if not _CONNECTOR_ID.fullmatch(identifier):
            raise ValueError("Ungültige Wallet-Connector-ID.")
        connectors[identifier] = load_wallet_connector(settings)
    endpoints = {}
    for endpoint, settings in config["endpoints"].items():
        validate_endpoint(endpoint)
        if (type(settings) is not dict or settings.keys() != {"connector", "profile"}
                or type(settings["connector"]) is not str or settings["connector"] not in connectors):
            raise ValueError("Ein Wallet-Endpunkt braucht einen festen Connector und ein Profil.")
        adapter = settings["connector"]
        profile = compile_wallet_profile(settings["profile"])
        version = rule_version({"profile": profile.version, "connector": config["connectors"][adapter]})
        endpoints[endpoint] = WalletEndpoint(adapter, connectors[adapter], profile, version)
    session_options = {_SESSION_LIMITS[key]: value for key, value in limits.items()}
    return WalletVerification(WalletSessions(sessions_path, **session_options), endpoints)

"""Compile, store and evaluate verification endpoint rules."""

import ipaddress
import json
import os
import re
import secrets
import sqlite3
import stat
import tempfile
import threading
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .evidence import ForwardingConflict, ForwardingEvidenceExpired, canonical_bytes, rule_version
from .forwarding import ForwardingUnavailable
from .json_numbers import bounded_int, finite_float
from .odrl import compile_policy


MAX_BODY_BYTES = 96 * 1024
MAX_STATE_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_ENDPOINTS = 64
MAX_ENDPOINT_LENGTH = 128
DEFAULT_ENDPOINT = "/verify"
_ENDPOINT = re.compile(r"/verify(?:/[A-Za-z0-9_-]+)*")
_OPERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_INVALID_URL = re.compile(r'[^\x21-\x7e]|[<>"{}|\\^`]|%(?![0-9a-f]{2})|%(?:[01][0-9a-f]|7f|5c)', re.IGNORECASE)
_URL_AUTHORITY = re.compile(r"(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::[0-9]+)?", re.IGNORECASE)
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE)
_NUMERIC_HOST_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*", re.IGNORECASE)
DEFAULT_RULE = {
    "language": "odrl",
    "policy": {
        "@context": [
            "http://www.w3.org/ns/odrl.jsonld",
            {"field": "https://proofsieve.example/facts/"},
        ],
        "@type": "Set",
        "uid": "urn:demo:policy:basic",
        "profile": "https://proofsieve.example/profiles/basic/v1",
        "permission": [
            {
                "target": "urn:demo:service",
                "action": "use",
                "constraint": [
                    {"leftOperand": "field:status", "operator": "eq", "rightOperand": "active"}
                ],
            }
        ],
    },
    "responseMode": "boolean",
}


class ReadOnlyEndpointError(Exception):
    pass


def unique_fields(items):
    values = {}
    for key, value in items:
        if key in values:
            raise ValueError("Doppelte JSON-Felder sind nicht erlaubt.")
        values[key] = value
    return values


def reject_constant(value):
    raise ValueError(f"Ungültige JSON-Zahl: {value}")


def load_json(raw):
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_fields,
            parse_constant=reject_constant,
            parse_float=finite_float,
            parse_int=bounded_int,
        )
    except RecursionError as exc:
        raise ValueError("Das JSON ist zu tief verschachtelt.") from exc
    pending = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError("Das JSON ist zu tief verschachtelt.")
        if type(value) is dict:
            pending.extend((child, depth + 1) for child in value.values())
            pending.extend((key, depth + 1) for key in value)
        elif type(value) is list:
            pending.extend((child, depth + 1) for child in value)
        elif type(value) is str and any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError("Das JSON enthält ungültige Unicode-Zeichen.")
    return document


def validate_result_url(value, field):
    if not isinstance(value, str):
        raise ValueError(f"{field} muss ein String sein.")
    if not value:
        return
    if not _INVALID_URL.search(value):
        try:
            url = urlsplit(value)
            if url.scheme == "https" and _URL_AUTHORITY.fullmatch(url.netloc) and url.port != 0:
                if url.netloc.startswith("["):
                    # urlsplit validates bracketed IPv6 addresses.
                    return
                host = url.hostname.removesuffix(".")
                labels = host.split(".")
                if len(host) <= 253 and all(_HOST_LABEL.fullmatch(label) for label in labels):
                    if _NUMERIC_HOST_LABEL.fullmatch(labels[-1]):
                        # Exclude ambiguous legacy IPv4 spellings interpreted differently by clients.
                        ipaddress.IPv4Address(host)
                    return
        except ValueError:
            pass
    raise ValueError(f"{field} muss eine absolute HTTPS-URL ohne Zugangsdaten sein.")


def compile_rule(rule, registry=None):
    required = {"language", "policy", "responseMode"}
    if not isinstance(rule, dict) or not required <= rule.keys():
        raise ValueError("Eine Regel braucht language, policy und responseMode.")
    if "credential" in rule:
        required.add("credential")
        if rule["language"] != "odrl":
            raise ValueError("Signierte Credentials brauchen eine ODRL-Regel.")
    mode = rule["responseMode"]
    if "bundle" in rule:
        required.add("bundle")
        if rule["language"] != "odrl" or mode != "decision" or rule.keys() & {"credential", "verification", "wallet"}:
            raise ValueError("Ein Nachweisbündel braucht einen eigenen ODRL-Entscheidungsendpunkt.")
    if "wallet" in rule:
        required.add("wallet")
        if (rule["wallet"] is not True or rule["language"] != "odrl" or mode != "decision"
                or "credential" in rule or "verification" in rule):
            raise ValueError("Wallet-Regeln brauchen ODRL im Entscheidungsmodus und ein Wallet-Profil.")
    if "verification" in rule:
        required.add("verification")
        if "credential" in rule or rule["language"] != "odrl" or mode != "decision":
            raise ValueError("verification benötigt ODRL im Entscheidungsmodus und eine eigene Prüfeingabe.")
        if registry is None:
            raise ValueError("Für verification ist eine Betreiberkonfiguration erforderlich.")
    if mode == "url":
        if rule.keys() != required | {"returnUrl", "failUrl"}:
            raise ValueError("Der URL-Modus braucht returnUrl und failUrl.")
        for field in ("returnUrl", "failUrl"):
            validate_result_url(rule[field], field)
        if not (rule["returnUrl"] or rule["failUrl"]):
            raise ValueError("Im URL-Modus muss mindestens eine URL gesetzt sein.")
    elif mode not in ("boolean", "guard", "decision"):
        raise ValueError("responseMode muss boolean, guard, url oder decision sein.")
    elif rule.keys() != required:
        raise ValueError("Dieser Antwortmodus akzeptiert keine zusätzlichen Felder.")
    if rule["language"] == "odrl":
        check = compile_policy(rule["policy"])
        verifier = None
        if "credential" in rule:
            verifier = compile_credential(rule["credential"])
        if "verification" in rule:
            verifier = registry.compile(rule["verification"])
        if "bundle" in rule:
            from .bundle import compile_bundle

            verifier = compile_bundle(rule["bundle"], compile_credential, registry)
        return check, verifier
    if rule["language"] == "shacl":
        from .shacl import compile_shapes

        return compile_shapes(rule["policy"]), None
    raise ValueError("language muss odrl oder shacl sein.")


def compile_credential(config):
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    if not isinstance(config, dict):
        raise ValueError("credential muss ein Objekt sein.")
    kind = config.get("format")
    if kind in ("jwt-vc", "vc-data-integrity"):
        from .vc_inputs import compile_vc_credential

        return compile_vc_credential(config)
    fields = {"format", "publicKeyPem"}
    if kind == "sd-jwt":
        fields.add("issuer")
    elif kind != "mdoc":
        raise ValueError("credential.format muss sd-jwt oder mdoc sein.")
    if config.keys() != fields:
        raise ValueError("Die Credential-Konfiguration enthält fehlende oder unbekannte Felder.")
    pem = config["publicKeyPem"]
    if (not isinstance(pem, str) or len(pem) > 1024
            or not re.fullmatch(r"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?", pem)):
        raise ValueError("publicKeyPem muss genau einen öffentlichen PEM-Schlüssel enthalten.")
    try:
        key = load_pem_public_key(pem.encode("ascii"))
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("Der öffentliche PEM-Schlüssel ist ungültig oder wird nicht unterstützt.") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Der Ausstellerschlüssel muss ein öffentlicher P-256-Schlüssel sein.")
    if kind == "sd-jwt":
        from .sd_jwt import verify_sd_jwt

        issuer = config["issuer"]
        if not isinstance(issuer, str) or not issuer or len(issuer) > 512:
            raise ValueError("SD-JWT braucht eine fest konfigurierte issuer-Kennung.")
        return lambda raw: verify_sd_jwt(raw, key, issuer=issuer, now=datetime.now(timezone.utc))

    from .mdoc import verify_mdoc

    return lambda raw: verify_mdoc(raw, key, now=datetime.now(timezone.utc))


def validate_endpoint(endpoint):
    if not isinstance(endpoint, str) or len(endpoint) > MAX_ENDPOINT_LENGTH or not _ENDPOINT.fullmatch(endpoint):
        raise ValueError("Ein Endpunkt muss /verify oder /verify/<segment> sein. Erlaubt sind ASCII-Buchstaben, Ziffern, _ und -.")
    return endpoint


def _read_state(state):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if state.is_symlink():
        raise ValueError("Die Regeldatei darf kein symbolischer Link sein.")
    try:
        fd = os.open(state, flags)
    except FileNotFoundError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Die Regeldatei muss eine reguläre Datei sein.")
        with os.fdopen(fd, "rb", closefd=False) as saved:
            return saved.read(MAX_STATE_BYTES + 1)
    finally:
        os.close(fd)


class Guard:
    def __init__(self, state, demos, *, evidence=None, registry=None, forwarding=None, wallet_endpoints=()):
        self.state = state
        self.evidence = evidence
        self.registry = registry
        self.forwarding = dict(forwarding or {})
        self.wallet_endpoints = frozenset(wallet_endpoints)
        if self.forwarding and (evidence is None or self.forwarding.keys() & demos.keys()):
            raise ValueError("Weiterleitung braucht einen Nachweisspeicher und eigene Prüfendpunkte.")
        if self.wallet_endpoints and (evidence is None or self.wallet_endpoints & (demos.keys() | self.forwarding.keys())):
            raise ValueError("Wallet-Prüfungen brauchen einen eigenen Endpunkt und einen Nachweisspeicher.")
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.RLock()
        raw = _read_state(state)
        if raw is not None:
            if len(raw) > MAX_STATE_BYTES:
                raise ValueError("Gespeicherte Regeln überschreiten das Größenlimit.")
            saved_state = load_json(raw)
            if isinstance(saved_state, dict) and ("version" in saved_state or "rules" in saved_state):
                if (set(saved_state) != {"version", "rules"} or type(saved_state["version"]) is not int
                        or saved_state["version"] != 1 or not isinstance(saved_state["rules"], dict)):
                    raise ValueError("Das Dateiformat der gespeicherten Regeln ist ungültig.")
                rules = saved_state["rules"]
            else:
                if len(raw) > MAX_BODY_BYTES:
                    raise ValueError("Gespeicherte Regel überschreitet das Größenlimit.")
                rules = {DEFAULT_ENDPOINT: saved_state}
        else:
            rules = {DEFAULT_ENDPOINT: deepcopy(DEFAULT_RULE)}
        if DEFAULT_ENDPOINT not in rules or len(rules) > MAX_ENDPOINTS:
            raise ValueError("Die Regelsammlung braucht /verify und darf höchstens 64 Endpunkte enthalten.")
        if rules.keys() & demos.keys():
            raise ValueError("Gespeicherte Regeln belegen einen reservierten Demo-Endpunkt.")
        if not self.wallet_endpoints <= rules.keys():
            raise ValueError("Ein konfigurierter Wallet-Endpunkt hat keine gespeicherte Regel.")
        self.demos = deepcopy(demos)
        self.routes = {}
        for endpoint, rule in rules.items():
            validate_rule_size(rule)
            self.routes[validate_endpoint(endpoint)] = (rule, self.compile(rule, endpoint))
        self.demo_routes = {endpoint: (demo["rule"], compile_rule(demo["rule"]))
                            for endpoint, demo in self.demos.items()}

    def compile(self, rule, endpoint):
        compiled = compile_rule(rule, self.registry)
        if (endpoint in self.wallet_endpoints) != ("wallet" in rule):
            raise ValueError("Wallet-Regel und Betreiberprofil müssen für denselben Endpunkt konfiguriert sein.")
        if endpoint in self.forwarding and rule["responseMode"] != "decision":
            raise ValueError("Ein Weiterleitungsendpunkt braucht den Entscheidungsmodus.")
        if rule["responseMode"] == "decision" and self.evidence is None:
            raise ValueError("Der Entscheidungsmodus braucht einen Nachweisspeicher.")
        return compiled

    def endpoints(self):
        with self.lock:
            return sorted(self.routes.keys() | self.demo_routes.keys())

    def verification_profiles(self):
        with self.lock:
            profiles = {}
            for endpoint, (rule, _) in sorted((self.routes | self.demo_routes).items()):
                kind = rule["language"]
                if "bundle" in rule:
                    kind = "bundle"
                elif "wallet" in rule:
                    kind = "wallet"
                elif "credential" in rule:
                    kind = rule["credential"]["format"]
                elif "verification" in rule:
                    kind = "document"
                profiles[endpoint] = (kind, rule["responseMode"])
            return profiles

    def bundle_inputs(self, endpoint):
        with self.lock:
            rule = self.routes[endpoint][0]
            return {
                label: item["credential"]["format"] if "credential" in item else "document"
                for label, item in rule.get("bundle", {}).get("items", {}).items()
            }

    def has_endpoint(self, endpoint):
        with self.lock:
            return endpoint in self.routes or endpoint in self.demo_routes

    def describe(self, endpoint):
        with self.lock:
            if endpoint in self.demos:
                details = {**self.demos[endpoint], "readOnly": True}
            elif endpoint in self.routes:
                details = {"rule": self.routes[endpoint][0]}
            else:
                return None
            rule = details["rule"]
            if rule["language"] == "odrl":
                # JSON parsing in the browser can round integers before the editor sees them.
                details["policyText"] = json.dumps(rule["policy"], ensure_ascii=True, indent=2)
            return {"endpoint": endpoint, "endpoints": self.endpoints(), **deepcopy(details)}

    def update(self, rule, endpoint=DEFAULT_ENDPOINT, *, create_only=False, if_match=None, manage_trust=True):
        validate_endpoint(endpoint)
        if endpoint in self.demos:
            raise ReadOnlyEndpointError("Der Demo-Endpunkt ist schreibgeschützt.")
        rule = deepcopy(rule)
        check = self.compile(rule, endpoint)
        validate_rule_size(rule)
        with self.lock:
            current = self.routes.get(endpoint)
            if if_match is not None and (current is None or rule_version(current[0]) != if_match):
                return None
            previous = current[0] if current else {}
            if not manage_trust:
                trust_changed = any(previous.get(key) != rule.get(key) for key in ("credential", "verification", "bundle"))
                evidence_disabled = previous.get("responseMode") == "decision" and rule["responseMode"] != "decision"
                if trust_changed or evidence_disabled:
                    raise PermissionError("Prüfvertrauen und Nachweispflicht verwaltet ein globaler Admin.")
            if create_only and endpoint in self.routes:
                return None
            routes = {**self.routes, endpoint: (rule, check)}
            if len(routes) > MAX_ENDPOINTS:
                raise ValueError("Es können höchstens 64 Endpunkte gespeichert werden.")
            rules = {name: value[0] for name, value in routes.items()}
            state = {"version": 1, "rules": rules}
            serialized = json.dumps(state, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
            if len(serialized) > MAX_STATE_BYTES:
                raise ValueError("Die Regelsammlung würde das Größenlimit überschreiten.")
            self.state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=self.state.parent, delete=False) as temporary:
                path = Path(temporary.name)
                try:
                    temporary.write(serialized)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                    temporary.close()
                    os.replace(path, self.state)
                finally:
                    path.unlink(missing_ok=True)
            self.routes = routes
            return self.describe(endpoint)

    def verify(self, data, endpoint=DEFAULT_ENDPOINT, *, operation_id=None, caller=None, request_body=None, if_match=None):
        if endpoint in self.wallet_endpoints:
            raise ValueError("Dieser Endpunkt erfordert eine serverseitig geprüfte Wallet-Sitzung.")
        with self.lock:
            rule, compiled = self.demo_routes.get(endpoint) or self.routes[endpoint]
            version = rule_version(rule) if if_match is not None or rule["responseMode"] == "decision" else None
            if if_match is not None and if_match != version:
                return 412, {"error": "Die gespeicherte Regel wurde geändert.", "code": "rule_version_conflict"}
        if rule["responseMode"] != "decision":
            if operation_id is not None:
                raise ValueError("operationId ist nur im Entscheidungsmodus zulässig.")
            return evaluate_rule(rule, compiled, data)
        if not isinstance(operation_id, str) or not _OPERATION.fullmatch(operation_id):
            raise ValueError("Der Entscheidungsmodus braucht eine gültige operationId.")
        if caller is None:
            return 403, {"error": "Der Entscheidungsmodus erfordert einen authentifizierten Aufruf.", "code": "forbidden"}
        target = self.forwarding.get(endpoint)
        if target is not None and (not isinstance(request_body, bytes) or not 0 < len(request_body) <= MAX_BODY_BYTES
                                  or canonical_bytes(load_json(request_body))
                                  != canonical_bytes({"data": data, "operationId": operation_id})):
            raise ValueError("Der Weiterleitungsvorgang stimmt nicht mit der geprüften Anfrage überein.")
        evaluation = evaluate(rule, compiled, data, operation_id=operation_id)
        if target is not None and evaluation.outcome == "allow":
            return self.deliver(target, request_body, endpoint, caller, operation_id, data, version, evaluation)
        status, result = self.record_decision(endpoint, caller, operation_id, data, version, evaluation)
        if target is None or "decisionId" not in result:
            return status, result
        return (403 if evaluation.outcome == "deny" else 503), {
            **result, "delivery": {"state": "not_forwarded"},
        }

    def wallet_rule_version(self, endpoint):
        if endpoint not in self.wallet_endpoints:
            raise ValueError("Kein Wallet-Endpunkt.")
        with self.lock:
            return rule_version(self.routes[endpoint][0])

    def verify_wallet(self, endpoint, caller, operation_id, expected_version, claims, check, *,
                      wallet_session, expiry_replay_deadline=None):
        with self.lock:
            if self.wallet_rule_version(endpoint) != expected_version:
                return 409, {"error": "Die Wallet-Regel wurde geändert.", "code": "wallet_rule_changed"}
            rule, compiled = self.routes[endpoint]
        if expiry_replay_deadline is not None:
            evaluation = Evaluation("indeterminate", "wallet_expired", (check,))
        elif claims is None:
            evaluation = Evaluation("deny", "wallet_rejected", (check,))
        else:
            evaluated = evaluate(rule, compiled, claims)
            evaluation = Evaluation(evaluated.outcome, evaluated.reason, (check,))
        status, result = self.record_decision(
            endpoint, caller, operation_id, claims, expected_version, evaluation, wallet_session=wallet_session,
            expiry_replay_deadline=expiry_replay_deadline,
        )
        return (403 if "decisionId" in result and evaluation.outcome == "deny" else status), result

    def record_decision(self, endpoint, caller, operation_id, data, version, evaluation, *,
                        wallet_session=None, expiry_replay_deadline=None):
        try:
            decision_id = self.evidence.record(
                endpoint=endpoint, caller=caller, operation_id=operation_id, data=data,
                version=version, outcome=evaluation.outcome, reason=evaluation.reason, checks=evaluation.checks,
                wallet_session=wallet_session, expiry_replay_deadline=expiry_replay_deadline,
            )
        except (OSError, sqlite3.Error):
            return 503, {"error": "Der Nachweisspeicher ist nicht verfügbar.", "code": "evidence_unavailable"}
        return evaluation.status, {
            **evaluation.body, "decisionId": decision_id, "operationId": operation_id, "ruleVersion": version,
        }

    def deliver(self, target, request_body, endpoint, caller, operation_id, data, version, evaluation):
        try:
            decision_id, recorded_version, recorded_reason, delivery = self.evidence.record_forwarding_approval(
                endpoint=endpoint, caller=caller, operation_id=operation_id, data=data,
                version=version, reason=evaluation.reason, checks=evaluation.checks,
            )
        except ForwardingConflict:
            return 409, {"error": "Die Vorgangsreferenz ist bereits an eine andere Eingabe gebunden.",
                         "code": "operation_conflict"}
        except ForwardingEvidenceExpired:
            return 409, {"error": "Der ursprüngliche Weiterleitungsnachweis ist abgelaufen.",
                         "code": "operation_evidence_expired"}
        except (OSError, sqlite3.Error, ValueError):
            return 503, {"error": "Der Weiterleitungsnachweis ist nicht verfügbar.", "code": "evidence_unavailable"}
        result = {**evaluation.body, "reason": recorded_reason, "decisionId": decision_id,
                  "operationId": operation_id, "ruleVersion": recorded_version}
        if delivery.acquired:
            try:
                status = target.send(request_body, delivery.id)
            except ForwardingUnavailable:
                status, state = None, "unknown"
            else:
                state = "delivered" if 200 <= status < 300 else "rejected"
            try:
                delivery = self.evidence.finish_forwarding(delivery.id, state=state, upstream_status=status)
            except (OSError, sqlite3.Error, ValueError):
                return 503, {**result, "delivery": {"id": delivery.id, "state": "unknown"}}
        details = {"id": delivery.id, "state": delivery.state}
        if delivery.upstream_status is not None:
            details["upstreamStatus"] = delivery.upstream_status
        return {"delivered": 200, "rejected": 502, "unknown": 503, "pending": 503}[delivery.state], {
            **result, "delivery": details,
        }

    def preview(self, rule, data, endpoint=None):
        if isinstance(rule, dict) and "verification" in rule:
            with self.lock:
                current = self.routes.get(endpoint)
                if current is None or current[0].get("verification") != rule["verification"]:
                    raise ValueError("Die Vorschau benötigt die gespeicherte Prüfkonfiguration des Endpunkts.")
        return preview_rule(rule, data, registry=self.registry)


@dataclass(frozen=True)
class Evaluation:
    outcome: str
    reason: str
    checks: tuple = ()
    credential_error: str | None = None

    @property
    def status(self):
        return 503 if self.outcome == "indeterminate" else 200

    @property
    def body(self):
        return {"outcome": self.outcome, "valid": self.outcome == "allow", "reason": self.reason}


def evaluate(rule, compiled, data, *, trace=None, operation_id=None):
    check, verifier = compiled
    checks = ()
    if rule.keys() & {"verification", "bundle"}:
        verified = verifier(data, operation_id) if "bundle" in rule else verifier(data)
        checks = verified.evidence
        if verified.outcome == "indeterminate":
            return Evaluation("indeterminate", "check_indeterminate", checks)
        if verified.outcome != "passed":
            return Evaluation("deny", "check_failed", checks)
        data = verified.facts
    elif verifier is not None:
        kind = rule["credential"]["format"]
        try:
            if kind == "vc-data-integrity" and not isinstance(data, dict):
                raise ValueError("Ein Data-Integrity-Credential muss als JSON-Objekt in data übergeben werden.")
            if kind != "vc-data-integrity" and not isinstance(data, str):
                raise ValueError("Ein signiertes Credential muss als String in data übergeben werden.")
            data = verifier(data)
        except ValueError as exc:
            return Evaluation("deny", "credential_rejected", ({"kind": kind, "outcome": "failed"},), str(exc))
        checks = ({"kind": kind, "outcome": "passed"},)
    elif rule["language"] == "odrl" and not isinstance(data, dict):
        raise ValueError("ODRL erwartet ein JSON-Objekt als data.")
    elif rule["language"] == "shacl" and not isinstance(data, str):
        raise ValueError("SHACL erwartet Turtle-Text als data.")
    valid = check(data, trace=trace) if trace is not None and rule["language"] == "odrl" else check(data)
    return Evaluation("allow" if valid else "deny", "policy_allowed" if valid else "policy_denied", checks)


def evaluate_rule(rule, compiled, data, *, trace=None):
    result = evaluate(rule, compiled, data, trace=trace)
    if rule["responseMode"] == "decision":
        return result.status, result.body
    if result.credential_error is not None:
        return 403, {"stage": "credential", "code": "credential_rejected", "error": result.credential_error}
    valid = result.outcome == "allow"
    if rule["responseMode"] == "url":
        result = {"valid": valid}
        target = rule["returnUrl" if valid else "failUrl"]
        if target:
            result["redirectUrl"] = target
        return 200, result
    return (403 if rule["responseMode"] == "guard" and not valid else 200), valid


def validate_rule_size(rule):
    size = len(json.dumps(rule, ensure_ascii=True, separators=(",", ":"))) + 1
    if size > MAX_BODY_BYTES:
        raise ValueError("Die gespeicherte Regel würde das Größenlimit überschreiten.")


def preview_rule(rule, data, *, registry=None):
    if not isinstance(rule, dict):
        raise ValueError("Eine Regel braucht language, policy und responseMode.")
    validate_rule_size(rule)
    if "bundle" in rule:
        raise ValueError("Nachweisbündel werden mit einer Vorgangsreferenz am gespeicherten Endpunkt geprüft.")
    encoded_data = json.dumps({"data": data}, ensure_ascii=False, separators=(",", ":"))
    if len(encoded_data.encode("utf-8", errors="backslashreplace")) > MAX_BODY_BYTES:
        raise ValueError("Die Prüfeingabe überschreitet das Größenlimit von 96 KiB.")
    trace = []
    compiled = compile_rule(rule, registry)
    evaluation = evaluate(rule, compiled, data, trace=trace) if rule["responseMode"] == "decision" else None
    if evaluation is not None:
        status, decision = evaluation.status, evaluation.body
    else:
        status, decision = evaluate_rule(rule, compiled, data, trace=trace)
    credential_rejected = isinstance(decision, dict) and (
        decision.get("stage") == "credential" or decision.get("reason") == "credential_rejected"
    )
    result = {
        "stage": "credential" if credential_rejected else "policy",
        "valid": decision if isinstance(decision, bool) else decision.get("valid", False),
        "decisionStatus": status,
        "decision": decision,
    }
    if "credential" in rule:
        result["credentialVerified"] = not credential_rejected
    if "verification" in rule:
        result["checks"] = evaluation.checks
        if evaluation.reason in ("check_failed", "check_indeterminate"):
            result["stage"] = "verification"
    if trace:
        result["trace"] = trace[0]
    return result

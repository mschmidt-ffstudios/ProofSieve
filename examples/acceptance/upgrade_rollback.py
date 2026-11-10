"""Rehearse installed release recovery using signed synthetic wallet decisions."""

import hashlib
import json
import secrets
import sqlite3
import subprocess
from contextlib import closing, contextmanager
from pathlib import Path
from urllib.parse import urlencode

from services import available_port, request, secure_json, service, wait_http
from wallet_cases import SURNAME, SyntheticCredential, present, require
from proofsieve.evidence import verify_evidence_export


PREVIOUS_VERSION = "0.4.0-rc.11"
ENDPOINT = "/verify/compare/credo-sd-jwt"
PRINCIPAL = "upgrade-verifier"
STATUS = "approved-before-upgrade"


def call(base, path, token, *, method="GET", body=None, editor=None, status=200):
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if editor is not None:
        headers["X-ProofSieve-Token"] = editor
    actual, data = request(base + path, method, None if body is None else json.dumps(body).encode(), headers)
    require(actual == status, f"{method} {path.split('?')[0]} returned {actual}, expected {status}")
    return json.loads(data)


@contextmanager
def installed_guard(binary, work, state, env, version, phase, verifier):
    port = available_port()
    base = f"http://127.0.0.1:{port}"
    command = [
        str(binary), "--port", str(port), "--auth-config", str(work / "access.json"),
        "--wallet-config", str(work / "wallet.json"), "--state", str(state / "rules.json"),
        "--evidence", str(state / "evidence.db"), "--evidence-export",
        "--wallet-sessions", str(state / "wallet-sessions.db"),
    ]
    with service(command, work / f"{phase}.log", cwd=work, env=env) as process:
        wait_http(base + "/auth/me", 401, process)
        specification = call(base, "/openapi.json", verifier)
        require(specification["info"]["version"] == version, f"{phase} started the wrong installed version")
        yield base


def snapshot(source, destination):
    destination.mkdir(mode=0o700)
    (destination / "rules.json").write_bytes((source / "rules.json").read_bytes())
    for name in ("evidence.db", "wallet-sessions.db"):
        target = destination / name
        target.touch(mode=0o600, exist_ok=False)
        with closing(sqlite3.connect((source / name).as_uri() + "?mode=ro", uri=True)) as original:
            with closing(sqlite3.connect(target)) as backup:
                original.backup(backup)
                require(backup.execute("PRAGMA quick_check").fetchone() == ("ok",), f"Invalid {name} snapshot")


def verify_saved_rule(base, token):
    for value, expected in ((STATUS, True), ("active", False)):
        result = call(base, "/verify", token, method="POST", body={"data": {"status": value}})
        require(result is expected, "The installed release changed the saved rule outcome")


def verify_session(base, token, operation, data, status):
    return call(base, ENDPOINT, token, method="POST", body={"operationId": operation, "data": data}, status=status)


def evidence_path(operation, decision_id=None):
    fields = {"endpoint": ENDPOINT, "operationId": operation}
    if decision_id is not None:
        fields["decisionId"] = decision_id
    return "/evidence?" + urlencode(fields)


def complete_wallet(base, token, operation, target, fixture, nonces, pin=None):
    started = verify_session(base, token, operation, {"action": "start"}, 201)
    credential = SyntheticCredential.issue("dc+sd-jwt", fixture, SURNAME)
    present(target, started["authorizationRequestUri"], credential, wrong_nonce=False, observed_nonces=nonces)
    complete = {"action": "complete", "sessionId": started["sessionId"]}
    decision = verify_session(base, token, operation, complete, 200)
    require((decision["outcome"], decision["operationId"]) == ("allow", operation),
            "A valid signed wallet presentation did not produce an approval")
    exported = call(base, evidence_path(operation, decision["decisionId"]), token)
    require(exported["scope"] == {"caller": PRINCIPAL, "endpoint": ENDPOINT, "operationId": operation},
            "The wallet decision export changed its scope")
    require(verify_evidence_export(exported, public_key=pin or exported["integrity"]["publicKey"]),
            "The wallet decision has an invalid signature")
    return decision["decisionId"], complete, exported


def verify_retained_decision(base, token, operation, saved, pin):
    decision_id, complete, exported = saved
    actual = call(base, evidence_path(operation, decision_id), token)
    require(actual == exported and verify_evidence_export(actual, public_key=pin),
            "The installed release changed the recorded decision or its signature")
    require(verify_session(base, token, operation, complete, 409)["code"] == "wallet_session_conflict",
            "A previously consumed wallet session was accepted")
    require(verify_session(base, token, operation, {"action": "start"}, 409)["code"] == "wallet_session_conflict",
            "A previously reserved business operation was accepted")
    require(call(base, evidence_path(operation), token)["decisions"] == exported["decisions"],
            "Replay created another decision")


def reconcile_before_rollback(base, candidate, state, token, target, fixture, nonces, pin):
    operation = "interrupted-before-rollback"
    started = verify_session(base, token, operation, {"action": "start"}, 201)
    present(target, started["authorizationRequestUri"], SyntheticCredential.issue("dc+sd-jwt", fixture, SURNAME),
            wrong_nonce=False, observed_nonces=nonces)
    complete = {"action": "complete", "sessionId": started["sessionId"]}
    journal = state / "wallet-sessions.db"

    def inspect(expected_status):
        result = subprocess.run([str(candidate), "--wallet-receipts", "--wallet-sessions", str(journal)],
                                capture_output=True, text=True, timeout=10)
        require(result.returncode == expected_status and json.loads(result.stdout)["pending"] == expected_status,
                "Wallet receipt check did not enforce the downgrade precondition")

    with closing(sqlite3.connect(state / "evidence.db")) as lock:
        lock.execute("BEGIN EXCLUSIVE")
        failed = verify_session(base, token, operation, complete, 503)
        require(failed.get("code") == "evidence_unavailable", "The injected evidence write failure was missed")
        inspect(1)
    decision = verify_session(base, token, operation, complete, 503)
    require((decision.get("outcome"), decision.get("reason")) == ("indeterminate", "wallet_evidence_interrupted"),
            "Retry did not preserve the blocked operation")
    exported = call(base, evidence_path(operation, decision["decisionId"]), token)
    require(verify_evidence_export(exported, public_key=pin), "The reconciled decision signature is invalid")
    inspect(0)
    return operation, (decision["decisionId"], complete, exported)


def rehearse(previous, candidate, candidate_version, source, fixture, target, env, report_path):
    report = {"status": "fail", "previousVersion": PREVIOUS_VERSION, "candidateVersion": candidate_version, "checks": []}
    try:
        work = source / "upgrade"
        work.mkdir(mode=0o700)
        state = work / "live"
        state.mkdir(mode=0o700)
        initial_rules = json.loads((source / "rules.json").read_text())["rules"]
        secure_json(state / "rules.json", {"version": 1, "rules": {
            path: initial_rules[path] for path in ("/verify", ENDPOINT)
        }})
        initial_wallet = json.loads((source / "wallet.json").read_text())
        secure_json(work / "wallet.json", {"version": 1, "connectors": {
            "credo": initial_wallet["connectors"]["credo"]
        }, "endpoints": {ENDPOINT: initial_wallet["endpoints"][ENDPOINT]}})

        operator, verifier, observer = (secrets.token_urlsafe(32) for _ in range(3))
        secure_json(work / "access.json", {"version": 1, "principals": [
            {"id": identity, "role": role, "endpoints": endpoints,
             "tokenSha256": hashlib.sha256(token.encode("ascii")).hexdigest()}
            for identity, role, endpoints, token in (
                ("upgrade-operator", "admin", ["*"], operator),
                (PRINCIPAL, "verifier", ["/verify", ENDPOINT], verifier),
                ("upgrade-observer", "verifier", [ENDPOINT], observer),
            )
        ]})
        nonces = set()
        with installed_guard(previous, work, state, env, PREVIOUS_VERSION, "baseline", verifier) as base:
            csrf = call(base, "/auth/me", operator)["csrfToken"]
            rule = call(base, "/admin/rule", operator)["rule"]
            rule["policy"]["permission"][0]["constraint"][0]["rightOperand"] = STATUS
            call(base, "/admin/rule", operator, method="PUT", body=rule, editor=csrf)
            verify_saved_rule(base, verifier)
            before = complete_wallet(base, verifier, "before-upgrade", target, fixture, nonces)
            pin = before[2]["integrity"]["publicKey"]
            call(base, evidence_path("before-upgrade", before[0]), observer, status=404)
        report["checks"].append("rc11-saved-rule-and-signed-wallet-decision")
        backup = work / "pre-upgrade-backup"
        snapshot(state, backup)
        report["checks"].append("stopped-rules-evidence-and-wallet-snapshot")

        with installed_guard(candidate, work, state, env, candidate_version, "upgrade", verifier) as base:
            verify_saved_rule(base, verifier)
            verify_retained_decision(base, verifier, "before-upgrade", before, pin)
            after = complete_wallet(base, verifier, "after-upgrade", target, fixture, nonces, pin)
            interrupted, reconciled = reconcile_before_rollback(
                base, candidate, state, verifier, target, fixture, nonces, pin,
            )
        report["checks"].append("candidate-preserves-rules-evidence-and-wallet-replay-protection")
        report["checks"].append("candidate-reconciles-open-wallet-receipt-before-downgrade")

        with installed_guard(previous, work, state, env, PREVIOUS_VERSION, "rollback", verifier) as base:
            verify_saved_rule(base, verifier)
            verify_retained_decision(base, verifier, "before-upgrade", before, pin)
            verify_retained_decision(base, verifier, "after-upgrade", after, pin)
            verify_retained_decision(base, verifier, interrupted, reconciled, pin)
            complete_wallet(base, verifier, "after-rollback", target, fixture, nonces, pin)
        report["checks"].append("rc11-rollback-reads-candidate-state-and-signs-new-decisions")

        restored = work / "restored"
        snapshot(backup, restored)
        with installed_guard(candidate, work, restored, env, candidate_version, "restore", verifier) as base:
            verify_saved_rule(base, verifier)
            verify_retained_decision(base, verifier, "before-upgrade", before, pin)
            call(base, evidence_path("after-upgrade", after[0]), verifier, status=404)
        report["checks"].append("candidate-restore-preserves-baseline-signature-and-replay-protection")
        report["status"] = "pass"
    finally:
        secure_json(report_path, report)

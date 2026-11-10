"""Exercise the live HTTP boundary for operation-bound wallet decisions."""

import hashlib
import http.client
import json
import secrets
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlencode

from proofsieve.access import AccessPolicy
from proofsieve.evidence import EvidenceStore, verify_evidence_export
from proofsieve.guard import DEFAULT_RULE, Guard
from proofsieve.server import Handler, LoopbackHTTPServer
from proofsieve.wallet import WalletEndpoint, WalletVerification
from proofsieve.wallet_protocol import WalletRejected, WalletTransaction, WalletUnavailable
from proofsieve.wallet_sessions import COMPLETION_RECOVERY_SECONDS, WalletSessions, pending_wallet_receipts


ENDPOINT = "/verify/wallet-pid"


class Connector:
    def __init__(self):
        self.started = {}
        self.result_calls = 0
        self.reply = None

    def start(self, *, profile, nonce):
        identifier = secrets.token_urlsafe(24)
        self.started[identifier] = (profile, nonce)
        return WalletTransaction(identifier, "haip-vp://?example=internal")

    def result(self, *, transaction_id, profile, nonce):
        assert self.started[transaction_id] == (profile, nonce)
        self.result_calls += 1
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


class WalletHTTPTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.tokens = {role: secrets.token_urlsafe(32) for role in ("first", "second", "other", "admin")}
        auth = self.work / "auth.json"
        auth.write_text(json.dumps({"version": 1, "principals": [
            {"id": role, "role": "admin" if role == "admin" else "verifier",
             "tokenSha256": hashlib.sha256(token.encode()).hexdigest(),
             "endpoints": ["/verify" if role == "other" else ENDPOINT]}
            for role, token in self.tokens.items()
        ]}))
        auth.chmod(0o600)
        self.evidence = EvidenceStore(self.work / "evidence.db")
        self.epoch = time.time() - 1_000
        self.now = 1_000
        self.sessions = self.open_sessions()
        self.connector = Connector()
        profile = SimpleNamespace(format="dc+sd-jwt", status_mode="not-required")
        self.binding = WalletEndpoint("reference", self.connector, profile, "profile-v1")
        self.rule = {**DEFAULT_RULE, "responseMode": "decision", "wallet": True}
        self.state = self.work / "rules.json"
        self.state.write_text(json.dumps({"version": 1, "rules": {"/verify": DEFAULT_RULE, ENDPOINT: self.rule}}))
        self.state.chmod(0o600)
        self.guard = Guard(self.state, {}, evidence=self.evidence, wallet_endpoints=(ENDPOINT,))
        self.server = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
        self.server.access_policy = AccessPolicy.load(auth)
        self.server.guard = self.guard
        self.server.credential_checks = {}
        self.server.wallet = WalletVerification(self.sessions, {ENDPOINT: self.binding})
        self.server.evidence_export = True
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)

    def open_sessions(self, **options):
        return WalletSessions(self.work / "wallet.db", clock=lambda: self.epoch + self.now, lifetime_seconds=10,
                              retention_seconds=20, **options)

    def request(self, data=None, operation="order-1", user="first", path=ENDPOINT, *, include_headers=False):
        headers = {"Content-Type": "application/json"}
        if user:
            headers["Authorization"] = f"Bearer {self.tokens[user]}"
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            body = json.dumps({"data": data, "operationId": operation}) if data is not None else None
            connection.request("POST" if body else "GET", path, body, headers)
            with connection.getresponse() as reply:
                result = (reply.status, json.loads(reply.read()))
                return (*result, reply.headers) if include_headers else result
        finally:
            connection.close()

    def start(self, operation="order-1"):
        status, session = self.request({"action": "start"}, operation)
        self.assertEqual(status, 201)
        self.assertEqual(session["operationId"], operation)
        self.assertEqual(session["state"], "pending")
        return {"action": "complete", "sessionId": session["sessionId"]}

    def test_exact_scope_binding_pending_and_single_use(self):
        self.assertEqual(self.request({"action": "start"}, user=None)[0], 401)
        self.assertEqual(self.request({"action": "start"}, user="other")[0], 403)
        self.assertEqual(self.request({"status": "active"})[0], 400)
        complete = self.start()
        self.assertEqual(self.request({"action": "start"})[0], 409)
        self.assertEqual(self.request(complete, user="second")[0], 404)
        self.assertEqual(self.request(complete, operation="other-order")[0], 404)
        self.assertEqual(self.request({**complete, "status": "active"})[0], 400)
        self.assertEqual(self.connector.result_calls, 0)
        self.assertEqual(self.request(complete)[0], 202)
        self.connector.reply = {"status": "active", "private": "synthetic claim"}
        status, result = self.request(complete)
        self.assertEqual((status, result["outcome"], result["operationId"]), (200, "allow", "order-1"))
        self.assertEqual(self.request(complete)[0], 409)
        self.assertEqual(self.connector.result_calls, 2)
        with closing(self.evidence.connect()) as db:
            outcome, checks = db.execute("SELECT outcome, checks FROM decisions").fetchone()
        self.assertEqual(outcome, "allow")
        self.assertEqual(json.loads(checks)[0]["kind"], "wallet_presentation")
        self.assertEqual(json.loads(checks)[0]["statusMode"], "not-required")
        self.assertNotIn(b"synthetic claim", self.evidence.path.read_bytes())

    def reopen_runtime(self):
        self.evidence = EvidenceStore(self.work / "evidence.db")
        self.guard = Guard(self.state, {}, evidence=self.evidence, wallet_endpoints=(ENDPOINT,))
        self.server.guard = self.guard
        self.server.wallet = WalletVerification(self.open_sessions(), {ENDPOINT: self.binding})

    def test_completion_evidence_outage_repairs_once_without_approval_after_restart(self):
        complete = self.start()
        private_claim = "sensitive-claim-that-must-not-be-journaled"
        self.connector.reply = {"status": "active", "private": private_claim}

        with closing(self.evidence.connect()) as locked:
            locked.execute("BEGIN EXCLUSIVE")
            status, result = self.request(complete)
            self.assertEqual((status, result["code"]), (503, "evidence_unavailable"))
            self.assertNotIn("decisionId", result)
            with closing(sqlite3.connect(self.work / "wallet.db")) as journal:
                self.assertEqual(journal.execute(
                    "SELECT state FROM wallet_sessions WHERE id = ?", (complete["sessionId"],),
                ).fetchone(), ("consumed",))
        for path in self.work.glob("wallet.db*"):
            self.assertNotIn(private_claim.encode(), path.read_bytes(), path.name)

        self.reopen_runtime()
        evidence_path = "/evidence?" + urlencode({"endpoint": ENDPOINT, "operationId": "order-1"})
        self.assertEqual(self.request(complete, user="second")[0], 404)
        self.assertEqual(self.request(complete, operation="other-order")[0], 404)
        self.assertEqual(self.request({"action": "start"})[0], 409)
        self.assertEqual(self.request(path=evidence_path)[0], 404)

        ready = threading.Barrier(2)

        def retry():
            ready.wait(timeout=2)
            return self.request(complete)

        with ThreadPoolExecutor(max_workers=2) as pool:
            requests = [pool.submit(retry) for _ in range(2)]
            results = [request.result(timeout=5) for request in requests]
        self.assertEqual(sorted(status for status, _ in results), [409, 503])
        decision, = [body for status, body in results if status == 503]
        self.assertEqual((decision["valid"], decision["outcome"], decision["reason"], decision["operationId"]),
                         (False, "indeterminate", "wallet_evidence_interrupted", "order-1"))
        self.assertEqual(self.request(complete)[0], 409)
        self.assertEqual(self.connector.result_calls, 1)

        status, bundle = self.request(path=evidence_path)
        self.assertEqual(status, 200)
        self.assertEqual(self.request(path=evidence_path, user="second")[0], 404)
        self.assertEqual(bundle["scope"], {"caller": "first", "endpoint": ENDPOINT, "operationId": "order-1"})
        self.assertTrue(verify_evidence_export(bundle, public_key=self.evidence.export_public_key))
        self.assertEqual(len(bundle["decisions"]), 1)
        self.assertEqual({key: bundle["decisions"][0][key] for key in ("decisionId", "outcome", "reason", "ruleVersion")},
                         {key: decision[key] for key in ("decisionId", "outcome", "reason", "ruleVersion")})
        self.assertNotIn(complete["sessionId"], json.dumps(bundle))
        self.assertNotIn(private_claim, json.dumps(bundle))
        self.assertNotIn(private_claim.encode(), self.evidence.path.read_bytes())

    def test_pending_receipt_survives_repeated_outages_and_ordinary_retention(self):
        complete = self.start()
        self.connector.reply = {"status": "active"}
        with patch.object(self.evidence, "record", side_effect=OSError):
            self.assertEqual(self.request(complete)[1]["code"], "evidence_unavailable")

        self.now = 1_031  # Beyond both the deadline and normal replay retention.
        self.reopen_runtime()
        self.start("other-order")  # A new reservation also prunes ordinary replay records.
        self.assertEqual(self.request({"action": "start"})[0], 409)
        with patch.object(self.evidence, "recover_wallet_completion", side_effect=OSError):
            for _ in range(2):
                status, body = self.request(complete)
                self.assertEqual((status, body["code"]), (503, "evidence_unavailable"))

        status, body = self.request(complete)
        self.assertEqual((status, body["reason"]), (503, "wallet_evidence_interrupted"))
        self.assertEqual(self.request(complete)[0], 404)
        self.assertEqual(self.connector.result_calls, 1)

    def test_committed_completion_with_interrupted_acknowledgment_cannot_approve_again(self):
        complete = self.start()
        self.connector.reply = {"status": "active"}
        original_record = self.evidence.record
        committed = []

        def record_then_interrupt(**fields):
            committed.append(original_record(**fields))
            raise OSError("simulated interruption after the evidence commit")

        with patch.object(self.evidence, "record", side_effect=record_then_interrupt):
            status, result = self.request(complete)
        self.assertEqual((status, result["code"]), (503, "evidence_unavailable"))
        self.assertEqual(len(committed), 1)

        self.reopen_runtime()
        self.assertEqual(self.request(complete)[0], 409)
        self.assertEqual(self.request(complete)[0], 409)
        self.assertEqual(self.request({"action": "start"})[0], 409)
        self.assertEqual(self.connector.result_calls, 1)
        evidence_path = "/evidence?" + urlencode({"endpoint": ENDPOINT, "operationId": "order-1"})
        status, bundle = self.request(path=evidence_path)
        self.assertEqual(status, 200)
        self.assertTrue(verify_evidence_export(bundle, public_key=self.evidence.export_public_key))
        self.assertEqual(len(bundle["decisions"]), 1)
        record = bundle["decisions"][0]
        self.assertEqual((record["decisionId"], record["outcome"], record["reason"]),
                         (committed[0], "allow", "policy_allowed"))

    def test_pruned_committed_evidence_keeps_the_original_signed_identity(self):
        self.evidence.retention = timedelta(days=1)
        complete = self.start()
        self.connector.reply = {"status": "active"}
        record = self.evidence.record

        def interrupt_after_commit(**fields):
            record(**fields)
            raise OSError("interrupted after commit")

        with patch.object(self.evidence, "record", side_effect=interrupt_after_commit):
            self.assertEqual(self.request(complete)[1]["code"], "evidence_unavailable")
        self.assertEqual(len(pending_wallet_receipts(self.work / "wallet.db")), 1)
        evidence_path = "/evidence?" + urlencode({"endpoint": ENDPOINT, "operationId": "order-1"})
        status, original = self.request(path=evidence_path)
        self.assertEqual(status, 200)
        self.assertEqual(original["decisions"][0]["outcome"], "allow")
        self.assertTrue(verify_evidence_export(original, public_key=self.evidence.export_public_key))

        with patch("proofsieve.evidence.datetime") as clock:
            clock.now.return_value = datetime.now(timezone.utc) + timedelta(days=2)
            record(endpoint=ENDPOINT, caller="first", operation_id="other-order", data={},
                   version="a" * 64, outcome="deny", reason="policy_denied", checks=())
        self.reopen_runtime()  # The clock has returned, but the irreversible prune boundary survives.
        self.assertEqual(self.request(complete)[0], 409)
        self.assertEqual(self.request(complete)[0], 409)
        self.assertEqual(self.request(path=evidence_path)[0], 404)
        self.assertEqual(self.connector.result_calls, 1)
        self.assertEqual(pending_wallet_receipts(self.work / "wallet.db"), [])

    def test_abandoned_receipt_reports_actual_quota_deadline_and_expires(self):
        self.server.wallet.sessions = self.open_sessions(max_retained_per_caller=1)
        complete = self.start()
        self.connector.reply = {"status": "active"}
        with patch.object(self.evidence, "record", side_effect=OSError):
            self.assertEqual(self.request(complete)[0], 503)
        self.now += 31
        status, response, headers = self.request({"action": "start"}, "other-order", include_headers=True)
        remaining = COMPLETION_RECOVERY_SECONDS - 31
        self.assertEqual((status, response["retryAfterSeconds"], headers["Retry-After"]),
                         (429, remaining, str(remaining)))
        self.now += remaining
        self.assertEqual(self.request(complete)[0], 404)
        self.start("other-order")
        self.assertEqual(self.request(complete)[0], 404)

    def test_credential_rejection_policy_denial_and_temporary_outage(self):
        complete = self.start()
        self.connector.reply = WalletUnavailable()
        self.assertEqual(self.request(complete)[0], 503)
        self.connector.reply = WalletRejected()
        status, result = self.request(complete)
        self.assertEqual((status, result["reason"]), (403, "wallet_rejected"))
        self.assertEqual(self.request(complete)[0], 409)
        other = self.start("order-2")
        self.connector.reply = {"status": "blocked"}
        status, result = self.request(other, "order-2")
        self.assertEqual((status, result["reason"]), (403, "policy_denied"))

    def test_wallet_start_quota_preserves_other_callers_and_replay_records(self):
        self.server.wallet.sessions = self.open_sessions(max_recent_per_caller=2, max_retained_per_caller=3)
        start = {"action": "start"}
        with patch.object(self.connector, "start", side_effect=WalletUnavailable()):
            self.assertEqual(self.request(start, "failed")[0], 503)
        complete = self.start()
        status, response, headers = self.request(start, "next", include_headers=True)
        self.assertEqual((status, response["code"], response["retryAfterSeconds"]), (429, "wallet_rate_limited", 10))
        self.assertEqual(headers["Retry-After"], "10")
        _, specification = self.request(path="/openapi.json")
        documented = specification["paths"][ENDPOINT]["post"]["responses"]["429"]
        self.assertEqual(documented["content"]["application/json"]["schema"]["properties"]["code"],
                         {"const": response["code"]})
        self.assertEqual(self.request(start, "other", user="second")[0], 201)
        self.connector.reply = {"status": "active"}
        self.assertEqual(self.request(complete)[0], 200)
        self.assertEqual(self.request(start, "next")[0], 429)
        self.assertEqual(self.request(start, "failed")[0], 409)
        self.assertEqual(self.request(complete)[0], 409)

        self.now = 1_010
        self.assertEqual(self.request(start, "next")[0], 201)
        status, response = self.request(start, "new")
        self.assertEqual((status, response["code"], response["retryAfterSeconds"]), (429, "wallet_rate_limited", 20))
        self.now = 1_030
        self.assertEqual(self.request(start, "new")[0], 201)

    def test_pending_expiry_records_one_signed_decision_for_the_exact_scope(self):
        complete = self.start()
        self.assertEqual(self.request(complete), (202, {"state": "pending", "operationId": "order-1"}))
        self.now = 1_010
        self.assertEqual(self.request(complete, user="second")[0], 404)
        self.assertEqual(self.request(complete, operation="other-order")[0], 404)
        self.assertEqual(self.request({**complete, "sessionId": "A" * 43})[0], 404)

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.request(complete), range(4)))
        status, decision = results[0]
        self.assertEqual((status, decision["outcome"], decision["reason"], decision["valid"]),
                         (503, "indeterminate", "wallet_expired", False))
        self.assertEqual(results, [(status, decision)] * 4)
        self.assertEqual(self.connector.result_calls, 1)

        path = "/evidence?" + urlencode({
            "endpoint": ENDPOINT, "operationId": "order-1", "decisionId": decision["decisionId"],
        })
        self.assertEqual(self.request(path=path, user="second")[0], 404)
        status, bundle = self.request(path=path)
        self.assertEqual(status, 200)
        self.assertTrue(verify_evidence_export(bundle, public_key=self.evidence.export_public_key))
        [record] = bundle["decisions"]
        self.assertEqual((record["reason"], record["outcome"]), ("wallet_expired", "indeterminate"))
        self.assertEqual(record["checks"], [{
            "kind": "wallet_presentation", "outcome": "indeterminate", "reason": "wallet_expired",
            "adapter": "reference", "format": "dc+sd-jwt", "profileVersion": "profile-v1",
        }])
        self.assertNotIn(complete["sessionId"], json.dumps(bundle))

        self.server.wallet.sessions = self.open_sessions()
        self.now = 1_005  # A sealed expiry remains terminal across restart and clock rollback.
        self.connector.reply = {"status": "active"}
        self.assertEqual(self.request(complete), (503, decision))
        self.assertEqual(self.connector.result_calls, 1)
        self.now = 1_030
        self.assertEqual(self.request(complete)[0], 404)
        with closing(self.evidence.connect()) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM decisions").fetchone(), (1,))

    def test_expiry_recovers_when_the_first_evidence_write_fails(self):
        complete = self.start()
        self.now = 1_010
        with patch.object(self.evidence, "record", side_effect=OSError("simulated write failure")):
            status, result = self.request(complete)
        self.assertEqual((status, result["code"]), (503, "evidence_unavailable"))

        self.server.wallet.sessions = self.open_sessions()
        self.now = 1_005
        self.connector.reply = {"status": "active"}
        status, result = self.request(complete)
        self.assertEqual((status, result["outcome"], result["reason"]), (503, "indeterminate", "wallet_expired"))
        self.assertEqual(self.request(complete), (status, result))
        self.assertEqual(self.connector.result_calls, 0)

    def test_pruned_expiry_cannot_be_resigned_after_clock_correction(self):
        self.evidence.retention = timedelta(days=1)
        cases = {operation: self.start(operation) for operation in ("order-1", "legacy-order")}
        self.now = 1_010
        paths = {}
        for operation, complete in cases.items():
            status, result = self.request(complete, operation)
            self.assertEqual((status, result["reason"]), (503, "wallet_expired"))
            paths[operation] = "/evidence?" + urlencode({
                "endpoint": ENDPOINT, "operationId": operation, "decisionId": result["decisionId"],
            })
            status, bundle = self.request(path=paths[operation])
            self.assertEqual(status, 200)
            self.assertTrue(verify_evidence_export(bundle, public_key=self.evidence.export_public_key))
        # A previous release could record wallet expiry without a commit marker.
        with closing(self.evidence.connect()) as db, db:
            db.execute("""DELETE FROM wallet_completion_commits WHERE id IN (
                              SELECT id FROM decisions WHERE operation_id = 'legacy-order'
                          )""")

        with patch("proofsieve.evidence.datetime") as clock:
            clock.now.return_value = datetime.now(timezone.utc) + timedelta(days=2)
            self.evidence.record(endpoint=ENDPOINT, caller="first", operation_id="unrelated", data={},
                                 version="a" * 64, outcome="deny", reason="policy_denied", checks=())
        self.reopen_runtime()
        for operation, complete in cases.items():
            status, result = self.request(complete, operation)
            self.assertEqual((status, result["code"]), (409, "wallet_session_conflict"))
            self.assertEqual(self.request(path=paths[operation])[0], 404)
        self.assertEqual(self.connector.result_calls, 0)

    def test_upstream_success_after_the_local_deadline_cannot_approve(self):
        complete = self.start()

        def late_result(**_):
            self.now = 1_010
            return {"status": "active"}

        with patch.object(self.connector, "result", side_effect=late_result):
            status, result = self.request(complete)
        self.assertEqual((status, result["outcome"], result["reason"]), (503, "indeterminate", "wallet_expired"))

    def test_expiry_checks_the_saved_profile_and_rule(self):
        complete = self.start()
        self.now = 1_010
        self.server.wallet.endpoints[ENDPOINT] = replace(self.binding, version="profile-v2")
        self.assertEqual(self.request(complete)[0], 409)
        self.server.wallet.endpoints[ENDPOINT] = self.binding
        self.guard.update({**self.rule, "policy": {**self.rule["policy"], "uid": "urn:changed"}}, ENDPOINT)
        self.assertEqual(self.request(complete)[0], 409)
        self.assertEqual(self.connector.result_calls, 0)
        with closing(self.evidence.connect()) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM decisions").fetchone(), (0,))

    def test_drift_and_configuration_cannot_downgrade_to_json(self):
        complete = self.start()
        self.guard.update({**self.rule, "policy": {**self.rule["policy"], "uid": "urn:changed"}}, ENDPOINT)
        self.assertEqual(self.request(complete)[0], 409)
        self.assertEqual(self.connector.result_calls, 0)
        with self.assertRaises(ValueError):
            self.guard.update(DEFAULT_RULE, ENDPOINT)
        with self.assertRaises(ValueError):
            Guard(self.state, {}, evidence=self.evidence)
        with self.assertRaises(ValueError):
            Guard(self.state, {}, evidence=self.evidence, forwarding={ENDPOINT: object()}, wallet_endpoints=(ENDPOINT,))
        with self.assertRaises(ValueError):
            self.guard.verify({"status": "active"}, ENDPOINT, operation_id="direct", caller="first")
        _, spec = self.request(path="/openapi.json")
        operation = spec["paths"][ENDPOINT]["post"]
        self.assertEqual(operation["x-proofsieve-input"], "wallet")
        self.assertTrue({"201", "202", "403", "404", "409", "503"} <= operation["responses"].keys())

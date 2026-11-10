"""Exercise forwarding at the live Guard HTTP and evidence boundaries."""

import hashlib
import http.client
import json
import secrets
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from proofsieve.access import AccessPolicy
from proofsieve.evidence import EvidenceStore
from proofsieve.forwarding import ForwardingUnavailable
from proofsieve.guard import DEFAULT_RULE, Guard
from proofsieve.server import Handler, LoopbackHTTPServer


ENDPOINT = "/verify/orders"


class Target:
    def __init__(self, store):
        self.store = store
        self.calls = []
        self.status = 204

    def send(self, body, delivery_id):
        with closing(self.store.connect()) as db:
            recorded = db.execute(
                "SELECT decisions.outcome, forwarding.state FROM forwarding "
                "JOIN decisions ON forwarding.decision_id = decisions.id WHERE forwarding.id = ?",
                (delivery_id,),
            ).fetchone()
        if recorded != ("allow", "pending"):
            raise AssertionError("Destination called before approval was recorded")
        self.calls.append((body, delivery_id))
        if self.status is None:
            raise ForwardingUnavailable()
        return self.status


class ForwardingTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        self.tokens = {role: secrets.token_urlsafe(32) for role in ("admin", "verifier", "other")}
        config = work / "auth.json"
        config.write_text(json.dumps({"version": 1, "principals": [
            {"id": role, "role": "admin" if role == "admin" else "verifier",
             "tokenSha256": hashlib.sha256(token.encode()).hexdigest(),
             "endpoints": [ENDPOINT] if role != "other" else ["/verify"]}
            for role, token in self.tokens.items()
        ]}))
        config.chmod(0o600)
        self.store = EvidenceStore(work / "audit.db")
        self.target = Target(self.store)
        self.state = work / "rules.json"
        self.guard = Guard(self.state, {}, evidence=self.store, forwarding={ENDPOINT: self.target})
        self.rule = {**DEFAULT_RULE, "responseMode": "decision"}
        self.guard.update(self.rule, ENDPOINT)
        self.server = LoopbackHTTPServer(("127.0.0.1", 0), Handler)
        self.server.access_policy = AccessPolicy.load(config)
        self.server.guard = self.guard
        self.server.credential_checks = {}
        self.server.evidence_export = True
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)

    def request(self, path, body=None, user="verifier", *, extra_headers=None):
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if user:
            headers["Authorization"] = f"Bearer {self.tokens[user]}"
        if extra_headers:
            headers.update(extra_headers)
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request("POST" if body is not None else "GET", path, body, headers)
            with connection.getresponse() as reply:
                return reply.status, json.loads(reply.read())
        finally:
            connection.close()

    def test_only_approved_exact_bytes_reach_the_configured_target(self):
        blocked = b'{"data":{"status":"blocked"},"operationId":"PO-1041"}'
        approved = b'{ "operationId" : "PO-1042", "data" : { "status" : "active", "amount" : 100 } }'
        status, result = self.request(ENDPOINT, blocked)
        self.assertEqual((status, result["outcome"], result["delivery"]), (403, "deny", {"state": "not_forwarded"}))
        self.assertEqual(self.request(ENDPOINT, approved, user=None)[0], 401)
        self.assertEqual(self.request(ENDPOINT, approved, user="other")[0], 403)
        self.assertEqual(self.request(ENDPOINT, b'{"data":{"status":"active"}}')[0], 400)
        self.assertEqual(self.request(ENDPOINT, approved.replace(b'"active"', b'"blocked","status":"active"'))[0], 400)
        status, conflict = self.request(ENDPOINT, approved, extra_headers={"If-Match": '"' + "0" * 64 + '"'})
        self.assertEqual((status, conflict["code"]), (412, "rule_version_conflict"))
        self.assertEqual(self.request("/evidence?endpoint=%2Fverify%2Forders&operationId=PO-1042")[0], 404)
        self.assertEqual(self.target.calls, [])
        status, result = self.request(ENDPOINT, approved)
        self.assertEqual((status, result["outcome"], result["delivery"]["upstreamStatus"]), (200, "allow", 204))
        self.assertEqual(self.target.calls, [(approved, result["delivery"]["id"])])
        changed_rule = deepcopy(self.rule)
        changed_rule["policy"]["uid"] = "urn:demo:policy:new-version"
        self.guard.update(changed_rule, ENDPOINT)
        self.assertEqual(self.request(ENDPOINT, approved), (200, result))
        conflict_status, conflict = self.request(ENDPOINT, approved.replace(b"100", b"200"))
        self.assertEqual((conflict_status, conflict["code"]), (409, "operation_conflict"))
        evidence_status, bundle = self.request("/evidence?endpoint=%2Fverify%2Forders&operationId=PO-1042")
        self.assertEqual(evidence_status, 200)
        self.assertEqual(len(bundle["decisions"]), 1)
        decision = bundle["decisions"][0]
        self.assertEqual((decision["decisionId"], decision["ruleVersion"], decision["delivery"]["id"]),
                         (result["decisionId"], result["ruleVersion"], result["delivery"]["id"]))
        self.assertEqual(len(self.target.calls), 1)

    def test_concurrent_approval_retries_report_the_one_reserved_decision(self):
        body = b'{"operationId":"PO-concurrent","data":{"status":"active"}}'
        entered, resume = threading.Event(), threading.Event()
        send = self.target.send

        def slow_send(raw, delivery_id):
            entered.set()
            if not resume.wait(timeout=3):
                raise AssertionError("Delivery was not resumed")
            return send(raw, delivery_id)

        with patch.object(self.target, "send", side_effect=slow_send), ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(self.request, ENDPOINT, body)
            try:
                self.assertTrue(entered.wait(timeout=2))
                status, pending = self.request(ENDPOINT, body)
                self.assertEqual((status, pending["delivery"]["state"]), (503, "pending"))
            finally:
                resume.set()
            status, delivered = first.result(timeout=3)
        self.assertEqual((status, delivered["decisionId"], delivered["delivery"]["id"]),
                         (200, pending["decisionId"], pending["delivery"]["id"]))
        self.assertEqual(len(self.target.calls), 1)

    def test_failed_reservation_rolls_back_approval_before_a_retry(self):
        body = b'{"operationId":"PO-unavailable","data":{"status":"active"}}'
        with patch.object(self.store, "_insert_forwarding", side_effect=OSError("journal unavailable")):
            status, result = self.request(ENDPOINT, body)
        self.assertEqual((status, result["code"]), (503, "evidence_unavailable"))
        evidence_url = "/evidence?endpoint=%2Fverify%2Forders&operationId=PO-unavailable"
        self.assertEqual(self.request(evidence_url)[0], 404)
        self.assertEqual(self.target.calls, [])
        self.assertEqual(self.request(ENDPOINT, body)[0], 200)
        self.assertEqual(len(self.request(evidence_url)[1]["decisions"]), 1)
        self.assertEqual(len(self.target.calls), 1)

    def test_expired_approval_keeps_the_operation_reserved_after_restart(self):
        body = b'{"operationId":"PO-expired","data":{"status":"active"}}'
        self.assertEqual(self.request(ENDPOINT, body)[0], 200)
        with closing(self.store.connect()) as db, db:
            db.execute("UPDATE decisions SET decided_at = '2000-01-01T00:00:00+00:00'")
        self.store = EvidenceStore(self.store.path)
        self.server.guard = Guard(self.state, {}, evidence=self.store, forwarding={ENDPOINT: self.target})
        status, result = self.request(ENDPOINT, body)
        self.assertEqual((status, result["code"]), (409, "operation_evidence_expired"))
        self.assertEqual(self.request("/evidence?endpoint=%2Fverify%2Forders&operationId=PO-expired")[0], 404)
        self.assertEqual(len(self.target.calls), 1)

    def test_rejected_or_unconfirmed_delivery_never_retries_after_restart(self):
        for upstream, expected, state in ((302, 502, "rejected"), (None, 503, "unknown")):
            with self.subTest(upstream=upstream):
                self.target.status = upstream
                body = json.dumps({"data": {"status": "active"}, "operationId": f"PO-{expected}"}).encode()
                status, result = self.request(ENDPOINT, body)
                self.assertEqual((status, result["delivery"]["state"]), (expected, state))
                current = Guard(self.state, {}, evidence=self.store, forwarding={ENDPOINT: self.target})
                self.server.guard = current
                replay_status, replay = self.request(ENDPOINT, body)
                self.assertEqual((replay_status, replay["delivery"]), (expected, result["delivery"]))
        self.assertEqual(len(self.target.calls), 2)

    def test_preview_and_mismatched_raw_input_do_not_forward(self):
        self.assertTrue(self.guard.preview(self.rule, {"status": "active"}, ENDPOINT)["valid"])
        with self.assertRaises(ValueError):
            self.guard.verify({"status": "active"}, ENDPOINT, operation_id="PO-1042", caller="verifier",
                              request_body=b'{"data":{"status":"blocked"},"operationId":"PO-1042"}')
        self.assertEqual(self.target.calls, [])
        _, spec = self.request("/openapi.json")
        operation = spec["paths"][ENDPOINT]["post"]
        self.assertTrue(operation["x-proofsieve-forwarding"])
        responses = operation["responses"]
        self.assertTrue({"403", "409", "412", "502", "503"} <= responses.keys())
        example = responses["200"]["content"]["application/json"]["examples"]["forwarded"]["value"]
        self.assertNotEqual(example["decisionId"], example["delivery"]["id"])
        conflict = responses["409"]["content"]["application/json"]["schema"]
        self.assertEqual(conflict["properties"]["code"]["enum"],
                         ["operation_conflict", "operation_evidence_expired"])

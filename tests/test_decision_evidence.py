"""Decision semantics, durable metadata and fail-closed behavior."""

import copy
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

from proofsieve.evidence import EvidenceStore
from proofsieve.guard import DEFAULT_RULE, Guard


class FixedRegistry:
    def compile(self, profile):
        def verify(data):
            return SimpleNamespace(
                outcome=data["outcome"],
                evidence=({"signer": "fixture-a", "outcome": data["outcome"]},),
                facts={"status": "active"},
            )
        return verify


class DecisionEvidenceTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.store = EvidenceStore(self.directory / "audit.db")
        self.state = self.directory / "rules.json"
        self.guard = Guard(self.state, {}, evidence=self.store, registry=FixedRegistry())
        self.rule = {**copy.deepcopy(DEFAULT_RULE), "responseMode": "decision"}
        self.guard.update(self.rule, "/verify/order")

    def check(self, data, *, operation="order-1042", path="/verify/order"):
        return self.guard.verify(data, path, operation_id=operation, caller="portal")

    def records(self):
        with closing(self.store.connect()) as db:
            return db.execute("SELECT * FROM decisions ORDER BY decided_at").fetchall()

    def test_decisions_bind_operation_input_caller_and_rule_version(self):
        data = {"status": "active", "privateValue": "do not store this payload"}
        status, approval = self.check(data)
        self.assertEqual((status, approval["outcome"], approval["valid"]), (200, "allow", True))
        self.assertEqual(approval["operationId"], "order-1042")
        denial = self.check({"status": "inactive"})[1]
        second = self.check(data, operation="order-1043")[1]
        self.assertEqual(denial["reason"], "policy_denied")
        self.assertEqual(approval["ruleVersion"], denial["ruleVersion"])
        records = self.records()
        self.assertEqual([row[0] for row in records], [approval["decisionId"], denial["decisionId"], second["decisionId"]])
        self.assertEqual(records[0][2:6], ("/verify/order", "portal", "order-1042", approval["ruleVersion"]))
        self.assertNotEqual(records[0][6], records[2][6])
        self.assertNotIn("do not store", repr(records))
        reopened = EvidenceStore(self.directory / "audit.db")
        self.assertEqual(reopened.key, self.store.key)
        self.assertEqual(len(self.records()), 3)

    def test_retention_runs_on_the_next_decision(self):
        self.check({"status": "active"})
        with closing(self.store.connect()) as db, db:
            db.execute("UPDATE decisions SET decided_at = '2000-01-01T00:00:00+00:00'")
        self.check({"status": "active"})
        self.assertEqual(len(self.records()), 1)

    def test_invalid_context_and_unavailable_store(self):
        with self.assertRaises(ValueError):
            self.check({"status": "active"}, operation="order with spaces")
        with self.assertRaises(ValueError):
            self.check({"status": "active"}, path="/verify")
        self.assertEqual(self.guard.verify({"status": "active"}, "/verify/order", operation_id="order-1042")[0], 403)
        self.assertEqual(self.records(), [])
        self.store.path = self.directory / "missing-directory" / "audit.db"
        status, body = self.check({"status": "active"})
        self.assertEqual((status, body["code"]), (503, "evidence_unavailable"))
        self.assertNotIn("decisionId", body)

    def test_preview_preserves_connector_scope_and_does_not_record(self):
        document_rule = {**self.rule, "verification": {"profile": "operator-owned"}}
        self.guard.update(document_rule, "/verify/seal")
        with self.assertRaises(PermissionError):
            self.guard.update(self.rule, "/verify/seal", manage_trust=False)
        with self.assertRaises(ValueError):
            self.guard.preview(document_rule, {"outcome": "passed"}, "/verify/order")
        preview = self.guard.preview(document_rule, {"outcome": "passed"}, "/verify/seal")
        self.assertTrue(preview["valid"])
        self.assertEqual(self.records(), [])
        unknown = self.check({"outcome": "indeterminate"}, path="/verify/seal")
        self.assertEqual((unknown[0], unknown[1]["outcome"], unknown[1]["valid"]), (503, "indeterminate", False))
        self.assertIn("fixture-a", self.records()[0][-1])

    def test_scoped_admin_can_edit_policy_but_cannot_downgrade_decision(self):
        changed = copy.deepcopy(self.rule)
        changed["policy"]["permission"][0]["constraint"][0]["rightOperand"] = "reviewed"
        self.guard.update(changed, "/verify/order", manage_trust=False)
        self.assertEqual(self.check({"status": "reviewed"})[1]["outcome"], "allow")
        with self.assertRaises(PermissionError):
            self.guard.update(DEFAULT_RULE, "/verify/order", manage_trust=False)

    def test_existing_public_and_nonprivate_files_are_rejected(self):
        self.store.path.chmod(0o644)
        with self.assertRaises(ValueError):
            EvidenceStore(self.store.path)
        symlink = self.directory / "link.db"
        symlink.symlink_to(self.store.path)
        with self.assertRaises(OSError):
            EvidenceStore(symlink)

    def test_backup_restores_evidence_and_binding_key(self):
        _, decision = self.check({"status": "active"})
        backup = self.directory / "backup.db"
        backup.touch(mode=0o600)
        with closing(self.store.connect()) as source, closing(sqlite3.connect(backup)) as destination:
            source.backup(destination)
        restored = EvidenceStore(backup)
        self.assertEqual(restored.key, self.store.key)
        with closing(restored.connect()) as db:
            self.assertEqual(db.execute("SELECT id FROM decisions").fetchall(), [(decision["decisionId"],)])

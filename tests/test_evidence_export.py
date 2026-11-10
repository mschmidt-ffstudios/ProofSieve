"""Portable evidence uses scoped metadata and a separately pinned signing key."""

import base64
import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from proofsieve.evidence import EvidenceExportError, EvidenceStore, verify_evidence_export


class EvidenceExportTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "evidence.db"
        self.store = EvidenceStore(self.path)
        self.operation = {"caller": "portal", "endpoint": "/verify/order", "operation_id": "order-1042"}
        self.payload = {"name": "Raw customer payload must not be exported", "status": "active"}

    def record(self, **changes):
        values = {
            **self.operation, "data": self.payload, "version": "a" * 64, "outcome": "allow",
            "reason": "policy_allowed", "checks": (),
        }
        return self.store.record(**(values | changes))

    def export(self, **changes):
        return self.store.export(**(self.operation | changes))

    def verify(self, export):
        return verify_evidence_export(export, public_key=self.store.export_public_key)

    def test_exact_scope_decision_selector_and_delivery_link(self):
        original = self.record()
        reservation = self.store.reserve_forwarding(decision_id=original, data=self.payload, **self.operation)
        self.store.finish_forwarding(reservation.id, state="delivered", upstream_status=204)
        repeated = self.record()
        other_scope = [
            self.record(caller="another-portal"),
            self.record(endpoint="/verify/other"),
            self.record(operation_id="other-order"),
        ]
        bundle = self.export()
        self.assertTrue(self.verify(bundle))
        self.assertEqual(bundle["scope"], {"caller": "portal", "endpoint": "/verify/order", "operationId": "order-1042"})
        self.assertEqual([item["decisionId"] for item in bundle["decisions"]], [repeated, original])
        self.assertNotIn("delivery", bundle["decisions"][0])
        delivery = bundle["decisions"][1]["delivery"]
        self.assertEqual((delivery["id"], delivery["state"], delivery["upstreamStatus"]),
                         (reservation.id, "delivered", 204))
        self.assertTrue({"reservedAt", "completedAt"} <= delivery.keys())
        self.assertEqual(self.export(decision_id=original)["decisions"], [bundle["decisions"][1]])
        for decision_id in other_scope:
            with self.subTest(decision_id=decision_id):
                self.assertIsNone(self.export(decision_id=decision_id))
        self.assertIsNone(self.export(decision_id=original, caller="another-portal"))

    def test_exports_only_safe_metadata_and_hmacs_external_report_identifiers(self):
        check = {
            "kind": "dss", "signer": "supplier", "outcome": "passed", "reason": "connector_verdict",
            "item": "supplier-record", "format": "xades-detached",
            "connector": "dss-connector", "connectorProfile": "profile-1", "reportId": "private-UPSTREAM-reference",
            "response": {"token": "private_access_token", "claims": self.payload},
            "certificatePem": "certificate-secret-placeholder",
        }
        first = self.record(checks=[check])
        self.record(checks=[check], data={"status": "blocked"})
        other = self.record(checks=[check], operation_id="order-1043")
        bundle = self.export()
        self.assertTrue(self.verify(bundle))
        fingerprint, original = bundle["decisions"]
        self.assertEqual(original["decisionId"], first)
        self.assertNotEqual(fingerprint["inputFingerprint"], original["inputFingerprint"])
        self.assertEqual(
            original["inputFingerprint"],
            self.store._input_mac(self.operation["endpoint"], self.operation["caller"],
                                  self.operation["operation_id"], self.payload),
        )
        metadata = original["checks"][0]
        self.assertEqual(metadata["connectorProfile"], "profile-1")
        self.assertEqual((metadata["item"], metadata["format"]), ("supplier-record", "xades-detached"))
        self.assertRegex(metadata["reportFingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual(metadata["reportFingerprint"], fingerprint["checks"][0]["reportFingerprint"])
        second_operation = self.export(operation_id="order-1043", decision_id=other)["decisions"][0]
        self.assertNotEqual(metadata["reportFingerprint"], second_operation["checks"][0]["reportFingerprint"])
        self.assertNotEqual(original["inputFingerprint"], second_operation["inputFingerprint"])
        serialized = json.dumps(bundle)
        for private in (self.payload["name"], check["reportId"], "private_access_token",
                        check["certificatePem"], "requestMacKey", "exportEd25519Key"):
            self.assertNotIn(private, serialized)

    def test_rejects_tampering_and_a_replacement_public_key(self):
        self.record()
        bundle = self.export()
        pinned = self.store.export_public_key
        self.assertTrue(verify_evidence_export(json.loads(json.dumps(bundle)), public_key=pinned))
        decoded = base64.urlsafe_b64decode(pinned + "=")
        self.assertEqual(bundle["integrity"]["keyId"], hashlib.sha256(decoded).hexdigest())
        for field, value in (("outcome", "deny"), ("inputFingerprint", "c" * 64)):
            tampered = copy.deepcopy(bundle)
            tampered["decisions"][0][field] = value
            self.assertFalse(self.verify(tampered))
        tampered = copy.deepcopy(bundle)
        tampered["scope"]["operationId"] = "other"
        self.assertFalse(self.verify(tampered))
        tampered = copy.deepcopy(bundle)
        tampered["integrity"]["signature"] += "="
        self.assertFalse(self.verify(tampered))

        substitute = EvidenceStore(self.path.with_name("substitute.db"))
        substitute.record(**self.operation, data=self.payload, version="a" * 64,
                          outcome="deny", reason="policy_denied", checks=())
        forged = substitute.export(**self.operation)
        self.assertTrue(verify_evidence_export(forged, public_key=substitute.export_public_key))
        self.assertFalse(self.verify(forged))
        tampered = copy.deepcopy(bundle)
        tampered["integrity"]["publicKey"] = substitute.export_public_key
        self.assertFalse(self.verify(tampered))

    def test_exports_known_formats_from_current_and_older_checks(self):
        credentials = {
            "sd-jwt": "dc+sd-jwt", "mdoc": "mso_mdoc",
            "jwt-vc": "jwt-vc", "vc-data-integrity": "vc-data-integrity",
        }
        cases = [
            ({"kind": "bundle_item", "format": name}, expected)
            for name, expected in credentials.items()
        ] + [
            ({"kind": name}, expected) for name, expected in credentials.items()
        ] + [
            ({"kind": "signature", "format": name}, name) for name in (
                "dc+sd-jwt", "mso_mdoc", "bundle", "document", "raw", "pades",
                "cades-detached", "xades-detached", "jades-detached", "cbades-detached",
                "asic-s", "asic-e", "rfc3161",
            )
        ] + [
            ({"kind": "sd-jwt", "format": "private-identifier"}, None),
            ({"kind": "mdoc", "format": ["mso_mdoc"]}, None),
            ({"kind": "dss"}, None),
        ]
        for check, expected in cases:
            with self.subTest(check=check):
                decision_id = self.record(checks=[check])
                export = self.export(decision_id=decision_id)
                self.assertTrue(self.verify(export))
                exported = export["decisions"][0]["checks"][0]
                if expected is None:
                    self.assertNotIn("format", exported)
                else:
                    self.assertEqual(exported["format"], expected)

    def test_older_store_migration_and_backup_preserve_independent_keys(self):
        decision_id = self.record()
        original_input_key = self.store.key
        with closing(self.store.connect()) as db, db:
            db.execute("DELETE FROM settings WHERE key = 'exportEd25519Key'")
            db.execute("DROP INDEX decisions_operation")
        migrated = EvidenceStore(self.path)
        self.assertEqual(migrated.key, original_input_key)
        bundle = migrated.export(**self.operation, decision_id=decision_id)
        backup = self.path.with_name("backup.db")
        backup.touch(mode=0o600)
        with closing(migrated.connect()) as source, closing(sqlite3.connect(backup)) as destination:
            source.backup(destination)
        restored = EvidenceStore(backup)
        self.assertEqual(restored.export_public_key, migrated.export_public_key)
        self.assertTrue(verify_evidence_export(bundle, public_key=restored.export_public_key))
        self.assertEqual(restored.export(**self.operation, decision_id=decision_id), bundle)

    def test_retention_and_latest_first_limit(self):
        expired = self.record()
        with closing(self.store.connect()) as db, db:
            db.execute("UPDATE decisions SET decided_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (expired,))
        self.assertIsNone(self.export(decision_id=expired))
        self.assertIsNone(self.export())
        ids = [self.record() for _ in range(33)]
        bundle = self.export()
        self.assertTrue(self.verify(bundle))
        self.assertTrue(bundle["truncated"])
        self.assertEqual([decision["decisionId"] for decision in bundle["decisions"]], ids[:0:-1])
        self.assertFalse(self.export(decision_id=ids[0])["truncated"])

    def test_oversized_or_corrupt_stored_check_data_fails_closed(self):
        decision_id = self.record(checks=[{"unknownPrivatePayload": "x" * (16 * 1024)}])
        with self.assertRaises(EvidenceExportError):
            self.export(decision_id=decision_id)
        with closing(self.store.connect()) as db, db:
            db.execute("UPDATE decisions SET checks = 'null' WHERE id = ?", (decision_id,))
        with self.assertRaises(EvidenceExportError):
            self.export(decision_id=decision_id)

    def test_total_bundle_size_is_bounded(self):
        # All rows fit their own limit but together exceed the portable export limit.
        keys = ("kind", "outcome", "reason", "signer", "connector", "connectorProfile", "adapter", "profileVersion")
        checks = [dict.fromkeys(keys, "q" * 110) for _ in range(16)]
        for _ in range(32):
            decision_id = self.record(checks=checks)
        self.assertTrue(self.verify(self.export(decision_id=decision_id)))
        with self.assertRaises(EvidenceExportError):
            self.export()


if __name__ == "__main__":
    unittest.main()

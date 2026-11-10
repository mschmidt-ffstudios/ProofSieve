"""Forwarding reservations bind a single attempt to a recorded approval."""

import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from proofsieve.evidence import EvidenceStore, ForwardingConflict


class ForwardingEvidenceTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "audit.db"
        self.store = EvidenceStore(self.path)
        self.operation = {
            "endpoint": "/verify/order", "caller": "portal", "operation_id": "order-1042",
            "data": {"status": "active", "privateValue": "payload remains out of evidence"},
        }

    def record(self, *, outcome="allow", **changes):
        return self.store.record(
            **(self.operation | changes), version="rule-version", outcome=outcome,
            reason="policy_allowed" if outcome == "allow" else "policy_denied", checks=(),
        )

    def reserve(self, decision, **changes):
        return self.store.reserve_forwarding(decision_id=decision, **(self.operation | changes))

    def test_requires_matching_approved_decision_and_keeps_payload_private(self):
        denied = self.record(outcome="deny")
        approved = self.record()
        for decision, changes in (
            (denied, {}), ("missing", {}), (approved, {"caller": "other"}),
            (approved, {"endpoint": "/verify/other"}), (approved, {"operation_id": "wrong-order"}),
            (approved, {"data": {"status": "active"}}),
        ):
            with self.subTest(decision=decision, changes=changes), self.assertRaisesRegex(ValueError, "Freigabe"):
                self.reserve(decision, **changes)
        reservation = self.reserve(approved)
        self.assertTrue(reservation.acquired)
        self.assertNotIn(b"payload remains out of evidence", self.path.read_bytes())

    def test_delivery_is_remembered_after_reopen_and_decision_retention(self):
        approved = self.record()
        reservation = self.reserve(approved)
        self.store.finish_forwarding(reservation.id, state="delivered", upstream_status=204)
        with closing(self.store.connect()) as db, db:
            db.execute("UPDATE decisions SET decided_at = '2000-01-01T00:00:00+00:00'")
        self.store = EvidenceStore(self.path)
        newer = self.record()
        repeated = self.reserve(newer)
        self.assertEqual((repeated.id, repeated.state, repeated.upstream_status, repeated.acquired),
                         (reservation.id, "delivered", 204, False))
        with closing(self.store.connect()) as db:
            self.assertEqual(db.execute("SELECT id FROM decisions").fetchall(), [(newer,)])
            self.assertEqual(db.execute("SELECT decision_id FROM forwarding").fetchall(), [(approved,)])

    def test_concurrent_requests_acquire_only_once(self):
        approved = self.record()
        barrier = threading.Barrier(6)

        def reserve_together(_):
            barrier.wait(timeout=5)
            return self.reserve(approved)

        with ThreadPoolExecutor(max_workers=6) as pool:
            reservations = list(pool.map(reserve_together, range(6)))
        self.assertEqual(sum(item.acquired for item in reservations), 1)
        self.assertEqual(len({item.id for item in reservations}), 1)

    def test_reusing_operation_id_with_different_approved_data_conflicts(self):
        first = self.reserve(self.record())
        changed = {"data": {"status": "active", "privateValue": "another payload"}}
        second = self.record(**changed)
        with self.assertRaises(ForwardingConflict):
            self.reserve(second, **changed)
        other = {"caller": "another-portal"}
        independent = self.reserve(self.record(**other), **other)
        self.assertTrue(independent.acquired)
        self.assertNotEqual(first.id, independent.id)

    def test_interrupted_and_failed_attempts_are_never_reacquired(self):
        approved = self.record()
        reservation = self.reserve(approved)
        self.store = EvidenceStore(self.path)
        self.assertEqual(self.reserve(approved).state, "pending")
        self.assertFalse(self.reserve(approved).acquired)
        self.store.finish_forwarding(reservation.id, state="unknown")
        self.assertEqual(self.reserve(approved).state, "unknown")
        self.assertFalse(self.reserve(approved).acquired)
        with self.assertRaisesRegex(ValueError, "nicht offen"):
            self.store.finish_forwarding(reservation.id, state="delivered", upstream_status=200)

        next_operation = {"operation_id": "order-1043"}
        next_decision = self.record(**next_operation)
        next_delivery = self.reserve(next_decision, **next_operation)
        self.store.finish_forwarding(next_delivery.id, state="rejected", upstream_status=503)
        repeated = self.reserve(next_decision, **next_operation)
        self.assertEqual((repeated.state, repeated.upstream_status, repeated.acquired), ("rejected", 503, False))

    def test_capacity_keeps_existing_reservations_and_fails_closed_for_new_ones(self):
        approved = self.record()
        first = self.reserve(approved)
        next_operation = {"operation_id": "order-1043"}
        next_decision = self.record(**next_operation)
        with patch("proofsieve.evidence._MAX_FORWARDING_RESERVATIONS", 1):
            self.assertEqual(self.reserve(approved).id, first.id)
            with self.assertRaisesRegex(OSError, "Kapazitätsgrenze"):
                self.reserve(next_decision, **next_operation)

    def test_existing_version_one_database_can_create_forwarding_journal(self):
        with closing(self.store.connect()) as db, db:
            db.execute("DROP TABLE forwarding")
        approved = self.record()
        self.store = EvidenceStore(self.path)
        self.assertTrue(self.reserve(approved).acquired)


if __name__ == "__main__":
    unittest.main()

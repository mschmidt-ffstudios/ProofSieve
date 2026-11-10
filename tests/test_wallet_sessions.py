"""Wallet session storage fails closed across expiry, retries and concurrency."""

import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from proofsieve.wallet_sessions import SessionCapacity, SessionConflict, SessionQuota, SessionUnavailable, WalletSessions


class WalletSessionTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "wallet.db"
        self.now = 1_000
        self.store = self.open_store()
        self.operation = {"caller": "service-one", "endpoint": "/verify/pid", "operation_id": "order-1042"}
        self.versions = {"rule_version": "a" * 64, "profile_version": "profile-v1"}

    def open_store(self, **options):
        return WalletSessions(
            self.path, clock=lambda: self.now, lifetime_seconds=10, retention_seconds=20, **options
        )

    def create(self, **changes):
        defaults = dict(self.operation, adapter="eudi", format="dc+sd-jwt", **self.versions)
        return self.store.create(**(defaults | changes))

    def claim(self, session, **changes):
        binding = {
            "caller": session.caller, "endpoint": session.endpoint, "operation_id": session.operation_id,
            "transaction_id": session.transaction_id, **self.versions,
        }
        return self.store.claim(session.id, **(binding | changes))

    def test_exact_caller_endpoint_operation_and_config_binding(self):
        created = self.create()
        self.assertEqual((created.state, created.created_at, created.expires_at), ("creating", 1_000, 1_010))
        self.assertEqual(len(created.nonce), 43)
        bound = self.store.bind(created.id, transaction_id="_tx-123")
        self.assertEqual(self.store.get(created.id, **self.operation), bound)
        for change in (
            {"caller": "another-service"}, {"endpoint": "/verify/other"}, {"operation_id": "another-order"},
        ):
            with self.subTest(change=change), self.assertRaises(SessionUnavailable):
                self.claim(bound, **change)
        for change in (
            {"transaction_id": "other-tx"}, {"rule_version": "b" * 64}, {"profile_version": "profile-v2"},
        ):
            with self.subTest(change=change), self.assertRaises(SessionConflict):
                self.claim(bound, **change)
        claimed = self.claim(bound)
        self.assertEqual((claimed.state, claimed.nonce), ("claimed", bound.nonce))
        self.store.finish(created.id, state="consumed")
        self.assertEqual(self.store.get(created.id, **self.operation).state, "consumed")
        with self.assertRaises(SessionConflict):
            self.claim(bound)

    def test_atomic_operation_creation_and_single_claim(self):
        start = threading.Barrier(6)

        def create_race():
            start.wait(timeout=5)
            try:
                return self.create()
            except SessionConflict:
                return None

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(create_race) for _ in range(6)]
            created = [future.result() for future in futures]
        winners = [item for item in created if item is not None]
        self.assertEqual(len(winners), 1)
        bound = self.store.bind(winners[0].id, transaction_id="transaction")
        start = threading.Barrier(6)

        def claim_race():
            start.wait(timeout=5)
            try:
                return self.claim(bound)
            except SessionConflict:
                return None

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(claim_race) for _ in range(6)]
            claimed = [future.result() for future in futures]
        self.assertEqual(sum(item is not None for item in claimed), 1)
        self.store = self.open_store()
        with self.assertRaises(SessionConflict):
            self.claim(bound)

    def test_upstream_transaction_cannot_be_reused_on_adapter(self):
        first = self.store.bind(self.create().id, transaction_id="upstream-1")
        self.claim(first)
        self.store.finish(first.id, state="failed")
        self.store = self.open_store()
        next_session = self.create(operation_id="order-1043")
        with self.assertRaises(SessionConflict):
            self.store.bind(next_session.id, transaction_id="upstream-1")
        next_bound = self.store.bind(next_session.id, transaction_id="upstream-2")
        self.assertEqual(self.claim(next_bound).state, "claimed")

        other = self.create(adapter="other-eudi", operation_id="order-1044", format="mso_mdoc")
        other_bound = self.store.bind(other.id, transaction_id="upstream-1")
        self.assertEqual(self.claim(other_bound).state, "claimed")

    def test_expiry_prevents_consumption_and_retention_preserves_replay_state(self):
        bound = self.store.bind(self.create().id, transaction_id="upstream")
        self.claim(bound)
        self.now = 1_010
        with self.assertRaises(SessionUnavailable):
            self.store.get(bound.id, **self.operation)
        with self.assertRaises(SessionConflict):
            self.store.finish(bound.id, state="consumed")
        self.store.finish(bound.id, state="failed")
        self.store = self.open_store()
        self.now = 1_029
        with self.assertRaises(SessionConflict):
            self.create()
        self.now = 1_030
        second = self.create()
        self.assertNotEqual((second.id, second.nonce), (bound.id, bound.nonce))

    def test_capacity_does_not_evict_unexpired_sessions(self):
        self.store = self.open_store(max_sessions=1)
        first = self.create()
        with self.assertRaises(SessionCapacity):
            self.create(operation_id="other-order")
        self.assertEqual(self.store.get(first.id, **self.operation), first)
        self.store.finish(first.id, state="failed")
        with self.assertRaises(SessionCapacity):
            self.create(operation_id="other-order")
        self.now = 1_030
        self.assertEqual(self.create(operation_id="other-order").state, "creating")

    def test_simultaneous_starts_share_caller_quota_across_endpoints(self):
        self.store = self.open_store(max_recent_per_caller=2, max_retained_per_caller=5)
        start = threading.Barrier(6)

        def create_race(index):
            start.wait(timeout=5)
            try:
                self.create(endpoint=f"/verify/pid-{index}")
                return None
            except SessionQuota as exc:
                return exc.retry_after

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(create_race, range(6)))
        self.assertEqual(results.count(None), 2)
        self.assertEqual(results.count(10), 4)
        self.assertEqual(self.create(caller="another-service").state, "creating")

    def test_rejects_unrelated_database_and_unprivate_storage(self):
        unrelated = self.path.with_name("unrelated.db")
        unrelated.touch(mode=0o600)
        with closing(sqlite3.connect(unrelated)) as db, db:
            db.execute("CREATE TABLE foreign_data (value TEXT)")
        with self.assertRaisesRegex(ValueError, "not a wallet session journal"):
            WalletSessions(unrelated)

        symlink = self.path.with_name("symlink.db")
        symlink.symlink_to(self.path)
        with self.assertRaises(OSError):
            WalletSessions(symlink)
        hardlink = self.path.with_name("hardlink.db")
        os.link(self.path, hardlink)
        with self.assertRaisesRegex(ValueError, "private regular file"):
            WalletSessions(hardlink)
        hardlink.unlink()
        self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private regular file"):
            self.open_store()


if __name__ == "__main__":
    unittest.main()

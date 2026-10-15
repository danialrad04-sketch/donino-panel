import tempfile
import unittest
from pathlib import Path

from agent.journal import UsageJournal


class JournalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "usage.db"
        self.journal = UsageJournal(self.path)
        self.journal.bind("https://panel.example.com", "node-id")

    def tearDown(self):
        self.tmp.cleanup()

    def test_snapshot_survives_restart_and_partial_ack_does_not_erase_new_bytes(self):
        first = [{"user_id": "u", "up": 100, "down": 200}]
        self.journal.record("epoch-1", first)
        reopened = UsageJournal(self.path)
        self.assertEqual(reopened.pending(), ("epoch-1", first))
        reopened.record("epoch-1", [{"user_id": "u", "up": 120, "down": 300}])
        reopened.acknowledge("epoch-1", first)
        self.assertEqual(reopened.pending()[1][0]["down"], 300)
        epoch, pending = reopened.pending()
        reopened.acknowledge(epoch, pending)
        self.assertIsNone(reopened.pending())

    def test_lower_or_duplicate_counters_cannot_rebill(self):
        sample = [{"user_id": "u", "up": 100, "down": 200}]
        self.journal.record("e", sample)
        self.journal.acknowledge("e", sample)
        self.journal.record("e", [{"user_id": "u", "up": 10, "down": 20}])
        self.assertEqual(self.journal.count(), 0)

    def test_state_cannot_be_reused_for_different_node_or_panel(self):
        for panel, node in [
            ("https://other.example.com", "node-id"),
            ("https://panel.example.com", "other-node"),
        ]:
            with self.assertRaises(ValueError):
                self.journal.bind(panel, node)

    def test_retired_epoch_is_pruned_only_after_ack(self):
        rows = [{"user_id": "u", "up": 1, "down": 2}]
        self.journal.record("old", rows)
        self.journal.prune("new")
        self.assertEqual(self.journal.count(), 1)
        self.journal.acknowledge("old", rows)
        self.journal.prune("new")
        self.assertIsNone(self.journal.pending())

    def test_large_snapshot_is_split_into_bounded_batches(self):
        self.journal.record(
            "e", [{"user_id": f"u-{i:04}", "up": 1, "down": 2} for i in range(1100)]
        )
        sizes = []
        while pending := self.journal.pending():
            epoch, rows = pending
            sizes.append(len(rows))
            self.journal.acknowledge(epoch, rows)
        self.assertEqual(sizes, [500, 500, 100])

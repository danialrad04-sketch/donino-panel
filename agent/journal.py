"""Durable high-water usage queue. HTTP acknowledgements never precede disk writes."""

import os
import sqlite3
from contextlib import contextmanager


class UsageJournal:
    def __init__(self, path):
        self.path = path
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS identity (binding TEXT PRIMARY KEY)")
            db.execute("""CREATE TABLE IF NOT EXISTS samples (
                epoch TEXT NOT NULL, user_id TEXT NOT NULL,
                up INTEGER NOT NULL, down INTEGER NOT NULL,
                ack_up INTEGER NOT NULL DEFAULT 0, ack_down INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(epoch,user_id))""")
            if "period_no" not in {
                row[1] for row in db.execute("PRAGMA table_info(samples)")
            }:
                db.execute("ALTER TABLE samples ADD COLUMN period_no INTEGER")
            if "lease_id" not in {
                row[1] for row in db.execute("PRAGMA table_info(samples)")
            }:
                db.execute("ALTER TABLE samples ADD COLUMN lease_id TEXT")
            db.execute(
                "CREATE TABLE IF NOT EXISTS lease_totals(lease_id TEXT PRIMARY KEY,up INTEGER NOT NULL,down INTEGER NOT NULL)"
            )

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        os.chmod(self.path, 0o600)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        try:
            with db:
                yield db
        finally:
            db.close()

    def bind(self, panel, node_id):
        binding = panel + "|" + node_id
        with self.connect() as db:
            old = db.execute("SELECT binding FROM identity").fetchone()
            if old and old["binding"] != binding:
                raise ValueError(
                    "Node state belongs to another panel or node; use a separate state directory"
                )
            db.execute("INSERT OR IGNORE INTO identity VALUES(?)", (binding,))

    def record(self, epoch, samples):
        with self.connect() as db:
            for sample in samples:
                old = db.execute(
                    "SELECT period_no,lease_id,up,down FROM samples WHERE epoch=? AND user_id=?",
                    (epoch, sample["user_id"]),
                ).fetchone()
                if old and old["period_no"] != sample.get("period_no"):
                    raise ValueError("A journal epoch cannot change period generation")
                if old and old["lease_id"] != sample.get("lease_id"):
                    raise ValueError("A journal epoch cannot change budget lease")
                if sample.get("lease_id"):
                    up = max(sample["up"], old["up"] if old else 0) - (
                        old["up"] if old else 0
                    )
                    down = max(sample["down"], old["down"] if old else 0) - (
                        old["down"] if old else 0
                    )
                    db.execute(
                        "INSERT INTO lease_totals VALUES(?,?,?) ON CONFLICT(lease_id) DO UPDATE SET up=up+excluded.up,down=down+excluded.down",
                        (sample["lease_id"], up, down),
                    )
                db.execute(
                    """INSERT INTO samples(epoch,user_id,up,down,period_no,lease_id) VALUES(?,?,?,?,?,?)
                    ON CONFLICT(epoch,user_id) DO UPDATE SET up=MAX(up,excluded.up),down=MAX(down,excluded.down)""",
                    (
                        epoch,
                        sample["user_id"],
                        sample["up"],
                        sample["down"],
                        sample.get("period_no"),
                        sample.get("lease_id"),
                    ),
                )

    def pending(self):
        with self.connect() as db:
            epoch = db.execute(
                "SELECT epoch FROM samples WHERE up>ack_up OR down>ack_down ORDER BY epoch LIMIT 1"
            ).fetchone()
            if not epoch:
                return None
            rows = db.execute(
                """SELECT user_id,up,down,period_no,lease_id FROM samples WHERE epoch=?
                AND (up>ack_up OR down>ack_down) ORDER BY user_id LIMIT 500""",
                (epoch["epoch"],),
            ).fetchall()
            return epoch["epoch"], [
                {k: v for k, v in dict(r).items() if v is not None} for r in rows
            ]

    def acknowledge(self, epoch, samples):
        with self.connect() as db:
            for sample in samples:
                db.execute(
                    """UPDATE samples SET ack_up=MAX(ack_up,?),ack_down=MAX(ack_down,?)
                    WHERE epoch=? AND user_id=?""",
                    (sample["up"], sample["down"], epoch, sample["user_id"]),
                )

    def count(self):
        with self.connect() as db:
            return db.execute(
                "SELECT COUNT(*) FROM samples WHERE up>ack_up OR down>ack_down"
            ).fetchone()[0]

    def prune(self, current_epoch):
        with self.connect() as db:
            db.execute(
                "DELETE FROM samples WHERE epoch<>? AND up=ack_up AND down=ack_down",
                (current_epoch,),
            )

    def budget_spent(self):
        with self.connect() as db:
            return {
                row["lease_id"]: row["up"] + row["down"]
                for row in db.execute("SELECT * FROM lease_totals")
            }

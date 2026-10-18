"""Inspect or reversibly stage doctor-dns data; source code is never executed."""

import argparse
import json
import sqlite3
import uuid
from pathlib import Path

from app.db import initialize, IntegrityErrors
from app.doctor_import import inspect_source, stage, rollback
from app.gaming_catalog import SOURCE_REVISION


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "apply"):
        command = sub.add_parser(name)
        command.add_argument("source", type=Path)
        command.add_argument("--revision", default=SOURCE_REVISION)
        command.add_argument(
            "--source-instance", type=uuid.UUID, required=name == "apply"
        )
        if name == "apply":
            command.add_argument("--expected", required=True)
            command.add_argument("--backup", type=Path, required=True)
    command = sub.add_parser("rollback")
    command.add_argument("import_id", type=uuid.UUID)
    command.add_argument("--backup", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "rollback":
            initialize()
            value = rollback(str(args.import_id), args.backup)
        else:
            snapshot = inspect_source(args.source, revision=args.revision)
            instance = str(args.source_instance or uuid.uuid4())
            if args.command == "inspect":
                value = {
                    "source_instance": instance,
                    "source_revision": args.revision,
                    "fingerprint": snapshot["fingerprint"],
                    "summary": snapshot["summary"],
                }
            else:
                value = stage(snapshot, instance, args.expected, args.backup)
        print(json.dumps(value, ensure_ascii=False, indent=2))
    except IntegrityErrors:
        parser.exit(
            2,
            "Doctor import refused: database identity conflict; no partial import was committed.\n",
        )
    except sqlite3.DatabaseError:
        parser.exit(2, "Doctor import refused: invalid or unsupported SQLite source.\n")
    except (ValueError, OSError, RuntimeError, KeyError, TypeError) as error:
        # Validation errors identify fields, never password hashes or receipts.
        parser.exit(2, f"Doctor import refused: {error}\n")


if __name__ == "__main__":
    main()

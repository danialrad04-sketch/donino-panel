import argparse
import getpass
from pathlib import Path
from .db import initialize, database, hash_password, audit, SCHEMA_VERSION
from . import __version__
from . import ops


def main():
    parser = argparse.ArgumentParser(description="Donino Panel administration")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate", help="Back up and migrate an older supported database")
    create = sub.add_parser(
        "admin", help="Create/update an admin and invalidate their sessions"
    )
    create.add_argument("username")
    create.add_argument(
        "--role", choices=["owner", "operator", "viewer"], default="owner"
    )
    backup = sub.add_parser(
        "backup", help="Create a consistent SQLite backup with a SHA-256 manifest"
    )
    backup.add_argument("destination", type=Path)
    sub.add_parser("doctor", help="Read-only health check; exit 1 on failures")
    restore = sub.add_parser(
        "restore", help="Restore a verified backup (stop the panel first)"
    )
    restore.add_argument("source", type=Path)
    restore.add_argument(
        "--replace",
        action="store_true",
        help="Overwrite the current database; a safety copy is kept first",
    )
    args = parser.parse_args()
    if args.command == "doctor":
        rows, code = ops.doctor()
        for level, name, detail in rows:
            print(f"{level:4} {name}: {detail}")
        raise SystemExit(code)
    if args.command == "restore":
        try:
            result = ops.restore(args.source, replace=args.replace)
        except (FileNotFoundError, FileExistsError, ValueError, RuntimeError) as error:
            parser.exit(2, f"restore refused: {error}\n")
        print(f"Restored schema {result['schema_version']} from {result['restored_from']}.")
        if result["safety_copy"]:
            print(f"Previous database kept at {result['safety_copy']}.")
        return
    if args.command == "backup":
        try:
            manifest = ops.backup(args.destination)
        except (FileExistsError, FileNotFoundError, RuntimeError) as error:
            parser.exit(2, f"backup refused: {error}\n")
        print(f"Backup saved. sha256={manifest['sha256']} schema={manifest['schema_version']}")
        return
    initialize()
    if args.command == "migrate":
        print(
            f"Database ready at schema {SCHEMA_VERSION}. Older databases were backed up before migration."
        )
        return
    if args.command == "admin":
        if not 1 <= len(args.username) <= 64:
            parser.error("Username must be 1–64 characters")
        password = getpass.getpass("New password (at least 12 characters): ")
        if len(password) < 12 or len(password) > 256:
            parser.error("Password must be 12–256 characters")
        if password != getpass.getpass("Confirm password: "):
            parser.error("Passwords do not match")
        with database() as db:
            owners = db.execute(
                "SELECT COUNT(*) FROM admins WHERE role='owner' AND username<>?",
                (args.username,),
            ).fetchone()[0]
            if args.role != "owner" and not owners:
                parser.error("At least one owner is required")
            db.execute(
                "INSERT INTO admins VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET password=excluded.password,role=excluded.role",
                (args.username, hash_password(password), args.role),
            )
            db.execute("DELETE FROM sessions WHERE username=?", (args.username,))
            audit(db, "local-cli", "admin.upsert", args.username)
        print("Admin saved; previous sessions revoked.")
    else:
        parser.error("unknown command")


if __name__ == "__main__":
    main()

import argparse
import getpass
from pathlib import Path

from . import __version__
from .db import SCHEMA_VERSION, audit, database, hash_password, initialize


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
    backup = sub.add_parser("backup", help="Create a consistent SQLite backup")
    backup.add_argument("destination", type=Path)
    move = sub.add_parser(
        "import-sqlite",
        help="Copy a supported SQLite database into an empty destination",
    )
    move.add_argument("source", type=Path)
    restore = sub.add_parser(
        "restore-archive",
        help="Restore a Donino PostgreSQL archive into an empty destination",
    )
    restore.add_argument("source", type=Path)
    args = parser.parse_args()
    initialize()
    if args.command == "migrate":
        print(
            f"Database ready at schema {SCHEMA_VERSION}. Older databases were backed up before migration."
        )
        return
    if args.command == "import-sqlite":
        from .storage import import_sqlite

        import_sqlite(args.source)
        print("Database imported. Preserve the source master.key when migrating MFA.")
        return
    if args.command == "restore-archive":
        from .storage import restore_archive

        restore_archive(args.source)
        print(
            "Database restored. Restore the matching master.key before serving MFA logins."
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
            db.execute("DELETE FROM api_tokens WHERE username=?", (args.username,))
            audit(db, "local-cli", "admin.upsert", args.username)
        print("Admin saved; previous sessions revoked.")
    else:
        from .storage import backup_database

        backup_database(args.destination)
        print(
            "Backup saved with private permissions. Also preserve the matching master.key."
        )


if __name__ == "__main__":
    main()

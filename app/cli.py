import argparse
import getpass
import sqlite3
from pathlib import Path
from .db import initialize, database, hash_password, audit, db_path


def main():
    parser = argparse.ArgumentParser(description='Donino Panel administration')
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('admin', help='Create/update an admin and invalidate their sessions')
    create.add_argument('username')
    create.add_argument('--role', choices=['owner', 'operator', 'viewer'], default='owner')
    backup = sub.add_parser('backup', help='Create a consistent SQLite backup')
    backup.add_argument('destination', type=Path)
    args = parser.parse_args()
    initialize()
    if args.command == 'admin':
        if not 1 <= len(args.username) <= 64:
            parser.error('Username must be 1–64 characters')
        password = getpass.getpass('New password (at least 12 characters): ')
        if len(password) < 12 or len(password) > 256:
            parser.error('Password must be 12–256 characters')
        if password != getpass.getpass('Confirm password: '):
            parser.error('Passwords do not match')
        with database() as db:
            owners = db.execute("SELECT COUNT(*) FROM admins WHERE role='owner' AND username<>?", (args.username,)).fetchone()[0]
            if args.role != 'owner' and not owners:
                parser.error('At least one owner is required')
            db.execute('INSERT INTO admins VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET password=excluded.password,role=excluded.role',
                       (args.username, hash_password(password), args.role))
            db.execute('DELETE FROM sessions WHERE username=?', (args.username,))
            audit(db, 'local-cli', 'admin.upsert', args.username)
        print('Admin saved; previous sessions revoked.')
    else:
        if args.destination.exists():
            parser.error('Destination already exists')
        args.destination.parent.mkdir(parents=True, exist_ok=True)
        import os
        fd = os.open(args.destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        source, target = sqlite3.connect(db_path()), sqlite3.connect(args.destination)
        try:
            source.backup(target)
        finally:
            source.close()
            target.close()
        print('Backup saved.')


if __name__ == '__main__':
    main()

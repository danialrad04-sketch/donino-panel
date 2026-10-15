"""Portable baseline, device credentials and security foundation."""

import time
import uuid

import sqlalchemy as sa
from alembic import op

from app.schema_v1 import metadata

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    metadata.create_all(connection, checkfirst=True)
    for table in metadata.tables.values():
        for index in table.indexes:
            index.create(connection, checkfirst=True)
    # Preserve legacy UUID, secret, subscription, user IDs and counter baselines.
    for user in connection.execute(sa.text("SELECT * FROM users")).mappings():
        uid, period = user["id"], str(uuid.uuid4())
        connection.execute(
            sa.text(
                "INSERT INTO devices(id,user_id,name,created,legacy) VALUES(:u,:u,'Primary',:t,1)"
            ),
            {"u": uid, "t": user["created"]},
        )
        for protocol in ("vless", "vmess", "trojan"):
            connection.execute(
                sa.text(
                    "INSERT INTO credentials(id,device_id,protocol,secret) VALUES(:id,:u,:p,:s)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "u": uid,
                    "p": protocol,
                    "s": user["credential"],
                },
            )
        connection.execute(
            sa.text(
                "INSERT INTO user_periods(id,user_id,started,uploaded,downloaded,legacy_used,reason) VALUES(:p,:u,:t,:up,:down,:legacy,'migration')"
            ),
            {
                "p": period,
                "u": uid,
                "t": int(time.time()),
                "up": user["uploaded"],
                "down": user["downloaded"],
                "legacy": user["legacy_used"],
            },
        )
        connection.execute(
            sa.text("INSERT INTO user_state(user_id,period_id) VALUES(:u,:p)"),
            {"u": uid, "p": period},
        )


def downgrade():
    raise RuntimeError(
        "Restore the matching pre-upgrade backup; destructive downgrade is unsupported"
    )

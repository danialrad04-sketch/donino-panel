"""Frozen schema for Alembic 0001. Do not change after publication."""

import sqlalchemy as sa

metadata = sa.MetaData()
T = sa.Text
I = sa.BigInteger


def col(name, kind=T, **kwargs):
    return sa.Column(name, kind, **kwargs)


def number(name, default="0", **kwargs):
    return col(name, I, nullable=False, server_default=default, **kwargs)


admins = sa.Table(
    "admins",
    metadata,
    col("username", primary_key=True),
    col("password", nullable=False),
    col("role", nullable=False),
)
sessions = sa.Table(
    "sessions",
    metadata,
    col("token", primary_key=True),
    sa.Column(
        "username",
        T,
        sa.ForeignKey("admins.username", ondelete="CASCADE"),
        nullable=False,
    ),
    col("expires", I, nullable=False),
)
login_attempts = sa.Table(
    "login_attempts",
    metadata,
    col("address", primary_key=True),
    number("attempts"),
    number("until"),
)
users = sa.Table(
    "users",
    metadata,
    col("id", primary_key=True),
    col("credential", nullable=False),
    col("name", unique=True, nullable=False),
    number("enabled", "1"),
    number("quota"),
    number("used"),
    col("expires", I),
    col("token", unique=True, nullable=False),
    number("created"),
    number("uploaded"),
    number("downloaded"),
    number("legacy_used"),
)
nodes = sa.Table(
    "nodes",
    metadata,
    col("id", primary_key=True),
    col("name", nullable=False),
    col("host", nullable=False),
    col("token", unique=True, nullable=False),
    number("enabled", "1"),
    col("last_seen", I),
    col("applied_revision"),
    col("error"),
    col("agent_version", nullable=False, server_default=""),
    col("apply_mode", nullable=False, server_default=""),
    col("core_running", I),
    number("pending_usage"),
)
inbounds = sa.Table(
    "inbounds",
    metadata,
    col("id", primary_key=True),
    sa.Column(
        "node_id", T, sa.ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False
    ),
    col("name", nullable=False),
    col("protocol", nullable=False),
    col("port", sa.Integer, nullable=False),
    col("settings", nullable=False),
    number("enabled", "1"),
    sa.UniqueConstraint("node_id", "port"),
)
counters = sa.Table(
    "counters",
    metadata,
    sa.Column(
        "node_id", T, sa.ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    ),
    col("epoch", primary_key=True),
    sa.Column(
        "user_id", T, sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    ),
    number("up"),
    number("down"),
)
audit = sa.Table(
    "audit",
    metadata,
    col("id", sa.Integer, primary_key=True, autoincrement=True),
    number("at"),
    col("actor", nullable=False),
    col("action", nullable=False),
    col("target", nullable=False),
)

devices = sa.Table(
    "devices",
    metadata,
    col("id", primary_key=True),
    sa.Column(
        "user_id", T, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    ),
    col("name", nullable=False),
    number("enabled", "1"),
    col("expires", I),
    number("created"),
    number("legacy"),
    sa.UniqueConstraint("user_id", "name"),
)
credentials = sa.Table(
    "credentials",
    metadata,
    col("id", primary_key=True),
    sa.Column(
        "device_id", T, sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    ),
    col("protocol", nullable=False),
    col("secret", nullable=False),
    number("generation", "1"),
    sa.UniqueConstraint("device_id", "protocol"),
)
device_counters = sa.Table(
    "device_counters",
    metadata,
    sa.Column(
        "node_id", T, sa.ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    ),
    col("epoch", primary_key=True),
    sa.Column(
        "device_id",
        T,
        sa.ForeignKey("devices.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    col("period_id", primary_key=True),
    number("up"),
    number("down"),
)
user_periods = sa.Table(
    "user_periods",
    metadata,
    col("id", primary_key=True),
    sa.Column(
        "user_id", T, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    ),
    number("started"),
    col("ended", I),
    number("uploaded"),
    number("downloaded"),
    number("legacy_used"),
    col("reason", nullable=False),
)
user_state = sa.Table(
    "user_state",
    metadata,
    sa.Column(
        "user_id", T, sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    ),
    sa.Column("period_id", T, sa.ForeignKey("user_periods.id"), nullable=False),
    number("validity_seconds"),
    col("first_used", I),
    col("owner_username", T),
)
node_policy = sa.Table(
    "node_policy",
    metadata,
    sa.Column(
        "node_id", T, sa.ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    ),
    col("mode", nullable=False, server_default="all"),
)
user_nodes = sa.Table(
    "user_nodes",
    metadata,
    sa.Column(
        "node_id", T, sa.ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    ),
    sa.Column(
        "user_id", T, sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    ),
)
mfa = sa.Table(
    "admin_mfa",
    metadata,
    sa.Column(
        "username",
        T,
        sa.ForeignKey("admins.username", ondelete="CASCADE"),
        primary_key=True,
    ),
    col("secret", nullable=False),
    number("enabled"),
    number("last_step", "-1"),
)
recovery_codes = sa.Table(
    "recovery_codes",
    metadata,
    col("digest", primary_key=True),
    sa.Column(
        "username",
        T,
        sa.ForeignKey("admins.username", ondelete="CASCADE"),
        nullable=False,
    ),
)
api_tokens = sa.Table(
    "api_tokens",
    metadata,
    col("id", primary_key=True),
    col("digest", unique=True, nullable=False),
    sa.Column(
        "username",
        T,
        sa.ForeignKey("admins.username", ondelete="CASCADE"),
        nullable=False,
    ),
    col("name", nullable=False),
    col("scopes", nullable=False),
    col("expires", I, nullable=False),
    number("created"),
    col("last_used", I),
)

sa.Index("ix_users_created_id", users.c.created, users.c.id)
sa.Index("ix_devices_user", devices.c.user_id)
sa.Index("ix_periods_user_start", user_periods.c.user_id, user_periods.c.started)
sa.Index("ix_sessions_expiry", sessions.c.expires)
sa.Index("ix_audit_at", audit.c.at)

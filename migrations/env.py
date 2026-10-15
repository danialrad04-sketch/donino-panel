from alembic import context

from app.models import metadata

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("Run migrations through python -m app.cli migrate")
context.configure(
    connection=connection, target_metadata=metadata, transactional_ddl=True
)
with context.begin_transaction():
    context.run_migrations()

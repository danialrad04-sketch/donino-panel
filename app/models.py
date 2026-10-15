"""Current portable schema, cloned from the immutable migration baseline."""

import sqlalchemy as sa

from .schema_v1 import metadata as baseline

metadata = sa.MetaData()
for table in baseline.sorted_tables:
    table.to_metadata(metadata)

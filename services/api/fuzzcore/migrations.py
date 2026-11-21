"""Small, explicit forward-only MVP migration ledger. No destructive upgrades."""
from sqlalchemy import text, inspect


def upgrade(engine, metadata, active_index):
    # Version 1 adopts the earlier prototype tables without deleting records.
    # Version 2 adds the partial active-run index and durable outbox table.
    with engine.begin() as connection:
        connection.execute(text('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)'))
        version = connection.execute(text('SELECT COALESCE(MAX(version), 0) FROM schema_migrations')).scalar_one()
        if version > 3:
            raise RuntimeError('Database schema is newer than this application')
        if version < 1:
            metadata.create_all(connection)
            connection.execute(text('INSERT INTO schema_migrations (version) VALUES (1)'))
        if version < 2:
            metadata.create_all(connection)
            # Existing conflicting active rows cause a visible migration failure;
            # never discard records or silently choose a run to cancel.
            active_index.create(connection, checkfirst=True)
            connection.execute(text('INSERT INTO schema_migrations (version) VALUES (2)'))

        if version < 3:
            columns = {column['name'] for column in inspect(connection).get_columns('scans')}
            additions = {
                'target_id': "VARCHAR NOT NULL DEFAULT 'local-lab'",
                'scope_version': "VARCHAR NOT NULL DEFAULT 'lab-v1'",
                'authorization_confirmed_at': 'VARCHAR',
            }
            for name, definition in additions.items():
                if name not in columns:
                    connection.execute(text(f'ALTER TABLE scans ADD COLUMN {name} {definition}'))
            connection.execute(text('INSERT INTO schema_migrations (version) VALUES (3)'))

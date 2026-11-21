"""Small, explicit forward-only MVP migration ledger. No destructive upgrades."""
from sqlalchemy import text, inspect


def upgrade(engine, metadata, active_index):
    # Version 1 adopts the earlier prototype tables without deleting records.
    # Version 2 adds the partial active-run index and durable outbox table.
    with engine.begin() as connection:
        connection.execute(text('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)'))
        version = connection.execute(text('SELECT COALESCE(MAX(version), 0) FROM schema_migrations')).scalar_one()
        if version > 7:
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

        if version < 4:
            # Old records have no per-scan authorization evidence. Preserve
            # history but never turn unknown consent into executable work.
            connection.execute(text("UPDATE scans SET status='interrupted', "
                "error='authorization_confirmation_required' "
                "WHERE status='queued' AND authorization_confirmed_at IS NULL"))
            connection.execute(text("INSERT INTO enqueue_intents (scan_id, attempts, sent_at) "
                "SELECT s.id, 0, NULL FROM scans s "
                "WHERE s.status='queued' AND s.authorization_confirmed_at IS NOT NULL "
                "AND NOT EXISTS (SELECT 1 FROM enqueue_intents e WHERE e.scan_id=s.id)"))
            connection.execute(text('INSERT INTO schema_migrations (version) VALUES (4)'))

        if version < 5:
            scan_columns = {c['name'] for c in inspect(connection).get_columns('scans')}
            if 'selected_modules' not in scan_columns:
                connection.execute(text("ALTER TABLE scans ADD COLUMN selected_modules VARCHAR NOT NULL DEFAULT 'directories'"))
            finding_columns = {c['name'] for c in inspect(connection).get_columns('findings')}
            for name, definition in {'module':"VARCHAR NOT NULL DEFAULT 'directories'", 'evidence':"TEXT NOT NULL DEFAULT '{}'"}.items():
                if name not in finding_columns:
                    connection.execute(text(f'ALTER TABLE findings ADD COLUMN {name} {definition}'))
            connection.execute(text('INSERT INTO schema_migrations (version) VALUES (5)'))

        if version < 6:
            columns = {c['name'] for c in inspect(connection).get_columns('findings')}
            for name, default in {'severity':'informational','confidence':'observed'}.items():
                if name not in columns:
                    connection.execute(text(f"ALTER TABLE findings ADD COLUMN {name} VARCHAR NOT NULL DEFAULT '{default}'"))
            connection.execute(text('INSERT INTO schema_migrations (version) VALUES (6)'))

        if version < 7:
            columns={c['name'] for c in inspect(connection).get_columns('scans')}
            for name,definition in {'custom_cases':"TEXT NOT NULL DEFAULT '[]'",'case_version':'VARCHAR'}.items():
                if name not in columns:
                    connection.execute(text(f'ALTER TABLE scans ADD COLUMN {name} {definition}'))
            connection.execute(text('INSERT INTO schema_migrations (version) VALUES (7)'))

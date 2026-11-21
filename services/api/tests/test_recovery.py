import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from fuzzcore.api import create_app
from fuzzcore.core import Scan, database

TOKEN = 'test-recovery-only-not-real-12345678'


def test_failed_enqueue_survives_and_same_request_can_retry(tmp_path):
    sessions = database('sqlite:///' + str(tmp_path/'outbox.db'))
    deliveries = []
    available = [False]
    def enqueue(scan_id):
        if not available[0]:
            raise ConnectionError('private queue detail must not leak')
        deliveries.append(scan_id)
    c = TestClient(create_app(sessions, enqueue, TOKEN), headers={'Authorization':'Bearer '+TOKEN})
    def start():
        return c.post('/v1/scans', headers={'Idempotency-Key':'recovery-case-001'},
                      json={'target_id':'local-lab','authorization_confirmed':True})
    first = start()
    assert first.status_code == 503
    assert 'private queue' not in first.text
    with sessions() as db:
        row = db.scalar(select(Scan))
        assert row.status == 'queued'
        scan_id = row.id
    available[0] = True
    retried = start()
    assert retried.status_code == 202 and retried.json()['id'] == scan_id
    assert deliveries == [scan_id]
    assert start().status_code == 202
    assert deliveries == [scan_id]


def test_database_records_applied_schema_version(tmp_path):
    from sqlalchemy import text
    sessions = database('sqlite:///' + str(tmp_path/'schema.db'))
    with sessions() as db:
        assert db.execute(text('SELECT max(version) FROM schema_migrations')).scalar_one() >= 2


def test_stale_recovery_requires_stopped_worker_and_preserves_recent_runs(tmp_path):
    from fuzzcore.recovery import recover_stale
    sessions = database('sqlite:///' + str(tmp_path/'stale.db'))
    with sessions() as db:
        db.add_all([
            Scan(id='stale',owner='a',request_key='stale-001',status='running',updated_at='2026-01-01T00:00:00+00:00'),
            Scan(id='recent',owner='b',request_key='recent-001',status='running',updated_at='2026-11-21T06:00:00+00:00'),
        ]); db.commit()
    with pytest.raises(ValueError):
        recover_stale(sessions, '2026-11-21T05:00:00+00:00', worker_stopped=False)
    assert recover_stale(sessions, '2026-11-21T05:00:00+00:00', worker_stopped=True) == 1
    with sessions() as db:
        assert db.get(Scan,'stale').status == 'interrupted'
        assert db.get(Scan,'recent').status == 'running'


def test_legacy_schema_upgrade_preserves_history_and_unknown_authorization(tmp_path):
    import sqlite3
    path = tmp_path/'legacy.db'
    db = sqlite3.connect(path)
    db.executescript('''CREATE TABLE scans (
        id VARCHAR PRIMARY KEY, owner VARCHAR NOT NULL, request_key VARCHAR NOT NULL,
        status VARCHAR NOT NULL, attempted INTEGER NOT NULL, planned INTEGER NOT NULL,
        error VARCHAR, created_at VARCHAR NOT NULL, updated_at VARCHAR NOT NULL,
        UNIQUE(owner,request_key));
        INSERT INTO scans VALUES ('old','demo','old-key-001','completed',4,4,NULL,'2026-11-20','2026-11-20');''')
    db.close()
    sessions = database('sqlite:///' + str(path))
    with sessions() as db:
        row = db.get(Scan,'old')
        assert row.status == 'completed' and row.attempted == 4
        assert row.authorization_confirmed_at is None
        assert row.target_id == 'local-lab'
    # Re-running migrations is harmless.
    database('sqlite:///' + str(path))

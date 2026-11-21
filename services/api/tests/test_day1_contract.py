"""Day 1 behavior tests added before lifecycle implementation."""
import pytest
from fastapi.testclient import TestClient
from fuzzcore.api import create_app
from fuzzcore.core import database

TOKEN = 'local-test-token-not-real-123456789'

@pytest.fixture
def client(tmp_path):
    queue = []
    app = create_app(database('sqlite:///' + str(tmp_path/'day1.db')), queue.append, TOKEN)
    return TestClient(app, headers={'Authorization': 'Bearer ' + TOKEN}), queue


def submit(c, key, **body):
    return c.post('/v1/scans', headers={'Idempotency-Key': key}, json={
        'target_id': 'local-lab', 'authorization_confirmed': True, **body})


def test_authorization_must_be_explicit(client):
    c, queue = client
    for body in [{'target_id':'local-lab'}, {'target_id':'local-lab','authorization_confirmed':False}]:
        assert c.post('/v1/scans', headers={'Idempotency-Key':'scope-test-001'}, json=body).status_code == 422
    assert not queue
    assert submit(c, 'scope-test-002').status_code == 202


def test_single_active_scan_conflict_and_idempotent_retry(client):
    c, queue = client
    first = submit(c, 'request-day1-001')
    assert first.status_code == 202
    assert submit(c, 'request-day1-001').json()['id'] == first.json()['id']
    assert submit(c, 'request-day1-002').status_code == 409
    assert len(queue) == 1
    c.post('/v1/scans/' + first.json()['id'] + '/cancel')
    assert submit(c, 'request-day1-002').status_code == 202


def test_capabilities_never_advertise_unimplemented_modules(client):
    c, _ = client
    result = c.get('/v1/capabilities')
    assert result.status_code == 200
    body = result.json()
    assert body['modules']['directories']['supported'] is True
    for key in ['vhosts','api','parameters','custom','subdomains']:
        assert body['modules'][key]['supported'] is True
    assert body['profile']['max_attempts'] == 28
    assert submit(c, 'unsupported-001', modules=['unknown']).status_code == 422


def test_active_scan_constraint_holds_across_app_instances(tmp_path):
    url = 'sqlite:///' + str(tmp_path/'shared.db')
    queued = []
    a = TestClient(create_app(database(url), queued.append, TOKEN), headers={'Authorization':'Bearer '+TOKEN})
    b = TestClient(create_app(database(url), queued.append, TOKEN), headers={'Authorization':'Bearer '+TOKEN})
    assert submit(a, 'shared-first-001').status_code == 202
    assert submit(b, 'shared-second-002').status_code == 409
    assert len(queued) == 1


def test_authorization_rejects_non_boolean_confirmation(client):
    c, queue = client
    for value in [1, 'true', 'yes']:
        assert submit(c, 'nonboolean-001', authorization_confirmed=value).status_code == 422
    assert queue == []


def test_scan_persists_the_authorized_scope_snapshot(client):
    c, _ = client
    row = submit(c, 'scope-snapshot-001').json()
    detail = c.get('/v1/scans/' + row['id']).json()
    assert detail['target_id'] == 'local-lab'
    assert detail['scope_version'] == 'lab-v1'
    assert detail['authorization_confirmed_at']

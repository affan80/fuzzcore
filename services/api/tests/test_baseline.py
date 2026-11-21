import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from fuzzcore.api import create_app
from fuzzcore.core import Scan, Finding, database, run_scan, validate_lab_origin, PATHS, http_probe

TOKEN = 'test-only-not-a-real-secret-123456'

@pytest.fixture
def setup(tmp_path):
    sessions = database('sqlite:///' + str(tmp_path / 'test.db'))
    queued = []
    app = create_app(sessions, queued.append, TOKEN)
    client = TestClient(app, headers={'Authorization': 'Bearer ' + TOKEN})
    return sessions, queued, client


def start(client, key='request-0001', **extra):
    return client.post('/v1/scans', json={'target_id': 'local-lab', 'authorization_confirmed': True, **extra}, headers={'Idempotency-Key': key})


def test_auth_and_fixed_scope(setup):
    _, q, c = setup
    assert c.get('/v1/targets', headers={'Authorization': ''}).status_code == 401
    assert c.get('/health', headers={'Authorization': ''}).status_code == 200
    assert start(c, target_url='http://169.254.169.254/').status_code == 422
    assert start(c, target_id='outside').status_code == 422
    assert not q


def test_idempotency_and_complete_scan(setup):
    s, q, c = setup
    a = start(c); b = start(c)
    assert a.status_code == 202
    assert a.json()['id'] == b.json()['id']
    assert len(q) == 1
    run_scan(q[0], s, lambda path: 404 if path == PATHS[-1] else 200, pause=lambda _: None)
    row = c.get('/v1/scans/' + q[0]).json()
    assert row['status'] == 'completed' and row['attempted'] == 4
    findings = c.get('/v1/scans/' + q[0] + '/findings').json()
    assert len(findings) == 3
    assert all(f['severity'] == 'informational' for f in findings)
    run_scan(q[0], s, lambda _: pytest.fail('terminal job replayed'))
    assert len(c.get('/v1/scans').json()) == 1


def test_cancel_before_execution(setup):
    s, q, c = setup
    scan_id = start(c).json()['id']
    assert c.post('/v1/scans/' + scan_id + '/cancel').json()['status'] == 'cancelled'
    run_scan(scan_id, s, lambda _: pytest.fail('cancelled scan made request'))


def test_cancel_during_scan(setup):
    s, q, c = setup
    scan_id = start(c).json()['id']
    requests = []
    def probe(path):
        requests.append(path)
        c.post('/v1/scans/' + scan_id + '/cancel')
        return 200
    run_scan(scan_id, s, probe, pause=lambda _: None)
    assert len(requests) == 1
    assert c.get('/v1/scans/' + scan_id).json()['status'] == 'cancelled'


def test_error_does_not_leak_exception(setup):
    s, q, c = setup
    scan_id = start(c).json()['id']
    def probe(_): raise RuntimeError('private infrastructure detail')
    run_scan(scan_id, s, probe)
    row = c.get('/v1/scans/' + scan_id).json()
    assert row['status'] == 'failed' and row['error'] == 'probe_failed'


def test_rate_limit_stops_scan(setup):
    s, q, c = setup
    scan_id = start(c).json()['id']
    run_scan(scan_id, s, lambda _: 429, pause=lambda _: None)
    row = c.get('/v1/scans/' + scan_id).json()
    assert row['attempted'] == 1 and row['error'] == 'target_rate_limited'


@pytest.mark.parametrize('origin', ['http://localhost:8081', 'http://lab:8081@evil.example', 'http://lab:8081/admin', 'https://lab:8081', 'http://169.254.169.254'])
def test_origin_guard(origin):
    with pytest.raises(ValueError): validate_lab_origin(origin)


def test_http_does_not_follow_redirect_or_request_unknown_path():
    seen = []
    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={'Location': 'http://169.254.169.254/'})
    with httpx.Client(base_url='http://lab:8081', follow_redirects=False, transport=httpx.MockTransport(handler)) as client:
        probe = http_probe(client)
        assert probe('/') == 302
        with pytest.raises(ValueError): probe('/other')
    assert seen == ['http://lab:8081/']


def test_cross_owner_hidden(setup):
    s, q, c = setup
    scan_id = start(c).json()['id']
    with s() as db:
        row = db.get(Scan, scan_id); row.owner = 'other'; db.commit()
    assert c.get('/v1/scans/' + scan_id).status_code == 404
    assert c.get('/v1/scans/' + scan_id + '/findings').status_code == 404
    assert c.post('/v1/scans/' + scan_id + '/cancel').status_code == 404
    assert c.get('/v1/scans').json() == []


def test_database_persists_after_app_recreation(setup):
    s, q, c = setup
    scan_id = start(c).json()['id']
    second = TestClient(create_app(s, q.append, TOKEN), headers={'Authorization': 'Bearer ' + TOKEN})
    assert second.get('/v1/scans/' + scan_id).json()['status'] == 'queued'


def test_queue_failure_is_visible(tmp_path):
    s = database('sqlite:///' + str(tmp_path / 'queue.db'))
    def broken(_): raise ConnectionError('not connected')
    c = TestClient(create_app(s, broken, TOKEN), headers={'Authorization': 'Bearer ' + TOKEN})
    assert start(c).status_code == 503
    assert c.get('/v1/scans').json()[0]['error'] == 'enqueue_failed'


def test_scanner_gateway_rejects_unapproved_paths():
    from fuzzcore.scanner import create_scanner
    seen = []
    def handler(request):
        seen.append(str(request.url)); return httpx.Response(200)
    app = create_scanner(httpx.MockTransport(handler), delay=lambda _: None)
    c = TestClient(app)
    assert c.get('/probe', params={'path':'http://evil.example/'}).status_code == 422
    assert c.get('/probe', params={'path':'/'}).json() == {'status_code':200}
    assert seen == ['http://lab:8081/']


def test_real_loopback_fixture_end_to_end(setup):
    import importlib.util
    import threading
    from http.server import ThreadingHTTPServer
    from pathlib import Path
    spec = importlib.util.spec_from_file_location('fixture', Path(__file__).resolve().parents[2] / 'lab' / 'server.py')
    fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
    server = ThreadingHTTPServer(('127.0.0.1', 0), fixture.Handler)
    thread = threading.Thread(target=server.serve_forever); thread.start()
    try:
        s, q, c = setup
        scan_id = start(c).json()['id']
        with httpx.Client(base_url=f'http://127.0.0.1:{server.server_port}', follow_redirects=False, trust_env=False) as transport:
            run_scan(scan_id, s, http_probe(transport), pause=lambda _: None)
        assert c.get('/v1/scans/' + scan_id).json()['status'] == 'completed'
        assert len(c.get('/v1/scans/' + scan_id + '/findings').json()) == 3
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_placeholder_token_is_refused(tmp_path):
    with pytest.raises(ValueError):
        create_app(database('sqlite:///' + str(tmp_path/'placeholder.db')), lambda _:None, 'replace_with_generated_random_demo_token')

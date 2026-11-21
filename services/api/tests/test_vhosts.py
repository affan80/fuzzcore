import httpx
import pytest
from fastapi.testclient import TestClient
from fuzzcore.api import create_app
from fuzzcore.core import database, run_scan

TOKEN = 'fixture-only-test-token-not-secret'


def test_vhost_selection_persists_and_shares_the_global_budget(tmp_path):
    sessions = database('sqlite:///' + str(tmp_path/'vhosts.db'))
    queued = []
    client = TestClient(create_app(sessions, queued.append, TOKEN), headers={'Authorization':'Bearer '+TOKEN})
    body = {'target_id':'local-lab','authorization_confirmed':True,'modules':['directories','vhosts']}
    response = client.post('/v1/scans', json=body, headers={'Idempotency-Key':'vhost-first-test'})
    assert response.status_code == 202
    scan_id = response.json()['id']
    detail = client.get('/v1/scans/'+scan_id).json()
    assert detail['modules'] == ['directories','vhosts'] and detail['planned'] == 7
    calls = []
    def vhost(case):
        calls.append(case)
        return {'host':case+'.lab.invalid','status_code':200,'body_sha256':'b'*64 if case=='seeded' else 'a'*64,'bytes':10}
    run_scan(scan_id, sessions, lambda path:404, pause=lambda _:None, vhost_probe=vhost)
    detail = client.get('/v1/scans/'+scan_id).json()
    assert detail['status']=='completed' and detail['attempted']==7
    findings = client.get('/v1/scans/'+scan_id+'/findings').json()
    assert len(findings)==1 and findings[0]['module']=='vhosts'
    assert findings[0]['severity']=='informational'
    assert findings[0]['evidence']['rule_id']=='vhost-difference-v1'
    assert calls==['default','control','seeded']
    assert client.get('/v1/capabilities').json()['modules']['vhosts']['supported'] is True


@pytest.mark.parametrize('same_as', ['default','control','redirect'])
def test_vhost_baselines_filter_default_wildcard_and_redirects(tmp_path, same_as):
    from fuzzcore.vhosts import discover
    def probe(case):
        hashes = {'default':'a'*64,'control':'b'*64,'seeded':'c'*64}
        if same_as != 'redirect': hashes['seeded']=hashes[same_as]
        return {'status_code':302 if same_as=='redirect' else 200,'body_sha256':hashes[case],'bytes':10,'host':case+'.lab.invalid'}
    assert discover({case:probe(case) for case in ('default','control','seeded')}) is None


def test_gateway_pins_destination_rejects_unknown_cases_and_retains_no_body():
    from fuzzcore.scanner import create_scanner
    seen=[]
    def handler(request):
        seen.append((str(request.url),request.headers['host']))
        return httpx.Response(200,content=b'private fixture content')
    client=TestClient(create_scanner(httpx.MockTransport(handler),delay=lambda _:None))
    assert client.get('/vhost',params={'case':'http://external.invalid'}).status_code==422
    for case in ['default','control','seeded']:
        result=client.get('/vhost',params={'case':case})
        assert result.status_code==200 and len(result.json()['body_sha256'])==64
        assert 'private fixture' not in result.text
    assert all(url=='http://lab:8081/' for url,host in seen)
    assert seen[0][1]=='default.lab.invalid' and seen[2][1]=='admin.lab.invalid'
    assert seen[1][1].endswith('.lab.invalid') and seen[1][1] not in (seen[0][1],seen[2][1])


def test_vhost_body_limit_is_enforced():
    from fuzzcore.vhosts import http_vhost_probe
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(lambda _:httpx.Response(200,content=b'x'*20000))) as client:
        with pytest.raises(ValueError): http_vhost_probe(client)('seeded')


def test_vhost_only_fixture_end_to_end_and_cancel(tmp_path):
    import importlib.util
    import threading
    from http.server import ThreadingHTTPServer
    from pathlib import Path
    from fuzzcore.vhosts import http_vhost_probe
    spec=importlib.util.spec_from_file_location('fixture',Path(__file__).resolve().parents[2]/'lab'/'server.py')
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    server=ThreadingHTTPServer(('127.0.0.1',0),fixture.Handler)
    thread=threading.Thread(target=server.serve_forever);thread.start()
    try:
        sessions=database('sqlite:///'+str(tmp_path/'real.db'))
        queued=[]
        c=TestClient(create_app(sessions,queued.append,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
        body={'target_id':'local-lab','authorization_confirmed':True,'modules':['vhosts']}
        scan=c.post('/v1/scans',json=body,headers={'Idempotency-Key':'real-vhosts-001'}).json()['id']
        with httpx.Client(base_url=f'http://127.0.0.1:{server.server_port}',trust_env=False,follow_redirects=False) as client:
            run_scan(scan,sessions,lambda _:pytest.fail('directory traffic in vhost-only run'),pause=lambda _:None,vhost_probe=http_vhost_probe(client))
        assert c.get('/v1/scans/'+scan).json()['attempted']==3
        findings=c.get('/v1/scans/'+scan+'/findings').json()
        assert len(findings)==1 and findings[0]['path']=='admin.lab.invalid'
        second=c.post('/v1/scans',json=body,headers={'Idempotency-Key':'real-vhosts-002'}).json()['id']
        called=[]
        def cancel(case):
            called.append(case);c.post('/v1/scans/'+second+'/cancel')
            return {'host':'default.lab.invalid','status_code':200,'body_sha256':'a'*64,'bytes':10}
        run_scan(second,sessions,lambda _:404,pause=lambda _:None,vhost_probe=cancel)
        assert len(called)==1 and c.get('/v1/scans/'+second).json()['status']=='cancelled'
    finally:
        server.shutdown();server.server_close();thread.join()


def test_module_retry_cannot_change_scope_or_accept_unknown_modules(tmp_path):
    sessions=database('sqlite:///'+str(tmp_path/'scope.db'))
    c=TestClient(create_app(sessions,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    body={'target_id':'local-lab','authorization_confirmed':True,'modules':['vhosts']}
    headers={'Idempotency-Key':'module-retry-001'}
    assert c.post('/v1/scans',json=body,headers=headers).status_code==202
    assert c.post('/v1/scans',json={**body,'modules':['directories']},headers=headers).status_code==409
    for modules in [[],['vhosts','vhosts'],['custom']]:
        assert c.post('/v1/scans',json={**body,'modules':modules},headers=headers).status_code==422


def test_combined_rate_limit_stops_before_next_module(tmp_path):
    sessions=database('sqlite:///'+str(tmp_path/'rate.db'))
    c=TestClient(create_app(sessions,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    body={'target_id':'local-lab','authorization_confirmed':True,'modules':['directories','vhosts']}
    scan=c.post('/v1/scans',json=body,headers={'Idempotency-Key':'module-rate-001'}).json()['id']
    run_scan(scan,sessions,lambda _:429,pause=lambda _:None,vhost_probe=lambda _:pytest.fail('rate-limited run continued'))
    row=c.get('/v1/scans/'+scan).json()
    assert row['status']=='failed' and row['attempted']==1 and row['error']=='target_rate_limited'

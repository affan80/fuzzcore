import importlib.util
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer
import httpx
import pytest
from fastapi.testclient import TestClient
from fuzzcore.api import create_app
from fuzzcore.core import database, run_scan
TOKEN='fixture-parameter-tests-not-secret'


def test_parameter_gateway_pinned_and_evidence_redacted():
    from fuzzcore.scanner import create_scanner
    from fuzzcore.parameters import CASES
    seen=[]
    def handler(request):
        seen.append(request)
        values=request.url.params.get_list('q')
        return httpx.Response(200,json={'fixture':True,'values':values,'secret':'do-not-retain'})
    c=TestClient(create_scanner(httpx.MockTransport(handler),delay=lambda _:None))
    assert c.get('/parameter-check',params={'case':'https://external.invalid'}).status_code==422
    for case in CASES:
        r=c.get('/parameter-check',params={'case':case})
        assert r.status_code==200 and 'do-not-retain' not in r.text and 'values' not in r.json()
    assert len(seen)==6 and all(r.url.host=='lab' and r.url.port==8081 and r.url.path=='/parameter-fixture' for r in seen)
    assert any(r.url.params.get_list('q')==['fc-alpha-7f23','fc-beta-7f23'] for r in seen)
    assert all('authorization' not in r.headers for r in seen)


@pytest.mark.parametrize('secure',[False,True])
def test_parameter_real_fixture_signals_and_negative_controls(tmp_path,secure):
    from fuzzcore.parameters import http_parameter_probe
    spec=importlib.util.spec_from_file_location('parameter_fixture',Path(__file__).resolve().parents[2]/'lab'/'server.py')
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    fixture.Handler.parameter_signals = not secure
    server=ThreadingHTTPServer(('127.0.0.1',0),fixture.Handler)
    thread=threading.Thread(target=server.serve_forever);thread.start()
    try:
        sessions=database('sqlite:///'+str(tmp_path/'parameters.db'))
        c=TestClient(create_app(sessions,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
        body={'target_id':'local-lab','authorization_confirmed':True,'modules':['parameters']}
        response=c.post('/v1/scans',json=body,headers={'Idempotency-Key':'parameters-real-001'})
        assert response.status_code==202
        scan=response.json()['id']
        with httpx.Client(base_url=f'http://127.0.0.1:{server.server_port}',follow_redirects=False,trust_env=False) as client:
            run_scan(scan,sessions,lambda _:pytest.fail('wrong surface'),pause=lambda _:None,parameter_probe=http_parameter_probe(client))
        detail=c.get('/v1/scans/'+scan).json()
        assert detail['status']=='completed' and detail['attempted']==detail['planned']==6
        findings=c.get('/v1/scans/'+scan+'/findings').json()
        assert len(findings)==(0 if secure else 2)
        assert all(f['severity']=='informational' and f['confidence']=='signal' for f in findings)
        assert {f['evidence']['rule_id'] for f in findings}== (set() if secure else {'parameter-reflection-signal-v1','duplicate-parameter-signal-v1'})
        assert all('not proof' in f['summary'] for f in findings)
        response=c.post('/v1/scans',json={**body,'modules':['directories','vhosts','api','parameters']},headers={'Idempotency-Key':'parameters-all-002'})
        assert c.get('/v1/scans/'+response.json()['id']).json()['planned']==19
    finally:
        server.shutdown();server.server_close();thread.join()


def test_static_reflection_and_login_page_do_not_create_signals():
    from fuzzcore.parameters import http_parameter_probe,assess,CASES
    for body in [b'<html>login</html>',b'{"fixture":true,"values":["fc-alpha-7f23"]}']:
        with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(lambda _:httpx.Response(200,content=body))) as client:
            probe=http_parameter_probe(client)
            assert assess({case:probe(case) for case in CASES})==[]


def test_redirect_and_body_budget_do_not_produce_evidence():
    from fuzzcore.parameters import http_parameter_probe,assess,CASES
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(lambda _:httpx.Response(302,headers={'Location':'http://external.invalid/'})),follow_redirects=False) as client:
        probe=http_parameter_probe(client)
        assert assess({case:probe(case) for case in CASES})==[]
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(lambda _:httpx.Response(200,content=b'x'*20000))) as client:
        with pytest.raises(ValueError):http_parameter_probe(client)('alpha')

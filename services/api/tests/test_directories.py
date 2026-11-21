import importlib.util
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer
import httpx
import pytest
from fastapi.testclient import TestClient
from fuzzcore.api import create_app
from fuzzcore.core import database,run_scan,PATHS


def test_directory_signature_filters_soft404_and_redirects():
    from fuzzcore.directories import discover
    baseline={'status_code':200,'bytes':10,'body_sha256':'a'*64}
    values={p:{**baseline,'path':p} for p in PATHS}
    assert discover(values)==[]
    values['/health']={**values['/health'],'body_sha256':'b'*64}
    found=discover(values)
    assert len(found)==1 and found[0]['path']=='/health'
    assert found[0]['evidence']['rule_id']=='directory-control-v1'
    assert 'body' not in str(found[0]['evidence']) or 'body_sha256' in str(found[0]['evidence'])
    values['/health']['status_code']=302
    assert discover(values)==[]


def test_directory_gateway_pins_paths_randomizes_control_and_redacts():
    seen=[]
    def handler(request):
        seen.append(str(request.url));return httpx.Response(200,content=b'sensitive fixture text')
    from fuzzcore.scanner import create_scanner
    c=TestClient(create_scanner(httpx.MockTransport(handler),delay=lambda _:None))
    assert c.get('/directory-check',params={'path':'http://outside.invalid'}).status_code==422
    for p in [PATHS[-1],PATHS[-1],'/health']:
        r=c.get('/directory-check',params={'path':p});assert r.status_code==200
        assert len(r.json()['body_sha256'])==64 and 'sensitive fixture text' not in r.text
    assert seen[0]!=seen[1] and all(x.startswith('http://lab:8081/missing-control-') for x in seen[:2])
    assert seen[2]=='http://lab:8081/health'


def test_directory_adapter_rejects_large_bodies_and_unknown_paths():
    from fuzzcore.directories import http_directory_probe
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(lambda _:httpx.Response(200,content=b'x'*20000))) as client:
        probe=http_directory_probe(client)
        with pytest.raises(ValueError):probe('/')
        with pytest.raises(ValueError):probe('/other')


def test_missing_directory_control_cannot_confirm_candidate():
    from fuzzcore.directories import discover
    assert discover({'/':{'path':'/','status_code':200,'bytes':1,'body_sha256':'a'*64}})==[]


@pytest.mark.parametrize('soft404',[False,True])
def test_real_directory_control_fixture_end_to_end(tmp_path,soft404):
    from fuzzcore.directories import http_directory_probe
    spec=importlib.util.spec_from_file_location('directory_fixture',Path(__file__).resolve().parents[2]/'lab'/'server.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    class Handler(mod.Handler):
        directory_soft404=soft404
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);t=threading.Thread(target=server.serve_forever);t.start()
    try:
        s=database('sqlite:///'+str(tmp_path/'directory.db'))
        c=TestClient(create_app(s,lambda _:None,'directory-fixture-token-not-secret'),headers={'Authorization':'Bearer directory-fixture-token-not-secret'})
        id=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True},headers={'Idempotency-Key':'directory-control-001'}).json()['id']
        with httpx.Client(base_url=f'http://127.0.0.1:{server.server_port}',trust_env=False,follow_redirects=False) as client:
            run_scan(id,s,lambda _:pytest.fail('legacy status-only adapter used'),pause=lambda _:None,directory_probe=http_directory_probe(client))
        detail=c.get('/v1/scans/'+id).json()
        assert detail['attempted']==detail['planned']==4 and detail['status']=='completed'
        findings=c.get('/v1/scans/'+id+'/findings').json()
        assert len(findings)==(0 if soft404 else 3)
        assert all(f['evidence']['rule_id']=='directory-control-v1' and f['severity']=='informational' for f in findings)
    finally:server.shutdown();server.server_close();t.join()


@pytest.mark.parametrize('control_status',[302,500])
def test_failed_directory_baseline_keeps_run_partial_not_clean(tmp_path,control_status):
    s=database('sqlite:///'+str(tmp_path/'bad-control.db'))
    c=TestClient(create_app(s,lambda _:None,'directory-fixture-token-not-secret'),headers={'Authorization':'Bearer directory-fixture-token-not-secret'})
    id=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True},headers={'Idempotency-Key':'bad-directory-control'}).json()['id']
    def probe(path):return {'path':path,'status_code':control_status if path==PATHS[-1] else 200,'bytes':1,'body_sha256':'a'*64}
    run_scan(id,s,lambda _:pytest.fail('wrong probe'),pause=lambda _:None,directory_probe=probe)
    value=c.get('/v1/scans/'+id+'/report.json').json()
    assert value['partial'] is True and value['scan']['status']=='failed'
    assert value['scan']['module_progress']['directories']['state']=='failed'
    assert value['totals']['findings']==0


def test_production_worker_uses_signature_gateway_without_status_only_fallback(tmp_path,monkeypatch):
    import fuzzcore.core as core
    s=database('sqlite:///'+str(tmp_path/'worker-control.db'))
    c=TestClient(create_app(s,lambda _:None,'directory-fixture-token-not-secret'),headers={'Authorization':'Bearer directory-fixture-token-not-secret'})
    id=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True},headers={'Idempotency-Key':'production-directory-control'}).json()['id']
    seen=[];original=httpx.Client
    def handler(request):
        seen.append(request)
        p=request.url.params['path']
        return httpx.Response(200,json={'path':p,'status_code':404 if p==PATHS[-1] else 200,'bytes':1,'body_sha256':'a'*64})
    monkeypatch.setenv('DATABASE_URL','fixture-value')
    monkeypatch.setattr(core,'database',lambda _:s)
    monkeypatch.setattr(core.httpx,'Client',lambda **kwargs:original(**kwargs,transport=httpx.MockTransport(handler)))
    core.execute_job(id)
    assert len(seen)==4 and all(request.url.path=='/directory-check' for request in seen)
    assert seen[0].url.params['path']==PATHS[-1]
    assert c.get('/v1/scans/'+id).json()['status']=='completed'
    findings=c.get('/v1/scans/'+id+'/findings').json()
    assert len(findings)==3 and all(f['evidence']['rule_id']=='directory-control-v1' for f in findings)


def test_directory_rate_limit_preserves_shared_stop_reason(tmp_path):
    s=database('sqlite:///'+str(tmp_path/'directory-rate.db'))
    c=TestClient(create_app(s,lambda _:None,'directory-fixture-token-not-secret'),headers={'Authorization':'Bearer directory-fixture-token-not-secret'})
    id=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True},headers={'Idempotency-Key':'directory-rate-control'}).json()['id']
    run_scan(id,s,lambda _:pytest.fail('wrong adapter'),pause=lambda _:None,directory_probe=lambda p:{'path':p,'status_code':429,'bytes':0,'body_sha256':'a'*64})
    row=c.get('/v1/scans/'+id).json()
    assert row['error']=='target_rate_limited' and row['status']=='failed' and row['attempted']==1

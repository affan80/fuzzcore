import importlib.util
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer
import httpx
import pytest
from fastapi.testclient import TestClient
from fuzzcore.api import create_app
from fuzzcore.core import database,run_scan,Scan
TOKEN='inventory-fixture-tests-only-token'


def setup(tmp_path):
    s=database('sqlite:///'+str(tmp_path/'inventory.db'));c=TestClient(create_app(s,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    return s,c


def start(c,**extra):
    r=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':['api'],'api_cases':['inventory-v1'],**extra},headers={'Idempotency-Key':'api-inventory-001'})
    assert r.status_code==202,r.text
    return r.json()['id']


@pytest.fixture
def fixture():
    spec=importlib.util.spec_from_file_location('inventory_fixture',Path(__file__).resolve().parents[2]/'lab'/'server.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    server=ThreadingHTTPServer(('127.0.0.1',0),mod.Handler);t=threading.Thread(target=server.serve_forever);t.start()
    try:yield mod.Handler,'http://127.0.0.1:'+str(server.server_port)
    finally:server.shutdown();server.server_close();t.join()


def test_opt_in_inventory_preserves_defaults_and_immutable_scope(tmp_path):
    s,c=setup(tmp_path);id=start(c);row=c.get('/v1/scans/'+id).json()
    assert row['api_cases']==['inventory-v1'] and row['planned']==10 and row['module_progress']['api']['planned']==10
    body={'target_id':'local-lab','authorization_confirmed':True,'modules':['api']}
    assert c.post('/v1/scans',json=body,headers={'Idempotency-Key':'api-inventory-001'}).status_code==409
    c.post('/v1/scans/'+id+'/cancel')
    old=c.post('/v1/scans',json=body,headers={'Idempotency-Key':'api-default-001'}).json()['id']
    assert c.get('/v1/scans/'+old).json()['planned']==6
    caps=c.get('/v1/capabilities').json();assert caps['api_cases']['inventory-v1']['requests']==4 and caps['api_cases']['inventory-v1']['default'] is False
    assert caps['profile']['max_attempts']==38


@pytest.mark.parametrize('extra',[{'modules':['directories']},{'api_cases':['inventory-v1','inventory-v1']},{'api_cases':['unknown']},{'api_cases':['http://outside.invalid']}])
def test_inventory_scope_rejections(tmp_path,extra):
    _,c=setup(tmp_path)
    r=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':['api'],'api_cases':['inventory-v1'],**extra},headers={'Idempotency-Key':'inventory-rejected'})
    assert r.status_code==422


def test_real_curated_inventory_distinguishes_public_protected_hidden_without_vuln_claim(tmp_path,fixture):
    from fuzzcore.api_inventory import http_inventory_probe
    from fuzzcore.api_checks import http_api_probe
    Handler,base=fixture;s,c=setup(tmp_path);id=start(c)
    with httpx.Client(base_url=base,trust_env=False,follow_redirects=False) as client:
        run_scan(id,s,lambda _:404,pause=lambda _:None,api_probe=http_api_probe(client),inventory_probe=http_inventory_probe(client))
    row=c.get('/v1/scans/'+id).json();assert row['status']=='completed' and row['attempted']==row['planned']==10
    found=c.get('/v1/scans/'+id+'/findings').json();inventory=[f for f in found if f['evidence'].get('rule_id')=='curated-api-discovery-v1']
    assert len(inventory)==3 and sorted(f['evidence']['access'] for f in inventory)==['hidden','protected','public']
    assert all(f['severity']=='informational' and f['confidence']=='observed' for f in inventory)
    assert all(f['evidence']['transport']['scheme']=='http' and f['evidence']['transport']['scope']=='isolated_fixture_only' for f in inventory)
    assert all(f['evidence']['security_headers']['content_type_json'] and f['evidence']['security_headers']['nosniff'] for f in inventory)
    assert len(found)==4


def test_soft404_and_redirect_inventory_cannot_be_discoveries(tmp_path):
    from fuzzcore.api_inventory import http_inventory_probe,assess
    seen=[]
    def soft(request):seen.append(request);return httpx.Response(200,json={'fixture':True,'route':'same'})
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(soft),trust_env=False,follow_redirects=False) as client:
        probe=http_inventory_probe(client);values={case:probe(case) for case in ('control','public','protected','hidden')}
        assert assess(values)==[]
    assert len(seen)==4 and seen[0].url.path.startswith('/api/inventory/missing-control-')
    assert all(r.method=='GET' and r.url.host=='lab' for r in seen)
    def redirect(request):return httpx.Response(302,headers={'Location':'https://outside.invalid'})
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(redirect),trust_env=False,follow_redirects=False) as client:
        assert assess({case:http_inventory_probe(client)(case) for case in ('control','public','protected','hidden')})==[]


def test_inventory_control_failure_is_partial_and_no_followup_after_429(tmp_path):
    from fuzzcore.api_inventory import http_inventory_probe
    from fuzzcore.api_checks import http_api_probe
    s,c=setup(tmp_path);id=start(c);calls=[]
    def inventory(case):calls.append(case);return {'status_code':429,'bytes':0,'body_sha256':'a'*64,'fixture':False,'route':'unknown','headers':{}}
    def existing(case):return {'status_code':404,'bytes':0,'body_sha256':'b'*64,'fixture':True,'owner':'unknown','object':'unknown'}
    run_scan(id,s,lambda _:404,pause=lambda _:None,api_probe=existing,inventory_probe=inventory)
    row=c.get('/v1/scans/'+id).json();assert row['status']=='failed' and row['error']=='target_rate_limited' and calls==['control'] and row['attempted']==7
    assert c.get('/v1/scans/'+id+'/report.json').json()['partial']


def test_maximum_inventory_plan_and_exact_retest_scope(tmp_path):
    from fuzzcore.custom_cases import CustomCase
    _,c=setup(tmp_path);modules=['directories','vhosts','api','parameters','custom','subdomains'];cases=[CustomCase(path='/health').model_dump()]*3
    id=start(c,modules=modules,directory_cases=['canary-v1','upload-v1'],custom_cases=cases)
    assert c.get('/v1/scans/'+id).json()['planned']==38
    c.post('/v1/scans/'+id+'/cancel')
    r=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':modules,'directory_cases':['canary-v1','upload-v1'],'custom_cases':cases,'retest_of':id},headers={'Idempotency-Key':'inventory-wrong-retest'})
    assert r.status_code==422


def test_inventory_adapter_rejects_unknown_cases_and_caps_data():
    from fuzzcore.api_inventory import http_inventory_probe
    seen=[]
    def handle(request):seen.append(request);return httpx.Response(200,content=b'x'*16385)
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(handle),trust_env=False) as client:
        probe=http_inventory_probe(client)
        with pytest.raises(ValueError):probe('http://outside.invalid')
        assert seen==[]
        with pytest.raises(ValueError):probe('public')
        assert len(seen)==1


def test_inventory_gateway_and_worker_dispatch_are_pinned(tmp_path,monkeypatch):
    import fuzzcore.core as core
    from fuzzcore.scanner import create_scanner
    seen=[]
    def handle(request):seen.append(request);return httpx.Response(200,json={'fixture':True,'route':'public'})
    c=TestClient(create_scanner(httpx.MockTransport(handle),delay=lambda _:None))
    assert c.get('/inventory-check',params={'case':'outside'}).status_code==422
    assert c.get('/inventory-check',params={'case':'public'}).status_code==200
    assert len(seen)==1 and seen[0].url.host=='lab'
    s,c=setup(tmp_path);id=start(c);captured={};RealClient=httpx.Client
    monkeypatch.setenv('DATABASE_URL','sqlite:///'+str(tmp_path/'inventory.db'))
    def run(scan_id,sessions,probe,**kwargs):captured.update(kwargs);kwargs['inventory_probe']('public')
    monkeypatch.setattr(core,'run_scan',run)
    monkeypatch.setattr(core.httpx,'Client',lambda **kw:RealClient(**kw,transport=httpx.MockTransport(handle)))
    core.execute_job(id);assert 'inventory_probe' in captured and seen[-1].url.host=='scanner' and seen[-1].url.path=='/inventory-check'


def test_invalid_inventory_baseline_fails_partial_with_accurate_response_count(tmp_path):
    s,c=setup(tmp_path);id=start(c)
    def existing(_):return {'status_code':404}
    def invalid(case):return {'status_code':200,'fixture':False,'route':'unknown','body_sha256':'a'*64}
    run_scan(id,s,lambda _:404,pause=lambda _:None,api_probe=existing,inventory_probe=invalid)
    row=c.get('/v1/scans/'+id).json()
    assert row['status']=='failed' and row['error']=='inventory_control_unavailable' and row['attempted']==7
    assert row['module_progress']['api']['completed']==7 and row['module_progress']['api']['state']=='failed'


def test_inventory_migration_does_not_expand_preexisting_scan(tmp_path):
    from sqlalchemy import text
    s,c=setup(tmp_path)
    r=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':['api']},headers={'Idempotency-Key':'legacy-inventory-migration'})
    id=r.json()['id'];before=c.get('/v1/scans/'+id).json()
    with s() as db:db.execute(text('ALTER TABLE scans DROP COLUMN api_cases'));db.execute(text('DELETE FROM schema_migrations WHERE version>=15'));db.commit()
    s=database('sqlite:///'+str(tmp_path/'inventory.db'));c=TestClient(create_app(s,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    assert c.get('/v1/scans/'+id).json()==before and before['api_cases']==[] and before['planned']==6


def test_persisted_unrecognized_inventory_scope_never_sends_traffic(tmp_path):
    s,c=setup(tmp_path);id=start(c)
    with s() as db:db.get(Scan,id).api_cases='["outside"]';db.commit()
    run_scan(id,s,lambda _:pytest.fail('Corrupt scope traffic'),pause=lambda _:None,api_probe=lambda _:pytest.fail('Corrupt scope traffic'),inventory_probe=lambda _:pytest.fail('Corrupt scope traffic'))
    row=c.get('/v1/scans/'+id).json();assert row['status']=='failed' and row['attempted']==0

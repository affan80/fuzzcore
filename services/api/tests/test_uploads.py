import json
import threading
import importlib.util
import uuid
from pathlib import Path
from http.server import ThreadingHTTPServer
import httpx
import pytest
from fastapi.testclient import TestClient
from fuzzcore.core import database,run_scan,Scan,PATHS
from fuzzcore.api import create_app

TOKEN='benign-upload-fixture-test-token-not-secret'


@pytest.fixture
def fixture_server():
    spec=importlib.util.spec_from_file_location('upload_fixture',Path(__file__).resolve().parents[2]/'lab'/'server.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    class Handler(mod.Handler):
        uploads={}
        upload_lock=threading.Lock()
        upload_ttl_seconds=300
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);t=threading.Thread(target=server.serve_forever);t.start()
    try:yield Handler,f'http://127.0.0.1:{server.server_port}'
    finally:
        server.shutdown();server.server_close();t.join()
        for value in Handler.uploads.values():value['timer'].cancel()


def setup(tmp_path):
    s=database('sqlite:///'+str(tmp_path/'upload.db'))
    return s,TestClient(create_app(s,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})


def start(c,key='upload-fixture-001',**extra):
    r=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':['directories'],'directory_cases':['upload-v1'],**extra},headers={'Idempotency-Key':key})
    assert r.status_code==202,r.text
    return r.json()['id']


def test_upload_scope_is_explicit_immutable_and_reserves_cleanup_budget(tmp_path):
    s,c=setup(tmp_path);id=start(c)
    row=c.get('/v1/scans/'+id).json()
    assert row['planned']==10 and row['directory_cases']==['upload-v1']
    assert row['cleanup_status']=='not_required' and row['cleanup_attempted']==0
    r=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':['directories']},headers={'Idempotency-Key':'upload-fixture-001'})
    assert r.status_code==409
    caps=c.get('/v1/capabilities').json()
    assert caps['directory_cases']['upload-v1']['requests']==6 and caps['directory_cases']['upload-v1']['cleanup_reserve']==2
    assert caps['profile']['max_attempts']==34


def test_real_benign_roundtrip_verifies_deletion_and_unused_reserve(tmp_path,fixture_server):
    from fuzzcore.uploads import http_upload_probe
    from fuzzcore.directories import http_directory_probe
    Handler,base=fixture_server;s,c=setup(tmp_path);id=start(c)
    with httpx.Client(base_url=base,trust_env=False,follow_redirects=False) as transport:
        run_scan(id,s,lambda _:pytest.fail('legacy probe'),pause=lambda _:None,directory_probe=http_directory_probe(transport),upload_probe=http_upload_probe(transport,id))
    row=c.get('/v1/scans/'+id).json();p=row['module_progress']['directories']
    assert row['status']=='completed' and row['attempted']==8 and row['planned']==10
    assert row['cleanup_status']=='verified_absent' and row['cleanup_attempted']==2
    assert p['completed']==8 and p['skipped']==2 and p['state']=='completed'
    assert Handler.uploads=={}
    found=[f for f in c.get('/v1/scans/'+id+'/findings').json() if f['evidence'].get('rule_id')=='benign-upload-roundtrip-v1']
    assert len(found)==1 and found[0]['severity']=='informational'
    assert found[0]['evidence']['cleanup_verified'] is True
    assert c.get('/v1/scans/'+id+'/report.json').json()['partial'] is False


@pytest.mark.parametrize('mode',['cancel','lost-create-response'])
def test_cancel_or_unknown_create_result_still_cleans_up(tmp_path,fixture_server,mode):
    from fuzzcore.uploads import http_upload_probe
    from fuzzcore.directories import http_directory_probe
    Handler,base=fixture_server;s,c=setup(tmp_path);id=start(c)
    with httpx.Client(base_url=base,trust_env=False,follow_redirects=False) as transport:
        raw=http_upload_probe(transport,id)
        def probe(action):
            result=raw(action)
            if action=='create':
                with s() as db:assert db.get(Scan,id).cleanup_status=='pending'
                if mode=='cancel':c.post('/v1/scans/'+id+'/cancel')
                else:raise httpx.ReadTimeout('fixture deliberately loses response')
            return result
        run_scan(id,s,lambda _:404,pause=lambda _:None,directory_probe=http_directory_probe(transport),upload_probe=probe)
    row=c.get('/v1/scans/'+id).json()
    assert row['status']==('cancelled' if mode=='cancel' else 'failed')
    assert row['cleanup_status']=='verified_absent' and row['attempted']==7
    assert Handler.uploads=={} and c.get('/v1/scans/'+id+'/report.json').json()['partial'] is True


def test_failed_cleanup_is_never_success_and_operator_recovery_does_not_repost(tmp_path,fixture_server):
    from fuzzcore.uploads import http_upload_probe,recover_pending_uploads
    from fuzzcore.directories import http_directory_probe
    Handler,base=fixture_server;s,c=setup(tmp_path);id=start(c);seen=[]
    with httpx.Client(base_url=base,trust_env=False,follow_redirects=False) as transport:
        raw=http_upload_probe(transport,id)
        def bad(action):
            seen.append(action)
            if action=='verify':return {'status_code':500,'known_marker':False,'bytes':0,'body_sha256':'a'*64}
            return raw(action)
        run_scan(id,s,lambda _:404,pause=lambda _:None,directory_probe=http_directory_probe(transport),upload_probe=bad)
        row=c.get('/v1/scans/'+id).json()
        assert row['status']=='failed' and row['cleanup_status']=='unverified'
        assert row['error']=='cleanup_unverified' and row['attempted']==8
        assert recover_pending_uploads(s,lambda scan_id:http_upload_probe(transport,scan_id),worker_stopped=True)==1
    row=c.get('/v1/scans/'+id).json()
    assert row['cleanup_status']=='verified_absent' and row['cleanup_attempted']==4
    assert row['attempted']==row['planned']==10 and row['status']=='failed'
    assert seen.count('create')==1 and Handler.uploads=={}


def test_cleanup_recovers_unknown_delete_with_reserved_attempts(tmp_path,fixture_server):
    from fuzzcore.uploads import http_upload_probe,recover_pending_uploads
    Handler,base=fixture_server;s,c=setup(tmp_path);id=start(c)
    with httpx.Client(base_url=base,trust_env=False,follow_redirects=False) as transport:
        raw=http_upload_probe(transport,id);assert raw('create')['status_code']==201
        with s() as db:
            row=db.get(Scan,id);row.status='interrupted';row.attempted=7;row.cleanup_status='pending';row.cleanup_attempted=1
            progress=json.loads(row.module_progress);progress['directories'].update(state='interrupted',attempted=7,completed=6);row.module_progress=json.dumps(progress);db.commit()
        assert recover_pending_uploads(s,lambda scan_id:http_upload_probe(transport,scan_id),worker_stopped=True)==1
    assert Handler.uploads=={}
    row=c.get('/v1/scans/'+id).json()
    assert row['status']=='interrupted' and row['cleanup_status']=='verified_absent' and row['attempted']==9


def test_cleanup_never_exceeds_reserved_or_global_budget(tmp_path):
    from fuzzcore.uploads import recover_pending_uploads
    s,c=setup(tmp_path);id=start(c)
    with s() as db:
        row=db.get(Scan,id);row.status='failed';row.cleanup_status='unverified';row.cleanup_attempted=4;row.attempted=10;db.commit()
    assert recover_pending_uploads(s,lambda _:lambda action:pytest.fail('Cleanup exceeded budget'),worker_stopped=True)==0
    assert c.get('/v1/scans/'+id).json()['cleanup_status']=='unverified'
    with pytest.raises(ValueError):recover_pending_uploads(s,lambda _:None,worker_stopped=False)


def test_upload_fixture_only_accepts_fixed_benign_data_and_expires(fixture_server):
    from fuzzcore.uploads import MARKER
    Handler,base=fixture_server;object_id=uuid.uuid4().hex
    with httpx.Client(base_url=base,trust_env=False,follow_redirects=False) as c:
        assert c.post('/upload-fixture/'+object_id,content=b'not the benign marker',headers={'Content-Type':'application/octet-stream'}).status_code==400
        assert c.post('/upload-fixture/not-valid',content=MARKER).status_code in (400,404,422)
        assert Handler.uploads=={}
        Handler.upload_ttl_seconds=0.05
        assert c.post('/upload-fixture/'+object_id,content=MARKER,headers={'Content-Type':'application/octet-stream'}).status_code==201
        timer=Handler.uploads[object_id]['timer'];timer.join(timeout=1)
        assert Handler.uploads=={} and c.get('/upload-fixture/'+object_id).status_code==404


def test_scanner_upload_gateway_validates_object_ids_and_redacts():
    from fuzzcore.uploads import MARKER
    from fuzzcore.scanner import create_scanner
    seen=[]
    def handle(request):
        seen.append(request)
        return httpx.Response(201 if request.method=='POST' else 200,content=MARKER)
    c=TestClient(create_scanner(httpx.MockTransport(handle),delay=lambda _:None));object_id=uuid.uuid4().hex
    assert c.get('/upload-check',params={'case':'create','object_id':'http://outside.invalid'}).status_code==422
    assert c.get('/upload-check',params={'case':'unknown','object_id':object_id}).status_code==422
    r=c.get('/upload-check',params={'case':'create','object_id':object_id});assert r.status_code==200
    assert 'FUZZCORE_BENIGN' not in r.text and len(seen)==1
    assert seen[0].method=='POST' and seen[0].url.host=='lab' and seen[0].content==MARKER


def test_default_scans_never_start_upload_cleanup(tmp_path):
    s,c=setup(tmp_path);id=start(c,directory_cases=[])
    run_scan(id,s,lambda p:404 if p==PATHS[-1] else 200,pause=lambda _:None,upload_probe=lambda _:pytest.fail('Default scan added writes'))
    row=c.get('/v1/scans/'+id).json()
    assert row['attempted']==4 and row['cleanup_status']=='not_required'


def test_timeout_after_creation_keeps_cleanup_counted(tmp_path,fixture_server):
    from fuzzcore.uploads import http_upload_probe
    from fuzzcore.directories import http_directory_probe
    Handler,base=fixture_server;s,c=setup(tmp_path);id=start(c);elapsed=[0]
    with httpx.Client(base_url=base,trust_env=False,follow_redirects=False) as transport:
        raw=http_upload_probe(transport,id)
        def probe(action):
            result=raw(action)
            if action=='create':elapsed[0]=301
            return result
        run_scan(id,s,lambda _:404,pause=lambda _:None,clock=lambda:elapsed[0],directory_probe=http_directory_probe(transport),upload_probe=probe)
    row=c.get('/v1/scans/'+id).json()
    assert row['status']=='timed_out' and row['cleanup_status']=='verified_absent' and row['attempted']==7 and Handler.uploads=={}


def test_old_rows_migrate_without_cleanup_obligation(tmp_path):
    from sqlalchemy import text
    s,c=setup(tmp_path);id=start(c,directory_cases=[])
    with s() as db:
        db.execute(text('DELETE FROM schema_migrations WHERE version>=12'))
        for column in ('cleanup_status','cleanup_attempted'):db.execute(text('ALTER TABLE scans DROP COLUMN '+column))
        db.commit()
    s=database('sqlite:///'+str(tmp_path/'upload.db'))
    with s() as db:
        assert db.get(Scan,id).cleanup_status=='not_required' and db.get(Scan,id).cleanup_attempted==0
        assert db.execute(text('SELECT max(version) FROM schema_migrations')).scalar()==14


def test_pending_cleanup_blocks_new_upload_but_not_read_only_scans(tmp_path):
    s,c=setup(tmp_path);id=start(c)
    with s() as db:
        row=db.get(Scan,id);row.status='failed';row.cleanup_status='unverified';db.commit()
    body={'target_id':'local-lab','authorization_confirmed':True,'modules':['directories'],'directory_cases':['upload-v1']}
    r=c.post('/v1/scans',json=body,headers={'Idempotency-Key':'blocked-upload-002'})
    assert r.status_code==409 and r.json()['detail']=='pending_upload_cleanup'
    assert start(c,key='read-only-allowed',directory_cases=[])


def test_maximum_plan_and_same_scope_retest(tmp_path):
    from fuzzcore.custom_cases import CustomCase
    s,c=setup(tmp_path)
    cases=[CustomCase(path=path).model_dump() for path in ('/health','/api/status','/custom-fixture')]
    modules=['directories','vhosts','api','parameters','custom','subdomains']
    id=start(c,modules=modules,custom_cases=cases,directory_cases=['canary-v1','upload-v1'])
    row=c.get('/v1/scans/'+id).json()
    assert row['planned']==34 and row['module_progress']['directories']['planned']==13
    c.post('/v1/scans/'+id+'/cancel')
    r=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':modules,'custom_cases':cases,'directory_cases':['canary-v1'],'retest_of':id},headers={'Idempotency-Key':'upload-retest-scope-001'})
    assert r.status_code==422
    id2=start(c,key='upload-retest-scope-002',modules=modules,custom_cases=cases,directory_cases=['canary-v1','upload-v1'],retest_of=id)
    assert c.get('/v1/scans/'+id2).json()['planned']==34


def test_upload_adapter_caps_body_and_rejects_actions_before_traffic():
    from fuzzcore.uploads import http_upload_probe
    seen=[]
    def handle(request):seen.append(request);return httpx.Response(200,content=b'x'*16385)
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(handle),trust_env=False) as c:
        probe=http_upload_probe(c,str(uuid.uuid4()))
        with pytest.raises(ValueError):probe('execute')
        assert seen==[]
        with pytest.raises(ValueError,match='budget'):probe('read')
        assert len(seen)==1


def test_upload_in_production_job_uses_network_separated_gateway(tmp_path,monkeypatch):
    import fuzzcore.core as core
    s,c=setup(tmp_path);id=start(c);captured={};seen=[]
    monkeypatch.setenv('DATABASE_URL','sqlite:///'+str(tmp_path/'upload.db'))
    def run(scan_id,sessions,probe,**kwargs):
        captured.update(kwargs)
        assert 'upload_probe' in kwargs
        kwargs['upload_probe']('verify')
    monkeypatch.setattr(core,'run_scan',run)
    RealClient=httpx.Client
    def transport(request):
        seen.append(request)
        return httpx.Response(200,json={'status_code':404,'known_marker':False,'bytes':0,'body_sha256':'a'*64})
    monkeypatch.setattr(core.httpx,'Client',lambda **kw:RealClient(**kw,transport=httpx.MockTransport(transport)))
    core.execute_job(id)
    assert 'upload_probe' in captured
    assert len(seen)==1 and seen[0].url.host=='scanner' and seen[0].url.path=='/upload-check'
    assert seen[0].url.params['object_id']==uuid.UUID(id).hex
    with pytest.raises(ValueError):captured['upload_probe']('execute')

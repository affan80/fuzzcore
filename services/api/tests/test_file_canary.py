import json
import importlib.util
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer
import pytest
import httpx
from fastapi.testclient import TestClient
from sqlalchemy import text
from fuzzcore.api import create_app
from fuzzcore.core import database,run_scan,Scan,PATHS

TOKEN='synthetic-canary-fixture-token-not-secret'


def client(tmp_path):
    s=database('sqlite:///'+str(tmp_path/'canary.db'))
    c=TestClient(create_app(s,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    return s,c


def submit(c,key='canary-test-001',**extra):
    return c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':['directories'],**extra},headers={'Idempotency-Key':key})


def test_canary_selection_is_opt_in_immutable_and_budgeted(tmp_path):
    s,c=client(tmp_path)
    first=submit(c);assert first.status_code==202
    id=first.json()['id'];row=c.get('/v1/scans/'+id).json()
    assert row['directory_cases']==[] and row['planned']==4
    assert submit(c,directory_cases=['canary-v1']).status_code==409
    c.post('/v1/scans/'+id+'/cancel')
    second=submit(c,key='canary-test-002',directory_cases=['canary-v1']);assert second.status_code==202
    row=c.get('/v1/scans/'+second.json()['id']).json()
    assert row['directory_cases']==['canary-v1'] and row['planned']==7
    assert row['module_progress']['directories']['planned']==7
    caps=c.get('/v1/capabilities').json()
    assert caps['directory_cases']['canary-v1']['requests']==3 and caps['profile']['max_attempts']==38


@pytest.mark.parametrize('extra',[{'directory_cases':['unknown-v1']},{'directory_cases':['canary-v1','canary-v1']},{'modules':['vhosts'],'directory_cases':['canary-v1']},{'directory_cases':['../outside']}])
def test_unknown_duplicate_or_unselected_directory_cases_rejected(tmp_path,extra):
    s,c=client(tmp_path)
    assert submit(c,**extra).status_code==422
    assert c.get('/v1/scans').json()==[]


def test_legacy_scope_does_not_gain_canary_checks_during_upgrade(tmp_path):
    s,c=client(tmp_path)
    id=submit(c).json()['id']
    with s() as db:
        db.execute(text('DELETE FROM schema_migrations WHERE version>=11'))
        db.execute(text('ALTER TABLE scans DROP COLUMN directory_cases'));db.commit()
    s=database('sqlite:///'+str(tmp_path/'canary.db'))
    with s() as db:assert db.get(Scan,id).directory_cases=='[]'
    run_scan(id,s,lambda p:404 if p==PATHS[-1] else 200,pause=lambda _:None,file_probe=lambda _:pytest.fail('Legacy scope expanded'))
    assert c.get('/v1/scans/'+id).json()['attempted']==4


@pytest.mark.parametrize('seeded',[True,False])
def test_real_synthetic_canary_positive_and_secure_counterpart(tmp_path,seeded):
    from fuzzcore.directories import http_directory_probe
    from fuzzcore.file_canary import http_file_probe,CANARY
    spec=importlib.util.spec_from_file_location('canary_fixture',Path(__file__).resolve().parents[2]/'lab'/'server.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    class Handler(mod.Handler):allow_seeded_canary=seeded
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);t=threading.Thread(target=server.serve_forever);t.start()
    try:
        s,c=client(tmp_path)
        id=submit(c,directory_cases=['canary-v1']).json()['id']
        with httpx.Client(base_url=f'http://127.0.0.1:{server.server_port}',trust_env=False,follow_redirects=False) as transport:
            run_scan(id,s,lambda _:pytest.fail('wrong adapter'),pause=lambda _:None,directory_probe=http_directory_probe(transport),file_probe=http_file_probe(transport))
        detail=c.get('/v1/scans/'+id).json()
        assert detail['status']=='completed' and detail['attempted']==detail['planned']==7
        rows=c.get('/v1/scans/'+id+'/findings').json()
        found=[f for f in rows if f['evidence'].get('rule_id')=='fixture-path-allowlist-v1']
        assert len(found)==int(seeded)
        if seeded:
            assert found[0]['severity']=='medium' and found[0]['confidence']=='fixture-confirmed'
            assert CANARY.decode() not in json.dumps(found[0])
            assert 'no host files' in found[0]['summary']
        assert len(rows)==3+int(seeded)
        # Retest cannot silently remove the additional case snapshot.
        assert submit(c,key='canary-retest-001',retest_of=id).status_code==422
        retest=submit(c,key='canary-retest-001',retest_of=id,directory_cases=['canary-v1'])
        assert retest.status_code==202
    finally:server.shutdown();server.server_close();t.join()


def test_file_gateway_pins_three_named_cases_and_retains_no_canary():
    from fuzzcore.file_canary import CANARY,PUBLIC
    from fuzzcore.scanner import create_scanner
    seen=[]
    def handler(request):
        seen.append(request)
        name=request.url.params['name']
        return httpx.Response(200 if name in ('public.txt','../canary.txt') else 403,content=PUBLIC if name=='public.txt' else CANARY if name=='../canary.txt' else b'denied')
    c=TestClient(create_scanner(httpx.MockTransport(handler),delay=lambda _:None))
    assert c.get('/file-canary',params={'case':'http://outside.invalid'}).status_code==422
    for name in ['public','denied','canary']:
        r=c.get('/file-canary',params={'case':name});assert r.status_code==200
        assert 'FUZZCORE_SYNTHETIC' not in r.text and len(r.json()['body_sha256'])==64
    assert len(seen)==3 and all(r.url.host=='lab' and r.url.port==8081 and r.url.path=='/file-fixture' for r in seen)


def test_canary_requires_exact_marker_positive_and_denied_controls():
    from fuzzcore.file_canary import assess
    correct={'status_code':200,'known_marker':True,'body_sha256':'a'*64,'bytes':1}
    values={'public':correct,'denied':{**correct,'status_code':403,'known_marker':False},'canary':correct}
    assert assess(values) is not None
    for case,change in [('public',{'known_marker':False}),('denied',{'status_code':200}),('canary',{'known_marker':False}),('canary',{'status_code':302})]:
        assert assess({**values,case:{**values[case],**change}}) is None
    assert assess({'canary':correct}) is None


def test_canary_cancellation_stops_remaining_cases_and_retains_partial(tmp_path):
    s,c=client(tmp_path)
    id=submit(c,directory_cases=['canary-v1']).json()['id']
    def file_probe(case):
        c.post('/v1/scans/'+id+'/cancel')
        return {'status_code':200,'known_marker':True,'body_sha256':'a'*64,'bytes':1}
    run_scan(id,s,lambda p:404 if p==PATHS[-1] else 200,pause=lambda _:None,file_probe=file_probe)
    row=c.get('/v1/scans/'+id).json()
    assert row['status']=='cancelled' and row['attempted']==5
    assert c.get('/v1/scans/'+id+'/report.json').json()['partial'] is True


def test_file_adapter_rejects_unknown_cases_and_oversized_body():
    from fuzzcore.file_canary import http_file_probe
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(lambda _:httpx.Response(200,content=b'x'*20000))) as transport:
        probe=http_file_probe(transport)
        with pytest.raises(ValueError):probe('canary')
        with pytest.raises(ValueError):probe('outside')


def test_worker_rejects_unknown_persisted_directory_case_before_traffic(tmp_path):
    s,c=client(tmp_path)
    id=submit(c).json()['id']
    with s() as db:
        row=db.get(Scan,id);row.directory_cases='["unknown-v1"]';db.commit()
    run_scan(id,s,lambda _:pytest.fail('Unknown persisted selection made traffic'),pause=lambda _:None,file_probe=lambda _:pytest.fail('Unknown fixture made traffic'))
    row=c.get('/v1/scans/'+id).json()
    assert row['status']=='failed' and row['attempted']==0


def test_default_and_explicit_canary_maximum_plans_are_different(tmp_path):
    s,c=client(tmp_path)
    extra={'modules':['directories','vhosts','api','parameters','custom','subdomains'],'custom_cases':[{'path':'/health','contains':'fixture'}]*3}
    old=submit(c,key='old-max-plan-001',**extra);assert old.status_code==202
    oldid=old.json()['id'];assert c.get('/v1/scans/'+oldid).json()['planned']==25
    c.post('/v1/scans/'+oldid+'/cancel')
    new=submit(c,key='new-max-plan-002',directory_cases=['canary-v1'],**extra);assert new.status_code==202
    row=c.get('/v1/scans/'+new.json()['id']).json()
    assert row['planned']==28 and row['module_progress']['directories']['planned']==7

import hashlib
import json
import threading
import importlib.util
from pathlib import Path
from http.server import ThreadingHTTPServer
import httpx
import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from fuzzcore.custom_cases import CustomCase,canonical,version,http_custom_probe
from fuzzcore.scanner import create_scanner
from fuzzcore.core import database,run_scan
from fuzzcore.api import create_app

OLD={'path':'/health','method':'GET','params':{},'expect_status':200,'contains':'fixture'}
POST={'path':'/custom-disposable','method':'POST','params':{},'body':{'marker':'harmless-marker'},'expect_status':200,'contains':'fixture','expect_headers':{'content-type':'application/json','x-fixture-mode':'disposable'}}


def test_new_fields_preserve_old_canonical_snapshot_and_hash():
    old=json.dumps([OLD],sort_keys=True,separators=(',',':'))
    assert canonical([OLD])==old
    assert version([OLD])==hashlib.sha256(old.encode()).hexdigest()
    assert canonical([POST])!=old and json.loads(canonical([POST]))==[POST]


@pytest.mark.parametrize('change',[
 {'path':'/health'}, {'path':'https://outside.invalid/'}, {'method':'DELETE'},
 {'body':{'marker':'<script>'}}, {'body':{'marker':'x'*65}}, {'body':{'path':'/tmp/file'}},
 {'expect_headers':{'set-cookie':'value'}}, {'expect_headers':{'content-type':'x'*65}},
 {'headers':{'Authorization':'not-allowed'}}, {'params':{'q':'marker'}},
])
def test_post_and_header_schema_rejects_expanded_authority(change):
    with pytest.raises(ValidationError):CustomCase.model_validate({**POST,**change})


def test_get_rejects_body_and_post_requires_named_disposable_body():
    for value in [{**OLD,'body':{'marker':'ok'}},{**POST,'body':None},{**POST,'body':{}},{**POST,'method':'GET'}]:
        with pytest.raises(ValidationError):CustomCase.model_validate(value)


def test_probe_sends_only_declarative_marker_and_records_safe_header_results():
    seen=[]
    def handle(request):
        seen.append(request)
        return httpx.Response(200,headers={'content-type':'application/json','x-fixture-mode':'disposable','set-cookie':'not-for-evidence'},content=b'fixture private response')
    c=TestClient(create_scanner(httpx.MockTransport(handle),delay=lambda _:None))
    r=c.post('/custom-check',json=POST)
    assert r.status_code==200 and r.json()['passed'] is True
    assert seen[0].method=='POST' and str(seen[0].url)=='http://lab:8081/custom-disposable'
    assert json.loads(seen[0].content)=={'marker':'harmless-marker'}
    assert r.json()['headers_matched'] is True and set(r.json()['header_checks'])=={'content-type','x-fixture-mode'}
    assert 'private response' not in r.text and 'not-for-evidence' not in r.text
    assert c.post('/custom-check',json={**POST,'path':'/health'}).status_code==422
    assert len(seen)==1


@pytest.mark.parametrize('headers,status',[( {'content-type':'text/plain','x-fixture-mode':'disposable'},200),({'content-type':'application/json'},200),({'content-type':'application/json','x-fixture-mode':'disposable'},302)])
def test_header_mismatch_missing_or_redirect_is_not_pass(headers,status):
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(lambda _:httpx.Response(status,headers=headers,content=b'fixture')),follow_redirects=False) as c:
        assert http_custom_probe(c)(POST)['passed'] is False


def test_real_disposable_post_and_header_expectation_share_unchanged_budget(tmp_path):
    spec=importlib.util.spec_from_file_location('custom_post_fixture',Path(__file__).resolve().parents[2]/'lab'/'server.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    server=ThreadingHTTPServer(('127.0.0.1',0),mod.Handler);thread=threading.Thread(target=server.serve_forever);thread.start()
    try:
        s=database('sqlite:///'+str(tmp_path/'post.db'))
        c=TestClient(create_app(s,lambda _:None,'fixture-token-post-not-secret'),headers={'Authorization':'Bearer fixture-token-post-not-secret'})
        body={'target_id':'local-lab','authorization_confirmed':True,'modules':['custom'],'custom_cases':[OLD,POST,{**POST,'expect_headers':{'x-fixture-mode':'secure'}}]}
        r=c.post('/v1/scans',json=body,headers={'Idempotency-Key':'custom-post-test-001'});assert r.status_code==202
        id=r.json()['id']
        with httpx.Client(base_url=f'http://127.0.0.1:{server.server_port}',trust_env=False,follow_redirects=False) as client:
            run_scan(id,s,lambda _:pytest.fail('wrong module'),pause=lambda _:None,custom_probe=http_custom_probe(client))
        detail=c.get('/v1/scans/'+id).json()
        assert detail['status']=='completed' and detail['attempted']==detail['planned']==3
        findings=c.get('/v1/scans/'+id+'/findings').json()
        assert sorted(f['evidence']['passed'] for f in findings)==[False,True,True]
        assert all(f['severity']=='informational' for f in findings)
        assert detail['custom_cases']==body['custom_cases']
        assert c.post('/v1/scans',json={**body,'custom_cases':[OLD]},headers={'Idempotency-Key':'custom-post-test-001'}).status_code==409
    finally:server.shutdown();server.server_close();thread.join()


def test_capabilities_expose_exact_declarative_post_limits(tmp_path):
    s=database('sqlite:///'+str(tmp_path/'cap.db'))
    c=TestClient(create_app(s,lambda _:None,'fixture-token-post-not-secret'),headers={'Authorization':'Bearer fixture-token-post-not-secret'})
    schema=c.get('/v1/capabilities').json()['custom_case_schema']
    assert schema=={'version':'declarative-v2','methods':['GET','POST'],'post_paths':['/custom-disposable'],'response_header_names':['content-type','x-fixture-mode'],'max_body_marker_length':64,'max_cases':3}

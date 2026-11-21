import pytest
import httpx
from fastapi.testclient import TestClient
from fuzzcore.api import create_app
from fuzzcore.core import database,run_scan
TOKEN='custom-fixture-tests-not-secret'
CASE={'path':'/health','method':'GET','params':{},'expect_status':200,'contains':'fixture'}


def client(tmp_path):
    sessions=database('sqlite:///'+str(tmp_path/'custom.db'))
    return sessions,TestClient(create_app(sessions,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})


def submit(c,cases,key='custom-case-test'):
    return c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':['custom'],'custom_cases':cases},headers={'Idempotency-Key':key})


@pytest.mark.parametrize('change',[
    {'path':'http://external.invalid/'},{'path':'//external.invalid/'},{'path':'/../etc/passwd'},
    {'method':'POST'},{'shell':'echo test'},{'expect_status':500},{'contains':'x'*100},
    {'params':{'url':'http://external.invalid'}},{'params':{'q':'x'*100}},
    {'params':{'q':'<script>'}},{'headers':{'Authorization':'private'}},
])
def test_custom_schema_rejects_unsafe_fields_before_queue(tmp_path,change):
    from fuzzcore.custom_cases import CustomCase
    from pydantic import ValidationError
    assert CustomCase.model_validate(CASE).path=='/health'
    with pytest.raises(ValidationError):CustomCase.model_validate({**CASE,**change})
    s,c=client(tmp_path)
    assert submit(c,[{**CASE,**change}]).status_code==422
    assert c.get('/v1/scans').json()==[]


def test_custom_case_count_and_module_scope_are_strict(tmp_path):
    s,c=client(tmp_path)
    for cases in [[],[CASE]*4]:assert submit(c,cases).status_code==422
    body={'target_id':'local-lab','authorization_confirmed':True,'modules':['directories'],'custom_cases':[CASE]}
    assert c.post('/v1/scans',json=body,headers={'Idempotency-Key':'extra-custom-test'}).status_code==422


def test_custom_case_snapshot_version_and_retry_are_immutable(tmp_path):
    from fuzzcore.custom_cases import http_custom_probe
    s,c=client(tmp_path)
    r=submit(c,[CASE]);assert r.status_code==202
    scan=r.json()['id'];detail=c.get('/v1/scans/'+scan).json()
    assert detail['custom_cases']==[CASE] and len(detail['case_version'])==64 and detail['planned']==1
    assert submit(c,[{**CASE,'contains':'different'}]).status_code==409
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(lambda _:httpx.Response(200,content=b'{"fixture":true}'))) as transport:
        run_scan(scan,s,lambda _:pytest.fail('wrong surface'),pause=lambda _:None,custom_probe=http_custom_probe(transport))
    detail=c.get('/v1/scans/'+scan).json();assert detail['attempted']==1 and detail['status']=='completed'
    findings=c.get('/v1/scans/'+scan+'/findings').json()
    assert len(findings)==1 and findings[0]['module']=='custom'
    assert findings[0]['evidence']['passed'] is True and findings[0]['confidence']=='observed'
    assert findings[0]['evidence']['case_version']==detail['case_version']


def test_gateway_revalidates_pins_and_redacts_custom_text():
    from fuzzcore.scanner import create_scanner
    seen=[]
    def handler(request):
        seen.append(request);return httpx.Response(200,content=b'fixture secret-response-content')
    c=TestClient(create_scanner(httpx.MockTransport(handler),delay=lambda _:None))
    assert c.post('/custom-check',json={**CASE,'path':'https://external.invalid'}).status_code==422
    r=c.post('/custom-check',json=CASE)
    assert r.status_code==200 and r.json()['passed'] is True
    assert 'secret-response-content' not in r.text
    assert str(seen[0].url)=='http://lab:8081/health' and len(seen)==1


def test_custom_mismatch_redirect_and_body_limit_are_not_passes():
    from fuzzcore.custom_cases import http_custom_probe
    for status,body in [(404,b'fixture'),(302,b'fixture'),(200,b'other')]:
        with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(lambda _:httpx.Response(status,content=body)),follow_redirects=False) as c:
            assert http_custom_probe(c)(CASE)['passed'] is False
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(lambda _:httpx.Response(200,content=b'x'*20000))) as c:
        with pytest.raises(ValueError):http_custom_probe(c)(CASE)


def test_real_custom_fixture_and_mismatch_remain_informational(tmp_path):
    import importlib.util,threading
    from pathlib import Path
    from http.server import ThreadingHTTPServer
    from fuzzcore.custom_cases import http_custom_probe
    spec=importlib.util.spec_from_file_location('custom_fixture',Path(__file__).resolve().parents[2]/'lab'/'server.py')
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    server=ThreadingHTTPServer(('127.0.0.1',0),fixture.Handler)
    thread=threading.Thread(target=server.serve_forever);thread.start()
    try:
        s,c=client(tmp_path)
        cases=[CASE,{**CASE,'path':'/custom-fixture','contains':'ready'},{**CASE,'expect_status':404}]
        scan=submit(c,cases).json()['id']
        with httpx.Client(base_url=f'http://127.0.0.1:{server.server_port}',trust_env=False,follow_redirects=False) as transport:
            run_scan(scan,s,lambda _:pytest.fail('wrong surface'),pause=lambda _:None,custom_probe=http_custom_probe(transport))
        row=c.get('/v1/scans/'+scan).json()
        assert row['attempted']==row['planned']==3
        findings=c.get('/v1/scans/'+scan+'/findings').json()
        assert sorted(f['evidence']['passed'] for f in findings)==[False,True,True]
        assert all(f['severity']=='informational' for f in findings)
    finally:
        server.shutdown();server.server_close();thread.join()

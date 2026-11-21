"""Two-identity fixture proof. No arbitrary endpoints, actors or credentials."""
import importlib.util
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer

import httpx
import pytest
from fastapi.testclient import TestClient
from fuzzcore.api import create_app
from fuzzcore.core import database, run_scan

TOKEN='fixture-api-test-token-not-secret'


def proven_results():
    return {
        'missing':{'status_code':404},
        'anonymous':{'status_code':401},
        'alice-own':{'status_code':200,'fixture':True,'owner':'alice','object':'alice-owned'},
        'alice-denied':{'status_code':403},
        'bob-own':{'status_code':200,'fixture':True,'owner':'bob','object':'bob-vulnerable'},
        'alice-cross':{'status_code':200,'fixture':True,'owner':'bob','object':'bob-vulnerable'},
    }


@pytest.mark.parametrize('fault', ['anonymous','alice-own','alice-denied','bob-own','alice-cross','fixture-marker'])
def test_authz_does_not_claim_a_defect_without_controls(fault):
    from fuzzcore.api_checks import assess
    data=proven_results()
    if fault=='fixture-marker':data['alice-cross']['fixture']=False
    else:data[fault]={'status_code':200 if fault in ('anonymous','alice-denied') else 403}
    assert assess(data) is None


def test_authz_rule_identifies_only_the_seeded_cross_owner_fixture():
    from fuzzcore.api_checks import assess
    result=assess(proven_results())
    assert result['rule_id']=='fixture-object-ownership-v1'
    assert result['severity']=='high' and result['confidence']=='fixture-confirmed'
    assert result['path']=='/api/fixture/objects/bob-vulnerable'


def test_api_gateway_allows_only_fixed_cases_and_no_user_token_forwarding():
    from fuzzcore.scanner import create_scanner
    from fuzzcore.api_checks import CASES
    seen=[]
    def handler(request):
        seen.append(request)
        return httpx.Response(200,json={'fixture':True,'owner':'alice','object':'alice-owned','secret':'not-for-evidence'})
    c=TestClient(create_scanner(httpx.MockTransport(handler),delay=lambda _:None))
    assert c.get('/api-check',params={'case':'https://external.invalid'}).status_code==422
    for case in CASES:
        response=c.get('/api-check',params={'case':case})
        assert response.status_code==200 and 'not-for-evidence' not in response.text
    assert len(seen)==6 and all(r.url.host=='lab' and r.url.port==8081 for r in seen)
    assert all('authorization' not in r.headers for r in seen)
    assert {r.headers.get('x-fixture-actor') for r in seen}=={None,'alice','bob'}


@pytest.mark.parametrize('secure', [False,True])
def test_api_fixture_end_to_end_records_proof_and_combined_budget(tmp_path, secure):
    from fuzzcore.api_checks import http_api_probe
    spec=importlib.util.spec_from_file_location('api_fixture',Path(__file__).resolve().parents[2]/'lab'/'server.py')
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    fixture.Handler.allow_seeded_cross_owner = not secure
    server=ThreadingHTTPServer(('127.0.0.1',0),fixture.Handler)
    thread=threading.Thread(target=server.serve_forever);thread.start()
    try:
        sessions=database('sqlite:///'+str(tmp_path/'api.db'))
        c=TestClient(create_app(sessions,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
        body={'target_id':'local-lab','authorization_confirmed':True,'modules':['api']}
        response=c.post('/v1/scans',json=body,headers={'Idempotency-Key':'api-fixture-001'})
        assert response.status_code==202
        scan=response.json()['id']
        with httpx.Client(base_url=f'http://127.0.0.1:{server.server_port}',trust_env=False,follow_redirects=False) as client:
            run_scan(scan,sessions,lambda _:pytest.fail('unexpected directory probe'),pause=lambda _:None,api_probe=http_api_probe(client))
        row=c.get('/v1/scans/'+scan).json()
        assert row['status']=='completed' and row['attempted']==row['planned']==6
        findings=c.get('/v1/scans/'+scan+'/findings').json()
        assert len(findings)==(0 if secure else 1)
        if not secure:
            assert findings[0]['module']=='api'
            assert findings[0]['severity']=='high' and findings[0]['confidence']=='fixture-confirmed'
            assert findings[0]['evidence']['rule_id']=='fixture-object-ownership-v1'
        assert 'secret' not in str(findings)
        response=c.post('/v1/scans',json={**body,'modules':['directories','vhosts','api']},headers={'Idempotency-Key':'api-combined-002'})
        assert c.get('/v1/scans/'+response.json()['id']).json()['planned']==13
    finally:
        server.shutdown();server.server_close();thread.join()


def test_api_body_budget_and_html_false_positive_are_rejected():
    from fuzzcore.api_checks import http_api_probe
    for content in [b'x'*20000,b'<html>login form</html>']:
        with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(lambda _:httpx.Response(200,content=content))) as client:
            if len(content)>16384:
                with pytest.raises(ValueError):http_api_probe(client)('alice-cross')
            else:
                result=http_api_probe(client)('alice-cross')
                assert result['fixture'] is False


def test_failed_api_attempt_is_counted_and_never_retried_automatically(tmp_path):
    sessions=database('sqlite:///'+str(tmp_path/'failed-attempt.db'))
    c=TestClient(create_app(sessions,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    scan=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':['api']},headers={'Idempotency-Key':'api-failed-attempt'}).json()['id']
    calls=[]
    def failed(case):
        calls.append(case)
        raise httpx.ReadTimeout('private fixture exception detail')
    run_scan(scan,sessions,lambda _:pytest.fail('wrong module'),pause=lambda _:None,api_probe=failed)
    row=c.get('/v1/scans/'+scan).json()
    assert row['status']=='failed' and row['attempted']==1 and row['error']=='probe_failed'
    assert 'private fixture' not in str(row)
    run_scan(scan,sessions,lambda _:pytest.fail('terminal replay'),api_probe=failed)
    assert len(calls)==1

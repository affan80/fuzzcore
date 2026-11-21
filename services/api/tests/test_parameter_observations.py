import httpx
import pytest
from fuzzcore.parameters import CASES,ALPHA,BETA,http_parameter_probe,assess


def results(mode='normal'):
    def handler(request):
        values=request.url.params.get_list('q')
        body={'fixture':True,'values':values,'validation_value':values[0] if values else None,'effective_value':values[-1] if values else None,'private':'untrusted-private-text'}
        if mode!='mismatch':body['effective_value']=body['validation_value']
        status=500 if mode=='error' and values==[ALPHA+'\'"'] else 200
        if mode=='error':body['error_kind']='synthetic_parse_error' if status==500 else None
        return httpx.Response(status,json=body)
    with httpx.Client(base_url='http://lab:8081',transport=httpx.MockTransport(handler)) as client:
        return {case:http_parameter_probe(client)(case) for case in CASES}


def test_known_parameter_recognition_is_grounded_by_distinct_marker_controls():
    findings=assess(results())
    assert findings and all(f['evidence']['parameter_discovery']=={'name':'q','scope':'fixed_fixture_only','distinct_marker_controls':True} for f in findings)
    assert 'untrusted-private-text' not in str(findings)


def test_duplicate_validation_and_use_mismatch_is_bounded_signal_not_bypass_proof():
    findings=assess(results('mismatch'))
    item=next(f for f in findings if f['evidence']['rule_id']=='parameter-parser-mismatch-signal-v1')
    assert 'not proof' in item['summary'] and item['status_code']==200
    assert item['evidence']['controls']['duplicate']['parser_mismatch'] is True
    assert 'untrusted-private-text' not in str(item)


def test_error_differential_preserves_http_status_and_does_not_claim_injection():
    findings=assess(results('error'))
    item=next(f for f in findings if f['evidence']['rule_id']=='parameter-error-differential-signal-v1')
    assert item['status_code']==500 and 'not proof' in item['summary']
    assert 'untrusted-private-text' not in str(item)


@pytest.mark.parametrize('mode',['normal','mismatch','error'])
def test_invalid_baseline_cannot_create_discovery_or_differential(mode):
    values=results(mode);values['baseline']['fixture']=False
    assert assess(values)==[]


def test_static_or_unrecognized_markers_do_not_create_parser_mismatch():
    values=results('mismatch');values['alpha']['exact_echo']=False
    assert not any(f['evidence']['rule_id']=='parameter-parser-mismatch-signal-v1' for f in assess(values))


@pytest.mark.parametrize('mode',['normal','mismatch','error'])
def test_real_http_fixture_worker_and_export_keep_bounded_status_evidence(tmp_path,mode):
    import importlib.util,threading
    from pathlib import Path
    from http.server import ThreadingHTTPServer
    from fastapi.testclient import TestClient
    from fuzzcore.api import create_app
    from fuzzcore.core import database,run_scan
    spec=importlib.util.spec_from_file_location('parameter_observation_fixture',Path(__file__).resolve().parents[2]/'lab'/'server.py')
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    fixture.Handler.parameter_parser_mismatch=mode=='mismatch';fixture.Handler.parameter_error_signal=mode=='error'
    server=ThreadingHTTPServer(('127.0.0.1',0),fixture.Handler);thread=threading.Thread(target=server.serve_forever);thread.start()
    try:
        token='parameter-observation-fixture-tests'
        sessions=database('sqlite:///'+str(tmp_path/'parameters.db'))
        c=TestClient(create_app(sessions,lambda _:None,token),headers={'Authorization':'Bearer '+token})
        scan=c.post('/v1/scans',json={'target_id':'local-lab','modules':['parameters'],'authorization_confirmed':True},headers={'Idempotency-Key':'parameter-observations-001'}).json()['id']
        with httpx.Client(base_url=f'http://127.0.0.1:{server.server_port}',follow_redirects=False,trust_env=False) as client:
            run_scan(scan,sessions,lambda _:pytest.fail('wrong probe'),pause=lambda _:None,parameter_probe=http_parameter_probe(client))
        state=c.get('/v1/scans/'+scan).json()
        assert state['status']=='completed' and state['attempted']==state['planned']==6
        report=c.get('/v1/scans/'+scan+'/report.json').json()
        assert len(report['findings'])==(3 if mode=='mismatch' else 2)
        assert all(f['severity']=='informational' and f['confidence']=='signal' for f in report['findings'])
        if mode=='error':assert next(f for f in report['findings'] if f['evidence']['rule_id']=='parameter-error-differential-signal-v1')['status_code']==500
    finally:server.shutdown();server.server_close();thread.join()


@pytest.mark.parametrize('mutation',['unlabelled','redirect','rate_limited','error_control'])
def test_error_differential_needs_named_error_and_successful_controls(mutation):
    values=results('error')
    if mutation=='unlabelled':values['quoted']['synthetic_parse_error']=False
    if mutation=='redirect':values['quoted']['status_code']=302
    if mutation=='rate_limited':values['encoded']['status_code']=429
    if mutation=='error_control':values['baseline']['status_code']=500
    assert not any(f['evidence']['rule_id']=='parameter-error-differential-signal-v1' for f in assess(values))

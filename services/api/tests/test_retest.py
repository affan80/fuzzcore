from fastapi.testclient import TestClient
from fuzzcore.api import create_app
from fuzzcore.core import Scan,database,run_scan
TOKEN='retest-fixture-token-tests-only'


def setup(tmp_path):
    s=database('sqlite:///'+str(tmp_path/'retest.db'))
    c=TestClient(create_app(s,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    body={'target_id':'local-lab','authorization_confirmed':True,'modules':['directories']}
    old=c.post('/v1/scans',json=body,headers={'Idempotency-Key':'retest-original'}).json()['id']
    return s,c,body,old


def test_retest_requires_new_explicit_authorization_and_same_case_snapshot(tmp_path):
    s,c,body,old=setup(tmp_path)
    run_scan(old,s,lambda _:200,pause=lambda _:None)
    url='/v1/scans'
    assert c.post(url,json={**body,'retest_of':old,'authorization_confirmed':False},headers={'Idempotency-Key':'retest-without-consent'}).status_code==422
    assert c.post(url,json={**body,'retest_of':old,'modules':['vhosts']},headers={'Idempotency-Key':'retest-wrong-scope'}).status_code==422
    r=c.post(url,json={**body,'retest_of':old},headers={'Idempotency-Key':'retest-confirmed'});assert r.status_code==202
    new=r.json()['id'];assert new!=old
    assert c.get('/v1/scans/'+new).json()['retest_of']==old
    run_scan(new,s,lambda _:404,pause=lambda _:None)
    comparison=c.get('/v1/scans/'+new+'/retest-comparison').json()
    assert comparison['original_scan_id']==old and comparison['retest_scan_id']==new
    assert len(comparison['not_observed'])==4 and comparison['still_observed']==[]
    assert comparison['conclusion']=='No automatic fixed or secure state. Review matched scope and evidence.'
    assert all(f['review_state']=='open' for f in c.get('/v1/scans/'+old+'/findings').json())
    assert c.get('/v1/scans/'+old+'/retest-comparison').status_code==409


def test_retest_cannot_relabel_idempotent_run_or_cross_owner(tmp_path):
    s,c,body,old=setup(tmp_path)
    assert c.post('/v1/scans',json={**body,'retest_of':old},headers={'Idempotency-Key':'retest-active-old'}).status_code==409
    run_scan(old,s,lambda _:404,pause=lambda _:None)
    assert c.post('/v1/scans',json={**body,'retest_of':old},headers={'Idempotency-Key':'retest-original'}).status_code==409
    with s() as db:db.get(Scan,old).owner='other';db.commit()
    assert c.post('/v1/scans',json={**body,'retest_of':old},headers={'Idempotency-Key':'retest-cross-owner'}).status_code==404

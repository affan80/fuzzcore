import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from fuzzcore.api import create_app
from fuzzcore.core import database,Scan
from fuzzcore.custom_cases import version
TOKEN='saved-case-fixture-tests-only-token'
CASES=[{'path':'/health','method':'GET','params':{},'expect_status':200,'contains':'fixture'}]


def setup(tmp_path):
    s=database('sqlite:///'+str(tmp_path/'cases.db'));enqueued=[]
    c=TestClient(create_app(s,enqueued.append,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    return s,c,enqueued


def save(c,**extra):return c.post('/v1/custom-cases',json={'name':'Health smoke','cases':CASES,**extra})


def test_save_list_retrieve_immutable_validated_version_without_running(tmp_path):
    s,c,enqueued=setup(tmp_path);r=save(c);assert r.status_code==201,r.text
    first=r.json();assert first['version']==version(CASES) and first['schema_version']=='declarative-v2'
    assert first['name']=='Health smoke' and first['created_at'] and first['id']
    assert c.get('/v1/custom-cases').json()==[first]
    assert c.get('/v1/custom-cases/'+first['id']).json()==first
    assert enqueued==[] and c.get('/v1/scans').json()==[]
    assert c.patch('/v1/custom-cases/'+first['id'],json={'name':'changed'}).status_code==405
    assert c.delete('/v1/custom-cases/'+first['id']).status_code==405


def test_duplicate_save_is_idempotent_new_content_preserves_old_version(tmp_path):
    s,c,_=setup(tmp_path);first=save(c).json();again=save(c)
    assert again.status_code==200 and again.json()==first
    new=save(c,cases=[{**CASES[0],'contains':'different'}]);assert new.status_code==201
    assert new.json()['version']!=first['version'] and new.json()['id']!=first['id']
    assert c.get('/v1/custom-cases/'+first['id']).json()==first
    assert len(c.get('/v1/custom-cases').json())==2


@pytest.mark.parametrize('extra',[{'name':''},{'name':' '*3},{'name':'x'*81},{'name':'bad\nlabel'},{'cases':[]},{'cases':CASES*4},{'cases':[{'path':'http://outside.invalid'}]},{'cases':[{'path':'/custom-fixture','method':'POST'}]},{'cases':[{'path':'/health','run':'anything'}]},{'code':'x'}])
def test_saved_validation_rejects_invalid_content_without_enqueue(tmp_path,extra):
    _,c,enqueued=setup(tmp_path);assert save(c,**extra).status_code==422
    assert c.get('/v1/custom-cases').json()==[] and enqueued==[]


def test_owner_and_auth_apply_to_list_and_individual_versions(tmp_path):
    from fuzzcore.core import SavedCaseVersion
    s,c,_=setup(tmp_path);first=save(c).json()
    for path in ('/v1/custom-cases','/v1/custom-cases/'+first['id']):
        assert c.get(path,headers={'Authorization':''}).status_code==401
    assert c.post('/v1/custom-cases',json={'name':'Health','cases':CASES},headers={'Authorization':''}).status_code==401
    with s() as db:db.get(SavedCaseVersion,first['id']).owner='other';db.commit()
    assert c.get('/v1/custom-cases').json()==[]
    assert c.get('/v1/custom-cases/'+first['id']).status_code==404
    own=save(c).json();assert own['id']!=first['id']


def test_saved_selection_is_copied_to_run_not_mutable_reference(tmp_path):
    from fuzzcore.core import SavedCaseVersion
    from fuzzcore.custom_cases import canonical
    s,c,enqueued=setup(tmp_path);saved=save(c).json()
    body={'target_id':'local-lab','authorization_confirmed':True,'modules':['custom'],'custom_cases':saved['cases']}
    r=c.post('/v1/scans',json=body,headers={'Idempotency-Key':'saved-version-run-001'});assert r.status_code==202
    id=r.json()['id'];row=c.get('/v1/scans/'+id).json()
    assert row['case_version']==saved['version'] and row['planned']==1
    save(c,cases=[{**CASES[0],'contains':'new'}])
    assert c.get('/v1/scans/'+id).json()['case_version']==saved['version']
    assert enqueued==[id]


def test_saved_versions_storage_and_list_are_bounded(tmp_path):
    from fuzzcore.core import SavedCaseVersion
    s,c,_=setup(tmp_path)
    with s() as db:
        for i in range(100):db.add(SavedCaseVersion(id='case-'+str(i),owner='demo',name='name-'+str(i),slot=i,case_version=str(i),cases=json.dumps(CASES)))
        db.commit()
    assert len(c.get('/v1/custom-cases').json())==50
    r=save(c);assert r.status_code==409 and r.json()['detail']=='saved_case_limit_reached'
    assert c.get('/v1/capabilities').json()['saved_custom_cases']=={'supported':True,'immutable':True,'max_versions':100,'list_limit':50,'max_cases_per_version':3}


def test_migration_adds_empty_saved_case_table_without_changing_run(tmp_path):
    s,c,_=setup(tmp_path)
    r=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True},headers={'Idempotency-Key':'before-saved-upgrade'})
    id=r.json()['id'];before=c.get('/v1/scans/'+id).json()
    with s() as db:
        db.execute(text('DROP TABLE saved_case_versions'));db.execute(text('DELETE FROM schema_migrations WHERE version>=13'));db.commit()
    s=database('sqlite:///'+str(tmp_path/'cases.db'));c=TestClient(create_app(s,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    assert c.get('/v1/custom-cases').json()==[] and c.get('/v1/scans/'+id).json()==before
    with s() as db:assert db.execute(text('SELECT max(version) FROM schema_migrations')).scalar()==15


def test_listing_cursor_reaches_older_versions_and_cannot_cross_owner(tmp_path):
    from fuzzcore.core import SavedCaseVersion
    s,c,_=setup(tmp_path)
    with s() as db:
        for i in range(60):db.add(SavedCaseVersion(id='case-'+str(i).zfill(2),owner='demo',name='n'+str(i),slot=i,case_version=str(i),cases=json.dumps(CASES),created_at='2026-11-21T10:00:00+00:00'))
        db.add(SavedCaseVersion(id='other-cursor',owner='other',name='private',slot=0,case_version='other',cases=json.dumps(CASES)));db.commit()
    page=c.get('/v1/custom-cases').json();assert len(page)==50
    older=c.get('/v1/custom-cases',params={'after_id':page[-1]['id']}).json()
    assert len(older)==10 and len({v['id'] for v in page+older})==60
    assert c.get('/v1/custom-cases',params={'after_id':'other-cursor'}).status_code==404
    assert c.get('/v1/custom-cases',params={'after_id':'unknown'}).status_code==404


def test_concurrent_duplicate_saves_share_one_immutable_id(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    s,c,_=setup(tmp_path)
    def submit(_):
        client=TestClient(c.app,headers={'Authorization':'Bearer '+TOKEN})
        r=save(client);assert r.status_code in (200,201);return r.json()['id']
    with ThreadPoolExecutor(max_workers=6) as pool:ids=list(pool.map(submit,range(6)))
    assert len(set(ids))==1 and len(c.get('/v1/custom-cases').json())==1


def test_slot_constraints_bound_concurrent_near_limit_saves(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from fuzzcore.core import SavedCaseVersion
    s,c,_=setup(tmp_path)
    with s() as db:
        for i in range(99):db.add(SavedCaseVersion(id='pre-'+str(i),owner='demo',name='pre-'+str(i),case_version=str(i),cases=json.dumps(CASES),slot=i))
        db.commit()
    def submit(i):
        client=TestClient(c.app,headers={'Authorization':'Bearer '+TOKEN})
        return save(client,name='concurrent-'+str(i)).status_code
    with ThreadPoolExecutor(max_workers=4) as pool:codes=list(pool.map(submit,range(4)))
    assert codes.count(201)==1 and codes.count(409)==3
    with s() as db:assert len(list(db.query(SavedCaseVersion).filter_by(owner='demo')))==100

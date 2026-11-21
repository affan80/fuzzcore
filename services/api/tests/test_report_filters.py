import json
import pytest
from fastapi.testclient import TestClient
from fuzzcore.api import create_app
from fuzzcore.core import Scan,Finding,database,run_scan
TOKEN='filtered-report-test-fixture-token'


def setup(tmp_path):
    s=database('sqlite:///'+str(tmp_path/'review.db'));c=TestClient(create_app(s,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    body={'target_id':'local-lab','authorization_confirmed':True}
    id=c.post('/v1/scans',json=body,headers={'Idempotency-Key':'filter-original-001'}).json()['id']
    run_scan(id,s,lambda _:404,pause=lambda _:None)
    with s() as db:
        for id2,module,severity,confidence,state in [('api-high','api','high','fixture-confirmed','open'),('dir-low','directories','informational','observed','acknowledged'),('param-signal','parameters','informational','signal','open')]:
            db.add(Finding(id=id2,scan_id=id,path='/'+id2,status_code=200,module=module,severity=severity,confidence=confidence,review_state=state,summary='Fixture data, not secure',evidence=json.dumps({'rule_id':id2+'-v1'})))
        db.commit()
    return s,c,body,id


def test_filters_apply_to_findings_json_html_and_snapshot_with_matching_totals(tmp_path):
    s,c,_,id=setup(tmp_path);prefix='/v1/scans/'+id
    q='?severity=high&module=api&confidence=fixture-confirmed&review_state=open'
    found=c.get(prefix+'/findings'+q).json();assert [v['id'] for v in found]==['api-high']
    report=c.get(prefix+'/report.json'+q).json()
    assert report['totals']['findings']==1 and report['totals']['severity']=={'high':1}
    assert report['filters']=={'severity':'high','module':'api','confidence':'fixture-confirmed','review_state':'open'}
    assert report['unfiltered_findings']==3 and report['filtered'] is True
    html=c.get(prefix+'/report.html'+q).text
    assert '/api-high' in html and '/dir-low' not in html and '/param-signal' not in html
    assert 'Report filters' in html
    snap=c.post(prefix+'/report-snapshots'+q);assert snap.status_code==201
    saved=c.get('/v1/report-snapshots/'+snap.json()['id']).json()['report']
    assert saved['filters']==report['filters'] and saved['totals']==report['totals']
    assert c.get(prefix+'/report.json?severity=low').json()['totals']['findings']==0
    assert c.get(prefix+'/report.json').json()['totals']['findings']==3


@pytest.mark.parametrize('query',['severity=critical','confidence=proven','module=outside','review_state=secure'])
def test_invalid_filters_are_rejected_consistently(tmp_path,query):
    _,c,_,id=setup(tmp_path)
    for suffix in ('findings','report.json','report.html'):
        assert c.get('/v1/scans/'+id+'/'+suffix+'?'+query).status_code==422
    assert c.post('/v1/scans/'+id+'/report-snapshots?'+query).status_code==422


def retest(c,body,old,key='filter-retest-001'):
    r=c.post('/v1/scans',json={**body,'retest_of':old},headers={'Idempotency-Key':key});assert r.status_code==202
    return r.json()['id']


def test_fixed_review_requires_manual_note_and_complete_same_scope_linked_retest(tmp_path):
    s,c,body,id=setup(tmp_path);url='/v1/scans/'+id+'/findings/api-high/review'
    assert c.patch(url,json={'state':'fixed'}).status_code==422
    new=retest(c,body,id)
    assert c.patch(url,json={'state':'fixed','note':'Reviewed manually','retest_scan_id':new}).status_code==409
    run_scan(new,s,lambda _:404,pause=lambda _:None)
    before=c.get('/v1/scans/'+id+'/findings').json();assert all(v['review_state']!='fixed' for v in before)
    r=c.patch(url,json={'state':'fixed','note':'Manual fixture fix and same-scope absence reviewed.','retest_scan_id':new})
    assert r.status_code==200,r.text
    row=r.json();assert row['review_state']=='fixed' and row['review_retest_id']==new and row['reviewed_at']
    assert row['severity']=='high' and row['confidence']=='fixture-confirmed'
    assert new in c.get('/v1/scans/'+id+'/report.html?review_state=fixed').text
    report=c.get('/v1/scans/'+id+'/report.json?review_state=fixed').json();assert report['totals']['findings']==1
    assert 'not a security certificate' in report['limitations']
    r=c.patch(url,json={'state':'open','note':'Reopened for follow-up.'});assert r.status_code==200
    assert r.json()['review_retest_id'] is None


def test_still_observed_partial_unrelated_or_foreign_retests_cannot_mark_fixed(tmp_path):
    s,c,body,id=setup(tmp_path);url='/v1/scans/'+id+'/findings/api-high/review';new=retest(c,body,id)
    run_scan(new,s,lambda _:404,pause=lambda _:None)
    with s() as db:
        db.add(Finding(id='same-new',scan_id=new,path='/api-high',status_code=200,module='api',severity='high',confidence='fixture-confirmed',evidence=json.dumps({'rule_id':'api-high-v1'}),summary='Still observed'));db.commit()
    payload={'state':'fixed','note':'Manual review','retest_scan_id':new}
    assert c.patch(url,json=payload).status_code==409
    with s() as db:db.delete(db.get(Finding,'same-new'));db.get(Scan,new).status='cancelled';db.commit()
    assert c.patch(url,json=payload).status_code==409
    with s() as db:db.get(Scan,new).status='completed';db.get(Scan,new).retest_of=None;db.commit()
    assert c.patch(url,json=payload).status_code==409
    with s() as db:db.get(Scan,new).retest_of=id;db.get(Scan,new).owner='other';db.commit()
    assert c.patch(url,json=payload).status_code==404


def test_filters_cannot_bypass_owner_or_corrupt_snapshot_scope(tmp_path):
    s,c,_,id=setup(tmp_path)
    snapshot=c.post('/v1/scans/'+id+'/report-snapshots?module=api').json()
    c.patch('/v1/scans/'+id+'/findings/api-high/review',json={'state':'acknowledged'})
    saved=c.get('/v1/report-snapshots/'+snapshot['id']).json()['report']
    assert saved['findings'][0]['review_state']=='open' and saved['filters']=={'module':'api'}
    with s() as db:db.get(Scan,id).owner='other';db.commit()
    assert c.get('/v1/scans/'+id+'/report.json?module=api').status_code==404
    assert c.get('/v1/scans/'+id+'/findings?module=api').status_code==404
    assert c.get('/v1/report-snapshots/'+snapshot['id']).status_code==404


def test_fixed_review_rejects_changed_snapshot_or_unverified_cleanup(tmp_path):
    s,c,body,id=setup(tmp_path);new=retest(c,body,id);run_scan(new,s,lambda _:404,pause=lambda _:None)
    url='/v1/scans/'+id+'/findings/api-high/review';payload={'state':'fixed','note':'Manual review','retest_scan_id':new}
    with s() as db:db.get(Scan,new).custom_cases='[{"path":"/health"}]';db.commit()
    assert c.patch(url,json=payload).status_code==409
    with s() as db:db.get(Scan,new).custom_cases='[]';db.get(Scan,new).cleanup_status='unverified';db.commit()
    assert c.patch(url,json=payload).status_code==409


def test_v13_migration_does_not_invent_fixed_review_evidence(tmp_path):
    from sqlalchemy import text
    s,c,_,id=setup(tmp_path)
    with s() as db:
        db.execute(text('DELETE FROM schema_migrations WHERE version>=14'))
        for column in ('review_retest_id','reviewed_at'):db.execute(text('ALTER TABLE findings DROP COLUMN '+column))
        db.commit()
    s=database('sqlite:///'+str(tmp_path/'review.db'))
    with s() as db:
        item=db.get(Finding,'api-high');assert item.review_state=='open' and item.review_retest_id is None and item.reviewed_at is None
        assert db.execute(text('SELECT max(version) FROM schema_migrations')).scalar()==14

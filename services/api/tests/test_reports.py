import json
from fastapi.testclient import TestClient
import pytest
from fuzzcore.api import create_app
from fuzzcore.core import Scan,Finding,database,run_scan
TOKEN='report-fixture-token-tests-only'


def setup(tmp_path):
    sessions=database('sqlite:///'+str(tmp_path/'reports.db'))
    c=TestClient(create_app(sessions,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    r=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True},headers={'Idempotency-Key':'report-first-scan'})
    return sessions,c,r.json()['id']


def test_authenticated_json_report_totals_scope_and_no_security_certificate(tmp_path):
    s,c,scan=setup(tmp_path)
    run_scan(scan,s,lambda _:200,pause=lambda _:None)
    r=c.get('/v1/scans/'+scan+'/report.json');assert r.status_code==200
    report=r.json()
    assert report['schema_version']=='report-v1' and report['scan']['id']==scan
    assert report['totals']['findings']==4 and report['totals']['severity']['informational']==4
    assert report['scan']['authorization_confirmed_at'] and report['scan']['target_id']=='local-lab'
    assert 'not a security certificate' in report['limitations']
    assert report['partial'] is False
    assert c.get('/v1/scans/'+scan+'/report.json',headers={'Authorization':''}).status_code==401
    with s() as db:db.get(Scan,scan).owner='other';db.commit()
    assert c.get('/v1/scans/'+scan+'/report.json').status_code==404


def test_html_report_escapes_source_strings_and_blocks_execution(tmp_path):
    s,c,scan=setup(tmp_path)
    run_scan(scan,s,lambda _:404,pause=lambda _:None)
    with s() as db:
        db.add(Finding(id='danger',scan_id=scan,path='<img src=x onerror=alert(1)>',status_code=200,summary='<script>bad()</script>',evidence=json.dumps({'rule_id':'<svg onload=alert(1)>'})))
        db.commit()
    r=c.get('/v1/scans/'+scan+'/report.html')
    assert r.status_code==200 and r.headers['content-type'].startswith('text/html')
    assert '<script>bad' not in r.text and '<img src=x' not in r.text
    assert '&lt;script&gt;bad' in r.text and '&lt;img' in r.text
    assert "default-src 'none'" in r.headers['content-security-policy']
    assert 'text/html' not in c.get('/v1/scans/'+scan+'/report.json').json()['limitations']


def test_partial_cancelled_empty_report_stays_honest(tmp_path):
    s,c,scan=setup(tmp_path)
    c.post('/v1/scans/'+scan+'/cancel')
    report=c.get('/v1/scans/'+scan+'/report.json').json()
    assert report['partial'] is True and report['totals']['findings']==0
    assert report['scan']['status']=='cancelled'
    assert 'secure' not in report['summary'].lower()


def test_review_states_validated_and_reports_reflect_review_not_automatic_fix(tmp_path):
    s,c,scan=setup(tmp_path)
    run_scan(scan,s,lambda _:200,pause=lambda _:None)
    finding=c.get('/v1/scans/'+scan+'/findings').json()[0]
    assert finding['review_state']=='open'
    url='/v1/scans/'+scan+'/findings/'+finding['id']+'/review'
    assert c.patch(url,json={'state':'fixed'}).status_code==422
    assert c.patch(url,json={'state':'acknowledged','note':'Reviewed fixture evidence.'}).status_code==200
    r=c.get('/v1/scans/'+scan+'/report.json').json()
    assert any(f['review_state']=='acknowledged' for f in r['findings'])
    assert c.patch(url,json={'state':'retest_requested','note':'Manual fixture change is ready.'}).status_code==200
    assert c.patch(url,json={'state':'open','note':'x'*501}).status_code==422
    assert c.patch(url,json={'state':'open','note':'ok','run':'shell'}).status_code==422
    with s() as db:db.get(Scan,scan).owner='other';db.commit()
    assert c.patch(url,json={'state':'open'}).status_code==404


def test_report_snapshot_is_immutable_after_later_review(tmp_path):
    s,c,scan=setup(tmp_path)
    run_scan(scan,s,lambda _:200,pause=lambda _:None)
    r=c.post('/v1/scans/'+scan+'/report-snapshots');assert r.status_code==201
    snapshot=r.json();assert snapshot['id'] and snapshot['report']['scan']['id']==scan
    finding=c.get('/v1/scans/'+scan+'/findings').json()[0]
    c.patch('/v1/scans/'+scan+'/findings/'+finding['id']+'/review',json={'state':'acknowledged'})
    saved=c.get('/v1/report-snapshots/'+snapshot['id']).json()
    assert saved==snapshot
    assert all(f['review_state']=='open' for f in saved['report']['findings'])
    assert c.get('/v1/report-snapshots/'+snapshot['id'],headers={'Authorization':''}).status_code==401

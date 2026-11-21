import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from fuzzcore.api import create_app
from fuzzcore.core import database, run_scan, Scan

TOKEN='fixture-only-test-token-not-secret'


def setup(tmp_path, modules=None):
    sessions=database('sqlite:///'+str(tmp_path/'progress.db'))
    client=TestClient(create_app(sessions,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
    value=client.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':modules or ['directories','vhosts']},headers={'Idempotency-Key':'module-progress-001'})
    assert value.status_code==202
    return sessions,client,value.json()['id']


def test_progress_queued_running_completed_is_per_module_and_persistent(tmp_path):
    sessions,c,id=setup(tmp_path)
    detail=lambda:c.get('/v1/scans/'+id).json()
    p=detail()['module_progress']
    assert set(p)=={'directories','vhosts'}
    assert p['directories']=={'state':'queued','planned':4,'attempted':0,'completed':0}
    seen=[]
    def probe(path):
        seen.append(detail()['module_progress'])
        return 404
    def vhost(case):
        p=detail()['module_progress']
        assert p['directories']['state']=='completed' and p['directories']['completed']==4
        assert p['vhosts']['state']=='running'
        return {'status_code':200,'host':case+'.lab.invalid','body_sha256':'a'*64,'bytes':1}
    run_scan(id,sessions,probe,pause=lambda _:None,vhost_probe=vhost)
    assert seen[0]['directories']=={'state':'running','planned':4,'attempted':1,'completed':0}
    assert seen[0]['vhosts']['state']=='queued'
    p=detail()['module_progress']
    assert p['directories']=={'state':'completed','planned':4,'attempted':4,'completed':4}
    assert p['vhosts']=={'state':'completed','planned':3,'attempted':3,'completed':3}
    restarted=database('sqlite:///'+str(tmp_path/'progress.db'))
    with restarted() as db:assert json.loads(db.get(Scan,id).module_progress)['vhosts']['completed']==3
    assert c.get('/v1/scans').json()[0]['module_progress']==p
    assert c.get('/v1/scans/'+id+'/report.json').json()['scan']['module_progress']==p


@pytest.mark.parametrize('mode',['cancel','error','rate','timeout'])
def test_terminal_progress_never_completes_unattempted_modules(tmp_path,mode):
    sessions,c,id=setup(tmp_path)
    calls=[]
    ticks=iter([0,0,301])
    def probe(path):
        calls.append(path)
        if mode=='cancel':c.post('/v1/scans/'+id+'/cancel')
        if mode=='error':raise RuntimeError('probe fixture error')
        return 429 if mode=='rate' else 404
    run_scan(id,sessions,probe,pause=lambda _:None,clock=(lambda:next(ticks)) if mode=='timeout' else (lambda:0),vhost_probe=lambda _:pytest.fail('Unreached vhost module ran'))
    row=c.get('/v1/scans/'+id).json();p=row['module_progress']
    assert row['status']=={'cancel':'cancelled','error':'failed','rate':'failed','timeout':'timed_out'}[mode]
    assert p['directories']['state']==row['status']
    assert p['directories']['attempted']==1
    assert p['directories']['completed']==(0 if mode=='error' else 1)
    assert p['vhosts']=={'state':'not_run','planned':3,'attempted':0,'completed':0}


def test_queued_cancel_and_legacy_history_are_not_fabricated(tmp_path):
    sessions,c,id=setup(tmp_path)
    c.post('/v1/scans/'+id+'/cancel')
    assert all(p['state']=='not_run' for p in c.get('/v1/scans/'+id).json()['module_progress'].values())
    with sessions() as db:
        row=db.get(Scan,id);row.module_progress='{}';row.status='completed';row.attempted=7;db.commit()
    value=c.get('/v1/scans/'+id).json()
    assert value['module_progress']=={} and value['progress_available'] is False


def test_recovery_marks_only_inflight_progress_interrupted(tmp_path):
    from fuzzcore.recovery import recover_stale
    sessions,c,id=setup(tmp_path)
    with sessions() as db:
        row=db.get(Scan,id);row.status='running';row.updated_at='2000-01-01';row.attempted=5
        row.module_progress=json.dumps({'directories':{'state':'completed','planned':4,'attempted':4,'completed':4},'vhosts':{'state':'running','planned':3,'attempted':1,'completed':0}});db.commit()
    assert recover_stale(sessions,'2026-11-21T00:00:00+00:00',worker_stopped=True)==1
    p=c.get('/v1/scans/'+id).json()['module_progress']
    assert p['directories']['state']=='completed' and p['vhosts']['state']=='interrupted'
    assert p['vhosts']['completed']==0


def test_v9_upgrade_does_not_invent_module_results(tmp_path):
    sessions,c,id=setup(tmp_path,['directories'])
    with sessions() as db:
        db.execute(text('DELETE FROM schema_migrations WHERE version>=10'))
        db.execute(text('ALTER TABLE scans DROP COLUMN module_progress'));db.commit()
    sessions=database('sqlite:///'+str(tmp_path/'progress.db'))
    with sessions() as db:
        assert db.get(Scan,id).module_progress=='{}'
        assert db.execute(text('SELECT max(version) FROM schema_migrations')).scalar()==15


def test_final_response_rate_limit_is_failed_not_completed_module(tmp_path):
    sessions,c,id=setup(tmp_path,['directories'])
    counter=[]
    def probe(path):
        counter.append(path)
        return 429 if len(counter)==4 else 200
    run_scan(id,sessions,probe,pause=lambda _:None)
    p=c.get('/v1/scans/'+id).json()['module_progress']['directories']
    assert p=={'state':'failed','planned':4,'attempted':4,'completed':4}

import os
import json
import secrets
import uuid
from typing import Literal

from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .core import Scan, Finding, EnqueueIntent, ReportSnapshot, database, utcnow, TERMINAL
from .reports import finding_json,report,render_html
from .report_filters import report_filters,matching,fingerprint
from .outbox import dispatch_one
from .progress import initial_progress, progress_for, settle_progress, planned_attempts
from .custom_cases import CustomCase, canonical, version


def create_app(sessions, enqueue, token):
    if len(token) < 24 or token.startswith('replace_'):
        raise ValueError('Supply a random demo token of at least 24 characters through the environment')

    def auth(authorization: str = Header(default='')):
        if not secrets.compare_digest(authorization, 'Bearer ' + token):
            raise HTTPException(401, 'unauthorized')
        return 'demo'

    def owned(db, scan_id, owner):
        row = db.get(Scan, scan_id)
        if not row or row.owner != owner:
            raise HTTPException(404, 'scan_not_found')
        return row

    app = FastAPI(title='FuzzCore lab-only Day 1 API')

    class NewScan(BaseModel):
        model_config = ConfigDict(extra='forbid')
        target_id: Literal['local-lab']
        profile_id: Literal['lab-small'] = 'lab-small'
        authorization_confirmed: Literal[True]
        modules: list[Literal['directories','vhosts','api','parameters','custom','subdomains']] = ['directories']

        retest_of:str|None=Field(default=None,min_length=1,max_length=64)
        api_cases:list[Literal['inventory-v1']]=Field(default_factory=list,max_length=1)
        directory_cases:list[Literal['canary-v1','upload-v1']]=Field(default_factory=list,max_length=2)
        custom_cases:list[CustomCase]=Field(default_factory=list,max_length=3)

        @model_validator(mode='after')
        def custom_scope(self):
            if self.api_cases and 'api' not in self.modules:raise ValueError('Inventory cases require API module')
            if len(self.directory_cases)!=len(set(self.directory_cases)):raise ValueError('Select directory cases once')
            if self.directory_cases and 'directories' not in self.modules:raise ValueError('Directory cases require the directories module')
            if ('custom' in self.modules and not 1<=len(self.custom_cases)<=3) or ('custom' not in self.modules and self.custom_cases):
                raise ValueError('Custom module requires one to three cases, and only that module may carry them')
            return self

        @field_validator('authorization_confirmed', mode='before')
        @classmethod
        def explicit_boolean(cls, value):
            if value is not True:
                raise ValueError('Explicit authorization confirmation is required')
            return value

    @app.get('/health')
    def health():
        return {'status': 'alive'}

    @app.get('/v1/capabilities')
    def capabilities(owner=Depends(auth)):
        return {
            'modules': {name: {'supported': name in ('directories','vhosts','api','parameters','custom','subdomains'),
                              'reason': None if name in ('directories','vhosts','api','parameters','custom','subdomains') else 'not_implemented'}
                        for name in ('directories', 'vhosts', 'api', 'parameters', 'custom', 'subdomains')},
            'profile': {'id': 'lab-small', 'max_attempts': 38,
                        'requests_per_second': 2, 'concurrency': 1},
            'api_cases':{'inventory-v1':{'requests':4,'default':False,'mode':'curated_read_only_fixture'}},
            'directory_cases':{'upload-v1':{'requests':6,'cleanup_reserve':2,'mode':'fixed_benign_in_memory','default':False,'ttl_seconds':300},'canary-v1':{'requests':3,'mode':'synthetic_read_only','default':False}},
            'saved_custom_cases':{'supported':True,'immutable':True,'max_versions':100,'list_limit':50,'max_cases_per_version':3},
            'custom_case_schema':{'version':'declarative-v2','methods':['GET','POST'],'post_paths':['/custom-disposable'],'response_header_names':['content-type','x-fixture-mode'],'max_body_marker_length':64,'max_cases':3},
            'target_mode': 'fixed_lab_only', 'authorization_required': True,
        }

    from .saved_cases import attach_saved_cases
    attach_saved_cases(app,sessions,auth)

    @app.get('/v1/targets')
    def targets(owner=Depends(auth)):
        return [{'id': 'local-lab', 'name': 'Isolated FuzzCore fixture lab'}]

    @app.post('/v1/scans', status_code=202)
    def create_scan(body: NewScan, idempotency_key: str = Header(min_length=8, max_length=128), owner=Depends(auth)):
        if not body.modules or len(body.modules) != len(set(body.modules)):
            raise HTTPException(422, 'select_supported_modules_once')
        with sessions() as db:
            if body.retest_of:
                original=owned(db,body.retest_of,owner)
                if original.status not in TERMINAL:raise HTTPException(409,'original_scan_not_terminal')
                if original.api_cases!=json.dumps(sorted(body.api_cases)) or original.directory_cases!=json.dumps(sorted(body.directory_cases)) or original.selected_modules.split(',')!=sorted(body.modules) or original.custom_cases!=canonical([c.model_dump() for c in body.custom_cases]):
                    raise HTTPException(422,'retest_requires_same_scope_and_cases')
            row = db.scalar(select(Scan).where(Scan.owner == owner, Scan.request_key == idempotency_key))
            if not row:
                if 'upload-v1' in body.directory_cases and db.scalar(select(Scan.id).where(Scan.owner==owner,Scan.cleanup_status.in_(['pending','unverified'])).limit(1)):
                    raise HTTPException(409,'pending_upload_cleanup')
                row = Scan(api_cases=json.dumps(sorted(body.api_cases)),directory_cases=json.dumps(sorted(body.directory_cases)),module_progress=json.dumps(initial_progress(sorted(body.modules),body.custom_cases,body.directory_cases,body.api_cases)),id=str(uuid.uuid4()), owner=owner, request_key=idempotency_key, retest_of=body.retest_of, authorization_confirmed_at=utcnow(), selected_modules=','.join(sorted(body.modules)), custom_cases=canonical([c.model_dump() for c in body.custom_cases]), case_version=version([c.model_dump() for c in body.custom_cases]) if body.custom_cases else None, planned=planned_attempts(body.modules,body.custom_cases,body.directory_cases,body.api_cases))
                db.add(row)
                db.add(EnqueueIntent(scan_id=row.id))
                try:
                    db.commit()
                except IntegrityError:
                    db.rollback()
                    row = db.scalar(select(Scan).where(Scan.owner == owner, Scan.request_key == idempotency_key))
                    if not row:
                        raise HTTPException(409, 'active_scan_exists')
            if row.api_cases!=json.dumps(sorted(body.api_cases)) or row.directory_cases!=json.dumps(sorted(body.directory_cases)) or row.retest_of!=body.retest_of or row.selected_modules.split(',') != sorted(body.modules) or row.custom_cases != canonical([c.model_dump() for c in body.custom_cases]):
                raise HTTPException(409, 'idempotency_scope_mismatch')
            scan_id = row.id
        if not dispatch_one(sessions, enqueue, scan_id):
            raise HTTPException(503, 'queue_unavailable_retry_same_request')
        with sessions() as db:
            row = db.get(Scan, scan_id)
            return {'id': row.id, 'status': row.status}

    @app.get('/v1/scans')
    def history(owner=Depends(auth)):
        with sessions() as db:
            return [serialize(row) for row in db.scalars(select(Scan).where(Scan.owner == owner).order_by(Scan.created_at.desc()).limit(50))]

    @app.get('/v1/scans/{scan_id}')
    def detail(scan_id: str, owner=Depends(auth)):
        with sessions() as db:
            return serialize(owned(db, scan_id, owner))

    @app.post('/v1/scans/{scan_id}/cancel')
    def cancel(scan_id: str, owner=Depends(auth)):
        with sessions() as db:
            row = owned(db, scan_id, owner)
            if row.status == 'queued':
                row.status = 'cancelled'
            elif row.status == 'running':
                row.status = 'cancelling'
            row.updated_at = utcnow(); settle_progress(row); db.commit()
            return serialize(row)

    @app.get('/v1/scans/{scan_id}/findings')
    def findings(scan_id: str, owner=Depends(auth),filters=Depends(report_filters)):
        with sessions() as db:
            owned(db, scan_id, owner)
            return matching([finding_json(r) for r in db.scalars(select(Finding).where(Finding.scan_id==scan_id).order_by(Finding.id).limit(100))],filters)

    @app.get('/v1/scans/{scan_id}/retest-comparison')
    def comparison(scan_id:str,owner=Depends(auth)):
        with sessions() as db:
            row=owned(db,scan_id,owner)
            if not row.retest_of:raise HTTPException(409,'not_a_retest')
            old=owned(db,row.retest_of,owner)
            if row.status not in TERMINAL:raise HTTPException(409,'retest_not_terminal')
            def fingerprints(scan):
                return {(item.module,item.path,json.loads(item.evidence).get('rule_id','resource-status-v1'))
                        for item in db.scalars(select(Finding).where(Finding.scan_id==scan.id))}
            before,after=fingerprints(old),fingerprints(row)
            return {'original_scan_id':old.id,'retest_scan_id':row.id,
                'not_observed':sorted(before-after),'still_observed':sorted(before & after),'newly_observed':sorted(after-before),
                'partial':row.status!='completed',
                'conclusion':'No automatic fixed or secure state. Review matched scope and evidence.'}

    class Review(BaseModel):
        model_config=ConfigDict(extra='forbid')
        state:Literal['open','acknowledged','retest_requested','fixed']
        note:str=Field(default='',max_length=500)
        retest_scan_id:str|None=Field(default=None,min_length=1,max_length=64)

        @model_validator(mode='after')
        def fixed_evidence(self):
            if self.state=='fixed' and (not self.note.strip() or not self.retest_scan_id):raise ValueError('Manual review note and completed linked retest are required')
            if self.state!='fixed' and self.retest_scan_id:raise ValueError('Retest reference only accompanies fixed review')
            return self

    @app.patch('/v1/scans/{scan_id}/findings/{finding_id}/review')
    def review(scan_id:str,finding_id:str,body:Review,owner=Depends(auth)):
        with sessions() as db:
            original=owned(db,scan_id,owner)
            item=db.get(Finding,finding_id)
            if not item or item.scan_id!=scan_id:raise HTTPException(404,'finding_not_found')
            if body.state=='fixed':
                retest=owned(db,body.retest_scan_id,owner)
                if retest.retest_of!=original.id or retest.status!='completed' or original.status not in TERMINAL or any(getattr(retest,key)!=getattr(original,key) for key in ('target_id','scope_version','selected_modules','custom_cases','case_version','directory_cases','api_cases')):
                    raise HTTPException(409,'complete_matched_scope_linked_retest_required')
                if retest.cleanup_status in ('pending','unverified'):raise HTTPException(409,'retest_cleanup_unverified')
                if any(fingerprint(new)==fingerprint(item) for new in db.scalars(select(Finding).where(Finding.scan_id==retest.id))):raise HTTPException(409,'finding_still_observed')
            item.review_state=body.state;item.review_note=body.note;item.review_retest_id=body.retest_scan_id if body.state=='fixed' else None;item.reviewed_at=utcnow();db.commit()
            return finding_json(item)

    @app.get('/v1/scans/{scan_id}/report.json')
    def json_report(scan_id:str,owner=Depends(auth),filters=Depends(report_filters)):
        with sessions() as db:return report(db,owned(db,scan_id,owner),serialize,filters)

    @app.get('/v1/scans/{scan_id}/report.html',response_class=HTMLResponse)
    def html_report(scan_id:str,owner=Depends(auth),filters=Depends(report_filters)):
        with sessions() as db:
            value=report(db,owned(db,scan_id,owner),serialize,filters)
            return HTMLResponse(render_html(value),headers={
                'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
                'X-Content-Type-Options':'nosniff','Cache-Control':'no-store'})

    @app.post('/v1/scans/{scan_id}/report-snapshots',status_code=201)
    def snapshot(scan_id:str,owner=Depends(auth),filters=Depends(report_filters)):
        with sessions() as db:
            row=owned(db,scan_id,owner)
            content=report(db,row,serialize,filters)
            item=ReportSnapshot(id=str(uuid.uuid4()),scan_id=scan_id,owner=owner,content=json.dumps(content))
            db.add(item);db.commit()
            return {'id':item.id,'created_at':item.created_at,'report':content}

    @app.get('/v1/report-snapshots/{snapshot_id}')
    def saved_snapshot(snapshot_id:str,owner=Depends(auth)):
        with sessions() as db:
            item=db.get(ReportSnapshot,snapshot_id)
            if not item or item.owner!=owner:raise HTTPException(404,'report_not_found')
            owned(db,item.scan_id,owner)
            return {'id':item.id,'created_at':item.created_at,'report':json.loads(item.content)}


    return app


def serialize(row):
    return {'api_cases':json.loads(row.api_cases),'cleanup_status':row.cleanup_status,'cleanup_attempted':row.cleanup_attempted,'directory_cases':json.loads(row.directory_cases),'module_progress':progress_for(row),'progress_available':bool(json.loads(row.module_progress)),'modules':row.selected_modules.split(','),'custom_cases':json.loads(row.custom_cases),'case_version':row.case_version,'retest_of':row.retest_of, **{key: getattr(row, key) for key in ('id', 'status', 'attempted', 'planned', 'created_at', 'updated_at', 'error', 'target_id', 'scope_version', 'authorization_confirmed_at')}}


def production_app():
    from redis import Redis
    from rq import Queue
    sessions = database(os.environ['DATABASE_URL'])
    queue = Queue('scans', connection=Redis.from_url(os.environ['REDIS_URL']))
    def enqueue(scan_id):
        queue.enqueue('fuzzcore.core.execute_job', scan_id, job_id=scan_id, job_timeout=360, result_ttl=3600)
    return create_app(sessions, enqueue, os.environ['FUZZCORE_TOKEN'])

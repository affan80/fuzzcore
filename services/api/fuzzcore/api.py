import os
import secrets
import uuid
from typing import Literal

from fastapi import FastAPI, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .core import Scan, Finding, EnqueueIntent, database, utcnow
from .outbox import dispatch_one


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
        modules: list[Literal['directories']] = ['directories']

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
            'modules': {name: {'supported': name == 'directories',
                              'reason': None if name == 'directories' else 'not_implemented'}
                        for name in ('directories', 'vhosts', 'api', 'parameters', 'custom', 'subdomains')},
            'profile': {'id': 'lab-small', 'max_attempts': 4,
                        'requests_per_second': 2, 'concurrency': 1},
            'target_mode': 'fixed_lab_only', 'authorization_required': True,
        }

    @app.get('/v1/targets')
    def targets(owner=Depends(auth)):
        return [{'id': 'local-lab', 'name': 'Isolated FuzzCore fixture lab'}]

    @app.post('/v1/scans', status_code=202)
    def create_scan(body: NewScan, idempotency_key: str = Header(min_length=8, max_length=128), owner=Depends(auth)):
        if not body.modules or len(body.modules) != len(set(body.modules)):
            raise HTTPException(422, 'select_supported_modules_once')
        with sessions() as db:
            row = db.scalar(select(Scan).where(Scan.owner == owner, Scan.request_key == idempotency_key))
            if not row:
                row = Scan(id=str(uuid.uuid4()), owner=owner, request_key=idempotency_key, authorization_confirmed_at=utcnow())
                db.add(row)
                db.add(EnqueueIntent(scan_id=row.id))
                try:
                    db.commit()
                except IntegrityError:
                    db.rollback()
                    row = db.scalar(select(Scan).where(Scan.owner == owner, Scan.request_key == idempotency_key))
                    if not row:
                        raise HTTPException(409, 'active_scan_exists')
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
            row.updated_at = utcnow(); db.commit()
            return serialize(row)

    @app.get('/v1/scans/{scan_id}/findings')
    def findings(scan_id: str, owner=Depends(auth)):
        with sessions() as db:
            owned(db, scan_id, owner)
            return [{'id': r.id, 'path': r.path, 'status_code': r.status_code, 'summary': r.summary, 'severity': 'informational', 'confidence': 'observed'}
                    for r in db.scalars(select(Finding).where(Finding.scan_id == scan_id).limit(100))]

    return app


def serialize(row):
    return {key: getattr(row, key) for key in ('id', 'status', 'attempted', 'planned', 'created_at', 'updated_at', 'error', 'target_id', 'scope_version', 'authorization_confirmed_at')}


def production_app():
    from redis import Redis
    from rq import Queue
    sessions = database(os.environ['DATABASE_URL'])
    queue = Queue('scans', connection=Redis.from_url(os.environ['REDIS_URL']))
    def enqueue(scan_id):
        queue.enqueue('fuzzcore.core.execute_job', scan_id, job_id=scan_id, job_timeout=360, result_ttl=3600)
    return create_app(sessions, enqueue, os.environ['FUZZCORE_TOKEN'])

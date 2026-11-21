"""Opt-in fixed benign in-memory upload. Four operations, two cleanup recovery reserves."""
import hashlib
import json
import uuid
import time
from sqlalchemy import select

MARKER=b'FUZZCORE_BENIGN_UPLOAD_FIXTURE_v1'
ACTIONS={'create':'POST','read':'GET','delete':'DELETE','verify':'GET'}


def http_upload_probe(client,scan_id):
    object_id=uuid.UUID(scan_id).hex
    def probe(action):
        if action not in ACTIONS:raise ValueError('Unknown benign upload action')
        kwargs={'headers':{'Accept-Encoding':'identity'}}
        if action=='create':kwargs.update(content=MARKER,headers={'Accept-Encoding':'identity','Content-Type':'application/octet-stream'})
        with client.stream(ACTIONS[action],'/upload-fixture/'+object_id,**kwargs) as response:
            body=bytearray()
            for chunk in response.iter_bytes(chunk_size=4096):
                if len(body)+len(chunk)>16384:raise ValueError('Upload evidence budget exceeded')
                body.extend(chunk)
            return {'status_code':response.status_code,'bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest(),'known_marker':bytes(body)==MARKER}
    return probe


def cleanup(sessions,scan_id,probe,pause=time.sleep):
    from .core import Scan,utcnow
    from .progress import advance_progress
    with sessions() as db:
        row=db.get(Scan,scan_id)
        if row.cleanup_status not in ('pending','unverified'):return row.cleanup_status=='verified_absent'
        if row.cleanup_attempted>2 or row.attempted+2>min(row.planned,34):return False
    for action in ('delete','verify'):
        pause(0.5)
        with sessions() as db:
            row=db.get(Scan,scan_id)
            row.attempted+=1;row.cleanup_attempted+=1
            advance_progress(row,'directories');row.updated_at=utcnow();db.commit()
        try:result=probe(action)
        except Exception:result=None
        with sessions() as db:
            row=db.get(Scan,scan_id)
            if result is not None:advance_progress(row,'directories',completed=True)
            if action=='verify':
                row.cleanup_status='verified_absent' if result is not None and result['status_code']==404 else 'unverified'
                if row.cleanup_status=='verified_absent':
                    progress=json.loads(row.module_progress)
                    if progress:
                        item=progress['directories'];item['skipped']=max(0,4-row.cleanup_attempted)
                        if item['completed']+item['skipped']==item['planned']:item['state']='completed'
                        row.module_progress=json.dumps(progress)
            row.updated_at=utcnow();db.commit()
    with sessions() as db:return db.get(Scan,scan_id).cleanup_status=='verified_absent'


def run_upload(sessions,scan_id,probe,*,clock,started,pause=time.sleep):
    from .core import Scan,Finding,utcnow
    from .progress import advance_progress
    values={}
    try:
        for action in ('create','read'):
            pause(0.5)
            with sessions() as db:
                row=db.get(Scan,scan_id)
                if row.status!='running':return
                if clock()-started>300:
                    row.status='timed_out';db.commit();return
                if row.attempted>=min(row.planned-2,32):raise ValueError('Upload budget exhausted')
                if action=='create':row.cleanup_status='pending'
                row.attempted+=1;advance_progress(row,'directories');row.updated_at=utcnow();db.commit()
            result=probe(action);values[action]=result
            with sessions() as db:
                row=db.get(Scan,scan_id);advance_progress(row,'directories',completed=True);row.updated_at=utcnow();db.commit()
            if result['status_code']!=(201 if action=='create' else 200) or (action=='read' and result['known_marker'] is not True):raise ValueError('Benign fixture roundtrip did not match')
    finally:
        if not cleanup(sessions,scan_id,probe,pause=pause):
            with sessions() as db:
                row=db.get(Scan,scan_id)
                if row.cleanup_status in ('pending','unverified'):row.error='cleanup_unverified';db.commit();raise ValueError('Cleanup unverified')
    if set(values)=={'create','read'}:
        with sessions() as db:
            db.add(Finding(id=str(uuid.uuid4()),scan_id=scan_id,path='/upload-fixture [fixed benign text]',status_code=200,module='directories',severity='informational',confidence='observed',summary='Fixed benign in-memory upload returned its known marker and subsequent absence was verified. No executable content or filesystem writes.',evidence=json.dumps({'rule_id':'benign-upload-roundtrip-v1','case_version':'upload-v1','controls':values,'cleanup_verified':True,'remediation':'Keep uploads isolated, strictly validate type and size, disable execution, expire temporary content, and verify deletion. This fixture observation does not prove insecure upload or an applied fix.'})));db.commit()


def recover_pending_uploads(sessions,probe_factory,*,worker_stopped):
    from .core import Scan,TERMINAL
    if not worker_stopped:raise ValueError('Stop worker before cleanup recovery')
    with sessions() as db:
        ids=[row.id for row in db.scalars(select(Scan).where(Scan.status.in_(TERMINAL),Scan.cleanup_status.in_(['pending','unverified']),Scan.cleanup_attempted<=2))]
    return sum(cleanup(sessions,id,probe_factory(id)) for id in ids)


def scanner_upload_probe(client,scan_id):
    object_id=uuid.UUID(scan_id).hex
    def probe(action):
        if action not in ACTIONS:raise ValueError('Unknown upload fixture action')
        response=client.get('/upload-check',params={'case':action,'object_id':object_id})
        response.raise_for_status();return response.json()
    return probe

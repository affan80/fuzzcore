"""Durable enqueue retry. Queue payloads are stable scan IDs, never secrets."""
from sqlalchemy import select
from .core import Scan, EnqueueIntent, utcnow


def dispatch_one(sessions, enqueue, scan_id):
    with sessions() as db:
        scan = db.get(Scan, scan_id)
        intent = db.get(EnqueueIntent, scan_id)
        if not scan or not intent or intent.sent_at or scan.status != 'queued':
            return True
        intent.attempts += 1
        db.commit()
    try:
        enqueue(scan_id)
    except Exception:
        with sessions() as db:
            scan = db.get(Scan, scan_id)
            if scan and scan.status == 'queued':
                scan.error = 'enqueue_failed'
                scan.updated_at = utcnow()
            db.commit()
        return False
    with sessions() as db:
        intent = db.get(EnqueueIntent, scan_id)
        intent.sent_at = utcnow()
        scan = db.get(Scan, scan_id)
        if scan and scan.status == 'queued':
            scan.error = None
            scan.updated_at = utcnow()
        db.commit()
    return True


def retry_pending(sessions, enqueue):
    with sessions() as db:
        ids = list(db.scalars(select(EnqueueIntent.scan_id).join(Scan, Scan.id == EnqueueIntent.scan_id).where(EnqueueIntent.sent_at.is_(None), Scan.status == 'queued').limit(100)))
    outcomes = [dispatch_one(sessions, enqueue, scan_id) for scan_id in ids]
    return {'checked': len(ids), 'failed': outcomes.count(False)}

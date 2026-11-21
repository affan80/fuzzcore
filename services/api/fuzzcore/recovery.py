"""Recovery is operator-only after stopping the worker, never a blind auto-replay."""
import os
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from .core import Scan, database, utcnow
from .outbox import retry_pending
from .progress import settle_progress


def recover_stale(sessions, cutoff, *, worker_stopped):
    if not worker_stopped:
        raise ValueError('Stop the worker before recovering interrupted jobs')
    count = 0
    with sessions() as db:
        for row in db.scalars(select(Scan).where(
                Scan.status.in_(['running', 'cancelling']), Scan.updated_at < cutoff)):
            row.status = 'cancelled' if row.status == 'cancelling' else 'interrupted'
            row.error = None if row.status == 'cancelled' else 'worker_interrupted'
            row.updated_at = utcnow()
            settle_progress(row)
            count += 1
        db.commit()
    return count


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker-stopped', action='store_true', required=True)
    parser.add_argument('--cleanup-uploads',action='store_true',help='Use remaining reserved DELETE/absence checks, never repost')
    args = parser.parse_args()
    sessions = database(os.environ['DATABASE_URL'])
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    interrupted = recover_stale(sessions, cutoff, worker_stopped=args.worker_stopped)
    cleaned=0
    if args.cleanup_uploads:
        import httpx
        from .uploads import recover_pending_uploads,scanner_upload_probe
        with httpx.Client(base_url='http://scanner:8082',timeout=12,follow_redirects=False,trust_env=False) as client:
            cleaned=recover_pending_uploads(sessions,lambda scan_id:scanner_upload_probe(client,scan_id),worker_stopped=args.worker_stopped)
    from redis import Redis
    from rq import Queue
    queue = Queue('scans', connection=Redis.from_url(os.environ['REDIS_URL']))
    def enqueue(scan_id):
        queue.enqueue('fuzzcore.core.execute_job', scan_id, job_id=scan_id, job_timeout=360, result_ttl=3600)
    print({'upload_cleanup_verified':cleaned,'interrupted': interrupted, 'outbox': retry_pending(sessions, enqueue)})


if __name__ == '__main__':
    main()

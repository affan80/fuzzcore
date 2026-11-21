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
    args = parser.parse_args()
    sessions = database(os.environ['DATABASE_URL'])
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    interrupted = recover_stale(sessions, cutoff, worker_stopped=args.worker_stopped)
    from redis import Redis
    from rq import Queue
    queue = Queue('scans', connection=Redis.from_url(os.environ['REDIS_URL']))
    def enqueue(scan_id):
        queue.enqueue('fuzzcore.core.execute_job', scan_id, job_id=scan_id, job_timeout=360, result_ttl=3600)
    print({'interrupted': interrupted, 'outbox': retry_pending(sessions, enqueue)})


if __name__ == '__main__':
    main()

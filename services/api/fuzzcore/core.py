"""Lab-only Day 1 core. No arbitrary targets, payloads or commands."""
import os
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import create_engine, Column, String, Integer, Text, select, UniqueConstraint, Index, text, update
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()
TERMINAL = {'completed', 'cancelled', 'failed', 'timed_out', 'interrupted'}
PATHS = ('/', '/health', '/api/status', '/missing-control-7f23')


def utcnow():
    return datetime.now(timezone.utc).isoformat()


class Scan(Base):
    __tablename__ = 'scans'
    id = Column(String, primary_key=True)
    owner = Column(String, nullable=False)
    request_key = Column(String, nullable=False)
    target_id = Column(String, nullable=False, default='local-lab')
    scope_version = Column(String, nullable=False, default='lab-v1')
    authorization_confirmed_at = Column(String, nullable=True)
    status = Column(String, nullable=False, default='queued')
    attempted = Column(Integer, nullable=False, default=0)
    planned = Column(Integer, nullable=False, default=len(PATHS))
    error = Column(String, nullable=True)
    created_at = Column(String, nullable=False, default=utcnow)
    updated_at = Column(String, nullable=False, default=utcnow)
    __table_args__ = (UniqueConstraint('owner', 'request_key'),)


ACTIVE_SCAN_INDEX = Index(
    'uq_scans_one_active_owner', Scan.owner, unique=True,
    sqlite_where=text("status IN ('queued','running','cancelling')"),
    postgresql_where=text("status IN ('queued','running','cancelling')"),
)


class Finding(Base):
    __tablename__ = 'findings'
    id = Column(String, primary_key=True)
    scan_id = Column(String, nullable=False, index=True)
    path = Column(String, nullable=False)
    status_code = Column(Integer, nullable=False)
    summary = Column(Text, nullable=False)


class EnqueueIntent(Base):
    __tablename__ = 'enqueue_intents'
    scan_id = Column(String, primary_key=True)
    attempts = Column(Integer, nullable=False, default=0)
    sent_at = Column(String, nullable=True)


def database(url):
    engine = create_engine(url, connect_args={'check_same_thread': False} if url.startswith('sqlite') else {})
    from .migrations import upgrade
    upgrade(engine, Base.metadata, ACTIVE_SCAN_INDEX)
    return sessionmaker(engine, expire_on_commit=False)


def validate_lab_origin(origin):
    parsed = urlsplit(origin)
    # Fixed service name on the private lab network. No user-supplied origins.
    if parsed.scheme != 'http' or parsed.hostname != 'lab' or parsed.port != 8081:
        raise ValueError('Only the fixed isolated lab origin is supported')
    if parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('Invalid lab origin')
    return 'http://lab:8081'


def run_scan(scan_id, sessions, probe, pause=time.sleep, clock=time.monotonic):
    """Cooperative, single-worker fixture discovery. probe accepts fixed paths only."""
    with sessions() as db:
        claimed = db.execute(update(Scan).where(
            Scan.id == scan_id, Scan.status == 'queued'
        ).values(status='running', updated_at=utcnow()))
        db.commit()
        if claimed.rowcount != 1:
            # Another delivery already owns this run, or it is terminal.
            return
    started = clock()
    try:
        for path in PATHS:
            with sessions() as db:
                row = db.get(Scan, scan_id)
                if row.status == 'cancelling':
                    row.status = 'cancelled'; row.updated_at = utcnow(); db.commit(); return
                if row.status != 'running':
                    return
                if clock() - started > 300:
                    row.status = 'timed_out'; row.updated_at = utcnow(); db.commit(); return
            status = probe(path)
            with sessions() as db:
                row = db.get(Scan, scan_id)
                row.attempted += 1; row.updated_at = utcnow()
                if 200 <= status < 300:
                    db.add(Finding(id=str(uuid.uuid4()), scan_id=scan_id, path=path,
                                   status_code=status, summary='Lab resource discovered; not a vulnerability.'))
                if status == 429:
                    row.status = 'failed'; row.error = 'target_rate_limited'; db.commit(); return
                db.commit()
            pause(0.5)  # Concurrency one and at most two fixture requests per second.
        with sessions() as db:
            row = db.get(Scan, scan_id)
            row.status = 'cancelled' if row.status == 'cancelling' else 'completed'
            row.updated_at = utcnow(); db.commit()
    except Exception:
        with sessions() as db:
            row = db.get(Scan, scan_id)
            row.status = 'cancelled' if row.status == 'cancelling' else 'failed'
            row.error = None if row.status == 'cancelled' else 'probe_failed'
            row.updated_at = utcnow(); db.commit()


def http_probe(client):
    def probe(path):
        if path not in PATHS:
            raise ValueError('Out-of-scope path')
        # Never follow redirects or read response bodies. Environment proxies disabled by caller.
        with client.stream('GET', path) as response:
            return response.status_code
    return probe


def execute_job(scan_id):
    sessions = database(os.environ['DATABASE_URL'])
    # Worker has data/control networks only; the scanner has control/lab only.
    with httpx.Client(base_url='http://scanner:8082', timeout=12, follow_redirects=False, trust_env=False) as client:
        def probe(path):
            if path not in PATHS:
                raise ValueError('Out-of-scope path')
            response = client.get('/probe', params={'path': path})
            response.raise_for_status()
            return response.json()['status_code']
        run_scan(scan_id, sessions, probe)

import threading
from concurrent.futures import ThreadPoolExecutor
from fuzzcore.core import Scan, database, run_scan


def test_concurrent_deliveries_claim_a_queued_scan_only_once(tmp_path):
    raw_sessions = database('sqlite:///' + str(tmp_path/'claim.db'))
    with raw_sessions() as db:
        db.add(Scan(id='claim-run',owner='demo',request_key='claim-key-001'));db.commit()
    both_read = threading.Barrier(2)
    def sessions():
        db = raw_sessions()
        original_get = db.get
        def get(model, key, *args, **kwargs):
            row = original_get(model, key, *args, **kwargs)
            if model is Scan and row and row.status == 'queued':
                # Force the old read-then-write race. An atomic UPDATE claim
                # does not read a queued row this way and needs no barrier.
                both_read.wait(timeout=3)
            return row
        db.get = get
        return db
    attempts = []
    lock = threading.Lock()
    def probe(path):
        with lock: attempts.append(path)
        return 200
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: run_scan('claim-run', sessions, probe, pause=lambda _:None), range(2)))
    assert len(attempts) == 4

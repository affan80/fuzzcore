"""Network-separated fixture probe. Receives no DB, queue or authentication secrets."""
import threading
import time
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException

from .core import validate_lab_origin, http_probe


def create_scanner(transport=None, delay=time.sleep):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    lock = threading.Lock()

    @app.get('/probe')
    def probe(path: Literal['/', '/health', '/api/status', '/missing-control-7f23']):
        if not lock.acquire(blocking=False):
            raise HTTPException(429, 'probe_busy')
        try:
            with httpx.Client(base_url=validate_lab_origin('http://lab:8081'), transport=transport,
                              timeout=10, follow_redirects=False, trust_env=False) as client:
                try:
                    result = http_probe(client)(path)
                except httpx.HTTPError:
                    raise HTTPException(502, 'fixture_unreachable')
                delay(0.5)
                return {'status_code': result}
        finally:
            lock.release()
    return app


app = create_scanner()

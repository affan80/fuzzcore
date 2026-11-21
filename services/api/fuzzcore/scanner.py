"""Network-separated fixture probe. Receives no DB, queue or authentication secrets."""
import threading
import time
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException

from .core import validate_lab_origin, http_probe
from .custom_cases import CustomCase


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
    @app.get('/vhost')
    def vhost(case: Literal['default','control','seeded']):
        from .vhosts import http_vhost_probe
        if not lock.acquire(blocking=False):
            raise HTTPException(429, 'probe_busy')
        try:
            with httpx.Client(base_url=validate_lab_origin('http://lab:8081'), transport=transport,
                              timeout=10, follow_redirects=False, trust_env=False) as client:
                try:
                    result = http_vhost_probe(client)(case)
                except (httpx.HTTPError, ValueError):
                    raise HTTPException(502, 'fixture_evidence_unavailable')
                delay(0.5)
                return result
        finally:
            lock.release()
    @app.get('/api-check')
    def api_check(case: Literal['missing','anonymous','alice-own','alice-denied','bob-own','alice-cross']):
        from .api_checks import http_api_probe
        if not lock.acquire(blocking=False):
            raise HTTPException(429, 'probe_busy')
        try:
            with httpx.Client(base_url=validate_lab_origin('http://lab:8081'), transport=transport,
                              timeout=10, follow_redirects=False, trust_env=False) as client:
                try:
                    result = http_api_probe(client)(case)
                except (httpx.HTTPError, ValueError):
                    raise HTTPException(502, 'fixture_evidence_unavailable')
                delay(0.5)
                return result
        finally:
            lock.release()
    @app.get('/parameter-check')
    def parameter_check(case: Literal['baseline','alpha','beta','duplicate','quoted','encoded']):
        from .parameters import http_parameter_probe
        if not lock.acquire(blocking=False):raise HTTPException(429, 'probe_busy')
        try:
            with httpx.Client(base_url=validate_lab_origin('http://lab:8081'),transport=transport,
                              timeout=10,follow_redirects=False,trust_env=False) as client:
                try:result=http_parameter_probe(client)(case)
                except (httpx.HTTPError,ValueError):raise HTTPException(502,'fixture_evidence_unavailable')
                delay(0.5)
                return result
        finally:lock.release()
    @app.post('/custom-check')
    def custom_check(case:CustomCase):
        from .custom_cases import http_custom_probe
        if not lock.acquire(blocking=False):raise HTTPException(429,'probe_busy')
        try:
            with httpx.Client(base_url=validate_lab_origin('http://lab:8081'),transport=transport,
                              timeout=10,follow_redirects=False,trust_env=False) as client:
                try:result=http_custom_probe(client)(case.model_dump())
                except (httpx.HTTPError,ValueError):raise HTTPException(502,'fixture_evidence_unavailable')
                delay(0.5)
                return result
        finally:lock.release()
    return app


app = create_scanner()

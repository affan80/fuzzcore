"""CI-only real Docker/Postgres/Redis/lab smoke. No external scan traffic."""
import json
import subprocess
import time
import urllib.request
from pathlib import Path

values = dict(line.split('=', 1) for line in Path('.env').read_text().splitlines())
base = 'http://127.0.0.1:8000'

def request(path, body=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body else None,
        headers={'Authorization':'Bearer ' + values['FUZZCORE_TOKEN'], 'Idempotency-Key':'ci-fixture-0001', 'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)

for attempt in range(60):
    try:
        request('/health'); break
    except Exception:
        time.sleep(2)
else:
    raise RuntimeError('API did not become ready')
assert request('/v1/capabilities')['authorization_required'] is True
scan = request('/v1/scans', {'target_id':'local-lab','profile_id':'lab-small','authorization_confirmed':True})
for attempt in range(30):
    detail = request('/v1/scans/' + scan['id'])
    if detail['status'] == 'completed': break
    if detail['status'] in ('failed','timed_out'): raise RuntimeError('Fixture scan failed')
    time.sleep(1)
else:
    raise RuntimeError('Fixture did not finish')
findings = request('/v1/scans/' + scan['id'] + '/findings')
assert len(findings) == 3 and detail['attempted'] == 4
# Network membership check: scanner has neither data network nor injected data credentials.
container = subprocess.check_output(['docker','compose','ps','-q','scanner'],text=True).strip()
config = json.loads(subprocess.check_output(['docker','inspect',container]))[0]
assert not any(name.endswith('_data') for name in config['NetworkSettings']['Networks'])
assert not any(value.startswith(('DATABASE_URL=', 'REDIS_URL=', 'FUZZCORE_TOKEN=')) for value in config['Config']['Env'])
# Runtime boundary: scanner must not resolve/reach data-only service names.
probe = '''import socket
for host, port in [('db',5432), ('redis',6379)]:
    try:
        connection = socket.create_connection((host,port), timeout=2)
    except OSError:
        continue
    else:
        connection.close()
        raise SystemExit('Scanner unexpectedly reached a data service')
print('Scanner cannot reach data services')
'''
subprocess.run(['docker','compose','exec','-T','scanner','python','-c',probe], check=True)
print('Real fixture run passed: 4 checks, 3 informational discoveries; scanner network membership checked.')

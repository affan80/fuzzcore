"""CI-only real Docker/Postgres/Redis/lab smoke. No external scan traffic."""
import json
import subprocess
import time
import urllib.request
from pathlib import Path

values = dict(line.split('=', 1) for line in Path('.env').read_text().splitlines())
base = 'http://127.0.0.1:8000'

def request(path, body=None, key='ci-fixture-0001'): 
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body else None,
        headers={'Authorization':'Bearer ' + values['FUZZCORE_TOKEN'], 'Idempotency-Key':key, 'Content-Type':'application/json'})
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
assert all(f['evidence']['rule_id']=='directory-control-v1' for f in findings)
assert all(f['evidence']['baseline']['status_code']==404 for f in findings)
# The same key cannot change its authorized module snapshot.
from urllib.error import HTTPError
try:
    request('/v1/scans', {'target_id':'local-lab','authorization_confirmed':True,'modules':['vhosts']})
except HTTPError as error:
    assert error.code == 409
else:
    raise AssertionError('Idempotency scope changed silently')
scan = request('/v1/scans', {'target_id':'local-lab','authorization_confirmed':True,'modules':['directories','vhosts']}, key='ci-vhosts-0002')
for attempt in range(40):
    detail = request('/v1/scans/' + scan['id'])
    if detail['status'] == 'completed': break
    if detail['status'] in ('failed','timed_out'): raise RuntimeError('Combined fixture scan failed')
    time.sleep(1)
else:
    raise RuntimeError('Combined fixture did not finish')
findings = request('/v1/scans/' + scan['id'] + '/findings')
assert detail['attempted'] == detail['planned'] == 7
vhosts = [f for f in findings if f['module']=='vhosts']
assert len(findings)==4 and len(vhosts)==1 and vhosts[0]['path']=='admin.lab.invalid'
assert vhosts[0]['evidence']['rule_id']=='vhost-difference-v1'
assert set(vhosts[0]['evidence']['baseline'])=={'default','control','seeded'}
# Third run includes the six bounded synthetic two-actor API checks.
scan = request('/v1/scans', {'target_id':'local-lab','authorization_confirmed':True,'modules':['directories','vhosts','api']}, key='ci-api-proof-0003')
for attempt in range(60):
    detail = request('/v1/scans/' + scan['id'])
    if detail['status']=='completed': break
    if detail['status'] in ('failed','timed_out'): raise RuntimeError('API fixture run failed')
    time.sleep(1)
else:
    raise RuntimeError('API fixture run did not finish')
findings = request('/v1/scans/' + scan['id'] + '/findings')
assert detail['attempted']==detail['planned']==13
api_findings = [f for f in findings if f['module']=='api']
assert len(findings)==5 and len(api_findings)==1
assert api_findings[0]['severity']=='high' and api_findings[0]['confidence']=='fixture-confirmed'
assert api_findings[0]['evidence']['rule_id']=='fixture-object-ownership-v1'
# Fourth run includes six harmless parameter-marker observations.
scan = request('/v1/scans', {'target_id':'local-lab','authorization_confirmed':True,'modules':['directories','vhosts','api','parameters']}, key='ci-parameters-0004')
for attempt in range(80):
    detail=request('/v1/scans/'+scan['id'])
    if detail['status']=='completed':break
    if detail['status'] in ('failed','timed_out'):raise RuntimeError('Parameter fixture failed')
    time.sleep(1)
else:raise RuntimeError('Parameter fixture timed out')
findings=request('/v1/scans/'+scan['id']+'/findings')
assert detail['attempted']==detail['planned']==19
parameter_findings=[f for f in findings if f['module']=='parameters']
assert len(findings)==7 and len(parameter_findings)==2
assert all(f['evidence']['parameter_discovery']=={'name':'q','scope':'fixed_fixture_only','distinct_marker_controls':True} for f in parameter_findings)
assert all(f['severity']=='informational' and f['confidence']=='signal' for f in parameter_findings)
# Maximum custom-case plan shares the same counter and immutable version.
cases=[{'path':'/health','method':'GET','params':{},'expect_status':200,'contains':'fixture'},
       {'path':'/custom-disposable','method':'POST','params':{},'body':{'marker':'harmless'},'expect_status':200,'contains':'fixture','expect_headers':{'content-type':'application/json','x-fixture-mode':'disposable'}},
       {'path':'/api/status','method':'GET','params':{},'expect_status':404,'contains':''}]
before_save=len(request('/v1/scans'))
saved=request('/v1/custom-cases',{'name':'CI smoke cases','cases':cases})
assert len(request('/v1/scans'))==before_save
assert request('/v1/custom-cases')[0]==saved
assert request('/v1/custom-cases/'+saved['id'])==saved
assert request('/v1/custom-cases',{'name':'CI smoke cases','cases':cases})==saved
scan=request('/v1/scans', {'target_id':'local-lab','authorization_confirmed':True,'modules':['directories','vhosts','api','parameters','custom'],'custom_cases':saved['cases']},key='ci-custom-0005')
for attempt in range(90):
    detail=request('/v1/scans/'+scan['id'])
    if detail['status']=='completed':break
    if detail['status'] in ('failed','timed_out'):raise RuntimeError('Custom fixture failed')
    time.sleep(1)
else:raise RuntimeError('Custom fixture timed out')
findings=request('/v1/scans/'+scan['id']+'/findings')
assert detail['attempted']==detail['planned']==22 and detail['case_version']==saved['version']
assert request('/v1/custom-cases/'+saved['id'])==saved
custom_findings=[f for f in findings if f['module']=='custom']
assert len(findings)==10 and len(custom_findings)==3
assert sorted(f['evidence']['passed'] for f in custom_findings)==[False,True,True]
assert any(f['evidence']['header_checks'].get('x-fixture-mode',{}).get('matched') is True for f in custom_findings)
assert all(f['evidence']['case_version']==detail['case_version'] for f in custom_findings)
# DNS adds exactly three local fixture queries, never HTTP to discovered names.
scan=request('/v1/scans', {'target_id':'local-lab','authorization_confirmed':True,'modules':['directories','vhosts','api','parameters','custom','subdomains'],'directory_cases':['canary-v1','upload-v1'],'api_cases':['inventory-v1'],'custom_cases':cases},key='ci-dns-0006')
for attempt in range(100):
    detail=request('/v1/scans/'+scan['id'])
    if detail['status']=='completed':break
    if detail['status'] in ('failed','timed_out'):raise RuntimeError('DNS fixture failed')
    time.sleep(1)
else:raise RuntimeError('DNS fixture timed out')
findings=request('/v1/scans/'+scan['id']+'/findings')
assert detail['attempted']==36 and detail['planned']==38
assert detail['directory_cases']==['canary-v1','upload-v1']
assert detail['api_cases']==['inventory-v1']
assert detail['module_progress']['api']['planned']==10
assert detail['module_progress']['directories']['planned']==13
assert set(detail['module_progress'])=={'directories','vhosts','api','parameters','custom','subdomains'}
assert all(p['state']=='completed' and p['attempted']==p['completed'] and p['completed']+p.get('skipped',0)==p['planned'] for p in detail['module_progress'].values())
assert sum(p['completed'] for p in detail['module_progress'].values())==36
assert detail['cleanup_status']=='verified_absent' and detail['cleanup_attempted']==2
assert detail['module_progress']['directories']['skipped']==2
uploads=[f for f in findings if f['evidence'].get('rule_id')=='benign-upload-roundtrip-v1']
assert len(uploads)==1 and uploads[0]['severity']=='informational' and uploads[0]['evidence']['cleanup_verified'] is True
inventory=[f for f in findings if f['evidence'].get('rule_id')=='curated-api-discovery-v1']
assert len(inventory)==3 and sorted(f['evidence']['access'] for f in inventory)==['hidden','protected','public']
assert all(f['severity']=='informational' and f['evidence']['transport']['scope']=='isolated_fixture_only' for f in inventory)
names=[f for f in findings if f['module']=='subdomains']
assert len(findings)==16 and len(names)==1 and names[0]['path']=='app.lab.invalid'
assert names[0]['evidence']['controls']['seeded']['dns_metadata']=={'authoritative':False,'recursion_available':False,'truncated':False,'alias_observed':False,'scope':'isolated_fixture_only'}
assert names[0]['evidence']['records']==['192.0.2.10']
canaries=[f for f in findings if f['evidence'].get('rule_id')=='fixture-path-allowlist-v1']
assert len(canaries)==1 and canaries[0]['confidence']=='fixture-confirmed' and canaries[0]['severity']=='medium'
assert set(canaries[0]['evidence']['controls'])=={'public','denied','canary'}
# Authenticated exports and immutable snapshot reflect the real stored run.
report=request('/v1/scans/'+scan['id']+'/report.json')
assert report['totals']['findings']==16 and report['partial'] is False
assert report['scan']['attempted']==36 and 'not a security certificate' in report['limitations']
html_req=urllib.request.Request(base+'/v1/scans/'+scan['id']+'/report.html',headers={'Authorization':'Bearer '+values['FUZZCORE_TOKEN']})
with urllib.request.urlopen(html_req,timeout=10) as response:
    assert "default-src 'none'" in response.headers['Content-Security-Policy']
    assert b'FuzzCore lab report' in response.read()
snapshot_req=urllib.request.Request(base+'/v1/scans/'+scan['id']+'/report-snapshots',data=b'',method='POST',headers={'Authorization':'Bearer '+values['FUZZCORE_TOKEN']})
with urllib.request.urlopen(snapshot_req,timeout=10) as response:snapshot=json.load(response)
assert request('/v1/report-snapshots/'+snapshot['id'])['report']['totals']['findings']==16
finding=report['findings'][0]
review_req=urllib.request.Request(base+'/v1/scans/'+scan['id']+'/findings/'+finding['id']+'/review',data=b'{"state":"acknowledged"}',method='PATCH',headers={'Authorization':'Bearer '+values['FUZZCORE_TOKEN'],'Content-Type':'application/json'})
with urllib.request.urlopen(review_req,timeout=10) as response:assert json.load(response)['review_state']=='acknowledged'
assert all(f['review_state']=='open' for f in request('/v1/report-snapshots/'+snapshot['id'])['report']['findings'])
filtered=request('/v1/scans/'+scan['id']+'/report.json?severity=high&module=api')
assert filtered['totals']['findings']==1 and filtered['unfiltered_findings']==16
assert filtered['filters']=={'severity':'high','module':'api'}
assert request('/v1/scans/'+scan['id']+'/findings?severity=high&module=api')==filtered['findings']
assert all(f['review_retest_id'] is None for f in filtered['findings'])

# A smaller linked retest copies the original directory-only scope, with fresh consent.
original_id=report['scan']['id']
first_run=request('/v1/scans')[ -1 ]
assert first_run['modules']==['directories']
retest=request('/v1/scans',{'target_id':'local-lab','authorization_confirmed':True,'modules':['directories'],'retest_of':first_run['id']},key='ci-linked-retest-0007')
for attempt in range(30):
    value=request('/v1/scans/'+retest['id'])
    if value['status']=='completed':break
    time.sleep(1)
else:raise RuntimeError('Linked retest timed out')
comparison=request('/v1/scans/'+retest['id']+'/retest-comparison')
assert len(comparison['still_observed'])==3 and comparison['not_observed']==[]
assert 'No automatic fixed' in comparison['conclusion']
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
print('Real fixture run passed: directory-only 4/3 , combined7/4 and three-module13/5 fixture checks/findings; scanner network membership checked.')

import threading
import httpx
import pytest
from fastapi.testclient import TestClient
from fuzzcore.api import create_app
from fuzzcore.core import database,run_scan
TOKEN='dns-fixture-tests-not-secret'


@pytest.mark.parametrize('wildcard',[False,True])
def test_real_local_dns_positive_and_wildcard_controls(tmp_path,wildcard):
    from fuzzcore.dns_fixture import server
    from fuzzcore.subdomains import dns_probe
    fixture=server(('127.0.0.1',0),wildcard=wildcard)
    thread=threading.Thread(target=fixture.serve_forever);thread.start()
    try:
        sessions=database('sqlite:///'+str(tmp_path/'dns.db'))
        c=TestClient(create_app(sessions,lambda _:None,TOKEN),headers={'Authorization':'Bearer '+TOKEN})
        response=c.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':['subdomains']},headers={'Idempotency-Key':'dns-fixture-001'})
        assert response.status_code==202
        scan=response.json()['id']
        run_scan(scan,sessions,lambda _:pytest.fail('DNS discovered name followed with HTTP'),pause=lambda _:None,dns_probe=dns_probe('127.0.0.1',fixture.server_address[1]))
        row=c.get('/v1/scans/'+scan).json()
        assert row['attempted']==row['planned']==3 and row['status']=='completed'
        findings=c.get('/v1/scans/'+scan+'/findings').json()
        assert len(findings)==(0 if wildcard else 1)
        if not wildcard:
            assert findings[0]['path']=='app.lab.invalid' and findings[0]['module']=='subdomains'
            assert findings[0]['severity']=='informational' and findings[0]['confidence']=='observed'
            assert findings[0]['evidence']['rule_id']=='local-dns-discovery-v1'
            assert findings[0]['evidence']['records']==['192.0.2.10']
    finally:
        fixture.shutdown();fixture.server_close();thread.join()


def test_dns_probe_rejects_arbitrary_names_and_uses_no_external_resolver():
    from fuzzcore.subdomains import dns_probe
    seen=[]
    def exchange(message,where,**kwargs):
        import dns.message,dns.rcode
        seen.append((str(message.question[0].name),where,kwargs))
        response=dns.message.make_response(message);response.set_rcode(dns.rcode.NXDOMAIN)
        return response
    probe=dns_probe('127.0.0.1',5353,exchange=exchange)
    with pytest.raises(ValueError):probe('external.invalid')
    for case in ['baseline','control','seeded']:probe(case)
    assert len(seen)==3 and all((name=='lab.invalid.' or name.endswith('.lab.invalid.')) and dest=='127.0.0.1' and args['port']==5353 and args['timeout']==2 for name,dest,args in seen)
    assert seen[1][0].startswith('control-') and seen[2][0]=='app.lab.invalid.'


def test_dns_gateway_does_not_accept_user_destination(monkeypatch):
    import fuzzcore.subdomains as module
    from fuzzcore.scanner import create_scanner
    monkeypatch.setattr(module,'production_probe',lambda case:{'name':'app.lab.invalid','records':['192.0.2.10'],'rcode':0})
    c=TestClient(create_scanner(delay=lambda _:None))
    assert c.get('/dns-check',params={'case':'external.invalid'}).status_code==422
    assert c.get('/dns-check',params={'case':'seeded'}).status_code==200


def test_dns_errors_and_unexpected_records_do_not_produce_discoveries():
    from fuzzcore.subdomains import discover
    baseline={'name':'lab.invalid','records':[],'rcode':3}
    control={'name':'control.lab.invalid','records':[],'rcode':3}
    for result in [dict(name='app.lab.invalid',records=[],rcode=3),dict(name='external.invalid',records=['192.0.2.10'],rcode=0),dict(name='app.lab.invalid',records=['169.254.169.254'],rcode=0)]:
        assert discover({'baseline':baseline,'control':control,'seeded':result}) is None

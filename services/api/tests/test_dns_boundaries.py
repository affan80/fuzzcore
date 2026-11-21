import pytest
import dns.message
import dns.flags
import dns.rrset
from fuzzcore.subdomains import dns_probe


def response_for(query):
    result=dns.message.make_response(query)
    result.flags|=dns.flags.AA
    result.answer.append(dns.rrset.from_text('app.lab.invalid.',30,'IN','A','192.0.2.10'))
    return result


def test_probe_does_not_request_recursion_and_exports_bounded_dns_metadata():
    seen=[]
    def exchange(query,where,**kwargs):
        seen.append(query)
        return response_for(query)
    value=dns_probe('127.0.0.1',exchange=exchange)('seeded')
    assert not seen[0].flags & dns.flags.RD
    assert value['dns_metadata']=={'authoritative':True,'recursion_available':False,'truncated':False,'alias_observed':False,'scope':'isolated_fixture_only'}


@pytest.mark.parametrize('mutation',['truncated','wrong_question','wrong_class'])
def test_invalid_dns_envelopes_fail_closed(mutation):
    def exchange(query,where,**kwargs):
        result=response_for(query)
        if mutation=='truncated':result.flags|=dns.flags.TC
        if mutation=='wrong_question':result.question=dns.message.make_query('foreign.invalid','A').question
        if mutation=='wrong_class':result.question=dns.message.make_query('app.lab.invalid','A','CH').question
        return result
    with pytest.raises(ValueError):dns_probe('127.0.0.1',exchange=exchange)('seeded')


def test_alias_is_metadata_only_never_followed_or_a_record_discovery():
    calls=[]
    def exchange(query,where,**kwargs):
        calls.append(where)
        result=response_for(query)
        result.answer.insert(0,dns.rrset.from_text('app.lab.invalid.',30,'IN','CNAME','external.invalid.'))
        return result
    result=dns_probe('127.0.0.1',exchange=exchange)('seeded')
    assert result['records']==[] and result['dns_metadata']['alias_observed'] is True
    assert calls==['127.0.0.1'] and 'external.invalid' not in str(result)


def test_actual_udp_fixture_exposes_metadata_without_extra_lookup():
    import threading
    from fuzzcore.dns_fixture import server
    fixture=server(('127.0.0.1',0));thread=threading.Thread(target=fixture.serve_forever);thread.start()
    try:
        value=dns_probe('127.0.0.1',port=fixture.server_address[1])('seeded')
        assert value['records']==['192.0.2.10']
        assert value['dns_metadata']=={'authoritative':False,'recursion_available':False,'truncated':False,'alias_observed':False,'scope':'isolated_fixture_only'}
    finally:fixture.shutdown();fixture.server_close();thread.join()


def test_recursion_available_is_observation_not_vulnerability_or_followup():
    calls=[]
    def exchange(query,where,**kwargs):
        calls.append(where);result=response_for(query);result.flags|=dns.flags.RA;return result
    value=dns_probe('127.0.0.1',exchange=exchange)('seeded')
    assert value['dns_metadata']['recursion_available'] is True
    assert calls==['127.0.0.1'] and set(value)=={'name','records','rcode','dns_metadata'}


def test_dns_failure_is_counted_once_and_no_discovery_is_fabricated(tmp_path):
    from fuzzcore.api import create_app
    from fuzzcore.core import database,run_scan
    from fastapi.testclient import TestClient
    sessions=database('sqlite:///'+str(tmp_path/'failed-dns.db'))
    client=TestClient(create_app(sessions,lambda _:None,'fixture-tests-not-secret'),headers={'Authorization':'Bearer fixture-tests-not-secret'})
    scan=client.post('/v1/scans',json={'target_id':'local-lab','authorization_confirmed':True,'modules':['subdomains']},headers={'Idempotency-Key':'dns-boundaries-001'}).json()['id']
    def invalid(case):raise ValueError('Unexpected or truncated DNS response')
    run_scan(scan,sessions,lambda _:pytest.fail('unexpected HTTP'),pause=lambda _:None,dns_probe=invalid)
    state=client.get('/v1/scans/'+scan).json()
    assert state['status']=='failed' and state['attempted']==1 and state['planned']==3
    assert client.get('/v1/scans/'+scan+'/findings').json()==[]

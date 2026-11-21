"""Three bounded local-DNS observations. Discovered names never authorize HTTP."""
import secrets
import socket
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
CASES=('baseline','control','seeded')


def dns_probe(destination,port=5353,exchange=dns.query.udp):
    def probe(case):
        if case not in CASES:raise ValueError('Out-of-scope DNS case')
        name={'baseline':'lab.invalid','seeded':'app.lab.invalid'}.get(case)
        if name is None:name='control-'+secrets.token_hex(6)+'.lab.invalid'
        query=dns.message.make_query(name,'A',use_edns=False)
        response=exchange(query,destination,port=port,timeout=2,raise_on_truncation=True)
        records=[]
        if response.rcode()==dns.rcode.NOERROR:
            for rrset in response.answer:
                if rrset.rdtype==dns.rdatatype.A and str(rrset.name).rstrip('.')==name:
                    records.extend(record.address for record in rrset)
        return {'name':name,'records':sorted(set(records))[:4],'rcode':response.rcode()}
    return probe


def production_probe(case):
    # Resolve only the preconfigured Docker fixture service, never a candidate.
    return dns_probe(socket.gethostbyname('dns-lab'),5353)(case)


def discover(results):
    seeded=results['seeded']
    if seeded['name']!='app.lab.invalid' or seeded['rcode']!=0 or seeded['records']!=['192.0.2.10']:return None
    if any(results[case]['rcode'] not in (0,3) for case in ('baseline','control')):return None
    if any(results[case]['records'] and results[case]['records']==seeded['records'] for case in ('baseline','control')):return None
    return {'path':'app.lab.invalid','records':seeded['records'],
        'evidence':{'rule_id':'local-dns-discovery-v1','records':seeded['records'],'controls':results,
            'scope':'Local synthetic DNS discovery only. No HTTP follow-up, ownership or takeover claim.',
            'remediation':'Review whether this fixture name should be listed. DNS resolution alone is not a vulnerability.'}}

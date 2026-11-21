"""Harmless fixed-marker observations, never SQL/XSS/RCE exploitation."""
import hashlib
import json
ALPHA='fc-alpha-7f23'
BETA='fc-beta-7f23'
CASES={
    'baseline':[],
    'alpha':[('q',ALPHA)],
    'beta':[('q',BETA)],
    'duplicate':[('q',ALPHA),('q',BETA)],
    'quoted':[('q',ALPHA+"'\"")],
    'encoded':[('q',ALPHA+' +&')],
}


def http_parameter_probe(client):
    def probe(case):
        if case not in CASES:raise ValueError('Out-of-scope parameter case')
        with client.stream('GET','/parameter-fixture',params=CASES[case],headers={'Accept-Encoding':'identity'}) as response:
            body=bytearray()
            for chunk in response.iter_bytes(chunk_size=4096):
                if len(body)+len(chunk)>16384:raise ValueError('Fixture evidence budget exceeded')
                body.extend(chunk)
            try:value=json.loads(body)
            except (ValueError,UnicodeError):value={}
            if not isinstance(value,dict):value={}
            values=value.get('values')
            if not isinstance(values,list):values=[]
            # Nothing supplied by a target becomes evidence text. Compare only
            # our own known markers, then retain booleans and coarse modes.
            expected=[item[1] for item in CASES[case]]
            return {'status_code':response.status_code,'fixture':value.get('fixture') is True,
                'body_sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body),
                'alpha_present':ALPHA in values,'beta_present':BETA in values,
                'exact_echo':bool(expected) and values==expected,
                'duplicate_mode':'both' if values==[ALPHA,BETA] else 'single' if values in ([ALPHA],[BETA]) else 'other'}
    return probe


def assess(results):
    if not all(results.get(case,{}).get('status_code')==200 and results[case].get('fixture') is True for case in CASES):return []
    if results['baseline'].get('alpha_present') or results['baseline'].get('beta_present'):return []
    signals=[]
    def signal(rule,summary,fix):
        return {'path':'/parameter-fixture?q','summary':summary,'evidence':{
            'rule_id':rule,'controls':results,'scope':'Harmless fixed-marker fixture observations only.',
            'remediation':fix}}
    if all(results[c].get('exact_echo') for c in ('alpha','beta','quoted','encoded')):
        signals.append(signal('parameter-reflection-signal-v1',
            'The fixture returned known markers including quotes and encoded characters; not proof of XSS, SQL injection or code execution.',
            'Apply context-appropriate output encoding and typed input validation. Reflection in JSON alone is not a vulnerability.'))
    if results['alpha'].get('exact_echo') and results['beta'].get('exact_echo') and results['duplicate'].get('duplicate_mode')=='both':
        signals.append(signal('duplicate-parameter-signal-v1',
            'The fixture retained two values for one parameter name; not proof of an authorization bypass or exploitable parser mismatch.',
            'Where one value is expected, reject duplicate parameters and validate the same parsed value that is used.'))
    return signals

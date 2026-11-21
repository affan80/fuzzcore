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
                'parser_mismatch':case=='duplicate' and value.get('validation_value')==ALPHA and value.get('effective_value')==BETA,
                'synthetic_parse_error':value.get('error_kind')=='synthetic_parse_error',
                'duplicate_mode':'both' if values==[ALPHA,BETA] else 'single' if values in ([ALPHA],[BETA]) else 'other'}
    return probe


def assess(results):
    if set(results)!=set(CASES) or not all(results[case].get('fixture') is True for case in CASES):return []
    if not all(results[case].get('status_code')==200 for case in ('baseline','alpha','beta','duplicate','encoded')):return []
    if results['quoted'].get('status_code') not in (200,500):return []
    if results['baseline'].get('alpha_present') or results['baseline'].get('beta_present'):return []
    signals=[]
    def signal(rule,summary,fix,status=200):
        return {'path':'/parameter-fixture?q','status_code':status,'summary':summary,'evidence':{
            'parameter_discovery':{'name':'q','scope':'fixed_fixture_only','distinct_marker_controls':bool(results['alpha'].get('exact_echo') and results['beta'].get('exact_echo'))},
            'rule_id':rule,'controls':results,'scope':'Harmless fixed-marker fixture observations only.',
            'remediation':fix}}
    if results['quoted'].get('status_code')==200 and all(results[c].get('exact_echo') for c in ('alpha','beta','quoted','encoded')):
        signals.append(signal('parameter-reflection-signal-v1',
            'The fixture returned known markers including quotes and encoded characters; not proof of XSS, SQL injection or code execution.',
            'Apply context-appropriate output encoding and typed input validation. Reflection in JSON alone is not a vulnerability.'))
    if results['alpha'].get('exact_echo') and results['beta'].get('exact_echo') and results['duplicate'].get('duplicate_mode')=='both':
        signals.append(signal('duplicate-parameter-signal-v1',
            'The fixture retained two values for one parameter name; not proof of an authorization bypass or exploitable parser mismatch.',
            'Where one value is expected, reject duplicate parameters and validate the same parsed value that is used.'))
    if results['alpha'].get('exact_echo') and results['beta'].get('exact_echo') and results['duplicate'].get('duplicate_mode')=='both' and results['duplicate'].get('parser_mismatch'):
        signals.append(signal('parameter-parser-mismatch-signal-v1',
            'The synthetic fixture validated the first known value and used the second; not proof of an authorization bypass or exploitable injection.',
            'Reject duplicates where one value is expected and ensure validation and use share the same canonical value. No fix was applied.'))
    if results['alpha'].get('exact_echo') and results['beta'].get('exact_echo') and results['quoted'].get('status_code')==500 and results['quoted'].get('synthetic_parse_error'):
        signals.append(signal('parameter-error-differential-signal-v1',
            'A harmless quoted marker triggered the named synthetic fixture error while baseline markers succeeded; not proof of SQL injection, XSS or code execution.',
            'Handle parsing failures consistently, validate input types and avoid exposing internal error details. No exploit or fix was executed.',500))
    return signals

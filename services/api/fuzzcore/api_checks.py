"""Six fixed read-only checks against the deliberately seeded two-user lab."""
import hashlib
import json

CASES = {
    'missing':('/api/fixture/missing',None),
    'anonymous':('/api/fixture/objects/alice-owned',None),
    'alice-own':('/api/fixture/objects/alice-owned','alice'),
    'alice-denied':('/api/fixture/objects/bob-owned','alice'),
    'bob-own':('/api/fixture/objects/bob-vulnerable','bob'),
    'alice-cross':('/api/fixture/objects/bob-vulnerable','alice'),
}


def http_api_probe(client):
    def probe(case):
        if case not in CASES:
            raise ValueError('Out-of-scope API case')
        path, actor = CASES[case]
        headers = {'X-Fixture-Actor':actor} if actor else {}
        with client.stream('GET',path,headers={**headers,'Accept-Encoding':'identity'}) as response:
            body=bytearray()
            for chunk in response.iter_bytes(chunk_size=4096):
                if len(body)+len(chunk)>16384:
                    raise ValueError('Fixture evidence budget exceeded')
                body.extend(chunk)
            try:
                value=json.loads(body)
            except (ValueError,UnicodeError):
                value={}
            if not isinstance(value,dict):value={}
            return {'status_code':response.status_code, 'bytes':len(body),
                'body_sha256':hashlib.sha256(body).hexdigest(),
                'fixture':value.get('fixture') is True,
                'owner':value.get('owner') if value.get('owner') in ('alice','bob') else 'unknown',
                'object':value.get('object') if value.get('object') in ('alice-owned','bob-owned','bob-vulnerable') else 'unknown'}
    return probe


def assess(results):
    if not all(results.get(case,{}).get('status_code')==status for case,status in
               [('missing',404),('anonymous',401),('alice-own',200),('alice-denied',403),('bob-own',200),('alice-cross',200)]):
        return None
    for case,owner,obj in [('alice-own','alice','alice-owned'),('bob-own','bob','bob-vulnerable'),('alice-cross','bob','bob-vulnerable')]:
        value=results[case]
        if value.get('fixture') is not True or value.get('owner')!=owner or value.get('object')!=obj:
            return None
    return {'rule_id':'fixture-object-ownership-v1','severity':'high','confidence':'fixture-confirmed',
        'path':'/api/fixture/objects/bob-vulnerable',
        'summary':'Seeded lab ownership defect: fixture actor Alice received Bob\'s known object. This proof applies only to this synthetic fixture.',
        'evidence':{'rule_id':'fixture-object-ownership-v1','controls':results,
            'scope':'Synthetic two-actor lab only. No real account or third-party authorization was tested.',
            'remediation':'Check object ownership server-side on every object access. Deny cross-owner reads and rerun the same fixture checks.',
            'reference':'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'}}

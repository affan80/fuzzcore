"""Curated read-only endpoint inventory. Discoveries, never transport vulnerability claims."""
import hashlib
import json
import secrets
CASES=('control','public','protected','hidden')
PATHS={case:'/api/inventory/'+case for case in CASES if case!='control'}


def http_inventory_probe(client):
    def probe(case):
        if case not in CASES:raise ValueError('Unknown curated inventory case')
        path='/api/inventory/missing-control-'+secrets.token_hex(12) if case=='control' else PATHS[case]
        with client.stream('GET',path,headers={'Accept-Encoding':'identity'}) as response:
            body=bytearray()
            for chunk in response.iter_bytes(chunk_size=4096):
                if len(body)+len(chunk)>16384:raise ValueError('Inventory evidence budget exceeded')
                body.extend(chunk)
            try:value=json.loads(body)
            except (ValueError,UnicodeError):value={}
            if not isinstance(value,dict):value={}
            return {'status_code':response.status_code,'bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest(),
                'fixture':value.get('fixture') is True,'route':value.get('route') if value.get('route') in ('public','protected','hidden','missing') else 'unknown',
                'transport':{'scheme':response.request.url.scheme,'scope':'isolated_fixture_only'},
                'security_headers':{'content_type_json':response.headers.get('content-type','').split(';',1)[0]=='application/json',
                    'nosniff':response.headers.get('x-content-type-options','').lower()=='nosniff','hsts_present':'strict-transport-security' in response.headers,'csp_present':'content-security-policy' in response.headers}}
    return probe


def valid_control(value):return value.get('status_code')==404 and value.get('fixture') is True and value.get('route')=='missing'


def assess(values):
    if set(values)!=set(CASES) or not valid_control(values['control']):return []
    found=[]
    for case in CASES[1:]:
        result=values[case]
        if result.get('status_code')!=(401 if case=='protected' else 200) or result.get('fixture') is not True or result.get('route')!=case or result.get('body_sha256')==values['control'].get('body_sha256'):continue
        found.append({'path':PATHS[case],'status_code':result['status_code'],'summary':'Curated lab API route identified as '+case+'. Header/transport metadata is informational and does not prove a production weakness.',
            'evidence':{'rule_id':'curated-api-discovery-v1','case_version':'inventory-v1','access':case,'control':values['control'],'response':result,
                'transport':result['transport'],'security_headers':result['security_headers'],
                'remediation':'Confirm each route is intentionally exposed and enforce server-side authorization. Use trusted HTTPS at the real client-facing boundary. Header presence alone does not establish safe configuration; isolated fixture HTTP is not a production finding. No changes were applied.'}})
    return found

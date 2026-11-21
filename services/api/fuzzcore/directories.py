"""Bounded directory signatures, with a fresh missing-path control per run."""
import hashlib
import secrets

PATHS=('/', '/health', '/api/status', '/missing-control-7f23')


def http_directory_probe(client):
    def probe(path):
        if path not in PATHS:raise ValueError('Out-of-scope directory path')
        destination='/missing-control-'+secrets.token_hex(12) if path==PATHS[-1] else path
        with client.stream('GET',destination,headers={'Accept-Encoding':'identity'}) as response:
            body=bytearray()
            for chunk in response.iter_bytes(chunk_size=4096):
                if len(body)+len(chunk)>16384:raise ValueError('Directory evidence budget exceeded')
                body.extend(chunk)
            return {'path':path,'status_code':response.status_code,'bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest()}
    return probe


def discover(values):
    control=values.get(PATHS[-1])
    if not control:return []
    if not (200<=control['status_code']<300 or control['status_code']==404):raise ValueError('Directory baseline unavailable')
    def signature(value):return {key:value[key] for key in ('status_code','bytes','body_sha256')}
    baseline=signature(control)
    return [{'path':path,'status_code':value['status_code'],'evidence':{
        'rule_id':'directory-control-v1','baseline':baseline,'candidate':signature(value),
        'remediation':'Confirm intended publication. Remove unnecessary resources or require server-side authorization. A differing resource is discovery, not a vulnerability.'}}
        for path in PATHS[:-1] if (value:=values.get(path)) and 200<=value['status_code']<300 and signature(value)!=baseline]

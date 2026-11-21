"""Synthetic in-memory traversal canary. Never opens or includes a host file."""
import hashlib

CASES=('public','denied','canary')
NAMES={'public':'public.txt','denied':'../../outside.txt','canary':'../canary.txt'}
PUBLIC=b'FUZZCORE_PUBLIC_FIXTURE_v1'
CANARY=b'FUZZCORE_SYNTHETIC_CANARY_v1'


def http_file_probe(client):
    def probe(case):
        if case not in CASES:raise ValueError('Unknown synthetic file case')
        with client.stream('GET','/file-fixture',params={'name':NAMES[case]},headers={'Accept-Encoding':'identity'}) as response:
            body=bytearray()
            for chunk in response.iter_bytes(chunk_size=4096):
                if len(body)+len(chunk)>16384:raise ValueError('File fixture evidence budget exceeded')
                body.extend(chunk)
            expected={'public':PUBLIC,'canary':CANARY}.get(case)
            return {'status_code':response.status_code,'bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest(),
                    'known_marker':expected is not None and bytes(body)==expected}
    return probe


def assess(values):
    if set(values)!=set(CASES):return None
    public,denied,canary=(values[key] for key in CASES)
    if public['status_code']!=200 or public['known_marker'] is not True or denied['status_code']!=403 or canary['status_code']!=200 or canary['known_marker'] is not True:return None
    return {'path':'/file-fixture [synthetic traversal case]', 'severity':'medium','confidence':'fixture-confirmed',
            'summary':'Known synthetic canary returned despite the fixture allowlist boundary; no host files were read or included.',
            'evidence':{'rule_id':'fixture-path-allowlist-v1','case_version':'canary-v1','controls':values,
                'remediation':'Use server-side file identifiers and an allowlist. If paths are necessary, validate resolved containment before reading. This recommendation has not been applied automatically.'}}

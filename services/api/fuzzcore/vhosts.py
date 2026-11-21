"""Fixed-fixture virtual-host discovery. Hash evidence, never raw response bodies."""
import hashlib
import secrets

CASES = ('default', 'control', 'seeded')
MAX_BODY_BYTES = 16384


def http_vhost_probe(client):
    def probe(case):
        if case not in CASES:
            raise ValueError('Out-of-scope vhost case')
        host = {'default':'default.lab.invalid', 'seeded':'admin.lab.invalid'}.get(case)
        if host is None:
            host = 'control-' + secrets.token_hex(6) + '.lab.invalid'
        # Host affects routing only. The HTTP destination stays on the supplied
        # trusted client, which production pins to the isolated lab service.
        with client.stream('GET', '/', headers={'Host':host,'Accept-Encoding':'identity'}) as response:
            digest = hashlib.sha256()
            size = 0
            for chunk in response.iter_bytes(chunk_size=4096):
                size += len(chunk)
                if size > MAX_BODY_BYTES:
                    raise ValueError('Fixture response exceeds evidence budget')
                digest.update(chunk)
            return {'host':host,'status_code':response.status_code,'body_sha256':digest.hexdigest(),'bytes':size}
    return probe


def discover(results):
    def signature(item):
        return (item['status_code'], item['body_sha256'], item['bytes'])
    seeded = results['seeded']
    if not 200 <= seeded['status_code'] < 300:
        return None
    if any(signature(seeded) == signature(results[case]) for case in ('default','control')):
        return None
    return {
        'host':seeded['host'], 'status_code':seeded['status_code'],
        'evidence':{'rule_id':'vhost-difference-v1','baseline':results,
                    'meaning':'Different fixture response, not proof of tenant isolation failure.'},
    }

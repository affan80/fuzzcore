"""Deterministic fixture server. Not a deployable third-party target."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
from urllib.parse import urlsplit, parse_qs

class Handler(BaseHTTPRequestHandler):
    # Synthetic actors are fixture switches, not real authentication credentials.
    allow_seeded_cross_owner = True

    parameter_signals = True
    directory_soft404 = False

    def do_POST(self):
        # Named stateless disposable scenario: no files, DB changes or retained data.
        if self.path!='/custom-disposable':
            self.send_error(404);return
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 1<=length<=256 or self.headers.get('Content-Type')!='application/json' or self.headers.get('Transfer-Encoding'):
                raise ValueError('Invalid fixture input')
            value=json.loads(self.rfile.read(length))
            if not isinstance(value,dict) or set(value)!={'marker'} or not isinstance(value['marker'],str) or not re.fullmatch(r'[A-Za-z0-9 _-]{1,64}',value['marker']):
                raise ValueError('Invalid fixture marker')
        except (ValueError,UnicodeError):
            self.send_error(400);return
        body=json.dumps({'fixture':True,'disposable':True,'marker_accepted':True}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json')
        self.send_header('X-Fixture-Mode','disposable')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)

    def do_GET(self):
        parsed=urlsplit(self.path)
        if parsed.path=='/custom-fixture':
            body=b'custom fixture marker ready'
            self.send_response(200);self.send_header('Content-Type','text/plain')
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            return
        if parsed.path=='/parameter-fixture':
            values=parse_qs(parsed.query,keep_blank_values=True,max_num_fields=8).get('q',[])
            status=200
            if not self.parameter_signals:
                if len(values)>1:status=400
                values=[]
            body=json.dumps({'fixture':True,'values':values}).encode()
            self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            return
        if self.path.startswith('/api/fixture/'):
            actor = self.headers.get('X-Fixture-Actor')
            objects = {'alice-owned':'alice','bob-owned':'bob','bob-vulnerable':'bob'}
            obj = self.path.removeprefix('/api/fixture/objects/')
            status, value = 404, {'fixture':True}
            if obj in objects:
                owner = objects[obj]
                if actor not in ('alice','bob'):
                    status = 401
                elif actor != owner and not (obj=='bob-vulnerable' and self.allow_seeded_cross_owner):
                    status = 403
                else:
                    status, value = 200, {'fixture':True,'owner':owner,'object':obj}
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)))
            self.end_headers();self.wfile.write(body)
            return
        found = self.path in ('/', '/health', '/api/status')
        body = b'{"fixture":true}' if found else b'not found'
        if self.headers.get('Host') == 'admin.lab.invalid' and self.path == '/':
            body = b'{"fixture":true,"vhost":"admin"}'
        if self.directory_soft404 and (self.path in ('/','/health','/api/status') or self.path.startswith('/missing-control-')):
            found=True;body=b'synthetic soft404 baseline'
        self.send_response(200 if found else 404)
        self.send_header('Content-Type', 'application/json' if found else 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    HTTPServer(('0.0.0.0', 8081), Handler).serve_forever()

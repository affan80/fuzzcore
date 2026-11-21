"""Deterministic fixture server. Not a deployable third-party target."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
import threading
import time
from urllib.parse import urlsplit, parse_qs

class Handler(BaseHTTPRequestHandler):
    # Synthetic actors are fixture switches, not real authentication credentials.
    allow_seeded_cross_owner = True

    parameter_signals = True
    directory_soft404 = False
    allow_seeded_canary = True

    uploads={}
    upload_lock=threading.Lock()
    upload_ttl_seconds=300

    def upload_id(self):
        match=re.fullmatch(r'/upload-fixture/([a-f0-9]{32})',self.path)
        return match[1] if match else None

    @classmethod
    def expire_upload(cls,object_id,expires_at):
        with cls.upload_lock:
            if cls.uploads.get(object_id,{}).get('expires_at')==expires_at:cls.uploads.pop(object_id,None)

    def upload_reply(self,status,body=b''):
        self.send_response(status);self.send_header('Content-Type','application/octet-stream')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)

    def do_DELETE(self):
        object_id=self.upload_id()
        if object_id is None:self.send_error(404);return
        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length','0')!='0':self.send_error(400);return
        with self.upload_lock:
            value=self.uploads.pop(object_id,None)
            if value:value['timer'].cancel()
        self.upload_reply(204)

    def do_POST(self):
        if self.path.startswith('/upload-fixture/'):
            object_id=self.upload_id();marker=b'FUZZCORE_BENIGN_UPLOAD_FIXTURE_v1'
            try:
                length=int(self.headers.get('Content-Length','0'))
                if object_id is None or length!=len(marker) or self.headers.get('Content-Type')!='application/octet-stream' or self.headers.get('Transfer-Encoding'):raise ValueError()
                if self.rfile.read(length)!=marker:raise ValueError()
            except ValueError:self.send_error(400);return
            with self.upload_lock:
                if object_id in self.uploads:self.send_error(409);return
                if len(self.uploads)>=64:self.send_error(503);return
                expires_at=time.monotonic()+self.upload_ttl_seconds
                timer=threading.Timer(self.upload_ttl_seconds,type(self).expire_upload,args=(object_id,expires_at));timer.daemon=True
                self.uploads[object_id]={'timer':timer,'expires_at':expires_at};timer.start()
            self.upload_reply(201,b'created');return

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
        if parsed.path.startswith('/upload-fixture/'):
            object_id=self.upload_id()
            if object_id is None:self.send_error(404);return
            with self.upload_lock:
                value=self.uploads.get(object_id)
                exists=value is not None and value['expires_at']>time.monotonic()
            self.upload_reply(200 if exists else 404,b'FUZZCORE_BENIGN_UPLOAD_FIXTURE_v1' if exists else b'absent');return

        if parsed.path=='/file-fixture':
            # Symbolic dictionary response only. Never opens, resolves or includes a file.
            values=parse_qs(parsed.query,max_num_fields=1).get('name',[])
            name=values[0] if len(values)==1 else ''
            status,body=403,b'denied'
            if name=='public.txt':status,body=200,b'FUZZCORE_PUBLIC_FIXTURE_v1'
            elif name=='../canary.txt' and self.allow_seeded_canary:status,body=200,b'FUZZCORE_SYNTHETIC_CANARY_v1'
            self.send_response(status);self.send_header('Content-Type','text/plain')
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            return
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
        if parsed.path.startswith('/api/inventory/'):
            route=parsed.path.removeprefix('/api/inventory/');known=route in ('public','protected','hidden')
            status=401 if route=='protected' else 200 if known else 404
            body=json.dumps({'fixture':True,'route':route if known else 'missing'}).encode()
            self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return
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

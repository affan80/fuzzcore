"""Deterministic fixture server. Not a deployable third-party target."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    # Synthetic actors are fixture switches, not real authentication credentials.
    allow_seeded_cross_owner = True

    def do_GET(self):
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
        self.send_response(200 if found else 404)
        self.send_header('Content-Type', 'application/json' if found else 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    HTTPServer(('0.0.0.0', 8081), Handler).serve_forever()

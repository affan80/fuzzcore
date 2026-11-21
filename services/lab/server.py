"""Deterministic fixture server. Not a deployable third-party target."""
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
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

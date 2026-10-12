#!/usr/bin/env python3
"""VERDICT-v0.9 REST API server.
Upload a binary, get JSON analysis with evidence chains.
"""
import os, sys, json, tempfile, time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from batch import analyze

class MuseHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self._json({'status': 'ok', 'version': '0.9.0', 'engine': 'VERDICT-v0.7'})
        elif self.path == '/':
            self._html()
        else:
            self._json({'error': 'not found'}, 404)

    def do_POST(self):
        if self.path == '/analyze':
            self._handle_analyze()
        elif self.path == '/diff':
            self._json({'error': 'diff mode coming in v0.9.1'}, 501)
        else:
            self._json({'error': 'not found'}, 404)

    def _handle_analyze(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0 or length > 50 * 1024 * 1024:
            self._json({'error': 'binary required (max 50MB)'}, 400)
            return
        data = self.rfile.read(length)
        # Write to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(data)
            tmppath = f.name
        try:
            t0 = time.time()
            result = analyze(tmppath)
            dt = time.time() - t0
            # Enrich with metadata
            result['verdict_version'] = '0.9.0'
            result['analysis_time_s'] = round(dt, 2)
            result['summary'] = {
                'total_sites': len(result['results']),
                'resolved': sum(1 for r in result['results'] if r['confidence']),
                'unknown': sum(1 for r in result['results'] if not r['confidence']),
            }
            self._json(result)
        except Exception as e:
            self._json({'error': str(e)}, 500)
        finally:
            os.unlink(tmppath)

    def _json(self, obj, code=200):
        body = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self):
        html = b"""<html><head><title>VERDICT v0.9 API</title></head><body>
<h1>VERDICT Binary Analysis API v0.9</h1>
<p>POST /analyze with binary data (max 50MB)</p>
<p>GET /health for status</p>
<h2>Example</h2>
<pre>curl -X POST --data-binary @/bin/ls http://localhost:8080/analyze</pre>
</body></html>"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def log_message(self, *args):
        pass  # quiet

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(('0.0.0.0', port), MuseHandler)
    print(f"VERDICT v0.9 API on http://0.0.0.0:{port}")
    print("  POST /analyze  - upload binary, get JSON")
    print("  GET  /health   - status check")
    server.serve_forever()

if __name__ == '__main__':
    main()

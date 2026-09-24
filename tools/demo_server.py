#!/usr/bin/env python3
"""Localhost UI + LAN signaling proxy, requiring only Python's standard library.
Run: python3 tools/demo_server.py --board 192.168.1.123
The proxy keeps browser microphone access on a secure localhost origin and
avoids HTTPS/mixed-content restrictions for the board's local HTTP server.
"""
import argparse
import ipaddress
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen, ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[1] / 'browser'
ALLOWED = {'GET': {'answer', 'stats', 'config'}, 'POST': {'offer', 'stop', 'mic'}}
class Handler(SimpleHTTPRequestHandler):
    board = ''
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)
    def do_GET(self):
        if self.path.startswith('/api/'): self.proxy()
        else: super().do_GET()
    def do_POST(self): self.proxy()
    def proxy(self):
        path = self.path.removeprefix('/api/')
        if path not in ALLOWED.get(self.command, set()):
            self.send_error(404); return
        # Do not let unrelated websites drive a board through this localhost proxy.
        origin = self.headers.get('Origin')
        if origin and origin != f'http://127.0.0.1:{self.server.server_port}' and origin != f'http://localhost:{self.server.server_port}':
            self.send_error(403); return
        try: size = int(self.headers.get('Content-Length', '0'))
        except ValueError: self.send_error(400); return
        if not 0 <= size <= 8192: self.send_error(413); return
        body = self.rfile.read(size) if self.command == 'POST' else None
        request = Request(f'http://{self.board}/{path}', data=body, method=self.command,
                          headers={'Content-Type': 'text/plain'})
        try:
            with build_opener(ProxyHandler({})).open(request, timeout=10) as response:
                data = response.read(32769)
                if len(data) > 32768: self.send_error(502); return
                self.send_response(response.status)
                self.send_header('Content-Type', response.headers.get('Content-Type', 'text/plain'))
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers(); self.wfile.write(data)
        except HTTPError as error: self.send_error(error.code, 'Board rejected request')
        except (URLError, TimeoutError, OSError): self.send_error(502, 'Cannot reach ESP32')
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--board', required=True, type=ipaddress.IPv4Address)
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    Handler.board = str(args.board)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    print(f'Open http://localhost:{args.port}; signaling to {args.board}', flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: server.server_close()

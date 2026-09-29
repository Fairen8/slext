#!/usr/bin/env python3
"""SLExt test origin — лёгкая заглушка для тестового сайта SafeLine.

Отдаёт понятную страницу с маркером, умеет /slow (задержка), /health,
/asset.js и /missing (404) — для проверки страниц ошибок, зала ожидания,
логов и теста ёмкости на тестовом контуре. Без внешних зависимостей.
"""
import json
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 8088
START = time.time()
PAGE = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SLExt Test Origin</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif;
background:linear-gradient(160deg,#0b1420,#10233a);color:#e8eef7}
.card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:20px;
padding:36px 42px;text-align:center;box-shadow:0 30px 80px -30px rgba(0,0,0,.7)}
.badge{display:inline-block;padding:6px 12px;border-radius:999px;font-size:12px;letter-spacing:.12em;
text-transform:uppercase;color:#7ef0e6;border:1px solid rgba(126,240,230,.35);margin-bottom:14px}
h1{margin:0 0 8px;font-size:26px}p{color:#93a4bd;margin:6px 0 0;font-size:14px}
code{color:#7ef0e6}
</style></head><body>
<div class="card" data-slext-test-origin="1">
  <div class="badge">SafeLine test contour</div>
  <h1>SLExt Test Origin</h1>
  <p>живой ответ заглушки · <code>%s</code></p>
  <p>uptime: %d c · маркер: <code>data-slext-test-origin</code></p>
</div></body></html>"""


class H(BaseHTTPRequestHandler):
    server_version = 'SLExtTestOrigin/1.0'
    protocol_version = 'HTTP/1.1'

    def _send(self, code, body, ctype='text/html; charset=utf-8'):
        data = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == '/health':
            self._send(200, json.dumps({'ok': True, 'uptime': int(time.time() - START)}),
                       'application/json')
            return
        if u.path == '/slow':
            try:
                ms = min(30000, max(0, int(qs.get('ms', ['500'])[0])))
            except ValueError:
                ms = 500
            time.sleep(ms / 1000.0)
            self._send(200, PAGE % (time.ctime(), int(time.time() - START)))
            return
        if u.path == '/asset.js':
            self._send(200, 'window.SLEXT_TEST_ORIGIN=1;\n', 'application/javascript')
            return
        if u.path == '/missing':
            self._send(404, 'not found', 'text/plain; charset=utf-8')
            return
        self._send(200, PAGE % (time.ctime(), int(time.time() - START)))

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, fmt, *args):
        print('[teststub] %s %s' % (self.address_string(), fmt % args), flush=True)


def main():
    srv = ThreadingHTTPServer(('0.0.0.0', PORT), H)
    srv.daemon_threads = True
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    print('[teststub] on :%d pid=%d host=%s' % (PORT, __import__('os').getpid(), socket.gethostname()),
          flush=True)
    main()

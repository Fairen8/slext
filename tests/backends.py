#!/usr/bin/env python3
import http.server
import os
import socketserver

PORT = int(os.environ.get('PORT', '9101'))
NAME = os.environ.get('NAME', str(PORT))


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ('backend %s path=%s' % (NAME, self.path)).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


socketserver.TCPServer.allow_reuse_address = True
http.server.ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()

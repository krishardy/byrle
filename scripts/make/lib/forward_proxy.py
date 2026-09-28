"""A plain-HTTP forward proxy that logs each request it carries, for smoke-proxy.sh.

Usage: forward_proxy.py <port> <log file>
"""
import http.server
import sys
import urllib.request

DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Forward(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(sys.argv[2], "a", encoding="utf-8") as log:
            log.write(f"GET {self.path}\n")
        try:
            upstream = DIRECT.open(self.path, timeout=10)
            status, body = upstream.status, upstream.read()
        except urllib.error.HTTPError as e:
            status, body = e.code, e.read()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Forward).serve_forever()

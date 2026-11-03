"""Pass-through proxy in front of the AMFA engine.

Only a /decision response's riskLevel is replaced, and only while the control
file holds a number, so a test can put a login in any tier on demand. Every
other request and response, including the login-event webhook, passes through
unchanged.

usage: risk_override_proxy.py <listen-port> <engine-url> <control-file>
"""
import http.server
import json
import socketserver
import sys
import urllib.error
import urllib.request

PORT, ENGINE, CONTROL = int(sys.argv[1]), sys.argv[2].rstrip("/"), sys.argv[3]


def forced_level():
    try:
        text = open(CONTROL).read().strip()
        return int(text) if text else None
    except (OSError, ValueError):
        return None


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        del format, args  # keep the proxy quiet

    def _proxy(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(ENGINE + self.path, data=body, method=self.command)
        for k, v in self.headers.items():
            if k.lower() not in ("host", "connection", "content-length"):
                req.add_header(k, v)
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            status, data, headers = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            status, data, headers = e.code, e.read(), e.headers
        level = forced_level()
        if self.path.split("?")[0] == "/decision" and status == 200 and level is not None:
            engine_level = json.loads(data).get("riskLevel")
            data = json.dumps({"riskLevel": level}).encode()
            print(f"decision: engine said {engine_level}, forced {level}", flush=True)
        self.send_response(status)
        for k, v in headers.items():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = _proxy
    do_POST = _proxy


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    Server(("0.0.0.0", PORT), Handler).serve_forever()

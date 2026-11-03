"""Round-robin reverse proxy in front of two Keycloak nodes (cluster mode).

Every request goes to the other node than the one before, so the steps of one
login, including the AMFA steps and the request that fires its LOGIN event,
land on both nodes. Each request is printed as: node METHOD path -> status.

usage: lb.py <listen-port> <node1-url> <node2-url>
"""
import http.client
import http.server
import itertools
import socketserver
import sys
import threading
import urllib.parse

def _node(name: str, url: str) -> tuple:
    parts = urllib.parse.urlsplit(url)
    if not parts.hostname:
        raise SystemExit(f"{name}: no host in {url!r}")
    return name, parts.hostname, parts.port


PORT = int(sys.argv[1])
NODES = [_node("n1", sys.argv[2]), _node("n2", sys.argv[3])]
_next = itertools.cycle(NODES)
_lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        del format, args  # each request is printed by _proxy instead

    def _proxy(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        with _lock:
            name, host, port = next(_next)
        conn = http.client.HTTPConnection(host, port, timeout=60)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("connection", "content-length")}
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        except OSError as e:
            self.send_error(502, f"{name} unreachable: {e}")
            print(f"{name} {self.command} {self.path.split('?')[0]} -> 502 ({e})", flush=True)
            return
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        conn.close()
        print(f"{name} {self.command} {self.path.split('?')[0]} -> {resp.status}", flush=True)

    do_GET = do_POST = do_PUT = do_DELETE = _proxy


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    Server(("0.0.0.0", PORT), Handler).serve_forever()

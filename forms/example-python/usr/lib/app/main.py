"""A small HTTP example, using only Python's standard library.

Its greeting is a setting (etc/sv/app/service): GREETING, if the machine
was given one.
"""

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

GREETING = os.environ.get("GREETING", "Hello from Python on werewolf!")


class Hello(BaseHTTPRequestHandler):
    timeout = 5

    def do_GET(self):
        path = urlsplit(self.path).path
        bodies = {"/": GREETING.encode() + b"\n", "/health": b"ok\n"}
        body = bodies.get(path, b"not found\n")
        self.send_response(200 if path in bodies else 404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Hello)
    print("app: listening on :8080", flush=True)
    server.serve_forever()

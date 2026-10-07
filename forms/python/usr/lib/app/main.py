"""The python form's application until yours replaces it: one line of
text on :8080, to show Python runs here, leashed."""

import platform
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8080


class Hello(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"werewolf: Python {platform.python_version()} is answering\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # a machine on the internet is scanned all day


server = ThreadingHTTPServer(("", PORT), Hello)
print(f"app: listening on :{PORT}")
server.serve_forever()

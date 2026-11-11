#!/usr/bin/env python3
"""EchoLike Lite inbox — the simplest server that works with the extension.

Run:   python3 server.py [--port 8911]
Store: likes.jsonl (one JSON object per line) + .token (bearer token).

Endpoints:
  GET  /api/health   -> {"ok": true}
  POST /api/likes    -> {"items": [...]} with  Authorization: Bearer <token>
                        returns {"received": N}
  GET  /             -> readable list of the last 100 captures
"""
import argparse
import html
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(HERE, ".token")
LOG_FILE = os.path.join(HERE, "likes.jsonl")


def token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as f:
            return f.read().strip()
    t = secrets.token_hex(16)
    with open(TOKEN_FILE, "w") as f:
        f.write(t)
    os.chmod(TOKEN_FILE, 0o600)
    return t


TOKEN = token()


class H(BaseHTTPRequestHandler):
    server_version = "EchoLikeLite/1.0"

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/health":
            return self._json({"ok": True})
        if self.path == "/":
            rows = []
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE) as f:
                    lines = f.readlines()[-100:]
                for ln in reversed(lines):
                    try:
                        it = json.loads(ln)
                    except ValueError:
                        continue
                    rows.append(
                        "<li><b>%s</b> @%s — %s<br><small>%s · %s</small></li>"
                        % (
                            html.escape(str(it.get("kind", "?"))),
                            html.escape(str(it.get("handle", "?"))),
                            html.escape(str(it.get("text", ""))[:200]),
                            html.escape(str(it.get("url", ""))),
                            html.escape(str(it.get("clicked_at", ""))),
                        )
                    )
            page = "<!doctype html><meta charset=utf-8><title>EchoLike Lite inbox</title><h1>EchoLike Lite inbox</h1><ul>%s</ul>" % "".join(rows)
            body = page.encode()
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path != "/api/likes":
            return self._json({"error": "not found"}, 404)
        if self.headers.get("authorization", "") != "Bearer " + TOKEN:
            return self._json({"error": "unauthorized"}, 401)
        try:
            n = int(self.headers.get("content-length", "0"))
            items = json.loads(self.rfile.read(max(n, 0)) or b"{}").get("items", [])
        except (ValueError, OSError):
            return self._json({"error": "bad json"}, 400)
        if not isinstance(items, list):
            return self._json({"error": "items must be a list"}, 400)
        with open(LOG_FILE, "a") as f:
            for it in items:
                f.write(json.dumps(it) + "\n")
        return self._json({"received": len(items)})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8911)
    args = ap.parse_args()
    print("EchoLike Lite inbox on port %d" % args.port)
    print("Token: %s" % TOKEN)
    print("Paste the address + token into the extension popup. This token never leaves your machines.")
    ThreadingHTTPServer(("0.0.0.0", args.port), H).serve_forever()

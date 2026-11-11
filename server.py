#!/usr/bin/env python3
"""EchoLike Lite inbox — the simplest server that works with the extension.

Run:   python3 server.py [--port 8911] [--host 0.0.0.0]
Store: likes.jsonl (one JSON object per line) + .token (bearer token),
       both in the directory you launch it from.

Endpoints:
  GET  /api/health   -> {"ok": true}
  POST /api/likes    -> {"items": [...]} with  Authorization: Bearer <token>
                        returns {"received": N}
  GET  /             -> readable list of the last 100 captures

A bad request can never take the server down: every handler is wrapped, and a
client that hangs up mid-response is ignored instead of raising.
"""
import argparse
import html
import json
import os
import secrets
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.getcwd()  # data lives in the folder you run it from, not next to the script
TOKEN_FILE = os.path.join(HERE, ".token")
LOG_FILE = os.path.join(HERE, "likes.jsonl")
LOCK = threading.Lock()  # two simultaneous posts must not interleave lines


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
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, body, ctype, code=200):
        try:
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the client left: not our problem, never a crash

    def _json(self, obj, code=200):
        self._send(json.dumps(obj).encode(), "application/json", code)

    def _safe(self, fn):
        try:
            fn()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc()
            try:
                self._json({"error": "internal"}, 500)
            except Exception:
                pass

    def _page(self):
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
                    "<li><b>%s</b> @%s — %s<br><small><a href=\"%s\">%s</a> · %s</small></li>"
                    % (
                        html.escape(str(it.get("kind", "?"))),
                        html.escape(str(it.get("handle", "?"))),
                        html.escape(str(it.get("text", ""))[:200]),
                        html.escape(str(it.get("url", ""))),
                        html.escape(str(it.get("url", ""))),
                        html.escape(str(it.get("clicked_at", ""))),
                    )
                )
        body = (
            "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>EchoLike Lite inbox</title>"
            "<style>body{font:15px system-ui;max-width:640px;margin:24px auto;padding:0 14px}"
            "li{margin:10px 0}small{color:#555}a{color:#1d9bf0}</style>"
            "<h1>EchoLike Lite inbox</h1><p>%d capture(s). Newest first.</p><ul>%s</ul>"
            % (len(rows), "".join(rows) or "<li>Nothing yet. Like a post on X.</li>")
        ).encode()
        self._send(body, "text/html; charset=utf-8")

    def _likes(self):
        if self.headers.get("authorization", "") != "Bearer " + TOKEN:
            return self._json({"error": "unauthorized"}, 401)
        try:
            n = int(self.headers.get("content-length", "0"))
            items = json.loads(self.rfile.read(max(n, 0)) or b"{}").get("items", [])
        except (ValueError, OSError):
            return self._json({"error": "bad json"}, 400)
        if not isinstance(items, list):
            return self._json({"error": "items must be a list"}, 400)
        with LOCK:
            with open(LOG_FILE, "a") as f:
                for it in items:
                    f.write(json.dumps(it) + "\n")
        self._json({"received": len(items)})

    def do_GET(self):
        self._safe(
            lambda: self._json({"ok": True})
            if self.path == "/api/health"
            else self._page()
            if self.path.split("?")[0] == "/"
            else self._json({"error": "not found"}, 404)
        )

    def do_POST(self):
        self._safe(lambda: self._likes() if self.path == "/api/likes" else self._json({"error": "not found"}, 404))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8931)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), H)
    srv.daemon_threads = True
    print("EchoLike Lite inbox on %s:%d" % (args.host, args.port), flush=True)
    print("Token: %s" % TOKEN, flush=True)
    print("Paste the address + token into the extension popup.", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()
        sys.exit(1)

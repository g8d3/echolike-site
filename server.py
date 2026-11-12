#!/usr/bin/env python3
"""EchoLike Lite inbox — the simplest server that works with the extension.

Run:   python3 server.py [--port 8911] [--host 0.0.0.0]
Store: likes.jsonl (one JSON object per line) + .token (bearer token),
       both in the directory you launch it from.

Endpoints:
  GET  /api/health   -> {"ok": true, "claim": "private"|"open"}
  GET  /api/likes    -> {"items": [...], "total": N}  Bearer token. The blobs, newest
                        first, so the extension's inbox tab can read from this server
                        exactly as it reads from the hosted one.
  POST /api/claim    -> {"token": "..."}  no token needed from a private network
                        (loopback, RFC1918, link-local, Tailscale 100.64/10);
                        the extension calls this itself, so the user pastes nothing
  POST /api/likes    -> {"items": [{uid,iv,ct}, ...]} with  Authorization: Bearer <token>
                        (server token or any claimed device token)
                        The extension encrypts in the browser, so what arrives is a
                        blob this server cannot read — by design. It stores it as
                        one JSON line and returns {"received": N}
  GET  /             -> how many captures, and where to read them decrypted
  GET  /             -> readable list of the last 100 captures

A bad request can never take the server down: every handler is wrapped, and a
client that hangs up mid-response is ignored instead of raising.
"""
import argparse
import hashlib
import html
import ipaddress
import json
import os
import secrets
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.getcwd()  # data lives in the folder you run it from, not next to the script
TOKEN_FILE = os.path.join(HERE, ".token")
DEVICES_FILE = os.path.join(HERE, ".devices.json")  # sha256 of every claimed device token
LOG_FILE = os.path.join(HERE, "likes.jsonl")
LOCK = threading.Lock()  # two simultaneous posts must not interleave lines

MAX_DEVICES = int(os.environ.get("ECHO_MAX_DEVICES", "10"))  # a reinstall burns one; 5 was too tight
CLAIM_PER_IP_HOUR = int(os.environ.get("ECHO_CLAIM_PER_HOUR", "5"))
OPEN_CLAIM = False  # --open-claim: a public server that knowingly accepts claims
CLAIMS = {}  # ip -> [unixtime, ...], in memory: a restart forgets, the device cap does not
CGNAT = ipaddress.ip_network("100.64.0.0/10")  # Tailscale lives here and is NOT private in ipaddress


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


def sha(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def is_private(ip):
    """Is this client already on a network only its owner can reach?"""
    try:
        a = ipaddress.ip_address(str(ip).replace("::ffff:", "").split("%")[0])
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a in CGNAT


def devices():
    try:
        with open(DEVICES_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def authorized(header):
    """Bearer token: the server token printed at start, or any claimed device token."""
    got = (header or "").replace("Bearer ", "").strip()
    if not got:
        return False
    if secrets.compare_digest(got, TOKEN):
        return True
    want = sha(got)
    return any(secrets.compare_digest(want, str(d.get("sha256", ""))) for d in devices())


def claim(ip, ua):
    """Mint a device token: the extension never has to carry a secret by hand.

    The private-network check happens in the handler; this only enforces the
    limits. Returns (token, None) or (None, reason).
    """
    now = time.time()
    hits = [t for t in CLAIMS.get(ip, []) if now - t < 3600]
    if len(hits) >= CLAIM_PER_IP_HOUR:
        return None, "rate"
    ds = devices()
    if len(ds) >= MAX_DEVICES:
        return None, "cap"
    tok = secrets.token_hex(16)
    ds.append(
        {
            "id": secrets.token_hex(4),
            "sha256": sha(tok),
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ip": ip,
            "ua": str(ua or "")[:120],
        }
    )
    tmp = DEVICES_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(ds, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, DEVICES_FILE)
    CLAIMS[ip] = hits + [now]
    return tok, None


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
        n = 0
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE) as f:
                n = sum(1 for ln in f if ln.strip())
        body = (
            "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>EchoLike Lite inbox</title>"
            "<style>body{font:15px system-ui;max-width:640px;margin:24px auto;padding:0 14px}"
            "small{color:#555}a{color:#1d9bf0}</style>"
            "<h1>EchoLike Lite inbox</h1>"
            "<p>%d capture(s) stored. They are encrypted: this server cannot read them, "
            "which is the point.</p>"
            "<p>Read them in the extension: open the popup and press <b>Open my inbox</b> "
            "(it decrypts in your browser with the key that never leaves it).</p>"
            "<p><small>Data: <code>likes.jsonl</code>, one opaque blob per line, next to this script.</small></p>" % n
        ).encode()
        self._send(body, "text/html; charset=utf-8")

    def _claim(self):
        """POST /api/claim — no token needed: the private network is the credential."""
        ip = self.client_address[0]
        if not (OPEN_CLAIM or is_private(ip)):
            return self._json(
                {
                    "ok": False,
                    "error": "claim only from a private network",
                    "hint": "run the server with --open-claim to allow public claims",
                },
                403,
            )
        tok, why = claim(ip, self.headers.get("user-agent"))
        if why == "rate":
            return self._json({"ok": False, "error": "too many claims from this address"}, 429)
        if why == "cap":
            return self._json(
                {
                    "ok": False,
                    "error": "this inbox has reached its device limit (%d)" % MAX_DEVICES,
                    "hint": "start it with --max-devices 50, or delete .devices.json to start over",
                },
                409,
            )
        print("Claim from %s -> device token issued" % ip, flush=True)
        self._json({"ok": True, "token": tok, "server": "echolike-lite", "api": 2})

    def _likes(self):
        if not authorized(self.headers.get("authorization", "")):
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

    def _likes_list(self):
        if not authorized(self.headers.get("authorization", "")):
            return self._json({"ok": False, "error": "unauthorized"}, 401)
        items = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE) as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        items.append(json.loads(ln))
                    except ValueError:
                        continue  # a half-written line never breaks the list
        try:
            limit = int(self.path.split("limit=")[1].split("&")[0])
        except (IndexError, ValueError):
            limit = 200
        limit = max(1, min(500, limit))
        self._json({"ok": True, "items": list(reversed(items))[:limit], "total": len(items), "api": 2})

    def do_GET(self):
        self._safe(
            lambda: self._likes_list()
            if self.path.split("?")[0] == "/api/likes"
            else self._json(
                {"ok": True, "server": "echolike-lite", "api": 2, "claim": "open" if OPEN_CLAIM else "private"}
            )
            if self.path == "/api/health"
            else self._page()
            if self.path.split("?")[0] == "/"
            else self._json({"error": "not found"}, 404)
        )

    def do_POST(self):
        path = self.path.split("?")[0]
        self._safe(
            lambda: self._likes()
            if path == "/api/likes"
            else self._claim()
            if path == "/api/claim"
            else self._json({"error": "not found"}, 404)
        )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8931)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--open-claim", action="store_true", help="allow POST /api/claim from public addresses")
    ap.add_argument("--max-devices", type=int, default=MAX_DEVICES, help="how many devices may claim (default 10)")
    args = ap.parse_args()
    OPEN_CLAIM = OPEN_CLAIM or args.open_claim
    MAX_DEVICES = args.max_devices
    srv = ThreadingHTTPServer((args.host, args.port), H)
    srv.daemon_threads = True
    print("EchoLike Lite inbox on %s:%d" % (args.host, args.port), flush=True)
    print("Token: %s" % TOKEN, flush=True)
    print(
        "Pairing: open the extension and press Find my inbox (a device token is issued on the spot)."
        " Paste this token + address only for a hosted inbox or another machine.",
        flush=True,
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()
        sys.exit(1)

#!/usr/bin/env python3
"""EchoLike inbox server: corre en TU pc. Mismo contrato que el inbox worker
(POST /api/likes, GET /api/inbox, GET /api/health), con SQLite en vez de D1.
Sin dependencias: solo Python 3 stdlib.

Uso:
  python3 server.py                 # escucha en 127.0.0.1:8911 (solo este aparato)
  python3 server.py --host 0.0.0.0  # también visible en tu LAN / Tailscale (pide token igual)
  python3 server.py --port 8911 --dir ~/.echolike-inbox

La primera vez genera un device token, lo imprime UNA vez y lo guarda en
<dir>/device_token.txt (0600). Pégalo en la extensión (Inbox settings).
Desde el teléfono usa la IP de ESTE pc (p. ej. http://100.x:8911 si usas
Tailscale, o http://192.168.x.x:8911 en tu wifi). Nada sale a internet.
"""
import argparse
import hashlib
import subprocess
import time as _time
import json
import os
import secrets
import sqlite3
import stat
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DAILY_CAP = 2000
MAX_DEVICES = int(os.environ.get("ECHO_MAX_DEVICES", "10"))
# The producer knows when a row is durable, so it tells the analysis pipeline instead of
# a file watcher guessing: the kernel event can arrive before sqlite commits.
INGEST_CMD = os.environ.get("ECHO_INGEST_CMD",
                            os.path.expanduser("~/code/p4/e092-echolike/operador/inbox_a_pipeline.py"))
OPEN_CLAIM = os.environ.get("ECHO_OPEN_CLAIM") == "1"
CLAIM_PER_IP_HOUR = int(os.environ.get("ECHO_CLAIM_PER_HOUR", "3"))


def is_private(ip):
    """LAN, Tailscale and loopback: places where getting in already means trust."""
    try:
        a, b = [int(x) for x in ip.split(".")[:2]]
    except Exception:
        return ip in ("::1", "localhost") or ip.startswith("100.") or ip.startswith("fd")
    return (a == 127 or a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)
            or (a == 100 and 64 <= b <= 127))


class _Rate:   # claims per address, so one client cannot fill the device table
    def __init__(self):
        self.hits = {}

    def blocked(self, ip):
        import time as _t
        now = _t.time()
        self.hits = {k: [t for t in v if now - t < 3600] for k, v in self.hits.items()}
        return len(self.hits.get(ip, [])) >= CLAIM_PER_IP_HOUR

    def hit(self, ip):
        import time as _t
        self.hits.setdefault(ip, []).append(_t.time())


RATE = _Rate()
KINDS = {"like", "bookmark", "unlike", "unbookmark", "note", "nota_texto", "nota_voz"}


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def utcnow():
    return datetime.now(timezone.utc).isoformat()


class DB:
    def __init__(self, path):
        self.c = sqlite3.connect(path, check_same_thread=False)
        self.c.execute("CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)")
        self.c.execute("CREATE TABLE IF NOT EXISTS likes (id TEXT PRIMARY KEY, device TEXT NOT NULL, kind TEXT, handle TEXT, url TEXT, text TEXT, nota TEXT, clicked_at TEXT, recv_at TEXT, raw TEXT)")
        # Which phone/PC sent it: without this, two devices with the same token are one blur (added 2026-10-29).
        cols = {r[1] for r in self.c.execute("PRAGMA table_info(likes)")}
        for c, t in (("ua", "TEXT"), ("ip", "TEXT")):
            if c not in cols:
                self.c.execute(f"ALTER TABLE likes ADD COLUMN {c} {t}")
        self.c.execute("CREATE TABLE IF NOT EXISTS daily (device TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (device, day))")
        self.c.commit()

    def device_id(self, token):
        if not token:
            return None
        want = sha(token)
        row = self.c.execute("SELECT id FROM devices WHERE token_hash=? AND revoked=0", (want,)).fetchone()
        return row[0] if row else None

    def claim(self, ip, ua, max_devices):
        """Mint a device token for a new client. Returns the token once, or None."""
        n = self.c.execute("SELECT COUNT(*) FROM devices WHERE revoked=0").fetchone()[0]
        if n >= max_devices:
            return None
        tok = "dt_" + secrets.token_urlsafe(32)
        dev = "dev-" + secrets.token_hex(4)
        self.c.execute("INSERT INTO devices (id, token_hash) VALUES (?, ?)", (dev, sha(tok)))
        self.c.commit()
        self.c.execute("CREATE TABLE IF NOT EXISTS claims (at TEXT, ip TEXT, device TEXT, ua TEXT)")
        self.c.execute("INSERT INTO claims (at, ip, device, ua) VALUES (?,?,?,?)", (utcnow(), ip, dev, str(ua or "")[:300]))
        self.c.commit()
        return tok

    def device_count(self):
        return self.c.execute("SELECT COUNT(*) FROM devices WHERE revoked=0").fetchone()[0]

    def ensure_first_device(self):
        row = self.c.execute("SELECT id FROM devices LIMIT 1").fetchone()
        if row:
            return None
        token = "dt_" + secrets.token_urlsafe(32)
        self.c.execute("INSERT INTO devices (id, token_hash) VALUES (?, ?)", ("pc-1", sha(token)))
        self.c.commit()
        return token

    def check_cap(self, device, n):
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        row = self.c.execute("SELECT n FROM daily WHERE device=? AND day=?", (device, day)).fetchone()
        used = row[0] if row else 0
        if used + n > DAILY_CAP:
            return False
        self.c.execute("INSERT INTO daily (device, day, n) VALUES (?,?,?) ON CONFLICT (device, day) DO UPDATE SET n = daily.n + excluded.n", (device, day, n))
        self.c.commit()
        return True

    def notify_pipeline(self):
        """Fire-and-forget: the ingest script is idempotent, so a double call is harmless."""
        if not INGEST_CMD or not os.path.exists(INGEST_CMD):
            return
        try:
            subprocess.Popen(["/usr/bin/python3", INGEST_CMD, "--quiet"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
        except OSError:
            pass

    def store(self, device, items, ua="", ip=""):
        got = []
        for it in items:
            if not isinstance(it, dict):
                continue
            iid = str(it.get("id") or secrets.token_hex(12))
            kind = str(it.get("kind", ""))
            try:
                self.c.execute(
                    "INSERT OR IGNORE INTO likes (id, device, kind, handle, url, text, nota, clicked_at, recv_at, raw, ua, ip) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (iid, device, kind, str(it.get("handle", "") or ""), str(it.get("url", "") or ""),
                     str(it.get("text", "") or "")[:4000], str(it.get("nota", "") or "")[:4000],
                     str(it.get("clicked_at", "") or ""), utcnow(), json.dumps(it)[:8000],
                     str(ua or "")[:300], str(ip or "")[:60]),
                )
                got.append({"id": iid, "kind": kind})
            except sqlite3.Error:
                pass
        self.c.commit()
        if got:
            self.notify_pipeline()
        return got

    def latest(self, limit=50):
        rows = self.c.execute("SELECT id, kind, handle, url, text, nota, clicked_at, recv_at FROM likes ORDER BY recv_at DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r[0], "kind": r[1], "handle": r[2], "url": r[3], "text": r[4], "nota": r[5], "clicked_at": r[6], "recv_at": r[7]} for r in rows]


def make_handler(db):
    class H(BaseHTTPRequestHandler):
        server_version = "EchoLikeInbox/1.0"

        def log_message(self, *a):
            pass

        def _json(self, o, status=200):
            b = json.dumps(o).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _auth(self):
            auth = (self.headers.get("authorization") or "").strip()
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            return db.device_id(tok)

        def _claim(self):
            """POST /api/claim — no token needed: the network is the credential.

            Allowed from private addresses (LAN, Tailscale, loopback) by default;
            a public server needs --open-claim. Capped and logged either way."""
            ip = (self.headers.get("x-forwarded-for") or self.client_address[0] or "").split(",")[0].strip()
            if not (OPEN_CLAIM or is_private(ip)):
                return self._json({"ok": False, "error": "claim only from a private network",
                                   "hint": "run the server with --open-claim to allow public claims"}, 403)
            if RATE.blocked(ip):
                return self._json({"ok": False, "error": "too many claims from this address"}, 429)
            tok = db.claim(ip, self.headers.get("user-agent"), MAX_DEVICES)
            if not tok:
                return self._json({"ok": False, "error": f"device limit reached ({MAX_DEVICES})"}, 409)
            RATE.hit(ip)
            return self._json({"ok": True, "device_token": tok, "devices": db.device_count()})

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/api/health":
                # now_ms lets a client measure its own clock offset against this machine instead of
                # guessing: the phones' clocks are ~300 ms off and that lands in every latency number.
                return self._json({"ok": True, "time": utcnow(), "now_ms": int(_time.time() * 1000), "api": 2,
                                   "claim": "open" if OPEN_CLAIM else "private",
                                   "devices": db.device_count()})
            if u.path == "/api/inbox":
                dev = self._auth()
                if not dev:
                    return self._json({"ok": False, "error": "unauthorized"}, 401)
                q = parse_qs(u.query)
                try:
                    limit = max(1, min(200, int(q.get("limit", ["50"])[0])))
                except ValueError:
                    limit = 50
                return self._json({"ok": True, "items": db.latest(limit)})
            if u.path == "/" or u.path == "/index.html":
                items = ""
                try:
                    dev = self._auth()
                    if dev:
                        for it in db.latest(30):
                            title = (it["text"] or it["nota"] or it["id"])[:120]
                            items += f"<li><b>{it['kind']}</b> @{it['handle'] or '?'} — {title}</li>"
                except BrokenPipeError:
                    return
                html = ("<!doctype html><meta charset=utf-8><title>EchoLike inbox (tu pc)</title>"
                        "<body style='font-family:system-ui;max-width:640px;margin:2rem auto;padding:0 1rem'>"
                        "<h1>EchoLike inbox · en tu pc</h1>"
                        "<p>Pega tu device token arriba (cabecera) o usa <code>/api/inbox</code> con "
                        "<code>Authorization: Bearer &lt;token&gt;</code>.</p><ul>" + (items or "<li>vacío</li>") + "</ul></body>")
                b = html.encode()
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(b)))
                self.end_headers()
                try:
                    self.wfile.write(b)
                except BrokenPipeError:
                    pass
                return
            return self._json({"ok": False, "error": "not found"}, 404)

        def do_POST(self):
            u = urlparse(self.path)
            if u.path == "/api/claim":
                return self._claim()
            if u.path != "/api/likes":
                return self._json({"ok": False, "error": "not found"}, 404)
            dev = self._auth()
            if not dev:
                return self._json({"ok": False, "error": "unauthorized"}, 401)
            try:
                n = int(self.headers.get("content-length") or 0)
            except ValueError:
                n = 0
            if n > 4_000_000:
                return self._json({"ok": False, "error": "too large"}, 413)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, OSError):
                return self._json({"ok": False, "error": "bad json"}, 400)
            items = body.get("items")
            if not isinstance(items, list):
                return self._json({"ok": False, "error": "items must be a list"}, 400)
            if not db.check_cap(dev, len(items)):
                return self._json({"ok": False, "error": "daily cap"}, 429)
            return self._json({"ok": True, "received": db.store(dev, items, self.headers.get("user-agent") or "",
                                                                self.headers.get("x-forwarded-for") or self.client_address[0])})

    return H


def main(argv=None):
    ap = argparse.ArgumentParser(description="EchoLike inbox en tu pc")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8911)
    ap.add_argument("--dir", default=os.path.expanduser("~/.echolike-inbox"))
    ap.add_argument("--open-claim", action="store_true", help="allow POST /api/claim from public addresses")
    a = ap.parse_args(argv)
    global OPEN_CLAIM
    OPEN_CLAIM = OPEN_CLAIM or a.open_claim
    os.makedirs(a.dir, exist_ok=True)
    db = DB(os.path.join(a.dir, "inbox.db"))
    fresh = db.ensure_first_device()
    tok_path = os.path.join(a.dir, "device_token.txt")
    if fresh:
        with open(tok_path, "w") as fh:
            fh.write(fresh + "\n")
        os.chmod(tok_path, stat.S_IRUSR | stat.S_IWUSR)
        print("DEVICE TOKEN (guárdalo en la extensión → Inbox settings):")
        print(fresh)
        print(f"(también en {tok_path})")
    else:
        print(f"inbox listo; tu token está en {tok_path}")
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(db))
    print(f"escuchando en http://{a.host}:{a.port}  (Ctrl+C para parar)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

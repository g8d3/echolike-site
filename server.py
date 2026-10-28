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
        self.c.execute("CREATE TABLE IF NOT EXISTS daily (device TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (device, day))")
        self.c.commit()

    def device_id(self, token):
        if not token:
            return None
        want = sha(token)
        row = self.c.execute("SELECT id FROM devices WHERE token_hash=? AND revoked=0", (want,)).fetchone()
        return row[0] if row else None

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

    def store(self, device, items):
        n = 0
        for it in items:
            if not isinstance(it, dict):
                continue
            iid = str(it.get("id") or secrets.token_hex(12))
            try:
                self.c.execute(
                    "INSERT OR IGNORE INTO likes (id, device, kind, handle, url, text, nota, clicked_at, recv_at, raw) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (iid, device, str(it.get("kind", "")), str(it.get("handle", "") or ""), str(it.get("url", "") or ""),
                     str(it.get("text", "") or "")[:4000], str(it.get("nota", "") or "")[:4000],
                     str(it.get("clicked_at", "") or ""), utcnow(), json.dumps(it)[:8000]),
                )
                n += self.c.total_changes and 1 or 0
            except sqlite3.Error:
                pass
        self.c.commit()
        return n

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

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/api/health":
                return self._json({"ok": True, "time": utcnow()})
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
            return self._json({"ok": True, "received": db.store(dev, items)})

    return H


def main(argv=None):
    ap = argparse.ArgumentParser(description="EchoLike inbox en tu pc")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8911)
    ap.add_argument("--dir", default=os.path.expanduser("~/.echolike-inbox"))
    a = ap.parse_args(argv)
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

#!/usr/bin/env python3
"""EchoLike inbox server: corre en TU pc. Mismo contrato que el inbox worker
(POST /api/likes, GET /api/inbox, GET /api/health), con SQLite en vez de D1.
Sin dependencias: solo Python 3 stdlib.

Multi-tenant (v1): cada claim crea un usuario nuevo (u_xxx) con su dispositivo
(dev-xxx). El device claim ES la identidad de usuario: la DB queda namespaced
por usuario y /api/inbox solo devuelve lo de tu usuario. El dato viejo
(pc-1) pertenece a u_owner: sin cambio de comportamiento para el owner.

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
# Pricing (demo mode): the meter prices every action, but nothing is enforced
# until ECHO_ENFORCE_QUOTA=1. Prices are integer credit-units; the extension
# shows them before writing (see /api/health prices). Charging comes later.
PRICE_LIKE_IN = int(os.environ.get("ECHO_PRICE_LIKE_IN", "1"))
PRICE_READ = int(os.environ.get("ECHO_PRICE_READ", "0"))
PRICE_ANALYSIS = int(os.environ.get("ECHO_PRICE_ANALYSIS", "5"))
FREE_DAILY = int(os.environ.get("ECHO_FREE_DAILY", "2000"))
ENFORCE_QUOTA = os.environ.get("ECHO_ENFORCE_QUOTA") == "1"
# The producer knows when a row is durable, so it tells the analysis pipeline instead of
# a file watcher guessing: the kernel event can arrive before sqlite commits.
INGEST_CMD = os.environ.get("ECHO_INGEST_CMD",
                            os.path.expanduser("~/code/p4/e092-echolike/operador/inbox_a_pipeline.py"))
OPEN_CLAIM = os.environ.get("ECHO_OPEN_CLAIM") == "1"
CLAIM_PER_IP_HOUR = int(os.environ.get("ECHO_CLAIM_PER_HOUR", "3"))
OWNER_USER = "u_owner"


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


def today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class DB:
    def __init__(self, path):
        self.c = sqlite3.connect(path, check_same_thread=False)
        self.c.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT '')")
        self.c.execute("CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)")
        self.c.execute("CREATE TABLE IF NOT EXISTS likes (id TEXT PRIMARY KEY, device TEXT NOT NULL, kind TEXT, handle TEXT, url TEXT, text TEXT, nota TEXT, clicked_at TEXT, recv_at TEXT, raw TEXT)")
        # Which phone/PC sent it: without this, two devices with the same token are one blur (added 2026-10-29).
        cols = {r[1] for r in self.c.execute("PRAGMA table_info(likes)")}
        for c, t in (("ua", "TEXT"), ("ip", "TEXT")):
            if c not in cols:
                self.c.execute(f"ALTER TABLE likes ADD COLUMN {c} {t}")
        dcols = {r[1] for r in self.c.execute("PRAGMA table_info(devices)")}
        if "user_id" not in dcols:
            self.c.execute("ALTER TABLE devices ADD COLUMN user_id TEXT")
        self.c.execute("CREATE TABLE IF NOT EXISTS daily (device TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (device, day))")
        self.c.execute("CREATE TABLE IF NOT EXISTS claims (at TEXT, ip TEXT, device TEXT, ua TEXT)")
        # Credit meter (v1: counts only, charging comes later). One row per user per day.
        self.c.execute("CREATE TABLE IF NOT EXISTS usage (day TEXT NOT NULL, user_id TEXT NOT NULL, likes_in INTEGER NOT NULL DEFAULT 0, inbox_reads INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, user_id))")
        # Pipeline handoffs: likes per user handed to the analysis pipeline (the
        # real inference cost driver). Written by operador/inbox_a_pipeline.py.
        self.c.execute("CREATE TABLE IF NOT EXISTS pipeline (day TEXT NOT NULL, user_id TEXT NOT NULL, handoff_likes INTEGER NOT NULL DEFAULT 0, handoff_runs INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, user_id))")
        # Inference ledger: actual AI spend per user, recorded by likes_loop.py
        # after each muse call (calls, wall seconds, output chars). The cash
        # register counts first (handoff), this counts what was really spent.
        self.c.execute("CREATE TABLE IF NOT EXISTS inference (day TEXT NOT NULL, user_id TEXT NOT NULL, calls INTEGER NOT NULL DEFAULT 0, seconds_ms INTEGER NOT NULL DEFAULT 0, chars INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day, user_id))")
        self.c.commit()
        self._ensure_users()

    def _ensure_users(self):
        """Backfill: every device without owner belongs to u_owner. Idempotent."""
        self.c.execute("INSERT OR IGNORE INTO users (id, created_at) VALUES (?, ?)", (OWNER_USER, utcnow()))
        self.c.execute("UPDATE devices SET user_id=? WHERE user_id IS NULL OR user_id=''", (OWNER_USER,))
        self.c.commit()

    def user_of_device(self, device):
        row = self.c.execute("SELECT user_id FROM devices WHERE id=? AND revoked=0", (device,)).fetchone()
        return row[0] if row and row[0] else OWNER_USER

    def devices_of_user(self, user_id):
        return [r[0] for r in self.c.execute("SELECT id FROM devices WHERE user_id=? AND revoked=0", (user_id,))]

    def user_of_token(self, token):
        dev = self.device_id(token)
        return (dev, self.user_of_device(dev)) if dev else (None, None)

    def device_id(self, token):
        if not token:
            return None
        want = sha(token)
        row = self.c.execute("SELECT id FROM devices WHERE token_hash=? AND revoked=0", (want,)).fetchone()
        return row[0] if row else None

    def claim(self, ip, ua, max_devices):
        """Mint a device token for a NEW user. Returns (token, user_id) once, or (None, None).

        v1 rule: one claim = one user namespace. Linking a second device to the
        same user is a later /api/link call; until then every newcomer is
        isolated by construction and the owner flow is untouched."""
        n = self.c.execute("SELECT COUNT(*) FROM devices WHERE revoked=0").fetchone()[0]
        if n >= max_devices:
            return None, None
        tok = "dt_" + secrets.token_urlsafe(32)
        dev = "dev-" + secrets.token_hex(4)
        uid = "u_" + secrets.token_hex(4)
        self.c.execute("INSERT OR IGNORE INTO users (id, created_at) VALUES (?, ?)", (uid, utcnow()))
        self.c.execute("INSERT INTO devices (id, token_hash, user_id) VALUES (?, ?, ?)", (dev, sha(tok), uid))
        self.c.commit()
        self.c.execute("INSERT INTO claims (at, ip, device, ua) VALUES (?,?,?,?)", (utcnow(), ip, dev, str(ua or "")[:300]))
        self.c.commit()
        return tok, uid

    def device_count(self):
        return self.c.execute("SELECT COUNT(*) FROM devices WHERE revoked=0").fetchone()[0]

    def user_count(self):
        return self.c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def ensure_first_device(self):
        row = self.c.execute("SELECT id FROM devices LIMIT 1").fetchone()
        if row:
            self._ensure_users()
            return None
        token = "dt_" + secrets.token_urlsafe(32)
        self.c.execute("INSERT OR IGNORE INTO users (id, created_at) VALUES (?, ?)", (OWNER_USER, utcnow()))
        self.c.execute("INSERT INTO devices (id, token_hash, user_id) VALUES (?, ?, ?)", ("pc-1", sha(token), OWNER_USER))
        self.c.commit()
        return token

    def check_cap(self, device, n):
        day = today()
        row = self.c.execute("SELECT n FROM daily WHERE device=? AND day=?", (device, day)).fetchone()
        used = row[0] if row else 0
        if used + n > DAILY_CAP:
            return False
        self.c.execute("INSERT INTO daily (device, day, n) VALUES (?,?,?) ON CONFLICT (device, day) DO UPDATE SET n = daily.n + excluded.n", (device, day, n))
        self.c.commit()
        return True

    def bump_usage(self, user_id, likes_in=0, inbox_reads=0):
        try:
            self.c.execute("INSERT INTO usage (day, user_id, likes_in, inbox_reads) VALUES (?,?,?,?) "
                           "ON CONFLICT (day, user_id) DO UPDATE SET likes_in = likes_in + excluded.likes_in, "
                           "inbox_reads = inbox_reads + excluded.inbox_reads",
                           (today(), user_id, likes_in, inbox_reads))
            self.c.commit()
        except sqlite3.Error:
            pass

    def get_usage(self, user_id):
        day = today()
        row = self.c.execute("SELECT likes_in, inbox_reads FROM usage WHERE day=? AND user_id=?", (day, user_id)).fetchone()
        t = self.c.execute("SELECT COALESCE(SUM(likes_in),0), COALESCE(SUM(inbox_reads),0) FROM usage WHERE user_id=?", (user_id,)).fetchone()
        likes_total = self.c.execute("SELECT COUNT(*) FROM likes WHERE device IN (SELECT id FROM devices WHERE user_id=?)",
                                     (user_id,)).fetchone()[0]
        tin, trd = (row[0] if row else 0), (row[1] if row else 0)
        inf = self.get_inference(user_id)
        ctoday = tin * PRICE_LIKE_IN + trd * PRICE_READ + inf["today"]["calls"] * PRICE_ANALYSIS
        ctotal = t[0] * PRICE_LIKE_IN + t[1] * PRICE_READ + inf["total"]["calls"] * PRICE_ANALYSIS
        return {"user_id": user_id, "day": day,
                "today": {"likes_in": tin, "inbox_reads": trd},
                "total": {"likes_in": t[0], "inbox_reads": t[1], "likes_stored": likes_total},
                "credits": {"today": ctoday, "total": ctotal,
                              "prices": {"inbox_write": PRICE_LIKE_IN, "inbox_read": PRICE_READ,
                                         "analysis_call": PRICE_ANALYSIS}},
                "quota": {"free_daily": FREE_DAILY, "used_today": ctoday,
                            "left_today": max(0, FREE_DAILY - ctoday), "enforcing": ENFORCE_QUOTA},
                "pipeline": self.get_pipeline(user_id),
                "inference": self.get_inference(user_id)}

    def bump_pipeline(self, user_id, likes_n):
        """One pipeline handoff: the analyser will spend inference on these likes."""
        try:
            self.c.execute("INSERT INTO pipeline (day, user_id, handoff_likes, handoff_runs) VALUES (?,?,?,1) "
                           "ON CONFLICT (day, user_id) DO UPDATE SET handoff_likes = handoff_likes + excluded.handoff_likes, "
                           "handoff_runs = handoff_runs + 1",
                           (today(), user_id, likes_n))
            self.c.commit()
        except sqlite3.Error:
            pass

    def get_pipeline(self, user_id):
        day = today()
        row = self.c.execute("SELECT handoff_likes, handoff_runs FROM pipeline WHERE day=? AND user_id=?", (day, user_id)).fetchone()
        t = self.c.execute("SELECT COALESCE(SUM(handoff_likes),0), COALESCE(SUM(handoff_runs),0) FROM pipeline WHERE user_id=?", (user_id,)).fetchone()
        return {"today": {"handoff_likes": row[0] if row else 0, "handoff_runs": row[1] if row else 0},
                "total": {"handoff_likes": t[0], "handoff_runs": t[1]}}

    def bump_inference(self, user_id, seconds=0.0, chars=0):
        """One finished muse call for this user. Best-effort: never raises."""
        try:
            ms = int(round(float(seconds) * 1000))
            self.c.execute("INSERT INTO inference (day, user_id, calls, seconds_ms, chars) VALUES (?,?,1,?,?) "
                           "ON CONFLICT (day, user_id) DO UPDATE SET calls = calls + 1, "
                           "seconds_ms = seconds_ms + excluded.seconds_ms, chars = chars + excluded.chars",
                           (today(), user_id, ms, int(chars)))
            self.c.commit()
        except (sqlite3.Error, ValueError, TypeError):
            pass

    def get_inference(self, user_id):
        day = today()
        try:
            row = self.c.execute("SELECT calls, seconds_ms, chars FROM inference WHERE day=? AND user_id=?", (day, user_id)).fetchone()
            t = self.c.execute("SELECT COALESCE(SUM(calls),0), COALESCE(SUM(seconds_ms),0), COALESCE(SUM(chars),0) FROM inference WHERE user_id=?", (user_id,)).fetchone()
        except sqlite3.Error:
            return {"today": {"calls": 0, "seconds": 0.0, "chars": 0},
                    "total": {"calls": 0, "seconds": 0.0, "chars": 0}}
        return {"today": {"calls": row[0] if row else 0, "seconds": round((row[1] if row else 0) / 1000.0, 2), "chars": row[2] if row else 0},
                "total": {"calls": t[0], "seconds": round(t[1] / 1000.0, 2), "chars": t[2]}}

    def quota_left(self, user_id):
        """Billable units the user may still store today. Infinite when not enforcing."""
        if not ENFORCE_QUOTA:
            return None
        row = self.c.execute("SELECT likes_in FROM usage WHERE day=? AND user_id=?", (today(), user_id)).fetchone()
        return max(0, FREE_DAILY - (row[0] if row else 0))

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

    def store(self, device, items, ua="", ip="", post_ms=None):
        got = []
        for it in items:
            if not isinstance(it, dict):
                continue
            iid = str(it.get("id") or secrets.token_hex(12))
            kind = str(it.get("kind", ""))
            # how long the client's POST took to come back (the number its toast shows)
            if post_ms is not None and "post_ms" not in it:
                it["post_ms"] = post_ms
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
            self.bump_usage(self.user_of_device(device), likes_in=len(got))
            self.notify_pipeline()
        return got

    def latest(self, user_id, limit=50):
        devs = self.devices_of_user(user_id)
        if not devs:
            return []
        marks = ",".join("?" * len(devs))
        rows = self.c.execute(f"SELECT id, kind, handle, url, text, nota, clicked_at, recv_at FROM likes WHERE device IN ({marks}) ORDER BY recv_at DESC LIMIT ?",
                              (*devs, limit)).fetchall()
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

        def _identity(self):
            auth = (self.headers.get("authorization") or "").strip()
            tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            if not tok:
                # table page convenience: ?token= works like the header
                try:
                    tok = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
                except Exception:
                    tok = ""
            return db.user_of_token(tok)

        def _claim(self):
            """POST /api/claim — no token needed: the network is the credential.

            Allowed from private addresses (LAN, Tailscale, loopback) by default;
            a public server needs --open-claim. Capped and logged either way.
            Each claim mints a fresh user namespace (device claim = identity)."""
            ip = (self.headers.get("x-forwarded-for") or self.client_address[0] or "").split(",")[0].strip()
            if not (OPEN_CLAIM or is_private(ip)):
                return self._json({"ok": False, "error": "claim only from a private network",
                                   "hint": "run the server with --open-claim to allow public claims"}, 403)
            if RATE.blocked(ip):
                return self._json({"ok": False, "error": "too many claims from this address"}, 429)
            tok, uid = db.claim(ip, self.headers.get("user-agent"), MAX_DEVICES)
            if not tok:
                return self._json({"ok": False, "error": f"device limit reached ({MAX_DEVICES})"}, 409)
            RATE.hit(ip)
            return self._json({"ok": True, "device_token": tok, "user_id": uid, "devices": db.device_count()})

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/api/health":
                # now_ms lets a client measure its own clock offset against this machine instead of
                # guessing: the phones' clocks are ~300 ms off and that lands in every latency number.
                return self._json({"ok": True, "time": utcnow(), "now_ms": int(_time.time() * 1000), "api": 2,
                                   "claim": "open" if OPEN_CLAIM else "private",
                                   "devices": db.device_count(), "users": db.user_count(),
                                   "multi_tenant": True,
                                   "prices": {"inbox_write": PRICE_LIKE_IN, "inbox_read": PRICE_READ,
                                               "analysis_call": PRICE_ANALYSIS,
                                               "free_daily": FREE_DAILY, "enforcing": ENFORCE_QUOTA}})
            if u.path == "/api/me":
                dev, uid = self._identity()
                if not dev:
                    return self._json({"ok": False, "error": "unauthorized"}, 401)
                return self._json({"ok": True, "user_id": uid, "device": dev,
                                   "devices": db.devices_of_user(uid)})
            if u.path == "/api/usage":
                dev, uid = self._identity()
                if not dev:
                    return self._json({"ok": False, "error": "unauthorized"}, 401)
                return self._json({"ok": True, **db.get_usage(uid)})
            if u.path == "/api/inbox":
                dev, uid = self._identity()
                if not dev:
                    return self._json({"ok": False, "error": "unauthorized"}, 401)
                q = parse_qs(u.query)
                try:
                    limit = max(1, min(200, int(q.get("limit", ["50"])[0])))
                except ValueError:
                    limit = 50
                db.bump_usage(uid, inbox_reads=1)
                return self._json({"ok": True, "user_id": uid, "items": db.latest(uid, limit)})
            if u.path == "/" or u.path == "/index.html":
                items = ""
                try:
                    dev, uid = self._identity()
                    if dev:
                        for it in db.latest(uid, 30):
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
            left = db.quota_left(db.user_of_device(dev))
            if left is not None and len(items) > left:
                return self._json({"ok": False, "error": "quota_exceeded",
                                   "hint": "free daily quota spent; demo-only, raise ECHO_FREE_DAILY or unset ECHO_ENFORCE_QUOTA",
                                   "quota": {"free_daily": FREE_DAILY, "left_today": left}}, 429)
            post_ms = body.get("post_ms") if isinstance(body.get("post_ms"), (int, float)) else None
            return self._json({"ok": True, "received": db.store(dev, items, self.headers.get("user-agent") or "",
                                                                self.headers.get("x-forwarded-for") or self.client_address[0],
                                                                post_ms)})

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

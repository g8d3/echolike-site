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
from datetime import datetime, timedelta, timezone
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
# Checkout hint (read-only): public receive addresses so a buyer knows where
# to pay for credits. Env-driven, never hardcoded; empty = unset = None in
# /api/health. Showing them moves no money: the owner still mints the prepaid
# code by hand after seeing the payment off-band.
CHECKOUT_SOL = os.environ.get("ECHO_SOL_ADDRESS", "").strip()
CHECKOUT_EVM = os.environ.get("ECHO_EVM_ADDRESS", "").strip()
# Referrer commission rate (report-only): percent of each settled sale owed to
# the agent who brought the buyer, from ECHO_COMMISSION_PCT (0..100). Unset,
# blank or out-of-range means no program: totals carry commission_pct None
# and owed {}. Reporting only: no payout moves here, the owner pays off-band.
COMMISSION_PCT = None
try:
    _pct = float(os.environ.get("ECHO_COMMISSION_PCT", "").strip())
    if 0 <= _pct <= 100 and _pct == _pct:  # NaN never equals itself
        COMMISSION_PCT = _pct
except (ValueError, TypeError, AttributeError):
    COMMISSION_PCT = None
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


def _metric(v):
    """A visible X counter: a non-negative int, or None when X did not show it."""
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        return None
    return v


def today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class DB:
    def __init__(self, path):
        self.c = sqlite3.connect(path, check_same_thread=False)
        self.c.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT '')")
        self.c.execute("CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)")
        self.c.execute("CREATE TABLE IF NOT EXISTS likes (id TEXT PRIMARY KEY, device TEXT NOT NULL, kind TEXT, handle TEXT, url TEXT, text TEXT, nota TEXT, clicked_at TEXT, recv_at TEXT, raw TEXT)")
        # Which phone/PC sent it: without this, two devices with the same token are one blur (added 2026-10-29).
        # Visible X counters at capture time (added 2026-11-02: the extension reads
        # replies/reposts/likes/views from the tweet action bar; bookmarks have no
        # public counter on X, so that column never exists). Null = X did not show it.
        cols = {r[1] for r in self.c.execute("PRAGMA table_info(likes)")}
        for c, t in (("ua", "TEXT"), ("ip", "TEXT"),
                      ("replies", "INTEGER"), ("reposts", "INTEGER"),
                      ("likes", "INTEGER"), ("views", "INTEGER")):
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
        # Credit grants: the funding side of the cash register. The meter above
        # counts what each user spent; this records what was given to them
        # (founder free credits, promo, manual top-ups after a crypto payment
        # is seen on-chain). Bookkeeping only: granting moves no money.
        self.c.execute("CREATE TABLE IF NOT EXISTS grants (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, day TEXT NOT NULL, user_id TEXT NOT NULL, credits INTEGER NOT NULL, reason TEXT NOT NULL DEFAULT '')")
        # Referral attribution: who brought each user. First touch wins and is
        # never overwritten (last-touch theft and self-dealing pay nothing).
        # Set alongside a grant, read by /api/usage for commission payouts.
        self.c.execute("CREATE TABLE IF NOT EXISTS referrals (user_id TEXT PRIMARY KEY, referred_by TEXT NOT NULL, at TEXT NOT NULL)")
        # Prepaid codes: the first sellable unit. The owner mints a code
        # (localhost POST /api/mint) after seeing a payment off-band, hands
        # the code to the buyer, and the buyer redeems it (authed POST
        # /api/redeem) into granted credits. Single-use: first redeemer wins.
        # Bookkeeping only: minting and redeeming move no money.
        self.c.execute("CREATE TABLE IF NOT EXISTS grant_codes (code TEXT PRIMARY KEY, credits INTEGER NOT NULL, reason TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, redeemed_by TEXT NOT NULL DEFAULT '', redeemed_at TEXT NOT NULL DEFAULT '')")
        # Revoked codes: a leaked or unsold code the owner kills before it is
        # redeemed (localhost POST /api/revoke). Redeeming a revoked code is
        # refused; the sales book keeps showing it, marked. Added 2026-11-01.
        gcols = {r[1] for r in self.c.execute("PRAGMA table_info(grant_codes)")}
        if "revoked" not in gcols:
            self.c.execute("ALTER TABLE grant_codes ADD COLUMN revoked TEXT NOT NULL DEFAULT ''")
        # Expiry: mint can stamp a deadline (expires_at, '' = never); redeeming
        # past it is refused 410, so pre-minted batches stop being bearer money.
        # Added 2026-11-01; old rows backfill '' and read as None.
        if "expires_at" not in gcols:
            self.c.execute("ALTER TABLE grant_codes ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''")
        # Sale recording: what the buyer actually paid for these credits
        # (sale_amount + sale_currency, optional sale_ref for the tx hash or
        # note). The owner mints after seeing a payment off-band and writes
        # down what arrived, so the sales book measures real revenue per code.
        # Bookkeeping only: recording a sale moves no money and changes no
        # gate. Added 2026-11-01; old rows backfill NULL/'' and read as None.
        if "sale_amount" not in gcols:
            self.c.execute("ALTER TABLE grant_codes ADD COLUMN sale_amount NUMERIC DEFAULT NULL")
            self.c.execute("ALTER TABLE grant_codes ADD COLUMN sale_currency TEXT NOT NULL DEFAULT ''")
            self.c.execute("ALTER TABLE grant_codes ADD COLUMN sale_ref TEXT NOT NULL DEFAULT ''")
        # Payouts: what the owner actually paid each bringer off-band
        # (recorded here after the money moves, so the book knows what is
        # settled). localhost POST /api/payout writes one row per payment;
        # /api/codes totals read it as paid{} and payable{} (owed - paid).
        # Bookkeeping only: recording a payout moves no money. New table,
        # so old books simply show no payouts. Added 2026-11-01.
        self.c.execute("CREATE TABLE IF NOT EXISTS payouts (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, day TEXT NOT NULL, agent TEXT NOT NULL, amount NUMERIC NOT NULL, currency TEXT NOT NULL, ref TEXT NOT NULL DEFAULT '')")
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
        granted = self.get_grants(user_id)["total"]
        return {"user_id": user_id, "day": day,
                "today": {"likes_in": tin, "inbox_reads": trd},
                "total": {"likes_in": t[0], "inbox_reads": t[1], "likes_stored": likes_total},
                "credits": {"today": ctoday, "total": ctotal,
                              "prices": {"inbox_write": PRICE_LIKE_IN, "inbox_read": PRICE_READ,
                                         "analysis_call": PRICE_ANALYSIS}},
                "quota": {"free_daily": FREE_DAILY, "used_today": ctoday,
                            "left_today": max(0, FREE_DAILY - ctoday), "enforcing": ENFORCE_QUOTA},
                "pipeline": self.get_pipeline(user_id),
                "inference": self.get_inference(user_id),
                "balance": {"granted_total": granted, "spent_total": ctotal,
                              "left_total": granted - ctotal,
                              "referred_by": self.get_referrer(user_id),
                              "recent_grants": self.get_grant_history(user_id)},
                "history": self.get_spend_history(user_id)}

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

    def grant_credits(self, user_id, credits, reason="", referred_by=None):
        """Record gifted credits for a user. Returns the new granted total.

        When referred_by names the agent id that brought this user, the first
        such name is kept forever (INSERT OR IGNORE): first touch wins, later
        names are ignored, and naming yourself stores nothing. Raises
        ValueError on bad input. Never touches enforcement: the quota
        gate reads FREE_DAILY only, so grants are visible but refuse nothing
        until the owner turns enforcement on."""
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("user_id must be a non-empty string")
        if isinstance(credits, bool) or not isinstance(credits, int) or credits <= 0:
            raise ValueError("credits must be a positive integer")
        reason = str(reason or "")[:200]
        self.c.execute("INSERT INTO grants (at, day, user_id, credits, reason) VALUES (?,?,?,?,?)",
                       (utcnow(), today(), user_id, credits, reason))
        if isinstance(referred_by, str) and referred_by and referred_by != user_id:
            self.c.execute("INSERT OR IGNORE INTO referrals (user_id, referred_by, at) VALUES (?,?,?)",
                           (user_id, referred_by[:120], utcnow()))
        self.c.commit()
        return self.get_grants(user_id)["total"]

    @staticmethod
    def _norm_sale(amount, currency, ref):
        """Normalize an optional recorded sale. Returns (amount, currency, ref).

        All three are optional (None or '' = absent). amount must be a
        positive number when present; currency a non-empty string (stored
        upper-cased, cut at 16 chars); ref a string cut at 200 chars.
        amount and currency go together: one without the other raises
        ValueError, because a sale without a unit is not measurable."""
        if ref is None:
            ref = ""
        if not isinstance(ref, str):
            raise ValueError("sale_ref must be a string")
        ref = ref[:200]
        if amount is None or amount == "":
            amount = None
        elif isinstance(amount, bool) or not isinstance(amount, (int, float)) or not amount > 0:
            raise ValueError("sale_amount must be a positive number")
        if currency is None or currency == "":
            currency = None
        elif not isinstance(currency, str) or not currency.strip():
            raise ValueError("sale_currency must be a non-empty string")
        else:
            currency = currency.strip().upper()[:16]
        if (amount is None) != (currency is None):
            raise ValueError("sale_amount and sale_currency go together")
        return amount, currency or "", ref

    def mint_code(self, credits, reason="", expires_days=None, sale_amount=None,
                  sale_currency=None, sale_ref=None):
        """Mint one single-use prepaid code worth credits. Returns the code.

        Localhost only (the HTTP layer enforces it): the owner mints after
        seeing a payment off-band and hands the code to the buyer. ValueError
        on bad input; reason cut at 200 chars, stored for the grant history.
        expires_days (None or '' = never expires, else an integer number of
        days 1..3650) stamps expires_at; redeeming past it raises
        LookupError("expired"). sale_amount/sale_currency/sale_ref record
        what the buyer paid (see _norm_sale); the sales book shows it."""
        return self.mint_codes(credits, reason, expires_days, 1, sale_amount,
                               sale_currency, sale_ref)[0]

    def mint_codes(self, credits, reason="", expires_days=None, count=1,
                   sale_amount=None, sale_currency=None, sale_ref=None):
        """Mint count single-use prepaid codes worth credits. Returns [codes].

        One call per launch batch: the owner mints N codes with one reason,
        one deadline and one sale instead of N calls. Same validation as
        mint_code, plus count (None or '' = 1, else an integer 1..100;
        bool/str/0/negative rejected with ValueError). Every code carries
        the same credits, reason, expires_at and sale."""
        if isinstance(credits, bool) or not isinstance(credits, int) or credits <= 0:
            raise ValueError("credits must be a positive integer")
        reason = str(reason or "")[:200]
        if expires_days is None or expires_days == "":
            expires_at = ""
        elif isinstance(expires_days, bool) or not isinstance(expires_days, int):
            raise ValueError("expires_days must be an integer number of days")
        elif not 1 <= expires_days <= 3650:
            raise ValueError("expires_days must be between 1 and 3650")
        else:
            expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
        if count is None or count == "":
            count = 1
        if isinstance(count, bool) or not isinstance(count, int):
            raise ValueError("count must be an integer number of codes")
        if not 1 <= count <= 100:
            raise ValueError("count must be between 1 and 100")
        amount, currency, ref = self._norm_sale(sale_amount, sale_currency, sale_ref)
        codes = []
        for _ in range(count):
            for _ in range(10):
                code = "EL-" + secrets.token_hex(4).upper()
                try:
                    self.c.execute("INSERT INTO grant_codes (code, credits, reason, created_at, expires_at, sale_amount, sale_currency, sale_ref) VALUES (?,?,?,?,?,?,?,?)",
                                   (code, credits, reason, utcnow(), expires_at, amount, currency, ref))
                    self.c.commit()
                    codes.append(code)
                    break
                except sqlite3.IntegrityError:
                    continue
            else:
                raise ValueError("could not mint a unique code")
        return codes

    def redeem_code(self, user_id, code, referred_by=None):
        """Redeem a prepaid code into granted credits. Returns the new total.

        Single-use: the first redeemer wins, a second redeem raises
        LookupError("already redeemed"). Unknown codes raise LookupError,
        blank codes ValueError, revoked codes LookupError("revoked"),
        codes past their expires_at LookupError("expired"). The
        grant carries the code's stored reason,
        so the history shows why the credits exist. An optional
        referred_by names the agent id that brought this buyer; it stamps
        first-touch (INSERT OR IGNORE, self/junk ignored) only after every
        gate passes, so a failed redeem never squats a referral and the
        winner's stamp is the one that sticks."""
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("user_id must be a non-empty string")
        if not isinstance(code, str) or not code.strip():
            raise ValueError("code must be a non-empty string")
        code = code.strip().upper()
        row = self.c.execute("SELECT credits, reason, redeemed_by, revoked, expires_at FROM grant_codes WHERE code=?",
                             (code,)).fetchone()
        if not row:
            raise LookupError("unknown code")
        if row[3]:
            raise LookupError("revoked")
        if row[2]:
            raise LookupError("already redeemed")
        if row[4] and row[4] <= utcnow():
            raise LookupError("expired")
        if isinstance(referred_by, str) and referred_by and referred_by != user_id:
            self.c.execute("INSERT OR IGNORE INTO referrals (user_id, referred_by, at) VALUES (?,?,?)",
                           (user_id, referred_by[:120], utcnow()))
        self.c.execute("INSERT INTO grants (at, day, user_id, credits, reason) VALUES (?,?,?,?,?)",
                       (utcnow(), today(), user_id, row[0], row[1]))
        self.c.execute("UPDATE grant_codes SET redeemed_by=?, redeemed_at=? WHERE code=?",
                       (user_id, utcnow(), code))
        self.c.commit()
        return self.get_grants(user_id)["total"]

    def revoke_code(self, code):
        """Kill an unredeemed prepaid code before it can be spent.

        Localhost only (the HTTP layer enforces it): the owner revokes a
        leaked or unsold code. Returns the revoke timestamp. Blank codes
        raise ValueError; unknown codes LookupError; redeemed codes
        LookupError("already redeemed"); already-revoked codes
        LookupError("already revoked"). Writes no grant: the ledger is
        untouched, only the code dies."""
        if not isinstance(code, str) or not code.strip():
            raise ValueError("code must be a non-empty string")
        code = code.strip().upper()
        row = self.c.execute("SELECT redeemed_by, revoked FROM grant_codes WHERE code=?",
                             (code,)).fetchone()
        if not row:
            raise LookupError("unknown code")
        if row[0]:
            raise LookupError("already redeemed")
        if row[1]:
            raise LookupError("already revoked")
        at = utcnow()
        self.c.execute("UPDATE grant_codes SET revoked=? WHERE code=?", (at, code))
        self.c.commit()
        return at

    def record_payout(self, agent, amount, currency, ref=""):
        """Record an off-band payout to a bringer. Returns the timestamp.

        Localhost only (the HTTP layer enforces it): the owner pays the
        bringer off-band (crypto, after the commission rate decision) and
        writes down what moved, so totals can show paid{} and payable{}.
        agent must be a non-empty string (cut at 120, like referrals);
        amount a positive number (bool rejected); currency a non-empty
        string (stored upper-cased, cut at 16); ref a string cut at 200.
        Anything else raises ValueError. Writes no grant and changes no
        gate: the ledger only remembers."""
        if not isinstance(agent, str) or not agent.strip():
            raise ValueError("agent must be a non-empty string")
        agent = agent.strip()[:120]
        if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not amount > 0:
            raise ValueError("amount must be a positive number")
        if not isinstance(currency, str) or not currency.strip():
            raise ValueError("currency must be a non-empty string")
        currency = currency.strip().upper()[:16]
        if ref is None:
            ref = ""
        if not isinstance(ref, str):
            raise ValueError("ref must be a string")
        at = utcnow()
        self.c.execute("INSERT INTO payouts (at, day, agent, amount, currency, ref) VALUES (?,?,?,?,?,?)",
                       (at, today(), agent, amount, currency, ref[:200]))
        self.c.commit()
        return at

    def get_payouts(self):
        """Paid-out totals per bringer, read-only.

        {agent: {CUR: total}} over the payouts table, rounded to 9 decimals;
        never an error, unknown state is {}."""
        try:
            rows = self.c.execute("SELECT agent, currency, amount FROM payouts").fetchall()
        except sqlite3.Error:
            return {}
        out = {}
        for agent, currency, amount in rows:
            if not agent or not currency:
                continue
            bucket = out.setdefault(agent, {})
            bucket[currency] = bucket.get(currency, 0) + float(amount)
        return {a: {k: round(v, 9) for k, v in sorted(cur.items())}
                for a, cur in sorted(out.items())}

    def list_payouts(self, limit=100, agent=None):
        """Off-band payout ledger, newest first, read-only.

        [{at, day, agent, amount, currency, ref}] over the payouts table
        for the owner (localhost GET /api/payouts): one row per payment
        the owner recorded after paying a bringer off-band, so the totals'
        paid{}/payable{} can be checked line by line. ref is '' when the
        owner recorded no tx hash or note; never an error, unknown state
        is an empty list. Limit clamped to 1..500, default 100. agent is
        an optional exact-match filter (localhost GET /api/payouts?agent=X
        answers 'did I already pay this bringer?' without grepping the full
        list); None or blank means every bringer, unknown agents report []."""
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 100
        limit = max(1, min(500, limit))
        want = agent.strip() if isinstance(agent, str) else ""
        try:
            if want:
                rows = self.c.execute(
                    "SELECT at, day, agent, amount, currency, ref "
                    "FROM payouts WHERE agent=? ORDER BY rowid DESC LIMIT ?",
                    (want, limit)).fetchall()
            else:
                rows = self.c.execute(
                    "SELECT at, day, agent, amount, currency, ref "
                    "FROM payouts ORDER BY rowid DESC LIMIT ?",
                    (limit,)).fetchall()
        except sqlite3.Error:
            return []
        return [{"at": r[0], "day": r[1], "agent": r[2],
                 "amount": r[3], "currency": r[4],
                 "ref": r[5] or ""} for r in rows]

    def list_codes(self, limit=100):
        """Prepaid code inventory, newest first.

        Read-only view over grant_codes for the owner (localhost GET
        /api/codes): [{code, credits, reason, created_at, redeemed_by,
        redeemed_at, revoked, expires_at, sale_amount, sale_currency,
        sale_ref}]. Unredeemed codes report redeemed_by/
        redeemed_at as None, live codes report revoked as None, codes minted
        without a deadline report expires_at as None, codes minted without a
        recorded sale report sale_amount/sale_currency/sale_ref as None;
        never an error, unknown state is an empty list. Limit clamped
        to 1..500, default 100."""
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 100
        limit = max(1, min(500, limit))
        try:
            rows = self.c.execute(
                "SELECT code, credits, reason, created_at, redeemed_by, redeemed_at, revoked, expires_at, "
                "sale_amount, sale_currency, sale_ref "
                "FROM grant_codes ORDER BY rowid DESC LIMIT ?",
                (limit,)).fetchall()
        except sqlite3.Error:
            return []
        return [{"code": r[0], "credits": r[1], "reason": r[2],
                 "created_at": r[3], "redeemed_by": r[4] or None,
                 "redeemed_at": r[5] or None, "revoked": r[6] or None,
                 "expires_at": r[7] or None,
                 "sale_amount": r[8],
                 "sale_currency": r[9] or None,
                 "sale_ref": r[10] or None} for r in rows]

    def get_sales_totals(self):
        """Recorded revenue totals over prepaid codes, read-only.

        {codes, redeemed, revoked, outstanding, with_sale, sales:{CUR: total},
        by_referrer:{agent: {CUR: total}}, commission_pct, owed:{agent: {CUR: amount}},
        paid:{agent: {CUR: total}}, payable:{agent: {CUR: amount}},
        timeline:[{day, sales:{CUR: total}, settled}],
        by_referrer_daily:{agent: [{day, sales, settled}]}}.
        Sums every row carrying a sale
        (a revoked code keeps its note: the money arrived, the code was
        killed); free/promo rows count in codes but add nothing. by_referrer
        is the settled commission base: only REDEEMED codes whose redeemer
        carries a first-touch referrer stamp count, so the owner sees what
        each bringer's clients actually paid and settled. Unredeemed,
        revoked and unstamped rows stay in sales but never in by_referrer.
        owed applies the ECHO_COMMISSION_PCT rate to that settled base
        (report-only: the owner pays off-band); with no rate set
        commission_pct is None and owed is {}. paid sums the payouts table
        (localhost POST /api/payout, one row per off-band payment to a
        bringer); payable is owed minus paid per agent and currency, so the
        owner sees what is still due — negative when a bringer was overpaid,
        honest either way. timeline is the per-day settled revenue over the
        last 30 days, newest first: one row per day {day, sales:{CUR: total},
        settled} where day is the redemption day (redeemed_at[:10]), sales
        sums only REDEEMED codes carrying a sale, settled counts them, and
        quiet days report sales{} settled 0 so a chart stays stable. Rows
        with no usable redemption day are ignored there (never an error).
        by_referrer_daily is the same settlement cut per bringer: {agent:
        [{day, sales, settled}]} over the same 30-day window, newest first,
        sparse (only days where that agent's clients settled something, so
        the payload stays small). It answers WHEN each bringer earned what
        the by_referrer total already says: the daily commission base.
        Totals always cover the
        whole book, never just the ?limit= window
        of /api/codes. Sums round to 9 decimals (a lamport) so float dust
        never reaches the owner. No new table, never an error, unknown
        state is all zeros (timeline [])."""
        zero = {"codes": 0, "redeemed": 0, "revoked": 0, "outstanding": 0,
                "with_sale": 0, "sales": {}, "by_referrer": {},
                "commission_pct": COMMISSION_PCT, "owed": {},
                "paid": {}, "payable": {}, "timeline": [],
                "by_referrer_daily": {}}
        try:
            rows = self.c.execute(
                "SELECT redeemed_by, revoked, sale_amount, sale_currency, redeemed_at "
                "FROM grant_codes").fetchall()
        except sqlite3.Error:
            return zero
        try:
            refmap = {r[0]: r[1] for r in self.c.execute(
                "SELECT user_id, referred_by FROM referrals").fetchall()}
        except sqlite3.Error:
            refmap = {}
        sales = {}
        by_ref = {}
        owed_raw = {}
        per_day = {}
        per_day_n = {}
        per_agent_day = {}
        for redeemed_by, revoked, amount, currency, redeemed_at in rows:
            zero["codes"] += 1
            if redeemed_by:
                zero["redeemed"] += 1
            elif revoked:
                zero["revoked"] += 1
            else:
                zero["outstanding"] += 1
            if amount is not None and currency:
                zero["with_sale"] += 1
                sales[currency] = sales.get(currency, 0) + float(amount)
                if redeemed_by and isinstance(redeemed_at, str) and len(redeemed_at) >= 10:
                    day = redeemed_at[:10]
                    bucket = per_day.setdefault(day, {})
                    bucket[currency] = bucket.get(currency, 0) + float(amount)
                    per_day_n[day] = per_day_n.get(day, 0) + 1
                agent = refmap.get(redeemed_by) if redeemed_by else None
                if agent:
                    bucket = by_ref.setdefault(agent, {})
                    bucket[currency] = bucket.get(currency, 0) + float(amount)
                    if COMMISSION_PCT is not None:
                        ob = owed_raw.setdefault(agent, {})
                        ob[currency] = (ob.get(currency, 0) + float(amount) * COMMISSION_PCT / 100)
                    if isinstance(redeemed_at, str) and len(redeemed_at) >= 10:
                        aday = redeemed_at[:10]
                        ab = per_agent_day.setdefault(agent, {}).setdefault(aday, [{}, 0])
                        ab[0][currency] = ab[0].get(currency, 0) + float(amount)
                        ab[1] += 1
        zero["sales"] = {k: round(v, 9) for k, v in sorted(sales.items())}
        zero["by_referrer"] = {a: {k: round(v, 9) for k, v in sorted(cur.items())}
                                 for a, cur in sorted(by_ref.items())}
        zero["owed"] = {a: {k: round(v, 9) for k, v in sorted(cur.items())}
                            for a, cur in sorted(owed_raw.items())}
        try:
            prows = self.c.execute(
                "SELECT agent, currency, amount FROM payouts").fetchall()
        except sqlite3.Error:
            prows = []
        paid_raw = {}
        for agent, currency, amount in prows:
            if not agent or not currency:
                continue
            bucket = paid_raw.setdefault(agent, {})
            bucket[currency] = bucket.get(currency, 0) + float(amount)
        zero["paid"] = {a: {k: round(v, 9) for k, v in sorted(cur.items())}
                           for a, cur in sorted(paid_raw.items())}
        payable_raw = {}
        for agent in set(owed_raw) | set(paid_raw):
            for currency in set(owed_raw.get(agent, {})) | set(paid_raw.get(agent, {})):
                due = owed_raw.get(agent, {}).get(currency, 0) - paid_raw.get(agent, {}).get(currency, 0)
                payable_raw.setdefault(agent, {})[currency] = due
        zero["payable"] = {a: {k: round(v, 9) for k, v in sorted(cur.items())}
                              for a, cur in sorted(payable_raw.items())}
        days = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
                for i in range(30)]
        zero["timeline"] = [{"day": d,
                               "sales": {k: round(v, 9) for k, v in sorted(per_day.get(d, {}).items())},
                               "settled": per_day_n.get(d, 0)} for d in days]
        zero["by_referrer_daily"] = {
            a: [{"day": d,
                 "sales": {k: round(v, 9) for k, v in sorted(per_agent_day[a][d][0].items())},
                 "settled": per_agent_day[a][d][1]}
                for d in days if d in per_agent_day.get(a, {})]
            for a in sorted(per_agent_day)}
        return zero

    def get_referrer(self, user_id):
        """The agent id that first brought this user, or None.

        Read-only view over the referrals table; unknown users and users
        granted without a referrer report None, never an error."""
        try:
            row = self.c.execute("SELECT referred_by FROM referrals WHERE user_id=?",
                                 (user_id,)).fetchone()
        except sqlite3.Error:
            return None
        return row[0] if row else None

    def get_grants(self, user_id):
        try:
            row = self.c.execute("SELECT COALESCE(SUM(credits),0), COUNT(*) FROM grants WHERE user_id=?",
                                 (user_id,)).fetchone()
        except sqlite3.Error:
            return {"total": 0, "count": 0}
        return {"total": row[0] if row else 0, "count": row[1] if row else 0}

    def get_grant_history(self, user_id, limit=5):
        """Last grants for this user, newest first: [{day, credits, reason}].

        Read-only view over the grants ledger for the options badge; empty
        list for unknown users, never an error."""
        try:
            rows = self.c.execute(
                "SELECT day, credits, reason FROM grants WHERE user_id=? "
                "ORDER BY id DESC LIMIT ?", (user_id, limit)).fetchall()
        except sqlite3.Error:
            return []
        return [{"day": r[0], "credits": r[1], "reason": r[2]} for r in rows]

    def get_spend_history(self, user_id, days=7):
        """Per-day spend off the same cash register, newest first: [{day, spent, granted}].

        No new backend: spent reuses the usage + inference rows with the same
        prices get_usage() applies; granted sums the grants ledger per day.
        Days with no activity report zeros so a chart stays stable; unknown
        users get zeros, never an error. Read-only."""
        try:
            days = max(1, min(30, int(days)))
        except (TypeError, ValueError):
            days = 7
        try:
            from datetime import timedelta
            base = datetime.now(timezone.utc).date()
            out = []
            for i in range(days):
                d = str(base - timedelta(days=i))
                u = self.c.execute("SELECT likes_in, inbox_reads FROM usage WHERE day=? AND user_id=?",
                                   (d, user_id)).fetchone()
                f = self.c.execute("SELECT calls FROM inference WHERE day=? AND user_id=?",
                                   (d, user_id)).fetchone()
                g = self.c.execute("SELECT COALESCE(SUM(credits),0) FROM grants WHERE day=? AND user_id=?",
                                   (d, user_id)).fetchone()
                spent = ((u[0] if u else 0) * PRICE_LIKE_IN + (u[1] if u else 0) * PRICE_READ
                         + (f[0] if f else 0) * PRICE_ANALYSIS)
                out.append({"day": d, "spent": spent, "granted": g[0] if g else 0})
            return out
        except sqlite3.Error:
            return []

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
            metrics = {k: _metric(it.get(k)) for k in ("replies", "reposts", "likes", "views")}
            # how long the client's POST took to come back (the number its toast shows)
            if post_ms is not None and "post_ms" not in it:
                it["post_ms"] = post_ms
            try:
                self.c.execute(
                    "INSERT OR IGNORE INTO likes (id, device, kind, handle, url, text, nota, clicked_at, recv_at, raw, ua, ip, replies, reposts, likes, views) VALUES (?,?,?,?,?,?,?,?,?,?,?, ?,?,?,?,?)",
                    (iid, device, kind, str(it.get("handle", "") or ""), str(it.get("url", "") or ""),
                     str(it.get("text", "") or "")[:4000], str(it.get("nota", "") or "")[:4000],
                     str(it.get("clicked_at", "") or ""), utcnow(), json.dumps(it)[:8000],
                     str(ua or "")[:300], str(ip or "")[:60],
                     metrics["replies"], metrics["reposts"], metrics["likes"], metrics["views"]),
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
        rows = self.c.execute(f"SELECT id, kind, handle, url, text, nota, clicked_at, recv_at, replies, reposts, likes, views FROM likes WHERE device IN ({marks}) ORDER BY recv_at DESC LIMIT ?",
                              (*devs, limit)).fetchall()
        return [{"id": r[0], "kind": r[1], "handle": r[2], "url": r[3], "text": r[4], "nota": r[5], "clicked_at": r[6], "recv_at": r[7],
                 "replies": r[8], "reposts": r[9], "likes": r[10], "views": r[11]} for r in rows]


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
                                               "free_daily": FREE_DAILY, "enforcing": ENFORCE_QUOTA},
                                   "checkout": {"sol": CHECKOUT_SOL or None,
                                                "evm": CHECKOUT_EVM or None}})
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
            if u.path == "/api/codes":
                peer = (self.client_address[0] if self.client_address else "")
                if peer not in ("127.0.0.1", "::1"):
                    return self._json({"ok": False, "error": "codes only from this machine"}, 403)
                q = parse_qs(u.query)
                try:
                    limit = max(1, min(500, int(q.get("limit", ["100"])[0])))
                except ValueError:
                    limit = 100
                return self._json({"ok": True, "codes": db.list_codes(limit),
                                     "totals": db.get_sales_totals()})
            if u.path == "/api/payouts":
                peer = (self.client_address[0] if self.client_address else "")
                if peer not in ("127.0.0.1", "::1"):
                    return self._json({"ok": False, "error": "payouts only from this machine"}, 403)
                q = parse_qs(u.query)
                try:
                    limit = max(1, min(500, int(q.get("limit", ["100"])[0])))
                except ValueError:
                    limit = 100
                agent = q.get("agent", [None])[0]
                want = agent.strip() if isinstance(agent, str) and agent.strip() else None
                return self._json({"ok": True, "agent": want,
                                     "payouts": db.list_payouts(limit, want)})
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

        def _grant(self):
            """POST /api/grant — localhost only, no token needed: the operator
            records gifted credits (founder free tier, promo, a top-up after a
            payment is seen on-chain). Bookkeeping only, moves no money."""
            peer = (self.client_address[0] if self.client_address else "")
            if peer not in ("127.0.0.1", "::1"):
                return self._json({"ok": False, "error": "grant only from this machine"}, 403)
            try:
                n = int(self.headers.get("content-length") or 0)
            except ValueError:
                n = 0
            if n > 1_000_000:
                return self._json({"ok": False, "error": "too large"}, 413)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, OSError):
                return self._json({"ok": False, "error": "bad json"}, 400)
            try:
                total = db.grant_credits(body.get("user_id"), body.get("credits"),
                                         body.get("reason", ""),
                                         body.get("referred_by"))
            except ValueError as e:
                return self._json({"ok": False, "error": str(e)}, 400)
            return self._json({"ok": True, "user_id": body.get("user_id"),
                               "granted_total": total,
                               "balance": db.get_usage(body.get("user_id"))["balance"]})

        def _mint(self):
            """POST /api/mint — localhost only: mint one batch of prepaid codes."""
            peer = (self.client_address[0] if self.client_address else "")
            if peer not in ("127.0.0.1", "::1"):
                return self._json({"ok": False, "error": "mint only from this machine"}, 403)
            try:
                n = int(self.headers.get("content-length") or 0)
            except ValueError:
                n = 0
            if n > 1_000_000:
                return self._json({"ok": False, "error": "too large"}, 413)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, OSError):
                return self._json({"ok": False, "error": "bad json"}, 400)
            try:
                codes = db.mint_codes(body.get("credits"), body.get("reason", ""),
                                      body.get("expires_days"),
                                      body.get("count", 1) if "count" in body else 1,
                                      body.get("sale_amount"),
                                      body.get("sale_currency"),
                                      body.get("sale_ref", "") if "sale_ref" in body else "")
            except ValueError as e:
                return self._json({"ok": False, "error": str(e)}, 400)
            latest = {c["code"]: c for c in db.list_codes(len(codes))}
            first = latest.get(codes[0], {}) if codes else {}
            sale = {k: first.get(k) for k in ("sale_amount", "sale_currency", "sale_ref")}
            return self._json({"ok": True, "code": codes[0],
                               "codes": codes,
                               "credits": body.get("credits"),
                               "reason": str(body.get("reason", "") or "")[:200],
                               "expires_at": first.get("expires_at"),
                               "sale": sale})

        def _redeem(self):
            """POST /api/redeem — authed user redeems a prepaid code once."""
            dev, uid = self._identity()
            if not dev:
                return self._json({"ok": False, "error": "unauthorized"}, 401)
            try:
                n = int(self.headers.get("content-length") or 0)
            except ValueError:
                n = 0
            if n > 1_000_000:
                return self._json({"ok": False, "error": "too large"}, 413)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, OSError):
                return self._json({"ok": False, "error": "bad json"}, 400)
            try:
                total = db.redeem_code(uid, body.get("code"), body.get("referred_by"))
            except ValueError as e:
                return self._json({"ok": False, "error": str(e)}, 400)
            except LookupError as e:
                msg = str(e)
                if msg == "expired":
                    return self._json({"ok": False, "error": msg}, 410)
                if "already" in msg or "revoked" in msg:
                    return self._json({"ok": False, "error": msg}, 409)
                return self._json({"ok": False, "error": msg}, 404)
            return self._json({"ok": True, "user_id": uid,
                               "granted_total": total,
                               "balance": db.get_usage(uid)["balance"]})

        def _revoke(self):
            """POST /api/revoke — localhost only: kill an unredeemed code."""
            peer = (self.client_address[0] if self.client_address else "")
            if peer not in ("127.0.0.1", "::1"):
                return self._json({"ok": False, "error": "revoke only from this machine"}, 403)
            try:
                n = int(self.headers.get("content-length") or 0)
            except ValueError:
                n = 0
            if n > 1_000_000:
                return self._json({"ok": False, "error": "too large"}, 413)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, OSError):
                return self._json({"ok": False, "error": "bad json"}, 400)
            try:
                at = db.revoke_code(body.get("code"))
            except ValueError as e:
                return self._json({"ok": False, "error": str(e)}, 400)
            except LookupError as e:
                msg = str(e)
                if "already" in msg:
                    return self._json({"ok": False, "error": msg}, 409)
                return self._json({"ok": False, "error": msg}, 404)
            code = str(body.get("code") or "").strip().upper()
            return self._json({"ok": True, "code": code, "revoked_at": at})

        def _payout(self):
            """POST /api/payout — localhost only: record an off-band payout."""
            peer = (self.client_address[0] if self.client_address else "")
            if peer not in ("127.0.0.1", "::1"):
                return self._json({"ok": False, "error": "payout only from this machine"}, 403)
            try:
                n = int(self.headers.get("content-length") or 0)
            except ValueError:
                n = 0
            if n > 1_000_000:
                return self._json({"ok": False, "error": "too large"}, 413)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, OSError):
                return self._json({"ok": False, "error": "bad json"}, 400)
            try:
                at = db.record_payout(body.get("agent"), body.get("amount"),
                                      body.get("currency"), body.get("ref", ""))
            except ValueError as e:
                return self._json({"ok": False, "error": str(e)}, 400)
            return self._json({"ok": True, "agent": str(body.get("agent") or "").strip()[:120],
                               "amount": body.get("amount"),
                               "currency": str(body.get("currency") or "").strip().upper()[:16],
                               "paid_at": at})

        def do_POST(self):
            u = urlparse(self.path)
            if u.path == "/api/claim":
                return self._claim()
            if u.path == "/api/grant":
                return self._grant()
            if u.path == "/api/mint":
                return self._mint()
            if u.path == "/api/redeem":
                return self._redeem()
            if u.path == "/api/revoke":
                return self._revoke()
            if u.path == "/api/payout":
                return self._payout()
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

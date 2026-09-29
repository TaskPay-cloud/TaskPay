import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, g, render_template, request, redirect, url_for, session, jsonify, Response, render_template_string
from markupsafe import Markup, escape
from werkzeug.security import generate_password_hash, check_password_hash



def _find_app_dir():
    """Finds the TaskPay folder (the one holding index.html, dashboard.html,
    etc). Pydroid 3 runs a temporary copy of app.py from its own private
    folder, so __file__ can point there instead of at TaskPay -- which made
    Flask look for index.html in the wrong place. We look for the real
    folder instead."""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        here = None

    def is_taskpay(d):
        for base in (d, os.path.join(d, "templates")):
            if os.path.isfile(os.path.join(base, "index.html")) and \
               os.path.isfile(os.path.join(base, "dashboard.html")):
                return True
        return False

    candidates = [os.environ.get("TASKPAY_DIR"), here, os.getcwd()]
    for root in ("/storage/emulated/0", "/sdcard"):
        for name in ("TaskPay", "Taskpay", "taskpay", "TASKPAY"):
            candidates.append(os.path.join(root, name))
    for d in candidates:
        if d and os.path.isdir(d) and is_taskpay(d):
            return d

    # Last resort: look one or two levels deep in device storage.
    for root in ("/storage/emulated/0", "/sdcard"):
        try:
            for name in sorted(os.listdir(root)):
                d1 = os.path.join(root, name)
                if not os.path.isdir(d1):
                    continue
                if is_taskpay(d1):
                    return d1
                try:
                    for sub in sorted(os.listdir(d1)):
                        d2 = os.path.join(d1, sub)
                        if os.path.isdir(d2) and is_taskpay(d2):
                            return d2
                except OSError:
                    pass
        except OSError:
            pass
    return here or os.getcwd()


APP_DIR = _find_app_dir()
def _pick_db_path():
    """Use the first location we can actually write to.
    Some hosts (Deplexo included) run the container with a read-only /app,
    so we try the configured path first, then common writable folders."""
    wanted = os.environ.get("DB_PATH")
    candidates = ([wanted] if wanted else []) + [
        "/data/taskpay.db",
        os.path.join(APP_DIR, "taskpay.db"),
        "/tmp/taskpay.db",
    ]
    for path in candidates:
        folder = os.path.dirname(path) or "."
        try:
            os.makedirs(folder, exist_ok=True)
            probe = os.path.join(folder, ".write_test")
            with open(probe, "w") as fh:
                fh.write("ok")
            os.remove(probe)
            return path
        except OSError as exc:
            print(f"[warn] Cannot use {folder} for the database: {exc}", flush=True)
    print("[FATAL] No writable folder found for the SQLite database.", flush=True)
    raise SystemExit(1)

DB_PATH = _pick_db_path()
print(f"[info] TaskPay folder: {APP_DIR}", flush=True)
print(f"[info] SQLite library {sqlite3.sqlite_version}, database file: {DB_PATH}", flush=True)
if DB_PATH.startswith("/tmp"):
    print("[WARN] Database is in /tmp: it will be ERASED on every redeploy/restart. "
          "Attach a persistent volume and set DB_PATH to it.", flush=True)

# ---------- settings (loaded from a .env file in the TaskPay folder) ----------
# Create a plain text file named  .env  in the same folder as app.py
# (e.g. /storage/emulated/0/TaskPay/.env) with lines like:
#     PAYSTACK_SECRET_KEY=sk_test_xxxxxxxx
# Restart the app after editing it. No extra packages needed.
def _env_candidates():
    dirs = [APP_DIR, os.getcwd(), "/storage/emulated/0/TaskPay", "/sdcard/TaskPay"]
    seen, paths = set(), []
    for d in dirs:
        for name in (".env", ".env.txt"):
            p = os.path.join(d, name)
            if p not in seen:
                seen.add(p)
                paths.append(p)
    return paths


ENV_PATH = None
_ENV_VALUES = {}
for _p in _env_candidates():
    if os.path.isfile(_p):
        try:
            with open(_p, "r", encoding="utf-8-sig") as _f:
                for _line in _f:
                    _line = _line.strip()
                    if not _line or _line.startswith("#") or "=" not in _line:
                        continue
                    if _line.lower().startswith("export "):
                        _line = _line[7:].strip()
                    _k, _, _v = _line.partition("=")
                    _v = _v.strip()
                    if len(_v) >= 2 and _v[0] == _v[-1] and _v[0] in "\"'":
                        _v = _v[1:-1]
                    _ENV_VALUES.setdefault(_k.strip(), _v)
            ENV_PATH = _p
            break
        except OSError as _exc:
            print(f"[warn] Could not read {_p}: {_exc}")

if ENV_PATH:
    print(f"[info] Loaded settings from {ENV_PATH}")
else:
    print("[warn] No .env file found. Looked in: " + ", ".join(_env_candidates()[:4]))


def env(key, default=""):
    """Real environment variable first, then the .env file, then the default."""
    return os.environ.get(key) or _ENV_VALUES.get(key) or default


def _get_secret_key():
    """SECRET_KEY from .env; if it's missing, make one and save it to the
    .env file so logins survive restarts."""
    key = env("SECRET_KEY")
    if key:
        return key
    key = secrets.token_hex(32)
    target = ENV_PATH or os.path.join(APP_DIR, ".env")
    try:
        with open(target, "a", encoding="utf-8") as f:
            f.write(f"\nSECRET_KEY={key}\n")
        print(f"[info] Generated a SECRET_KEY and saved it to {target}")
    except OSError as exc:
        print(f"[warn] Could not save SECRET_KEY to {target} ({exc}); logins will reset on restart.")
    return key


SECRET_KEY = _get_secret_key()
APP_BASE_URL = env("APP_BASE_URL", "http://localhost:5000")

PAYSTACK_SECRET_KEY = env("PAYSTACK_SECRET_KEY")

GOOGLE_CLIENT_ID = env("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = env("GOOGLE_CLIENT_SECRET")

BREVO_API_KEY = env("BREVO_API_KEY")
BREVO_SENDER_EMAIL = env("BREVO_SENDER_EMAIL", "no-reply@taskpay.local")
BREVO_SENDER_NAME = env("BREVO_SENDER_NAME", "TaskPay")

# SMTP sending (Brevo SMTP relay) -- used when BREVO_API_KEY isn't set.
# Values set in the host's Env tab (or a .env file) override the defaults below.
SMTP_HOST = env("SMTP_HOST", "smtp-relay.brevo.com")
SMTP_PORT = int(re.sub(r"\D", "", env("SMTP_PORT", "587")) or 587)
SMTP_USER = env("SMTP_USER") or env("GMAIL_USER") or "b05013001@smtp-brevo.com"
SMTP_PASSWORD = (
    env("SMTP_PASSWORD") or env("SMTP_PASS") or env("GMAIL_APP_PASSWORD")
    or "xsmtpsib-lb54e5fa8d38827e9f415fd66bdceb804c5bd41e0e58f17a336163d8534a566ab-bS9Os3vgyXdIoIw"
).replace(" ", "")
# The address emails appear to come from. Must be a sender/domain verified in Brevo.
MAIL_FROM = env("MAIL_FROM") or env("BREVO_SENDER_EMAIL") or "noreply@playconsistency.com.ng"
EMAIL_ENABLED = bool(BREVO_API_KEY or (SMTP_USER and SMTP_PASSWORD))

LAUNCH_DATE_ISO = env("LAUNCH_DATE_ISO", "2026-11-30T00:00:00+00:00")
REFERRAL_COMMISSION_RATE = float(env("REFERRAL_COMMISSION_RATE", "0.05"))

# CPX Research (from publisher.cpx-research.com -> your app)
CPX_APP_ID = env("CPX_APP_ID")
CPX_SECURE_HASH = env("CPX_SECURE_HASH")

# Offerwall.GG (placement keys from the Integrate page of your placement)
OFFERWALL_PUBLIC_KEY = env("OFFERWALL_PUBLIC_KEY", "ffff91446997aa1cdc2f571a29e4c6db")
OFFERWALL_SECRET = env("OFFERWALL_SECRET")
# How many of the wall's units equal 1 USD for the user. If the wall shows
# dollars (Currency name USD), leave at 1. If it shows points at 1000 per
# USD, set OFFERWALL_UNITS_PER_USD=1000. Users are credited what the wall showed.
OFFERWALL_UNITS_PER_USD = float(env("OFFERWALL_UNITS_PER_USD", "1") or 1)

# Only used if the live exchange-rate feed has never been reachable
FALLBACK_RATE_NGN = float(env("FALLBACK_RATE_NGN", "1500"))
FALLBACK_RATE_XOF = float(env("FALLBACK_RATE_XOF", "570"))


app = Flask(__name__, root_path=APP_DIR, static_folder=None)
app.config["SECRET_KEY"] = SECRET_KEY

# Behind Deplexo's proxy: use the real scheme/host so url_for(_external=True)
# (Google sign-in redirect, referral links) produces https:// URLs.
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Templates: use TaskPay/templates/ if it exists, and also accept the HTML
# files sitting directly in the TaskPay folder.
from jinja2 import ChoiceLoader, FileSystemLoader
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(os.path.join(APP_DIR, "templates")),
    FileSystemLoader(APP_DIR),
])

# Static files (style.css, script.js, images) from TaskPay/static/ or from
# the TaskPay folder itself. Only web asset types are ever served, so
# app.py, .env and the database can never be downloaded.
_STATIC_TYPES = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2"}


def serve_static(filename):
    from flask import send_from_directory, abort
    if os.path.splitext(filename)[1].lower() not in _STATIC_TYPES:
        abort(404)
    for folder in (os.path.join(APP_DIR, "static"), APP_DIR):
        if os.path.isfile(os.path.join(folder, filename)):
            return send_from_directory(folder, filename)
    abort(404)


app.add_url_rule("/static/<path:filename>", endpoint="static", view_func=serve_static)
# Without this, Flask issues a plain "session cookie" that has no expiry
# date and gets wiped whenever the browser/app process is closed -- which
# is what made the language choice (and login) forget itself. Making the
# session permanent gives the cookie a real expiry, so it survives closing
# the browser/app.
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=365)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ---------- Google sign-in ----------
# Create OAuth credentials at https://console.cloud.google.com/apis/credentials
# (OAuth client ID, type "Web application") and set the redirect URI to
# APP_BASE_URL + /auth/google/callback.
oauth = OAuth(app)
google_oauth = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# ---------- Brevo transactional email (signup confirmation) ----------
# Get an API key at https://app.brevo.com/settings/keys/api and verify a
# sender address/domain in Brevo before sending -- unverified senders get
# silently rejected.

# ---------- earning sources ----------
# Users earn from tasks only. Settlement (has the money actually landed in
# your account?) is still tracked so payouts are only released once you
# confirm it.
SOURCES = {
    "internal": {"label": "Tasks"},
    "cpx": {"label": "CPX Research"},
    "offerwallgg": {"label": "Offerwall.GG"},
}

# ---------- supported countries ----------
# Drives the country dropdown at signup/Settings and which bank list gets
# requested from Paystack. NOTE: Paystack's /bank list endpoint currently
# only documents support for nigeria/ghana/kenya/south africa -- Togo is
# not one of them, so picking Togo will show "no banks found" until
# Paystack adds it (or you point payouts at a different provider for
# Togo). Left configurable here so that's a one-line fix later.
COUNTRIES = {
    "nigeria": {"label": "Nigeria", "paystack_country": "nigeria", "currency": "NGN"},
    "togo": {"label": "Togo", "paystack_country": "togo", "currency": "XOF"},
}
DEFAULT_COUNTRY = "nigeria"

# ---------- currencies + live exchange rates ----------
# Everything is stored in USD. Each user
# picks a currency at signup, and every balance/reward they see is
# converted from USD at the live rate. Payouts to Nigerian banks go out in
# NGN via Paystack, converted at the live rate at the moment of payout.
CURRENCIES = {
    "NGN": {"label": "Naira (₦)", "symbol": "₦", "decimals": 2},
    "XOF": {"label": "CFA franc (CFA)", "symbol": "CFA ", "decimals": 0},
    "USD": {"label": "US dollar ($)", "symbol": "$", "decimals": 2},
}
DEFAULT_CURRENCY = "NGN"
CURRENCY_SYMBOLS = {code: info["symbol"].strip() for code, info in CURRENCIES.items()}

# Only used if the live rate feed has never been reachable.
FALLBACK_RATES = {
    "USD": 1.0,
    "NGN": FALLBACK_RATE_NGN,
    "XOF": FALLBACK_RATE_XOF,
}
FX_URL = "https://open.er-api.com/v6/latest/USD"
FX_REFRESH_SECONDS = 900          # re-fetch at most every 15 minutes
FX_STALE_AFTER_SECONDS = 6 * 3600  # older than this is no longer "live"
_fx_cache = {"rates": None, "fetched_at": None, "last_attempt": None}


def get_fx_rates(force=False):
    """Returns {"rates": {"USD":1,"NGN":..,"XOF":..}, "live": bool, "updated": iso}.
    Cached in memory; a failed fetch is not retried for 60s so an offline
    server doesn't slow every page load."""
    now = datetime.utcnow()
    fetched = _fx_cache["fetched_at"]
    age = (now - fetched).total_seconds() if fetched else None
    needs_refresh = force or age is None or age > FX_REFRESH_SECONDS
    last_attempt = _fx_cache["last_attempt"]
    recently_tried = last_attempt and (now - last_attempt).total_seconds() < 60 and not force

    if needs_refresh and not recently_tried:
        _fx_cache["last_attempt"] = now
        try:
            resp = requests.get(FX_URL, timeout=5)
            data = resp.json()
            if data.get("result") == "success":
                r = data["rates"]
                _fx_cache["rates"] = {"USD": 1.0, "NGN": float(r["NGN"]), "XOF": float(r["XOF"])}
                _fx_cache["fetched_at"] = now
                fetched, age = now, 0
        except (requests.RequestException, ValueError, KeyError, TypeError):
            pass

    if _fx_cache["rates"]:
        live = age is not None and (now - _fx_cache["fetched_at"]).total_seconds() < FX_STALE_AFTER_SECONDS
        return {"rates": _fx_cache["rates"], "live": live,
                "updated": _fx_cache["fetched_at"].strftime("%Y-%m-%d %H:%M:%S") + " UTC"}
    return {"rates": dict(FALLBACK_RATES), "live": False, "updated": None}


def user_country_key(user):
    key = ((user["country"] if user else None) or DEFAULT_COUNTRY).lower()
    return key if key in COUNTRIES else DEFAULT_COUNTRY


def user_currency(user):
    """The currency this user picked at signup; falls back to the currency
    of their country for older accounts."""
    code = None
    if user:
        try:
            code = user["currency"]
        except (KeyError, IndexError):
            code = None
    if code in CURRENCIES:
        return code
    return COUNTRIES[user_country_key(user)]["currency"]


def convert_usd(amount_usd, currency, rates=None):
    rates = rates or get_fx_rates()["rates"]
    return float(amount_usd or 0) * rates.get(currency, 1.0)


def format_money(amount_usd, currency, rates=None):
    info = CURRENCIES[currency]
    value = convert_usd(amount_usd, currency, rates)
    return f"{info['symbol']}{value:,.{info['decimals']}f}"


def money(amount_usd, user=None, currency=None):
    """Template helper: renders a USD amount in the user's currency as a
    <span> that script.js keeps updated with the live rate."""
    code = currency if currency in CURRENCIES else user_currency(user)
    text = format_money(amount_usd, code)
    return Markup(
        f'<span class="money" data-usd="{float(amount_usd or 0):.6f}" data-cur="{code}">{text}</span>'
    )


def money_others(amount_usd, user=None):
    """The same amount in the two currencies the user did NOT pick."""
    own = user_currency(user)
    parts = [money(amount_usd, currency=c) for c in CURRENCIES if c != own]
    return Markup(" · ".join(str(p) for p in parts))


def local_money(amount, currency):
    """A fixed amount already in `currency` (what a payout actually paid),
    shown as-is with no live conversion."""
    info = CURRENCIES.get(currency, CURRENCIES["USD"])
    return f"{info['symbol']}{float(amount or 0):,.{info['decimals']}f}"


def user_currency_symbol(user):
    return CURRENCY_SYMBOLS.get(user_currency(user), "$")


@app.context_processor
def inject_currency_helper():
    return {
        "currency_symbol": user_currency_symbol,
        "money": money,
        "money_others": money_others,
        "local_money": local_money,
        "public_source": lambda src: {"cpx": tr("src.surveys"), "offerwallgg": tr("src.offers")}.get(src, tr("src.tasks")),
        "currencies": CURRENCIES,
    }


# ---------- Paystack (user payouts) ----------
# Get your secret key from Settings -> API Keys & Webhooks in the Paystack
# dashboard: https://dashboard.paystack.com/#/settings/developer
# Use a test secret key (sk_test_...) while developing -- switch to your
# live key (sk_live_...) only once you're ready to move real money.
PAYSTACK_BASE_URL = "https://api.paystack.co"

_bank_list_cache = {}  # country key -> {"banks": [...], "fetched_at": datetime}


def _paystack_headers():
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }


def user_paystack_country(user):
    """The Paystack `country` param to use for a given user's bank list,
    falling back to Nigeria for anyone without a country set yet (e.g.
    accounts created before this field existed)."""
    key = ((user["country"] if user else None) or DEFAULT_COUNTRY).lower()
    return COUNTRIES.get(key, COUNTRIES[DEFAULT_COUNTRY])["paystack_country"]


PAYSTACK_BANK_COUNTRIES = {"nigeria", "ghana", "kenya", "south africa"}

# Paystack has no bank list or transfers for Togo/XOF, so those users pick
# a mobile-money wallet or bank here and enter the number; payouts to them
# are recorded as "manual" for you to send yourself (or via another
# provider) rather than through Paystack.
MANUAL_PAYOUT_METHODS = {
    "togo": [
        {"code": "tmoney", "name": "T-Money (Togocel)"},
        {"code": "flooz", "name": "Flooz (Moov Africa)"},
        {"code": "ecobank_tg", "name": "Ecobank Togo"},
        {"code": "orabank_tg", "name": "Orabank Togo"},
    ],
}


def get_paystack_banks(country="nigeria", force_refresh=False):
    """Live bank list from Paystack, sorted by name. Follows Paystack's
    cursor pagination -- a single request returns at most 100 banks, and
    Nigeria has more than that, so the old dropdown was missing banks.
    Cached in memory per country for an hour."""
    cache = _bank_list_cache.setdefault(country, {"banks": None, "fetched_at": None})
    if not force_refresh and cache["banks"] and cache["fetched_at"]:
        if (datetime.utcnow() - cache["fetched_at"]).total_seconds() < 3600:
            return cache["banks"]

    if not PAYSTACK_SECRET_KEY:
        print("[warn] PAYSTACK_SECRET_KEY is empty -- add it to your .env file in the TaskPay folder, or the bank list stays empty.")
        return []

    banks_by_code = {}
    params = {"country": country, "perPage": 100, "use_cursor": "true"}
    try:
        for _ in range(10):  # hard stop so a bad cursor can never loop forever
            resp = requests.get(f"{PAYSTACK_BASE_URL}/bank", headers=_paystack_headers(),
                                params=params, timeout=10)
            data = resp.json()
            if not data.get("status"):
                print(f"[error] Paystack bank list failed for {country}: {data.get('message')}")
                return cache["banks"] or []
            for b in data["data"]:
                if b.get("is_deleted") or b.get("active") is False:
                    continue
                banks_by_code.setdefault(b["code"], {"code": b["code"], "name": b["name"]})
            nxt = (data.get("meta") or {}).get("next")
            if not nxt:
                break
            params["next"] = nxt
    except (requests.RequestException, ValueError, KeyError) as exc:
        print(f"[error] Paystack bank list request failed for {country}: {exc}")
        return cache["banks"] or []

    banks = sorted(banks_by_code.values(), key=lambda b: b["name"].lower())
    cache["banks"] = banks
    cache["fetched_at"] = datetime.utcnow()
    return banks


def payout_methods_for(country_key):
    """(list, manual) -- Paystack banks for supported countries, otherwise
    the manual mobile-money/bank list."""
    country = COUNTRIES[country_key]
    if country["paystack_country"] in PAYSTACK_BANK_COUNTRIES:
        return get_paystack_banks(country=country["paystack_country"]), False
    return MANUAL_PAYOUT_METHODS.get(country_key, []), True


def save_payout_details(db, user, country_key, bank_code, bank_name, account_number):
    """Verifies + stores payout details. Returns (account_name, error).
    Paystack countries: resolve the account and register a transfer
    recipient. Other countries: validate the number and store it for a
    manual payout."""
    methods, manual = payout_methods_for(country_key)
    if not manual:
        account_name, error = paystack_resolve_account(account_number, bank_code)
        if error:
            return None, error
        _, error = paystack_get_or_create_recipient(db, user, bank_code, bank_name, account_number, account_name)
        return (None, error) if error else (account_name, None)

    method = next((m for m in methods if m["code"] == bank_code), None)
    if method is None:
        return None, tr("err.pick_method")
    digits = account_number.replace(" ", "").lstrip("+")
    if not digits.isdigit() or not 8 <= len(digits) <= 15:
        return None, tr("err.number_invalid")
    db.execute(
        "UPDATE users SET bank_code = ?, bank_name = ?, account_number = ?, "
        "account_name = ?, paystack_recipient_code = NULL WHERE id = ?",
        (method["code"], method["name"], digits, user["username"], user["id"]),
    )
    db.commit()
    return user["username"], None


def paystack_resolve_account(account_number, bank_code):
    """Confirms an account number is real and reachable at that bank, and
    returns the account holder's name so the user can double-check it's
    theirs before we save it. This is Paystack's account-resolve endpoint,
    not a guess -- if it fails, the account number/bank combo is wrong."""
    if not PAYSTACK_SECRET_KEY:
        return None, tr("err.paystack_missing")
    try:
        resp = requests.get(
            f"{PAYSTACK_BASE_URL}/bank/resolve",
            headers=_paystack_headers(),
            params={"account_number": account_number, "bank_code": bank_code},
            timeout=15,
        )
        data = resp.json()
        if not data.get("status"):
            return None, data.get("message") or tr("err.account_verify")
        return data["data"]["account_name"], None
    except requests.RequestException as exc:
        return None, tr("err.paystack_failed")


def paystack_get_or_create_recipient(db, user, bank_code, bank_name, account_number, account_name):
    """Creates (or reuses) a Paystack transfer recipient for this user and
    caches the recipient_code on their row -- Paystack transfers are made
    to a recipient_code, not a raw account number, so this only needs to
    happen once per user unless their bank details change."""
    try:
        resp = requests.post(
            f"{PAYSTACK_BASE_URL}/transferrecipient",
            headers=_paystack_headers(),
            json={
                "type": "nuban",
                "name": account_name,
                "account_number": account_number,
                "bank_code": bank_code,
                "currency": "NGN",
            },
            timeout=15,
        )
        data = resp.json()
        if not data.get("status"):
            return None, data.get("message") or tr("err.paystack_register")
        recipient_code = data["data"]["recipient_code"]
        db.execute(
            "UPDATE users SET bank_code = ?, bank_name = ?, account_number = ?, "
            "account_name = ?, paystack_recipient_code = ? WHERE id = ?",
            (bank_code, bank_name, account_number, account_name, recipient_code, user["id"]),
        )
        db.commit()
        return recipient_code, None
    except requests.RequestException as exc:
        return None, tr("err.paystack_failed")


def paystack_send_transfer(recipient_code, amount, reason):
    """Actually moves money: initiates a Paystack transfer to a recipient.
    Amount is in naira here and converted to kobo (Paystack's base unit)
    since that's what the API expects. Returns (ok, reference_or_None, message)."""
    if not PAYSTACK_SECRET_KEY:
        return False, None, "PAYSTACK_SECRET_KEY not set."
    try:
        resp = requests.post(
            f"{PAYSTACK_BASE_URL}/transfer",
            headers=_paystack_headers(),
            json={
                "source": "balance",
                "amount": int(round(amount * 100)),
                "recipient": recipient_code,
                "reason": reason,
            },
            timeout=20,
        )
        data = resp.json()
        if not data.get("status"):
            return False, None, data.get("message", "Transfer failed.")
        return True, data["data"].get("reference"), data.get("message", "Transfer sent.")
    except requests.RequestException as exc:
        return False, None, f"Paystack request failed: {exc}"


# ---------- launch + referral config ----------
# Public rewards (real payouts) go live on this date. Tasks can be
# completed before it -- balances just accumulate -- but referral
# commissions and the "public launch" framing only kick in from this
# month onward.


def launch_month_key():
    return datetime.fromisoformat(LAUNCH_DATE_ISO).strftime("%Y-%m")


def is_post_launch(mkey):
    return mkey >= launch_month_key()


@app.context_processor
def inject_launch_date():
    return {"launch_date_iso": LAUNCH_DATE_ISO}


# ---------- language / i18n ----------
# Site-wide language switch. "en"/"fr" is stored in the session once the
# user picks one (via the animated chooser on the landing page), and the
# `t()` helper below is available in every template to translate a key.
# Add more keys/languages here as you translate more of the UI.
SUPPORTED_LANGUAGES = ["en", "fr"]

TRANSLATIONS = {
    "en": {
        "nav.dashboard": "Dashboard",
        "nav.referrals": "Referrals",
        "nav.payout_account": "Payout account",
        "nav.settings": "Settings",
        "nav.admin": "Admin",
        "nav.logout": "Logout",
        "nav.login": "Login",
        "nav.signup": "Sign up",
        "launch.banner": "Rewards go live on {date} — keep completing tasks now, payouts start then.",
        "launch.date_label": "30th November",
        "footer.tagline": "TaskPay — complete tasks, get paid once funds clear.",
        "language.choose_title": "Choose your language",
        "language.choose_sub": "Pick English or Français — this changes the whole app.",
        "language.continue": "Continue",
        "login.title": "Welcome back",
        "login.reward_note": "Rewards go live on 30th November — log in and keep earning until then.",
        "login.new_here": "New here?",
        "login.create_account": "Create an account",
        "login.google": "Continue with Google",
        "login.or": "or",
        "login.identifier_label": "Username or email",
        "login.password_label": "Password",
        "login.submit": "Log in",
        "login.registered_banner": "Account created! Check your email for a confirmation link before completing tasks.",
        "login.confirmed_banner": "Email confirmed — you're all set. Log in below.",
        "register.title": "Create your account",
        "register.reward_note": "Sign up now and start completing tasks — rewards begin paying out on 30th November.",
        "register.google": "Continue with Google",
        "register.or": "or",
        "register.username_label": "Username",
        "register.email_label": "Email",
        "register.password_label": "Password",
        "register.ref_label": "Referral code (optional)",
        "register.ref_placeholder": "Leave blank if none",
        "register.country_label": "Country",
        "register.bank_section_title": "Payout account (optional)",
        "register.bank_section_hint": "Add now, or skip and set it up later in Settings.",
        "register.bank_label": "Bank",
        "register.bank_placeholder": "Select your bank",
        "register.account_label": "Account number",
        "register.submit": "Sign up",
        "register.have_account": "Already have an account?",
        "register.login_link": "Log in",
        "login.forgot_password": "Forgot password?",
        "login.reset_banner": "Password updated. Log in with your new password.",
        "forgot.title": "Reset your password",
        "forgot.sub": "Enter the email on your account and we'll send you a link to set a new password.",
        "forgot.email_label": "Email",
        "forgot.submit": "Send reset link",
        "forgot.sent": "If that email has an account, a reset link is on its way. Check your inbox (and spam folder).",
        "forgot.back_to_login": "Back to log in",
        "reset.title": "Set a new password",
        "reset.password_label": "New password",
        "reset.confirm_label": "Confirm new password",
        "reset.submit": "Update password",
        "reset.invalid": "This reset link is invalid or has expired. Request a new one below.",
        "reset.request_new": "Request a new link",
        "settings.title": "Settings",
        "settings.password_title": "Change password",
        "settings.current_password_label": "Current password",
        "settings.new_password_label": "New password",
        "settings.password_submit": "Update password",
        "settings.account_title": "Payout account",
        "settings.account_sub": "The country, bank and account rewards get paid into.",
        "settings.country_label": "Country",
        "settings.bank_label": "Bank",
        "settings.account_label": "Account number",
        "settings.save": "Save payout account",
        "settings.current_account": "Currently on file",
        "settings.no_account": "No payout account on file yet.",
        "payout.title": "Payout account",
        "payout.sub": "This is the bank account rewards get paid into when payouts run on 30th November onward.",
        "payout.bank_label": "Bank",
        "payout.account_label": "Account number",
        "payout.save": "Save payout account",
    },
    "fr": {
        "nav.dashboard": "Tableau de bord",
        "nav.referrals": "Parrainages",
        "nav.payout_account": "Compte de paiement",
        "nav.settings": "Paramètres",
        "nav.admin": "Administration",
        "nav.logout": "Déconnexion",
        "nav.login": "Connexion",
        "nav.signup": "S'inscrire",
        "launch.banner": "Les récompenses seront disponibles le {date} — continuez à effectuer des tâches, les paiements commenceront ensuite.",
        "launch.date_label": "30 novembre",
        "footer.tagline": "TaskPay — accomplissez des tâches, soyez payé une fois les fonds validés.",
        "language.choose_title": "Choisissez votre langue",
        "language.choose_sub": "Choisissez Français ou English — cela change toute l'application.",
        "language.continue": "Continuer",
        "login.title": "Content de vous revoir",
        "login.reward_note": "Les récompenses seront disponibles le 30 novembre — connectez-vous et continuez à gagner d'ici là.",
        "login.new_here": "Nouveau ici ?",
        "login.create_account": "Créer un compte",
        "login.google": "Continuer avec Google",
        "login.or": "ou",
        "login.identifier_label": "Nom d'utilisateur ou e-mail",
        "login.password_label": "Mot de passe",
        "login.submit": "Se connecter",
        "login.registered_banner": "Compte créé ! Vérifiez votre e-mail pour le lien de confirmation avant de commencer les tâches.",
        "login.confirmed_banner": "E-mail confirmé — vous êtes prêt. Connectez-vous ci-dessous.",
        "register.title": "Créez votre compte",
        "register.reward_note": "Inscrivez-vous maintenant et commencez à effectuer des tâches — les récompenses seront versées à partir du 30 novembre.",
        "register.google": "Continuer avec Google",
        "register.or": "ou",
        "register.username_label": "Nom d'utilisateur",
        "register.email_label": "E-mail",
        "register.password_label": "Mot de passe",
        "register.ref_label": "Code de parrainage (facultatif)",
        "register.ref_placeholder": "Laissez vide si aucun",
        "register.country_label": "Pays",
        "register.bank_section_title": "Compte de paiement (facultatif)",
        "register.bank_section_hint": "Ajoutez-le maintenant, ou configurez-le plus tard dans Paramètres.",
        "register.bank_label": "Banque",
        "register.bank_placeholder": "Sélectionnez votre banque",
        "register.account_label": "Numéro de compte",
        "register.submit": "S'inscrire",
        "register.have_account": "Vous avez déjà un compte ?",
        "register.login_link": "Se connecter",
        "login.forgot_password": "Mot de passe oublié ?",
        "login.reset_banner": "Mot de passe mis à jour. Connectez-vous avec votre nouveau mot de passe.",
        "forgot.title": "Réinitialiser votre mot de passe",
        "forgot.sub": "Entrez l'e-mail de votre compte et nous vous enverrons un lien pour définir un nouveau mot de passe.",
        "forgot.email_label": "E-mail",
        "forgot.submit": "Envoyer le lien",
        "forgot.sent": "Si cet e-mail correspond à un compte, un lien de réinitialisation est en route. Vérifiez votre boîte de réception (et vos spams).",
        "forgot.back_to_login": "Retour à la connexion",
        "reset.title": "Définir un nouveau mot de passe",
        "reset.password_label": "Nouveau mot de passe",
        "reset.confirm_label": "Confirmer le nouveau mot de passe",
        "reset.submit": "Mettre à jour le mot de passe",
        "reset.invalid": "Ce lien de réinitialisation est invalide ou a expiré. Demandez-en un nouveau ci-dessous.",
        "reset.request_new": "Demander un nouveau lien",
        "settings.title": "Paramètres",
        "settings.password_title": "Changer le mot de passe",
        "settings.current_password_label": "Mot de passe actuel",
        "settings.new_password_label": "Nouveau mot de passe",
        "settings.password_submit": "Mettre à jour le mot de passe",
        "settings.account_title": "Compte de paiement",
        "settings.account_sub": "Le pays, la banque et le compte sur lesquels les récompenses sont versées.",
        "settings.country_label": "Pays",
        "settings.bank_label": "Banque",
        "settings.account_label": "Numéro de compte",
        "settings.save": "Enregistrer le compte de paiement",
        "settings.current_account": "Actuellement enregistré",
        "settings.no_account": "Aucun compte de paiement enregistré pour le moment.",
        "payout.title": "Compte de paiement",
        "payout.sub": "C'est le compte bancaire sur lequel les récompenses seront versées à partir du 30 novembre.",
        "payout.bank_label": "Banque",
        "payout.account_label": "Numéro de compte",
        "payout.save": "Enregistrer le compte de paiement",
    },
}


# Extra keys: server-side messages, emails, verification page, dashboard.
TRANSLATIONS["en"].update({'err.login_required': 'Login required',
 'err.admin_only': 'Admin only',
 'err.fields_required': 'All fields are required.',
 'err.email_invalid': 'Enter a valid email address.',
 'err.password_short': 'Password must be at least 6 characters.',
 'err.taken': 'Username or email already taken.',
 'err.send_failed': "We couldn't send the verification code. Check your email address and try again.",
 'err.wait': 'Please wait {s} seconds before requesting another code.',
 'err.signup_expired': 'Your sign-up session expired. Please fill in the form again.',
 'err.code_format': 'Enter the 6-digit code.',
 'err.code_expired': 'That code has expired. Request a new one.',
 'err.code_locked': 'Too many wrong attempts. Request a new code.',
 'err.code_invalid': 'That code is incorrect. {left} attempt(s) left.',
 'err.confirm_link_invalid': 'That confirmation link is invalid or already used.',
 'err.already_confirmed': 'Your email is already confirmed.',
 'ok.confirmation_sent': 'Confirmation email sent.',
 'err.email_send_failed_now': 'Could not send email right now.',
 'err.invalid_credentials': 'Invalid credentials.',
 'err.passwords_mismatch': "Passwords don't match.",
 'err.google_no_email': "Google didn't return an email address. Try again.",
 'err.confirm_first': 'Please confirm your email before completing tasks.',
 'err.task_not_found': 'Task not found or inactive.',
 'err.task_done': 'You already completed this task this month.',
 'err.wall_not_configured': 'Offerwall is not configured yet.',
 'err.bank_and_account': 'Account number and bank are both required.',
 'ok.currency_saved': 'Currency saved.',
 'err.select_bank': 'Select a bank and enter your account number.',
 'ok.payout_saved': 'Payout account saved: {name} ({bank}).',
 'err.current_password_wrong': 'Current password is incorrect.',
 'err.new_password_short': 'New password must be at least 6 characters.',
 'ok.password_updated': 'Password updated.',
 'ok.country_updated': 'Country updated.',
 'err.paystack_missing': "Payouts aren't configured yet. Please contact support.",
 'err.account_verify': 'Could not verify that account.',
 'err.paystack_failed': 'Could not reach the payment provider. Please try again.',
 'err.paystack_register': 'Could not register this account with Paystack.',
 'err.pick_method': 'Pick one of the listed payout methods.',
 'err.number_invalid': 'Enter a valid phone / account number (8 to 15 digits).',
 'src.tasks': 'Tasks',
 'src.surveys': 'Surveys',
 'src.offers': 'Offers',
 'wall.surveys_title': 'Surveys',
 'wall.surveys_h2': 'Surveys & offers',
 'wall.offers_title': 'Offers',
 'verify.title': 'Verify your email',
 'verify.sub': 'We sent a 6-digit code to {email}. Enter it below to finish creating your account.',
 'verify.code_label': 'Verification code',
 'verify.submit': 'Verify and create account',
 'verify.resend': 'Resend code',
 'verify.resend_wait': 'You can request a new code in {s}s.',
 'verify.hint': "Can't find it? Check your spam folder. The code expires in {minutes} minutes.",
 'verify.sent': 'A new code has been sent.',
 'verify.wrong_email': 'Wrong email address?',
 'verify.start_again': 'Start again',
 'email.code.subject': 'Your TaskPay verification code: {code}',
 'email.code.body': '<p>Hi {name},</p><p>Your TaskPay verification code is:</p><p '
                    'style="font-size:28px;letter-spacing:6px;font-weight:bold">{code}</p><p>It expires in '
                    "{minutes} minutes. If you didn't try to sign up, you can ignore this email.</p>",
 'email.confirm.subject': 'Confirm your TaskPay account',
 'email.confirm.body': '<p>Hi {name},</p><p>Welcome to TaskPay! Confirm your email to start completing '
                       'tasks:</p><p><a href="{url}">{url}</a></p><p>If you didn\'t sign up, you can ignore '
                       'this email.</p>',
 'email.reset.subject': 'Reset your TaskPay password',
 'email.reset.body': '<p>Hi {name},</p><p>Click the link below to set a new password. This link expires in 1 '
                     'hour:</p><p><a href="{url}">{url}</a></p><p>If you didn\'t request this, you can '
                     "safely ignore this email -- your password won't change.</p>",
 'dash.confirm_banner': 'Please confirm your email to start completing tasks.',
 'dash.resend': 'Resend email',
 'tab.overview': 'Overview',
 'tab.tasks': 'Tasks',
 'tab.history': 'Payout history',
 'dash.this_month': "This month's earnings",
 'dash.tasks_completed': '{n} task(s) completed',
 'dash.rate_loading': 'Live rate loading…',
 'dash.cycle_closes': 'Earning cycle closes in',
 'dash.cycle_paid': 'This cycle has been paid out.',
 'dash.cycle_cleared': 'Funds cleared, payout pending.',
 'dash.cycle_pending': 'Awaiting funds to clear.',
 'dash.launch_in': 'Public rewards launch in',
 'dash.launch_hint': "Keep completing tasks — everything you've built up counts toward your balance once "
                     'rewards go public.',
 'dash.tip_a': '💡 The more tasks you complete this month, the bigger your share at payout time. ',
 'dash.tip_link': 'Refer a friend',
 'dash.tip_b': ' and earn a cut of their earnings too.',
 'dash.available_tasks': 'Available tasks',
 'dash.completed': 'Completed',
 'dash.mark_complete': 'Mark complete',
 'dash.no_tasks': 'No tasks available right now — check back soon.',
 'dash.history_title': 'Payout history',
 'dash.col_month': 'Month',
 'dash.col_source': 'Source',
 'dash.col_amount': 'Amount',
 'dash.col_paid_at': 'Paid at',
 'dash.no_payouts': 'No payouts yet — your first one follows once this cycle closes and payments clear.',
 'js.network': 'Network error. Please try again.',
 'js.sent': 'Sent.',
 'js.could_not_send': 'Could not send.',
 'js.could_not_complete': 'Could not complete task.',
 'js.could_not_update': 'Could not update task.',
 'js.completed': 'Completed',
 'js.payout_day': 'Payout day is here!',
 'js.its_here': "It's here!"})
TRANSLATIONS["fr"].update({'err.login_required': 'Connexion requise',
 'err.admin_only': 'Réservé aux administrateurs',
 'err.fields_required': 'Tous les champs sont obligatoires.',
 'err.email_invalid': 'Saisissez une adresse e-mail valide.',
 'err.password_short': 'Le mot de passe doit contenir au moins 6 caractères.',
 'err.taken': "Nom d'utilisateur ou e-mail déjà utilisé.",
 'err.send_failed': "Nous n'avons pas pu envoyer le code de vérification. Vérifiez votre adresse e-mail et "
                    'réessayez.',
 'err.wait': 'Veuillez patienter {s} secondes avant de demander un autre code.',
 'err.signup_expired': "Votre session d'inscription a expiré. Veuillez remplir à nouveau le formulaire.",
 'err.code_format': 'Saisissez le code à 6 chiffres.',
 'err.code_expired': 'Ce code a expiré. Demandez-en un nouveau.',
 'err.code_locked': 'Trop de tentatives incorrectes. Demandez un nouveau code.',
 'err.code_invalid': 'Ce code est incorrect. Il vous reste {left} tentative(s).',
 'err.confirm_link_invalid': 'Ce lien de confirmation est invalide ou a déjà été utilisé.',
 'err.already_confirmed': 'Votre e-mail est déjà confirmé.',
 'ok.confirmation_sent': 'E-mail de confirmation envoyé.',
 'err.email_send_failed_now': "Impossible d'envoyer l'e-mail pour le moment.",
 'err.invalid_credentials': 'Identifiants invalides.',
 'err.passwords_mismatch': 'Les mots de passe ne correspondent pas.',
 'err.google_no_email': "Google n'a pas renvoyé d'adresse e-mail. Réessayez.",
 'err.confirm_first': "Veuillez confirmer votre e-mail avant d'effectuer des tâches.",
 'err.task_not_found': 'Tâche introuvable ou inactive.',
 'err.task_done': 'Vous avez déjà effectué cette tâche ce mois-ci.',
 'err.wall_not_configured': "Le mur d'offres n'est pas encore configuré.",
 'err.bank_and_account': 'Le numéro de compte et la banque sont tous deux requis.',
 'ok.currency_saved': 'Devise enregistrée.',
 'err.select_bank': 'Sélectionnez une banque et saisissez votre numéro de compte.',
 'ok.payout_saved': 'Compte de paiement enregistré : {name} ({bank}).',
 'err.current_password_wrong': 'Le mot de passe actuel est incorrect.',
 'err.new_password_short': 'Le nouveau mot de passe doit contenir au moins 6 caractères.',
 'ok.password_updated': 'Mot de passe mis à jour.',
 'ok.country_updated': 'Pays mis à jour.',
 'err.paystack_missing': 'Les paiements ne sont pas encore configurés. Veuillez contacter le support.',
 'err.account_verify': 'Impossible de vérifier ce compte.',
 'err.paystack_failed': 'Impossible de joindre le prestataire de paiement. Veuillez réessayer.',
 'err.paystack_register': "Impossible d'enregistrer ce compte auprès de Paystack.",
 'err.pick_method': "Choisissez l'un des modes de paiement proposés.",
 'err.number_invalid': 'Saisissez un numéro de téléphone / de compte valide (8 à 15 chiffres).',
 'src.tasks': 'Tâches',
 'src.surveys': 'Sondages',
 'src.offers': 'Offres',
 'wall.surveys_title': 'Sondages',
 'wall.surveys_h2': 'Sondages et offres',
 'wall.offers_title': 'Offres',
 'verify.title': 'Vérifiez votre e-mail',
 'verify.sub': 'Nous avons envoyé un code à 6 chiffres à {email}. Saisissez-le ci-dessous pour terminer la '
               'création de votre compte.',
 'verify.code_label': 'Code de vérification',
 'verify.submit': 'Vérifier et créer le compte',
 'verify.resend': 'Renvoyer le code',
 'verify.resend_wait': 'Vous pourrez demander un nouveau code dans {s} s.',
 'verify.hint': 'Vous ne le trouvez pas ? Vérifiez vos spams. Le code expire dans {minutes} minutes.',
 'verify.sent': 'Un nouveau code a été envoyé.',
 'verify.wrong_email': 'Mauvaise adresse e-mail ?',
 'verify.start_again': 'Recommencer',
 'email.code.subject': 'Votre code de vérification TaskPay : {code}',
 'email.code.body': '<p>Bonjour {name},</p><p>Votre code de vérification TaskPay est :</p><p '
                    'style="font-size:28px;letter-spacing:6px;font-weight:bold">{code}</p><p>Il expire dans '
                    "{minutes} minutes. Si vous n'avez pas essayé de vous inscrire, vous pouvez ignorer cet "
                    'e-mail.</p>',
 'email.confirm.subject': 'Confirmez votre compte TaskPay',
 'email.confirm.body': '<p>Bonjour {name},</p><p>Bienvenue sur TaskPay ! Confirmez votre e-mail pour '
                       'commencer à effectuer des tâches :</p><p><a href="{url}">{url}</a></p><p>Si vous ne '
                       'vous êtes pas inscrit, vous pouvez ignorer cet e-mail.</p>',
 'email.reset.subject': 'Réinitialisez votre mot de passe TaskPay',
 'email.reset.body': '<p>Bonjour {name},</p><p>Cliquez sur le lien ci-dessous pour définir un nouveau mot de '
                     'passe. Ce lien expire dans 1 heure :</p><p><a href="{url}">{url}</a></p><p>Si vous '
                     "n'êtes pas à l'origine de cette demande, vous pouvez ignorer cet e-mail -- votre mot "
                     'de passe ne changera pas.</p>',
 'dash.confirm_banner': 'Veuillez confirmer votre e-mail pour commencer à effectuer des tâches.',
 'dash.resend': "Renvoyer l'e-mail",
 'tab.overview': 'Aperçu',
 'tab.tasks': 'Tâches',
 'tab.history': 'Historique des paiements',
 'dash.this_month': 'Gains de ce mois',
 'dash.tasks_completed': '{n} tâche(s) effectuée(s)',
 'dash.rate_loading': 'Chargement du taux en direct…',
 'dash.cycle_closes': 'Le cycle de gains se termine dans',
 'dash.cycle_paid': 'Ce cycle a été payé.',
 'dash.cycle_cleared': 'Fonds validés, paiement en attente.',
 'dash.cycle_pending': 'En attente de la validation des fonds.',
 'dash.launch_in': 'Lancement public des récompenses dans',
 'dash.launch_hint': 'Continuez à effectuer des tâches — tout ce que vous avez accumulé comptera dans votre '
                     'solde dès le lancement public des récompenses.',
 'dash.tip_a': '💡 Plus vous effectuez de tâches ce mois-ci, plus votre part sera importante au moment du '
               'paiement. ',
 'dash.tip_link': 'Parrainez un ami',
 'dash.tip_b': ' et touchez aussi une partie de ses gains.',
 'dash.available_tasks': 'Tâches disponibles',
 'dash.completed': 'Terminée',
 'dash.mark_complete': 'Marquer comme terminée',
 'dash.no_tasks': 'Aucune tâche disponible pour le moment — revenez bientôt.',
 'dash.history_title': 'Historique des paiements',
 'dash.col_month': 'Mois',
 'dash.col_source': 'Source',
 'dash.col_amount': 'Montant',
 'dash.col_paid_at': 'Payé le',
 'dash.no_payouts': 'Aucun paiement pour le moment — le premier arrivera une fois ce cycle clôturé et les '
                    'paiements validés.',
 'js.network': 'Erreur réseau. Veuillez réessayer.',
 'js.sent': 'Envoyé.',
 'js.could_not_send': 'Envoi impossible.',
 'js.could_not_complete': 'Impossible de terminer la tâche.',
 'js.could_not_update': 'Impossible de mettre à jour la tâche.',
 'js.completed': 'Terminée',
 'js.payout_day': 'Le jour du paiement est arrivé !',
 'js.its_here': "C'est arrivé !"})


def get_lang():
    lang = session.get("lang")
    return lang if lang in SUPPORTED_LANGUAGES else "en"


def tr(key, **kwargs):
    """Translate a key in Python code (flash messages, JSON errors, emails)
    using the language stored in the session -- same lookup as t() in templates."""
    table = TRANSLATIONS.get(get_lang(), TRANSLATIONS["en"])
    text = table.get(key, TRANSLATIONS["en"].get(key, key))
    return text.format(**kwargs) if kwargs else text


@app.context_processor
def inject_translator():
    lang = get_lang()

    def t(key, **kwargs):
        text = TRANSLATIONS.get(lang, TRANSLATIONS["en"]).get(key, TRANSLATIONS["en"].get(key, key))
        return text.format(**kwargs) if kwargs else text

    return {"t": t, "current_lang": lang, "supported_languages": SUPPORTED_LANGUAGES}


@app.before_request
def _make_session_permanent():
    # Applies to every request, so the language choice, "lang_chosen" flag,
    # and login (user_id) all get a real, long-lived cookie instead of one
    # that disappears the moment the browser/app is closed.
    session.permanent = True


@app.route("/set-language/<lang>", methods=["POST"])
def set_language(lang):
    if lang in SUPPORTED_LANGUAGES:
        session["lang"] = lang
        session["lang_chosen"] = True
    return redirect(request.referrer or url_for("index"))


# ---------- DB helpers ----------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------- database schema ----------
# Inlined here (instead of a separate schema.sql file) so app.py is fully
# self-contained -- nothing to find on disk, nothing that can go missing
# depending on the working directory the app happens to be launched from.
# Every statement uses CREATE TABLE IF NOT EXISTS, so running this again
# against a database that already has some/all tables is always safe.
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    auth_provider TEXT NOT NULL DEFAULT 'password',
    email_confirmed INTEGER NOT NULL DEFAULT 0,
    confirmation_token TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0,
    referral_code TEXT UNIQUE,
    referred_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL,
    bank_code TEXT,
    bank_name TEXT,
    account_number TEXT,
    account_name TEXT,
    paystack_recipient_code TEXT,
    country TEXT NOT NULL DEFAULT 'nigeria',
    reset_token TEXT,
    reset_token_expires TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    reward REAL NOT NULL,
    repeatable INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS task_completions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    month_key TEXT NOT NULL,
    reward_earned REAL NOT NULL,
    completed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_settlements (
    source TEXT NOT NULL,
    month_key TEXT NOT NULL,
    settled INTEGER NOT NULL DEFAULT 0,
    settled_at TEXT,
    processed INTEGER NOT NULL DEFAULT 0,
    processed_at TEXT,
    PRIMARY KEY (source, month_key)
);

CREATE TABLE IF NOT EXISTS provider_conversions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    external_id TEXT,
    amount REAL NOT NULL,
    month_key TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS referral_commissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    referrer_id INTEGER NOT NULL REFERENCES users(id),
    referred_user_id INTEGER NOT NULL REFERENCES users(id),
    source TEXT NOT NULL,
    month_key TEXT NOT NULL,
    base_amount REAL NOT NULL,
    commission_amount REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    month_key TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'internal',
    amount REAL NOT NULL,
    paid_at TEXT NOT NULL,
    transfer_reference TEXT,
    transfer_status TEXT NOT NULL DEFAULT 'pending'
);
"""


def init_db():
    db = sqlite3.connect(DB_PATH, timeout=30)
    db.executescript(SCHEMA_SQL)
    # seed a default admin so there's always a way in
    existing = db.execute("SELECT id FROM users WHERE is_admin = 1").fetchone()
    if not existing:
        db.execute(
            "INSERT INTO users (username, email, password_hash, is_admin, email_confirmed, referral_code, created_at) "
            "VALUES (?, ?, ?, 1, 1, ?, ?)",
            ("admin", "admin@taskpay.local", generate_password_hash("admin123"),
             secrets.token_hex(4), datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        )
    db.commit()
    db.close()


def ensure_db():
    """Self-healing DB check, run on every app startup (not just when the
    .db file is totally absent). This is what actually fixes 'no such
    table: users': sqlite3.connect() creates an empty .db file the instant
    it's opened, *before* the schema is written -- so if the very first
    run ever got interrupted, crashed, or was started in a way that skipped
    init_db() (e.g. launched via `flask run`/a WSGI server instead of
    `python app.py`, which is common on Pydroid/Termux setups), the empty
    file was left behind and every run after that saw "the .db file
    exists" and silently skipped creating any tables. Checking for the
    actual `users` table -- and creating it if missing -- fixes that for
    good, no matter how the app is launched."""
    db = sqlite3.connect(DB_PATH, timeout=30)
    try:
        db.execute("SELECT 1 FROM users LIMIT 1")
    except sqlite3.OperationalError:
        db.close()
        init_db()
    else:
        db.close()


def _ensure_column(db, table, column, ddl):
    cols = [row["name"] for row in db.execute(f"PRAGMA table_info({table})")]
    if column not in cols:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def migrate_db():
    """Adds columns introduced after the original schema (country, password
    reset token/expiry) to a database that already exists, so upgrading
    never loses data. Each ALTER only fires if the column isn't there yet,
    so this is safe to run on every startup."""
    db = sqlite3.connect(DB_PATH, timeout=30)
    db.row_factory = sqlite3.Row
    _ensure_column(db, "users", "country", "country TEXT NOT NULL DEFAULT 'nigeria'")
    _ensure_column(db, "users", "reset_token", "reset_token TEXT")
    _ensure_column(db, "users", "reset_token_expires", "reset_token_expires TEXT")
    _ensure_column(db, "users", "currency", "currency TEXT")
    # Sign-ups waiting for their emailed code. The account is only created
    # in `users` once the code is entered correctly.
    db.execute(
        "CREATE TABLE IF NOT EXISTS pending_signups ("
        "email TEXT PRIMARY KEY, username TEXT NOT NULL, password_hash TEXT NOT NULL, "
        "ref_code TEXT, country TEXT, currency TEXT, bank_code TEXT, bank_name TEXT, "
        "account_number TEXT, code_hash TEXT NOT NULL, expires_at TEXT NOT NULL, "
        "attempts INTEGER NOT NULL DEFAULT 0, last_sent_at TEXT NOT NULL)"
    )
    _ensure_column(db, "payouts", "currency", "currency TEXT")
    _ensure_column(db, "payouts", "amount_local", "amount_local REAL")
    # Older accounts: give them the currency of their country.
    db.execute("UPDATE users SET currency = CASE WHEN country = 'togo' THEN 'XOF' ELSE 'NGN' END "
               "WHERE currency IS NULL OR currency = ''")
    db.commit()
    db.close()


ensure_db()
migrate_db()


def now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def month_key(dt=None):
    dt = dt or datetime.utcnow()
    return dt.strftime("%Y-%m")


def _smtp_send(to_email, name, subject, html):
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{BREVO_SENDER_NAME} <{MAIL_FROM}>"
    msg["To"] = f"{name} <{to_email}>" if name else to_email
    msg.set_content(re.sub(r"<[^>]+>", " ", html))
    msg.add_alternative(html, subtype="html")
    try:
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
            server.starttls()
        with server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as exc:
        print(f"[error] SMTP send to {to_email} failed: {exc!r}")
        return False


def _brevo_send(to_email, name, subject, html, dev_note):
    """Sends one transactional email: Brevo if BREVO_API_KEY is set,
    otherwise Gmail/SMTP if SMTP_USER + SMTP_PASSWORD are set."""
    if not BREVO_API_KEY:
        if SMTP_USER and SMTP_PASSWORD:
            return _smtp_send(to_email, name, subject, html)
        print(f"[error] No email provider configured (set SMTP_USER + SMTP_PASSWORD, or BREVO_API_KEY) -- "
              f"could not send {dev_note} to {to_email}")
        return False
    try:
        resp = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": BREVO_API_KEY,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json={
                "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
                "to": [{"email": to_email, "name": name}],
                "subject": subject,
                "htmlContent": html,
            },
            timeout=10,
        )
        if resp.status_code not in (200, 201):
            print(f"[error] Brevo rejected email to {to_email}: {resp.status_code} {resp.text[:300]}")
        return resp.status_code in (200, 201)
    except requests.RequestException as exc:
        print(f"[error] Brevo send failed for {to_email}: {exc}")
        return False


def send_verification_code(to_email, username, code, lang=None):
    """Emails the 6-digit sign-up code, in the user's chosen language."""
    if not EMAIL_ENABLED:
        print(f"[dev] verification code for {to_email}: {code}")
    old = session.get("lang")
    if lang in SUPPORTED_LANGUAGES:
        session["lang"] = lang
    try:
        subject = tr("email.code.subject", code=code)
        html = tr("email.code.body", name=escape(username), code=code, minutes=CODE_LIFETIME_MINUTES)
    finally:
        if old is not None:
            session["lang"] = old
    return _brevo_send(to_email, username, subject, html, "verification code")


def send_confirmation_email(to_email, username, token):
    """Confirmation link for older accounts (and the dashboard 'resend' button)."""
    confirm_url = f"{APP_BASE_URL}{url_for('confirm_email', token=token)}"
    if not EMAIL_ENABLED:
        print(f"[dev] confirmation link for {to_email}: {confirm_url}")
    return _brevo_send(
        to_email, username, tr("email.confirm.subject"),
        tr("email.confirm.body", name=escape(username), url=confirm_url), "confirmation link",
    )


RESET_TOKEN_LIFETIME = timedelta(hours=1)


def send_reset_email(to_email, username, token):
    reset_url = f"{APP_BASE_URL}{url_for('reset_password', token=token)}"
    if not EMAIL_ENABLED:
        print(f"[dev] password reset link for {to_email}: {reset_url}")
    return _brevo_send(
        to_email, username, tr("email.reset.subject"),
        tr("email.reset.body", name=escape(username), url=reset_url), "password reset link",
    )


def json_ok(data=None, **kwargs):
    payload = {"ok": True}
    if data:
        payload.update(data)
    payload.update(kwargs)
    return jsonify(payload)


def json_err(message, status=400):
    return jsonify({"ok": False, "error": message}), status


# ---------- auth helpers ----------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return json_err(tr("err.login_required"), 401)
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            if request.path.startswith("/api/"):
                return json_err(tr("err.admin_only"), 403)
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    if not session.get("user_id"):
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


# ---------- earnings helpers ----------

def user_month_earnings(db, user_id, mkey):
    row = db.execute(
        "SELECT COALESCE(SUM(reward_earned), 0) AS total, COUNT(*) AS task_count "
        "FROM task_completions WHERE user_id = ? AND month_key = ?",
        (user_id, mkey),
    ).fetchone()
    cpx = db.execute(
        "SELECT COALESCE(SUM(amount), 0) AS total FROM provider_conversions "
        "WHERE user_id = ? AND month_key = ?",
        (user_id, mkey),
    ).fetchone()
    return row["total"] + cpx["total"], row["task_count"]


def get_or_create_settlement(db, source, mkey):
    row = db.execute(
        "SELECT * FROM provider_settlements WHERE source = ? AND month_key = ?", (source, mkey)
    ).fetchone()
    if row is None:
        db.execute(
            "INSERT INTO provider_settlements (source, month_key, settled, processed) VALUES (?, ?, 0, 0)",
            (source, mkey),
        )
        db.commit()
        row = db.execute(
            "SELECT * FROM provider_settlements WHERE source = ? AND month_key = ?", (source, mkey)
        ).fetchone()
    return row


def source_month_total(db, source, mkey):
    """Total owed to users from one source for a month."""
    if source != "internal":
        row = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total FROM provider_conversions "
            "WHERE provider = ? AND month_key = ?",
            (source, mkey),
        ).fetchone()
        return row["total"]
    row = db.execute(
        "SELECT COALESCE(SUM(reward_earned), 0) AS total FROM task_completions WHERE month_key = ?",
        (mkey,),
    ).fetchone()
    return row["total"]


# ---------- public / auth routes ----------

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


CODE_LIFETIME_MINUTES = 10
CODE_RESEND_SECONDS = 60
CODE_MAX_ATTEMPTS = 5
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _code_hash(email, code):
    return hmac.new(str(SECRET_KEY).encode(), f"{email}:{code}".encode(), hashlib.sha256).hexdigest()


def _parse_ts(value):
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def _register_ctx(**overrides):
    ctx = dict(ref_code="", countries=COUNTRIES, default_country=DEFAULT_COUNTRY,
               currencies=CURRENCIES, default_currency=COUNTRIES[DEFAULT_COUNTRY]["currency"])
    ctx.update(overrides)
    return ctx


def _resend_wait(row):
    """Seconds left before another code may be requested for this sign-up."""
    if not row:
        return 0
    elapsed = (datetime.utcnow() - _parse_ts(row["last_sent_at"])).total_seconds()
    return max(0, int(CODE_RESEND_SECONDS - elapsed))


def _issue_code(db, email, username):
    """Creates a fresh code for a pending sign-up, stores its hash, emails it.
    Returns True if the email went out (or we're in local dev without Brevo)."""
    code = f"{secrets.randbelow(1000000):06d}"
    expires = (datetime.utcnow() + timedelta(minutes=CODE_LIFETIME_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "UPDATE pending_signups SET code_hash = ?, expires_at = ?, attempts = 0, last_sent_at = ? WHERE email = ?",
        (_code_hash(email, code), expires, now_str(), email),
    )
    db.commit()
    sent = send_verification_code(email, username, code, get_lang())
    # Local development without a Brevo key: the code is printed in the
    # server console, so let the flow continue. Never true in production.
    return sent or (not EMAIL_ENABLED and APP_BASE_URL.startswith("http://localhost"))


@app.route("/register", methods=["GET", "POST"])
def register():
    ref_code = request.args.get("ref", "").strip()
    if request.method == "GET":
        return render_template("register.html", **_register_ctx(ref_code=ref_code))

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    ref_code = request.form.get("ref_code", "").strip()
    country = request.form.get("country", DEFAULT_COUNTRY).strip().lower()
    if country not in COUNTRIES:
        country = DEFAULT_COUNTRY
    currency = request.form.get("currency", "").strip().upper()
    if currency not in CURRENCIES:
        currency = COUNTRIES[country]["currency"]
    bank_code = request.form.get("bank_code", "").strip()
    bank_name = request.form.get("bank_name", "").strip()
    account_number = request.form.get("account_number", "").strip()

    form_ctx = _register_ctx(ref_code=ref_code, default_country=country, default_currency=currency)

    if not username or not email or not password:
        return render_template("register.html", error=tr("err.fields_required"), **form_ctx)
    if not EMAIL_RE.match(email):
        return render_template("register.html", error=tr("err.email_invalid"), **form_ctx)
    if len(password) < 6:
        return render_template("register.html", error=tr("err.password_short"), **form_ctx)

    db = get_db()
    # Housekeeping: forget sign-ups abandoned more than a day ago.
    db.execute("DELETE FROM pending_signups WHERE expires_at < ?",
               ((datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),))

    # Case-insensitive check -- otherwise "Sam" and "sam" could both register.
    existing = db.execute(
        "SELECT id FROM users WHERE LOWER(username) = ? OR email = ?", (username.lower(), email)
    ).fetchone()
    if existing:
        return render_template("register.html", error=tr("err.taken"), **form_ctx)

    previous = db.execute("SELECT * FROM pending_signups WHERE email = ?", (email,)).fetchone()
    wait = _resend_wait(previous)
    if wait:
        return render_template("register.html", error=tr("err.wait", s=wait), **form_ctx)

    # NOTHING is created in `users` yet. We park the details, email a
    # 6-digit code, and only create the account once it's entered.
    db.execute(
        "INSERT OR REPLACE INTO pending_signups (email, username, password_hash, ref_code, country, currency, "
        "bank_code, bank_name, account_number, code_hash, expires_at, attempts, last_sent_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, 0, ?)",
        (email, username, generate_password_hash(password), ref_code, country, currency,
         bank_code, bank_name, account_number, now_str(), "2000-01-01 00:00:00"),
    )
    db.commit()

    if not _issue_code(db, email, username):
        db.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
        db.commit()
        return render_template("register.html", error=tr("err.send_failed"), **form_ctx)

    session["pending_email"] = email
    return redirect(url_for("verify_email"))


def _render_verify(row, **extra):
    return render_template(
        "verify_email.html", email=row["email"], resend_in=_resend_wait(row),
        minutes=CODE_LIFETIME_MINUTES, **extra,
    )


@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    email = session.get("pending_email")
    db = get_db()
    row = db.execute("SELECT * FROM pending_signups WHERE email = ?", (email,)).fetchone() if email else None
    if row is None:
        return redirect(url_for("register"))

    if request.method == "GET":
        return _render_verify(row)

    code = "".join(ch for ch in request.form.get("code", "") if ch.isdigit())
    if len(code) != 6:
        return _render_verify(row, error=tr("err.code_format"))
    if row["attempts"] >= CODE_MAX_ATTEMPTS:
        return _render_verify(row, error=tr("err.code_locked"))
    if datetime.utcnow() > _parse_ts(row["expires_at"]):
        return _render_verify(row, error=tr("err.code_expired"))

    if not hmac.compare_digest(row["code_hash"], _code_hash(email, code)):
        db.execute("UPDATE pending_signups SET attempts = attempts + 1 WHERE email = ?", (email,))
        db.commit()
        left = max(0, CODE_MAX_ATTEMPTS - row["attempts"] - 1)
        return _render_verify(row, error=tr("err.code_invalid", left=left) if left else tr("err.code_locked"))

    # Code is right -> now (and only now) the account is created.
    taken = db.execute(
        "SELECT id FROM users WHERE LOWER(username) = ? OR email = ?", (row["username"].lower(), email)
    ).fetchone()
    if taken:
        db.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
        db.commit()
        session.pop("pending_email", None)
        return render_template("register.html", error=tr("err.taken"), **_register_ctx())

    referrer = None
    if row["ref_code"]:
        referrer = db.execute("SELECT id FROM users WHERE referral_code = ?", (row["ref_code"],)).fetchone()

    db.execute(
        "INSERT INTO users (username, email, password_hash, auth_provider, email_confirmed, "
        "confirmation_token, is_admin, referral_code, referred_by, country, currency, created_at) "
        "VALUES (?, ?, ?, 'password', 1, NULL, 0, ?, ?, ?, ?, ?)",
        (row["username"], email, row["password_hash"], secrets.token_hex(4),
         referrer["id"] if referrer else None, row["country"], row["currency"], now_str()),
    )
    db.commit()
    new_user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    # Bank details are optional -- never let them block account creation.
    if row["bank_code"] and row["account_number"]:
        save_payout_details(db, new_user, row["country"], row["bank_code"], row["bank_name"], row["account_number"])

    db.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
    db.commit()
    session.pop("pending_email", None)
    session["user_id"] = new_user["id"]
    session["is_admin"] = False
    return redirect(url_for("dashboard"))


@app.route("/verify-email/resend", methods=["POST"])
def verify_email_resend():
    email = session.get("pending_email")
    db = get_db()
    row = db.execute("SELECT * FROM pending_signups WHERE email = ?", (email,)).fetchone() if email else None
    if row is None:
        return redirect(url_for("register"))
    wait = _resend_wait(row)
    if wait:
        return _render_verify(row, error=tr("err.wait", s=wait))
    if not _issue_code(db, email, row["username"]):
        return _render_verify(row, error=tr("err.send_failed"))
    row = db.execute("SELECT * FROM pending_signups WHERE email = ?", (email,)).fetchone()
    return _render_verify(row, notice=tr("verify.sent"))


@app.route("/confirm/<token>")
def confirm_email(token):
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE confirmation_token = ?", (token,)).fetchone()
    if user is None:
        return render_template("login.html", error=tr("err.confirm_link_invalid"))
    db.execute(
        "UPDATE users SET email_confirmed = 1, confirmation_token = NULL WHERE id = ?",
        (user["id"],),
    )
    db.commit()
    return redirect(url_for("login", confirmed=1))


@app.route("/resend-confirmation", methods=["POST"])
@login_required
def resend_confirmation():
    user = current_user()
    if user["email_confirmed"]:
        return json_err(tr("err.already_confirmed"))
    db = get_db()
    token = secrets.token_urlsafe(24)
    db.execute("UPDATE users SET confirmation_token = ? WHERE id = ?", (token, user["id"]))
    db.commit()
    sent = send_confirmation_email(user["email"], user["username"], token)
    return json_ok(message=tr("ok.confirmation_sent") if sent else tr("err.email_send_failed_now"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template(
            "login.html",
            registered=request.args.get("registered"),
            confirmed=request.args.get("confirmed"),
            reset=request.args.get("reset"),
        )

    identifier = request.form.get("identifier", "").strip().lower()
    password = request.form.get("password", "")

    db = get_db()
    # Compare usernames case-insensitively -- usernames are stored with
    # whatever case the user signed up with, but "identifier" above is
    # lowercased, so a plain "=" match silently failed for any username
    # containing an uppercase letter and looked like a wrong password.
    user = db.execute(
        "SELECT * FROM users WHERE LOWER(username) = ? OR email = ?", (identifier, identifier)
    ).fetchone()

    if user is None or not user["password_hash"] or not check_password_hash(user["password_hash"], password):
        return render_template("login.html", error=tr("err.invalid_credentials"))

    session["user_id"] = user["id"]
    session["is_admin"] = bool(user["is_admin"])
    return redirect(url_for("admin_dashboard") if user["is_admin"] else url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    email = request.form.get("email", "").strip().lower()
    db = get_db()
    # Only password accounts get a reset link -- a Google-only account has
    # no password_hash to replace.
    user = db.execute(
        "SELECT * FROM users WHERE email = ? AND auth_provider = 'password'", (email,)
    ).fetchone()

    if user:
        token = secrets.token_urlsafe(32)
        expires = (datetime.utcnow() + RESET_TOKEN_LIFETIME).strftime("%Y-%m-%d %H:%M:%S")
        db.execute(
            "UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?",
            (token, expires, user["id"]),
        )
        db.commit()
        send_reset_email(user["email"], user["username"], token)

    # Same response whether or not that email has an account -- never
    # reveal to a visitor which emails are registered.
    return render_template("forgot_password.html", sent=True)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE reset_token = ?", (token,)).fetchone()

    def token_is_valid():
        if user is None or not user["reset_token_expires"]:
            return False
        expires = datetime.strptime(user["reset_token_expires"], "%Y-%m-%d %H:%M:%S")
        return datetime.utcnow() < expires

    if not token_is_valid():
        return render_template("reset_password.html", invalid=True)

    if request.method == "GET":
        return render_template("reset_password.html", token=token)

    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if len(password) < 6:
        return render_template("reset_password.html", token=token, error=tr("err.password_short"))
    if password != confirm_password:
        return render_template("reset_password.html", token=token, error=tr("err.passwords_mismatch"))

    db.execute(
        "UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?",
        (generate_password_hash(password), user["id"]),
    )
    db.commit()
    return redirect(url_for("login", reset=1))


def unique_username_from(base):
    base = "".join(c for c in base.lower() if c.isalnum()) or "user"
    db = get_db()
    candidate = base
    suffix = 0
    while db.execute("SELECT id FROM users WHERE username = ?", (candidate,)).fetchone():
        suffix += 1
        candidate = f"{base}{suffix}"
    return candidate


@app.route("/auth/google")
def google_login():
    ref_code = request.args.get("ref", "").strip()
    if ref_code:
        session["pending_ref"] = ref_code
    redirect_uri = url_for("google_callback", _external=True)
    return google_oauth.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    token = google_oauth.authorize_access_token()
    userinfo = token.get("userinfo") or {}
    email = (userinfo.get("email") or "").strip().lower()
    name = userinfo.get("name") or (email.split("@")[0] if email else "user")

    if not email:
        return render_template("login.html", error=tr("err.google_no_email"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if user is None:
        ref_code = session.pop("pending_ref", "")
        referrer = None
        if ref_code:
            referrer = db.execute("SELECT id FROM users WHERE referral_code = ?", (ref_code,)).fetchone()

        username = unique_username_from(name)
        referral_code = secrets.token_hex(4)
        db.execute(
            "INSERT INTO users (username, email, password_hash, auth_provider, email_confirmed, "
            "is_admin, referral_code, referred_by, created_at) "
            "VALUES (?, ?, NULL, 'google', 1, 0, ?, ?, ?)",
            (username, email, referral_code, referrer["id"] if referrer else None, now_str()),
        )
        db.commit()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    session["user_id"] = user["id"]
    session["is_admin"] = bool(user["is_admin"])
    return redirect(url_for("admin_dashboard") if user["is_admin"] else url_for("dashboard"))


# ---------- user dashboard ----------

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = current_user()
    mkey = month_key()

    total_earned, task_count = user_month_earnings(db, user["id"], mkey)

    settlement = get_or_create_settlement(db, "internal", mkey)
    cycle_status = "paid" if settlement["processed"] else ("cleared" if settlement["settled"] else "pending")

    tasks = db.execute("SELECT * FROM tasks WHERE is_active = 1 ORDER BY created_at DESC").fetchall()

    completed_task_ids = {
        r["task_id"] for r in db.execute(
            "SELECT task_id FROM task_completions WHERE user_id = ? AND month_key = ?",
            (user["id"], mkey),
        ).fetchall()
    }

    past_payouts = db.execute(
        "SELECT * FROM payouts WHERE user_id = ? ORDER BY paid_at DESC LIMIT 12",
        (user["id"],),
    ).fetchall()

    return render_template(
        "dashboard.html",
        user=user,
        tasks=tasks,
        completed_task_ids=completed_task_ids,
        total_earned=total_earned,
        task_count=task_count,
        cycle_status=cycle_status,
        past_payouts=past_payouts,
    )


@app.route("/api/tasks/<int:task_id>/complete", methods=["POST"])
@login_required
def complete_task(task_id):
    db = get_db()
    user = current_user()
    mkey = month_key()

    if not user["email_confirmed"]:
        return json_err(tr("err.confirm_first"), 403)

    task = db.execute("SELECT * FROM tasks WHERE id = ? AND is_active = 1", (task_id,)).fetchone()
    if task is None:
        return json_err(tr("err.task_not_found"), 404)

    if not task["repeatable"]:
        already = db.execute(
            "SELECT id FROM task_completions WHERE user_id = ? AND task_id = ? AND month_key = ?",
            (user["id"], task_id, mkey),
        ).fetchone()
        if already:
            return json_err(tr("err.task_done"))

    db.execute(
        "INSERT INTO task_completions (user_id, task_id, month_key, reward_earned, completed_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (user["id"], task_id, mkey, task["reward"], now_str()),
    )
    db.commit()

    total_earned, task_count = user_month_earnings(db, user["id"], mkey)
    return json_ok(total_earned=total_earned, task_count=task_count, reward=task["reward"])


# ---------- CPX Research offerwall + postback ----------

def _md5(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


@app.route("/surveys")
@login_required
def cpx_wall():
    """Shows the CPX offerwall inside a TaskPay page (iframe), so users
    stay on the site. The user's id is passed so postbacks credit them."""
    if not CPX_APP_ID or not CPX_SECURE_HASH:
        return tr("err.wall_not_configured"), 503
    uid = str(session["user_id"])
    wall_url = (
        "https://offers.cpx-research.com/index.php"
        f"?app_id={CPX_APP_ID}&ext_user_id={uid}&secure_hash={_md5(uid + '-' + CPX_SECURE_HASH)}"
    )
    return render_template_string(
        """{% extends "base.html" %}
{% block title %}{{ t('wall.surveys_title') }} — TaskPay{% endblock %}
{% block content %}
<h2>{{ t('wall.surveys_h2') }}</h2>
<iframe src="{{ wall_url }}" title="{{ t('wall.surveys_title') }}"
        style="width:100%;height:80vh;min-height:520px;border:0;border-radius:12px;"></iframe>
{% endblock %}""",
        wall_url=wall_url,
    )


def _apply_conversion(provider, user_id, tx, usd, reverse):
    """Credit or reverse one provider conversion. Safe to call repeatedly
    with the same transaction id (it will not double credit/reverse)."""
    db = get_db()
    original = db.execute(
        "SELECT amount FROM provider_conversions WHERE provider = ? AND external_id = ?",
        (provider, tx),
    ).fetchone()
    if reverse:
        done = db.execute(
            "SELECT id FROM provider_conversions WHERE provider = ? AND external_id = ?",
            (provider, tx + ":reversal"),
        ).fetchone()
        if original and not done:
            db.execute(
                "INSERT INTO provider_conversions (provider, user_id, external_id, amount, month_key, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (provider, user_id, tx + ":reversal", -original["amount"], month_key(), now_str()),
            )
            db.commit()
    elif original is None and usd > 0:
        db.execute(
            "INSERT INTO provider_conversions (provider, user_id, external_id, amount, month_key, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (provider, user_id, tx, usd, month_key(), now_str()),
        )
        db.commit()


@app.route("/offerwall")
@login_required
def offerwall():
    """Offerwall.GG shown inside a TaskPay page (iframe)."""
    if not OFFERWALL_PUBLIC_KEY:
        return tr("err.wall_not_configured"), 503
    wall_url = f"https://offerwall.gg/wall/{OFFERWALL_PUBLIC_KEY}?userId={session['user_id']}"
    return render_template_string(
        """{% extends "base.html" %}
{% block title %}{{ t('wall.offers_title') }} — TaskPay{% endblock %}
{% block content %}
<h2>{{ t('wall.offers_title') }}</h2>
<iframe src="{{ wall_url }}" title="{{ t('wall.offers_title') }}"
        style="width:100%;height:85vh;min-height:560px;border:0;border-radius:12px;"></iframe>
{% endblock %}""",
        wall_url=wall_url,
    )


@app.route("/offerwall/postback")
def offerwall_postback():
    """Offerwall.GG calls this (GET) when a user earns or a conversion is
    reversed. Answers 'ok' (2xx) once handled; anything else is retried."""
    if not OFFERWALL_SECRET:
        return Response("not configured", status=503)

    a = request.args
    user = a.get("user", "").strip()
    tx = a.get("tx", "").strip()
    amount = a.get("amount", "").strip()  # currencyAmount, exactly as signed
    given = a.get("sig", "").strip()

    if not (user and tx and amount and given):
        return Response("bad request", status=400)

    msg = f"{user}:{tx}:{amount}".encode("utf-8")
    digest = hmac.new(OFFERWALL_SECRET.encode("utf-8"), msg, hashlib.sha256).digest()
    ok_hex = hmac.compare_digest(given.lower(), digest.hex())
    ok_b64 = hmac.compare_digest(
        given.rstrip("="), base64.urlsafe_b64encode(digest).decode().rstrip("=")
    ) or hmac.compare_digest(given.rstrip("="), base64.b64encode(digest).decode().rstrip("="))
    if not (ok_hex or ok_b64):
        return Response("invalid signature", status=403)

    if a.get("test", "") == "1":
        return Response("ok", status=200)  # test postback: never credit

    try:
        user_id = int(user)
        # currencyAmount is covered by the signature, so it is the safe value to credit
        usd = abs(float(amount)) / OFFERWALL_UNITS_PER_USD
        # Safety cap: never credit more than the payout you earned on the offer,
        # so a wrong "Units per USD" setting cannot over-credit users.
        payout = a.get("payout", "").strip()
        if payout:
            usd = min(usd, abs(float(payout)))
    except ValueError:
        return Response("bad request", status=400)

    db = get_db()
    if db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone() is None:
        return Response("ok", status=200)  # unknown user: nothing to credit

    _apply_conversion("offerwallgg", user_id, tx, usd, a.get("status", "") == "reversed")
    return Response("ok", status=200)


@app.route("/cpx/postback")
def cpx_postback():
    """CPX calls this when a user earns (status=1) or a completion is
    reversed as fraud (status=2). Must answer 200 once handled."""
    if not CPX_SECURE_HASH:
        return Response("not configured", status=503)

    a = request.args
    trans_id = a.get("trans_id", "").strip()
    status = a.get("status", "").strip()
    given_hash = a.get("hash", "").strip().lower()

    if not trans_id or not hmac.compare_digest(given_hash, _md5(f"{trans_id}-{CPX_SECURE_HASH}")):
        return Response("invalid hash", status=403)

    try:
        user_id = int(a.get("user_id", ""))
        amount = float(a.get("amount_usd", "0"))
    except ValueError:
        return Response("bad request", status=400)

    db = get_db()
    if db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone() is None:
        return Response("unknown user", status=404)

    _apply_conversion("cpx", user_id, trans_id, amount, status == "2")
    return Response("ok", status=200)


@app.route("/referrals")
@login_required
def referrals():
    user = current_user()
    db = get_db()

    referral_link = url_for("register", ref=user["referral_code"], _external=True)

    referred_users = db.execute(
        "SELECT username, created_at FROM users WHERE referred_by = ? ORDER BY created_at DESC",
        (user["id"],),
    ).fetchall()

    total_earned = db.execute(
        "SELECT COALESCE(SUM(commission_amount), 0) AS total FROM referral_commissions WHERE referrer_id = ?",
        (user["id"],),
    ).fetchone()["total"]

    this_month_earned = db.execute(
        "SELECT COALESCE(SUM(commission_amount), 0) AS total FROM referral_commissions "
        "WHERE referrer_id = ? AND month_key = ?",
        (user["id"], month_key()),
    ).fetchone()["total"]

    return render_template(
        "referrals.html",
        user=user,
        referral_link=referral_link,
        referred_users=referred_users,
        total_earned=total_earned,
        this_month_earned=this_month_earned,
        commission_pct=int(REFERRAL_COMMISSION_RATE * 100),
    )


# ---------- payout setup (Paystack) ----------

@app.route("/api/rates")
def api_rates():
    """Live USD -> NGN/XOF rates; script.js polls this so every balance on
    screen stays current without a page reload."""
    fx = get_fx_rates()
    return json_ok(rates=fx["rates"], live=fx["live"], updated=fx["updated"])


@app.route("/api/paystack/banks")
@login_required
def api_paystack_banks():
    """Payout methods for the payout-setup/Settings dropdown. Defaults to
    the logged-in user's saved country, but accepts ?country= so the list
    can refresh when someone changes country before saving."""
    country_key = request.args.get("country", "").strip().lower()
    if country_key not in COUNTRIES:
        country_key = user_country_key(current_user())
    banks, manual = payout_methods_for(country_key)
    return json_ok(banks=banks, manual=manual, has_key=bool(PAYSTACK_SECRET_KEY))


@app.route("/api/public/banks")
def api_public_banks():
    """Same as /api/paystack/banks but reachable while signed out, so the
    bank dropdown on the registration page can populate itself."""
    country_key = request.args.get("country", DEFAULT_COUNTRY).strip().lower()
    if country_key not in COUNTRIES:
        country_key = DEFAULT_COUNTRY
    banks, manual = payout_methods_for(country_key)
    return json_ok(banks=banks, manual=manual, has_key=bool(PAYSTACK_SECRET_KEY))


@app.route("/api/paystack/resolve-account", methods=["POST"])
@login_required
def api_paystack_resolve_account():
    account_number = request.form.get("account_number", "").strip()
    bank_code = request.form.get("bank_code", "").strip()
    if not account_number or not bank_code:
        return json_err(tr("err.bank_and_account"))
    account_name, error = paystack_resolve_account(account_number, bank_code)
    if error:
        return json_err(error)
    return json_ok(account_name=account_name)


@app.route("/payout-setup", methods=["GET", "POST"])
@login_required
def payout_setup():
    user = current_user()

    def render(**extra):
        u = extra.pop("user", None) or current_user()
        return render_template(
            "payout_setup.html", user=u, currencies=CURRENCIES,
            selected_currency=user_currency(u),
            country_label=COUNTRIES[user_country_key(u)]["label"], **extra,
        )

    if request.method == "GET":
        return render(user=user)

    db = get_db()
    currency = request.form.get("currency", "").strip().upper()
    if currency in CURRENCIES:
        db.execute("UPDATE users SET currency = ? WHERE id = ?", (currency, user["id"]))
        db.commit()
        user = current_user()

    bank_code = request.form.get("bank_code", "").strip()
    bank_name = request.form.get("bank_name", "").strip()
    account_number = request.form.get("account_number", "").strip()

    if not bank_code and not account_number:
        return render(user=user, success=tr("ok.currency_saved"))
    if not bank_code or not account_number:
        return render(user=user, error=tr("err.select_bank"))

    account_name, error = save_payout_details(
        db, user, user_country_key(user), bank_code, bank_name, account_number
    )
    if error:
        return render(user=user, error=error)

    return render(
        user=current_user(),
        success=tr("ok.payout_saved", name=account_name, bank=bank_name),
    )


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """One place to change everything account-related that isn't a task/
    payout action: password, country, and payout bank account. The forgot-
    password flow (routes above) covers the signed-out case; this covers
    the signed-in one."""
    user = current_user()

    def render(**extra):
        u = extra.pop("user", None) or current_user()
        return render_template(
            "settings.html", user=u, countries=COUNTRIES, currencies=CURRENCIES,
            user_currency_code=user_currency(u),
            banks=payout_methods_for(user_country_key(u))[0],
            **extra,
        )

    if request.method == "GET":
        return render(user=user)

    action = request.form.get("action")
    db = get_db()

    if action == "password":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        if not user["password_hash"] or not check_password_hash(user["password_hash"], current_password):
            return render(user=user, password_error=tr("err.current_password_wrong"))
        if len(new_password) < 6:
            return render(user=user, password_error=tr("err.new_password_short"))
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), user["id"]))
        db.commit()
        return render(password_success=tr("ok.password_updated"))

    if action == "bank":
        country = request.form.get("country", DEFAULT_COUNTRY).strip().lower()
        if country not in COUNTRIES:
            country = DEFAULT_COUNTRY
        bank_code = request.form.get("bank_code", "").strip()
        bank_name = request.form.get("bank_name", "").strip()
        account_number = request.form.get("account_number", "").strip()

        db.execute("UPDATE users SET country = ? WHERE id = ?", (country, user["id"]))
        new_currency = request.form.get("currency", "").strip().upper()
        if new_currency in CURRENCIES:
            db.execute("UPDATE users SET currency = ? WHERE id = ?", (new_currency, user["id"]))
        db.commit()
        user = current_user()

        if not bank_code or not account_number:
            # Country alone still saves -- bank details are only
            # validated/attached if both fields were actually filled in.
            return render(user=user, bank_success=tr("ok.country_updated"))

        account_name, error = save_payout_details(db, user, country, bank_code, bank_name, account_number)
        if error:
            return render(user=user, bank_error=error)

        return render(bank_success=tr("ok.payout_saved", name=account_name, bank=bank_name))

    return redirect(url_for("settings"))


# ---------- admin routes ----------

@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    db = get_db()
    mkey = month_key()

    source_rows = []
    for source, cfg in SOURCES.items():
        settlement = get_or_create_settlement(db, source, mkey)
        source_rows.append({
            "key": source,
            "label": cfg["label"],
            "owed": source_month_total(db, source, mkey),
            "settled": bool(settlement["settled"]),
            "settled_at": settlement["settled_at"],
            "processed": bool(settlement["processed"]),
        })

    tasks = db.execute("SELECT * FROM tasks ORDER BY created_at DESC").fetchall()

    leaderboard = db.execute(
        "SELECT u.id, u.username, "
        "COALESCE((SELECT SUM(reward_earned) FROM task_completions WHERE user_id = u.id AND month_key = ?), 0) "
        "+ COALESCE((SELECT SUM(amount) FROM provider_conversions WHERE user_id = u.id AND month_key = ?), 0) AS total, "
        "COALESCE((SELECT COUNT(*) FROM task_completions WHERE user_id = u.id AND month_key = ?), 0) AS task_count "
        "FROM users u WHERE u.is_admin = 0 "
        "ORDER BY total DESC",
        (mkey, mkey, mkey),
    ).fetchall()

    total_owed = sum(row["total"] for row in leaderboard)

    return render_template(
        "admin.html",
        tasks=tasks,
        leaderboard=leaderboard,
        source_rows=source_rows,
        total_owed=total_owed,
        month_key=mkey,
    )


@app.route("/api/admin/tasks", methods=["POST"])
@login_required
@admin_required
def admin_create_task():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    reward = request.form.get("reward", "0")
    repeatable = 1 if request.form.get("repeatable") == "on" else 0

    try:
        reward = float(reward)
    except ValueError:
        return json_err("Reward must be a number.")

    if not title or reward <= 0:
        return json_err("Title and a positive reward are required.")

    db = get_db()
    db.execute(
        "INSERT INTO tasks (title, description, reward, repeatable, is_active, created_at) "
        "VALUES (?, ?, ?, ?, 1, ?)",
        (title, description, reward, repeatable, now_str()),
    )
    db.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/api/admin/tasks/<int:task_id>/toggle", methods=["POST"])
@login_required
@admin_required
def admin_toggle_task(task_id):
    db = get_db()
    task = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if task is None:
        return json_err("Task not found.", 404)
    db.execute("UPDATE tasks SET is_active = ? WHERE id = ?", (0 if task["is_active"] else 1, task_id))
    db.commit()
    return json_ok()


@app.route("/api/admin/settle/<source>", methods=["POST"])
@login_required
@admin_required
def admin_settle_source(source):
    """Confirm that the money for this month's tasks is actually in your
    account, so its payouts can be processed."""
    if source not in SOURCES:
        return json_err("Unknown source.", 404)
    mkey = request.form.get("month_key") or month_key()
    db = get_db()
    settlement = get_or_create_settlement(db, source, mkey)
    if settlement["processed"]:
        return json_err("This source was already processed for this cycle.")
    db.execute(
        "UPDATE provider_settlements SET settled = 1, settled_at = ? WHERE source = ? AND month_key = ?",
        (now_str(), source, mkey),
    )
    db.commit()
    return json_ok(message=f"{SOURCES[source]['label']} settlement confirmed. Its payouts can now be processed.")


def credit_referral_commission(db, referrer_id, referred_user_id, source, mkey, base_amount):
    """Adds this referred user's cut to the referrer's running 'referral'
    payout for the month, creating it if needed. Logged separately too so
    the exact source/referred-user breakdown is auditable."""
    commission = round(base_amount * REFERRAL_COMMISSION_RATE, 2)
    if commission <= 0:
        return

    db.execute(
        "INSERT INTO referral_commissions "
        "(referrer_id, referred_user_id, source, month_key, base_amount, commission_amount, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (referrer_id, referred_user_id, source, mkey, base_amount, commission, now_str()),
    )

    existing = db.execute(
        "SELECT id, amount FROM payouts WHERE user_id = ? AND month_key = ? AND source = 'referral'",
        (referrer_id, mkey),
    ).fetchone()
    if existing:
        db.execute(
            "UPDATE payouts SET amount = ? WHERE id = ?",
            (existing["amount"] + commission, existing["id"]),
        )
    else:
        db.execute(
            "INSERT INTO payouts (user_id, month_key, source, amount, paid_at) VALUES (?, ?, 'referral', ?, ?)",
            (referrer_id, mkey, commission, now_str()),
        )


@app.route("/api/admin/process-payouts/<source>", methods=["POST"])
@login_required
@admin_required
def admin_process_payouts(source):
    """Pays every user their balance from ONE source for the month -- gated
    on that source's own settled flag, so the backend never releases money
    it hasn't confirmed it actually received."""
    if source not in SOURCES:
        return json_err("Unknown source.", 404)
    mkey = request.form.get("month_key") or month_key()
    db = get_db()
    settlement = get_or_create_settlement(db, source, mkey)

    if not settlement["settled"]:
        return json_err(f"Cannot process payouts: {SOURCES[source]['label']} is not yet confirmed settled.", 403)
    if settlement["processed"]:
        return json_err("Payouts for this source/cycle were already processed.")

    if source != "internal":
        earners = db.execute(
            "SELECT user_id, SUM(amount) AS total FROM provider_conversions "
            "WHERE provider = ? AND month_key = ? GROUP BY user_id HAVING total > 0",
            (source, mkey),
        ).fetchall()
    else:
        earners = db.execute(
            "SELECT user_id, SUM(reward_earned) AS total FROM task_completions "
            "WHERE month_key = ? GROUP BY user_id HAVING total > 0",
            (mkey,),
        ).fetchall()

    # Balances are stored in USD but Paystack pays Nigerian banks in naira,
    # so convert at the live rate right now. Refuse to run on a stale or
    # fallback rate -- that would pay people the wrong amount.
    fx = get_fx_rates(force=True)
    if not fx["live"]:
        return json_err("Live exchange rate is unavailable right now, so payouts were not sent. "
                        "Try again in a minute.", 503)
    rates = fx["rates"]
    ngn_rate = rates["NGN"]

    paid_count = 0
    manual_count = 0
    transfer_failures = []
    for row in earners:
        already = db.execute(
            "SELECT id FROM payouts WHERE user_id = ? AND month_key = ? AND source = ?",
            (row["user_id"], mkey, source),
        ).fetchone()
        if already:
            continue

        earner_user = db.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()

        # Actually move the money via Paystack if this user has a payout
        # account on file. If they don't yet (or the transfer API call
        # fails), we still record what's owed -- transfer_status shows
        # which payouts are real bank transfers vs. still pending one.
        transfer_status = "no_bank_info"
        transfer_reference = None
        pay_currency = user_currency(earner_user)
        amount_local = round(convert_usd(row["total"], pay_currency, rates), 2)
        if earner_user and earner_user["paystack_recipient_code"]:
            pay_currency = "NGN"
            amount_local = round(row["total"] * ngn_rate, 2)
            ok, transfer_reference, message = paystack_send_transfer(
                earner_user["paystack_recipient_code"],
                amount_local,
                reason=f"TaskPay payout {mkey}",
            )
            transfer_status = "sent" if ok else "failed"
            if not ok:
                transfer_failures.append(f"{earner_user['username']}: {message}")
        elif earner_user and earner_user["account_number"]:
            # Manual payout method (e.g. Togo mobile money): you send it yourself.
            transfer_status = "manual"
            manual_count += 1

        db.execute(
            "INSERT INTO payouts (user_id, month_key, source, amount, paid_at, transfer_reference, "
            "transfer_status, currency, amount_local) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (row["user_id"], mkey, source, row["total"], now_str(), transfer_reference,
             transfer_status, pay_currency, amount_local),
        )
        paid_count += 1

        # Referral commissions only apply from the public launch cycle
        # onward -- not on pre-launch shakedown earnings.
        if is_post_launch(mkey):
            earner = db.execute("SELECT referred_by FROM users WHERE id = ?", (row["user_id"],)).fetchone()
            if earner and earner["referred_by"]:
                credit_referral_commission(db, earner["referred_by"], row["user_id"], source, mkey, row["total"])

    db.execute(
        "UPDATE provider_settlements SET processed = 1, processed_at = ? WHERE source = ? AND month_key = ?",
        (now_str(), source, mkey),
    )
    db.commit()
    message = f"Processed {SOURCES[source]['label']} payouts for {paid_count} user(s)."
    if manual_count:
        message += f" {manual_count} user(s) use a manual payout method (mobile money/bank outside Paystack) -- send those yourself."
    if transfer_failures:
        message += f" {len(transfer_failures)} transfer(s) failed: " + "; ".join(transfer_failures)
    return json_ok(message=message, paid_count=paid_count, transfer_failures=transfer_failures)


if not PAYSTACK_SECRET_KEY:
    print("[warn] PAYSTACK_SECRET_KEY is empty. Add it to your .env file in the TaskPay folder to enable the bank list and payouts.")

if __name__ == "__main__":
    # ensure_db() already ran at import time above, so the DB/tables exist
    # by the time we get here no matter how this file was launched.
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", "3000")))

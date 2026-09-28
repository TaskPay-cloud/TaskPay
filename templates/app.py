import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, g, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "taskpay.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
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
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5000")
oauth = OAuth(app)
google_oauth = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID", ""),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# ---------- Brevo transactional email (signup confirmation) ----------
# Get an API key at https://app.brevo.com/settings/keys/api and verify a
# sender address/domain in Brevo before sending -- unverified senders get
# silently rejected.
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "no-reply@taskpay.local")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "TaskPay")

# ---------- offerwall provider config ----------
# Fill these in from each provider's publisher dashboard after your app is
# approved. Postback secrets are how we verify a payout callback really came
# from the provider and wasn't faked by a random visitor hitting the URL.
PROVIDERS = {
    "cpalead": {
        "label": "CPAlead",
        "signup_url": "https://cpalead.com",
        "offerwall_url": os.environ.get("CPALEAD_OFFERWALL_URL", "https://cpalead.com/offerwall/?id=YOUR_APP_ID"),
        "postback_secret": os.environ.get("CPALEAD_POSTBACK_SECRET", ""),
    },
    "adgate": {
        "label": "AdGate Media",
        "signup_url": "https://adgatemedia.com",
        "offerwall_url": os.environ.get("ADGATE_OFFERWALL_URL", "https://wall.adgaterewards.com/YOUR_WALL_CODE"),
        "postback_secret": os.environ.get("ADGATE_POSTBACK_SECRET", ""),
    },
    "torox": {
        "label": "Torox (formerly OfferToro)",
        "signup_url": "https://torox.io",
        "offerwall_url": os.environ.get("TOROX_OFFERWALL_URL", "https://www.offertoro.com/ofw/YOUR_APP_ID"),
        "postback_secret": os.environ.get("TOROX_POSTBACK_SECRET", ""),
    },
}

# Every place money can come from: your own tasks ("internal") plus each
# offerwall provider. Settlement (has the money actually landed in your
# account?) is tracked separately per source below, so a fast payer like
# CPAlead can be released to users without waiting on slower ones.
SOURCES = {"internal": {"label": "Internal tasks"}}
SOURCES.update({key: {"label": cfg["label"]} for key, cfg in PROVIDERS.items()})

# ---------- Paystack (user payouts) ----------
# Get your secret key from Settings -> API Keys & Webhooks in the Paystack
# dashboard: https://dashboard.paystack.com/#/settings/developer
# Use a test secret key (sk_test_...) while developing -- switch to your
# live key (sk_live_...) only once you're ready to move real money.
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "")
PAYSTACK_BASE_URL = "https://api.paystack.co"

_bank_list_cache = {"banks": None, "fetched_at": None}


def _paystack_headers():
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }


def get_paystack_banks(force_refresh=False):
    """Live list of Nigerian banks from Paystack, sorted alphabetically by
    name for the payout-setup dropdown. Cached in memory for an hour so
    every page load doesn't re-hit the API -- refresh manually with
    force_refresh=True if a bank is missing."""
    cache = _bank_list_cache
    if not force_refresh and cache["banks"] and cache["fetched_at"]:
        if (datetime.utcnow() - cache["fetched_at"]).total_seconds() < 3600:
            return cache["banks"]

    if not PAYSTACK_SECRET_KEY:
        return []

    try:
        resp = requests.get(
            f"{PAYSTACK_BASE_URL}/bank",
            headers=_paystack_headers(),
            params={"country": "nigeria", "currency": "NGN", "perPage": 100},
            timeout=10,
        )
        data = resp.json()
        if not data.get("status"):
            print(f"[error] Paystack bank list failed: {data.get('message')}")
            return cache["banks"] or []
        banks = sorted(
            [{"code": b["code"], "name": b["name"]} for b in data["data"]],
            key=lambda b: b["name"].lower(),
        )
        cache["banks"] = banks
        cache["fetched_at"] = datetime.utcnow()
        return banks
    except requests.RequestException as exc:
        print(f"[error] Paystack bank list request failed: {exc}")
        return cache["banks"] or []


def paystack_resolve_account(account_number, bank_code):
    """Confirms an account number is real and reachable at that bank, and
    returns the account holder's name so the user can double-check it's
    theirs before we save it. This is Paystack's account-resolve endpoint,
    not a guess -- if it fails, the account number/bank combo is wrong."""
    if not PAYSTACK_SECRET_KEY:
        return None, "Paystack isn't configured yet (missing PAYSTACK_SECRET_KEY)."
    try:
        resp = requests.get(
            f"{PAYSTACK_BASE_URL}/bank/resolve",
            headers=_paystack_headers(),
            params={"account_number": account_number, "bank_code": bank_code},
            timeout=15,
        )
        data = resp.json()
        if not data.get("status"):
            return None, data.get("message", "Could not verify that account.")
        return data["data"]["account_name"], None
    except requests.RequestException as exc:
        return None, f"Paystack request failed: {exc}"


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
            return None, data.get("message", "Could not register this account with Paystack.")
        recipient_code = data["data"]["recipient_code"]
        db.execute(
            "UPDATE users SET bank_code = ?, bank_name = ?, account_number = ?, "
            "account_name = ?, paystack_recipient_code = ? WHERE id = ?",
            (bank_code, bank_name, account_number, account_name, recipient_code, user["id"]),
        )
        db.commit()
        return recipient_code, None
    except requests.RequestException as exc:
        return None, f"Paystack request failed: {exc}"


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
# Public rewards (real payouts) go live on this date. Tasks/offers can be
# completed before it -- balances just accumulate -- but referral
# commissions and the "public launch" framing only kick in from this
# month onward.
LAUNCH_DATE_ISO = os.environ.get("LAUNCH_DATE_ISO", "2026-11-30T00:00:00+00:00")
REFERRAL_COMMISSION_RATE = float(os.environ.get("REFERRAL_COMMISSION_RATE", "0.05"))


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
        "nav.offers": "Offers",
        "nav.referrals": "Referrals",
        "nav.payout_account": "Payout account",
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
        "register.submit": "Sign up",
        "register.have_account": "Already have an account?",
        "register.login_link": "Log in",
        "payout.title": "Payout account",
        "payout.sub": "This is the bank account rewards get paid into when payouts run on 30th November onward.",
        "payout.bank_label": "Bank",
        "payout.account_label": "Account number",
        "payout.save": "Save payout account",
    },
    "fr": {
        "nav.dashboard": "Tableau de bord",
        "nav.offers": "Offres",
        "nav.referrals": "Parrainages",
        "nav.payout_account": "Compte de paiement",
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
        "register.submit": "S'inscrire",
        "register.have_account": "Vous avez déjà un compte ?",
        "register.login_link": "Se connecter",
        "payout.title": "Compte de paiement",
        "payout.sub": "C'est le compte bancaire sur lequel les récompenses seront versées à partir du 30 novembre.",
        "payout.bank_label": "Banque",
        "payout.account_label": "Numéro de compte",
        "payout.save": "Enregistrer le compte de paiement",
    },
}


def get_lang():
    lang = session.get("lang")
    return lang if lang in SUPPORTED_LANGUAGES else "en"


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
        g.db = sqlite3.connect(DB_PATH)
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
    paystack_recipient_code TEXT
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
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA_SQL)
    # seed a default admin so there's always a way in
    existing = db.execute("SELECT id FROM users WHERE is_admin = 1").fetchone()
    if not existing:
        db.execute(
            "INSERT INTO users (username, email, password_hash, is_admin, email_confirmed, referral_code, created_at) "
            "VALUES (?, ?, ?, 1, 1, ?, ?)",
            ("admin", "admin@taskpay.local", generate_password_hash("admin123"),
             secrets.token_hex(4), now_str()),
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
    db = sqlite3.connect(DB_PATH)
    try:
        db.execute("SELECT 1 FROM users LIMIT 1")
    except sqlite3.OperationalError:
        db.close()
        init_db()
    else:
        db.close()


ensure_db()


def now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def month_key(dt=None):
    dt = dt or datetime.utcnow()
    return dt.strftime("%Y-%m")


def send_confirmation_email(to_email, username, token):
    """Sends the signup confirmation email via Brevo's transactional API.
    Fails quietly (logs to stdout) if BREVO_API_KEY isn't set yet -- lets
    you develop locally without an API key, but nothing actually sends
    until you fill it in."""
    confirm_url = f"{APP_BASE_URL}{url_for('confirm_email', token=token)}"

    if not BREVO_API_KEY:
        print(f"[dev] BREVO_API_KEY not set -- confirmation link for {to_email}: {confirm_url}")
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
                "to": [{"email": to_email, "name": username}],
                "subject": "Confirm your TaskPay account",
                "htmlContent": (
                    f"<p>Hi {username},</p>"
                    f"<p>Welcome to TaskPay! Confirm your email to start completing tasks:</p>"
                    f'<p><a href="{confirm_url}">{confirm_url}</a></p>'
                    f"<p>If you didn't sign up, you can ignore this email.</p>"
                ),
            },
            timeout=10,
        )
        return resp.status_code in (200, 201)
    except requests.RequestException as exc:
        print(f"[error] Brevo send failed for {to_email}: {exc}")
        return False


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
                return json_err("Login required", 401)
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            if request.path.startswith("/api/"):
                return json_err("Admin only", 403)
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
    tasks_row = db.execute(
        "SELECT COALESCE(SUM(reward_earned), 0) AS total, COUNT(*) AS task_count "
        "FROM task_completions WHERE user_id = ? AND month_key = ?",
        (user_id, mkey),
    ).fetchone()
    provider_row = db.execute(
        "SELECT COALESCE(SUM(amount), 0) AS total, COUNT(*) AS task_count "
        "FROM provider_conversions WHERE user_id = ? AND month_key = ?",
        (user_id, mkey),
    ).fetchone()
    total = tasks_row["total"] + provider_row["total"]
    task_count = tasks_row["task_count"] + provider_row["task_count"]
    return total, task_count


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
    """Total earned from one source (internal tasks or a specific provider)
    across all users for a given month -- what that source owes users."""
    if source == "internal":
        row = db.execute(
            "SELECT COALESCE(SUM(reward_earned), 0) AS total FROM task_completions WHERE month_key = ?",
            (mkey,),
        ).fetchone()
    else:
        row = db.execute(
            "SELECT COALESCE(SUM(amount), 0) AS total FROM provider_conversions "
            "WHERE provider = ? AND month_key = ?",
            (source, mkey),
        ).fetchone()
    return row["total"]


# ---------- public / auth routes ----------

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    ref_code = request.args.get("ref", "").strip()
    if request.method == "GET":
        return render_template("register.html", ref_code=ref_code)

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    ref_code = request.form.get("ref_code", "").strip()

    if not username or not email or not password:
        return render_template("register.html", error="All fields are required.", ref_code=ref_code)

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
    ).fetchone()
    if existing:
        return render_template("register.html", error="Username or email already taken.", ref_code=ref_code)

    referrer = None
    if ref_code:
        referrer = db.execute(
            "SELECT id FROM users WHERE referral_code = ?", (ref_code,)
        ).fetchone()

    new_referral_code = secrets.token_hex(4)
    confirmation_token = secrets.token_urlsafe(24)
    db.execute(
        "INSERT INTO users (username, email, password_hash, auth_provider, email_confirmed, "
        "confirmation_token, is_admin, referral_code, referred_by, created_at) "
        "VALUES (?, ?, ?, 'password', 0, ?, 0, ?, ?, ?)",
        (username, email, generate_password_hash(password), confirmation_token,
         new_referral_code, referrer["id"] if referrer else None, now_str()),
    )
    db.commit()
    send_confirmation_email(email, username, confirmation_token)
    return redirect(url_for("login", registered=1))


@app.route("/confirm/<token>")
def confirm_email(token):
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE confirmation_token = ?", (token,)).fetchone()
    if user is None:
        return render_template("login.html", error="That confirmation link is invalid or already used.")
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
        return json_err("Your email is already confirmed.")
    db = get_db()
    token = secrets.token_urlsafe(24)
    db.execute("UPDATE users SET confirmation_token = ? WHERE id = ?", (token, user["id"]))
    db.commit()
    sent = send_confirmation_email(user["email"], user["username"], token)
    return json_ok(message="Confirmation email sent." if sent else "Could not send email right now.")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template(
            "login.html",
            registered=request.args.get("registered"),
            confirmed=request.args.get("confirmed"),
        )

    identifier = request.form.get("identifier", "").strip().lower()
    password = request.form.get("password", "")

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier)
    ).fetchone()

    if user is None or not user["password_hash"] or not check_password_hash(user["password_hash"], password):
        return render_template("login.html", error="Invalid credentials.")

    session["user_id"] = user["id"]
    session["is_admin"] = bool(user["is_admin"])
    return redirect(url_for("admin_dashboard") if user["is_admin"] else url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


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
        return render_template("login.html", error="Google didn't return an email address. Try again.")

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

    source_status = []
    for source, cfg in SOURCES.items():
        settlement = get_or_create_settlement(db, source, mkey)
        source_status.append({
            "label": cfg["label"],
            "settled": bool(settlement["settled"]),
            "processed": bool(settlement["processed"]),
        })

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
        source_status=source_status,
        past_payouts=past_payouts,
    )


@app.route("/api/tasks/<int:task_id>/complete", methods=["POST"])
@login_required
def complete_task(task_id):
    db = get_db()
    user = current_user()
    mkey = month_key()

    if not user["email_confirmed"]:
        return json_err("Please confirm your email before completing tasks.", 403)

    task = db.execute("SELECT * FROM tasks WHERE id = ? AND is_active = 1", (task_id,)).fetchone()
    if task is None:
        return json_err("Task not found or inactive.", 404)

    if not task["repeatable"]:
        already = db.execute(
            "SELECT id FROM task_completions WHERE user_id = ? AND task_id = ? AND month_key = ?",
            (user["id"], task_id, mkey),
        ).fetchone()
        if already:
            return json_err("You already completed this task this month.")

    db.execute(
        "INSERT INTO task_completions (user_id, task_id, month_key, reward_earned, completed_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (user["id"], task_id, mkey, task["reward"], now_str()),
    )
    db.commit()

    total_earned, task_count = user_month_earnings(db, user["id"], mkey)
    return json_ok(total_earned=total_earned, task_count=task_count, reward=task["reward"])


def build_offerwall_url(provider_key, user_id):
    """Appends the user's id as the subid/tracking param each network uses
    to tell us which user completed an offer, so the postback can credit
    the right person."""
    base = PROVIDERS[provider_key]["offerwall_url"]
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}subid={user_id}"


@app.route("/offers")
@login_required
def offers():
    user = current_user()
    provider_links = [
        {"key": key, "label": cfg["label"], "url": build_offerwall_url(key, user["id"])}
        for key, cfg in PROVIDERS.items()
    ]
    return render_template("offers.html", provider_links=provider_links)


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
        referral_link=referral_link,
        referred_users=referred_users,
        total_earned=total_earned,
        this_month_earned=this_month_earned,
        commission_pct=int(REFERRAL_COMMISSION_RATE * 100),
    )


# ---------- payout setup (Paystack) ----------

@app.route("/api/paystack/banks")
@login_required
def api_paystack_banks():
    """Bank list for the payout-setup dropdown -- live from Paystack,
    sorted alphabetically by name."""
    return json_ok(banks=get_paystack_banks())


@app.route("/api/paystack/resolve-account", methods=["POST"])
@login_required
def api_paystack_resolve_account():
    account_number = request.form.get("account_number", "").strip()
    bank_code = request.form.get("bank_code", "").strip()
    if not account_number or not bank_code:
        return json_err("Account number and bank are both required.")
    account_name, error = paystack_resolve_account(account_number, bank_code)
    if error:
        return json_err(error)
    return json_ok(account_name=account_name)


@app.route("/payout-setup", methods=["GET", "POST"])
@login_required
def payout_setup():
    user = current_user()

    if request.method == "GET":
        return render_template("payout_setup.html", user=user, banks=get_paystack_banks())

    bank_code = request.form.get("bank_code", "").strip()
    bank_name = request.form.get("bank_name", "").strip()
    account_number = request.form.get("account_number", "").strip()

    if not bank_code or not account_number:
        return render_template(
            "payout_setup.html", user=user, banks=get_paystack_banks(),
            error="Select a bank and enter your account number.",
        )

    account_name, error = paystack_resolve_account(account_number, bank_code)
    if error:
        return render_template("payout_setup.html", user=user, banks=get_paystack_banks(), error=error)

    db = get_db()
    recipient_code, error = paystack_get_or_create_recipient(
        db, user, bank_code, bank_name, account_number, account_name
    )
    if error:
        return render_template("payout_setup.html", user=user, banks=get_paystack_banks(), error=error)

    return render_template(
        "payout_setup.html", user=current_user(), banks=get_paystack_banks(),
        success=f"Payout account saved: {account_name} ({bank_name}).",
    )


@app.route("/postback/<provider_key>")
def provider_postback(provider_key):
    """Server-to-server callback the offerwall network hits when a user
    completes one of ITS offers and pays out to us. This is the only place
    a user's balance grows from provider tasks -- never trust anything the
    browser/user reports directly.

    Exact query param names vary per network; check your dashboard once
    approved and adjust the field lookups below (subid/user_id/aff_sub4,
    amount/payout/reward, secret/signature) to match what they actually send.
    """
    if provider_key not in PROVIDERS:
        return "unknown provider", 404

    cfg = PROVIDERS[provider_key]
    secret = request.args.get("secret") or request.args.get("signature")
    if not cfg["postback_secret"] or secret != cfg["postback_secret"]:
        return "invalid secret", 403

    user_id = request.args.get("subid") or request.args.get("user_id")
    amount = request.args.get("amount") or request.args.get("payout")
    external_id = request.args.get("offer_id") or request.args.get("trans_id") or ""

    if not user_id or not amount:
        return "missing subid/amount", 400

    try:
        user_id = int(user_id)
        amount = float(amount)
    except ValueError:
        return "bad subid/amount", 400

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return "unknown user", 404

    mkey = month_key()
    db.execute(
        "INSERT INTO provider_conversions (provider, user_id, external_id, amount, month_key, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (provider_key, user_id, external_id, amount, mkey, now_str()),
    )
    db.commit()
    # NOTE: this postback only means the provider *tracked* a conversion --
    # it is NOT the same as the provider actually depositing money into our
    # account. Most offerwall networks settle on Net-15/Net-30 terms (or
    # longer), so the cash for a given month's conversions often doesn't
    # land until well into the following month. Do NOT auto-mark the cycle
    # as provider_paid here. The admin should only click "Confirm provider
    # paid" on /admin once the actual invoice/payment has cleared in your
    # bank/PayPal/etc -- check each network's payout schedule in their
    # publisher dashboard, since it varies by provider and account tier.
    return "1"  # most networks expect a plain "1"/"OK" body to mark the postback delivered


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
        "COALESCE((SELECT COUNT(*) FROM task_completions WHERE user_id = u.id AND month_key = ?), 0) "
        "+ COALESCE((SELECT COUNT(*) FROM provider_conversions WHERE user_id = u.id AND month_key = ?), 0) AS task_count "
        "FROM users u WHERE u.is_admin = 0 "
        "ORDER BY total DESC",
        (mkey, mkey, mkey, mkey),
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
    """Confirm that a specific source (a provider, or your own 'internal'
    tasks) has actually paid real money into your account for this month.
    Each source is independent -- confirming CPAlead doesn't touch AdGate
    or Torox, so a fast payer never has to wait on a slow one."""
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

    if source == "internal":
        earners = db.execute(
            "SELECT user_id, SUM(reward_earned) AS total FROM task_completions "
            "WHERE month_key = ? GROUP BY user_id HAVING total > 0",
            (mkey,),
        ).fetchall()
    else:
        earners = db.execute(
            "SELECT user_id, SUM(amount) AS total FROM provider_conversions "
            "WHERE provider = ? AND month_key = ? GROUP BY user_id HAVING total > 0",
            (source, mkey),
        ).fetchall()

    paid_count = 0
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
        if earner_user and earner_user["paystack_recipient_code"]:
            ok, transfer_reference, message = paystack_send_transfer(
                earner_user["paystack_recipient_code"],
                row["total"],
                reason=f"TaskPay {SOURCES[source]['label']} payout — {mkey}",
            )
            transfer_status = "sent" if ok else "failed"
            if not ok:
                transfer_failures.append(f"{earner_user['username']}: {message}")

        db.execute(
            "INSERT INTO payouts (user_id, month_key, source, amount, paid_at, transfer_reference, transfer_status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (row["user_id"], mkey, source, row["total"], now_str(), transfer_reference, transfer_status),
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
    if transfer_failures:
        message += f" {len(transfer_failures)} transfer(s) failed: " + "; ".join(transfer_failures)
    return json_ok(message=message, paid_count=paid_count, transfer_failures=transfer_failures)


if __name__ == "__main__":
    # ensure_db() already ran at import time above, so the DB/tables exist
    # by the time we get here no matter how this file was launched.
    app.run(debug=True, host="0.0.0.0", port=5000)

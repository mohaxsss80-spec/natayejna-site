from flask import Flask, render_template, jsonify, request, url_for, redirect, session, abort
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
import hmac
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
import urllib.error
import urllib.parse
import urllib.request

app = Flask(__name__)
BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"
DATA_FILE = DATA_DIR / "results.json"
SITE_CONFIG_FILE = DATA_DIR / "site_config.json"
AUTH_DATABASE_PATH = Path(os.environ.get("AUTH_DATABASE_PATH", str(DATA_DIR / "accounts.sqlite3"))).expanduser()
UPLOAD_DIR = BASE / "static" / "uploads"
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ADMIN_PASSWORD_FILE = DATA_DIR / "admin_password.txt"
SESSION_SECRET_FILE = DATA_DIR / "session_secret.txt"


def get_admin_password():
    password = os.environ.get("ADMIN_PASSWORD", "").strip()
    if password:
        return password
    try:
        return ADMIN_PASSWORD_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def get_session_secret():
    try:
        secret = SESSION_SECRET_FILE.read_text(encoding="utf-8").strip()
        if secret:
            return secret
    except Exception:
        pass
    secret = secrets.token_urlsafe(48)
    try:
        SESSION_SECRET_FILE.write_text(secret, encoding="utf-8")
    except Exception:
        pass
    return secret


app.secret_key = os.environ.get("FLASK_SECRET_KEY", get_session_secret())
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() in {"1", "true", "yes"},
)


@contextmanager
def auth_db():
    AUTH_DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(AUTH_DATABASE_PATH), timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_auth_db():
    with auth_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                share_email INTEGER NOT NULL DEFAULT 0,
                share_email_consented_at TEXT,
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS auth_rate_limits (
                scope TEXT NOT NULL,
                client_hash TEXT NOT NULL,
                window_start INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (scope, client_hash, window_start)
            )
        """)
        account_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(accounts)").fetchall()
        }
        if "google_sub" not in account_columns:
            connection.execute("ALTER TABLE accounts ADD COLUMN google_sub TEXT")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_google_sub "
            "ON accounts(google_sub) WHERE google_sub IS NOT NULL"
        )
    try:
        os.chmod(AUTH_DATABASE_PATH, 0o600)
    except OSError:
        pass


init_auth_db()


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {
        "csrf_token": csrf_token,
        "google_oauth_enabled": bool(
            os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET")
        ),
    }


@app.before_request
def protect_csrf():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    expected = session.get("_csrf_token", "")
    supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        if request.path.startswith("/api/"):
            return jsonify({"error": "طلب غير صالح؛ أعد تحميل الصفحة وحاول مجدداً"}), 400
        abort(400, description="رمز الحماية غير صالح؛ أعد تحميل الصفحة وحاول مجدداً")
    return None


def auth_rate_limited(scope, limit, window_seconds):
    remote = request.remote_addr or "unknown"
    key = hmac.new(str(app.secret_key).encode("utf-8"), f"{scope}:{remote}".encode("utf-8"), hashlib.sha256).hexdigest()
    now = int(time.time())
    window_start = now - (now % window_seconds)
    with auth_db() as connection:
        connection.execute("DELETE FROM auth_rate_limits WHERE window_start < ?", (now - 86400,))
        connection.execute(
            "INSERT INTO auth_rate_limits (scope, client_hash, window_start, attempts) VALUES (?, ?, ?, 1) "
            "ON CONFLICT(scope, client_hash, window_start) DO UPDATE SET attempts = attempts + 1",
            (scope, key, window_start),
        )
        row = connection.execute(
            "SELECT attempts FROM auth_rate_limits WHERE scope = ? AND client_hash = ? AND window_start = ?",
            (scope, key, window_start),
        ).fetchone()
    return bool(row and row["attempts"] > limit)


def account_by_id(user_id):
    try:
        numeric_id = int(user_id)
    except (TypeError, ValueError):
        return None
    with auth_db() as connection:
        return connection.execute(
            "SELECT id, email, share_email, share_email_consented_at, created_at FROM accounts WHERE id = ?",
            (numeric_id,),
        ).fetchone()


@app.after_request
def prevent_private_page_caching(response):
    if request.path in {
        "/login", "/register", "/account", "/admin/users",
        "/auth/google", "/auth/google/callback",
    }:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.before_request
def protect_admin_area():
    is_admin_page = request.path == "/admin" or request.path.startswith("/admin/")
    is_editor_api = request.path.startswith("/api/site-config") or request.path == "/api/upload"
    if not (is_admin_page or is_editor_api):
        return None
    if request.path in {"/admin/login", "/admin/logout"}:
        return None
    if not get_admin_password():
        if is_editor_api:
            return jsonify({"error": "لم يتم إعداد كلمة مرور لوحة التحكم بعد"}), 503
        return render_template("admin_login.html", error="أنشئ ملف admin_password.txt أولًا في مجلد data")
    if not session.get("admin_authenticated"):
        if is_editor_api:
            return jsonify({"error": "يجب تسجيل الدخول أولًا"}), 401
        return redirect(url_for("admin_login"))
    return None


DEFAULT_CONFIG = {
    "site_name": "نتائجنا",
    "developer": "Awad Hazim",
    "tagline": "منصة طلاب سوريا",
    "background": "#031613",
    "accent": "#43e36b",
    "elements": []
}


def load_results():
    try:
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def load_config():
    try:
        saved = json.loads(SITE_CONFIG_FILE.read_text(encoding="utf-8"))
        config = dict(DEFAULT_CONFIG)
        config.update(saved if isinstance(saved, dict) else {})
        if not isinstance(config.get("elements"), list):
            config["elements"] = []
        return config
    except Exception:
        return dict(DEFAULT_CONFIG)


def save_config(config):
    clean = dict(DEFAULT_CONFIG)
    clean.update(config if isinstance(config, dict) else {})
    clean["site_name"] = str(clean.get("site_name", "نتائجنا"))[:120]
    clean["developer"] = str(clean.get("developer", "Awad Hazim"))[:120]
    clean["tagline"] = str(clean.get("tagline", "منصة طلاب سوريا"))[:200]
    clean["background"] = str(clean.get("background", "#031613"))[:40]
    clean["accent"] = str(clean.get("accent", "#43e36b"))[:40]
    clean["elements"] = clean.get("elements", [])[:100] if isinstance(clean.get("elements"), list) else []
    SITE_CONFIG_FILE.write_text(json.dumps(clean, ensure_ascii=False, indent=2), encoding="utf-8")
    return clean


@app.get("/")
def home():
    return render_template("index.html", config=load_config())


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    status = 200
    if request.method == "POST":
        if auth_rate_limited("register", 5, 3600):
            return render_template("account_auth.html", mode="register", error="محاولات كثيرة. حاول مرة أخرى بعد قليل."), 429
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        share_email = request.form.get("share_email") == "on"
        if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            error, status = "أدخل بريداً إلكترونياً صالحاً.", 400
        elif not share_email:
            error, status = "لإنشاء الحساب، يجب الموافقة على إظهار بريدك الإلكتروني لمالك الموقع في لوحة التحكم.", 400
        elif len(password) < 12 or len(password) > 256:
            error, status = "يجب أن تكون كلمة المرور بين 12 و256 حرفاً.", 400
        elif password != confirm_password:
            error, status = "كلمتا المرور غير متطابقتين.", 400
        else:
            created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            consented_at = created_at
            try:
                with auth_db() as connection:
                    cursor = connection.execute(
                        "INSERT INTO accounts (email, password_hash, share_email, share_email_consented_at, created_at) VALUES (?, ?, 1, ?, ?)",
                        (email, generate_password_hash(password), consented_at, created_at),
                    )
                    user_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                error, status = "يوجد حساب بهذا البريد الإلكتروني بالفعل.", 409
            else:
                session.clear()
                session["user_id"] = user_id
                session.permanent = True
                return redirect(url_for("account", created=1))
    return render_template("account_auth.html", mode="register", error=error), status


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    status = 200
    if request.method == "POST":
        if auth_rate_limited("login", 10, 900):
            return render_template("account_auth.html", mode="login", error="محاولات كثيرة. حاول مرة أخرى بعد 15 دقيقة."), 429
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with auth_db() as connection:
            user = connection.execute("SELECT id, password_hash FROM accounts WHERE email = ?", (email,)).fetchone()
        if user and user["password_hash"] and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(url_for("account"))
        error, status = "البريد الإلكتروني أو كلمة المرور غير صحيحة.", 401
    return render_template("account_auth.html", mode="login", error=error), status


def google_userinfo_from_code(code):
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", "").strip() or url_for(
        "google_callback", _external=True
    )
    token_data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }).encode("utf-8")
    token_request = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=token_data,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(token_request, timeout=10) as response:
        token_payload = json.loads(response.read().decode("utf-8"))
    access_token = token_payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise ValueError("Google did not return an access token")
    userinfo_request = urllib.request.Request(
        "https://openidconnect.googleapis.com/v1/userinfo",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(userinfo_request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


@app.post("/auth/google")
def google_auth_start():
    if not (os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET")):
        return render_template(
            "account_auth.html", mode="login", error="تسجيل Google غير مهيأ بعد."
        ), 503
    if request.form.get("share_email") != "on":
        return render_template(
            "account_auth.html", mode="login",
            error="للمتابعة عبر Google، وافق على إظهار بريدك الإلكتروني لمالك الموقع.",
        ), 400
    if auth_rate_limited("google_auth_start", 10, 900):
        return render_template(
            "account_auth.html", mode="login", error="محاولات كثيرة. حاول مرة أخرى بعد 15 دقيقة."
        ), 429

    state = secrets.token_urlsafe(32)
    session["google_oauth_state"] = state
    session["google_oauth_share_email"] = True
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", "").strip() or url_for(
        "google_callback", _external=True
    )
    params = urllib.parse.urlencode({
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email",
        "state": state,
        "prompt": "select_account",
    })
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + params)


@app.get("/auth/google/callback")
def google_callback():
    expected_state = session.pop("google_oauth_state", None)
    share_email = session.pop("google_oauth_share_email", False)
    returned_state = request.args.get("state", "")
    if not expected_state or not returned_state or not hmac.compare_digest(expected_state, returned_state):
        abort(400, description="تعذر التحقق من طلب تسجيل Google. أعد المحاولة.")
    if request.args.get("error"):
        return render_template(
            "account_auth.html", mode="login", error="تم إلغاء تسجيل الدخول عبر Google."
        ), 400
    code = request.args.get("code", "")
    if not code or not share_email:
        return render_template(
            "account_auth.html", mode="login", error="تعذر إكمال تسجيل الدخول عبر Google."
        ), 400
    if not (os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET")):
        return render_template(
            "account_auth.html", mode="login", error="تسجيل Google غير مهيأ بعد."
        ), 503

    try:
        profile = google_userinfo_from_code(code)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        app.logger.warning("Google sign-in failed (%s)", type(exc).__name__)
        return render_template(
            "account_auth.html", mode="login", error="تعذر التحقق من حساب Google. حاول مرة أخرى."
        ), 502
    if not isinstance(profile, dict):
        return render_template(
            "account_auth.html", mode="login", error="أعاد Google بيانات غير صالحة."
        ), 502
    email = str(profile.get("email", "")).strip().lower()
    google_sub = str(profile.get("sub", "")).strip()
    verified = profile.get("email_verified") is True or profile.get("email_verified") == "true"
    if (
        not verified or not google_sub or len(google_sub) > 255
        or len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
    ):
        return render_template(
            "account_auth.html", mode="login", error="لم يؤكد Google ملكية البريد الإلكتروني."
        ), 403

    consented_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with auth_db() as connection:
            user = connection.execute(
                "SELECT id, email, google_sub FROM accounts WHERE google_sub = ?",
                (google_sub,),
            ).fetchone()
            if user:
                conflicting = connection.execute(
                    "SELECT id FROM accounts WHERE email = ? AND id != ?",
                    (email, user["id"]),
                ).fetchone()
                if conflicting:
                    return render_template(
                        "account_auth.html", mode="login",
                        error="تعذر ربط البريد بحساب موجود. تواصل مع مالك الموقع.",
                    ), 409
                connection.execute(
                    "UPDATE accounts SET email = ?, share_email = 1, share_email_consented_at = ? WHERE id = ?",
                    (email, consented_at, user["id"]),
                )
                user_id = user["id"]
            else:
                user = connection.execute(
                    "SELECT id, google_sub FROM accounts WHERE email = ?",
                    (email,),
                ).fetchone()
                if user:
                    if user["google_sub"] not in (None, google_sub):
                        return render_template(
                            "account_auth.html", mode="login",
                            error="تعذر ربط حساب Google بهذا البريد. تواصل مع مالك الموقع.",
                        ), 409
                    connection.execute(
                        "UPDATE accounts SET google_sub = ?, share_email = 1, share_email_consented_at = ? WHERE id = ?",
                        (google_sub, consented_at, user["id"]),
                    )
                    user_id = user["id"]
                else:
                    cursor = connection.execute(
                        "INSERT INTO accounts (email, password_hash, share_email, share_email_consented_at, created_at, google_sub) "
                        "VALUES (?, '', 1, ?, ?, ?)",
                        (email, consented_at, consented_at, google_sub),
                    )
                    user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return render_template(
            "account_auth.html", mode="login",
            error="يوجد حساب مرتبط بهذه البيانات. سجّل الدخول بالطريقة التي استخدمتها أول مرة.",
        ), 409

    session.clear()
    session["user_id"] = user_id
    session.permanent = True
    return redirect(url_for("account"))


@app.route("/account", methods=["GET", "POST"])
def account():
    user = account_by_id(session.get("user_id"))
    if user is None:
        session.pop("user_id", None)
        return redirect(url_for("login"))
    if request.method == "POST":
        share_email = request.form.get("share_email") == "on"
        consented_at = datetime.now(timezone.utc).isoformat(timespec="seconds") if share_email else None
        with auth_db() as connection:
            connection.execute(
                "UPDATE accounts SET share_email = ?, share_email_consented_at = ? WHERE id = ?",
                (int(share_email), consented_at, user["id"]),
            )
        return redirect(url_for("account", updated=1))
    return render_template("account.html", user=user, created=request.args.get("created") == "1", updated=request.args.get("updated") == "1")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    password = get_admin_password()
    if request.method == "POST":
        entered = request.form.get("password", "")
        if password and hmac.compare_digest(entered, password):
            session.clear()
            session["admin_authenticated"] = True
            session.permanent = True
            return redirect(url_for("admin"))
        error = "كلمة المرور غير صحيحة"
    return render_template("admin_login.html", error=error, configured=bool(password))


@app.post("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.get("/admin")
def admin():
    return render_template("admin.html", config=load_config())


@app.get("/admin/users")
def admin_users():
    with auth_db() as connection:
        users = connection.execute(
            "SELECT email, share_email_consented_at, created_at, "
            "CASE WHEN google_sub IS NULL THEN 'البريد وكلمة المرور' ELSE 'Google' END AS sign_in_method "
            "FROM accounts WHERE share_email = 1 ORDER BY id DESC"
        ).fetchall()
    return render_template("admin_users.html", users=users)


@app.get("/api/site-config")
def get_site_config():
    return jsonify(load_config())


@app.post("/api/site-config")
def update_site_config():
    payload = request.get_json(silent=True) or {}
    return jsonify(save_config(payload))


@app.post("/api/upload")
def upload_image():
    image = request.files.get("image")
    if not image or not image.filename:
        return jsonify({"error": "لم يتم اختيار صورة"}), 400
    extension = Path(secure_filename(image.filename)).suffix.lower()
    if extension not in {".jpg", ".jpeg", ".png", ".webp", ".gif"}:
        return jsonify({"error": "نوع الصورة غير مدعوم"}), 400
    filename = uuid.uuid4().hex + extension
    image.save(UPLOAD_DIR / filename)
    return jsonify({"url": url_for("static", filename="uploads/" + filename)})


EXAM_API_BASE_URL = os.environ.get("EXAM_API_BASE_URL", "https://examresult.edu-access.net").rstrip("/")
EXAM_RESULTS_PATH = os.environ.get("EXAM_RESULTS_PATH", "/directorateResultsNew/")

def _rows_from_upstream(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("results", "data", "items", "rows", "result"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                return [value]
        return [payload]
    return []

def _normalize_upstream_row(row):
    if not isinstance(row, dict):
        return {"name": str(row)}
    normalized = dict(row)
    aliases = {
        "name": ("name", "student_name", "full_name"),
        "seat_number": ("seat_number", "number", "student_number", "subscription_number"),
        "branch": ("branch", "programme", "program", "examination_programme"),
        "stage": ("stage", "class_name", "class"),
        "governorate": ("governorate", "directorate_name", "governorate_name"),
        "total": ("total", "final_mark", "exam_mark", "result"),
        "max": ("max", "max_mark", "certificate_total"),
    }
    for target, keys in aliases.items():
        if normalized.get(target) in (None, ""):
            for key in keys:
                if normalized.get(key) not in (None, ""):
                    normalized[target] = normalized[key]
                    break
    return normalized

def _fetch_upstream_results(filters):
    api_filters = dict(filters)
    alias_map = {
        "branch": "examination_programme",
        "stage": "class_name",
        "governorate": "directorate_name",
    }
    for source, target in alias_map.items():
        if filters.get(source):
            api_filters[target] = filters[source]
    query = urllib.parse.urlencode({key: value for key, value in api_filters.items() if value})
    url = EXAM_API_BASE_URL + "/" + EXAM_RESULTS_PATH.lstrip("/")
    if query:
        url += "?" + query
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "natayejna-site/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return [_normalize_upstream_row(row) for row in _rows_from_upstream(payload)], None
    except urllib.error.HTTPError as exc:
        return [], f"خدمة النتائج أعادت الحالة {exc.code}"
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return [], f"تعذر الاتصال بخدمة النتائج: {exc}"

@app.get("/api/results")
def results():
    filters = {
        "number": request.args.get("number", "").strip(),
        "branch": request.args.get("branch", "").strip(),
        "stage": request.args.get("stage", "").strip(),
        "governorate": request.args.get("governorate", "").strip(),
        "exam_year": request.args.get("exam_year", "").strip(),
        "examination_period_id": request.args.get("examination_period_id", "").strip(),
        "birth_date": request.args.get("birth_date", "").strip(),
    }
    rows, error = _fetch_upstream_results(filters)
    if error:
        return jsonify({"error": error}), 502
    return jsonify(rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

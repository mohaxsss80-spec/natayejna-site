from flask import Flask, render_template, jsonify, request, url_for, redirect, session
import json
import os
import uuid
import hmac
import secrets
from pathlib import Path
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE = Path(__file__).resolve().parent
DATA_DIR = BASE / "data"
DATA_FILE = DATA_DIR / "results.json"
SITE_CONFIG_FILE = DATA_DIR / "site_config.json"
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


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    password = get_admin_password()
    if request.method == "POST":
        entered = request.form.get("password", "")
        if password and hmac.compare_digest(entered, password):
            session["admin_authenticated"] = True
            return redirect(url_for("admin"))
        error = "كلمة المرور غير صحيحة"
    return render_template("admin_login.html", error=error, configured=bool(password))


@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.get("/admin")
def admin():
    return render_template("admin.html", config=load_config())


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


@app.get("/api/results")
def results():
    number = request.args.get("number", "").strip()
    branch = request.args.get("branch", "").strip()
    stage = request.args.get("stage", "").strip()
    governorate = request.args.get("governorate", "").strip()

    rows = load_results()
    if number:
        rows = [r for r in rows if r.get("seat_number", "") == number]
    if branch:
        rows = [r for r in rows if r.get("branch", "") == branch]
    if stage:
        rows = [r for r in rows if r.get("stage", "") == stage]
    if governorate:
        rows = [r for r in rows if r.get("governorate", "") == governorate]
    return jsonify(rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

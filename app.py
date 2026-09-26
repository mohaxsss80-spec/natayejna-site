from flask import Flask, render_template, jsonify, request, url_for
import json
import os
import uuid
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

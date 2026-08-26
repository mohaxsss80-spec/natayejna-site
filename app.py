from flask import Flask, render_template, jsonify, request
import json
from pathlib import Path

app = Flask(__name__)
BASE = Path(__file__).resolve().parent.parent
DATA_FILE = BASE / "data" / "results.json"

def load_results():
    try:
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []

@app.get("/")
def home():
    return render_template("index.html")

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

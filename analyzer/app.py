"""Analyst dashboard: reads the enriched alerts SQLite DB (built by cli.py)
and renders it as a web page a non-technical stakeholder can skim.

Run: python analyzer/app.py
"""

from __future__ import annotations

import json
import os

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, url_for

import db

load_dotenv()

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "alerts.db"))

app = Flask(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


@app.route("/")
def index():
    with db.connect(DB_PATH) as conn:
        alerts = db.all_alerts(conn)

    severity_filter = request.args.get("severity")
    status_filter = request.args.get("status", "all")

    rows = [dict(a) for a in alerts]
    if severity_filter:
        rows = [r for r in rows if r["llm_severity"] == severity_filter]
    if status_filter != "all":
        rows = [r for r in rows if r["status"] == status_filter]

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for a in alerts:
        if a["llm_severity"] in counts:
            counts[a["llm_severity"]] += 1

    return render_template(
        "index.html",
        alerts=rows,
        counts=counts,
        severity_order=SEVERITY_ORDER,
        active_severity=severity_filter,
        active_status=status_filter,
        total_raw_events=sum(a["count"] for a in alerts),
    )


@app.route("/alert/<path:group_key>")
def detail(group_key):
    with db.connect(DB_PATH) as conn:
        alert = db.get_alert(conn, group_key)
        if alert is None:
            return "Not found", 404
        alert = dict(alert)
        alert["sample_events"] = json.dumps(json.loads(alert["sample_events"]), indent=2)

    return render_template("detail.html", alert=alert)


@app.route("/alert/<path:group_key>/status", methods=["POST"])
def update_status(group_key):
    new_status = request.form.get("status", "new")
    with db.connect(DB_PATH) as conn:
        db.set_status(conn, group_key, new_status)
    return redirect(url_for("detail", group_key=group_key))


if __name__ == "__main__":
    app.run(debug=True, port=5050)

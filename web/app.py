from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
WEB_DIR = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder=str(WEB_DIR / "templates"),
    static_folder=str(WEB_DIR / "static"),
)


def default_status() -> dict[str, Any]:
    return {
        "running": False,
        "mode": "demo",
        "interface": "not-started",
        "packet_count": 0,
        "alert_count": 0,
        "device_count": 0,
        "last_update": "",
        "message": "Dashboard ready. Run main.py to start monitoring.",
        "error": "",
    }


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []

    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            return list(reader)
    except (csv.Error, OSError):
        return []


def load_json(path: Path, default_payload: Any) -> Any:
    if not path.exists():
        return default_payload

    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError):
        return default_payload


def tail(items: list[Any], limit: int) -> list[Any]:
    return list(reversed(items[-limit:]))


def build_dashboard_payload() -> dict[str, Any]:
    status = load_json(DATA_DIR / "status.json", default_status())
    devices = load_json(DATA_DIR / "devices.json", [])
    alerts = load_csv_rows(DATA_DIR / "alerts.csv")
    traffic_logs = load_csv_rows(DATA_DIR / "traffic_logs.csv")
    activity_logs = load_json(DATA_DIR / "activity_logs.json", [])

    protocol_breakdown = Counter(
        row.get("protocol", "Unknown") or "Unknown" for row in traffic_logs
    )
    top_sources = Counter(
        (row.get("src_ip") or row.get("src_mac") or "unknown") for row in traffic_logs
    )
    alert_type_breakdown = Counter(
        row.get("alert_type", "Unknown") or "Unknown" for row in alerts
    )
    severity_breakdown = Counter(
        row.get("severity", "Unknown") or "Unknown" for row in alerts
    )

    total_bytes = 0
    for row in traffic_logs:
        try:
            total_bytes += int(row.get("length", 0) or 0)
        except ValueError:
            continue

    stats = {
        "total_packets": len(traffic_logs),
        "total_alerts": len(alerts),
        "trusted_devices": sum(1 for device in devices if device.get("trusted")),
        "untrusted_devices": sum(1 for device in devices if not device.get("trusted")),
        "total_bytes": total_bytes,
        "protocol_breakdown": dict(protocol_breakdown),
        "top_sources": dict(top_sources.most_common(5)),
        "alert_type_breakdown": dict(alert_type_breakdown),
        "severity_breakdown": dict(severity_breakdown),
    }

    return {
        "status": status,
        "devices": devices,
        "alerts": tail(alerts, 20),
        "traffic_logs": tail(traffic_logs, 20),
        "activity_logs": tail(activity_logs, 20),
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": stats,
    }


@app.route("/")
def dashboard() -> str:
    payload = build_dashboard_payload()
    return render_template("dashboard.html", payload=payload)


@app.route("/api/dashboard-data")
def dashboard_data() -> Any:
    return jsonify(build_dashboard_payload())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

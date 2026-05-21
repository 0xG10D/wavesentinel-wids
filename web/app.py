from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request


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
        "mode": "live",
        "interface": "not-started",
        "channel_lock": "",
        "current_channel": "",
        "target_bssid": "",
        "target_essid": "",
        "packet_count": 0,
        "alert_count": 0,
        "ap_count": 0,
        "client_count": 0,
        "severity_counts": {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        },
        "attack_counts": {},
        "frame_counters": {
            "deauth": 0,
            "disassoc": 0,
            "beacon": 0,
            "probe": 0,
        },
        "last_update": "",
        "message": "Dashboard ready. Start live monitoring with main.py.",
        "error": "",
    }


def default_devices() -> dict[str, Any]:
    return {
        "access_points": [],
        "clients": [],
        "summary": {
            "access_point_count": 0,
            "client_count": 0,
        },
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


def normalize_text(value: str | None) -> str:
    return str(value or "").strip()


def normalize_mac(value: str | None) -> str:
    text = normalize_text(value).replace("-", ":").upper()
    while "::" in text:
        text = text.replace("::", ":")
    return text


def tail(items: list[Any], limit: int) -> list[Any]:
    return list(reversed(items[-limit:]))


def read_filters(args: Any) -> dict[str, str]:
    return {
        "severity": normalize_text(args.get("severity")),
        "bssid": normalize_text(args.get("bssid")),
        "essid": normalize_text(args.get("essid")),
        "attack_type": normalize_text(args.get("attack_type")),
    }


def matches_alert(alert: dict[str, Any], filters: dict[str, str]) -> bool:
    severity = filters["severity"].upper()
    bssid = normalize_mac(filters["bssid"])
    essid = filters["essid"]
    attack_type = filters["attack_type"]

    if severity and str(alert.get("severity", "")).upper() != severity:
        return False
    if attack_type and str(alert.get("attack_type", "")) != attack_type:
        return False
    if bssid:
        alert_candidates = {
            normalize_mac(alert.get("bssid")),
            normalize_mac(alert.get("source")),
            normalize_mac(alert.get("destination")),
        }
        if bssid not in alert_candidates:
            return False
    if essid and str(alert.get("essid", "")) != essid:
        return False
    return True


def matches_traffic(row: dict[str, Any], filters: dict[str, str]) -> bool:
    bssid = normalize_mac(filters["bssid"])
    essid = filters["essid"]

    if bssid:
        traffic_candidates = {
            normalize_mac(row.get("bssid")),
            normalize_mac(row.get("src_mac")),
            normalize_mac(row.get("dst_mac")),
            normalize_mac(row.get("transmitter")),
            normalize_mac(row.get("receiver")),
        }
        if bssid not in traffic_candidates:
            return False
    if essid and str(row.get("essid", "")) != essid:
        return False
    return True


def matches_access_point(record: dict[str, Any], filters: dict[str, str]) -> bool:
    bssid = normalize_mac(filters["bssid"])
    essid = filters["essid"]

    if bssid and normalize_mac(record.get("bssid")) != bssid:
        return False
    if essid and str(record.get("essid", "")) != essid:
        return False
    return True


def matches_client(record: dict[str, Any], filters: dict[str, str]) -> bool:
    bssid = normalize_mac(filters["bssid"])
    essid = filters["essid"]

    if bssid:
        client_candidates = {
            normalize_mac(record.get("associated_bssid")),
            normalize_mac(record.get("client_mac")),
        }
        if bssid not in client_candidates:
            return False
    if essid and str(record.get("associated_essid", "")) != essid:
        return False
    return True


def build_dashboard_payload(filters: dict[str, str]) -> dict[str, Any]:
    status = load_json(DATA_DIR / "status.json", default_status())
    devices = load_json(DATA_DIR / "devices.json", default_devices())
    alerts = load_json(DATA_DIR / "alerts.json", [])
    if not alerts:
        alerts = load_csv_rows(DATA_DIR / "alerts.csv")
    traffic_logs = load_csv_rows(DATA_DIR / "traffic_logs.csv")
    activity_logs = load_json(DATA_DIR / "activity_logs.json", [])

    filtered_alerts = [alert for alert in alerts if matches_alert(alert, filters)]
    filtered_traffic = [row for row in traffic_logs if matches_traffic(row, filters)]
    filtered_access_points = [
        record
        for record in devices.get("access_points", [])
        if matches_access_point(record, filters)
    ]
    filtered_clients = [
        record
        for record in devices.get("clients", [])
        if matches_client(record, filters)
    ]

    severity_breakdown = Counter(
        str(alert.get("severity", "Unknown") or "Unknown") for alert in filtered_alerts
    )
    attack_breakdown = Counter(
        str(alert.get("attack_type", "Unknown") or "Unknown") for alert in filtered_alerts
    )
    high_severity_alerts = [
        alert
        for alert in filtered_alerts
        if str(alert.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
    ]

    attack_type_options = sorted(
        {
            str(alert.get("attack_type", "")).strip()
            for alert in alerts
            if str(alert.get("attack_type", "")).strip()
        }
    )

    return {
        "status": status,
        "devices": {
            "access_points": filtered_access_points,
            "clients": filtered_clients,
            "summary": {
                "access_point_count": len(filtered_access_points),
                "client_count": len(filtered_clients),
            },
        },
        "alerts": tail(filtered_alerts, 50),
        "recent_high_alerts": tail(high_severity_alerts, 10),
        "traffic_logs": tail(filtered_traffic, 50),
        "activity_logs": tail(activity_logs, 30),
        "stats": {
            "severity_breakdown": dict(severity_breakdown),
            "attack_breakdown": dict(attack_breakdown),
            "access_point_count": len(filtered_access_points),
            "client_count": len(filtered_clients),
            "high_alert_count": len(high_severity_alerts),
        },
        "filters": filters,
        "filter_options": {
            "severity": ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "attack_types": attack_type_options,
        },
        "last_updated": status.get("last_update") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.route("/")
def dashboard() -> str:
    payload = build_dashboard_payload(read_filters(request.args))
    return render_template("dashboard.html", payload=payload)


@app.route("/api/dashboard-data")
def dashboard_data() -> Any:
    return jsonify(build_dashboard_payload(read_filters(request.args)))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

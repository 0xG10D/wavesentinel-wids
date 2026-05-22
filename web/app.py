from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, render_template, request, send_from_directory

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
WEB_DIR = Path(__file__).resolve().parent

DOWNLOADABLE_FILES = {
    "alerts.csv",
    "alerts.json",
    "traffic_logs.csv",
    "devices.json",
    "status.json",
    "activity_logs.json",
}

BRANDING = {
    "project_name": "WaveSentinel",
    "full_title": "WaveSentinel: Real-Time 802.11 Wireless Intrusion Detection Dashboard",
    "dashboard_title": "WaveSentinel Dashboard",
    "dashboard_subtitle": "Real-Time 802.11 Wireless Threat Monitoring",
    "tool_name": "WaveSentinel WIDS",
    "description": (
        "WaveSentinel provides real-time wireless monitoring for authorized lab and "
        "defensive environments using monitor-mode packet capture, alert correlation, "
        "and dashboard-based visibility."
    ),
}

app = Flask(
    __name__,
    template_folder=str(WEB_DIR / "templates"),
    static_folder=str(WEB_DIR / "static"),
)
app.json.sort_keys = False


def default_status() -> dict[str, Any]:
    return {
        "running": False,
        "state": "Stopped",
        "mode": "live",
        "pid": None,
        "requested_interface": "",
        "interface": "not-started",
        "interface_mode": "",
        "interface_resolution": "",
        "channel_lock": "",
        "current_channel": "",
        "target_bssid": "",
        "target_essid": "",
        "session_started_at": "",
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
        "advisories": [],
        "troubleshooting": [],
        "last_update": "",
        "message": "WaveSentinel ready. Start live monitoring with main.py.",
        "error": "",
    }


def default_devices() -> dict[str, Any]:
    return {
        "access_points": [],
        "clients": [],
    }


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []

    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            rows: list[dict[str, str]] = []
            for raw_row in reader:
                if not isinstance(raw_row, dict):
                    continue
                clean_row = {
                    str(key): value
                    for key, value in raw_row.items()
                    if key is not None
                }
                rows.append(clean_row)
            return rows
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


def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def normalize_mac(value: Any) -> str:
    text = normalize_text(value).replace("-", ":").upper()
    while "::" in text:
        text = text.replace("::", ":")
    return text


def normalize_channel(value: Any) -> str:
    text = normalize_text(value)
    if not text:
        return ""
    try:
        return str(int(float(text)))
    except ValueError:
        return text


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def sanitize_mapping(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    return {
        str(key): value
        for key, value in payload.items()
        if key is not None
    }


def tail(items: list[Any], limit: int) -> list[Any]:
    return list(reversed(items[-limit:]))


def make_json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for key, item in value.items():
            label = normalize_text(key) or "Unknown"
            safe[label] = make_json_safe(item)
        return safe
    if isinstance(value, list):
        return [make_json_safe(item) for item in value]
    if isinstance(value, tuple) or isinstance(value, set):
        return [make_json_safe(item) for item in value]
    return value


def normalize_counter(payload: Any, expected_keys: list[str] | None = None) -> dict[str, int]:
    result: dict[str, int] = {}
    if isinstance(payload, dict):
        for key, value in payload.items():
            label = normalize_text(key) or "Unknown"
            result[label] = safe_int(value)
    if expected_keys is not None:
        normalized = {key: result.get(key, 0) for key in expected_keys}
        return normalized
    return result


def normalize_string_list(payload: Any) -> list[str]:
    if isinstance(payload, list):
        return [normalize_text(item) for item in payload if normalize_text(item)]
    if isinstance(payload, str):
        return [item.strip() for item in payload.split(",") if item.strip()]
    return []


def normalize_status_payload(payload: Any) -> dict[str, Any]:
    normalized = default_status()
    source = sanitize_mapping(payload)

    if not source:
        return normalized

    if "monitoring" in source and "running" not in source:
        source["running"] = bool(source["monitoring"])
    if source.get("last_updated") and not source.get("last_update"):
        source["last_update"] = source["last_updated"]
    if source.get("device_count") and not source.get("client_count"):
        source["client_count"] = source["device_count"]

    for key in (
        "state",
        "mode",
        "requested_interface",
        "interface",
        "interface_mode",
        "interface_resolution",
        "channel_lock",
        "current_channel",
        "target_bssid",
        "target_essid",
        "session_started_at",
        "last_update",
        "message",
        "error",
    ):
        if key in source:
            normalized[key] = normalize_text(source.get(key))

    normalized["running"] = bool(source.get("running", normalized["running"]))
    if not normalized["state"]:
        normalized["state"] = "Running" if normalized["running"] else "Stopped"
    normalized["pid"] = source.get("pid")
    normalized["packet_count"] = safe_int(source.get("packet_count"))
    normalized["alert_count"] = safe_int(source.get("alert_count"))
    normalized["ap_count"] = safe_int(source.get("ap_count"))
    normalized["client_count"] = safe_int(source.get("client_count"))
    normalized["severity_counts"] = normalize_counter(
        source.get("severity_counts"),
        expected_keys=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    )
    normalized["attack_counts"] = normalize_counter(source.get("attack_counts"))
    normalized["frame_counters"] = normalize_counter(
        source.get("frame_counters"),
        expected_keys=["deauth", "disassoc", "beacon", "probe"],
    )
    normalized["advisories"] = normalize_advisories(source.get("advisories"))
    normalized["troubleshooting"] = normalize_string_list(source.get("troubleshooting"))
    return normalized


def normalize_access_point_record(payload: Any) -> dict[str, Any]:
    source = sanitize_mapping(payload)
    return {
        "bssid": normalize_mac(source.get("bssid") or source.get("mac_address")),
        "essid": normalize_text(source.get("essid")),
        "channel": normalize_channel(source.get("channel")),
        "security": normalize_text(source.get("security")) or "UNKNOWN",
        "first_seen": normalize_text(source.get("first_seen")),
        "last_seen": normalize_text(source.get("last_seen")),
        "frame_count": safe_int(source.get("frame_count") or source.get("packet_count")),
        "beacon_count": safe_int(source.get("beacon_count")),
        "client_count": safe_int(source.get("client_count")),
        "rssi": normalize_text(source.get("rssi") or source.get("last_signal_dbm")),
    }


def normalize_client_record(payload: Any) -> dict[str, Any]:
    source = sanitize_mapping(payload)
    ip_address = normalize_text(source.get("ip_address"))
    src_ips = normalize_string_list(source.get("src_ips"))
    if ip_address and not src_ips:
        src_ips = [ip_address]
    return {
        "client_mac": normalize_mac(source.get("client_mac") or source.get("mac_address")),
        "associated_bssid": normalize_mac(source.get("associated_bssid")),
        "associated_essid": normalize_text(source.get("associated_essid")),
        "first_seen": normalize_text(source.get("first_seen")),
        "last_seen": normalize_text(source.get("last_seen")),
        "frame_count": safe_int(source.get("frame_count") or source.get("packet_count")),
        "probe_request_count": safe_int(source.get("probe_request_count")),
        "probe_essids": normalize_string_list(source.get("probe_essids")),
        "src_ips": src_ips,
        "rssi": normalize_text(source.get("rssi") or source.get("last_signal_dbm")),
    }


def normalize_devices_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, list):
        normalized_clients = []
        for item in payload:
            client = normalize_client_record(item)
            if client["client_mac"]:
                normalized_clients.append(client)
        return {
            "access_points": [],
            "clients": normalized_clients,
        }

    source = sanitize_mapping(payload)
    access_points = source.get("access_points", [])
    clients = source.get("clients", [])

    normalized_access_points: list[dict[str, Any]] = []
    if isinstance(access_points, list):
        for item in access_points:
            record = normalize_access_point_record(item)
            if record["bssid"]:
                normalized_access_points.append(record)

    normalized_clients: list[dict[str, Any]] = []
    if isinstance(clients, list):
        for item in clients:
            record = normalize_client_record(item)
            if record["client_mac"]:
                normalized_clients.append(record)

    return {
        "access_points": normalized_access_points,
        "clients": normalized_clients,
    }


def normalize_alert_record(payload: Any) -> dict[str, Any]:
    source = sanitize_mapping(payload)
    attack_type = normalize_text(source.get("attack_type") or source.get("alert_type"))
    return {
        "timestamp": normalize_text(source.get("timestamp")),
        "severity": normalize_text(source.get("severity")).upper() or "LOW",
        "attack_type": attack_type or "Unknown Alert",
        "alert_type": attack_type or "Unknown Alert",
        "source": normalize_text(source.get("source")),
        "destination": normalize_text(source.get("destination")),
        "bssid": normalize_mac(source.get("bssid")),
        "essid": normalize_text(source.get("essid")),
        "channel": normalize_channel(source.get("channel")),
        "packet_count": safe_int(source.get("packet_count"), default=1),
        "details": normalize_text(source.get("details")),
        "mitre_tactic": normalize_text(source.get("mitre_tactic")) or "N/A",
        "mitre_technique": normalize_text(source.get("mitre_technique")) or "N/A",
    }


def normalize_alert_rows(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        return []
    alerts = []
    for item in payload:
        alert = normalize_alert_record(item)
        if alert["timestamp"] or alert["attack_type"] != "Unknown Alert":
            alerts.append(alert)
    return alerts


def normalize_traffic_record(payload: Any) -> dict[str, Any]:
    source = sanitize_mapping(payload)
    frame_type = (
        normalize_text(source.get("frame_type") or source.get("frame_class")) or "Unknown"
    )
    frame_subtype = (
        normalize_text(source.get("frame_subtype") or source.get("wireless_subtype"))
        or frame_type
    )
    return {
        "timestamp": normalize_text(source.get("timestamp")),
        "frame_type": frame_type,
        "frame_subtype": frame_subtype,
        "bssid": normalize_mac(source.get("bssid")),
        "essid": normalize_text(source.get("essid")),
        "source": normalize_text(
            source.get("source") or source.get("src_ip") or source.get("src_mac")
        ),
        "destination": normalize_text(
            source.get("destination") or source.get("dst_ip") or source.get("dst_mac")
        ),
        "channel": normalize_channel(source.get("channel")),
        "rssi": normalize_text(source.get("rssi") or source.get("signal_dbm")),
    }


def normalize_traffic_rows(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        return []
    rows = []
    for item in payload:
        row = normalize_traffic_record(item)
        if any(row.values()):
            rows.append(row)
    return rows


def normalize_activity_record(payload: Any) -> dict[str, str]:
    source = sanitize_mapping(payload)
    return {
        "timestamp": normalize_text(source.get("timestamp")),
        "level": normalize_text(source.get("level")).upper() or "INFO",
        "message": normalize_text(source.get("message")),
    }


def normalize_activity_rows(payload: Any) -> list[dict[str, str]]:
    if not isinstance(payload, list):
        return []
    rows = []
    for item in payload:
        row = normalize_activity_record(item)
        if row["timestamp"] or row["message"]:
            rows.append(row)
    return rows


def normalize_advisories(payload: Any) -> list[dict[str, str]]:
    if not isinstance(payload, list):
        return []
    rows = []
    for item in payload:
        source = sanitize_mapping(item)
        message = normalize_text(source.get("message"))
        if not message:
            continue
        rows.append(
            {
                "severity": normalize_text(source.get("severity")).upper() or "LOW",
                "message": message,
            }
        )
    return rows


def sort_channels(values: set[str]) -> list[str]:
    def channel_key(value: str) -> tuple[int, Any]:
        try:
            return (0, int(value))
        except ValueError:
            return (1, value)

    return sorted((value for value in values if value), key=channel_key)


def read_filters(args: Any) -> dict[str, str]:
    return {
        "severity": normalize_text(args.get("severity")),
        "bssid": normalize_text(args.get("bssid")),
        "essid": normalize_text(args.get("essid")),
        "attack_type": normalize_text(args.get("attack_type")),
        "channel": normalize_channel(args.get("channel")),
    }


def matches_alert(alert: dict[str, Any], filters: dict[str, str]) -> bool:
    severity = filters["severity"].upper()
    bssid = normalize_mac(filters["bssid"])
    essid = filters["essid"]
    attack_type = filters["attack_type"]
    channel = filters["channel"]

    if severity and str(alert.get("severity", "")).upper() != severity:
        return False
    if attack_type and str(alert.get("attack_type", "")) != attack_type:
        return False
    if channel and normalize_channel(alert.get("channel")) != channel:
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
    channel = filters["channel"]

    if channel and normalize_channel(row.get("channel")) != channel:
        return False
    if bssid:
        traffic_candidates = {
            normalize_mac(row.get("bssid")),
            normalize_mac(row.get("source")),
            normalize_mac(row.get("destination")),
        }
        if bssid not in traffic_candidates:
            return False
    if essid and str(row.get("essid", "")) != essid:
        return False
    return True


def matches_access_point(record: dict[str, Any], filters: dict[str, str]) -> bool:
    bssid = normalize_mac(filters["bssid"])
    essid = filters["essid"]
    channel = filters["channel"]

    if bssid and normalize_mac(record.get("bssid")) != bssid:
        return False
    if essid and str(record.get("essid", "")) != essid:
        return False
    if channel and normalize_channel(record.get("channel")) != channel:
        return False
    return True


def matches_client(
    record: dict[str, Any],
    filters: dict[str, str],
    ap_channel_by_bssid: dict[str, str],
) -> bool:
    bssid = normalize_mac(filters["bssid"])
    essid = filters["essid"]
    channel = filters["channel"]

    if bssid:
        client_candidates = {
            normalize_mac(record.get("associated_bssid")),
            normalize_mac(record.get("client_mac")),
        }
        if bssid not in client_candidates:
            return False
    if essid and str(record.get("associated_essid", "")) != essid:
        return False
    if channel:
        client_channel = ap_channel_by_bssid.get(
            normalize_mac(record.get("associated_bssid")),
            "",
        )
        if normalize_channel(client_channel) != channel:
            return False
    return True


def build_summary_view(
    status: dict[str, Any],
    alerts: list[dict[str, Any]],
    devices: dict[str, Any],
    stats: dict[str, Any],
) -> dict[str, Any]:
    critical_count = sum(
        1
        for alert in alerts
        if alert["severity"] in {"HIGH", "CRITICAL"}
    )
    warning_count = sum(
        1
        for alert in alerts
        if alert["severity"] in {"LOW", "MEDIUM"}
    )

    if status["error"]:
        overall_level = "CRITICAL"
        overall_message = "WaveSentinel hit an error and needs operator attention."
    elif critical_count:
        overall_level = "CRITICAL"
        overall_message = "High-risk wireless activity was detected in the monitored airspace."
    elif warning_count or status["troubleshooting"] or not status["running"]:
        overall_level = "WARNING"
        overall_message = "The monitor needs review or there are lower-risk issues nearby."
    else:
        overall_level = "SAFE"
        overall_message = (
            "Your Wi-Fi monitor is running and no high-risk attack is currently flagged."
        )

    attack_types = {alert["attack_type"] for alert in alerts}
    advisories = [item["message"] for item in status.get("advisories", [])]

    explanations = [
        (
            "Monitoring is running."
            if status["running"]
            else "Monitoring is not running."
        ),
        (
            "No deauthentication attack detected."
            if "Deauthentication Flood" not in attack_types
            else "Deauthentication activity was detected."
        ),
    ]
    if "Open Network Detected" in attack_types:
        explanations.append("Open Wi-Fi network detected nearby.")
    if any("Beacon flood alert may be normal" in item for item in advisories):
        explanations.append("Beacon activity may be normal if it comes from one network.")
    if status["troubleshooting"]:
        explanations.append(status["troubleshooting"][0])
    if status["interface_resolution"]:
        explanations.append(status["interface_resolution"])

    recommendations: list[str] = []
    if not status["running"]:
        recommendations.append("Start the WIDS engine before relying on the dashboard state.")
    if status["troubleshooting"]:
        recommendations.append(
            "Check monitor mode, channel lock, and the USB adapter driver first."
        )
    if critical_count:
        recommendations.append(
            "Review the technical alert feed and validate the suspicious BSSID "
            "and channel immediately."
        )
    if "Open Network Detected" in attack_types:
        recommendations.append(
            "Treat the open SSID as untrusted until you verify it is expected "
            "in the lab."
        )
    if not recommendations:
        recommendations.append(
            "Keep the monitor on the expected lab channel and review alerts periodically."
        )

    glossary = [
        {"term": "AP", "meaning": "A Wi-Fi access point such as your lab router."},
        {"term": "Client", "meaning": "A phone, laptop, or device talking to an access point."},
        {"term": "Packet", "meaning": "One wireless frame captured from the air."},
        {"term": "Beacon", "meaning": "A broadcast frame that announces a Wi-Fi network."},
        {
            "term": "Deauth",
            "meaning": (
                "A frame that disconnects a client from Wi-Fi and can be abused "
                "in attacks."
            ),
        },
    ]

    return {
        "overall_risk": {
            "level": overall_level,
            "message": overall_message,
        },
        "risk_cards": [
            {
                "level": "SAFE",
                "value": 1 if overall_level == "SAFE" else 0,
                "description": "Monitor running without active high-risk wireless alerts.",
            },
            {
                "level": "WARNING",
                "value": warning_count + len(status["troubleshooting"]),
                "description": "Lower-risk alerts, troubleshooting, or idle state detected.",
            },
            {
                "level": "CRITICAL",
                "value": critical_count + (1 if status["error"] else 0),
                "description": "High-severity alerts or engine errors needing analyst review.",
            },
        ],
        "friendly_stats": [
            {
                "label": "Access Points",
                "value": stats["access_point_count"],
                "description": "Nearby Wi-Fi networks seen in the air.",
            },
            {
                "label": "Clients",
                "value": stats["client_count"],
                "description": "Devices observed talking over Wi-Fi.",
            },
            {
                "label": "Packets",
                "value": status["packet_count"],
                "description": "Wireless frames captured by the monitor.",
            },
            {
                "label": "Alerts",
                "value": status["alert_count"],
                "description": "Detection events raised from real captured traffic.",
            },
        ],
        "explanations": explanations,
        "recommendations": recommendations,
        "glossary": glossary,
        "advisories": advisories,
        "plain_status": {
            "interface": status["interface"],
            "channel": status["current_channel"] or status["channel_lock"] or "unknown",
            "aps": len(devices["access_points"]),
            "clients": len(devices["clients"]),
        },
    }


def build_dashboard_payload(filters: dict[str, str]) -> dict[str, Any]:
    status = normalize_status_payload(load_json(DATA_DIR / "status.json", default_status()))
    devices = normalize_devices_payload(load_json(DATA_DIR / "devices.json", default_devices()))
    alerts = normalize_alert_rows(load_json(DATA_DIR / "alerts.json", []))
    if not alerts:
        alerts = normalize_alert_rows(load_csv_rows(DATA_DIR / "alerts.csv"))
    traffic_logs = normalize_traffic_rows(load_csv_rows(DATA_DIR / "traffic_logs.csv"))
    activity_logs = normalize_activity_rows(load_json(DATA_DIR / "activity_logs.json", []))

    ap_channel_by_bssid = {
        normalize_mac(record["bssid"]): normalize_channel(record["channel"])
        for record in devices["access_points"]
        if record["bssid"]
    }

    filtered_alerts = [alert for alert in alerts if matches_alert(alert, filters)]
    filtered_traffic = [row for row in traffic_logs if matches_traffic(row, filters)]
    filtered_access_points = [
        record
        for record in devices["access_points"]
        if matches_access_point(record, filters)
    ]
    filtered_clients = [
        record
        for record in devices["clients"]
        if matches_client(record, filters, ap_channel_by_bssid)
    ]

    severity_breakdown = Counter(
        normalize_text(alert.get("severity")) or "Unknown"
        for alert in filtered_alerts
    )
    attack_breakdown = Counter(
        normalize_text(alert.get("attack_type")) or "Unknown"
        for alert in filtered_alerts
    )
    high_severity_alerts = [
        alert
        for alert in filtered_alerts
        if str(alert.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
    ]

    channels = {
        normalize_channel(record.get("channel"))
        for record in devices["access_points"]
    }
    channels.update(normalize_channel(row.get("channel")) for row in traffic_logs)
    channels.update(normalize_channel(alert.get("channel")) for alert in alerts)
    if status["current_channel"]:
        channels.add(normalize_channel(status["current_channel"]))

    attack_type_options = sorted(
        {
            normalize_text(alert.get("attack_type"))
            for alert in alerts
            if normalize_text(alert.get("attack_type"))
        }
    )

    stats = {
        "severity_breakdown": dict(severity_breakdown),
        "attack_breakdown": dict(attack_breakdown),
        "access_point_count": len(filtered_access_points),
        "client_count": len(filtered_clients),
        "high_alert_count": len(high_severity_alerts),
    }

    payload = {
        "branding": BRANDING,
        "status": status,
        "devices": {
            "access_points": filtered_access_points,
            "clients": filtered_clients,
        },
        "alerts": tail(filtered_alerts, 50),
        "recent_high_alerts": tail(high_severity_alerts, 10),
        "traffic_logs": tail(filtered_traffic, 50),
        "activity_logs": tail(activity_logs, 30),
        "stats": stats,
        "summary_view": build_summary_view(
            status=status,
            alerts=filtered_alerts,
            devices={
                "access_points": filtered_access_points,
                "clients": filtered_clients,
            },
            stats=stats,
        ),
        "filters": filters,
        "filter_options": {
            "severity": ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "attack_types": attack_type_options,
            "channels": [""] + sort_channels(channels),
        },
        "downloads": {
            "alerts_csv": "/download/alerts.csv",
            "alerts_json": "/download/alerts.json",
            "traffic_csv": "/download/traffic_logs.csv",
            "devices_json": "/download/devices.json",
            "status_json": "/download/status.json",
        },
        "last_updated": status.get("last_update") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    return make_json_safe(payload)


@app.route("/")
def dashboard() -> str:
    payload = build_dashboard_payload(read_filters(request.args))
    return render_template("dashboard.html", payload=payload)


@app.route("/api/dashboard-data")
def dashboard_data() -> Any:
    return jsonify(build_dashboard_payload(read_filters(request.args)))


@app.route("/download/<path:filename>")
def download_file(filename: str) -> Any:
    if filename not in DOWNLOADABLE_FILES:
        abort(404)
    return send_from_directory(DATA_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

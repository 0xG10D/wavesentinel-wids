from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any


ALERT_HEADERS = [
    "timestamp",
    "severity",
    "attack_type",
    "alert_type",
    "source",
    "destination",
    "bssid",
    "essid",
    "channel",
    "packet_count",
    "details",
    "mitre_tactic",
    "mitre_technique",
]

TRAFFIC_HEADERS = [
    "timestamp",
    "interface",
    "channel",
    "frame_type",
    "frame_subtype",
    "protocol",
    "src_mac",
    "dst_mac",
    "bssid",
    "transmitter",
    "receiver",
    "src_ip",
    "dst_ip",
    "essid",
    "security",
    "signal_dbm",
    "length",
    "source",
    "destination",
]


class MonitorLogger:
    def __init__(self, data_dir: Path | str) -> None:
        self.data_dir = Path(data_dir)
        self.alerts_csv_file = self.data_dir / "alerts.csv"
        self.alerts_json_file = self.data_dir / "alerts.json"
        self.traffic_file = self.data_dir / "traffic_logs.csv"
        self.status_file = self.data_dir / "status.json"
        self.devices_file = self.data_dir / "devices.json"
        self.activity_file = self.data_dir / "activity_logs.json"

        self._ensure_storage()

    def _ensure_storage(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_csv(self.alerts_csv_file, ALERT_HEADERS)
        self._ensure_csv(self.traffic_file, TRAFFIC_HEADERS)
        self._ensure_json(self.alerts_json_file, [])
        self._ensure_json(self.status_file, self.default_status())
        self._ensure_json(self.devices_file, self.default_devices())
        self._ensure_json(self.activity_file, [])

    def reset_runtime_outputs(self) -> None:
        self._rewrite_csv(self.alerts_csv_file, ALERT_HEADERS)
        self._rewrite_csv(self.traffic_file, TRAFFIC_HEADERS)
        self._write_json_atomic(self.alerts_json_file, [])
        self._write_json_atomic(self.status_file, self.default_status())
        self._write_json_atomic(self.devices_file, self.default_devices())
        self._write_json_atomic(self.activity_file, [])

    @staticmethod
    def default_status() -> dict[str, Any]:
        return {
            "running": False,
            "mode": "live",
            "interface": "not-started",
            "channel_lock": "",
            "current_channel": "",
            "target_bssid": "",
            "target_essid": "",
            "last_update": "",
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
            "message": "Dashboard ready. Start live monitoring with main.py.",
            "error": "",
        }

    @staticmethod
    def default_devices() -> dict[str, Any]:
        return {
            "access_points": [],
            "clients": [],
            "summary": {
                "access_point_count": 0,
                "client_count": 0,
            },
        }

    def append_alert(self, alert: dict[str, Any]) -> None:
        self._append_csv_row(self.alerts_csv_file, ALERT_HEADERS, alert)
        self._append_json_item(self.alerts_json_file, alert)

    def append_traffic(self, packet: dict[str, Any]) -> None:
        self._append_csv_row(self.traffic_file, TRAFFIC_HEADERS, packet)

    def update_status(self, **fields: Any) -> dict[str, Any]:
        status = self.load_status()
        status.update(fields)
        self._write_json_atomic(self.status_file, status)
        return status

    def load_status(self) -> dict[str, Any]:
        return self._load_json(self.status_file, self.default_status())

    def save_devices(self, devices: dict[str, Any]) -> None:
        self._write_json_atomic(self.devices_file, devices)

    def append_activity(
        self,
        message: str,
        level: str = "INFO",
    ) -> None:
        entry = {
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "level": level.upper(),
            "message": message,
        }
        self._append_json_item(self.activity_file, entry, max_items=500)

    @staticmethod
    def _ensure_csv(path: Path, headers: list[str]) -> None:
        if path.exists() and path.stat().st_size > 0:
            return
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()

    @staticmethod
    def _rewrite_csv(path: Path, headers: list[str]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()

    @staticmethod
    def _append_csv_row(
        path: Path,
        headers: list[str],
        row: dict[str, Any],
    ) -> None:
        write_header = not path.exists() or path.stat().st_size == 0
        cleaned = {header: row.get(header, "") for header in headers}
        with path.open("a", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            if write_header:
                writer.writeheader()
            writer.writerow(cleaned)

    def _ensure_json(self, path: Path, default_payload: Any) -> None:
        if path.exists():
            return
        self._write_json_atomic(path, default_payload)

    @staticmethod
    def _load_json(path: Path, default_payload: Any) -> Any:
        if not path.exists():
            return default_payload
        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except (json.JSONDecodeError, OSError):
            return default_payload

    def _append_json_item(
        self,
        path: Path,
        item: dict[str, Any],
        max_items: int | None = None,
    ) -> None:
        payload = self._load_json(path, [])
        if not isinstance(payload, list):
            payload = []
        payload.append(item)
        if max_items is not None:
            payload = payload[-max_items:]
        self._write_json_atomic(path, payload)

    @staticmethod
    def _write_json_atomic(path: Path, payload: Any) -> None:
        temp_file = path.with_suffix(path.suffix + ".tmp")
        with temp_file.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        temp_file.replace(path)

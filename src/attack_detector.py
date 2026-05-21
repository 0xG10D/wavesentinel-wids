from __future__ import annotations

import json
from collections import Counter, defaultdict, deque
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

from src.packet_capture import normalize_mac


SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"

DEFAULT_THRESHOLD_CONFIG: dict[str, dict[str, Any]] = {
    "deauth_flood": {
        "count": 15,
        "window_seconds": 10,
        "cooldown_seconds": 30,
        "severity": "CRITICAL",
    },
    "disassociation_flood": {
        "count": 15,
        "window_seconds": 10,
        "cooldown_seconds": 30,
        "severity": "HIGH",
    },
    "beacon_flood": {
        "count": 80,
        "unique_ssids": 12,
        "window_seconds": 10,
        "cooldown_seconds": 45,
        "severity": "HIGH",
    },
    "probe_request_flood": {
        "count": 40,
        "window_seconds": 10,
        "cooldown_seconds": 45,
        "severity": "MEDIUM",
    },
    "evil_twin": {
        "cooldown_seconds": 60,
        "severity": "HIGH",
    },
    "open_network": {
        "cooldown_seconds": 300,
        "severity": "LOW",
    },
    "arp_spoofing": {
        "cooldown_seconds": 60,
        "severity": "HIGH",
    },
}

MITRE_MAPPINGS = {
    "deauth_flood": {
        "tactic": "Impact",
        "technique": "T1498 Network Denial of Service",
    },
    "disassociation_flood": {
        "tactic": "Impact",
        "technique": "T1498 Network Denial of Service",
    },
    "beacon_flood": {
        "tactic": "Impact",
        "technique": "T1498 Network Denial of Service",
    },
    "probe_request_flood": {
        "tactic": "Impact",
        "technique": "T1498 Network Denial of Service",
    },
    "evil_twin": {
        "tactic": "Credential Access",
        "technique": "T1557 Adversary-in-the-Middle",
    },
    "open_network": {
        "tactic": "N/A",
        "technique": "N/A",
    },
    "arp_spoofing": {
        "tactic": "Credential Access",
        "technique": "T1557 Adversary-in-the-Middle",
    },
}


def load_threshold_config(path: Path | str) -> dict[str, dict[str, Any]]:
    config_path = Path(path)
    merged = deepcopy(DEFAULT_THRESHOLD_CONFIG)

    if not config_path.exists():
        raise FileNotFoundError(f"Threshold config file not found: {config_path}")

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            overrides = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Threshold config is not valid JSON: {config_path}") from exc

    if not isinstance(overrides, dict):
        raise ValueError("Threshold config root must be a JSON object.")

    for section, values in overrides.items():
        if section not in merged or not isinstance(values, dict):
            continue
        merged[section].update(values)

    return merged


class AttackDetector:
    def __init__(self, thresholds: dict[str, dict[str, Any]]) -> None:
        self.thresholds = thresholds

        self.access_points: dict[str, dict[str, Any]] = {}
        self.clients: dict[str, dict[str, Any]] = {}
        self.ssid_profiles: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        self.arp_bindings: dict[str, str] = {}
        self.rate_windows: dict[str, deque[float]] = defaultdict(deque)
        self.beacon_windows: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self.last_alert_epoch: dict[str, float] = {}

        self.packet_count = 0
        self.alert_count = 0
        self.current_channel = ""
        self.frame_counters = Counter(
            {
                "deauth": 0,
                "disassoc": 0,
                "beacon": 0,
                "probe": 0,
            }
        )
        self.severity_counts = Counter({level: 0 for level in SEVERITY_LEVELS})
        self.attack_counts: Counter[str] = Counter()

    def process_packet(self, packet: dict[str, Any]) -> list[dict[str, Any]]:
        self.packet_count += 1
        event_time = self._packet_epoch(str(packet.get("timestamp", "")))

        if packet.get("channel"):
            self.current_channel = str(packet["channel"])

        self._update_frame_counters(packet)
        self._observe_access_point(packet)
        self._observe_clients(packet)

        alerts: list[dict[str, Any]] = []
        alert = self._detect_deauth_flood(packet, event_time)
        if alert:
            alerts.append(alert)

        alert = self._detect_disassociation_flood(packet, event_time)
        if alert:
            alerts.append(alert)

        alert = self._detect_beacon_flood(packet, event_time)
        if alert:
            alerts.append(alert)

        alert = self._detect_probe_request_flood(packet, event_time)
        if alert:
            alerts.append(alert)

        alert = self._detect_evil_twin(packet, event_time)
        if alert:
            alerts.append(alert)

        alert = self._detect_open_network(packet, event_time)
        if alert:
            alerts.append(alert)

        alert = self._detect_arp_spoofing(packet, event_time)
        if alert:
            alerts.append(alert)

        for alert in alerts:
            self.alert_count += 1
            self.severity_counts[str(alert["severity"]).upper()] += 1
            self.attack_counts[str(alert["attack_type"])] += 1

        return alerts

    def export_devices(self) -> dict[str, Any]:
        client_counts = Counter()
        for client in self.clients.values():
            associated_bssid = str(client.get("associated_bssid", "") or "")
            if associated_bssid:
                client_counts[associated_bssid] += 1

        access_points = []
        for record in self.access_points.values():
            access_points.append(
                {
                    "bssid": record["bssid"],
                    "essid": record["essid"],
                    "channel": record["channel"],
                    "security": record["security"],
                    "first_seen": record["first_seen"],
                    "last_seen": record["last_seen"],
                    "packet_count": record["packet_count"],
                    "beacon_count": record["beacon_count"],
                    "client_count": client_counts.get(record["bssid"], 0),
                    "last_signal_dbm": record["last_signal_dbm"],
                }
            )

        clients = []
        for record in self.clients.values():
            clients.append(
                {
                    "client_mac": record["client_mac"],
                    "associated_bssid": record["associated_bssid"],
                    "associated_essid": record["associated_essid"],
                    "first_seen": record["first_seen"],
                    "last_seen": record["last_seen"],
                    "frame_count": record["frame_count"],
                    "probe_request_count": record["probe_request_count"],
                    "probe_essids": sorted(record["probe_essids"]),
                    "src_ips": sorted(record["src_ips"]),
                    "last_signal_dbm": record["last_signal_dbm"],
                }
            )

        access_points.sort(key=lambda item: (item["essid"], item["bssid"]))
        clients.sort(key=lambda item: (item["associated_essid"], item["client_mac"]))

        return {
            "access_points": access_points,
            "clients": clients,
            "summary": {
                "access_point_count": len(access_points),
                "client_count": len(clients),
            },
        }

    def get_status_snapshot(self) -> dict[str, Any]:
        inventory = self.export_devices()
        return {
            "packet_count": self.packet_count,
            "alert_count": self.alert_count,
            "ap_count": inventory["summary"]["access_point_count"],
            "client_count": inventory["summary"]["client_count"],
            "current_channel": self.current_channel,
            "frame_counters": {
                "deauth": self.frame_counters["deauth"],
                "disassoc": self.frame_counters["disassoc"],
                "beacon": self.frame_counters["beacon"],
                "probe": self.frame_counters["probe"],
            },
            "severity_counts": {
                severity: self.severity_counts.get(severity, 0)
                for severity in SEVERITY_LEVELS
            },
            "attack_counts": dict(self.attack_counts),
        }

    def _observe_access_point(self, packet: dict[str, Any]) -> None:
        bssid = normalize_mac(str(packet.get("bssid", "")))
        if not bssid:
            return

        essid = str(packet.get("essid", "") or "")
        channel = str(packet.get("channel", "") or "")
        security = str(packet.get("security", "") or "")
        timestamp = str(packet.get("timestamp", "") or "")

        record = self.access_points.setdefault(
            bssid,
            {
                "bssid": bssid,
                "essid": essid,
                "channel": channel,
                "security": security,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "packet_count": 0,
                "beacon_count": 0,
                "last_signal_dbm": packet.get("signal_dbm", ""),
            },
        )

        record["last_seen"] = timestamp
        record["packet_count"] += 1
        if essid:
            record["essid"] = essid
        if channel:
            record["channel"] = channel
        if security:
            record["security"] = security
        if packet.get("signal_dbm", "") != "":
            record["last_signal_dbm"] = packet.get("signal_dbm", "")
        if packet.get("frame_subtype") == "Beacon":
            record["beacon_count"] += 1

        if essid:
            self.ssid_profiles[essid][bssid] = {
                "security": record["security"] or "UNKNOWN",
                "channel": record["channel"],
            }

    def _observe_clients(self, packet: dict[str, Any]) -> None:
        bssid = normalize_mac(str(packet.get("bssid", "")))
        frame_type = str(packet.get("frame_type", "") or "")
        frame_subtype = str(packet.get("frame_subtype", "") or "")

        source_client = normalize_mac(str(packet.get("src_mac", "")))
        if source_client and source_client != bssid and source_client != BROADCAST_MAC:
            self._observe_client(source_client, packet, bssid)

        if frame_type in {"Management", "Data"} and frame_subtype not in {"Beacon", "Probe Response"}:
            destination_client = normalize_mac(str(packet.get("dst_mac", "")))
            if destination_client and destination_client != bssid and destination_client != BROADCAST_MAC:
                self._observe_client(destination_client, packet, bssid)

    def _observe_client(self, client_mac: str, packet: dict[str, Any], bssid: str) -> None:
        timestamp = str(packet.get("timestamp", "") or "")
        essid = str(packet.get("essid", "") or "")

        if not essid and bssid in self.access_points:
            essid = str(self.access_points[bssid].get("essid", "") or "")

        record = self.clients.setdefault(
            client_mac,
            {
                "client_mac": client_mac,
                "associated_bssid": bssid,
                "associated_essid": essid,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "frame_count": 0,
                "probe_request_count": 0,
                "probe_essids": set(),
                "src_ips": set(),
                "last_signal_dbm": packet.get("signal_dbm", ""),
            },
        )

        record["last_seen"] = timestamp
        record["frame_count"] += 1
        if bssid:
            record["associated_bssid"] = bssid
        if essid:
            record["associated_essid"] = essid
        if packet.get("src_ip"):
            record["src_ips"].add(str(packet["src_ip"]))
        if packet.get("frame_subtype") == "Probe Request":
            record["probe_request_count"] += 1
            if packet.get("essid"):
                record["probe_essids"].add(str(packet["essid"]))
        if packet.get("signal_dbm", "") != "":
            record["last_signal_dbm"] = packet.get("signal_dbm", "")

    def _update_frame_counters(self, packet: dict[str, Any]) -> None:
        subtype = str(packet.get("frame_subtype", "") or "")
        if subtype == "Deauthentication":
            self.frame_counters["deauth"] += 1
        elif subtype == "Disassociation":
            self.frame_counters["disassoc"] += 1
        elif subtype == "Beacon":
            self.frame_counters["beacon"] += 1
        elif subtype == "Probe Request":
            self.frame_counters["probe"] += 1

    def _detect_deauth_flood(
        self,
        packet: dict[str, Any],
        event_time: float,
    ) -> dict[str, Any] | None:
        if packet.get("frame_subtype") != "Deauthentication":
            return None

        config = self.thresholds["deauth_flood"]
        source = normalize_mac(str(packet.get("src_mac", ""))) or normalize_mac(str(packet.get("bssid", "")))
        if not source:
            source = "unknown-source"

        key = f"deauth:{source}"
        count = self._push_rate_window(key, event_time, int(config["window_seconds"]))
        if count < int(config["count"]):
            return None
        if not self._should_emit(key, event_time, int(config["cooldown_seconds"])):
            return None

        return self._build_alert(
            packet=packet,
            severity=str(config["severity"]),
            attack_type="Deauthentication Flood",
            details=(
                f"Observed {count} deauthentication frames from {source} within "
                f"{config['window_seconds']} seconds."
            ),
            mapping_key="deauth_flood",
            packet_count=count,
        )

    def _detect_disassociation_flood(
        self,
        packet: dict[str, Any],
        event_time: float,
    ) -> dict[str, Any] | None:
        if packet.get("frame_subtype") != "Disassociation":
            return None

        config = self.thresholds["disassociation_flood"]
        source = normalize_mac(str(packet.get("src_mac", ""))) or normalize_mac(str(packet.get("bssid", "")))
        if not source:
            source = "unknown-source"

        key = f"disassoc:{source}"
        count = self._push_rate_window(key, event_time, int(config["window_seconds"]))
        if count < int(config["count"]):
            return None
        if not self._should_emit(key, event_time, int(config["cooldown_seconds"])):
            return None

        return self._build_alert(
            packet=packet,
            severity=str(config["severity"]),
            attack_type="Disassociation Flood",
            details=(
                f"Observed {count} disassociation frames from {source} within "
                f"{config['window_seconds']} seconds."
            ),
            mapping_key="disassociation_flood",
            packet_count=count,
        )

    def _detect_beacon_flood(
        self,
        packet: dict[str, Any],
        event_time: float,
    ) -> dict[str, Any] | None:
        if packet.get("frame_subtype") != "Beacon":
            return None

        config = self.thresholds["beacon_flood"]
        source = normalize_mac(str(packet.get("src_mac", ""))) or normalize_mac(str(packet.get("bssid", "")))
        if not source:
            source = "unknown-source"

        window_key = f"beacon:{source}"
        count, unique_ssids = self._push_beacon_window(
            window_key,
            event_time,
            str(packet.get("essid", "") or ""),
            int(config["window_seconds"]),
        )
        if count < int(config["count"]) and unique_ssids < int(config["unique_ssids"]):
            return None
        if not self._should_emit(window_key, event_time, int(config["cooldown_seconds"])):
            return None

        return self._build_alert(
            packet=packet,
            severity=str(config["severity"]),
            attack_type="Beacon Flood",
            details=(
                f"Observed {count} beacon frames and {unique_ssids} unique SSIDs from {source} "
                f"within {config['window_seconds']} seconds."
            ),
            mapping_key="beacon_flood",
            packet_count=count,
        )

    def _detect_probe_request_flood(
        self,
        packet: dict[str, Any],
        event_time: float,
    ) -> dict[str, Any] | None:
        if packet.get("frame_subtype") != "Probe Request":
            return None

        config = self.thresholds["probe_request_flood"]
        source = normalize_mac(str(packet.get("src_mac", "")))
        if not source:
            return None

        key = f"probe:{source}"
        count = self._push_rate_window(key, event_time, int(config["window_seconds"]))
        if count < int(config["count"]):
            return None
        if not self._should_emit(key, event_time, int(config["cooldown_seconds"])):
            return None

        return self._build_alert(
            packet=packet,
            severity=str(config["severity"]),
            attack_type="Probe Request Flood",
            details=(
                f"Observed {count} probe requests from {source} within "
                f"{config['window_seconds']} seconds."
            ),
            mapping_key="probe_request_flood",
            packet_count=count,
        )

    def _detect_evil_twin(
        self,
        packet: dict[str, Any],
        event_time: float,
    ) -> dict[str, Any] | None:
        if packet.get("frame_subtype") not in {"Beacon", "Probe Response"}:
            return None

        essid = str(packet.get("essid", "") or "")
        bssid = normalize_mac(str(packet.get("bssid", "")))
        if not essid or not bssid:
            return None

        profiles = self.ssid_profiles.get(essid, {})
        if len(profiles) < 2:
            return None

        security_profiles = {
            str(profile.get("security", "UNKNOWN") or "UNKNOWN")
            for profile in profiles.values()
        }
        if len(security_profiles) < 2:
            return None

        config = self.thresholds["evil_twin"]
        key = f"evil-twin:{essid}"
        if not self._should_emit(key, event_time, int(config["cooldown_seconds"])):
            return None

        severity = str(config["severity"])
        if "OPEN" in security_profiles and len(security_profiles) > 1:
            severity = "CRITICAL"

        profile_summary = ", ".join(
            f"{profile_bssid} ({profile.get('security', 'UNKNOWN')})"
            for profile_bssid, profile in sorted(profiles.items())
        )
        return self._build_alert(
            packet=packet,
            severity=severity,
            attack_type="Evil Twin Suspicion",
            details=(
                f"ESSID '{essid}' is advertising conflicting security profiles across BSSIDs: "
                f"{profile_summary}."
            ),
            mapping_key="evil_twin",
            packet_count=len(profiles),
        )

    def _detect_open_network(
        self,
        packet: dict[str, Any],
        event_time: float,
    ) -> dict[str, Any] | None:
        if packet.get("frame_subtype") not in {"Beacon", "Probe Response"}:
            return None
        if str(packet.get("security", "") or "") != "OPEN":
            return None

        config = self.thresholds["open_network"]
        bssid = normalize_mac(str(packet.get("bssid", "")))
        if not bssid:
            return None

        key = f"open-network:{bssid}"
        if not self._should_emit(key, event_time, int(config["cooldown_seconds"])):
            return None

        essid = str(packet.get("essid", "") or "<hidden>")
        return self._build_alert(
            packet=packet,
            severity=str(config["severity"]),
            attack_type="Open Network Detected",
            details=(
                f"Access point {bssid} is advertising ESSID '{essid}' without link-layer protection."
            ),
            mapping_key="open_network",
            packet_count=1,
        )

    def _detect_arp_spoofing(
        self,
        packet: dict[str, Any],
        event_time: float,
    ) -> dict[str, Any] | None:
        if packet.get("protocol") != "ARP":
            return None

        source_ip = str(packet.get("src_ip", "") or "")
        source_mac = normalize_mac(str(packet.get("src_mac", "")))
        if not source_ip or not source_mac:
            return None

        previous_mac = self.arp_bindings.get(source_ip)
        self.arp_bindings[source_ip] = source_mac
        if not previous_mac or previous_mac == source_mac:
            return None

        config = self.thresholds["arp_spoofing"]
        key = f"arp:{source_ip}:{source_mac}"
        if not self._should_emit(key, event_time, int(config["cooldown_seconds"])):
            return None

        return self._build_alert(
            packet=packet,
            severity=str(config["severity"]),
            attack_type="ARP Spoofing Suspicion",
            details=(
                f"IP address {source_ip} moved from MAC {previous_mac} to {source_mac}. "
                "Validate the station and gateway bindings."
            ),
            mapping_key="arp_spoofing",
            packet_count=1,
        )

    def _push_rate_window(self, key: str, event_time: float, window_seconds: int) -> int:
        window = self.rate_windows[key]
        window.append(event_time)
        while window and event_time - window[0] > window_seconds:
            window.popleft()
        return len(window)

    def _push_beacon_window(
        self,
        key: str,
        event_time: float,
        essid: str,
        window_seconds: int,
    ) -> tuple[int, int]:
        window = self.beacon_windows[key]
        window.append((event_time, essid))
        while window and event_time - window[0][0] > window_seconds:
            window.popleft()

        unique_ssids = {item_essid for _, item_essid in window if item_essid}
        return len(window), len(unique_ssids)

    def _should_emit(self, key: str, event_time: float, cooldown_seconds: int) -> bool:
        previous_time = self.last_alert_epoch.get(key, 0.0)
        if event_time - previous_time < cooldown_seconds:
            return False
        self.last_alert_epoch[key] = event_time
        return True

    def _build_alert(
        self,
        packet: dict[str, Any],
        severity: str,
        attack_type: str,
        details: str,
        mapping_key: str,
        packet_count: int,
    ) -> dict[str, Any]:
        mapping = MITRE_MAPPINGS[mapping_key]
        return {
            "timestamp": packet.get("timestamp", ""),
            "severity": severity.upper(),
            "attack_type": attack_type,
            "alert_type": attack_type,
            "source": packet.get("source", packet.get("src_mac", "")),
            "destination": packet.get("destination", packet.get("dst_mac", "")),
            "bssid": packet.get("bssid", ""),
            "essid": packet.get("essid", ""),
            "channel": packet.get("channel", ""),
            "packet_count": packet_count,
            "details": details,
            "mitre_tactic": mapping["tactic"],
            "mitre_technique": mapping["technique"],
        }

    @staticmethod
    def _packet_epoch(timestamp: str) -> float:
        try:
            return datetime.fromisoformat(timestamp).timestamp()
        except ValueError:
            return datetime.now().astimezone().timestamp()

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime

from src.device_scanner import TrustedDeviceRegistry, normalize_mac


class AttackDetector:
    def __init__(
        self,
        registry: TrustedDeviceRegistry,
        packet_rate_threshold: int = 25,
        rate_window_seconds: int = 10,
        deauth_threshold: int = 3,
    ) -> None:
        self.registry = registry
        self.packet_rate_threshold = packet_rate_threshold
        self.rate_window_seconds = rate_window_seconds
        self.deauth_threshold = deauth_threshold

        self.packet_windows: dict[str, deque[float]] = defaultdict(deque)
        self.deauth_windows: dict[str, deque[float]] = defaultdict(deque)
        self.arp_bindings: dict[str, str] = {}
        self.last_alert_epoch: dict[str, float] = {}
        self.unknown_devices_alerted: set[str] = set()

    def analyze(self, packet: dict[str, str]) -> list[dict[str, str]]:
        event_time = self._packet_epoch(packet.get("timestamp", ""))
        source_mac = normalize_mac(packet.get("src_mac"))
        source_ip = packet.get("src_ip", "").strip()
        alerts: list[dict[str, str]] = []

        unknown_device_alert = self._detect_unknown_device(
            packet=packet,
            source_mac=source_mac,
        )
        if unknown_device_alert:
            alerts.append(unknown_device_alert)

        arp_alert = self._detect_arp_spoofing(
            packet=packet,
            event_time=event_time,
            source_mac=source_mac,
            source_ip=source_ip,
        )
        if arp_alert:
            alerts.append(arp_alert)

        deauth_alert = self._detect_deauth_like(packet=packet, event_time=event_time)
        if deauth_alert:
            alerts.append(deauth_alert)

        flood_alert = self._detect_packet_flood(
            packet=packet,
            event_time=event_time,
            source_mac=source_mac,
            source_ip=source_ip,
        )
        if flood_alert:
            alerts.append(flood_alert)

        return alerts

    def _detect_unknown_device(
        self,
        packet: dict[str, str],
        source_mac: str,
    ) -> dict[str, str] | None:
        if not source_mac or self.registry.is_trusted(source_mac):
            return None

        if source_mac in self.unknown_devices_alerted:
            return None

        self.unknown_devices_alerted.add(source_mac)
        return self._build_alert(
            packet=packet,
            severity="MEDIUM",
            alert_type="Unknown Device Access",
            details=(
                f"Observed source MAC {source_mac} is not present in "
                "data/known_devices.csv."
            ),
        )

    def _detect_arp_spoofing(
        self,
        packet: dict[str, str],
        event_time: float,
        source_mac: str,
        source_ip: str,
    ) -> dict[str, str] | None:
        if packet.get("protocol") != "ARP" or not source_ip or not source_mac:
            return None

        previous_mac = self.arp_bindings.get(source_ip)
        self.arp_bindings[source_ip] = source_mac

        if not previous_mac or previous_mac == source_mac:
            return None

        alert_key = f"arp:{source_ip}:{source_mac}"
        if not self._should_emit(alert_key, event_time, cooldown_seconds=60):
            return None

        return self._build_alert(
            packet=packet,
            severity="HIGH",
            alert_type="ARP Spoofing Suspicion",
            details=(
                f"IP {source_ip} was previously mapped to {previous_mac} and is now "
                f"claiming {source_mac}. Review for ARP poisoning."
            ),
        )

    def _detect_deauth_like(
        self,
        packet: dict[str, str],
        event_time: float,
    ) -> dict[str, str] | None:
        subtype = packet.get("wireless_subtype", "")
        if subtype not in {"Deauthentication", "Disassociation"}:
            return None

        source = normalize_mac(packet.get("src_mac")) or "unknown-wireless-source"
        window = self.deauth_windows[source]
        window.append(event_time)
        self._trim_window(window, event_time, 30)

        if len(window) < self.deauth_threshold:
            return None

        alert_key = f"deauth:{source}"
        if not self._should_emit(alert_key, event_time, cooldown_seconds=60):
            return None

        return self._build_alert(
            packet=packet,
            severity="HIGH",
            alert_type="Deauthentication-Like Activity",
            details=(
                f"Detected {len(window)} wireless management events from {source} "
                "inside 30 seconds."
            ),
        )

    def _detect_packet_flood(
        self,
        packet: dict[str, str],
        event_time: float,
        source_mac: str,
        source_ip: str,
    ) -> dict[str, str] | None:
        source = source_ip or source_mac
        if not source:
            return None

        window = self.packet_windows[source]
        window.append(event_time)
        self._trim_window(window, event_time, self.rate_window_seconds)

        if len(window) < self.packet_rate_threshold:
            return None

        alert_key = f"flood:{source}"
        if not self._should_emit(alert_key, event_time, cooldown_seconds=45):
            return None

        return self._build_alert(
            packet=packet,
            severity="MEDIUM",
            alert_type="Abnormal Packet Rate",
            details=(
                f"Source {source} generated {len(window)} packets within "
                f"{self.rate_window_seconds} seconds."
            ),
        )

    @staticmethod
    def _packet_epoch(timestamp: str) -> float:
        try:
            return datetime.fromisoformat(timestamp).timestamp()
        except ValueError:
            return datetime.now().astimezone().timestamp()

    @staticmethod
    def _trim_window(window: deque[float], current_time: float, seconds: int) -> None:
        while window and current_time - window[0] > seconds:
            window.popleft()

    def _should_emit(
        self,
        key: str,
        event_time: float,
        cooldown_seconds: int,
    ) -> bool:
        last_time = self.last_alert_epoch.get(key, 0.0)
        if event_time - last_time < cooldown_seconds:
            return False
        self.last_alert_epoch[key] = event_time
        return True

    @staticmethod
    def _build_alert(
        packet: dict[str, str],
        severity: str,
        alert_type: str,
        details: str,
    ) -> dict[str, str]:
        return {
            "timestamp": packet.get("timestamp", ""),
            "severity": severity,
            "alert_type": alert_type,
            "source": packet.get("source", packet.get("src_ip", packet.get("src_mac", ""))),
            "destination": packet.get(
                "destination",
                packet.get("dst_ip", packet.get("dst_mac", "")),
            ),
            "details": details,
        }

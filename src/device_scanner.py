from __future__ import annotations

import csv
from pathlib import Path


def normalize_mac(mac_address: str | None) -> str:
    if not mac_address:
        return ""

    cleaned = mac_address.strip().replace("-", ":").upper()
    while "::" in cleaned:
        cleaned = cleaned.replace("::", ":")
    return cleaned


class TrustedDeviceRegistry:
    def __init__(self, csv_path: Path | str) -> None:
        self.csv_path = Path(csv_path)
        self.devices: dict[str, dict[str, str]] = {}
        self.load()

    def load(self) -> None:
        self.devices.clear()
        if not self.csv_path.exists():
            return

        with self.csv_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                mac = normalize_mac(row.get("mac_address"))
                if not mac:
                    continue
                self.devices[mac] = {
                    "device_name": row.get("device_name", "Unknown Trusted Device").strip(),
                    "mac_address": mac,
                    "ip_address": row.get("ip_address", "").strip(),
                    "owner": row.get("owner", "").strip(),
                    "notes": row.get("notes", "").strip(),
                }

    def is_trusted(self, mac_address: str | None) -> bool:
        mac = normalize_mac(mac_address)
        return mac in self.devices

    def get_device(self, mac_address: str | None) -> dict[str, str] | None:
        mac = normalize_mac(mac_address)
        return self.devices.get(mac)


class DeviceTracker:
    def __init__(self, registry: TrustedDeviceRegistry) -> None:
        self.registry = registry
        self.seen_devices: dict[str, dict[str, str | int | bool]] = {}

    def observe(self, packet: dict[str, str]) -> dict[str, str | int | bool] | None:
        mac = normalize_mac(packet.get("src_mac"))
        if not mac:
            return None

        trusted_record = self.registry.get_device(mac)
        timestamp = packet.get("timestamp", "")
        ip_address = packet.get("src_ip", "").strip()

        if mac not in self.seen_devices:
            self.seen_devices[mac] = {
                "device_name": (
                    trusted_record["device_name"] if trusted_record else "Unknown Device"
                ),
                "mac_address": mac,
                "ip_address": ip_address or (trusted_record or {}).get("ip_address", ""),
                "owner": (trusted_record or {}).get("owner", ""),
                "trusted": bool(trusted_record),
                "first_seen": timestamp,
                "last_seen": timestamp,
                "packet_count": 0,
                "last_protocol": "",
            }

        device = self.seen_devices[mac]
        device["last_seen"] = timestamp
        device["packet_count"] = int(device["packet_count"]) + 1
        device["last_protocol"] = packet.get("protocol", "")
        if ip_address:
            device["ip_address"] = ip_address

        return device

    def export_devices(self) -> list[dict[str, str | int | bool]]:
        devices = list(self.seen_devices.values())
        devices.sort(
            key=lambda item: (
                not bool(item["trusted"]),
                item.get("device_name", ""),
                item.get("mac_address", ""),
            )
        )
        return devices

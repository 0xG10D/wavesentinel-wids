from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

try:
    from scapy.all import (
        ARP,
        IP,
        Dot11,
        Dot11Beacon,
        Dot11Elt,
        Dot11ProbeResp,
        RadioTap,
        sniff,
    )
    from scapy.error import Scapy_Exception

    SCAPY_AVAILABLE = True
except ImportError:
    ARP = Dot11 = Dot11Beacon = Dot11Elt = Dot11ProbeResp = None
    IP = RadioTap = sniff = None
    Scapy_Exception = Exception
    SCAPY_AVAILABLE = False


class PacketCaptureError(RuntimeError):
    """Base error for packet capture failures."""


class PacketCapturePermissionError(PacketCaptureError):
    """Raised when capture privileges are insufficient."""


class PacketCaptureInterfaceError(PacketCaptureError):
    """Raised when the requested interface is invalid or unavailable."""


class PacketCaptureMonitorModeError(PacketCaptureError):
    """Raised when the interface is not in monitor mode."""


@dataclass
class InterfaceInfo:
    name: str
    mode: str
    phy: str = ""
    channel: str = ""
    mac_address: str = ""


def normalize_mac(mac_address: str | None) -> str:
    if not mac_address:
        return ""

    cleaned = mac_address.strip().replace("-", ":").upper()
    while "::" in cleaned:
        cleaned = cleaned.replace("::", ":")
    return cleaned


class PacketCapture:
    def __init__(
        self,
        interface: str,
        channel: int | None = None,
        bssid: str = "",
        essid: str = "",
        sniff_timeout: int = 1,
    ) -> None:
        self.requested_interface = interface.strip()
        self.interface = self.requested_interface
        self.channel = channel
        self.bssid_filter = normalize_mac(bssid)
        self.essid_filter = essid.strip()
        self.sniff_timeout = max(1, sniff_timeout)
        self.current_channel = str(channel or "")
        self.interface_mode = ""
        self.interface_resolution = ""

    def validate_interface(self) -> None:
        if not SCAPY_AVAILABLE:
            raise PacketCaptureError(
                "Scapy is not installed or importable. "
                "Install requirements before starting the WIDS engine."
            )
        if not self.requested_interface:
            raise PacketCaptureInterfaceError("A monitor-mode interface is required.")
        if not sys.platform.startswith("linux"):
            raise PacketCaptureMonitorModeError(
                "Monitor-mode validation is implemented for Linux lab hosts only."
            )

        info = self._resolve_interface()
        self.interface = info.name
        self.interface_mode = info.mode
        if info.channel and not self.current_channel:
            self.current_channel = info.channel

        if info.mode.lower() != "monitor":
            raise PacketCaptureMonitorModeError(
                f"Interface '{info.name}' is in {info.mode or 'unknown'} mode, not monitor mode."
            )

        if self.channel is not None:
            self._lock_channel(self.channel)
            self._verify_channel_lock(self.channel)

    def sniff_live(
        self,
        packet_callback: Callable[[dict[str, Any]], None],
        should_stop: Callable[[], bool] | None = None,
    ) -> None:
        while True:
            if should_stop and should_stop():
                return

            sniff_kwargs: dict[str, Any] = {
                "iface": self.interface,
                "prn": lambda packet: self._dispatch(packet, packet_callback),
                "promisc": True,
                "store": False,
                "timeout": self.sniff_timeout,
            }

            try:
                sniff(**sniff_kwargs)
            except KeyboardInterrupt:
                raise
            except PermissionError as exc:
                raise PacketCapturePermissionError(
                    "Packet capture requires root privileges or CAP_NET_RAW/CAP_NET_ADMIN."
                ) from exc
            except OSError as exc:
                raise PacketCapturePermissionError(
                    "The operating system blocked live capture. Re-run with elevated privileges."
                ) from exc
            except Scapy_Exception as exc:
                message = str(exc)
                lowered = message.lower()
                if "no such device" in lowered or "not found" in lowered:
                    raise PacketCaptureInterfaceError(
                        f"Capture interface '{self.interface}' is unavailable."
                    ) from exc
                raise PacketCaptureError(f"Scapy failed during live capture: {message}") from exc

    def _dispatch(
        self,
        packet: Any,
        packet_callback: Callable[[dict[str, Any]], None],
    ) -> None:
        summary = self.extract_packet_summary(packet, self.interface)
        if not summary:
            return
        if not self._matches_filters(summary):
            return
        if summary.get("channel"):
            self.current_channel = str(summary["channel"])
        packet_callback(summary)

    def _matches_filters(self, packet: dict[str, Any]) -> bool:
        if self.bssid_filter:
            bssid_candidates = {
                normalize_mac(packet.get("bssid")),
                normalize_mac(packet.get("src_mac")),
                normalize_mac(packet.get("dst_mac")),
            }
            if self.bssid_filter not in bssid_candidates:
                return False

        if self.essid_filter:
            packet_essid = str(packet.get("essid", "") or "").strip()
            if packet_essid != self.essid_filter:
                return False

        return True

    def _resolve_interface(self) -> InterfaceInfo:
        interfaces = self._list_linux_interfaces()
        requested = next(
            (item for item in interfaces if item.name == self.requested_interface),
            None,
        )
        monitor_interfaces = [
            item for item in interfaces if item.mode.lower() == "monitor"
        ]

        if requested is not None:
            if requested.mode.lower() == "monitor":
                return requested

            available_monitor_names = ", ".join(item.name for item in monitor_interfaces)
            hint = ""
            if available_monitor_names:
                hint = (
                    f" Active monitor interface(s): {available_monitor_names}. "
                    f"If airmon-ng renamed '{self.requested_interface}', "
                    "use that monitor interface instead. "
                    "Long adapter names are often renamed to wlan0mon."
                )
            raise PacketCaptureMonitorModeError(
                "Interface "
                f"'{self.requested_interface}' is in {requested.mode or 'unknown'} "
                f"mode, not monitor mode.{hint}"
            )

        if len(monitor_interfaces) == 1:
            resolved = monitor_interfaces[0]
            self.interface_resolution = (
                f"Requested interface '{self.requested_interface}' was not found. "
                f"Using active monitor interface '{resolved.name}' instead. "
                "airmon-ng may rename long adapter names to wlan0mon."
            )
            return resolved

        if len(monitor_interfaces) > 1:
            monitor_names = ", ".join(item.name for item in monitor_interfaces)
            raise PacketCaptureInterfaceError(
                f"Interface '{self.requested_interface}' was not found. "
                "Multiple monitor interfaces are active: "
                f"{monitor_names}. Re-run with the exact capture interface."
            )

        if interfaces:
            available = ", ".join(
                f"{item.name} ({item.mode or 'unknown'})" for item in interfaces
            )
            raise PacketCaptureInterfaceError(
                f"Interface '{self.requested_interface}' was not found. "
                f"Available interfaces: {available}. "
                "airmon-ng may rename long adapter names to wlan0mon."
            )

        raise PacketCaptureInterfaceError(
            f"Interface '{self.requested_interface}' was not found and no "
            "wireless interfaces were reported by iw. "
            "Check the adapter, driver, and monitor-mode setup."
        )

    def _list_linux_interfaces(self) -> list[InterfaceInfo]:
        iw_result = self._run_command(["iw", "dev"])
        if iw_result is not None and iw_result.returncode == 0:
            interfaces: list[InterfaceInfo] = []
            current_phy = ""
            current: InterfaceInfo | None = None

            for raw_line in iw_result.stdout.splitlines():
                line = raw_line.strip()
                if line.startswith("phy#"):
                    current_phy = line
                    continue
                if line.startswith("Interface "):
                    if current is not None:
                        interfaces.append(current)
                    current = InterfaceInfo(
                        name=line.split("Interface ", 1)[1].strip(),
                        mode="",
                        phy=current_phy,
                    )
                    continue
                if current is None:
                    continue
                if line.startswith("type "):
                    current.mode = line.split("type ", 1)[1].strip()
                elif line.startswith("channel "):
                    current.channel = line.split("channel ", 1)[1].split(" ", 1)[0].strip()
                elif line.startswith("addr "):
                    current.mac_address = normalize_mac(line.split("addr ", 1)[1].strip())

            if current is not None:
                interfaces.append(current)
            if interfaces:
                return interfaces

        iwconfig_result = self._run_command(["iwconfig"])
        if iwconfig_result is None or iwconfig_result.returncode != 0:
            return []

        interfaces: list[InterfaceInfo] = []
        for raw_line in iwconfig_result.stdout.splitlines():
            if not raw_line or raw_line.startswith(" "):
                continue
            parts = raw_line.split()
            if not parts:
                continue
            name = parts[0]
            lowered = raw_line.lower()
            mode = ""
            if "mode:monitor" in lowered:
                mode = "monitor"
            elif "mode:managed" in lowered:
                mode = "managed"
            interfaces.append(InterfaceInfo(name=name, mode=mode))
        return interfaces

    def _lock_channel(self, channel: int) -> None:
        iw_result = self._run_command(["iw", "dev", self.interface, "set", "channel", str(channel)])
        if iw_result is not None and iw_result.returncode == 0:
            self.current_channel = str(channel)
            return
        if iw_result is not None and self._looks_like_permission_error(iw_result.stderr):
            raise PacketCapturePermissionError(
                f"Channel lock on {self.interface} requires elevated privileges."
            )

        iwconfig_result = self._run_command(["iwconfig", self.interface, "channel", str(channel)])
        if iwconfig_result is not None and iwconfig_result.returncode == 0:
            self.current_channel = str(channel)
            return
        if (
            iwconfig_result is not None
            and self._looks_like_permission_error(iwconfig_result.stderr)
        ):
            raise PacketCapturePermissionError(
                f"Channel lock on {self.interface} requires elevated privileges."
            )

        raise PacketCaptureError(
            f"Failed to lock {self.interface} to channel {channel}. "
            "Check that the interface is monitor-mode capable."
        )

    def _verify_channel_lock(self, channel: int) -> None:
        refreshed = next(
            (item for item in self._list_linux_interfaces() if item.name == self.interface),
            None,
        )
        if refreshed is None:
            return

        self.interface_mode = refreshed.mode or self.interface_mode
        if refreshed.channel:
            self.current_channel = refreshed.channel

        if refreshed.channel and refreshed.channel != str(channel):
            raise PacketCaptureError(
                f"Interface '{self.interface}' is on channel {refreshed.channel} "
                f"after requesting channel {channel}. "
                "Re-check monitor mode and channel lock."
            )

    @staticmethod
    def _run_command(command: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return None

    @staticmethod
    def _looks_like_permission_error(stderr: str) -> bool:
        lowered = stderr.lower()
        return "operation not permitted" in lowered or "permission denied" in lowered

    @staticmethod
    def extract_packet_summary(packet: Any, interface: str) -> dict[str, Any] | None:
        if Dot11 is None or not packet.haslayer(Dot11):
            return None

        packet_time = getattr(packet, "time", datetime.now(tz=timezone.utc).timestamp())
        timestamp = datetime.fromtimestamp(
            float(packet_time),
            tz=timezone.utc,
        ).astimezone().isoformat(timespec="seconds")

        dot11 = packet[Dot11]
        frame_class = PacketCapture._frame_class_name(getattr(dot11, "type", -1))
        frame_subtype = PacketCapture._wireless_subtype(dot11)
        frame_type = PacketCapture._display_frame_type(frame_class, frame_subtype)
        bssid = PacketCapture._extract_bssid(dot11)
        transmitter = normalize_mac(getattr(dot11, "addr2", "") or "")
        receiver = normalize_mac(getattr(dot11, "addr1", "") or "")
        src_mac = transmitter
        dst_mac = receiver
        src_ip = ""
        dst_ip = ""
        protocol = "802.11"

        if ARP is not None and packet.haslayer(ARP):
            arp_layer = packet[ARP]
            protocol = "ARP"
            src_ip = getattr(arp_layer, "psrc", "") or ""
            dst_ip = getattr(arp_layer, "pdst", "") or ""
            src_mac = normalize_mac(getattr(arp_layer, "hwsrc", "") or src_mac)
            dst_mac = normalize_mac(getattr(arp_layer, "hwdst", "") or dst_mac)
        elif IP is not None and packet.haslayer(IP):
            ip_layer = packet[IP]
            protocol = "IP"
            src_ip = getattr(ip_layer, "src", "") or ""
            dst_ip = getattr(ip_layer, "dst", "") or ""

        essid, channel, security = PacketCapture._extract_wireless_metadata(packet)
        rssi = PacketCapture._extract_signal(packet)

        return {
            "timestamp": timestamp,
            "interface": interface,
            "frame_class": frame_class,
            "frame_type": frame_type,
            "frame_subtype": frame_subtype,
            "protocol": protocol,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "bssid": bssid,
            "essid": essid,
            "channel": channel,
            "rssi": rssi,
            "security": security,
            "source": src_ip or src_mac or transmitter or "unknown",
            "destination": dst_ip or dst_mac or receiver or "unknown",
        }

    @staticmethod
    def _extract_wireless_metadata(packet: Any) -> tuple[str, str, str]:
        essid = ""
        channel = ""
        has_rsn = False
        has_wpa = False
        privacy_enabled = False

        capability_layer = None
        if Dot11Beacon is not None and packet.haslayer(Dot11Beacon):
            capability_layer = packet[Dot11Beacon]
        elif Dot11ProbeResp is not None and packet.haslayer(Dot11ProbeResp):
            capability_layer = packet[Dot11ProbeResp]

        if capability_layer is not None:
            privacy_enabled = "privacy" in str(getattr(capability_layer, "cap", "")).lower()

        if Dot11Elt is None:
            return essid, channel, ""

        element = packet.getlayer(Dot11Elt)
        while isinstance(element, Dot11Elt):
            element_id = getattr(element, "ID", None)
            raw_info = bytes(getattr(element, "info", b"") or b"")

            if element_id == 0:
                essid = raw_info.decode("utf-8", errors="ignore").strip("\x00")
            elif element_id == 3 and raw_info:
                channel = str(raw_info[0])
            elif element_id == 48:
                has_rsn = True
            elif element_id == 221 and raw_info.startswith(b"\x00P\xf2\x01"):
                has_wpa = True

            element = element.payload.getlayer(Dot11Elt)

        if has_rsn and has_wpa:
            security = "WPA/WPA2"
        elif has_rsn:
            security = "WPA2/WPA3"
        elif has_wpa:
            security = "WPA"
        elif privacy_enabled:
            security = "WEP"
        elif essid or capability_layer is not None:
            security = "OPEN"
        else:
            security = ""

        return essid, channel, security

    @staticmethod
    def _extract_signal(packet: Any) -> int | str:
        if RadioTap is None or not packet.haslayer(RadioTap):
            return ""
        signal = getattr(packet[RadioTap], "dBm_AntSignal", None)
        if signal is None:
            return ""
        try:
            return int(signal)
        except (TypeError, ValueError):
            return ""

    @staticmethod
    def _extract_bssid(dot11_layer: Any) -> str:
        addr1 = normalize_mac(getattr(dot11_layer, "addr1", "") or "")
        addr2 = normalize_mac(getattr(dot11_layer, "addr2", "") or "")
        addr3 = normalize_mac(getattr(dot11_layer, "addr3", "") or "")

        if getattr(dot11_layer, "type", None) != 2:
            return addr3 or addr2 or addr1

        fc_field = int(getattr(dot11_layer, "FCfield", 0))
        to_ds = fc_field & 0x1
        from_ds = fc_field & 0x2

        if to_ds and not from_ds:
            return addr1
        if from_ds and not to_ds:
            return addr2
        if not to_ds and not from_ds:
            return addr3
        return addr1 or addr2 or addr3

    @staticmethod
    def _frame_class_name(frame_type: int) -> str:
        return {
            0: "Management",
            1: "Control",
            2: "Data",
        }.get(frame_type, "Other")

    @staticmethod
    def _display_frame_type(frame_class: str, frame_subtype: str) -> str:
        if frame_class == "Management" and frame_subtype not in {"Management", "Other"}:
            return frame_subtype
        if frame_class in {"Control", "Data"}:
            return frame_class
        return frame_subtype or frame_class

    @staticmethod
    def _wireless_subtype(dot11_layer: Any) -> str:
        subtype_map = {
            (0, 0): "Association Request",
            (0, 1): "Association Response",
            (0, 4): "Probe Request",
            (0, 5): "Probe Response",
            (0, 8): "Beacon",
            (0, 10): "Disassociation",
            (0, 11): "Authentication",
            (0, 12): "Deauthentication",
        }
        frame_type = getattr(dot11_layer, "type", -1)
        frame_subtype = getattr(dot11_layer, "subtype", -1)
        if frame_type == 2:
            return "Data"
        if frame_type == 1:
            return "Control"
        return subtype_map.get(
            (frame_type, frame_subtype),
            PacketCapture._frame_class_name(frame_type),
        )

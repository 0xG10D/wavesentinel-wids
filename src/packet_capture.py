from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Callable

try:
    from scapy.all import (
        ARP,
        Dot11,
        Dot11Beacon,
        Dot11Elt,
        Dot11ProbeReq,
        Dot11ProbeResp,
        IP,
        RadioTap,
        sniff,
    )
    from scapy.error import Scapy_Exception

    SCAPY_AVAILABLE = True
except ImportError:
    ARP = Dot11 = Dot11Beacon = Dot11Elt = Dot11ProbeReq = Dot11ProbeResp = None
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
        self.interface = interface.strip()
        self.channel = channel
        self.bssid_filter = normalize_mac(bssid)
        self.essid_filter = essid.strip()
        self.sniff_timeout = max(1, sniff_timeout)
        self.current_channel = str(channel or "")

    def validate_interface(self) -> None:
        if not SCAPY_AVAILABLE:
            raise PacketCaptureError("Scapy is not installed. Install requirements first.")
        if not self.interface:
            raise PacketCaptureInterfaceError("A monitor-mode interface is required.")

        self._validate_monitor_mode()
        if self.channel is not None:
            self._lock_channel(self.channel)

    def sniff_live(self, packet_callback: Callable[[dict[str, Any]], None]) -> None:
        while True:
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
                normalize_mac(packet.get("transmitter")),
                normalize_mac(packet.get("receiver")),
            }
            if self.bssid_filter not in bssid_candidates:
                return False

        if self.essid_filter:
            packet_essid = str(packet.get("essid", "") or "").strip()
            if packet_essid != self.essid_filter:
                return False

        return True

    def _validate_monitor_mode(self) -> None:
        if not sys.platform.startswith("linux"):
            raise PacketCaptureMonitorModeError(
                "Monitor-mode validation is implemented for Linux lab hosts only."
            )

        iw_result = self._run_command(["iw", "dev", self.interface, "info"])
        if iw_result is not None:
            if iw_result.returncode == 0 and "type monitor" in iw_result.stdout.lower():
                return
            if "no such device" in iw_result.stderr.lower():
                raise PacketCaptureInterfaceError(
                    f"Interface '{self.interface}' was not found by iw."
                )

        iwconfig_result = self._run_command(["iwconfig", self.interface])
        if iwconfig_result is not None:
            combined = f"{iwconfig_result.stdout}\n{iwconfig_result.stderr}".lower()
            if iwconfig_result.returncode == 0 and "mode:monitor" in combined:
                return
            if "no such device" in combined or "does not exist" in combined:
                raise PacketCaptureInterfaceError(
                    f"Interface '{self.interface}' was not found by iwconfig."
                )

        raise PacketCaptureMonitorModeError(
            f"Interface '{self.interface}' is not in monitor mode. Prepare it with iw/airmon-ng first."
        )

    def _lock_channel(self, channel: int) -> None:
        if not sys.platform.startswith("linux"):
            raise PacketCaptureMonitorModeError("Channel lock is implemented for Linux lab hosts only.")

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
        if iwconfig_result is not None and self._looks_like_permission_error(iwconfig_result.stderr):
            raise PacketCapturePermissionError(
                f"Channel lock on {self.interface} requires elevated privileges."
            )

        raise PacketCaptureError(
            f"Failed to lock {self.interface} to channel {channel}. Check that the interface is monitor-mode capable."
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
        frame_type = PacketCapture._frame_type_name(getattr(dot11, "type", -1))
        frame_subtype = PacketCapture._wireless_subtype(dot11)
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
        signal_dbm = PacketCapture._extract_signal(packet)

        summary = {
            "timestamp": timestamp,
            "interface": interface,
            "channel": channel,
            "frame_type": frame_type,
            "frame_subtype": frame_subtype,
            "protocol": protocol,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "bssid": bssid,
            "transmitter": transmitter,
            "receiver": receiver,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "essid": essid,
            "security": security,
            "signal_dbm": signal_dbm,
            "length": len(packet),
            "source": src_ip or src_mac or transmitter or "unknown",
            "destination": dst_ip or dst_mac or receiver or "unknown",
        }
        return summary

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
    def _frame_type_name(frame_type: int) -> str:
        return {
            0: "Management",
            1: "Control",
            2: "Data",
        }.get(frame_type, "Other")

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
        return subtype_map.get(
            (getattr(dot11_layer, "type", -1), getattr(dot11_layer, "subtype", -1)),
            f"Type {getattr(dot11_layer, 'type', -1)} / Subtype {getattr(dot11_layer, 'subtype', -1)}",
        )

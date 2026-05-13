from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from scapy.all import ARP, Dot11, Ether, ICMP, IP, IPv6, TCP, UDP, rdpcap, sniff
    from scapy.error import Scapy_Exception

    SCAPY_AVAILABLE = True
except ImportError:
    ARP = Dot11 = Ether = ICMP = IP = IPv6 = TCP = UDP = None
    rdpcap = sniff = None
    Scapy_Exception = Exception
    SCAPY_AVAILABLE = False


class PacketCaptureError(RuntimeError):
    """Base error for packet capture failures."""


class PacketCapturePermissionError(PacketCaptureError):
    """Raised when capture privileges are insufficient."""


class PacketCaptureInterfaceError(PacketCaptureError):
    """Raised when the requested interface is invalid or unavailable."""


class PacketCapture:
    def __init__(
        self,
        interface: str = "",
        pcap_path: str = "",
        timeout: int = 10,
        count: int = 50,
    ) -> None:
        self.interface = interface.strip()
        self.pcap_path = pcap_path.strip()
        self.timeout = timeout
        self.count = count

    def capture_live(self) -> list[dict[str, str]]:
        if not SCAPY_AVAILABLE:
            raise PacketCaptureError(
                "Scapy is not installed. Install dependencies or use demo mode."
            )

        sniff_kwargs: dict[str, Any] = {
            "store": True,
            "timeout": self.timeout,
            "count": self.count,
            "promisc": True,
        }
        if self.interface:
            sniff_kwargs["iface"] = self.interface

        try:
            packets = sniff(**sniff_kwargs)
        except PermissionError as exc:
            raise PacketCapturePermissionError(
                "Live capture requires root privileges or CAP_NET_RAW/CAP_NET_ADMIN."
            ) from exc
        except OSError as exc:
            raise PacketCapturePermissionError(
                "The operating system blocked packet capture. Try sudo or demo mode."
            ) from exc
        except Scapy_Exception as exc:
            message = str(exc)
            lowered = message.lower()
            if "no such device" in lowered or "not found" in lowered:
                raise PacketCaptureInterfaceError(
                    f"Capture interface '{self.interface or 'default'}' is unavailable."
                ) from exc
            raise PacketCaptureError(
                f"Scapy failed to capture packets: {message}"
            ) from exc

        return [self.extract_packet_summary(packet, capture_mode="live") for packet in packets]

    def load_pcap(self) -> list[dict[str, str]]:
        if not self.pcap_path:
            raise PacketCaptureError("No PCAP file was provided.")
        if not SCAPY_AVAILABLE:
            raise PacketCaptureError(
                "Scapy is not installed. Install dependencies before reading PCAP files."
            )

        pcap_file = Path(self.pcap_path)
        if not pcap_file.exists():
            raise PacketCaptureError(f"PCAP file not found: {pcap_file}")

        try:
            packets = rdpcap(str(pcap_file))
        except FileNotFoundError as exc:
            raise PacketCaptureError(f"PCAP file not found: {pcap_file}") from exc
        except Scapy_Exception as exc:
            raise PacketCaptureError(f"Failed to parse PCAP file: {exc}") from exc

        return [self.extract_packet_summary(packet, capture_mode="pcap") for packet in packets]

    def load_demo_packets(self) -> list[dict[str, str]]:
        now = datetime.now().astimezone()

        records: list[dict[str, str]] = [
            self._demo_record(
                now,
                src_mac="AA:BB:CC:DD:EE:10",
                dst_mac="AA:BB:CC:DD:EE:01",
                src_ip="192.168.1.10",
                dst_ip="192.168.1.1",
                protocol="TCP",
                transport="TCP",
                length="128",
            ),
            self._demo_record(
                now + timedelta(seconds=1),
                src_mac="AA:BB:CC:DD:EE:20",
                dst_mac="AA:BB:CC:DD:EE:01",
                src_ip="192.168.1.20",
                dst_ip="8.8.8.8",
                protocol="UDP",
                transport="UDP",
                length="96",
            ),
            self._demo_record(
                now + timedelta(seconds=2),
                src_mac="66:77:88:99:AA:BB",
                dst_mac="AA:BB:CC:DD:EE:10",
                src_ip="192.168.1.250",
                dst_ip="192.168.1.10",
                protocol="UDP",
                transport="UDP",
                length="144",
            ),
            self._demo_record(
                now + timedelta(seconds=3),
                src_mac="AA:BB:CC:DD:EE:01",
                dst_mac="FF:FF:FF:FF:FF:FF",
                src_ip="192.168.1.1",
                dst_ip="192.168.1.10",
                protocol="ARP",
                transport="",
                length="42",
            ),
            self._demo_record(
                now + timedelta(seconds=4),
                src_mac="DE:AD:BE:EF:00:01",
                dst_mac="FF:FF:FF:FF:FF:FF",
                src_ip="192.168.1.1",
                dst_ip="192.168.1.20",
                protocol="ARP",
                transport="",
                length="42",
            ),
        ]

        for offset in range(30):
            records.append(
                self._demo_record(
                    now + timedelta(seconds=5, milliseconds=offset * 150),
                    src_mac="66:77:88:99:AA:BB",
                    dst_mac="AA:BB:CC:DD:EE:01",
                    src_ip="192.168.1.250",
                    dst_ip="192.168.1.1",
                    protocol="UDP",
                    transport="UDP",
                    length="110",
                )
            )

        for offset in range(4):
            records.append(
                self._demo_record(
                    now + timedelta(seconds=8 + offset),
                    src_mac="CA:FE:00:00:00:99",
                    dst_mac="AA:BB:CC:DD:EE:10",
                    src_ip="",
                    dst_ip="",
                    protocol="802.11",
                    transport="",
                    length="64",
                    wireless_subtype="Deauthentication",
                )
            )

        return records

    @staticmethod
    def extract_packet_summary(packet: Any, capture_mode: str) -> dict[str, str]:
        packet_time = getattr(packet, "time", datetime.now(tz=timezone.utc).timestamp())
        timestamp = datetime.fromtimestamp(
            float(packet_time),
            tz=timezone.utc,
        ).astimezone().isoformat(timespec="seconds")

        src_mac = ""
        dst_mac = ""
        src_ip = ""
        dst_ip = ""
        protocol = "OTHER"
        transport = ""
        wireless_subtype = ""

        if Ether is not None and packet.haslayer(Ether):
            src_mac = getattr(packet[Ether], "src", "") or src_mac
            dst_mac = getattr(packet[Ether], "dst", "") or dst_mac

        if Dot11 is not None and packet.haslayer(Dot11):
            dot11 = packet[Dot11]
            src_mac = getattr(dot11, "addr2", "") or src_mac
            dst_mac = getattr(dot11, "addr1", "") or dst_mac
            protocol = "802.11"
            wireless_subtype = PacketCapture._wireless_subtype(dot11)

        if ARP is not None and packet.haslayer(ARP):
            arp_layer = packet[ARP]
            protocol = "ARP"
            src_ip = getattr(arp_layer, "psrc", "") or src_ip
            dst_ip = getattr(arp_layer, "pdst", "") or dst_ip
            src_mac = getattr(arp_layer, "hwsrc", "") or src_mac
            dst_mac = getattr(arp_layer, "hwdst", "") or dst_mac
        elif IP is not None and packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = getattr(ip_layer, "src", "") or src_ip
            dst_ip = getattr(ip_layer, "dst", "") or dst_ip
            protocol = "IP"
            if TCP is not None and packet.haslayer(TCP):
                protocol = "TCP"
                transport = "TCP"
            elif UDP is not None and packet.haslayer(UDP):
                protocol = "UDP"
                transport = "UDP"
            elif ICMP is not None and packet.haslayer(ICMP):
                protocol = "ICMP"
                transport = "ICMP"
        elif IPv6 is not None and packet.haslayer(IPv6):
            ipv6_layer = packet[IPv6]
            src_ip = getattr(ipv6_layer, "src", "") or src_ip
            dst_ip = getattr(ipv6_layer, "dst", "") or dst_ip
            protocol = "IPv6"

        source = src_ip or src_mac or "unknown"
        destination = dst_ip or dst_mac or "unknown"

        return {
            "timestamp": timestamp,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "transport": transport,
            "length": str(len(packet)),
            "source": source,
            "destination": destination,
            "capture_mode": capture_mode,
            "wireless_subtype": wireless_subtype,
        }

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
        return subtype_map.get((dot11_layer.type, dot11_layer.subtype), "")

    @staticmethod
    def _demo_record(
        timestamp: datetime,
        src_mac: str,
        dst_mac: str,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        transport: str,
        length: str,
        wireless_subtype: str = "",
    ) -> dict[str, str]:
        return {
            "timestamp": timestamp.isoformat(timespec="seconds"),
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "transport": transport,
            "length": length,
            "source": src_ip or src_mac,
            "destination": dst_ip or dst_mac,
            "capture_mode": "demo",
            "wireless_subtype": wireless_subtype,
        }

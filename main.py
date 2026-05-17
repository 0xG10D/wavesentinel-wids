from __future__ import annotations

import argparse
import time
from datetime import datetime
from pathlib import Path

from src.attack_detector import AttackDetector
from src.device_scanner import DeviceTracker, TrustedDeviceRegistry
from src.logger import MonitorLogger
from src.packet_capture import (
    PacketCapture,
    PacketCaptureError,
    PacketCaptureInterfaceError,
    PacketCapturePermissionError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Wireless Network Security Monitor",
    )
    parser.add_argument(
        "--mode",
        choices=("auto", "live", "pcap", "demo"),
        default="auto",
        help="Traffic source selection. 'auto' tries live capture first.",
    )
    parser.add_argument(
        "--interface",
        default="",
        help="Interface for live capture, for example wlan0 or wlan0mon.",
    )
    parser.add_argument(
        "--pcap",
        default="",
        help="Path to an offline PCAP file when using --mode pcap.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=50,
        help="Packets to capture per monitoring cycle.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Capture timeout in seconds per monitoring cycle.",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Delay between cycles when running multiple iterations.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Number of monitoring cycles. Use 0 for continuous monitoring.",
    )
    parser.add_argument(
        "--packet-rate-threshold",
        type=int,
        default=25,
        help="Packets from one source inside 10 seconds before flood alerting.",
    )
    parser.add_argument(
        "--reset-logs",
        action="store_true",
        help="Clear alert, traffic, device, and activity outputs before running.",
    )
    return parser


def resolve_mode(args: argparse.Namespace) -> str:
    if args.mode == "pcap" or args.pcap:
        return "pcap"
    if args.mode == "demo":
        return "demo"
    return "live"


def process_packets(
    packets: list[dict[str, str]],
    tracker: DeviceTracker,
    detector: AttackDetector,
    logger: MonitorLogger,
) -> tuple[int, int]:
    packet_total = 0
    alert_total = 0

    for packet in packets:
        logger.append_traffic(packet)
        tracker.observe(packet)
        packet_total += 1

        for alert in detector.analyze(packet):
            logger.append_alert(alert)
            logger.append_activity(
                f"{alert['alert_type']}: {alert['details']}",
                level=alert["severity"],
            )
            alert_total += 1

    logger.save_devices(tracker.export_devices())
    return packet_total, alert_total


def run_monitor(args: argparse.Namespace) -> int:
    base_dir = Path(__file__).resolve().parent
    data_dir = base_dir / "data"

    logger = MonitorLogger(data_dir)
    if args.reset_logs:
        logger.reset_runtime_outputs()

    registry = TrustedDeviceRegistry(data_dir / "known_devices.csv")
    tracker = DeviceTracker(registry)
    detector = AttackDetector(
        registry=registry,
        packet_rate_threshold=args.packet_rate_threshold,
    )
    capture = PacketCapture(
        interface=args.interface,
        pcap_path=args.pcap,
        timeout=args.timeout,
        count=args.count,
    )

    requested_mode = resolve_mode(args)
    interface_name = args.interface or "default"

    logger.append_activity(
        f"Monitoring session started in {requested_mode} mode on interface '{interface_name}'."
    )
    logger.update_status(
        running=True,
        mode=requested_mode,
        interface=interface_name,
        last_update=datetime.now().astimezone().isoformat(timespec="seconds"),
        packet_count=0,
        alert_count=0,
        device_count=0,
        message="Monitor initialized.",
        error="",
    )

    total_packets = 0
    total_alerts = 0
    cycle = 0
    last_effective_mode = requested_mode
    last_error = ""

    try:
        while args.iterations == 0 or cycle < args.iterations:
            cycle += 1
            active_mode = requested_mode
            cycle_message = ""

            try:
                if requested_mode == "pcap":
                    packets = capture.load_pcap()
                elif requested_mode == "demo":
                    packets = capture.load_demo_packets()
                else:
                    packets = capture.capture_live()
            except (
                PacketCapturePermissionError,
                PacketCaptureInterfaceError,
                PacketCaptureError,
            ) as exc:
                active_mode = "demo"
                requested_mode = "demo"
                cycle_message = f"{exc} Falling back to demo mode."
                last_error = cycle_message
                logger.append_activity(cycle_message, level="ERROR")
                packets = capture.load_demo_packets()

            if not packets:
                logger.append_activity(
                    "No packets were captured in the current monitoring cycle.",
                    level="WARN",
                )

            packets_processed, alerts_raised = process_packets(
                packets=packets,
                tracker=tracker,
                detector=detector,
                logger=logger,
            )

            total_packets += packets_processed
            total_alerts += alerts_raised
            devices = tracker.export_devices()
            last_effective_mode = active_mode

            if not cycle_message:
                cycle_message = (
                    f"Cycle {cycle} complete: processed {packets_processed} packets "
                    f"and raised {alerts_raised} alerts in {active_mode} mode."
                )
            logger.append_activity(cycle_message)
            logger.update_status(
                running=True,
                mode=active_mode,
                interface=interface_name,
                last_update=datetime.now().astimezone().isoformat(timespec="seconds"),
                packet_count=total_packets,
                alert_count=total_alerts,
                device_count=len(devices),
                message=cycle_message,
                error=last_error,
            )

            if requested_mode == "pcap":
                break

            if args.iterations == 0 or cycle < args.iterations:
                time.sleep(args.interval)

    except KeyboardInterrupt:
        logger.append_activity("Monitoring interrupted by the operator.", level="WARN")
    finally:
        completion_message = "Monitoring session completed."
        if args.iterations == 0:
            completion_message = "Monitoring session stopped by the operator."

        logger.update_status(
            running=False,
            mode=last_effective_mode,
            interface=interface_name,
            last_update=datetime.now().astimezone().isoformat(timespec="seconds"),
            packet_count=total_packets,
            alert_count=total_alerts,
            device_count=len(tracker.export_devices()),
            message=completion_message,
            error=last_error,
        )
        logger.append_activity(completion_message)

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if resolve_mode(args) == "pcap" and not args.pcap:
        parser.error("--mode pcap requires --pcap /path/to/file.pcap")

    return run_monitor(args)


if __name__ == "__main__":
    raise SystemExit(main())

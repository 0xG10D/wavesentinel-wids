from __future__ import annotations

import argparse
import time
from datetime import datetime
from pathlib import Path

from src.attack_detector import AttackDetector, load_threshold_config
from src.logger import MonitorLogger
from src.packet_capture import (
    PacketCapture,
    PacketCaptureError,
    PacketCaptureInterfaceError,
    PacketCaptureMonitorModeError,
    PacketCapturePermissionError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Real-time wireless IDS monitor for authorized lab environments.",
    )
    parser.add_argument(
        "--interface",
        required=True,
        help="Monitor-mode wireless interface, for example wlan0mon.",
    )
    parser.add_argument(
        "--channel",
        type=int,
        default=None,
        help="Optional channel lock applied before live capture starts.",
    )
    parser.add_argument(
        "--bssid",
        default="",
        help="Optional BSSID filter to scope capture and alerts to one AP.",
    )
    parser.add_argument(
        "--essid",
        default="",
        help="Optional ESSID filter to scope capture and alerts to one SSID.",
    )
    parser.add_argument(
        "--config",
        default="config/thresholds.json",
        help="Path to the shared detector threshold config file.",
    )
    parser.add_argument(
        "--status-interval",
        type=int,
        default=3,
        help="Seconds between status and inventory flushes to data/status.json.",
    )
    parser.add_argument(
        "--reset-logs",
        action="store_true",
        help="Clear persisted alerts, traffic logs, inventory, and status before monitoring.",
    )
    return parser


def resolve_path(base_dir: Path, candidate: str) -> Path:
    path = Path(candidate)
    if path.is_absolute():
        return path
    return base_dir / path


def run_monitor(args: argparse.Namespace) -> int:
    if args.channel is not None and args.channel <= 0:
        raise ValueError("--channel must be a positive integer.")
    if args.status_interval <= 0:
        raise ValueError("--status-interval must be a positive integer.")

    base_dir = Path(__file__).resolve().parent
    data_dir = base_dir / "data"
    config_path = resolve_path(base_dir, args.config)

    logger = MonitorLogger(data_dir)
    if args.reset_logs:
        logger.reset_runtime_outputs()

    thresholds = load_threshold_config(config_path)
    detector = AttackDetector(thresholds)
    capture = PacketCapture(
        interface=args.interface,
        channel=args.channel,
        bssid=args.bssid,
        essid=args.essid,
    )

    current_message = "Validating monitor-mode interface."
    current_error = ""
    exit_code = 0
    status_started = False
    last_flush = 0.0

    def flush_runtime_state(force: bool = False) -> None:
        nonlocal last_flush

        now = time.monotonic()
        if not force and now - last_flush < args.status_interval:
            return

        snapshot = detector.get_status_snapshot()
        logger.save_devices(detector.export_devices())
        logger.update_status(
            running=status_started,
            mode="live",
            interface=args.interface,
            channel_lock=str(args.channel or ""),
            current_channel=capture.current_channel or snapshot["current_channel"],
            target_bssid=args.bssid.strip().upper(),
            target_essid=args.essid.strip(),
            packet_count=snapshot["packet_count"],
            alert_count=snapshot["alert_count"],
            ap_count=snapshot["ap_count"],
            client_count=snapshot["client_count"],
            severity_counts=snapshot["severity_counts"],
            attack_counts=snapshot["attack_counts"],
            frame_counters=snapshot["frame_counters"],
            last_update=datetime.now().astimezone().isoformat(timespec="seconds"),
            message=current_message,
            error=current_error,
        )
        last_flush = now

    def handle_packet(packet: dict[str, object]) -> None:
        nonlocal current_message

        logger.append_traffic(packet)
        alerts = detector.process_packet(packet)
        if alerts:
            latest_alert = alerts[-1]
            current_message = (
                f"{latest_alert['severity']} {latest_alert['attack_type']} detected on "
                f"{latest_alert.get('essid') or latest_alert.get('bssid') or args.interface}."
            )
            for alert in alerts:
                logger.append_alert(alert)
                logger.append_activity(
                    f"{alert['attack_type']}: {alert['details']}",
                    level=str(alert["severity"]),
                )

        flush_runtime_state()

    logger.append_activity(f"Loading thresholds from {config_path}.")
    flush_runtime_state(force=True)

    try:
        capture.validate_interface()
        current_message = f"Live monitoring active on {args.interface}."
        if args.channel:
            current_message = (
                f"Live monitoring active on {args.interface} with channel lock {args.channel}."
            )
        status_started = True
        logger.append_activity(current_message)
        flush_runtime_state(force=True)
        capture.sniff_live(handle_packet)
    except KeyboardInterrupt:
        current_message = "Monitoring stopped by the operator."
        logger.append_activity(current_message, level="WARN")
    except (
        PacketCapturePermissionError,
        PacketCaptureInterfaceError,
        PacketCaptureMonitorModeError,
        PacketCaptureError,
        FileNotFoundError,
        ValueError,
    ) as exc:
        current_error = str(exc)
        current_message = "Monitoring stopped due to a capture or configuration error."
        exit_code = 1
        logger.append_activity(current_error, level="ERROR")
    finally:
        status_started = False
        flush_runtime_state(force=True)

    return exit_code


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_monitor(args)


if __name__ == "__main__":
    raise SystemExit(main())

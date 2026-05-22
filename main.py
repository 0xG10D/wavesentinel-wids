from __future__ import annotations

import argparse
import sys
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
from src.session_manager import SessionLockError, SessionManager

NO_PACKET_WARNING_SECONDS = 15
NO_PACKET_WARNING_MESSAGE = (
    "No packets captured. Check monitor mode, channel, adapter driver, or interface name."
)
SAFE_STOP_MESSAGE = "Monitoring stopped safely."


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WaveSentinel WIDS real-time monitor for authorized lab environments.",
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
        "--reset-session",
        dest="reset_session",
        action="store_true",
        help="Archive the current data/ folder and start with a clean session state.",
    )
    parser.add_argument(
        "--reset-logs",
        dest="reset_session",
        action="store_true",
        help="Alias for --reset-session.",
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
    archive_dir = base_dir / "archive"
    config_path = resolve_path(base_dir, args.config)

    session_manager = SessionManager(base_dir=base_dir, data_dir=data_dir, archive_dir=archive_dir)

    try:
        session_manager.acquire()
    except SessionLockError as exc:
        print(str(exc), file=sys.stderr, flush=True)
        return 1

    archive_path: Path | None = None
    if args.reset_session:
        archive_path = session_manager.archive_data_dir()

    logger = MonitorLogger(data_dir)
    if args.reset_session:
        logger.reset_runtime_outputs()

    thresholds = load_threshold_config(config_path)
    detector = AttackDetector(thresholds)
    capture = PacketCapture(
        interface=args.interface,
        channel=args.channel,
        bssid=args.bssid,
        essid=args.essid,
    )

    current_message = "Validating capture interface."
    current_state = "Starting"
    current_error = ""
    exit_code = 0
    session_running = False
    last_flush = 0.0
    session_started_at_iso = ""
    capture_started_at = 0.0
    no_packet_warning_logged = False
    stop_reason = ""
    stop_reason_logged = False

    def log_once(message: str, level: str = "INFO") -> None:
        logger.append_activity(message, level=level)
        print(message, flush=True)

    def handle_stop_signal(message: str) -> None:
        nonlocal current_message, current_state, stop_reason
        current_message = SAFE_STOP_MESSAGE
        current_state = "Stopping"
        stop_reason = SAFE_STOP_MESSAGE
        logger.append_activity(message, level="WARN")
        print(message, flush=True)

    def handle_suspend_signal(message: str) -> None:
        nonlocal current_message, current_state, stop_reason
        current_message = SAFE_STOP_MESSAGE
        current_state = "Stopping"
        stop_reason = SAFE_STOP_MESSAGE
        logger.append_activity(message, level="WARN")
        print(message, flush=True)

    session_manager.install_signal_handlers(
        on_stop=handle_stop_signal,
        on_suspend=handle_suspend_signal,
    )

    def flush_runtime_state(force: bool = False) -> None:
        nonlocal last_flush, no_packet_warning_logged, current_message, stop_reason_logged

        now = time.monotonic()
        if not force and now - last_flush < args.status_interval:
            return

        snapshot = detector.get_status_snapshot()
        logger.save_devices(detector.export_devices())

        troubleshooting: list[str] = []
        if session_running and snapshot["packet_count"] == 0 and capture_started_at:
            if now - capture_started_at >= NO_PACKET_WARNING_SECONDS:
                warning = NO_PACKET_WARNING_MESSAGE
                troubleshooting = [
                    warning,
                    (
                        f"WaveSentinel requested '{args.interface}' and is currently "
                        f"using '{capture.interface}'."
                    ),
                    "Verify the adapter is in monitor mode and locked to the expected channel.",
                    "airmon-ng may rename long adapter names to wlan0mon.",
                ]
                if not no_packet_warning_logged:
                    logger.append_activity(warning, level="WARN")
                    no_packet_warning_logged = True
                if not current_error and not stop_reason:
                    current_message = warning
        else:
            no_packet_warning_logged = False

        if stop_reason and not stop_reason_logged:
            logger.append_activity(stop_reason, level="WARN")
            stop_reason_logged = True

        logger.update_status(
            running=session_running,
            mode="live",
            pid=session_manager.pid,
            requested_interface=args.interface,
            interface=capture.interface or args.interface,
            interface_mode=capture.interface_mode,
            interface_resolution=capture.interface_resolution,
            channel_lock=str(args.channel or ""),
            current_channel=capture.current_channel or snapshot["current_channel"],
            target_bssid=args.bssid.strip().upper(),
            target_essid=args.essid.strip(),
            session_started_at=session_started_at_iso,
            packet_count=snapshot["packet_count"],
            alert_count=snapshot["alert_count"],
            ap_count=snapshot["ap_count"],
            client_count=snapshot["client_count"],
            severity_counts=snapshot["severity_counts"],
            attack_counts=snapshot["attack_counts"],
            frame_counters=snapshot["frame_counters"],
            advisories=snapshot["advisories"],
            troubleshooting=troubleshooting,
            last_update=datetime.now().astimezone().isoformat(timespec="seconds"),
            message=current_message,
            state=current_state,
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
                f"{latest_alert.get('essid') or latest_alert.get('bssid') or capture.interface}."
            )
            for alert in alerts:
                logger.append_alert(alert)
                logger.append_activity(
                    f"{alert['attack_type']}: {alert['details']}",
                    level=str(alert["severity"]),
                )
        elif detector.packet_count == 1 or current_message == NO_PACKET_WARNING_MESSAGE:
            current_message = f"Live monitoring active on {capture.interface}."

        flush_runtime_state()

    try:
        if archive_path is not None:
            logger.append_activity(f"Archived previous session data to {archive_path}.")

        logger.append_activity(f"Loading thresholds from {config_path}.")
        flush_runtime_state(force=True)

        capture.validate_interface()
        if capture.interface_resolution:
            logger.append_activity(capture.interface_resolution, level="WARN")

        session_started_at_iso = datetime.now().astimezone().isoformat(timespec="seconds")
        capture_started_at = time.monotonic()
        session_running = True
        current_state = "Running"
        current_message = f"Live monitoring active on {capture.interface}."
        if args.channel:
            current_message = (
                f"Live monitoring active on {capture.interface} with channel lock {args.channel}."
            )
        logger.append_activity(current_message)
        flush_runtime_state(force=True)

        capture.sniff_live(
            packet_callback=handle_packet,
            should_stop=lambda: session_manager.stop_requested,
        )

        if not current_error:
            current_message = stop_reason or SAFE_STOP_MESSAGE

    except KeyboardInterrupt:
        current_message = SAFE_STOP_MESSAGE
        current_state = "Stopped"
        stop_reason = SAFE_STOP_MESSAGE
    except (
        PacketCapturePermissionError,
        PacketCaptureInterfaceError,
        PacketCaptureMonitorModeError,
        PacketCaptureError,
        FileNotFoundError,
        ValueError,
    ) as exc:
        current_error = str(exc)
        current_state = "Error"
        current_message = "Monitoring stopped due to a capture or configuration error."
        exit_code = 1
        logger.append_activity(current_error, level="ERROR")
        print(current_error, file=sys.stderr, flush=True)
    except Exception as exc:  # pragma: no cover - safety net for runtime failures
        current_error = f"Unexpected WIDS engine error: {exc}"
        current_state = "Error"
        current_message = "Monitoring stopped due to an unexpected runtime error."
        exit_code = 1
        logger.append_activity(current_error, level="ERROR")
        print(current_error, file=sys.stderr, flush=True)
    finally:
        session_running = False
        if current_state != "Error":
            current_state = "Stopped"
            current_message = stop_reason or SAFE_STOP_MESSAGE
        flush_runtime_state(force=True)
        session_manager.release()

    return exit_code


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_monitor(args)


if __name__ == "__main__":
    raise SystemExit(main())

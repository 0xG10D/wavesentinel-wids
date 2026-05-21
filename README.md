# Wireless Security Monitor

This project is now a real-time, web UI focused wireless intrusion detection system for authorized lab use. The old desktop GUI, offline PCAP workflow, and demo mode have been removed. The monitor captures live 802.11 traffic from a real monitor-mode adapter, pushes every packet through one detection engine, and writes the dashboard data into `data/`.

## What it does

- Uses Scapy live sniffing with `store=False`.
- Validates that the selected interface is already in monitor mode before capture starts.
- Supports optional scope filters for `--bssid`, `--channel`, and `--essid`.
- Detects:
  - Deauthentication flood
  - Disassociation flood
  - Beacon flood
  - Probe request flood
  - Evil Twin suspicion based on duplicate SSID with conflicting security
  - Open network exposure
  - ARP spoofing where decoded from captured wireless data frames
- Persists runtime telemetry to:
  - `data/alerts.csv`
  - `data/alerts.json`
  - `data/traffic_logs.csv`
  - `data/devices.json`
  - `data/status.json`
  - `data/activity_logs.json`

## Project structure

- `main.py`
  - Starts live monitoring only.
  - Validates the monitor-mode interface.
  - Loads the shared thresholds from `config/thresholds.json`.
  - Streams packets into the unified detector and logger pipeline.
- `src/packet_capture.py`
  - Runs live Scapy sniffing.
  - Applies optional channel lock on Linux.
  - Normalizes live 802.11 packets into structured records.
- `src/attack_detector.py`
  - Maintains one detection engine for alerts, AP inventory, client inventory, and counters.
- `src/logger.py`
  - Persists alerts, traffic, device inventory, status, and activity logs to `data/`.
- `web/app.py`
  - Reads the generated files and serves the dashboard.
- `web/templates/dashboard.html`
  - Operator dashboard with auto-refresh and filter controls.
- `config/thresholds.json`
  - Single source of truth for alert thresholds and cooldowns.

## Requirements

- Linux lab host recommended. The interface validation and channel lock flow use `iw` or `iwconfig`.
- A monitor-mode capable wireless adapter.
- Root privileges or equivalent capture capabilities for Scapy.

Install dependencies:

```bash
pip install -r requirements.txt
```

## Prepare the interface

Example on Kali or another Linux lab host:

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
iw dev wlan0mon info
```

The monitor expects an interface such as `wlan0mon`. If the interface is not in monitor mode, `main.py` exits instead of falling back to any simulation path.

## Start live monitoring

Example with channel lock and BSSID targeting:

```bash
sudo python3 main.py --interface wlan0mon --channel 4 --bssid FC:3F:FC:93:7F:B1
```

Example with ESSID targeting:

```bash
sudo python3 main.py --interface wlan0mon --essid Lab-Network
```

Optional clean start:

```bash
sudo python3 main.py --interface wlan0mon --reset-logs
```

## Start the web dashboard

Run the dashboard in a second terminal:

```bash
python3 web/app.py
```

Then open:

```text
http://127.0.0.1:5000
```

The dashboard reads directly from the files in `data/` and shows:

- Live alert feed
- Threat severity count
- Detected APs
- Detected clients
- Current interface
- Current channel
- Packet count
- Deauth, disassoc, beacon, and probe statistics
- Recent high severity alerts
- Filters for severity, BSSID, ESSID, and attack type

## Threshold tuning

Thresholds are centralized in `config/thresholds.json`.

Example:

```json
{
  "deauth_flood": {
    "count": 15,
    "window_seconds": 10,
    "cooldown_seconds": 30,
    "severity": "CRITICAL"
  }
}
```

Tune these values for your lab density, channel usage, and false-positive tolerance.

## Defensive scope

This repository is detection-only. It does not contain attack execution helpers, deauth automation, or GUI-side simulation paths.

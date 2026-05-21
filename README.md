# WaveSentinel: Real-Time 802.11 Wireless Intrusion Detection Dashboard

Repository name: `wavesentinel-wids`

WaveSentinel is a defensive wireless intrusion detection system for authorized lab environments. It captures real 802.11 traffic from a monitor-mode adapter, correlates alerts in one detection pipeline, and exposes live status through a web dashboard.

## Features

- Live Scapy sniffing with `store=False`
- Monitor-mode validation before capture starts
- Automatic handling of `airmon-ng` interface renames such as `wlx6c1ff7d85510` to `wlan0mon`
- Real-time detection for:
  - Deauthentication flood
  - Disassociation flood
  - Beacon flood
  - Probe request flood
  - Evil Twin suspicion
  - Open network detection
  - ARP spoofing suspicion where traffic supports it
- Unified logging to:
  - `data/alerts.csv`
  - `data/alerts.json`
  - `data/traffic_logs.csv`
  - `data/devices.json`
  - `data/status.json`
  - `data/activity_logs.json`
- Web dashboard with non-technical and analyst views
- Defensive-only scope with no attack automation

## Recommended Two-Adapter Setup

Use one adapter for normal connectivity and one adapter for monitor-mode capture:

- `wlp3s0` = managed Wi-Fi / Internet adapter
- `wlx6c1ff7d85510` = USB adapter
- `wlan0mon` = actual monitor interface created by `airmon-ng`
- Channel `4` = lab channel
- Lab AP: `G10D_Lab_Env-2.4GHz`
- Lab BSSID: `FC:3F:FC:93:7F:B1`

WaveSentinel reports the real capture interface in `data/status.json` and in the dashboard so the UI matches the adapter Linux actually put into monitor mode.

## Requirements

- Linux lab host
- Monitor-mode capable USB Wi-Fi adapter
- Root privileges or equivalent capture capability
- `iw`, `iwconfig`, and `airmon-ng`
- Python dependencies from `requirements.txt`

Install dependencies:

```bash
pip install -r requirements.txt
```

For contributor setup, editable installs, and local validation commands, see
`DEVELOPMENT.md`.

## Usage

Start monitor mode on the USB adapter:

```bash
sudo airmon-ng start wlx6c1ff7d85510 4
```

Start WaveSentinel live monitoring:

```bash
sudo ../venv/bin/python3 -u main.py \
  --interface wlan0mon \
  --channel 4 \
  --reset-session
```

Start the dashboard:

```bash
python3 web/app.py
```

Open `http://127.0.0.1:5000`.

## Example Lab Notes

- If `airmon-ng` renames the long USB adapter name, use the real active monitor interface such as `wlan0mon`.
- Use `--bssid FC:3F:FC:93:7F:B1` when you want to scope monitoring to the lab AP.
- Use `CTRL+C` to stop the engine cleanly.
- Do not use `CTRL+Z`; WaveSentinel blocks suspend behavior to avoid leaving stopped capture processes behind.

## Session Behavior

- `--reset-session`
  - Archives the current `data/` folder into `archive/session_TIMESTAMP.tar.gz`
  - Resets alerts, traffic logs, devices, status, and activity logs
- `--reset-logs`
  - Alias for `--reset-session`
- A PID lock prevents multiple WaveSentinel engines from running at the same time

## Dashboard Views

### Non-Technical View

- Safe / Warning / Critical summary cards
- Plain-language findings
- Suggested operator actions
- Simple definitions for AP, client, packet, beacon, and deauth

### Technical Analyst View

- Real capture interface and channel
- Access point and client inventory
- Alert feed with severity and MITRE mapping
- Traffic logs table
- Filters for severity, attack type, BSSID, ESSID, and channel
- CSV and JSON exports for dashboard data

## Defensive Scope

WaveSentinel is detection-only.

- No deauthentication transmit automation
- No `aireplay-ng` execution
- No attack orchestration
- Monitoring, logging, and visualization only

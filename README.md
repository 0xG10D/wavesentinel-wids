# Wireless Network Security Monitor

Wireless Network Security Monitor is a defensive mini project for `CBS 2343 Wireless Network Security`. It captures or replays network traffic, extracts packet metadata, detects suspicious patterns, writes alerts to CSV, and visualizes the latest results on a localhost Flask dashboard.

This project is intentionally scoped for an authorized academic lab. It does **not** exploit targets, transmit attacks, or automate offensive actions.

## Core Capabilities

- Live packet capture with `Scapy`
- Offline replay from a `.pcap` file
- Demo mode with seeded sample traffic for presentation use
- Trusted device tracking from `data/known_devices.csv`
- Detection for:
  - Unknown device access
  - ARP spoofing suspicion
  - Deauthentication-like wireless events
  - Packet flood or abnormal packet rate
- CSV logging for alerts and traffic
- Flask dashboard at `http://127.0.0.1:5000`

## Project Structure

```text
wireless-security-monitor/
├── README.md
├── requirements.txt
├── main.py
├── src/
│   ├── __init__.py
│   ├── packet_capture.py
│   ├── device_scanner.py
│   ├── attack_detector.py
│   └── logger.py
├── web/
│   ├── app.py
│   ├── templates/dashboard.html
│   └── static/style.css
├── data/
│   ├── known_devices.csv
│   ├── alerts.csv
│   ├── traffic_logs.csv
│   ├── status.json
│   ├── devices.json
│   └── activity_logs.json
└── screenshots/
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run Commands

Run one monitoring cycle:

```bash
sudo python3 main.py
```

Run against a specific interface:

```bash
sudo python3 main.py --interface wlan0
```

Run continuously until you stop it:

```bash
sudo python3 main.py --interface wlan0 --iterations 0
```

Run in demo mode:

```bash
python3 main.py --mode demo --reset-logs
```

Replay a packet capture file:

```bash
python3 main.py --mode pcap --pcap /path/to/lab_capture.pcap --reset-logs
```

Start the dashboard:

```bash
python3 web/app.py
```

Open:

```text
http://127.0.0.1:5000
```

## How It Works

1. `main.py` selects a traffic source: live capture, PCAP replay, or demo mode.
2. `src/packet_capture.py` extracts packet metadata such as MAC, IP, protocol, packet size, and wireless subtype.
3. `src/device_scanner.py` compares observed devices against the trusted list in `data/known_devices.csv`.
4. `src/attack_detector.py` raises alerts when suspicious patterns appear.
5. `src/logger.py` writes:
   - `data/alerts.csv`
   - `data/traffic_logs.csv`
   - `data/status.json`
   - `data/devices.json`
   - `data/activity_logs.json`
6. `web/app.py` reads those files and renders the dashboard.

## Detection Logic

### 1. Unknown Device Access

If a source MAC address is not present in `data/known_devices.csv`, the monitor creates an alert.

Example:

```text
Observed source MAC 66:77:88:99:AA:BB is not on the trusted device list.
```

### 2. ARP Spoofing Suspicion

If the same IP address appears with different MAC addresses across ARP traffic, the monitor flags possible spoofing.

Example:

```text
192.168.1.1 was first seen with AA:BB:CC:DD:EE:01, then appeared with DE:AD:BE:EF:00:01.
```

### 3. Deauthentication-Like Events

If 802.11 management frames with `Deauthentication` or `Disassociation` subtypes are detected repeatedly, the monitor logs a high-severity wireless alert.

### 4. Packet Flood / Abnormal Rate

If a single source sends too many packets inside a short time window, the monitor raises a flood alert.

## Demo Mode

Demo mode is the operational fallback for presentations or restricted lab systems. It injects safe sample records that simulate:

- trusted traffic
- an unknown device
- ARP inconsistency
- flood-like traffic
- deauthentication-like frames

This keeps the dashboard functional even when:

- root privileges are unavailable
- no wireless adapter is present
- monitor mode is not configured
- packet capture is blocked in a VM

## Trusted Device File

Edit `data/known_devices.csv` to match your lab devices.

Example:

```csv
device_name,mac_address,ip_address,owner,notes
Lab Router,AA:BB:CC:DD:EE:01,192.168.1.1,Lab Admin,Default gateway
Student Laptop,AA:BB:CC:DD:EE:10,192.168.1.10,Student A,Authorized laptop
```

## Troubleshooting

### Permission Error

If live capture fails with a permission error, run:

```bash
sudo python3 main.py --interface wlan0
```

### Interface Not Found

Check your available interfaces:

```bash
ip link
iwconfig
```

Then rerun with the correct interface:

```bash
sudo python3 main.py --interface wlan0mon
```

### No Wireless Frames Appearing

That is normal on a standard managed interface. Deauthentication-like detection needs wireless management frames, usually from a monitor-mode interface or a PCAP file that already contains `Dot11` traffic.

### Dashboard Shows Old Data

Start a fresh run:

```bash
python3 main.py --mode demo --reset-logs
```

## Presentation Tips

- Use `--mode demo --reset-logs` before your presentation so the dashboard is populated with clean sample data.
- Keep the dashboard open on `http://127.0.0.1:5000`.
- Explain that this is a monitoring and alerting control, not an attack platform.

## Disclaimer

Use this project only in an authorized lab or approved test environment. It is designed for defensive monitoring, logging, and education.

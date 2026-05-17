# Wireless Intrusion Detection System (WIDS)

This project is a Wireless Intrusion Detection System (WIDS) designed for the TW18 Network Security Mini-Project. It uses Python and Scapy to monitor 802.11 network traffic, detecting malicious behavior such as Deauthentication Floods. Findings are presented on a modern Graphical User Interface built with CustomTkinter.

## Features

- **Packet Sniffing**: Uses Scapy to dissect 802.11 wireless frames.
- **Deauth Detection**: Tracks and detects anomalous spikes in Deauthentication frames (e.g., >50 frames to a target within 10 seconds).
- **Hybrid Modes**:
  - **Offline Mode**: Feed the tool an existing `.pcap` file captured via Wireshark.
  - **Live Mode**: Directly sniff traffic from a wireless interface in Monitor mode.
- **Modern GUI**: Real-time statistical dashboard and alert logging using CustomTkinter, executed in a thread-safe manner.

## Installation & Setup

1. **Clone the Repository or navigate to the project directory**:
   ```bash
   cd "wireless-security-monitor"
   ```

2. **Install Python Dependencies**:
   It is highly recommended to run this inside a virtual environment.
   ```bash
   pip install -r requirements.txt
   ```
   *Required packages: `scapy`, `customtkinter`, `Flask` (for legacy web dashboard support).*

3. **Npcap / libpcap Requirement**:
   - **Windows**: You must have [Npcap](https://npcap.com/) installed (ensure you check "Install Npcap in WinPcap API-compatible Mode" during installation) so that Scapy can read PCAP files and interface with network cards.
   - **Linux**: Ensure `tcpdump` and `libpcap` are installed (`sudo apt install tcpdump`).

## How to Run Offline Mode (Testing & Analysis)

1. Launch the Desktop Dashboard:
   ```bash
   python wids_gui.py
   ```
2. Select **Offline Mode** in the left sidebar.
3. In the Interface/PCAP Path box, type the path to your PCAP file (e.g., `test_capture.pcap`).
4. Click **Start Monitoring**. 
5. The application will process the packets rapidly, updating the stats and alerting you to any detected attacks.

## How to Run Live Mode (Real-Time Sniffing)

Live Mode requires your wireless network adapter to be capable of and set into **Monitor Mode**. This is typically done on a Linux system (like Kali Linux) using the Aircrack-ng suite.

### 1. Enable Monitor Mode (Linux/Kali)
Open your terminal and find your wireless interface name (e.g., `wlan0`):
```bash
iwconfig
```
Put the interface into monitor mode:
```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```
This usually creates a new interface called `wlan0mon`. Verify with `iwconfig`.

### 2. Run the Dashboard as Root/Admin
Scapy requires elevated privileges to sniff live traffic from a network interface.
```bash
sudo python3 wids_gui.py
```

### 3. Start Live Monitoring
1. In the GUI, select **Live Mode**.
2. Set the Interface field to your monitor mode interface (e.g., `wlan0mon`).
3. Click **Start Monitoring**. The system will now sniff raw 802.11 frames from the air.

## System Architecture

- **`wids_sniffer.py`**: Contains the core `WIDSSniffer` class. It manages the background thread to prevent blocking the GUI. It uses `scapy.sniff()` and applies threshold-based detection logic specifically for Management frames (Type 0, Subtype 12).
- **`wids_gui.py`**: Contains the `WIDSGui` class leveraging `customtkinter`. It establishes thread-safe communication using `after()` callbacks so the sniffer can asynchronously inject statistics and alerts onto the screen.

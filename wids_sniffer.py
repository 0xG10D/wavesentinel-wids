import threading
import time
from scapy.all import sniff, Dot11, PcapReader

class WIDSSniffer:
    """
    Core backend logic for the Wireless Intrusion Detection System (WIDS).
    Handles packet sniffing (both live and offline via PCAP) and implements
    the attack detection logic.
    """
    def __init__(self, mode="offline", source=""):
        self.mode = mode # 'live' or 'offline'
        self.source = source # interface name (e.g., wlan0mon) or pcap file path
        
        # Threat detection parameters
        # Threshold: if > 50 deauth frames are detected for the same MAC in 10 seconds, flag an attack.
        self.deauth_threshold = 50
        self.time_window = 10 # in seconds
        
        # Dictionary to keep track of deauthentication frames
        # Format: {target_mac: [timestamp1, timestamp2, ...]}
        self.deauth_records = {} 
        
        # Statistics to report back to GUI
        self.total_packets = 0
        self.suspicious_events = 0
        self.confirmed_attacks = 0
        
        # Control flags and thread objects
        self.is_running = False
        self.sniffer_thread = None
        
        # Callback functions to communicate with the GUI thread
        self.on_packet_update = None
        self.on_alert = None

    def start(self):
        """Starts the packet sniffing process on a separate background thread."""
        if self.is_running: 
            return
            
        self.is_running = True
        self.total_packets = 0
        self.suspicious_events = 0
        self.confirmed_attacks = 0
        self.deauth_records.clear()
        
        # Threading is crucial here! 
        # Sniffing is a blocking operation. If we ran it on the main thread, 
        # the GUI would completely freeze. Using a daemon thread ensures it runs in the background.
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()

    def stop(self):
        """Stops the packet sniffing process."""
        self.is_running = False
        if self.sniffer_thread:
            # Wait a short moment for the thread to close cleanly
            self.sniffer_thread.join(timeout=1.0)
            
    def set_callbacks(self, on_packet_update, on_alert):
        """Register callbacks so the backend can send data to the frontend GUI."""
        self.on_packet_update = on_packet_update
        self.on_alert = on_alert

    def _sniff_loop(self):
        """The main sniffing loop executed by the background thread."""
        if self.mode == "offline":
            try:
                # Read pcap iteratively using Scapy's PcapReader to save memory
                with PcapReader(self.source) as pcap_reader:
                    for pkt in pcap_reader:
                        if not self.is_running: 
                            break
                        self._process_packet(pkt)
                        # Small artificial delay to simulate live traffic flow in offline mode
                        time.sleep(0.01) 
            except Exception as e:
                if self.on_alert: 
                    self.on_alert(f"[ERROR] Error loading PCAP: {e}")
                    
        elif self.mode == "live":
            try:
                # Loop allows sniff to timeout and check the is_running flag,
                # preventing zombie threads from lingering on idle networks.
                while self.is_running:
                    sniff(
                        iface=self.source, 
                        prn=self._process_packet, 
                        store=False, 
                        timeout=1.0,
                        stop_filter=lambda x: not self.is_running
                    )
            except PermissionError:
                if self.on_alert: 
                    self.on_alert(f"[ERROR] Permission denied. Are you running as root/admin?")
            except Exception as e:
                if self.on_alert: 
                    self.on_alert(f"[ERROR] Error sniffing on {self.source}: {e}")
                
        # Ensure flag is set to false when the loop exits naturally
        self.is_running = False

    def _process_packet(self, pkt):
        """Processes an individual packet, checking against detection logic."""
        self.total_packets += 1
        
        # Check if the packet has an 802.11 layer (Wi-Fi Protocol)
        if pkt.haslayer(Dot11):
            # Filtering for Management frames (Type 0) and Deauthentication subtype (Subtype 12)
            if pkt.type == 0 and pkt.subtype == 12:
                self.suspicious_events += 1
                
                target_mac = pkt.addr1 # addr1 is the destination (receiver MAC)
                source_mac = pkt.addr2 # addr2 is the source (transmitter MAC/BSSID)
                
                # We pass the MAC addresses to our threshold logic
                self._analyze_deauth(target_mac, source_mac)
                
        # To avoid overwhelming the GUI thread, we only trigger UI updates every 10 packets
        if self.total_packets % 10 == 0 and self.on_packet_update:
            self.on_packet_update(self.total_packets, self.suspicious_events, self.confirmed_attacks)

    def _analyze_deauth(self, target_mac, source_mac):
        """
        Threshold-based detection logic.
        Tracks if a specific target MAC receives more than `deauth_threshold` Deauth frames
        within `time_window` seconds.
        """
        current_time = time.time()
        
        # Initialize an empty list for this target MAC if it hasn't been tracked yet
        if target_mac not in self.deauth_records:
            self.deauth_records[target_mac] = []
            
        # Add the current timestamp to the record for this target MAC
        self.deauth_records[target_mac].append(current_time)
        
        # Clean up old records: only keep timestamps that occurred within our time window (last 10 seconds)
        self.deauth_records[target_mac] = [
            t for t in self.deauth_records[target_mac] 
            if current_time - t <= self.time_window
        ]
        
        # Evaluate threshold
        if len(self.deauth_records[target_mac]) >= self.deauth_threshold:
            # We detected a Deauth Flood!
            self.confirmed_attacks += 1
            if self.on_alert:
                timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_time))
                msg = f"[{timestamp_str}] DEAUTH ATTACK DETECTED! Target: {target_mac} (Spoofed Source: {source_mac})"
                self.on_alert(msg)
                
            # Clear the records for this MAC to prevent spamming duplicate alerts for the exact same ongoing flood
            self.deauth_records[target_mac].clear()

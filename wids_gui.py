import customtkinter as ctk
import threading
from wids_sniffer import WIDSSniffer

# Set the appearance and theme to a modern, dark aesthetic
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class WIDSGui(ctk.CTk):
    """
    Main GUI class for the Wireless Intrusion Detection System.
    Upgraded to a modern, premium dark-mode dashboard.
    """
    def __init__(self):
        super().__init__()
        
        self.title("WIDS - Wireless Intrusion Detection System")
        self.geometry("1000x650")
        self.minsize(900, 600)
        
        # Initialize the backend sniffing engine
        self.sniffer = WIDSSniffer()
        
        # Register the GUI update callbacks
        self.sniffer.set_callbacks(self.update_stats, self.log_alert)
        
        self._build_ui()
        
    def _build_ui(self):
        """Constructs the modern user interface elements."""
        # Base grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # ==========================================
        # LEFT PANEL: Control Sidebar
        # ==========================================
        # Deep dark gray/blue for the sidebar
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color="#1e1e2e")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(8, weight=1)
        
        # Logo / Title
        self.logo_label = ctk.CTkLabel(
            self.sidebar, text="🛡️ WIDS Engine", 
            font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"),
            text_color="#cdd6f4"
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 25), sticky="w")
        
        # Mode Selection
        self.mode_label = ctk.CTkLabel(
            self.sidebar, text="OPERATION MODE", 
            font=ctk.CTkFont(size=11, weight="bold"), text_color="#7f849c"
        )
        self.mode_label.grid(row=1, column=0, padx=25, pady=(10, 5), sticky="w")
        
        self.mode_var = ctk.StringVar(value="offline")
        
        self.radio_live = ctk.CTkRadioButton(
            self.sidebar, text="📡 Live Sniffing", variable=self.mode_var, value="live",
            font=ctk.CTkFont(size=14, weight="bold"), fg_color="#89b4fa", hover_color="#b4befe"
        )
        self.radio_live.grid(row=2, column=0, pady=(5, 10), padx=25, sticky="w")
        
        self.radio_offline = ctk.CTkRadioButton(
            self.sidebar, text="📁 PCAP Offline", variable=self.mode_var, value="offline",
            font=ctk.CTkFont(size=14, weight="bold"), fg_color="#89b4fa", hover_color="#b4befe"
        )
        self.radio_offline.grid(row=3, column=0, pady=(0, 15), padx=25, sticky="w")
        
        # Source Input Field
        self.source_label = ctk.CTkLabel(
            self.sidebar, text="TARGET INTERFACE / FILE", 
            font=ctk.CTkFont(size=11, weight="bold"), text_color="#7f849c"
        )
        self.source_label.grid(row=4, column=0, padx=25, pady=(15, 5), sticky="w")
        
        self.source_entry = ctk.CTkEntry(
            self.sidebar, placeholder_text="e.g., wlan0mon or test.pcap", 
            height=40, font=ctk.CTkFont(size=13), corner_radius=8,
            fg_color="#181825", border_color="#313244", text_color="#cdd6f4"
        )
        self.source_entry.grid(row=5, column=0, padx=20, pady=5, sticky="ew")
        
        # Action Buttons
        self.btn_start = ctk.CTkButton(
            self.sidebar, text="▶ START MONITOR", command=self.start_monitoring, 
            height=45, font=ctk.CTkFont(weight="bold", size=13), corner_radius=8,
            fg_color="#a6e3a1", hover_color="#94e2d5", text_color="#11111b"
        )
        self.btn_start.grid(row=6, column=0, padx=20, pady=(35, 10), sticky="ew")
        
        self.btn_stop = ctk.CTkButton(
            self.sidebar, text="⏹ STOP", command=self.stop_monitoring, state="disabled",
            height=45, font=ctk.CTkFont(weight="bold", size=13), corner_radius=8,
            fg_color="#f38ba8", hover_color="#eba0ac", text_color="#11111b"
        )
        self.btn_stop.grid(row=7, column=0, padx=20, pady=10, sticky="ew")
        
        # Status Indicator
        self.status_label = ctk.CTkLabel(
            self.sidebar, text="● SYSTEM IDLE", 
            font=ctk.CTkFont(size=12, weight="bold"), text_color="#6c7086"
        )
        self.status_label.grid(row=9, column=0, padx=20, pady=25, sticky="s")
        
        # ==========================================
        # RIGHT PANEL: Main Dashboard Area
        # ==========================================
        # Darker background for the main content area
        self.main_frame = ctk.CTkFrame(self, fg_color="#11111b", corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        
        # --- Statistics Cards ---
        self.stats_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.stats_container.grid(row=0, column=0, padx=30, pady=(35, 20), sticky="ew")
        self.stats_container.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Card 1: Total Packets
        self.card_packets = ctk.CTkFrame(self.stats_container, fg_color="#181825", corner_radius=15, border_width=1, border_color="#313244")
        self.card_packets.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        ctk.CTkLabel(
            self.card_packets, text="TOTAL PACKETS", 
            font=ctk.CTkFont(size=12, weight="bold"), text_color="#89b4fa"
        ).pack(pady=(20, 5))
        self.lbl_total_packets = ctk.CTkLabel(
            self.card_packets, text="0", 
            font=ctk.CTkFont(size=42, weight="bold"), text_color="#cdd6f4"
        )
        self.lbl_total_packets.pack(pady=(0, 20))
        
        # Card 2: Suspicious Events
        self.card_suspicious = ctk.CTkFrame(self.stats_container, fg_color="#181825", corner_radius=15, border_width=1, border_color="#313244")
        self.card_suspicious.grid(row=0, column=1, padx=10, sticky="ew")
        ctk.CTkLabel(
            self.card_suspicious, text="SUSPICIOUS EVENTS", 
            font=ctk.CTkFont(size=12, weight="bold"), text_color="#f9e2af"
        ).pack(pady=(20, 5))
        self.lbl_suspicious = ctk.CTkLabel(
            self.card_suspicious, text="0", 
            font=ctk.CTkFont(size=42, weight="bold"), text_color="#cdd6f4"
        )
        self.lbl_suspicious.pack(pady=(0, 20))
        
        # Card 3: Confirmed Attacks
        self.card_attacks = ctk.CTkFrame(self.stats_container, fg_color="#181825", corner_radius=15, border_width=1, border_color="#f38ba8")
        self.card_attacks.grid(row=0, column=2, padx=(10, 0), sticky="ew")
        ctk.CTkLabel(
            self.card_attacks, text="CONFIRMED ATTACKS", 
            font=ctk.CTkFont(size=12, weight="bold"), text_color="#f38ba8"
        ).pack(pady=(20, 5))
        self.lbl_attacks = ctk.CTkLabel(
            self.card_attacks, text="0", 
            font=ctk.CTkFont(size=42, weight="bold"), text_color="#f38ba8"
        )
        self.lbl_attacks.pack(pady=(0, 20))
        
        # --- Terminal Console (Alert Log) ---
        self.console_frame = ctk.CTkFrame(self.main_frame, fg_color="#181825", corner_radius=15, border_width=1, border_color="#313244")
        self.console_frame.grid(row=1, column=0, padx=30, pady=(10, 35), sticky="nsew")
        
        self.console_title = ctk.CTkLabel(
            self.console_frame, text=">_ LIVE SECURITY LOG", 
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"), text_color="#a6e3a1"
        )
        self.console_title.pack(anchor="w", padx=20, pady=(15, 5))
        
        # Textbox acting as a terminal window
        self.alert_box = ctk.CTkTextbox(
            self.console_frame, state="disabled", wrap="word", 
            fg_color="transparent", text_color="#bac2de", 
            font=ctk.CTkFont(family="Consolas", size=13)
        )
        self.alert_box.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def start_monitoring(self):
        """Triggered when the 'Start Monitoring' button is clicked."""
        mode = self.mode_var.get()
        source = self.source_entry.get().strip()
        
        if not source:
            self.log_alert("[!] ERROR: Please specify a network interface or a PCAP file path.")
            return
            
        # Configure the backend sniffer with user's inputs
        self.sniffer.mode = mode
        self.sniffer.source = source
        
        # Update UI state to "Running"
        self.btn_start.configure(state="disabled", fg_color="#313244") # Dim the start button
        self.btn_stop.configure(state="normal", fg_color="#f38ba8")
        self.source_entry.configure(state="disabled")
        self.radio_live.configure(state="disabled")
        self.radio_offline.configure(state="disabled")
        
        self.status_label.configure(text=f"● RUNNING ({mode.upper()})", text_color="#a6e3a1")
        self.log_alert(f"[*] Started monitoring in {mode} mode on '{source}'...")
        
        # Start the background sniffer thread
        self.sniffer.start()
        
        # Initiate the thread monitoring loop
        self.check_thread_status()

    def stop_monitoring(self):
        """Triggered when the 'Stop' button is clicked or when a PCAP file finishes."""
        # Stop the backend engine
        self.sniffer.stop()
        
        # Restore UI state to "Idle"
        self.btn_start.configure(state="normal", fg_color="#a6e3a1")
        self.btn_stop.configure(state="disabled", fg_color="#313244") # Dim the stop button
        self.source_entry.configure(state="normal")
        self.radio_live.configure(state="normal")
        self.radio_offline.configure(state="normal")
        
        self.status_label.configure(text="● SYSTEM IDLE", text_color="#6c7086")
        self.log_alert("[*] Monitoring stopped.")

    def check_thread_status(self):
        """
        Periodically checks if the background sniffing thread is still alive.
        """
        if self.sniffer.is_running and self.sniffer.sniffer_thread and not self.sniffer.sniffer_thread.is_alive():
            self.stop_monitoring()
            self.log_alert("[*] Capture finished or thread stopped unexpectedly.")
            
        if self.sniffer.is_running:
            self.after(1000, self.check_thread_status)

    def update_stats(self, total_packets, suspicious_events, confirmed_attacks):
        """Callback triggered by the backend sniffer thread to update the counters."""
        self.after(0, self._apply_stats, total_packets, suspicious_events, confirmed_attacks)
        
    def _apply_stats(self, total_packets, suspicious_events, confirmed_attacks):
        """Actual method that updates the GUI labels."""
        self.lbl_total_packets.configure(text=f"{total_packets}")
        self.lbl_suspicious.configure(text=f"{suspicious_events}")
        self.lbl_attacks.configure(text=f"{confirmed_attacks}")

    def log_alert(self, message):
        """Callback triggered by the backend sniffer thread to log an alert/system message."""
        self.after(0, self._apply_log, message)
        
    def _apply_log(self, message):
        """Actual method that appends text to the alert log box."""
        self.alert_box.configure(state="normal")
        self.alert_box.insert("end", message + "\n")
        self.alert_box.see("end")  # Auto-scroll to bottom
        self.alert_box.configure(state="disabled")

if __name__ == "__main__":
    app = WIDSGui()
    app.mainloop()

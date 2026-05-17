import customtkinter as ctk
import threading
from wids_sniffer import WIDSSniffer

# Set the appearance and theme of the CustomTkinter GUI
ctk.set_appearance_mode("System")  # Follows system theme (dark/light)
ctk.set_default_color_theme("blue")

class WIDSGui(ctk.CTk):
    """
    Main GUI class for the Wireless Intrusion Detection System.
    Provides the frontend interface, dashboard counters, and alert logging.
    """
    def __init__(self):
        super().__init__()
        
        self.title("Wireless Intrusion Detection System (WIDS)")
        self.geometry("850x600")
        
        # Initialize the backend sniffing engine
        self.sniffer = WIDSSniffer()
        
        # Register the GUI update methods as callbacks to the sniffer.
        # This allows the backend thread to push data to the frontend.
        self.sniffer.set_callbacks(self.update_stats, self.log_alert)
        
        self._build_ui()
        
    def _build_ui(self):
        """Constructs the user interface elements."""
        # Configure the main window grid layout (2 columns, 3 rows)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)
        
        # ==========================================
        # LEFT PANEL: Controls & Configuration
        # ==========================================
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)
        
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame, 
            text="WIDS Dashboard", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        # Mode Selection (Live Sniffing vs Offline PCAP)
        self.mode_var = ctk.StringVar(value="offline")
        
        self.radio_live = ctk.CTkRadioButton(
            self.sidebar_frame, text="Live Mode", variable=self.mode_var, value="live"
        )
        self.radio_live.grid(row=1, column=0, pady=10, padx=20, sticky="w")
        
        self.radio_offline = ctk.CTkRadioButton(
            self.sidebar_frame, text="Offline Mode", variable=self.mode_var, value="offline"
        )
        self.radio_offline.grid(row=2, column=0, pady=10, padx=20, sticky="w")
        
        # Source Input Field
        self.source_label = ctk.CTkLabel(self.sidebar_frame, text="Interface / PCAP Path:")
        self.source_label.grid(row=3, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.source_entry = ctk.CTkEntry(
            self.sidebar_frame, 
            placeholder_text="e.g., wlan0mon or test.pcap"
        )
        self.source_entry.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
        
        # Start and Stop Buttons
        self.btn_start = ctk.CTkButton(
            self.sidebar_frame, text="Start Monitoring", command=self.start_monitoring, fg_color="green"
        )
        self.btn_start.grid(row=6, column=0, padx=20, pady=10)
        
        self.btn_stop = ctk.CTkButton(
            self.sidebar_frame, text="Stop", command=self.stop_monitoring, fg_color="#C62828", state="disabled"
        )
        self.btn_stop.grid(row=7, column=0, padx=20, pady=20)
        
        # Status Indicator
        self.status_label = ctk.CTkLabel(
            self.sidebar_frame, text="Status: IDLE", font=ctk.CTkFont(weight="bold")
        )
        self.status_label.grid(row=8, column=0, padx=20, pady=10)
        
        # ==========================================
        # TOP RIGHT: Statistics Counters
        # ==========================================
        self.stats_frame = ctk.CTkFrame(self)
        self.stats_frame.grid(row=0, column=1, padx=20, pady=20, sticky="ew")
        self.stats_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        self.lbl_total_packets = ctk.CTkLabel(
            self.stats_frame, text="Total Packets\n0", font=ctk.CTkFont(size=16)
        )
        self.lbl_total_packets.grid(row=0, column=0, padx=10, pady=10)
        
        self.lbl_suspicious = ctk.CTkLabel(
            self.stats_frame, text="Suspicious Events\n0", font=ctk.CTkFont(size=16), text_color="#F57C00"
        )
        self.lbl_suspicious.grid(row=0, column=1, padx=10, pady=10)
        
        self.lbl_attacks = ctk.CTkLabel(
            self.stats_frame, text="Confirmed Attacks\n0", font=ctk.CTkFont(size=16, weight="bold"), text_color="red"
        )
        self.lbl_attacks.grid(row=0, column=2, padx=10, pady=10)
        
        # ==========================================
        # MIDDLE RIGHT: Alert Log Console
        # ==========================================
        self.log_label = ctk.CTkLabel(self, text="Real-Time Alert Log", font=ctk.CTkFont(size=16, weight="bold"))
        self.log_label.grid(row=1, column=1, padx=20, pady=(10, 0), sticky="w")
        
        self.alert_box = ctk.CTkTextbox(self, state="disabled", wrap="word", font=ctk.CTkFont(family="Consolas", size=13))
        self.alert_box.grid(row=2, column=1, padx=20, pady=(0, 20), sticky="nsew")

    def start_monitoring(self):
        """Triggered when the 'Start Monitoring' button is clicked."""
        mode = self.mode_var.get()
        source = self.source_entry.get().strip()
        
        if not source:
            self.log_alert("[System] Error: Please specify a network interface or a PCAP file path.")
            return
            
        # Configure the backend sniffer with user's inputs
        self.sniffer.mode = mode
        self.sniffer.source = source
        
        # Update UI state to "Running"
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.source_entry.configure(state="disabled")
        self.radio_live.configure(state="disabled")
        self.radio_offline.configure(state="disabled")
        
        self.status_label.configure(text=f"Status: RUNNING ({mode.upper()})", text_color="green")
        self.log_alert(f"[System] Started monitoring in {mode} mode on '{source}'.")
        
        # Start the background sniffer thread
        self.sniffer.start()
        
        # Initiate the thread monitoring loop
        self.check_thread_status()

    def stop_monitoring(self):
        """Triggered when the 'Stop' button is clicked or when a PCAP file finishes."""
        # Stop the backend engine
        self.sniffer.stop()
        
        # Restore UI state to "Idle"
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.source_entry.configure(state="normal")
        self.radio_live.configure(state="normal")
        self.radio_offline.configure(state="normal")
        
        self.status_label.configure(text="Status: IDLE", text_color="white")
        self.log_alert("[System] Monitoring stopped.")

    def check_thread_status(self):
        """
        Periodically checks if the background sniffing thread is still alive.
        This is especially useful for Offline Mode, where the thread terminates naturally
        after reading the entire PCAP file.
        """
        if self.sniffer.is_running and self.sniffer.sniffer_thread and not self.sniffer.sniffer_thread.is_alive():
            # Thread died or finished executing
            self.stop_monitoring()
            self.log_alert("[System] Capture finished or thread stopped unexpectedly.")
            
        if self.sniffer.is_running:
            # Re-schedule this check in 1000ms (1 second)
            self.after(1000, self.check_thread_status)

    def update_stats(self, total_packets, suspicious_events, confirmed_attacks):
        """
        Callback triggered by the backend sniffer thread to update the counters.
        To maintain thread-safety in Tkinter, we use .after(0, ...) to execute 
        the GUI updates on the main thread.
        """
        self.after(0, self._apply_stats, total_packets, suspicious_events, confirmed_attacks)
        
    def _apply_stats(self, total_packets, suspicious_events, confirmed_attacks):
        """Actual method that updates the GUI labels."""
        self.lbl_total_packets.configure(text=f"Total Packets\n{total_packets}")
        self.lbl_suspicious.configure(text=f"Suspicious Events\n{suspicious_events}")
        self.lbl_attacks.configure(text=f"Confirmed Attacks\n{confirmed_attacks}")

    def log_alert(self, message):
        """
        Callback triggered by the backend sniffer thread to log an alert/system message.
        Thread-safe execution via .after(0, ...)
        """
        self.after(0, self._apply_log, message)
        
    def _apply_log(self, message):
        """Actual method that appends text to the alert log box."""
        self.alert_box.configure(state="normal") # Temporarily enable to insert text
        self.alert_box.insert("end", message + "\n")
        self.alert_box.see("end")  # Auto-scroll to the very bottom
        self.alert_box.configure(state="disabled") # Disable to prevent user typing

if __name__ == "__main__":
    app = WIDSGui()
    app.mainloop()

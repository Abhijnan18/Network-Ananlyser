import scapy.all as scapy
from scapy.layers import http
from collections import defaultdict
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import queue
import datetime
import json
import logging
import os
from typing import Dict, List, Tuple


class NetworkMonitor:
    def __init__(self):
        self.packet_counts = defaultdict(int)
        self.bandwidth_usage = defaultdict(list)
        self.alerts = queue.Queue()
        self.is_capturing = False
        self.threshold_mbps = 10  # Alert threshold in Mbps

        # Setup logging
        logging.basicConfig(
            filename='network_monitor.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

        # Check privileges
        self.is_root = os.geteuid() == 0

        # Initialize the GUI
        self.setup_gui()

    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("Network Monitor")
        self.root.geometry("1200x800")

        # Create main frames
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=10)

        # Control buttons
        self.start_button = ttk.Button(
            control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(
            control_frame, text="Stop Capture", command=self.stop_capture)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Status label
        self.status_label = ttk.Label(control_frame, text="")
        self.status_label.pack(side=tk.LEFT, padx=20)

        # Update status based on privileges
        self.update_status_label()

        # Create graphs
        self.setup_graphs()

        # Alerts section
        alerts_frame = ttk.LabelFrame(self.root, text="Alerts")
        alerts_frame.pack(pady=10, padx=10, fill=tk.X)
        self.alerts_text = tk.Text(alerts_frame, height=5)
        self.alerts_text.pack(pady=5, padx=5, fill=tk.X)

        # Start the update loop
        self.update_gui()

    def update_status_label(self):
        if not self.is_root:
            self.status_label.config(
                text="⚠️ Root privileges required for packet capture",
                foreground="red"
            )
            self.start_button.config(state="disabled")
        else:
            self.status_label.config(
                text="✓ Ready to capture",
                foreground="green"
            )
            self.start_button.config(state="normal")

    def setup_graphs(self):
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(10, 8))

        self.ax1.set_title("Bandwidth Usage Over Time")
        self.ax1.set_xlabel("Time")
        self.ax1.set_ylabel("Bandwidth (Mbps)")

        self.ax2.set_title("Protocol Distribution")
        self.ax2.set_xlabel("Protocol")
        self.ax2.set_ylabel("Packet Count")

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(pady=10, padx=10)

    def packet_callback(self, packet):
        if not self.is_capturing:
            return

        if packet.haslayer(scapy.IP):
            protocol = packet[scapy.IP].proto
            self.packet_counts[protocol] += 1

            packet_size = len(packet)
            current_time = time.time()
            self.bandwidth_usage[current_time] = packet_size

            self.check_alerts(packet_size)

    def check_alerts(self, packet_size):
        recent_times = [t for t in self.bandwidth_usage.keys()
                        if time.time() - t <= 1]
        current_bandwidth = sum(
            self.bandwidth_usage[t] for t in recent_times) * 8 / 1_000_000

        if current_bandwidth > self.threshold_mbps:
            alert_msg = f"High bandwidth usage detected: {current_bandwidth:.2f} Mbps"
            self.alerts.put(alert_msg)
            logging.warning(alert_msg)

    def start_capture(self):
        if not self.is_root:
            messagebox.showerror(
                "Permission Error",
                "This application requires root privileges for packet capture.\n\n"
                "Please run the application using sudo:\n"
                "sudo python3 network_monitor.py"
            )
            return

        if not self.is_capturing:
            try:
                self.is_capturing = True
                self.capture_thread = threading.Thread(
                    target=self.capture_packets)
                self.capture_thread.daemon = True
                self.capture_thread.start()
                logging.info("Packet capture started")
                self.status_label.config(
                    text="✓ Capturing packets", foreground="green")
            except Exception as e:
                self.is_capturing = False
                error_msg = f"Failed to start capture: {str(e)}"
                logging.error(error_msg)
                messagebox.showerror("Error", error_msg)

    def stop_capture(self):
        self.is_capturing = False
        logging.info("Packet capture stopped")
        self.status_label.config(text="✓ Capture stopped", foreground="blue")

    def capture_packets(self):
        try:
            scapy.sniff(prn=self.packet_callback, store=False)
        except Exception as e:
            logging.error(f"Packet capture error: {str(e)}")
            self.alerts.put(f"Capture error: {str(e)}")
            self.is_capturing = False

    def update_gui(self):
        if self.is_capturing:
            # Update bandwidth graph
            self.ax1.clear()
            times = list(self.bandwidth_usage.keys())[-100:]
            values = [self.bandwidth_usage[t] * 8 / 1_000_000 for t in times]
            self.ax1.plot(times, values)
            self.ax1.set_title("Bandwidth Usage Over Time")

            # Update protocol distribution
            self.ax2.clear()
            protocols = list(self.packet_counts.keys())
            counts = list(self.packet_counts.values())
            self.ax2.bar(protocols, counts)
            self.ax2.set_title("Protocol Distribution")

            self.canvas.draw()

            # Update alerts
            while not self.alerts.empty():
                alert = self.alerts.get()
                self.alerts_text.insert(
                    tk.END, f"{datetime.datetime.now()}: {alert}\n")
                self.alerts_text.see(tk.END)

        self.root.after(1000, self.update_gui)

    def save_statistics(self):
        stats = {
            "packet_counts": dict(self.packet_counts),
            "bandwidth_usage": {str(k): v for k, v in self.bandwidth_usage.items()},
            "timestamp": str(datetime.datetime.now())
        }

        with open(f"network_stats_{int(time.time())}.json", "w") as f:
            json.dump(stats, f, indent=4)

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def on_closing(self):
        self.stop_capture()
        self.save_statistics()
        self.root.destroy()


if __name__ == "__main__":
    monitor = NetworkMonitor()
    monitor.run()

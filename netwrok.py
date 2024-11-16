import psutil
import time
import tkinter as tk
from tkinter import messagebox
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class NetworkMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Monitoring Tool")
        self.root.geometry("800x600")

        # Data storage for plotting
        self.timestamps = []
        self.upload_speeds = []
        self.download_speeds = []

        # Setup the GUI components
        self.setup_ui()

        # Start monitoring in a separate thread
        self.monitor_thread = threading.Thread(
            target=self.monitor_network, daemon=True)
        self.monitor_thread.start()

    def setup_ui(self):
        # Add a canvas to display the graph
        self.fig, self.ax = plt.subplots()
        self.ax.set_title("Network Traffic Monitor")
        self.ax.set_xlabel("Time (seconds)")
        self.ax.set_ylabel("Speed (bytes/s)")
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Add a button to stop the monitoring (for demonstration purposes)
        self.stop_button = tk.Button(
            self.root, text="Stop Monitoring", command=self.stop_monitoring)
        self.stop_button.pack()

    def monitor_network(self):
        prev_upload = psutil.net_io_counters().bytes_sent
        prev_download = psutil.net_io_counters().bytes_recv

        while True:
            # Calculate network usage
            time.sleep(1)
            curr_upload = psutil.net_io_counters().bytes_sent
            curr_download = psutil.net_io_counters().bytes_recv

            upload_speed = curr_upload - prev_upload
            download_speed = curr_download - prev_download

            # Append the current speeds for graph plotting
            self.timestamps.append(time.time())
            self.upload_speeds.append(upload_speed)
            self.download_speeds.append(download_speed)

            # Update previous counters
            prev_upload = curr_upload
            prev_download = curr_download

            # Update the graph in real-time
            self.update_graph()

    def update_graph(self):
        # Update the plot with new data
        self.ax.clear()
        self.ax.set_title("Network Traffic Monitor")
        self.ax.set_xlabel("Time (seconds)")
        self.ax.set_ylabel("Speed (bytes/s)")
        self.ax.plot(self.timestamps, self.upload_speeds,
                     label="Upload Speed", color="blue")
        self.ax.plot(self.timestamps, self.download_speeds,
                     label="Download Speed", color="green")
        self.ax.legend()

        self.canvas.draw()

    def stop_monitoring(self):
        # Stop the monitoring thread (for demonstration purposes)
        messagebox.showinfo("Info", "Stopping network monitoring.")
        self.root.quit()


if __name__ == "__main__":
    # Create the main Tkinter window
    root = tk.Tk()

    # Instantiate the NetworkMonitor class
    monitor = NetworkMonitor(root)

    # Run the Tkinter main loop
    root.mainloop()

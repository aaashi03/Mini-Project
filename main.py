import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from scapy.all import AsyncSniffer, IP
from collections import defaultdict
import time
import threading
from queue import Queue

# Global variables
request_count = defaultdict(int)
ip_timestamps = defaultdict(float)
alert_threshold = 10  # Threshold for potential DOS attack
time_window = 2  # Sliding time window in seconds
is_sniffing = False  # Flag to control sniffing
lock = threading.Lock()  # To control access to shared resources
detected_ips = set()  # Track IPs involved in potential DOS attacks
log_queue = Queue()  # Queue for GUI log updates
sniffer_instance = None  # Instance of the packet sniffer

# Function to analyze packets
def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = time.time()
        with lock:
            request_count[src_ip] += 1
            ip_timestamps[src_ip] = current_time

# Function to detect DOS attacks
def detect_dos_attack(gui):
    current_time = time.time()
    with lock:
        for src_ip, timestamp in list(ip_timestamps.items()):
            if current_time - timestamp > time_window:
                del request_count[src_ip]
                del ip_timestamps[src_ip]
            elif request_count[src_ip] > alert_threshold:
                if src_ip not in detected_ips:
                    detected_ips.add(src_ip)
                    log_queue.put(f"Potential DOS attack detected from IP: {src_ip} with {request_count[src_ip]} requests.")

# Monitor traffic in intervals
def monitor_traffic(gui):
    while is_sniffing:
        time.sleep(time_window)
        detect_dos_attack(gui)

# Function to process log updates
def process_log_updates(gui):
    while is_sniffing:
        if not log_queue.empty():
            message = log_queue.get()
            gui.update_log(message)

# Start the DOS detection system
def start_detection(gui):
    global is_sniffing, sniffer_instance
    is_sniffing = True
    gui.update_log("""
#########################################################
#          0 0 0     0 0 0 0                 0 0 0 0    #
#        0          0        0               0      0   #
#      0           0                         0      0   #
#     0             0                        0     0    #
#     0               0 0 0 0     =====      0 0 0      #
#     0                      0   |     |     0     0    #
#       0                    0    =====      0      0   #
#         0                 0                0      0   #
#           0 0 0    0 0 0 0                 0 0 0 0    #
#                                                       #
#                 MINI PROJECT BY TEAM                  #
#                   1. Manisha                          #
#                   2. Ashish                           #
#                   3. Sahithi                          #
#                   4. Sapthajeeth                      #
#########################################################
#                  DOS detection started...             #
#########################################################""")

    sniffer_instance = AsyncSniffer(prn=analyze_packet, store=0)
    sniffer_instance.start()

    threading.Thread(target=monitor_traffic, args=(gui,), daemon=True).start()
    threading.Thread(target=process_log_updates, args=(gui,), daemon=True).start()

# Stop the DOS detection system
def stop_detection(gui):
    global is_sniffing, sniffer_instance
    is_sniffing = False
    if sniffer_instance:
        sniffer_instance.stop()
        sniffer_instance = None
    gui.update_log("""
#########################################################
#                                                       #
#                DOS detection stopped.                 #
#                                                       #
#########################################################""")

# Function to save the log to a text file
def save_report(gui):
    log_content = gui.log_window.get("1.0", tk.END).strip()
    if not log_content:
        messagebox.showwarning("No Data", "No data to save in the log.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                             filetypes=[("Text Files", "*.txt")],
                                             title="Save Report As")
    if file_path:
        with open(file_path, 'w') as file:
            file.write(log_content)
        messagebox.showinfo("Saved", f"Report saved successfully at {file_path}")

# Function to clear the log
def clear_log(gui):
    gui.log_window.delete('1.0', tk.END)
    gui.update_log("Log cleared.")

# GUI class for DOS Detection System
class DOSDetectionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DOS Detection System")

        # Set Black Theme
        self.root.configure(bg='black')

        # Add Text-based Logo
        self.logo_label = tk.Label(root, text='''
========
 CS--B
########
# TEAM #
# 6262 #
# 6289 #
# 6267 #
# 6273 #
########
========
''', 
                                    font=("Helvetica", 16), fg="white", bg="black", anchor="nw")
        self.logo_label.place(x=10, y=10)

        # Create a frame for buttons
        self.button_frame = tk.Frame(root, bg='black')
        self.button_frame.place(relx=1.0, y=10, anchor="ne")

        # Start Button
        self.start_button = tk.Button(self.button_frame, text="Start Detection", command=lambda: start_detection(self), 
                                      fg="white", bg="gray20", width=20)
        self.start_button.pack(pady=5)

        # Stop Button
        self.stop_button = tk.Button(self.button_frame, text="Stop Detection", command=lambda: stop_detection(self), 
                                     fg="white", bg="gray20", width=20)
        self.stop_button.pack(pady=5)

        # Save Report Button
        self.save_button = tk.Button(self.button_frame, text="Save Report", command=lambda: save_report(self), 
                                     fg="white", bg="gray20", width=20)
        self.save_button.pack(pady=5)

        # Clear Log Button
        self.clear_button = tk.Button(self.button_frame, text="Clear Log", command=lambda: clear_log(self), 
                                      fg="white", bg="gray20", width=20)
        self.clear_button.pack(pady=5)

        # Log Window (ScrolledText)
        self.log_window = scrolledtext.ScrolledText(root, width=80, height=30, bg="black", fg="white", insertbackground="white")
        self.log_window.pack(pady=10)

        # Add Exit Button
        self.exit_button = tk.Button(self.button_frame, text="Exit", command=self.root.quit, fg="white", bg="gray20", width=20)
        self.exit_button.pack(pady=5)

    # Function to update the log in the GUI
    def update_log(self, message):
        self.log_window.insert(tk.END, message + "\n")
        self.log_window.yview(tk.END)  # Auto-scroll to the bottom

# Main GUI loop
if __name__ == "__main__":
    root = tk.Tk()
    app = DOSDetectionGUI(root)
    root.geometry("900x600")  # Set window size
    root.mainloop()

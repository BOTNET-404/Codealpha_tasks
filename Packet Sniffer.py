import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

captured_packets = []
sniffing = False
sniff_thread = None

# Process packet
def process_packet(packet):
    if not sniffing:
        return

    packet_data = {
        "time": datetime.now().strftime('%H:%M:%S'),
        "src": packet[IP].src if IP in packet else "N/A",
        "dst": packet[IP].dst if IP in packet else "N/A",
        "proto": "Other",
        "sport": "",
        "dport": "",
        "payload": ""
    }

    if TCP in packet:
        packet_data["proto"] = "TCP"
        packet_data["sport"] = packet[TCP].sport
        packet_data["dport"] = packet[TCP].dport
    elif UDP in packet:
        packet_data["proto"] = "UDP"
        packet_data["sport"] = packet[UDP].sport
        packet_data["dport"] = packet[UDP].dport
    elif ICMP in packet:
        packet_data["proto"] = "ICMP"

    if Raw in packet:
        try:
            packet_data["payload"] = packet[Raw].load.decode(errors='replace')
        except:
            packet_data["payload"] = "<Binary Data>"

    captured_packets.append(packet_data)
    insert_packet_gui(packet_data)

# Insert into GUI
def insert_packet_gui(packet):
    tree.insert('', 'end', values=(
        packet["time"], packet["proto"], packet["src"],
        packet["dst"], packet["sport"], packet["dport"],
        packet["payload"][:40]
    ))

# Start sniffing
def sniff_packets():
    sniff(prn=process_packet, stop_filter=lambda x: not sniffing, store=False)

def start_sniffing():
    global sniffing, sniff_thread
    sniffing = True
    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()
    start_btn.config(state=tk.DISABLED)
    stop_btn.config(state=tk.NORMAL)

def stop_sniffing():
    global sniffing
    sniffing = False
    stop_btn.config(state=tk.DISABLED)
    start_btn.config(state=tk.NORMAL)

def search_packets():
    keyword = search_entry.get().lower()
    tree.delete(*tree.get_children())
    for pkt in captured_packets:
        if any(keyword in str(val).lower() for val in pkt.values()):
            insert_packet_gui(pkt)

def close_app():
    if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
        stop_sniffing()
        root.destroy()

# GUI Setup
root = tk.Tk()
root.title("🛡️ Packet Sniffer - Cyber Toolkit")
root.geometry("1100x650")
root.configure(bg="#1e1e1e")

# Exit handler
root.protocol("WM_DELETE_WINDOW", close_app)

# Style
style = ttk.Style(root)
style.theme_use("clam")
style.configure("Treeview",
                background="#2b2b2b",
                foreground="white",
                rowheight=25,
                fieldbackground="#2b2b2b",
                font=('Segoe UI', 10))
style.configure("Treeview.Heading",
                background="#444",
                foreground="white",
                font=('Segoe UI', 10, 'bold'))
style.map('Treeview', background=[('selected', '#3e65ff')])

# Title Header
title_label = tk.Label(root, text="📡 Real-Time Packet Sniffer Dashboard", bg="#1e1e1e",
                       fg="#00ffcc", font=("Segoe UI", 16, "bold"))
title_label.pack(pady=10)

# Search Frame
search_frame = tk.Frame(root, bg="#1e1e1e")
search_frame.pack(pady=5)

search_entry = tk.Entry(search_frame, width=50, font=('Segoe UI', 10))
search_entry.pack(side=tk.LEFT, padx=5)
search_btn = tk.Button(search_frame, text="🔍 Search", command=search_packets,
                       font=('Segoe UI', 10), bg="#3e65ff", fg="white", width=12)
search_btn.pack(side=tk.LEFT)

# Control Buttons
control_frame = tk.Frame(root, bg="#1e1e1e")
control_frame.pack(pady=10)

start_btn = tk.Button(control_frame, text="▶ Start Sniffing", command=start_sniffing,
                      font=('Segoe UI', 10, 'bold'), bg="#28a745", fg="white", width=18)
start_btn.pack(side=tk.LEFT, padx=10)

stop_btn = tk.Button(control_frame, text="■ Stop Sniffing", command=stop_sniffing,
                     font=('Segoe UI', 10, 'bold'), bg="#dc3545", fg="white", width=18, state=tk.DISABLED)
stop_btn.pack(side=tk.LEFT, padx=10)

close_btn = tk.Button(control_frame, text="✖ Close", command=close_app,
                      font=('Segoe UI', 10, 'bold'), bg="#6c757d", fg="white", width=18)
close_btn.pack(side=tk.LEFT, padx=10)

# Treeview for Packet Display
columns = ("Time", "Protocol", "Source IP", "Destination IP", "Src Port", "Dst Port", "Payload")
tree = ttk.Treeview(root, columns=columns, show="headings", height=22)

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, anchor=tk.CENTER, width=130 if col != "Payload" else 320)

tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Start GUI
root.mainloop()

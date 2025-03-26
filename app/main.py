# app/main.py
import sys
import os
import socket
import sqlite3
import netifaces
import threading
import logging
import subprocess
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTableWidget, QVBoxLayout, QWidget, 
                            QTableWidgetItem, QPushButton, QHBoxLayout, QLabel, QInputDialog, 
                            QMessageBox, QLineEdit)
from PyQt5.QtCore import QTimer
from scapy.all import sniff, DNS, IP, TCP, UDP, Ether
from flask import Flask, jsonify, request

# Setup logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(message)s")

# Flask app for internal config
flask_app = Flask(__name__)
monitoring_running = False

@flask_app.route('/status', methods=['GET'])
def get_status():
    return jsonify({"monitoring": monitoring_running})

@flask_app.route('/toggle', methods=['POST'])
def toggle_monitoring():
    global monitoring_running
    monitoring_running = not monitoring_running
    return jsonify({"monitoring": monitoring_running, "message": "Monitoring toggled"})

def run_flask():
    flask_app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

# Monitoring functions
def get_device_name(ip):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except socket.herror:
        return "Unknown"

def get_active_interface():
    for iface in netifaces.interfaces():
        if iface != 'lo':
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                logging.info(f"Found active interface: {iface}")
                return iface
    logging.error("No active interface found!")
    return None

def log_to_db(device_name, ip, mac, domain=None, app=None, port=None):
    db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "db", "netwatch.db"))
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO activity (timestamp, device_name, ip, mac, domain, app, port) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (timestamp, device_name, ip, mac, domain, app, port)
    )
    conn.commit()
    conn.close()

def process_packet(packet):
    if not monitoring_running:
        return True
    logging.debug("Packet received!")
    if packet.haslayer(IP) and packet.haslayer(Ether):
        ip_src = packet[IP].src
        mac_src = packet[Ether].src
        device_name = get_device_name(ip_src)
        
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
            logging.info(f"Device {device_name} ({ip_src}, {mac_src}) visited site: {domain}")
            log_to_db(device_name, ip_src, mac_src, domain=domain)
        
        elif packet.haslayer(TCP) or packet.haslayer(UDP):
            port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            app_guess = guess_app_from_port(port)
            logging.info(f"Device {device_name} ({ip_src}, {mac_src}) used app: {app_guess} (port {port})")
            log_to_db(device_name, ip_src, mac_src, app=app_guess, port=port)

def guess_app_from_port(port):
    port_map = {
        80: "Web Browser (HTTP)",
        443: "Web Browser (HTTPS)",
        53: "DNS Client",
        5228: "Google Services (e.g., Play Store)",
        1935: "Streaming App (e.g., Flash)",
    }
    return port_map.get(port, "Unknown App")

def start_monitoring_thread(iface):
    logging.info(f"Starting sniff on {iface}...")
    sniff(iface=iface, prn=process_packet, store=0, stop_filter=lambda x: not monitoring_running)

# GUI
class NetWatchWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetWatch")
        self.setGeometry(100, 100, 800, 600)
        
        # Initialize status label early
        self.status_label = QLabel("Initializing...", self)
        self.status_label.setStyleSheet("color: blue")
        
        # Check and request privileges
        self.ensure_privileges()
        
        # Update status label if we get past elevation
        self.status_label.setText("Ready to monitor")
        self.status_label.setStyleSheet("color: green")
        
        # Setup table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Time", "Device", "IP", "MAC", "Site", "App"])
        
        # Buttons
        self.start_btn = QPushButton("Start Monitoring")
        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        
        # Layout
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout = QVBoxLayout()
        layout.addWidget(self.status_label)
        layout.addLayout(btn_layout)
        layout.addWidget(self.table)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        
        # Timer for table updates
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_table)
        self.timer.start(2000)
        
        # Start Flask in a thread
        flask_thread = threading.Thread(target=run_flask, daemon=True)
        flask_thread.start()
        
        self.update_table()
        self.monitor_thread = None

    def ensure_privileges(self):
        if os.geteuid() != 0:
            password, ok = QInputDialog.getText(self, "Admin Access Required", "Enter root password:", QLineEdit.Password)
            if ok and password:
                try:
                    # Preserve display environment
                    display = os.environ.get("DISPLAY", ":0")
                    xauth = os.environ.get("XAUTHORITY", os.path.expanduser("~/.Xauthority"))
                    cmd = f"echo '{password}' | pkexec --disable-internal-agent env DISPLAY={display} XAUTHORITY={xauth} {sys.executable} {__file__}"
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    if process.returncode == 0:
                        sys.exit(0)  # Relaunch successful
                    else:
                        QMessageBox.critical(self, "Error", f"Failed to elevate: {stderr.decode()}")
                        self.status_label.setText("Error: Must run with root privileges!")
                        self.status_label.setStyleSheet("color: red")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Elevation failed: {e}")
                    self.status_label.setText("Error: Elevation failed!")
                    self.status_label.setStyleSheet("color: red")
            else:
                self.status_label.setText("Error: Root password required!")
                self.status_label.setStyleSheet("color: red")

    def update_table(self):
        try:
            db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "db", "netwatch.db"))
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("SELECT timestamp, device_name, ip, mac, domain, app FROM activity ORDER BY timestamp DESC LIMIT 50")
            rows = c.fetchall()
            conn.close()
            
            self.table.setRowCount(len(rows))
            for row_idx, row_data in enumerate(rows):
                for col_idx, data in enumerate(row_data):
                    self.table.setItem(row_idx, col_idx, QTableWidgetItem(str(data or "")))
        except sqlite3.OperationalError as e:
            logging.error(f"Database error: {e}")

    def start_monitoring(self):
        global monitoring_running
        if os.geteuid() != 0:
            self.status_label.setText("Error: Must run with root privileges!")
            return
        iface = get_active_interface()
        if not iface:
            self.status_label.setText("Error: No network interface found!")
            return
        
        monitoring_running = True
        self.monitor_thread = threading.Thread(target=start_monitoring_thread, args=(iface,), daemon=True)
        self.monitor_thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Monitoring started")
        self.status_label.setStyleSheet("color: green")

    def stop_monitoring(self):
        global monitoring_running
        monitoring_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Monitoring stopped")
        self.status_label.setStyleSheet("color: green")

# Initialize DB with updated schema
def init_db():
    db_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "db"))
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, "netwatch.db")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_name TEXT,
            ip TEXT,
            mac TEXT,
            domain TEXT,
            app TEXT,
            port INTEGER
        )
    """)
    try:
        c.execute("ALTER TABLE activity ADD COLUMN mac TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    app = QApplication(sys.argv)
    window = NetWatchWindow()
    window.show()
    sys.exit(app.exec_())

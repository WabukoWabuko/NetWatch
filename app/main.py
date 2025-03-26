# app/main.py
import sys
import os
import socket
import sqlite3
import netifaces
import threading
import logging
import subprocess
import requests
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTableWidget, QVBoxLayout, QWidget, 
                            QTableWidgetItem, QPushButton, QHBoxLayout, QLabel, QInputDialog, 
                            QMessageBox, QLineEdit, QComboBox, QDialog, QFormLayout, QCheckBox)
from PyQt5.QtCore import QTimer

# Setup logging with a basic handler to avoid recursion
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(message)s", handlers=[logging.StreamHandler(sys.stdout)])

# Global DB path (computed once)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "db")
DB_PATH = os.path.join(DB_DIR, "netwatch.db")
os.makedirs(DB_DIR, exist_ok=True)

# Monitoring state
monitoring_running = False

# Monitoring functions
def get_device_name(ip):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except socket.herror:
        return "Unknown"

def get_domain_from_ip(ip):
    try:
        domain, _, _ = socket.gethostbyaddr(ip)
        return domain
    except socket.herror:
        return None

def get_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = response.json()
        if data["status"] == "success":
            return f"{data['city']}, {data['regionName']}, {data['country']}"
        return "Unknown"
    except requests.RequestException:
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

def log_to_db(device_name, ip, mac, domain=None, app=None, port=None, location=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            "INSERT INTO activity (timestamp, device_name, ip, mac, domain, app, port, location) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, device_name, ip, mac, domain, app, port, location)
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"DB Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

def process_packet(packet):
    if not monitoring_running:
        return True
    from scapy.all import IP, Ether, DNS, TCP, UDP
    logging.debug("Packet received!")
    if packet.haslayer(IP) and packet.haslayer(Ether):
        ip_src = packet[IP].src
        mac_src = packet[Ether].src
        device_name = get_device_name(ip_src)
        location = get_location(ip_src)
        
        if packet.haslayer(DNS) and packet[DNS].qr == 0:
            domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
            logging.info(f"Device {device_name} ({ip_src}, {mac_src}) visited site: {domain} at {location}")
            log_to_db(device_name, ip_src, mac_src, domain=domain, location=location)
        
        elif packet.haslayer(TCP) or packet.haslayer(UDP):
            port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            app = guess_app_from_port(port, packet)
            domain = get_domain_from_ip(packet[IP].dst) if packet[IP].dst else None
            logging.info(f"Device {device_name} ({ip_src}, {mac_src}) used app: {app} (port {port}) to {domain or 'unknown'} at {location}")
            log_to_db(device_name, ip_src, mac_src, domain=domain, app=app, port=port, location=location)

def guess_app_from_port(port, packet):
    port_map = {
        80: "HTTP Browser",
        443: "HTTPS Browser",
        53: "DNS Client",
        5228: "Google Play",
        1935: "Flash Stream",
        5222: "WhatsApp",
        3478: "Zoom",
        25565: "Minecraft",
    }
    app = port_map.get(port, "Unknown App")
    if packet.haslayer(TCP) and port in [80, 443]:
        if b"GET" in bytes(packet[TCP].payload) or b"POST" in bytes(packet[TCP].payload):
            app = "Web Browser"
        elif b"youtube" in bytes(packet[TCP].payload).lower():
            app = "YouTube"
    return app

def start_monitoring_thread(iface):
    from scapy.all import sniff
    logging.info(f"Starting sniff on {iface}...")
    sniff(iface=iface, prn=process_packet, store=0, stop_filter=lambda x: not monitoring_running)

# Settings Dialog
class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        layout = QFormLayout()
        self.monitor_toggle = QCheckBox("Enable Monitoring")
        self.monitor_toggle.stateChanged.connect(self.toggle_monitoring)
        layout.addRow("Monitoring:", self.monitor_toggle)
        self.setLayout(layout)

    def toggle_monitoring(self, state):
        global monitoring_running
        monitoring_running = bool(state)
        parent = self.parent()
        if monitoring_running:
            parent.start_monitoring()
        else:
            parent.stop_monitoring()

# GUI
class NetWatchWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetWatch")
        self.setGeometry(100, 100, 1000, 700)
        
        self.status_label = QLabel("Initializing...", self)
        self.status_label.setStyleSheet("color: blue")
        
        self.ensure_privileges()
        self.status_label.setText("Ready to monitor")
        self.status_label.setStyleSheet("color: green")
        
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["Time", "Device", "IP", "MAC", "Site", "App", "Location"])
        self.table.horizontalHeader().setStretchLastSection(True)
        
        self.start_btn = QPushButton("Start Monitoring")
        self.stop_btn = QPushButton("Stop Monitoring")
        self.refresh_btn = QPushButton("Refresh")
        self.settings_btn = QPushButton("Settings")
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All Devices")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.refresh_btn.clicked.connect(self.update_table)
        self.settings_btn.clicked.connect(self.show_settings)
        self.filter_combo.currentTextChanged.connect(self.update_table)
        
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.refresh_btn)
        btn_layout.addWidget(self.settings_btn)
        btn_layout.addWidget(QLabel("Filter:"))
        btn_layout.addWidget(self.filter_combo)
        layout = QVBoxLayout()
        layout.addWidget(self.status_label)
        layout.addLayout(btn_layout)
        layout.addWidget(self.table)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_table)
        self.timer.start(2000)
        
        self.update_table()
        self.monitor_thread = None

    def ensure_privileges(self):
        if os.geteuid() != 0:
            password, ok = QInputDialog.getText(self, "Admin Access Required", "Enter root password:", QLineEdit.Password)
            if ok and password:
                try:
                    display = os.environ.get("DISPLAY", ":0")
                    xauth = os.environ.get("XAUTHORITY", os.path.expanduser("~/.Xauthority"))
                    xdg = os.environ.get("XDG_RUNTIME_DIR", "/tmp/runtime-root")
                    cmd = f"echo '{password}' | pkexec --disable-internal-agent env DISPLAY={display} XAUTHORITY={xauth} XDG_RUNTIME_DIR={xdg} {sys.executable} {__file__}"
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    if process.returncode == 0:
                        sys.exit(0)
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
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            filter_device = self.filter_combo.currentText()
            if filter_device == "All Devices":
                c.execute("SELECT timestamp, device_name, ip, mac, domain, app, location FROM activity ORDER BY timestamp DESC LIMIT 50")
            else:
                c.execute("SELECT timestamp, device_name, ip, mac, domain, app, location FROM activity WHERE device_name = ? ORDER BY timestamp DESC LIMIT 50", (filter_device,))
            rows = c.fetchall()
            
            c.execute("SELECT DISTINCT device_name FROM activity")
            devices = [row[0] for row in c.fetchall() if row[0]]
            self.filter_combo.clear()
            self.filter_combo.addItem("All Devices")
            self.filter_combo.addItems(devices)
            
            conn.close()
            
            self.table.setRowCount(len(rows))
            for row_idx, row_data in enumerate(rows):
                for col_idx, data in enumerate(row_data):
                    self.table.setItem(row_idx, col_idx, QTableWidgetItem(str(data or "")))
        except Exception as e:
            print(f"Table update error: {e}")

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

    def show_settings(self):
        dialog = SettingsDialog(self)
        dialog.exec_()

# Initialize DB with updated schema
def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
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
                port INTEGER,
                location TEXT
            )
        """)
        try:
            c.execute("ALTER TABLE activity ADD COLUMN mac TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            c.execute("ALTER TABLE activity ADD COLUMN location TEXT")
        except sqlite3.OperationalError:
            pass
        conn.commit()
    except sqlite3.Error as e:
        print(f"DB Init Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    init_db()
    app = QApplication(sys.argv)
    window = NetWatchWindow()
    window.show()
    sys.exit(app.exec_())

# service/monitor.py
import os
import sys
import socket
import netifaces
import sqlite3
from datetime import datetime
from scapy.all import sniff, DNS, IP, TCP, UDP, Ether
import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(message)s")
running = True  # Global flag for start/stop

def get_device_name(ip):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except socket.herror:
        return "Unknown"

def elevate_privileges():
    if os.geteuid() != 0:
        logging.info("Elevating privileges...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        sys.exit(0)

def get_active_interface():
    for iface in netifaces.interfaces():
        if iface != 'lo':
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                logging.info(f"Found active interface: {iface}")
                return iface
    logging.error("No active interface found!")
    sys.exit(1)

def log_to_db(device_name, ip, mac, domain=None, app=None, port=None):
    conn = sqlite3.connect("db/netwatch.db")
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO activity (timestamp, device_name, ip, mac, domain, app, port) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (timestamp, device_name, ip, mac, domain, app, port)
    )
    conn.commit()
    conn.close()

def process_packet(packet):
    global running
    if not running:
        return True  # Stop sniffing if running is False
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

def capture_traffic():
    logging.info("Starting network monitoring...")
    iface = get_active_interface()
    logging.info(f"Sniffing on interface: {iface}")
    try:
        with open(f"/sys/class/net/{iface}/operstate") as f:
            status = f.read().strip()
        logging.info(f"Interface {iface} status: {status}")
        if status != "up":
            logging.warning("Interface is not up!")
    except FileNotFoundError:
        logging.error(f"Interface {iface} inaccessible")
    
    logging.debug(f"Starting sniff on {iface}...")
    sniff(iface=iface, prn=process_packet, store=0, stop_filter=lambda x: not running)

if __name__ == "__main__":
    elevate_privileges()
    logging.info("Initializing Scapy...")
    try:
        capture_traffic()
    except Exception as e:
        logging.error(f"Error during sniffing: {e}")
        sys.exit(1)

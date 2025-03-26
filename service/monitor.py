# service/monitor.py
import os
import sys
import socket
import netifaces
from scapy.all import sniff, DNS, IP, TCP, UDP, conf
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(message)s")

def get_device_name(ip):
    """Resolve device name from IP."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except socket.herror:
        return "Unknown"

def elevate_privileges():
    """Re-run script with sudo if not elevated."""
    if os.geteuid() != 0:
        logging.info("Elevating privileges...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        sys.exit(0)

def get_active_interface():
    """Find the active non-loopback interface."""
    for iface in netifaces.interfaces():
        if iface != 'lo':
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                logging.info(f"Found active interface: {iface}")
                return iface
    logging.error("No active interface found!")
    sys.exit(1)

def capture_traffic():
    logging.info("Starting network monitoring...")
    
    # Auto-detect interface
    iface = get_active_interface()
    logging.info(f"Sniffing on interface: {iface}")
    
    # Check interface status
    try:
        with open(f"/sys/class/net/{iface}/operstate") as f:
            status = f.read().strip()
        logging.info(f"Interface {iface} status: {status}")
        if status != "up":
            logging.warning("Interface is not up!")
    except FileNotFoundError:
        logging.error(f"Interface {iface} inaccessible")

    def process_packet(packet):
        logging.debug("Packet received!")
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            device_name = get_device_name(ip_src)
            
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                logging.info(f"Device {device_name} ({ip_src}) visited site: {domain}")
            
            elif packet.haslayer(TCP) or packet.haslayer(UDP):
                port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
                app_guess = guess_app_from_port(port)
                logging.info(f"Device {device_name} ({ip_src}) used app: {app_guess} (port {port})")

def guess_app_from_port(port):
    """Guess app based on common ports."""
    port_map = {
        80: "Web Browser (HTTP)",
        443: "Web Browser (HTTPS)",
        53: "DNS Client",
        5228: "Google Services (e.g., Play Store)",
        1935: "Streaming App (e.g., Flash)",
    }
    return port_map.get(port, "Unknown App")

if __name__ == "__main__":
    elevate_privileges()
    logging.info("Initializing Scapy...")
    try:
        # Sniff with verbose mode and timeout to debug
        iface = get_active_interface()
        logging.debug(f"Starting sniff on {iface}...")
        sniff(iface=iface, prn=process_packet, store=0, verbose=True, timeout=60)
        logging.info("Sniffing stopped after 60 seconds.")
    except Exception as e:
        logging.error(f"Error during sniffing: {e}")
        sys.exit(1)

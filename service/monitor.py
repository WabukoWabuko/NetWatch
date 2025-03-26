# service/monitor.py
import os
import sys
import socket
import netifaces
from scapy.all import sniff, DNS, IP, TCP, UDP, conf

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
        print("Elevating privileges...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        sys.exit(0)

def get_active_interface():
    """Find the active non-loopback interface."""
    for iface in netifaces.interfaces():
        if iface != 'lo':  # Skip loopback
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:  # Has an IPv4 address
                print(f"Found active interface: {iface}")
                return iface
    print("No active interface found!")
    sys.exit(1)

def capture_traffic():
    print("Starting network monitoring...")
    
    # Auto-detect interface
    iface = get_active_interface()
    print(f"Sniffing on interface: {iface}")
    
    # Check interface status
    try:
        with open(f"/sys/class/net/{iface}/operstate") as f:
            status = f.read().strip()
        print(f"Interface {iface} status: {status}")
        if status != "up":
            print("Warning: Interface is not up!")
    except FileNotFoundError:
        print(f"Error: Interface {iface} inaccessible")

    def process_packet(packet):
        print("Packet received!")  # Debug
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            device_name = get_device_name(ip_src)
            
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                print(f"Device {device_name} ({ip_src}) visited site: {domain}")
            
            elif packet.haslayer(TCP) or packet.haslayer(UDP):
                port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
                app_guess = guess_app_from_port(port)
                print(f"Device {device_name} ({ip_src}) used app: {app_guess} (port {port})")

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
    try:
        print("Initializing Scapy...")
        # Sniff all traffic, no filter for now
        capture_traffic()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

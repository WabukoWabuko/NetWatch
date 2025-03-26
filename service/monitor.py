# service/monitor.py
import os
import sys
import socket
from scapy.all import sniff, DNS, IP, TCP, UDP

def get_device_name(ip):
    """Resolve device name from IP."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except socket.herror:
        return "Unknown"

def elevate_privileges():
    """Re-run script with sudo if not already elevated."""
    if os.geteuid() != 0:  # Not root
        print("Elevating privileges...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        sys.exit(0)  # Shouldn’t reach here

def capture_traffic(iface=None):
    print("Starting network monitoring...")
    
    def process_packet(packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            device_name = get_device_name(ip_src)
            
            # DNS query (site visited)
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                print(f"Device {device_name} ({ip_src}) visited site: {domain}")
            
            # TCP/UDP traffic (app detection)
            elif packet.haslayer(TCP) or packet.haslayer(UDP):
                port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
                app_guess = guess_app_from_port(port)
                print(f"Device {device_name} ({ip_src}) used app: {app_guess} (port {port})")

def guess_app_from_port(port):
    """Guess app based on common ports (simplified)."""
    port_map = {
        80: "Web Browser (HTTP)",
        443: "Web Browser (HTTPS)",
        53: "DNS Client",
        5228: "Google Services (e.g., Play Store)",
        1935: "Streaming App (e.g., Flash)",
    }
    return port_map.get(port, "Unknown App")

if __name__ == "__main__":
    elevate_privileges()  # Auto-elevate if needed
    # Use default interface; specify if needed (e.g., "wlan0")
    capture_traffic()

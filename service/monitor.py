# service/monitor.py
from scapy.all import sniff, DNS

def capture_traffic():
    print("Starting network monitoring...")
    def process_packet(packet):
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query (not response)
            domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
            ip_src = packet['IP'].src
            print(f"Device {ip_src} queried {domain}")
    
    # Sniff DNS traffic (port 53), limit to 10 packets for testing
    sniff(filter="udp port 53", prn=process_packet, count=10)

if __name__ == "__main__":
    capture_traffic()

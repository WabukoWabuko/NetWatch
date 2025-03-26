# service/monitor.py
import socket
import struct

def capture_dns(start_port=5353, max_attempts=8):
    print("Starting DNS monitoring...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Try binding to a port in the range
    for port in range(start_port, start_port + max_attempts):
        try:
            sock.bind(("0.0.0.0", port))
            print(f"Listening on port {port}")
            break
        except OSError as e:
            if e.errno == 98:  # Address already in use
                print(f"Port {port} in use, trying next...")
                continue
            raise  # Re-raise other errors
    else:
        raise OSError("No available ports found in range!")

    while True:
        try:
            data, addr = sock.recvfrom(512)  # DNS packets are small
            if len(data) > 12:  # Skip header
                query = data[12:].decode('utf-8', errors='ignore').split('\x00')[0]
                print(f"Device {addr[0]} queried {query}")
        except KeyboardInterrupt:
            print("Stopping DNS monitoring...")
            sock.close()
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    capture_dns()

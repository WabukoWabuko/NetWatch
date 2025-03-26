# service/monitor.py
import socket

def capture_dns(start_port=5353, max_attempts=8, upstream_dns="8.8.8.8"):
    print("Starting DNS monitoring...")
    
    # Create UDP socket for listening
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Find an available port
    for port in range(start_port, start_port + max_attempts):
        try:
            sock.bind(("0.0.0.0", port))
            print(f"Listening on port {port}")
            break
        except OSError as e:
            if e.errno == 98:
                print(f"Port {port} in use, trying next...")
                continue
            raise
    else:
        raise OSError("No available ports found!")

    # Upstream DNS server socket
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        try:
            data, addr = sock.recvfrom(512)  # Receive DNS query from client
            if len(data) > 12:  # Basic DNS header check
                query = data[12:].decode('utf-8', errors='ignore').split('\x00')[0]
                print(f"Device {addr[0]} queried {query}")
            
            # Forward query to upstream DNS (e.g., Google)
            upstream.sendto(data, (upstream_dns, 53))
            response, _ = upstream.recvfrom(512)  # Get response
            sock.sendto(response, addr)  # Send response back to client

        except KeyboardInterrupt:
            print("Stopping DNS monitoring...")
            sock.close()
            upstream.close()
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    capture_dns()

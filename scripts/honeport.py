#!/usr/bin/env python3
"""
Lightweight SMB Honeyport listener for internal lateral movement detection.
Logs unauthorized connection attempts to trigger firewall mitigation.
"""
import socket
import sys
import logging

PORT = 445
BIND_IP = "0.0.0.0"
LOG_FILE = "/var/log/honeyport_alerts.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def start_honeyport():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((BIND_IP, PORT))
        server.listen(5)
        print(f"[*] Honeyport listening on {BIND_IP}:{PORT}...")
    except PermissionError:
        print("[!] Error: Root privileges required to bind to port 445.")
        sys.exit(1)

    while True:
        client_sock, client_addr = server.accept()
        attacker_ip = client_addr[0]
        alert_msg = f"SECURITY ALERT: Unauthorized probe on Honeyport TCP/{PORT} from {attacker_ip}"
        
        print(f"[!] {alert_msg}")
        logging.warning(alert_msg)
        client_sock.close()

if __name__ == "__main__":
    start_honeyport()
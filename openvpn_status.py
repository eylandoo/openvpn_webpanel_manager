#!/usr/bin/python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import json
import time
import os
import glob
from concurrent.futures import ThreadPoolExecutor

PORT = 7506
OPENVPN_CONF_DIR = '/etc/openvpn/server/'

class StatusHandler(BaseHTTPRequestHandler):
    def _log(self, message):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)

    def get_status_from_management_port(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=1) as sock:
                sock.settimeout(1)
                sock.recv(4096)
                sock.sendall(b"status 2\n")
                data = b""
                while b"END" not in data:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    data += chunk
                return data.decode('utf-8', errors='ignore')
        except Exception:
            return ""

    def get_all_openvpn_statuses(self):
        port_map = {}
        management_ports_to_scan = set()
        
        try:
            conf_files = glob.glob(os.path.join(OPENVPN_CONF_DIR, '*.conf'))
            for conf_file in conf_files:
                public_port, protocol, mgmt_port = None, None, None
                with open(conf_file, 'r') as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped.startswith('port '):
                            public_port = stripped.split()[1]
                        elif stripped.startswith('proto '):
                            protocol = stripped.split()[1]
                        elif stripped.startswith('management '):
                            mgmt_port = int(stripped.split()[2])
                
                if mgmt_port and public_port and protocol:
                    port_map[mgmt_port] = {'public_port': public_port, 'protocol': protocol}
                    management_ports_to_scan.add(mgmt_port)

        except Exception as e:
            self._log(f"Error scanning for conf files: {e}")
        
        port_map[7505] = {'public_port': '1194', 'protocol': 'udp'}
        if os.path.exists(os.path.join(OPENVPN_CONF_DIR, 'server.conf')):
             with open(os.path.join(OPENVPN_CONF_DIR, 'server.conf'), 'r') as f:
                p, proto = None, None
                for line in f:
                    if line.strip().startswith('port '): p = line.strip().split()[1]
                    if line.strip().startswith('proto '): proto = line.strip().split()[1]
                if p and proto:
                    port_map[7505] = {'public_port': p, 'protocol': proto}
        management_ports_to_scan.add(7505)

        status_outputs = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(self.get_status_from_management_port, '127.0.0.1', port): port for port in management_ports_to_scan}
            for future in future_to_port:
                port = future_to_port[future]
                try:
                    data = future.result()
                    if data:
                        status_outputs[port] = data
                except Exception as e:
                    self._log(f"Error fetching status from a thread for port {port}: {e}")

        return status_outputs, port_map

    def do_GET(self):
        try:
            status_outputs, port_map = self.get_all_openvpn_statuses()
            
            detailed_users = {}
            for mgmt_port, status_data in status_outputs.items():
                port_info = port_map.get(mgmt_port)
                if not port_info: continue
                
                public_port_key = f"{port_info['public_port']}/{port_info['protocol']}"
                for line in status_data.split("\n"):
                    if line.startswith("CLIENT_LIST"):
                        parts = line.split(",")
                        if len(parts) >= 7:
                            username = parts[1].strip()
                            if username:
                                detailed_users.setdefault(username, {})
                                detailed_users[username].setdefault(public_port_key, { "active": 0, "bytes_received": 0, "bytes_sent": 0 })
                                detailed_users[username][public_port_key]["active"] += 1
                                try:
                                    detailed_users[username][public_port_key]["bytes_received"] += int(parts[5])
                                    detailed_users[username][public_port_key]["bytes_sent"] += int(parts[6])
                                except (ValueError, IndexError):
                                    pass
            
            aggregated_users = {}
            for username, port_data in detailed_users.items():
                aggregated_users[username] = { "active": 0, "bytes_received": 0, "bytes_sent": 0 }
                for port, stats in port_data.items():
                    aggregated_users[username]["active"] += stats["active"]
                    aggregated_users[username]["bytes_received"] += stats["bytes_received"]
                    aggregated_users[username]["bytes_sent"] += stats["bytes_sent"]

            final_response = {
                "aggregated": aggregated_users,
                "detailed": detailed_users
            }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(final_response).encode('utf-8'))
        except Exception as e:
            self._log(f"Error in do_GET: {str(e)}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Internal server error"}).encode('utf-8'))

def run_server():
    try:
        server = HTTPServer(('0.0.0.0', PORT), StatusHandler)
        print(f"Smart OpenVPN Status Server (v2) running on http://0.0.0.0:{PORT}", flush=True)
        server.serve_forever()
    except OSError as e:
        print(f"FATAL: Could not bind to port {PORT}. Error: {e}", flush=True)

if __name__ == "__main__":
    run_server()

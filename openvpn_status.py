#!/usr/bin/python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import socket
import json
import time
import os
import glob
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import fcntl

PORT = 7506
OPENVPN_CONF_DIR = '/etc/openvpn/server/'
CCD_DIR = '/etc/openvpn/server/ccd/'
OVPN_FILES_DIR = '/root/ovpnfiles/'
L2TP_ACTIVE_FILE = "/dev/shm/active_l2tp_users"

class StatusHandler(BaseHTTPRequestHandler):
    def _log(self, message):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)

    def _get_all_management_ports(self):
        management_ports = {7505}
        try:
            conf_files = glob.glob(os.path.join(OPENVPN_CONF_DIR, '*.conf'))
            for conf_file in conf_files:
                with open(conf_file, 'r') as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped.startswith('management '):
                            try:
                                mgmt_port = int(stripped.split()[2])
                                management_ports.add(mgmt_port)
                            except (ValueError, IndexError):
                                continue
        except Exception as e:
            self._log(f"Error scanning for conf files: {e}")
        return list(management_ports)

    def get_status_from_management_port(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=2) as sock:
                sock.settimeout(2)
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

    def get_all_openvpn_statuses(self, management_ports_to_scan):
        port_map = {}
        try:
            conf_files = glob.glob(os.path.join(OPENVPN_CONF_DIR, '*.conf'))
            for conf_file in conf_files:
                public_port, protocol, mgmt_port = None, None, None
                with open(conf_file, 'r') as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped.startswith('port '): public_port = stripped.split()[1]
                        elif stripped.startswith('proto '): protocol = stripped.split()[1]
                        elif stripped.startswith('management '): mgmt_port = int(stripped.split()[2])
                if mgmt_port:
                     port_map[mgmt_port] = {'public_port': public_port or 'N/A', 'protocol': protocol or 'N/A'}

            server_conf_path = os.path.join(OPENVPN_CONF_DIR, 'server.conf')
            if os.path.exists(server_conf_path):
                with open(server_conf_path, 'r') as f:
                    p, proto = None, None
                    for line in f:
                        if line.strip().startswith('port '): p = line.strip().split()[1]
                        if line.strip().startswith('proto '): proto = line.strip().split()[1]
                    if p and proto: port_map[7505] = {'public_port': p, 'protocol': proto}
        except Exception as e:
            self._log(f"Error creating port map: {e}")

        status_outputs = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(self.get_status_from_management_port, '127.0.0.1', port): port for port in management_ports_to_scan}
            for future in future_to_port:
                port = future_to_port[future]
                try:
                    data = future.result()
                    if data: status_outputs[port] = data
                except Exception as e:
                    self._log(f"Error fetching status from port {port}: {e}")
        return status_outputs, port_map

    def _get_l2tp_stats(self):
        l2tp_data = {}
        try:
            if not os.path.exists(L2TP_ACTIVE_FILE):
                return {}
            interface_map = {}
            active_interfaces = set()
            if os.path.exists("/proc/net/dev"):
                with open("/proc/net/dev", "r") as f:
                    for line in f:
                        if ":" in line:
                            active_interfaces.add(line.split(":")[0].strip())
            seen_sessions = set()
            with open(L2TP_ACTIVE_FILE, 'r') as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_SH)
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) == 2:
                            uname = parts[0]
                            iface = parts[1].strip()
                            if iface in active_interfaces and iface not in seen_sessions:
                                interface_map[iface] = uname
                                seen_sessions.add(iface)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
            if not interface_map:
                return {}
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            for line in lines:
                if ":" not in line: continue
                parts = line.split(":")
                iface_name = parts[0].strip()
                if iface_name in interface_map:
                    stats = parts[1].split()
                    rx = int(stats[0])
                    tx = int(stats[8])
                    username = interface_map[iface_name]
                    if username not in l2tp_data:
                        l2tp_data[username] = {'active': 0, 'bytes_received': 0, 'bytes_sent': 0}
                    l2tp_data[username]['active'] += 1
                    l2tp_data[username]['bytes_received'] += rx 
                    l2tp_data[username]['bytes_sent'] += tx 
        except Exception as e:
            self._log(f"Error getting L2TP stats: {e}")
        return l2tp_data

    def _get_cisco_stats(self):
        cisco_data = {}
        try:
            result = subprocess.run(['occtl', '-j', 'show', 'users'], capture_output=True, text=True)
            if result.returncode == 0:
                users_list = json.loads(result.stdout)
                for user in users_list:
                    username = user.get('Username')
                    if not username: continue
                    
                    if username not in cisco_data:
                        cisco_data[username] = {'active': 0, 'bytes_received': 0, 'bytes_sent': 0}
                    
                    cisco_data[username]['active'] += 1
                    try:
                        rx = int(user.get('RX', 0))
                        tx = int(user.get('TX', 0))
                        cisco_data[username]['bytes_received'] += rx
                        cisco_data[username]['bytes_sent'] += tx
                    except: pass
        except Exception as e:
            self._log(f"Error getting Cisco stats: {e}")
        return cisco_data

    def do_GET(self):
        try:
            mgmt_ports = self._get_all_management_ports()
            status_outputs, port_map = self.get_all_openvpn_statuses(mgmt_ports)
            
            detailed_users = {}
            for mgmt_port, status_data in status_outputs.items():
                port_info = port_map.get(mgmt_port)
                if not port_info: continue
                key = f"{port_info['public_port']}/{port_info['protocol']}"
                for line in status_data.split("\n"):
                    if line.startswith("CLIENT_LIST"):
                        parts = line.split(",")
                        if len(parts) >= 7:
                            uname = parts[1].strip()
                            if uname:
                                detailed_users.setdefault(uname, {})
                                detailed_users[uname].setdefault(key, { "active": 0, "bytes_received": 0, "bytes_sent": 0 })
                                detailed_users[uname][key]["active"] += 1
                                try:
                                    detailed_users[uname][key]["bytes_received"] += int(parts[5])
                                    detailed_users[uname][key]["bytes_sent"] += int(parts[6])
                                except: pass
            
            l2tp_stats = self._get_l2tp_stats()
            for uname, stats in l2tp_stats.items():
                detailed_users.setdefault(uname, {})
                key = "L2TP/IPsec"
                detailed_users[uname].setdefault(key, { "active": 0, "bytes_received": 0, "bytes_sent": 0 })
                detailed_users[uname][key]["active"] += stats['active']
                detailed_users[uname][key]["bytes_received"] += stats['bytes_received']
                detailed_users[uname][key]["bytes_sent"] += stats['bytes_sent']

            cisco_stats = self._get_cisco_stats()
            for uname, stats in cisco_stats.items():
                detailed_users.setdefault(uname, {})
                key = "Cisco AnyConnect"
                detailed_users[uname].setdefault(key, { "active": 0, "bytes_received": 0, "bytes_sent": 0 })
                detailed_users[uname][key]["active"] += stats['active']
                detailed_users[uname][key]["bytes_received"] += stats['bytes_received']
                detailed_users[uname][key]["bytes_sent"] += stats['bytes_sent']

            aggregated = {}
            for u, p_data in detailed_users.items():
                aggregated[u] = { "active": 0, "bytes_received": 0, "bytes_sent": 0 }
                for p, s in p_data.items():
                    aggregated[u]["active"] += s["active"]
                    aggregated[u]["bytes_received"] += s["bytes_received"]
                    aggregated[u]["bytes_sent"] += s["bytes_sent"]

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({ "aggregated": aggregated, "detailed": detailed_users }).encode('utf-8'))
        except Exception as e:
            self._log(f"Error in do_GET: {str(e)}")
            self.send_response(500)

    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data)
            commands = data.get('commands', [])
            results = []
            
            for item in commands:
                cmd = item.get('command')
                uname = item.get('username')
                success, msg = False, "Unknown"
                
                if cmd == 'kill':
                    # OpenVPN Kill
                    mgmt_ports = self._get_all_management_ports()
                    for port in mgmt_ports:
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=0.5) as s:
                                s.recv(4096); s.sendall(f"kill {uname}\n".encode()); s.recv(4096)
                        except: pass
                    
                    # L2TP Kill
                    try:
                        if os.path.exists(L2TP_ACTIVE_FILE):
                            with open(L2TP_ACTIVE_FILE, 'r') as f:
                                lines = f.readlines()
                            for line in lines:
                                parts = line.strip().split(':')
                                if len(parts) == 2 and parts[0] == uname:
                                    pid_file = f"/var/run/{parts[1]}.pid"
                                    if os.path.exists(pid_file):
                                        with open(pid_file) as pf:
                                            pid = pf.read().strip()
                                            if pid.isdigit(): subprocess.run(["kill", "-9", pid])
                    except: pass

                    # Cisco Kill
                    try:
                        subprocess.run(['occtl', 'disconnect', 'user', uname], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except: pass
                    
                    success, msg = True, "Kill commands sent"

                elif cmd == 'enable_user':
                    Path(CCD_DIR).mkdir(parents=True, exist_ok=True)
                    (Path(CCD_DIR)/uname).touch()
                    success, msg = True, "CCD created"
                elif cmd == 'disable_user':
                    (Path(CCD_DIR)/uname).unlink(missing_ok=True)
                    (Path(OVPN_FILES_DIR)/f"{uname}.ovpn").unlink(missing_ok=True)
                    success, msg = True, "Files removed"
                elif cmd == 'upload_ovpn':
                    content = item.get('ovpn_content')
                    if content:
                        p = Path(OVPN_FILES_DIR)/f"{uname}.ovpn"
                        p.parent.mkdir(parents=True, exist_ok=True)
                        p.write_text(content, encoding='utf-8')
                        success, msg = True, "Uploaded"
                elif cmd == 'delete_user_completely':
                    (Path(CCD_DIR)/uname).unlink(missing_ok=True)
                    (Path(OVPN_FILES_DIR)/f"{uname}.ovpn").unlink(missing_ok=True)
                    try:
                        subprocess.run(['occtl', 'disconnect', 'user', uname], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except: pass
                    success, msg = True, "User deleted from node"
                
                results.append({"username": uname, "success": success, "message": msg})

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"results": results}).encode('utf-8'))
        except Exception as e:
            self.send_error(500, str(e))

def run_server():
    try:
        server = HTTPServer(('0.0.0.0', PORT), StatusHandler)
        server.serve_forever()
    except OSError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    run_server()

#!/usr/bin/python3
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import socket
import json
import time
import os
import glob
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import fcntl
import base64
from datetime import datetime
import sys

PORT = 7506
OPENVPN_CONF_DIR = '/etc/openvpn/server/'
CCD_DIR = '/etc/openvpn/server/ccd/'
OVPN_FILES_DIR = '/root/ovpnfiles/'
L2TP_ACTIVE_FILE = "/dev/shm/active_l2tp_users"
OCCTL_BIN = "/usr/bin/occtl"

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class StatusHandler(BaseHTTPRequestHandler):
    def _log(self, message):
        pass

    def _get_all_management_ports(self):
        management_ports = {7505}
        try:
            conf_files = glob.glob(os.path.join(OPENVPN_CONF_DIR, '*.conf'))
            for conf_file in conf_files:
                try:
                    with open(conf_file, 'r') as f:
                        for line in f:
                            if line.strip().startswith('management '):
                                parts = line.strip().split()
                                if len(parts) >= 3:
                                    try: management_ports.add(int(parts[2]))
                                    except: pass
                except: pass
        except: pass
        return list(management_ports)

    def get_status_from_management_port(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                sock.settimeout(3)
                sock.recv(1024)
                sock.sendall(b"status 2\n")
                data = b""
                while b"END" not in data:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    data += chunk
                return data.decode('utf-8', errors='ignore')
        except: return ""

    def get_all_openvpn_statuses(self):
        ports = self._get_all_management_ports()
        port_map = {}
        try:
            for conf in glob.glob(os.path.join(OPENVPN_CONF_DIR, '*.conf')):
                m_port, proto, pub_port = None, 'UDP', '?'
                with open(conf, 'r') as f:
                    for line in f:
                        if line.startswith('management '): m_port = int(line.split()[2])
                        if line.startswith('proto '): proto = line.split()[1]
                        if line.startswith('port '): pub_port = line.split()[1]
                if m_port: 
                    port_map[m_port] = {'proto': proto.upper(), 'port': pub_port}
        except: pass
        if 7505 not in port_map: port_map[7505] = {'proto': 'UDP', 'port': '1194'}

        results = {}
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(self.get_status_from_management_port, '127.0.0.1', p): p for p in ports}
            for f in futures:
                try:
                    res = f.result()
                    if res: results[futures[f]] = res
                except: pass
        return results, port_map

    def do_GET(self):
        try:
            status_outputs, port_map = self.get_all_openvpn_statuses()
            sessions = []
            detailed_users = {}

            for port, data in status_outputs.items():
                p_info = port_map.get(port, {'proto': 'UDP', 'port': '?'})
                legacy_key = f"{p_info['port']}/{p_info['proto']}"
                
                for line in data.split('\n'):
                    if line.startswith("CLIENT_LIST"):
                        parts = line.split(',')
                        if len(parts) >= 7:
                            uname = parts[1].strip()
                            if uname == 'UNDEF': continue
                            try:
                                real_ip = parts[2].split(':')[0]
                                v_ip = parts[3]
                                rx = int(parts[5])
                                tx = int(parts[6])
                                c_time = time.time()
                                cid = None
                                for i, p in enumerate(parts):
                                    if len(p) == 10 and p.isdigit() and (p.startswith('17') or p.startswith('18')):
                                        c_time = int(p); break
                                if len(parts) > 0 and parts[-2].isdigit(): cid = int(parts[-2])

                                sessions.append({
                                    "username": uname,
                                    "protocol": f"OpenVPN ({p_info['proto']})",
                                    "ip": real_ip,
                                    "v_ip": v_ip,
                                    "bytes_received": rx,
                                    "bytes_sent": tx,
                                    "connected_at": c_time,
                                    "session_id": cid,
                                    "mgmt_port": port
                                })

                                if uname not in detailed_users: detailed_users[uname] = {}
                                if legacy_key not in detailed_users[uname]:
                                    detailed_users[uname][legacy_key] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
                                detailed_users[uname][legacy_key]["active"] += 1
                                detailed_users[uname][legacy_key]["bytes_received"] += rx
                                detailed_users[uname][legacy_key]["bytes_sent"] += tx
                            except: pass

            try:
                if os.path.exists(L2TP_ACTIVE_FILE):
                    valid_lines = []
                    file_dirty = False
                    
                    with open(L2TP_ACTIVE_FILE, 'r') as f:
                        lines = f.readlines()
                    
                    for line in lines:
                        p = line.strip().split(':')
                        if len(p) == 2: 
                            uname = p[0]
                            iface = p[1].strip()
                            
                            if os.path.exists(f"/sys/class/net/{iface}"):
                                valid_lines.append(line)
                                rx, tx = 0, 0
                                try:
                                    with open(f"/sys/class/net/{iface}/statistics/rx_bytes") as f: rx = int(f.read().strip())
                                    with open(f"/sys/class/net/{iface}/statistics/tx_bytes") as f: tx = int(f.read().strip())
                                except: pass
                                
                                pid = 0
                                try:
                                    with open(f"/var/run/{iface}.pid") as f: pid = int(f.read().strip())
                                except: pass

                                sessions.append({
                                    "username": uname,
                                    "protocol": "L2TP",
                                    "ip": "Remote",
                                    "v_ip": "10.10.x.x",
                                    "bytes_received": rx,
                                    "bytes_sent": tx,
                                    "connected_at": time.time(),
                                    "session_id": pid
                                })

                                legacy_key = "L2TP/IPsec"
                                if uname not in detailed_users: detailed_users[uname] = {}
                                if legacy_key not in detailed_users[uname]:
                                    detailed_users[uname][legacy_key] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
                                detailed_users[uname][legacy_key]["active"] += 1
                                detailed_users[uname][legacy_key]["bytes_received"] += rx
                                detailed_users[uname][legacy_key]["bytes_sent"] += tx
                            else:
                                file_dirty = True
                    
                    if file_dirty:
                        try:
                            with open(L2TP_ACTIVE_FILE, 'w') as f: f.writelines(valid_lines)
                        except: pass
            except: pass

            try:
                if os.path.exists(OCCTL_BIN):
                    res = subprocess.run([OCCTL_BIN, '-j', 'show', 'users'], capture_output=True, text=True)
                    if res.returncode == 0:
                        for u in json.loads(res.stdout):
                            uname = u.get('Username')
                            if not uname: continue
                            rx, tx = int(u.get('RX', 0)), int(u.get('TX', 0))
                            
                            sessions.append({
                                "username": uname,
                                "protocol": "Cisco",
                                "ip": u.get('Remote IP', 'N/A'),
                                "v_ip": u.get('VPN IP', 'N/A'),
                                "bytes_received": rx,
                                "bytes_sent": tx,
                                "connected_at": time.time(),
                                "session_id": u.get('ID')
                            })

                            legacy_key = "Cisco AnyConnect"
                            if uname not in detailed_users: detailed_users[uname] = {}
                            if legacy_key not in detailed_users[uname]:
                                detailed_users[uname][legacy_key] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
                            detailed_users[uname][legacy_key]["active"] += 1
                            detailed_users[uname][legacy_key]["bytes_received"] += rx
                            detailed_users[uname][legacy_key]["bytes_sent"] += tx
            except: pass

            aggregated = {}
            for u, data in detailed_users.items():
                aggregated[u] = { "active": 0, "bytes_received": 0, "bytes_sent": 0 }
                for _, stats in data.items():
                    aggregated[u]["active"] += stats["active"]
                    aggregated[u]["bytes_received"] += stats["bytes_received"]
                    aggregated[u]["bytes_sent"] += stats["bytes_sent"]

            response_payload = {
                "sessions": sessions,
                "detailed": detailed_users,
                "aggregated": aggregated
            }
            
            data_json = json.dumps(response_payload)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(data_json))
            self.end_headers()
            self.wfile.write(data_json.encode('utf-8'))

        except Exception as e: 
            self.send_error(500, str(e))

    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data)
            commands = data.get('commands', [])
            results = []
            
            for item in commands:
                try:
                    cmd = item.get('command')
                    uname = item.get('username')
                    success, msg = False, "Unknown"
                    
                    if cmd == 'update_l2tp_secrets':
                        content = item.get('content')
                        if content is not None:
                            try:
                                with open('/etc/ppp/chap-secrets', 'w') as f: f.write(content)
                                success, msg = True, "Updated"
                            except Exception as e: success, msg = False, str(e)

                    elif cmd == 'update_cisco_secrets':
                        content = item.get('content')
                        if content is not None:
                            try:
                                with open('/etc/ocserv/ocpasswd', 'wb') as f: f.write(base64.b64decode(content))
                                success, msg = True, "Updated"
                            except Exception as e: success, msg = False, str(e)
                            
                    elif cmd == 'kill':
                        try:
                            subprocess.run(["pkill", "-9", "-f", f"pppd.*name {uname}"], check=False)
                        except: pass

                        if os.path.exists(OCCTL_BIN):
                            try: subprocess.run([OCCTL_BIN, 'disconnect', 'user', uname], check=False, stdout=subprocess.DEVNULL)
                            except: pass

                        for port in self._get_all_management_ports():
                            try:
                                with socket.create_connection(('127.0.0.1', port), timeout=1) as s:
                                    s.recv(1024); s.sendall(f"kill {uname}\n".encode()); s.recv(1024)
                            except: pass
                        
                        if os.path.exists(L2TP_ACTIVE_FILE):
                            try:
                                lines = []
                                with open(L2TP_ACTIVE_FILE, 'r') as f: lines = f.readlines()
                                with open(L2TP_ACTIVE_FILE, 'w') as f:
                                    for line in lines:
                                        if not line.startswith(f"{uname}:"): f.write(line)
                            except: pass

                        success, msg = True, "Kill Signal Sent"

                    elif cmd == 'enable_user':
                        try:
                            Path(CCD_DIR).mkdir(parents=True, exist_ok=True)
                            (Path(CCD_DIR)/uname).touch()
                            success, msg = True, "CCD created"
                        except Exception as e:
                            success, msg = False, f"CCD Error: {str(e)}"

                    elif cmd == 'disable_user':
                        (Path(CCD_DIR)/uname).unlink(missing_ok=True)
                        (Path(OVPN_FILES_DIR)/f"{uname}.ovpn").unlink(missing_ok=True)
                        success, msg = True, "Disabled"

                    elif cmd == 'upload_ovpn':
                        if item.get('ovpn_content'):
                            try:
                                p = Path(OVPN_FILES_DIR)/f"{uname}.ovpn"
                                p.parent.mkdir(parents=True, exist_ok=True)
                                p.write_text(item.get('ovpn_content'), encoding='utf-8')
                                success, msg = True, "Uploaded"
                            except Exception as e:
                                success, msg = False, f"Upload Error: {str(e)}"
                    
                    elif cmd == 'delete_user_completely':
                        (Path(CCD_DIR)/uname).unlink(missing_ok=True)
                        (Path(OVPN_FILES_DIR)/f"{uname}.ovpn").unlink(missing_ok=True)
                        if os.path.exists(OCCTL_BIN):
                            subprocess.run([OCCTL_BIN, 'disconnect', 'user', uname], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        success, msg = True, "Deleted"

                    results.append({"username": uname, "success": success, "message": msg})

                except Exception as inner_e:
                    results.append({"username": item.get('username'), "success": False, "message": f"Critical Error: {str(inner_e)}"})

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"results": results}).encode('utf-8'))
        except Exception as e:
            self.send_error(500, str(e))

def run_server():
    server = ThreadingHTTPServer(('0.0.0.0', PORT), StatusHandler)
    server.serve_forever()

if __name__ == "__main__":
    run_server()
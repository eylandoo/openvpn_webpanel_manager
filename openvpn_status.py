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
                                ts_index = -1
                                cid = None
                                for i, p in enumerate(parts):
                                    if len(p) == 10 and p.isdigit() and (p.startswith('17') or p.startswith('18')):
                                        ts_index = i
                                        c_time = int(p)
                                        break
                                
                                if ts_index != -1:
                                    if len(parts) > ts_index + 2 and parts[ts_index+2].isdigit():
                                        cid = int(parts[ts_index+2])
                                    elif len(parts) > ts_index + 1 and parts[ts_index+1].isdigit():
                                        cid = int(parts[ts_index+1])
                                
                                if cid is None and len(parts) >= 2 and parts[-2].isdigit():
                                    cid = int(parts[-2])

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
                    l2tp_map = {}
                    with open(L2TP_ACTIVE_FILE, 'r') as f:
                        for line in f:
                            p = line.strip().split(':')
                            if len(p) == 2: l2tp_map[p[1].strip()] = p[0]
                    
                    if os.path.exists("/proc/net/dev"):
                        with open("/proc/net/dev", 'r') as f:
                            for line in f:
                                if ':' in line:
                                    parts = line.split(':')
                                    iface = parts[0].strip()
                                    if iface in l2tp_map:
                                        stats = parts[1].split()
                                        rx, tx = int(stats[0]), int(stats[8])
                                        uname = l2tp_map[iface]
                                        pid_path = f"/var/run/{iface}.pid"
                                        ts = os.path.getmtime(pid_path) if os.path.exists(pid_path) else time.time()
                                        
                                        pid = 0
                                        if os.path.exists(pid_path):
                                            with open(pid_path) as pf: 
                                                pstr = pf.read().strip()
                                                if pstr.isdigit(): pid = int(pstr)

                                        sessions.append({
                                            "username": uname,
                                            "protocol": "L2TP",
                                            "ip": "Remote",
                                            "v_ip": "10.10.x.x",
                                            "bytes_received": rx,
                                            "bytes_sent": tx,
                                            "connected_at": ts,
                                            "session_id": pid
                                        })

                                        legacy_key = "L2TP/IPsec"
                                        if uname not in detailed_users: detailed_users[uname] = {}
                                        if legacy_key not in detailed_users[uname]:
                                            detailed_users[uname][legacy_key] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
                                        detailed_users[uname][legacy_key]["active"] += 1
                                        detailed_users[uname][legacy_key]["bytes_received"] += rx
                                        detailed_users[uname][legacy_key]["bytes_sent"] += tx
            except: pass

            try:
                if os.path.exists(OCCTL_BIN):
                    res = subprocess.run([OCCTL_BIN, '-j', 'show', 'users'], capture_output=True, text=True)
                    if res.returncode == 0:
                        for u in json.loads(res.stdout):
                            uname = u.get('Username')
                            if not uname: continue
                            ts = time.time()
                            try: ts = datetime.strptime(u.get('Connected at',''), "%Y-%m-%d %H:%M:%S").timestamp()
                            except: pass
                            rx, tx = int(u.get('RX', 0)), int(u.get('TX', 0))
                            
                            cid = u.get('ID')

                            sessions.append({
                                "username": uname,
                                "protocol": "Cisco",
                                "ip": u.get('Remote IP', 'N/A'),
                                "v_ip": u.get('VPN IP', 'N/A'),
                                "bytes_received": rx,
                                "bytes_sent": tx,
                                "connected_at": ts,
                                "session_id": cid
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

        except: self.send_response(500)

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
                
                if cmd == 'update_l2tp_secrets':
                    if item.get('content'):
                        try:
                            with open('/etc/ppp/chap-secrets', 'w') as f: f.write(item.get('content'))
                            success, msg = True, "Updated"
                        except Exception as e: success, msg = False, str(e)
                elif cmd == 'update_cisco_secrets':
                    if item.get('content'):
                        try:
                            with open('/etc/ocserv/ocpasswd', 'wb') as f: f.write(base64.b64decode(item.get('content')))
                            success, msg = True, "Updated"
                        except Exception as e: success, msg = False, str(e)
                        
                elif cmd == 'kill':
                    target_sid = item.get('session_id')
                    target_proto = item.get('protocol', '')
                    target_mgmt = item.get('mgmt_port')
                    
                    killed_specific = False

                    if target_sid:
                        if 'OpenVPN' in target_proto and target_mgmt:
                            try:
                                with socket.create_connection(('127.0.0.1', target_mgmt), timeout=1) as s:
                                    s.recv(1024)
                                    s.sendall(f"client-kill {target_sid}\n".encode())
                                    s.recv(1024)
                                    killed_specific = True
                                    msg = f"Killed CID {target_sid}"
                            except: pass
                        elif 'Cisco' in target_proto:
                            if os.path.exists(OCCTL_BIN):
                                try:
                                    subprocess.run([OCCTL_BIN, 'disconnect', 'id', str(target_sid)], check=False, stdout=subprocess.DEVNULL)
                                    killed_specific = True
                                    msg = f"Killed Cisco ID {target_sid}"
                                except: pass
                        elif 'L2TP' in target_proto:
                            try:
                                subprocess.run(["kill", "-9", str(target_sid)], check=False)
                                killed_specific = True
                                msg = f"Killed L2TP PID {target_sid}"
                            except: pass

                    if not killed_specific:
                        try:
                            for port in self._get_all_management_ports():
                                try:
                                    with socket.create_connection(('127.0.0.1', port), timeout=1) as s:
                                        s.recv(1024); s.sendall(f"kill {uname}\n".encode()); s.recv(1024)
                                except: pass
                            if os.path.exists(L2TP_ACTIVE_FILE):
                                with open(L2TP_ACTIVE_FILE, 'r') as f:
                                    for line in f:
                                        parts = line.strip().split(':')
                                        if len(parts) == 2 and parts[0] == uname:
                                            pid_file = f"/var/run/{parts[1]}.pid"
                                            if os.path.exists(pid_file):
                                                with open(pid_file) as pf: subprocess.run(["kill", "-9", pf.read().strip()], check=False)
                            if os.path.exists(OCCTL_BIN):
                                subprocess.run([OCCTL_BIN, 'disconnect', 'user', uname], check=False, stdout=subprocess.DEVNULL)
                            msg = "Killed all (Fallback)"
                        except: pass
                    
                    success = True

                elif cmd == 'enable_user':
                    Path(CCD_DIR).mkdir(parents=True, exist_ok=True)
                    (Path(CCD_DIR)/uname).touch()
                    success, msg = True, "CCD created"
                elif cmd == 'disable_user':
                    (Path(CCD_DIR)/uname).unlink(missing_ok=True)
                    (Path(OVPN_FILES_DIR)/f"{uname}.ovpn").unlink(missing_ok=True)
                    success, msg = True, "Disabled"
                elif cmd == 'upload_ovpn':
                    if item.get('ovpn_content'):
                        p = Path(OVPN_FILES_DIR)/f"{uname}.ovpn"
                        p.parent.mkdir(parents=True, exist_ok=True)
                        p.write_text(item.get('ovpn_content'), encoding='utf-8')
                        success, msg = True, "Uploaded"
                elif cmd == 'delete_user_completely':
                    (Path(CCD_DIR)/uname).unlink(missing_ok=True)
                    (Path(OVPN_FILES_DIR)/f"{uname}.ovpn").unlink(missing_ok=True)
                    if os.path.exists(OCCTL_BIN):
                        subprocess.run([OCCTL_BIN, 'disconnect', 'user', uname], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    success, msg = True, "Deleted"

                results.append({"username": uname, "success": success, "message": msg})

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
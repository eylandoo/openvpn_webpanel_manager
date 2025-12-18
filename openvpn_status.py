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
import base64
import sys
import datetime

PORT = 7506
OPENVPN_CONF_DIR = '/etc/openvpn/server/'
CCD_DIR = '/etc/openvpn/server/ccd/'
OVPN_FILES_DIR = '/root/ovpnfiles/'
L2TP_ACTIVE_FILE = "/dev/shm/active_l2tp_users"
OCCTL_BIN = "/usr/bin/occtl"
CHAP_SECRETS = '/etc/ppp/chap-secrets'
OCPASSWD = '/etc/ocserv/ocpasswd'
OCSERV_CONF = '/etc/ocserv/ocserv.conf'

os.makedirs(OVPN_FILES_DIR, exist_ok=True)
os.makedirs(CCD_DIR, exist_ok=True)

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
            current_system_time = time.time()

            for port, data in status_outputs.items():
                p_info = port_map.get(port, {'proto': 'UDP', 'port': '?'})
                legacy_key = f"{p_info['port']}/{p_info['proto']}"
                for line in data.split('\n'):
                    if line.startswith("CLIENT_LIST"):
                        parts = line.split(',')
                        if len(parts) >= 11:
                            uname = parts[1].strip()
                            if uname == 'UNDEF': continue
                            try:
                                real_ip = parts[2].split(':')[0]
                                v_ip = parts[3]
                                rx = int(parts[5])
                                tx = int(parts[6])
                                c_time = 0
                                found_time = False
                                if len(parts) > 8 and parts[8].isdigit() and len(parts[8]) >= 10:
                                    c_time = int(parts[8])
                                    found_time = True
                                elif len(parts) > 7 and parts[7].isdigit() and len(parts[7]) >= 10:
                                    c_time = int(parts[7])
                                    found_time = True
                                if not found_time:
                                    for p in parts:
                                        if len(p) >= 10 and p.isdigit() and (p.startswith('16') or p.startswith('17') or p.startswith('18')):
                                            c_time = int(p)
                                            break
                                cid = None
                                if len(parts) > 10 and parts[10].isdigit(): cid = int(parts[10])
                                elif len(parts) > 9 and parts[9].isdigit(): cid = int(parts[9])
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
                                    with open(f"/sys/class/net/{iface}/statistics/rx_bytes") as f_rx: rx = int(f_rx.read().strip())
                                    with open(f"/sys/class/net/{iface}/statistics/tx_bytes") as f_tx: tx = int(f_tx.read().strip())
                                except: pass
                                pid = 0
                                l2tp_conn_time = current_system_time
                                try:
                                    pid_path = f"/var/run/{iface}.pid"
                                    if os.path.exists(pid_path):
                                        with open(pid_path) as f_pid: pid = int(f_pid.read().strip())
                                        l2tp_conn_time = os.stat(pid_path).st_mtime
                                except: pass
                                sessions.append({
                                    "username": uname,
                                    "protocol": "L2TP",
                                    "ip": "Remote",
                                    "v_ip": "10.10.x.x",
                                    "bytes_received": rx,
                                    "bytes_sent": tx,
                                    "connected_at": l2tp_conn_time,
                                    "session_id": pid
                                })
                                legacy_key = "L2TP/IPsec"
                                if uname not in detailed_users: detailed_users[uname] = {}
                                if legacy_key not in detailed_users[uname]:
                                    detailed_users[uname][legacy_key] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
                                detailed_users[uname][legacy_key]["active"] += 1
                                detailed_users[uname][legacy_key]["bytes_received"] += rx
                                detailed_users[uname][legacy_key]["bytes_sent"] += tx
                            else: file_dirty = True
                    if file_dirty:
                        try:
                            with open(L2TP_ACTIVE_FILE, 'w') as f_out:
                                f_out.writelines(valid_lines)
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
                            cisco_conn_time = current_system_time
                            conn_str = u.get('Connected at')
                            if conn_str:
                                formats = ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%d/%m/%Y %H:%M:%S', '%Y-%m-%d %H:%M']
                                parsed_ts = None
                                clean_str = conn_str.split('+')[0].split('.')[0].strip()
                                for fmt in formats:
                                    try:
                                        dt = datetime.datetime.strptime(clean_str, fmt)
                                        parsed_ts = dt.timestamp()
                                        break
                                    except: continue
                                if parsed_ts:
                                    diff = current_system_time - parsed_ts
                                    if diff < -600 or diff > 31536000: parsed_ts = current_system_time
                                    cisco_conn_time = parsed_ts
                            sessions.append({
                                "username": uname,
                                "protocol": "Cisco",
                                "ip": u.get('Remote IP', 'N/A'),
                                "v_ip": u.get('VPN IP', 'N/A'),
                                "bytes_received": rx,
                                "bytes_sent": tx,
                                "connected_at": cisco_conn_time,
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
            for u, data_u in detailed_users.items():
                aggregated[u] = { "active": 0, "bytes_received": 0, "bytes_sent": 0 }
                for stats in data_u.values():
                    aggregated[u]["active"] += stats["active"]
                    aggregated[u]["bytes_received"] += stats["bytes_received"]
                    aggregated[u]["bytes_sent"] += stats["bytes_sent"]

            data_json = json.dumps({"sessions": sessions, "detailed": detailed_users, "aggregated": aggregated})
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
            
            if isinstance(data, dict):
                command = data.get('command')
                if command == 'update_cisco_port':
                    new_port = data.get('port')
                    conf_path = '/etc/ocserv/ocserv.conf'
                    subprocess.run(['sed', '-i', f's/^tcp-port.*/tcp-port = {new_port}/', conf_path], check=False)
                    subprocess.run(['sed', '-i', f's/^udp-port.*/udp-port = {new_port}/', conf_path], check=False)
                    subprocess.run(f"iptables -D INPUT -p tcp --dport {new_port} -j ACCEPT || true", shell=True, check=False)
                    subprocess.run(f"iptables -D INPUT -p udp --dport {new_port} -j ACCEPT || true", shell=True, check=False)
                    subprocess.run(f"iptables -I INPUT -p tcp --dport {new_port} -j ACCEPT", shell=True, check=False)
                    subprocess.run(f"iptables -I INPUT -p udp --dport {new_port} -j ACCEPT", shell=True, check=False)
                    subprocess.run(['systemctl', 'restart', 'ocserv'], check=False)
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"success": True}).encode())
                    return

                if command == 'update_openvpn_port':
                    new_port = data.get('port')
                    conf_files = glob.glob('/etc/openvpn/server/*.conf')
                    for cf in conf_files:
                        subprocess.run(['sed', '-i', f's/^port .*/port {new_port}/', cf], check=False)
                    
                    subprocess.run(f"iptables -D INPUT -p udp --dport {new_port} -j ACCEPT || true", shell=True, check=False)
                    subprocess.run(f"iptables -D INPUT -p tcp --dport {new_port} -j ACCEPT || true", shell=True, check=False)
                    subprocess.run(f"iptables -I INPUT -p udp --dport {new_port} -j ACCEPT", shell=True, check=False)
                    subprocess.run(f"iptables -I INPUT -p tcp --dport {new_port} -j ACCEPT", shell=True, check=False)
                    
                    list_units = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running', 'openvpn-server@*', '--no-legend'], capture_output=True, text=True)
                    for line in list_units.stdout.splitlines():
                        unit_name = line.split()[0].strip()
                        if unit_name:
                            subprocess.run(['systemctl', 'restart', unit_name], check=False)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"success": True}).encode())
                    return

            if isinstance(data, dict) and 'commands' in data:
                commands = data.get('commands', [])
            elif isinstance(data, list):
                commands = data
            else:
                commands = [data]

            results = []
            for item in commands:
                try:
                    cmd = item.get('command')
                    uname = item.get('username')
                    success, msg = False, "Unknown"

                    if cmd == 'update_cisco_config':
                        new_port = item.get('port')
                        if new_port:
                            try:
                                conf_path = '/etc/ocserv/ocserv.conf'
                                subprocess.run(['sed', '-i', f's/^tcp-port.*/tcp-port = {new_port}/', conf_path], check=False)
                                subprocess.run(['sed', '-i', f's/^udp-port.*/udp-port = {new_port}/', conf_path], check=False)
                                subprocess.run(['systemctl', 'restart', 'ocserv'], check=False)
                                success, msg = True, "Cisco Config Updated"
                            except Exception as e: success, msg = False, str(e)
                    
                    elif cmd == 'update_l2tp_secrets':
                        content = item.get('content')
                        if content is not None:
                            try:
                                os.makedirs(os.path.dirname(CHAP_SECRETS), exist_ok=True)
                                with open(CHAP_SECRETS, 'w') as f: f.write(content)
                                success, msg = True, "Updated L2TP Secrets"
                            except Exception as e: success, msg = False, str(e)

                    elif cmd == 'update_cisco_secrets':
                        content = item.get('content')
                        if content is not None:
                            try:
                                decoded = base64.b64decode(content)
                                os.makedirs(os.path.dirname(OCPASSWD), exist_ok=True)
                                with open(OCPASSWD, 'wb') as f: f.write(decoded)
                                success, msg = True, "Updated Cisco Secrets"
                            except Exception as e: success, msg = False, str(e)

                    elif cmd == 'upload_ccd':
                        content = item.get('content')
                        if content is not None:
                            try:
                                Path(CCD_DIR).mkdir(parents=True, exist_ok=True)
                                p = Path(CCD_DIR)/uname
                                p.write_text(content, encoding='utf-8')
                                success, msg = True, "CCD Uploaded"
                            except Exception as e: success, msg = False, str(e)

                    elif cmd == 'enable_user':
                        try:
                            Path(CCD_DIR).mkdir(parents=True, exist_ok=True)
                            p_ccd = Path(CCD_DIR)/uname
                            p_ccd.touch()
                            try: os.chmod(str(p_ccd), 0o644)
                            except: pass
                            success, msg = True, "CCD Created"
                        except Exception as e: success, msg = False, str(e)

                    elif cmd == 'kill':
                        try:
                            subprocess.run(["pkill", "-9", "-f", f"pppd.*name {uname}"], check=False)
                            if os.path.exists(OCCTL_BIN):
                                subprocess.run([OCCTL_BIN, 'disconnect', 'user', uname], check=False, stdout=subprocess.DEVNULL)
                            for port in self._get_all_management_ports():
                                try:
                                    with socket.create_connection(('127.0.0.1', port), timeout=1) as s:
                                        s.recv(1024)
                                        s.sendall(f"kill {uname}\n".encode())
                                        s.recv(1024)
                                except: pass
                            if os.path.exists(L2TP_ACTIVE_FILE):
                                try:
                                    with open(L2TP_ACTIVE_FILE, 'r') as f: lines = f.readlines()
                                    with open(L2TP_ACTIVE_FILE, 'w') as f:
                                        for line in lines:
                                            if not line.startswith(f"{uname}:"): f.write(line)
                                except: pass
                            success, msg = True, "Kill Signal Sent"
                        except Exception as e: success, msg = False, str(e)

                    elif cmd == 'disable_user':
                        try:
                            ccd_path = Path(CCD_DIR) / uname
                            if ccd_path.exists():
                                ccd_path.unlink()
                            success, msg = True, "CCD Removed"
                        except Exception as e: success, msg = False, str(e)

                    elif cmd == 'upload_ovpn':
                        content = item.get('ovpn_content') or item.get('content')
                        if content:
                            try:
                                p = Path(OVPN_FILES_DIR)/f"{uname}.ovpn"
                                p.parent.mkdir(parents=True, exist_ok=True)
                                p.write_text(content, encoding='utf-8')
                                success, msg = True, "Uploaded OVPN"
                            except Exception as e: success, msg = False, str(e)
                    
                    elif cmd == 'delete_user_completely':
                        try:
                            (Path(CCD_DIR)/uname).unlink(missing_ok=True)
                            (Path(OVPN_FILES_DIR)/f"{uname}.ovpn").unlink(missing_ok=True)
                            if os.path.exists(OCCTL_BIN):
                                subprocess.run([OCCTL_BIN, 'disconnect', 'user', uname], check=False, stdout=subprocess.DEVNULL)
                            subprocess.run(["pkill", "-9", "-f", f"pppd.*name {uname}"], check=False)
                            success, msg = True, "Deleted"
                        except Exception as e: success, msg = False, str(e)

                    results.append({"username": uname, "success": success, "message": msg})

                except Exception as inner_e:
                    results.append({"username": item.get('username'), "success": False, "message": str(inner_e)})

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
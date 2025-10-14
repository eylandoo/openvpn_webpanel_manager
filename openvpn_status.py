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

PORT = 7506
OPENVPN_CONF_DIR = '/etc/openvpn/server/'
CCD_DIR = '/etc/openvpn/server/ccd/'
OVPN_FILES_DIR = '/root/ovpnfiles/'
OPENVPN_SCRIPT_PATH = "/root/openvpn.sh"

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
                    if data:
                        status_outputs[port] = data
                except Exception as e:
                    self._log(f"Error fetching status from a thread for port {port}: {e}")
        return status_outputs, port_map

    def do_GET(self):
        try:
            management_ports = self._get_all_management_ports()
            status_outputs, port_map = self.get_all_openvpn_statuses(management_ports)
            
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

            final_response = { "aggregated": aggregated_users, "detailed": detailed_users }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(final_response).encode('utf-8'))
        except Exception as e:
            self._log(f"Error in do_GET: {str(e)}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Internal server error"}).encode('utf-8'))

    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data)

            commands = data.get('commands')
            if not commands or not isinstance(commands, list):
                return self.send_error(400, "Request body must contain a 'commands' list.")

            results = []
            
            users_for_batch_delete = [
                item['username'] for item in commands 
                if item.get('command') == 'delete_user_completely' and item.get('username')
            ]
            if users_for_batch_delete:
                success, message = self._handle_batch_delete(users_for_batch_delete)
                results.append({"command": "batch_delete", "success": success, "message": message})

            for item in commands:
                command = item.get('command')
                username = item.get('username')
                
                if command == 'delete_user_completely':
                    continue

                if not command or not username or '/' in username or '..' in username or not username.isascii():
                    results.append({"username": username, "success": False, "error": "Invalid command or username"})
                    continue
                
                success, message = False, "Unknown command"
                if command == 'kill':
                    success, message = self._handle_kill_command(username)
                elif command == 'enable_user':
                    success, message = self._handle_user_files_command(username, 'create_ccd')
                elif command == 'disable_user':
                    success, message = self._handle_user_files_command(username, 'delete_files')
                elif command == 'upload_ovpn':
                    success, message = self._handle_user_files_command(username, 'upload_ovpn', content=item.get('ovpn_content'))
                
                results.append({"username": username, "success": success, "message": message})

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"results": results}).encode('utf-8'))

        except Exception as e:
            self._log(f"Error in do_POST (batch): {str(e)}")
            self.send_error(500, f"Internal server error: {e}")

    def _handle_kill_command(self, username):
        management_ports = self._get_all_management_ports()
        kill_count = 0
        for port in management_ports:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.5) as sock:
                    sock.recv(4096)
                    sock.sendall(f"kill {username}\n".encode())
                    sock.recv(4096)
                    kill_count += 1
            except Exception:
                continue
        return True, f"Kill command sent. {kill_count} sessions terminated."

    def _handle_user_files_command(self, username, action, content=None):
        ccd_path = Path(CCD_DIR) / username
        ovpn_path = Path(OVPN_FILES_DIR) / f"{username}.ovpn"
        try:
            if action == 'create_ccd':
                ccd_path.parent.mkdir(parents=True, exist_ok=True); ccd_path.touch()
                return True, "CCD file created."
            elif action == 'delete_files':
                ccd_path.unlink(missing_ok=True); ovpn_path.unlink(missing_ok=True)
                return True, "CCD and OVPN files removed."
            elif action == 'upload_ovpn':
                if content is None: return False, "Missing ovpn_content"
                ovpn_path.parent.mkdir(parents=True, exist_ok=True)
                ovpn_path.write_text(content, encoding='utf-8')
                return True, "OVPN file uploaded."
        except Exception as e:
            return False, str(e)
            
    def _handle_batch_delete(self, usernames):
        self._log(f"Received FINAL BATCH DELETE command for {len(usernames)} users on this node.")
        try:
            if usernames:
                index_path = "/etc/openvpn/server/easy-rsa/pki/index.txt"
                revoked_count = 0
                if os.path.exists(index_path):
                    with open(index_path, "r+") as f:
                        fcntl.flock(f, fcntl.LOCK_EX)
                        lines = f.readlines()
                        new_lines = []
                        usernames_set = set(usernames)
                        
                        for line in lines:
                            parts = line.strip().split("\t")
                            if len(parts) > 5 and parts[0] == "V":
                                cn_part = next((p for p in parts[5].split("/") if p.startswith("CN=")), None)
                                if cn_part and cn_part.split("=")[1] in usernames_set:
                                    parts[0] = "R"
                                    parts[2] = time.strftime("%y%m%d%H%M%SZ", time.gmtime())
                                    new_lines.append("\t".join(parts) + "\n")
                                    revoked_count += 1
                                    continue
                            new_lines.append(line)

                        f.seek(0)
                        f.writelines(new_lines)
                        f.truncate()
                        fcntl.flock(f, fcntl.LOCK_UN)
                    
                    crl_command = "cd /etc/openvpn/server/easy-rsa/ && ./easyrsa gen-crl"
                    subprocess.run(crl_command, shell=True, check=True, capture_output=True, text=True, executable='/bin/bash')
                    self._log(f"Marked {revoked_count} users as 'Revoked' and regenerated CRL on node.")

            for username in usernames:
                self._handle_kill_command(username)

            files_to_delete = []
            for username in usernames:
                files_to_delete.append(str(Path(CCD_DIR) / username))
                files_to_delete.append(str(Path(OVPN_FILES_DIR) / f"{username}.ovpn"))
            
            if files_to_delete:
                rm_proc = subprocess.Popen(['xargs', '-0', 'rm', '-f'], stdin=subprocess.PIPE, text=True)
                rm_proc.communicate('\0'.join(files_to_delete))
                self._log(f"Batch-deleted {len(files_to_delete)} files on node.")

            return True, f"{len(usernames)} users processed for batch deletion on this node."
        except Exception as e:
            self._log(f"Error during ultimate batch delete on node: {str(e)}")
            return False, f"Batch delete failed on node: {str(e)}"

def run_server():
    try:
        server = HTTPServer(('0.0.0.0', PORT), StatusHandler)
        print(f"Smart OpenVPN Status & Command Server (v6.0 - Ultimate Batch) running on http://0.0.0.0:{PORT}", flush=True)
        server.serve_forever()
    except OSError as e:
        print(f"FATAL: Could not bind to port {PORT}. Error: {e}", flush=True)

if __name__ == "__main__":
    run_server()

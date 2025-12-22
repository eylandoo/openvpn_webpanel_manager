#!/usr/bin/python3
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import json
import time
import os
import glob
import subprocess
import base64
import datetime

PORT = 7506
OPENVPN_CONF_DIR = "/etc/openvpn/server/"
CCD_DIR = "/etc/openvpn/server/ccd/"
OVPN_FILES_DIR = "/root/ovpnfiles/"
L2TP_ACTIVE_FILE = "/dev/shm/active_l2tp_users"
OCCTL_BIN = "/usr/bin/occtl"
CHAP_SECRETS = "/etc/ppp/chap-secrets"
OCPASSWD = "/etc/ocserv/ocpasswd"
OCSERV_CONF = "/etc/ocserv/ocserv.conf"

Path(OVPN_FILES_DIR).mkdir(parents=True, exist_ok=True)
Path(CCD_DIR).mkdir(parents=True, exist_ok=True)

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class StatusHandler(BaseHTTPRequestHandler):
    def _log(self, message):
        return

    def log_message(self, format, *args):
        return

    def _send_json(self, status_code, data):
        payload = json.dumps(data)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload.encode("utf-8"))

    def _get_system_stats(self):
        try:
            with open("/proc/loadavg", "r") as f:
                load = f.read().split()[0]
                cpu_usage = float(load) * 100 / max(os.cpu_count() or 1, 1)

            with open("/proc/meminfo", "r") as f:
                meminfo = {}
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        meminfo[parts[0].strip()] = int(parts[1].split()[0])
                total = meminfo.get("MemTotal", 1)
                free = meminfo.get("MemFree", 0) + meminfo.get("Buffers", 0) + meminfo.get("Cached", 0)
                ram_usage = ((total - free) / total) * 100

            st = os.statvfs("/")
            disk_usage = ((st.f_blocks - st.f_bfree) / max(st.f_blocks, 1)) * 100
            return round(cpu_usage, 1), round(ram_usage, 1), round(disk_usage, 1)
        except:
            return 0.0, 0.0, 0.0

    def _get_all_management_ports(self):
        management_ports = {7505}
        try:
            for conf_file in glob.glob(os.path.join(OPENVPN_CONF_DIR, "*.conf")):
                try:
                    with open(conf_file, "r") as f:
                        for line in f:
                            s = line.strip()
                            if s.startswith("management"):
                                parts = s.split()
                                if len(parts) >= 3:
                                    try:
                                        management_ports.add(int(parts[2]))
                                    except:
                                        pass
                except:
                    pass
        except:
            pass
        return list(management_ports)

    def _get_status_from_management_port(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                sock.settimeout(3)
                try:
                    sock.recv(1024)
                except:
                    pass
                sock.sendall(b"status 2\n")
                data = b""
                while b"END" not in data:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                return data.decode("utf-8", errors="ignore")
        except:
            return ""

    def _get_openvpn_port_map(self):
        port_map = {}
        try:
            for conf in glob.glob(os.path.join(OPENVPN_CONF_DIR, "*.conf")):
                m_port = None
                proto = "UDP"
                pub_port = "?"
                try:
                    with open(conf, "r") as f:
                        for line in f:
                            if line.startswith("management "):
                                parts = line.split()
                                if len(parts) >= 3:
                                    try:
                                        m_port = int(parts[2])
                                    except:
                                        m_port = None
                            elif line.startswith("proto "):
                                parts = line.split()
                                if len(parts) >= 2:
                                    proto = parts[1]
                            elif line.startswith("port "):
                                parts = line.split()
                                if len(parts) >= 2:
                                    pub_port = parts[1]
                except:
                    continue
                if m_port:
                    port_map[m_port] = {"proto": str(proto).upper(), "port": str(pub_port)}
        except:
            pass
        if 7505 not in port_map:
            port_map[7505] = {"proto": "UDP", "port": "1194"}
        return port_map

    def _get_all_openvpn_statuses(self):
        ports = self._get_all_management_ports()
        port_map = self._get_openvpn_port_map()
        results = {}
        with ThreadPoolExecutor(max_workers=6) as ex:
            futures = {ex.submit(self._get_status_from_management_port, "127.0.0.1", p): p for p in ports}
            for fut, p in futures.items():
                try:
                    res = fut.result()
                    if res:
                        results[p] = res
                except:
                    pass
        return results, port_map

    def _extract_openvpn_sessions(self, status_outputs, port_map, detailed_users):
        sessions = []
        for mgmt_port, data in status_outputs.items():
            p_info = port_map.get(mgmt_port, {"proto": "UDP", "port": "?"})
            legacy_key = f"{p_info.get('port', '?')}/{p_info.get('proto', 'UDP')}"
            for line in data.split("\n"):
                if not line.startswith("CLIENT_LIST"):
                    continue
                parts = line.split(",")
                if len(parts) < 9:
                    continue
                uname = parts[1].strip()
                if not uname or uname == "Common Name" or uname == "UNDEF":
                    continue
                try:
                    real_ip = parts[2].split(":")[0]
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
                            if p.isdigit() and len(p) >= 10 and (p.startswith("16") or p.startswith("17") or p.startswith("18") or p.startswith("19") or p.startswith("20")):
                                c_time = int(p)
                                break

                    cid = None
                    if len(parts) > 10 and parts[10].isdigit():
                        cid = int(parts[10])
                    elif len(parts) > 9 and parts[9].isdigit():
                        cid = int(parts[9])

                    sessions.append(
                        {
                            "username": uname,
                            "protocol": f"OpenVPN ({p_info.get('proto', 'UDP')})",
                            "ip": real_ip,
                            "v_ip": v_ip,
                            "bytes_received": rx,
                            "bytes_sent": tx,
                            "connected_at": c_time,
                            "session_id": cid,
                            "mgmt_port": mgmt_port,
                        }
                    )

                    if uname not in detailed_users:
                        detailed_users[uname] = {}
                    if legacy_key not in detailed_users[uname]:
                        detailed_users[uname][legacy_key] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
                    detailed_users[uname][legacy_key]["active"] += 1
                    detailed_users[uname][legacy_key]["bytes_received"] += rx
                    detailed_users[uname][legacy_key]["bytes_sent"] += tx
                except:
                    pass
        return sessions

    def _extract_l2tp_sessions(self, detailed_users):
        sessions = []
        current_system_time = time.time()
        if not os.path.exists(L2TP_ACTIVE_FILE):
            return sessions

        try:
            with open(L2TP_ACTIVE_FILE, "r") as f:
                lines = f.readlines()
        except:
            return sessions

        valid_lines = []
        file_dirty = False

        for line in lines:
            p = line.strip().split(":")
            if len(p) != 2:
                file_dirty = True
                continue
            uname = p[0].strip()
            iface = p[1].strip()
            if not uname or not iface:
                file_dirty = True
                continue
            if not os.path.exists(f"/sys/class/net/{iface}"):
                file_dirty = True
                continue

            valid_lines.append(line)

            rx, tx = 0, 0
            try:
                with open(f"/sys/class/net/{iface}/statistics/rx_bytes") as f_rx:
                    rx = int(f_rx.read().strip() or "0")
                with open(f"/sys/class/net/{iface}/statistics/tx_bytes") as f_tx:
                    tx = int(f_tx.read().strip() or "0")
            except:
                pass

            pid = 0
            l2tp_conn_time = current_system_time
            try:
                pid_path = f"/var/run/{iface}.pid"
                if os.path.exists(pid_path):
                    with open(pid_path) as f_pid:
                        pid = int((f_pid.read().strip() or "0"))
                    l2tp_conn_time = os.stat(pid_path).st_mtime
            except:
                l2tp_conn_time = current_system_time

            sessions.append(
                {
                    "username": uname,
                    "protocol": "L2TP",
                    "ip": "Remote",
                    "v_ip": "10.10.x.x",
                    "bytes_received": rx,
                    "bytes_sent": tx,
                    "connected_at": l2tp_conn_time,
                    "session_id": pid,
                }
            )

            legacy_key = "L2TP/IPsec"
            if uname not in detailed_users:
                detailed_users[uname] = {}
            if legacy_key not in detailed_users[uname]:
                detailed_users[uname][legacy_key] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
            detailed_users[uname][legacy_key]["active"] += 1
            detailed_users[uname][legacy_key]["bytes_received"] += rx
            detailed_users[uname][legacy_key]["bytes_sent"] += tx

        if file_dirty:
            try:
                with open(L2TP_ACTIVE_FILE, "w") as f_out:
                    f_out.writelines(valid_lines)
            except:
                pass

        return sessions

    def _parse_time_str_to_epoch(self, s, fallback_epoch):
        if not s:
            return fallback_epoch
        try:
            clean = str(s).split("+")[0].split(".")[0].strip()
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%d/%m/%Y %H:%M:%S",
                "%Y-%m-%d %H:%M",
                "%Y-%m-%dT%H:%M",
            ]
            for fmt in formats:
                try:
                    dt = datetime.datetime.strptime(clean, fmt)
                    ts = dt.timestamp()
                    if ts < 0:
                        return fallback_epoch
                    return ts
                except:
                    continue
            return fallback_epoch
        except:
            return fallback_epoch

    def _extract_cisco_sessions(self, detailed_users):
        sessions = []
        current_system_time = time.time()
        if not os.path.exists(OCCTL_BIN):
            return sessions
        try:
            res = subprocess.run([OCCTL_BIN, "-j", "show", "users"], capture_output=True, text=True)
            if res.returncode != 0:
                return sessions
            users = json.loads(res.stdout or "[]")
            for u in users:
                uname = u.get("Username")
                if not uname:
                    continue
                rx = int(u.get("RX", 0) or 0)
                tx = int(u.get("TX", 0) or 0)
                conn_time = current_system_time
                conn_str = u.get("Connected at")
                conn_time = self._parse_time_str_to_epoch(conn_str, current_system_time)

                sessions.append(
                    {
                        "username": uname,
                        "protocol": "Cisco",
                        "ip": u.get("Remote IP", "N/A"),
                        "v_ip": u.get("VPN IP", "N/A"),
                        "bytes_received": rx,
                        "bytes_sent": tx,
                        "connected_at": conn_time,
                        "session_id": u.get("ID"),
                    }
                )

                legacy_key = "Cisco AnyConnect"
                if uname not in detailed_users:
                    detailed_users[uname] = {}
                if legacy_key not in detailed_users[uname]:
                    detailed_users[uname][legacy_key] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
                detailed_users[uname][legacy_key]["active"] += 1
                detailed_users[uname][legacy_key]["bytes_received"] += rx
                detailed_users[uname][legacy_key]["bytes_sent"] += tx
        except:
            pass
        return sessions

    def _build_aggregated(self, detailed_users):
        aggregated = {}
        for uname, d in detailed_users.items():
            aggregated[uname] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
            try:
                for stats in d.values():
                    aggregated[uname]["active"] += int(stats.get("active", 0) or 0)
                    aggregated[uname]["bytes_received"] += int(stats.get("bytes_received", 0) or 0)
                    aggregated[uname]["bytes_sent"] += int(stats.get("bytes_sent", 0) or 0)
            except:
                pass
        return aggregated

    def _handle_l2tp_single(self, cmd):
        uname = (cmd.get("username") or "").strip()
        passw = cmd.get("password")
        action = (cmd.get("action") or "add").strip().lower()

        if not uname:
            return False, "Missing username"

        Path(os.path.dirname(CHAP_SECRETS) or "/").mkdir(parents=True, exist_ok=True)
        if not os.path.exists(CHAP_SECRETS):
            try:
                with open(CHAP_SECRETS, "w") as f:
                    f.write("# Secrets for L2TP\n")
            except:
                return False, "Cannot init secrets"

        try:
            with open(CHAP_SECRETS, "r") as f:
                lines = f.readlines()
        except:
            lines = []

        new_lines = []
        user_quoted = f"\"{uname}\""
        for line in lines:
            parts = line.strip().split()
            if not parts:
                new_lines.append(line)
                continue
            if parts[0] == user_quoted:
                continue
            new_lines.append(line)

        if action in ["add", "update"]:
            if not passw:
                return False, "Missing password"
            new_lines.append(f"\"{uname}\" l2tpd \"{passw}\" *\n")

        try:
            with open(CHAP_SECRETS, "w") as f:
                f.writelines(new_lines)
            return True, f"L2TP {action} success"
        except:
            return False, "Write failed"

    def _handle_cisco_single(self, cmd):
        uname = (cmd.get("username") or "").strip()
        passw = cmd.get("password")
        action = (cmd.get("action") or "add").strip().lower()

        if not uname:
            return False, "Missing username"

        Path(os.path.dirname(OCPASSWD) or "/").mkdir(parents=True, exist_ok=True)
        if not os.path.exists(OCPASSWD):
            try:
                with open(OCPASSWD, "wb") as f:
                    f.write(b"")
            except:
                return False, "Cannot init ocpasswd file"

        try:
            if action == "delete":
                subprocess.run(["ocpasswd", "-c", OCPASSWD, "-d", uname], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True, "Cisco delete success"
            if action in ["add", "update"]:
                if not passw:
                    return False, "Missing password"
                proc = subprocess.Popen(["ocpasswd", "-c", OCPASSWD, uname], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                proc.communicate(input=f"{passw}\n{passw}\n".encode("utf-8"))
                return True, f"Cisco {action} success"
            return False, "Unknown action"
        except:
            return False, "Cisco action failed"

    def _update_iptables_port(self, port):
        p = str(int(port))
        subprocess.run(f"iptables -D INPUT -p tcp --dport {p} -j ACCEPT || true", shell=True, check=False)
        subprocess.run(f"iptables -D INPUT -p udp --dport {p} -j ACCEPT || true", shell=True, check=False)
        subprocess.run(f"iptables -I INPUT -p tcp --dport {p} -j ACCEPT", shell=True, check=False)
        subprocess.run(f"iptables -I INPUT -p udp --dport {p} -j ACCEPT", shell=True, check=False)

    def _restart_openvpn_units(self):
        list_units = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "openvpn-server@*", "--no-legend"],
            capture_output=True,
            text=True,
        )
        for line in (list_units.stdout or "").splitlines():
            unit_name = (line.split() or [""])[0].strip()
            if unit_name:
                subprocess.run(["systemctl", "restart", unit_name], check=False)

    def do_GET(self):
        try:
            cpu, ram, disk = self._get_system_stats()

            status_outputs, port_map = self._get_all_openvpn_statuses()
            detailed_users = {}

            sessions = []
            sessions.extend(self._extract_openvpn_sessions(status_outputs, port_map, detailed_users))
            sessions.extend(self._extract_l2tp_sessions(detailed_users))
            sessions.extend(self._extract_cisco_sessions(detailed_users))

            aggregated = self._build_aggregated(detailed_users)

            self._send_json(
                200,
                {
                    "cpu": cpu,
                    "ram": ram,
                    "disk": disk,
                    "sessions": sessions,
                    "detailed": detailed_users,
                    "aggregated": aggregated,
                },
            )
        except Exception as e:
            try:
                self.send_error(500, str(e))
            except:
                pass

    def do_POST(self):
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"
            data = json.loads(post_data or b"{}")

            if isinstance(data, dict):
                cmd0 = data.get("command")
                if cmd0 == "update_cisco_port":
                    new_port = data.get("port")
                    if new_port is not None:
                        p = str(int(new_port))
                        if os.path.exists(OCSERV_CONF):
                            subprocess.run(["sed", "-i", f"s/^tcp-port.*/tcp-port = {p}/", OCSERV_CONF], check=False)
                            subprocess.run(["sed", "-i", f"s/^udp-port.*/udp-port = {p}/", OCSERV_CONF], check=False)
                        self._update_iptables_port(p)
                        subprocess.run(["systemctl", "restart", "ocserv"], check=False)
                        self._send_json(200, {"success": True})
                        return

                if cmd0 == "update_openvpn_port":
                    new_port = data.get("port")
                    if new_port is not None:
                        p = str(int(new_port))
                        for cf in glob.glob(os.path.join(OPENVPN_CONF_DIR, "*.conf")):
                            subprocess.run(["sed", "-i", f"s/^port .*/port {p}/", cf], check=False)
                        self._update_iptables_port(p)
                        self._restart_openvpn_units()
                        self._send_json(200, {"success": True})
                        return

            if isinstance(data, dict) and "commands" in data:
                commands = data.get("commands", [])
            elif isinstance(data, list):
                commands = data
            else:
                commands = [data]

            results = []
            for item in commands:
                try:
                    cmd = item.get("command")
                    uname = item.get("username")
                    success, msg = False, "Unknown"

                    if cmd == "l2tp_single_action":
                        success, msg = self._handle_l2tp_single(item)

                    elif cmd == "cisco_single_action":
                        success, msg = self._handle_cisco_single(item)

                    elif cmd == "update_cisco_config":
                        new_port = item.get("port")
                        if new_port is not None:
                            p = str(int(new_port))
                            if os.path.exists(OCSERV_CONF):
                                subprocess.run(["sed", "-i", f"s/^tcp-port.*/tcp-port = {p}/", OCSERV_CONF], check=False)
                                subprocess.run(["sed", "-i", f"s/^udp-port.*/udp-port = {p}/", OCSERV_CONF], check=False)
                            subprocess.run(["systemctl", "restart", "ocserv"], check=False)
                            success, msg = True, "Cisco Config Updated"
                        else:
                            success, msg = False, "Missing port"

                    elif cmd == "update_l2tp_secrets":
                        content = item.get("content")
                        if content is not None:
                            Path(os.path.dirname(CHAP_SECRETS) or "/").mkdir(parents=True, exist_ok=True)
                            with open(CHAP_SECRETS, "w") as f:
                                f.write(content)
                            success, msg = True, "Updated L2TP Secrets"
                        else:
                            success, msg = False, "Missing content"

                    elif cmd == "update_cisco_secrets":
                        content = item.get("content")
                        if content is not None:
                            decoded = base64.b64decode(content)
                            Path(os.path.dirname(OCPASSWD) or "/").mkdir(parents=True, exist_ok=True)
                            with open(OCPASSWD, "wb") as f:
                                f.write(decoded)
                            success, msg = True, "Updated Cisco Secrets"
                        else:
                            success, msg = False, "Missing content"

                    elif cmd == "upload_ccd":
                        content = item.get("content")
                        if uname and content is not None:
                            Path(CCD_DIR).mkdir(parents=True, exist_ok=True)
                            p = Path(CCD_DIR) / str(uname)
                            p.write_text(content, encoding="utf-8")
                            success, msg = True, "CCD Uploaded"
                        else:
                            success, msg = False, "Missing username/content"

                    elif cmd == "enable_user":
                        if uname:
                            Path(CCD_DIR).mkdir(parents=True, exist_ok=True)
                            p_ccd = Path(CCD_DIR) / str(uname)
                            p_ccd.touch(exist_ok=True)
                            try:
                                os.chmod(str(p_ccd), 0o644)
                            except:
                                pass
                            success, msg = True, "CCD Created"
                        else:
                            success, msg = False, "Missing username"

                    elif cmd == "disable_user":
                        if uname:
                            try:
                                (Path(CCD_DIR) / str(uname)).unlink(missing_ok=True)
                            except:
                                pass
                            try:
                                self._handle_l2tp_single({"username": uname, "action": "delete"})
                            except:
                                pass
                            try:
                                self._handle_cisco_single({"username": uname, "action": "delete"})
                            except:
                                pass
                            success, msg = True, "User Disabled"
                        else:
                            success, msg = False, "Missing username"

                    elif cmd == "upload_ovpn":
                        content = item.get("ovpn_content") or item.get("content")
                        if uname and content:
                            p = Path(OVPN_FILES_DIR) / f"{uname}.ovpn"
                            p.parent.mkdir(parents=True, exist_ok=True)
                            p.write_text(content, encoding="utf-8")
                            success, msg = True, "Uploaded OVPN"
                        else:
                            success, msg = False, "Missing username/content"

                    elif cmd == "kill":
                        if uname:
                            try:
                                subprocess.run(["pkill", "-9", "-f", f"pppd.*name {uname}"], check=False)
                            except:
                                pass
                            try:
                                if os.path.exists(OCCTL_BIN):
                                    subprocess.run([OCCTL_BIN, "disconnect", "user", str(uname)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            except:
                                pass
                            try:
                                for port in self._get_all_management_ports():
                                    try:
                                        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                                            s.settimeout(2)
                                            try:
                                                s.recv(1024)
                                            except:
                                                pass
                                            s.sendall(f"kill {uname}\n".encode("utf-8"))
                                            try:
                                                s.recv(1024)
                                            except:
                                                pass
                                    except:
                                        pass
                            except:
                                pass
                            try:
                                if os.path.exists(L2TP_ACTIVE_FILE):
                                    with open(L2TP_ACTIVE_FILE, "r") as f:
                                        lines = f.readlines()
                                    with open(L2TP_ACTIVE_FILE, "w") as f:
                                        for line in lines:
                                            if not line.startswith(f"{uname}:"):
                                                f.write(line)
                            except:
                                pass
                            success, msg = True, "Kill Signal Sent"
                        else:
                            success, msg = False, "Missing username"

                    elif cmd == "kill_id":
                        sid = item.get("session_id")
                        proto = str(item.get("protocol") or "")
                        uname2 = (item.get("username") or "").strip()
                        try:
                            if sid is not None and ("Cisco" in proto):
                                subprocess.run(
                                    [OCCTL_BIN, "disconnect", "id", str(sid)],
                                    check=False,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                )
                                success, msg = True, "Killed by ID"

                            elif sid is not None and ("L2TP" in proto):
                                subprocess.run(
                                    ["kill", "-9", str(sid)],
                                    check=False,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                )
                                success, msg = True, "Killed by ID"

                            elif sid is not None and ("OpenVPN" in proto):
                                for port in self._get_all_management_ports():
                                    try:
                                        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                                            s.settimeout(2)
                                            try:
                                                s.recv(1024)
                                            except:
                                                pass
                                            s.sendall(f"client-kill {sid}\n".encode("utf-8"))
                                            try:
                                                s.recv(1024)
                                            except:
                                                pass
                                    except:
                                        pass
                                success, msg = True, "Killed by ID"

                            else:
                                success, msg = False, "Unsupported"

                        except:
                            success, msg = False, "Kill ID failed"


                    elif cmd == "delete_user_completely":
                        if uname:
                            try:
                                (Path(CCD_DIR) / str(uname)).unlink(missing_ok=True)
                            except:
                                pass
                            try:
                                (Path(OVPN_FILES_DIR) / f"{uname}.ovpn").unlink(missing_ok=True)
                            except:
                                pass
                            try:
                                self._handle_l2tp_single({"username": uname, "action": "delete"})
                            except:
                                pass
                            try:
                                self._handle_cisco_single({"username": uname, "action": "delete"})
                            except:
                                pass
                            try:
                                subprocess.run(["pkill", "-9", "-f", f"pppd.*name {uname}"], check=False)
                            except:
                                pass
                            try:
                                if os.path.exists(OCCTL_BIN):
                                    subprocess.run([OCCTL_BIN, "disconnect", "user", str(uname)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            except:
                                pass
                            success, msg = True, "Deleted"
                        else:
                            success, msg = False, "Missing username"

                    elif cmd == "update_openvpn_port":
                        new_port = item.get("port")
                        if new_port is not None:
                            p = str(int(new_port))
                            for cf in glob.glob(os.path.join(OPENVPN_CONF_DIR, "*.conf")):
                                subprocess.run(["sed", "-i", f"s/^port .*/port {p}/", cf], check=False)
                            self._update_iptables_port(p)
                            self._restart_openvpn_units()
                            success, msg = True, "Port Updated"
                        else:
                            success, msg = False, "Missing port"

                    elif cmd == "update_cisco_port":
                        new_port = item.get("port")
                        if new_port is not None:
                            p = str(int(new_port))
                            if os.path.exists(OCSERV_CONF):
                                subprocess.run(["sed", "-i", f"s/^tcp-port.*/tcp-port = {p}/", OCSERV_CONF], check=False)
                                subprocess.run(["sed", "-i", f"s/^udp-port.*/udp-port = {p}/", OCSERV_CONF], check=False)
                            self._update_iptables_port(p)
                            subprocess.run(["systemctl", "restart", "ocserv"], check=False)
                            success, msg = True, "Cisco Port Updated"
                        else:
                            success, msg = False, "Missing port"

                    results.append({"username": uname, "success": success, "message": msg})
                except Exception as inner_e:
                    results.append({"username": item.get("username"), "success": False, "message": str(inner_e)})

            self._send_json(200, {"results": results})
        except Exception as e:
            try:
                self.send_error(500, str(e))
            except:
                pass

def run_server():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), StatusHandler)
    server.serve_forever()

if __name__ == "__main__":
    run_server()

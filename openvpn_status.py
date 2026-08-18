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
import shutil
import base64
import datetime
import tempfile
import threading
import fcntl
import re
import urllib.request
import urllib.error

PORT = 7506
OPENVPN_CONF_DIR = "/etc/openvpn/server/"
CCD_DIR = "/etc/openvpn/server/ccd/"
OVPN_FILES_DIR = "/root/ovpnfiles/"
L2TP_ACTIVE_FILE = "/dev/shm/active_l2tp_users"
OCCTL_BIN = "/usr/bin/occtl"
CHAP_SECRETS = "/etc/ppp/chap-secrets"
OCPASSWD = "/etc/ocserv/ocpasswd"
OCSERV_CONF = "/etc/ocserv/ocserv.conf"

WG1_CONF = "/etc/wireguard/wg1.conf"
WG1_BASE = "/etc/wireguard/wg1_base.conf"
WG1_PEERS_DB = "/etc/wireguard/wg1_peers.json"
WG1_IFACE = "wg1"
WG1_HANDSHAKE_TIMEOUT = 120

WG1_TRAFFIC_TIMEOUT = 10
WG1_PEER_ACTIVITY = {}
WG_INSTANCE_PEER_ACTIVITY = {}

WG_KILL_STRIKES = {}
WG_KILL_STRIKES_LOCK = threading.Lock()
WG_STRIKE_WINDOW_SECONDS = 60

WG_KICK_GENERATION = {}
WG_KICK_GENERATION_LOCK = threading.Lock()

WG_TEMP_BLOCKED_UNTIL = {}
WG_TEMP_BLOCKED_UNTIL_LOCK = threading.Lock()


def _wg_should_block_after_kill(username, instance_name, pubkey):
    key = username
    now = time.time()
    with WG_KILL_STRIKES_LOCK:
        last = WG_KILL_STRIKES.get(key)
        WG_KILL_STRIKES[key] = now
        return last is not None and (now - last) < WG_STRIKE_WINDOW_SECONDS
WG1_DB_MUTEX = threading.RLock()
WG1_DB_LAST_ERR_LOG = 0.0
WG1_DB_ERR_LOG_EVERY = 10.0

WG1_DB_CACHE = {}
WG1_DB_LAST_MTIME = 0

WG_INSTANCE_NAME_RE = re.compile(r'^wg([2-9]|[1-9][0-9]+)$')
WG_INSTANCE_DB_MUTEX = threading.RLock()


def _is_valid_wg_instance_name(name):
    return bool(name) and bool(WG_INSTANCE_NAME_RE.match(str(name)))


L2TP_SESSION_CACHE = {}
L2TP_CACHE_LOCK = threading.Lock()
DETAILED_LOCK = threading.Lock()

SINGBOX_CONFIG_PATH = "/etc/eylan-singbox/config.json"
SINGBOX_LOG_PATH = "/var/log/eylan-singbox/access.log"
SINGBOX_SERVICE_NAME = "eylan-singbox"
SINGBOX_CLASH_API = "http://127.0.0.1:9190"
SINGBOX_LOCAL_LOCK = threading.RLock()
SINGBOX_GUARD_TABLE = "eylan_singbox_guard"
SINGBOX_GUARD_RULE_COMMENT = "eylan-singbox-guard-rule"

SINGBOX_KILL_STRIKES = {}
SINGBOX_KILL_STRIKES_LOCK = threading.Lock()
SINGBOX_STRIKE_WINDOW_SECONDS = 60


def _singbox_should_block_after_kill(username, source_ip):
    key = username
    now = time.time()
    with SINGBOX_KILL_STRIKES_LOCK:
        last = SINGBOX_KILL_STRIKES.get(key)
        SINGBOX_KILL_STRIKES[key] = now
        return last is not None and (now - last) < SINGBOX_STRIKE_WINDOW_SECONDS


def _singbox_guard_ensure_nft_setup():
    try:
        subprocess.run(["nft", "add", "table", "inet", SINGBOX_GUARD_TABLE], check=False, capture_output=True)
        subprocess.run(
            ["nft", "add", "set", "inet", SINGBOX_GUARD_TABLE, "singbox_ports", "{ type inet_service; }"],
            check=False, capture_output=True
        )
        subprocess.run(
            ["nft", "add", "set", "inet", SINGBOX_GUARD_TABLE, "blocked_ips", "{ type ipv4_addr; flags timeout; }"],
            check=False, capture_output=True
        )
        subprocess.run(
            ["nft", "add", "chain", "inet", SINGBOX_GUARD_TABLE, "input",
             "{ type filter hook input priority -1; policy accept; }"],
            check=False, capture_output=True
        )
        existing = subprocess.run(
            ["nft", "list", "chain", "inet", SINGBOX_GUARD_TABLE, "input"],
            check=False, capture_output=True, text=True
        )
        if SINGBOX_GUARD_RULE_COMMENT not in (existing.stdout or ""):
            subprocess.run(
                ["nft", "add", "rule", "inet", SINGBOX_GUARD_TABLE, "input",
                 "ip", "saddr", "@blocked_ips", "tcp", "dport", "@singbox_ports", "drop",
                 "comment", f'"{SINGBOX_GUARD_RULE_COMMENT}"'],
                check=False, capture_output=True
            )
    except Exception:
        pass


def _singbox_temp_block_ip(source_ip, duration_seconds=200):
    if not source_ip:
        return False
    try:
        _singbox_guard_ensure_nft_setup()

        config = _singbox_load_config()
        ports = sorted({
            ib.get("listen_port") for ib in (config.get("inbounds") or [])
            if isinstance(ib.get("listen_port"), int)
        })
        if not ports:
            return False

        subprocess.run(
            ["nft", "flush", "set", "inet", SINGBOX_GUARD_TABLE, "singbox_ports"],
            check=False, capture_output=True
        )
        port_list = ", ".join(str(p) for p in ports)
        subprocess.run(
            ["nft", "add", "element", "inet", SINGBOX_GUARD_TABLE, "singbox_ports", "{ " + port_list + " }"],
            check=False, capture_output=True
        )

        result = subprocess.run(
            ["nft", "add", "element", "inet", SINGBOX_GUARD_TABLE, "blocked_ips",
             "{ " + str(source_ip) + f" timeout {int(duration_seconds)}s }}"],
            check=False, capture_output=True, text=True
        )
        return result.returncode == 0
    except Exception:
        return False


SINGBOX_LOG_CONTEXT_CACHE = {}
SINGBOX_LOG_LOCK = threading.Lock()
SINGBOX_LOG_LAST_OFFSET = 0

SINGBOX_LOG_FROM_RE = re.compile(r'\[(\d+)\s+\d+ms\]\s+inbound/\w+\[([^\]]+)\]:\s+inbound(?:\s+packet)?\s+connection from\s+([0-9a-fA-F:.]+):(\d+)')
SINGBOX_LOG_USER_RE = re.compile(r'\[(\d+)\s+\d+ms\]\s+inbound/\w+\[([^\]]+)\]:\s+\[([^\]]*)\]\s+inbound(?:\s+packet)?\s+connection')


SINGBOX_CONN_START_RE = re.compile(r'^(.*T\d{2}:\d{2}:\d{2})\.(\d+)(.*)$')

SINGBOX_CONN_FIRST_SEEN = {}
SINGBOX_CONN_FIRST_SEEN_LOCK = threading.Lock()


def _singbox_parse_conn_start(start_val):
    if isinstance(start_val, (int, float)) and start_val > 0:
        return float(start_val)
    if isinstance(start_val, str) and start_val:
        try:
            cleaned = start_val.replace("Z", "+00:00")
            m = SINGBOX_CONN_START_RE.match(cleaned)
            if m:
                cleaned = f"{m.group(1)}.{m.group(2)[:6]}{m.group(3)}"
            return datetime.datetime.fromisoformat(cleaned).timestamp()
        except Exception:
            pass
    return time.time()


def _singbox_load_config():
    try:
        with open(SINGBOX_CONFIG_PATH, 'r') as f:
            return json.load(f)
    except Exception:
        return {"log": {"level": "info"}, "inbounds": [], "outbounds": [{"type": "direct", "tag": "direct"}]}


def _singbox_clash_api_get(path):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(f"{SINGBOX_CLASH_API}{path}")
        with opener.open(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _singbox_clash_api_delete(path):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(f"{SINGBOX_CLASH_API}{path}", method="DELETE")
        with opener.open(req, timeout=5):
            return True
    except Exception:
        return False


GLOBAL_DATA_STORE = {
    "data": None,
    "lock": threading.Lock()
}

Path(OVPN_FILES_DIR).mkdir(parents=True, exist_ok=True)
Path(CCD_DIR).mkdir(parents=True, exist_ok=True)

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class StatusHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server, run_setup=True):
        if run_setup:
            super().__init__(request, client_address, server)

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

    def _wg1_get_iface_public_key(self):
        try:
            proc = subprocess.run(["wg", "show", WG1_IFACE, "public-key"], capture_output=True, text=True, check=False, timeout=5)
            pk = (proc.stdout or "").strip()
            if pk:
                return pk
        except:
            pass

        for cf in (WG1_BASE, WG1_CONF):
            try:
                if not os.path.exists(cf):
                    continue
                with open(cf, "r") as f:
                    for line in f:
                        s = line.strip()
                        if s.lower().startswith("privatekey"):
                            parts = s.split("=", 1)
                            if len(parts) == 2:
                                priv = parts[1].strip()
                                if priv:
                                    p2 = subprocess.run(["wg", "pubkey"], input=(priv + "\n").encode("utf-8"),
                                                        capture_output=True, check=False, timeout=5)
                                    pk2 = (p2.stdout or b"").decode("utf-8", "ignore").strip()
                                    if pk2:
                                        return pk2
            except:
                pass
        return None

    def _wg1_get_listen_port(self):
        try:
            proc = subprocess.run(["wg", "show", WG1_IFACE, "listen-port"], capture_output=True, text=True, check=False, timeout=5)
            p = (proc.stdout or "").strip()
            if p.isdigit():
                return int(p)
        except:
            pass
        for cf in (WG1_CONF, WG1_BASE):
            try:
                if not os.path.exists(cf):
                    continue
                with open(cf, "r") as f:
                    for line in f:
                        s = line.strip()
                        if s.lower().startswith("listenport"):
                            parts = s.split("=", 1)
                            if len(parts) == 2 and parts[1].strip().isdigit():
                                return int(parts[1].strip())
            except:
                pass
        return None

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
                limit = 0
                while b"END" not in data and limit < 100:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    limit += 1
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
                    res = fut.result(timeout=5)
                    if res:
                        results[p] = res
                except:
                    continue
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
                    real_ip = parts[2].split(":")[0].strip() if parts[2] else ""
                    v_ip = (parts[3] or "").strip()
                    rx = int(parts[5] or 0)
                    tx = int(parts[6] or 0)

                    c_time = 0
                    found_time = False

                    if len(parts) > 8 and str(parts[8]).isdigit() and len(str(parts[8])) >= 10:
                        c_time = int(parts[8])
                        found_time = True
                    elif len(parts) > 7 and str(parts[7]).isdigit() and len(str(parts[7])) >= 10:
                        c_time = int(parts[7])
                        found_time = True

                    if not found_time:
                        for p in parts:
                            p = str(p or "").strip()
                            if p.isdigit() and len(p) >= 10 and (p.startswith("16") or p.startswith("17") or p.startswith("18") or p.startswith("19") or p.startswith("20")):
                                c_time = int(p)
                                break

                    cid = None
                    if len(parts) > 10 and str(parts[10]).isdigit():
                        cid = int(parts[10])
                    elif len(parts) > 9 and str(parts[9]).isdigit():
                        cid = int(parts[9])
                    elif len(parts) >= 2 and str(parts[-2]).isdigit():
                        cid = int(parts[-2])

                    sessions.append({
                        "username": uname,
                        "protocol": f"OpenVPN ({p_info.get('proto', 'UDP')})",
                        "ip": real_ip,
                        "real_ip": real_ip,
                        "v_ip": v_ip,
                        "bytes_received": rx,
                        "bytes_sent": tx,
                        "connected_at": c_time,
                        "session_id": cid,
                        "mgmt_port": mgmt_port,
                        "management_port": mgmt_port,
                        "source": "node"
                    })

                    with DETAILED_LOCK:
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
        global L2TP_SESSION_CACHE, L2TP_CACHE_LOCK

        sessions = []
        current_system_time = time.time()

        try:
            all_sys_ifaces = glob.glob("/sys/class/net/ppp*")
            all_iface_names = {os.path.basename(p) for p in all_sys_ifaces}
        except:
            all_sys_ifaces = []
            all_iface_names = set()

        lines = []
        if os.path.exists(L2TP_ACTIVE_FILE):
            try:
                with open(L2TP_ACTIVE_FILE, "r") as f:
                    lines = f.readlines()
            except:
                pass

        file_info_map = {}
        for line in lines:
            try:
                p = line.strip().split(":")
                if len(p) == 2:
                    u, i = p[0].strip(), p[1].strip()
                    if u and i and i in all_iface_names:
                        file_info_map[i] = u
            except:
                pass

        with L2TP_CACHE_LOCK:
            for cached_iface in list(L2TP_SESSION_CACHE.keys()):
                if cached_iface not in all_iface_names:
                    del L2TP_SESSION_CACHE[cached_iface]

            for iface in all_iface_names:
                username = None
                pid = 0
                conn_time = current_system_time

                cached = L2TP_SESSION_CACHE.get(iface)
                cache_valid = False

                if cached:
                    try:
                        if os.path.exists(f"/proc/{cached['pid']}"):
                            cache_valid = True
                    except:
                        pass

                if cache_valid:
                    username = cached['username']
                    pid = cached['pid']
                    conn_time = cached['conn_time']

                    if iface in file_info_map and file_info_map[iface] != username:
                        username = file_info_map[iface]
                        L2TP_SESSION_CACHE[iface]['username'] = username
                else:
                    if iface in file_info_map:
                        username = file_info_map[iface]

                    try:
                        pid_path = f"/var/run/{iface}.pid"
                        if os.path.exists(pid_path):
                            conn_time = os.path.getmtime(pid_path)
                            with open(pid_path, 'r') as f:
                                pid = int(f.read().strip() or 0)
                    except:
                        pass

                    if not username and pid > 0:
                        try:
                            with open(f"/proc/{pid}/cmdline", "rb") as f_cmd:
                                cmd_bytes = f_cmd.read()
                                args = cmd_bytes.replace(b'\x00', b' ').decode('utf-8', errors='ignore').split()
                                for i, arg in enumerate(args):
                                    if arg in ["name", "user"] and (i + 1 < len(args)):
                                        username = args[i + 1]
                                        break
                                    if arg.startswith("name=") or arg.startswith("user="):
                                        username = arg.split("=", 1)[1]
                                        break
                        except:
                            pass

                    if username and pid > 0:
                        L2TP_SESSION_CACHE[iface] = {
                            'username': username,
                            'pid': pid,
                            'conn_time': conn_time
                        }

                if username:
                    rx = 0
                    tx = 0
                    try:
                        with open(f"/sys/class/net/{iface}/statistics/rx_bytes") as f:
                            rx = int(f.read().strip() or 0)
                    except:
                        rx = 0

                    try:
                        with open(f"/sys/class/net/{iface}/statistics/tx_bytes") as f:
                            tx = int(f.read().strip() or 0)
                    except:
                        tx = 0

                    sessions.append({
                        "username": username,
                        "protocol": "L2TP",
                        "ip": "Remote",
                        "v_ip": "10.10.x.x",
                        "interface": iface,
                        "bytes_received": rx,
                        "bytes_sent": tx,
                        "connected_at": conn_time,
                        "session_id": pid,
                        "source": "node"
                    })

                    legacy_key = "L2TP/IPsec"
                    with DETAILED_LOCK:
                        if username not in detailed_users:
                            detailed_users[username] = {}
                        if legacy_key not in detailed_users[username]:
                            detailed_users[username][legacy_key] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}

                        detailed_users[username][legacy_key]["active"] += 1
                        detailed_users[username][legacy_key]["bytes_received"] += rx
                        detailed_users[username][legacy_key]["bytes_sent"] += tx

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
                "%Y-%m-dT%H:%M",
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
            res = subprocess.run([OCCTL_BIN, "-j", "show", "users"], capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                return sessions

            users = json.loads(res.stdout or "[]")

            for u in users:
                uname = u.get("Username")
                if not uname:
                    continue

                try:
                    rx = int(u.get("RX", 0) or 0)
                except:
                    rx = 0

                try:
                    tx = int(u.get("TX", 0) or 0)
                except:
                    tx = 0

                conn_str = u.get("Connected at")
                conn_time = self._parse_time_str_to_epoch(conn_str, current_system_time)

                sessions.append({
                    "username": uname,
                    "protocol": "Cisco",
                    "ip": u.get("Remote IP", "N/A"),
                    "v_ip": u.get("VPN IP", "N/A"),
                    "bytes_received": rx,
                    "bytes_sent": tx,
                    "connected_at": conn_time,
                    "session_id": u.get("ID"),
                    "source": "node"
                })

                legacy_key = "Cisco AnyConnect"
                with DETAILED_LOCK:
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

    def _wg1_load_peers_db(self):
        global WG1_DB_CACHE, WG1_DB_LAST_MTIME
        with WG1_DB_MUTEX:
            try:
                if not os.path.exists(WG1_PEERS_DB):
                    return {}

                current_mtime = os.stat(WG1_PEERS_DB).st_mtime

                if WG1_DB_CACHE and current_mtime == WG1_DB_LAST_MTIME:
                    return WG1_DB_CACHE.copy()

                with open(WG1_PEERS_DB, "r", encoding="utf-8") as f:
                    raw = f.read()

                if not raw.strip():
                    data = {}
                else:
                    data = json.loads(raw)

                data = data if isinstance(data, dict) else {}

                WG1_DB_CACHE = data
                WG1_DB_LAST_MTIME = current_mtime

                return data.copy() if isinstance(data, dict) else {}
            except Exception as e:
                global WG1_DB_LAST_ERR_LOG
                now = time.time()
                try:
                    if now - float(WG1_DB_LAST_ERR_LOG) >= float(WG1_DB_ERR_LOG_EVERY):
                        WG1_DB_LAST_ERR_LOG = now
                        try:
                            sz = os.path.getsize(WG1_PEERS_DB) if os.path.exists(WG1_PEERS_DB) else -1
                        except Exception:
                            sz = -1
                        print(f"[WG1] ERROR loading peers db: {e} (size={sz})", flush=True)
                except Exception:
                    pass
                return None

    def _wg1_save_peers_db(self, data):
        if not isinstance(data, dict):
            return False

        with WG1_DB_MUTEX:
            tmp_path = None
            try:
                Path(os.path.dirname(WG1_PEERS_DB) or "/").mkdir(parents=True, exist_ok=True)
                d = os.path.dirname(WG1_PEERS_DB) or "/"
                fd, tmp_path = tempfile.mkstemp(prefix="wg1_peers_", suffix=".tmp", dir=d)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except Exception:
                        pass
                os.replace(tmp_path, WG1_PEERS_DB)
                tmp_path = None
                try:
                    os.chmod(WG1_PEERS_DB, 0o600)
                except:
                    pass
                return True
            except Exception as e:
                global WG1_DB_LAST_ERR_LOG
                now = time.time()
                try:
                    if now - float(WG1_DB_LAST_ERR_LOG) >= float(WG1_DB_ERR_LOG_EVERY):
                        WG1_DB_LAST_ERR_LOG = now
                        print(f"[WG1] ERROR saving peers db: {e}", flush=True)
                except Exception:
                    pass
                return False
            finally:
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass

    def _wg1_write_conf(self, content):
        try:
            if os.path.exists(WG1_CONF):
                with open(WG1_CONF, "r") as f:
                    if f.read().strip() == (content or "").strip():
                        return "NO_CHANGE"
            Path(os.path.dirname(WG1_CONF) or "/").mkdir(parents=True, exist_ok=True)
            tmp = WG1_CONF + ".tmp"
            with open(tmp, "w") as f:
                f.write(content or "")
            os.replace(tmp, WG1_CONF)
            try:
                os.chmod(WG1_CONF, 0o600)
            except:
                pass
            return True
        except:
            return False

    def _wg1_restart(self):
        try:
            cp = subprocess.run(["ip", "link", "show", WG1_IFACE], capture_output=True, text=True, timeout=5)
            if cp.returncode == 0:
                subprocess.run(f"wg syncconf {WG1_IFACE} <(wg-quick strip {WG1_IFACE})", 
                               shell=True, executable="/bin/bash", check=False, timeout=10)
                return True
            subprocess.run(["systemctl", "restart", f"wg-quick@{WG1_IFACE}"], check=False, timeout=10)
            return True
        except:
            return False

    def _wg1_update_listen_port_files(self, port):
        try:
            p = int(port)
        except:
            return False

        def _update_file(path):
            try:
                if not os.path.exists(path):
                    return True

                with open(path, "r") as f:
                    lines = f.readlines()
                replaced = False
                out = []
                for line in lines:
                    if (not replaced) and re.match(r"^\s*ListenPort\s*=", line):
                        out.append(f"ListenPort = {p}\n")
                        replaced = True
                    else:
                        out.append(line)
                if not replaced:
                    inserted = False
                    out2 = []
                    for line in out:
                        out2.append(line)
                        if (not inserted) and re.match(r"^\s*Address\s*=", line):
                            out2.append(f"ListenPort = {p}\n")
                            inserted = True
                    out = out2
                tmp = path + ".tmp"
                with open(tmp, "w") as f:
                    f.writelines(out)
                try:
                    os.chmod(tmp, 0o600)
                except:
                    pass
                os.replace(tmp, path)
                return True
            except:
                return False

        ok1 = _update_file(WG1_BASE)
        ok2 = _update_file(WG1_CONF)
        return ok1 and ok2

    def _wg1_read_base_conf(self):
        try:
            if os.path.exists(WG1_BASE):
                with open(WG1_BASE, "r", encoding="utf-8", errors="ignore") as f:
                    txt = f.read().strip()
                if txt:
                    return txt + "\n\n"
        except:
            pass

        try:
            if os.path.exists(WG1_CONF):
                with open(WG1_CONF, "r", encoding="utf-8", errors="ignore") as f:
                    txt = f.read()
                idx = txt.find("\n[Peer]")
                if idx < 0:
                    idx = txt.find("[Peer]")
                base = txt[:idx].strip() if idx >= 0 else txt.strip()
                if base:
                    try:
                        Path(os.path.dirname(WG1_BASE) or "/").mkdir(parents=True, exist_ok=True)
                        tmp = WG1_BASE + ".tmp"
                        with open(tmp, "w", encoding="utf-8") as f:
                            f.write(base + "\n")
                            f.flush()
                            try:
                                os.fsync(f.fileno())
                            except:
                                pass
                        try:
                            os.chmod(tmp, 0o600)
                        except:
                            pass
                        os.replace(tmp, WG1_BASE)
                    except:
                        pass
                    return base + "\n\n"
        except:
            pass

        return "[Interface]\n"

    def _wg1_rebuild_conf_from_peers_db(self):
        try:
            peers = self._wg1_load_peers_db()
            if not isinstance(peers, dict):
                return False

            base = self._wg1_read_base_conf().rstrip() + "\n\n"
            out = [base]

            for uname, pdata in peers.items():
                try:
                    if not isinstance(pdata, dict):
                        continue
                    if bool(pdata.get("disabled")):
                        continue
                    pk = str(pdata.get("public_key") or "").strip()
                    allowed = (
                        pdata.get("allowed_ips")
                        or pdata.get("allowed_ip")
                        or pdata.get("allowed_ips_v4")
                        or pdata.get("ip")
                        or pdata.get("wg1_ip")
                    )
                    allowed_norm = self._wg1_normalize_allowed_ips(allowed)
                    if not pk or not allowed_norm:
                        continue
                    out.append("[Peer]\n")
                    out.append(f"PublicKey = {pk}\n")
                    out.append(f"AllowedIPs = {allowed_norm}\n")
                    psk = str(pdata.get("preshared_key") or "").strip()
                    if psk:
                        out.append(f"PresharedKey = {psk}\n")
                    out.append("\n")
                except:
                    continue

            Path(os.path.dirname(WG1_CONF) or "/").mkdir(parents=True, exist_ok=True)
            tmp = WG1_CONF + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.writelines(out)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except:
                    pass
            try:
                os.chmod(tmp, 0o600)
            except:
                pass
            os.replace(tmp, WG1_CONF)
            return True
        except Exception as e:
            try:
                print(f"[WG1] rebuild config failed: {e}", flush=True)
            except:
                pass
            return False

    def _wg1_ensure_runtime(self):
        try:
            if not shutil.which("wg") or not shutil.which("wg-quick"):
                return False, "wireguard tools missing"

            try:
                Path(os.path.dirname(WG1_CONF) or "/").mkdir(parents=True, exist_ok=True)
            except:
                pass

            try:
                if not os.path.exists(WG1_CONF):
                    self._wg1_rebuild_conf_from_peers_db()
            except:
                pass

            for _ in range(2):
                try:
                    cp = subprocess.run(
                        ["wg", "show", WG1_IFACE],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if cp.returncode == 0:
                        return True, "ok"
                except:
                    pass

                try:
                    subprocess.run(
                        ["systemctl", "start", f"wg-quick@{WG1_IFACE}"],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=20
                    )
                except:
                    pass

            try:
                cp2 = subprocess.run(
                    ["wg", "show", WG1_IFACE],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if cp2.returncode == 0:
                    return True, "ok"
                return False, (cp2.stderr or "wg interface not active").strip()
            except Exception as e:
                return False, str(e)
        except Exception as e:
            return False, str(e)

    def _wg1_normalize_allowed_ips(self, allowed_ips):
        if allowed_ips is None:
            return None

        try:
            s = str(allowed_ips).strip()
            if not s:
                return None

            parts = [p.strip() for p in re.split(r"[,\s]+", s) if p.strip()]
            norm_parts = []

            for p in parts:
                if "/" not in p:
                    if ":" in p:
                        norm_parts.append(p + "/128")
                    else:
                        norm_parts.append(p + "/32")
                else:
                    norm_parts.append(p)

            return ",".join(norm_parts) if norm_parts else None
        except:
            return str(allowed_ips).strip() if allowed_ips else None

    def _wg1_set_peer(self, pub_key, allowed_ips=None, preshared_key=None, reset_first=False):
        if not pub_key:
            return False

        pub = str(pub_key).strip()
        allowed_norm = self._wg1_normalize_allowed_ips(allowed_ips)

        ok_runtime, runtime_msg = self._wg1_ensure_runtime()
        if not ok_runtime:
            try:
                print(f"[WG1] runtime unavailable before set peer: {runtime_msg}", flush=True)
            except:
                pass
            return False

        tmp_psk = None

        try:
            WG1_PEER_ACTIVITY.pop(pub, None)
        except:
            pass

        try:
            if reset_first:
                subprocess.run(
                    ["wg", "set", WG1_IFACE, "peer", pub, "remove"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10
                )

            cmd = ["wg", "set", WG1_IFACE, "peer", pub]
            if allowed_norm:
                cmd += ["allowed-ips", allowed_norm]

            if preshared_key:
                tmp_psk = tempfile.NamedTemporaryFile(mode="w", delete=False)
                tmp_psk.write(str(preshared_key).strip() + "\n")
                tmp_psk.flush()
                tmp_psk.close()
                try:
                    os.chmod(tmp_psk.name, 0o600)
                except:
                    pass
                cmd += ["preshared-key", tmp_psk.name]

            cp = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=10
            )

            if cp.returncode != 0:
                try:
                    print(f"[WG1] set peer failed: {cp.stderr.strip()}", flush=True)
                except:
                    pass
                return False

            return True
        except Exception as e:
            try:
                print(f"[WG1] set peer exception: {e}", flush=True)
            except:
                pass
            return False
        finally:
            if tmp_psk is not None:
                try:
                    os.unlink(tmp_psk.name)
                except:
                    pass

    def _wg1_remove_peer(self, pub_key):
        if not pub_key:
            return False
        pub = str(pub_key).strip()
        try:
            WG1_PEER_ACTIVITY.pop(pub, None)
        except:
            pass
        try:
            ok_runtime, _runtime_msg = self._wg1_ensure_runtime()
            if not ok_runtime:
                return True
            cp = subprocess.run(
                ["wg", "set", WG1_IFACE, "peer", pub, "remove"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10
            )
            return cp.returncode == 0
        except:
            return False

    def _wg1_kick_peer(self, pub_key):
        if not pub_key:
            return False

        pub = str(pub_key).strip()
        db = self._wg1_load_peers_db()
        info = None
        for _u, d in (db or {}).items():
            try:
                if isinstance(d, dict) and str(d.get("public_key") or "").strip() == pub:
                    info = d
                    break
            except:
                pass

        try:
            WG1_PEER_ACTIVITY.pop(pub, None)
        except:
            pass

        self._wg1_remove_peer(pub)

        if isinstance(info, dict):
            try:
                if bool(info.get("disabled")):
                    return True
            except:
                pass

            allowed = (
                info.get("allowed_ips")
                or info.get("allowed_ip")
                or info.get("allowed_ips_v4")
                or info.get("ip")
                or info.get("wg1_ip")
            )
            psk = info.get("preshared_key")
            return self._wg1_set_peer(pub, allowed_ips=allowed, preshared_key=psk, reset_first=False)

        return True

    def _wg1_temp_kick_peer(self, pub_key, duration_seconds=200):
        if not pub_key:
            return False
        pub = str(pub_key).strip()
        key = ("wg1", pub)
        with WG_KICK_GENERATION_LOCK:
            gen = WG_KICK_GENERATION.get(key, 0) + 1
            WG_KICK_GENERATION[key] = gen

        with WG_TEMP_BLOCKED_UNTIL_LOCK:
            WG_TEMP_BLOCKED_UNTIL[key] = time.time() + duration_seconds

        db = self._wg1_load_peers_db()
        info = None
        for _u, d in (db or {}).items():
            try:
                if isinstance(d, dict) and str(d.get("public_key") or "").strip() == pub:
                    info = d
                    break
            except:
                pass

        try:
            WG1_PEER_ACTIVITY.pop(pub, None)
        except:
            pass

        self._wg1_remove_peer(pub)

        if isinstance(info, dict) and not bool(info.get("disabled")):
            allowed = (
                info.get("allowed_ips")
                or info.get("allowed_ip")
                or info.get("allowed_ips_v4")
                or info.get("ip")
                or info.get("wg1_ip")
            )
            psk = info.get("preshared_key")

            def _restore():
                with WG_KICK_GENERATION_LOCK:
                    if WG_KICK_GENERATION.get(key) != gen:
                        return
                with WG_TEMP_BLOCKED_UNTIL_LOCK:
                    WG_TEMP_BLOCKED_UNTIL.pop(key, None)
                self._wg1_set_peer(pub, allowed_ips=allowed, preshared_key=psk, reset_first=False)

            threading.Timer(duration_seconds, _restore).start()

        return True

    def _extract_wg_sessions(self, detailed_users):
        sessions = []
        peers_map = self._wg1_load_peers_db()

        pub_to_user = {}
        for uname, udata in (peers_map or {}).items():
            try:
                if isinstance(udata, dict):
                    pub = udata.get("public_key")
                    if pub:
                        if bool(udata.get("disabled")):
                            continue
                        pub_to_user[pub] = (uname, udata)
            except:
                pass

        try:
            res = subprocess.run(["wg", "show", WG1_IFACE, "dump"], capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                return sessions

            dump_lines = (res.stdout or "").strip().splitlines()
            now_ts = int(time.time())

            for line in dump_lines:
                parts = line.split("\t")
                if len(parts) < 8:
                    continue

                pub_key = parts[0].strip()
                endpoint = (parts[2] or "").strip()
                allowed_ips = (parts[3] or "").strip()

                try:
                    latest_handshake = int(parts[4] or 0)
                except:
                    latest_handshake = 0

                try:
                    rx = int(parts[5] or 0)
                except:
                    rx = 0

                try:
                    tx = int(parts[6] or 0)
                except:
                    tx = 0

                u = pub_to_user.get(pub_key)
                if not u:
                    continue

                username, _uinfo = u
                endpoint_present = bool(endpoint)
                fresh_handshake = bool(latest_handshake > 0 and (now_ts - latest_handshake) <= 45)

                prev = WG1_PEER_ACTIVITY.get(pub_key)
                if prev is None:
                    WG1_PEER_ACTIVITY[pub_key] = {
                        "rx": rx,
                        "tx": tx,
                        "last_activity": float(now_ts) if (fresh_handshake and endpoint_present) else 0.0,
                        "last_handshake": latest_handshake,
                        "endpoint": endpoint,
                    }
                    prev = WG1_PEER_ACTIVITY[pub_key]
                else:
                    try:
                        prev_rx = int(prev.get("rx", 0) or 0)
                    except:
                        prev_rx = 0

                    try:
                        prev_tx = int(prev.get("tx", 0) or 0)
                    except:
                        prev_tx = 0

                    try:
                        prev_hs = int(prev.get("last_handshake", 0) or 0)
                    except:
                        prev_hs = 0

                    prev_ep = str(prev.get("endpoint") or "")

                    counter_reset = (rx < prev_rx) or (tx < prev_tx)
                    traffic_moved = rx > prev_rx
                    handshake_moved = latest_handshake > prev_hs
                    endpoint_changed = endpoint_present and endpoint != prev_ep

                    if counter_reset:
                        prev["rx"] = rx
                        prev["tx"] = tx
                        prev["last_handshake"] = latest_handshake
                        prev["endpoint"] = endpoint
                        prev["last_activity"] = float(now_ts) if (fresh_handshake and endpoint_present) else 0.0
                    else:
                        if traffic_moved or handshake_moved or endpoint_changed:
                            prev["last_activity"] = float(now_ts)

                        prev["rx"] = rx
                        prev["tx"] = tx
                        prev["last_handshake"] = latest_handshake
                        prev["endpoint"] = endpoint

                last_activity = float(prev.get("last_activity", 0) or 0)
                recent_activity = bool(last_activity > 0 and (float(now_ts) - last_activity) <= 45)
                online = bool(recent_activity or (fresh_handshake and endpoint_present))

                was_online = bool(prev.get("online"))
                if online and not was_online:
                    prev["first_seen"] = float(now_ts)
                elif online and not prev.get("first_seen"):
                    prev["first_seen"] = float(now_ts)
                prev["online"] = online

                if not online:
                    continue

                first_seen = float(prev.get("first_seen") or now_ts)

                real_ip = ""
                if endpoint_present:
                    if endpoint.startswith("[") and "]" in endpoint:
                        real_ip = endpoint.split("]")[0].lstrip("[")
                    elif ":" in endpoint:
                        real_ip = endpoint.split(":")[0]
                    else:
                        real_ip = endpoint

                wg_entry = {
                    "username": username,
                    "protocol": "WireGuard",
                    "online": True,
                    "is_active": True,
                    "ip": real_ip,
                    "v_ip": allowed_ips,
                    "bytes_received": rx,
                    "bytes_sent": tx,
                    "connected_at": int(first_seen),
                    "session_id": pub_key,
                    "public_key": pub_key,
                    "peer_key": pub_key,
                    "source": "node",
                }

                sessions.append(wg_entry)

                with DETAILED_LOCK:
                    if username not in detailed_users:
                        detailed_users[username] = {}
                    if "WireGuard" not in detailed_users[username]:
                        detailed_users[username]["WireGuard"] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
                    detailed_users[username]["WireGuard"]["active"] += 1
                    detailed_users[username]["WireGuard"]["bytes_received"] += rx
                    detailed_users[username]["WireGuard"]["bytes_sent"] += tx

        except:
            pass

        return sessions


    def _wg_instances(self):
        instances = []
        try:
            confs = glob.glob("/etc/wireguard/wg*.conf")
        except Exception:
            confs = []
        for conf in confs:
            name = os.path.basename(conf).replace('.conf', '')
            if name in ('wg0', 'wg1') or name.endswith('_base'):
                continue
            port = None
            subnet = None
            try:
                with open(conf, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                port_match = re.search(r'ListenPort\s*=\s*(\d+)', content)
                port = int(port_match.group(1)) if port_match else None
                subnet_match = re.search(r'Address\s*=\s*([\d.]+/\d+)', content)
                subnet = subnet_match.group(1) if subnet_match else None
            except Exception:
                pass
            unit_state = self._systemctl_state(f"wg-quick@{name}.service")
            if unit_state["state"] == "not-found":
                unit_state = self._systemctl_state(f"wg-quick@{name}")
            instances.append({
                "name": name,
                "conf": conf,
                "port": port,
                "subnet": subnet,
                "service": unit_state
            })
        return instances

    def _wg_instance_load_peers_db(self, instance_name):
        peers_db_path = f"/etc/wireguard/{instance_name}_peers.json"
        with WG_INSTANCE_DB_MUTEX:
            try:
                if not os.path.exists(peers_db_path):
                    return {}
                with open(peers_db_path, "r", encoding="utf-8") as f:
                    raw = f.read()
                if not raw.strip():
                    return {}
                data = json.loads(raw)
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}

    def _wg_instance_save_peers_db(self, instance_name, data):
        if not isinstance(data, dict):
            return False
        peers_db_path = f"/etc/wireguard/{instance_name}_peers.json"
        with WG_INSTANCE_DB_MUTEX:
            tmp_path = None
            try:
                Path(os.path.dirname(peers_db_path) or "/").mkdir(parents=True, exist_ok=True)
                fd, tmp_path = tempfile.mkstemp(prefix=f"{instance_name}_peers_", suffix=".tmp", dir=os.path.dirname(peers_db_path))
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False)
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except Exception:
                        pass
                os.replace(tmp_path, peers_db_path)
                tmp_path = None
                try:
                    os.chmod(peers_db_path, 0o600)
                except Exception:
                    pass
                return True
            except Exception as e:
                print(f"[WG-instance] ERROR saving peers db for {instance_name}: {e}", flush=True)
                return False
            finally:
                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass

    def _wg_instance_read_base_conf(self, instance_name):
        base_path = f"/etc/wireguard/{instance_name}_base.conf"
        try:
            if os.path.exists(base_path):
                with open(base_path, "r", encoding="utf-8", errors="ignore") as f:
                    txt = f.read().strip()
                if txt:
                    return txt + "\n\n"
        except Exception:
            pass
        return "[Interface]\n"

    def _wg_instance_normalize_allowed_ips(self, allowed_ips):
        if not allowed_ips:
            return None
        try:
            s = str(allowed_ips).strip()
            if not s:
                return None
            parts = [p.strip() for p in re.split(r"[,\s]+", s) if p.strip()]
            norm_parts = []
            for p in parts:
                if "/" not in p:
                    norm_parts.append(p + ("/128" if ":" in p else "/32"))
                else:
                    norm_parts.append(p)
            return ",".join(norm_parts) if norm_parts else None
        except Exception:
            return str(allowed_ips).strip() or None

    def _wg_instance_rebuild_conf_from_peers_db(self, instance_name):
        try:
            peers = self._wg_instance_load_peers_db(instance_name)
            if not isinstance(peers, dict):
                return False
            base = self._wg_instance_read_base_conf(instance_name).rstrip() + "\n\n"
            out = [base]
            for uname, pdata in peers.items():
                if not isinstance(pdata, dict):
                    continue
                if bool(pdata.get("disabled")):
                    continue
                pk = str(pdata.get("public_key") or "").strip()
                allowed = pdata.get("allowed_ip") or pdata.get("allowed_ips")
                allowed_norm = self._wg_instance_normalize_allowed_ips(allowed)
                if not pk or not allowed_norm:
                    continue
                out.append("[Peer]\n")
                out.append(f"PublicKey = {pk}\n")
                out.append(f"AllowedIPs = {allowed_norm}\n\n")

            conf_path = f"/etc/wireguard/{instance_name}.conf"
            Path(os.path.dirname(conf_path) or "/").mkdir(parents=True, exist_ok=True)
            tmp = conf_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.writelines(out)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
            try:
                os.chmod(tmp, 0o600)
            except Exception:
                pass
            os.replace(tmp, conf_path)
            return True
        except Exception as e:
            print(f"[WG-instance] rebuild config failed for {instance_name}: {e}", flush=True)
            return False

    def _wg_instance_sync_kernel(self, instance_name):
        try:
            cp = subprocess.run(["ip", "link", "show", instance_name], capture_output=True, text=True, timeout=5)
            if cp.returncode == 0:
                subprocess.run(
                    f"wg syncconf {instance_name} <(wg-quick strip {instance_name})",
                    shell=True, executable="/bin/bash", check=False, timeout=10
                )
                return True
            subprocess.run(["systemctl", "start", f"wg-quick@{instance_name}"], check=False, timeout=15)
            return True
        except Exception:
            return False

    def _wg_instance_ensure_runtime(self, instance_name):
        try:
            if not shutil.which("wg") or not shutil.which("wg-quick"):
                return False, "wireguard tools missing"

            conf_path = f"/etc/wireguard/{instance_name}.conf"
            try:
                Path(os.path.dirname(conf_path) or "/").mkdir(parents=True, exist_ok=True)
                if not os.path.exists(conf_path):
                    self._wg_instance_rebuild_conf_from_peers_db(instance_name)
            except Exception:
                pass

            for _ in range(2):
                try:
                    cp = subprocess.run(["wg", "show", instance_name], capture_output=True, text=True, timeout=5)
                    if cp.returncode == 0:
                        return True, "ok"
                except Exception:
                    pass
                try:
                    subprocess.run(
                        ["systemctl", "start", f"wg-quick@{instance_name}"],
                        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20
                    )
                except Exception:
                    pass

            try:
                cp2 = subprocess.run(["wg", "show", instance_name], capture_output=True, text=True, timeout=5)
                if cp2.returncode == 0:
                    return True, "ok"
                return False, (cp2.stderr or "wg interface not active").strip()
            except Exception as e:
                return False, str(e)
        except Exception as e:
            return False, str(e)

    def _wg_instance_remove_peer(self, instance_name, pub_key):
        if not pub_key:
            return False
        pub_key = str(pub_key).strip()
        try:
            WG_INSTANCE_PEER_ACTIVITY.pop(f"{instance_name}:{pub_key}", None)
        except Exception:
            pass
        try:
            self._wg_instance_ensure_runtime(instance_name)
            cp = subprocess.run(
                ["wg", "set", instance_name, "peer", str(pub_key).strip(), "remove"],
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10
            )
            return cp.returncode == 0
        except Exception:
            return False

    def _wg_instance_kick_peer(self, instance_name, pub_key):
        if not pub_key:
            return False
        pub = str(pub_key).strip()
        db = self._wg_instance_load_peers_db(instance_name)
        info = None
        for _u, d in (db or {}).items():
            try:
                if isinstance(d, dict) and str(d.get("public_key") or "").strip() == pub:
                    info = d
                    break
            except Exception:
                pass

        try:
            WG_INSTANCE_PEER_ACTIVITY.pop(f"{instance_name}:{pub}", None)
        except Exception:
            pass

        self._wg_instance_remove_peer(instance_name, pub)

        if isinstance(info, dict):
            try:
                if bool(info.get("disabled")):
                    return True
            except Exception:
                pass
            allowed = info.get("allowed_ip") or info.get("allowed_ips")
            allowed_norm = self._wg_instance_normalize_allowed_ips(allowed)
            if allowed_norm:
                try:
                    cp = subprocess.run(
                        ["wg", "set", instance_name, "peer", pub, "allowed-ips", allowed_norm],
                        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10
                    )
                    if cp.returncode != 0:
                        return False
                except Exception:
                    return False
            return True
        return True

    def _wg_instance_temp_kick_peer(self, instance_name, pub_key, duration_seconds=200):
        if not pub_key:
            return False
        pub = str(pub_key).strip()
        key = (instance_name, pub)
        with WG_KICK_GENERATION_LOCK:
            gen = WG_KICK_GENERATION.get(key, 0) + 1
            WG_KICK_GENERATION[key] = gen

        with WG_TEMP_BLOCKED_UNTIL_LOCK:
            WG_TEMP_BLOCKED_UNTIL[key] = time.time() + duration_seconds

        db = self._wg_instance_load_peers_db(instance_name)
        info = None
        for _u, d in (db or {}).items():
            try:
                if isinstance(d, dict) and str(d.get("public_key") or "").strip() == pub:
                    info = d
                    break
            except Exception:
                pass

        try:
            WG_INSTANCE_PEER_ACTIVITY.pop(f"{instance_name}:{pub}", None)
        except Exception:
            pass

        self._wg_instance_remove_peer(instance_name, pub)

        if isinstance(info, dict) and not bool(info.get("disabled")):
            allowed = info.get("allowed_ip") or info.get("allowed_ips")
            allowed_norm = self._wg_instance_normalize_allowed_ips(allowed)

            def _restore():
                with WG_KICK_GENERATION_LOCK:
                    if WG_KICK_GENERATION.get(key) != gen:
                        return
                with WG_TEMP_BLOCKED_UNTIL_LOCK:
                    WG_TEMP_BLOCKED_UNTIL.pop(key, None)
                if allowed_norm:
                    subprocess.run(
                        ["wg", "set", instance_name, "peer", pub, "allowed-ips", allowed_norm],
                        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10
                    )

            threading.Timer(duration_seconds, _restore).start()

        return True

    def _update_listen_port_in_file(self, path, port):
        try:
            if not os.path.exists(path):
                return True
            with open(path, "r") as f:
                lines = f.readlines()
            replaced = False
            out = []
            for line in lines:
                if (not replaced) and re.match(r"^\s*ListenPort\s*=", line):
                    out.append(f"ListenPort = {int(port)}\n")
                    replaced = True
                else:
                    out.append(line)
            if not replaced:
                inserted = False
                out2 = []
                for line in out:
                    out2.append(line)
                    if (not inserted) and re.match(r"^\s*Address\s*=", line):
                        out2.append(f"ListenPort = {int(port)}\n")
                        inserted = True
                out = out2
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                f.writelines(out)
            try:
                os.chmod(tmp, 0o600)
            except Exception:
                pass
            os.replace(tmp, path)
            return True
        except Exception:
            return False

    def _wg_instance_detect_public_iface(self):
        try:
            cp = subprocess.run(
                "ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i==\"dev\") {print $(i+1); exit}}'",
                shell=True, executable="/bin/bash", capture_output=True, text=True, timeout=5
            )
            iface = (cp.stdout or "").strip()
            if iface:
                return iface
        except Exception:
            pass
        return "eth0"

    def _wg_instance_open_udp_port(self, port):
        p = str(int(port))
        try:
            if shutil.which("ufw"):
                subprocess.run(["ufw", "allow", f"{p}/udp"], check=False, capture_output=True, timeout=10)
        except Exception:
            pass
        try:
            check = subprocess.run(["iptables", "-C", "INPUT", "-p", "udp", "--dport", p, "-j", "ACCEPT"], check=False, capture_output=True, timeout=5)
            if check.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "-p", "udp", "--dport", p, "-j", "ACCEPT"], check=False, capture_output=True, timeout=5)
        except Exception:
            pass

    def _wg_instance_provision(self, instance_name, port, subnet):
        try:
            port = int(port)
            wg_dir = "/etc/wireguard"
            Path(wg_dir).mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(wg_dir, 0o700)
            except Exception:
                pass

            try:
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False, timeout=5)
                sysctl_conf = "/etc/sysctl.conf"
                content = ""
                if os.path.exists(sysctl_conf):
                    with open(sysctl_conf, "r") as f:
                        content = f.read()
                if "net.ipv4.ip_forward" not in content:
                    with open(sysctl_conf, "a") as f:
                        f.write("\nnet.ipv4.ip_forward=1\n")
            except Exception:
                pass

            if not shutil.which("wg") or not shutil.which("wg-quick"):
                subprocess.run(["apt-get", "update", "-y"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
                subprocess.run(["apt-get", "install", "-y", "wireguard", "wireguard-tools", "iproute2", "iptables"],
                                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
                if not shutil.which("wg") or not shutil.which("wg-quick"):
                    return False, "Failed to install wireguard-tools"

            priv_path = f"{wg_dir}/{instance_name}_privatekey"
            pub_path = f"{wg_dir}/{instance_name}_publickey"
            if not (os.path.exists(priv_path) and os.path.exists(pub_path)):
                try:
                    os.umask(0o077)
                except Exception:
                    pass
                priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, timeout=10).stdout.strip()
                if not priv:
                    return False, "Failed to generate private key"
                pub = subprocess.run(["wg", "pubkey"], input=(priv + "\n"), capture_output=True, text=True, timeout=10).stdout.strip()
                if not pub:
                    return False, "Failed to derive public key"
                with open(priv_path, "w") as f:
                    f.write(priv + "\n")
                with open(pub_path, "w") as f:
                    f.write(pub + "\n")
                try:
                    os.chmod(priv_path, 0o600)
                    os.chmod(pub_path, 0o600)
                except Exception:
                    pass

            with open(priv_path, "r") as f:
                priv_key_content = f.read().strip()

            pub_iface = self._wg_instance_detect_public_iface()
            base_conf = (
                "[Interface]\n"
                f"Address = {subnet}\n"
                f"ListenPort = {port}\n"
                f"PrivateKey = {priv_key_content}\n"
                "SaveConfig = false\n\n"
                f"PostUp = iptables -t nat -I POSTROUTING 1 -s {subnet} -o {pub_iface} -j MASQUERADE\n"
                f"PostDown = iptables -t nat -D POSTROUTING -s {subnet} -o {pub_iface} -j MASQUERADE\n"
            )
            base_path = f"{wg_dir}/{instance_name}_base.conf"
            tmp = base_path + ".tmp"
            with open(tmp, "w") as f:
                f.write(base_conf)
            try:
                os.chmod(tmp, 0o600)
            except Exception:
                pass
            os.replace(tmp, base_path)

            peers_path = f"{wg_dir}/{instance_name}_peers.json"
            if not os.path.exists(peers_path):
                self._wg_instance_save_peers_db(instance_name, {})

            self._wg_instance_rebuild_conf_from_peers_db(instance_name)
            self._wg_instance_open_udp_port(port)

            try:
                if shutil.which("netfilter-persistent"):
                    subprocess.run(["netfilter-persistent", "save"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            except Exception:
                pass

            subprocess.run(["systemctl", "enable", f"wg-quick@{instance_name}"], check=False, timeout=15)
            subprocess.run(["systemctl", "restart", f"wg-quick@{instance_name}"], check=False, timeout=20)
            return True, "Instance provisioned"
        except Exception as e:
            return False, f"Provisioning failed: {e}"

    def _wg_instance_teardown(self, instance_name):
        try:
            subprocess.run(["systemctl", "stop", f"wg-quick@{instance_name}"], check=False, timeout=15)
            subprocess.run(["systemctl", "disable", f"wg-quick@{instance_name}"], check=False, timeout=15)
            for path in (
                f"/etc/wireguard/{instance_name}.conf",
                f"/etc/wireguard/{instance_name}_base.conf",
                f"/etc/wireguard/{instance_name}_privatekey",
                f"/etc/wireguard/{instance_name}_publickey",
                f"/etc/wireguard/{instance_name}_peers.json",
            ):
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except Exception:
                    pass
            subprocess.run(["systemctl", "daemon-reload"], check=False, timeout=10)
            return True, "Instance removed"
        except Exception as e:
            return False, f"Removal failed: {e}"

    def _extract_wg_sessions_for_instance(self, instance_name, detailed_users):
        sessions = []
        try:
            peers = self._wg_instance_load_peers_db(instance_name)
            pub_to_user = {}
            for uname, pdata in (peers or {}).items():
                if isinstance(pdata, dict):
                    pk = pdata.get("public_key")
                    if pk and not bool(pdata.get("disabled")):
                        pub_to_user[pk] = uname
            if not pub_to_user:
                return sessions

            res = subprocess.run(["wg", "show", instance_name, "dump"], capture_output=True, text=True, timeout=3)
            if res.returncode != 0:
                return sessions

            now_ts = int(time.time())

            for line in (res.stdout or "").strip().splitlines()[1:]:
                parts = line.split("\t")
                if len(parts) < 8:
                    continue
                pub_key = parts[0].strip()
                uname = pub_to_user.get(pub_key)
                if not uname:
                    continue
                endpoint = (parts[2] or "").strip()
                allowed_ips = parts[3].strip()
                try:
                    rx = int(parts[5] or 0)
                except Exception:
                    rx = 0
                try:
                    tx = int(parts[6] or 0)
                except Exception:
                    tx = 0
                try:
                    latest_handshake = int(parts[4] or 0)
                except Exception:
                    latest_handshake = 0

                if rx <= 0 and tx <= 0 and latest_handshake <= 0:
                    continue

                activity_key = f"{instance_name}:{pub_key}"
                endpoint_present = bool(endpoint)
                fresh_handshake = bool(latest_handshake > 0 and (now_ts - latest_handshake) <= 45)

                prev = WG_INSTANCE_PEER_ACTIVITY.get(activity_key)
                if prev is None:
                    WG_INSTANCE_PEER_ACTIVITY[activity_key] = {
                        "rx": rx,
                        "tx": tx,
                        "last_activity": float(now_ts) if (fresh_handshake and endpoint_present) else 0.0,
                        "last_handshake": latest_handshake,
                        "endpoint": endpoint,
                    }
                    prev = WG_INSTANCE_PEER_ACTIVITY[activity_key]
                else:
                    try:
                        prev_rx = int(prev.get("rx", 0) or 0)
                    except Exception:
                        prev_rx = 0
                    try:
                        prev_tx = int(prev.get("tx", 0) or 0)
                    except Exception:
                        prev_tx = 0
                    try:
                        prev_hs = int(prev.get("last_handshake", 0) or 0)
                    except Exception:
                        prev_hs = 0
                    prev_ep = str(prev.get("endpoint") or "")

                    counter_reset = (rx < prev_rx) or (tx < prev_tx)
                    traffic_moved = rx > prev_rx
                    handshake_moved = latest_handshake > prev_hs
                    endpoint_changed = endpoint_present and endpoint != prev_ep

                    if counter_reset:
                        prev["rx"] = rx
                        prev["tx"] = tx
                        prev["last_handshake"] = latest_handshake
                        prev["endpoint"] = endpoint
                        prev["last_activity"] = float(now_ts) if (fresh_handshake and endpoint_present) else 0.0
                    else:
                        if traffic_moved or handshake_moved or endpoint_changed:
                            prev["last_activity"] = float(now_ts)
                        prev["rx"] = rx
                        prev["tx"] = tx
                        prev["last_handshake"] = latest_handshake
                        prev["endpoint"] = endpoint

                last_activity = float(prev.get("last_activity", 0) or 0)
                recent_activity = bool(last_activity > 0 and (float(now_ts) - last_activity) <= 45)
                online = bool(recent_activity or (fresh_handshake and endpoint_present))

                was_online = bool(prev.get("online"))
                if online and not was_online:
                    prev["first_seen"] = float(now_ts)
                elif online and not prev.get("first_seen"):
                    prev["first_seen"] = float(now_ts)
                prev["online"] = online

                if not online:
                    continue

                first_seen = float(prev.get("first_seen") or now_ts)

                real_ip = ""
                if endpoint_present:
                    if endpoint.startswith("[") and "]" in endpoint:
                        real_ip = endpoint.split("]")[0].lstrip("[")
                    elif ":" in endpoint:
                        real_ip = endpoint.split(":")[0]
                    else:
                        real_ip = endpoint

                sessions.append({
                    "username": uname,
                    "protocol": f"WireGuard ({instance_name})",
                    "instance": instance_name,
                    "ip": real_ip,
                    "v_ip": allowed_ips,
                    "bytes_received": rx,
                    "bytes_sent": tx,
                    "connected_at": int(first_seen),
                    "session_id": pub_key,
                    "public_key": pub_key,
                    "peer_key": pub_key,
                    "source": "node",
                    "is_active": True
                })

                with DETAILED_LOCK:
                    if uname not in detailed_users:
                        detailed_users[uname] = {}
                    key = f"WireGuard ({instance_name})"
                    if key not in detailed_users[uname]:
                        detailed_users[uname][key] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
                    detailed_users[uname][key]["active"] += 1
                    detailed_users[uname][key]["bytes_received"] += rx
                    detailed_users[uname][key]["bytes_sent"] += tx
        except Exception:
            pass
        return sessions

    def _get_all_wg_statuses(self, detailed_users):
        all_sessions = []
        try:
            instances = self._wg_instances()
        except Exception:
            instances = []
        for inst in instances:
            if inst.get("service", {}).get("active"):
                try:
                    all_sessions.extend(self._extract_wg_sessions_for_instance(inst["name"], detailed_users))
                except Exception:
                    pass
        return all_sessions

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
            with open(CHAP_SECRETS, "r+") as f:
                fcntl.flock(f, fcntl.LOCK_EX)

                lines = f.readlines()

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
                        fcntl.flock(f, fcntl.LOCK_UN)
                        return False, "Missing password"
                    new_lines.append(f"\"{uname}\" l2tpd \"{passw}\" *\n")

                f.seek(0)
                f.truncate()
                f.writelines(new_lines)
                f.flush()
                os.fsync(f.fileno())

                fcntl.flock(f, fcntl.LOCK_UN)

            return True, f"L2TP {action} success"

        except Exception as e:
            return False, f"Write failed: {str(e)}"

    def _handle_cisco_single(self, cmd):
        uname = (cmd.get("username") or "").strip()
        passw = cmd.get("password")
        action = (cmd.get("action") or "add").strip().lower()

        if not uname:
            return False, "Missing username"

        ocpasswd_file = "/etc/ocserv/ocpasswd"

        try:
            os.makedirs(os.path.dirname(ocpasswd_file), exist_ok=True)
            if not os.path.exists(ocpasswd_file):
                with open(ocpasswd_file, "w") as f:
                    pass
        except Exception as e:
            return False, f"Init failed: {e}"

        try:
            hashed_pw = ""
            if action in ["add", "update"] and passw:
                try:
                    salt = os.urandom(8).hex()
                    chk = subprocess.check_output(
                        ["openssl", "passwd", "-6", "-salt", salt, passw],
                        stderr=subprocess.DEVNULL, timeout=5
                    ).decode().strip()
                    hashed_pw = f"{uname}:*:{chk}"
                except:
                    return False, "OpenSSL failed to generate hash"

            with open(ocpasswd_file, 'r+') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    lines = f.readlines()
                    new_lines = []
                    user_found = False
                    user_prefix = f"{uname}:"

                    for line in lines:
                        if not line.strip():
                            continue
                        if line.startswith(user_prefix):
                            user_found = True
                            if action == "delete":
                                continue
                            elif action in ["add", "update"]:
                                new_lines.append(hashed_pw + "\n")
                        else:
                            new_lines.append(line)

                    if action in ["add", "update"] and not user_found:
                        new_lines.append(hashed_pw + "\n")

                    f.seek(0)
                    f.truncate()
                    f.writelines(new_lines)
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

            subprocess.run(["occtl", "reload"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)

            subprocess.run(["pkill", "-HUP", "ocserv-main"], check=False, timeout=5)

            return True, f"Cisco {action} done via OpenSSL"

        except Exception as e:
            return False, f"Cisco Error: {str(e)}"


    def _singbox_load_config(self):
        try:
            with open(SINGBOX_CONFIG_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            return {"log": {"level": "info"}, "inbounds": [], "outbounds": [{"type": "direct", "tag": "direct"}]}

    def _singbox_save_config(self, config):
        tmp_path = f"{SINGBOX_CONFIG_PATH}.tmp{os.getpid()}"
        with open(tmp_path, "w") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, SINGBOX_CONFIG_PATH)

    def _singbox_reload(self):
        try:
            subprocess.run(["systemctl", "reload", SINGBOX_SERVICE_NAME], check=False, timeout=10)
            return True
        except Exception:
            return False

    def _handle_singbox_single(self, item):
        uname = str(item.get("username") or "").strip()
        inbound_tag = item.get("inbound_tag")
        credential = item.get("credential")
        action = item.get("action")
        flow = item.get("flow")

        if not uname or not inbound_tag:
            return False, "Missing username or inbound_tag"

        with SINGBOX_LOCAL_LOCK:
            config = self._singbox_load_config()
            inbounds = config.get("inbounds", [])

            target = None
            for inb in inbounds:
                if inb.get("tag") == inbound_tag:
                    target = inb
                    break
            if target is None:
                return False, f"Inbound {inbound_tag} not found on this node"

            users_list = target.setdefault("users", [])
            users_list[:] = [u for u in users_list if u.get("name") != uname]

            if action in ("add", "update"):
                if not credential:
                    return False, f"Empty credential for {uname}/{inbound_tag}"
                entry = {"name": uname}
                if target.get("type") in ("vless", "vmess"):
                    entry["uuid"] = credential
                    if target.get("type") == "vless" and flow:
                        entry["flow"] = flow
                else:
                    entry["password"] = credential
                users_list.append(entry)
            elif action != "delete":
                return False, f"Unknown action: {action}"

            config["inbounds"] = inbounds
            self._singbox_save_config(config)

        self._singbox_reload()
        return True, f"sing-box user {uname} {action} on {inbound_tag}"

    def _handle_singbox_inbound_provision(self, item):
        inbound_definition = item.get("inbound_definition")
        tag = inbound_definition.get("tag") if isinstance(inbound_definition, dict) else None
        if not tag:
            return False, "Missing inbound_definition/tag"

        with SINGBOX_LOCAL_LOCK:
            config = self._singbox_load_config()
            inbounds = config.get("inbounds", [])
            inbounds[:] = [i for i in inbounds if i.get("tag") != tag]
            inbounds.append(inbound_definition)
            config["inbounds"] = inbounds
            self._singbox_save_config(config)

        self._singbox_reload()
        return True, f"sing-box inbound {tag} provisioned"

    def _handle_singbox_inbound_remove(self, item):
        inbound_tag = item.get("inbound_tag")
        if not inbound_tag:
            return False, "Missing inbound_tag"

        with SINGBOX_LOCAL_LOCK:
            config = self._singbox_load_config()
            inbounds = config.get("inbounds", [])
            inbounds[:] = [i for i in inbounds if i.get("tag") != inbound_tag]
            config["inbounds"] = inbounds
            self._singbox_save_config(config)

        self._singbox_reload()
        return True, f"sing-box inbound {inbound_tag} removed"

    def _handle_singbox_sync_inbound_users(self, item):
        inbound_tag = item.get("inbound_tag")
        users = item.get("users")
        if not inbound_tag or not isinstance(users, list):
            return False, "Missing inbound_tag or users"

        with SINGBOX_LOCAL_LOCK:
            config = self._singbox_load_config()
            target = None
            for inb in config.get("inbounds", []):
                if inb.get("tag") == inbound_tag:
                    target = inb
                    break
            if target is None:
                return False, f"Inbound {inbound_tag} not found on this node"
            target["users"] = users
            self._singbox_save_config(config)

        self._singbox_reload()
        return True, f"sing-box inbound {inbound_tag} users synced ({len(users)})"

    def _singbox_extract_sessions(self, detailed_users):
        sessions = []

        if not os.path.exists(SINGBOX_LOG_PATH):
            return sessions

        try:
            with open(SINGBOX_LOG_PATH, 'r', errors='ignore') as f:
                lines = f.readlines()

            ctx_map = {}
            for line in lines:
                m_from = SINGBOX_LOG_FROM_RE.search(line)
                if m_from:
                    ctx_id, tag, ip, port = m_from.groups()
                    entry = ctx_map.setdefault(ctx_id, {})
                    entry["source_ip"] = ip
                    entry["source_port"] = port
                    entry["tag"] = tag
                    continue
                m_user = SINGBOX_LOG_USER_RE.search(line)
                if m_user:
                    ctx_id, tag, uname = m_user.groups()
                    entry = ctx_map.setdefault(ctx_id, {})
                    entry["username"] = uname
                    entry["tag"] = tag

            ip_to_user = {}
            ip_port_to_tag = {}
            for entry in ctx_map.values():
                ip = entry.get("source_ip")
                port = entry.get("source_port")
                uname = entry.get("username")
                if ip and port and uname:
                    ip_to_user[(ip, str(port))] = uname
                if ip and port and entry.get("tag"):
                    ip_port_to_tag[(ip, str(port))] = entry["tag"]

            if not ip_to_user:
                return sessions

            snapshot = _singbox_clash_api_get("/connections")
            if not snapshot or "connections" not in snapshot:
                return sessions

            aggregated = {}

            for conn in snapshot.get("connections") or []:
                meta = conn.get("metadata", {})
                source_ip = meta.get("sourceIP")
                source_port = meta.get("sourcePort")

                username = ip_to_user.get((source_ip, str(source_port)))
                if not username or not source_ip or not source_port:
                    continue

                download = int(conn.get("download") or 0)
                upload = int(conn.get("upload") or 0)
                connected_at = _singbox_parse_conn_start(conn.get("start"))
                conn_tag = ip_port_to_tag.get((source_ip, str(source_port)))

                key = (username, source_ip)
                is_new_session = key not in aggregated

                if is_new_session:
                    aggregated[key] = {
                        "username": username,
                        "protocol": "SINGBOX",
                        "ip": source_ip,
                        "v_ip": "",
                        "interface": "singbox",
                        "bytes_received": 0,
                        "bytes_sent": 0,
                        "connected_at": connected_at,
                        "session_id": source_ip,
                        "source": "node",
                        "inbound_tag": conn_tag,
                        "is_active": True
                    }
                else:
                    aggregated[key]["bytes_received"] += upload
                    aggregated[key]["bytes_sent"] += download
                    if connected_at < aggregated[key]["connected_at"]:
                        aggregated[key]["connected_at"] = connected_at

                legacy_key = f"sing-box:{conn_tag}" if conn_tag else "sing-box"
                with DETAILED_LOCK:
                    if username not in detailed_users:
                        detailed_users[username] = {}
                    if legacy_key not in detailed_users[username]:
                        detailed_users[username][legacy_key] = {"active": 0, "bytes_received": 0, "bytes_sent": 0}
                    if is_new_session:
                        detailed_users[username][legacy_key]["active"] += 1
                    detailed_users[username][legacy_key]["bytes_received"] += upload
                    detailed_users[username][legacy_key]["bytes_sent"] += download

            now_epoch = time.time()
            with SINGBOX_CONN_FIRST_SEEN_LOCK:
                for key, sess in aggregated.items():
                    cached = SINGBOX_CONN_FIRST_SEEN.get(key)
                    if cached is None:
                        SINGBOX_CONN_FIRST_SEEN[key] = {"first_seen": sess["connected_at"], "last_seen": now_epoch}
                    else:
                        sess["connected_at"] = cached["first_seen"]
                        cached["last_seen"] = now_epoch
                for stale_key, entry in list(SINGBOX_CONN_FIRST_SEEN.items()):
                    if now_epoch - entry.get("last_seen", 0) > 90:
                        SINGBOX_CONN_FIRST_SEEN.pop(stale_key, None)

            sessions = list(aggregated.values())

        except Exception:
            pass

        return sessions

    def _singbox_kill_user(self, username, target_ip=None):
        snapshot = _singbox_clash_api_get("/connections")
        if not snapshot:
            return 0

        if not os.path.exists(SINGBOX_LOG_PATH):
            return 0

        try:
            with open(SINGBOX_LOG_PATH, 'r', errors='ignore') as f:
                lines = f.readlines()

            ctx_map = {}
            for line in lines:
                m_from = SINGBOX_LOG_FROM_RE.search(line)
                if m_from:
                    ctx_id, tag, ip, port = m_from.groups()
                    entry = ctx_map.setdefault(ctx_id, {})
                    entry["source_ip"] = ip
                    entry["source_port"] = port
                    entry["tag"] = tag
                    continue
                m_user = SINGBOX_LOG_USER_RE.search(line)
                if m_user:
                    ctx_id, tag, uname = m_user.groups()
                    entry = ctx_map.setdefault(ctx_id, {})
                    entry["username"] = uname
                    entry["tag"] = tag

            ip_to_user = {}
            for entry in ctx_map.values():
                ip = entry.get("source_ip")
                port = entry.get("source_port")
                uname = entry.get("username")
                if ip and port and uname:
                    ip_to_user[(ip, str(port))] = uname

            killed = 0
            for conn in snapshot.get("connections") or []:
                meta = conn.get("metadata", {})
                source_ip = meta.get("sourceIP")
                source_port = meta.get("sourcePort")
                conn_username = ip_to_user.get((source_ip, str(source_port)))

                if conn_username == username:
                    if target_ip and source_ip != target_ip:
                        continue
                    if _singbox_clash_api_delete(f"/connections/{conn.get('id')}"):
                        killed += 1

            return killed
        except Exception:
            return 0

    def _update_iptables_port(self, port):
        p = str(int(port))
        subprocess.run(f"iptables -D INPUT -p tcp --dport {p} -j ACCEPT 2>/dev/null || true", shell=True, check=False, timeout=5)
        subprocess.run(f"iptables -D INPUT -p udp --dport {p} -j ACCEPT 2>/dev/null || true", shell=True, check=False, timeout=5)
        subprocess.run(f"iptables -I INPUT -p tcp --dport {p} -j ACCEPT", shell=True, check=False, timeout=5)
        subprocess.run(f"iptables -I INPUT -p udp --dport {p} -j ACCEPT", shell=True, check=False, timeout=5)

    def _restart_openvpn_units(self):
        list_units = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "openvpn-server@*", "--no-legend"],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in (list_units.stdout or "").splitlines():
            unit_name = (line.split() or [""])[0].strip()
            if unit_name:
                subprocess.run(["systemctl", "restart", unit_name], check=False, timeout=5)

    def _systemctl_state(self, unit_name):
        try:
            if not shutil.which("systemctl"):
                return {"installed": False, "active": False, "state": "not-found", "unit": unit_name}
            cp = subprocess.run(
                ["systemctl", "is-active", unit_name],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                text=True,
            )
            out = (cp.stdout or "").strip()
            err = (cp.stderr or "").strip()
            if cp.returncode == 0 and out == "active":
                return {"installed": True, "active": True, "state": "active", "unit": unit_name}
            if "could not be found" in err.lower() or out in ("unknown", ""):
                return {"installed": False, "active": False, "state": "not-found", "unit": unit_name}
            return {"installed": True, "active": False, "state": out or "inactive", "unit": unit_name}
        except Exception:
            return {"installed": False, "active": False, "state": "error", "unit": unit_name}

    def _openvpn_instances(self):
        instances = []
        try:
            confs = sorted(glob.glob(os.path.join(OPENVPN_CONF_DIR, "*.conf")))
        except Exception:
            confs = []
        for conf in confs:
            name = os.path.splitext(os.path.basename(conf))[0]
            m_port = None
            proto = "UDP"
            pub_port = None
            try:
                with open(conf, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or line.startswith(";"):
                            continue
                        if line.startswith("management "):
                            parts = line.split()
                            if len(parts) >= 3:
                                try:
                                    m_port = int(parts[2])
                                except Exception:
                                    m_port = None
                        elif line.startswith("proto "):
                            parts = line.split()
                            if len(parts) >= 2:
                                proto = parts[1].upper()
                        elif line.startswith("port "):
                            parts = line.split()
                            if len(parts) >= 2:
                                pub_port = parts[1]
            except Exception:
                pass

            unit_candidates = [
                f"openvpn-server@{name}.service",
                f"openvpn@{name}.service",
                f"openvpn-server@{name}",
                f"openvpn@{name}",
            ]

            unit_state = None
            for u in unit_candidates:
                st = self._systemctl_state(u)
                if st["state"] != "not-found":
                    unit_state = st
                    break
            if unit_state is None:
                unit_state = self._systemctl_state(unit_candidates[0])

            instances.append(
                {
                    "name": name,
                    "conf": conf,
                    "management_port": m_port,
                    "proto": proto,
                    "port": pub_port,
                    "service": unit_state,
                }
            )

        return instances

    def _is_safe_unit(self, unit):
        try:
            u = (unit or "").strip()
            if not u:
                return False
            return bool(re.match(r'^[A-Za-z0-9@._:-]+$', u))
        except Exception:
            return False

    def _handle_service_control(self, cmd):
        unit = (cmd.get("unit") or "").strip()
        action = (cmd.get("action") or "restart").strip().lower()
        if not self._is_safe_unit(unit):
            return False, "Invalid unit", "", ""
        if action not in ("start", "stop", "restart"):
            return False, "Invalid action", "", ""

        try:
            if shutil.which("systemctl") is None:
                return False, "systemctl not available", "", ""

            proc = subprocess.run(
                ["systemctl", action, unit],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=40,
                check=False,
            )
            out = (proc.stdout or b"").decode("utf-8", errors="ignore")
            err = (proc.stderr or b"").decode("utf-8", errors="ignore")

            state = ""
            try:
                st = subprocess.run(
                    ["systemctl", "is-active", unit],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                state = (st.stdout or b"").decode("utf-8", errors="ignore").strip() or (st.stderr or b"").decode("utf-8", errors="ignore").strip()
            except Exception:
                state = ""

            details = ""
            try:
                ss = subprocess.run(
                    ["systemctl", "status", unit, "--no-pager", "-n", "30"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=12,
                    check=False,
                )
                details = (ss.stdout or b"").decode("utf-8", errors="ignore")
                if not details:
                    details = (ss.stderr or b"").decode("utf-8", errors="ignore")
            except Exception:
                details = ""

            ok = (proc.returncode == 0)
            if action == "stop":
                ok = ok and (state in ("inactive", "failed", "deactivating", "unknown") or state.startswith("inactive"))
            elif action in ("start", "restart"):
                ok = ok and (state == "active" or state == "activating")

            msg = f"{action} {unit}: {state or 'unknown'}"
            extra = (err.strip() or out.strip())
            if extra and extra not in details:
                details = (extra + ("\n\n" + details if details else "")).strip()

            return ok, msg, details, state
        except Exception as e:
            return False, f"Service control failed: {str(e)}", "", ""

    def _handle_service_logs(self, cmd):
        unit = (cmd.get("unit") or "").strip()
        try:
            lines = int(cmd.get("lines") or 200)
        except Exception:
            lines = 200
        lines = max(10, min(1000, lines))

        if not self._is_safe_unit(unit):
            return False, "Invalid unit", "", ""

        try:
            if shutil.which("journalctl") is None:
                return False, "journalctl not available", "", ""

            jp = subprocess.run(
                ["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "--output=short-iso"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            output = (jp.stdout or b"").decode("utf-8", errors="ignore")
            err = (jp.stderr or b"").decode("utf-8", errors="ignore")

            if jp.returncode != 0:
                return False, "Failed to read logs", err.strip(), ""

            if not output.strip():
                return True, "No logs", "", ""

            return True, "OK", "", output
        except Exception as e:
            return False, f"Logs failed: {str(e)}", "", ""

    def _services_status(self):
        openvpn_installed = bool(shutil.which("openvpn")) or (
            os.path.isdir(OPENVPN_CONF_DIR) and len(glob.glob(os.path.join(OPENVPN_CONF_DIR, "*.conf"))) > 0
        )
        ocserv_installed = bool(shutil.which("ocserv")) or os.path.exists(OCSERV_CONF)
        xl2tpd_installed = bool(shutil.which("xl2tpd"))
        pppd_installed = bool(shutil.which("pppd"))
        wg_installed = bool(shutil.which("wg")) and bool(shutil.which("wg-quick"))

        openvpn_instances = self._openvpn_instances() if openvpn_installed else []
        openvpn_any_active = any(i.get("service", {}).get("active") for i in openvpn_instances)

        cisco_unit = self._systemctl_state("ocserv.service")
        if cisco_unit["state"] == "not-found":
            cisco_unit = self._systemctl_state("ocserv")

        l2tp_unit = self._systemctl_state("xl2tpd.service")
        if l2tp_unit["state"] == "not-found":
            l2tp_unit = self._systemctl_state("xl2tpd")
        l2tp_installed = bool(xl2tpd_installed) or (l2tp_unit.get("state") != "not-found")
        wg_unit = self._systemctl_state(f"wg-quick@{WG1_IFACE}.service")
        if wg_unit["state"] == "not-found":
            wg_unit = self._systemctl_state(f"wg-quick@{WG1_IFACE}")

        wg_instances = [{
            "name": WG1_IFACE,
            "port": self._wg1_get_listen_port(),
            "installed": wg_installed,
            "service": wg_unit,
        }]
        try:
            for inst in self._wg_instances():
                wg_instances.append({
                    "name": inst.get("name"),
                    "port": inst.get("port"),
                    "installed": wg_installed,
                    "service": inst.get("service") or {},
                })
        except Exception:
            pass

        wg_any_active = bool(wg_unit.get("active")) or any(bool((i.get("service") or {}).get("active")) for i in wg_instances[1:])

        singbox_installed = bool(shutil.which("eylan-singbox")) or os.path.exists("/usr/local/bin/eylan-singbox")
        singbox_unit = self._systemctl_state(f"{SINGBOX_SERVICE_NAME}.service")
        if singbox_unit["state"] == "not-found":
            singbox_unit = self._systemctl_state(SINGBOX_SERVICE_NAME)

        return {
            "openvpn": {"installed": openvpn_installed, "active": bool(openvpn_any_active), "instances": openvpn_instances},
            "cisco": {"installed": ocserv_installed, "active": bool(cisco_unit.get("active")), "service": cisco_unit},
            "l2tp": {"installed": bool(l2tp_installed), "active": bool(l2tp_unit.get("active")), "service": l2tp_unit, "services": {"xl2tpd": l2tp_unit}},
            "wireguard": {"installed": wg_installed, "active": wg_any_active, "service": wg_unit, "instances": wg_instances},
            "singbox": {"installed": singbox_installed, "active": bool(singbox_unit.get("active")), "service": singbox_unit},
        }

    def do_GET(self):
        try:
            response_data = None
            with GLOBAL_DATA_STORE["lock"]:
                if GLOBAL_DATA_STORE["data"]:
                    response_data = GLOBAL_DATA_STORE["data"]

            if not response_data:
                cpu, ram, disk = self._get_system_stats()
                response_data = {
                    "cpu": cpu,
                    "ram": ram,
                    "disk": disk,
                    "status": "initializing"
                }

            self._send_json(200, response_data)
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
                        subprocess.run(["systemctl", "restart", "ocserv"], check=False, timeout=5)
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

                if cmd0 in ("wg1_upload_conf", "upload_wg1_conf"):
                    wg_conf = data.get("content") if "content" in data else data.get("conf")
                    if wg_conf is not None:
                        old_file_content = ""
                        if os.path.exists(WG1_CONF):
                            with open(WG1_CONF, "r") as f:
                                old_file_content = f.read().strip()
                        if old_file_content != wg_conf.strip():
                            ok = self._wg1_write_conf(wg_conf)
                            if ok is True and bool(data.get("restart", True)):
                                self._wg1_restart()
                        else:
                            ok = True
                        self._send_json(200, {"success": bool(ok)})
                        return

                if cmd0 in ("wg1_upload_peers_db", "upload_wg1_peers_db"):
                    pdb = data.get("peers_db")
                    if pdb is None and data.get("content") is not None:
                        try:
                            pdb = json.loads(data.get("content"))
                        except:
                            pdb = None
                    ok = isinstance(pdb, dict) and self._wg1_save_peers_db(pdb)
                    if ok:
                        self._wg1_rebuild_conf_from_peers_db()
                    self._send_json(200, {"success": bool(ok)})
                    return

            if isinstance(data, dict) and "commands" in data:
                commands = data.get("commands", [])
            elif isinstance(data, list):
                commands = data
            else:
                commands = [data]

            results = []
            for item in commands:
                time.sleep(0.01)
                try:
                    cmd = item.get("command")
                    uname = item.get("username")
                    success, msg = False, "Unknown"
                    res_extra = {}

                    if cmd == "l2tp_single_action":
                        success, msg = self._handle_l2tp_single(item)

                    elif cmd == "cisco_single_action":
                        success, msg = self._handle_cisco_single(item)

                    elif cmd == "service_control":
                        success, msg, details, state = self._handle_service_control(item)
                        res_extra = {"details": details, "state": state}

                    elif cmd == "service_logs":
                        success, msg, details, output = self._handle_service_logs(item)
                        res_extra = {"details": details, "output": output}

                    elif cmd == "sync_revocation":
                        pki_dir = "/etc/openvpn/server/easy-rsa/pki"
                        os.makedirs(pki_dir, exist_ok=True)

                        crl_b64 = item.get("crl_pem_b64", "")
                        idx_b64 = item.get("index_txt_b64", "")

                        if not crl_b64 or not idx_b64:
                            success, msg = False, "Missing crl_pem_b64 or index_txt_b64"
                        else:
                            try:
                                crl_bytes = base64.b64decode(crl_b64.encode("utf-8"))
                                idx_bytes = base64.b64decode(idx_b64.encode("utf-8"))
                            except Exception as e:
                                success, msg = False, f"Base64 decode failed: {e}"
                            else:
                                crl_path = os.path.join(pki_dir, "crl.pem")
                                idx_path = os.path.join(pki_dir, "index.txt")

                                try:
                                    tmp_crl = crl_path + ".tmp"
                                    tmp_idx = idx_path + ".tmp"
                                    with open(tmp_crl, "wb") as f:
                                        f.write(crl_bytes)
                                    with open(tmp_idx, "wb") as f:
                                        f.write(idx_bytes)
                                    os.replace(tmp_crl, crl_path)
                                    os.replace(tmp_idx, idx_path)
                                    os.chmod(crl_path, 0o644)
                                    os.chmod(idx_path, 0o644)
                                except Exception as e:
                                    success, msg = False, f"Write CRL/Index failed: {e}"
                                else:
                                    try:
                                        conf_dir = "/etc/openvpn/server"
                                        for name in os.listdir(conf_dir):
                                            if not name.endswith(".conf"):
                                                continue
                                            fp = os.path.join(conf_dir, name)
                                            try:
                                                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                                                    content = f.read()
                                                if "crl-verify" not in content:
                                                    with open(fp, "a", encoding="utf-8") as f:
                                                        f.write("\ncrl-verify crl.pem\n")
                                            except Exception:
                                                pass
                                    except Exception as e:
                                        success, msg = False, f"Ensure crl-verify failed: {e}"
                                    else:
                                        restart_mode = (item.get("restart_mode") or "active").strip().lower()
                                        try:
                                            subprocess.run(["systemctl", "daemon-reload"], check=False)
                                            if restart_mode == "all":
                                                subprocess.run(["bash", "-lc", "systemctl restart 'openvpn-server@*'"], check=False)
                                            else:
                                                subprocess.run(
                                                    ["bash", "-lc",
                                                     "systemctl list-units --type=service --state=active \"openvpn-server@*\" --no-legend | awk '{print $1}' | xargs -r systemctl restart"],
                                                    check=False
                                                )
                                            success, msg = True, "CRL/index synced and OpenVPN restarted"
                                            res_extra = {"restart_mode": restart_mode}
                                        except Exception as e:
                                            success, msg = False, f"Restart failed: {e}"

                    elif cmd == "update_cisco_config":
                        new_port = item.get("port")
                        if new_port is not None:
                            p = str(int(new_port))
                            if os.path.exists(OCSERV_CONF):
                                subprocess.run(["sed", "-i", f"s/^tcp-port.*/tcp-port = {p}/", OCSERV_CONF], check=False)
                                subprocess.run(["sed", "-i", f"s/^udp-port.*/udp-port = {p}/", OCSERV_CONF], check=False)
                            subprocess.run(["systemctl", "restart", "ocserv"], check=False, timeout=5)
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

                            try:
                                dbp = self._wg1_load_peers_db()
                                info = dbp.get(uname) if isinstance(dbp, dict) else None
                                if isinstance(info, dict):
                                    pub = (info.get('public_key') or "").strip()
                                    allowed = (
                                        info.get('allowed_ips')
                                        or info.get('allowed_ip')
                                        or info.get('allowed_ips_v4')
                                        or info.get('ip')
                                        or info.get('wg1_ip')
                                    )
                                    psk = info.get('preshared_key')
                                    if pub and allowed:
                                        allowed_norm = self._wg1_normalize_allowed_ips(allowed)

                                        current_allowed = None
                                        try:
                                            dump = subprocess.run(
                                                ["wg", "show", WG1_IFACE, "dump"],
                                                capture_output=True, text=True, timeout=5
                                            )
                                            if dump.returncode == 0:
                                                for line in dump.stdout.splitlines():
                                                    parts = line.split("\t")
                                                    if len(parts) >= 4 and parts[0].strip() == pub:
                                                        current_allowed = parts[3].strip()
                                                        break
                                        except:
                                            pass

                                        if current_allowed == (allowed_norm or ""):
                                            success, msg = True, "Peer already configured correctly"
                                        else:
                                            try:
                                                self._wg1_remove_peer(pub)
                                            except:
                                                pass
                                            ok_peer = self._wg1_set_peer(pub, allowed_ips=allowed, preshared_key=psk, reset_first=False)
                                            if ok_peer:
                                                info["disabled"] = False
                                                if allowed and not info.get("allowed_ips"):
                                                    info["allowed_ips"] = str(allowed).strip()
                                                self._wg1_save_peers_db(dbp)
                            except:
                                pass

                            wg_instance_failures = []
                            try:
                                for inst in self._wg_instances():
                                    inst_name = inst.get("name")
                                    if not inst_name or not _is_valid_wg_instance_name(inst_name):
                                        continue
                                    try:
                                        with WG_INSTANCE_DB_MUTEX:
                                            inst_db = self._wg_instance_load_peers_db(inst_name)
                                            entry = inst_db.get(uname) if isinstance(inst_db, dict) else None
                                            if not isinstance(entry, dict):
                                                continue
                                            pub_i = (entry.get('public_key') or "").strip()
                                            allowed_i = entry.get('allowed_ip') or entry.get('allowed_ips')
                                            if not pub_i or not allowed_i:
                                                continue
                                            allowed_norm_i = self._wg_instance_normalize_allowed_ips(allowed_i)
                                            if not allowed_norm_i:
                                                continue
                                            cp = subprocess.run(
                                                ["wg", "set", inst_name, "peer", pub_i, "allowed-ips", allowed_norm_i],
                                                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10
                                            )
                                            if cp.returncode != 0:
                                                wg_instance_failures.append(inst_name)
                                                continue
                                            entry["disabled"] = False
                                            inst_db[uname] = entry
                                            self._wg_instance_save_peers_db(inst_name, inst_db)
                                    except Exception:
                                        wg_instance_failures.append(inst_name)
                            except:
                                pass

                            if wg_instance_failures:
                                success, msg = True, f"CCD Created (warning: wg peer update failed on: {', '.join(wg_instance_failures)})"
                            else:
                                success, msg = True, "CCD Created"
                        else:
                            success, msg = False, "Missing username"

                    elif cmd == "disable_user":
                        if uname:
                            protocol_failures = []
                            try:
                                (Path(CCD_DIR) / str(uname)).unlink(missing_ok=True)
                            except:
                                pass
                            try:
                                ok_l2tp, msg_l2tp = self._handle_l2tp_single({"username": uname, "action": "delete"})
                                if not ok_l2tp:
                                    protocol_failures.append(f"L2TP: {msg_l2tp}")
                            except Exception as e:
                                protocol_failures.append(f"L2TP: {e}")
                            try:
                                ok_cisco, msg_cisco = self._handle_cisco_single({"username": uname, "action": "delete"})
                                if not ok_cisco:
                                    protocol_failures.append(f"Cisco: {msg_cisco}")
                            except Exception as e:
                                protocol_failures.append(f"Cisco: {e}")
                            try:
                                dbp = self._wg1_load_peers_db()
                                info = dbp.get(uname) if isinstance(dbp, dict) else None
                                pub = None
                                if isinstance(info, dict):
                                    pub = info.get('public_key')
                                elif isinstance(info, str):
                                    pub = info
                                if pub:
                                    self._wg1_remove_peer(pub)
                            except:
                                pass
                            try:
                                if isinstance(dbp, dict):
                                    if uname not in dbp or not isinstance(dbp.get(uname), dict):
                                        if uname in dbp and isinstance(dbp.get(uname), str):
                                            dbp[uname] = {"public_key": dbp.get(uname)}
                                        else:
                                            dbp[uname] = dbp.get(uname) if isinstance(dbp.get(uname), dict) else {}
                                    if isinstance(dbp.get(uname), dict):
                                        dbp[uname]["disabled"] = True
                                    self._wg1_save_peers_db(dbp)
                            except:
                                pass
                            wg_instance_failures = []
                            try:
                                for inst in self._wg_instances():
                                    inst_name = inst.get("name")
                                    if not inst_name or not _is_valid_wg_instance_name(inst_name):
                                        continue
                                    try:
                                        with WG_INSTANCE_DB_MUTEX:
                                            inst_db = self._wg_instance_load_peers_db(inst_name)
                                            if not isinstance(inst_db, dict) or uname not in inst_db:
                                                continue
                                            entry = inst_db.get(uname)
                                            if isinstance(entry, dict):
                                                pub_i = entry.get('public_key')
                                                if pub_i and not self._wg_instance_remove_peer(inst_name, pub_i):
                                                    wg_instance_failures.append(inst_name)
                                                entry["disabled"] = True
                                                inst_db[uname] = entry
                                                self._wg_instance_save_peers_db(inst_name, inst_db)
                                    except Exception:
                                        wg_instance_failures.append(inst_name)
                            except:
                                pass
                            if wg_instance_failures:
                                protocol_failures.append(f"WG peer removal failed on: {', '.join(wg_instance_failures)}")
                            if protocol_failures:
                                success, msg = True, f"User Disabled (warning: {'; '.join(protocol_failures)})"
                            else:
                                success, msg = True, "User Disabled"
                        else:
                            success, msg = False, "Missing username"


                    elif cmd == "delete_ccd":
                        if uname:
                            try:
                                (Path(CCD_DIR) / str(uname)).unlink(missing_ok=True)
                                success, msg = True, "CCD Deleted"
                            except Exception as e:
                                success, msg = False, f"Failed to delete CCD: {e}"
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

                    elif cmd in ("wg1_upload_conf", "upload_wg1_conf"):
                        wg_conf = item.get("content")
                        if wg_conf is None:
                            wg_conf = item.get("conf")
                        if wg_conf is not None:
                            ok = self._wg1_write_conf(wg_conf)
                            if ok is True and bool(item.get("restart", True)):
                                self._wg1_restart()
                            success = bool(ok)
                            msg = "WG1 config updated" if ok else "Failed to write WG1 config"
                        else:
                            success, msg = False, "Missing content"

                    elif cmd in ("wg1_upload_peers_db", "upload_wg1_peers_db"):
                        pdb = item.get("peers_db")
                        if pdb is None and item.get("content") is not None:
                            try:
                                pdb = json.loads(item.get("content"))
                            except:
                                pdb = None
                        if isinstance(pdb, dict):
                            ok = self._wg1_save_peers_db(pdb)
                            if ok:
                                self._wg1_rebuild_conf_from_peers_db()
                            success = bool(ok)
                            msg = "WG1 peers DB updated" if ok else "Failed to write WG1 peers DB"
                        else:
                            success, msg = False, "Missing/invalid peers_db"

                    elif cmd in ("wg1_peer_action", "wg1_set_peer"):
                        action = str(item.get("action") or "add").strip().lower()
                        pub = item.get("public_key") or item.get("pub_key") or item.get("session_id")
                        allowed = (
                            item.get("allowed_ips")
                            or item.get("allowed_ip")
                            or item.get("wg1_ip")
                            or item.get("ip")
                            or item.get("v_ip")
                        )
                        psk = item.get("preshared_key")
                        uname_wg = (item.get("username") or "").strip()

                        if action == "upsert":
                            action = "add"
                        if action == "remove":
                            action = "delete"

                        dbp = self._wg1_load_peers_db()
                        if not isinstance(dbp, dict):
                            dbp = {}

                        if action == "delete":
                            if not pub and uname_wg and isinstance(dbp.get(uname_wg), dict):
                                pub = dbp.get(uname_wg, {}).get("public_key")
                            if not allowed and uname_wg and isinstance(dbp.get(uname_wg), dict):
                                allowed = dbp.get(uname_wg, {}).get("allowed_ips") or dbp.get(uname_wg, {}).get("allowed_ip")

                            ok = True
                            if pub:
                                ok = self._wg1_remove_peer(str(pub).strip())

                            purge_db = True
                            try:
                                if "purge_db" in item:
                                    purge_db = bool(item.get("purge_db"))
                            except:
                                purge_db = True

                            if uname_wg:
                                if purge_db:
                                    dbp.pop(uname_wg, None)
                                else:
                                    if uname_wg not in dbp or not isinstance(dbp.get(uname_wg), dict):
                                        dbp[uname_wg] = {}
                                    if pub:
                                        dbp[uname_wg]["public_key"] = str(pub).strip()
                                    if allowed:
                                        dbp[uname_wg]["allowed_ips"] = self._wg1_normalize_allowed_ips(allowed)
                                    dbp[uname_wg]["disabled"] = True
                                self._wg1_save_peers_db(dbp)
                                self._wg1_rebuild_conf_from_peers_db()

                            success = bool(ok)
                            msg = "WG1 peer removed" if ok else "Failed to remove peer"

                        elif action in ("kick", "kill"):
                            if pub:
                                self._wg1_remove_peer(str(pub).strip())
                            ok = True
                            if pub and (allowed or psk):
                                ok = self._wg1_set_peer(str(pub).strip(), allowed_ips=allowed, preshared_key=psk, reset_first=True)
                            elif pub:
                                ok = self._wg1_kick_peer(str(pub).strip())
                            else:
                                ok = False

                            success = bool(ok)
                            msg = "WG1 peer kicked" if ok else "Failed to kick peer"

                        else:
                            if not pub and uname_wg and isinstance(dbp.get(uname_wg), dict):
                                pub = dbp.get(uname_wg, {}).get("public_key")
                            if not allowed and uname_wg and isinstance(dbp.get(uname_wg), dict):
                                allowed = dbp.get(uname_wg, {}).get("allowed_ips") or dbp.get(uname_wg, {}).get("allowed_ip")

                            if not pub:
                                success, msg = False, "Missing public_key"
                            elif not allowed:
                                success, msg = False, "Missing allowed_ips"
                            else:
                                reset_first = True
                                try:
                                    if "reset_first" in item:
                                        reset_first = bool(item.get("reset_first"))
                                except:
                                    reset_first = True

                                if reset_first:
                                    try:
                                        self._wg1_remove_peer(str(pub).strip())
                                    except:
                                        pass

                                ok = self._wg1_set_peer(str(pub).strip(), allowed_ips=allowed, preshared_key=psk, reset_first=True)

                                if ok and uname_wg:
                                    if uname_wg not in dbp or not isinstance(dbp.get(uname_wg), dict):
                                        dbp[uname_wg] = {}
                                    dbp[uname_wg]["public_key"] = str(pub).strip()
                                    dbp[uname_wg]["allowed_ips"] = self._wg1_normalize_allowed_ips(allowed)
                                    dbp[uname_wg]["allowed_ip"] = self._wg1_normalize_allowed_ips(allowed)
                                    dbp[uname_wg]["disabled"] = False
                                    if psk:
                                        dbp[uname_wg]["preshared_key"] = psk
                                    self._wg1_save_peers_db(dbp)
                                    self._wg1_rebuild_conf_from_peers_db()

                                success = bool(ok)
                                msg = "WG1 peer updated" if ok else "Failed to set peer"

                    elif cmd in ("wg1_sync_peers", "wg1_bulk_sync"):
                      with WG1_DB_MUTEX:
                        peers = item.get("peers")
                        remove_unknown = bool(item.get("remove_unknown", False))
                        ok = True

                        desired_pubs = set()
                        db = self._wg1_load_peers_db() or {}

                        current_wg_peers = {}
                        try:
                            dump_proc = subprocess.run(["wg", "show", WG1_IFACE, "dump"], capture_output=True, text=True, timeout=5)
                            if dump_proc.returncode == 0:
                                lines = dump_proc.stdout.strip().splitlines()
                                if len(lines) > 1:
                                    for line in lines[1:]:
                                        parts = line.split("\t")
                                        if len(parts) >= 4:
                                            current_wg_peers[parts[0].strip()] = parts[3].strip()
                        except:
                            pass

                        if isinstance(peers, list):
                            for p in peers:
                                try:
                                    pub = p.get("public_key") or p.get("pub_key")
                                    uname_p = p.get("username")
                                    allowed = p.get("allowed_ips") or p.get("v_ip")
                                    psk = p.get("preshared_key")
                                    if not pub:
                                        continue
                                    pub = str(pub).strip()
                                    desired_pubs.add(pub)

                                    allowed_norm = self._wg1_normalize_allowed_ips(allowed)
                                    needs_update = True

                                    if pub in current_wg_peers and current_wg_peers[pub] == (allowed_norm or "") and not psk:
                                        needs_update = False

                                    block_until = WG_TEMP_BLOCKED_UNTIL.get(("wg1", pub))
                                    if block_until and time.time() < block_until:
                                        needs_update = False

                                    if needs_update:
                                        self._wg1_set_peer(pub, allowed_ips=allowed, preshared_key=psk, reset_first=False)

                                    if uname_p:
                                        if uname_p not in db or not isinstance(db.get(uname_p), dict):
                                            db[uname_p] = {}
                                        db[uname_p]["public_key"] = pub
                                        db[uname_p]["disabled"] = False
                                        if allowed:
                                            db[uname_p]["allowed_ips"] = allowed
                                        if psk:
                                            db[uname_p]["preshared_key"] = psk
                                except:
                                    ok = False
                                    continue

                            if remove_unknown:
                                try:
                                    r = subprocess.run(["wg", "show", WG1_IFACE, "peers"], capture_output=True, text=True, timeout=5)
                                    if r.returncode == 0:
                                        for pub in (r.stdout or "").split():
                                            if pub and pub not in desired_pubs:
                                                self._wg1_remove_peer(pub)
                                except:
                                    pass

                            if remove_unknown:
                                try:
                                    pruned = {}
                                    for _uname_k, _ud in (db or {}).items():
                                        try:
                                            if isinstance(_ud, dict):
                                                _pubk = (_ud.get("public_key") or _ud.get("pub_key") or "").strip()
                                            else:
                                                _pubk = ""
                                            if _pubk and (_pubk in desired_pubs):
                                                pruned[_uname_k] = _ud
                                        except:
                                            continue
                                    db = pruned
                                except:
                                    pass

                            try:
                                self._wg1_save_peers_db(db)
                            except:
                                ok = False

                            success = bool(ok)
                            msg = "WG1 peers synced" if ok else "WG1 peers sync completed with errors"
                        else:
                            success, msg = False, "Missing peers list"

                    elif cmd == "wg_instance_sync_peers":
                        instance_name = str(item.get("instance") or "").strip()
                        peers = item.get("peers")
                        remove_unknown = bool(item.get("remove_unknown", False))

                        if not _is_valid_wg_instance_name(instance_name):
                            success, msg = False, "Invalid or reserved instance name"
                        elif not isinstance(peers, list):
                            success, msg = False, "Missing peers list"
                        else:
                            self._wg_instance_ensure_runtime(instance_name)
                            with WG_INSTANCE_DB_MUTEX:
                                ok = True
                                desired_pubs = set()
                                db_peers = self._wg_instance_load_peers_db(instance_name)
                                if not isinstance(db_peers, dict):
                                    db_peers = {}

                                current_peers = {}
                                try:
                                    dump_proc = subprocess.run(["wg", "show", instance_name, "dump"], capture_output=True, text=True, timeout=5)
                                    if dump_proc.returncode == 0:
                                        for line in (dump_proc.stdout or "").strip().splitlines()[1:]:
                                            parts = line.split("\t")
                                            if len(parts) >= 4:
                                                current_peers[parts[0].strip()] = parts[3].strip()
                                except Exception:
                                    pass

                                for p in peers:
                                    try:
                                        pub = p.get("public_key") or p.get("pub_key")
                                        uname_p = p.get("username")
                                        allowed = p.get("allowed_ips") or p.get("allowed_ip") or p.get("v_ip")
                                        if not pub or not allowed:
                                            continue
                                        pub = str(pub).strip()
                                        allowed_norm = self._wg_instance_normalize_allowed_ips(allowed)
                                        if not allowed_norm:
                                            continue
                                        desired_pubs.add(pub)

                                        block_until = WG_TEMP_BLOCKED_UNTIL.get((instance_name, pub))
                                        actively_blocked = bool(block_until and time.time() < block_until)

                                        if current_peers.get(pub) != allowed_norm and not actively_blocked:
                                            subprocess.run(
                                                ["wg", "set", instance_name, "peer", pub, "allowed-ips", allowed_norm],
                                                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10
                                            )

                                        if uname_p:
                                            if uname_p not in db_peers or not isinstance(db_peers.get(uname_p), dict):
                                                db_peers[uname_p] = {}
                                            db_peers[uname_p]["public_key"] = pub
                                            db_peers[uname_p]["allowed_ip"] = allowed_norm
                                            db_peers[uname_p]["disabled"] = False
                                    except Exception:
                                        ok = False
                                        continue

                                if remove_unknown:
                                    try:
                                        r = subprocess.run(["wg", "show", instance_name, "peers"], capture_output=True, text=True, timeout=5)
                                        if r.returncode == 0:
                                            for pub in (r.stdout or "").split():
                                                if pub and pub not in desired_pubs:
                                                    self._wg_instance_remove_peer(instance_name, pub)
                                    except Exception:
                                        pass
                                    try:
                                        pruned = {}
                                        for uname_k, ud in (db_peers or {}).items():
                                            pubk = (ud.get("public_key") or "").strip() if isinstance(ud, dict) else ""
                                            if pubk and pubk in desired_pubs:
                                                pruned[uname_k] = ud
                                        db_peers = pruned
                                    except Exception:
                                        pass

                                try:
                                    self._wg_instance_save_peers_db(instance_name, db_peers)
                                    self._wg_instance_rebuild_conf_from_peers_db(instance_name)
                                except Exception:
                                    ok = False

                                success = bool(ok)
                                msg = "WG instance peers synced" if ok else "WG instance peers sync completed with errors"

                    elif cmd == "wg_instance_peer_action":
                        instance_name = str(item.get("instance") or "").strip()
                        action = str(item.get("action") or "add").strip().lower()
                        pub = item.get("public_key") or item.get("pub_key")
                        allowed = item.get("allowed_ips") or item.get("allowed_ip") or item.get("v_ip")
                        uname_wg = (item.get("username") or "").strip()

                        if action == "upsert":
                            action = "add"
                        if action == "remove":
                            action = "delete"

                        if not _is_valid_wg_instance_name(instance_name):
                            success, msg = False, "Invalid or reserved instance name"
                        elif not pub:
                            success, msg = False, "Missing public_key"
                        else:
                            pub = str(pub).strip()
                            with WG_INSTANCE_DB_MUTEX:
                                db_peers = self._wg_instance_load_peers_db(instance_name)
                                if not isinstance(db_peers, dict):
                                    db_peers = {}

                                if action == "delete":
                                    ok = self._wg_instance_remove_peer(instance_name, pub)
                                    if uname_wg and uname_wg in db_peers:
                                        db_peers.pop(uname_wg, None)
                                    else:
                                        for _u, _d in list(db_peers.items()):
                                            if isinstance(_d, dict) and str(_d.get("public_key") or "").strip() == pub:
                                                db_peers.pop(_u, None)
                                    try:
                                        self._wg_instance_save_peers_db(instance_name, db_peers)
                                        self._wg_instance_rebuild_conf_from_peers_db(instance_name)
                                    except Exception:
                                        ok = False
                                    success = bool(ok)
                                    msg = "WG instance peer removed" if ok else "Failed to remove peer"
                                else:
                                    allowed_norm = self._wg_instance_normalize_allowed_ips(allowed)
                                    if not allowed_norm:
                                        success, msg = False, "Missing/invalid allowed_ips"
                                    else:
                                        self._wg_instance_ensure_runtime(instance_name)
                                        set_res = subprocess.run(
                                            ["wg", "set", instance_name, "peer", pub, "allowed-ips", allowed_norm],
                                            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10
                                        )
                                        ok = (set_res.returncode == 0)
                                        if uname_wg:
                                            if uname_wg not in db_peers or not isinstance(db_peers.get(uname_wg), dict):
                                                db_peers[uname_wg] = {}
                                            db_peers[uname_wg]["public_key"] = pub
                                            db_peers[uname_wg]["allowed_ip"] = allowed_norm
                                            db_peers[uname_wg]["disabled"] = False
                                        try:
                                            self._wg_instance_save_peers_db(instance_name, db_peers)
                                            self._wg_instance_rebuild_conf_from_peers_db(instance_name)
                                        except Exception:
                                            ok = False
                                        success = bool(ok)
                                        msg = "WG instance peer added" if ok else "Failed to add peer"

                    elif cmd == "wg_instance_provision":
                        instance_name = str(item.get("instance") or "").strip()
                        port = item.get("port")
                        subnet = str(item.get("subnet") or "").strip()
                        if not _is_valid_wg_instance_name(instance_name):
                            success, msg = False, "Invalid or reserved instance name"
                        elif not port or not subnet:
                            success, msg = False, "Missing port or subnet"
                        else:
                            success, msg = self._wg_instance_provision(instance_name, port, subnet)

                    elif cmd == "wg_instance_remove":
                        instance_name = str(item.get("instance") or "").strip()
                        if not _is_valid_wg_instance_name(instance_name):
                            success, msg = False, "Invalid or reserved instance name"
                        else:
                            success, msg = self._wg_instance_teardown(instance_name)

                    elif cmd == "wg_instance_update_port":
                        instance_name = str(item.get("instance") or "").strip()
                        new_port = item.get("port")
                        if not _is_valid_wg_instance_name(instance_name):
                            success, msg = False, "Invalid or reserved instance name"
                        elif new_port is None:
                            success, msg = False, "Missing port"
                        else:
                            try:
                                p = int(new_port)
                                ok1 = self._update_listen_port_in_file(f"/etc/wireguard/{instance_name}_base.conf", p)
                                ok2 = self._update_listen_port_in_file(f"/etc/wireguard/{instance_name}.conf", p)
                                self._wg_instance_open_udp_port(p)
                                try:
                                    live = subprocess.run(["wg", "show", instance_name], capture_output=True, text=True, timeout=5)
                                    if live.returncode == 0:
                                        subprocess.run(["wg", "set", instance_name, "listen-port", str(p)],
                                                        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                                    else:
                                        subprocess.run(["systemctl", "restart", f"wg-quick@{instance_name}"], check=False, timeout=20)
                                except Exception:
                                    pass
                                success = bool(ok1 and ok2)
                                msg = f"Port updated to {p}" if success else "Failed to update port files"
                            except Exception as e:
                                success, msg = False, f"Port update failed: {e}"

                    elif cmd == "kill" or cmd == "kill_id":
                        uname = str(item.get("username") or "").strip()
                        sid = item.get("session_id")
                        proto = str(item.get("protocol") or "").upper()
                        mgmt_port = item.get("mgmt_port")

                        success = False
                        msg = "Init"

                        if sid:
                            try:
                                if "CISCO" in proto:
                                    subprocess.run([OCCTL_BIN, "disconnect", "id", str(sid)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                                    success = True
                                    msg = "Killed Cisco ID"
                                elif "L2TP" in proto:
                                    os.kill(int(sid), 9)
                                    success = True
                                    msg = "Killed L2TP PID"
                                elif "OPENVPN" in proto or "OVPN" in proto:
                                    ports = [mgmt_port] if mgmt_port else self._get_all_management_ports()
                                    for p in ports:
                                        try:
                                            with socket.create_connection(("127.0.0.1", int(p)), timeout=2) as s:
                                                s.settimeout(2)
                                                s.recv(1024)
                                                s.sendall(f"client-kill {sid}\n".encode("utf-8"))
                                                s.recv(1024)
                                        except:
                                            pass
                                    success = True
                                    msg = "Killed OVPN CID"
                                elif "WIREGUARD" in proto or proto == "WG":
                                    inst_name = str(item.get("instance") or "").strip() or None
                                    effective_inst = inst_name if (inst_name and inst_name != "wg1" and _is_valid_wg_instance_name(inst_name)) else "wg1"
                                    if _wg_should_block_after_kill(uname, effective_inst, str(sid)):
                                        if effective_inst != "wg1":
                                            self._wg_instance_temp_kick_peer(effective_inst, str(sid), duration_seconds=200)
                                        else:
                                            self._wg1_temp_kick_peer(str(sid), duration_seconds=200)
                                        msg = "Kicked WG Peer (blocked 200s)"
                                    else:
                                        if effective_inst != "wg1":
                                            self._wg_instance_kick_peer(effective_inst, str(sid))
                                        else:
                                            self._wg1_kick_peer(str(sid))
                                        msg = "Kicked WG Peer"
                                    success = True
                                elif "SINGBOX" in proto:
                                    killed_n = self._singbox_kill_user(uname, sid)
                                    success = killed_n > 0
                                    if success:
                                        blocked = False
                                        if _singbox_should_block_after_kill(uname, sid):
                                            blocked = _singbox_temp_block_ip(sid, duration_seconds=200)
                                        msg = f"Killed {killed_n} sing-box connection(s), blocked={blocked}"
                                    else:
                                        msg = "sing-box kill failed"
                            except Exception as e:
                                success = False
                                msg = str(e)

                        if not success and uname:
                            try:
                                subprocess.run(["pkill", "-9", "-f", f"pppd.*name {uname}"], check=False, timeout=5)
                            except:
                                pass

                            try:
                                if os.path.exists(OCCTL_BIN):
                                    subprocess.run([OCCTL_BIN, "disconnect", "user", str(uname)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                            except:
                                pass

                            try:
                                for port in self._get_all_management_ports():
                                    try:
                                        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                                            s.settimeout(2)
                                            s.recv(1024)
                                            s.sendall(f"kill {uname}\n".encode("utf-8"))
                                            s.recv(1024)
                                    except:
                                        pass
                            except:
                                pass

                            try:
                                if os.path.exists(L2TP_ACTIVE_FILE):
                                    with open(L2TP_ACTIVE_FILE, "r+") as f:
                                        fcntl.flock(f, fcntl.LOCK_EX)
                                        lines = f.readlines()
                                        f.seek(0)
                                        f.truncate()
                                        for line in lines:
                                            if not line.startswith(f"{uname}:"):
                                                f.write(line)
                                        f.flush()
                                        os.fsync(f.fileno())
                                        fcntl.flock(f, fcntl.LOCK_UN)
                            except:
                                pass

                            try:
                                dbp = self._wg1_load_peers_db()
                                if uname in dbp:
                                    pub = (dbp.get(uname) or {}).get('public_key')
                                    if pub:
                                        self._wg1_kick_peer(pub)
                            except:
                                pass

                            wg_instance_failures = []
                            try:
                                for inst in self._wg_instances():
                                    inst_name = inst.get("name")
                                    if not inst_name or not _is_valid_wg_instance_name(inst_name):
                                        continue
                                    try:
                                        with WG_INSTANCE_DB_MUTEX:
                                            inst_db = self._wg_instance_load_peers_db(inst_name)
                                            entry = inst_db.get(uname) if isinstance(inst_db, dict) else None
                                            if isinstance(entry, dict):
                                                pub_i = entry.get("public_key")
                                                if pub_i and not self._wg_instance_kick_peer(inst_name, pub_i):
                                                    wg_instance_failures.append(inst_name)
                                    except Exception:
                                        wg_instance_failures.append(inst_name)
                            except:
                                pass

                            try:
                                self._singbox_kill_user(uname)
                            except:
                                pass

                            success = True
                            msg = "Full Kill Sent" if not wg_instance_failures else f"Full Kill Sent (warning: wg kick failed on: {', '.join(wg_instance_failures)})"

                    elif cmd == "delete_user_completely":
                        if uname:
                            protocol_failures = []
                            try:
                                (Path(CCD_DIR) / str(uname)).unlink(missing_ok=True)
                            except:
                                pass
                            try:
                                (Path(OVPN_FILES_DIR) / f"{uname}.ovpn").unlink(missing_ok=True)
                            except:
                                pass
                            try:
                                ok_l2tp, msg_l2tp = self._handle_l2tp_single({"username": uname, "action": "delete"})
                                if not ok_l2tp:
                                    protocol_failures.append(f"L2TP: {msg_l2tp}")
                            except Exception as e:
                                protocol_failures.append(f"L2TP: {e}")
                            try:
                                ok_cisco, msg_cisco = self._handle_cisco_single({"username": uname, "action": "delete"})
                                if not ok_cisco:
                                    protocol_failures.append(f"Cisco: {msg_cisco}")
                            except Exception as e:
                                protocol_failures.append(f"Cisco: {e}")
                            try:
                                subprocess.run(["pkill", "-9", "-f", f"pppd.*name {uname}"], check=False, timeout=5)
                            except:
                                pass
                            try:
                                if os.path.exists(OCCTL_BIN):
                                    subprocess.run([OCCTL_BIN, "disconnect", "user", str(uname)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                            except:
                                pass
                            try:
                                dbp = self._wg1_load_peers_db()
                                if uname in dbp:
                                    pub = (dbp.get(uname) or {}).get('public_key')
                                    if pub:
                                        self._wg1_remove_peer(pub)
                                    dbp.pop(uname, None)
                                    self._wg1_save_peers_db(dbp)
                            except:
                                pass
                            wg_instance_failures = []
                            try:
                                for inst in self._wg_instances():
                                    inst_name = inst.get("name")
                                    if not inst_name or not _is_valid_wg_instance_name(inst_name):
                                        continue
                                    try:
                                        with WG_INSTANCE_DB_MUTEX:
                                            inst_db = self._wg_instance_load_peers_db(inst_name)
                                            if not isinstance(inst_db, dict) or uname not in inst_db:
                                                continue
                                            entry = inst_db.get(uname)
                                            pub_i = entry.get('public_key') if isinstance(entry, dict) else None
                                            if pub_i and not self._wg_instance_remove_peer(inst_name, pub_i):
                                                wg_instance_failures.append(inst_name)
                                            inst_db.pop(uname, None)
                                            self._wg_instance_save_peers_db(inst_name, inst_db)
                                            self._wg_instance_rebuild_conf_from_peers_db(inst_name)
                                    except Exception:
                                        wg_instance_failures.append(inst_name)
                            except:
                                pass
                            if wg_instance_failures:
                                protocol_failures.append(f"WG peer removal failed on: {', '.join(wg_instance_failures)}")
                            if protocol_failures:
                                success, msg = True, f"Deleted (warning: {'; '.join(protocol_failures)})"
                            else:
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
                            subprocess.run(["systemctl", "restart", "ocserv"], check=False, timeout=5)
                            success, msg = True, "Cisco Port Updated"
                        else:
                            success, msg = False, "Missing port"

                    elif cmd == "wg1_sync_files":
                        wg_conf = item.get("wg1_conf")
                        peers_json = item.get("peers_json")
                        listen_port = item.get("listen_port")
                        provision = bool(item.get("provision", False))

                        if not wg_conf or not peers_json:
                            success, msg = False, "Missing wg1_conf or peers_json"
                        else:
                            try:
                                json.loads(peers_json)
                            except Exception as e:
                                success, msg = False, f"Invalid peers_json: {e}"
                            else:
                                try:
                                    os.makedirs("/etc/wireguard", exist_ok=True)
                                    try:
                                        os.chmod("/etc/wireguard", 0o700)
                                    except:
                                        pass

                                    def _atomic_write(path, content, mode=0o600):
                                        tmp = path + ".new"
                                        with open(tmp, "w", encoding="utf-8") as f:
                                            f.write(content)
                                            f.flush()
                                            os.fsync(f.fileno())
                                        try:
                                            os.chown(tmp, 0, 0)
                                        except:
                                            pass
                                        try:
                                            os.chmod(tmp, mode)
                                        except:
                                            pass
                                        os.replace(tmp, path)

                                    _atomic_write("/etc/wireguard/wg1.conf", wg_conf, 0o600)
                                    _atomic_write("/etc/wireguard/wg1_peers.json", peers_json, 0o600)

                                    if listen_port is not None:
                                        try:
                                            p = int(listen_port)
                                            self._wg1_update_listen_port_files(p)
                                        except:
                                            pass

                                    if provision:
                                        def _get_default_iface():
                                            try:
                                                cp = subprocess.run(
                                                    "ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if ($i==\"dev\") {print $(i+1); exit}}'",
                                                    shell=True,
                                                    executable="/bin/bash",
                                                    capture_output=True,
                                                    text=True,
                                                    timeout=5
                                                )
                                                iface = (cp.stdout or "").strip()
                                                return iface or None
                                            except:
                                                return None

                                        def _patch_nat_iface_in_file(path, iface):
                                            try:
                                                if not iface or not os.path.exists(path):
                                                    return
                                                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                                                    txt = f.read()
                                                new_txt = re.sub(
                                                    r"(\bPOSTROUTING\s+-o\s+)(\S+)(\s+-j\s+MASQUERADE\b)",
                                                    r"\g<1>" + iface + r"\g<3>",
                                                    txt
                                                )
                                                if new_txt != txt:
                                                    _atomic_write(path, new_txt, 0o600)
                                            except:
                                                pass

                                        iface = _get_default_iface()
                                        _patch_nat_iface_in_file("/etc/wireguard/wg1.conf", iface)
                                        _patch_nat_iface_in_file("/etc/wireguard/wg1_base.conf", iface)

                                    if shutil.which("wg") and shutil.which("wg-quick"):
                                        cp = subprocess.run(
                                            ["systemctl", "is-active", f"wg-quick@{WG1_IFACE}"],
                                            capture_output=True,
                                            text=True,
                                            timeout=5
                                        )
                                        if cp.returncode == 0 and cp.stdout.strip() == "active":
                                            subprocess.run(
                                                f"wg syncconf {WG1_IFACE} <(wg-quick strip {WG1_IFACE})",
                                                shell=True,
                                                executable="/bin/bash",
                                                check=False,
                                                timeout=10
                                            )
                                        else:
                                            subprocess.run(
                                                ["systemctl", "start", f"wg-quick@{WG1_IFACE}"],
                                                check=False,
                                                timeout=10
                                            )

                                    try:
                                        peers_after_sync = self._wg1_load_peers_db() or {}
                                        self._wg1_ensure_runtime()
                                        for _uname_sync, _pdata_sync in peers_after_sync.items():
                                            if not isinstance(_pdata_sync, dict) or bool(_pdata_sync.get("disabled")):
                                                continue
                                            _pub_sync = _pdata_sync.get("public_key")
                                            _allowed_sync = _pdata_sync.get("allowed_ips") or _pdata_sync.get("allowed_ip") or _pdata_sync.get("ip") or _pdata_sync.get("wg1_ip")
                                            if _pub_sync and _allowed_sync:
                                                self._wg1_set_peer(_pub_sync, allowed_ips=_allowed_sync, preshared_key=_pdata_sync.get("preshared_key"), reset_first=False)
                                    except:
                                        pass

                                    success, msg = True, "WG1 synced without restart"
                                except Exception as e:
                                    success, msg = False, str(e)

                    elif cmd == "update_wg1_port":
                        new_port = item.get("port")
                        if new_port is not None:
                            p_int = int(new_port)

                            self._wg1_update_listen_port_files(p_int)

                            try:
                                self._update_iptables_port(str(p_int))
                            except:
                                pass
                            try:
                                if shutil.which("ufw"):
                                    subprocess.run(["ufw", "allow", f"{p_int}/udp"], check=False, capture_output=True, timeout=5)
                            except:
                                pass

                            try:
                                self._wg1_restart()
                            except:
                                pass

                            success, msg = True, f"WireGuard (wg1) port updated to {p_int}"
                        else:
                            success, msg = False, "Missing port"

                    elif cmd == "singbox_user_action":
                        success, msg = self._handle_singbox_single(item)

                    elif cmd == "singbox_inbound_provision":
                        success, msg = self._handle_singbox_inbound_provision(item)

                    elif cmd == "singbox_inbound_remove":
                        success, msg = self._handle_singbox_inbound_remove(item)

                    elif cmd == "singbox_sync_inbound_users":
                        success, msg = self._handle_singbox_sync_inbound_users(item)

                    elif cmd == "singbox_kill_user":
                        killed_count = self._singbox_kill_user(uname)
                        success, msg = True, f"Killed {killed_count} sing-box connection(s) for {uname}"

                    result_obj = {"username": uname, "success": success, "message": msg}
                    if isinstance(res_extra, dict) and res_extra:
                        result_obj.update(res_extra)
                    if cmd in ("service_control", "service_logs"):
                        result_obj["unit"] = item.get("unit")
                        if cmd == "service_control":
                            result_obj["action"] = item.get("action")
                    results.append(result_obj)
                except Exception as inner_e:
                    results.append({"username": item.get("username"), "success": False, "message": str(inner_e)})

            self._send_json(200, {"results": results})
        except Exception as e:
            try:
                self.send_error(500, str(e))
            except:
                pass


def background_monitor_engine():
    dummy_handler = StatusHandler(None, None, None, run_setup=False)
    executor = ThreadPoolExecutor(max_workers=8)

    while True:
        start_ts = time.time()
        try:
            cpu, ram, disk = dummy_handler._get_system_stats()

            local_detailed = {}
            sessions = []

            def get_openvpn():
                status_outputs, port_map = dummy_handler._get_all_openvpn_statuses()
                return dummy_handler._extract_openvpn_sessions(status_outputs, port_map, local_detailed)

            def get_l2tp():
                return dummy_handler._extract_l2tp_sessions(local_detailed)

            def get_cisco():
                return dummy_handler._extract_cisco_sessions(local_detailed)

            def get_wireguard():
                return dummy_handler._extract_wg_sessions(local_detailed)

            def get_wireguard_multi():
                return dummy_handler._get_all_wg_statuses(local_detailed)

            def get_singbox():
                return dummy_handler._singbox_extract_sessions(local_detailed)

            f_ovpn = executor.submit(get_openvpn)
            f_l2tp = executor.submit(get_l2tp)
            f_cisco = executor.submit(get_cisco)
            f_wg = executor.submit(get_wireguard)
            f_wg_multi = executor.submit(get_wireguard_multi)
            f_singbox = executor.submit(get_singbox)

            try:
                sessions.extend(f_ovpn.result(timeout=10) or [])
                sessions.extend(f_l2tp.result(timeout=10) or [])
                sessions.extend(f_cisco.result(timeout=10) or [])
                sessions.extend(f_wg.result(timeout=10) or [])
                sessions.extend(f_wg_multi.result(timeout=10) or [])
                sessions.extend(f_singbox.result(timeout=10) or [])
            except:
                pass

            aggregated = dummy_handler._build_aggregated(local_detailed)

            final_data = {
                "cpu": cpu,
                "ram": ram,
                "disk": disk,
                "sessions": sessions,
                "detailed": local_detailed,
                "aggregated": aggregated,
                "wireguard": {
                    "iface": WG1_IFACE,
                    "public_key": dummy_handler._wg1_get_iface_public_key(),
                    "listen_port": dummy_handler._wg1_get_listen_port()
                },
                "services": dummy_handler._services_status(),
                "openvpn_ports": dummy_handler._get_openvpn_port_map(),
                "timestamp": time.time()
            }

            with GLOBAL_DATA_STORE["lock"]:
                GLOBAL_DATA_STORE["data"] = final_data

        except:
            pass

        elapsed = time.time() - start_ts
        time.sleep(max(1.0, 10.0 - elapsed))


def run_server():
    monitor_thread = threading.Thread(target=background_monitor_engine, daemon=True)
    monitor_thread.start()

    server = ThreadingHTTPServer(("0.0.0.0", PORT), StatusHandler)
    server.serve_forever()

if __name__ == "__main__":
    run_server()

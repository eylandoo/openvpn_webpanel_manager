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
WG1_DB_MUTEX = threading.RLock()
WG1_DB_LAST_ERR_LOG = 0.0
WG1_DB_ERR_LOG_EVERY = 10.0

WG1_DB_CACHE = {}
WG1_DB_LAST_MTIME = 0

L2TP_SESSION_CACHE = {}
L2TP_CACHE_LOCK = threading.Lock()

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

    def _wg1_get_iface_public_key(self):
        try:
            proc = subprocess.run(["wg", "show", WG1_IFACE, "public-key"], capture_output=True, text=True, check=False)
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
                                                        capture_output=True, check=False)
                                    pk2 = (p2.stdout or b"").decode("utf-8", "ignore").strip()
                                    if pk2:
                                        return pk2
            except:
                pass
        return None

    def _wg1_get_listen_port(self):
        try:
            proc = subprocess.run(["wg", "show", WG1_IFACE, "listen-port"], capture_output=True, text=True, check=False)
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
        global L2TP_SESSION_CACHE, L2TP_CACHE_LOCK
        sessions = []
        current_system_time = time.time()
        
        try:
            all_sys_ifaces = glob.glob("/sys/class/net/ppp*")
            all_iface_names = {os.path.basename(p) for p in all_sys_ifaces}
        except:
            all_sys_ifaces = []
            all_iface_names = set()

        processed_ifaces = set()

        lines = []
        if os.path.exists(L2TP_ACTIVE_FILE):
            try:
                with open(L2TP_ACTIVE_FILE, "r") as f:
                    lines = f.readlines()
            except: pass

        file_info_map = {}
        for line in lines:
            try:
                p = line.strip().split(":")
                if len(p) == 2:
                    u, i = p[0].strip(), p[1].strip()
                    if u and i and i in all_iface_names:
                        file_info_map[i] = u
            except: pass

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
                    except: pass
                
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
                    except: pass
                    
                    if not username and pid > 0:
                        try:
                            with open(f"/proc/{pid}/cmdline", "rb") as f_cmd:
                                cmd_bytes = f_cmd.read()
                                args = cmd_bytes.replace(b'\x00', b' ').decode('utf-8', errors='ignore').split()
                                for i, arg in enumerate(args):
                                    if arg in ["name", "user"] and (i + 1 < len(args)):
                                        username = args[i+1]
                                        break
                                    if arg.startswith("name=") or arg.startswith("user="):
                                        username = arg.split("=", 1)[1]
                                        break
                        except: pass
                    
                    if username and pid > 0:
                        L2TP_SESSION_CACHE[iface] = {
                            'username': username,
                            'pid': pid,
                            'conn_time': conn_time
                        }

                if username:
                    processed_ifaces.add(iface)
                    rx, tx = 0, 0
                    try:
                        with open(f"/sys/class/net/{iface}/statistics/rx_bytes") as f: rx = int(f.read().strip() or 0)
                        with open(f"/sys/class/net/{iface}/statistics/tx_bytes") as f: tx = int(f.read().strip() or 0)
                    except: pass

                    sessions.append({
                        "username": username,
                        "protocol": "L2TP",
                        "ip": "Remote",
                        "v_ip": "10.10.x.x",
                        "bytes_received": rx,
                        "bytes_sent": tx,
                        "connected_at": conn_time,
                        "session_id": pid,
                    })

                    legacy_key = "L2TP/IPsec"
                    if username not in detailed_users: detailed_users[username] = {}
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

    def _wg1_load_peers_db(self):
        global WG1_DB_CACHE, WG1_DB_LAST_MTIME
        with WG1_DB_MUTEX:
            try:
                if not os.path.exists(WG1_PEERS_DB):
                    return {}
                
                current_mtime = os.stat(WG1_PEERS_DB).st_mtime
                
                if WG1_DB_CACHE and current_mtime == WG1_DB_LAST_MTIME:
                    return WG1_DB_CACHE

                with open(WG1_PEERS_DB, "r", encoding="utf-8") as f:
                    raw = f.read()
                
                if not raw.strip():
                    data = {}
                else:
                    data = json.loads(raw)
                
                data = data if isinstance(data, dict) else {}
                
                WG1_DB_CACHE = data
                WG1_DB_LAST_MTIME = current_mtime
                
                return data
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
            subprocess.run(
                ["systemctl", "restart", f"wg-quick@{WG1_IFACE}"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
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
                import re
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

    def _wg1_set_peer(self, pub_key, allowed_ips=None, preshared_key=None):
        if not pub_key:
            return False

        allowed_norm = None
        if allowed_ips:
            try:
                s = str(allowed_ips).strip()
                if s:
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
                    allowed_norm = ",".join(norm_parts) if norm_parts else None
            except Exception:
                allowed_norm = str(allowed_ips)

        cmd = ["wg", "set", WG1_IFACE, "peer", str(pub_key).strip()]
        if allowed_norm:
            cmd += ["allowed-ips", allowed_norm]

        tmp_psk = None
        try:
            if preshared_key:
                tmp_psk = tempfile.NamedTemporaryFile(mode="w", delete=False)
                tmp_psk.write(str(preshared_key).strip() + "\n")
                tmp_psk.flush()
                tmp_psk.close()
                cmd += ["preshared-key", tmp_psk.name]

            cp = subprocess.run(cmd, check=False, capture_output=True, text=True)
            return cp.returncode == 0
        finally:
            if tmp_psk is not None:
                try:
                    os.unlink(tmp_psk.name)
                except:
                    pass

    def _wg1_remove_peer(self, pub_key):
        if not pub_key:
            return False
        try:
            subprocess.run(
                ["wg", "set", WG1_IFACE, "peer", pub_key, "remove"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except:
            return False

    def _wg1_kick_peer(self, pub_key):
        if not pub_key:
            return False

        db = self._wg1_load_peers_db()
        info = None
        for u, d in (db or {}).items():
            try:
                if isinstance(d, dict) and d.get("public_key") == pub_key:
                    info = d
                    break
            except:
                pass

        self._wg1_remove_peer(pub_key)

        if isinstance(info, dict):
            try:
                if bool(info.get("disabled")):
                    return True
            except:
                pass

        if isinstance(info, dict):
            allowed = (
                info.get("allowed_ips")
                or info.get("allowed_ip")
                or info.get("allowed_ips_v4")
                or info.get("ip")
                or info.get("wg1_ip")
            )
            psk = info.get("preshared_key")
            self._wg1_set_peer(pub_key, allowed_ips=allowed, preshared_key=psk)
            return True

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
                        try:
                            if bool(udata.get("disabled")):
                                continue
                        except:
                            pass
                        pub_to_user[pub] = (uname, udata)
            except:
                pass

        try:
            res = subprocess.run(["wg", "show", WG1_IFACE, "dump"], capture_output=True, text=True)
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

                prev = WG1_PEER_ACTIVITY.get(pub_key)

                if prev is None:
                    WG1_PEER_ACTIVITY[pub_key] = {
                        'rx': int(rx),
                        'tx': int(tx),
                        'last_activity': 0.0,
                        'last_handshake': int(latest_handshake) if latest_handshake else 0
                    }
                    prev = WG1_PEER_ACTIVITY[pub_key]

                try:
                    prev_rx = int(prev.get('rx', 0) or 0)
                    prev_tx = int(prev.get('tx', 0) or 0)
                    prev_hs = int(prev.get('last_handshake', 0) or 0)
                except:
                    prev_rx, prev_tx, prev_hs = 0, 0, 0

                try:
                    rx_i = int(rx or 0)
                except:
                    rx_i = 0
                try:
                    tx_i = int(tx or 0)
                except:
                    tx_i = 0
                try:
                    hs_i = int(latest_handshake or 0)
                except:
                    hs_i = 0

                activity = False
                if rx_i > prev_rx:
                    activity = True

                if activity:
                    prev['last_activity'] = float(now_ts)

                prev['rx'] = rx_i
                prev['tx'] = tx_i
                prev['last_handshake'] = hs_i

                last_activity = float(prev.get('last_activity', 0) or 0)
                age = (float(now_ts) - last_activity) if last_activity else 10**9
                online = bool(age < WG1_TRAFFIC_TIMEOUT)
                real_ip = ""
                if online and endpoint:
                    if endpoint.startswith("[") and "]" in endpoint:
                        real_ip = endpoint.split("]")[0].lstrip("[")
                    elif ":" in endpoint:
                        real_ip = endpoint.split(":")[0]
                    else:
                        real_ip = endpoint

                wg_entry = {
                    "username": username,
                    "protocol": "WireGuard",
                    "online": online,
                    "is_active": online,
                    "ip": real_ip if online else "",
                    "v_ip": allowed_ips,
                    "bytes_received": rx,
                    "bytes_sent": tx,
                    "connected_at": int(last_activity) if online and last_activity else 0,
                    "session_id": pub_key,
                }
                if online:
                    sessions.append(wg_entry)

                if online:
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
        import fcntl
        import os

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

        return {
            "openvpn": {"installed": openvpn_installed, "active": bool(openvpn_any_active), "instances": openvpn_instances},
            "cisco": {"installed": ocserv_installed, "active": bool(cisco_unit.get("active")), "service": cisco_unit},
            "l2tp": {"installed": bool(l2tp_installed), "active": bool(l2tp_unit.get("active")), "service": l2tp_unit, "services": {"xl2tpd": l2tp_unit}},
            "wireguard": {"installed": wg_installed, "active": bool(wg_unit.get("active")), "service": wg_unit},
        }

    def do_GET(self):
        try:
            cpu, ram, disk = self._get_system_stats()

            detailed_users = {}
            sessions = []
            
            def get_openvpn():
                status_outputs, port_map = self._get_all_openvpn_statuses()
                return self._extract_openvpn_sessions(status_outputs, port_map, detailed_users)

            def get_l2tp():
                return self._extract_l2tp_sessions(detailed_users)

            def get_cisco():
                return self._extract_cisco_sessions(detailed_users)

            def get_wireguard():
                return self._extract_wg_sessions(detailed_users)

            with ThreadPoolExecutor(max_workers=4) as executor:
                future_ovpn = executor.submit(get_openvpn)
                future_l2tp = executor.submit(get_l2tp)
                future_cisco = executor.submit(get_cisco)
                future_wg = executor.submit(get_wireguard)

                sessions.extend(future_ovpn.result() or [])
                sessions.extend(future_l2tp.result() or [])
                sessions.extend(future_cisco.result() or [])
                sessions.extend(future_wg.result() or [])

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
                    "wireguard": {"iface": WG1_IFACE, "public_key": self._wg1_get_iface_public_key(), "listen_port": self._wg1_get_listen_port()},
                    "services": self._services_status(),
                    "openvpn_ports": self._get_openvpn_port_map(),
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

                if cmd0 in ("wg1_upload_conf", "upload_wg1_conf"):
                    wg_conf = data.get("content") if "content" in data else data.get("conf")
                    if wg_conf is not None:
                        ok = self._wg1_write_conf(wg_conf)
                        if ok and bool(data.get("restart", True)):
                            self._wg1_restart()
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
                                        try:
                                            self._wg1_remove_peer(pub)
                                        except:
                                            pass
                                        ok_peer = self._wg1_set_peer(pub, allowed_ips=allowed, preshared_key=psk)
                                        if ok_peer:
                                            info["disabled"] = False
                                            try:
                                                if allowed and not info.get("allowed_ips"):
                                                    info["allowed_ips"] = str(allowed).strip()
                                            except:
                                                pass
                                            self._wg1_save_peers_db(dbp)
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

                    elif cmd in ("wg1_upload_conf", "upload_wg1_conf"):
                        wg_conf = item.get("content")
                        if wg_conf is None:
                            wg_conf = item.get("conf")
                        if wg_conf is not None:
                            ok = self._wg1_write_conf(wg_conf)
                            if ok and bool(item.get("restart", True)):
                                self._wg1_restart()
                            success, msg = (ok, "WG1 config updated" if ok else "Failed to write WG1 config")
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
                            success, msg = (ok, "WG1 peers DB updated" if ok else "Failed to write WG1 peers DB")
                        else:
                            success, msg = False, "Missing/invalid peers_db"

                    elif cmd in ("wg1_peer_action", "wg1_set_peer"):
                        action = str(item.get("action") or "upsert").lower()
                        pub = item.get("public_key") or item.get("pub_key") or item.get("session_id")
                        allowed = item.get("allowed_ips") or item.get("v_ip")
                        psk = item.get("preshared_key")
                        uname_wg = (item.get("username") or "").strip()

                        dbp = self._wg1_load_peers_db()

                        if action in ("remove", "delete"):
                            ok = self._wg1_remove_peer(pub)

                            purge_db = False
                            try:
                                purge_db = bool(item.get("purge_db", False)) or (action == "delete")
                            except:
                                purge_db = (action == "delete")

                            if uname_wg:
                                try:
                                    if purge_db:
                                        dbp.pop(uname_wg, None)
                                    else:
                                        if uname_wg not in dbp or not isinstance(dbp.get(uname_wg), dict):
                                            if uname_wg in dbp and isinstance(dbp.get(uname_wg), str):
                                                dbp[uname_wg] = {"public_key": dbp.get(uname_wg)}
                                            else:
                                                dbp[uname_wg] = {}
                                        if isinstance(dbp.get(uname_wg), dict):
                                            if pub:
                                                dbp[uname_wg]["public_key"] = pub
                                            if allowed:
                                                dbp[uname_wg]["allowed_ips"] = allowed
                                            dbp[uname_wg]["disabled"] = True
                                    self._wg1_save_peers_db(dbp)
                                except:
                                    pass

                            success, msg = (ok, "WG1 peer removed" if ok else "Failed to remove peer")

                        elif action in ("kick", "kill"):
                            self._wg1_remove_peer(pub)
                            ok = True
                            if allowed or psk:
                                ok = self._wg1_set_peer(pub, allowed_ips=allowed, preshared_key=psk)
                            else:
                                ok = self._wg1_kick_peer(pub)
                            success, msg = (ok, "WG1 peer kicked" if ok else "Failed to kick peer")

                        else:
                            reset_first = False
                            try:
                                reset_first = bool(item.get("reset_first", False)) or (action == "add")
                            except:
                                reset_first = (action == "add")

                            if reset_first and pub:
                                try:
                                    self._wg1_remove_peer(pub)
                                except:
                                    pass

                            ok = self._wg1_set_peer(pub, allowed_ips=allowed, preshared_key=psk)

                            if ok and uname_wg and pub:
                                try:
                                    if uname_wg not in dbp or not isinstance(dbp.get(uname_wg), dict):
                                        dbp[uname_wg] = {}
                                    dbp[uname_wg]["public_key"] = pub
                                    dbp[uname_wg]["disabled"] = False
                                    if allowed:
                                        dbp[uname_wg]["allowed_ips"] = str(allowed).strip()
                                    if psk:
                                        dbp[uname_wg]["preshared_key"] = psk
                                    self._wg1_save_peers_db(dbp)
                                except:
                                    pass
                            success, msg = (ok, "WG1 peer updated" if ok else "Failed to set peer")

                    elif cmd in ("wg1_sync_peers", "wg1_bulk_sync"):
                        peers = item.get("peers")
                        remove_unknown = bool(item.get("remove_unknown", False))
                        ok = True

                        desired_pubs = set()
                        db = self._wg1_load_peers_db() or {}

                        if isinstance(peers, list):
                            for p in peers:
                                try:
                                    pub = p.get("public_key") or p.get("pub_key")
                                    uname_p = p.get("username")
                                    allowed = p.get("allowed_ips") or p.get("v_ip")
                                    psk = p.get("preshared_key")
                                    if not pub:
                                        continue
                                    desired_pubs.add(pub)
                                    self._wg1_set_peer(pub, allowed_ips=allowed, preshared_key=psk)

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
                                    r = subprocess.run(["wg", "show", WG1_IFACE, "peers"], capture_output=True, text=True)
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

                            success, msg = (ok, "WG1 peers synced" if ok else "WG1 peers sync completed with errors")
                        else:
                            success, msg = False, "Missing peers list"

                    elif cmd == "kill" or cmd == "kill_id":
                        uname = str(item.get("username") or "").strip()
                        sid = item.get("session_id")
                        proto = str(item.get("protocol") or "")
                        mgmt_port = item.get("mgmt_port")
                        
                        success = False
                        msg = "Init"

                        if sid:
                            try:
                                if "Cisco" in proto:
                                    subprocess.run([OCCTL_BIN, "disconnect", "id", str(sid)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                    success = True
                                    msg = "Killed Cisco ID"
                                elif "L2TP" in proto:
                                    os.kill(int(sid), 9)
                                    success = True
                                    msg = "Killed L2TP PID"
                                elif "OpenVPN" in proto:
                                    ports = [mgmt_port] if mgmt_port else self._get_all_management_ports()
                                    for p in ports:
                                        try:
                                            with socket.create_connection(("127.0.0.1", int(p)), timeout=2) as s:
                                                s.settimeout(2)
                                                s.recv(1024)
                                                s.sendall(f"client-kill {sid}\n".encode("utf-8"))
                                                s.recv(1024)
                                        except: pass
                                    success = True
                                    msg = "Killed OVPN CID"
                                elif "WireGuard" in proto or "WG" in proto:
                                    self._wg1_kick_peer(str(sid))
                                    success = True
                                    msg = "Kicked WG Peer"
                            except Exception as e:
                                success = False
                                msg = str(e)

                        if not success and uname:
                            try:
                                subprocess.run(["pkill", "-9", "-f", f"pppd.*name {uname}"], check=False)
                            except: pass

                            try:
                                if os.path.exists(OCCTL_BIN):
                                    subprocess.run([OCCTL_BIN, "disconnect", "user", str(uname)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            except: pass

                            try:
                                for port in self._get_all_management_ports():
                                    try:
                                        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                                            s.settimeout(2)
                                            s.recv(1024)
                                            s.sendall(f"kill {uname}\n".encode("utf-8"))
                                            s.recv(1024)
                                    except: pass
                            except: pass
                            
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
                            except: pass

                            try:
                                dbp = self._wg1_load_peers_db()
                                if uname in dbp:
                                    pub = (dbp.get(uname) or {}).get('public_key')
                                    if pub:
                                        self._wg1_kick_peer(pub)
                            except: pass
                            
                            success = True
                            msg = "Full Kill Sent"

                        results.append({"username": uname, "success": success, "message": msg})

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
                                    subprocess.run(["ufw", "allow", f"{p_int}/udp"], check=False, capture_output=True)
                            except:
                                pass

                            try:
                                self._wg1_restart()
                            except:
                                pass

                            success, msg = True, f"WireGuard (wg1) port updated to {p_int}"
                        else:
                            success, msg = False, "Missing port"

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

def run_server():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), StatusHandler)
    server.serve_forever()

if __name__ == "__main__":
    run_server()

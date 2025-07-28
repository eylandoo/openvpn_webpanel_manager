#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
APP_DIR="/root/wg-manager-pro"
LOG_DIR="/var/log/wgpanel"
SERVICE_NAME="wgpanel"
NGINX_CONF="/etc/nginx/sites-available/wgpanel"
FLASK_PORT=5001 # Internal port for Gunicorn

# --- Helper Functions ---
print_info() { echo -e "\033[34m[INFO]\033[0m $1"; }
print_success() { echo -e "\033[32m[SUCCESS]\033[0m $1"; }
print_error() { echo -e "\033[31m[ERROR]\033[0m $1" >&2; exit 1; }
print_warn() { echo -e "\033[33m[WARNING]\033[0m $1"; }

# --- Uninstaller Function ---
uninstall_panel() {
    print_warn "This will permanently delete the panel, its services, and ALL WireGuard configurations."
    read -p "Are you sure you want to continue? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Uninstallation cancelled."
        exit 0
    fi

    print_info "Stopping and disabling services..."
    systemctl stop $SERVICE_NAME nginx wg-quick@wg1 >/dev/null 2>&1 || true
    systemctl disable $SERVICE_NAME nginx wg-quick@wg1 >/dev/null 2>&1 || true

    print_info "Removing files and directories..."
    rm -f /etc/systemd/system/$SERVICE_NAME.service
    rm -f /etc/nginx/sites-available/wgpanel
    rm -f /etc/nginx/sites-enabled/wgpanel
    rm -rf $APP_DIR /etc/wg-manager $LOG_DIR /etc/wireguard

    print_info "Reloading systemd and Nginx..."
    systemctl daemon-reload
    systemctl restart nginx >/dev/null 2>&1 || true

    print_success "Uninstallation complete."
    exit 0
}

# --- Installer Function ---
install_panel() {
    print_info "Starting the Definitive WireGuard Panel installation..."

    IS_UBUNTU_24=false
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" && "$VERSION_ID" == "24.04" ]]; then
            IS_UBUNTU_24=true
            print_info "Ubuntu 24.04 detected. Using virtual environment for Python packages."
        fi
    fi

    print_info "Step 1: Panel Configuration"
    read -p "Enter the PUBLIC IP of THIS server: " MAIN_SERVER_IP
    if [[ -z "$MAIN_SERVER_IP" ]]; then print_error "The public IP cannot be empty."; fi
    PANEL_HOST=$MAIN_SERVER_IP

    read -p "Enter the public port for the web panel (e.g., 80): " PANEL_PORT; PANEL_PORT=${PANEL_PORT:-80}
    read -p "Enter a username for the panel login: " ADMIN_USER
    read -s -p "Enter a password for the panel login: " ADMIN_PASS; echo ""
    if [[ -z "$ADMIN_USER" || -z "$ADMIN_PASS" ]]; then print_error "Username and password cannot be empty."; fi
    
    print_info "Step 2: Installing System & Python Dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    
    APT_PACKAGES="python3-pip nginx wireguard-tools curl net-tools ufw"
    if [ "$IS_UBUNTU_24" = true ]; then APT_PACKAGES+=" python3-venv"; fi
    apt-get install -y $APT_PACKAGES || print_error "Failed to install system dependencies."

    print_info "Step 3: Setting up Application Environment..."
    mkdir -p $APP_DIR/templates
    
    if [ "$IS_UBUNTU_24" = true ]; then
        python3 -m venv "$APP_DIR/venv"
        "$APP_DIR/venv/bin/pip3" install --upgrade pip
        "$APP_DIR/venv/bin/pip3" install flask flask-login paramiko gunicorn werkzeug || print_error "Failed to install Python packages in venv."
    else
        pip3 install --upgrade pip
        pip3 install flask flask-login paramiko gunicorn werkzeug || print_error "Failed to install Python packages."
    fi
    
    mkdir -p /etc/wg-manager; mkdir -p /etc/wireguard; mkdir -p $LOG_DIR && chmod 755 $LOG_DIR
    echo '[]' > /etc/wireguard/peers.json; chmod 600 /etc/wireguard/peers.json
    
    SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
    echo "$SECRET_KEY" > /etc/wg-manager/secret.key; chmod 600 /etc/wg-manager/secret.key

    HASHED_PASS=$(python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('$ADMIN_PASS'))")
    echo "{\"username\": \"$ADMIN_USER\", \"password_hash\": \"$HASHED_PASS\"}" > /etc/wg-manager/auth.json; chmod 600 /etc/wg-manager/auth.json

    print_info "Step 4: Configuring Main WireGuard Server..."
    DEFAULT_IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    if [[ -z "$DEFAULT_IFACE" ]]; then print_error "Could not determine the default network interface."; fi
    MAIN_PRIV_KEY=$(wg genkey)
    cat << EOF > /etc/wireguard/wg1.conf
[Interface]
Address = 10.100.100.1/24
ListenPort = 6464
PrivateKey = $MAIN_PRIV_KEY
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_IFACE -j MASQUERADE
EOF
    chmod 600 /etc/wireguard/wg1.conf
    echo "$MAIN_SERVER_IP" > /etc/wireguard/iran_public_ip.txt
    
    print_info "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    sed -i '/net.ipv4.ip_forward=1/s/^#*//' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    
    print_info "Disabling firewall (UFW) on main server as requested..."
    ufw disable || true

    print_info "Starting main WireGuard interface..."
    systemctl enable --now wg-quick@wg1
    
    print_info "Step 5: Creating Application Files..."
    # worker.py
    cat << 'EOF' > $APP_DIR/worker.py
import sys, os, subprocess, json, re, time, paramiko, shlex, fcntl

LOG_DIR = "/var/log/wgpanel"
PEERS_FILE = "/etc/wireguard/peers.json"
WG_INTERFACE = "wg1"
CONFIG_FILE_PATH = "/etc/wireguard/wg1.conf"
IRAN_IP = "10.100.100.1"
WG_PORT = "6464"
IRAN_PUBLIC_IP_FILE = "/etc/wireguard/iran_public_ip.txt"

class Logger:
    def __init__(self, log_file_path): self.log_file = open(log_file_path, 'w')
    def log(self, message, is_error=False):
        prefix = "[ERROR]" if is_error else "[INFO]"
        full_message = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {prefix} {message}\n"
        print(full_message, end='')
        self.log_file.write(full_message)
        self.log_file.flush()
    def done(self, final_message=""): self.log_file.write(f"\n---DONE--- {final_message}\n"); self.log_file.close()
    def error(self, final_message): self.log(final_message, is_error=True); self.log_file.write(f"\n---ERROR--- {final_message}\n"); self.log_file.close()

def run_cmd(command, stdin_input=None):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True, input=stdin_input, executable='/bin/bash', timeout=60)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.strip() if e.stderr else e.stdout.strip()
        raise Exception(f"Command '{command[0:50]}...' failed: {error_output}")
    except Exception as e:
        raise Exception(f"Failed to run command '{command[0:50]}...': {str(e)}")

def ssh_exec(ip, port, user, password, command, logger, ignore_fail=False):
    logger.log(f"Executing on remote: {command}")
    try:
        ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=int(port), username=user, password=password, timeout=20)
        _, stdout, stderr = ssh.exec_command(command, timeout=300) 
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        ssh.close()
        message = f"Output: {output}" if output else ""; message += f"\nStderr: {error}" if error else ""
        if exit_status != 0 and not ignore_fail:
            logger.log(f"Remote command failed with exit code {exit_status}.\n{message}", is_error=True)
            raise Exception(f"Remote command failed. Stderr: {error}" if error else f"Remote command failed with exit code {exit_status}.")
        logger.log(f"Remote command successful.")
        return True, output
    except Exception as e: 
        if not ignore_fail: raise Exception(f"SSH connection or execution failed: {str(e)}")
        else: return False, str(e)

def get_iran_public_key():
    try:
        with open(f"/etc/wireguard/{WG_INTERFACE}.conf", 'r') as f: content = f.read()
        match = re.search(r"PrivateKey\s*=\s*(\S+)", content)
        if not match: raise Exception("Could not find PrivateKey in local wg1.conf")
        return run_cmd(f"echo '{match.group(1).strip()}' | wg pubkey")
    except Exception as e:
        raise Exception(f"Could not get main server public key: {str(e)}")

def get_full_config(peer_data, logger):
    try:
        with open(IRAN_PUBLIC_IP_FILE, 'r') as f: iran_public_ip = f.read().strip()
    except FileNotFoundError: raise Exception("Main server public IP file not found.")
    if not iran_public_ip: raise Exception("Main server public IP is empty.")
    
    iran_pub_key = get_iran_public_key()
    
    success, remote_iface = ssh_exec(peer_data['public_ip'], peer_data['ssh_port'], peer_data['ssh_user'], peer_data['ssh_pass'], "ip -4 route ls | grep default | grep -Po '(?<=dev )(\\S+)' | head -1", logger)
    if not remote_iface:
        raise Exception("Could not detect default network interface on remote server.")

    post_up_down = f"PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {remote_iface} -j MASQUERADE\\nPostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {remote_iface} -j MASQUERADE"
    return f"[Interface]\\nAddress = {peer_data['ip']}/24\\nPrivateKey = {peer_data['privkey']}\\n{post_up_down}\\n\\n[Peer]\\nPublicKey = {iran_pub_key}\\nPresharedKey = {peer_data['psk']}\\nAllowedIPs = {IRAN_IP}/32\\nEndpoint = {iran_public_ip}:{WG_PORT}\\nPersistentKeepalive = 25\\n"

def main():
    if len(sys.argv) < 2: sys.exit(1)
    public_ip = sys.argv[1]
    log_file_path = os.path.join(LOG_DIR, f"{public_ip}.log")
    logger = Logger(log_file_path)
    
    try:
        logger.log("Installation process started for peer.")
        
        with open(PEERS_FILE, 'r+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                peers = json.load(f)
                peer_data = next((p for p in peers if p.get('public_ip') == public_ip), None)
                if not peer_data: raise Exception(f"Peer with IP {public_ip} not found in peers file.")
                used_ips = {int(p['ip'].split('.')[-1]) for p in peers if p.get('ip')}
                next_ip_suffix = 2
                while next_ip_suffix in used_ips: next_ip_suffix += 1
                peer_data['ip'] = f"10.100.100.{next_ip_suffix}"
                logger.log(f"Assigned private IP: {peer_data['ip']}")
                logger.log("Generating cryptographic keys...")
                peer_data["privkey"] = run_cmd("wg genkey")
                peer_data["psk"] = run_cmd("wg genpsk")
                peer_data["pubkey"] = run_cmd(f"echo '{peer_data['privkey']}' | wg pubkey")
                if not all([peer_data["privkey"], peer_data["psk"], peer_data["pubkey"]]):
                    raise Exception("Failed to generate one or more WireGuard keys.")
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

        ssh_creds = (peer_data['public_ip'], peer_data['ssh_port'], peer_data['ssh_user'], peer_data['ssh_pass'])
        
        cleanup_cmd = f"systemctl stop wg-quick@wg1 >/dev/null 2>&1 || true; ip link delete dev {WG_INTERFACE} >/dev/null 2>&1 || true; rm -f {CONFIG_FILE_PATH}"
        logger.log("Step 1/6: Cleaning up old configs and interfaces on remote server..."); ssh_exec(*ssh_creds, cleanup_cmd, logger)
        
        logger.log("Step 2/6: Updating package lists on remote server..."); ssh_exec(*ssh_creds, "export DEBIAN_FRONTEND=noninteractive; apt-get update -y", logger)
        logger.log("Step 3/6: Installing dependencies on remote server..."); ssh_exec(*ssh_creds, "export DEBIAN_FRONTEND=noninteractive; apt-get install -y wireguard-tools ufw", logger)
        
        logger.log("Step 4/6: Disabling firewall (UFW) on remote server as requested...")
        ssh_exec(*ssh_creds, "ufw disable", logger, ignore_fail=True)
        
        logger.log("Step 5/6: Writing configuration and enabling IP forwarding on remote server...")
        remote_cfg = get_full_config(peer_data, logger)
        write_config_cmd = f"echo -e {shlex.quote(remote_cfg)} | tee {CONFIG_FILE_PATH} > /dev/null && chmod 600 {CONFIG_FILE_PATH} && sysctl -w net.ipv4.ip_forward=1 && sed -i '/net.ipv4.ip_forward=1/s/^#*//' /etc/sysctl.conf"
        ssh_exec(*ssh_creds, write_config_cmd, logger)
        
        logger.log("Step 6/6: Starting WireGuard service on remote server...")
        try:
            ssh_exec(*ssh_creds, f"systemctl enable --now wg-quick@wg1", logger)
        except Exception as e:
            logger.log("!!! Service start failed. Automatically gathering diagnostics...", is_error=True)
            _, status_output = ssh_exec(*ssh_creds, "systemctl status wg-quick@wg1.service --no-pager -l", logger, ignore_fail=True)
            logger.log(f"\n--- [DIAGNOSTICS] systemctl status wg-quick@wg1 ---\n{status_output}\n-------------------------------------------------\n")
            _, journal_output = ssh_exec(*ssh_creds, "journalctl -xeu wg-quick@wg1.service --no-pager -n 50", logger, ignore_fail=True)
            logger.log(f"\n--- [DIAGNOSTICS] journalctl -xeu wg-quick@wg1 ---\n{journal_output}\n------------------------------------------------\n")
            raise Exception(f"Failed to start wg-quick@wg1 service. See diagnostic logs above.")
        
        logger.log("Configuring peer on local server...")
        run_cmd(f"wg set {WG_INTERFACE} peer \"{peer_data['pubkey']}\" allowed-ips \"{peer_data['ip']}/32\" preshared-key /dev/stdin", stdin_input=peer_data['psk'])
        logger.log("Saving configuration permanently...")
        run_cmd(f"wg-quick save {WG_INTERFACE}")
        
        logger.log("Verifying connection (Step 1/2: Handshake)...")
        handshake_found = False
        for i in range(5):
            time.sleep(3)
            if run_cmd(f"wg show {WG_INTERFACE} latest-handshakes | grep -w \"{peer_data['pubkey']}\""):
                handshake_found = True; break
            logger.log(f"Waiting for handshake... (Attempt {i+1}/5)")
        
        if not handshake_found:
            logger.log("Handshake NOT detected. Rolling back...", is_error=True)
            run_cmd(f"wg set {WG_INTERFACE} peer \"{peer_data['pubkey']}\" remove")
            run_cmd(f"wg-quick save {WG_INTERFACE}")
            raise Exception("Handshake timeout. Connection failed. Check network connectivity. Peer rolled back.")
        
        logger.log("Handshake successful! Verifying connection (Step 2/2: Ping)...")
        try:
            run_cmd(f"ping -c 3 -W 5 {peer_data['ip']}")
            logger.log("Ping successful! End-to-end connection is truly Active.")
        except Exception as e:
            logger.log("Ping test FAILED. Rolling back...", is_error=True)
            run_cmd(f"wg set {WG_INTERFACE} peer \"{peer_data['pubkey']}\" remove")
            run_cmd(f"wg-quick save {WG_INTERFACE}")
            raise Exception("Ping failed. Handshake OK, but data packets are blocked. Check FORWARD rules in iptables on the remote server.")

        peer_data['state'] = 'installed'
        
        with open(PEERS_FILE, 'r+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                peers = json.load(f)
                for i, p in enumerate(peers):
                    if p.get('public_ip') == peer_data['public_ip']: peers[i] = peer_data; break
                f.seek(0); json.dump(peers, f, indent=2); f.truncate()
                f.flush(); os.fsync(f.fileno())
            finally: fcntl.flock(f, fcntl.LOCK_UN)

        logger.done("Installation successful!")
    except Exception as e:
        logger.error(f"FATAL: {str(e)}")

if __name__ == "__main__": main()
EOF

    # app.py
    cat << 'EOF' > $APP_DIR/app.py
import os, subprocess, json, re, fcntl
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import check_password_hash
import paramiko

app = Flask(__name__)

SECRET_KEY_FILE = "/etc/wg-manager/secret.key"
try:
    with open(SECRET_KEY_FILE, 'r') as f: app.config['SECRET_KEY'] = f.read().strip()
except Exception as e:
    raise RuntimeError(f"Could not load SECRET_KEY from {SECRET_KEY_FILE}. Reinstall panel. Error: {e}")

login_manager = LoginManager(); login_manager.init_app(app); login_manager.login_view = 'login'

WG_INTERFACE = "wg1"; PEERS_FILE = "/etc/wireguard/peers.json"; AUTH_FILE = "/etc/wg-manager/auth.json"
LOG_DIR = "/var/log/wgpanel"; APP_DIR = "/root/wg-manager-pro"; IRAN_PUBLIC_IP_FILE = "/etc/wireguard/iran_public_ip.txt"

class User(UserMixin):
    def __init__(self, id, username, password_hash): self.id, self.username, self.password_hash = id, username, password_hash
    @staticmethod
    def get(user_id):
        try:
            with open(AUTH_FILE, 'r') as f: auth_data = json.load(f)
            if user_id == auth_data['username']: return User(id=auth_data['username'], username=auth_data['username'], password_hash=auth_data['password_hash'])
        except: return None

@login_manager.user_loader
def load_user(user_id): return User.get(user_id)

def run_cmd(command, check=True):
    try:
        return subprocess.run(command, shell=True, check=check, capture_output=True, text=True, executable='/bin/bash', timeout=5)
    except: return None

def load_peers():
    try:
        with open(PEERS_FILE, 'r') as f:
            fcntl.flock(f, fcntl.LOCK_SH); peers = json.load(f); fcntl.flock(f, fcntl.LOCK_UN)
            return peers
    except: return []

def save_peers(peers_data):
    with open(PEERS_FILE, 'w') as f:
        fcntl.flock(f, fcntl.LOCK_EX); json.dump(peers_data, f, indent=2); f.flush()
        os.fsync(f.fileno()); fcntl.flock(f, fcntl.LOCK_UN)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.get(request.form['username'])
        if user and check_password_hash(user.password_hash, request.form['password']):
            login_user(user); return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout(): logout_user(); return redirect(url_for('login'))

@app.route('/')
@login_required
def index(): return render_template('dashboard.html')

@app.route('/api/data')
@login_required
def api_data():
    all_peers = load_peers()
    main_ip, main_private_ip = "Not Set", "Not Set"
    try:
        with open(IRAN_PUBLIC_IP_FILE, 'r') as f: main_ip = f.read().strip()
    except: pass
    try:
        with open(f"/etc/wireguard/{WG_INTERFACE}.conf", 'r') as f:
            for line in f:
                if line.strip().lower().startswith("address"):
                    main_private_ip = line.split('=')[1].strip().split('/')[0]
                    break
    except: pass
        
    peers_data = [{k: v for k, v in p.items() if k not in ['ssh_pass', 'privkey', 'psk']} for p in all_peers]
    return jsonify({'peers': peers_data, 'main_server_ip': main_ip, 'main_server_private_ip': main_private_ip})

@app.route('/api/ping/<private_ip>')
@login_required
def ping_peer(private_ip):
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", private_ip):
        return jsonify({'status': 'error', 'message': 'Invalid IP format'}), 400
    peers = load_peers()
    if not any(p.get('ip') == private_ip for p in peers):
        return jsonify({'status': 'error', 'message': 'Unknown peer'}), 404

    result = run_cmd(f"ping -c 1 -W 2 {private_ip}", check=False)
    return jsonify({'status': 'Online'}) if result and result.returncode == 0 else jsonify({'status': 'Offline'})

@app.route('/api/restart_peer', methods=['POST'])
@login_required
def restart_peer():
    public_ip = request.json.get('public_ip')
    if not public_ip: return jsonify({'message': 'Public IP is required'}), 400
    
    peers = load_peers()
    peer = next((p for p in peers if p.get('public_ip') == public_ip), None)
    if not peer: return jsonify({'message': 'Peer not found.'}), 404

    try:
        run_cmd("systemctl restart wg-quick@wg1")
        
        ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(peer['public_ip'], port=int(peer['ssh_port']), username=peer['ssh_user'], password=peer['ssh_pass'], timeout=20)
        _, stdout, stderr = ssh.exec_command("systemctl restart wg-quick@wg1")
        if stdout.channel.recv_exit_status() != 0:
            raise Exception(f"Failed to restart remote service: {stderr.read().decode()}")
        ssh.close()
        
        return jsonify({'message': 'Restart signal sent to both servers successfully.'})
    except Exception as e:
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500

@app.route('/api/verify_and_add', methods=['POST'])
@login_required
def verify_and_add():
    data = request.json; ip, port, user, password = data['f_ip'], data['s_port'], data['s_user'], data['s_pass']
    peers = load_peers()
    if any(p['public_ip'] == ip for p in peers): return jsonify({'message': 'A peer with this public IP already exists.'}), 400
    try:
        ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=int(port), username=user, password=password, timeout=20); ssh.close()
    except Exception as e: return jsonify({'message': f'SSH connection failed: {e}'}), 500
    new_peer = {"public_ip": ip, "ssh_port": port, "ssh_user": user, "ssh_pass": password, "state": "pending"}
    peers.append(new_peer); save_peers(peers)
    return jsonify({'message': 'SSH verified. Peer added in "Pending" state.'})

@app.route('/api/install', methods=['POST'])
@login_required
def install_peer():
    public_ip = request.json.get('public_ip')
    if not public_ip: return jsonify({'message': 'Public IP is required'}), 400
    log_file = os.path.join(LOG_DIR, f"{public_ip}.log")
    if os.path.exists(log_file): os.remove(log_file)
    python_executable = f'{APP_DIR}/venv/bin/python3' if os.path.exists(f'{APP_DIR}/venv/bin/python3') else '/usr/bin/python3'
    command = [python_executable, f'{APP_DIR}/worker.py', public_ip]
    subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return jsonify({'status': 'started'})

@app.route('/api/log/<path:public_ip>')
@login_required
def get_log(public_ip):
    if not re.match(r"^[0-9a-zA-Z\.:-]+$", public_ip): return jsonify({"status": "error", "log": "Invalid characters in IP address."}), 400
    log_file_path = os.path.join(LOG_DIR, f"{public_ip}.log")
    if not os.path.exists(log_file_path): return jsonify({'status': 'running', 'log': 'Waiting for process to start...'})
    with open(log_file_path, 'r') as f: content = f.read()
    status = 'running'
    if '---DONE---' in content: status = 'done'
    elif '---ERROR---' in content: status = 'error'
    return jsonify({'status': status, 'log': content})

@app.route('/peers/remove', methods=['POST'])
@login_required
def remove_peer():
    public_ip = request.json.get('public_ip')
    if not public_ip: return jsonify({'message': 'Public IP is required.'}), 400
    peers = load_peers()
    peer = next((p for p in peers if p.get('public_ip') == public_ip), None)
    if not peer: return jsonify({'message': 'Peer not found.'}), 404
    
    new_peers_list = [p for p in peers if p.get('public_ip') != public_ip]
    
    if peer.get('state') == 'installed':
        try:
            run_cmd(f"wg set {WG_INTERFACE} peer \"{peer['pubkey']}\" remove")
            run_cmd(f"wg-quick save {WG_INTERFACE}")
            ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(peer['public_ip'], port=int(peer['ssh_port']), username=peer['ssh_user'], password=peer['ssh_pass'], timeout=20)
            ssh.exec_command("systemctl stop wg-quick@wg1 >/dev/null 2>&1; systemctl disable wg-quick@wg1 >/dev/null 2>&1; rm -f /etc/wireguard/wg1.conf")
            ssh.close()
        except Exception as e:
            save_peers(new_peers_list)
            return jsonify({'message': f'Peer removed locally, but could not clean up remote server: {e}'}), 500
    
    save_peers(new_peers_list)
    return jsonify({'message': 'Peer removed successfully.'})

if __name__ == '__main__': app.run(host='127.0.0.1', port=int(os.environ.get("FLASK_PORT", 5001)))
EOF

    cat << 'EOF' > $APP_DIR/templates/dashboard.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WG Panel Ultimate</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes toastIn { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes toastOut { from { opacity: 1; transform: translateY(0); } to { opacity: 0; transform: translateY(-20px); } }
        .fade-in { animation: fadeIn 0.5s ease-out forwards; }
        [x-cloak] { display: none !important; }
        .glass-card { background: rgba(31, 41, 55, 0.5); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .status-badge .dot { width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
        .log-step { display: flex; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid #374151; transition: all 0.3s ease; }
        .log-step.status-success { color: #4ade80; } .log-step.status-error { color: #f87171; }
        .log-step.status-pending { color: #9ca3af; } .log-step.status-running { color: #60a5fa; }
        .log-step-icon { width: 24px; height: 24px; margin-right: 1rem; }
    </style>
</head>
<body class="bg-gray-900 text-gray-200" x-data="wireguardManager()" x-cloak>
    
    <div class="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-gray-900 to-black -z-10"></div>

    <div x-show="notification.show" 
         class="fixed top-5 right-5 z-[100] flex items-center p-4 max-w-sm text-white rounded-lg shadow-lg glass-card"
         :class="{ 'border-green-400': notification.type === 'success', 'border-red-400': notification.type === 'error' }"
         x-transition:enter="toastIn 0.3s ease-out" x-transition:leave="toastOut 0.3s ease-in">
        <div x-text="notification.message"></div>
        <button @click="notification.show = false" class="ml-4 text-xl">&times;</button>
    </div>

    <div class="container mx-auto p-4 md:p-8">
        <header class="flex flex-col sm:flex-row justify-between items-center mb-8 pb-4 border-b border-gray-700/50">
            <h1 class="text-3xl font-bold flex items-center mb-4 sm:mb-0 text-white">
                <svg class="w-8 h-8 mr-3 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                WG Panel Ultimate
            </h1>
            <div class="flex items-center space-x-4"><div class="text-right"><div class="text-xs text-gray-400">Main Server (Public / Private)</div><div class="font-mono text-sm"><span x-text="mainServerIp"></span> / <span x-text="mainServerPrivateIp"></span></div></div><a href="/logout" class="text-gray-400 hover:text-white transition" title="Logout"><i class="bi bi-box-arrow-right text-2xl"></i></a></div>
        </header>

        <main>
            <div class="flex justify-end mb-6"><button @click="modals.addPeer = true" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg transition flex items-center shadow-lg transform hover:scale-105"><i class="bi bi-plus-circle mr-2"></i> Add New Server</button></div>
            <div x-show="peers.length === 0" class="text-center text-gray-500 py-16 fade-in"><i class="bi bi-hdd-network text-6xl mb-4"></i><p>No foreign servers have been added yet.</p></div>
            <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                <template x-for="(peer, index) in peers" :key="peer.public_ip">
                    <div class="glass-card rounded-xl shadow-lg p-5 flex flex-col justify-between hover:border-blue-400 transition fade-in" :style="`animation-delay: ${index * 100}ms`">
                        <div>
                            <div class="flex justify-between items-start mb-4"><div><p class="text-xs text-gray-400">Public IP</p><p class="font-bold text-lg font-mono text-white" x-text="peer.public_ip"></p></div><div class="flex items-center text-xs font-semibold px-2 py-1 rounded-full" :class="{ 'bg-green-500/10 text-green-400': peer.status === 'Online', 'bg-red-500/10 text-red-400': peer.status === 'Offline', 'bg-yellow-500/10 text-yellow-400': peer.status === 'Pending', 'bg-blue-500/10 text-blue-400': peer.status === 'Pinging...' }"><span class="dot" :class="{ 'bg-green-400': peer.status === 'Online', 'bg-red-400': peer.status === 'Offline', 'bg-yellow-400': peer.status === 'Pending', 'bg-blue-400 animate-pulse': peer.status === 'Pinging...' }"></span><span x-text="peer.status"></span></div></div>
                            <p class="text-xs text-gray-400">Private IP</p><p class="font-mono bg-gray-900/50 inline-block px-2 py-1 rounded" x-text="peer.ip || 'N/A'"></p>
                        </div>
                        <div class="mt-6 flex justify-end items-center space-x-2 border-t border-gray-700/50 pt-4">
                            <template x-if="peer.state === 'installed'"><button @click="showConfirm('Restart Connection?', `This will restart the WireGuard service on both the main server and ${peer.public_ip}.`, () => restartPeer(peer))" :disabled="peer.restarting" class="text-gray-400 hover:text-blue-400 transition p-2 rounded-full disabled:opacity-50 disabled:cursor-not-allowed" title="Restart Connection"><svg x-show="peer.restarting" class="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg><i x-show="!peer.restarting" class="bi bi-arrow-repeat text-xl"></i></button></template>
                            <template x-if="peer.state === 'pending'"><button @click="installPeer(peer)" class="text-gray-400 hover:text-green-400 transition p-2 rounded-full" title="Install"><i class="bi bi-download text-xl"></i></button></template>
                            <button @click="showConfirm('Remove Peer?', `This will permanently remove ${peer.public_ip} and its configuration. This action cannot be undone.`, () => removePeer(peer))" class="text-gray-400 hover:text-red-400 transition p-2 rounded-full" title="Remove"><i class="bi bi-trash text-xl"></i></button>
                        </div>
                    </div>
                </template>
            </div>
        </main>
    </div>

    <div x-show="confirmModal.show" @keydown.escape.window="confirmModal.show = false" class="fixed inset-0 z-50 flex items-center justify-center p-4" x-cloak>
        <div @click="confirmModal.show = false" class="fixed inset-0 bg-black/70 backdrop-blur-sm"></div>
        <div class="glass-card rounded-xl shadow-lg p-6 w-full max-w-sm z-20">
            <h3 class="text-lg font-bold mb-2 text-white" x-text="confirmModal.title"></h3>
            <p class="text-gray-300 mb-6" x-text="confirmModal.message"></p>
            <div class="flex justify-end items-center"><button @click="confirmModal.show = false" class="bg-gray-600/50 hover:bg-gray-500/50 text-white px-4 py-2 rounded-lg mr-2 transition">Cancel</button><button @click="confirmModal.onConfirm(); confirmModal.show = false;" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition">Confirm</button></div>
        </div>
    </div>
    
    <div x-show="modals.log" @keydown.escape.window="closeLogModal()" class="fixed inset-0 z-50 flex items-center justify-center p-4" x-cloak>
        <div @click="closeLogModal()" class="fixed inset-0 bg-black/70 backdrop-blur-sm"></div><div class="bg-gray-800 rounded-lg shadow-xl w-full max-w-2xl z-20 border border-gray-700 max-h-[90vh] flex flex-col"><div class="flex justify-between items-center p-4 border-b border-gray-700"><h5 class="font-bold text-white" x-text="`Installation on ${log.peerIp}`"></h5><button @click="closeLogModal()" class="text-gray-400 hover:text-white">&times;</button></div><div class="p-6 overflow-y-auto"><ul><template x-for="step in log.steps" :key="step.id"><li class="log-step" :class="`status-${step.status}`"><div class="log-step-icon" x-html="getStepIcon(step.status)"></div><span class="font-semibold" x-text="step.text"></span></li></template></ul></div><div class="p-4 border-t border-gray-700"><button @click="log.showRaw = !log.showRaw" class="text-xs text-gray-400 hover:text-white">Toggle Raw Log</button><div x-show="log.showRaw" x-collapse><pre class="mt-2 text-xs bg-black p-2 rounded max-h-48 overflow-y-auto" x-text="log.rawOutput"></pre></div></div></div>
    </div>
    <div x-show="modals.addPeer" @keydown.escape.window="modals.addPeer = false" class="fixed inset-0 z-50 flex items-center justify-center p-4" x-cloak>
        <div @click="modals.addPeer = false" class="fixed inset-0 bg-black/70 backdrop-blur-sm"></div><div class="glass-card rounded-xl shadow-lg p-6 w-full max-w-md z-20"><h3 class="text-lg font-bold mb-4 text-white">Add & Verify Server</h3><div x-show="addForm.error" class="bg-red-500/20 border border-red-500 text-red-300 p-3 rounded mb-4" x-text="addForm.error"></div><form @submit.prevent="verifyAndAddPeer"><div class="mb-3"><label class="block text-sm text-gray-300">Foreign IP</label><input type="text" x-model="addForm.f_ip" class="w-full bg-gray-900/50 border border-gray-600 rounded p-2 mt-1 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div class="mb-3"><label class="block text-sm text-gray-300">SSH Port</label><input type="number" x-model="addForm.s_port" class="w-full bg-gray-900/50 border border-gray-600 rounded p-2 mt-1 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div class="mb-3"><label class="block text-sm text-gray-300">SSH User</label><input type="text" x-model="addForm.s_user" class="w-full bg-gray-900/50 border border-gray-600 rounded p-2 mt-1 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div class="mb-3"><label class="block text-sm text-gray-300">SSH Pass</label><input type="password" x-model="addForm.s_pass" class="w-full bg-gray-900/50 border border-gray-600 rounded p-2 mt-1 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required></div><div class="flex justify-end items-center mt-4"><button type="button" @click="modals.addPeer = false" class="bg-gray-600/50 hover:bg-gray-500/50 text-white px-4 py-2 rounded-lg mr-2 transition">Cancel</button><button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center transition" :class="{'opacity-50': addForm.loading}" :disabled="addForm.loading"><span x-show="addForm.loading" class="animate-spin spinner mr-2 inline-block w-4 h-4 border-2 rounded-full"></span>Verify & Add</button></div></form></div>
    </div>
    
    <script>
    document.addEventListener('alpine:init', () => {
        Alpine.data('wireguardManager', () => ({
            peers: [], mainServerIp: '...', mainServerPrivateIp: '...',
            modals: { addPeer: false, log: false },
            addForm: { f_ip: '', s_port: 22, s_user: 'root', s_pass: '', loading: false, error: '' },
            log: { peerIp: '', poller: null, rawOutput: '', showRaw: false, steps: [] },
            notification: { show: false, message: '', type: 'success' },
            confirmModal: { show: false, title: '', message: '', onConfirm: () => {} },
            
            init() { this.fetchData(); },

            showNotification(message, type = 'success', duration = 4000) { this.notification.message = message; this.notification.type = type; this.notification.show = true; setTimeout(() => this.notification.show = false, duration); },
            showConfirm(title, message, onConfirmCallback) { this.confirmModal.title = title; this.confirmModal.message = message; this.confirmModal.onConfirm = onConfirmCallback; this.confirmModal.show = true; },

            async apiRequest(url, method = 'GET', body = null) {
                try {
                    const res = await fetch(url, { method, headers: body ? {'Content-Type': 'application/json'} : {}, body: body ? JSON.stringify(body) : null });
                    if (res.status === 401) { window.location.reload(); throw new Error("Session expired."); }
                    // Try to parse JSON, if it fails, throw an error with the text content
                    const text = await res.text();
                    const data = text ? JSON.parse(text) : {};
                    if (!res.ok) { throw new Error(data.message || `An unknown error occurred (Status: ${res.status}).`); }
                    return data;
                } catch (error) {
                    throw error instanceof Error ? error : new Error("An unknown network or parsing error occurred.");
                }
            },
            
            async fetchData() { try { const data = await this.apiRequest('/api/data'); this.peers = data.peers.map(p => ({...p, status: p.state === 'installed' ? 'Pinging...' : 'Pending', restarting: false})); this.mainServerIp = data.main_server_ip; this.mainServerPrivateIp = data.main_server_private_ip; this.updateAllPingStatus(); } catch (e) { this.showNotification(e.message, 'error'); } },
            async updateAllPingStatus() { this.peers.filter(p => p.state === 'installed' && p.ip).forEach(p => { this.apiRequest(`/api/ping/${p.ip}`).then(data => { const peer = this.peers.find(i => i.ip === p.ip); if(peer) peer.status = data.status; }).catch(() => { const peer = this.peers.find(i => i.ip === p.ip); if(peer) peer.status = 'Offline'; }); }); },
            
            async restartPeer(peer) {
                if(peer.restarting) return;
                peer.restarting = true;
                peer.status = 'Pinging...';
                try {
                    const data = await this.apiRequest('/api/restart_peer', 'POST', { public_ip: peer.public_ip });
                    this.showNotification(data.message, 'success');
                    setTimeout(() => this.updateAllPingStatus(), 3000); 
                } catch (e) { this.showNotification('Error: ' + e.message, 'error'); this.fetchData();
                } finally { setTimeout(() => { const p = this.peers.find(i => i.public_ip === peer.public_ip); if(p) p.restarting = false; }, 3000); }
            },

            async verifyAndAddPeer() {
                this.addForm.loading = true; this.addForm.error = '';
                try {
                    const data = await this.apiRequest('/api/verify_and_add', 'POST', this.addForm);
                    this.showNotification(data.message, 'success');
                    this.modals.addPeer = false; this.addForm = { f_ip: '', s_port: 22, s_user: 'root', s_pass: '', loading: false, error: '' };
                    this.fetchData();
                } catch (e) { this.addForm.error = e.message; } finally { this.addForm.loading = false; }
            },
            
            async removePeer(peer) {
                try {
                    const data = await this.apiRequest('/peers/remove', 'POST', { public_ip: peer.public_ip });
                    this.showNotification(data.message, 'success');
                    this.fetchData();
                } catch(e) { this.showNotification('Error: ' + e.message, 'error'); }
            },

            installPeer(peer) {
                this.log.peerIp = peer.public_ip; this.log.steps = [ { id: 1, text: 'Cleaning up remote server', status: 'pending', keyword: 'Step 1/6' }, { id: 2, text: 'Installing dependencies', status: 'pending', keyword: 'Step 3/6' }, { id: 3, text: 'Writing configuration', status: 'pending', keyword: 'Step 5/6' }, { id: 4, text: 'Starting remote service', status: 'pending', keyword: 'Step 6/6' }, { id: 5, text: 'Verifying handshake', status: 'pending', keyword: 'Handshake successful' }, { id: 6, text: 'Verifying data transfer (Ping)', status: 'pending', keyword: 'Ping successful' } ];
                this.log.rawOutput = 'Requesting installation start...'; this.modals.log = true;
                this.apiRequest('/api/install', 'POST', { public_ip: peer.public_ip }).then(() => this.log.poller = setInterval(() => this.fetchLog(peer.public_ip), 2000)).catch(e => { this.log.rawOutput += `\n[ERROR] Start failed: ${e.message}`; this.showNotification(e.message, 'error'); });
            },
            
            async fetchLog(public_ip) {
                try {
                    const data = await this.apiRequest(`/api/log/${public_ip}`); this.log.rawOutput = data.log; let currentStep = -1;
                    this.log.steps.forEach((step, i) => { if (step.status !== 'success') { if (data.log.includes(step.keyword)) { step.status = 'success'; currentStep = i; } } });
                    if(currentStep > -1 && currentStep + 1 < this.log.steps.length){ this.log.steps[currentStep + 1].status = 'running'; } 
                    else if (this.log.steps[0].status === 'pending' && data.log.includes('Step 1/6')) { this.log.steps[0].status = 'running'; }
                    if (data.status === 'done') { this.log.steps.forEach(s => s.status = 'success'); setTimeout(() => this.closeLogModal(), 1500);
                    } else if (data.status === 'error') { const runningStep = this.log.steps.find(s => s.status === 'running'); if(runningStep) runningStep.status = 'error'; clearInterval(this.log.poller); this.log.poller = null; }
                } catch (e) {
                    this.log.rawOutput += "\n\nError fetching log."; const runningStep = this.log.steps.find(s => s.status === 'running'); if(runningStep) runningStep.status = 'error'; clearInterval(this.log.poller); this.log.poller = null;
                }
            },
            
            closeLogModal() { if (this.log.poller) clearInterval(this.log.poller); this.log.poller = null; this.modals.log = false; this.fetchData(); },
            getStepIcon(status) { if (status === 'running') return `<svg class="animate-spin text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>`; if (status === 'success') return `<svg class="text-green-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>`; if (status === 'error') return `<svg class="text-red-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>`; return `<svg class="text-gray-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><circle cx="12" cy="12" r="10" stroke-width="2" class="stroke-current opacity-50" /><path d="M12,2 a10,10 0 0,0 0,20" class="stroke-current" /></svg>`; }
        }));
    });
    </script>
</body>
</html>
EOF

    cat << 'EOF' > $APP_DIR/templates/login.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - WG Panel Ultimate</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 flex items-center justify-center min-h-screen">
    <div class="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-gray-900 to-black -z-10"></div>
    <div class="bg-gray-800/50 backdrop-filter backdrop-blur-lg border border-gray-700 p-8 rounded-xl shadow-2xl w-full max-w-sm">
        <div class="flex justify-center mb-6">
             <svg class="w-16 h-16 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
        </div>
        <h2 class="text-2xl font-bold text-white text-center mb-6">Panel Login</h2>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                <div class="bg-red-500/80 border border-red-400 text-white p-3 rounded mb-4 text-center">{{ messages[0] }}</div>
            {% endif %}
        {% endwith %}
        <form method="POST" action="/login">
            <div class="mb-4">
                <label for="username" class="block text-gray-300 mb-2">Username</label>
                <input type="text" name="username" id="username" class="w-full bg-gray-900/70 text-white rounded-lg p-3 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 transition" required>
            </div>
            <div class="mb-6">
                <label for="password" class="block text-gray-300 mb-2">Password</label>
                <input type="password" name="password" id="password" class="w-full bg-gray-900/70 text-white rounded-lg p-3 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 transition" required>
            </div>
            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg transition transform hover:scale-105">Login</button>
        </form>
    </div>
</body>
</html>
EOF

    print_info "Step 6: Finalizing Setup..."
    
    if [ "$IS_UBUNTU_24" = true ]; then
        EXEC_START_CMD="$APP_DIR/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:$FLASK_PORT app:app"
    else
        EXEC_START_CMD="/usr/bin/python3 -m gunicorn --workers 2 --bind 127.0.0.1:$FLASK_PORT app:app"
    fi
    
    cat << EOF > /etc/systemd/system/$SERVICE_NAME.service
[Unit]
Description=Gunicorn instance to serve the WG Panel
After=network.target
[Service]
User=root
Group=root
WorkingDirectory=$APP_DIR
ExecStart=$EXEC_START_CMD
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF

    cat << EOF > $NGINX_CONF
server {
    listen $PANEL_PORT;
    server_name $PANEL_HOST _;
    location / {
        proxy_pass http://127.0.0.1:$FLASK_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    rm -f /etc/nginx/sites-enabled/default
    ln -s -f $NGINX_CONF /etc/nginx/sites-enabled/
    
    print_info "Reloading daemons and starting services..."
    systemctl daemon-reload
    systemctl restart $SERVICE_NAME
    systemctl enable $SERVICE_NAME
    if ! nginx -t; then
        print_error "Nginx configuration test failed."
    fi
    systemctl restart nginx
    systemctl enable nginx

    print_success "Installation is complete!"
    print_info "Please open your web browser and navigate to: http://$PANEL_HOST:$PANEL_PORT"
}

# --- Main Menu ---
uninstall_panel_silent() {
    print_info "Performing a full cleanup before installation..."
    systemctl stop $SERVICE_NAME nginx wg-quick@wg1 >/dev/null 2>&1 || true
    systemctl disable $SERVICE_NAME nginx wg-quick@wg1 >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/$SERVICE_NAME.service
    rm -f /etc/nginx/sites-available/wgpanel
    rm -f /etc/nginx/sites-enabled/wgpanel
    rm -rf $APP_DIR /etc/wg-manager $LOG_DIR /etc/wireguard
    systemctl daemon-reload
    print_info "Cleanup complete."
}



show_menu() {
    clear
        echo "┌────────────────────────────────────────────────────────────┐"
        echo "│                                                            │"
        echo "│   ███████╗██╗   ██╗██╗      █████╗ ███╗   ██╗              │"
        echo "│   ██╔════╝╚██╗ ██╔╝██║     ██╔══██╗████╗  ██║              │"
        echo "│   █████╗   ╚████╔╝ ██║     ███████║██╔██╗ ██║              │"
        echo "│   ██╔══╝    ╚██╔╝  ██║     ██╔══██║██║╚██╗██║              │"
        echo "│   ███████╗   ██║   ███████╗██║  ██║██║ ╚████║              │"
        echo "│   ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝              │"
        echo "│                                                            │"
        echo "│   █████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗       │"
        echo "│   ╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║        │"
        echo "│      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║        │"
        echo "│      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║        │"
        echo "│      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗   │"
        echo "│      ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝   │"
        echo "│                                                            │"
    echo -e "${MAGENTA}────────────────────────────────────────────────────────────${NC}"
    echo "1. Install or Re-install Panel"
    echo "2. Uninstall Everything"
    echo "3. Exit"
    echo "--------------------------------------------------------------"
    read -p "Select an option [1-3]: " choice
    case $choice in
        1) uninstall_panel_silent; install_panel ;;
        2) uninstall_panel ;;
        3) exit 0 ;;
        *) print_error "Invalid option." ;;
    esac
}

# --- Script Entry Point ---
if [ "$(id -u)" -ne 0 ]; then
   print_error "This script must be run as root."
fi
show_menu

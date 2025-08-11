#!/bin/bash

set -e

# --- Global Configuration ---
PROJECT_DIR="/var/www/tinc_panel"
VENV_DIR="$PROJECT_DIR/venv"
INTERNAL_PORT="8001" # Internal port for Gunicorn

# --- Menu and UI Functions ---
print_menu() {
    clear
    echo -e "\033[1;36m┌──────────────────────────────────────────────────────────────────┐\033[0m"
    echo -e "\033[1;36m│\033[0m                                                                  \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m███████╗██╗   ██╗██╗      █████╗ ███╗   ██╗\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m██╔════╝╚██╗ ██╔╝██║     ██╔══██╗████╗  ██║\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m█████╗   ╚████╔╝ ██║     ███████║██╔██╗ ██║\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m██╔══╝    ╚██╔╝  ██║     ██╔══██║██║╚██╗██║\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m███████╗   ██║   ███████╗██║  ██║██║ ╚████║\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝\033[0m                    \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m                                                                  \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m█████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗\033[0m             \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║\033[0m              \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m   ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║\033[0m              \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m   ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║\033[0m              \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m   ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗\033[0m         \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m   \033[1;35m   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝\033[0m         \033[1;36m│\033[0m"
    echo -e "\033[1;36m│\033[0m                                                                  \033[1;36m│\033[0m"
    echo -e "\033[1;36m└──────────────────────────────────────────────────────────────────┘\033[0m"

    if [ -d "$PROJECT_DIR" ]; then
        echo -e "\n  \033[1;32m1)\033[0m Reinstall DejTunnel"
        echo -e "  \033[1;31m2)\033[0m Complete Uninstall"
        echo -e "  \033[1;34m3)\033[0m Change Username / Password / Port"
        echo -e "  \033[1;33m4)\033[0m Exit\n"
    else
        echo -e "\n  \033[1;32m1)\033[0m Install DejTunnel"
        echo -e "  \033[1;33m2)\033[0m Exit\n"
    fi
}

wait_for_enter() {
    echo -e "\n\033[1;33mPress [Enter] to return to the main menu...\033[0m"
    read
}

# --- Core Logic Functions ---
run_full_uninstall() {
    echo -e "\033[0;31m\n--- Starting Complete Uninstallation ---\033[0m"
    read -p "WARNING: This will permanently remove DejTunnel, all Tinc configurations, and the database. Are you sure? [y/N]: " confirmation
    if [[ ! "$confirmation" =~ ^[Yy]$ ]]; then
        echo -e "\033[1;33mUninstall cancelled.\033[0m"
        return
    fi

    echo "  -> Stopping services..."
    systemctl stop tinc_panel nginx tinc@* &>/dev/null || true

    echo "  -> Removing system files..."
    rm -rf "$PROJECT_DIR" \
           /etc/tinc \
           /etc/systemd/system/tinc_panel.service \
           /etc/nginx/sites-available/tinc_panel \
           /etc/nginx/sites-enabled/tinc_panel

    echo "  -> Reloading system services..."
    systemctl daemon-reload
    echo -e "\033[1;32mUninstallation has been completed successfully.\033[0m"
}

change_configuration() {
    echo -e "\033[1;34m\n--- Change DejTunnel Configuration ---\033[0m"
    read -p "Enter new web panel port (leave blank to keep current): " NEW_PORT
    if [[ -n "$NEW_PORT" ]]; then
        echo "  -> Changing port..."
        OLD_PORT=$(grep -E '^\s*listen\s+' /etc/nginx/sites-available/tinc_panel | awk '{print $2}' | sed 's/;//')
        if [[ -n "$OLD_PORT" ]]; then
            sed -i "s/listen ${OLD_PORT};/listen ${NEW_PORT};/" /etc/nginx/sites-available/tinc_panel
            systemctl restart nginx
            echo -e "\033[1;32m  -> Port successfully changed to ${NEW_PORT}.\033[0m"
        else
            echo -e "\033[1;31m  -> Could not determine the old port. Port not changed.\033[0m"
        fi
    fi

    read -p "Enter new admin username (leave blank to keep current): " NEW_USER
    read -s -p "Enter new admin password (leave blank to keep current): " NEW_PASS; echo
    if [[ -n "$NEW_USER" || -n "$NEW_PASS" ]]; then
        echo "  -> Updating credentials in database..."
        CMD_OUTPUT=$(bash -c "cd $PROJECT_DIR && source venv/bin/activate && python3 update_credentials.py '$NEW_USER' '$NEW_PASS' 2>&1")
        echo -e "\033[0;35m  -> Script output: ${CMD_OUTPUT}\033[0m"
    fi
    echo -e "\n\033[1;32mConfiguration update finished.\033[0m"
}

run_installation() {
    echo -e "\033[1;32m\n--- Starting DejTunnel Panel Installation\033[0m"

    # --- PART 1: GATHER ALL INFORMATION ---
    echo -e "\n\033[1;34mStep 1/7: Gathering Configuration Details\033[0m"
    read -p "Enter this server's public IP address: " SERVER_PUBLIC_IP
    read -p "Enter a port for the web panel [Default: 80]: " PANEL_PORT
    PANEL_PORT=${PANEL_PORT:-80}
    read -p "Enter a username for the panel administrator: " ADMIN_USER
    read -s -p "Enter a secure password for the admin: " ADMIN_PASS; echo
    echo ""
    read -p "Enter a name for your Tinc network (e.g., myvpn): " TINC_NET_NAME
    read -p "Enter a name for this main server (e.g., iranserver): " TINC_NODE_NAME
    read -p "Enter the private IP for this main server (e.g., 10.20.0.1): " TINC_PRIVATE_IP
    read -p "Enter the subnet mask (e.g., 255.255.255.0): " TINC_NETMASK

    # --- 2. System & Tinc Dependencies ---
    echo -e "\n\033[1;34mStep 2/7: Installing System Dependencies\033[0m"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y > /dev/null
    echo "  -> Installing required packages (python, nginx, tinc, etc.)..."
    apt-get install -y python3 python3-pip python3-venv nginx gunicorn tinc net-tools curl sshpass psmisc tar > /dev/null
    for cmd in tincd sshpass ifconfig ping pkill tar; do
        if ! command -v $cmd &> /dev/null; then echo -e "\033[0;31mFATAL ERROR: Command '$cmd' was not found. Installation cannot continue.\033[0m"; exit 1; fi
    done
    echo "  -> All dependencies installed and verified."

    # --- 3. Create Project Directory ---
    echo -e "\n\033[1;34mStep 3/7: Creating Project Directory\033[0m"
    mkdir -p "$PROJECT_DIR/templates" "$PROJECT_DIR/backups"
    echo "  -> Project directory created at $PROJECT_DIR"

    # --- 4. Setup Main Tinc Node ---
    echo -e "\n\033[1;34mStep 4/7: Configuring Tinc Main Node\033[0m"
    TINC_DIR="/etc/tinc/$TINC_NET_NAME"
    HOSTS_DIR="$TINC_DIR/hosts"
    CLIENTS_INFO_DIR="/etc/tinc/clients_info"
    mkdir -p "$HOSTS_DIR" "$CLIENTS_INFO_DIR"

    printf "Name = %s\nAddressFamily = ipv4\nInterface = %s\n" "$TINC_NODE_NAME" "$TINC_NET_NAME" > "$TINC_DIR/tinc.conf"
    printf "Address = %s\nSubnet = %s/32\n" "$SERVER_PUBLIC_IP" "$TINC_PRIVATE_IP" > "$HOSTS_DIR/$TINC_NODE_NAME"
    printf "#!/bin/sh\n/sbin/ifconfig \$INTERFACE %s netmask %s\n" "$TINC_PRIVATE_IP" "$TINC_NETMASK" > "$TINC_DIR/tinc-up"
    printf "#!/bin/sh\n/sbin/ifconfig \$INTERFACE down\n" > "$TINC_DIR/tinc-down"
    chmod +x "$TINC_DIR/tinc-up" "$TINC_DIR/tinc-down"
    echo "  -> Generating Tinc RSA keys (4096-bit)..."
    tincd -n "$TINC_NET_NAME" -K4096 &>/dev/null
    systemctl enable "tinc@$TINC_NET_NAME" > /dev/null
    systemctl restart "tinc@$TINC_NET_NAME"
    echo "  -> Tinc main node configured and started."

    # --- 5. Setup Web Panel ---
    echo -e "\n\033[1;34mStep 5/7: Generating Web Panel Files & UI\033[0m"
    
    cat > "$PROJECT_DIR/requirements.txt" << 'EOL'
Flask==2.2.2
Werkzeug==2.2.2
gunicorn==20.1.0
Flask-SQLAlchemy==2.5.1
SQLAlchemy==1.4.46
Flask-Bcrypt==1.0.1
python-dotenv==1.0.0
EOL
    SECRET_KEY_VALUE=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
    cat > "$PROJECT_DIR/.env" << EOL
SECRET_KEY=${SECRET_KEY_VALUE}
EOL

    # app.py (FINAL VERSION with restored log functions)
    cat > "$PROJECT_DIR/app.py" << 'EOL'
import os
import subprocess
import uuid
import threading
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config.from_mapping(
    SECRET_KEY=os.getenv('SECRET_KEY'),
    SQLALCHEMY_DATABASE_URI='sqlite:///database.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    PERMANENT_SESSION_LIFETIME=timedelta(days=31),
    UPLOAD_FOLDER=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
tasks = {}

# --- Constants & Paths ---
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = app.config['UPLOAD_FOLDER']
CMD_SUDO='/usr/bin/sudo'; CMD_SYSTEMCTL='/bin/systemctl'; CMD_PING='/bin/ping'; CMD_SSHPASS='/usr/bin/sshpass'; CMD_SSH='/usr/bin/ssh'; CMD_SCP='/usr/bin/scp'; CMD_TINCD='/usr/sbin/tincd'; CMD_IFCONFIG='/sbin/ifconfig'; CMD_RM='/bin/rm'; CMD_JOURNALCTL='/bin/journalctl'; CMD_PKILL='/usr/bin/pkill'

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True); username=db.Column(db.String(80),unique=True,nullable=False); password_hash=db.Column(db.String(128),nullable=False)
class TincNetwork(db.Model):
    id=db.Column(db.Integer,primary_key=True); net_name=db.Column(db.String(80),unique=True,nullable=False); main_node_name=db.Column(db.String(80),nullable=False); main_public_ip=db.Column(db.String(45),nullable=False); main_private_ip=db.Column(db.String(45),nullable=False); subnet_mask=db.Column(db.String(45),nullable=False)
class RemoteNode(db.Model):
    id=db.Column(db.Integer,primary_key=True); name=db.Column(db.String(80),unique=True,nullable=False); public_ip=db.Column(db.String(45),nullable=False); private_ip=db.Column(db.String(45),nullable=False); ssh_user=db.Column(db.String(80),nullable=False); ssh_pass=db.Column(db.String(256),nullable=False)

def login_required(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        if 'logged_in' not in session: return redirect(url_for('login'))
        return f(*args,**kwargs)
    return decorated_function

def get_main_node_status(main_network):
    try:
        service_res=subprocess.run([CMD_SUDO,CMD_SYSTEMCTL,"is-active",f"tinc@{main_network.net_name}"],capture_output=True,text=True,check=True)
        if "active" not in service_res.stdout.strip(): return {"status":"Service Down"}
        ping_res=subprocess.run([CMD_PING,"-c","1","-W","1",main_network.main_private_ip],capture_output=True,text=True)
        if ping_res.returncode!=0: return {"status":"Unreachable"}
        return {"status":"Online"}
    except Exception: return {"status":"Check Error"}
def get_remote_node_status(private_ip):
    try:
        res=subprocess.run([CMD_PING,"-c","1","-W","1",private_ip],capture_output=True,text=True,timeout=2)
        return {"status":"Online"} if res.returncode==0 else {"status":"Offline"}
    except Exception: return {"status":"Offline"}

def _run_single_node_provision(node_data, main_network_info, existing_nodes):
    node_name = node_data['name']
    public_ip = node_data['public_ip']
    private_ip = node_data['private_ip']
    ssh_user = node_data['ssh_user']
    ssh_pass = node_data['ssh_pass']
    
    net_name, node_name_main, netmask = main_network_info.net_name, main_network_info.main_node_name, main_network_info.subnet_mask
    hosts_dir = f"/etc/tinc/{net_name}/hosts"
    clients_dir = "/etc/tinc/clients_info"
    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
    
    # [1] Cleanup remote server
    cleanup_script = f"if [ -d /etc/tinc/{net_name} ]; then sudo {CMD_RM} -rf /etc/tinc/{net_name}; fi"
    subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SSH,*ssh_opts,f"{ssh_user}@{public_ip}",cleanup_script],capture_output=True,text=True,timeout=60)
    
    # [2] Configure Tinc on remote
    remote_script=f"""set -e
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install --reinstall tinc net-tools > /dev/null
mkdir -p /etc/tinc/{net_name}/hosts;
echo "Name = {node_name}" | sudo tee /etc/tinc/{net_name}/tinc.conf > /dev/null
echo "AddressFamily = ipv4" | sudo tee -a /etc/tinc/{net_name}/tinc.conf > /dev/null
echo "Interface = {net_name}" | sudo tee -a /etc/tinc/{net_name}/tinc.conf > /dev/null
echo "ConnectTo = {node_name_main}" | sudo tee -a /etc/tinc/{net_name}/tinc.conf > /dev/null
echo "#!/bin/sh" | sudo tee /etc/tinc/{net_name}/tinc-up > /dev/null
echo "{CMD_IFCONFIG} \\$INTERFACE {private_ip} netmask {netmask}" | sudo tee -a /etc/tinc/{net_name}/tinc-up > /dev/null
sudo chmod +x /etc/tinc/{net_name}/tinc-up
sudo {CMD_TINCD} -n {net_name} -K4096
echo "Address = {public_ip}" | sudo tee -a /etc/tinc/{net_name}/hosts/{node_name} > /dev/null
echo "Subnet = {private_ip}/32" | sudo tee -a /etc/tinc/{net_name}/hosts/{node_name} > /dev/null
"""
    subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SSH,*ssh_opts,f"{ssh_user}@{public_ip}",remote_script],check=True,capture_output=True,text=True,timeout=300)
    
    # [3] Exchange host files
    subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SCP,*ssh_opts,f"{ssh_user}@{public_ip}:{hosts_dir}/{node_name}",f"{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)
    subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SCP,*ssh_opts,f"{hosts_dir}/{node_name_main}",f"{ssh_user}@{public_ip}:{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)
    
    # [4] Create full mesh with existing nodes
    for node in existing_nodes:
        subprocess.run([CMD_SSHPASS,"-p",node.ssh_pass,CMD_SCP,*ssh_opts,f"{hosts_dir}/{node_name}",f"{node.ssh_user}@{node.public_ip}:{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)
        subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SCP,*ssh_opts,f"{hosts_dir}/{node.name}",f"{ssh_user}@{public_ip}:{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)
        reload_script = f"sudo {CMD_PKILL} -HUP -f 'tincd -n {net_name}'"
        subprocess.run([CMD_SSHPASS, "-p", node.ssh_pass, CMD_SSH, *ssh_opts, f"{node.ssh_user}@{node.public_ip}", reload_script], check=True, capture_output=True, text=True, timeout=30)
    
    # [5] Finalize services
    if not os.path.exists(clients_dir): os.makedirs(clients_dir)
    with open(f"{clients_dir}/{node_name}","w") as f: f.write(f"IP_PUBLIC={public_ip}\\nUSER={ssh_user}\\nPASS='{ssh_pass}'\\n")
    subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SSH,*ssh_opts,f"{ssh_user}@{public_ip}",f"sudo {CMD_SYSTEMCTL} enable tinc@{net_name} && sudo {CMD_SYSTEMCTL} restart tinc@{net_name}"],check=True,capture_output=True,text=True,timeout=30)
    
    # [6] Reload main server and save to DB
    subprocess.run([CMD_SUDO, CMD_PKILL, "-HUP", "-f", f"tincd -n {net_name}"], check=True, capture_output=True)
    with app.app_context():
        # Check if node already exists before adding
        if not RemoteNode.query.filter_by(name=node_name).first():
            db.session.add(RemoteNode(name=node_name,public_ip=public_ip,private_ip=private_ip,ssh_user=ssh_user,ssh_pass=ssh_pass))
            db.session.commit()

# --- ASYNC TASK FUNCTIONS (NEW LOGIC) ---
def add_node_task(task_id,form_data):
    def log(message, progress, is_error=False):
        tasks[task_id]['log'].append(message); tasks[task_id]['progress'] = progress
        tasks[task_id]['status']='Failed' if is_error else 'In Progress'
    try:
        log("Starting node provision...", 5)
        with app.app_context():
            main_network = TincNetwork.query.first()
            existing_nodes = RemoteNode.query.all()
        log("Configuration loaded, executing provision script...", 15)
        _run_single_node_provision(form_data, main_network, existing_nodes)
        log("SUCCESS: Node provisioned and added to the mesh!", 100)
        tasks[task_id]['status']='Completed'
    except Exception as e:
        error_output = e.stderr if hasattr(e,'stderr') and e.stderr else str(e)
        log(f"ERROR: {error_output}", tasks[task_id]['progress'], is_error=True)

def delete_node_task(task_id, node_id):
    def log(message, progress, is_error=False):
        tasks[task_id]['log'].append(message); tasks[task_id]['progress'] = progress
        tasks[task_id]['status'] = 'Failed' if is_error else 'In Progress'
    try:
        with app.app_context():
            node_to_delete = RemoteNode.query.get(node_id); other_nodes = RemoteNode.query.filter(RemoteNode.id != node_id).all(); main_network = TincNetwork.query.first()
        if not node_to_delete:
            log("ERROR: Node not found in database.", 100, is_error=True); return
        net_name = main_network.net_name; hosts_dir = f"/etc/tinc/{net_name}/hosts"; clients_dir = "/etc/tinc/clients_info"
        ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
        log(f"-> Uninstalling Tinc from {node_to_delete.name}...", 10)
        cleanup_script = f"sudo {CMD_SYSTEMCTL} stop tinc@{net_name}; sudo {CMD_SYSTEMCTL} disable tinc@{net_name}; sudo {CMD_RM} -rf /etc/tinc/{net_name}"
        subprocess.run([CMD_SSHPASS, "-p", node_to_delete.ssh_pass, CMD_SSH, *ssh_opts, f"{node_to_delete.ssh_user}@{node_to_delete.public_ip}", cleanup_script], capture_output=True, text=True, timeout=60)
        log(f"-> Deleting local files...", 40)
        if os.path.exists(f"{hosts_dir}/{node_to_delete.name}"): os.remove(f"{hosts_dir}/{node_to_delete.name}")
        if os.path.exists(f"{clients_dir}/{node_to_delete.name}"): os.remove(f"{clients_dir}/{node_to_delete.name}")
        log(f"-> Updating other nodes...", 60)
        if other_nodes:
            for i, node in enumerate(other_nodes):
                progress = 60 + int(20 * (i + 1) / len(other_nodes))
                log(f"  - Sending update to {node.name}...", progress)
                update_script = f"sudo {CMD_RM} -f {hosts_dir}/{node_to_delete.name} && sudo {CMD_PKILL} -HUP -f 'tincd -n {net_name}'"
                subprocess.run([CMD_SSHPASS, "-p", node.ssh_pass, CMD_SSH, *ssh_opts, f"{node.ssh_user}@{node.public_ip}", update_script], capture_output=True, text=True, timeout=45)
        log(f"-> Reloading main server...", 85)
        subprocess.run([CMD_SUDO, CMD_PKILL, "-HUP", "-f", f"tincd -n {net_name}"], check=True, capture_output=True)
        log(f"-> Removing from database...", 95)
        with app.app_context():
            node_to_del_in_db = db.session.get(RemoteNode, node_id)
            if node_to_del_in_db: db.session.delete(node_to_del_in_db); db.session.commit()
        log("-> SUCCESS: Node removal complete!", 100)
        tasks[task_id]['status'] = 'Completed'
    except Exception as e:
        error_output = e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)
        log(f"FATAL ERROR: {error_output}", tasks[task_id]['progress'], is_error=True)

def change_ip_task(task_id, new_ip):
    def log(message, progress, is_error=False):
        tasks[task_id]['log'].append(message); tasks[task_id]['progress'] = progress
        tasks[task_id]['status'] = 'Failed' if is_error else 'In Progress'
    try:
        with app.app_context():
            net_info = TincNetwork.query.first(); all_nodes = RemoteNode.query.all()
        log("-> Starting IP change process...", 5)
        old_ip = net_info.main_public_ip; main_node_file = f"/etc/tinc/{net_info.net_name}/hosts/{net_info.main_node_name}"
        log(f"-> Updating main server Tinc host file...", 10)
        subprocess.run([CMD_SUDO, "sed", "-i", f"s/^Address = .*/Address = {new_ip}/", main_node_file], check=True)
        log(f"-> Updating Nginx configuration...", 20)
        subprocess.run([CMD_SUDO, "sed", "-i", f"s/server_name {old_ip} _;/server_name {new_ip} _;/", "/etc/nginx/sites-available/tinc_panel"], check=True)
        if not all_nodes:
            log("-> No remote nodes found.", 80)
        else:
            log(f"-> Updating {len(all_nodes)} remote node(s)...", 30)
            ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
            for i, node in enumerate(all_nodes):
                progress = 30 + int(50 * (i + 1) / len(all_nodes))
                log(f"  - Updating {node.name}...", progress)
                remote_main_node_file = f"/etc/tinc/{net_info.net_name}/hosts/{net_info.main_node_name}"
                update_script = f"sudo sed -i 's/^Address = .*/Address = {new_ip}/' {remote_main_node_file} && sudo {CMD_SYSTEMCTL} restart tinc@{net_info.net_name}"
                subprocess.run([CMD_SSHPASS, "-p", node.ssh_pass, CMD_SSH, *ssh_opts, f"{node.ssh_user}@{node.public_ip}", update_script], check=True, capture_output=True, text=True, timeout=60)
        log("-> Updating database with new IP...", 90)
        with app.app_context():
            net_info_db = TincNetwork.query.first()
            if net_info_db: net_info_db.main_public_ip = new_ip; db.session.commit()
            else: raise Exception("DB update failed: network info not found")
        log("-> Restarting local services...", 95)
        subprocess.run([CMD_SUDO, CMD_SYSTEMCTL, "restart", f"tinc@{net_info.net_name}"], check=True)
        subprocess.run([CMD_SUDO, CMD_SYSTEMCTL, "restart", "nginx"], check=True)
        log("-> SUCCESS: IP change complete!", 100)
        tasks[task_id]['status'] = 'Completed'
    except Exception as e:
        error_output = e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)
        log(f"FATAL ERROR: {error_output}", tasks[task_id]['progress'], is_error=True)

def export_nodes_task(task_id):
    def log(message, progress, is_error=False):
        tasks[task_id]['log'].append(message); tasks[task_id]['progress'] = progress
        tasks[task_id]['status'] = 'Failed' if is_error else 'In Progress'
    try:
        log("-> Fetching nodes from database...", 25)
        with app.app_context():
            nodes = RemoteNode.query.all()
        if not nodes:
            log("-> No remote nodes found to export.", 100); tasks[task_id]['status'] = 'Completed'; return
        
        nodes_data = [{'name': n.name, 'public_ip': n.public_ip, 'private_ip': n.private_ip, 'ssh_user': n.ssh_user, 'ssh_pass': n.ssh_pass} for n in nodes]
        
        log(f"-> Found {len(nodes_data)} nodes. Creating JSON file...", 75)
        export_filename = f"dejtunnel_nodes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        export_filepath = os.path.join(BACKUP_DIR, export_filename)
        
        with open(export_filepath, 'w') as f:
            json.dump(nodes_data, f, indent=2)
            
        tasks[task_id]['download_file'] = export_filename
        log("-> SUCCESS: Node list is ready for download.", 100)
        tasks[task_id]['status'] = 'Completed'
    except Exception as e:
        log(f"FATAL ERROR: {str(e)}", tasks[task_id]['progress'], is_error=True)

def import_nodes_task(task_id, import_filepath):
    def log(message, progress, is_error=False):
        tasks[task_id]['log'].append(message); tasks[task_id]['progress'] = progress
        tasks[task_id]['status'] = 'Failed' if is_error else 'In Progress'
    try:
        log("-> Reading and parsing node import file...", 10)
        with open(import_filepath, 'r') as f:
            nodes_to_import = json.load(f)
        total_nodes = len(nodes_to_import)
        if total_nodes == 0:
            log("-> Import file is empty. Nothing to do.", 100); tasks[task_id]['status'] = 'Completed'; return

        log(f"-> Found {total_nodes} nodes to import. Starting batch provisioning...", 20)
        with app.app_context():
            main_network = TincNetwork.query.first()
        
        for i, node_data in enumerate(nodes_to_import):
            progress = 20 + int(75 * (i + 1) / total_nodes)
            log(f"--- Provisioning Node {i+1}/{total_nodes}: {node_data.get('name')} ---", progress)
            try:
                with app.app_context():
                    existing_nodes = RemoteNode.query.all()
                _run_single_node_provision(node_data, main_network, existing_nodes)
                log(f"-> Successfully provisioned node '{node_data.get('name')}'.", progress)
            except Exception as e:
                error_output = e.stderr if hasattr(e,'stderr') and e.stderr else str(e)
                log(f"-> FAILED to provision node '{node_data.get('name')}': {error_output}", progress, is_error=True)
                # Continue with the next node
        
        log("-> Batch import process finished.", 95)
        tasks[task_id]['status'] = 'Completed'

    except Exception as e:
        log(f"FATAL ERROR: {str(e)}", tasks[task_id]['progress'], is_error=True)
    finally:
        if os.path.exists(import_filepath): os.remove(import_filepath)

def restart_node_task(task_id, node_id):
    def log(message, progress, is_error=False):
        tasks[task_id]['log'].append(message); tasks[task_id]['progress'] = progress
        tasks[task_id]['status'] = 'Failed' if is_error else 'In Progress'
    try:
        with app.app_context():
            net_info = TincNetwork.query.first()
            if node_id == 0: node_name = net_info.main_node_name
            else: node = RemoteNode.query.get(node_id); node_name = node.name
        
        log(f"-> Issuing restart for '{node_name}'...", 25)
        if node_id == 0:
            cmd = [CMD_SUDO, CMD_SYSTEMCTL, "restart", f"tinc@{net_info.net_name}"]
        else:
            ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
            cmd = [CMD_SSHPASS, "-p", node.ssh_pass, CMD_SSH, *ssh_opts, f"{node.ssh_user}@{node.public_ip}", f"sudo {CMD_SYSTEMCTL} restart tinc@{net_info.net_name}"]
        
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
        log("-> SUCCESS: Node restart command executed.", 100)
        tasks[task_id]['status'] = 'Completed'
    except Exception as e:
        error_output = e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)
        log(f"FATAL ERROR: {error_output}", tasks[task_id]['progress'], is_error=True)


# --- Routes ---
@app.route('/login',methods=['GET','POST'])
def login():
    if 'logged_in' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and bcrypt.check_password_hash(user.password_hash, request.form.get('password')):
            session['logged_in'] = True; session.permanent = True
            return redirect(url_for('dashboard'))
        else: flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); flash('You have been logged out.', 'success'); return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    main_network = TincNetwork.query.first(); remote_nodes = RemoteNode.query.all()
    if main_network: main_network.live_status = get_main_node_status(main_network)
    for node in remote_nodes: node.live_status = get_remote_node_status(node.private_ip)
    return render_template('dashboard.html', main_network=main_network, remote_nodes=remote_nodes)

@app.route('/download_export/<filename>')
@login_required
def download_export(filename):
    return send_from_directory(BACKUP_DIR, filename, as_attachment=True, mimetype='application/json')

# --- LOG VIEW FUNCTIONS (REVISED FOR CLEAN OUTPUT) ---
@app.route('/api/get_main_log')
@login_required
def get_main_log():
    net_info = TincNetwork.query.first()
    if not net_info: return jsonify({"log": "Network info not found."}), 404
    try:
        cmd = [CMD_JOURNALCTL, "-u", f"tinc@{net_info.net_name}", "-n", "50", "--no-pager", "--output=cat"]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=15)
        return jsonify({"log": result.stdout or "Log is empty."})
    except Exception as e:
        error = e.stderr if hasattr(e, 'stderr') else str(e)
        return jsonify({"log": f"Failed to fetch log: {error}"}), 500

@app.route('/api/get_remote_log/<int:node_id>')
@login_required
def get_remote_log(node_id):
    node = RemoteNode.query.get(node_id); net_info = TincNetwork.query.first()
    if not node or not net_info: return jsonify({"log": "Node not found."}), 404
    try:
        remote_cmd = f"journalctl -u tinc@{net_info.net_name} -n 50 --no-pager --output=cat"
        cmd = [CMD_SSHPASS, "-p", node.ssh_pass, CMD_SSH, "-T", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", f"{node.ssh_user}@{node.public_ip}", remote_cmd]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
        return jsonify({"log": result.stdout or "Log is empty."})
    except Exception as e:
        error = e.stderr if hasattr(e, 'stderr') else str(e)
        return jsonify({"log": f"Failed to fetch log: {error}"}), 500
# --- END OF LOG VIEW FUNCTIONS ---

@app.route('/api/task_status/<task_id>')
@login_required
def get_task_status(task_id):
    task = tasks.get(task_id); return jsonify(task) if task else (jsonify({"status": "Not Found"}), 404)

@app.route('/api/add_node_task', methods=['POST'])
@login_required
def start_add_node_task():
    task_id = str(uuid.uuid4()); tasks[task_id] = {'status': 'Queued', 'log': [], 'progress': 0}
    thread = threading.Thread(target=add_node_task, args=(task_id, request.form.to_dict())); thread.start()
    return jsonify({"task_id": task_id})

@app.route('/api/delete_node_task/<int:node_id>', methods=['POST'])
@login_required
def start_delete_node_task(node_id):
    task_id = str(uuid.uuid4()); tasks[task_id] = {'status': 'Queued', 'log': [], 'progress': 0}
    thread = threading.Thread(target=delete_node_task, args=(task_id, node_id)); thread.start()
    return jsonify({"task_id": task_id})

@app.route('/api/change_ip_task', methods=['POST'])
@login_required
def start_change_ip_task():
    new_ip = request.form.get('new_ip')
    task_id = str(uuid.uuid4()); tasks[task_id] = {'status': 'Queued', 'log': [], 'progress': 0}
    thread = threading.Thread(target=change_ip_task, args=(task_id, new_ip)); thread.start()
    return jsonify({"task_id": task_id})
    
@app.route('/api/export_nodes_task', methods=['POST'])
@login_required
def start_export_nodes_task():
    task_id = str(uuid.uuid4()); tasks[task_id] = {'status': 'Queued', 'log': [], 'progress': 0}
    thread = threading.Thread(target=export_nodes_task, args=(task_id,)); thread.start()
    return jsonify({"task_id": task_id})

@app.route('/api/import_nodes_task', methods=['POST'])
@login_required
def start_import_nodes_task():
    if 'import_file' not in request.files: return jsonify({"error": "No file part"}), 400
    file = request.files['import_file']
    if file.filename == '': return jsonify({"error": "No selected file"}), 400
    if file and file.filename.endswith('.json'):
        import_filename = f"dejtunnel_import_{str(uuid.uuid4())}.json"
        filepath = os.path.join(BACKUP_DIR, import_filename)
        file.save(filepath)
        task_id = str(uuid.uuid4()); tasks[task_id] = {'status': 'Queued', 'log': [], 'progress': 0}
        thread = threading.Thread(target=import_nodes_task, args=(task_id, filepath)); thread.start()
        return jsonify({"task_id": task_id})
    return jsonify({"error": "Invalid file type. Please upload a .json file."}), 400

@app.route('/api/restart_node_task/<int:node_id>', methods=['POST'])
@login_required
def start_restart_node_task(node_id):
    task_id = str(uuid.uuid4()); tasks[task_id] = {'status': 'Queued', 'log': [], 'progress': 0}
    thread = threading.Thread(target=restart_node_task, args=(task_id, node_id)); thread.start()
    return jsonify({"task_id": task_id})
EOL

    echo "  -> Generated Flask application file (app.py)."
    
    cat > "$PROJECT_DIR/wsgi.py" << 'EOL'
from app import app
if __name__ == "__main__":
    app.run()
EOL
    cat > "$PROJECT_DIR/initial_setup.py" << 'EOL'
import sys
from app import app, db, User, TincNetwork, bcrypt
if len(sys.argv) != 8: sys.exit(1)
admin_user, admin_pass, net_name, node_name, public_ip, private_ip, netmask = sys.argv[1:8]
with app.app_context():
    db.create_all()
    if User.query.first() is None:
        db.session.add(User(username=admin_user, password_hash=bcrypt.generate_password_hash(admin_pass).decode('utf-8')))
    if TincNetwork.query.first() is None:
        db.session.add(TincNetwork(net_name=net_name, main_node_name=node_name, main_public_ip=public_ip, main_private_ip=private_ip, subnet_mask=netmask))
    db.session.commit()
EOL
    cat > "$PROJECT_DIR/update_credentials.py" << 'EOL'
import sys
from app import app, db, User, bcrypt
if len(sys.argv) != 3: sys.exit(1)
new_username, new_password = sys.argv[1], sys.argv[2]
with app.app_context():
    user = User.query.first()
    if not user:
        print("Error: No admin user found in the database.")
        sys.exit(1)
    updated_fields = []
    if new_username:
        user.username = new_username
        updated_fields.append("username")
    if new_password:
        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        updated_fields.append("password")
    if updated_fields:
        db.session.commit()
        print(f"Successfully updated: {', '.join(updated_fields)}")
    else:
        print("No changes provided. Nothing updated.")
EOL

    # --- HTML Templates (with new Export/Import UI) ---
    cat > "$PROJECT_DIR/templates/base.html" << 'EOL'
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DejTunnel Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css" />
    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-webgl@0.15.0/lib/xterm-addon-webgl.min.js"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        'gray': {
                            900: '#111827',
                            800: '#1F2937',
                            700: '#374151',
                            600: '#4B5563',
                            500: '#6B7280',
                            400: '#9CA3AF',
                            300: '#D1D5DB',
                            200: '#E5E7EB',
                            100: '#F3F4F6',
                        },
                        'teal': {
                            400: '#2dd4bf',
                            500: '#14b8a6',
                        }
                    }
                }
            }
        }
    </script>
    <style>
        @import url('https://rsms.me/inter/inter.css');
        html { font-family: 'Inter', sans-serif; }
        .modal { display: none; }
        .modal.is-open { display: flex; }
        .xterm .xterm-viewport {
            overflow-y: auto !important;
            scrollbar-width: thin;
            scrollbar-color: #4B5563 #1F2937;
        }
        .xterm .xterm-viewport::-webkit-scrollbar { width: 8px; }
        .xterm .xterm-viewport::-webkit-scrollbar-track { background: #1F2937; }
        .xterm .xterm-viewport::-webkit-scrollbar-thumb { background-color: #4B5563; border-radius: 4px; }
        @keyframes pulse-green {
            0% { box-shadow: 0 0 0 0 rgba(74, 222, 128, 0.7); }
            70% { box-shadow: 0 0 0 8px rgba(74, 222, 128, 0); }
            100% { box-shadow: 0 0 0 0 rgba(74, 222, 128, 0); }
        }
        .pulse-online { animation: pulse-green 2s infinite; }
    </style>
</head>
<body class="bg-gray-900 text-gray-300">
    <div id="app">
        <nav class="bg-gray-800 shadow-lg shadow-black/20">
            <div class="container mx-auto px-6 py-4 flex justify-between items-center">
                <div class="flex items-center space-x-3">
                    <svg class="h-8 w-8 text-teal-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                    </svg>
                    <h1 class="text-xl font-bold text-gray-100">DejTunnel</h1>
                </div>
                <div class="flex items-center space-x-2">
                    {% if session.logged_in %}
                    <button onclick="showModal('settingsModal')" class="p-2 rounded-lg text-gray-400 hover:bg-gray-700 hover:text-white transition-colors" title="Settings">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-6 h-6">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M10.5 6h9.75M10.5 6a1.5 1.5 0 11-3 0m3 0a1.5 1.5 0 10-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 01-3 0m3 0a1.5 1.5 0 00-3 0m-9.75 0h9.75" />
                        </svg>
                    </button>
                    <a href="{{ url_for('logout') }}" class="flex items-center space-x-2 p-2 rounded-lg text-gray-400 hover:bg-red-900/50 hover:text-red-400 transition-colors" title="Logout">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-6 h-6">
                          <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9" />
                        </svg>
                    </a>
                    {% endif %}
                </div>
            </div>
        </nav>
        <main class="container mx-auto p-4 sm:p-6 lg:p-8">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="mb-4 p-4 rounded-lg text-white font-medium 
                            {% if category == 'danger' %} bg-red-500/80 border border-red-400 
                            {% elif category == 'success' %} bg-green-500/80 border border-green-400
                            {% else %} bg-blue-500/80 border border-blue-400 {% endif %}">
                            {{ message }}
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            {% block content %}{% endblock %}
        </main>
    </div>
</body>
</html>
EOL
    cat > "$PROJECT_DIR/templates/login.html" << 'EOL'
{% extends "base.html" %}
{% block content %}
<div class="flex items-center justify-center min-h-[calc(100vh-200px)]">
    <div class="w-full max-w-sm p-8 space-y-6 bg-gray-800 rounded-2xl shadow-2xl shadow-black/30 border border-gray-700">
        <div class="text-center">
            <h2 class="text-3xl font-bold text-gray-100">DejTunnel Login</h2>
            <p class="mt-2 text-sm text-gray-400">Please sign in to continue</p>
        </div>
        <form method="POST" class="space-y-6">
            <div>
                <label for="username" class="sr-only">Username</label>
                <input type="text" name="username" id="username" placeholder="Username" class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:ring-2 focus:ring-teal-400 focus:outline-none transition" required>
            </div>
            <div>
                <label for="password" class="sr-only">Password</label>
                <input type="password" name="password" id="password" placeholder="Password" class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:ring-2 focus:ring-teal-400 focus:outline-none transition" required>
            </div>
            <button type="submit" class="w-full bg-teal-500 text-gray-900 font-bold py-3 px-4 rounded-lg hover:bg-teal-400 transition-colors shadow-lg shadow-teal-500/20">
                Sign In
            </button>
        </form>
    </div>
</div>
{% endblock %}
EOL
    cat > "$PROJECT_DIR/templates/dashboard.html" << 'EOL'
{% extends "base.html" %}
{% block content %}
<div class="grid grid-cols-1 xl:grid-cols-3 gap-8">
    <div class="xl:col-span-1 space-y-8">
        <div class="bg-gray-800 p-6 rounded-2xl shadow-lg shadow-black/20 border border-gray-700">
            <h2 class="text-xl font-bold text-gray-100 mb-4 pb-4 border-b border-gray-700 flex items-center gap-3">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-6 h-6 text-teal-400">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M21.75 17.25v-.228a4.5 4.5 0 00-.12-1.03l-2.268-9.64a3.375 3.375 0 00-3.285-2.602H7.923a3.375 3.375 0 00-3.285 2.602l-2.268 9.64a4.5 4.5 0 00-.12 1.03v.228m15.56 0A2.25 2.25 0 0118.75 21H5.25a2.25 2.25 0 01-2.25-2.25m15.56 0-1.081-4.71a1.125 1.125 0 011.12-1.223h.056a1.125 1.125 0 011.12 1.223L21.75 17.25m-15.56 0a1.125 1.125 0 011.12-1.223h.056a1.125 1.125 0 011.12 1.223L6.25 17.25m11.25 0h-4.5a1.125 1.125 0 010-2.25h4.5a1.125 1.125 0 010 2.25z" />
                </svg>
                Main Server Status
            </h2>
            {% if main_network %}
            <div class="space-y-3 text-sm">
                <div class="flex justify-between items-center">
                    <span class="text-gray-400 font-medium">Status</span>
                    {% if main_network.live_status.status == 'Online' %}
                    <div class="flex items-center space-x-2 bg-green-500/10 text-green-400 px-2 py-1 rounded-full">
                        <div class="w-2.5 h-2.5 rounded-full bg-green-400 pulse-online"></div>
                        <span class="font-semibold text-xs uppercase tracking-wider">Online</span>
                    </div>
                    {% else %}
                    <div class="flex items-center space-x-2 bg-red-500/10 text-red-400 px-2 py-1 rounded-full">
                        <div class="w-2.5 h-2.5 rounded-full bg-red-400"></div>
                        <span class="font-semibold text-xs uppercase tracking-wider">{{ main_network.live_status.status }}</span>
                    </div>
                    {% endif %}
                </div>
                <div class="flex justify-between items-center pt-2">
                    <span class="text-gray-400 font-medium">Node Name</span>
                    <span class="font-mono text-gray-200">{{ main_network.main_node_name }}</span>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-gray-400 font-medium">Public IP</span>
                    <span class="font-mono text-gray-200">{{ main_network.main_public_ip }}</span>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-gray-400 font-medium">Private IP</span>
                    <span class="font-mono text-gray-200">{{ main_network.main_private_ip }}</span>
                </div>
                <div class="flex justify-between items-center">
                    <span class="text-gray-400 font-medium">Tinc Network</span>
                    <span class="font-mono text-gray-200">{{ main_network.net_name }}</span>
                </div>
            </div>
            <div class="mt-6 pt-6 border-t border-gray-700 flex space-x-2">
                <button type="button" onclick="viewMainLog('{{ main_network.main_node_name }}')" class="w-full flex justify-center items-center gap-2 text-sm bg-gray-700/80 text-gray-200 hover:bg-gray-700 font-semibold py-2 px-3 rounded-lg transition-colors">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" /></svg>
                    View Log
                </button>
                <button type="button" onclick="restartNode(0, '{{main_network.main_node_name}} (Main Server)')" class="w-full flex justify-center items-center gap-2 text-sm bg-blue-600/80 text-blue-200 hover:bg-blue-600 font-semibold py-2 px-3 rounded-lg transition-colors">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0011.664 0l3.181-3.183m-11.664 0l4.992-4.993m-4.993 0l-3.181 3.183a8.25 8.25 0 000 11.664l3.181 3.183" /></svg>
                    Restart
                </button>
            </div>
            {% else %}
            <p class="text-gray-500">Main server information not found.</p>
            {% endif %}
        </div>
    </div>
    <div class="xl:col-span-2">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center mb-5 gap-4">
            <h2 class="text-2xl font-bold text-gray-100 flex items-center gap-3">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-6 h-6 text-teal-400">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M6.429 9.75L2.25 12l4.179 2.25m0-4.5l5.571 3 5.571-3m-11.142 0L2.25 12l4.179 2.25m0 0l5.571 3m5.571-3l4.179-2.25L17.75 12l-4.179-2.25m-5.571 3l5.571 3m0 0l5.571-3m0 0l4.179 2.25m-4.179-2.25L21.75 12l-4.179-2.25m-5.571 4.5l5.571-3m-5.571 3L6.429 9.75" />
                </svg>
                Remote Nodes
            </h2>
            <button onclick="showModal('addNodeModal')" class="bg-teal-500 hover:bg-teal-400 text-gray-900 font-bold py-2 px-5 rounded-lg shadow-lg shadow-teal-500/20 transition-colors flex items-center justify-center space-x-2">
                <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" /></svg>
                <span>Add Node</span>
            </button>
        </div>
        <div class="space-y-4">
            {% for node in remote_nodes %}
            <div class="bg-gray-800 p-5 rounded-2xl shadow-lg shadow-black/20 border border-gray-700/80 transition-all hover:border-gray-600 hover:shadow-xl hover:shadow-black/20">
                <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-4">
                    <h3 class="text-xl font-bold text-gray-100 mb-2 sm:mb-0">{{ node.name }}</h3>
                    <div class="flex items-center space-x-2">
                        {% if node.live_status.status == 'Online' %}
                        <div class="flex items-center space-x-2 bg-green-500/10 text-green-400 px-2 py-1 rounded-full">
                            <div class="w-2 h-2 rounded-full bg-green-400 pulse-online"></div>
                            <span class="text-xs font-semibold uppercase tracking-wider">Online</span>
                        </div>
                        {% else %}
                        <div class="flex items-center space-x-2 bg-red-500/10 text-red-400 px-2 py-1 rounded-full">
                            <div class="w-2 h-2 rounded-full bg-red-400"></div>
                            <span class="text-xs font-semibold uppercase tracking-wider">Offline</span>
                        </div>
                        {% endif %}
                    </div>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-sm mb-4 border-t border-gray-700/80 pt-4">
                    <p><strong class="text-gray-400">Private IP:</strong> <span class="font-mono text-gray-200">{{ node.private_ip }}</span></p>
                    <p><strong class="text-gray-400">Public IP:</strong> <span class="font-mono text-gray-200">{{ node.public_ip }}</span></p>
                </div>
                <div class="mt-4 flex flex-wrap gap-2">
                    <button type="button" onclick="viewLog({{ node.id }}, '{{ node.name }}')" class="flex-1 min-w-[100px] flex justify-center items-center gap-2 text-sm bg-gray-700/80 text-gray-200 hover:bg-gray-700 font-semibold py-2 px-3 rounded-lg transition-colors">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" /></svg>
                        <span>View Log</span>
                    </button>
                    <button type="button" onclick="restartNode({{ node.id }}, '{{ node.name }}')" class="flex-1 min-w-[100px] flex justify-center items-center gap-2 text-sm bg-blue-600/80 text-blue-200 hover:bg-blue-600 font-semibold py-2 px-3 rounded-lg transition-colors">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0011.664 0l3.181-3.183m-11.664 0l4.992-4.993m-4.993 0l-3.181 3.183a8.25 8.25 0 000 11.664l3.181 3.183" /></svg>
                        <span>Restart</span>
                    </button>
                    <button type="button" onclick="deleteNode({{ node.id }}, '{{ node.name }}')" class="flex-1 min-w-[100px] flex justify-center items-center gap-2 text-sm bg-red-600/80 text-red-200 hover:bg-red-600 font-semibold py-2 px-3 rounded-lg transition-colors">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.134-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.067-2.09 1.02-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" /></svg>
                        <span>Delete</span>
                    </button>
                </div>
            </div>
            {% else %}
            <div class="text-center py-16 px-6 bg-gray-800 rounded-2xl shadow-lg shadow-black/20 border-2 border-dashed border-gray-700">
                <svg class="mx-auto h-12 w-12 text-gray-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
                <h3 class="mt-2 text-lg font-medium text-gray-100">No remote nodes found</h3>
                <p class="mt-1 text-sm text-gray-400">Get started by adding a new remote node.</p>
            </div>
            {% endfor %}
        </div>
    </div>
</div>

<div id="addNodeModal" class="modal fixed inset-0 bg-black bg-opacity-70 h-full w-full items-center justify-center z-50 p-4 backdrop-blur-sm">
    <div class="p-8 w-full max-w-lg shadow-2xl shadow-black/40 rounded-2xl bg-gray-800 border border-gray-700 transform transition-all" onclick="event.stopPropagation()">
        <h3 class="text-2xl font-bold text-gray-100 text-center">Add a New Remote Node</h3>
        <p class="text-center text-sm text-gray-400 mt-1">Enter the details of the new server to add to the mesh.</p>
        <form id="addNodeForm" class="mt-6 space-y-4">
            <input class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:ring-2 focus:ring-teal-400 focus:outline-none transition" name="name" placeholder="Node Name (e.g., germanynode)" required pattern="[a-zA-Z0-9]+" title="Please use English letters and numbers only (no spaces or symbols)." oninput="this.value = this.value.replace(/[^a-zA-Z0-9]/g, '')">
            <input class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:ring-2 focus:ring-teal-400 focus:outline-none transition" name="public_ip" placeholder="Public IP Address" required>
            <input class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:ring-2 focus:ring-teal-400 focus:outline-none transition" name="private_ip" placeholder="Tinc Private IP (e.g., 10.20.0.2)" required>
            <input class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:ring-2 focus:ring-teal-400 focus:outline-none transition" name="ssh_user" placeholder="SSH Username (e.g., root)" required>
            <input class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:ring-2 focus:ring-teal-400 focus:outline-none transition" type="password" name="ssh_pass" placeholder="SSH Password" required>
            <div class="flex justify-end pt-4 space-x-3">
                <button type="button" onclick="hideModal('addNodeModal')" class="px-5 py-2 bg-gray-600 text-gray-200 rounded-lg hover:bg-gray-500 transition-colors font-semibold">Cancel</button>
                <button type="submit" class="px-5 py-2 bg-teal-500 text-gray-900 rounded-lg hover:bg-teal-400 transition-colors font-semibold shadow-md shadow-teal-500/20">Add & Provision</button>
            </div>
        </form>
    </div>
</div>

<div id="settingsModal" class="modal fixed inset-0 bg-black bg-opacity-70 h-full w-full items-center justify-center z-50 p-4 backdrop-blur-sm">
    <div class="p-8 w-full max-w-2xl shadow-2xl shadow-black/40 rounded-2xl bg-gray-800 border border-gray-700 transform transition-all" onclick="event.stopPropagation()">
        <div class="flex justify-between items-start">
            <h3 class="text-2xl font-bold text-gray-100">DejTunnel Settings</h3>
            <button type="button" onclick="hideModal('settingsModal')" class="p-1 rounded-full text-gray-400 hover:text-white hover:bg-gray-700 transition-colors">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-6 h-6"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
        </div>
        <div class="mt-6 space-y-8">
            <div class="p-5 bg-gray-900/50 border border-gray-700 rounded-lg">
                <h4 class="font-bold text-lg text-gray-200 flex items-center gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-5 h-5 text-teal-400"><path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A11.953 11.953 0 0112 13.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0021 12c0-3.072-1.49-5.839-3.75-7.668" /></svg>
                    Change Main Server IP
                </h4>
                <p class="text-sm text-gray-400 mt-1">If your main server's public IP has changed, update it here. This will reconfigure the main server and all remote nodes.</p>
                <form id="changeIpForm" class="mt-4 flex flex-col sm:flex-row items-end gap-3">
                    <div class="flex-grow w-full">
                        <label for="new_ip" class="block text-sm font-medium text-gray-300 mb-1">New Public IP Address</label>
                        <input type="text" name="new_ip" id="new_ip" value="{{ main_network.main_public_ip if main_network else '' }}" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-gray-200 focus:ring-2 focus:ring-teal-400 focus:outline-none transition" required>
                    </div>
                    <button type="submit" class="w-full sm:w-auto px-5 py-2 bg-teal-500 text-gray-900 rounded-lg hover:bg-teal-400 transition-colors font-semibold shadow-md shadow-teal-500/20">Save & Apply</button>
                </form>
            </div>
            <div class="p-5 bg-gray-900/50 border border-gray-700 rounded-lg">
                <h4 class="font-bold text-lg text-gray-200 flex items-center gap-2">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-5 h-5 text-teal-400"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" /></svg>
                    Export / Import Nodes
                </h4>
                <p class="text-sm text-gray-400 mt-1">Export a JSON file of all node connection details, or import a file to batch-provision multiple nodes.</p>
                <div class="mt-4 flex flex-col sm:flex-row gap-4">
                    <button id="exportNodesBtn" class="flex-1 flex justify-center items-center gap-2 px-5 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-500 transition-colors font-semibold shadow-md shadow-blue-600/20">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-5 h-5"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" /></svg>
                        <span>Export Node List (.json)</span>
                    </button>
                    <form id="importNodesForm" class="flex-1">
                        <input type="file" id="import_file_input" name="import_file" accept=".json" class="hidden">
                        <label for="import_file_input" class="w-full cursor-pointer flex justify-center items-center gap-2 text-center px-5 py-3 bg-green-600 text-white rounded-lg hover:bg-green-500 transition-colors font-semibold shadow-md shadow-green-600/20">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-5 h-5"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" /></svg>
                            <span>Import & Provision Nodes</span>
                        </label>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<div id="logModal" class="modal fixed inset-0 bg-black bg-opacity-80 h-full w-full items-center justify-center z-[100] p-4 backdrop-blur-sm">
    <div class="w-full max-w-6xl shadow-2xl rounded-xl bg-gray-900 border border-gray-700 flex flex-col max-h-[90vh]" onclick="event.stopPropagation()">
        <div class="p-4 border-b border-gray-700 flex-shrink-0">
            <div class="flex items-center justify-between">
                <h3 id="logModalTitle" class="text-xl font-semibold text-teal-300"></h3>
                <button onclick="hideModal('logModal')" class="text-gray-400 hover:text-white">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-6 h-6"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
            </div>
            <div class="w-full bg-gray-700 rounded-full h-2 mt-3 overflow-hidden">
                <div id="progressBar" class="bg-teal-400 h-2 rounded-full transition-all duration-500" style="width: 0%"></div>
            </div>
        </div>
        <div class="terminal-container flex-grow overflow-hidden relative">
            <div id="terminal" class="w-full h-full p-4"></div>
            <div id="terminalOverlay" class="absolute inset-0 bg-gray-900/80 z-10 flex flex-col justify-center items-center text-white text-lg hidden">
                 <i class="fas fa-spinner fa-spin text-4xl mb-4 text-teal-400"></i>
                 <p class="text-center">Connecting to server...</p>
            </div>
        </div>
        <div class="p-4 border-t border-gray-700 flex justify-center flex-shrink-0">
            <button id="closeLogBtn" class="flex items-center gap-2 px-8 py-2 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors font-semibold text-white">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-5 h-5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                <span>Close</span>
            </button>
        </div>
    </div>
</div>

<div id="confirmModal" class="modal fixed inset-0 bg-black bg-opacity-70 h-full w-full items-center justify-center z-[101] p-4 backdrop-blur-sm">
    <div class="p-8 w-full max-w-md shadow-2xl shadow-black/40 rounded-2xl bg-gray-800 border border-gray-700 transform transition-all text-center" onclick="event.stopPropagation()">
        <h3 id="confirmTitle" class="text-2xl font-bold text-gray-100"></h3>
        <p id="confirmMessage" class="text-center text-gray-400 mt-2"></p>
        <div class="flex justify-center pt-6 space-x-4">
            <button id="cancelBtn" class="px-6 py-2 bg-gray-600 text-gray-200 rounded-lg hover:bg-gray-500 transition-colors font-semibold">Cancel</button>
            <button id="confirmBtn" class="px-6 py-2 text-white rounded-lg transition-colors font-semibold shadow-md"></button>
        </div>
    </div>
</div>

<script>
    const modals = ['addNodeModal', 'settingsModal', 'logModal', 'confirmModal'];
    const terminalContainer = document.getElementById('terminal');
    const terminalOverlay = document.getElementById('terminalOverlay');
    const logModalTitle = document.getElementById('logModalTitle');
    const closeLogBtn = document.getElementById('closeLogBtn');
    const progressBar = document.getElementById('progressBar');
    
    const term = new Terminal({
        convertEol: true, fontFamily: 'monospace', fontSize: 14, cursorBlink: true,
        theme: { background: '#111827', foreground: '#d1d5db', cursor: '#f9fafb', selectionBackground: '#374151' },
        allowTransparency: true,
    });
    
    const fitAddon = new FitAddon.FitAddon();
    const webglAddon = new WebglAddon.WebglAddon();
    term.loadAddon(fitAddon);
    term.onRender(() => { try { if (!webglAddon.textureAtlas) { webglAddon.activate(term); } } catch (e) { console.log("WebGL addon activation failed:", e); } });

    function showModal(id) {
        const modal = document.getElementById(id);
        modal.classList.add('is-open');
        if (id === 'logModal') { if (!term.element) { term.open(terminalContainer); } fitAddon.fit(); }
    }
    
    function hideModal(id) { document.getElementById(id).classList.remove('is-open'); }
    
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { modals.forEach(hideModal); } });
    modals.forEach(id => { const modal = document.getElementById(id); if(modal) modal.addEventListener('click', () => hideModal(id)); });
    
    closeLogBtn.addEventListener('click', () => {
        hideModal('logModal');
        if (closeLogBtn.dataset.taskFinished === 'true') { term.clear(); window.location.reload(); }
    });
    
    function showConfirmationModal(title, message, options = {}) {
        const { confirmClass = 'bg-blue-600 hover:bg-blue-700', confirmText = 'Confirm' } = options;
        
        document.getElementById('confirmTitle').textContent = title;
        document.getElementById('confirmMessage').textContent = message;
        
        const confirmBtn = document.getElementById('confirmBtn');
        confirmBtn.textContent = confirmText;
        confirmBtn.className = `px-6 py-2 text-white rounded-lg transition-colors font-semibold shadow-md ${confirmClass}`;
        
        const cancelBtn = document.getElementById('cancelBtn');
        
        showModal('confirmModal');
        
        return new Promise((resolve) => {
            confirmBtn.addEventListener('click', () => { hideModal('confirmModal'); resolve(true); }, { once: true });
            cancelBtn.addEventListener('click', () => { hideModal('confirmModal'); resolve(false); }, { once: true });
        });
    }

    async function runTask(endpoint, formData, title) {
        modals.forEach(hideModal);
        logModalTitle.textContent = title;
        term.clear(); progressBar.style.width = '0%';
        showModal('logModal');
        closeLogBtn.dataset.taskFinished = 'false';
        try {
            term.write('\x1b[36mConnecting to server to start task...\x1b[0m\r\n');
            const response = await fetch(endpoint, { method: 'POST', body: formData });
            if (!response.ok) throw new Error(`Server responded with status: ${response.status}`);
            const data = await response.json();
            if (data.error) throw new Error(data.error);
            const taskId = data.task_id;
            if (!taskId) throw new Error('Did not receive a valid task ID.');
            term.write('\x1b[32mTask started successfully (ID: ' + taskId + '). Polling for updates...\x1b[0m\r\n\r\n');
            
            const interval = setInterval(async () => {
                try {
                    const statusResponse = await fetch(`/api/task_status/${taskId}`);
                    if (!statusResponse.ok) { clearInterval(interval); term.write(`\r\n\r\n\x1b[1;31m--- POLLING FAILED: Could not connect to server. ---`); closeLogBtn.dataset.taskFinished = 'true'; return; }
                    const statusData = await statusResponse.json();
                    term.clear();
                    statusData.log.forEach(entry => {
                        if (entry.includes('ERROR') || entry.includes('FAILED')) { term.write(`\x1b[31m${entry}\x1b[0m\r\n`); } 
                        else if (entry.includes('SUCCESS')) { term.write(`\x1b[32m${entry}\x1b[0m\r\n`); } 
                        else if (entry.includes('WARNING')) { term.write(`\x1b[33m${entry}\x1b[0m\r\n`); } 
                        else { term.write(`${entry}\r\n`); }
                    });
                    progressBar.style.width = statusData.progress + '%';
                    
                    if (statusData.status === 'Completed' || statusData.status === 'Failed') {
                        clearInterval(interval);
                        progressBar.style.width = '100%';
                        closeLogBtn.dataset.taskFinished = 'true';
                        if (statusData.status === 'Completed') {
                            term.write(`\r\n\r\n\x1b[1;32m--- TASK COMPLETED ---\x1b[0m`);
                            let closeDelay = 1500, shouldReload = true;
                            if (statusData.download_file) {
                                term.write(`\r\n\x1b[33mExport successful. Download will start...\x1b[0m\r\n`);
                                window.location.href = `/download_export/${statusData.download_file}`;
                                shouldReload = false; closeDelay = 3000;
                            } else { term.write(`\r\n\x1b[33mOperation successful. Refreshing panel...\x1b[0m\r\n`); }
                            setTimeout(() => {
                                hideModal('logModal'); term.clear();
                                if (shouldReload) { window.location.reload(); }
                            }, closeDelay);
                        } else {
                            term.write(`\r\n\r\n\x1b[1;31m--- TASK FAILED ---\x1b[0m`);
                            term.write(`\r\n\x1b[31mThe operation failed. Please review the log and close this window manually.\x1b[0m\r\n`);
                        }
                    }
                } catch (err) { clearInterval(interval); term.write(`\r\n\r\n\x1b[1;31m--- ERROR POLLING FOR STATUS: ${err.message}. ---`); closeLogBtn.dataset.taskFinished = 'true'; }
            }, 2000);
        } catch (error) { term.write(`\r\n\r\n\x1b[1;31m--- FATAL ERROR STARTING TASK: ${error.message} ---\x1b[0m`); closeLogBtn.dataset.taskFinished = 'true'; }
    }
    
    async function fetchAndDisplayLog(endpoint, title) {
        modals.forEach(hideModal);
        logModalTitle.textContent = `Static Log: ${title}`;
        term.clear(); progressBar.style.width = '100%'; showModal('logModal');
        terminalOverlay.classList.remove('hidden');
        try {
            const response = await fetch(endpoint);
            const data = await response.json();
            if (data.log) {
                const lines = data.log.split('\n');
                lines.forEach(line => {
                    if (line.toLowerCase().includes('error') || line.toLowerCase().includes('failed')) { term.write(`\x1b[31m${line}\x1b[0m\r\n`); } 
                    else if (line.toLowerCase().includes('warning')) { term.write(`\x1b[33m${line}\x1b[0m\r\n`); } 
                    else if (line.toLowerCase().includes('success')) { term.write(`\x1b[32m${line}\x1b[0m\r\n`); } 
                    else { term.write(`${line}\r\n`); }
                });
            } else { term.write('\x1b[33mNo log data available\x1b[0m\r\n'); }
        } catch (error) { term.write(`\x1b[31mFailed to fetch logs: ${error.message}\x1b[0m\r\n`); } 
        finally { terminalOverlay.classList.add('hidden'); closeLogBtn.dataset.taskFinished = 'true'; }
    }

    document.getElementById('addNodeForm').addEventListener('submit', (e) => { e.preventDefault(); runTask("{{ url_for('start_add_node_task') }}", new FormData(e.target), 'Provisioning New Node...'); });
    document.getElementById('changeIpForm').addEventListener('submit', async (e) => { e.preventDefault(); const confirmed = await showConfirmationModal('Change IP?', 'This will change the main IP and restart services. Are you sure?', { confirmClass: 'bg-blue-600 hover:bg-blue-700', confirmText: 'Yes, Change IP' }); if (confirmed) { runTask("{{ url_for('start_change_ip_task') }}", new FormData(e.target), 'Changing Main Server IP...'); } });
    document.getElementById('exportNodesBtn').addEventListener('click', () => { runTask("{{ url_for('start_export_nodes_task') }}", null, 'Exporting Node List...'); });
    document.getElementById('import_file_input').addEventListener('change', async function(e) { if (this.files.length > 0) { const confirmed = await showConfirmationModal('Import Nodes?', 'Are you sure you want to import and provision all nodes from this file?', { confirmClass: 'bg-green-600 hover:bg-green-700', confirmText: 'Yes, Import' }); if (confirmed) { const formData = new FormData(); formData.append('import_file', this.files[0]); runTask("{{ url_for('start_import_nodes_task') }}", formData, 'Importing & Provisioning Nodes...'); } this.value = ''; } });
    async function deleteNode(nodeId, nodeName) { const confirmed = await showConfirmationModal('Delete Node?', `Are you sure you want to permanently delete node "${nodeName}"? This action cannot be undone.`, { confirmClass: 'bg-red-600 hover:bg-red-700', confirmText: 'Yes, Delete' }); if (confirmed) { runTask(`/api/delete_node_task/${nodeId}`, null, `Deleting Node: ${nodeName}...`); } }
    async function restartNode(nodeId, nodeName) { const confirmed = await showConfirmationModal('Restart Node?', `Are you sure you want to restart the Tinc service on node '${nodeName}'?`, { confirmClass: 'bg-blue-600 hover:bg-blue-700', confirmText: 'Yes, Restart' }); if (confirmed) { runTask(`/api/restart_node_task/${nodeId}`, null, `Restarting Node: ${nodeName}...`); } }
    function viewLog(nodeId, nodeName) { fetchAndDisplayLog(`/api/get_remote_log/${nodeId}`, `Remote Node: ${nodeName}`); }
    function viewMainLog(nodeName) { fetchAndDisplayLog("{{ url_for('get_main_log') }}", `Main Server: ${nodeName}`); }
    window.addEventListener('resize', () => { fitAddon.fit(); });
</script>
{% endblock %}
EOL
    echo "  -> Generated all HTML templates."

    # --- 6. Python Env ---
    echo -e "\n\033[1;34mStep 6/7: Installing Python Packages\033[0m"
    echo "  -> Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    echo "  -> Installing Python packages from requirements.txt..."
    bash -c "source $VENV_DIR/bin/activate && pip install -q --no-cache-dir -r $PROJECT_DIR/requirements.txt"
    echo "  -> Python environment is ready."

    # --- 7. Configure and Start Services ---
    echo -e "\n\033[1;34mStep 7/7: Configuring and Starting System Services\033[0m"
    cat > /etc/systemd/system/tinc_panel.service << EOL
[Unit]
Description=Gunicorn for DejTunnel Panel
After=network.target
[Service]
User=root
Group=root
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$VENV_DIR/bin/gunicorn --workers 1 --bind 127.0.0.1:${INTERNAL_PORT} wsgi:app
[Install]
WantedBy=multi-user.target
EOL
    systemctl daemon-reload; systemctl start tinc_panel; systemctl enable tinc_panel
    echo "  -> Gunicorn service (tinc_panel) created and started."
    
    cat > /etc/nginx/sites-available/tinc_panel << EOL
server {
    listen ${PANEL_PORT};
    server_name ${SERVER_PUBLIC_IP} _;
    location / {
        proxy_pass http://127.0.0.1:${INTERNAL_PORT};
        include proxy_params;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOL
    if [ -f /etc/nginx/sites-enabled/default ]; then rm -f /etc/nginx/sites-enabled/default; fi
    ln -s -f /etc/nginx/sites-available/tinc_panel /etc/nginx/sites-enabled/
    systemctl restart nginx
    echo "  -> Nginx reverse proxy configured and started."

    # --- Final DB Setup ---
    echo -e "\n\033[1;34mSeeding Initial Database...\033[0m"
    bash -c "cd $PROJECT_DIR && source venv/bin/activate && python3 initial_setup.py '$ADMIN_USER' '$ADMIN_PASS' '$TINC_NET_NAME' '$TINC_NODE_NAME' '$SERVER_PUBLIC_IP' '$TINC_PRIVATE_IP' '$TINC_NETMASK'" > /dev/null
    echo "  -> Database created and initial admin/network data seeded."

    echo -e "\n\033[1;32m✅ --- Installation Complete! ---\033[0m"
    echo -e "You can now access your DejTunnel panel at:"
    echo -e "  \033[1;33mhttp://${SERVER_PUBLIC_IP}:${PANEL_PORT}\033[0m"
    echo -e "Login with username '\033[1;33m${ADMIN_USER}\033[0m' and the password you provided."
}

# --- Main Menu Logic ---
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[1;31mError: This script requires root privileges. Please run with 'sudo'.\033[0m"
    exit 1
fi

while true; do
    IS_INSTALLED=false
    if [ -d "$PROJECT_DIR" ]; then
        IS_INSTALLED=true
    fi

    print_menu
    
    if $IS_INSTALLED; then
        read -p "Select an option [1-4]: " choice
        case $choice in
            1)
                run_full_uninstall && run_installation
                wait_for_enter
                ;;
            2)
                run_full_uninstall
                wait_for_enter
                ;;
            3)
                change_configuration
                wait_for_enter
                ;;
            4)
                echo -e "\033[1;36mExiting Panel Manager. Goodbye!\033[0m"
                exit 0
                ;;
            *)
                echo -e "\033[1;31mInvalid option. Please try again.\033[0m"
                sleep 2
                ;;
        esac
    else
        read -p "Select an option [1-2]: " choice
        case $choice in
            1)
                run_installation
                wait_for_enter
                ;;
            2)
                echo -e "\033[1;36mExiting Panel Manager. Goodbye!\033[0m"
                exit 0
                ;;
            *)
                echo -e "\033[1;31mInvalid option. Please try again.\033[0m"
                sleep 2
                ;;
        esac
    fi
done

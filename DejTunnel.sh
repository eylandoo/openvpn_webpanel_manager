#!/bin/bash

set -e

# --- Global Configuration ---
PROJECT_DIR="/var/www/tinc_panel"
VENV_DIR="$PROJECT_DIR/venv"
APP_USER="tinc_panel_user"
APP_GROUP="tinc-admins" # Shared group for permissions

# --- Menu and UI Functions (Smarter UI with Branding) ---
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

    echo "  -> Removing system files, user, and group..."
    rm -rf "$PROJECT_DIR" \
           /etc/tinc \
           /etc/sudoers.d/tinc_panel_permissions \
           /etc/systemd/system/tinc_panel.service \
           /etc/nginx/sites-available/tinc_panel \
           /etc/nginx/sites-enabled/tinc_panel
    userdel -r $APP_USER &>/dev/null || true
    groupdel $APP_GROUP &>/dev/null || true

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
        CMD_OUTPUT=$(sudo -u $APP_USER bash -c "cd $PROJECT_DIR && source venv/bin/activate && python3 update_credentials.py '$NEW_USER' '$NEW_PASS' 2>&1")
        echo -e "\033[0;35m  -> Script output: ${CMD_OUTPUT}\033[0m"
    fi
    echo -e "\n\033[1;32mConfiguration update finished.\033[0m"
}

run_installation() {
    echo -e "\033[1;32m\n--- Starting DejTunnel Panel Installation ---\033[0m"

    # --- PART 1: GATHER ALL INFORMATION ---
    echo -e "\n\033[1;34mStep 1/8: Gathering Configuration Details\033[0m"
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
    echo -e "\n\033[1;34mStep 2/8: Installing System Dependencies\033[0m"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y > /dev/null
    echo "  -> Installing required packages (python, nginx, tinc, etc.)..."
    apt-get install -y python3 python3-pip python3-venv nginx gunicorn tinc net-tools curl sshpass > /dev/null
    for cmd in tincd sshpass ifconfig ping; do
        if ! command -v $cmd &> /dev/null; then echo -e "\033[0;31mFATAL ERROR: Command '$cmd' was not found. Installation cannot continue.\033[0m"; exit 1; fi
    done
    echo "  -> All dependencies installed and verified."

    # --- 3. Create User, Group and Set Permissions ---
    echo -e "\n\033[1;34mStep 3/8: Creating User, Group, and Permissions\033[0m"
    echo "  -> Creating shared group '$APP_GROUP'..."
    groupadd --system $APP_GROUP || true # Fails gracefully if group exists
    echo "  -> Creating application user '$APP_USER'..."
    if ! id -u $APP_USER > /dev/null 2>&1; then
        useradd -r -m -s /bin/false -g $APP_GROUP $APP_USER
    fi
    echo "  -> Adding panel user to required groups..."
    usermod -aG systemd-journal,$APP_GROUP $APP_USER
    echo "  -> Adding webserver user (www-data) to shared group for socket access..."
    usermod -aG $APP_GROUP www-data
    
    mkdir -p "$PROJECT_DIR/templates"
    
    # Correct, minimal sudo permissions
    cat > /etc/sudoers.d/tinc_panel_permissions << EOL
Defaults:$APP_USER !requiretty
$APP_USER ALL=(ALL) NOPASSWD: /bin/systemctl is-active tinc@*
$APP_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart tinc@*
EOL
    chmod 0440 /etc/sudoers.d/tinc_panel_permissions
    echo "  -> System permissions configured securely."

    # --- 4. Setup Main Tinc Node ---
    echo -e "\n\033[1;34mStep 4/8: Configuring Tinc Main Node\033[0m"
    TINC_DIR="/etc/tinc/$TINC_NET_NAME"
    HOSTS_DIR="$TINC_DIR/hosts"
    CLIENTS_INFO_DIR="/etc/tinc/clients_info"
    mkdir -p "$HOSTS_DIR" "$CLIENTS_INFO_DIR"
    
    # Set correct shared permissions for Tinc directory
    echo "  -> Setting shared permissions for /etc/tinc..."
    chown -R root:$APP_GROUP /etc/tinc
    chmod -R g+rw /etc/tinc
    find /etc/tinc -type d -exec chmod g+s {} +

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
    echo -e "\n\033[1;34mStep 5/8: Generating Web Panel Files & UI\033[0m"
    chown -R $APP_USER:$APP_GROUP "$PROJECT_DIR"
    
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

    # app.py (FINAL, CORRECTED VERSION)
    cat > "$PROJECT_DIR/app.py" << 'EOL'
import os
import subprocess
import uuid
import threading
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config.from_mapping(SECRET_KEY=os.getenv('SECRET_KEY'),SQLALCHEMY_DATABASE_URI='sqlite:///database.db',SQLALCHEMY_TRACK_MODIFICATIONS=False)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
tasks = {}

CMD_SUDO='/usr/bin/sudo'; CMD_SYSTEMCTL='/bin/systemctl'; CMD_PING='/bin/ping'; CMD_SSHPASS='/usr/bin/sshpass'; CMD_SSH='/usr/bin/ssh'; CMD_SCP='/usr/bin/scp'; CMD_TINCD='/usr/sbin/tincd'; CMD_IFCONFIG='/sbin/ifconfig'; CMD_RM='/bin/rm'; CMD_JOURNALCTL='/bin/journalctl'

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

def add_node_task(task_id,form_data):
    def log(message,is_error=False): tasks[task_id]['log'].append(message); tasks[task_id]['status']='Failed' if is_error else 'In Progress'
    try:
        with app.app_context():
            main_network = TincNetwork.query.first(); existing_nodes = RemoteNode.query.all()
        node_name, public_ip, private_ip, ssh_user, ssh_pass = (form_data.get(k) for k in ['name','public_ip','private_ip','ssh_user','ssh_pass'])
        net_name, node_name_main, netmask = main_network.net_name, main_network.main_node_name, main_network.subnet_mask
        hosts_dir, clients_dir = f"/etc/tinc/{net_name}/hosts", "/etc/tinc/clients_info"
        ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
        log(f"-> [1/7] Cleaning up remote...")
        cleanup_script = f"if [ -d /etc/tinc/{net_name} ]; then sudo {CMD_RM} -rf /etc/tinc/{net_name} && echo 'Previous config found and removed.'; else echo 'No previous config found, skipping cleanup.'; fi"
        subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SSH,*ssh_opts,f"{ssh_user}@{public_ip}",cleanup_script],capture_output=True,text=True,timeout=60)
        log(f"-> [2/7] Configuring remote server...")
        remote_script=f"""set -e
echo "--> Checking for TUN device availability..."
if [ ! -c /dev/net/tun ]; then
    echo "    - /dev/net/tun not found. Attempting to load kernel module..."
    sudo modprobe tun || echo "    - WARNING: Could not load TUN module. This may be a container limitation. Continuing..."
else
    echo "    - TUN device is available."
fi
echo "--> Checking for dependencies (tinc, net-tools)..."
if ! command -v tincd &> /dev/null || ! command -v ifconfig &> /dev/null; then
    echo "    - A dependency is missing. Installing/updating..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -y > /dev/null
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tinc net-tools
else
    echo "    - All dependencies are already installed."
fi
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
        log(f"-> [3/7] Exchanging host files...")
        subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SCP,*ssh_opts,f"{ssh_user}@{public_ip}:{hosts_dir}/{node_name}",f"{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)
        subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SCP,*ssh_opts,f"{hosts_dir}/{node_name_main}",f"{ssh_user}@{public_ip}:{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)
        log(f"-> [4/7] Creating full mesh...")
        for node in existing_nodes:
            log(f"  - Updating {node.name} and restarting...")
            subprocess.run([CMD_SSHPASS,"-p",node.ssh_pass,CMD_SCP,*ssh_opts,f"{hosts_dir}/{node_name}",f"{node.ssh_user}@{node.public_ip}:{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)
            subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SCP,*ssh_opts,f"{hosts_dir}/{node.name}",f"{ssh_user}@{public_ip}:{hosts_dir}/"],check=True,capture_output=True,text=True,timeout=30)
            subprocess.run([CMD_SSHPASS,"-p",node.ssh_pass,CMD_SSH,*ssh_opts,f"{node.ssh_user}@{node.public_ip}",f"sudo {CMD_SYSTEMCTL} restart tinc@{net_name}"],check=True,capture_output=True,text=True,timeout=30)
        log(f"-> [5/7] Finalizing services...")
        with open(f"{clients_dir}/{node_name}","w") as f: f.write(f"IP_PUBLIC={public_ip}\\nUSER={ssh_user}\\nPASS='{ssh_pass}'\\n")
        subprocess.run([CMD_SSHPASS,"-p",ssh_pass,CMD_SSH,*ssh_opts,f"{ssh_user}@{public_ip}",f"sudo {CMD_SYSTEMCTL} enable tinc@{net_name} && sudo {CMD_SYSTEMCTL} restart tinc@{net_name}"],check=True,capture_output=True,text=True,timeout=30)
        subprocess.run([CMD_SUDO,CMD_SYSTEMCTL,"restart",f"tinc@{net_name}"],check=True)
        log("-> [6/7] Saving to database...")
        with app.app_context():
            db.session.add(RemoteNode(name=node_name,public_ip=public_ip,private_ip=private_ip,ssh_user=ssh_user,ssh_pass=ssh_pass))
            db.session.commit()
        tasks[task_id]['log'].append("-> [7/7] SUCCESS: Node added!"); tasks[task_id]['status']='Completed'
    except Exception as e:
        error_output = e.stderr if hasattr(e,'stderr') and e.stderr else str(e)
        tasks[task_id]['log'].append(f"ERROR: {error_output}"); tasks[task_id]['status']='Failed'

def delete_node_task(task_id,node_id):
    def log(message,is_error=False): tasks[task_id]['log'].append(message); tasks[task_id]['status']='Failed' if is_error else 'In Progress'
    try:
        with app.app_context():
            node_to_delete = RemoteNode.query.get(node_id); other_nodes = RemoteNode.query.filter(RemoteNode.id != node_id).all(); main_network = TincNetwork.query.first()
        if not node_to_delete: log("ERROR: Node not found.", is_error=True); return
        net_name, hosts_dir, clients_dir = main_network.net_name, f"/etc/tinc/{main_network.net_name}/hosts", "/etc/tinc/clients_info"
        ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
        log(f"-> [1/5] Uninstalling Tinc from {node_to_delete.name}...")
        cleanup_script = f"sudo {CMD_SYSTEMCTL} stop tinc@{net_name}; sudo {CMD_SYSTEMCTL} disable tinc@{net_name}; sudo {CMD_RM} -rf /etc/tinc/{net_name}"
        subprocess.run([CMD_SSHPASS,"-p",node_to_delete.ssh_pass,CMD_SSH,*ssh_opts,f"{node_to_delete.ssh_user}@{node_to_delete.public_ip}",cleanup_script],check=True,timeout=60)
        log(f"-> [2/5] Deleting local files...")
        os.remove(f"{hosts_dir}/{node_to_delete.name}")
        os.remove(f"{clients_dir}/{node_to_delete.name}")
        log(f"-> [3/5] Updating other mesh nodes...")
        for node in other_nodes:
            log(f"  - Removing host file from {node.name} and restarting...")
            update_script = f"sudo {CMD_RM} -f {hosts_dir}/{node_to_delete.name} && sudo {CMD_SYSTEMCTL} restart tinc@{net_name}"
            subprocess.run([CMD_SSHPASS,"-p",node.ssh_pass,CMD_SSH,*ssh_opts,f"{node.ssh_user}@{node.public_ip}",update_script],check=True,timeout=45)
        log(f"-> [4/5] Restarting main server's service...")
        subprocess.run([CMD_SUDO,CMD_SYSTEMCTL,"restart",f"tinc@{net_name}"],check=True)
        log(f"-> [5/5] Removing from database...")
        with app.app_context():
            db.session.delete(node_to_delete); db.session.commit()
        tasks[task_id]['log'].append("SUCCESS: Node removed!"); tasks[task_id]['status']='Completed'
    except Exception as e:
        error_output = e.stderr if hasattr(e,'stderr') else str(e)
        tasks[task_id]['log'].append(f"ERROR: {error_output}"); tasks[task_id]['status']='Failed'

# --- Routes ---
@app.route('/login',methods=['GET','POST'])
def login():
    if 'logged_in' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and bcrypt.check_password_hash(user.password_hash, request.form.get('password')):
            session['logged_in'] = True; return redirect(url_for('dashboard'))
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

@app.route('/api/restart_main_node', methods=['POST'])
@login_required
def restart_main_node():
    net_info = TincNetwork.query.first()
    if not net_info: return redirect(url_for('dashboard'))
    try:
        cmd = [CMD_SUDO, CMD_SYSTEMCTL, "restart", f"tinc@{net_info.net_name}"]
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
        flash(f"Main server node '{net_info.main_node_name}' restarted successfully.", "success")
    except Exception as e:
        error = e.stderr if hasattr(e, 'stderr') else str(e)
        flash(f"Failed to restart main server node: {error}", "danger")
    return redirect(url_for('dashboard'))

@app.route('/api/get_main_log')
@login_required
def get_main_log():
    net_info = TincNetwork.query.first()
    if not net_info: return jsonify({"log": "Network info not found."}), 404
    try:
        cmd = [CMD_JOURNALCTL, "-u", f"tinc@{net_info.net_name}", "-n", "50", "--no-pager"]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
        return jsonify({"log": result.stdout or "Log is empty."})
    except Exception as e:
        error = e.stderr if hasattr(e, 'stderr') else str(e)
        return jsonify({"log": f"Failed to fetch log: {error}"}), 500

@app.route('/api/restart_node/<int:node_id>', methods=['POST'])
@login_required
def restart_node(node_id):
    node = RemoteNode.query.get(node_id); net_info = TincNetwork.query.first()
    if not node or not net_info: return jsonify({"success": False, "error": "Node not found"}), 404
    try:
        cmd = [CMD_SSHPASS, "-p", node.ssh_pass, CMD_SSH, "-o", "StrictHostKeyChecking=no", f"{node.ssh_user}@{node.public_ip}", f"sudo {CMD_SYSTEMCTL} restart tinc@{net_info.net_name}"]
        subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
        flash(f"Node '{node.name}' restarted successfully.", "success")
    except Exception as e:
        error = e.stderr if hasattr(e, 'stderr') else str(e)
        flash(f"Failed to restart node '{node.name}': {error}", "danger")
    return redirect(url_for('dashboard'))

@app.route('/api/get_remote_log/<int:node_id>')
@login_required
def get_remote_log(node_id):
    node = RemoteNode.query.get(node_id); net_info = TincNetwork.query.first()
    if not node or not net_info: return jsonify({"log": "Node not found."}), 404
    try:
        cmd = [CMD_SSHPASS, "-p", node.ssh_pass, CMD_SSH, "-o", "StrictHostKeyChecking=no", f"{node.ssh_user}@{node.public_ip}", f"journalctl -u tinc@{net_info.net_name} -n 50 --no-pager"]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=30)
        return jsonify({"log": result.stdout or "Log is empty."})
    except Exception as e:
        error = e.stderr if hasattr(e, 'stderr') else str(e)
        return jsonify({"log": f"Failed to fetch log: {error}"}), 500

@app.route('/api/add_node_task', methods=['POST'])
@login_required
def start_add_node_task():
    task_id = str(uuid.uuid4()); tasks[task_id] = {'status': 'Queued', 'log': []}
    form_data_dict = request.form.to_dict()
    thread = threading.Thread(target=add_node_task, args=(task_id, form_data_dict)); thread.daemon = True; thread.start()
    return jsonify({"task_id": task_id})

@app.route('/api/delete_node_task/<int:node_id>', methods=['POST'])
@login_required
def start_delete_node_task(node_id):
    task_id = str(uuid.uuid4()); tasks[task_id] = {'status': 'Queued', 'log': []}
    thread = threading.Thread(target=delete_node_task, args=(task_id, node_id)); thread.daemon = True; thread.start()
    return jsonify({"task_id": task_id})

@app.route('/api/task_status/<task_id>')
@login_required
def get_task_status(task_id):
    task = tasks.get(task_id);
    if not task: return jsonify({"status": "Not Found"}), 404
    return jsonify(task)
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

    # --- HTML Templates ---
    cat > "$PROJECT_DIR/templates/base.html" << 'EOL'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>DejTunnel Panel</title><script src="https://cdn.tailwindcss.com"></script><style>body { font-family: 'Inter', sans-serif; } @import url('https://rsms.me/inter/inter.css'); .pulse-online { box-shadow: 0 0 0 0 rgba(16, 185, 129, 1); animation: pulse-green 2s infinite; } @keyframes pulse-green { 0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); } 70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); } 100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); } } .modal { display: none; } .modal.is-open { display: flex; }</style></head><body class="bg-slate-100 text-slate-800"><div id="app"><nav class="bg-white shadow-md"><div class="container mx-auto px-6 py-3 flex justify-between items-center"><div class="flex items-center space-x-3"><svg class="h-8 w-8 text-slate-800" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M12 11.1429C12.6219 11.1429 13.1429 10.6219 13.1429 10C13.1429 9.37813 12.6219 8.85714 12 8.85714C11.3781 8.85714 10.8571 9.37813 10.8571 10C10.8571 10.6219 11.3781 11.1429 12 11.1429Z"></path><path d="M12 12V14"></path></svg><h1 class="text-xl font-bold text-slate-800">DejTunnel</h1></div>{% if session.logged_in %}<a href="{{ url_for('logout') }}" class="text-sm font-medium text-slate-600 hover:text-red-600 transition-colors">Logout</a>{% endif %}</div></nav><main class="container mx-auto p-4 sm:p-6 lg:p-8">{% with messages = get_flashed_messages(with_categories=true) %}{% if messages %}{% for category, message in messages %}<div class="mb-4 p-4 rounded-lg text-white font-medium {% if category == 'danger' %} bg-red-500 {% elif category == 'success' %} bg-green-500 {% else %} bg-blue-500 {% endif %}">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}{% block content %}{% endblock %}</main></div></body></html>
EOL
    cat > "$PROJECT_DIR/templates/login.html" << 'EOL'
{% extends "base.html" %}{% block content %}<div class="flex items-center justify-center min-h-[calc(100vh-200px)]"><div class="w-full max-w-sm p-8 space-y-6 bg-white rounded-2xl shadow-lg"><div class="text-center"><h2 class="text-2xl font-bold text-slate-900">DejTunnel Login</h2><p class="mt-2 text-sm text-slate-600">Please sign in to continue</p></div><form method="POST" class="space-y-4"><div><label for="username" class="sr-only">Username</label><input type="text" name="username" id="username" placeholder="Username" class="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-slate-400 focus:outline-none transition" required></div><div><label for="password" class="sr-only">Password</label><input type="password" name="password" id="password" placeholder="Password" class="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-slate-400 focus:outline-none transition" required></div><button type="submit" class="w-full bg-slate-800 text-white font-bold py-3 px-4 rounded-lg hover:bg-slate-900 transition-colors shadow-md">Sign In</button></form></div></div>{% endblock %}
EOL
    cat > "$PROJECT_DIR/templates/dashboard.html" << 'EOL'
{% extends "base.html" %}{% block content %}<div class="grid grid-cols-1 lg:grid-cols-3 gap-8"><div class="lg:col-span-1 space-y-8"><div class="bg-white p-6 rounded-2xl shadow-lg"><h2 class="text-xl font-bold text-slate-800 mb-4 border-b pb-3">Main Server Status</h2>{% if main_network %}<div class="space-y-4 text-sm"><div class="flex justify-between items-center"><span class="text-slate-500 font-medium">Status</span>{% if main_network.live_status.status == 'Online' %}<div class="flex items-center space-x-2"><div class="w-3 h-3 rounded-full bg-green-500 pulse-online"></div><span class="font-semibold text-green-600">Online</span></div>{% else %}<div class="flex items-center space-x-2"><div class="w-3 h-3 rounded-full bg-red-500"></div><span class="font-semibold text-red-600">{{ main_network.live_status.status }}</span></div>{% endif %}</div><div class="flex justify-between items-center"><span class="text-slate-500 font-medium">Node Name</span><span class="font-mono text-slate-900">{{ main_network.main_node_name }}</span></div><div class="flex justify-between items-center"><span class="text-slate-500 font-medium">Public IP</span><span class="font-mono text-slate-900">{{ main_network.main_public_ip }}</span></div><div class="flex justify-between items-center"><span class="text-slate-500 font-medium">Private IP</span><span class="font-mono text-slate-900">{{ main_network.main_private_ip }}</span></div><div class="flex justify-between items-center"><span class="text-slate-500 font-medium">Tinc Network</span><span class="font-mono text-slate-900">{{ main_network.net_name }}</span></div></div><div class="mt-6 pt-6 border-t border-slate-200 flex space-x-2"><button onclick="viewMainLog('{{ main_network.main_node_name }}')" class="flex-1 text-sm bg-slate-100 text-slate-800 hover:bg-slate-200 font-semibold py-2 px-3 rounded-lg transition-colors">View Log</button><form action="{{ url_for('restart_main_node') }}" method="POST" class="flex-1"><button type="submit" onclick="return confirm('Are you sure you want to restart the main server Tinc service?')" class="w-full text-sm bg-blue-100 text-blue-800 hover:bg-blue-200 font-semibold py-2 px-3 rounded-lg transition-colors">Restart</button></form></div>{% else %}<p class="text-slate-500">Main server information not found.</p>{% endif %}</div></div><div class="lg:col-span-2"><div class="flex justify-between items-center mb-5"><h2 class="text-2xl font-bold text-slate-800">Remote Nodes</h2><button onclick="showModal('addNodeModal')" class="bg-slate-800 hover:bg-slate-900 text-white font-bold py-2 px-4 rounded-lg shadow-md transition-colors flex items-center space-x-2"><svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" /></svg><span>Add Node</span></button></div><div class="space-y-4">{% for node in remote_nodes %}<div class="bg-white p-5 rounded-2xl shadow-lg transition-shadow hover:shadow-xl"><div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-4"><h3 class="text-xl font-bold text-slate-800 mb-2 sm:mb-0">{{ node.name }}</h3><div class="flex items-center space-x-2">{% if node.live_status.status == 'Online' %}<div class="w-3 h-3 rounded-full bg-green-500 pulse-online"></div><span class="text-sm font-medium text-green-600">Online</span>{% else %}<div class="w-3 h-3 rounded-full bg-red-500"></div><span class="text-sm font-medium text-red-600">Offline</span>{% endif %}</div></div><div class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-sm mb-4"><p><strong class="text-slate-500">Private IP:</strong> <span class="font-mono text-slate-700">{{ node.private_ip }}</span></p><p><strong class="text-slate-500">Public IP:</strong> <span class="font-mono text-slate-700">{{ node.public_ip }}</span></p></div><div class="mt-4 pt-4 border-t border-slate-200 flex flex-wrap gap-2"><button onclick="viewLog({{ node.id }}, '{{ node.name }}')" class="flex-1 min-w-[80px] text-sm bg-slate-100 text-slate-800 hover:bg-slate-200 font-semibold py-2 px-3 rounded-lg transition-colors">View Log</button><form action="{{ url_for('restart_node', node_id=node.id) }}" method="POST" class="flex-1 min-w-[80px]"><button type="submit" onclick="return confirm('Are you sure you want to restart node \'{{node.name}}\'?')" class="w-full text-sm bg-blue-100 text-blue-800 hover:bg-blue-200 font-semibold py-2 px-3 rounded-lg transition-colors">Restart</button></form><button onclick="deleteNode({{ node.id }}, '{{ node.name }}')" class="flex-1 min-w-[80px] text-sm bg-red-100 text-red-800 hover:bg-red-200 font-semibold py-2 px-3 rounded-lg transition-colors">Delete</button></div></div>{% else %}<div class="text-center py-12 px-6 bg-white rounded-2xl shadow-lg"><svg class="mx-auto h-12 w-12 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/></svg><h3 class="mt-2 text-lg font-medium text-slate-900">No remote nodes found</h3><p class="mt-1 text-sm text-slate-500">Get started by adding a new remote node.</p></div>{% endfor %}</div></div></div><div id="addNodeModal" class="modal fixed inset-0 bg-slate-900 bg-opacity-50 h-full w-full items-center justify-center z-50 p-4"><div class="p-8 w-full max-w-lg shadow-2xl rounded-2xl bg-white transform transition-all" onclick="event.stopPropagation()"><h3 class="text-xl font-bold text-gray-900 text-center">Add a New Remote Node</h3><p class="text-center text-sm text-slate-600 mt-1">Enter the details of the new server to add to the mesh.</p><form id="addNodeForm" class="mt-6 space-y-4"><input class="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-slate-400 focus:outline-none transition" name="name" placeholder="Node Name (e.g., germanynode)" required pattern="[a-zA-Z0-9]+" title="Please use English letters and numbers only (no spaces or symbols)." oninput="this.value = this.value.replace(/[^a-zA-Z0-9]/g, '')"><input class="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-slate-400 focus:outline-none transition" name="public_ip" placeholder="Public IP Address" required><input class="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-slate-400 focus:outline-none transition" name="private_ip" placeholder="Tinc Private IP (e.g., 10.20.0.2)" required><input class="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-slate-400 focus:outline-none transition" name="ssh_user" placeholder="SSH Username (e.g., root)" required><input class="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-slate-400 focus:outline-none transition" type="password" name="ssh_pass" placeholder="SSH Password" required><div class="flex justify-end pt-4 space-x-3"><button type="button" onclick="hideModal('addNodeModal')" class="px-5 py-2 bg-slate-200 text-slate-800 rounded-lg hover:bg-slate-300 transition-colors font-semibold">Cancel</button><button type="submit" class="px-5 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-900 transition-colors font-semibold shadow-md">Add & Provision</button></div></form></div></div><div id="logModal" class="modal fixed inset-0 bg-slate-900 bg-opacity-75 h-full w-full items-center justify-center z-50 p-4"><div class="p-6 w-full max-w-4xl shadow-2xl rounded-2xl bg-slate-900 text-white font-mono flex flex-col" onclick="event.stopPropagation()"><h3 id="logModalTitle" class="text-xl font-semibold mb-4 text-cyan-400"></h3><pre id="logContent" class="flex-grow w-full h-96 overflow-y-scroll bg-black p-4 rounded-md text-sm whitespace-pre-wrap select-all"></pre><div class="mt-4 text-center"><button id="closeLogBtn" class="px-8 py-2 bg-slate-600 rounded-md hover:bg-slate-700 transition-colors font-semibold">Close & Refresh</button></div></div></div><script>const addNodeModal = document.getElementById('addNodeModal'); const logModal = document.getElementById('logModal'); const logContent = document.getElementById('logContent'); const logModalTitle = document.getElementById('logModalTitle'); const closeLogBtn = document.getElementById('closeLogBtn'); function showModal(id) { document.getElementById(id).classList.add('is-open'); } function hideModal(id) { document.getElementById(id).classList.remove('is-open'); } document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { hideModal('addNodeModal'); hideModal('logModal'); } }); addNodeModal.addEventListener('click', () => hideModal('addNodeModal')); logModal.addEventListener('click', () => hideModal('logModal')); closeLogBtn.addEventListener('click', () => { hideModal('logModal'); logContent.textContent = ''; if (closeLogBtn.dataset.taskFinished === 'true') { window.location.reload(); } }); async function runTask(endpoint, formData, title) { hideModal('addNodeModal'); logModalTitle.textContent = title; showModal('logModal'); logContent.textContent = 'Starting task, please wait...\\n'; closeLogBtn.dataset.taskFinished = 'false'; try { const response = await fetch(endpoint, { method: 'POST', body: formData }); if (!response.ok) throw new Error(`Server responded with status: ${response.status}`); const data = await response.json(); const taskId = data.task_id; if (!taskId) throw new Error('Did not receive a valid task ID.'); const interval = setInterval(async () => { try { const statusResponse = await fetch(`/api/task_status/${taskId}`); if (!statusResponse.ok) return; const statusData = await statusResponse.json(); logContent.textContent = statusData.log.join('\\n'); logContent.scrollTop = logContent.scrollHeight; if (statusData.status === 'Completed' || statusData.status === 'Failed') { clearInterval(interval); logContent.textContent += `\\n\\n--- TASK ${statusData.status.toUpperCase()} ---`; logContent.textContent += `\\n\\nPanel will automatically refresh in 3 seconds...`; setTimeout(() => { hideModal('logModal'); window.location.reload(); }, 3000); } } catch (err) { clearInterval(interval); logContent.textContent += `\\n\\n--- ERROR POLLING FOR STATUS: ${err.message} ---`; closeLogBtn.dataset.taskFinished = 'true'; } }, 2000); } catch (error) { logContent.textContent += `\\n\\n--- FATAL ERROR STARTING TASK: ${error.message} ---`; closeLogBtn.dataset.taskFinished = 'true'; } } document.getElementById('addNodeForm').addEventListener('submit', function(e) { e.preventDefault(); runTask("{{ url_for('start_add_node_task') }}", new FormData(this), 'Provisioning New Node...'); }); function deleteNode(nodeId, nodeName) { if (!confirm(`Are you sure you want to permanently delete node "${nodeName}"? This action cannot be undone.`)) return; runTask(`/api/delete_node_task/${nodeId}`, null, `Deleting Node: ${nodeName}...`); } async function fetchAndDisplayLog(endpoint, title) { showModal('logModal'); logModalTitle.textContent = title; logContent.textContent = 'Fetching logs...'; closeLogBtn.dataset.taskFinished = 'false'; try { const response = await fetch(endpoint); const data = await response.json(); logContent.textContent = data.log; } catch (error) { logContent.textContent = `Failed to fetch logs: ${error.message}`; } } function viewLog(nodeId, nodeName) { fetchAndDisplayLog(`/api/get_remote_log/${nodeId}`, `Logs for Remote Node: ${nodeName}`); } function viewMainLog(nodeName) { fetchAndDisplayLog("{{ url_for('get_main_log') }}", `Logs for Main Server: ${nodeName}`); }</script>{% endblock %}
EOL
    echo "  -> Generated all HTML templates."

    # --- 6. Set Final Permissions & Python Env ---
    echo -e "\n\033[1;34mStep 6/8: Setting Ownership and Installing Python Packages\033[0m"
    chown -R $APP_USER:$APP_GROUP "$PROJECT_DIR"
    echo "  -> Creating Python virtual environment..."
    sudo -u $APP_USER python3 -m venv "$VENV_DIR"
    echo "  -> Installing Python packages from requirements.txt..."
    sudo -u $APP_USER bash -c "source $VENV_DIR/bin/activate && pip install -q --no-cache-dir -r $PROJECT_DIR/requirements.txt"
    echo "  -> Python environment is ready."

    # --- 7. Configure and Start Services ---
    echo -e "\n\033[1;34mStep 7/8: Configuring and Starting System Services\033[0m"
    cat > /etc/systemd/system/tinc_panel.service << EOL
[Unit]
Description=Gunicorn for DejTunnel Panel
After=network.target
[Service]
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$VENV_DIR/bin"
ExecStart=$VENV_DIR/bin/gunicorn --workers 3 --bind unix:tinc_panel.sock -m 007 wsgi:app
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
        include proxy_params;
        proxy_pass http://unix:${PROJECT_DIR}/tinc_panel.sock;
    }
}
EOL
    if [ -f /etc/nginx/sites-enabled/default ]; then rm -f /etc/nginx/sites-enabled/default; fi
    ln -s -f /etc/nginx/sites-available/tinc_panel /etc/nginx/sites-enabled/
    systemctl restart nginx
    echo "  -> Nginx reverse proxy configured and started."

    # --- 8. Final DB Setup ---
    echo -e "\n\033[1;34mStep 8/8: Seeding Initial Database\033[0m"
    sudo -u $APP_USER bash -c "cd $PROJECT_DIR && source venv/bin/activate && python3 initial_setup.py '$ADMIN_USER' '$ADMIN_PASS' '$TINC_NET_NAME' '$TINC_NODE_NAME' '$SERVER_PUBLIC_IP' '$TINC_PRIVATE_IP' '$TINC_NETMASK'" > /dev/null
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
                run_installation # Reinstall
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
                run_installation # Install
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

#!/bin/bash

GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
CYAN='\033[1;36m'
RESET='\033[0m'

BACKHAUL_BIN="/root/backhaul"
STATE_FILE="/root/.backhaul_tunnels"
KEY_PATH="/root/.ssh/backhaul_id_ed25519"
LOCK_FILE="/var/lock/backhaul-manager.lock"
REPO="Musixal/Backhaul"

die() {
    echo -e "${RED}[✘] $1${RESET}"
    read -p "Press Enter to return to the menu..." _
}

TOTAL_STEPS=10
CURRENT_STEP=0
step() {
    ((CURRENT_STEP++))
    local pct=$(( CURRENT_STEP * 100 / TOTAL_STEPS ))
    echo -e "${CYAN}[Step ${CURRENT_STEP}/${TOTAL_STEPS} - ${pct}%] $1${RESET}"
}

graceful_exit() {
    echo -e "\n${YELLOW}Exiting...${RESET}"
    exit 0
}

ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[✘] This script must be run as root.${RESET}"
        exit 1
    fi
}

ensure_single_instance() {
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        echo -e "${RED}[✘] Another instance of this script is already running.${RESET}"
        exit 1
    fi
}

apt_install_retry() {
    local pkgs="$1"
    local attempts=4 delay=5 i
    export DEBIAN_FRONTEND=noninteractive
    for ((i = 1; i <= attempts; i++)); do
        if apt-get update -qq && apt-get install -y -qq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" $pkgs; then
            return 0
        fi
        echo -e "${YELLOW}[!] Package install attempt ${i}/${attempts} failed, retrying in ${delay}s...${RESET}" >&2
        sleep "$delay"
        delay=$((delay * 2))
    done
    return 1
}

remote_apt_install_retry() {
    local pkgs="$1"
    remote_run_retry "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq -o Dpkg::Options::=\"--force-confdef\" -o Dpkg::Options::=\"--force-confold\" ${pkgs}"
}

ensure_dependencies() {
    local missing=()
    for bin in wget tar curl ssh ssh-keygen sshpass openssl file ss iperf3; do
        command -v "$bin" &>/dev/null || missing+=("$bin")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${YELLOW}[+] Installing missing dependencies...${RESET}"
        if ! apt_install_retry "wget tar curl openssh-client sshpass openssl file iproute2 iperf3"; then
            die "Could not install required packages after several attempts. Check this server's internet/apt access."
            return 1
        fi
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l) echo "arm" ;;
        *) echo "amd64" ;;
    esac
}

latest_backhaul_version() {
    local v
    v=$(curl -s --max-time 8 "https://api.github.com/repos/${REPO}/releases/latest" | grep -Po '"tag_name"\s*:\s*"\K[^"]+')
    if [[ -z "$v" ]]; then
        v=$(curl -s --max-time 8 -o /dev/null -w '%{redirect_url}' "https://github.com/${REPO}/releases/latest" | grep -oP '(?<=/tag/)v[0-9.]+')
    fi
    [[ -z "$v" ]] && v="v0.7.2"
    echo "$v"
}

verify_binary() {
    local bin_path="$1"
    [[ -s "$bin_path" ]] || return 1
    local size
    size=$(stat -c%s "$bin_path" 2>/dev/null || echo 0)
    [[ "$size" -ge 1000000 ]] || return 1
    file "$bin_path" 2>/dev/null | grep -q "ELF" || return 1
    return 0
}

install_backhaul_local() {
    if [[ -f "$BACKHAUL_BIN" ]] && verify_binary "$BACKHAUL_BIN"; then
        echo -e "${GREEN}[✔] Backhaul core already installed at $BACKHAUL_BIN${RESET}"
        return 0
    fi

    local version arch url tmp ok=0
    version=$(latest_backhaul_version)
    arch=$(detect_arch)
    url="https://github.com/${REPO}/releases/download/${version}/backhaul_linux_${arch}.tar.gz"
    tmp=$(mktemp -d)

    for source in "$url" "https://gh-proxy.com/${url}"; do
        echo -e "${YELLOW}[+] Downloading Backhaul ${version} (${arch})...${RESET}"
        if wget -q --timeout=20 "$source" -O "$tmp/backhaul.tar.gz" && tar -xzf "$tmp/backhaul.tar.gz" -C "$tmp" 2>/dev/null && verify_binary "$tmp/backhaul"; then
            ok=1
            break
        fi
        echo -e "${YELLOW}[!] That source failed or returned an invalid file, trying the next one...${RESET}"
    done

    if [[ "$ok" -ne 1 ]]; then
        rm -rf "$tmp"
        die "Failed to download a valid Backhaul binary from GitHub or the mirror."
        return 1
    fi

    chmod +x "$tmp/backhaul"
    mv "$tmp/backhaul" "$BACKHAUL_BIN"
    rm -rf "$tmp"
    echo -e "${GREEN}[✔] Backhaul core installed and verified at $BACKHAUL_BIN${RESET}"
}

ensure_ssh_key() {
    if [[ ! -f "$KEY_PATH" ]]; then
        mkdir -p /root/.ssh
        ssh-keygen -t ed25519 -N "" -f "$KEY_PATH" -q
    fi
}

ssh_ok() {
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes \
        -i "$KEY_PATH" -p "$IRAN_SSH_PORT" "${IRAN_USER}@${IRAN_IP}" "echo ok" &>/dev/null
}

remote_run() {
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 -i "$KEY_PATH" \
        -p "$IRAN_SSH_PORT" "${IRAN_USER}@${IRAN_IP}" "$1"
}

remote_run_retry() {
    local cmd="$1"
    local attempts=3 delay=3 i
    for ((i = 1; i <= attempts; i++)); do
        if remote_run "$cmd"; then
            return 0
        fi
        sleep "$delay"
        delay=$((delay * 2))
    done
    return 1
}

remote_write_file() {
    local path="$1"
    local content="$2"
    local attempts=3 delay=3 i local_hash remote_hash
    local_hash=$(printf '%s\n' "$content" | md5sum | awk '{print $1}')
    for ((i = 1; i <= attempts; i++)); do
        if printf '%s\n' "$content" | ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 -i "$KEY_PATH" -p "$IRAN_SSH_PORT" "${IRAN_USER}@${IRAN_IP}" "cat > '${path}'"; then
            remote_hash=$(remote_run "md5sum '${path}' 2>/dev/null | awk '{print \$1}'")
            if [[ "$remote_hash" == "$local_hash" ]]; then
                return 0
            fi
        fi
        sleep "$delay"
        delay=$((delay * 2))
    done
    return 1
}

setup_iran_ssh_access() {
    ensure_ssh_key
    local i
    for i in 1 2 3; do
        if ssh_ok; then
            echo -e "${GREEN}[✔] Key-based SSH access to Iran server already works.${RESET}"
            return 0
        fi
        sleep 2
    done

    echo -e "${YELLOW}[+] Copying SSH key to the Iran server (one-time, needs the password)...${RESET}"
    export SSHPASS="$IRAN_PASS"
    timeout 25 sshpass -e ssh-copy-id -o StrictHostKeyChecking=no -o ConnectTimeout=15 -p "$IRAN_SSH_PORT" \
        -i "${KEY_PATH}.pub" "${IRAN_USER}@${IRAN_IP}" &>/dev/null
    unset SSHPASS

    for i in 1 2 3; do
        if ssh_ok; then
            echo -e "${GREEN}[✔] SSH key installed on the Iran server.${RESET}"
            return 0
        fi
        sleep 3
    done

    die "Could not establish SSH access to the Iran server. Check IP, port, username and password."
    return 1
}

verify_remote_root() {
    if ! remote_run "test \$(id -u) -eq 0"; then
        die "The Iran SSH user '$IRAN_USER' is not root. This tool needs root privileges on the Iran server (systemctl, apt, service files). Use root or a fully-privileged account."
        return 1
    fi
    return 0
}

remote_install_backhaul() {
    if remote_run "test -s /root/backhaul && [ \$(stat -c%s /root/backhaul) -ge 1000000 ]"; then
        echo -e "${GREEN}[✔] Backhaul core already installed on Iran server.${RESET}"
        return 0
    fi

    local version attempt
    version=$(latest_backhaul_version)

    for attempt in 1 2 3; do
        echo -e "${YELLOW}[+] Installing Backhaul ${version} on the Iran server (attempt ${attempt})...${RESET}"
        if remote_run "VERSION='$version' bash -s" <<'REMOTE_SCRIPT'
set -e
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) BH_ARCH="amd64" ;;
    aarch64|arm64) BH_ARCH="arm64" ;;
    armv7l) BH_ARCH="arm" ;;
    *) BH_ARCH="amd64" ;;
esac
BASE_URL="https://github.com/Musixal/Backhaul/releases/download/${VERSION}/backhaul_linux_${BH_ARCH}.tar.gz"
MIRROR_URL="https://gh-proxy.com/${BASE_URL}"
cd /root
for SRC in "$BASE_URL" "$MIRROR_URL"; do
    rm -f backhaul.tar.gz backhaul
    if wget -q --timeout=20 "$SRC" -O backhaul.tar.gz && tar -xzf backhaul.tar.gz 2>/dev/null; then
        SIZE=$(stat -c%s backhaul 2>/dev/null || echo 0)
        if [[ "$SIZE" -ge 1000000 ]] && file backhaul | grep -q "ELF"; then
            chmod +x backhaul
            rm -f backhaul.tar.gz
            exit 0
        fi
    fi
done
exit 1
REMOTE_SCRIPT
        then
            echo -e "${GREEN}[✔] Backhaul core installed and verified on the Iran server.${RESET}"
            return 0
        fi
        sleep 4
    done

    die "Failed to install a valid Backhaul binary on the Iran server (direct and mirror both failed)."
    return 1
}

check_local_port_free() {
    local port="$1"
    if [[ -f "$STATE_FILE" ]] && awk -F'|' -v p="$port" '$2 == p {f=1} END{exit !f}' "$STATE_FILE"; then
        return 1
    fi
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":${port}$"; then
        return 1
    fi
    return 0
}

check_remote_port_free() {
    local port="$1"
    if remote_run "ss -ltnu 2>/dev/null | grep -q ':${port} '"; then
        return 1
    fi
    return 0
}

probe_local_mtu() {
    local target="$1"
    local low=500 high=1472 best=0 mid
    while (( low <= high )); do
        mid=$(( (low + high) / 2 ))
        if ping -c 2 -W 2 -M do -s "$mid" "$target" &>/dev/null; then
            best=$mid
            low=$((mid + 1))
        else
            high=$((mid - 1))
        fi
    done
    echo "$best"
}

probe_remote_mtu() {
    local target="$1"
    remote_run "TARGET='$target' bash -s" <<'REMOTE_PROBE' 2>/dev/null
low=500
high=1472
best=0
while [ "$low" -le "$high" ]; do
    mid=$(( (low + high) / 2 ))
    if ping -c 2 -W 2 -M do -s "$mid" "$TARGET" &>/dev/null; then
        best=$mid
        low=$((mid + 1))
    else
        high=$((mid - 1))
    fi
done
echo "$best"
REMOTE_PROBE
}

discover_best_mss() {
    echo -e "${CYAN}[+] Measuring path MTU: Kharej -> Iran...${RESET}" >&2
    local best_out mtu_out=0
    best_out=$(probe_local_mtu "$IRAN_IP")
    if [[ "$best_out" =~ ^[0-9]+$ ]] && (( best_out > 0 )); then
        mtu_out=$((best_out + 28))
        echo -e "${GREEN}    Kharej -> Iran: MTU ${mtu_out} bytes${RESET}" >&2
    else
        echo -e "${YELLOW}    Kharej -> Iran: blocked or unmeasurable (ICMP filtered).${RESET}" >&2
    fi

    local kharej_ip
    kharej_ip=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null)
    [[ -z "$kharej_ip" ]] && kharej_ip=$(curl -s --max-time 5 https://icanhazip.com 2>/dev/null | tr -d '[:space:]')

    local mtu_in=0
    if [[ -n "$kharej_ip" ]]; then
        echo -e "${CYAN}[+] Measuring path MTU: Iran -> Kharej (${kharej_ip})...${RESET}" >&2
        local best_in
        best_in=$(probe_remote_mtu "$kharej_ip")
        if [[ "$best_in" =~ ^[0-9]+$ ]] && (( best_in > 0 )); then
            mtu_in=$((best_in + 28))
            echo -e "${GREEN}    Iran -> Kharej: MTU ${mtu_in} bytes${RESET}" >&2
        else
            echo -e "${YELLOW}    Iran -> Kharej: blocked or unmeasurable (this is the direction Iran filters, so this is expected on some setups).${RESET}" >&2
        fi
    else
        echo -e "${YELLOW}    Could not detect this server's public IP, skipping reverse-direction test.${RESET}" >&2
    fi

    local candidates=()
    (( mtu_out > 0 )) && candidates+=("$mtu_out")
    (( mtu_in > 0 )) && candidates+=("$mtu_in")

    if [[ ${#candidates[@]} -eq 0 ]]; then
        echo -e "${YELLOW}[!] Both directions blocked, using safe default MSS 1360.${RESET}" >&2
        echo "1360"
        return
    fi

    local min_mtu="${candidates[0]}"
    local c
    for c in "${candidates[@]}"; do
        (( c < min_mtu )) && min_mtu=$c
    done

    if [[ ${#candidates[@]} -eq 1 ]]; then
        echo -e "${YELLOW}[!] Only one direction was measurable, using it with extra safety margin.${RESET}" >&2
    fi

    local mss=$((min_mtu - 40 - 10))
    echo -e "${GREEN}[✔] Using MSS = ${mss} (worst-case of both directions, with safety margin)${RESET}" >&2
    echo "$mss"
}

format_ports_array() {
    local raw="$1"
    local lines=""
    IFS=',' read -ra arr <<< "$raw"
    for p in "${arr[@]}"; do
        p=$(echo "$p" | xargs)
        [[ -z "$p" ]] && continue
        lines+="  \"$p\",
"
    done
    echo -e "$lines" | sed '$ s/,$//'
}

validate_ports() {
    local raw="$1"
    IFS=',' read -ra arr <<< "$raw"
    for p in "${arr[@]}"; do
        p=$(echo "$p" | xargs)
        if ! [[ "$p" =~ ^[0-9]+(-[0-9]+)?(:[0-9]+)?(=[0-9a-zA-Z\.]+(:[0-9]+)?)?$ ]]; then
            return 1
        fi
    done
    return 0
}

install_watchdog_local() {
    local force="$1"
    local script_content
    script_content=$(cat <<'EOF'
#!/bin/bash
STATE_FILE="/root/.backhaul_tunnels"
LOG="/var/log/backhaul-watchdog.log"
RUN_DIR="/run/backhaul-watchdog"
MISS_LIMIT=3
RETRY_EVERY=15
[[ -f "$STATE_FILE" ]] || exit 0
mkdir -p "$RUN_DIR" 2>/dev/null

while IFS='|' read -r name port transport ip sshport user; do
    [[ -z "$name" ]] && continue
    conf="/root/${name}.toml"
    miss_file="${RUN_DIR}/${name}.miss"

    if ! systemctl is-active --quiet "${name}.service"; then
        echo "$(date '+%F %T') [${name}] service inactive, restarting" >> "$LOG"
        systemctl restart "${name}.service"
        rm -f "$miss_file"
        continue
    fi

    raddr=$(grep -m1 '^remote_addr' "$conf" 2>/dev/null | cut -d'"' -f2)
    rport="${raddr##*:}"
    pid=$(systemctl show -p MainPID --value "${name}.service" 2>/dev/null)
    if [[ "$transport" == "udp" ]] || ! [[ "$rport" =~ ^[0-9]+$ && "$pid" =~ ^[1-9][0-9]*$ ]]; then
        rm -f "$miss_file"
        continue
    fi

    if ! rows=$(ss -tnp state established "( dport = :${rport} )" 2>/dev/null); then
        continue
    fi
    established=$(printf '%s\n' "$rows" | grep -c "pid=${pid},")
    if (( established == 0 )) && ! printf '%s\n' "$rows" | grep -q 'pid='; then
        established=$(printf '%s\n' "$rows" | awk '$1 ~ /^[0-9]+$/ {c++} END{print c+0}')
    fi

    misses=$(cat "$miss_file" 2>/dev/null)
    [[ "$misses" =~ ^[0-9]+$ ]] || misses=0

    if (( established > 0 )); then
        if (( misses >= MISS_LIMIT )); then
            echo "$(date '+%F %T') [${name}] connected again (${established} established to ${raddr})" >> "$LOG"
        fi
        rm -f "$miss_file"
        continue
    fi

    misses=$((misses + 1))
    echo "$misses" > "$miss_file"

    if (( misses == MISS_LIMIT || (misses > MISS_LIMIT && (misses - MISS_LIMIT) % RETRY_EVERY == 0) )); then
        echo "$(date '+%F %T') [${name}] no established TCP connection to ${raddr} for ${misses} checks in a row, restarting" >> "$LOG"
        systemctl restart "${name}.service"
    fi
done < "$STATE_FILE"
EOF
)
    if [[ "$force" != "force" ]] && [[ -f /usr/local/bin/backhaul-watchdog.sh ]] && [[ "$(cat /usr/local/bin/backhaul-watchdog.sh 2>/dev/null)" == "$script_content" ]]; then
        return 0
    fi

    printf '%s\n' "$script_content" > /usr/local/bin/backhaul-watchdog.sh
    chmod +x /usr/local/bin/backhaul-watchdog.sh

    cat > /etc/systemd/system/backhaul-watchdog.service <<'EOF'
[Unit]
Description=Backhaul Tunnel Watchdog

[Service]
Type=oneshot
ExecStart=/usr/local/bin/backhaul-watchdog.sh
EOF

    cat > /etc/systemd/system/backhaul-watchdog.timer <<'EOF'
[Unit]
Description=Run Backhaul Watchdog periodically

[Timer]
OnBootSec=1min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now backhaul-watchdog.timer &>/dev/null
}

install_watchdog_remote() {
    local force="$1"
    local script_content service_content timer_content wanted_hash current_hash
    script_content=$(cat <<'EOF'
#!/bin/bash
LOG="/var/log/backhaul-watchdog.log"
RUN_DIR="/run/backhaul-watchdog"
MISS_LIMIT=3
RETRY_EVERY=15
mkdir -p "$RUN_DIR" 2>/dev/null

for svc in /etc/systemd/system/bh-*.service; do
    [[ -f "$svc" ]] || continue
    name=$(basename "$svc" .service)
    conf="/root/${name}.toml"
    miss_file="${RUN_DIR}/${name}.miss"

    if ! systemctl is-active --quiet "${name}"; then
        echo "$(date '+%F %T') [${name}] service inactive, restarting" >> "$LOG"
        systemctl restart "${name}"
        rm -f "$miss_file"
        continue
    fi

    transport=$(grep -m1 '^transport' "$conf" 2>/dev/null | cut -d'"' -f2)
    bport=$(grep -m1 '^bind_addr' "$conf" 2>/dev/null | grep -oE ':[0-9]+"' | tr -d ':"')
    if [[ -z "$bport" || "$transport" == "udp" ]]; then
        rm -f "$miss_file"
        continue
    fi

    if ! rows=$(ss -tn state established "( sport = :${bport} )" 2>/dev/null); then
        continue
    fi
    established=$(printf '%s\n' "$rows" | awk '$1 ~ /^[0-9]+$/ {c++} END{print c+0}')

    misses=$(cat "$miss_file" 2>/dev/null)
    [[ "$misses" =~ ^[0-9]+$ ]] || misses=0

    if (( established > 0 )); then
        if (( misses >= MISS_LIMIT )); then
            echo "$(date '+%F %T') [${name}] connected again (${established} established on port ${bport})" >> "$LOG"
        fi
        rm -f "$miss_file"
        continue
    fi

    misses=$((misses + 1))
    echo "$misses" > "$miss_file"

    if (( misses == MISS_LIMIT || (misses > MISS_LIMIT && (misses - MISS_LIMIT) % RETRY_EVERY == 0) )); then
        echo "$(date '+%F %T') [${name}] no established TCP connection on port ${bport} for ${misses} checks in a row, restarting" >> "$LOG"
        systemctl restart "${name}"
    fi
done
EOF
)
    if [[ "$force" != "force" ]]; then
        wanted_hash=$(printf '%s\n' "$script_content" | md5sum | awk '{print $1}')
        current_hash=$(remote_run "md5sum /usr/local/bin/backhaul-watchdog.sh 2>/dev/null | awk '{print \$1}'" </dev/null)
        if [[ -n "$current_hash" && "$current_hash" == "$wanted_hash" ]]; then
            return 0
        fi
    fi

    remote_write_file "/usr/local/bin/backhaul-watchdog.sh" "$script_content" || return 1
    remote_run_retry "chmod +x /usr/local/bin/backhaul-watchdog.sh"

    service_content=$(cat <<'EOF'
[Unit]
Description=Backhaul Tunnel Watchdog

[Service]
Type=oneshot
ExecStart=/usr/local/bin/backhaul-watchdog.sh
EOF
)
    remote_write_file "/etc/systemd/system/backhaul-watchdog.service" "$service_content" || return 1

    timer_content=$(cat <<'EOF'
[Unit]
Description=Run Backhaul Watchdog periodically

[Timer]
OnBootSec=1min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
EOF
)
    remote_write_file "/etc/systemd/system/backhaul-watchdog.timer" "$timer_content" || return 1

    remote_run_retry "systemctl daemon-reload && systemctl enable --now backhaul-watchdog.timer"
}

install_quality_watchdog_remote() {
    local force="$1"
    local script_content service_content timer_content wanted_hash current_hash
    script_content=$(cat <<'EOF'
#!/bin/bash
LOG="/var/log/backhaul-watchdog.log"
TARGET="1.1.1.1"
RESULT=$(ping -c 10 -W 2 "$TARGET" 2>/dev/null)
LOSS=$(echo "$RESULT" | grep -oP '\d+(?=% packet loss)')
AVG_RTT=$(echo "$RESULT" | grep -oP '(rtt|round-trip)[^=]*= [0-9.]+/\K[0-9.]+' 2>/dev/null)
if [[ -z "$LOSS" ]]; then
    echo "$(date '+%F %T') [quality-check] could not measure (ping unavailable or network unreachable)" >> "$LOG"
    exit 0
fi
echo "$(date '+%F %T') [quality-check] packet_loss=${LOSS}% avg_rtt=${AVG_RTT:-N/A}ms" >> "$LOG"
if (( LOSS >= 20 )); then
    echo "$(date '+%F %T') [quality-check] link quality degraded (${LOSS}% loss to ${TARGET}), tunnels left running" >> "$LOG"
fi
EOF
)
    if [[ "$force" != "force" ]]; then
        wanted_hash=$(printf '%s\n' "$script_content" | md5sum | awk '{print $1}')
        current_hash=$(remote_run "md5sum /usr/local/bin/backhaul-quality.sh 2>/dev/null | awk '{print \$1}'" </dev/null)
        if [[ -n "$current_hash" && "$current_hash" == "$wanted_hash" ]]; then
            return 0
        fi
    fi

    remote_write_file "/usr/local/bin/backhaul-quality.sh" "$script_content" || return 1
    remote_run_retry "chmod +x /usr/local/bin/backhaul-quality.sh"

    service_content=$(cat <<'EOF'
[Unit]
Description=Backhaul Link Quality Check

[Service]
Type=oneshot
ExecStart=/usr/local/bin/backhaul-quality.sh
EOF
)
    remote_write_file "/etc/systemd/system/backhaul-quality.service" "$service_content" || return 1

    timer_content=$(cat <<'EOF'
[Unit]
Description=Run Backhaul Link Quality Check every 30 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
EOF
)
    remote_write_file "/etc/systemd/system/backhaul-quality.timer" "$timer_content" || return 1

    remote_run_retry "systemctl daemon-reload && systemctl enable --now backhaul-quality.timer"
}

install_status_script_remote() {
    local status_content
    status_content=$(cat <<'EOF'
#!/bin/bash
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
CYAN='\033[1;36m'
RESET='\033[0m'

echo -e "${CYAN}== Backhaul Tunnels on this (Iran) server ==${RESET}"
found=0
for conf in /root/bh-*.toml; do
    [[ -f "$conf" ]] || continue
    found=1
    name=$(basename "$conf" .toml)
    bind=$(grep -m1 '^bind_addr' "$conf" | cut -d'"' -f2)
    transport=$(grep -m1 '^transport' "$conf" | cut -d'"' -f2)
    ports=$(grep -A20 '^ports' "$conf" | grep -oE '"[^"]+"' | tr -d '"' | paste -sd, -)
    bport="${bind##*:}"
    if ! systemctl is-active --quiet "${name}.service"; then
        status="🔴 not running"
    elif [[ "$transport" == "udp" ]] || ! [[ "$bport" =~ ^[0-9]+$ ]] || ! rows=$(ss -tn state established "( sport = :${bport} )" 2>/dev/null); then
        status="🟢 running"
    else
        established=$(printf '%s\n' "$rows" | awk '$1 ~ /^[0-9]+$/ {c++} END{print c+0}')
        if (( established > 0 )); then
            status="🟢 connected (${established} connections)"
        else
            status="🟡 running, not connected"
        fi
    fi
    echo -e " - ${name} [${transport}] bind=${bind} ports=${ports} -> ${status}"
done
[[ "$found" -eq 0 ]] && echo "(no tunnels configured on this server)"

echo
if systemctl is-active --quiet backhaul-watchdog.timer; then
    echo -e "${GREEN}Watchdog: active${RESET}"
else
    echo -e "${YELLOW}Watchdog: not installed${RESET}"
fi

echo
echo "Last 15 watchdog log lines:"
tail -n 15 /var/log/backhaul-watchdog.log 2>/dev/null || echo "(no log yet)"
EOF
)
    remote_write_file "/usr/local/bin/backhaul-status" "$status_content" || return 1
    remote_run_retry "chmod +x /usr/local/bin/backhaul-status"
}

rollback_remote_config() {
    remote_run "systemctl stop ${CONFIG_NAME}.service 2>/dev/null; systemctl disable ${CONFIG_NAME}.service 2>/dev/null; rm -f /etc/systemd/system/${CONFIG_NAME}.service /root/${CONFIG_NAME}.toml; systemctl daemon-reload" &>/dev/null
}

update_installation() {
    echo -e "${CYAN}== Update / Repair Installation ==${RESET}"
    ensure_dependencies || return

    echo -e "${CYAN}[+] Checking local Backhaul core...${RESET}"
    install_backhaul_local || return

    echo -e "${CYAN}[+] Refreshing local watchdog to the latest version...${RESET}"
    install_watchdog_local force

    if [[ ! -f "$STATE_FILE" ]]; then
        echo -e "${YELLOW}No tunnels recorded locally yet. Nothing else to update.${RESET}"
        read -p "Press Enter to continue..." _
        return
    fi

    mapfile -t entries < <(grep -v '^[[:space:]]*$' "$STATE_FILE")
    if [[ ${#entries[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No tunnels recorded locally yet. Nothing else to update.${RESET}"
        read -p "Press Enter to continue..." _
        return
    fi

    local entry name port transport ip sshport user
    for entry in "${entries[@]}"; do
        IFS='|' read -r name port transport ip sshport user <<< "$entry"
        echo -e "${CYAN}[+] Checking ${name} (Iran: ${ip})...${RESET}"

        IRAN_IP="$ip"; IRAN_SSH_PORT="$sshport"; IRAN_USER="$user"
        if ! ssh_ok </dev/null; then
            echo -e "${YELLOW}    Cannot reach ${ip} with the saved SSH key right now. Skipping remote checks for this tunnel.${RESET}"
        else
            if ! remote_run "test -s /root/backhaul && [ \$(stat -c%s /root/backhaul) -ge 1000000 ]" </dev/null; then
                echo -e "${YELLOW}    Backhaul core missing/invalid on Iran, reinstalling...${RESET}"
                remote_install_backhaul
            fi

            if ! remote_run "test -f /root/${name}.toml && test -f /etc/systemd/system/${name}.service" </dev/null; then
                echo -e "${RED}    Server config/service for ${name} is missing on Iran. Use 'Migrate a Tunnel' or a fresh 'Full Auto Setup' to recreate it.${RESET}"
            else
                remote_run "systemctl is-enabled ${name}.service" </dev/null &>/dev/null || remote_run_retry "systemctl enable ${name}.service"
                if ! remote_run "systemctl is-active --quiet ${name}.service" </dev/null; then
                    echo -e "${YELLOW}    Service not active on Iran, starting it...${RESET}"
                    remote_run_retry "systemctl restart ${name}.service"
                fi
                install_watchdog_remote force
                install_quality_watchdog_remote force
                install_status_script_remote force
            fi
        fi

        if [[ ! -f "/root/${name}.toml" || ! -f "/etc/systemd/system/${name}.service" ]]; then
            echo -e "${RED}    Local client config/service for ${name} is missing here. Use 'Migrate a Tunnel' or a fresh 'Full Auto Setup' to recreate it.${RESET}"
            continue
        fi

        systemctl is-enabled --quiet "${name}.service" 2>/dev/null || systemctl enable "${name}.service" &>/dev/null
        if ! systemctl is-active --quiet "${name}.service"; then
            echo -e "${YELLOW}    Local client service not active, starting it...${RESET}"
            systemctl restart "${name}.service"
        fi

        echo -e "${GREEN}    ${name} checked and up to date.${RESET}"
    done

    echo -e "${GREEN}[✔] Update/repair pass complete.${RESET}"
    read -p "Press Enter to continue..." _
}

setup_full_tunnel() {
    CURRENT_STEP=0
    step "Checking dependencies"
    ensure_dependencies || return
    step "Installing/verifying local Backhaul core"
    install_backhaul_local || return

    echo -e "${CYAN}== Iran Server Connection Details ==${RESET}"
    while true; do
        read -p "Iran server IP or hostname: " IRAN_IP
        [[ -n "$IRAN_IP" ]] && break
        echo -e "${RED}Cannot be empty.${RESET}"
    done
    while true; do
        read -p "Iran SSH port [22]: " IRAN_SSH_PORT
        IRAN_SSH_PORT=${IRAN_SSH_PORT:-22}
        [[ "$IRAN_SSH_PORT" =~ ^[0-9]+$ ]] && break
        echo -e "${RED}Port must be numeric.${RESET}"
    done
    read -p "Iran SSH username [root]: " IRAN_USER
    IRAN_USER=${IRAN_USER:-root}
    read -s -p "Iran SSH password: " IRAN_PASS
    echo

    step "Connecting to Iran server via SSH"
    setup_iran_ssh_access || { unset IRAN_PASS; return; }
    unset IRAN_PASS
    step "Verifying root privileges on Iran server"
    verify_remote_root || return
    step "Installing Backhaul core on Iran server"
    remote_install_backhaul || return

    step "Collecting tunnel settings"
    echo -e "${CYAN}== Tunnel Settings ==${RESET}"
    while true; do
        read -p "Tunnel (control) port between the servers [443]: " TUNNEL_PORT
        TUNNEL_PORT=${TUNNEL_PORT:-443}
        if ! [[ "$TUNNEL_PORT" =~ ^[0-9]+$ ]] || (( TUNNEL_PORT < 1 || TUNNEL_PORT > 65535 )); then
            echo -e "${RED}Invalid port number.${RESET}"
            continue
        fi
        if ! check_local_port_free "$TUNNEL_PORT"; then
            echo -e "${RED}Port ${TUNNEL_PORT} is already used by another local tunnel here.${RESET}"
            continue
        fi
        if ! check_remote_port_free "$TUNNEL_PORT"; then
            echo -e "${RED}Port ${TUNNEL_PORT} is already in use on the Iran server (possibly an existing Backhaul or other service).${RESET}"
            continue
        fi
        break
    done

    while true; do
        read -p "User-facing ports to forward, comma separated (e.g. 443,8080-8090): " USER_PORTS
        if validate_ports "$USER_PORTS"; then
            break
        fi
        echo -e "${RED}Invalid port format, try again.${RESET}"
    done

    echo -e "${CYAN}Transport mode:${RESET}"
    echo "1) tcpmux + UDP (recommended, best for high traffic + TCP and UDP together)"
    echo "2) plain tcp"
    echo "3) plain udp"
    read -p "Choice [1]: " MODE_CHOICE
    MODE_CHOICE=${MODE_CHOICE:-1}
    case "$MODE_CHOICE" in
        1) TRANSPORT="tcpmux"; ACCEPT_UDP="true" ;;
        2) TRANSPORT="tcp"; ACCEPT_UDP="false" ;;
        3) TRANSPORT="udp"; ACCEPT_UDP="false" ;;
        *) TRANSPORT="tcpmux"; ACCEPT_UDP="true" ;;
    esac

    BEST_MSS=1360
    MSS_LINE=""
    if [[ "$TRANSPORT" != "udp" ]]; then
        step "Detecting optimal MSS for this route"
        BEST_MSS=$(discover_best_mss)
        MSS_LINE="mss = ${BEST_MSS}"
    else
        step "Skipping MSS detection (not applicable for plain UDP)"
    fi

    TOKEN=$(openssl rand -hex 24)
    CONFIG_NAME="bh-${TUNNEL_PORT}"
    PORT_LINES=$(format_ports_array "$USER_PORTS")

    if [[ "$TRANSPORT" == "tcpmux" ]]; then
        SERVER_CONF=$(cat <<EOF
[server]
bind_addr = "0.0.0.0:${TUNNEL_PORT}"
transport = "${TRANSPORT}"
accept_udp = ${ACCEPT_UDP}
token = "${TOKEN}"
keepalive_period = 75
nodelay = true
heartbeat = 20
channel_size = 4096
mux_con = 16
mux_version = 2
mux_framesize = 32768
mux_recievebuffer = 8388608
mux_streambuffer = 262144
mss = ${BEST_MSS}
so_rcvbuf = 8388608
so_sndbuf = 8388608
web_port = 0
log_level = "info"
ports = [
${PORT_LINES}
]
EOF
)
    else
        SERVER_CONF=$(cat <<EOF
[server]
bind_addr = "0.0.0.0:${TUNNEL_PORT}"
transport = "${TRANSPORT}"
token = "${TOKEN}"
keepalive_period = 75
nodelay = true
heartbeat = 20
channel_size = 4096
${MSS_LINE}
web_port = 0
log_level = "info"
ports = [
${PORT_LINES}
]
EOF
)
    fi

    SERVER_SERVICE=$(cat <<EOF
[Unit]
Description=Backhaul Reverse Tunnel Server (${CONFIG_NAME})
After=network.target

[Service]
Type=simple
ExecStart=/root/backhaul -c /root/${CONFIG_NAME}.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
)

    echo -e "${YELLOW}[+] Pushing server config to Iran server...${RESET}"
    step "Pushing configuration to Iran server"
    if ! remote_write_file "/root/${CONFIG_NAME}.toml" "$SERVER_CONF"; then
        rollback_remote_config
        die "Failed to reliably write the server config on the Iran server after multiple attempts. Rolled back."
        return
    fi
    if ! remote_write_file "/etc/systemd/system/${CONFIG_NAME}.service" "$SERVER_SERVICE"; then
        rollback_remote_config
        die "Failed to reliably write the systemd service on the Iran server after multiple attempts. Rolled back."
        return
    fi
    if ! remote_run_retry "systemctl daemon-reload && systemctl enable ${CONFIG_NAME}.service && systemctl restart ${CONFIG_NAME}.service"; then
        rollback_remote_config
        die "Could not start the tunnel service on the Iran server. Rolled back."
        return
    fi

    echo -e "${YELLOW}[+] Writing client config on this (Kharej) server...${RESET}"
    step "Configuring this (Kharej) server"
    if [[ "$TRANSPORT" == "tcpmux" ]]; then
        cat > "/root/${CONFIG_NAME}.toml" <<EOF
[client]
remote_addr = "${IRAN_IP}:${TUNNEL_PORT}"
transport = "${TRANSPORT}"
token = "${TOKEN}"
connection_pool = 16
aggressive_pool = true
keepalive_period = 75
nodelay = true
dial_timeout = 10
retry_interval = 3
mux_version = 2
mux_framesize = 32768
mux_recievebuffer = 8388608
mux_streambuffer = 262144
mss = ${BEST_MSS}
so_rcvbuf = 8388608
so_sndbuf = 8388608
web_port = 0
log_level = "info"
EOF
    else
        cat > "/root/${CONFIG_NAME}.toml" <<EOF
[client]
remote_addr = "${IRAN_IP}:${TUNNEL_PORT}"
transport = "${TRANSPORT}"
token = "${TOKEN}"
connection_pool = 8
aggressive_pool = false
keepalive_period = 75
dial_timeout = 10
nodelay = true
retry_interval = 3
${MSS_LINE}
web_port = 0
log_level = "info"
EOF
    fi

    cat > "/etc/systemd/system/${CONFIG_NAME}.service" <<EOF
[Unit]
Description=Backhaul Reverse Tunnel Client (${CONFIG_NAME})
After=network.target

[Service]
Type=simple
ExecStart=${BACKHAUL_BIN} -c /root/${CONFIG_NAME}.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${CONFIG_NAME}.service" &>/dev/null
    systemctl restart "${CONFIG_NAME}.service"
    sleep 2
    if ! systemctl is-active --quiet "${CONFIG_NAME}.service"; then
        systemctl restart "${CONFIG_NAME}.service"
        sleep 2
    fi

    if ! systemctl is-active --quiet "${CONFIG_NAME}.service"; then
        echo -e "${YELLOW}[!] Warning: the local client service did not become active. Server side is configured; you can retry starting it from Live Status.${RESET}"
    fi

    echo "${CONFIG_NAME}|${TUNNEL_PORT}|${TRANSPORT}|${IRAN_IP}|${IRAN_SSH_PORT}|${IRAN_USER}" >> "$STATE_FILE"

    echo -e "${YELLOW}[+] Installing self-healing watchdog and status tool on both servers...${RESET}"
    step "Installing watchdog and status tools"
    install_watchdog_local
    install_watchdog_remote
    install_quality_watchdog_remote
    install_status_script_remote

    echo -e "${CYAN}[+] Verifying connection...${RESET}"
    step "Verifying the tunnel connection"
    local ok=0 i
    for i in $(seq 1 10); do
        sleep 2
        local logs
        logs=$(journalctl -u "${CONFIG_NAME}.service" --no-pager -n 30 2>/dev/null | tr '[:upper:]' '[:lower:]')
        if echo "$logs" | grep -Eq "control channel established successfully|client with remote address.*started successfully"; then
            ok=1
            break
        fi
    done

    if [[ "$ok" -eq 1 ]]; then
        echo -e "${GREEN}[✔] Tunnel ${CONFIG_NAME} is UP and connected. Watchdog is active on both ends.${RESET}"
    else
        echo -e "${YELLOW}[!] Tunnel started but connection not confirmed yet.${RESET}"
        echo -e "${YELLOW}    The watchdog will keep retrying automatically. If it stays down, the most common causes are:${RESET}"
        echo -e "${YELLOW}    1) the tunnel port is blocked by a firewall on the Iran server (you manage this manually)${RESET}"
        echo -e "${YELLOW}    2) an ISP/network block on that specific port${RESET}"
        echo -e "${YELLOW}    Check again in a minute from Live Status, or run 'backhaul-status' directly on the Iran server.${RESET}"
    fi
    read -p "Press Enter to continue..." _
}

local_tunnel_connections() {
    local name="$1" transport="$2"
    local raddr rport pid rows count
    raddr=$(grep -m1 '^remote_addr' "/root/${name}.toml" 2>/dev/null | cut -d'"' -f2)
    rport="${raddr##*:}"
    pid=$(systemctl show -p MainPID --value "${name}.service" 2>/dev/null)
    if [[ "$transport" == "udp" ]] || ! [[ "$rport" =~ ^[0-9]+$ && "$pid" =~ ^[1-9][0-9]*$ ]]; then
        echo "unknown"
        return
    fi
    if ! rows=$(ss -tnp state established "( dport = :${rport} )" 2>/dev/null); then
        echo "unknown"
        return
    fi
    count=$(printf '%s\n' "$rows" | grep -c "pid=${pid},")
    if (( count == 0 )) && ! printf '%s\n' "$rows" | grep -q 'pid='; then
        count=$(printf '%s\n' "$rows" | awk '$1 ~ /^[0-9]+$/ {c++} END{print c+0}')
    fi
    echo "$count"
}

show_status() {
    if [[ -f "$BACKHAUL_BIN" ]] && verify_binary "$BACKHAUL_BIN"; then
        echo -e "${GREEN}✅ Backhaul core installed at $BACKHAUL_BIN${RESET}"
    else
        echo -e "${RED}❌ Backhaul core NOT installed or invalid.${RESET}"
    fi

    if systemctl is-active --quiet backhaul-watchdog.timer 2>/dev/null; then
        echo -e "${GREEN}🛡  Watchdog: active${RESET}"
    else
        echo -e "${YELLOW}🛡  Watchdog: not installed yet${RESET}"
    fi

    echo -e "${CYAN}🔰 Tunnels:${RESET}"
    [[ -f "$STATE_FILE" ]] || return

    while IFS='|' read -r name port transport ip sshport user <&3; do
        [[ -z "$name" ]] && continue
        local local_status established
        if ! systemctl is-active --quiet "${name}.service"; then
            local_status="🔴 not running"
        else
            established=$(local_tunnel_connections "$name" "$transport")
            case "$established" in
                unknown) local_status="🟢 running" ;;
                0) local_status="🟡 running, not connected" ;;
                *) local_status="🟢 connected" ;;
            esac
        fi

        local remote_status="⚪ unknown"
        IRAN_IP="$ip"; IRAN_SSH_PORT="$sshport"; IRAN_USER="$user"
        if ssh_ok </dev/null; then
            if remote_run "systemctl is-active ${name}.service" </dev/null 2>/dev/null | grep -q "^active"; then
                remote_status="🟢 running"
            else
                remote_status="🔴 not running"
            fi
        else
            remote_status="⚪ unreachable"
        fi

        echo -e " - ${name} (${transport}, port ${port}) → Iran ${ip}: ${remote_status} | This server: ${local_status}"
    done 3< "$STATE_FILE"
}

view_watchdog_log() {
    if [[ ! -f /var/log/backhaul-watchdog.log ]]; then
        die "No watchdog log yet — it appears after the first check cycle (within ~2 minutes of setup)."
        return
    fi

    echo -e "${CYAN}Last 50 watchdog entries (this server):${RESET}"
    tail -n 50 /var/log/backhaul-watchdog.log
    read -p "Follow live? (y/N): " follow
    if [[ "$follow" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Press Ctrl+C to stop following and return to the menu.${RESET}"
        trap 'kill $TAIL_PID 2>/dev/null' INT
        tail -f /var/log/backhaul-watchdog.log &
        TAIL_PID=$!
        wait $TAIL_PID 2>/dev/null
        trap graceful_exit INT
    fi
    read -p "Press Enter to continue..." _
}

migrate_tunnel() {
    [[ -f "$STATE_FILE" ]] || { die "No tunnels found."; return; }

    mapfile -t entries < <(grep -v '^[[:space:]]*$' "$STATE_FILE")
    if [[ ${#entries[@]} -eq 0 ]]; then
        die "No tunnels found."
        return
    fi

    echo -e "${YELLOW}Select a tunnel to point at a new Iran server:${RESET}"
    local i en ename eport etransport eip
    for i in "${!entries[@]}"; do
        en="${entries[$i]}"
        IFS='|' read -r ename eport etransport eip _ _ <<< "$en"
        echo "$((i+1))) ${ename} (${etransport}, port ${eport}) currently -> ${eip}"
    done
    echo "0) Back"
    read -p "Choice: " sel
    [[ "$sel" == "0" ]] && return
    if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${#entries[@]} )); then
        die "Invalid selection."
        return
    fi

    local entry="${entries[$((sel-1))]}"
    local name old_port transport old_ip old_sshport old_user
    IFS='|' read -r name old_port transport old_ip old_sshport old_user <<< "$entry"

    if [[ ! -f "/root/${name}.toml" ]]; then
        die "Local config /root/${name}.toml not found, cannot migrate ${name}."
        return
    fi

    local EXISTING_TOKEN
    EXISTING_TOKEN=$(grep -m1 '^token' "/root/${name}.toml" | cut -d'"' -f2)
    if [[ -z "$EXISTING_TOKEN" ]]; then
        die "Could not read the existing token from /root/${name}.toml."
        return
    fi

    echo -e "${CYAN}== New Iran Server Details for ${name} (old: ${old_ip}) ==${RESET}"
    while true; do
        read -p "New Iran server IP or hostname: " IRAN_IP
        [[ -n "$IRAN_IP" ]] && break
        echo -e "${RED}Cannot be empty.${RESET}"
    done
    while true; do
        read -p "New Iran SSH port [22]: " IRAN_SSH_PORT
        IRAN_SSH_PORT=${IRAN_SSH_PORT:-22}
        [[ "$IRAN_SSH_PORT" =~ ^[0-9]+$ ]] && break
        echo -e "${RED}Port must be numeric.${RESET}"
    done
    read -p "New Iran SSH username [root]: " IRAN_USER
    IRAN_USER=${IRAN_USER:-root}
    read -s -p "New Iran SSH password: " IRAN_PASS
    echo

    setup_iran_ssh_access || { unset IRAN_PASS; return; }
    unset IRAN_PASS
    verify_remote_root || return
    remote_install_backhaul || return

    if ! check_remote_port_free "$old_port"; then
        die "Port ${old_port} is already in use on the new Iran server. Free it first, or remove this tunnel and set up a fresh one with a different port."
        return
    fi

    while true; do
        read -p "User-facing ports to forward, comma separated (e.g. 443,8080-8090): " USER_PORTS
        if validate_ports "$USER_PORTS"; then
            break
        fi
        echo -e "${RED}Invalid port format, try again.${RESET}"
    done

    local BEST_MSS=1360 MSS_LINE=""
    if [[ "$transport" != "udp" ]]; then
        echo -e "${CYAN}[+] Measuring optimal MSS for the new route...${RESET}"
        BEST_MSS=$(discover_best_mss)
        MSS_LINE="mss = ${BEST_MSS}"
    fi

    local TUNNEL_PORT="$old_port"
    local CONFIG_NAME="$name"
    local TOKEN="$EXISTING_TOKEN"
    local TRANSPORT="$transport"
    local ACCEPT_UDP="false"
    [[ "$TRANSPORT" == "tcpmux" ]] && ACCEPT_UDP="true"
    local PORT_LINES
    PORT_LINES=$(format_ports_array "$USER_PORTS")

    local SERVER_CONF SERVER_SERVICE
    if [[ "$TRANSPORT" == "tcpmux" ]]; then
        SERVER_CONF=$(cat <<EOF
[server]
bind_addr = "0.0.0.0:${TUNNEL_PORT}"
transport = "${TRANSPORT}"
accept_udp = ${ACCEPT_UDP}
token = "${TOKEN}"
keepalive_period = 75
nodelay = true
heartbeat = 20
channel_size = 4096
mux_con = 16
mux_version = 2
mux_framesize = 32768
mux_recievebuffer = 8388608
mux_streambuffer = 262144
mss = ${BEST_MSS}
so_rcvbuf = 8388608
so_sndbuf = 8388608
web_port = 0
log_level = "info"
ports = [
${PORT_LINES}
]
EOF
)
    else
        SERVER_CONF=$(cat <<EOF
[server]
bind_addr = "0.0.0.0:${TUNNEL_PORT}"
transport = "${TRANSPORT}"
token = "${TOKEN}"
keepalive_period = 75
nodelay = true
heartbeat = 20
channel_size = 4096
${MSS_LINE}
web_port = 0
log_level = "info"
ports = [
${PORT_LINES}
]
EOF
)
    fi

    SERVER_SERVICE=$(cat <<EOF
[Unit]
Description=Backhaul Reverse Tunnel Server (${CONFIG_NAME})
After=network.target

[Service]
Type=simple
ExecStart=/root/backhaul -c /root/${CONFIG_NAME}.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
)

    echo -e "${YELLOW}[+] Pushing server config to the new Iran server...${RESET}"
    if ! remote_write_file "/root/${CONFIG_NAME}.toml" "$SERVER_CONF"; then
        rollback_remote_config
        die "Failed to reliably write the server config on the new Iran server after multiple attempts. Rolled back."
        return
    fi
    if ! remote_write_file "/etc/systemd/system/${CONFIG_NAME}.service" "$SERVER_SERVICE"; then
        rollback_remote_config
        die "Failed to reliably write the systemd service on the new Iran server after multiple attempts. Rolled back."
        return
    fi
    if ! remote_run_retry "systemctl daemon-reload && systemctl enable ${CONFIG_NAME}.service && systemctl restart ${CONFIG_NAME}.service"; then
        rollback_remote_config
        die "Could not start the tunnel service on the new Iran server. Rolled back."
        return
    fi

    echo -e "${YELLOW}[+] Re-pointing local client config at the new Iran server...${RESET}"
    sed -i "s|^remote_addr = .*|remote_addr = \"${IRAN_IP}:${TUNNEL_PORT}\"|" "/root/${name}.toml"
    if [[ -n "$MSS_LINE" ]] && grep -q '^mss' "/root/${name}.toml"; then
        sed -i "s|^mss = .*|mss = ${BEST_MSS}|" "/root/${name}.toml"
    fi

    systemctl restart "${name}.service"
    sleep 2
    if ! systemctl is-active --quiet "${name}.service"; then
        systemctl restart "${name}.service"
        sleep 2
    fi

    echo -e "${YELLOW}[+] Installing watchdog and status tool on the new Iran server...${RESET}"
    install_watchdog_remote
    install_quality_watchdog_remote
    install_status_script_remote

    awk -F'|' -v n="$name" -v ip="$IRAN_IP" -v sp="$IRAN_SSH_PORT" -v us="$IRAN_USER" \
        'BEGIN{OFS="|"} $1==n {$4=ip;$5=sp;$6=us} {print}' "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"

    echo -e "${CYAN}[+] Verifying connection to the new Iran server...${RESET}"
    local ok=0 j
    for j in $(seq 1 10); do
        sleep 2
        local logs
        logs=$(journalctl -u "${name}.service" --no-pager -n 30 2>/dev/null | tr '[:upper:]' '[:lower:]')
        if echo "$logs" | grep -Eq "control channel established successfully|client with remote address.*started successfully"; then
            ok=1
            break
        fi
    done

    if [[ "$ok" -eq 1 ]]; then
        echo -e "${GREEN}[✔] ${name} is now UP and connected to the new Iran server (${IRAN_IP}). Old server (${old_ip}) was not touched.${RESET}"
    else
        echo -e "${YELLOW}[!] Re-pointed, but connection not confirmed yet. The watchdog will keep retrying; check Live Status shortly.${RESET}"
    fi
    read -p "Press Enter to continue..." _
}

speed_test_tunnel() {
    [[ -f "$STATE_FILE" ]] || { die "No tunnels found."; return; }
    mapfile -t entries < <(grep -v '^[[:space:]]*$' "$STATE_FILE")
    if [[ ${#entries[@]} -eq 0 ]]; then
        die "No tunnels found."
        return
    fi

    echo -e "${YELLOW}Select a tunnel to speed-test:${RESET}"
    local i en ename eport etransport eip
    for i in "${!entries[@]}"; do
        en="${entries[$i]}"
        IFS='|' read -r ename eport etransport eip _ _ <<< "$en"
        echo "$((i+1))) ${ename} (${etransport}, port ${eport}) -> ${eip}"
    done
    echo "0) Back"
    read -p "Choice: " sel
    [[ "$sel" == "0" ]] && return
    if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${#entries[@]} )); then
        die "Invalid selection."
        return
    fi

    local entry="${entries[$((sel-1))]}"
    local name port transport ip sshport user
    IFS='|' read -r name port transport ip sshport user <<< "$entry"

    IRAN_IP="$ip"; IRAN_SSH_PORT="$sshport"; IRAN_USER="$user"
    if ! ssh_ok </dev/null; then
        die "Cannot reach the Iran server for ${name} right now."
        return
    fi

    echo -e "${YELLOW}[!] This test restarts ${name} on the Iran server twice (to add and then remove a scratch port).${RESET}"
    echo -e "${YELLOW}    Users on this tunnel are disconnected for a few seconds each time.${RESET}"
    read -p "Continue? (y/N): " speed_confirm
    [[ "$speed_confirm" =~ ^[Yy]$ ]] || return

    echo -e "${CYAN}[+] Picking a free scratch port on Iran (won't touch your live forwarded ports)...${RESET}"
    local test_port=""
    local try
    for try in 1 2 3 4 5; do
        local candidate=$(( (RANDOM % 20000) + 40000 ))
        if check_remote_port_free "$candidate"; then
            test_port="$candidate"
            break
        fi
    done
    if [[ -z "$test_port" ]]; then
        die "Could not find a free scratch port on the Iran server for testing."
        return
    fi
    echo -e "${CYAN}    Using scratch port ${test_port}.${RESET}"

    echo -e "${CYAN}[+] Temporarily adding ${test_port} to ${name}'s forwarded ports on Iran...${RESET}"
    if ! remote_run_retry "sed -i '/^ports = \[/a\\  \"${test_port}\",' /root/${name}.toml && systemctl restart ${name}.service"; then
        die "Could not add the scratch port on the Iran server."
        return
    fi
    sleep 2

    cleanup_scratch_port() {
        remote_run_retry "sed -i '/\"${test_port}\",/d' /root/${name}.toml && systemctl restart ${name}.service" &>/dev/null
    }

    echo -e "${CYAN}[+] Making sure iperf3 is installed locally...${RESET}"
    if ! command -v iperf3 &>/dev/null; then
        apt_install_retry "iperf3"
    fi
    if ! command -v iperf3 &>/dev/null; then
        cleanup_scratch_port
        die "Could not install iperf3 locally after several attempts. Check this server's internet/apt access."
        return
    fi

    pkill -f "iperf3 -s -p ${test_port} " 2>/dev/null
    sleep 1

    echo -e "${CYAN}[+] Running test 1/2 through the tunnel (this server -> Iran public IP -> back), 8 seconds...${RESET}"
    nohup iperf3 -s -p "$test_port" -1 -f m &>/tmp/bh_iperf_srv.log &
    sleep 2
    local up_out up_mbps
    up_out=$(timeout 30 iperf3 -c "${IRAN_IP}" -p "$test_port" -t 8 -f m 2>&1)
    up_mbps=$(echo "$up_out" | grep -i receiver | awk '{print $7}' | head -1)

    sleep 1
    echo -e "${CYAN}[+] Running test 2/2, reversed direction, same loop, 8 seconds...${RESET}"
    nohup iperf3 -s -p "$test_port" -1 -f m &>/tmp/bh_iperf_srv.log &
    sleep 2
    local down_out down_mbps
    down_out=$(timeout 30 iperf3 -c "${IRAN_IP}" -p "$test_port" -t 8 -f m -R 2>&1)
    down_mbps=$(echo "$down_out" | grep -i receiver | awk '{print $7}' | head -1)

    pkill -f "iperf3 -s -p ${test_port} " 2>/dev/null

    echo -e "${CYAN}[+] Removing the scratch port from Iran, restoring the tunnel to normal...${RESET}"
    cleanup_scratch_port

    echo
    echo -e "${CYAN}== Speed Test Result for ${name} (via scratch port ${test_port}, through the tunnel) ==${RESET}"
    echo -e "${CYAN}(Your forwarded ports were not changed; the tunnel was restarted twice for this test.)${RESET}"
    if [[ -z "$up_mbps" ]]; then
        echo -e "${RED}Test 1 failed (could not measure). Raw output:${RESET}"
        echo "$up_out" | sed 's/^/    /'
    else
        echo -e "Outbound leg (this server -> Iran -> back): ${GREEN}${up_mbps} Mbps${RESET}"
    fi
    if [[ -z "$down_mbps" ]]; then
        echo -e "${RED}Test 2 failed (could not measure). Raw output:${RESET}"
        echo "$down_out" | sed 's/^/    /'
    else
        echo -e "Reverse leg  (Iran -> this server, same loop): ${GREEN}${down_mbps} Mbps${RESET}"
    fi

    echo
    if [[ -z "$up_mbps" || -z "$down_mbps" ]]; then
        echo -e "${YELLOW}Could not produce a verdict since one or both directions failed to measure.${RESET}"
    else
        local verdict
        verdict=$(awk -v u="$up_mbps" -v d="$down_mbps" 'BEGIN{ m=(u<d)?u:d; if (m>=30) print "EXCELLENT"; else if (m>=8) print "ACCEPTABLE"; else print "POOR" }')
        case "$verdict" in
            EXCELLENT) echo -e "${GREEN}Verdict: EXCELLENT — plenty of headroom for multiple simultaneous users and HD streaming.${RESET}" ;;
            ACCEPTABLE) echo -e "${YELLOW}Verdict: ACCEPTABLE — fine for normal browsing, may feel tight with many simultaneous users or heavy streaming.${RESET}" ;;
            POOR) echo -e "${RED}Verdict: POOR — likely to feel slow. Worth checking MSS, BBR/congestion control, or the underlying link itself.${RESET}" ;;
        esac
    fi
    read -p "Press Enter to continue..." _
}

remove_tunnel() {
    [[ -f "$STATE_FILE" ]] || { die "No tunnels found."; return; }

    mapfile -t entries < <(grep -v '^[[:space:]]*$' "$STATE_FILE")
    if [[ ${#entries[@]} -eq 0 ]]; then
        die "No tunnels found."
        return
    fi

    echo -e "${YELLOW}Select a tunnel to remove:${RESET}"
    for i in "${!entries[@]}"; do
        echo "$((i+1))) $(echo "${entries[$i]}" | cut -d'|' -f1)"
    done
    echo "0) Back"
    read -p "Choice: " sel
    [[ "$sel" == "0" ]] && return
    if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${#entries[@]} )); then
        die "Invalid selection."
        return
    fi

    local entry="${entries[$((sel-1))]}"
    IFS='|' read -r name port transport ip sshport user <<< "$entry"

    systemctl stop "${name}.service" 2>/dev/null || true
    systemctl disable "${name}.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/${name}.service" "/root/${name}.toml"
    systemctl daemon-reload

    IRAN_IP="$ip"; IRAN_SSH_PORT="$sshport"; IRAN_USER="$user"
    if ssh_ok; then
        remote_run_retry "systemctl stop ${name}.service 2>/dev/null; systemctl disable ${name}.service 2>/dev/null; rm -f /etc/systemd/system/${name}.service /root/${name}.toml; systemctl daemon-reload"
    fi

    grep -v "^${name}|" "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
    echo -e "${GREEN}[✔] Tunnel ${name} removed (local and remote).${RESET}"
    read -p "Press Enter to continue..." _
}

full_uninstall() {
    read -p "This removes ALL tunnels, configs, the watchdog and the local core. Type 'yes' to confirm: " confirm
    [[ "$confirm" != "yes" ]] && return

    if [[ -f "$STATE_FILE" ]]; then
        while IFS='|' read -r name port transport ip sshport user; do
            [[ -z "$name" ]] && continue
            systemctl stop "${name}.service" 2>/dev/null || true
            systemctl disable "${name}.service" 2>/dev/null || true
            rm -f "/etc/systemd/system/${name}.service" "/root/${name}.toml"
        done < "$STATE_FILE"
    fi

    systemctl stop backhaul-watchdog.timer 2>/dev/null || true
    systemctl disable backhaul-watchdog.timer 2>/dev/null || true
    rm -f /etc/systemd/system/backhaul-watchdog.service /etc/systemd/system/backhaul-watchdog.timer /usr/local/bin/backhaul-watchdog.sh

    rm -f "$STATE_FILE" "$BACKHAUL_BIN"
    systemctl daemon-reload
    echo -e "${GREEN}[✔] Full local uninstall complete.${RESET}"
    read -p "Press Enter to continue..." _
}

main_menu() {
    while true; do
        clear
        show_status
        echo -e "${CYAN}"
        echo "┌────────────────────────────────────────────────────────────────┐"
        echo "│                    EYLAN BACKHAUL MANAGER                       │"
        echo "├────────────────────────────────────────────────────────────────┤"
        echo "│ 1. Full Auto Setup (run on Kharej, configures Iran over SSH)   │"
        echo "│ 2. Update / Repair Installation                                │"
        echo "│ 3. Live Status                                                 │"
        echo "│ 4. View Watchdog Log                                           │"
        echo "│ 5. Migrate a Tunnel to a New Iran Server                       │"
        echo "│ 6. Speed Test (Upload/Download through a Tunnel)               │"
        echo "│ 7. Remove a Tunnel                                             │"
        echo "│ 8. Full Uninstall (local)                                      │"
        echo "│ 0. Exit                                                        │"
        echo "└────────────────────────────────────────────────────────────────┘"
        echo -e "${RESET}"
        read -p "Select an option [0-8]: " choice
        case $choice in
            1) setup_full_tunnel ;;
            2) update_installation ;;
            3) read -p "Press Enter to return..." _ ;;
            4) view_watchdog_log ;;
            5) migrate_tunnel ;;
            6) speed_test_tunnel ;;
            7) remove_tunnel ;;
            8) full_uninstall ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid option.${RESET}"; sleep 1 ;;
        esac
    done
}

ensure_root
ensure_single_instance
touch "$STATE_FILE"
trap graceful_exit INT TERM
main_menu

#!/usr/bin/env bash
set -euo pipefail

WG_IFACE="${WG_IFACE:-wg1}"
WG_DIR="${WG_DIR:-/etc/wireguard}"
WG1_PORT="${WG1_PORT:-51821}"
WG1_ADDR="${WG1_ADDR:-10.201.201.1/16}"

WG_CONF="${WG_DIR}/${WG_IFACE}.conf"
WG_BASE="${WG_DIR}/${WG_IFACE}_base.conf"
WG_PRIV="${WG_DIR}/${WG_IFACE}_privatekey"
WG_PUB="${WG_DIR}/${WG_IFACE}_publickey"
WG_PEERS_DB="${WG_DIR}/${WG_IFACE}_peers.json"

log() { echo -e "[WG1] $*"; }

die() { echo -e "[WG1][ERR] $*" >&2; exit 1; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Please run as root (sudo)."
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

pkg_install() {
  if have_cmd apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y --no-install-recommends wireguard wireguard-tools iproute2 iptables
    apt-get install -y --no-install-recommends iptables-persistent netfilter-persistent || true
  elif have_cmd dnf; then
    dnf -y install wireguard-tools iproute iptables || true
  elif have_cmd yum; then
    yum -y install wireguard-tools iproute iptables || true
  elif have_cmd apk; then
    apk add --no-cache wireguard-tools iproute2 iptables || true
  else
    die "No supported package manager found (apt/dnf/yum/apk). Install wireguard-tools manually."
  fi
}

detect_public_iface() {
  local iface
  iface="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
  if [[ -z "${iface}" ]]; then
    iface="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5; exit}')"
  fi
  echo "${iface:-eth0}"
}

enable_ip_forward() {
  log "Enabling net.ipv4.ip_forward..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
  mkdir -p /etc/sysctl.d
  cat > "/etc/sysctl.d/99-${WG_IFACE}.conf" <<EOF
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null 2>&1 || true
}

ensure_dirs() {
  mkdir -p "${WG_DIR}"
  chmod 700 "${WG_DIR}" || true
}

gen_keys_if_missing() {
  if [[ -s "${WG_PRIV}" && -s "${WG_PUB}" ]]; then
    return 0
  fi
  log "Generating ${WG_IFACE} server keys..."
  umask 077
  wg genkey | tee "${WG_PRIV}" | wg pubkey > "${WG_PUB}"
  chmod 600 "${WG_PRIV}" "${WG_PUB}" || true
}

write_peers_db_if_missing() {
  if [[ -f "${WG_PEERS_DB}" ]]; then
    chmod 600 "${WG_PEERS_DB}" || true
    return 0
  fi
  log "Creating empty peers DB: ${WG_PEERS_DB}"
  echo '{}' > "${WG_PEERS_DB}"
  chmod 600 "${WG_PEERS_DB}" || true
}

write_base_conf() {
  local pub_iface
  pub_iface="$(detect_public_iface)"

  log "Writing base config: ${WG_BASE} (public iface: ${pub_iface})"

  cat > "${WG_BASE}" <<EOF
[Interface]
Address = ${WG1_ADDR}
ListenPort = ${WG1_PORT}
PrivateKey = $(cat "${WG_PRIV}")
SaveConfig = false


PostUp = ip route add 10.201.0.0/24 dev %i 2>/dev/null || true; iptables -t nat -I POSTROUTING 1 -s 10.201.0.0/24 -o ${pub_iface} -j MASQUERADE
PostDown = ip route del 10.201.0.0/24 dev %i 2>/dev/null || true; iptables -t nat -D POSTROUTING -s 10.201.0.0/24 -o ${pub_iface} -j MASQUERADE
EOF

  chmod 600 "${WG_BASE}" || true
}

ensure_conf_exists() {
  if [[ ! -f "${WG_CONF}" ]]; then
    log "Creating initial ${WG_CONF} from base..."
    cp -f "${WG_BASE}" "${WG_CONF}"
    echo "" >> "${WG_CONF}"
    chmod 600 "${WG_CONF}" || true
  else
    chmod 600 "${WG_CONF}" || true
  fi
}

open_firewall() {
  log "Opening firewall for UDP/${WG1_PORT} (best-effort)..."

  if have_cmd ufw; then
    ufw allow "${WG1_PORT}/udp" >/dev/null 2>&1 || true
  fi

  iptables -C INPUT -p udp --dport "${WG1_PORT}" -j ACCEPT 2>/dev/null || \
    iptables -I INPUT -p udp --dport "${WG1_PORT}" -j ACCEPT || true

  if have_cmd netfilter-persistent; then
    netfilter-persistent save >/dev/null 2>&1 || true
  elif have_cmd service; then
    service netfilter-persistent save >/dev/null 2>&1 || true
  fi
}

start_service() {
  log "Enabling and restarting wg-quick@${WG_IFACE}..."
  systemctl enable "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || true
  systemctl restart "wg-quick@${WG_IFACE}" || true

  if systemctl is-active --quiet "wg-quick@${WG_IFACE}"; then
    log "Service is active."
  else
    log "Service is not active yet (this can be OK if panel overwrites wg1.conf shortly)."
    log "Check logs: journalctl -u wg-quick@${WG_IFACE} --no-pager | tail -n 80"
  fi
}

main() {
  need_root

  if ! have_cmd wg; then
    log "WireGuard tools not found. Installing..."
    pkg_install
  fi

  ensure_dirs
  enable_ip_forward
  gen_keys_if_missing
  write_peers_db_if_missing
  write_base_conf
  ensure_conf_exists
  open_firewall
  start_service

  log "Done."
  log "PublicKey: $(cat "${WG_PUB}" 2>/dev/null || echo "<missing>")"
  log "Base: ${WG_BASE}"
  log "Conf: ${WG_CONF}"
  log "Peers DB: ${WG_PEERS_DB}"
}

main "$@"

#!/bin/bash
set -e

SINGBOX_VERSION="1.13.13"
BIN_PATH="/usr/local/bin/eylan-singbox"
CONF_DIR="/etc/eylan-singbox"
CONF_PATH="${CONF_DIR}/config.json"
SERVICE_NAME="eylan-singbox"

export DEBIAN_FRONTEND=noninteractive

wait_for_apt_lock() {
    while fuser /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock >/dev/null 2>&1; do
        echo "Waiting for other apt/dpkg processes to release locks..."
        sleep 3
    done
}

install_dependencies() {
    if command -v tar >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
        return 0
    fi
    wait_for_apt_lock
    apt-get update -y
    apt-get install -y --no-install-recommends curl tar ca-certificates
}

install_binary_if_missing() {
    if [ -x "$BIN_PATH" ]; then
        installed_version=$("$BIN_PATH" version 2>/dev/null | head -1 | awk '{print $3}')
        if [ "$installed_version" = "$SINGBOX_VERSION" ]; then
            echo "eylan-singbox binary already present (v${SINGBOX_VERSION}) -- skipping download."
            return 0
        fi
        echo "eylan-singbox binary present but version mismatch (found: ${installed_version:-unknown}, want: ${SINGBOX_VERSION}) -- reinstalling this binary only."
    fi

    echo "Downloading sing-box v${SINGBOX_VERSION}..."
    tmp_dir=$(mktemp -d)
    url="https://gh-proxy.com/https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz"
    if ! curl -fsSL -o "${tmp_dir}/sing-box.tar.gz" "$url"; then
        echo "Primary download failed, retrying direct GitHub URL..."
        curl -fsSL -o "${tmp_dir}/sing-box.tar.gz" \
            "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz"
    fi
    tar xzf "${tmp_dir}/sing-box.tar.gz" -C "$tmp_dir"
    mv "${tmp_dir}/sing-box-${SINGBOX_VERSION}-linux-amd64/sing-box" "$BIN_PATH"
    chmod +x "$BIN_PATH"
    rm -rf "$tmp_dir"
    echo "eylan-singbox binary installed at ${BIN_PATH}."
}

ensure_config_exists() {
    mkdir -p "$CONF_DIR"
    if [ -f "$CONF_PATH" ]; then
        echo "Config already exists at ${CONF_PATH} -- leaving it untouched (users/inbounds preserved)."
        return 0
    fi
    mkdir -p /var/log/eylan-singbox
    cat > "$CONF_PATH" <<'EOF'
{
  "log": {
    "level": "info",
    "output": "/var/log/eylan-singbox/access.log",
    "timestamp": true
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9190"
    }
  },
  "inbounds": [],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}
EOF
    chmod 600 "$CONF_PATH"
    echo "Created initial empty config at ${CONF_PATH}."

    if [ ! -f /etc/logrotate.d/eylan-singbox ]; then
        cat > /etc/logrotate.d/eylan-singbox <<'EOF'
/var/log/eylan-singbox/access.log {
    daily
    rotate 3
    missingok
    notifempty
    compress
    copytruncate
}
EOF
    fi
}

ensure_service_exists() {
    if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
        echo "Service ${SERVICE_NAME}.service already exists -- leaving it untouched."
        systemctl daemon-reload
        return 0
    fi
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=EylanPanel sing-box instance (isolated from any other sing-box install)
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=${BIN_PATH} run -c ${CONF_PATH}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo "Created systemd service ${SERVICE_NAME}.service."
}

main() {
    install_dependencies
    install_binary_if_missing
    ensure_config_exists
    ensure_service_exists

    systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
    systemctl restart "${SERVICE_NAME}"
    sleep 1
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo "SUCCESS: ${SERVICE_NAME} is active (binary: ${BIN_PATH}, config: ${CONF_PATH})."
    else
        echo "ERROR: ${SERVICE_NAME} failed to start. Check: journalctl -u ${SERVICE_NAME}"
        exit 1
    fi
}

main

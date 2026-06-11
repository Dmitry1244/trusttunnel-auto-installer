#!/usr/bin/env bash
set -euo pipefail

# Интерактивный установщик TrustTunnel endpoint + WARP.
# Целевая система: чистый Ubuntu/Debian VPS, запускать от root.
#
# Интерактивный запуск:
#   bash install-trusttunnel-warp.sh
#
# Автоматический запуск без вопросов:
#   CLIENTS=21 SSH_PORT=22 EMAIL=admin@example.com ENABLE_WARP=1 bash install-trusttunnel-warp.sh

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-admin@example.com}"
CLIENTS="${CLIENTS:-}"
SSH_PORT="${SSH_PORT:-}"
CHANGE_SSH_PORT="${CHANGE_SSH_PORT:-}"
ENABLE_WARP="${ENABLE_WARP:-}"
ENABLE_QUIC="${ENABLE_QUIC:-}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-}"
ENABLE_SYSTEM_UPGRADE="${ENABLE_SYSTEM_UPGRADE:-}"
ACTION="${ACTION:-}"
CONFIRM_FIREWALL_RESET="${CONFIRM_FIREWALL_RESET:-}"
TT_VERSION="${TT_VERSION:-v1.0.33}"
WGCF_VERSION="${WGCF_VERSION:-2.2.31}"
WIREPROXY_VERSION="${WIREPROXY_VERSION:-v1.1.2}"

TT_DIR="/opt/trusttunnel"
WARP_DIR="/opt/warp-proxy"
CLIENT_DIR="/root/trusttunnel-clients"
SOCKS_ADDR="127.0.0.1:40000"
WARP_HEALTH_ADDR="127.0.0.1:40001"

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Запусти скрипт от root." >&2
    exit 1
  fi
}

prompt_value() {
  local message="$1"
  if [ -r /dev/tty ]; then
    read -r -p "$message" REPLY_VALUE </dev/tty
  else
    read -r -p "$message" REPLY_VALUE
  fi
}

ask_required() {
  local var_name="$1"
  local message="$2"
  local value
  value="$(eval "printf '%s' \"\${${var_name}:-}\"")"
  while [ -z "$value" ]; do
    prompt_value "$message"
    value="$REPLY_VALUE"
  done
  printf -v "$var_name" '%s' "$value"
}

ask_default() {
  local var_name="$1"
  local message="$2"
  local default_value="$3"
  local value
  value="$(eval "printf '%s' \"\${${var_name}:-}\"")"
  if [ -n "$value" ]; then
    return
  fi
  prompt_value "${message} [${default_value}]: "
  value="${REPLY_VALUE:-$default_value}"
  printf -v "$var_name" '%s' "$value"
}

ask_yes_no() {
  local var_name="$1"
  local message="$2"
  local default_value="$3"
  local value prompt_suffix
  value="$(eval "printf '%s' \"\${${var_name}:-}\"")"
  if [ "$value" = "0" ] || [ "$value" = "1" ]; then
    return
  fi
  if [ "$default_value" = "1" ]; then
    prompt_suffix="Y/n"
  else
    prompt_suffix="y/N"
  fi
  while true; do
    prompt_value "${message} [${prompt_suffix}]: "
    value="${REPLY_VALUE:-}"
    case "$value" in
      y|Y|yes|YES|Yes|д|Д|да|Да|ДА) printf -v "$var_name" '%s' "1"; return ;;
      n|N|no|NO|No|н|Н|нет|Нет|НЕТ) printf -v "$var_name" '%s' "0"; return ;;
      "") printf -v "$var_name" '%s' "$default_value"; return ;;
      *) echo "Ответь y/n или да/нет." ;;
    esac
  done
}

detect_current_ssh_port() {
  if [ -n "${SSH_CONNECTION:-}" ]; then
    set -- $SSH_CONNECTION
    if [ $# -ge 4 ]; then
      printf '%s' "$4"
      return
    fi
  fi
  printf '22'
}

choose_action() {
  if [ -n "$ACTION" ]; then
    return
  fi

  while true; do
    echo
    echo "=== TrustTunnel auto-installer ==="
    echo "1) Установить или переустановить TrustTunnel"
    echo "2) Удалить TrustTunnel и WARP"
    echo "3) Установить или переустановить только WARP"
    echo "4) Удалить только WARP и переключить TrustTunnel на direct"
    echo "5) Показать статус"
    echo "0) Выход"
    echo
    prompt_value "Выбери действие [1]: "
    case "${REPLY_VALUE:-1}" in
      1) ACTION="install"; return ;;
      2) ACTION="remove-all"; return ;;
      3) ACTION="install-warp"; return ;;
      4) ACTION="remove-warp"; return ;;
      5) ACTION="status"; return ;;
      0) ACTION="exit"; return ;;
      *) echo "Нужно выбрать 0, 1, 2, 3, 4 или 5." ;;
    esac
  done
}

collect_config() {
  local detected_ssh_port
  detected_ssh_port="$(detect_current_ssh_port)"

  echo
  echo "=== Установка TrustTunnel + WARP ==="
  echo
  ask_required DOMAIN "Домен для TrustTunnel, например vpn.example.com: "
  ask_default CLIENTS "Сколько клиентов создать" "21"
  ask_yes_no CHANGE_SSH_PORT "Поменять SSH-порт сервера" "1"
  if [ "$CHANGE_SSH_PORT" = "1" ]; then
    ask_default SSH_PORT "Новый SSH-порт сервера" "49222"
  else
    ask_default SSH_PORT "Текущий SSH-порт, который нужно оставить открытым" "$detected_ssh_port"
  fi
  ask_yes_no ENABLE_SYSTEM_UPGRADE "Обновить систему перед установкой" "1"
  ask_yes_no ENABLE_WARP "Включить WARP для скрытия IP сервера от сайтов" "1"
  ask_yes_no ENABLE_QUIC "Включить QUIC/HTTP3 на UDP 443" "1"
  ask_yes_no ENABLE_FAIL2BAN "Включить fail2ban для защиты SSH" "1"

  if [ -z "$CONFIRM_FIREWALL_RESET" ]; then
    echo
    echo "Скрипт сбросит UFW firewall и откроет только:"
    echo "- ${SSH_PORT}/tcp для SSH"
    echo "- 443/tcp для TrustTunnel"
    ask_yes_no CONFIRM_FIREWALL_RESET "Продолжить" "0"
  fi
  if [ "$CONFIRM_FIREWALL_RESET" != "1" ]; then
    echo "Отменено."
    exit 1
  fi

  echo
  echo "Параметры установки:"
  echo "- Домен: ${DOMAIN}"
  echo "- Клиентов: ${CLIENTS}"
  echo "- Менять SSH-порт: ${CHANGE_SSH_PORT}"
  echo "- SSH-порт для firewall/fail2ban: ${SSH_PORT}"
  echo "- Обновить систему: ${ENABLE_SYSTEM_UPGRADE}"
  echo "- WARP: ${ENABLE_WARP}"
  echo "- QUIC/HTTP3: ${ENABLE_QUIC}"
  echo "- fail2ban: ${ENABLE_FAIL2BAN}"
  echo
}

confirm_action() {
  local message="$1"
  local answer=""
  prompt_value "$message Напиши YES для подтверждения: "
  answer="$REPLY_VALUE"
  if [ "$answer" != "YES" ]; then
    echo "Отменено."
    exit 1
  fi
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  if [ "$ENABLE_SYSTEM_UPGRADE" = "1" ]; then
    apt-get upgrade -y
  fi
  local packages
  packages="ca-certificates curl tar gzip openssl ufw iproute2 python3 zip coreutils sed grep gawk"
  if [ "$ENABLE_FAIL2BAN" = "1" ]; then
    packages="$packages fail2ban"
  fi
  apt-get install -y --no-install-recommends $packages
}

download_trusttunnel() {
  local arch asset url tmp
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) asset="trusttunnel-${TT_VERSION}-linux-x86_64.tar.gz" ;;
    aarch64|arm64) asset="trusttunnel-${TT_VERSION}-linux-aarch64.tar.gz" ;;
    *) echo "Unsupported CPU architecture: $arch" >&2; exit 1 ;;
  esac

  url="https://github.com/TrustTunnel/TrustTunnel/releases/download/${TT_VERSION}/${asset}"
  tmp="$(mktemp -d)"
  mkdir -p "$TT_DIR"
  curl -fL "$url" -o "$tmp/trusttunnel.tar.gz"
  tar -xzf "$tmp/trusttunnel.tar.gz" -C "$tmp"
  find "$tmp" -type f -name trusttunnel_endpoint -exec install -m 0755 {} "$TT_DIR/trusttunnel_endpoint" \;
  find "$tmp" -type f -name setup_wizard -exec install -m 0755 {} "$TT_DIR/setup_wizard" \; || true
  rm -rf "$tmp"

  if [ ! -x "$TT_DIR/trusttunnel_endpoint" ]; then
    echo "Failed to install trusttunnel_endpoint." >&2
    exit 1
  fi
}

download_wireproxy() {
  local arch asset url tmp
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) asset="wireproxy_linux_amd64.tar.gz" ;;
    aarch64|arm64) asset="wireproxy_linux_arm64.tar.gz" ;;
    *) echo "Unsupported CPU architecture for wireproxy: $arch" >&2; exit 1 ;;
  esac

  url="https://github.com/windtf/wireproxy/releases/download/${WIREPROXY_VERSION}/${asset}"
  tmp="$(mktemp -d)"
  mkdir -p "$WARP_DIR/bin"
  curl -fL "$url" -o "$tmp/wireproxy.tar.gz"
  tar -xzf "$tmp/wireproxy.tar.gz" -C "$tmp"
  find "$tmp" -type f -name wireproxy -exec install -m 0755 {} "$WARP_DIR/bin/wireproxy" \;
  rm -rf "$tmp"

  if [ ! -x "$WARP_DIR/bin/wireproxy" ]; then
    echo "Failed to install wireproxy." >&2
    exit 1
  fi
}

generate_warp_profile() {
  if [ "$ENABLE_WARP" != "1" ]; then
    return
  fi

  local arch wgcf_url work
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) wgcf_url="https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VERSION}/wgcf_${WGCF_VERSION}_linux_amd64" ;;
    aarch64|arm64) wgcf_url="https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VERSION}/wgcf_${WGCF_VERSION}_linux_arm64" ;;
    *) echo "Unsupported CPU architecture for wgcf: $arch" >&2; exit 1 ;;
  esac

  mkdir -p "$WARP_DIR/bin" "$WARP_DIR/wgcf"
  curl -fL "$wgcf_url" -o "$WARP_DIR/bin/wgcf"
  chmod 0755 "$WARP_DIR/bin/wgcf"

  work="$WARP_DIR/wgcf"
  (
    cd "$work"
    if [ ! -f wgcf-account.toml ]; then
      "$WARP_DIR/bin/wgcf" register --accept-tos
    fi
    "$WARP_DIR/bin/wgcf" generate
  )

  if [ ! -f "$work/wgcf-profile.conf" ]; then
    echo "wgcf did not create wgcf-profile.conf." >&2
    exit 1
  fi

  cp "$work/wgcf-profile.conf" "$WARP_DIR/wireproxy.conf"
  cat >> "$WARP_DIR/wireproxy.conf" <<EOF

[Socks5]
BindAddress = ${SOCKS_ADDR}
EOF
  chmod 0600 "$WARP_DIR/wireproxy.conf"
}

write_warp_systemd() {
  cat > /etc/systemd/system/warp-wireproxy.service <<EOF
[Unit]
Description=WARP SOCKS5 proxy for TrustTunnel outbound
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${WARP_DIR}
ExecStart=${WARP_DIR}/bin/wireproxy -c ${WARP_DIR}/wireproxy.conf -i ${WARP_HEALTH_ADDR}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now warp-wireproxy
}

switch_trusttunnel_forwarder() {
  local mode="$1"
  local config="$TT_DIR/vpn.toml"
  local tmp
  if [ ! -f "$config" ]; then
    return
  fi

  cp "$config" "$config.backup.$(date +%Y%m%d%H%M%S)"
  tmp="$(mktemp)"
  awk -v mode="$mode" -v socks_addr="$SOCKS_ADDR" '
    BEGIN { inserted = 0; skip = 0 }
    /^\[forward_protocol\.socks5\]$/ { skip = 1; next }
    /^\[forward_protocol\.direct\]$/ { skip = 1; next }
    skip && /^\[/ { skip = 0 }
    skip { next }
    { print }
    /^\[forward_protocol\]$/ && !inserted {
      print ""
      if (mode == "socks5") {
        print "[forward_protocol.socks5]"
        print "address = \"" socks_addr "\""
        print "extended_auth = false"
      } else {
        print "[forward_protocol.direct]"
      }
      inserted = 1
    }
  ' "$config" > "$tmp"
  cat "$tmp" > "$config"
  rm -f "$tmp"
  systemctl restart trusttunnel 2>/dev/null || true
}

write_certs() {
  mkdir -p "$TT_DIR/certs"
  openssl ecparam -name prime256v1 -genkey -noout -out "$TT_DIR/certs/key.pem"
  cat > "$TT_DIR/certs/openssl.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[dn]
CN = ${DOMAIN}

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = *.${DOMAIN}
EOF
  openssl req -x509 -new -nodes \
    -key "$TT_DIR/certs/key.pem" \
    -sha256 -days 365 \
    -out "$TT_DIR/certs/cert.pem" \
    -config "$TT_DIR/certs/openssl.cnf"
  chmod 0600 "$TT_DIR/certs/key.pem"
  chmod 0644 "$TT_DIR/certs/cert.pem"
}

write_server_config() {
  mkdir -p "$TT_DIR"
  cat > "$TT_DIR/vpn.toml" <<EOF
listen_address = "0.0.0.0:443"
credentials_file = "credentials.toml"
rules_file = "rules.toml"
ipv6_available = true
allow_private_network_connections = false
tls_handshake_timeout_secs = 10
client_listener_timeout_secs = 600
connection_establishment_timeout_secs = 30
tcp_connections_timeout_secs = 604800
udp_connections_timeout_secs = 300
speedtest_enable = false

[forward_protocol]
EOF

  if [ "$ENABLE_WARP" = "1" ]; then
    cat >> "$TT_DIR/vpn.toml" <<EOF
[forward_protocol.socks5]
address = "${SOCKS_ADDR}"
extended_auth = false
EOF
  fi

  cat >> "$TT_DIR/vpn.toml" <<EOF
[listen_protocols]

[listen_protocols.http1]
upload_buffer_size = 32768

[listen_protocols.http2]
initial_connection_window_size = 8388608
initial_stream_window_size = 131072
max_concurrent_streams = 1000
max_frame_size = 16384
header_table_size = 65536
EOF

  if [ "$ENABLE_QUIC" = "1" ]; then
    cat >> "$TT_DIR/vpn.toml" <<'EOF'

[listen_protocols.quic]
recv_udp_payload_size = 1350
send_udp_payload_size = 1350
initial_max_data = 104857600
initial_max_stream_data_bidi_local = 1048576
initial_max_stream_data_bidi_remote = 1048576
initial_max_stream_data_uni = 1048576
initial_max_streams_bidi = 4096
initial_max_streams_uni = 4096
max_connection_window = 25165824
max_stream_window = 16777216
disable_active_migration = true
enable_early_data = true
message_queue_capacity = 4096
EOF
  fi

  cat > "$TT_DIR/hosts.toml" <<EOF
ping_hosts = []
speedtest_hosts = []
reverse_proxy_hosts = []

[[main_hosts]]
hostname = "${DOMAIN}"
cert_chain_path = "certs/cert.pem"
private_key_path = "certs/key.pem"
allowed_sni = []
EOF

  cat > "$TT_DIR/rules.toml" <<'EOF'
# Empty rules file: all authenticated clients are allowed.
EOF
}

random_password() {
  printf 'TT-%s' "$(openssl rand -hex 12)"
}

write_clients() {
  local cert i user pass profile zip_path protocol protocols
  mkdir -p "$CLIENT_DIR"
  cert="$(cat "$TT_DIR/certs/cert.pem")"
  cp "$TT_DIR/certs/cert.pem" "$CLIENT_DIR/server-cert.pem"

  cat > "$TT_DIR/credentials.toml" <<'EOF'
# Managed TrustTunnel users. One user/password per client.
EOF
  : > "$CLIENT_DIR/clients-credentials.txt"

  for i in $(seq -w 1 "$CLIENTS"); do
    user="client${i}"
    pass="$(random_password)"
    cat >> "$TT_DIR/credentials.toml" <<EOF

[[client]]
username = "${user}"
password = "${pass}"
EOF
    printf '%s %s\n' "$user" "$pass" >> "$CLIENT_DIR/clients-credentials.txt"
    protocols="http2"
    if [ "$ENABLE_QUIC" = "1" ]; then
      protocols="http2 http3"
    fi
    for protocol in $protocols; do
      profile="$CLIENT_DIR/${user}-${protocol}.toml"
      cat > "$profile" <<EOF
# Endpoint host name, used for TLS session establishment
hostname = "${DOMAIN}"

# Endpoint addresses in IP:port or hostname:port format
addresses = ["${DOMAIN}:443"]

# Custom SNI value for TLS handshake.
custom_sni = ""

# Whether IPv6 traffic can be routed through the endpoint
has_ipv6 = true

# Username for authorization
username = "${user}"

# Password for authorization
password = "${pass}"

# TLS client random hex prefix for connection filtering.
client_random_prefix = ""

# Skip the endpoint certificate verification?
skip_verification = false

# Endpoint certificate in PEM format.
certificate = """
${cert}
"""

# Protocol to be used to communicate with the endpoint [http2, http3]
upstream_protocol = "${protocol}"

# Is anti-DPI measures should be enabled
anti_dpi = false
EOF
    done
  done

  chmod 0600 "$TT_DIR/credentials.toml"
  chmod 0600 "$CLIENT_DIR"/*.toml "$CLIENT_DIR/clients-credentials.txt"
  chmod 0644 "$CLIENT_DIR/server-cert.pem"
  zip_path="/root/trusttunnel-clients-${DOMAIN}.zip"
  rm -f "$zip_path"
  (cd "$CLIENT_DIR" && zip -q -r "$zip_path" .)
}

write_systemd() {
  if [ "$ENABLE_WARP" = "1" ]; then
    write_warp_systemd
  fi

  cat > /etc/systemd/system/trusttunnel.service <<EOF
[Unit]
Description=TrustTunnel endpoint
After=network-online.target warp-wireproxy.service
Wants=network-online.target warp-wireproxy.service

[Service]
Type=simple
WorkingDirectory=${TT_DIR}
ExecStart=${TT_DIR}/trusttunnel_endpoint --loglvl info vpn.toml hosts.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now trusttunnel
}

configure_firewall() {
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${SSH_PORT}/tcp" comment "SSH"
  ufw allow 443/tcp comment "TrustTunnel TCP"
  if [ "$ENABLE_QUIC" = "1" ]; then
    ufw allow 443/udp comment "TrustTunnel QUIC"
  fi
  ufw --force enable
}

configure_ssh_port() {
  if [ "$CHANGE_SSH_PORT" != "1" ]; then
    return
  fi

  local sshd_bin ssh_service
  sshd_bin="$(command -v sshd || true)"
  if [ -z "$sshd_bin" ] && [ -x /usr/sbin/sshd ]; then
    sshd_bin="/usr/sbin/sshd"
  fi
  if [ -z "$sshd_bin" ]; then
    echo "sshd not found, skipping SSH port change." >&2
    return
  fi

  if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null; then
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/99-trusttunnel-port.conf <<EOF
Port ${SSH_PORT}
EOF
  else
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup.$(date +%Y%m%d%H%M%S)"
    sed -i 's/^[[:space:]]*Port[[:space:]].*/# &/' /etc/ssh/sshd_config
    printf '\nPort %s\n' "$SSH_PORT" >> /etc/ssh/sshd_config
  fi

  "$sshd_bin" -t
  if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
    ssh_service="ssh"
  else
    ssh_service="sshd"
  fi
  systemctl restart "$ssh_service"
}

configure_fail2ban() {
  if [ "$ENABLE_FAIL2BAN" != "1" ]; then
    return
  fi
  mkdir -p /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
ignoreip = 127.0.0.1/8 ::1
EOF
  systemctl enable --now fail2ban
  systemctl restart fail2ban
}

configure_bbr() {
  cat > /etc/sysctl.d/99-trusttunnel-bbr.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
  sysctl --system >/dev/null || true
}

install_or_reinstall_warp_only() {
  ENABLE_WARP=1
  ENABLE_FAIL2BAN=0
  ENABLE_SYSTEM_UPGRADE="${ENABLE_SYSTEM_UPGRADE:-0}"
  install_packages
  download_wireproxy
  generate_warp_profile
  write_warp_systemd
  switch_trusttunnel_forwarder socks5
  echo "WARP установлен/переустановлен."
  trusttunnel-status 2>/dev/null || true
}

remove_warp_only() {
  confirm_action "Будет удален WARP/wireproxy. TrustTunnel переключится на direct, если он установлен."
  systemctl disable --now warp-wireproxy 2>/dev/null || true
  rm -f /etc/systemd/system/warp-wireproxy.service
  systemctl daemon-reload
  rm -rf "$WARP_DIR"
  switch_trusttunnel_forwarder direct
  echo "WARP удален. TrustTunnel переключен на direct."
  trusttunnel-status 2>/dev/null || true
}

remove_all() {
  confirm_action "Будут удалены TrustTunnel, WARP, клиентские файлы и порт 443 из UFW. SSH/fail2ban не удаляются."
  systemctl disable --now trusttunnel 2>/dev/null || true
  systemctl disable --now warp-wireproxy 2>/dev/null || true
  rm -f /etc/systemd/system/trusttunnel.service
  rm -f /etc/systemd/system/warp-wireproxy.service
  systemctl daemon-reload
  rm -rf "$TT_DIR" "$WARP_DIR" "$CLIENT_DIR"
  rm -f /root/trusttunnel-clients-*.zip
  rm -f /usr/local/sbin/trusttunnel-status
  ufw delete allow 443/tcp 2>/dev/null || true
  ufw delete allow 443/udp 2>/dev/null || true
  echo "TrustTunnel и WARP удалены. SSH и fail2ban оставлены без изменений."
}

show_status() {
  if command -v trusttunnel-status >/dev/null 2>&1; then
    trusttunnel-status
    return
  fi
  echo "Services:"
  systemctl --no-pager --plain is-active trusttunnel warp-wireproxy fail2ban 2>/dev/null || true
  echo
  echo "Listening:"
  ss -lntup | grep -E ':(443|40000|40001|22|49222)\b|sshd' || true
  echo
  echo "UFW:"
  ufw status 2>/dev/null || true
}

write_tools() {
  cat > /usr/local/sbin/trusttunnel-status <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "Services:"
systemctl --no-pager --plain is-active trusttunnel warp-wireproxy fail2ban 2>/dev/null || true
echo
echo "Listening:"
ss -lntup | grep -E ':(443|40000|40001|22|49222)\b|sshd' || true
echo
echo "Direct public IP:"
curl -4 -sS --max-time 8 https://ifconfig.me || true
echo
echo
echo "WARP public IP:"
curl -x socks5h://127.0.0.1:40000 -sS --max-time 12 https://ifconfig.me || true
echo
echo
echo "Fail2ban SSH jail:"
fail2ban-client status sshd 2>/dev/null || true
echo
echo "TCP congestion control:"
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc 2>/dev/null || true
EOF
  chmod 0755 /usr/local/sbin/trusttunnel-status
}

main() {
  need_root
  choose_action
  case "$ACTION" in
    install|reinstall)
      ;;
    install-warp)
      install_or_reinstall_warp_only
      exit 0
      ;;
    remove-warp)
      remove_warp_only
      exit 0
      ;;
    remove-all)
      remove_all
      exit 0
      ;;
    status)
      show_status
      exit 0
      ;;
    exit)
      echo "Выход."
      exit 0
      ;;
    *)
      echo "Unknown ACTION: $ACTION" >&2
      exit 1
      ;;
  esac

  collect_config
  install_packages
  download_trusttunnel
  if [ "$ENABLE_WARP" = "1" ]; then
    download_wireproxy
    generate_warp_profile
  fi
  write_certs
  write_server_config
  write_clients
  write_systemd
  configure_firewall
  configure_ssh_port
  configure_fail2ban
  configure_bbr
  write_tools

  echo
  echo "ГОТОВО"
  echo "Домен: ${DOMAIN}:443"
  echo "Клиентов: ${CLIENTS}"
  echo "Файлы клиентов: ${CLIENT_DIR}"
  echo "ZIP клиентов: /root/trusttunnel-clients-${DOMAIN}.zip"
  echo "Команда проверки: trusttunnel-status"
  if [ -f /var/run/reboot-required ]; then
    echo
    echo "ВНИМАНИЕ: после обновления системы сервер просит перезагрузку."
    echo "Проверь подключение и при удобном моменте выполни: reboot"
  fi
  echo
  trusttunnel-status || true
}

main "$@"

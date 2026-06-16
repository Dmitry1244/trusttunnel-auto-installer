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
ENDPOINT_PORT="${ENDPOINT_PORT:-}"
CHANGE_SSH_PORT="${CHANGE_SSH_PORT:-}"
ENABLE_WARP="${ENABLE_WARP:-}"
ENABLE_QUIC="${ENABLE_QUIC:-}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-}"
ENABLE_SYSTEM_UPGRADE="${ENABLE_SYSTEM_UPGRADE:-}"
ACTION="${ACTION:-}"
CONFIRM_FIREWALL_RESET="${CONFIRM_FIREWALL_RESET:-}"
PRESERVE_CLIENT_CONFIGS="${PRESERVE_CLIENT_CONFIGS:-}"
TT_VERSION="${TT_VERSION:-latest}"
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

validate_port() {
  local name="$1"
  local value="$2"
  case "$value" in
    ''|*[!0-9]*)
      echo "${name} должен быть числом от 1 до 65535." >&2
      exit 1
      ;;
  esac
  if [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
    echo "${name} должен быть числом от 1 до 65535." >&2
    exit 1
  fi
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
    echo "6) Обновить только TrustTunnel endpoint"
    echo "7) Проверить WARP"
    echo "8) Включить WARP"
    echo "9) Отключить WARP без удаления"
    echo "0) Выход"
    echo
    prompt_value "Выбери действие [1]: "
    case "${REPLY_VALUE:-1}" in
      1) ACTION="install"; return ;;
      2) ACTION="remove-all"; return ;;
      3) ACTION="install-warp"; return ;;
      4) ACTION="remove-warp"; return ;;
      5) ACTION="status"; return ;;
      6) ACTION="update-trusttunnel"; return ;;
      7) ACTION="check-warp"; return ;;
      8) ACTION="enable-warp"; return ;;
      9) ACTION="disable-warp"; return ;;
      0) ACTION="exit"; return ;;
      *) echo "Нужно выбрать 0, 1, 2, 3, 4, 5, 6, 7, 8 или 9." ;;
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
  ask_default ENDPOINT_PORT "Порт TrustTunnel для клиентов" "443"
  ask_yes_no CHANGE_SSH_PORT "Поменять SSH-порт сервера" "1"
  if [ "$CHANGE_SSH_PORT" = "1" ]; then
    ask_default SSH_PORT "Новый SSH-порт сервера" "49222"
  else
    ask_default SSH_PORT "Текущий SSH-порт, который нужно оставить открытым" "$detected_ssh_port"
  fi
  validate_port "Порт TrustTunnel" "$ENDPOINT_PORT"
  validate_port "SSH-порт" "$SSH_PORT"
  ask_yes_no ENABLE_SYSTEM_UPGRADE "Обновить систему перед установкой" "1"
  ask_yes_no ENABLE_WARP "Включить WARP для скрытия IP сервера от сайтов" "1"
  ask_yes_no ENABLE_QUIC "Включить QUIC/HTTP3 на UDP-порту TrustTunnel" "1"
  ask_yes_no ENABLE_FAIL2BAN "Включить fail2ban для защиты SSH" "1"

  if [ -f "$TT_DIR/credentials.toml" ] || [ -f "$TT_DIR/certs/cert.pem" ]; then
    ask_yes_no PRESERVE_CLIENT_CONFIGS "Сохранить текущий сертификат и клиентские логины/пароли при переустановке" "1"
  else
    PRESERVE_CLIENT_CONFIGS="${PRESERVE_CLIENT_CONFIGS:-0}"
  fi

  if [ -z "$CONFIRM_FIREWALL_RESET" ]; then
    echo
    echo "Скрипт сбросит UFW firewall и откроет только:"
    echo "- ${SSH_PORT}/tcp для SSH"
    echo "- ${ENDPOINT_PORT}/tcp для TrustTunnel"
    if [ "$ENABLE_QUIC" = "1" ]; then
      echo "- ${ENDPOINT_PORT}/udp для TrustTunnel QUIC/HTTP3"
    fi
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
  echo "- Порт TrustTunnel: ${ENDPOINT_PORT}"
  echo "- Менять SSH-порт: ${CHANGE_SSH_PORT}"
  echo "- SSH-порт для firewall/fail2ban: ${SSH_PORT}"
  echo "- Обновить систему: ${ENABLE_SYSTEM_UPGRADE}"
  echo "- WARP: ${ENABLE_WARP}"
  echo "- QUIC/HTTP3: ${ENABLE_QUIC}"
  echo "- fail2ban: ${ENABLE_FAIL2BAN}"
  echo "- Preserve client configs: ${PRESERVE_CLIENT_CONFIGS}"
  echo
}

confirm_action() {
  local message="$1"
  local answer=""
  prompt_value "$message Напиши YES/yes/да для подтверждения: "
  answer="$REPLY_VALUE"
  case "$answer" in
    YES|yes|Yes|Y|y|да|Да|ДА|д|Д) return ;;
    *)
      echo "Отменено."
      exit 1
      ;;
  esac
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  if [ "$ENABLE_SYSTEM_UPGRADE" = "1" ]; then
    apt-get upgrade -y
  fi
  local packages
  packages="ca-certificates curl tar gzip openssl ufw iproute2 python3 coreutils sed grep gawk"
  if [ "$ENABLE_FAIL2BAN" = "1" ]; then
    packages="$packages fail2ban"
  fi
  apt-get install -y --no-install-recommends --no-upgrade $packages
}

resolve_trusttunnel_version() {
  if [ "$TT_VERSION" != "latest" ] && [ -n "$TT_VERSION" ]; then
    printf '%s' "$TT_VERSION"
    return
  fi

  local latest
  latest="$(curl -fsSL https://api.github.com/repos/TrustTunnel/TrustTunnel/releases/latest \
    | sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' \
    | head -1)"
  if [ -z "$latest" ]; then
    echo "Не удалось определить latest TrustTunnel release через GitHub API." >&2
    exit 1
  fi
  printf '%s' "$latest"
}

download_trusttunnel() {
  local arch asset url tmp resolved_version backup_dir now
  resolved_version="$(resolve_trusttunnel_version)"
  echo "TrustTunnel version: ${resolved_version}"
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) asset="trusttunnel-${resolved_version}-linux-x86_64.tar.gz" ;;
    aarch64|arm64) asset="trusttunnel-${resolved_version}-linux-aarch64.tar.gz" ;;
    *) echo "Unsupported CPU architecture: $arch" >&2; exit 1 ;;
  esac

  url="https://github.com/TrustTunnel/TrustTunnel/releases/download/${resolved_version}/${asset}"
  tmp="$(mktemp -d)"
  mkdir -p "$TT_DIR"
  backup_dir="$TT_DIR/backups"
  mkdir -p "$backup_dir"
  now="$(date +%Y%m%d%H%M%S)"
  if [ -x "$TT_DIR/trusttunnel_endpoint" ]; then
    cp "$TT_DIR/trusttunnel_endpoint" "$backup_dir/trusttunnel_endpoint.${now}" || true
  fi
  if [ -x "$TT_DIR/setup_wizard" ]; then
    cp "$TT_DIR/setup_wizard" "$backup_dir/setup_wizard.${now}" || true
  fi
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
StartLimitIntervalSec=0

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
  if [ "${PRESERVE_CLIENT_CONFIGS:-0}" = "1" ] && [ -f "$TT_DIR/certs/cert.pem" ] && [ -f "$TT_DIR/certs/key.pem" ]; then
    if openssl x509 -in "$TT_DIR/certs/cert.pem" -noout -subject 2>/dev/null \
      | grep -Fq "CN = ${DOMAIN}"; then
      echo "Using existing certificate for ${DOMAIN}."
      return
    fi
  fi
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
listen_address = "0.0.0.0:${ENDPOINT_PORT}"
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
  else
    cat >> "$TT_DIR/vpn.toml" <<'EOF'
[forward_protocol.direct]
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

create_client_archive() {
  local source_dir="$1"
  local archive_path="$2"
  rm -f "$archive_path"
  if command -v zip >/dev/null 2>&1; then
    (cd "$source_dir" && zip -q -r "$archive_path" .)
    return
  fi

  python3 - "$source_dir" "$archive_path" <<'PY'
import pathlib
import sys
import zipfile

source = pathlib.Path(sys.argv[1])
archive = pathlib.Path(sys.argv[2])

with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for path in sorted(source.rglob("*")):
        if path.is_file():
            zf.write(path, path.relative_to(source))
PY
}

client_name_by_index() {
  local index="$1"
  local width="${#CLIENTS}"
  if [ "$width" -lt 2 ]; then
    width=2
  fi
  printf "client%0${width}d" "$index"
}

existing_password_for_user() {
  local user="$1"
  local file="${2:-}"
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    return 1
  fi

  awk -v wanted_user="$user" '
    /^\[\[client\]\]/ {
      current_user = ""
      current_password = ""
      next
    }
    /^[[:space:]]*username[[:space:]]*=/ {
      current_user = $0
      sub(/^[[:space:]]*username[[:space:]]*=[[:space:]]*"/, "", current_user)
      sub(/".*$/, "", current_user)
      next
    }
    /^[[:space:]]*password[[:space:]]*=/ {
      current_password = $0
      sub(/^[[:space:]]*password[[:space:]]*=[[:space:]]*"/, "", current_password)
      sub(/".*$/, "", current_password)
      if (current_user == wanted_user) {
        print current_password
        exit
      }
    }
  ' "$file"
}

list_existing_clients() {
  local file="${1:-}"
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    return 1
  fi

  awk '
    function flush_client() {
      if (current_user != "" && current_password != "") {
        print current_user, current_password
      }
    }
    /^\[\[client\]\]/ {
      flush_client()
      current_user = ""
      current_password = ""
      next
    }
    /^[[:space:]]*username[[:space:]]*=/ {
      current_user = $0
      sub(/^[[:space:]]*username[[:space:]]*=[[:space:]]*"/, "", current_user)
      sub(/".*$/, "", current_user)
      next
    }
    /^[[:space:]]*password[[:space:]]*=/ {
      current_password = $0
      sub(/^[[:space:]]*password[[:space:]]*=[[:space:]]*"/, "", current_password)
      sub(/".*$/, "", current_password)
      next
    }
    END {
      flush_client()
    }
  ' "$file"
}

write_client_profiles() {
  local cert="$1"
  local user="$2"
  local pass="$3"
  local profile protocol protocols
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
addresses = ["${DOMAIN}:${ENDPOINT_PORT}"]

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
}

write_clients() {
  local cert existing_clients existing_count existing_credentials generated_count index pass target_clients user zip_path
  mkdir -p "$CLIENT_DIR"
  rm -f "$CLIENT_DIR"/*.toml "$CLIENT_DIR/clients-credentials.txt" "$CLIENT_DIR/server-cert.pem" 2>/dev/null || true
  cert="$(cat "$TT_DIR/certs/cert.pem")"
  cp "$TT_DIR/certs/cert.pem" "$CLIENT_DIR/server-cert.pem"
  existing_credentials=""
  existing_clients=""
  if [ "${PRESERVE_CLIENT_CONFIGS:-0}" = "1" ] && [ -f "$TT_DIR/credentials.toml" ]; then
    existing_credentials="$(mktemp)"
    cp "$TT_DIR/credentials.toml" "$existing_credentials"
    existing_clients="$(mktemp)"
    list_existing_clients "$existing_credentials" > "$existing_clients" || true
  fi

  cat > "$TT_DIR/credentials.toml" <<'EOF'
# Managed TrustTunnel users. One user/password per client.
EOF
  : > "$CLIENT_DIR/clients-credentials.txt"

  target_clients="$CLIENTS"
  if [ -n "$existing_clients" ] && [ -s "$existing_clients" ]; then
    existing_count="$(wc -l < "$existing_clients" | tr -d '[:space:]')"
    if [ "${PRESERVE_CLIENT_CONFIGS:-0}" = "1" ] && [ "$existing_count" -gt "$target_clients" ]; then
      target_clients="$existing_count"
    fi
  fi

  generated_count=0
  if [ -n "$existing_clients" ] && [ -s "$existing_clients" ]; then
    while read -r user pass; do
      if [ -z "$user" ] || [ "$generated_count" -ge "$target_clients" ]; then
        continue
      fi
      generated_count=$((generated_count + 1))
      cat >> "$TT_DIR/credentials.toml" <<EOF

[[client]]
username = "${user}"
password = "${pass}"
EOF
      printf '%s %s\n' "$user" "$pass" >> "$CLIENT_DIR/clients-credentials.txt"
      write_client_profiles "$cert" "$user" "$pass"
    done < "$existing_clients"
  fi

  index=$((generated_count + 1))
  while [ "$index" -le "$target_clients" ]; do
    user="$(client_name_by_index "$index")"
    pass="$(random_password)"
    cat >> "$TT_DIR/credentials.toml" <<EOF

[[client]]
username = "${user}"
password = "${pass}"
EOF
    printf '%s %s\n' "$user" "$pass" >> "$CLIENT_DIR/clients-credentials.txt"
    write_client_profiles "$cert" "$user" "$pass"
    index=$((index + 1))
  done

  rm -f "$existing_credentials"
  rm -f "$existing_clients"

  chmod 0600 "$TT_DIR/credentials.toml"
  chmod 0600 "$CLIENT_DIR"/*.toml "$CLIENT_DIR/clients-credentials.txt"
  chmod 0644 "$CLIENT_DIR/server-cert.pem"
  zip_path="/root/trusttunnel-clients-${DOMAIN}.zip"
  create_client_archive "$CLIENT_DIR" "$zip_path"
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
StartLimitIntervalSec=0

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
  ufw allow "${ENDPOINT_PORT}/tcp" comment "TrustTunnel TCP"
  if [ "$ENABLE_QUIC" = "1" ]; then
    ufw allow "${ENDPOINT_PORT}/udp" comment "TrustTunnel QUIC"
  fi
  ufw --force enable
}

configure_ssh_port() {
  if [ "$CHANGE_SSH_PORT" != "1" ]; then
    return
  fi

  local sshd_bin ssh_service
  mkdir -p /run/sshd
  chmod 0755 /run/sshd

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

install_download_tools() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl tar gzip coreutils sed
}

update_trusttunnel_only() {
  if [ ! -d "$TT_DIR" ]; then
    echo "TrustTunnel не найден в ${TT_DIR}. Сначала выполни установку."
    exit 1
  fi
  install_download_tools
  systemctl stop trusttunnel 2>/dev/null || true
  download_trusttunnel
  systemctl daemon-reload
  systemctl restart trusttunnel
  echo "TrustTunnel endpoint обновлен и перезапущен."
  trusttunnel-status 2>/dev/null || show_status
}

check_warp() {
  echo "WARP service:"
  systemctl --no-pager --plain is-active warp-wireproxy 2>/dev/null || true
  echo
  echo "WARP listener:"
  ss -lntup | grep -E ':(40000|40001)\b|wireproxy' || true
  echo
  echo "Direct public IP:"
  curl -4 -sS --max-time 8 https://ifconfig.me || true
  echo
  echo
  echo "WARP public IP:"
  if curl -x socks5h://127.0.0.1:40000 -sS --max-time 12 https://ifconfig.me; then
    echo
  else
    echo "WARP SOCKS недоступен на 127.0.0.1:40000."
  fi
}

enable_warp() {
  if [ ! -x "$WARP_DIR/bin/wireproxy" ] || [ ! -f "$WARP_DIR/wireproxy.conf" ]; then
    echo "WARP не установлен полностью. Запускаю установку/переустановку WARP."
    install_or_reinstall_warp_only
    return
  fi
  write_warp_systemd
  switch_trusttunnel_forwarder socks5
  echo "WARP включен. TrustTunnel переключен на WARP/SOCKS."
  check_warp
}

disable_warp() {
  systemctl disable --now warp-wireproxy 2>/dev/null || true
  switch_trusttunnel_forwarder direct
  echo "WARP отключен без удаления файлов. TrustTunnel переключен на direct."
  check_warp
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

current_endpoint_port() {
  local config="$TT_DIR/vpn.toml"
  if [ -f "$config" ]; then
    sed -nE 's/^[[:space:]]*listen_address[[:space:]]*=[[:space:]]*"[^:"]+:([0-9]+)".*/\1/p' "$config" | head -1
    return
  fi
  printf '443'
}

remove_all() {
  confirm_action "Будут удалены TrustTunnel, WARP, клиентские файлы и порт TrustTunnel из UFW. SSH/fail2ban не удаляются."
  local endpoint_port
  endpoint_port="$(current_endpoint_port)"
  systemctl disable --now trusttunnel 2>/dev/null || true
  systemctl disable --now warp-wireproxy 2>/dev/null || true
  rm -f /etc/systemd/system/trusttunnel.service
  rm -f /etc/systemd/system/warp-wireproxy.service
  systemctl daemon-reload
  rm -rf "$TT_DIR" "$WARP_DIR" "$CLIENT_DIR"
  rm -f /root/trusttunnel-clients-*.zip
  rm -f /usr/local/sbin/trusttunnel-menu
  rm -f /usr/local/sbin/trusttunnel-status
  ufw delete allow "${endpoint_port}/tcp" 2>/dev/null || true
  ufw delete allow "${endpoint_port}/udp" 2>/dev/null || true
  echo "TrustTunnel и WARP удалены. SSH и fail2ban оставлены без изменений."
}

show_status() {
  if command -v trusttunnel-status >/dev/null 2>&1; then
    trusttunnel-status
    return
  fi
  local endpoint_port
  endpoint_port="$(current_endpoint_port)"
  echo "Services:"
  systemctl --no-pager --plain is-active trusttunnel warp-wireproxy fail2ban 2>/dev/null || true
  echo
  echo "Listening:"
  ss -lntup | grep -E ":(${endpoint_port}|40000|40001|22|49222)\b|sshd|trusttunnel" || true
  echo
  echo "UFW:"
  ufw status 2>/dev/null || true
}

write_tools() {
  cat > /usr/local/sbin/trusttunnel-menu <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_URL="https://raw.githubusercontent.com/Dmitry1244/trusttunnel-auto-installer/main/install-trusttunnel-warp.sh"
TMP_SCRIPT="/tmp/install-trusttunnel-warp.sh"
curl -fsSL -o "$TMP_SCRIPT" "${SCRIPT_URL}?$(date +%s)"
bash "$TMP_SCRIPT"
EOF
  chmod 0755 /usr/local/sbin/trusttunnel-menu

  cat > /usr/local/sbin/trusttunnel-status <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "Services:"
systemctl --no-pager --plain is-active trusttunnel warp-wireproxy fail2ban 2>/dev/null || true
echo
endpoint_port="$(sed -nE 's/^[[:space:]]*listen_address[[:space:]]*=[[:space:]]*"[^:"]+:([0-9]+)".*/\1/p' /opt/trusttunnel/vpn.toml 2>/dev/null | head -1)"
endpoint_port="${endpoint_port:-443}"
echo "TrustTunnel endpoint port:"
echo "$endpoint_port"
echo
echo "Listening:"
ss -lntup | grep -E ":(${endpoint_port}|40000|40001|22|49222)\b|sshd|trusttunnel" || true
echo
echo "TrustTunnel config:"
grep -E '^[[:space:]]*listen_address|^\[listen_protocols\.(http2|quic)\]' /opt/trusttunnel/vpn.toml 2>/dev/null || true
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
echo
echo "TrustTunnel logs since current start:"
active_since="$(systemctl show trusttunnel -p ActiveEnterTimestamp --value 2>/dev/null || true)"
if [ -n "$active_since" ]; then
  journalctl -u trusttunnel --since "$active_since" --no-pager 2>/dev/null || true
else
  journalctl -u trusttunnel -n 20 --no-pager 2>/dev/null || true
fi
EOF
  chmod 0755 /usr/local/sbin/trusttunnel-status
}

primary_client_name() {
  if [ -f "$CLIENT_DIR/clients-credentials.txt" ]; then
    awk 'NF { print $1; exit }' "$CLIENT_DIR/clients-credentials.txt"
    return
  fi
  printf 'client01'
}

print_mobile_instructions() {
  local sample_client
  sample_client="$(primary_client_name)"
  echo
  echo "=== Инструкция для мобильного клиента ==="
  echo
  echo "Самый простой способ:"
  echo "1) Скачай архив клиентов с сервера:"
  echo "   /root/trusttunnel-clients-${DOMAIN}.zip"
  echo "2) Распакуй архив на телефоне."
  echo "3) Импортируй TOML-файл нужного клиента в TrustTunnel app."
  echo
  echo "Рекомендуемый файл для проверки:"
  echo "   ${sample_client}-http2.toml"
  if [ "$ENABLE_QUIC" = "1" ]; then
    echo
    echo "Если хочешь QUIC/HTTP3:"
    echo "   ${sample_client}-http3.toml"
    echo "   Для QUIC/HTTP3 должен проходить UDP-порт ${ENDPOINT_PORT}."
  fi
  echo
  echo "Если вводишь вручную:"
  echo "   Address: ${DOMAIN}:${ENDPOINT_PORT}"
  echo "   Domain name from server certificate: ${DOMAIN}"
  echo "   Custom SNI: пусто"
  echo "   Username/Password: смотри clients-credentials.txt"
  echo "   Protocol: HTTP/2"
  if [ "$ENABLE_QUIC" = "1" ]; then
    echo "   Protocol также можно выбрать: QUIC/HTTP3"
  fi
  echo "   Self-signed certificate: server-cert.pem"
  echo
  echo "Файл паролей:"
  echo "   ${CLIENT_DIR}/clients-credentials.txt"
}

verify_endpoint_listening() {
  echo
  echo "=== Проверка TrustTunnel endpoint ==="
  if ss -lntup | grep -Eq ":${ENDPOINT_PORT}\b.*trusttunnel|trusttunnel.*:${ENDPOINT_PORT}\b"; then
    echo "OK: TrustTunnel слушает TCP-порт ${ENDPOINT_PORT}."
  else
    echo "ВНИМАНИЕ: TrustTunnel TCP-порт ${ENDPOINT_PORT} не найден в LISTEN."
    echo "Последние логи trusttunnel:"
    journalctl -u trusttunnel -n 60 --no-pager 2>/dev/null || true
  fi
  if [ "$ENABLE_QUIC" = "1" ]; then
    if ss -lunp | grep -Eq ":${ENDPOINT_PORT}\b.*trusttunnel|trusttunnel.*:${ENDPOINT_PORT}\b"; then
      echo "OK: TrustTunnel слушает UDP-порт ${ENDPOINT_PORT} для QUIC/HTTP3."
    else
      echo "ВНИМАНИЕ: TrustTunnel UDP-порт ${ENDPOINT_PORT} не найден в LISTEN."
    fi
  fi
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
    update-trusttunnel)
      update_trusttunnel_only
      exit 0
      ;;
    check-warp)
      check_warp
      exit 0
      ;;
    enable-warp)
      enable_warp
      exit 0
      ;;
    disable-warp)
      disable_warp
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
  echo "Домен: ${DOMAIN}:${ENDPOINT_PORT}"
  echo "Клиентов: ${CLIENTS}"
  echo "Файлы клиентов: ${CLIENT_DIR}"
  echo "ZIP клиентов: /root/trusttunnel-clients-${DOMAIN}.zip"
  echo "Команда проверки: trusttunnel-status"
  echo "Главное меню: trusttunnel-menu"
  if [ -f /var/run/reboot-required ]; then
    echo
    echo "ВНИМАНИЕ: после обновления системы сервер просит перезагрузку."
    echo "Проверь подключение и при удобном моменте выполни: reboot"
  fi
  echo
  trusttunnel-status || true
  verify_endpoint_listening
  print_mobile_instructions
}

main "$@"

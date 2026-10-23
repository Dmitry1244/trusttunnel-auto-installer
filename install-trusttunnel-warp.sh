#!/usr/bin/env bash
set -euo pipefail

# Интерактивный установщик TrustTunnel endpoint + WARP.
# Ubuntu/Debian VPS, в том числе с существующими настройками. Запускать от root.
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
RESET_UFW="${RESET_UFW:-0}"
PRESERVE_CLIENT_CONFIGS="${PRESERVE_CLIENT_CONFIGS:-}"
CERT_MODE="${CERT_MODE:-}"
FORCE_CERT_RENEW="${FORCE_CERT_RENEW:-0}"
TT_VERSION="${TT_VERSION:-latest}"
TT_CHANNEL="${TT_CHANNEL:-stable}"
WGCF_VERSION="${WGCF_VERSION:-2.2.31}"
WIREPROXY_VERSION="${WIREPROXY_VERSION:-v1.1.2}"
PANEL_PORT="${PANEL_PORT:-8088}"
PANEL_USER="${PANEL_USER:-admin}"
PANEL_PASSWORD="${PANEL_PASSWORD:-}"
CASCADE_SOCKS_ADDR="${CASCADE_SOCKS_ADDR:-}"

TT_DIR="/opt/trusttunnel"
WARP_DIR="/opt/warp-proxy"
CLIENT_DIR="/root/trusttunnel-clients"
SOCKS_ADDR="127.0.0.1:40000"
WARP_HEALTH_ADDR="127.0.0.1:40001"
IDENTITY_BACKUP_DIR="/root/trusttunnel-identity-backup"
CLIENT_SETTINGS_FILE="/etc/trusttunnel-panel-settings.env"
PANEL_TELEGRAM_ENV="/etc/trusttunnel-panel-telegram.env"
PANEL_MAINTENANCE_SERVICE="/etc/systemd/system/trusttunnel-maintenance.service"
PANEL_MAINTENANCE_TIMER="/etc/systemd/system/trusttunnel-maintenance.timer"
PANEL_SCRIPT_URL="https://raw.githubusercontent.com/Dmitry1244/trusttunnel-auto-installer/main/trusttunnel-panel.py"

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Запусти скрипт от root." >&2
    exit 1
  fi
}

prompt_value() {
  local message="$1"
  if [ -r /dev/tty ] && { true </dev/tty; } 2>/dev/null; then
    read -r -p "$message" REPLY_VALUE </dev/tty || { echo "Ввод закрыт. Для автоматического запуска задайте ACTION и все параметры явно." >&2; return 1; }
  else
    read -r -p "$message" REPLY_VALUE || { echo "Ввод закрыт. Для автоматического запуска задайте ACTION и все параметры явно." >&2; return 1; }
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

ask_cert_mode() {
  if [ "$CERT_MODE" = "self-signed" ] || [ "$CERT_MODE" = "letsencrypt" ]; then
    return
  fi
  if [ ! -r /dev/tty ]; then
    CERT_MODE="self-signed"
    return
  fi

  while true; do
    echo
    echo "Режим сертификата:"
    echo "1) self-signed"
    echo "   Разница: работает без 80 порта и не зависит от Let's Encrypt."
    echo "   Клиент использует вложенный файл server-cert.pem."
    echo "2) Let's Encrypt"
    echo "   Разница: публичный доверенный сертификат."
    echo "   Домен должен указывать на этот сервер, а 80/tcp должен быть доступен во время выпуска."
    prompt_value "Выбери режим сертификата [1]: "
    case "${REPLY_VALUE:-1}" in
      1|self|self-signed)
        CERT_MODE="self-signed"
        return
        ;;
      2|le|letsencrypt|lets-encrypt)
        CERT_MODE="letsencrypt"
        return
        ;;
      *)
        echo "Нужно выбрать 1 или 2."
        ;;
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
    echo "10) Полностью перерегистрировать WARP-аккаунт"
    echo "11) Создать backup identity (сертификат и клиенты)"
    echo "12) Восстановить identity из backup"
    echo "13) Обновить сертификат вручную"
    echo "14) Сменить режим сертификата (Let's Encrypt / self-signed)"
    echo "15) Тест скорости"
    echo "16) Настроить каскадный upstream SOCKS5"
    echo "17) Установить или обновить веб-панель"
    echo "18) Удалить веб-панель"
    echo "19) Правила маршрутизации/access rules"
    echo "20) Смена портов"
    echo "21) Управление fail2ban"
    echo "22) Управление UFW"
    echo "23) Настроить доступ к веб-панели (localhost / HTTPS)"
    echo "24) Включить / выключить веб-панель и сменить вход"
    echo "25) Управление клиентами и tt:// ссылками"
    echo "26) DNS, TLS profile, AntiDPI и post-quantum для TOML"
    echo "27) Система, диагностика и журнал"
    echo "28) Расширенное управление: безопасность, маршруты, DNS, мониторинг"
    echo "29) WARP MASQUE: установить, проверить, включить, остановить, удалить"
    echo "30) Обновления endpoint, метрики клиентов и HTTPS-подписки"
    echo "31) WARP через интерфейс без SOCKS (только трафик TrustTunnel)"
    echo "32) Все варианты WARP: управление и попытка сменить IP"
    echo "33) Рекомендации по безопасности и настройкам"
    echo "34) Защита от сканирования и ClientHello-фильтр"
    echo "35) Безопасность VPS, входящий ping и расписания обслуживания"
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
      10) ACTION="reregister-warp"; return ;;
      11) ACTION="backup-identity"; return ;;
      12) ACTION="restore-identity"; return ;;
      13) ACTION="renew-certificate"; return ;;
      14) ACTION="switch-certificate-mode"; return ;;
      15) ACTION="speedtest"; return ;;
      16) ACTION="configure-cascade"; return ;;
      17) ACTION="install-panel"; return ;;
      18) ACTION="remove-panel"; return ;;
      19) ACTION="configure-routing"; return ;;
      20) ACTION="manage-ports"; return ;;
      21) ACTION="manage-fail2ban"; return ;;
      22) ACTION="manage-ufw"; return ;;
      23) ACTION="configure-panel-access"; return ;;
      24) ACTION="manage-panel-service"; return ;;
      25) ACTION="manage-clients"; return ;;
      26) ACTION="manage-client-network"; return ;;
      27) ACTION="manage-system-tools"; return ;;
      28) ACTION="manage-admin"; return ;;
      29) ACTION="manage-masque"; return ;;
      30) ACTION="manage-endpoint-features"; return ;;
      31) ACTION="manage-interface"; return ;;
      32) ACTION="manage-warp"; return ;;
      33) ACTION="recommendations"; return ;;
      34) ACTION="manage-protection"; return ;;
      35) ACTION="manage-server-security"; return ;;
      0) ACTION="exit"; return ;;
      *) echo "Нужно выбрать 0-35 из меню." ;;
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
  [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] && [[ "$DOMAIN" == *.* ]] && [[ "$DOMAIN" != *..* ]] || { echo "Введите корректное доменное имя без URL и пробелов." >&2; return 1; }
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

  ask_cert_mode
  if [ "$CERT_MODE" = "letsencrypt" ] && { [ -z "$EMAIL" ] || [ "$EMAIL" = "admin@example.com" ]; }; then
    EMAIL=""
    ask_required EMAIL "Email для Let's Encrypt: "
  fi

  if [ -z "$CONFIRM_FIREWALL_RESET" ]; then
    echo
    echo "Скрипт сохранит существующие правила UFW и добавит:"
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
  echo "- Режим сертификата: ${CERT_MODE}"
  if [ "$CERT_MODE" = "letsencrypt" ]; then
    echo "- Email для Let's Encrypt: ${EMAIL}"
  fi
  echo "- Preserve client configs: ${PRESERVE_CLIENT_CONFIGS}"
  echo
}

confirm_action() {
  local message="$1"
  local answer=""
  if [ "${AUTO_CONFIRM:-0}" = "1" ]; then
    echo "Подтверждено неинтерактивным режимом: ${message}"
    return
  fi
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

normalize_apt_sources() {
  local file
  if [ -f /etc/apt/sources.list ]; then
    sed -i \
      -e 's|http://archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' \
      -e 's|http://security.ubuntu.com/ubuntu|https://security.ubuntu.com/ubuntu|g' \
      -e 's|http://ports.ubuntu.com/ubuntu-ports|https://ports.ubuntu.com/ubuntu-ports|g' \
      /etc/apt/sources.list
  fi

  for file in /etc/apt/sources.list.d/*.list; do
    [ -f "$file" ] || continue
    sed -i \
      -e 's|http://archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' \
      -e 's|http://security.ubuntu.com/ubuntu|https://security.ubuntu.com/ubuntu|g' \
      -e 's|http://ports.ubuntu.com/ubuntu-ports|https://ports.ubuntu.com/ubuntu-ports|g' \
      "$file"
  done

  for file in /etc/apt/sources.list.d/*.sources; do
    [ -f "$file" ] || continue
    sed -i \
      -e 's|URIs:[[:space:]]*http://archive.ubuntu.com/ubuntu|URIs: https://archive.ubuntu.com/ubuntu|g' \
      -e 's|URIs:[[:space:]]*http://security.ubuntu.com/ubuntu|URIs: https://security.ubuntu.com/ubuntu|g' \
      -e 's|URIs:[[:space:]]*http://ports.ubuntu.com/ubuntu-ports|URIs: https://ports.ubuntu.com/ubuntu-ports|g' \
      "$file"
  done
}

apt_update_retry() {
  normalize_apt_sources
  apt-get -o Acquire::Retries=3 update
}

apt_install_retry() {
  apt-get -o Acquire::Retries=3 install "$@"
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  local packages missing_packages required_commands cmd
  if ! apt_update_retry; then
    echo "Warning: apt-get update failed, using installed packages where possible." >&2
  fi
  if [ "$ENABLE_SYSTEM_UPGRADE" = "1" ]; then
    if ! apt-get -o Acquire::Retries=3 upgrade -y; then
      echo "Warning: apt-get upgrade failed, continuing without system upgrade." >&2
    fi
  fi
  packages="ca-certificates curl tar gzip openssl ufw iproute2 python3 coreutils sed grep gawk util-linux"
  if ! python3 -c 'import tomllib' 2>/dev/null; then packages="$packages python3-tomli"; fi
  if [ "$CERT_MODE" = "letsencrypt" ]; then
    packages="$packages certbot"
  fi
  if [ "$ENABLE_FAIL2BAN" = "1" ]; then
    packages="$packages fail2ban"
  fi
  if ! apt_install_retry -y --no-install-recommends --no-upgrade $packages; then
    echo "Warning: apt-get install failed, checking existing commands." >&2
  fi

  required_commands="curl tar gzip openssl ufw python3 sed grep gawk"
  missing_packages=""
  for cmd in $required_commands; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_packages="$missing_packages $cmd"
    fi
  done

  if [ "$ENABLE_FAIL2BAN" = "1" ] && ! command -v fail2ban-client >/dev/null 2>&1; then
    missing_packages="$missing_packages fail2ban"
  fi
  if [ "$CERT_MODE" = "letsencrypt" ] && ! command -v certbot >/dev/null 2>&1; then
    missing_packages="$missing_packages certbot"
  fi
  if [ -n "$missing_packages" ]; then
    echo "Missing required packages/commands:$missing_packages" >&2
    exit 1
  fi
}

resolve_trusttunnel_version() {
  if [ "$TT_VERSION" != "latest" ] && [ -n "$TT_VERSION" ]; then
    printf '%s' "$TT_VERSION"
    return
  fi

  local latest
  case "$TT_CHANNEL" in
    stable) latest="$(curl -fsSL https://api.github.com/repos/TrustTunnel/TrustTunnel/releases/latest | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')" ;;
    beta) latest="$(curl -fsSL 'https://api.github.com/repos/TrustTunnel/TrustTunnel/releases?per_page=20' | python3 -c 'import json,sys; print(next(r["tag_name"] for r in json.load(sys.stdin) if r["prerelease"] and not r["draft"]))')" ;;
    *) echo "Канал обновлений: stable или beta." >&2; return 1 ;;
  esac
  if ! [[ "$latest" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?$ ]]; then
    echo "Не удалось определить latest TrustTunnel release через GitHub API." >&2
    exit 1
  fi
  printf '%s' "$latest"
}

download_trusttunnel() {
  local arch asset url tmp resolved_version backup_dir now
  resolved_version="$(resolve_trusttunnel_version)"
  if ! [[ "$resolved_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?$ ]]; then
    echo "Некорректная версия TrustTunnel." >&2; return 1
  fi
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
  curl -fL "$url" -o "$tmp/trusttunnel.tar.gz" || { rm -rf "$tmp"; return 1; }
  tar -xzf "$tmp/trusttunnel.tar.gz" -C "$tmp" || { rm -rf "$tmp"; return 1; }
  find "$tmp" -type f -name trusttunnel_endpoint -exec install -m 0755 {} "$TT_DIR/trusttunnel_endpoint.new" \; || { rm -rf "$tmp"; return 1; }
  if [ ! -x "$TT_DIR/trusttunnel_endpoint.new" ] || ! "$TT_DIR/trusttunnel_endpoint.new" --version; then
    echo "Новый бинарный файл не прошёл проверку." >&2; rm -rf "$tmp"; return 1
  fi
  mv -f "$TT_DIR/trusttunnel_endpoint.new" "$TT_DIR/trusttunnel_endpoint"
  find "$tmp" -type f -name setup_wizard -exec install -m 0755 {} "$TT_DIR/setup_wizard.new" \; || true
  if [ -x "$TT_DIR/setup_wizard.new" ]; then mv -f "$TT_DIR/setup_wizard.new" "$TT_DIR/setup_wizard"; fi
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
  local socks_addr="${2:-$SOCKS_ADDR}"
  [ -f "$TT_DIR/vpn.toml" ] || return 0
  ensure_admin_helper || return
  if [ "$mode" = "direct" ]; then
    admin_call routing-switch mode=direct
  elif [ "$socks_addr" = "$SOCKS_ADDR" ]; then
    admin_call routing-switch mode=warp
  else
    admin_call routing-switch mode=socks5 "address=$socks_addr"
  fi
}

cert_matches_domain() {
  local cert_path="$1"
  if [ ! -f "$cert_path" ]; then
    return 1
  fi
  openssl x509 -in "$cert_path" -noout -subject 2>/dev/null | grep -Fq "CN = ${DOMAIN}"
}

cert_is_letsencrypt() {
  local cert_path="$1"
  if [ ! -f "$cert_path" ]; then
    return 1
  fi
  openssl x509 -in "$cert_path" -noout -issuer 2>/dev/null | grep -qiE "Let's Encrypt|ISRG"
}

deploy_certificate_pair() {
  python3 - "$TT_DIR" "$DOMAIN" "$1" "$2" <<'PY'
import os, re, ssl, subprocess, sys, tempfile, time
try: import tomllib
except ImportError: import tomli as tomllib
from pathlib import Path
root, domain, cert, key = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
subprocess.run(['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '0', '-checkhost', domain], check=True, stdout=subprocess.DEVNULL)
targets = {root / 'certs/cert.pem': (cert.read_bytes(), 0o644), root / 'certs/key.pem': (key.read_bytes(), 0o600)}
hosts = root / 'hosts.toml'
if hosts.exists():
    text = hosts.read_text()
    data = tomllib.loads(text)
    if sum(h.get('hostname') == domain for h in data.get('main_hosts', [])) != 1:
        raise ValueError('Expected exactly one matching main host; certificate was not changed')
    def update(match):
        block = match.group(0)
        if tomllib.loads(block)['main_hosts'][0].get('hostname') != domain:
            return block
        for field, value in (('cert_chain_path', 'certs/cert.pem'), ('private_key_path', 'certs/key.pem')):
            block, count = re.subn(r'(?m)^' + field + r'\s*=.*$', field + ' = "' + value + '"', block)
            if count != 1: raise ValueError('Ambiguous certificate path; no changes applied')
        return block
    text = re.sub(r'(?ms)^\[\[main_hosts\]\][ \t]*\n.*?(?=^\[|\Z)', update, text)
    selected = next(h for h in tomllib.loads(text)['main_hosts'] if h['hostname'] == domain)
    if selected.get('cert_chain_path') != 'certs/cert.pem' or selected.get('private_key_path') != 'certs/key.pem':
        raise ValueError('Certificate references were not updated')
    targets[hosts] = (text.encode(), 0o600)
def atomic(path, body, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.certificate-')
    try:
        with os.fdopen(fd, 'wb') as output: output.write(body); output.flush(); os.fsync(output.fileno())
        os.chmod(name, mode); os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)
original = {p: (p.read_bytes(), p.stat().st_mode & 0o777) if p.exists() else None for p in targets}
has_service = hosts.exists() and subprocess.run(['systemctl', 'cat', 'trusttunnel'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
try:
    for path, (body, mode) in targets.items(): atomic(path, body, mode)
    if has_service:
        subprocess.run(['systemctl', 'restart', 'trusttunnel'], check=True)
        time.sleep(1)
        subprocess.run(['systemctl', 'is-active', '--quiet', 'trusttunnel'], check=True)
except Exception:
    for path, previous in original.items():
        if previous: atomic(path, *previous)
        else: path.unlink(missing_ok=True)
    if has_service: subprocess.run(['systemctl', 'restart', 'trusttunnel'])
    raise
if subprocess.run(['systemctl', 'is-active', '--quiet', 'trusttunnel-panel'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
    subprocess.Popen(['sh', '-c', 'sleep 3; systemctl try-restart trusttunnel-panel >/dev/null 2>&1'], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print('Сертификат и ключ проверены; пути endpoint синхронизированы.')
PY
}

write_self_signed_cert() {
  mkdir -p "$TT_DIR/certs"
  if [ "${FORCE_CERT_RENEW:-0}" != "1" ] && [ "${PRESERVE_CLIENT_CONFIGS:-0}" = "1" ] && [ -f "$TT_DIR/certs/cert.pem" ] && [ -f "$TT_DIR/certs/key.pem" ]; then
    if cert_matches_domain "$TT_DIR/certs/cert.pem"; then
      echo "Using existing certificate for ${DOMAIN}."
      return
    fi
  fi
  local staged
  staged="$(mktemp -d "$TT_DIR/certs/.self-signed-XXXXXX")"
  openssl ecparam -name prime256v1 -genkey -noout -out "$staged/key.pem"
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
    -key "$staged/key.pem" \
    -sha256 -days 365 \
    -out "$staged/cert.pem" \
    -config "$TT_DIR/certs/openssl.cnf"
  deploy_certificate_pair "$staged/cert.pem" "$staged/key.pem"
  rm -rf -- "$staged"
}

write_letsencrypt_cert() (
  [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Некорректный домен." >&2; return 1; }
  ensure_letsencrypt_packages
  local certbot_name added_ufw_rule live_dir
  mkdir -p "$TT_DIR/certs"
  if [ "${FORCE_CERT_RENEW:-0}" != "1" ] && [ "${PRESERVE_CLIENT_CONFIGS:-0}" = "1" ] && [ -f "$TT_DIR/certs/cert.pem" ] && [ -f "$TT_DIR/certs/key.pem" ]; then
    if cert_matches_domain "$TT_DIR/certs/cert.pem" && cert_is_letsencrypt "$TT_DIR/certs/cert.pem"; then
      echo "Using existing Let's Encrypt certificate for ${DOMAIN}."
      return
    fi
  fi

  added_ufw_rule=0
  cleanup_initial_acme() { [ "$added_ufw_rule" != "1" ] || ufw --force delete allow 80/tcp >/dev/null 2>&1 || true; }
  trap cleanup_initial_acme EXIT
  trap 'exit 143' TERM INT
  if ufw status 2>/dev/null | grep -q "Status: active"; then
    if ! ufw status 2>/dev/null | awk '$1 == "80/tcp" && $2 == "ALLOW" && ($3 == "Anywhere" || ($3 == "IN" && $4 == "Anywhere")) { found=1 } END { exit !found }'; then
      ufw insert 1 allow 80/tcp comment "TrustTunnel Let's Encrypt" >/dev/null
      added_ufw_rule=1
    fi
  fi

  certbot_name="$DOMAIN"
  if ! certbot certonly --standalone --non-interactive --agree-tos -m "$EMAIL" -d "$DOMAIN" --preferred-challenges http $([ "${FORCE_CERT_RENEW:-0}" = "1" ] && printf '%s' '--force-renewal' || printf '%s' '--keep-until-expiring') --cert-name "$certbot_name"; then
    echo "Let's Encrypt issuance failed. Check DNS for ${DOMAIN} and inbound 80/tcp reachability." >&2
    exit 1
  fi

  if [ "$added_ufw_rule" = "1" ]; then
    ufw --force delete allow 80/tcp >/dev/null 2>&1 || true
    added_ufw_rule=0
  fi

  live_dir="/etc/letsencrypt/live/${certbot_name}"
  if [ ! -f "${live_dir}/fullchain.pem" ] || [ ! -f "${live_dir}/privkey.pem" ]; then
    echo "Let's Encrypt certificate files not found in ${live_dir}." >&2
    exit 1
  fi

  deploy_certificate_pair "${live_dir}/fullchain.pem" "${live_dir}/privkey.pem"
)

write_certificate_automation() {
  {
    printf '#!/usr/bin/env bash\nset -euo pipefail\nTT_DIR=%q\nDOMAIN=%q\n' "$TT_DIR" "$DOMAIN"
    declare -f deploy_certificate_pair
    printf 'deploy_certificate_pair "$1/fullchain.pem" "$1/privkey.pem"\n'
  } > /usr/local/sbin/trusttunnel-cert-deploy
  chmod 0700 /usr/local/sbin/trusttunnel-cert-deploy
  cat > /usr/local/sbin/trusttunnel-cert-renew <<EOF
#!/usr/bin/env bash
set -euo pipefail
TT_DIR="${TT_DIR}"
CERT_MODE="${CERT_MODE}"
DOMAIN="${DOMAIN}"

if [ "\${CERT_MODE}" != "letsencrypt" ]; then
  exit 0
fi

added_ufw_rule=0
cleanup() {
  if [ "\${added_ufw_rule}" = "1" ]; then
    ufw --force delete allow 80/tcp >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 143' TERM INT

if ufw status 2>/dev/null | grep -q "Status: active"; then
  if ! ufw status 2>/dev/null | awk '\$1 == "80/tcp" && \$2 == "ALLOW" && (\$3 == "Anywhere" || (\$3 == "IN" && \$4 == "Anywhere")) { found=1 } END { exit !found }'; then
    ufw insert 1 allow 80/tcp comment "TrustTunnel Let's Encrypt" >/dev/null
    added_ufw_rule=1
  fi
fi

certbot renew --standalone --non-interactive --no-random-sleep-on-renew --cert-name "\${DOMAIN}" "\$@" --deploy-hook '/usr/local/sbin/trusttunnel-cert-deploy "\$RENEWED_LINEAGE"'
EOF
  chmod 0755 /usr/local/sbin/trusttunnel-cert-renew

  cat > /etc/systemd/system/trusttunnel-cert-renew.service <<'EOF'
[Unit]
Description=Renew Let's Encrypt certificate for TrustTunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/trusttunnel-cert-renew
EOF

  cat > /etc/systemd/system/trusttunnel-cert-renew.timer <<'EOF'
[Unit]
Description=Run TrustTunnel Let's Encrypt renewal daily

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now trusttunnel-cert-renew.timer
}

remove_certificate_automation() {
  systemctl disable --now trusttunnel-cert-renew.timer 2>/dev/null || true
  rm -f /etc/systemd/system/trusttunnel-cert-renew.service
  rm -f /etc/systemd/system/trusttunnel-cert-renew.timer
  rm -f /usr/local/sbin/trusttunnel-cert-renew
  rm -f /usr/local/sbin/trusttunnel-cert-deploy
  systemctl daemon-reload
}

write_certs() {
  case "${CERT_MODE:-self-signed}" in
    letsencrypt)
      write_letsencrypt_cert
      ;;
    *)
      write_self_signed_cert
      ;;
  esac
}

assert_protection_unlocked() {
  [ -f "$TT_DIR/panel-protection.json" ] || return 0
  python3 - "$TT_DIR/panel-protection.json" <<'PY'
import json,sys
with open(sys.argv[1]) as source: state=json.load(source)
if any(state.get(key) for key in ('enabled','tls_enabled','transition')):
    raise SystemExit('Сначала явно отключите строгую TLS/ClientHello-защиту через ttmenu. Изменение правил или смена endpoint может обойти защиту.')
PY
}

write_server_config() {
  assert_protection_unlocked || return 1
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
  load_client_network_settings
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

EOF
    if [ "$CERT_MODE" = "self-signed" ]; then
      cat >> "$profile" <<EOF

# Endpoint certificate in PEM format.
certificate = """
${cert}
"""
EOF
    fi
    cat >> "$profile" <<EOF

# DNS resolvers for requests sent through the tunnel
dns_upstreams = ${CLIENT_DNS_TOML}

# Protocol to be used to communicate with the endpoint [http2, http3]
upstream_protocol = "${protocol}"

# TLS ClientHello profile used by the client
tls_profile = "${CLIENT_TLS_PROFILE}"

# Enable client AntiDPI measures
anti_dpi = ${CLIENT_ANTI_DPI}

# Hybrid post-quantum TLS key exchange (requires a current TrustTunnel client)
post_quantum_group_enabled = ${CLIENT_POST_QUANTUM}
EOF
  done
}

write_clients() {
  if [ "${PRESERVE_CLIENT_CONFIGS:-0}" = "1" ] && [ -f "$TT_DIR/credentials.toml" ]; then
    ensure_admin_helper || return 1
    admin_call client-rebuild
    return
  fi
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
  if [ "$RESET_UFW" = "1" ]; then ufw --force reset; fi
  if ! ufw status | grep -q '^Status: active'; then
    ufw default deny incoming
    ufw default allow outgoing
  fi
  ufw allow "${SSH_PORT}/tcp" comment "SSH"
  ufw allow "${ENDPOINT_PORT}/tcp" comment "TrustTunnel TCP"
  if [ "$ENABLE_QUIC" = "1" ]; then
    ufw allow "${ENDPOINT_PORT}/udp" comment "TrustTunnel QUIC"
  fi
  if [ -f /etc/trusttunnel-panel.env ]; then
    local saved_panel_port saved_panel_tls
    saved_panel_port="$(awk -F= '$1=="PANEL_PORT" {print $2}' /etc/trusttunnel-panel.env)"
    saved_panel_tls="$(awk -F= '$1=="PANEL_TLS" {print $2}' /etc/trusttunnel-panel.env)"
    if [ "$saved_panel_tls" = "1" ] && [[ "$saved_panel_port" =~ ^[0-9]{1,5}$ ]]; then
      ufw allow "${saved_panel_port}/tcp" comment "TrustTunnel Panel HTTPS"
    fi
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
  if [ ! -f /etc/fail2ban/jail.d/sshd.local ]; then
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
  else
    # Keep custom bans/exclusions; override only our managed enabled/port keys.
    cat > /etc/fail2ban/jail.d/zz-trusttunnel-port.local <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
EOF
  fi
  fail2ban-client -t
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
  apt_update_retry
  apt_install_retry -y --no-install-recommends --no-upgrade ca-certificates curl tar gzip coreutils sed
}

update_trusttunnel_only() {
  assert_protection_unlocked || return 1
  if [ ! -d "$TT_DIR" ]; then
    echo "TrustTunnel не найден в ${TT_DIR}. Сначала выполни установку."
    exit 1
  fi
  install_download_tools
  local rollback
  mkdir -p "$TT_DIR/backups"
  rollback="$(mktemp -d "$TT_DIR/backups/update-XXXXXX")"
  cp "$TT_DIR/trusttunnel_endpoint" "$rollback/trusttunnel_endpoint"
  if [ -x "$TT_DIR/setup_wizard" ]; then cp "$TT_DIR/setup_wizard" "$rollback/setup_wizard"; fi
  if ! download_trusttunnel; then
    install -m 0755 "$rollback/trusttunnel_endpoint" "$TT_DIR/trusttunnel_endpoint.rollback"
    mv -f "$TT_DIR/trusttunnel_endpoint.rollback" "$TT_DIR/trusttunnel_endpoint"
    echo "Не удалось скачать обновление. Прежний endpoint продолжает работать." >&2; return 1
  fi
  if ! systemctl restart trusttunnel; then
    echo "Не удалось перезапустить endpoint после обновления." >&2
  fi
  sleep 2
  if ! systemctl is-active --quiet trusttunnel; then
    install -m 0755 "$rollback/trusttunnel_endpoint" "$TT_DIR/trusttunnel_endpoint.rollback"
    mv -f "$TT_DIR/trusttunnel_endpoint.rollback" "$TT_DIR/trusttunnel_endpoint"
    if [ -x "$rollback/setup_wizard" ]; then install -m 0755 "$rollback/setup_wizard" "$TT_DIR/setup_wizard.rollback"; mv -f "$TT_DIR/setup_wizard.rollback" "$TT_DIR/setup_wizard"; fi
    systemctl restart trusttunnel
    echo "Новый endpoint не запустился. Восстановлена предыдущая версия." >&2; return 1
  fi
  echo "TrustTunnel endpoint обновлен и перезапущен."
  trusttunnel-status 2>/dev/null || show_status
}

manage_masque() {
  ensure_admin_helper || return
  local choice confirm
  while true; do
    echo "=== WARP MASQUE (usque, локальный TCP/UDP-прокси) ==="
    echo "Маршрут SSH не меняется. Сначала установка и проверка, затем включение."
    echo "1) Установить / обновить MASQUE"
    echo "2) Проверить TCP и UDP"
    echo "3) Направить TrustTunnel через MASQUE"
    echo "4) Перезапустить MASQUE"
    echo "5) Остановить MASQUE (сначала смените маршрут)"
    echo "6) Удалить MASQUE с backup аккаунта"
    echo "7) Перерегистрировать аккаунт MASQUE"
    echo "8) Статус MASQUE"
    echo "9) Вернуть TrustTunnel на WARP WireGuard"
    echo "10) Вернуть TrustTunnel на Direct"
    echo "0) Назад"
    prompt_value "Действие [0]: "; choice="${REPLY_VALUE:-0}"
    case "$choice" in
      0) return ;;
      1)
        echo "usque — сторонний клиент Cloudflare WARP. Условия: https://www.cloudflare.com/application/terms/"
        prompt_value "Принимаете условия Cloudflare? да/нет: "
        case "$REPLY_VALUE" in да|yes|YES|y|Y) admin_call masque-install accept_tos=1 ;; *) echo "Отменено." ;; esac ;;
      2) admin_call masque-check ;;
      3) admin_call masque-enable ;;
      4) admin_call masque-restart ;;
      5) admin_call masque-stop ;;
      6) prompt_value "Введите REMOVE: "; confirm="$REPLY_VALUE"; admin_call masque-remove "confirm=$confirm" ;;
      7) prompt_value "Введите REREGISTER: "; confirm="$REPLY_VALUE"; admin_call masque-reregister "confirm=$confirm" ;;
      8) admin_call masque-status ;;
      9) admin_call routing-switch mode=warp ;;
      10) admin_call routing-switch mode=direct ;;
      *) echo "Выберите 0–10." ;;
    esac
  done
}

manage_server_security() {
  ensure_admin_helper
  local choice kind day clock ack confirmed=0
  echo "1) Проверить сервер и получить рекомендации"
  echo "2) Запретить входящий ping через UFW"
  echo "3) Вернуть исходную политику ping"
  echo "4) Показать расписания"
  echo "5) Создать / изменить расписание"
  echo "6) Отключить расписание"
  echo "7) Применить выбранное исправление безопасности"
  echo "8) Диагностика endpoint, портов и TLS"
  echo "9) Проверить выход через текущий WARP"
  echo "10) Проверить прямой DNS/TCP/TLS выход VPS"
  echo "0) Назад"
  prompt_value "Выбор [1]: "; choice="${REPLY_VALUE:-1}"
  case "$choice" in
    1) admin_call security-scan; return ;;
    2|3)
      ask_yes_no confirmed "Изменить только входящие echo-request, сохраняя необходимые ICMPv6" 0
      [ "$confirmed" = 1 ] || return
      local enabled=0; [ "$choice" = 2 ] || enabled=1
      admin_call security-ping "enabled=$enabled" confirm=CONFIRMED; return ;;
    4) admin_call schedule-status; return ;;
    7)
      echo "Исправления: ntp, syn-cookies, private-files, metrics-private, kernel-baseline."
      ask_default kind "Исправление (сначала прочитайте отчёт проверки)" "ntp"
      confirm_action "Применить только выбранную настройку? Изоляция метрик перезапустит VPN. SSH-пароль и маршруты WARP не меняются."
      admin_call security-remediate "check=$kind" confirm=CONFIRMED; return ;;
    8) admin_call diagnostics-stack; return ;;
    9) admin_call diagnostics-warp; return ;;
    10)
      ask_default kind "Направление cloudflare/github" "cloudflare"
      admin_call diagnostics-egress "target=$kind"; return ;;
    5|6) ;;
    *) return ;;
  esac
  echo "Задачи: reboot (перезагрузка), packages (обновление ОС), security (проверка безопасности), releases (версии endpoint)."
  ask_default kind "Задача" "security"
  ask_yes_no confirmed "Изменить автоматическое обслуживание выбранной задачи" 0
  [ "$confirmed" = 1 ] || return
  if [ "$choice" = 6 ]; then admin_call schedule-disable "kind=$kind" confirm=CONFIRMED; return; fi
  ask_default day "День: daily или Mon/Tue/Wed/Thu/Fri/Sat/Sun" "daily"
  ask_default clock "Время сервера ЧЧ:ММ" "03:30"
  ack=0
  if [ "$kind" = packages ]; then ask_yes_no ack "Обновления ОС могут перезапускать службы. Допускаете" 0; fi
  admin_call schedule-save "kind=$kind" "day=$day" "time=$clock" "updates_ack=$ack" confirm=CONFIRMED
}

manage_protection() {
  ensure_admin_helper
  local choice op ready
  echo "=== Защита от сканирования ==="
  echo "1) Проверить состояние и совместимость"
  echo "2) Скрыть служебные HTTP-ответы без смены клиентских настроек"
  echo "3) Подготовить защищённые tt-ссылки (ничего не блокировать)"
  echo "4) Включить строгий ClientHello-фильтр: старые профили перестанут работать"
  echo "5) Отключить строгий фильтр и вернуть прежние правила"
  echo "6) Вернуть прежние HTTP-настройки"
  echo "7) Подготовить TLS-auth ссылки для App v1.3 (без блокировки)"
  echo "8) Обязательная TLS-аутентификация (только после проверки совместимости)"
  echo "9) Отключить обязательную TLS-аутентификацию"
  echo "10) AntiDPI + Chrome TLS + DoH для новых профилей"
  echo "11) Гибкая настройка AntiDPI новых профилей"
  echo "0) Назад"
  prompt_value "Выбор [1]: "; choice="${REPLY_VALUE:-1}"
  case "$choice" in
    1) admin_call protection-status; return ;;
    2) op=camouflage ;;
    3) op=prepare ;;
    4) op=enforce ;;
    5) op=disable ;;
    6) op=camouflage-restore ;;
    7) op=tls-prepare ;;
    8) op=tls-enforce ;;
    9) op=tls-disable ;;
    10) op=client-preset ;;
    11)
      local dns profile antidpi quantum
      ask_default dns "DNS (IP / DoH / DoT через запятую)" "https://dns.adguard-dns.com/dns-query"
      ask_default profile "TLS profile: chrome/safari/firefox/okhttp/openssl/default" "chrome"
      ask_yes_no antidpi "Штатный AntiDPI клиента" 1
      ask_yes_no quantum "Post-quantum TLS (не маскировка; нужен совместимый клиент)" 0
      confirm_action "Изменить только настройки новых профилей, не переписывая текущие TOML."
      admin_call protection-client-settings "dns=$dns" "tls_profile=$profile" "anti_dpi=$antidpi" "post_quantum=$quantum" confirm=CONFIRMED; return ;;
    *) return ;;
  esac
  echo "Это снижение обнаруживаемости, а не гарантия невидимости. Встроенные AntiDPI и TLS profile находятся в пункте 26."
  ready=0
  if [ "$op" = enforce ] || [ "$op" = tls-enforce ]; then
    ask_yes_no ready "Все устройства уже проверены с защищёнными ссылками" 0
    [ "$ready" = 1 ] || return
  fi
  local confirmed=0
  ask_yes_no confirmed "Применить изменение защиты" 0
  [ "$confirmed" = 1 ] || return
  local v13=0
  if [ "$op" = tls-enforce ]; then
    ask_yes_no v13 "На всех устройствах проверен App v1.3 с ключом TLS-auth (QUIC enforcement пока блокируется)" 0
    [ "$v13" = 1 ] || return
  fi
  admin_call "protection-$op" confirm=CONFIRMED "clients_ready=$ready" "client_v13=$v13"
}

manage_warp() {
  ensure_admin_helper || return
  local backend choice operation
  while true; do
    echo "=== Вариант WARP ==="
    echo "1) WireGuard через SOCKS"
    echo "2) MASQUE через SOCKS"
    echo "3) WireGuard через интерфейс без SOCKS"
    echo "4) MASQUE через TUN без SOCKS"
    echo "0) Назад"
    prompt_value "Вариант [0]: "
    case "${REPLY_VALUE:-0}" in 0) return ;; 1) backend=wg-socks ;; 2) backend=masque-socks ;; 3) backend=wg-interface ;; 4) backend=masque-interface ;; *) continue ;; esac
    echo "1) Статус; 2) Проверить; 3) Установить / переустановить"
    echo "4) Включить маршрут; 5) Отключить; 6) Перезапустить"
    echo "7) Попробовать сменить IP; 8) Новая регистрация; 9) Удалить"
    prompt_value "Действие [1]: "; choice="${REPLY_VALUE:-1}"
    case "$choice" in 1) operation=status ;; 2) operation=check ;; 3) operation=install ;; 4) operation=enable ;; 5) operation=disable ;; 6) operation=restart ;; 7) operation=rotate ;; 8) operation=reregister ;; 9) operation=remove ;; *) continue ;; esac
    if [ "$operation" != "status" ] && [ "$operation" != "check" ]; then
      echo "VPN может кратковременно прерваться. Отключение активного SOCKS включает Direct с IP VPS. Новый IP не гарантирован."
      prompt_value "Продолжить? да/нет: "
      case "$REPLY_VALUE" in да|yes|YES|y|Y) ;; *) continue ;; esac
    fi
    local tos=0
    if [ "$operation" = "install" ] || [ "$operation" = "reregister" ]; then
      prompt_value "Принимаете условия Cloudflare WARP? да/нет: "
      case "$REPLY_VALUE" in да|yes|YES|y|Y) tos=1 ;; *) continue ;; esac
    fi
    admin_call warp-operation "backend=$backend" "operation=$operation" confirm=CONFIRMED "accept_tos=$tos" || true
  done
}

manage_interface() {
  ensure_admin_helper || return
  local choice confirm
  while true; do
    echo "=== WARP-интерфейс: только трафик TrustTunnel ==="
    echo "SSH и маршруты других служб не меняются. Нужна отдельная WARP-регистрация."
    echo "1) Установить / переустановить"
    echo "2) Включить маршрут"
    echo "3) Отключить (вернуть прежний маршрут)"
    echo "4) Проверить"
    echo "5) Перезапустить интерфейс и TrustTunnel"
    echo "6) Перерегистрировать отдельный аккаунт"
    echo "7) Удалить"
    echo "8) Статус"
    echo "0) Назад"
    prompt_value "Действие [0]: "; choice="${REPLY_VALUE:-0}"
    case "$choice" in
      0) return ;;
      1)
        prompt_value "Принимаете условия Cloudflare WARP? да/нет: "
        case "$REPLY_VALUE" in да|yes|YES|y|Y) admin_call interface-install accept_tos=1 ;; *) echo "Отменено." ;; esac ;;
      2) admin_call interface-enable ;;
      3) admin_call interface-disable ;;
      4) admin_call interface-check ;;
      5) admin_call interface-restart ;;
      6) prompt_value "Введите REREGISTER: "; confirm="$REPLY_VALUE"; admin_call interface-reregister "confirm=$confirm" ;;
      7) prompt_value "Введите REMOVE: "; confirm="$REPLY_VALUE"; admin_call interface-remove "confirm=$confirm" ;;
      8) admin_call interface-status ;;
      *) echo "Выберите 0–8." ;;
    esac
  done
}

manage_endpoint_features() {
  ensure_admin_helper || return
  local choice enabled path confirm
  while true; do
    echo "=== Обновления и функции endpoint ==="
    echo "1) Проверить стабильный и предварительный выпуски"
    echo "2) Обновить до стабильного выпуска"
    echo "3) Обновить до beta (предварительная версия)"
    echo "4) Включить / выключить метрики пользователей (только localhost)"
    echo "5) Включить / выключить HTTPS-подписки (нужен совместимый endpoint)"
    echo "0) Назад"
    prompt_value "Действие [0]: "; choice="${REPLY_VALUE:-0}"
    case "$choice" in
      0) return ;;
      1) admin_call endpoint-releases ;;
      2) TT_CHANNEL=stable; update_trusttunnel_only ;;
      3)
        prompt_value "Beta может содержать ошибки. Введите BETA: "; confirm="$REPLY_VALUE"
        if [ "$confirm" = BETA ]; then TT_CHANNEL=beta; update_trusttunnel_only; else echo "Отменено."; fi ;;
      4)
        prompt_value "Включить: 1; выключить: 0 [0]: "; enabled="${REPLY_VALUE:-0}"
        admin_call endpoint-metrics "enabled=$enabled" ;;
      5)
        prompt_value "Включить: 1; выключить: 0 [0]: "; enabled="${REPLY_VALUE:-0}"
        prompt_value "Путь [/subscription]: "; path="${REPLY_VALUE:-/subscription}"
        admin_call endpoint-subscription "enabled=$enabled" "path=$path" ;;
      *) echo "Выберите 0–5." ;;
    esac
  done
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
  switch_trusttunnel_forwarder direct
  systemctl disable --now warp-wireproxy 2>/dev/null || true
  echo "WARP отключен без удаления файлов. TrustTunnel переключен на direct."
  check_warp
}

trusttunnel_uses_socks5() {
  grep -Fq "address = \"${SOCKS_ADDR}\"" "$TT_DIR/vpn.toml" 2>/dev/null
}

reregister_warp_account() {
  confirm_action "Будет полностью удален и заново зарегистрирован WARP-аккаунт. Клиенты TrustTunnel, сертификаты и настройки TrustTunnel затронуты не будут."
  ENABLE_WARP=1
  ENABLE_FAIL2BAN=0
  ENABLE_SYSTEM_UPGRADE="${ENABLE_SYSTEM_UPGRADE:-0}"
  install_packages
  download_wireproxy
  mkdir -p "$WARP_DIR/wgcf"
  local backup
  mkdir -p /root/trusttunnel-warp-account-backups
  chmod 0700 /root/trusttunnel-warp-account-backups
  backup="$(mktemp -d /root/trusttunnel-warp-account-backups/wg-socks-XXXXXX)"
  cp -a "$WARP_DIR/wgcf" "$backup/wgcf"
  if [ -f "$WARP_DIR/wireproxy.conf" ]; then cp -a "$WARP_DIR/wireproxy.conf" "$backup/wireproxy.conf"; fi
  WARP_REGISTRATION_BACKUP="$backup"
  trap 'rc=$?; if [ "$rc" -ne 0 ]; then cp -a "$WARP_REGISTRATION_BACKUP/wgcf/." "$WARP_DIR/wgcf/"; if [ -f "$WARP_REGISTRATION_BACKUP/wireproxy.conf" ]; then cp -a "$WARP_REGISTRATION_BACKUP/wireproxy.conf" "$WARP_DIR/wireproxy.conf"; fi; systemctl restart warp-wireproxy || true; fi' EXIT
  systemctl disable --now warp-wireproxy 2>/dev/null || true
  rm -f "$WARP_DIR/wireproxy.conf"
  rm -f "$WARP_DIR/wgcf/wgcf-account.toml" "$WARP_DIR/wgcf/wgcf-profile.conf"
  generate_warp_profile
  write_warp_systemd
  curl -fsS --max-time 15 --proxy "socks5h://${SOCKS_ADDR}" https://www.cloudflare.com/cdn-cgi/trace | grep -Eq '^warp=(on|plus)$'
  trap - EXIT
  unset WARP_REGISTRATION_BACKUP
  if trusttunnel_uses_socks5; then
    switch_trusttunnel_forwarder socks5
  fi
  echo "WARP-аккаунт полностью перерегистрирован."
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
  echo "WARP установлен/переустановлен. Текущий маршрут не изменён. Для включения выберите пункт 8."
  trusttunnel-status 2>/dev/null || true
}

remove_warp_only() {
  confirm_action "Будет удален WARP/wireproxy. Только если этот вариант активен, TrustTunnel переключится на Direct с IP VPS."
  if trusttunnel_uses_socks5; then switch_trusttunnel_forwarder direct; fi
  systemctl stop warp-wireproxy 2>/dev/null || true
  systemctl disable warp-wireproxy 2>/dev/null || true
  rm -f /etc/systemd/system/warp-wireproxy.service
  systemctl daemon-reload
  rm -rf "$WARP_DIR"
  echo "Wireproxy удален. Остальные варианты WARP не удалены."
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

current_domain() {
  if [ -f "$TT_DIR/hosts.toml" ]; then
    sed -nE 's/^hostname = "([^"]+)".*/\1/p' "$TT_DIR/hosts.toml" | head -1
    return
  fi
  printf '%s' "${DOMAIN:-}"
}

current_client_count() {
  if [ -f "$TT_DIR/credentials.toml" ]; then
    awk 'BEGIN { n = 0 } /^\[\[client\]\]/ { n++ } END { print (n > 0 ? n : 1) }' "$TT_DIR/credentials.toml"
    return
  fi
  printf '1'
}

current_quic_enabled() {
  if [ -f "$TT_DIR/vpn.toml" ] && grep -q '^\[listen_protocols\.quic\]' "$TT_DIR/vpn.toml"; then
    printf '1'
    return
  fi
  printf '0'
}

detect_current_cert_mode() {
  local cert_path domain issuer subject live_dir expected_issuer
  cert_path="$TT_DIR/certs/cert.pem"
  domain="$(current_domain)"
  if [ ! -f "$cert_path" ]; then
    printf 'self-signed'
    return
  fi

  if [ -n "$domain" ]; then
    live_dir="/etc/letsencrypt/live/${domain}"
    if [ -f "${live_dir}/fullchain.pem" ] && cmp -s "$cert_path" "${live_dir}/fullchain.pem"; then
      printf 'letsencrypt'
      return
    fi
  fi

  issuer="$(openssl x509 -in "$cert_path" -noout -issuer 2>/dev/null || true)"
  subject="$(openssl x509 -in "$cert_path" -noout -subject 2>/dev/null || true)"
  expected_issuer="${subject/subject=/issuer=}"
  if [ -n "$issuer" ] && [ "$issuer" = "$expected_issuer" ]; then
    printf 'self-signed'
    return
  fi
  if printf '%s\n' "$issuer" | grep -qi "let's encrypt\|ISRG"; then
    printf 'letsencrypt'
    return
  fi
  if [ -f /etc/systemd/system/trusttunnel-cert-renew.timer ]; then
    printf 'letsencrypt'
    return
  fi
  printf 'self-signed'
}

load_current_trusttunnel_context() {
  if [ ! -f "$TT_DIR/vpn.toml" ] || [ ! -f "$TT_DIR/hosts.toml" ] || [ ! -f "$TT_DIR/credentials.toml" ]; then
    echo "TrustTunnel config not found in ${TT_DIR}." >&2
    exit 1
  fi
  DOMAIN="$(current_domain)"
  ENDPOINT_PORT="$(current_endpoint_port)"
  CLIENTS="$(current_client_count)"
  ENABLE_QUIC="$(current_quic_enabled)"
  CERT_MODE="$(detect_current_cert_mode)"
  PRESERVE_CLIENT_CONFIGS=1
}

ensure_letsencrypt_packages() {
  export DEBIAN_FRONTEND=noninteractive
  if command -v certbot >/dev/null 2>&1; then
    return
  fi
  if ! apt_update_retry; then
    echo "Warning: apt-get update failed before certbot install." >&2
  fi
  apt_install_retry -y --no-install-recommends --no-upgrade certbot
  if ! command -v certbot >/dev/null 2>&1; then
    echo "certbot install failed." >&2
    exit 1
  fi
}

renew_certificate_manually() {
  local current_mode
  load_current_trusttunnel_context
  current_mode="$CERT_MODE"

  case "$current_mode" in
    letsencrypt)
      ask_required EMAIL "Email for Let's Encrypt: "
      ensure_letsencrypt_packages
      FORCE_CERT_RENEW=1
      write_letsencrypt_cert
      write_certificate_automation
      systemctl restart trusttunnel
      echo "Let's Encrypt certificate updated manually."
      ;;
    *)
      confirm_action "Будет выпущен новый self-signed сертификат. Клиентам потребуется обновленный TOML или новый server-cert.pem."
      FORCE_CERT_RENEW=1
      write_self_signed_cert
      write_clients
      remove_certificate_automation
      systemctl restart trusttunnel
      echo "Self-signed certificate regenerated. Client files updated in ${CLIENT_DIR}."
      ;;
  esac
}

switch_certificate_mode() {
  local current_mode target_mode requested_mode="${CERT_MODE:-}"
  load_current_trusttunnel_context
  current_mode="$CERT_MODE"
  CERT_MODE="$requested_mode"
  if [ "$CERT_MODE" != "self-signed" ] && [ "$CERT_MODE" != "letsencrypt" ]; then
    if [ ! -r /dev/tty ]; then
      echo "For non-interactive certificate switch set CERT_MODE=self-signed or CERT_MODE=letsencrypt." >&2
      exit 1
    fi
    CERT_MODE=""
    ask_cert_mode
  fi
  target_mode="$CERT_MODE"

  if [ "$target_mode" = "$current_mode" ]; then
    echo "Certificate mode already set to ${current_mode}."
    return
  fi

  case "$target_mode" in
    letsencrypt)
      confirm_action "Будет выполнен переход на Let's Encrypt. Во время выпуска сертификата временно откроется 80/tcp. Клиентские TOML будут обновлены."
      ask_required EMAIL "Email for Let's Encrypt: "
      ensure_letsencrypt_packages
      FORCE_CERT_RENEW=1
      write_letsencrypt_cert
      write_clients
      write_certificate_automation
      systemctl restart trusttunnel
      echo "Switched certificate mode to Let's Encrypt."
      ;;
    self-signed)
      confirm_action "Будет выполнен переход на self-signed сертификат. Клиентам понадобится обновленный TOML или новый server-cert.pem."
      FORCE_CERT_RENEW=1
      write_self_signed_cert
      write_clients
      remove_certificate_automation
      systemctl restart trusttunnel
      echo "Switched certificate mode to self-signed."
      ;;
    *)
      echo "Unsupported certificate mode: ${target_mode}" >&2
      exit 1
      ;;
  esac
}

backup_identity() {
  local backup_name archive_path backup_domain backup_port backup_cert_mode
  if [ ! -f "$TT_DIR/certs/cert.pem" ] || [ ! -f "$TT_DIR/certs/key.pem" ] || [ ! -f "$TT_DIR/credentials.toml" ]; then
    echo "Не найден полный набор identity-файлов TrustTunnel для backup."
    exit 1
  fi
  mkdir -p "$IDENTITY_BACKUP_DIR/certs" "$IDENTITY_BACKUP_DIR/client-files"
  chmod 0700 "$IDENTITY_BACKUP_DIR" "$IDENTITY_BACKUP_DIR/certs" "$IDENTITY_BACKUP_DIR/client-files"
  cp "$TT_DIR/certs/cert.pem" "$IDENTITY_BACKUP_DIR/certs/cert.pem"
  cp "$TT_DIR/certs/key.pem" "$IDENTITY_BACKUP_DIR/certs/key.pem"
  cp "$TT_DIR/credentials.toml" "$IDENTITY_BACKUP_DIR/credentials.toml"
  if [ -f "$TT_DIR/clients-state.json" ]; then
    cp "$TT_DIR/clients-state.json" "$IDENTITY_BACKUP_DIR/clients-state.json"
    chmod 0600 "$IDENTITY_BACKUP_DIR/clients-state.json"
  else
    rm -f "$IDENTITY_BACKUP_DIR/clients-state.json"
  fi
  cp "$TT_DIR/hosts.toml" "$IDENTITY_BACKUP_DIR/hosts.toml"
  for item in rules.toml panel-protection.json client-guard.json; do
    if [ -f "$TT_DIR/$item" ]; then cp "$TT_DIR/$item" "$IDENTITY_BACKUP_DIR/$item"; else rm -f "$IDENTITY_BACKUP_DIR/$item"; fi
  done
  find "$IDENTITY_BACKUP_DIR/client-files" -maxdepth 1 -type f -name '*.toml' -delete
  if [ -f "$CLIENT_DIR/clients-credentials.txt" ]; then
    cp "$CLIENT_DIR/clients-credentials.txt" "$IDENTITY_BACKUP_DIR/client-files/clients-credentials.txt"
  fi
  if [ -f "$CLIENT_DIR/server-cert.pem" ]; then
    cp "$CLIENT_DIR/server-cert.pem" "$IDENTITY_BACKUP_DIR/client-files/server-cert.pem"
  fi
  find "$CLIENT_DIR" -maxdepth 1 -type f -name '*.toml' -exec cp {} "$IDENTITY_BACKUP_DIR/client-files/" \; 2>/dev/null || true
  backup_domain="$(sed -nE 's/^hostname = "([^"]+)".*/\1/p' "$TT_DIR/hosts.toml" | head -1)"
  backup_port="$(current_endpoint_port)"
  backup_cert_mode="$(detect_current_cert_mode)"
  cat > "$IDENTITY_BACKUP_DIR/identity.env" <<EOF
DOMAIN=${backup_domain}
ENDPOINT_PORT=${backup_port}
CERT_MODE=${backup_cert_mode}
EOF
  backup_name="${backup_domain:-trusttunnel}-identity-backup"
  archive_path="/root/${backup_name}.tar.gz"
  tar -czf "$archive_path" -C "$IDENTITY_BACKUP_DIR" .
  chmod 0600 "$archive_path"
  echo "Identity backup создан:"
  echo "- Папка: ${IDENTITY_BACKUP_DIR}"
  echo "- Архив: ${archive_path}"
}

restore_identity() {
  assert_protection_unlocked || return 1
  local backup_domain backup_port backup_cert_mode current_domain current_port
  backup_cert_mode=""
  if [ ! -f "$IDENTITY_BACKUP_DIR/certs/cert.pem" ] || [ ! -f "$IDENTITY_BACKUP_DIR/certs/key.pem" ] || [ ! -f "$IDENTITY_BACKUP_DIR/credentials.toml" ]; then
    echo "Backup identity не найден в ${IDENTITY_BACKUP_DIR}."
    exit 1
  fi
  mkdir -p "$TT_DIR/certs" "$CLIENT_DIR"
  python3 - "$IDENTITY_BACKUP_DIR" "$TT_DIR" <<'PY'
import hashlib, json, pathlib, ssl, subprocess, sys
try: import tomllib
except ImportError: import tomli as tomllib
root = pathlib.Path(sys.argv[1])
ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(root/'certs/cert.pem', root/'certs/key.pem')
credentials = tomllib.loads((root/'credentials.toml').read_text())
clients = credentials.get('client', [])
if not clients or any(not c.get('username') or not c.get('password') for c in clients): raise SystemExit('Backup credentials invalid')
for name in ('hosts.toml','rules.toml'):
    if (root/name).exists(): tomllib.loads((root/name).read_text())
for name in ('clients-state.json','panel-protection.json','client-guard.json'):
    if (root/name).exists(): json.loads((root/name).read_text())
protection = json.loads((root/'panel-protection.json').read_text()) if (root/'panel-protection.json').exists() else {}
if protection.get('transition'): raise SystemExit('Backup contains an unfinished protection transition')
if protection.get('enabled') or protection.get('tls_enabled'):
    destination = pathlib.Path(sys.argv[2])
    config = tomllib.loads((destination/'vpn.toml').read_text())
    if 'quic' in config.get('listen_protocols', {}): raise SystemExit('Strict backup cannot be restored onto a QUIC-enabled endpoint')
    configured = pathlib.Path(config.get('rules_file', ''))
    if not configured.is_absolute(): configured = destination/configured
    if configured.resolve() != (destination/'rules.toml').resolve() or configured.is_symlink(): raise SystemExit('Destination rules_file is not the managed rules.toml')
    binary = destination/'trusttunnel_endpoint'
    result = subprocess.run([str(binary),'--help'],check=True,capture_output=True,text=True,timeout=8)
    flag = '--client-random-auth-key' if protection.get('tls_enabled') else '--client-random-prefix'
    if flag not in result.stdout: raise SystemExit('Destination endpoint does not support the restored protection')
    expected = protection.get('tls_rules_hash' if protection.get('tls_enabled') else 'rules_hash')
    if hashlib.sha256((root/'rules.toml').read_bytes()).hexdigest() != expected: raise SystemExit('Backup protection hash does not match its rules')
for path in (root/'client-files').glob('*.toml'): tomllib.loads(path.read_text())
subprocess.run(['openssl','x509','-in',str(root/'certs/cert.pem'),'-noout','-checkend','0'],check=True,stdout=subprocess.DEVNULL)
PY
  local rollback
  rollback="$(mktemp -d /root/trusttunnel-before-restore.XXXXXX)"
  cp -a "$TT_DIR" "$rollback/trusttunnel"
  cp -a "$CLIENT_DIR" "$rollback/client-files"
  cp "$IDENTITY_BACKUP_DIR/certs/cert.pem" "$TT_DIR/certs/cert.pem"
  cp "$IDENTITY_BACKUP_DIR/certs/key.pem" "$TT_DIR/certs/key.pem"
  cp "$IDENTITY_BACKUP_DIR/credentials.toml" "$TT_DIR/credentials.toml"
  if [ -f "$IDENTITY_BACKUP_DIR/clients-state.json" ]; then
    cp "$IDENTITY_BACKUP_DIR/clients-state.json" "$TT_DIR/clients-state.json"
    chmod 0600 "$TT_DIR/clients-state.json"
  else
    rm -f "$TT_DIR/clients-state.json"
  fi
  if [ -f "$IDENTITY_BACKUP_DIR/hosts.toml" ]; then
    cp "$IDENTITY_BACKUP_DIR/hosts.toml" "$TT_DIR/hosts.toml"
  fi
  for item in rules.toml panel-protection.json client-guard.json; do
    if [ -f "$IDENTITY_BACKUP_DIR/$item" ]; then cp "$IDENTITY_BACKUP_DIR/$item" "$TT_DIR/$item"; fi
  done
  if [ -d "$IDENTITY_BACKUP_DIR/client-files" ]; then
    cp -f "$IDENTITY_BACKUP_DIR"/client-files/* "$CLIENT_DIR"/ 2>/dev/null || true
  fi
  chmod 0600 "$TT_DIR/certs/key.pem" "$TT_DIR/credentials.toml"
  chmod 0644 "$TT_DIR/certs/cert.pem"
  backup_domain=""
  backup_port=""
  current_domain="$(sed -nE 's/^hostname = "([^"]+)".*/\1/p' "$TT_DIR/hosts.toml" | head -1)"
  current_port="$(current_endpoint_port)"
  if [ -f "$IDENTITY_BACKUP_DIR/identity.env" ]; then
    backup_domain="$(sed -nE 's/^DOMAIN=(.*)/\1/p' "$IDENTITY_BACKUP_DIR/identity.env" | head -1)"
    backup_port="$(sed -nE 's/^ENDPOINT_PORT=(.*)/\1/p' "$IDENTITY_BACKUP_DIR/identity.env" | head -1)"
    backup_cert_mode="$(sed -nE 's/^CERT_MODE=(.*)/\1/p' "$IDENTITY_BACKUP_DIR/identity.env" | head -1)"
  fi
  if [ -n "$backup_cert_mode" ]; then
    CERT_MODE="$backup_cert_mode"
  else
    CERT_MODE="$(detect_current_cert_mode)"
  fi
  if ! systemctl restart trusttunnel || ! systemctl is-active --quiet trusttunnel; then
    cp -a "$rollback/trusttunnel/." "$TT_DIR/"
    cp -a "$rollback/client-files/." "$CLIENT_DIR/"
    systemctl restart trusttunnel || true
    echo "Восстановление не прошло проверку. Предыдущее состояние возвращено; backup: $rollback" >&2
    return 1
  fi
  echo "Identity восстановлен. Состояние до восстановления: $rollback"
  [ -n "$backup_domain" ] && echo "Backup domain: ${backup_domain}"
  [ -n "$backup_port" ] && echo "Backup port: ${backup_port}"
  echo "Current domain after restore: ${current_domain}"
  echo "Current port after restore: ${current_port}"
  if [ "$CERT_MODE" = "letsencrypt" ]; then
    DOMAIN="${current_domain:-$backup_domain}"
    write_certificate_automation
  else
    remove_certificate_automation
  fi
  systemctl try-restart trusttunnel-panel 2>/dev/null || true
}

remove_all() {
  confirm_action "Будут удалены TrustTunnel, WARP, клиентские файлы и порт TrustTunnel из UFW. SSH/fail2ban не удаляются."
  local endpoint_port
  endpoint_port="$(current_endpoint_port)"
  backup_identity
  systemctl disable --now trusttunnel 2>/dev/null || true
  systemctl stop trusttunnel-panel 2>/dev/null || true
  systemctl disable --now warp-interface-watchdog.timer warp-interface.service warp-masque-tun.service warp-masque-bridge.service warp-masque.service 2>/dev/null || true
  rm -f /etc/systemd/system/trusttunnel.service.d/40-warp-interface.conf
  for unit in warp-interface.service warp-interface-watchdog.service warp-interface-watchdog.timer warp-masque-tun.service warp-masque-bridge.service warp-masque.service ttwarp.slice; do
    rm -f "/etc/systemd/system/$unit"
  done
  rm -rf /opt/warp-interface /opt/warp-masque-tun /opt/warp-masque
  systemctl stop warp-wireproxy 2>/dev/null || true
  systemctl disable warp-wireproxy 2>/dev/null || true
  rm -f /etc/systemd/system/trusttunnel.service
  rm -f /etc/systemd/system/warp-wireproxy.service
  systemctl daemon-reload
  rm -rf "$TT_DIR" "$WARP_DIR" "$CLIENT_DIR"
  rm -f /root/trusttunnel-clients-*.zip
  rm -f /usr/local/sbin/ttmenu
  rm -f /usr/local/sbin/trusttunnel-menu
  rm -f /usr/local/sbin/trusttunnel-status
  rm -f /usr/local/sbin/trusttunnel-cert-renew
  rm -f /etc/systemd/system/trusttunnel-cert-renew.service
  rm -f /etc/systemd/system/trusttunnel-cert-renew.timer
  systemctl disable --now trusttunnel-cert-renew.timer 2>/dev/null || true
  systemctl daemon-reload
  ufw delete allow "${endpoint_port}/tcp" 2>/dev/null || true
  ufw delete allow "${endpoint_port}/udp" 2>/dev/null || true
  echo "TrustTunnel и все варианты WARP удалены. SSH и fail2ban оставлены без изменений. Identity backup сохранён. Веб-панель остановлена; её отдельное удаление доступно в меню."
}

run_speedtest() {
  echo "=== Speedtest ==="
  echo "Direct public IP:"
  curl -4 -sS --max-time 10 https://ifconfig.me || true
  echo
  echo
  echo "WARP public IP:"
  curl -x socks5h://127.0.0.1:40000 -sS --max-time 12 https://ifconfig.me || echo "WARP SOCKS недоступен."
  echo
  echo
  if command -v speedtest-cli >/dev/null 2>&1; then
    speedtest-cli --secure --simple || true
  else
    echo "speedtest-cli не найден. Использую fallback download test через Cloudflare 100 MB."
    curl -L -o /dev/null -sS --max-time 60 -w 'download=%{speed_download} bytes/sec\n' 'https://speed.cloudflare.com/__down?bytes=104857600' || true
  fi
}

configure_cascade() {
  local addr
  ask_required CASCADE_SOCKS_ADDR "Адрес upstream SOCKS5 для каскада, например 127.0.0.1:1080 или proxy.example.com:1080: "
  addr="$CASCADE_SOCKS_ADDR"
  if ! printf '%s' "$addr" | grep -Eq '^[A-Za-z0-9_.:-]+:[0-9]{1,5}$'; then
    echo "Неверный формат SOCKS5 address: ${addr}" >&2
    exit 1
  fi
  switch_trusttunnel_forwarder socks5 "$addr"
  echo "TrustTunnel переключен на каскадный SOCKS5 upstream: ${addr}"
}

configure_routing() {
  ensure_admin_helper || return
  local choice cidr
  while true; do
    echo
    echo "=== Routing / access rules ==="
    echo "Это серверные access rules TrustTunnel: allow/deny по CIDR и client_random_prefix."
    echo "1) Показать rules.toml"
    echo "2) Добавить deny CIDR"
    echo "3) Сбросить rules.toml"
    echo "0) Назад"
    prompt_value "Выбери действие [1]: "
    choice="${REPLY_VALUE:-1}"
    case "$choice" in
      1)
        cat "$TT_DIR/rules.toml" 2>/dev/null || echo "rules.toml не найден."
        ;;
      2)
        assert_protection_unlocked || return
        ask_required cidr "CIDR для блокировки, например 1.2.3.4/32: "
        if ! printf '%s' "$cidr" | grep -Eq '^[0-9A-Fa-f:.]+/[0-9]{1,3}$'; then
          echo "Неверный CIDR: ${cidr}" >&2
          exit 1
        fi
        admin_call routing-rule-add "cidr=$cidr" decision=deny
        ;;
      3)
        assert_protection_unlocked || return
        confirm_action "rules.toml будет сброшен: все authenticated clients будут разрешены."
        admin_call routing-rule-reset confirm=CONFIRMED
        ;;
      0) return ;;
      *) echo "Нужно выбрать 0-3." ;;
    esac
  done
}

current_configured_ssh_port() {
  if [ -f /etc/ssh/sshd_config.d/99-trusttunnel-port.conf ]; then
    sed -nE 's/^[[:space:]]*Port[[:space:]]+([0-9]+).*/\1/p' /etc/ssh/sshd_config.d/99-trusttunnel-port.conf | tail -1
    return
  fi
  sed -nE 's/^[[:space:]]*Port[[:space:]]+([0-9]+).*/\1/p' /etc/ssh/sshd_config 2>/dev/null | tail -1 || true
}

change_endpoint_port() {
  local old_port new_port
  load_current_trusttunnel_context
  old_port="$ENDPOINT_PORT"
  ask_default new_port "Новый порт TrustTunnel" "$old_port"
  validate_port "Порт TrustTunnel" "$new_port"
  if [ "$new_port" = "$old_port" ]; then
    echo "Порт TrustTunnel уже ${old_port}."
    return
  fi
  cp "$TT_DIR/vpn.toml" "$TT_DIR/vpn.toml.backup.$(date +%Y%m%d%H%M%S)"
  sed -i -E "s/listen_address[[:space:]]*=[[:space:]]*\"[^:]+:[0-9]+\"/listen_address = \"0.0.0.0:${new_port}\"/" "$TT_DIR/vpn.toml"
  ufw allow "${new_port}/tcp" comment "TrustTunnel TCP" >/dev/null 2>&1 || true
  if [ "$ENABLE_QUIC" = "1" ]; then
    ufw allow "${new_port}/udp" comment "TrustTunnel QUIC" >/dev/null 2>&1 || true
    ufw delete allow "${old_port}/udp" >/dev/null 2>&1 || true
  fi
  ufw delete allow "${old_port}/tcp" >/dev/null 2>&1 || true
  ENDPOINT_PORT="$new_port"
  PRESERVE_CLIENT_CONFIGS=1
  write_clients
  systemctl restart trusttunnel
  echo "TrustTunnel порт изменен: ${old_port} -> ${new_port}. Клиентские TOML пересобраны в ${CLIENT_DIR}."
}

change_ssh_port_menu() {
  local old_port new_port
  old_port="$(current_configured_ssh_port)"
  old_port="${old_port:-$(detect_current_ssh_port)}"
  ask_default new_port "Новый SSH-порт" "${old_port:-49222}"
  validate_port "SSH-порт" "$new_port"
  if [ "$new_port" = "$old_port" ]; then
    echo "SSH-порт уже ${old_port}."
    return
  fi
  confirm_action "SSH будет переведен на порт ${new_port}. Новый порт будет открыт в UFW до перезапуска sshd. Старый порт ${old_port} останется открытым для безопасности."
  SSH_PORT="$new_port"
  CHANGE_SSH_PORT=1
  ufw allow "${new_port}/tcp" comment "SSH" >/dev/null 2>&1 || true
  configure_ssh_port
  if command -v fail2ban-client >/dev/null 2>&1; then
    ENABLE_FAIL2BAN=1
    configure_fail2ban || true
  fi
  echo "SSH-порт изменен на ${new_port}. Проверь новый вход перед закрытием старого порта ${old_port}."
}

manage_ports() {
  local choice
  while true; do
    echo
    echo "=== Смена портов ==="
    echo "1) Сменить порт TrustTunnel"
    echo "2) Сменить SSH-порт"
    echo "0) Назад"
    prompt_value "Выбери действие [1]: "
    choice="${REPLY_VALUE:-1}"
    case "$choice" in
      1) change_endpoint_port ;;
      2) change_ssh_port_menu ;;
      0) return ;;
      *) echo "Нужно выбрать 0-2." ;;
    esac
  done
}

manage_fail2ban() {
  local choice ip
  while true; do
    echo
    echo "=== fail2ban ==="
    echo "1) Статус sshd jail"
    echo "2) Включить/переустановить fail2ban для SSH"
    echo "3) Отключить fail2ban"
    echo "4) Разбанить IP"
    echo "0) Назад"
    prompt_value "Выбери действие [1]: "
    choice="${REPLY_VALUE:-1}"
    case "$choice" in
      1) fail2ban-client status sshd 2>/dev/null || systemctl --no-pager status fail2ban || true ;;
      2)
        ENABLE_FAIL2BAN=1
        SSH_PORT="$(current_configured_ssh_port)"
        SSH_PORT="${SSH_PORT:-$(detect_current_ssh_port)}"
        apt_update_retry || true
        apt_install_retry -y --no-install-recommends --no-upgrade fail2ban || true
        configure_fail2ban
        echo "fail2ban включен для SSH-порта ${SSH_PORT}."
        ;;
      3)
        confirm_action "fail2ban будет остановлен и отключен."
        systemctl disable --now fail2ban 2>/dev/null || true
        echo "fail2ban отключен."
        ;;
      4)
        ask_required ip "IP для разбана: "
        fail2ban-client set sshd unbanip "$ip" || true
        ;;
      0) return ;;
      *) echo "Нужно выбрать 0-4." ;;
    esac
  done
}

manage_ufw() {
  local choice port proto ssh_port endpoint_port quic
  while true; do
    echo
    echo "=== UFW firewall ==="
    echo "1) Статус"
    echo "2) Открыть порт"
    echo "3) Закрыть порт"
    echo "4) Пересобрать базовые правила SSH + TrustTunnel"
    echo "0) Назад"
    prompt_value "Выбери действие [1]: "
    choice="${REPLY_VALUE:-1}"
    case "$choice" in
      1) ufw status verbose ;;
      2)
        ask_required port "Порт: "
        validate_port "Порт" "$port"
        ask_default proto "Протокол tcp/udp" "tcp"
        ufw allow "${port}/${proto}" || true
        ;;
      3)
        ask_required port "Порт: "
        validate_port "Порт" "$port"
        ask_default proto "Протокол tcp/udp" "tcp"
        ufw delete allow "${port}/${proto}" || true
        ;;
      4)
        endpoint_port="$(current_endpoint_port)"
        quic="$(current_quic_enabled)"
        ssh_port="$(current_configured_ssh_port)"
        ssh_port="${ssh_port:-$(detect_current_ssh_port)}"
        confirm_action "UFW будет сброшен. Будут открыты SSH ${ssh_port}/tcp, TrustTunnel ${endpoint_port}/tcp и UDP при включенном QUIC."
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow "${ssh_port}/tcp" comment "SSH"
        ufw allow "${endpoint_port}/tcp" comment "TrustTunnel TCP"
        if [ "$quic" = "1" ]; then
          ufw allow "${endpoint_port}/udp" comment "TrustTunnel QUIC"
        fi
        ufw --force enable
        ufw status verbose
        ;;
      0) return ;;
      *) echo "Нужно выбрать 0-4." ;;
    esac
  done
}

load_panel_environment() {
  local env_key env_value
  [ -f /etc/trusttunnel-panel.env ] || return 0
  while IFS='=' read -r env_key env_value; do
    case "$env_key" in
      PANEL_BIND|PANEL_PORT|PANEL_USER|PANEL_PASSWORD|PANEL_TLS|PANEL_CERT|PANEL_KEY)
        printf -v "$env_key" '%s' "$env_value" ;;
    esac
  done < /etc/trusttunnel-panel.env
}

install_panel() {
  local panel_path env_file panel_mode ssh_port default_port default_mode old_port requested_panel_port requested_panel_mode
  requested_panel_port="${PANEL_PORT:-}"
  requested_panel_mode="${PANEL_ACCESS_MODE:-}"
  panel_path="/usr/local/sbin/trusttunnel-panel.py"
  env_file="/etc/trusttunnel-panel.env"
  default_port="$PANEL_PORT"
  default_mode="localhost"
  if [ -f "$env_file" ]; then
    load_panel_environment
    default_port="${PANEL_PORT:-$default_port}"
    if [ "${PANEL_TLS:-0}" = "1" ]; then
      default_mode="https"
    fi
  fi
  [ -n "$requested_panel_port" ] && PANEL_PORT="$requested_panel_port"
  [ -n "$requested_panel_mode" ] && PANEL_ACCESS_MODE="$requested_panel_mode"
  if [ -r /dev/tty ]; then
    prompt_value "Порт веб-панели [${default_port}]: "
    PANEL_PORT="${REPLY_VALUE:-$default_port}"
  else
    PANEL_PORT="${PANEL_PORT:-$default_port}"
  fi
  validate_port "Порт веб-панели" "$PANEL_PORT"
  if [ -n "${PANEL_ACCESS_MODE:-}" ]; then
    panel_mode="$PANEL_ACCESS_MODE"
  elif [ -r /dev/tty ]; then
    echo
    echo "Режим доступа к веб-панели:"
    echo "1) localhost - только через SSH-туннель, порт наружу не открывается"
    echo "2) HTTPS - публично на выбранном порту, порт откроется в UFW"
    prompt_value "Выбери режим [${default_mode}]: "
    case "${REPLY_VALUE:-$default_mode}" in
      2|https|HTTPS) panel_mode="https" ;;
      *) panel_mode="localhost" ;;
    esac
  else
    panel_mode="$default_mode"
  fi
  apt_update_retry || true
  apt_install_retry -y --no-install-recommends --no-upgrade python3 python3-tomli dnsutils curl qrencode
  local panel_candidate
  panel_candidate="$(mktemp)"
  if [ -n "${PANEL_SCRIPT_SOURCE:-}" ]; then
    python3 -c 'import os,stat,sys; s=os.stat(sys.argv[1]); assert s.st_uid==0 and not s.st_mode & 0o022 and stat.S_ISREG(s.st_mode), "Panel source must be root-owned and not writable by other users"' "$PANEL_SCRIPT_SOURCE"
    cp "$PANEL_SCRIPT_SOURCE" "$panel_candidate"
  else
    curl -fsSL -o "$panel_candidate" "$PANEL_SCRIPT_URL"
  fi
  python3 -m py_compile "$panel_candidate"
  install -m 0755 "$panel_candidate" "$panel_path"
  rm -f "$panel_candidate"
  old_port="$default_port"
  if [ -z "${PANEL_PASSWORD:-}" ]; then
    PANEL_PASSWORD="$(openssl rand -base64 18 | tr -d '=+/')"
  fi
  if [ "$panel_mode" = "https" ]; then
    if [ ! -f "$TT_DIR/certs/cert.pem" ] || [ ! -f "$TT_DIR/certs/key.pem" ]; then
      echo "Для HTTPS-панели не найден сертификат TrustTunnel в ${TT_DIR}/certs." >&2
      exit 1
    fi
    cat > "$env_file" <<EOF
PANEL_BIND=0.0.0.0
PANEL_PORT=${PANEL_PORT}
PANEL_USER=${PANEL_USER}
PANEL_PASSWORD=${PANEL_PASSWORD}
PANEL_TLS=1
PANEL_CERT=${TT_DIR}/certs/cert.pem
PANEL_KEY=${TT_DIR}/certs/key.pem
EOF
    ufw allow "${PANEL_PORT}/tcp" comment "TrustTunnel Panel HTTPS" >/dev/null 2>&1 || true
  else
    cat > "$env_file" <<EOF
PANEL_BIND=127.0.0.1
PANEL_PORT=${PANEL_PORT}
PANEL_USER=${PANEL_USER}
PANEL_PASSWORD=${PANEL_PASSWORD}
PANEL_TLS=0
PANEL_CERT=${TT_DIR}/certs/cert.pem
PANEL_KEY=${TT_DIR}/certs/key.pem
EOF
    ufw delete allow "${old_port}/tcp" >/dev/null 2>&1 || true
  fi
  chmod 0600 "$env_file"
  cat > /etc/systemd/system/trusttunnel-panel.service <<EOF
[Unit]
Description=TrustTunnel web panel
After=network-online.target trusttunnel.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${env_file}
ExecStart=/usr/bin/python3 ${panel_path}
Restart=always
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectControlGroups=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now trusttunnel-panel
  systemctl restart trusttunnel-panel
  ssh_port="$(current_configured_ssh_port)"
  ssh_port="${ssh_port:-$(detect_current_ssh_port)}"
  echo "Веб-панель установлена."
  echo "Логин: ${PANEL_USER}"
  echo "Пароль: ${PANEL_PASSWORD}"
  if [ "$panel_mode" = "https" ]; then
    echo "URL: https://$(current_domain):${PANEL_PORT}"
  else
    echo "URL: http://127.0.0.1:${PANEL_PORT}"
    echo "SSH-туннель: ssh -L ${PANEL_PORT}:127.0.0.1:${PANEL_PORT} -p ${ssh_port} root@SERVER_IP"
  fi
}
configure_panel_access() {
  if [ ! -f /etc/systemd/system/trusttunnel-panel.service ]; then
    echo "Веб-панель ещё не установлена. Сначала выбери пункт 17."
    return
  fi
  echo "Настройка доступа к веб-панели. VPN, пользователи и сертификат TrustTunnel не изменяются."
  install_panel
}
show_panel_credentials() {
  local panel_bind panel_port panel_user panel_password panel_tls panel_domain
  if [ ! -f /etc/trusttunnel-panel.env ]; then
    echo "Настройки веб-панели не найдены."
    return
  fi
  load_panel_environment
  panel_bind="${PANEL_BIND:-127.0.0.1}"
  panel_port="${PANEL_PORT:-8088}"
  panel_user="${PANEL_USER:-admin}"
  panel_password="${PANEL_PASSWORD:-}"
  panel_tls="${PANEL_TLS:-0}"
  echo "Логин: ${panel_user}"
  echo "Пароль: ${panel_password}"
  if [ "$panel_tls" = "1" ]; then
    panel_domain="$(current_domain)"
    echo "URL: https://${panel_domain}:${panel_port}"
  else
    echo "URL: http://127.0.0.1:${panel_port}"
    echo "Доступ только через SSH-туннель."
  fi
}

change_panel_credentials() {
  local panel_user panel_password
  prompt_value "Новый логин панели: "
  panel_user="$REPLY_VALUE"
  if ! [[ "$panel_user" =~ ^[A-Za-z0-9_.-]{1,64}$ ]]; then
    echo "Логин: только буквы, цифры, точка, _ и -; до 64 символов."
    return
  fi
  prompt_value "Новый пароль панели (минимум 12 символов): "
  panel_password="$REPLY_VALUE"
  if ! [[ "$panel_password" =~ ^[A-Za-z0-9._~!@%+,:/-]{12,128}$ ]]; then
    echo "Пароль: 12–128 букв, цифр или . _ ~ ! @ % + , : / -; без пробелов и кавычек."
    return
  fi
  ensure_admin_helper || return
  printf '{"username":"%s","password":"%s"}' "$panel_user" "$panel_password" | python3 "$ADMIN_HELPER_PATH" --admin panel-credentials
  echo "Данные входа веб-панели обновлены."
}

manage_panel_service() {
  local choice
  if [ ! -f /etc/systemd/system/trusttunnel-panel.service ]; then
    echo "Веб-панель ещё не установлена. Сначала выбери пункт 17."
    return
  fi
  while true; do
    echo
    echo "Веб-панель: $(systemctl is-active trusttunnel-panel 2>/dev/null || true)"
    echo "1) Включить и запустить"
    echo "2) Отключить и остановить"
    echo "3) Показать статус и последние логи"
    echo "4) Показать данные для входа"
    echo "5) Сменить логин и пароль"
    echo "0) Назад"
    prompt_value "Выбери действие [3]: "
    choice="${REPLY_VALUE:-3}"
    case "$choice" in
      1) ensure_admin_helper; admin_call panel-service enabled=1 confirm=CONFIRMED ;;
      2) ensure_admin_helper; admin_call panel-service enabled=0 confirm=CONFIRMED ;;
      3) systemctl --no-pager --full status trusttunnel-panel || true; journalctl -u trusttunnel-panel -n 30 --no-pager || true ;;
      4) show_panel_credentials ;;
      5) change_panel_credentials ;;
      0) return ;;
      *) echo "Нужно выбрать 0-5." ;;
    esac
  done
}
remove_panel() {
  confirm_action "Веб-панель TrustTunnel будет остановлена и удалена."
  systemctl disable --now trusttunnel-panel 2>/dev/null || true
  rm -f /etc/systemd/system/trusttunnel-panel.service
  rm -f /usr/local/sbin/trusttunnel-panel.py
  rm -f /etc/trusttunnel-panel.env
  systemctl daemon-reload
  echo "Веб-панель удалена."
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
  ss -lntup | grep -E ":(${endpoint_port}|40000|40001|22|49222)\b|sshd|trusttunnel|wireproxy" || true
  echo
  echo "UFW:"
  ufw status 2>/dev/null || true
}

load_client_network_settings() {
  local key value item first
  CLIENT_DNS_UPSTREAMS="94.140.14.14,94.140.15.15"
  CLIENT_TLS_PROFILE="chrome"
  CLIENT_ANTI_DPI_VALUE="0"
  CLIENT_POST_QUANTUM_VALUE="0"
  if [ -f "$CLIENT_SETTINGS_FILE" ]; then
    while IFS='=' read -r key value; do
      case "$key" in
        DNS_UPSTREAMS) CLIENT_DNS_UPSTREAMS="$value" ;;
        TLS_PROFILE) CLIENT_TLS_PROFILE="$value" ;;
        CLIENT_ANTI_DPI) CLIENT_ANTI_DPI_VALUE="$value" ;;
        POST_QUANTUM) CLIENT_POST_QUANTUM_VALUE="$value" ;;
      esac
    done < "$CLIENT_SETTINGS_FILE"
  fi
  validate_client_dns_upstreams "$CLIENT_DNS_UPSTREAMS" || CLIENT_DNS_UPSTREAMS="94.140.14.14,94.140.15.15"
  case "$CLIENT_TLS_PROFILE" in chrome|safari|firefox|okhttp|openssl|default) ;; *) CLIENT_TLS_PROFILE="chrome" ;; esac
  case "$CLIENT_ANTI_DPI_VALUE" in 1) CLIENT_ANTI_DPI=true ;; *) CLIENT_ANTI_DPI=false; CLIENT_ANTI_DPI_VALUE=0 ;; esac
  case "$CLIENT_POST_QUANTUM_VALUE" in 1) CLIENT_POST_QUANTUM=true ;; *) CLIENT_POST_QUANTUM=false; CLIENT_POST_QUANTUM_VALUE=0 ;; esac
  CLIENT_DNS_TOML="["
  first=1
  IFS=',' read -r -a _client_dns_items <<< "$CLIENT_DNS_UPSTREAMS"
  for item in "${_client_dns_items[@]}"; do
    item="$(printf '%s' "$item" | tr -d '[:space:]')"
    [ -z "$item" ] && continue
    [ "$first" = 1 ] || CLIENT_DNS_TOML+=", "
    CLIENT_DNS_TOML+="\"${item}\""
    first=0
  done
  CLIENT_DNS_TOML+="]"
}

validate_client_dns_upstreams() {
  local value="$1" item count=0
  IFS=',' read -r -a _dns_values <<< "$value"
  for item in "${_dns_values[@]}"; do
    item="$(printf '%s' "$item" | tr -d '[:space:]')"
    [ -z "$item" ] && continue
    count=$((count + 1))
    [[ "$item" =~ ^[A-Za-z0-9_.:/?-]{1,253}$ ]] || return 1
  done
  [ "$count" -ge 1 ] && [ "$count" -le 4 ]
}

save_client_network_settings() {
  validate_client_dns_upstreams "$CLIENT_DNS_UPSTREAMS" || { echo "DNS: от 1 до 4 адресов DNS/DoH/DoT/DoQ через запятую." >&2; return 1; }
  cat > "$CLIENT_SETTINGS_FILE" <<EOF
DNS_UPSTREAMS=${CLIENT_DNS_UPSTREAMS}
CLIENT_ANTI_DPI=${CLIENT_ANTI_DPI_VALUE}
TLS_PROFILE=${CLIENT_TLS_PROFILE}
POST_QUANTUM=${CLIENT_POST_QUANTUM_VALUE}
EOF
  chmod 0600 "$CLIENT_SETTINGS_FILE"
}

write_current_credentials_from_pairs() {
  local pairs="$1" user pass
  cat > "$TT_DIR/credentials.toml" <<'EOF'
# Managed TrustTunnel users. One user/password per client.
EOF
  while read -r user pass; do
    [ -z "$user" ] && continue
    if ! [[ "$user" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || ! [[ "$pass" =~ ^[A-Za-z0-9._-]{12,128}$ ]]; then
      echo "Некорректные данные клиента: ${user}" >&2
      return 1
    fi
    cat >> "$TT_DIR/credentials.toml" <<EOF

[[client]]
username = "${user}"
password = "${pass}"
EOF
  done < "$pairs"
  chmod 0600 "$TT_DIR/credentials.toml"
}

rebuild_current_client_exports() {
  load_current_trusttunnel_context
  write_clients
  systemctl restart trusttunnel
  echo "Клиентские TOML и ZIP пересобраны: /root/trusttunnel-clients-$(current_domain).zip"
}

manage_clients_legacy() {
  local choice user pass pairs updated link
  if [ ! -f "$TT_DIR/credentials.toml" ]; then
    echo "TrustTunnel ещё не установлен."
    return
  fi
  while true; do
    echo
    echo "=== Клиенты TrustTunnel ==="
    echo "1) Показать клиентов и пароли"
    echo "2) Добавить клиента"
    echo "3) Сменить пароль клиента"
    echo "4) Удалить клиента"
    echo "5) Пересобрать TOML и ZIP из текущих данных"
    echo "6) Показать tt:// ссылку клиента"
    echo "0) Назад"
    prompt_value "Выбери действие [1]: "
    choice="${REPLY_VALUE:-1}"
    case "$choice" in
      1) list_existing_clients "$TT_DIR/credentials.toml" | nl -ba ;;
      2)
        prompt_value "Логин нового клиента: "
        user="$REPLY_VALUE"
        if ! [[ "$user" =~ ^[A-Za-z0-9_.-]{1,64}$ ]]; then echo "Логин: буквы, цифры, точка, _ и -; до 64 символов."; continue; fi
        pairs="$(mktemp)"; list_existing_clients "$TT_DIR/credentials.toml" > "$pairs"
        if awk -v target="$user" '$1 == target { found=1 } END { exit(found ? 0 : 1) }' "$pairs"; then echo "Такой клиент уже существует."; rm -f "$pairs"; continue; fi
        prompt_value "Пароль (пусто = сгенерировать): "
        pass="${REPLY_VALUE:-$(random_password)}"
        if ! [[ "$pass" =~ ^[A-Za-z0-9._-]{12,128}$ ]]; then echo "Пароль: 12-128 символов, только буквы, цифры, точка, _ и -."; rm -f "$pairs"; continue; fi
        printf '%s %s\n' "$user" "$pass" >> "$pairs"
        write_current_credentials_from_pairs "$pairs" && rebuild_current_client_exports
        rm -f "$pairs"
        ;;
      3)
        prompt_value "Логин клиента: "; user="$REPLY_VALUE"
        pairs="$(mktemp)"; list_existing_clients "$TT_DIR/credentials.toml" > "$pairs"
        if ! awk -v target="$user" '$1 == target { found=1 } END { exit(found ? 0 : 1) }' "$pairs"; then echo "Клиент не найден."; rm -f "$pairs"; continue; fi
        prompt_value "Новый пароль (пусто = сгенерировать): "; pass="${REPLY_VALUE:-$(random_password)}"
        if ! [[ "$pass" =~ ^[A-Za-z0-9._-]{12,128}$ ]]; then echo "Некорректный пароль."; rm -f "$pairs"; continue; fi
        updated="$(mktemp)"; awk -v target="$user" -v replacement="$pass" '{ if ($1 == target) print $1, replacement; else print $0 }' "$pairs" > "$updated"
        write_current_credentials_from_pairs "$updated" && rebuild_current_client_exports
        rm -f "$pairs" "$updated"
        ;;
      4)
        prompt_value "Логин клиента для удаления: "; user="$REPLY_VALUE"
        pairs="$(mktemp)"; list_existing_clients "$TT_DIR/credentials.toml" > "$pairs"
        if ! awk -v target="$user" '$1 == target { found=1 } END { exit(found ? 0 : 1) }' "$pairs"; then echo "Клиент не найден."; rm -f "$pairs"; continue; fi
        if [ "$(wc -l < "$pairs" | tr -d '[:space:]')" -le 1 ]; then echo "Нельзя удалить последнего клиента."; rm -f "$pairs"; continue; fi
        confirm_action "Будет удалён клиент ${user} и его профили."
        updated="$(mktemp)"; awk -v target="$user" '$1 != target' "$pairs" > "$updated"
        write_current_credentials_from_pairs "$updated" && rebuild_current_client_exports
        rm -f "$pairs" "$updated"
        ;;
      5) rebuild_current_client_exports ;;
      6)
        prompt_value "Логин клиента: "; user="$REPLY_VALUE"
        if ! existing_password_for_user "$user" "$TT_DIR/credentials.toml" >/dev/null; then echo "Клиент не найден."; continue; fi
        load_current_trusttunnel_context
        ensure_admin_helper || return
        admin_call client-link "username=$user"
        ;;
      0) return ;;
      *) echo "Нужно выбрать 0-6." ;;
    esac
  done
}

ensure_admin_helper() {
  if ! python3 -c 'import tomllib' 2>/dev/null && ! python3 -c 'import tomli' 2>/dev/null; then
    apt_install_retry -y --no-install-recommends python3 python3-tomli || return 1
  fi
  ADMIN_HELPER_PATH="${ADMIN_HELPER_PATH:-/usr/local/sbin/trusttunnel-panel.py}"
  if [ -f "$ADMIN_HELPER_PATH" ] && grep -q "^ADMIN_VERSION = '2026.10.23'" "$ADMIN_HELPER_PATH"; then return; fi
  if [ -f /usr/local/lib/trusttunnel/admin.py ] && grep -q "^ADMIN_VERSION = '2026.10.23'" /usr/local/lib/trusttunnel/admin.py; then
    ADMIN_HELPER_PATH=/usr/local/lib/trusttunnel/admin.py
    return
  fi
  local candidate
  candidate="$(mktemp)"
  if ! curl -fsSL "$PANEL_SCRIPT_URL" -o "$candidate"; then rm -f "$candidate"; return 1; fi
  if ! python3 -m py_compile "$candidate" || ! grep -q "^ADMIN_VERSION = '2026.10.23'" "$candidate"; then
    rm -f "$candidate"
    echo "Требуется общий backend панели 2026.10.23. Обновите панель; старый backend не будет менять профили." >&2
    return 1
  fi
  mkdir -p /usr/local/lib/trusttunnel
  ADMIN_HELPER_PATH=/usr/local/lib/trusttunnel/admin.py
  install -m 0700 "$candidate" "$ADMIN_HELPER_PATH"
  rm -f "$candidate"
}

admin_call() {
  if python3 "$ADMIN_HELPER_PATH" --admin "$@" </dev/null; then return 0; fi
  echo "Операция не выполнена. Причина указана выше." >&2
  return 1
}

manage_clients() {
  ensure_admin_helper || return
  local choice user prefix count note
  while true; do
    echo "=== Клиенты (общие операции с панелью) ==="
    echo "1) Список и состояние"
    echo "2) Добавить клиента со случайным паролем"
    echo "3) Сменить пароль (случайный)"
    echo "4) Удалить клиента"
    echo "5) Пересобрать TOML и ZIP"
    echo "6) Показать tt:// ссылку"
    echo "7) Отключить клиента с сохранением пароля"
    echo "8) Включить клиента с прежним паролем"
    echo "9) Изменить заметку"
    echo "10) Создать группу клиентов"
    echo "11) Лимиты соединений HTTP/2 и QUIC (не привязка к устройству)"
    echo "12) Статистика: online, последний онлайн и накопленный трафик"
    echo "13) Антишаринг: общий лимит трафика и срок"
    echo "14) Убрать квоту и срок"
    echo "15) Одноразовое HTTPS-приглашение"
    echo "16) Отозвать неиспользованные приглашения"
    echo "17) Обновить сетевые параметры выбранного профиля"
    echo "18) Диагностика клиента (без секретов)"
    echo "0) Назад"
    prompt_value "Действие [0]: "; choice="${REPLY_VALUE:-0}"
    case "$choice" in
      0) return ;;
      1) admin_call client-list ;;
      12) admin_call guard-status ;;
      13)
        prompt_value "Логин клиента: "; user="$REPLY_VALUE"
        local quota expiry automatic ack
        ask_default quota "Общая квота ГиБ (0: без лимита; не месячная)" "0"
        prompt_value "Действует до UTC, ГГГГ-ММ-ДДTЧЧ:ММ (пусто: бессрочно): "; expiry="$REPLY_VALUE"
        ask_yes_no automatic "Автоматически отзывать доступ по квоте/сроку" 0
        ack=0
        if [ "$automatic" = 1 ]; then ask_yes_no ack "Допускаю краткий перезапуск VPN при автоотзыве" 0; fi
        confirm_action "Сохранить политику? Квота проверяется каждые 15 с при работающей панели; последний активный клиент не отключается."
        admin_call guard-save "username=$user" "quota_gib=$quota" "expires=$expiry" "auto_suspend=$automatic" "disconnect_ack=$ack" confirm=CONFIRMED ;;
      14|15|16|17|18)
        prompt_value "Логин клиента: "; user="$REPLY_VALUE"
        case "$choice" in
          14) confirm_action "Снять срок и квоту (не включает отключённого клиента)."; admin_call guard-remove "username=$user" confirm=CONFIRMED ;;
          15)
            local minutes protocol kind
            ask_default minutes "Срок приглашения, минут (1–1440)" "15"
            ask_default protocol "Протокол http2/http3" "http2"
            ask_default kind "Профиль static/protected/tls-auth" "static"
            confirm_action "Создать одноразовую выдачу? После получения сам профиль остаётся копируемым."
            admin_call enrollment-issue "username=$user" "minutes=$minutes" "protocol=$protocol" "kind=$kind" confirm=CONFIRMED ;;
          16) confirm_action "Отозвать непогашенные приглашения?"; admin_call enrollment-revoke "username=$user" confirm=CONFIRMED ;;
          17) confirm_action "Обновить DNS/AntiDPI/TLS профиль выбранного клиента. Ключи и SNI сохраняются, нужен повторный импорт."; admin_call client-refresh-network "username=$user" confirm=CONFIRMED ;;
          18) admin_call diagnostics-client "username=$user" ;;
        esac ;;
      5) confirm_action "Будут пересобраны клиентские профили."; admin_call client-rebuild ;;
      10)
        prompt_value "Префикс [client]: "; prefix="${REPLY_VALUE:-client}"
        prompt_value "Количество [5]: "; count="${REPLY_VALUE:-5}"
        admin_call client-batch "prefix=$prefix" "count=$count" ;;
      11)
        prompt_value "Логин клиента: "; user="$REPLY_VALUE"
        prompt_value "Лимит HTTP/2 (пусто: по умолчанию): "; local h2="$REPLY_VALUE"
        prompt_value "Лимит QUIC (пусто: по умолчанию): "; local h3="$REPLY_VALUE"
        admin_call client-limits "username=$user" "max_http2_conns=$h2" "max_http3_conns=$h3" ;;
      2|3|4|6|7|8|9)
        prompt_value "Логин клиента: "; user="$REPLY_VALUE"
        case "$choice" in
          2) admin_call client-add "username=$user" ;;
          3) confirm_action "Будет изменён пароль клиента."; admin_call client-password "username=$user" ;;
          4) confirm_action "Клиент будет удалён."; admin_call client-delete "username=$user" ;;
          6)
            prompt_value "Протокол http2 / http3 [http2]: "; local protocol="${REPLY_VALUE:-http2}"
            admin_call client-link "username=$user" "protocol=$protocol" ;;
          7) confirm_action "Доступ клиента будет отключён. TrustTunnel переподключит клиентов."; admin_call client-disable "username=$user" ;;
          8) admin_call client-enable "username=$user" ;;
          9) prompt_value "Заметка: "; note="$REPLY_VALUE"; admin_call client-note "username=$user" "note=$note" ;;
        esac ;;
      *) echo "Выберите 0–18." ;;
    esac
  done
}

manage_admin() {
  ensure_admin_helper || return
  local choice value second third
  while true; do
    echo "=== Расширенное управление (как в веб-панели) ==="
    echo "1) Мониторинг ресурсов и трафика"
    echo "2) Журнал сервиса"
    echo "3) Аудит действий"
    echo "4) UFW, fail2ban и конфигурация SSH"
    echo "5) Забанить IP в SSH jail"
    echo "6) Разбанить IP"
    echo "7) Настроить fail2ban: попытки, окно, время бана"
    echo "8) Открыть порт UFW"
    echo "9) Удалить разрешение порта UFW"
    echo "10) Исходящий маршрут Direct / WARP / SOCKS5"
    echo "11) Диагностика маршрута"
    echo "12) Добавить правило доступа allow / deny по CIDR"
    echo "13) Посмотреть и удалить правило доступа"
    echo "14) Сохранить DNS для будущих профилей"
    echo "15) Проверить DNS с сервера"
    echo "16) Применить DNS к TOML"
    echo "17) Сводка безопасности сервера"
    echo "18) Слушающие порты и процессы"
    echo "19) Журнал входов SSH"
    echo "20) Доверенные IP (исключения fail2ban SSH)"
    echo "21) Добавить доверенный IP / CIDR"
    echo "22) Удалить доверенный IP / CIDR"
    echo "23) Перезапустить TrustTunnel"
    echo "24) Перезагрузить VPS через 60 секунд"
    echo "25) Отменить запланированную перезагрузку"
    echo "0) Назад"
    prompt_value "Действие [0]: "; choice="${REPLY_VALUE:-0}"
    case "$choice" in
      0) return ;;
      1) admin_call monitor ;;
      2) prompt_value "Сервис [trusttunnel]: "; admin_call logs "unit=${REPLY_VALUE:-trusttunnel}" ;;
      3) admin_call audit ;;
      4) admin_call security-status ;;
      5|6) prompt_value "IP: "; value="$REPLY_VALUE"; if [ "$choice" = 5 ]; then admin_call security-ban "ip=$value"; else admin_call security-unban "ip=$value"; fi ;;
      7)
        prompt_value "Попытки [5]: "; value="${REPLY_VALUE:-5}"
        prompt_value "Окно, секунд [600]: "; second="${REPLY_VALUE:-600}"
        prompt_value "Бан, секунд [3600]: "; third="${REPLY_VALUE:-3600}"
        admin_call security-fail2ban "retry=$value" "findtime=$second" "bantime=$third" ;;
      8|9)
        prompt_value "Порт: "; value="$REPLY_VALUE"
        prompt_value "Протокол [tcp]: "; second="${REPLY_VALUE:-tcp}"
        prompt_value "Источник IP / CIDR (пусто = любой): "; third="$REPLY_VALUE"
        if [ "$choice" = 8 ]; then admin_call security-open "port=$value" "proto=$second" "source=$third"; else admin_call security-close "port=$value" "proto=$second" "source=$third"; fi ;;
      10)
        admin_call routing-current
        prompt_value "Режим direct / warp / masque / interface / interface-masque / socks5 (пусто: не менять): "; value="$REPLY_VALUE"; second=""
        if [ "$value" = socks5 ]; then prompt_value "SOCKS5 host:port: "; second="$REPLY_VALUE"; fi
        confirm_action "Будет изменён исходящий маршрут и перезапущен TrustTunnel."
        [ -n "$value" ] || continue
        admin_call routing-switch "mode=$value" "address=$second" ;;
      11) admin_call routing-check ;;
      12)
        prompt_value "CIDR: "; value="$REPLY_VALUE"
        prompt_value "Действие (allow / deny): "; second="$REPLY_VALUE"
        admin_call routing-rule-add "cidr=$value" "decision=$second" ;;
      13)
        cat "$TT_DIR/rules.toml"
        prompt_value "Номер правила для удаления (пусто = назад): "; value="$REPLY_VALUE"
        if [ -n "$value" ]; then confirm_action "Правило будет удалено."; admin_call routing-rule-delete "index=$value"; fi ;;
      14) prompt_value "DNS через запятую: "; admin_call dns-save "dns=$REPLY_VALUE" ;;
      15) admin_call dns-check ;;
      16) confirm_action "Клиентские TOML будут пересобраны."; admin_call dns-apply ;;
      17) admin_call security-audit ;;
      18) admin_call security-listeners ;;
      19) admin_call security-logins ;;
      20) admin_call security-ignore-list ;;
      21|22)
        prompt_value "IP / CIDR: "; value="$REPLY_VALUE"
        if [ "$choice" = 21 ]; then admin_call security-ignore-add "ip=$value"; else admin_call security-ignore-remove "ip=$value"; fi ;;
      23) confirm_action "TrustTunnel будет перезапущен, VPN кратковременно отключится."; admin_call system-restart ;;
      24) prompt_value "Перезагрузка отключит VPN, SSH и панель. Введите REBOOT: "; admin_call system-reboot "confirm=$REPLY_VALUE" ;;
      25) admin_call system-reboot-cancel ;;
      *) echo "Выберите 0–25." ;;
    esac
  done
}

manage_client_network_settings() {
  local choice value
  if [ ! -f "$TT_DIR/credentials.toml" ]; then echo "TrustTunnel ещё не установлен."; return; fi
  while true; do
    load_client_network_settings
    echo
    echo "=== Настройки экспортируемых TOML ==="
    echo "DNS upstream: ${CLIENT_DNS_UPSTREAMS}"
    echo "TLS profile: ${CLIENT_TLS_PROFILE}"
    echo "AntiDPI: ${CLIENT_ANTI_DPI}"
    echo "Post-quantum TLS: ${CLIENT_POST_QUANTUM}"
    echo "1) Изменить DNS upstream"
    echo "2) Изменить TLS profile"
    echo "3) Включить / отключить AntiDPI"
    echo "4) Включить / отключить post-quantum TLS"
    echo "5) Применить к TOML всех клиентов"
    echo "0) Назад"
    prompt_value "Выбери действие [0]: "
    choice="${REPLY_VALUE:-0}"
    case "$choice" in
      1)
        prompt_value "DNS через запятую (1-4 адреса): "; value="$REPLY_VALUE"
        if ! validate_client_dns_upstreams "$value"; then echo "Некорректные DNS upstream."; continue; fi
        CLIENT_DNS_UPSTREAMS="$value"; save_client_network_settings && echo "Сохранено. Для пересборки TOML выбери пункт 5." ;;
      2)
        echo "Допустимо: chrome, safari, firefox, okhttp, openssl, default"
        prompt_value "TLS profile: "; value="$REPLY_VALUE"
        case "$value" in chrome|safari|firefox|okhttp|openssl|default) CLIENT_TLS_PROFILE="$value"; save_client_network_settings && echo "Сохранено. Для пересборки TOML выбери пункт 5." ;; *) echo "Некорректный TLS profile." ;; esac
        ;;
      3)
        [ "$CLIENT_ANTI_DPI_VALUE" = 1 ] && CLIENT_ANTI_DPI_VALUE=0 || CLIENT_ANTI_DPI_VALUE=1
        save_client_network_settings && echo "AntiDPI сохранён. Для пересборки TOML выбери пункт 5."
        ;;
      4)
        [ "$CLIENT_POST_QUANTUM_VALUE" = 1 ] && CLIENT_POST_QUANTUM_VALUE=0 || CLIENT_POST_QUANTUM_VALUE=1
        save_client_network_settings && echo "Post-quantum TLS сохранён. Для пересборки TOML выбери пункт 5."
        ;;
      5)
        echo "Будут пересобраны TOML и ZIP, но сертификат, пользователи и пароли не изменятся."
        confirm_action "Применить настройки к экспортируемым TOML всех клиентов."
        rebuild_current_client_exports
        ;;
      0) return ;;
      *) echo "Нужно выбрать 0-5." ;;
    esac
  done
}

show_system_monitoring() {
  echo "=== Мониторинг системы ==="
  uptime || true
  echo
  free -h || true
  echo
  df -h / || true
  echo
  echo "Трафик сетевых интерфейсов:"
  awk -F'[: ]+' 'NR > 2 && $1 != "lo" { printf "%s: RX %s bytes, TX %s bytes\\n", $1, $3, $11 }' /proc/net/dev 2>/dev/null || true
}

run_diagnostics() {
  local domain endpoint_port
  domain="$(current_domain)"; endpoint_port="$(current_endpoint_port)"
  echo "=== Диагностика ==="
  echo "Домен: ${domain}"
  echo "Порт endpoint: ${endpoint_port}"
  echo "TrustTunnel: $(systemctl is-active trusttunnel 2>/dev/null || true)"
  echo "WARP: $(systemctl is-active warp-wireproxy 2>/dev/null || true)"
  echo
  echo "DNS домена:"; getent ahosts "$domain" 2>/dev/null || true
  echo
  echo "Слушающие порты:"; ss -lntup | grep -E ":(${endpoint_port}|40000|40001)\\b|trusttunnel|wireproxy" || true
  echo
  echo "Сертификат:"; openssl x509 -in "$TT_DIR/certs/cert.pem" -noout -dates -issuer 2>/dev/null || true
  echo
  check_warp
}

configure_maintenance_timer() {
  local choice
  while true; do
    echo
    echo "=== Ежедневная проверка сервисов ==="
    echo "1) Включить"
    echo "2) Отключить"
    echo "3) Показать статус"
    echo "0) Назад"
    prompt_value "Выбери действие [3]: "; choice="${REPLY_VALUE:-3}"
    case "$choice" in
      1)
        cat > "$PANEL_MAINTENANCE_SERVICE" <<'EOF'
[Unit]
Description=TrustTunnel daily maintenance

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'systemctl is-active --quiet trusttunnel || systemctl restart trusttunnel; systemctl is-active --quiet warp-wireproxy || true'
EOF
        cat > "$PANEL_MAINTENANCE_TIMER" <<'EOF'
[Unit]
Description=TrustTunnel daily maintenance timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload
        systemctl enable --now trusttunnel-maintenance.timer
        echo "Ежедневная проверка включена."
        ;;
      2) systemctl disable --now trusttunnel-maintenance.timer 2>/dev/null || true; echo "Ежедневная проверка отключена." ;;
      3) systemctl list-timers --all trusttunnel-maintenance.timer || true ;;
      0) return ;;
      *) echo "Нужно выбрать 0-3." ;;
    esac
  done
}

configure_telegram_notifications() {
  local token chat_id response
  echo "Telegram используется только для тестового сообщения. Автоматические уведомления не включаются без отдельной настройки."
  prompt_value "Bot token: "; token="$REPLY_VALUE"
  prompt_value "Chat ID: "; chat_id="$REPLY_VALUE"
  if [ -z "$token" ] || [ -z "$chat_id" ] || [[ "$token" == *$'\n'* ]] || [[ "$chat_id" == *$'\n'* ]]; then echo "Нужны Bot token и Chat ID."; return; fi
  cat > "$PANEL_TELEGRAM_ENV" <<EOF
TELEGRAM_BOT_TOKEN=${token}
TELEGRAM_CHAT_ID=${chat_id}
EOF
  chmod 0600 "$PANEL_TELEGRAM_ENV"
  response="$(curl -fsS --max-time 15 -X POST "https://api.telegram.org/bot${token}/sendMessage" -d "chat_id=${chat_id}" --data-urlencode "text=TrustTunnel: Telegram notifications are connected." 2>&1 || true)"
  if printf '%s' "$response" | grep -q '"ok":true'; then echo "Тестовое сообщение отправлено."; else echo "Данные сохранены, но тестовое сообщение не подтверждено Telegram."; fi
}

manage_system_tools() {
  local choice service
  while true; do
    echo
    echo "=== Система, диагностика и журнал ==="
    echo "1) Мониторинг CPU/RAM/диска/трафика"
    echo "2) Диагностика TrustTunnel и WARP"
    echo "3) Последние логи сервисов"
    echo "4) Обновить пакеты VPS"
    echo "5) Ежедневная проверка сервисов"
    echo "6) Настроить Telegram для тестового сообщения"
    echo "0) Назад"
    prompt_value "Выбери действие [1]: "; choice="${REPLY_VALUE:-1}"
    case "$choice" in
      1) show_system_monitoring ;;
      2) run_diagnostics ;;
      3)
        prompt_value "Сервис: trusttunnel, warp, fail2ban, panel [trusttunnel]: "; service="${REPLY_VALUE:-trusttunnel}"
        case "$service" in trusttunnel) service=trusttunnel ;; warp) service=warp-wireproxy ;; fail2ban) service=fail2ban ;; panel) service=trusttunnel-panel ;; *) echo "Неизвестный сервис."; continue ;; esac
        journalctl -u "$service" -n 120 --no-pager || true
        ;;
      4) confirm_action "Будут обновлены пакеты VPS через apt-get."; apt_update_retry && apt-get -o Acquire::Retries=3 upgrade -y || true ;;
      5) configure_maintenance_timer ;;
      6) configure_telegram_notifications ;;
      0) return ;;
      *) echo "Нужно выбрать 0-6." ;;
    esac
  done
}
write_tools() {
  local installed_installer="/usr/local/lib/trusttunnel/install-trusttunnel-warp.sh"
  mkdir -p /usr/local/lib/trusttunnel
  if [ "$(readlink -f "${BASH_SOURCE[0]}")" != "$installed_installer" ]; then
    install -m 0755 "${BASH_SOURCE[0]}" "$installed_installer"
  fi
  # Older installations used ttmenu -> trusttunnel-menu. Do not follow it
  # while replacing the two commands, which would create a recursive wrapper.
  for command_path in /usr/local/sbin/ttmenu /usr/local/sbin/trusttunnel-menu /usr/local/sbin/trusttunnel-status; do
    if [ -L "$command_path" ]; then rm -f "$command_path"; fi
  done
  cat > /usr/local/sbin/ttmenu <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_URL="https://raw.githubusercontent.com/Dmitry1244/trusttunnel-auto-installer/main/install-trusttunnel-warp.sh"
INSTALLED="/usr/local/lib/trusttunnel/install-trusttunnel-warp.sh"
if [ "${1:-}" = "--update" ] || [ ! -s "$INSTALLED" ]; then
  mkdir -p /usr/local/lib/trusttunnel
  umask 077
  TMP_SCRIPT="$(mktemp /usr/local/lib/trusttunnel/.installer-XXXXXX)"
  trap 'rm -f "$TMP_SCRIPT"' EXIT
  curl -fsSL --max-time 45 -o "$TMP_SCRIPT" "${SCRIPT_URL}?$(date +%s)"
  bash -n "$TMP_SCRIPT"
  chmod 0755 "$TMP_SCRIPT"
  mv -f "$TMP_SCRIPT" "$INSTALLED"
  if [ "${1:-}" = "--update" ]; then shift; fi
fi
exec bash "$INSTALLED" "$@"
EOF
  chmod 0755 /usr/local/sbin/ttmenu

  cat > /usr/local/sbin/trusttunnel-menu <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec /usr/local/sbin/ttmenu "$@"
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
  echo "Режим сертификата: ${CERT_MODE}"
  if [ "$CERT_MODE" = "self-signed" ]; then
    echo "Разница: клиент должен использовать вложенный файл server-cert.pem."
  else
    echo "Разница: публичный доверенный сертификат от Let's Encrypt."
    echo "Требование: домен должен указывать на этот сервер, а 80/tcp должен работать во время выпуска и продления."
  fi
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
  if [ "$CERT_MODE" = "self-signed" ]; then
    echo "   Certificate file: server-cert.pem"
  else
    echo "   Certificate file: usually not required, but server-cert.pem is included."
  fi
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
    refresh-tools)
      write_tools
      if [ -f "$TT_DIR/vpn.toml" ]; then
        load_current_trusttunnel_context
        if [ "$CERT_MODE" = letsencrypt ]; then write_certificate_automation; fi
      fi
      echo "Локальное меню и служебные команды обновлены. Клиенты и сертификаты не изменялись."
      exit 0
      ;;
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
    reregister-warp)
      reregister_warp_account
      exit 0
      ;;
    backup-identity)
      backup_identity
      exit 0
      ;;
    restore-identity)
      restore_identity
      exit 0
      ;;
    renew-certificate)
      renew_certificate_manually
      exit 0
      ;;
    switch-certificate-mode)
      switch_certificate_mode
      exit 0
      ;;
    speedtest)
      run_speedtest
      exit 0
      ;;
    configure-cascade)
      configure_cascade
      exit 0
      ;;
    install-panel)
      install_panel
      exit 0
      ;;
    remove-panel)
      remove_panel
      exit 0
      ;;
    configure-panel-access)
      configure_panel_access
      exit 0
      ;;
    manage-panel-service)
      manage_panel_service
      exit 0
      ;;
    manage-clients)
      manage_clients
      exit 0
      ;;
    manage-client-network)
      manage_client_network_settings
      exit 0
      ;;
    manage-system-tools)
      manage_system_tools
      exit 0
      ;;
    manage-admin)
      manage_admin
      exit 0
      ;;
    manage-masque)
      manage_masque
      exit 0
      ;;
    manage-endpoint-features)
      manage_endpoint_features
      exit 0
      ;;
    manage-interface)
      manage_interface
      exit 0
      ;;
    manage-warp)
      manage_warp
      exit 0
      ;;
    recommendations)
      ensure_admin_helper
      admin_call recommendations
      exit 0
      ;;
    manage-protection)
      manage_protection
      exit 0
      ;;
    manage-server-security)
      manage_server_security
      exit 0
      ;;
    configure-routing)
      configure_routing
      exit 0
      ;;
    manage-ports)
      manage_ports
      exit 0
      ;;
    manage-fail2ban)
      manage_fail2ban
      exit 0
      ;;
    manage-ufw)
      manage_ufw
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

  assert_protection_unlocked
  if [ -f /etc/systemd/system/trusttunnel.service.d/40-warp-interface.conf ]; then
    echo "Перед полной переустановкой отключите интерфейсный WARP через пункт 32. Текущие настройки не изменены." >&2
    return 1
  fi
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
  if [ "$CERT_MODE" = "letsencrypt" ]; then
    write_certificate_automation
  else
    remove_certificate_automation
  fi

  echo
  echo "ГОТОВО"
  echo "Домен: ${DOMAIN}:${ENDPOINT_PORT}"
  echo "Клиентов: ${CLIENTS}"
  echo "Файлы клиентов: ${CLIENT_DIR}"
  echo "ZIP клиентов: /root/trusttunnel-clients-${DOMAIN}.zip"
  echo "Команда проверки: trusttunnel-status"
  echo "Главное меню: ttmenu"
  echo "Старое имя тоже работает: trusttunnel-menu"
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

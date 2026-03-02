#!/usr/bin/env bash
#############################################################
# TrustTunnel Auto-Installer Advanced v4.4
# Полная установка TrustTunnel (endpoint) на Ubuntu 24.04
#############################################################

set -euo pipefail

# ============================================
# ЦВЕТА И ПЕРЕМЕННЫЕ
# ============================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

SCRIPT_VERSION="4.4"
INSTALL_LOG="/var/log/trusttunnel-install.log"

SERVER_IP="${SERVER_IP:-$(curl -fsS ifconfig.me 2>/dev/null || echo 127.0.0.1)}"
DOMAIN="${DOMAIN:-example.duckdns.org}"
EMAIL="${EMAIL:-admin@example.com}"
NUM_USERS="${NUM_USERS:-10}"
VPN_PORT_DEFAULT="${VPN_PORT_DEFAULT:-443}"
VPN_PORT="${VPN_PORT:-$VPN_PORT_DEFAULT}"

INSTALL_DIR="/opt/trusttunnel"
BIN_DIR="${INSTALL_DIR}/bin"
CONFIG_DIR="${INSTALL_DIR}/config"
CERTS_DIR="${INSTALL_DIR}/certs"
LOG_DIR="/var/log/trusttunnel"
BACKUP_DIR="/var/backups/trusttunnel"
SCRIPTS_DIR="${INSTALL_DIR}/scripts"

ENDPOINT_BIN="${BIN_DIR}/trusttunnel_endpoint"

# ============================================
# ЛОГИРОВАНИЕ
# ============================================
log_info()   { echo -e "${GREEN}[✓]${NC} $1" | tee -a "$INSTALL_LOG"; }
log_error()  { echo -e "${RED}[✗]${NC} $1" | tee -a "$INSTALL_LOG" >&2; }
log_warn()   { echo -e "${YELLOW}[⚠]${NC} $1" | tee -a "$INSTALL_LOG"; }
log_section() {
  echo "" | tee -a "$INSTALL_LOG"
  echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}" | tee -a "$INSTALL_LOG"
  echo -e "${BLUE}║${NC} $1" | tee -a "$INSTALL_LOG"
  echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}" | tee -a "$INSTALL_LOG"
  echo "" | tee -a "$INSTALL_LOG"
}

on_error() {
  local exit_code=$?
  log_error "Скрипт завершился с ошибкой (код: ${exit_code}). Смотри лог: ${INSTALL_LOG}"
  exit "$exit_code"
}
trap on_error ERR

clear_screen() {
  clear || true
  echo -e "${MAGENTA}"
  cat << 'BANNER'
████████╗██████╗ ██╗   ██╗███████╗████████╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║
   ██║   ██████╔╝██║   ██║███████╗   ██║      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
   ██║   ██╔══██╗██║   ██║╚════██║   ██║      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
   ██║   ██║  ██║╚██████╔╝███████║   ██║      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
BANNER
  echo -e "${NC}"
}

# ============================================
# ПРОВЕРКИ
# ============================================
check_root() {
  if [[ ${EUID} -ne 0 ]]; then
    log_error "Требуются права root"
    exit 1
  fi
}

check_system() {
  log_section "ПРОВЕРКА СИСТЕМЫ"
  if ! grep -q 'Ubuntu' /etc/os-release; then
    log_error "Требуется Ubuntu Server"
    exit 1
  fi
  if ! grep -q 'VERSION_ID="24.04"' /etc/os-release; then
    log_warn "Скрипт рассчитан на Ubuntu 24.04 (продолжаю, но возможны отличия)"
  else
    log_info "ОС: Ubuntu 24.04"
  fi
}

# ============================================
# ИНТЕРАКТИВНЫЙ ВВОД
# ============================================
prompt_parameters() {
  clear_screen
  log_section "⚙️ КОНФИГУРАЦИЯ ПАРАМЕТРОВ"

  read -r -p " IP адрес сервера [$SERVER_IP]: " INPUT_IP
  SERVER_IP="${INPUT_IP:-$SERVER_IP}"

  read -r -p " Доменное имя [$DOMAIN]: " INPUT_DOMAIN
  DOMAIN="${INPUT_DOMAIN:-$DOMAIN}"

  read -r -p " Email (для Let's Encrypt) [$EMAIL]: " INPUT_EMAIL
  EMAIL="${INPUT_EMAIL:-$EMAIL}"

  read -r -p " Порт VPN [$VPN_PORT_DEFAULT]: " INPUT_PORT
  VPN_PORT="${INPUT_PORT:-$VPN_PORT_DEFAULT}"

  read -r -p " Количество пользователей [$NUM_USERS]: " INPUT_USERS
  NUM_USERS="${INPUT_USERS:-$NUM_USERS}"

  echo ""
  read -r -p "Все верно? (y/n) [y]: " CONFIRM
  [[ "${CONFIRM:-y}" =~ ^[Yy]$ ]] || exit 0
}

# ============================================
# ДИРЕКТОРИИ
# ============================================
create_directories() {
  log_section "СОЗДАНИЕ ДИРЕКТОРИЙ"
  mkdir -p \
    "$INSTALL_DIR" \
    "$BIN_DIR" \
    "$CONFIG_DIR" \
    "$CERTS_DIR" \
    "$LOG_DIR" \
    "$BACKUP_DIR" \
    "$SCRIPTS_DIR"
  chmod 700 "$CERTS_DIR"
  log_info "Директории созданы"
}

# ============================================
# ОБНОВЛЕНИЕ СИСТЕМЫ
# ============================================
update_system() {
  log_section "ОБНОВЛЕНИЕ СИСТЕМЫ"
  apt-get update -qq
  apt-get upgrade -y -qq
  log_info "Система обновлена"
}

# ============================================
# УСТАНОВКА ЗАВИСИМОСТЕЙ
# ============================================
install_dependencies() {
  log_section "УСТАНОВКА ЗАВИСИМОСТЕЙ"
  apt-get install -y -qq \
    curl wget git jq \
    openssl ca-certificates \
    net-tools htop nano \
    ufw fail2ban \
    certbot \
    nginx
  log_info "Зависимости установлены"
}

# ============================================
# КОНФИГУРАЦИЯ ЯДРА + базовая защита
# ============================================
configure_kernel() {
  log_section "⚙️ НАСТРОЙКА ЯДРА (BBR) И БАЗОВАЯ СЕТЕВАЯ ЗАЩИТА"
  cat > /etc/sysctl.d/99-trusttunnel.conf << 'EOF'
# BBR
net.ipv4.tcp_congestion_control=bbr
net.core.default_qdisc=fq

# SYN Flood
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=4096
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=2

# IP Spoofing
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# Network buffers
net.core.netdev_max_backlog=5000
EOF
  sysctl --system >/dev/null 2>&1 || true
  log_info "BBR и базовая защита включены"
}

# ============================================
# FIREWALL
# ============================================
setup_firewall() {
  log_section "НАСТРОЙКА FIREWALL"
  ufw --force enable >/dev/null 2>&1 || true
  ufw allow ssh >/dev/null 2>&1 || true
  ufw allow 80/tcp >/dev/null 2>&1 || true
  ufw allow "${VPN_PORT}/tcp" >/dev/null 2>&1 || true
  ufw allow "${VPN_PORT}/udp" >/dev/null 2>&1 || true
  log_info "UFW настроен"
}

# ============================================
# FAIL2BAN
# ============================================
setup_fail2ban() {
  log_section "НАСТРОЙКА FAIL2BAN"
  cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
EOF
  systemctl restart fail2ban
  systemctl enable fail2ban >/dev/null 2>&1 || true
  log_info "Fail2Ban включён"
}

# ============================================
# LET'S ENCRYPT (standalone)
# ============================================
setup_certbot() {
  log_section "ПОЛУЧЕНИЕ СЕРТИФИКАТА LET'S ENCRYPT"

  systemctl stop nginx >/dev/null 2>&1 || true

  certbot certonly --standalone \
    -d "$DOMAIN" \
    --non-interactive --agree-tos \
    -m "$EMAIL" --keep-until-expiring

  mkdir -p "$CERTS_DIR"
  cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERTS_DIR/cert.pem"
  cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   "$CERTS_DIR/key.pem"
  chmod 600 "$CERTS_DIR/key.pem"
  chmod 644 "$CERTS_DIR/cert.pem"

  log_info "Сертификаты скопированы в ${CERTS_DIR}"
}

# ============================================
# УСТАНОВКА TRUSTTUNNEL (ОФИЦИАЛЬНЫЙ INSTALL.SH)
# ============================================
install_trusttunnel_binary() {
  log_section "⬇️ УСТАНОВКА TRUSTTUNNEL ENDPOINT (OFFICIAL RELEASE)"

  # Официальный инсталлер ставит в /opt/trusttunnel (или -o DIR)
  curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh \
    | sh -s - -o "$INSTALL_DIR"

  # Убедимся, что бинарники на месте
  if [[ ! -x "$INSTALL_DIR/trusttunnel_endpoint" ]]; then
    log_error "После установки не найден $INSTALL_DIR/trusttunnel_endpoint"
    exit 1
  fi

  # Приведём структуру к твоей (bin/)
  install -m 755 "$INSTALL_DIR/trusttunnel_endpoint" "$ENDPOINT_BIN"
  if [[ -x "$INSTALL_DIR/setup_wizard" ]]; then
    install -m 755 "$INSTALL_DIR/setup_wizard" "$BIN_DIR/setup_wizard"
  fi

  log_info "TrustTunnel endpoint установлен: $ENDPOINT_BIN"
}

# ============================================
# КОНФИГИ TRUSTTUNNEL (АКТУАЛЬНЫЙ ФОРМАТ)
# ============================================
create_trusttunnel_config() {
  log_section "⚙️ СОЗДАНИЕ КОНФИГУРАЦИИ TRUSTTUNNEL"

  # credentials.toml (формат [[client]] username/password)
  local cred_file="${CONFIG_DIR}/credentials.toml"
  : > "$cred_file"

  for i in $(seq 1 "$NUM_USERS"); do
    local user="user$i"
    local pass
    pass="$(openssl rand -base64 18 | tr -d '\n' | tr -d '/' | tr -d '+' | head -c 18)"
    cat >> "$cred_file" << EOF
[[client]]
username = "${user}"
password = "${pass}"

EOF
  done
  chmod 600 "$cred_file"
  log_info "Создано $NUM_USERS пользователей в ${cred_file}"

  # hosts.toml (актуальный формат [[main_hosts]])
  cat > "${CONFIG_DIR}/hosts.toml" << EOF
[[main_hosts]]
hostname = "${DOMAIN}"
cert_chain_path = "${CERTS_DIR}/cert.pem"
private_key_path = "${CERTS_DIR}/key.pem"
EOF
  chmod 644 "${CONFIG_DIR}/hosts.toml"

  # vpn.toml (актуальные ключи)
  cat > "${CONFIG_DIR}/vpn.toml" << EOF
# Main endpoint settings
listen_address = "0.0.0.0:${VPN_PORT}"

# Credentials
credentials_file = "${CONFIG_DIR}/credentials.toml"

# Enable common listen protocols
[listen_protocols]
[listen_protocols.http1]
upload_buffer_size = 32768

[listen_protocols.http2]
initial_connection_window_size = 8388608
initial_stream_window_size = 131072
max_concurrent_streams = 1000
max_frame_size = 16384
header_table_size = 65536

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

# Default forwarding: direct
[forward_protocol]
direct = {}
EOF
  chmod 644 "${CONFIG_DIR}/vpn.toml"

  log_info "Конфигурация TrustTunnel создана: vpn.toml / hosts.toml / credentials.toml"
}

# ============================================
# SYSTEMD СЕРВИС
# ============================================
create_systemd_service() {
  log_section "СОЗДАНИЕ SYSTEMD СЕРВИСА"

  mkdir -p "$LOG_DIR"
  touch "$LOG_DIR/endpoint.log"
  chmod 640 "$LOG_DIR/endpoint.log"

  cat > /etc/systemd/system/trusttunnel.service << EOF
[Unit]
Description=TrustTunnel Endpoint
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${ENDPOINT_BIN} ${CONFIG_DIR}/vpn.toml ${CONFIG_DIR}/hosts.toml --logfile ${LOG_DIR}/endpoint.log --loglvl info
Restart=always
RestartSec=3
StartLimitIntervalSec=60
StartLimitBurst=10
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable trusttunnel.service >/dev/null 2>&1 || true

  log_info "Systemd сервис trusttunnel.service создан"
}

# ============================================
# БЭКАПЫ И ВОССТАНОВЛЕНИЕ
# ============================================
create_backup_and_restore() {
  log_section "РЕЗЕРВНОЕ КОПИРОВАНИЕ И ВОССТАНОВЛЕНИЕ"

  cat > "${SCRIPTS_DIR}/backup.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
BACKUP_DIR="/var/backups/trusttunnel"
DATE="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${BACKUP_DIR}/trusttunnel_backup_${DATE}.tar.gz"
mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_FILE" \
  /opt/trusttunnel/config \
  /opt/trusttunnel/certs \
  /var/log/trusttunnel \
  2>/dev/null || true
find "$BACKUP_DIR" -name "trusttunnel_backup_*.tar.gz" -mtime +30 -delete || true
echo "[$(date)] Backup created: $BACKUP_FILE"
EOF
  chmod +x "${SCRIPTS_DIR}/backup.sh"

  cat > "${SCRIPTS_DIR}/restore-config.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
BACKUP_DIR="/var/backups/trusttunnel"
LATEST_BACKUP="$(ls -1t "${BACKUP_DIR}"/trusttunnel_backup_*.tar.gz 2>/dev/null | head -n1 || true)"
if [[ -z "${LATEST_BACKUP}" ]]; then
  echo "No backups found in ${BACKUP_DIR}"
  exit 1
fi
echo "Restoring from backup: $LATEST_BACKUP"
tar -xzf "$LATEST_BACKUP" -C /
systemctl restart trusttunnel || true
echo "Restore complete."
EOF
  chmod +x "${SCRIPTS_DIR}/restore-config.sh"

  cat > /etc/systemd/system/trusttunnel-backup.service << EOF
[Unit]
Description=TrustTunnel Backup Service
After=trusttunnel.service

[Service]
Type=oneshot
ExecStart=${SCRIPTS_DIR}/backup.sh
EOF

  cat > /etc/systemd/system/trusttunnel-backup.timer << 'EOF'
[Unit]
Description=Daily TrustTunnel Backup

[Timer]
OnCalendar=daily
OnBootSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable trusttunnel-backup.timer >/dev/null 2>&1 || true
  systemctl start trusttunnel-backup.timer >/dev/null 2>&1 || true

  log_info "Бэкапы и восстановление настроены"
}

# ============================================
# АВТООБНОВЛЕНИЕ TRUSTTUNNEL (через official install.sh)
# ============================================
create_trusttunnel_update() {
  log_section "♻️ АВТООБНОВЛЕНИЕ TRUSTTUNNEL (OFFICIAL)"

  cat > "${SCRIPTS_DIR}/update-trusttunnel.sh" << EOF
#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR}"
BIN_DIR="${BIN_DIR}"
ENDPOINT_BIN="${ENDPOINT_BIN}"

systemctl stop trusttunnel || true

curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh \\
  | sh -s - -o "\$INSTALL_DIR"

# обновим бинарники в bin/
install -m 755 "\$INSTALL_DIR/trusttunnel_endpoint" "\$ENDPOINT_BIN"
if [[ -x "\$INSTALL_DIR/setup_wizard" ]]; then
  install -m 755 "\$INSTALL_DIR/setup_wizard" "\$BIN_DIR/setup_wizard"
fi

systemctl start trusttunnel || true
echo "TrustTunnel updated successfully."
EOF
  chmod +x "${SCRIPTS_DIR}/update-trusttunnel.sh"

  cat > /etc/systemd/system/trusttunnel-update.service << EOF
[Unit]
Description=Weekly TrustTunnel Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPTS_DIR}/update-trusttunnel.sh
EOF

  cat > /etc/systemd/system/trusttunnel-update.timer << 'EOF'
[Unit]
Description=Weekly TrustTunnel Update Timer

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable trusttunnel-update.timer >/dev/null 2>&1 || true
  systemctl start trusttunnel-update.timer >/dev/null 2>&1 || true

  log_info "Автообновление TrustTunnel включено"
}

# ============================================
# CLI
# ============================================
create_cli() {
  log_section "СОЗДАНИЕ CLI ИНТЕРФЕЙСА"

  cat > "${SCRIPTS_DIR}/trusttunnel-cli.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="/opt/trusttunnel"
CONFIG_DIR="${INSTALL_DIR}/config"
USERS_FILE="${CONFIG_DIR}/credentials.toml"
SCRIPTS_DIR="${INSTALL_DIR}/scripts"
LOG_DIR="/var/log/trusttunnel"

case "${1:-}" in
  status)
    systemctl status trusttunnel --no-pager
    ;;
  restart)
    systemctl restart trusttunnel
    echo "TrustTunnel restarted."
    ;;
  logs)
    # endpoint пишет в файл + journal
    echo "---- FILE LOG (${LOG_DIR}/endpoint.log) ----"
    tail -n 200 "${LOG_DIR}/endpoint.log" 2>/dev/null || true
    echo ""
    echo "---- JOURNAL ----"
    journalctl -u trusttunnel -n 200 --no-pager
    ;;
  users)
    case "${2:-}" in
      list)
        echo "VPN Users:"
        awk '
          $0 ~ /^\[\[client\]\]$/ {in=1; u=""; p=""}
          in && $1=="username" {gsub(/"|=/,""); u=$3}
          in && $1=="password" {gsub(/"|=/,""); p=$3}
          in && u!="" && p!="" {print u ":" p; in=0}
        ' "$USERS_FILE" | nl -ba
        ;;
      add)
        USERNAME="${3:-}"
        if [[ -z "$USERNAME" ]]; then
          echo "Usage: trusttunnel-cli users add <username>"
          exit 1
        fi
        PASSWORD="$(openssl rand -base64 18 | tr -d '\n' | tr -d '/' | tr -d '+' | head -c 18)"
        cat >> "$USERS_FILE" << EOF2

[[client]]
username = "${USERNAME}"
password = "${PASSWORD}"
EOF2
        systemctl restart trusttunnel || true
        echo "User created: ${USERNAME}"
        echo "Password: ${PASSWORD}"
        ;;
      delete)
        USERNAME="${3:-}"
        if [[ -z "$USERNAME" ]]; then
          echo "Usage: trusttunnel-cli users delete <username>"
          exit 1
        fi
        # грубо, но работает: удаляем блок [[client]] где username совпал
        tmp="$(mktemp)"
        awk -v u="$USERNAME" '
          BEGIN{keep=1; block=""}
          {
            if ($0 ~ /^\[\[client\]\]$/) {block=$0"\n"; keep=1; next}
            if (block!="") {
              block = block $0 "\n"
              if ($0 ~ /username/ && $0 ~ u) {keep=0}
              # конец блока - пустая строка или следующий [[client]]
              if ($0 ~ /^$/) {
                if (keep) printf "%s", block
                block=""
              }
              next
            }
            print
          }
          END{
            if (block!="") { if (keep) printf "%s", block }
          }
        ' "$USERS_FILE" > "$tmp"
        mv "$tmp" "$USERS_FILE"
        systemctl restart trusttunnel || true
        echo "User deleted (if existed): ${USERNAME}"
        ;;
      *)
        echo "Usage: trusttunnel-cli users {list|add|delete} [username]"
        ;;
    esac
    ;;
  backup)
    "${SCRIPTS_DIR}/backup.sh"
    ;;
  restore)
    "${SCRIPTS_DIR}/restore-config.sh"
    ;;
  update)
    "${SCRIPTS_DIR}/update-trusttunnel.sh"
    ;;
  *)
    echo "TrustTunnel CLI"
    echo ""
    echo "Commands:"
    echo "  status                 - Service status"
    echo "  restart                - Restart service"
    echo "  logs                   - View logs"
    echo "  users list             - List users"
    echo "  users add <username>   - Add user"
    echo "  users delete <username>- Delete user"
    echo "  backup                 - Create backup"
    echo "  restore                - Restore from last backup"
    echo "  update                 - Update TrustTunnel"
    ;;
esac
EOF

  chmod +x "${SCRIPTS_DIR}/trusttunnel-cli.sh"
  ln -sf "${SCRIPTS_DIR}/trusttunnel-cli.sh" /usr/local/bin/trusttunnel-cli
  log_info "CLI интерфейс создан (trusttunnel-cli)"
}

# ============================================
# ФИНАЛЬНАЯ КОНФИГУРАЦИЯ
# ============================================
final_setup() {
  log_section "⚡ ФИНАЛЬНАЯ КОНФИГУРАЦИЯ"

  cat > /etc/logrotate.d/trusttunnel << 'EOF'
/var/log/trusttunnel/*.log {
  daily
  rotate 14
  compress
  delaycompress
  notifempty
  create 0640 root root
}
EOF

  cat > /etc/security/limits.d/99-trusttunnel.conf << 'EOF'
* soft nofile 1000000
* hard nofile 1000000
EOF

  log_info "Финальная конфигурация завершена"
}

# ============================================
# ИТОГОВЫЙ ВЫВОД
# ============================================
show_summary() {
  clear_screen
  log_section "✅ УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО!"
  echo ""
  echo -e "${CYAN}Информация о сервере:${NC}"
  echo " IP адрес:       $SERVER_IP"
  echo " Домен:          $DOMAIN"
  echo " Порт VPN:       $VPN_PORT"
  echo " Email:          $EMAIL"
  echo " Пользователей:  $NUM_USERS"
  echo ""
  echo -e "${CYAN}Файлы:${NC}"
  echo " ${CONFIG_DIR}/vpn.toml"
  echo " ${CONFIG_DIR}/hosts.toml"
  echo " ${CONFIG_DIR}/credentials.toml"
  echo " Лог: ${LOG_DIR}/endpoint.log"
  echo ""
  echo -e "${CYAN}Команды управления:${NC}"
  echo " trusttunnel-cli status"
  echo " trusttunnel-cli users list"
  echo " trusttunnel-cli users add john"
  echo " trusttunnel-cli users delete john"
  echo " trusttunnel-cli logs"
  echo " trusttunnel-cli restart"
  echo " trusttunnel-cli backup"
  echo " trusttunnel-cli restore"
  echo " trusttunnel-cli update"
  echo ""
  echo -e "${CYAN}Systemd:${NC}"
  echo " systemctl status trusttunnel"
  echo " systemctl restart trusttunnel"
  echo ""
  echo -e "${GREEN}Сервер готов к использованию!${NC}"
  echo ""
}

# ============================================
# MAIN
# ============================================
main() {
  check_root
  mkdir -p "$(dirname "$INSTALL_LOG")"
  : > "$INSTALL_LOG"

  clear_screen
  log_section "TRUSTTUNNEL AUTO-INSTALLER v$SCRIPT_VERSION"
  echo "Установка TrustTunnel Endpoint на Ubuntu Server 24.04"
  echo ""

  check_system
  prompt_parameters
  create_directories
  update_system
  install_dependencies
  configure_kernel
  setup_firewall
  setup_fail2ban
  setup_certbot
  install_trusttunnel_binary
  create_trusttunnel_config
  create_systemd_service
  create_backup_and_restore
  create_trusttunnel_update
  create_cli
  final_setup

  systemctl restart trusttunnel.service
  show_summary
}

main "$@"

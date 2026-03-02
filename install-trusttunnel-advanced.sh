#!/bin/bash

#############################################
# TrustTunnel Auto-Installer Advanced v4.1
# Полная установка TrustTunnel на Ubuntu 24.04
#############################################

set -e

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

SCRIPT_VERSION="4.1"
INSTALL_LOG="/var/log/trusttunnel-install.log"

SERVER_IP="${SERVER_IP:-$(curl -s ifconfig.me || echo 127.0.0.1)}"
DOMAIN="${DOMAIN:-example.duckdns.org}"
EMAIL="${EMAIL:-admin@example.com}"
NUM_USERS="${NUM_USERS:-10}"
VPN_PORT_DEFAULT="${VPN_PORT_DEFAULT:-443}"

INSTALL_DIR="/opt/trusttunnel"
BIN_DIR="${INSTALL_DIR}/bin"
CONFIG_DIR="${INSTALL_DIR}/config"
CERTS_DIR="${INSTALL_DIR}/certs"
LOG_DIR="/var/log/trusttunnel"
USERS_DIR="${INSTALL_DIR}/users"
BACKUP_DIR="/var/backups/trusttunnel"
SCRIPTS_DIR="${INSTALL_DIR}/scripts"

# ============================================
# ЛОГИРОВАНИЕ
# ============================================

log_info() { echo -e "${GREEN}[✓]${NC} $1" | tee -a "$INSTALL_LOG"; }
log_error() { echo -e "${RED}[✗]${NC} $1" | tee -a "$INSTALL_LOG"; }
log_warn() { echo -e "${YELLOW}[⚠]${NC} $1" | tee -a "$INSTALL_LOG"; }

log_section() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} $1"
    echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
    echo ""
}

clear_screen() {
    clear
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
    if [[ $EUID -ne 0 ]]; then
        log_error "Требуются права root"
        exit 1
    fi
}

check_system() {
    log_section "🔍 ПРОВЕРКА СИСТЕМЫ"

    if ! grep -q 'Ubuntu' /etc/os-release; then
        log_error "Требуется Ubuntu Server"
        exit 1
    fi

    if ! grep -q 'VERSION_ID="24.04"' /etc/os-release; then
        log_warn "Скрипт рассчитан на Ubuntu 24.04"
    fi

    log_info "ОС: Ubuntu 24.04"
}

# ============================================
# ИНТЕРАКТИВНЫЙ ВВОД
# ============================================

prompt_parameters() {
    clear_screen
    log_section "⚙️ КОНФИГУРАЦИЯ ПАРАМЕТРОВ"

    read -p "📍 IP адрес сервера [$SERVER_IP]: " INPUT_IP
    SERVER_IP="${INPUT_IP:-$SERVER_IP}"

    read -p "🌐 Доменное имя [$DOMAIN]: " INPUT_DOMAIN
    DOMAIN="${INPUT_DOMAIN:-$DOMAIN}"

    read -p "📧 Email [$EMAIL]: " INPUT_EMAIL
    EMAIL="${INPUT_EMAIL:-$EMAIL}"

    read -p "🔌 Порт VPN [$VPN_PORT_DEFAULT]: " INPUT_PORT
    VPN_PORT="${INPUT_PORT:-$VPN_PORT_DEFAULT}"

    read -p "👥 Количество пользователей [$NUM_USERS]: " INPUT_USERS
    NUM_USERS="${INPUT_USERS:-$NUM_USERS}"

    echo ""
    read -p "Все верно? (y/n) [y]: " CONFIRM
    [[ "$CONFIRM" =~ ^[Yy]?$ ]] || exit 0
}

# ============================================
# ДИРЕКТОРИИ
# ============================================

create_directories() {
    log_section "📁 СОЗДАНИЕ ДИРЕКТОРИЙ"

    mkdir -p "$INSTALL_DIR" "$BIN_DIR" "$CONFIG_DIR" "$CERTS_DIR" \
             "$LOG_DIR" "$USERS_DIR" "$BACKUP_DIR" "$SCRIPTS_DIR"

    log_info "Директории созданы"
}
# ============================================
# ОБНОВЛЕНИЕ СИСТЕМЫ
# ============================================

update_system() {
    log_section "🔄 ОБНОВЛЕНИЕ СИСТЕМЫ"

    apt-get update -qq
    apt-get upgrade -y -qq

    log_info "Система обновлена"
}

# ============================================
# УСТАНОВКА ЗАВИСИМОСТЕЙ
# ============================================

install_dependencies() {
    log_section "📦 УСТАНОВКА ЗАВИСИМОСТЕЙ"

    apt-get install -y -qq \
        curl wget git jq \
        openssl ca-certificates \
        net-tools htop nano \
        ufw fail2ban \
        certbot python3-certbot \
        nginx

    log_info "Зависимости установлены"
}

# ============================================
# КОНФИГУРАЦИЯ ЯДРА + DDoS
# ============================================

configure_kernel() {
    log_section "⚙️ НАСТРОЙКА ЯДРА И DDoS ЗАЩИТЫ"

    cat > /etc/sysctl.d/99-trusttunnel.conf << EOF
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

# Network Buffers
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.core.netdev_max_backlog=5000

# ICMP Flood
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
EOF

    sysctl --system > /dev/null 2>&1 || true
    log_info "BBR и DDoS защита включены"
}

# ============================================
# FIREWALL
# ============================================

setup_firewall() {
    log_section "🔐 НАСТРОЙКА FIREWALL"

    ufw --force enable > /dev/null 2>&1
    ufw allow ssh > /dev/null 2>&1
    ufw allow ${VPN_PORT}/tcp > /dev/null 2>&1
    ufw allow ${VPN_PORT}/udp > /dev/null 2>&1
    ufw allow 80/tcp > /dev/null 2>&1

    log_info "UFW настроен"
}

# ============================================
# FAIL2BAN
# ============================================

setup_fail2ban() {
    log_section "🛡️ НАСТРОЙКА FAIL2BAN"

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
    systemctl enable fail2ban

    log_info "Fail2Ban включён"
}

# ============================================
# LET'S ENCRYPT
# ============================================

setup_certbot() {
    log_section "🔐 ПОЛУЧЕНИЕ СЕРТИФИКАТА LET'S ENCRYPT"

    ufw allow 80/tcp > /dev/null 2>&1
    systemctl stop nginx 2>/dev/null || true

    certbot certonly --standalone \
        -d "$DOMAIN" \
        --non-interactive --agree-tos \
        -m "$EMAIL" --keep-until-expiring || {
            log_error "Ошибка получения сертификата"
            exit 1
        }

    ufw delete allow 80/tcp > /dev/null 2>&1 || true

    cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$CERTS_DIR/cert.pem"
    cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$CERTS_DIR/key.pem"

    log_info "Сертификаты скопированы"

    mkdir -p /etc/letsencrypt/renewal-hooks/pre /etc/letsencrypt/renewal-hooks/post

    cat > /etc/letsencrypt/renewal-hooks/pre/open80.sh << 'EOF'
#!/bin/bash
ufw allow 80/tcp || true
EOF

    cat > /etc/letsencrypt/renewal-hooks/post/close80.sh << 'EOF'
#!/bin/bash
ufw delete allow 80/tcp || true
EOF

    chmod +x /etc/letsencrypt/renewal-hooks/pre/open80.sh
    chmod +x /etc/letsencrypt/renewal-hooks/post/close80.sh
}

# ============================================
# СКАЧИВАНИЕ БИНАРНИКА TRUSTTUNNEL
# ============================================

install_trusttunnel_binary() {
    log_section "⬇️ УСТАНОВКА TRUSTTUNNEL (СТАБИЛЬНЫЙ БИНАРНИК)"

    local api_url="https://api.github.com/repos/TrustTunnel/TrustTunnel/releases/latest"
    local tmp="/tmp/trusttunnel"
    mkdir -p "$tmp"

    log_info "Получение информации о последнем релизе..."

    local asset_url
    asset_url=$(curl -s "$api_url" | jq -r '.assets[] | select(.name | test("endpoint.*x86_64.*linux.*tar.gz")) | .browser_download_url' | head -n1)

    if [[ -z "$asset_url" ]]; then
        log_error "Не найден бинарник endpoint для x86_64"
        exit 1
    fi

    log_info "Скачивание: $asset_url"

    curl -L -o "$tmp/endpoint.tar.gz" "$asset_url"

    tar -xzf "$tmp/endpoint.tar.gz" -C "$tmp"

    local endpoint_bin
    endpoint_bin=$(find "$tmp" -type f -name "endpoint" | head -n1)

    if [[ -z "$endpoint_bin" ]]; then
        log_error "Бинарник endpoint не найден в архиве"
        exit 1
    fi

    install -m 755 "$endpoint_bin" "${BIN_DIR}/trusttunnel-endpoint"

    log_info "TrustTunnel установлен: ${BIN_DIR}/trusttunnel-endpoint"
}
# ============================================
# КОНФИГИ TRUSTTUNNEL
# ============================================

create_trusttunnel_config() {
    log_section "⚙️ СОЗДАНИЕ КОНФИГУРАЦИИ TRUSTTUNNEL"

    # credentials.toml
    local cred_file="${CONFIG_DIR}/credentials.toml"
    : > "$cred_file"

    for i in $(seq 1 "$NUM_USERS"); do
        local user="user$i"
        local pass
        pass=$(openssl rand -base64 12)
        echo "${user}:${pass}" >> "$cred_file"
    done

    chmod 600 "$cred_file"
    log_info "Создано $NUM_USERS пользователей"

    # hosts.toml
    cat > "${CONFIG_DIR}/hosts.toml" << EOF
[[hosts]]
server_name = "$DOMAIN"
cert_file = "${CERTS_DIR}/cert.pem"
key_file  = "${CERTS_DIR}/key.pem"
EOF

    # vpn.toml
    cat > "${CONFIG_DIR}/vpn.toml" << EOF
bind_addr = "0.0.0.0:${VPN_PORT}"
public_ip = "${SERVER_IP}"
domain = "${DOMAIN}"
antidpi = true
credentials = "${CONFIG_DIR}/credentials.toml"
hosts = "${CONFIG_DIR}/hosts.toml"
EOF

    chmod 644 "${CONFIG_DIR}/vpn.toml" "${CONFIG_DIR}/hosts.toml"
    log_info "Конфигурация TrustTunnel создана"
}

# ============================================
# SYSTEMD СЕРВИС
# ============================================

create_systemd_service() {
    log_section "🔧 СОЗДАНИЕ SYSTEMD СЕРВИСА"

    cat > /etc/systemd/system/trusttunnel.service << EOF
[Unit]
Description=TrustTunnel Endpoint
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_DIR}/trusttunnel-endpoint --config ${CONFIG_DIR}/vpn.toml
Restart=always
RestartSec=3
StartLimitIntervalSec=60
StartLimitBurst=10
LimitNOFILE=1000000
StandardOutput=journal
StandardError=journal
SyslogIdentifier=trusttunnel

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable trusttunnel.service > /dev/null 2>&1 || true

    log_info "Systemd сервис trusttunnel.service создан"
}

# ============================================
# БЭКАПЫ И ВОССТАНОВЛЕНИЕ
# ============================================

create_backup_and_restore() {
    log_section "💾 РЕЗЕРВНОЕ КОПИРОВАНИЕ И ВОССТАНОВЛЕНИЕ"

    # backup.sh
    cat > "${SCRIPTS_DIR}/backup.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/trusttunnel"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/trusttunnel_backup_${DATE}.tar.gz"

mkdir -p "$BACKUP_DIR"

tar --exclude='*.log' -czf "$BACKUP_FILE" \
    /opt/trusttunnel/config \
    /opt/trusttunnel/users \
    /opt/trusttunnel/certs \
    2>/dev/null || true

find "$BACKUP_DIR" -name "trusttunnel_backup_*.tar.gz" -mtime +30 -delete

echo "[$(date)] Backup created: $BACKUP_FILE"
EOF

    chmod +x "${SCRIPTS_DIR}/backup.sh"

    # restore-config.sh
    cat > "${SCRIPTS_DIR}/restore-config.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/trusttunnel"
LATEST_BACKUP=$(ls -1t "${BACKUP_DIR}"/trusttunnel_backup_*.tar.gz 2>/dev/null | head -n1)

if [[ -z "$LATEST_BACKUP" ]]; then
    echo "No backups found in ${BACKUP_DIR}"
    exit 1
fi

echo "Restoring from backup: $LATEST_BACKUP"
tar -xzf "$LATEST_BACKUP" -C /

systemctl restart trusttunnel
echo "Restore complete."
EOF

    chmod +x "${SCRIPTS_DIR}/restore-config.sh"

    # systemd backup timer
    cat > /etc/systemd/system/trusttunnel-backup.service << EOF
[Unit]
Description=TrustTunnel Backup Service
After=trusttunnel.service

[Service]
Type=oneshot
ExecStart=${SCRIPTS_DIR}/backup.sh
StandardOutput=journal
StandardError=journal
EOF

    cat > /etc/systemd/system/trusttunnel-backup.timer << EOF
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
    systemctl enable trusttunnel-backup.timer > /dev/null 2>&1 || true
    systemctl start trusttunnel-backup.timer > /dev/null 2>&1 || true

    log_info "Бэкапы и восстановление настроены"
}

# ============================================
# АВТООБНОВЛЕНИЕ TRUSTTUNNEL
# ============================================

create_trusttunnel_update() {
    log_section "♻️ АВТООБНОВЛЕНИЕ TRUSTTUNNEL"

    cat > "${SCRIPTS_DIR}/update-trusttunnel.sh" << EOF
#!/bin/bash
set -e
API_URL="https://api.github.com/repos/TrustTunnel/TrustTunnel/releases/latest"
BIN_DIR="${BIN_DIR}"
TMP_DIR="/tmp/trusttunnel-update"

mkdir -p "\$TMP_DIR"

asset_url=\$(curl -s "\$API_URL" | jq -r '.assets[] | select(.name | test("endpoint.*x86_64.*linux.*tar.gz")) | .browser_download_url' | head -n1)

if [[ -z "\$asset_url" ]]; then
    echo "No endpoint binary found in latest release."
    exit 0
fi

tar_file="\$TMP_DIR/trusttunnel-endpoint.tar.gz"
curl -L -o "\$tar_file" "\$asset_url"

tar -xzf "\$tar_file" -C "\$TMP_DIR"
endpoint_bin=\$(find "\$TMP_DIR" -type f -name "endpoint" | head -n1)

if [[ -z "\$endpoint_bin" ]]; then
    echo "Endpoint binary not found in archive."
    exit 1
fi

systemctl stop trusttunnel || true
install -m 755 "\$endpoint_bin" "\$BIN_DIR/trusttunnel-endpoint"
systemctl start trusttunnel || true

echo "TrustTunnel updated successfully."
EOF

    chmod +x "${SCRIPTS_DIR}/update-trusttunnel.sh"

    cat > /etc/systemd/system/trusttunnel-update.service << EOF
[Unit]
Description=Weekly TrustTunnel Update
After=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPTS_DIR}/update-trusttunnel.sh
StandardOutput=journal
StandardError=journal
EOF

    cat > /etc/systemd/system/trusttunnel-update.timer << EOF
[Unit]
Description=Weekly TrustTunnel Update Timer

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable trusttunnel-update.timer > /dev/null 2>&1 || true
    systemctl start trusttunnel-update.timer > /dev/null 2>&1 || true

    log_info "Автообновление TrustTunnel включено"
}

# ============================================
# АВТООБНОВЛЕНИЕ UBUNTU
# ============================================

create_ubuntu_weekly_update() {
    log_section "♻️ ЕЖЕНЕДЕЛЬНОЕ ОБНОВЛЕНИЕ UBUNTU"

    cat > "${SCRIPTS_DIR}/ubuntu-weekly-update.sh" << 'EOF'
#!/bin/bash
set -e
LOG="/var/log/ubuntu-weekly-update.log"

echo "[$(date)] Starting weekly Ubuntu update..." >> "$LOG"

apt-get update >> "$LOG" 2>&1
apt-get upgrade -y >> "$LOG" 2>&1

echo "[$(date)] Update finished, rebooting..." >> "$LOG"
reboot
EOF

    chmod +x "${SCRIPTS_DIR}/ubuntu-weekly-update.sh"

    cat > /etc/systemd/system/ubuntu-weekly-update.service << EOF
[Unit]
Description=Weekly Ubuntu Update and Reboot
After=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPTS_DIR}/ubuntu-weekly-update.sh
StandardOutput=journal
StandardError=journal
EOF

    cat > /etc/systemd/system/ubuntu-weekly-update.timer << EOF
[Unit]
Description=Weekly Ubuntu Update Timer

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable ubuntu-weekly-update.timer > /dev/null 2>&1 || true
    systemctl start ubuntu-weekly-update.timer > /dev/null 2>&1 || true

    log_info "Еженедельное обновление Ubuntu включено"
}
# ============================================
# CLI
# ============================================

create_cli() {
    log_section "🎯 СОЗДАНИЕ CLI ИНТЕРФЕЙСА"

    cat > "${SCRIPTS_DIR}/trusttunnel-cli.sh" << 'EOFCLI'
#!/bin/bash

INSTALL_DIR="/opt/trusttunnel"
CONFIG_DIR="${INSTALL_DIR}/config"
USERS_FILE="${CONFIG_DIR}/credentials.toml"
SCRIPTS_DIR="${INSTALL_DIR}/scripts"

case "$1" in
    status)
        systemctl status trusttunnel --no-pager
        ;;
    restart)
        systemctl restart trusttunnel && echo "TrustTunnel restarted."
        ;;
    logs)
        journalctl -u trusttunnel -n 100 -f
        ;;
    users)
        case "$2" in
            list)
                echo "VPN Users:"
                nl -ba "$USERS_FILE"
                ;;
            add)
                USERNAME="$3"
                if [[ -z "$USERNAME" ]]; then
                    echo "Usage: trusttunnel-cli users add <username>"
                    exit 1
                fi
                PASSWORD=$(openssl rand -base64 12)
                echo "${USERNAME}:${PASSWORD}" >> "$USERS_FILE"
                systemctl restart trusttunnel
                echo "User created: ${USERNAME}"
                echo "Password: ${PASSWORD}"
                ;;
            delete)
                USERNAME="$3"
                if [[ -z "$USERNAME" ]]; then
                    echo "Usage: trusttunnel-cli users delete <username>"
                    exit 1
                fi
                if grep -q "^${USERNAME}:" "$USERS_FILE"; then
                    sed -i "/^${USERNAME}:/d" "$USERS_FILE"
                    systemctl restart trusttunnel
                    echo "User deleted: ${USERNAME}"
                else
                    echo "User not found: ${USERNAME}"
                fi
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
        echo "  status                    - Service status"
        echo "  restart                   - Restart service"
        echo "  logs                      - View logs"
        echo "  users list                - List users"
        echo "  users add <name>          - Add user"
        echo "  users delete <name>       - Delete user"
        echo "  backup                    - Create backup"
        echo "  restore                   - Restore from last backup"
        echo "  update                    - Update TrustTunnel"
        ;;
esac
EOFCLI

    chmod +x "${SCRIPTS_DIR}/trusttunnel-cli.sh"
    ln -sf "${SCRIPTS_DIR}/trusttunnel-cli.sh" /usr/local/bin/trusttunnel-cli

    log_info "CLI интерфейс создан (trusttunnel-cli)"
}

# ============================================
# ФИНАЛЬНАЯ КОНФИГУРАЦИЯ
# ============================================

final_setup() {
    log_section "⚡ ФИНАЛЬНАЯ КОНФИГУРАЦИЯ"

    # Ротация логов
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

    # Лимиты
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
    echo -e "${CYAN}📊 Информация о сервере:${NC}"
    echo "  IP адрес:        $SERVER_IP"
    echo "  Доменное имя:    $DOMAIN"
    echo "  Порт VPN:        $VPN_PORT"
    echo "  Email:           $EMAIL"
    echo "  Пользователей:   $NUM_USERS"
    echo ""
    echo -e "${CYAN}📁 Директории:${NC}"
    echo "  ${INSTALL_DIR}           - Основные файлы"
    echo "  ${CONFIG_DIR}            - Конфигурация"
    echo "  ${CERTS_DIR}             - Сертификаты"
    echo "  ${LOG_DIR}               - Логи"
    echo "  ${BACKUP_DIR}            - Резервные копии"
    echo ""
    echo -e "${CYAN}🎯 Команды управления:${NC}"
    echo "  trusttunnel-cli status              - Статус"
    echo "  trusttunnel-cli users list          - Список пользователей"
    echo "  trusttunnel-cli users add john      - Добавить пользователя"
    echo "  trusttunnel-cli users delete john   - Удалить пользователя"
    echo "  trusttunnel-cli logs                - Логи"
    echo "  trusttunnel-cli restart             - Перезапуск"
    echo "  trusttunnel-cli backup              - Бэкап"
    echo "  trusttunnel-cli restore             - Восстановление"
    echo "  trusttunnel-cli update              - Обновление TrustTunnel"
    echo ""
    echo -e "${CYAN}🛠️ Systemd команды:${NC}"
    echo "  systemctl status trusttunnel"
    echo "  systemctl restart trusttunnel"
    echo "  systemctl stop trusttunnel"
    echo "  systemctl start trusttunnel"
    echo ""
    echo -e "${GREEN}Сервер готов к использованию! 🎉${NC}"
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
    log_section "🎉 TRUSTTUNNEL AUTO-INSTALLER v$SCRIPT_VERSION"
    echo "Полная установка TrustTunnel VPN на Ubuntu Server 24.04"
    echo ""

    sleep 1

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
    create_ubuntu_weekly_update
    create_cli
    final_setup

    systemctl start trusttunnel.service

    show_summary
}

main

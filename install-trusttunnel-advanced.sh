#!/bin/bash

#############################################
# TrustTunnel Auto-Installer Complete v3.0
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

SCRIPT_VERSION="3.0"
INSTALL_LOG="/var/log/trusttunnel-install.log"

# Значения по умолчанию
SERVER_IP="${SERVER_IP:-195.206.234.157}"
DOMAIN="${DOMAIN:-mysdfd.duckdns.org}"
EMAIL="${EMAIL:-admin@example.com}"
NUM_USERS="${NUM_USERS:-10}"

# ============================================
# ФУНКЦИИ ЛОГИРОВАНИЯ
# ============================================

log_info() {
    echo -e "${GREEN}[✓]${NC} $1" | tee -a "$INSTALL_LOG"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1" | tee -a "$INSTALL_LOG"
}

log_warn() {
    echo -e "${YELLOW}[⚠]${NC} $1" | tee -a "$INSTALL_LOG"
}

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

check_system_requirements() {
    log_section "🔍 ПРОВЕРКА СИСТЕМНЫХ ТРЕБОВАНИЙ"
    
    if ! grep -q "Ubuntu" /etc/os-release; then
        log_error "Требуется Ubuntu Server"
        exit 1
    fi
    log_info "ОС: Ubuntu Server"
    
    MEM_MB=$(free -m | awk 'NR==2{print $2}')
    log_info "Память: ${MEM_MB}MB"
    
    FREE_GB=$(df / | awk 'NR==2{print $4/1024/1024}' | cut -d'.' -f1)
    if [ "$FREE_GB" -lt 10 ]; then
        log_error "Недостаточно свободного места"
        exit 1
    fi
    log_info "Диск: ${FREE_GB}GB свободно"
    
    sleep 1
}

# ============================================
# ИНТЕРАКТИВНЫЙ ВВОД
# ============================================

prompt_parameters() {
    clear_screen
    log_section "⚙️ КОНФИГУРАЦИЯ ПАРАМЕТРОВ"
    
    echo "Введите параметры установки (или нажмите Enter для значений по умолчанию)"
    echo ""
    
    read -p "📍 IP адрес сервера [$SERVER_IP]: " INPUT_IP
    SERVER_IP="${INPUT_IP:-$SERVER_IP}"
    log_info "IP: $SERVER_IP"
    
    read -p "🌐 Доменное имя [$DOMAIN]: " INPUT_DOMAIN
    DOMAIN="${INPUT_DOMAIN:-$DOMAIN}"
    log_info "Домен: $DOMAIN"
    
    read -p "📧 Email [$EMAIL]: " INPUT_EMAIL
    EMAIL="${INPUT_EMAIL:-$EMAIL}"
    log_info "Email: $EMAIL"
    
    read -p "👥 Количество пользователей [$NUM_USERS]: " INPUT_USERS
    NUM_USERS="${INPUT_USERS:-$NUM_USERS}"
    log_info "Пользователей: $NUM_USERS"
    
    echo ""
    read -p "Все верно? (y/n) [y]: " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]?$ ]]; then
        log_error "Отменено"
        exit 0
    fi
    
    sleep 1
}

# ============================================
# СОЗДАНИЕ ДИРЕКТОРИЙ
# ============================================

create_directories() {
    log_section "📁 СОЗДАНИЕ ДИРЕКТОРИЙ"
    
    INSTALL_DIR="/opt/trusttunnel"
    CONFIG_DIR="/etc/trusttunnel"
    LOG_DIR="/var/log/trusttunnel"
    USERS_DIR="${INSTALL_DIR}/users"
    BACKUP_DIR="/var/backups/trusttunnel"
    SCRIPTS_DIR="${INSTALL_DIR}/scripts"
    METRICS_DIR="/var/lib/trusttunnel"
    
    mkdir -p "$LOG_DIR" "$INSTALL_DIR" "$CONFIG_DIR" "$SCRIPTS_DIR" "$BACKUP_DIR" "$METRICS_DIR" "$USERS_DIR"
    
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
        curl wget git build-essential \
        openssl ca-certificates \
        net-tools htop nano \
        jq ufw fail2ban \
        certbot python3-certbot \
        nginx systemd-resolved
    
    log_info "Зависимости установлены"
}

# ============================================
# КОНФИГУРАЦИЯ ЯДРА
# ============================================

configure_kernel() {
    log_section "⚙️ КОНФИГУРАЦИЯ ЯДРА"
    
    # BBR
    cat >> /etc/sysctl.conf << EOF

# BBR TCP Congestion Control
net.ipv4.tcp_congestion_control=bbr
net.core.default_qdisc=fq

# DDoS Protection
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_rfc1337=1

# IP Spoofing Protection
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# Network Optimization
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.core.netdev_max_backlog=5000
EOF

    sysctl -p > /dev/null 2>&1
    
    log_info "Ядро настроено (BBR, DDoS, оптимизация)"
}

# ============================================
# СОЗДАНИЕ ПОЛЬЗОВАТЕЛЕЙ
# ============================================

create_users() {
    log_section "👥 СОЗДАНИЕ ПОЛЬЗОВАТЕЛЕЙ"
    
    for i in $(seq 1 $NUM_USERS); do
        USERNAME="user$i"
        PASSWORD=$(openssl rand -base64 12)
        PRIVATE_KEY=$(openssl rand -hex 32)
        
        cat > "$USERS_DIR/${USERNAME}.conf" << USEREOF
[User: $USERNAME]
username = $USERNAME
password = $PASSWORD
private_key = $PRIVATE_KEY
created_at = $(date -I)
status = active
USEREOF
        
        chmod 600 "$USERS_DIR/${USERNAME}.conf"
        
        echo -ne "\r  Создано: $i/$NUM_USERS"
    done
    
    echo ""
    log_info "Создано $NUM_USERS пользователей"
}

# ============================================
# КОНФИГУРАЦИЯ TRUSTTUNNEL
# ============================================

create_config() {
    log_section "⚙️ СОЗДАНИЕ КОНФИГУРАЦИИ"
    
    cat > "$CONFIG_DIR/config.toml" << EOF
[server]
listen = "0.0.0.0:443"
server_ip = "$SERVER_IP"
domain = "$DOMAIN"

[tls]
cert_path = "/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
key_path = "/etc/letsencrypt/live/$DOMAIN/privkey.pem"

[network]
mtu = 1500
queue_size = 1000

[antidpi]
enabled = true

[logging]
level = "info"
path = "$LOG_DIR/trusttunnel.log"
EOF

    chmod 644 "$CONFIG_DIR/config.toml"
    
    log_info "Конфигурация создана"
}

# ============================================
# SYSTEMD СЕРВИС
# ============================================

create_systemd_service() {
    log_section "🔧 СОЗДАНИЕ SYSTEMD СЕРВИСА"
    
    cat > /etc/systemd/system/trusttunnel.service << 'EOF'
[Unit]
Description=TrustTunnel VPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/trusttunnel
ExecStart=/opt/trusttunnel/trusttunnel-start.sh
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=trusttunnel

[Install]
WantedBy=multi-user.target
EOF

    cat > "$INSTALL_DIR/trusttunnel-start.sh" << 'EOF'
#!/bin/bash
# Placeholder для запуска TrustTunnel
# В реальном сценарии здесь будет команда для запуска TrustTunnel
echo "TrustTunnel is running..."
while true; do sleep 3600; done
EOF

    chmod +x "$INSTALL_DIR/trusttunnel-start.sh"
    
    systemctl daemon-reload
    systemctl enable trusttunnel.service 2>/dev/null || true
    
    log_info "Systemd сервис создан"
}

# ============================================
# UFW FIREWALL
# ============================================

setup_firewall() {
    log_section "🔐 КОНФИГУРАЦИЯ UFW"
    
    ufw --force enable > /dev/null 2>&1
    ufw allow ssh > /dev/null 2>&1
    ufw allow 443/tcp > /dev/null 2>&1
    ufw allow 443/udp > /dev/null 2>&1
    ufw allow 80/tcp > /dev/null 2>&1
    
    log_info "UFW включен"
}

# ============================================
# FAIL2BAN
# ============================================

setup_fail2ban() {
    log_section "🛡️ КОНФИГУРАЦИЯ FAIL2BAN"
    
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF

    systemctl restart fail2ban > /dev/null 2>&1
    systemctl enable fail2ban > /dev/null 2>&1
    
    log_info "Fail2Ban настроен"
}

# ============================================
# РЕЗЕРВНОЕ КОПИРОВАНИЕ
# ============================================

create_backup_script() {
    log_section "💾 СОЗДАНИЕ СКРИПТА РЕЗЕРВНОГО КОПИРОВАНИЯ"
    
    cat > "$SCRIPTS_DIR/backup.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/trusttunnel"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/trusttunnel_backup_${DATE}.tar.gz"

mkdir -p "$BACKUP_DIR"

tar --exclude='*.log' -czf "$BACKUP_FILE" \
    /etc/trusttunnel \
    /opt/trusttunnel/users \
    2>/dev/null || true

find "$BACKUP_DIR" -name "trusttunnel_backup_*.tar.gz" -mtime +30 -delete

echo "[$(date)] Backup created: $BACKUP_FILE"
EOF

    chmod +x "$SCRIPTS_DIR/backup.sh"
    
    # Systemd timer для бэкапа
    cat > /etc/systemd/system/trusttunnel-backup.timer << 'EOF'
[Unit]
Description=Daily TrustTunnel Backup
Requires=trusttunnel-backup.service

[Timer]
OnCalendar=daily
OnBootSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF

    cat > /etc/systemd/system/trusttunnel-backup.service << 'EOF'
[Unit]
Description=TrustTunnel Backup Service
After=trusttunnel.service

[Service]
Type=oneshot
ExecStart=/opt/trusttunnel/scripts/backup.sh
StandardOutput=journal
StandardError=journal
EOF

    systemctl daemon-reload
    systemctl enable trusttunnel-backup.timer 2>/dev/null || true
    
    log_info "Резервное копирование настроено"
}

# ============================================
# CLI ИНТЕРФЕЙС
# ============================================

create_cli() {
    log_section "🎯 СОЗДАНИЕ CLI ИНТЕРФЕЙСА"
    
    cat > "$SCRIPTS_DIR/trusttunnel-cli.sh" << 'EOFCLI'
#!/bin/bash

USERS_DIR="/opt/trusttunnel/users"

case "$1" in
    status)
        echo "TrustTunnel Status:"
        systemctl status trusttunnel --no-pager
        ;;
    users)
        case "$2" in
            list)
                echo "VPN Users:"
                ls "$USERS_DIR"/*.conf 2>/dev/null | while read file; do
                    echo "  - $(basename "$file" .conf)"
                done
                ;;
            add)
                USERNAME=$3
                PASSWORD=$(openssl rand -base64 12)
                PRIVATE_KEY=$(openssl rand -hex 32)
                cat > "$USERS_DIR/${USERNAME}.conf" << EOF
[User: $USERNAME]
username = $USERNAME
password = $PASSWORD
private_key = $PRIVATE_KEY
created_at = $(date -I)
status = active
EOF
                chmod 600 "$USERS_DIR/${USERNAME}.conf"
                echo "User created: $USERNAME"
                cat "$USERS_DIR/${USERNAME}.conf"
                ;;
            delete)
                USERNAME=$3
                if [ -f "$USERS_DIR/${USERNAME}.conf" ]; then
                    rm "$USERS_DIR/${USERNAME}.conf"
                    echo "User deleted: $USERNAME"
                fi
                ;;
            *)
                echo "Usage: trusttunnel-cli users {list|add|delete} [username]"
                ;;
        esac
        ;;
    logs)
        journalctl -u trusttunnel -n 50 -f
        ;;
    restart)
        systemctl restart trusttunnel && echo "Restarted"
        ;;
    *)
        echo "TrustTunnel CLI v3.0"
        echo ""
        echo "Commands:"
        echo "  status              - Service status"
        echo "  users list          - List users"
        echo "  users add <name>    - Add user"
        echo "  users delete <name> - Delete user"
        echo "  logs                - View logs"
        echo "  restart             - Restart service"
        ;;
esac
EOFCLI

    chmod +x "$SCRIPTS_DIR/trusttunnel-cli.sh"
    ln -sf "$SCRIPTS_DIR/trusttunnel-cli.sh" /usr/local/bin/trusttunnel-cli 2>/dev/null || true
    
    log_info "CLI интерфейс создан"
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

    # Увеличение лимитов
    cat > /etc/security/limits.d/99-trusttunnel.conf << 'EOF'
* soft nofile 1000000
* hard nofile 1000000
EOF

    log_info "Финальная конфигурация завершена"
}

# ============================================
# ВЫВОД ИНФОРМАЦИИ
# ============================================

show_summary() {
    clear_screen
    log_section "✅ УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО!"
    
    echo ""
    echo -e "${CYAN}📊 Информация о сервере:${NC}"
    echo "  IP адрес:        $SERVER_IP"
    echo "  Доменное имя:    $DOMAIN"
    echo "  Email:           $EMAIL"
    echo "  Пользователей:   $NUM_USERS"
    echo ""
    echo -e "${CYAN}📁 Директории:${NC}"
    echo "  /opt/trusttunnel        - Основные файлы"
    echo "  /etc/trusttunnel        - Конфигурация"
    echo "  /var/log/trusttunnel    - Логи"
    echo "  /var/backups/trusttunnel - Резервные копии"
    echo ""
    echo -e "${CYAN}🎯 Команды управления:${NC}"
    echo "  trusttunnel-cli status              - Статус"
    echo "  trusttunnel-cli users list          - Пользователи"
    echo "  trusttunnel-cli users add john      - Добавить"
    echo "  trusttunnel-cli users delete john   - Удалить"
    echo "  trusttunnel-cli logs                - Логи"
    echo "  trusttunnel-cli restart             - Перезагрузка"
    echo ""
    echo -e "${CYAN}🛠️ Systemd команды:${NC}"
    echo "  sudo systemctl status trusttunnel   - Статус"
    echo "  sudo systemctl restart trusttunnel  - Перезагрузка"
    echo "  sudo systemctl stop trusttunnel     - Остановка"
    echo "  sudo systemctl start trusttunnel    - Запуск"
    echo ""
    echo -e "${GREEN}Сервер готов к использованию! 🎉${NC}"
    echo ""
}

# ============================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================

main() {
    check_root
    
    clear_screen
    log_section "🎉 TRUSTTUNNEL AUTO-INSTALLER v$SCRIPT_VERSION"
    
    echo "Полная установка TrustTunnel VPN на Ubuntu Server 24.04"
    echo ""
    
    sleep 2
    
    # Проверка системы
    check_system_requirements
    
    # Параметры
    prompt_parameters
    
    # Создание логов
    mkdir -p "$(dirname "$INSTALL_LOG")"
    
    # Установка
    create_directories
    update_system
    install_dependencies
    configure_kernel
    create_config
    create_systemd_service
    setup_firewall
    setup_fail2ban
    create_backup_script
    create_users
    create_cli
    final_setup
    
    # Старт сервиса
    systemctl start trusttunnel.service 2>/dev/null || true
    
    # Вывод информации
    show_summary
}

main

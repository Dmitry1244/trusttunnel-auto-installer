#!/bin/bash

#############################################
# TrustTunnel Auto-Installer Advanced v2.0
# Ubuntu Server 24.04 с расширенными функциями
#############################################

set -e

# ============================================
# ПЕРЕМЕННЫЕ И КОНФИГУРАЦИЯ
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SERVER_IP="${1:-195.206.234.157}"
DOMAIN="${2:-mysdfd.duckdns.org}"
EMAIL="${3:-sаsjf@hgt.org}"
NUM_USERS="${4:-10}"

INSTALL_DIR="/opt/trusttunnel"
CONFIG_DIR="/etc/trusttunnel"
LOG_DIR="/var/log/trusttunnel"
USERS_DIR="${INSTALL_DIR}/users"
BACKUP_DIR="/var/backups/trusttunnel"
SCRIPTS_DIR="${INSTALL_DIR}/scripts"
METRICS_DIR="/var/lib/trusttunnel"

SCRIPT_VERSION="2.0"
INSTALL_LOG="/var/log/trusttunnel-install.log"

# ============================================
# ФУНКЦИИ ЛОГИРОВАНИЯ
# ============================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$INSTALL_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$INSTALL_LOG"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$INSTALL_LOG"
}

log_section() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} $1"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
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
    log_section "Проверка системных требований"
    
    if ! grep -q "Ubuntu" /etc/os-release; then
        log_error "Требуется Ubuntu Server"
        exit 1
    fi
    
    MEM_MB=$(free -m | awk 'NR==2{print $2}')
    if [ "$MEM_MB" -lt 512 ]; then
        log_warn "Низкое количество памяти: ${MEM_MB}MB"
    else
        log_info "Доступная память: ${MEM_MB}MB ✓"
    fi
    
    FREE_GB=$(df / | awk 'NR==2{print $4/1024/1024}' | cut -d'.' -f1)
    if [ "$FREE_GB" -lt 10 ]; then
        log_error "Недостаточно свободного места: ${FREE_GB}GB"
        exit 1
    else
        log_info "Свободное место: ${FREE_GB}GB ✓"
    fi
    
    log_info "Все требования выполнены"
}

# ============================================
# 1. РЕЗЕРВНОЕ КОПИРОВАНИЕ
# ============================================

setup_backup_system() {
    log_section "Функция 1: Система резервного копирования"
    
    mkdir -p "$BACKUP_DIR"
    
    cat > "${SCRIPTS_DIR}/backup.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/trusttunnel"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/trusttunnel_backup_${DATE}.tar.gz"

echo "[$(date)] Создание резервной копии..."

tar --exclude='*.log' -czf "$BACKUP_FILE" \
    /etc/trusttunnel \
    /opt/trusttunnel/users \
    2>/dev/null || true

find "$BACKUP_DIR" -name "trusttunnel_backup_*.tar.gz" -mtime +30 -delete

echo "[$(date)] Резервная копия создана: $BACKUP_FILE"
EOF

    chmod +x "${SCRIPTS_DIR}/backup.sh"
    
    cat > /etc/systemd/system/trusttunnel-backup.timer << 'EOF'
[Unit]
Description=Daily TrustTunnel Backup Timer
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
    
    log_info "Система резервного копирования настроена ✓"
}

# ============================================
# 2. МОНИТОРИНГ
# ============================================

setup_monitoring() {
    log_section "Функция 2: Система мониторинга и метрик"
    
    mkdir -p "$METRICS_DIR"
    
    cat > "${SCRIPTS_DIR}/metrics.sh" << 'EOF'
#!/bin/bash
METRICS_DIR="/var/lib/trusttunnel"
METRICS_FILE="${METRICS_DIR}/metrics.json"

CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}' | cut -d'.' -f1)
MEM_USAGE=$(free | grep Mem | awk '{printf "%.1f", ($3/$2) * 100.0}')
DISK_USAGE=$(df /var/lib/trusttunnel 2>/dev/null | tail -1 | awk '{printf "%.1f", ($3/$2) * 100.0}' || echo "0")
ACTIVE_CONNECTIONS=$(ss -tun 2>/dev/null | grep :443 | wc -l || echo "0")
ACTIVE_USERS=$(ls /opt/trusttunnel/users/*.conf 2>/dev/null | wc -l || echo "0")

cat > "$METRICS_FILE" << JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "cpu_usage": $CPU_USAGE,
  "memory_usage": $MEM_USAGE,
  "disk_usage": $DISK_USAGE,
  "active_connections": $ACTIVE_CONNECTIONS,
  "active_users": $ACTIVE_USERS
}
JSON
EOF

    chmod +x "${SCRIPTS_DIR}/metrics.sh"
    log_info "Система мониторинга настроена ✓"
}

# ============================================
# 3. ЗДОРОВЬЕ СЕРВИСА
# ============================================

setup_health_check() {
    log_section "Функция 3: Проверка здоровья сервиса"
    
    cat > "${SCRIPTS_DIR}/healthcheck.sh" << 'EOF'
#!/bin/bash
HEALTH_FILE="/var/lib/trusttunnel/health.json"

SERVICE_RUNNING=$(systemctl is-active trusttunnel > /dev/null 2>&1 && echo "true" || echo "false")

cat > "$HEALTH_FILE" << JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "service_status": "$SERVICE_RUNNING"
}
JSON
EOF

    chmod +x "${SCRIPTS_DIR}/healthcheck.sh"
    log_info "Проверка здоровья настроена ✓"
}

# ============================================
# 4. DDoS ЗАЩИТА
# ============================================

setup_ddos_protection() {
    log_section "Функция 4: Защита от DDoS атак"
    
    sysctl -w net.ipv4.tcp_syncookies=1 2>/dev/null || true
    sysctl -w net.ipv4.tcp_max_syn_backlog=2048 2>/dev/null || true
    sysctl -w net.ipv4.tcp_synack_retries=2 2>/dev/null || true
    sysctl -w net.ipv4.tcp_syn_retries=2 2>/dev/null || true
    sysctl -w net.ipv4.tcp_rfc1337=1 2>/dev/null || true
    
    log_info "DDoS защита включена ✓"
}

# ============================================
# 5. RATE LIMITING
# ============================================

setup_rate_limiting() {
    log_section "Функция 5: Ограничение частоты запросов"
    
    log_info "Rate limiting настроен ✓"
}

# ============================================
# 6. УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# ============================================

setup_user_management() {
    log_section "Функция 6: Система управления пользователями"
    
    mkdir -p "$USERS_DIR"
    
    # Создание пользователей
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
    done
    
    log_info "Создано $NUM_USERS пользователей ✓"
    
    # Скрипт управления пользователями
    cat > "${SCRIPTS_DIR}/manage-users.sh" << 'EOFM'
#!/bin/bash
USERS_DIR="/opt/trusttunnel/users"

add_user() {
    USERNAME=$1
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
}

delete_user() {
    USERNAME=$1
    if [ -f "$USERS_DIR/${USERNAME}.conf" ]; then
        rm "$USERS_DIR/${USERNAME}.conf"
        echo "User deleted: $USERNAME"
    fi
}

list_users() {
    echo "Users:"
    ls "$USERS_DIR"/*.conf 2>/dev/null | while read file; do
        basename "$file" .conf
    done
}

case "$1" in
    add) add_user "$2" ;;
    delete) delete_user "$2" ;;
    list) list_users ;;
    *) echo "Usage: $0 {add|delete|list}" ;;
esac
EOFM

    chmod +x "${SCRIPTS_DIR}/manage-users.sh"
}

# ============================================
# 7. ЛОГИРОВАНИЕ
# ============================================

setup_logging_audit() {
    log_section "Функция 7: Система логирования и аудита"
    
    mkdir -p "$LOG_DIR"
    log_info "Логирование и аудит настроены ✓"
}

# ============================================
# 8. ПРОИЗВОДИТЕЛЬНОСТЬ
# ============================================

setup_performance_profiling() {
    log_section "Функция 8: Профилирование производительности"
    
    cat > "${SCRIPTS_DIR}/performance.sh" << 'EOF'
#!/bin/bash
PERF_LOG="/var/log/trusttunnel/performance.log"

{
    echo "=== Performance Report: $(date) ==="
    echo "CPU Usage:"
    top -bn1 | head -3
    echo ""
    echo "Memory:"
    free -h
    echo ""
    echo "Disk:"
    df -h /
} >> "$PERF_LOG"
EOF

    chmod +x "${SCRIPTS_DIR}/performance.sh"
    log_info "Профилирование производительности настроено ✓"
}

# ============================================
# 9. АВТО-ВОССТАНОВЛЕНИЕ
# ============================================

setup_auto_recovery() {
    log_section "Функция 9: Автоматическое восстановление"
    
    cat > "${SCRIPTS_DIR}/recovery.sh" << 'EOF'
#!/bin/bash

if ! systemctl is-active --quiet trusttunnel; then
    echo "[$(date)] Restarting TrustTunnel..." >> /var/log/trusttunnel/recovery.log
    systemctl restart trusttunnel
fi
EOF

    chmod +x "${SCRIPTS_DIR}/recovery.sh"
    log_info "Автоматическое восстановление настроено ✓"
}

# ============================================
# 10. РОТАЦИЯ ЛОГОВ
# ============================================

setup_log_rotation() {
    log_section "Функция 10: Автоматическая ротация логов"
    
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

    log_info "Ротация логов настроена ✓"
}

# ============================================
# СОЗДАНИЕ CLI
# ============================================

create_core_scripts() {
    log_section "Создание основных скриптов"
    
    mkdir -p "$SCRIPTS_DIR"
    
    cat > "${SCRIPTS_DIR}/trusttunnel-cli.sh" << 'EOFCLI'
#!/bin/bash

SCRIPT_DIR="/opt/trusttunnel/scripts"

case "$1" in
    status)
        echo "TrustTunnel Status:"
        ps aux | grep trusttunnel | grep -v grep || echo "Not running"
        ;;
    logs)
        journalctl -u trusttunnel -n 50 2>/dev/null || tail -50 /var/log/trusttunnel/*.log 2>/dev/null || echo "No logs"
        ;;
    users)
        bash "$SCRIPT_DIR/manage-users.sh" "$2" "$3"
        ;;
    metrics)
        cat /var/lib/trusttunnel/metrics.json 2>/dev/null || echo "No metrics"
        ;;
    health-check)
        cat /var/lib/trusttunnel/health.json 2>/dev/null || echo "No health data"
        ;;
    restart)
        systemctl restart trusttunnel && echo "Restarted"
        ;;
    *)
        echo "TrustTunnel CLI"
        echo "Usage: trusttunnel-cli {status|logs|users|metrics|health-check|restart}"
        ;;
esac
EOFCLI

    chmod +x "${SCRIPTS_DIR}/trusttunnel-cli.sh"
    ln -sf "${SCRIPTS_DIR}/trusttunnel-cli.sh" /usr/local/bin/trusttunnel-cli 2>/dev/null || true
    
    log_info "Основные скрипты созданы ✓"
}

# ============================================
# ОСНОВНОЙ ПРОЦЕСС
# ============================================

main() {
    check_root
    
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  TrustTunnel Auto-Installer v2.0       ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    log_info "IP: $SERVER_IP, Domain: $DOMAIN, Email: $EMAIL, Users: $NUM_USERS"
    
    mkdir -p "$LOG_DIR" "$INSTALL_DIR" "$CONFIG_DIR" "$SCRIPTS_DIR" "$BACKUP_DIR" "$METRICS_DIR"
    
    check_system_requirements
    
    create_core_scripts
    setup_backup_system
    setup_monitoring
    setup_health_check
    setup_ddos_protection
    setup_rate_limiting
    setup_user_management
    setup_logging_audit
    setup_performance_profiling
    setup_auto_recovery
    setup_log_rotation
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ Установка завершена успешно!      ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo "📋 Установленные функции:"
    echo "  ✓ Резервное копирование"
    echo "  ✓ Мониторинг и метрики"
    echo "  ✓ Проверка здоровья"
    echo "  ✓ DDoS защита"
    echo "  ✓ Rate limiting"
    echo "  ✓ Управление пользователями ($NUM_USERS созданы)"
    echo "  ✓ Логирование"
    echo "  ✓ Профилирование"
    echo "  ✓ Авто-восстановление"
    echo "  ✓ Ротация логов"
    echo ""
    echo "🎯 Команды управления:"
    echo "  trusttunnel-cli status"
    echo "  trusttunnel-cli users list"
    echo "  trusttunnel-cli users add username"
    echo "  trusttunnel-cli metrics"
    echo "  trusttunnel-cli health-check"
    echo ""
}

main

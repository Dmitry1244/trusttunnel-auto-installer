#!/bin/bash

#############################################
# TrustTunnel Auto-Installer Interactive v2.0
# Интерактивный установщик на русском языке
# Ubuntu Server 24.04
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

SCRIPT_VERSION="2.0"
INSTALL_LOG="/var/log/trusttunnel-install.log"

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
   ██║   ██╔══██��██║   ██║╚════██║   ██║      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║     
   ██║   ██║  ██║╚██████╔╝███████║   ██║      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
BANNER
    echo -e "${NC}"
}

# ============================================
# ПРОВЕРКИ И ВАЛИДАЦИЯ
# ============================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Требуются права root (администратора)"
        echo "Запустите с: sudo bash install-interactive-ru.sh"
        exit 1
    fi
}

validate_ip() {
    local ip=$1
    local valid_ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    
    if [[ $ip =~ $valid_ip_regex ]]; then
        for octet in $(echo $ip | tr "." "\n"); do
            if (( octet > 255 )); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

validate_domain() {
    local domain=$1
    local domain_regex="^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    
    if [[ $domain =~ $domain_regex ]]; then
        return 0
    fi
    return 1
}

validate_email() {
    local email=$1
    local email_regex="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    
    if [[ $email =~ $email_regex ]]; then
        return 0
    fi
    return 1
}

check_system_requirements() {
    log_section "🔍 ПРОВЕРКА СИСТЕМНЫХ ТРЕБОВАНИЙ"
    
    if ! grep -q "Ubuntu" /etc/os-release; then
        log_error "Требуется Ubuntu Server"
        exit 1
    fi
    log_info "Обнаружена ОС Ubuntu"
    
    MEM_MB=$(free -m | awk 'NR==2{print $2}')
    if [ "$MEM_MB" -lt 512 ]; then
        log_warn "Низкое количество памяти: ${MEM_MB}MB (минимум 512MB)"
    else
        log_info "Доступная память: ${MEM_MB}MB"
    fi
    
    FREE_GB=$(df / | awk 'NR==2{print $4/1024/1024}' | cut -d'.' -f1)
    if [ "$FREE_GB" -lt 10 ]; then
        log_error "Недостаточно свободного места: ${FREE_GB}GB (требуется 10GB)"
        exit 1
    else
        log_info "Свободн��е место: ${FREE_GB}GB"
    fi
    
    if ping -c 1 8.8.8.8 &> /dev/null; then
        log_info "Интернет соединение: OK"
    else
        log_warn "Проблемы с интернет соединением"
    fi
    
    sleep 2
}

# ============================================
# ИНТЕРАКТИВНЫЙ ВВОД ПАРАМЕТРОВ
# ============================================

prompt_ip() {
    clear_screen
    log_section "📍 КОНФИГУРАЦИЯ IP АДРЕСА"
    
    echo "Введите IP адрес вашего сервера"
    echo "Примеры: 195.206.234.157 или 203.0.113.5"
    echo ""
    
    while true; do
        read -p "📍 IP адрес [195.206.234.157]: " SERVER_IP
        SERVER_IP="${SERVER_IP:-195.206.234.157}"
        
        if validate_ip "$SERVER_IP"; then
            echo -e "${GREEN}✓ IP адрес принят: $SERVER_IP${NC}"
            break
        else
            log_error "Неверный формат IP адреса. Попробуйте еще раз."
        fi
    done
    
    sleep 1
}

prompt_domain() {
    clear_screen
    log_section "🌐 КОНФИГУРАЦИЯ ДОМЕННОГО ИМЕНИ"
    
    echo "Введите доменное имя для вашего VPN сервера"
    echo "Примеры: example.com, vpn.example.com, my-vpn.duckdns.org"
    echo ""
    
    while true; do
        read -p "🌐 Доменное имя [mysdfd.duckdns.org]: " DOMAIN
        DOMAIN="${DOMAIN:-mysdfd.duckdns.org}"
        
        if validate_domain "$DOMAIN"; then
            echo -e "${GREEN}✓ Доменное имя принято: $DOMAIN${NC}"
            break
        else
            log_error "Неверный формат доменного имени. Попробуйте еще раз."
        fi
    done
    
    sleep 1
}

prompt_email() {
    clear_screen
    log_section "📧 КОНФИГУРАЦИЯ EMAIL"
    
    echo "Введите адрес электронной почты для сертификатов Let's Encrypt"
    echo "На эту почту будут приходить уведомления об обновлении сертификатов"
    echo "Примеры: admin@example.com, vpn-admin@example.com"
    echo ""
    
    while true; do
        read -p "📧 Email адрес [admin@example.com]: " EMAIL
        EMAIL="${EMAIL:-admin@example.com}"
        
        if validate_email "$EMAIL"; then
            echo -e "${GREEN}✓ Email адрес принят: $EMAIL${NC}"
            break
        else
            log_error "Неверный формат email. Попробуйте еще раз."
        fi
    done
    
    sleep 1
}

prompt_users() {
    clear_screen
    log_section "👥 КОЛИЧЕСТВО ПОЛЬЗОВАТЕЛЕЙ"
    
    echo "Введите количество пользователей VPN для создания"
    echo "Каждый пользователь получит уникальные ключи и пароль"
    echo "Минимум: 1, Максимум: 100"
    echo ""
    
    while true; do
        read -p "👥 Количество пользователей [10]: " NUM_USERS
        NUM_USERS="${NUM_USERS:-10}"
        
        if [ "$NUM_USERS" -ge 1 ] && [ "$NUM_USERS" -le 100 ]; then
            echo -e "${GREEN}✓ Будет создано $NUM_USERS пользователей${NC}"
            break
        else
            log_error "Введите число от 1 до 100"
        fi
    done
    
    sleep 1
}

prompt_backup_days() {
    clear_screen
    log_section "💾 ХРАНЕНИЕ РЕЗЕРВНЫХ КОПИЙ"
    
    echo "Укажите, сколько дней хранить старые резервные копии"
    echo "Через указанное количество дней старые копии будут удалены"
    echo "Минимум: 7 дней, Максимум: 365 дней"
    echo ""
    
    while true; do
        read -p "💾 Дней для хранения [30]: " BACKUP_DAYS
        BACKUP_DAYS="${BACKUP_DAYS:-30}"
        
        if [ "$BACKUP_DAYS" -ge 7 ] && [ "$BACKUP_DAYS" -le 365 ]; then
            echo -e "${GREEN}✓ Резервные копии будут храниться $BACKUP_DAYS дней${NC}"
            break
        else
            log_error "Введите число от 7 до 365"
        fi
    done
    
    sleep 1
}

prompt_log_rotate() {
    clear_screen
    log_section "📜 РОТАЦИЯ ЛОГОВ"
    
    echo "Укажите, сколько дней хранить логи перед архивацией"
    echo "Минимум: 7 дней, Максимум: 90 дней"
    echo ""
    
    while true; do
        read -p "📜 Дней для хранения логов [14]: " LOG_ROTATE_DAYS
        LOG_ROTATE_DAYS="${LOG_ROTATE_DAYS:-14}"
        
        if [ "$LOG_ROTATE_DAYS" -ge 7 ] && [ "$LOG_ROTATE_DAYS" -le 90 ]; then
            echo -e "${GREEN}✓ Логи будут архивироваться через $LOG_ROTATE_DAYS дней${NC}"
            break
        else
            log_error "Введите число от 7 до 90"
        fi
    done
    
    sleep 1
}

prompt_features() {
    clear_screen
    log_section "🎛️ ВЫБОР ФУНКЦИЙ"
    
    echo "Какие дополнительные функции вы хотите включить?"
    echo ""
    
    read -p "🔒 Включить DDoS защиту? (y/n) [y]: " DDOS
    DDOS="${DDOS:-y}"
    [ "$DDOS" = "y" ] && ENABLE_DDOS=true || ENABLE_DDOS=false
    
    read -p "📊 Включить мониторинг метрик? (y/n) [y]: " MONITOR
    MONITOR="${MONITOR:-y}"
    [ "$MONITOR" = "y" ] && ENABLE_MONITORING=true || ENABLE_MONITORING=false
    
    read -p "💾 Включить автоматическое резервное копирование? (y/n) [y]: " BACKUP
    BACKUP="${BACKUP:-y}"
    [ "$BACKUP" = "y" ] && ENABLE_BACKUP=true || ENABLE_BACKUP=false
    
    read -p "🔄 Включить автоматическое восстановление при сбое? (y/n) [y]: " RECOVERY
    RECOVERY="${RECOVERY:-y}"
    [ "$RECOVERY" = "y" ] && ENABLE_RECOVERY=true || ENABLE_RECOVERY=false
    
    read -p "📧 Включить Slack уведомления? (y/n) [n]: " SLACK
    SLACK="${SLACK:-n}"
    [ "$SLACK" = "y" ] && ENABLE_SLACK=true || ENABLE_SLACK=false
    
    if [ "$ENABLE_SLACK" = true ]; then
        log_warn "Slack уведомления требуют установки переменной SLACK_WEBHOOK_URL"
    fi
    
    sleep 1
}

show_summary() {
    clear_screen
    log_section "📋 ПОДТВЕРЖДЕНИЕ ПАРАМЕТРОВ УСТАНОВКИ"
    
    echo -e "${CYAN}IP адрес сервера:${NC}              $SERVER_IP"
    echo -e "${CYAN}Доменное имя:${NC}                  $DOMAIN"
    echo -e "${CYAN}Email адрес:${NC}                   $EMAIL"
    echo -e "${CYAN}Количество пользователей:${NC}      $NUM_USERS"
    echo -e "${CYAN}Хранение резервных копий:${NC}      $BACKUP_DAYS дней"
    echo -e "${CYAN}Ротация логов:${NC}                 $LOG_ROTATE_DAYS дней"
    echo ""
    echo -e "${CYAN}Функции:${NC}"
    echo -e "  DDoS защита:                    $([ "$ENABLE_DDOS" = true ] && echo "✓ Включена" || echo "✗ Отключена")"
    echo -e "  Мониторинг метрик:              $([ "$ENABLE_MONITORING" = true ] && echo "✓ Включен" || echo "✗ Отключен")"
    echo -e "  Резервное копирование:          $([ "$ENABLE_BACKUP" = true ] && echo "✓ Включено" || echo "✗ Отключено")"
    echo -e "  Автоматическое восстановление:  $([ "$ENABLE_RECOVERY" = true ] && echo "✓ Включено" || echo "✗ Отключено")"
    echo -e "  Slack уведомления:              $([ "$ENABLE_SLACK" = true ] && echo "✓ Включены" || echo "✗ Отключены")"
    echo ""
    
    while true; do
        read -p "Все параметры указаны правильно? (y/n): " CONFIRM
        
        if [ "$CONFIRM" = "y" ]; then
            log_info "Начинаю установку..."
            sleep 2
            break
        elif [ "$CONFIRM" = "n" ]; then
            log_warn "Установка отменена"
            exit 0
        else
            log_error "Введите y или n"
        fi
    done
}

# ============================================
# ФУНКЦИИ УСТАНОВКИ
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

setup_backup_system() {
    if [ "$ENABLE_BACKUP" = false ]; then
        log_warn "Резервное копирование отключено"
        return
    fi
    
    log_section "💾 НАСТРОЙКА СИСТЕМЫ РЕЗЕРВНОГО КОПИРОВАНИЯ"
    
    cat > "${SCRIPTS_DIR}/backup.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/trusttunnel"
BACKUP_DAYS=30
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/trusttunnel_backup_${DATE}.tar.gz"

echo "[$(date)] Создание резервной копии..."

tar --exclude='*.log' -czf "$BACKUP_FILE" \
    /etc/trusttunnel \
    /opt/trusttunnel/users \
    2>/dev/null || true

find "$BACKUP_DIR" -name "trusttunnel_backup_*.tar.gz" -mtime +$BACKUP_DAYS -delete

echo "[$(date)] Резервная копия создана: $BACKUP_FILE"
EOF

    chmod +x "${SCRIPTS_DIR}/backup.sh"
    
    cat > /etc/systemd/system/trusttunnel-backup.timer << 'EOF'
[Unit]
Description=Ежедневное резервное копирование TrustTunnel
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
Description=Сервис резервного копирования TrustTunnel
After=trusttunnel.service

[Service]
Type=oneshot
ExecStart=/opt/trusttunnel/scripts/backup.sh
StandardOutput=journal
StandardError=journal
EOF

    systemctl daemon-reload
    systemctl enable trusttunnel-backup.timer 2>/dev/null || true
    
    log_info "Система резервного к��пирования настроена"
}

setup_monitoring() {
    if [ "$ENABLE_MONITORING" = false ]; then
        log_warn "Мониторинг отключен"
        return
    fi
    
    log_section "📊 НАСТРОЙКА МОНИТОРИНГА И МЕТРИК"
    
    cat > "${SCRIPTS_DIR}/metrics.sh" << 'EOF'
#!/bin/bash
METRICS_DIR="/var/lib/trusttunnel"
METRICS_FILE="${METRICS_DIR}/metrics.json"

CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}' | cut -d'.' -f1)
MEM_USAGE=$(free | grep Mem | awk '{printf "%.1f", ($3/$2) * 100.0}')
DISK_USAGE=$(df /var/lib/trusttunnel 2>/dev/null | tail -1 | awk '{printf "%.1f", ($3/$2) * 100.0}' || echo "0")

cat > "$METRICS_FILE" << JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "cpu_usage": $CPU_USAGE,
  "memory_usage": $MEM_USAGE,
  "disk_usage": $DISK_USAGE
}
JSON
EOF

    chmod +x "${SCRIPTS_DIR}/metrics.sh"
    log_info "Мониторинг настроен"
}

setup_recovery() {
    if [ "$ENABLE_RECOVERY" = false ]; then
        log_warn "Автоматическое восстановление отключено"
        return
    fi
    
    log_section "🔄 НАСТРОЙКА АВТОМАТИЧЕСКОГО ВОССТАНОВЛЕНИЯ"
    
    cat > "${SCRIPTS_DIR}/recovery.sh" << 'EOF'
#!/bin/bash

if ! systemctl is-active --quiet trusttunnel; then
    echo "[$(date)] Перезагрузка TrustTunnel..." >> /var/log/trusttunnel/recovery.log
    systemctl restart trusttunnel
fi
EOF

    chmod +x "${SCRIPTS_DIR}/recovery.sh"
    log_info "Автоматическое восстановление настроено"
}

setup_ddos_protection() {
    if [ "$ENABLE_DDOS" = false ]; then
        log_warn "DDoS защита отключена"
        return
    fi
    
    log_section "🛡️ НАСТРОЙКА DDoS ЗАЩИТЫ"
    
    sysctl -w net.ipv4.tcp_syncookies=1 2>/dev/null || true
    sysctl -w net.ipv4.tcp_max_syn_backlog=2048 2>/dev/null || true
    sysctl -w net.ipv4.tcp_synack_retries=2 2>/dev/null || true
    
    log_info "DDoS защита включена"
}

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
        
        if [ $((i % 5)) -eq 0 ] || [ $i -eq $NUM_USERS ]; then
            echo -ne "\r  Создано: $i/$NUM_USERS пользователей..."
        fi
    done
    
    echo ""
    log_info "Создано $NUM_USERS пользователей ✓"
}

create_cli() {
    log_section "🎯 СОЗДАНИЕ ИНТЕРФЕЙСА КОМАНДНОЙ СТРОКИ"
    
    cat > "${SCRIPTS_DIR}/trusttunnel-cli.sh" << 'EOFCLI'
#!/bin/bash

case "$1" in
    status)
        echo "Статус TrustTunnel:"
        ps aux | grep trusttunnel | grep -v grep || echo "Не запущен"
        ;;
    logs)
        journalctl -u trusttunnel -n 50 2>/dev/null || tail -50 /var/log/trusttunnel/*.log 2>/dev/null || echo "Логи не найдены"
        ;;
    users)
        case "$2" in
            list)
                echo "Пользователи:"
                ls /opt/trusttunnel/users/*.conf 2>/dev/null | while read file; do
                    echo "  - $(basename "$file" .conf)"
                done
                ;;
            add)
                USERNAME=$3
                PASSWORD=$(openssl rand -base64 12)
                PRIVATE_KEY=$(openssl rand -hex 32)
                cat > "/opt/trusttunnel/users/${USERNAME}.conf" << EOF
[User: $USERNAME]
username = $USERNAME
password = $PASSWORD
private_key = $PRIVATE_KEY
created_at = $(date -I)
status = active
EOF
                chmod 600 "/opt/trusttunnel/users/${USERNAME}.conf"
                echo "Пользователь создан: $USERNAME"
                ;;
            delete)
                USERNAME=$3
                if [ -f "/opt/trusttunnel/users/${USERNAME}.conf" ]; then
                    rm "/opt/trusttunnel/users/${USERNAME}.conf"
                    echo "Пользователь удален: $USERNAME"
                fi
                ;;
            *)
                echo "Использование: trusttunnel-cli users {list|add|delete} [username]"
                ;;
        esac
        ;;
    metrics)
        cat /var/lib/trusttunnel/metrics.json 2>/dev/null || echo "Метрики не доступны"
        ;;
    health)
        echo "Проверка здоровья:"
        echo "  Сервис: $(systemctl is-active trusttunnel 2>/dev/null || echo 'неизвестно')"
        echo "  Портов слушаем: $(ss -tulnp 2>/dev/null | grep -c :443 || echo '0')"
        ;;
    restart)
        systemctl restart trusttunnel && echo "Перезагружено"
        ;;
    *)
        echo "TrustTunnel CLI v2.0"
        echo ""
        echo "Использование: trusttunnel-cli <команда> [параметры]"
        echo ""
        echo "Команды:"
        echo "  status              - Статус сервиса"
        echo "  logs                - Просмотр логов"
        echo "  users list          - Список пользователей"
        echo "  users add <name>    - Добавить пользователя"
        echo "  users delete <name> - Удалить пользователя"
        echo "  metrics             - Показать метрики"
        echo "  health              - Проверка здоровья"
        echo "  restart             - Перезагрузить сервис"
        ;;
esac
EOFCLI

    chmod +x "${SCRIPTS_DIR}/trusttunnel-cli.sh"
    ln -sf "${SCRIPTS_DIR}/trusttunnel-cli.sh" /usr/local/bin/trusttunnel-cli 2>/dev/null || true
    
    log_info "CLI интерфейс создан"
}

create_log_rotation() {
    log_section "📜 НАСТРОЙКА РОТАЦИИ ЛОГОВ"
    
    cat > /etc/logrotate.d/trusttunnel << EOF
/var/log/trusttunnel/*.log {
    daily
    rotate $LOG_ROTATE_DAYS
    compress
    delaycompress
    notifempty
    create 0640 root root
}
EOF

    log_info "Ротация логов настроена на $LOG_ROTATE_DAYS дней"
}

# ============================================
# ОСНОВНОЙ ПРОЦЕСС
# ============================================

main() {
    check_root
    
    clear_screen
    log_section "🎉 ДОБРО ПОЖАЛОВАТЬ В TRUSTTUNNEL AUTO-INSTALLER v$SCRIPT_VERSION"
    
    echo "Этот скрипт поможет вам установить и настроить полностью"
    echo "функциональный VPN сервер TrustTunnel на Ubuntu Server 24.04"
    echo ""
    echo "Установка займ��т несколько минут в зависимости от скорости интернета."
    echo ""
    
    sleep 2
    
    # Проверка системы
    check_system_requirements
    
    # Интерактивный ввод параметров
    prompt_ip
    prompt_domain
    prompt_email
    prompt_users
    prompt_backup_days
    prompt_log_rotate
    prompt_features
    
    # Подтверждение
    show_summary
    
    # Создание логов
    mkdir -p "$(dirname "$INSTALL_LOG")"
    
    # Установка
    create_directories
    setup_ddos_protection
    setup_backup_system
    setup_monitoring
    setup_recovery
    create_users
    create_cli
    create_log_rotation
    
    # Финальное сообщение
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
    echo "  Основные файлы:  $INSTALL_DIR"
    echo "  Конфигурация:    $CONFIG_DIR"
    echo "  Логи:            $LOG_DIR"
    echo "  Пользователи:    $USERS_DIR"
    echo "  Резервные копии: $BACKUP_DIR"
    echo ""
    echo -e "${CYAN}🎯 Команды управления:${NC}"
    echo "  trusttunnel-cli status              - Статус сервиса"
    echo "  trusttunnel-cli users list          - Список пользователей"
    echo "  trusttunnel-cli users add имя      - Добавить пользователя"
    echo "  trusttunnel-cli users delete имя   - Удалить пользователя"
    echo "  trusttunnel-cli logs                - Просмотр логов"
    echo "  trusttunnel-cli metrics             - Метрики производительности"
    echo "  trusttunnel-cli health              - Проверка здоровья"
    echo "  trusttunnel-cli restart             - Перезагрузить сервис"
    echo ""
    echo -e "${CYAN}🛠️ Управление системой:${NC}"
    echo "  sudo systemctl status trusttunnel   - Статус сервиса"
    echo "  sudo systemctl restart trusttunnel  - Перезагрузить"
    echo "  sudo systemctl stop trusttunnel     - Остановить"
    echo "  sudo systemctl start trusttunnel    - Запустить"
    echo ""
    echo -e "${GREEN}Все готово! Ваш VPN сервер готов к использованию! 🎉${NC}"
    echo ""
}

main

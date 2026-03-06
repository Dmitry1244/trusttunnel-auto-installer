#!/usr/bin/env bash
set -Euo pipefail

VERSION="1.0.0"
SCRIPT_NAME="TrustTunnel Interactive Installer"
LOG_FILE="/var/log/trusttunnel-installer.log"
MODE="main"

if [[ "${1:-}" == "--post-setup" ]]; then
  MODE="post"
fi

if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/trusttunnel-installer.log"
exec > >(tee -a "$LOG_FILE") 2>&1

log()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR ]${NC} $*"; }

banner() {
  clear 2>/dev/null || true
  echo -e "${CYAN}${BOLD}"
  cat <<'BANNER'
████████╗██████╗ ██╗   ██╗███████╗████████╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║
   ██║   ██████╔╝██║   ██║███████╗   ██║      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
   ██║   ██╔══██╗██║   ██║╚════██║   ██║      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
   ██║   ██║  ██║╚██████╔╝███████║   ██║      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
BANNER
  echo -e "${NC}${BOLD}${SCRIPT_NAME} v${VERSION}${NC}"
  echo "Лог: $LOG_FILE"
  echo
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    err "Запусти скрипт от root: sudo bash $0"
    exit 1
  fi
}

pause() {
  echo
  read -r -p "Нажми Enter для продолжения..." _unused
}

confirm_step() {
  local message="$1"
  local answer
  while true; do
    echo
    read -r -p "$message [Y/n/s/q]: " answer
    answer="${answer:-Y}"
    case "$answer" in
      Y|y|Д|д) return 0 ;;
      N|n|Н|н|S|s|К|к) return 1 ;;
      Q|q|Й|й) echo; warn "Установка остановлена пользователем."; exit 0 ;;
      *) echo "Введи Y, n, s или q." ;;
    esac
  done
}

handle_step_failure() {
  local step_name="$1"
  err "Шаг завершился с ошибкой: $step_name"
  echo
  echo "Что можно сделать дальше:"
  echo "  1) исправить проблему вручную и продолжить"
  echo "  2) пропустить этот шаг"
  echo "  3) прервать установку"
  echo
  local answer
  while true; do
    read -r -p "Выбери [c]ontinue / [s]kip / [q]uit: " answer
    answer="${answer:-q}"
    case "$answer" in
      c|C|с|С) return 0 ;;
      s|S|ы|Ы) return 1 ;;
      q|Q|й|Й) exit 1 ;;
      *) echo "Введи c, s или q." ;;
    esac
  done
}

run_step() {
  local step_name="$1"
  local fn="$2"

  echo
  echo "────────────────────────────────────────────────────────────"
  echo -e "${BOLD}$step_name${NC}"
  echo "────────────────────────────────────────────────────────────"

  if ! confirm_step "Выполнить этот шаг?"; then
    warn "Шаг пропущен: $step_name"
    return 0
  fi

  if "$fn"; then
    ok "Шаг выполнен: $step_name"
    return 0
  fi

  if handle_step_failure "$step_name"; then
    log "Повтори шаг после ручного исправления: $step_name"
    if "$fn"; then
      ok "Шаг выполнен после повтора: $step_name"
      return 0
    fi
  fi

  warn "Шаг пропущен после ошибки: $step_name"
  return 0
}

show_system_info() {
  . /etc/os-release
  echo "Система: ${PRETTY_NAME:-unknown}"
  echo "Режим:   $MODE"
  echo "Дата:    $(date '+%F %T')"
  echo "Ядро:    $(uname -r)"
  echo
}

check_os() {
  if [[ ! -f /etc/os-release ]]; then
    err "Не удалось определить ОС"
    return 1
  fi

  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    warn "Скрипт протестирован на Ubuntu. Обнаружено: ${PRETTY_NAME:-unknown}"
  else
    ok "Обнаружена ОС: ${PRETTY_NAME}"
  fi

  command -v systemctl >/dev/null 2>&1 || {
    err "systemctl не найден"
    return 1
  }

  return 0
}

update_system() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get upgrade -y
}

install_base_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y curl ca-certificates ufw fail2ban iproute2 gawk sed grep coreutils procps

  command -v curl >/dev/null 2>&1 || return 1
  command -v ufw >/dev/null 2>&1 || return 1
  command -v systemctl >/dev/null 2>&1 || return 1
  command -v ip >/dev/null 2>&1 || return 1
  command -v awk >/dev/null 2>&1 || return 1
  command -v sed >/dev/null 2>&1 || return 1
}

apply_sysctl_tuning() {
  cat >/etc/sysctl.d/99-trusttunnel-advanced.conf <<'EOF_SYSCTL'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.netdev_max_backlog=250000
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
EOF_SYSCTL

  sysctl --system >/dev/null

  [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" == "bbr" ]] || return 1
  [[ "$(sysctl -n net.core.default_qdisc 2>/dev/null)" == "fq" ]] || return 1
}

configure_ufw() {
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw logging on
  ufw --force enable

  ufw status | grep -q "Status: active"
}

_disable_ping_file() {
  local file="$1"
  local tmp
  tmp="$(mktemp)"

  if [[ ! -f "$file" ]]; then
    rm -f "$tmp"
    return 1
  fi

  cp -a "$file" "${file}.bak.$(date +%Y%m%d-%H%M%S)"

  awk '
    /# ok icmp codes for INPUT/ { print; block=7; next }
    block > 0 {
      gsub(/ACCEPT/, "DROP")
      print
      block--
      next
    }
    { print }
  ' "$file" > "$tmp"

  if cmp -s "$file" "$tmp"; then
    rm -f "$tmp"
    return 0
  fi

  cat "$tmp" > "$file"
  rm -f "$tmp"
  return 0
}

disable_ping() {
  local changed=0

  if _disable_ping_file /etc/ufw/before.rules; then
    changed=1
  fi

  if [[ -f /etc/ufw/before6.rules ]]; then
    _disable_ping_file /etc/ufw/before6.rules || true
  fi

  ufw reload >/dev/null 2>&1 || true

  if [[ $changed -eq 1 ]]; then
    ok "Ping отключён через UFW before.rules"
  fi

  return 0
}

configure_fail2ban() {
  cat >/etc/fail2ban/jail.local <<'EOF_F2B'
[DEFAULT]
bantime = 10m
findtime = 10m
maxretry = 5
backend = systemd
ignoreip = 127.0.0.1/8

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF_F2B

  systemctl enable fail2ban >/dev/null 2>&1
  systemctl restart fail2ban
  systemctl is-active --quiet fail2ban
}

install_trusttunnel() {
  curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s -

  [[ -x /opt/trusttunnel/trusttunnel_endpoint ]]
}

run_setup_wizard() {
  if [[ ! -x /opt/trusttunnel/setup_wizard ]]; then
    err "/opt/trusttunnel/setup_wizard не найден"
    return 1
  fi

  echo
  echo "Сейчас запустится интерактивный setup_wizard TrustTunnel."
  echo "Во время wizard не закрывай терминал."
  echo
  pause

  (
    cd /opt/trusttunnel
    ./setup_wizard
  )

  [[ -f /opt/trusttunnel/vpn.toml ]] || {
    err "После setup_wizard не найден /opt/trusttunnel/vpn.toml"
    return 1
  }

  [[ -f /opt/trusttunnel/hosts.toml ]] || {
    err "После setup_wizard не найден /opt/trusttunnel/hosts.toml"
    return 1
  }
}

configure_antidpi() {
  local config="/opt/trusttunnel/vpn.toml"

  [[ -f "$config" ]] || {
    err "$config не найден"
    return 1
  }

  cp -a "$config" "${config}.bak.$(date +%Y%m%d-%H%M%S)"

  if grep -qE '^\s*antidpi\s*=' "$config"; then
    sed -i -E 's/^\s*antidpi\s*=.*/antidpi = true/' "$config"
  else
    printf '\nantidpi = true\n' >> "$config"
  fi

  grep -qE '^\s*antidpi\s*=\s*true\s*$' "$config"
}

write_service_unit() {
  cat >/etc/systemd/system/trusttunnel.service <<'EOF_UNIT'
[Unit]
Description=TrustTunnel endpoint
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/trusttunnel
ExecStart=/opt/trusttunnel/trusttunnel_endpoint vpn.toml hosts.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF_UNIT

  grep -q '^WorkingDirectory=/opt/trusttunnel$' /etc/systemd/system/trusttunnel.service || return 1
  grep -q '^ExecStart=/opt/trusttunnel/trusttunnel_endpoint vpn.toml hosts.toml$' /etc/systemd/system/trusttunnel.service || return 1
}

apply_interface_tuning() {
  local iface
  iface="$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')"

  if [[ -z "$iface" ]]; then
    warn "Не удалось определить сетевой интерфейс по умолчанию"
    return 0
  fi

  ip link set dev "$iface" txqueuelen 10000 || true

  if compgen -G "/sys/class/net/$iface/queues/rx-*" >/dev/null; then
    for q in /sys/class/net/"$iface"/queues/rx-*; do
      echo ffffffff > "$q/rps_cpus" || true
    done
  fi

  ok "Сетевой тюнинг применён к интерфейсу: $iface"
  return 0
}

post_setup_finalize() {
  [[ -x /opt/trusttunnel/trusttunnel_endpoint ]] || {
    err "Не найден /opt/trusttunnel/trusttunnel_endpoint"
    return 1
  }

  [[ -f /opt/trusttunnel/vpn.toml ]] || {
    err "Не найден /opt/trusttunnel/vpn.toml"
    return 1
  }

  [[ -f /opt/trusttunnel/hosts.toml ]] || {
    err "Не найден /opt/trusttunnel/hosts.toml"
    return 1
  }

  run_step "Включить antidpi = true" configure_antidpi
  run_step "Создать systemd unit trusttunnel.service" write_service_unit

  systemctl daemon-reload
  systemctl enable trusttunnel >/dev/null 2>&1
  systemctl restart trusttunnel

  sleep 2
  systemctl is-active --quiet trusttunnel || {
    err "Сервис trusttunnel не запустился"
    systemctl status trusttunnel --no-pager || true
    journalctl -u trusttunnel -n 50 --no-pager || true
    return 1
  }

  ok "TrustTunnel успешно запущен"
  systemctl status trusttunnel --no-pager || true
  return 0
}

main_summary() {
  echo
  echo "============================================================"
  echo "Готово"
  echo "============================================================"
  echo "Базовая установка завершена."
  echo
  echo "Если ты уже прошёл setup_wizard и созданы vpn.toml и hosts.toml,"
  echo "можно сразу выполнить post-setup этим же файлом:"
  echo
  echo "  sudo bash $0 --post-setup"
  echo
  echo "Если запускаешь скрипт через GitHub raw URL, post-setup потом так:"
  echo
  echo "  bash <(curl -fsSL https://raw.githubusercontent.com/Dmitry1244/trusttunnel-auto-installer/main/install-trusttunnel-interactive-final.sh) --post-setup"
  echo
  echo "Проверки:"
  echo "  sysctl net.ipv4.tcp_congestion_control"
  echo "  sudo ufw status verbose"
  echo "  sudo systemctl status fail2ban --no-pager"
  echo "============================================================"
}

post_summary() {
  echo
  echo "============================================================"
  echo "Post-setup завершён"
  echo "============================================================"
  echo "Проверки:"
  echo "  sudo systemctl status trusttunnel --no-pager"
  echo "  sudo journalctl -u trusttunnel -n 50 --no-pager"
  echo "  sudo ss -tulpn | grep -E ':80|:443'"
  echo "============================================================"
}

run_main_mode() {
  run_step "Проверить ОС и systemd" check_os
  run_step "Обновить систему" update_system
  run_step "Установить базовые пакеты" install_base_packages
  run_step "Включить BBR и сетевой тюнинг" apply_sysctl_tuning
  run_step "Настроить UFW (22, 80, 443)" configure_ufw
  run_step "Отключить ping" disable_ping
  run_step "Настроить Fail2Ban" configure_fail2ban
  run_step "Установить TrustTunnel" install_trusttunnel
  run_step "Применить тюнинг сетевого интерфейса" apply_interface_tuning

  if confirm_step "Запустить setup_wizard прямо сейчас?"; then
    if run_setup_wizard; then
      ok "setup_wizard завершён и конфиги найдены"
      if confirm_step "Сразу выполнить post-setup и запустить сервис?"; then
        post_setup_finalize
      else
        warn "Post-setup пропущен. Его можно выполнить позже этим же файлом с ключом --post-setup."
      fi
    else
      warn "setup_wizard не завершён. Его можно запустить позже вручную: cd /opt/trusttunnel && ./setup_wizard"
    fi
  else
    warn "setup_wizard пропущен. Позже выполни: cd /opt/trusttunnel && ./setup_wizard"
  fi

  main_summary
}

run_post_mode() {
  run_step "Проверить ОС и systemd" check_os
  post_setup_finalize
  post_summary
}

main() {
  require_root
  banner
  show_system_info

  if [[ "$MODE" == "post" ]]; then
    run_post_mode
  else
    run_main_mode
  fi
}

main "$@"

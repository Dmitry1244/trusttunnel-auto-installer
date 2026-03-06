#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="2.0.0"
SCRIPT_NAME="TrustTunnel Interactive Installer"
SCRIPT_FILE_NAME="install-trusttunnel-advanced.sh"
RAW_URL="https://raw.githubusercontent.com/Dmitry1244/trusttunnel-auto-installer/main/install-trusttunnel-advanced.sh"
LOG_FILE="/var/log/trusttunnel-installer.log"
MODE="main"

if [[ "${1:-}" == "--post-setup" ]]; then
  MODE="post"
fi

export TERM="${TERM:-xterm-256color}"

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

on_unexpected_error() {
  local exit_code="$?"
  local line_no="$1"
  err "Непредвиденная ошибка на строке ${line_no}. Код выхода: ${exit_code}"
  err "Смотри лог: ${LOG_FILE}"
  exit "$exit_code"
}
trap 'on_unexpected_error $LINENO' ERR

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
  echo -e "${BOLD}ОТ GREAT DIMITRIUS${NC}"
  echo "Лог: $LOG_FILE"
  echo
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    err "Запусти скрипт от root"
    echo "Пример: sudo bash ${SCRIPT_FILE_NAME}"
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
  echo "  1) исправить проблему вручную и повторить"
  echo "  2) пропустить шаг"
  echo "  3) завершить установку"
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
    log "Повтор шага: $step_name"
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

  command -v systemctl >/dev/null 2>&1 || { err "systemctl не найден"; return 1; }
  command -v bash >/dev/null 2>&1 || { err "bash не найден"; return 1; }
  return 0
}

update_system() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get upgrade -y
}

install_base_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y curl ca-certificates ufw fail2ban iproute2 gawk sed grep coreutils procps iputils-ping

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
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp >/dev/null 2>&1 || true
  ufw allow 80/tcp >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ufw logging on >/dev/null 2>&1 || true
  ufw --force enable >/dev/null 2>&1 || true
  ufw status | grep -q "Status: active"
}

_disable_ping_file() {
  local file="$1"
  local tmp
  tmp="$(mktemp)"

  [[ -f "$file" ]] || { rm -f "$tmp"; return 1; }

  cp -an "$file" "${file}.bak.initial" >/dev/null 2>&1 || true

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
  else
    warn "Не удалось изменить before.rules или изменения уже были внесены"
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

  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban
  systemctl is-active --quiet fail2ban
}

install_trusttunnel() {
  if [[ -x /opt/trusttunnel/trusttunnel_endpoint ]]; then
    ok "TrustTunnel уже установлен, пропускаю повторную установку"
    return 0
  fi

  curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s -
  [[ -x /opt/trusttunnel/trusttunnel_endpoint ]]
}

show_port_conflicts() {
  local found=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    echo "  $line"
    found=1
  done < <(ss -tulpn 2>/dev/null | grep -E ':(80|443)\s' || true)

  [[ $found -eq 1 ]]
}

prepare_for_wizard_ports() {
  local had_trusttunnel=0

  if systemctl list-unit-files 2>/dev/null | grep -q '^trusttunnel\.service'; then
    if systemctl is-active --quiet trusttunnel; then
      warn "Сервис trusttunnel сейчас запущен. Для setup_wizard его лучше временно остановить."
      if confirm_step "Остановить trusttunnel перед setup_wizard?"; then
        systemctl stop trusttunnel
        had_trusttunnel=1
        ok "trusttunnel остановлен"
      fi
    fi
  fi

  if show_port_conflicts; then
    warn "Порты 80/443 уже кем-то заняты. setup_wizard может не пройти проверку или Let's Encrypt."
    echo
    ss -tulpn 2>/dev/null | grep -E ':(80|443)\s' || true
    echo
    if ! confirm_step "Продолжить запуск setup_wizard несмотря на занятые порты?"; then
      return 1
    fi
  fi

  return 0
}

run_setup_wizard() {
  if [[ ! -x /opt/trusttunnel/setup_wizard ]]; then
    err "/opt/trusttunnel/setup_wizard не найден"
    return 1
  fi

  if [[ ! -e /dev/tty ]]; then
    err "TTY не найден. setup_wizard нужно запускать в обычном интерактивном терминале."
    return 1
  fi

  prepare_for_wizard_ports || return 1

  echo
  echo "Сейчас запустится интерактивный setup_wizard TrustTunnel."
  echo "Он будет запущен напрямую через /dev/tty, без вывода через tee."
  echo "Если экран моргал раньше, это исправлено этим способом."
  echo
  pause

  local rc=0
  (
    cd /opt/trusttunnel || exit 1
    export TERM="${TERM:-xterm-256color}"
    stty sane < /dev/tty > /dev/tty 2>/dev/tty || true
    ./setup_wizard < /dev/tty > /dev/tty 2>&1
  ) || rc=$?

  stty sane < /dev/tty > /dev/tty 2>/dev/tty || true
  echo

  [[ $rc -eq 0 ]] || {
    err "setup_wizard завершился с ошибкой"
    return 1
  }

  [[ -f /opt/trusttunnel/vpn.toml ]] || { err "После setup_wizard не найден /opt/trusttunnel/vpn.toml"; return 1; }
  [[ -f /opt/trusttunnel/hosts.toml ]] || { err "После setup_wizard не найден /opt/trusttunnel/hosts.toml"; return 1; }
  return 0
}

configure_antidpi() {
  local config="/opt/trusttunnel/vpn.toml"

  [[ -f "$config" ]] || { err "$config не найден"; return 1; }

  cp -an "$config" "${config}.bak.initial" >/dev/null 2>&1 || true

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

check_trusttunnel_port_conflicts() {
  local lines
  lines="$(ss -tulpn 2>/dev/null | grep -E ':(443)\s' || true)"

  if [[ -z "$lines" ]]; then
    return 0
  fi

  if echo "$lines" | grep -q 'trusttunnel_endpoint'; then
    return 0
  fi

  warn "Порт 443 уже занят другим процессом:"
  echo "$lines"
  return 1
}

post_setup_finalize() {
  [[ -x /opt/trusttunnel/trusttunnel_endpoint ]] || { err "Не найден /opt/trusttunnel/trusttunnel_endpoint"; return 1; }
  [[ -f /opt/trusttunnel/vpn.toml ]] || { err "Не найден /opt/trusttunnel/vpn.toml"; return 1; }
  [[ -f /opt/trusttunnel/hosts.toml ]] || { err "Не найден /opt/trusttunnel/hosts.toml"; return 1; }

  run_step "Включить antidpi = true" configure_antidpi
  run_step "Создать systemd unit trusttunnel.service" write_service_unit

  if ! check_trusttunnel_port_conflicts; then
    err "Сначала освободи порт 443, затем запусти post-setup ещё раз"
    return 1
  fi

  systemctl daemon-reload
  systemctl enable trusttunnel >/dev/null 2>&1 || true
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
  echo "Если setup_wizard уже пройден и созданы vpn.toml и hosts.toml,"
  echo "выполни post-setup одной из команд:"
  echo
  echo "Локальный запуск, если файл сохранён на сервере:"
  echo "  sudo bash ./install-trusttunnel-advanced.sh --post-setup"
  echo
  echo "Запуск через GitHub raw URL:"
  echo "  bash <(curl -fsSL ${RAW_URL}) --post-setup"
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

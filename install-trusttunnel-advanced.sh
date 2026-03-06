#!/usr/bin/env bash
set -Eeuo pipefail

LOG_FILE="/var/log/trusttunnel-advanced-install.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

cleanup_on_error() {
  err "Скрипт завершился с ошибкой на строке $1"
  err "Смотри лог: $LOG_FILE"
}
trap 'cleanup_on_error $LINENO' ERR

exec > >(tee -a "$LOG_FILE") 2>&1

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Запусти скрипт от root"
    exit 1
  fi
}

check_os() {
  if [[ ! -f /etc/os-release ]]; then
    err "Не удалось определить ОС"
    exit 1
  fi

  . /etc/os-release

  if [[ "${ID:-}" != "ubuntu" ]]; then
    warn "Скрипт рассчитан на Ubuntu. Обнаружено: ${PRETTY_NAME:-unknown}"
  else
    ok "Обнаружена ОС: ${PRETTY_NAME}"
  fi
}

get_default_iface() {
  ip route 2>/dev/null | awk '/default/ {print $5; exit}'
}

enable_sysctl_tuning() {
  log "Настраиваю sysctl для VPN/сети..."

  cat >/etc/sysctl.d/99-trusttunnel-advanced.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.netdev_max_backlog=250000
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
EOF

  sysctl --system >/dev/null
  ok "BBR и сетевой тюнинг применены"
}

install_ufw() {
  log "Устанавливаю и настраиваю UFW..."

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y ufw

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp

  ufw logging on
  ufw --force enable

  ok "UFW настроен"
  ufw status verbose || true
}

install_fail2ban() {
  log "Устанавливаю и настраиваю Fail2Ban..."

  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y fail2ban

  cat >/etc/fail2ban/jail.local <<'EOF'
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
EOF

  systemctl enable fail2ban
  systemctl restart fail2ban

  ok "Fail2Ban настроен"
}

install_trusttunnel() {
  log "Устанавливаю TrustTunnel..."

  curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s -

  if [[ ! -d /opt/trusttunnel ]]; then
    err "Папка /opt/trusttunnel не найдена после установки"
    exit 1
  fi

  ok "TrustTunnel установлен в /opt/trusttunnel"
}

prepare_trusttunnel_service() {
  log "Пробую подготовить systemd unit для TrustTunnel..."

  local template="/opt/trusttunnel/trusttunnel.service.template"
  local target="/etc/systemd/system/trusttunnel.service"

  if [[ -f "$template" ]]; then
    cp -f "$template" "$target"
    systemctl daemon-reload
    ok "Systemd unit подготовлен: $target"
    warn "Сервис пока не запускаю. Сначала выполни setup_wizard вручную."
  else
    warn "Файл $template не найден. Возможно, он появится после setup_wizard."
  fi
}

enable_antidpi_if_possible() {
  local config="/opt/trusttunnel/vpn.toml"

  if [[ ! -f "$config" ]]; then
    warn "Конфиг $config пока не найден. antidpi будет удобнее включить после setup_wizard."
    return 0
  fi

  log "Включаю antidpi в $config..."

  cp -a "$config" "${config}.bak.$(date +%Y%m%d-%H%M%S)"

  if grep -qE '^\s*antidpi\s*=' "$config"; then
    sed -i -E 's/^\s*antidpi\s*=.*/antidpi = true/' "$config"
  else
    printf '\nantidpi = true\n' >> "$config"
  fi

  ok "antidpi включён"
}

apply_interface_tuning() {
  local iface
  iface="$(get_default_iface || true)"

  if [[ -z "${iface:-}" ]]; then
    warn "Не удалось определить сетевой интерфейс по умолчанию. Пропускаю txqueuelen и RPS."
    return 0
  fi

  log "Применяю тюнинг сетевого интерфейса: $iface"

  ip link set dev "$iface" txqueuelen 10000 || warn "Не удалось выставить txqueuelen для $iface"

  if compgen -G "/sys/class/net/$iface/queues/rx-*" > /dev/null; then
    for q in /sys/class/net/"$iface"/queues/rx-*; do
      echo ffffffff > "$q/rps_cpus" || true
    done
    ok "RPS включён для $iface"
  else
    warn "RX-очереди для $iface не найдены, RPS пропущен"
  fi
}

show_summary() {
  local iface
  iface="$(get_default_iface || true)"

  echo
  echo "=================================================="
  echo " Установка завершена"
  echo "=================================================="
  echo "Лог: $LOG_FILE"
  echo
  echo "Что уже сделано:"
  echo "  - система обновлена"
  echo "  - UFW установлен и включён"
  echo "  - Fail2Ban установлен и включён"
  echo "  - BBR и сетевой тюнинг применены"
  echo "  - TrustTunnel установлен"
  [[ -n "${iface:-}" ]] && echo "  - сетевой интерфейс: $iface"
  echo
  echo "Что сделать дальше вручную:"
  echo "  1) cd /opt/trusttunnel"
  echo "  2) ./setup_wizard"
  echo
  echo "После завершения setup_wizard выполни:"
  echo "  sudo cp /opt/trusttunnel/trusttunnel.service.template /etc/systemd/system/trusttunnel.service"
  echo "  sudo systemctl daemon-reload"
  echo "  sudo systemctl enable --now trusttunnel"
  echo
  echo "Если после setup_wizard появится /opt/trusttunnel/vpn.toml,"
  echo "можно включить antidpi так:"
  echo "  sudo sed -i -E 's/^\\s*antidpi\\s*=.*/antidpi = true/' /opt/trusttunnel/vpn.toml || echo 'antidpi = true' | sudo tee -a /opt/trusttunnel/vpn.toml"
  echo
  echo "Проверки:"
  echo "  sysctl net.ipv4.tcp_congestion_control"
  echo "  ufw status verbose"
  echo "  systemctl status fail2ban --no-pager"
  echo "  systemctl status trusttunnel --no-pager"
  echo "=================================================="
}

main() {
  require_root
  check_os

  log "Старт установки. Лог пишется в $LOG_FILE"

  export DEBIAN_FRONTEND=noninteractive

  log "Обновляю систему..."
  apt-get update -y
  apt-get upgrade -y
  ok "Система обновлена"

  enable_sysctl_tuning
  install_ufw
  install_fail2ban
  install_trusttunnel
  prepare_trusttunnel_service
  enable_antidpi_if_possible
  apply_interface_tuning
  show_summary
}

main "$@"

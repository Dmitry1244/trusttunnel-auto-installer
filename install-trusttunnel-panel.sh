#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="TrustTunnel Panel Installer"
VERSION="1.0.0"
INSTALL_DIR="/opt/trusttunnel-panel-mvp"
SERVICE_NAME="trusttunnel-panel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_FILE="/var/log/trusttunnel-panel-installer.log"
STAGING_ROOT="/tmp/trusttunnel-panel-build"
REPO_ZIP_URL="${PANEL_REPO_ZIP_URL:-https://github.com/Dmitry1244/trusttunnel-auto-installer/archive/refs/heads/main.zip}"
REPO_SUBDIR="${PANEL_REPO_SUBDIR:-trusttunnel-auto-installer-main/trusttunnel-panel-mvp}"
PANEL_HOST_DEFAULT="${PANEL_HOST_DEFAULT:-127.0.0.1}"
PANEL_PORT_DEFAULT="${PANEL_PORT_DEFAULT:-8787}"
TRUSTTUNNEL_DIR_DEFAULT="${TRUSTTUNNEL_DIR_DEFAULT:-/opt/trusttunnel}"
TRUSTTUNNEL_SERVICE_DEFAULT="${TRUSTTUNNEL_SERVICE_DEFAULT:-trusttunnel.service}"

if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/trusttunnel-panel-installer.log"
exec > >(tee -a "$LOG_FILE") 2>&1

log()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR ]${NC} $*" >&2; }

on_error() {
  local line="$1"
  err "Ошибка на строке $line"
  err "Смотри лог: $LOG_FILE"
}
trap 'on_error $LINENO' ERR

banner() {
  clear 2>/dev/null || true
  echo -e "${CYAN}${BOLD}"
  cat <<'BANNER'
████████╗██████╗ ██╗   ██╗███████╗████████╗████████╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗     
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚══██╔══╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║     
   ██║   ██████╔╝██║   ██║███████╗   ██║      ██║      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║     
   ██║   ██╔══██╗██║   ██║╚════██║   ██║      ██║      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║     
   ██║   ██║  ██║╚██████╔╝███████║   ██║      ██║      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝      ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
BANNER
  echo -e "${NC}${BOLD}${SCRIPT_NAME} v${VERSION}${NC}"
  echo -e "${BOLD}ОТ GREAT DIMITRIUS${NC}"
  echo "Лог: $LOG_FILE"
  echo
}

require_root() {
  if [[ ${EUID} -ne 0 ]]; then
    err "Запусти скрипт от root"
    exit 1
  fi
}

confirm() {
  local prompt="$1"
  local default="${2:-Y}"
  local answer
  if [[ ! -t 0 ]]; then
    [[ "$default" =~ ^[Yy]$ ]] && return 0 || return 1
  fi
  while true; do
    read -r -p "$prompt [Y/n]: " answer
    answer="${answer:-$default}"
    case "$answer" in
      Y|y|Д|д) return 0 ;;
      N|n|Н|н) return 1 ;;
      *) echo "Введи Y или n." ;;
    esac
  done
}

rand_hex() {
  openssl rand -hex "$1"
}

check_os() {
  if [[ ! -f /etc/os-release ]]; then
    err "Не удалось определить ОС"
    return 1
  fi
  . /etc/os-release
  log "Система: ${PRETTY_NAME:-unknown}"
  if [[ "${ID:-}" != "ubuntu" ]]; then
    warn "Скрипт рассчитан в первую очередь на Ubuntu. Продолжаю."
  fi
  return 0
}

install_base_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y \
    python3 python3-venv python3-pip \
    curl ca-certificates unzip rsync openssl \
    ufw fail2ban iproute2 gawk sed grep coreutils procps \
    gnupg lsb-release
}

acquire_source() {
  rm -rf "$STAGING_ROOT"
  mkdir -p "$STAGING_ROOT"

  if [[ -f "./requirements.txt" && -f "./app/main.py" ]]; then
    log "Использую локальные исходники из текущей директории"
    mkdir -p "$STAGING_ROOT/src"
    rsync -a --delete ./ "$STAGING_ROOT/src/"
    return 0
  fi

  log "Скачиваю исходники панели из архива репозитория"
  local archive="$STAGING_ROOT/repo.zip"
  curl -fsSL "$REPO_ZIP_URL" -o "$archive"
  unzip -q "$archive" -d "$STAGING_ROOT/unpack"

  if [[ ! -d "$STAGING_ROOT/unpack/$REPO_SUBDIR" ]]; then
    err "Не найден каталог проекта в архиве: $REPO_SUBDIR"
    err "Загрузи папку trusttunnel-panel-mvp в тот же GitHub-репозиторий или переопредели PANEL_REPO_SUBDIR"
    return 1
  fi

  mkdir -p "$STAGING_ROOT/src"
  rsync -a --delete "$STAGING_ROOT/unpack/$REPO_SUBDIR/" "$STAGING_ROOT/src/"
}

prepare_install_dir() {
  mkdir -p "$INSTALL_DIR"

  if [[ -f "$INSTALL_DIR/.env" ]]; then
    cp -a "$INSTALL_DIR/.env" "$STAGING_ROOT/.env.saved"
    ok "Сохранён существующий .env"
  fi

  rsync -a --delete \
    --exclude '.env' \
    --exclude '.venv' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    "$STAGING_ROOT/src/" "$INSTALL_DIR/"

  if [[ -f "$STAGING_ROOT/.env.saved" ]]; then
    mv -f "$STAGING_ROOT/.env.saved" "$INSTALL_DIR/.env"
  fi
}

prompt_env_values() {
  local admin_password="${PANEL_ADMIN_PASSWORD:-}"
  local panel_host="${PANEL_HOST:-$PANEL_HOST_DEFAULT}"
  local panel_port="${PANEL_PORT:-$PANEL_PORT_DEFAULT}"
  local trust_dir="${TRUSTTUNNEL_DIR:-$TRUSTTUNNEL_DIR_DEFAULT}"
  local trust_service="${TRUSTTUNNEL_SERVICE:-$TRUSTTUNNEL_SERVICE_DEFAULT}"
  local secret_key="${PANEL_SECRET_KEY:-$(rand_hex 32)}"
  local backup_dir="${PANEL_BACKUP_DIR:-${trust_dir}/panel-backups}"

  if [[ -f "$INSTALL_DIR/.env" ]]; then
    warn "Найден существующий .env. Оставляю его без изменений."
    return 0
  fi

  if [[ -z "$admin_password" ]]; then
    admin_password="$(rand_hex 12)"
    if [[ -t 0 ]]; then
      echo
      echo "Сгенерирован пароль администратора панели."
      echo "Нажми Enter, чтобы принять его, или введи свой."
      echo "Текущий: $admin_password"
      read -r -p "Пароль панели: " input_pw
      admin_password="${input_pw:-$admin_password}"
    fi
  fi

  if [[ -t 0 ]]; then
    read -r -p "Хост панели [$panel_host]: " input_host
    panel_host="${input_host:-$panel_host}"
    read -r -p "Порт панели [$panel_port]: " input_port
    panel_port="${input_port:-$panel_port}"
    read -r -p "Каталог TrustTunnel [$trust_dir]: " input_dir
    trust_dir="${input_dir:-$trust_dir}"
    read -r -p "Имя systemd-сервиса TrustTunnel [$trust_service]: " input_service
    trust_service="${input_service:-$trust_service}"
  fi

  cat > "$INSTALL_DIR/.env" <<EOF_ENV
PANEL_HOST=$panel_host
PANEL_PORT=$panel_port
PANEL_SECRET_KEY=$secret_key
PANEL_ADMIN_PASSWORD=$admin_password
TRUSTTUNNEL_DIR=$trust_dir
TRUSTTUNNEL_SERVICE=$trust_service
PANEL_BACKUP_DIR=$backup_dir
EOF_ENV

  chmod 600 "$INSTALL_DIR/.env"
  ok "Создан $INSTALL_DIR/.env"
  echo
  echo "Пароль панели: $admin_password"
  echo "Сохрани его в безопасном месте."
}

setup_venv() {
  cd "$INSTALL_DIR"
  if [[ ! -d .venv ]]; then
    python3 -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
}

write_systemd_unit() {
  local env_file="$INSTALL_DIR/.env"
  # shellcheck disable=SC1090
  source "$env_file"

  cat > "$SERVICE_FILE" <<EOF_UNIT
[Unit]
Description=TrustTunnel Panel MVP
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$env_file
ExecStart=$INSTALL_DIR/.venv/bin/uvicorn app.main:app --host ${PANEL_HOST} --port ${PANEL_PORT}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF_UNIT

  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
  sleep 2
  systemctl is-active --quiet "$SERVICE_NAME"
}

maybe_open_panel_port() {
  # shellcheck disable=SC1090
  source "$INSTALL_DIR/.env"

  if [[ "$PANEL_HOST" == "127.0.0.1" || "$PANEL_HOST" == "localhost" ]]; then
    ok "Панель слушает только localhost; порт в UFW не открываю"
    return 0
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${PANEL_PORT}/tcp" >/dev/null 2>&1 || true
    ok "Открыт порт панели в UFW: ${PANEL_PORT}/tcp"
  fi
}

maybe_install_warp() {
  if ! confirm "Установить Cloudflare WARP CLI сейчас?" "n"; then
    warn "Установка WARP пропущена"
    return 0
  fi

  log "Добавляю официальный репозиторий Cloudflare WARP"
  curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflare-client.list
  apt-get update -y
  apt-get install -y cloudflare-warp

  if command -v warp-cli >/dev/null 2>&1; then
    ok "warp-cli установлен"
  else
    err "warp-cli не найден после установки"
    return 1
  fi
}

show_summary() {
  # shellcheck disable=SC1090
  source "$INSTALL_DIR/.env"
  echo
  echo "============================================================"
  echo "Панель установлена"
  echo "============================================================"
  echo "Сервис:    $SERVICE_NAME"
  echo "Каталог:   $INSTALL_DIR"
  echo "Хост:      $PANEL_HOST"
  echo "Порт:      $PANEL_PORT"
  echo "Лог:       $LOG_FILE"
  echo
  echo "Проверки:"
  echo "  sudo systemctl status $SERVICE_NAME --no-pager"
  echo "  sudo journalctl -u $SERVICE_NAME -n 50 --no-pager"
  echo
  if [[ "$PANEL_HOST" == "127.0.0.1" || "$PANEL_HOST" == "localhost" ]]; then
    echo "Доступ к панели:"
    echo "  ssh -L ${PANEL_PORT}:127.0.0.1:${PANEL_PORT} root@<SERVER_IP>"
    echo "  затем открой: http://127.0.0.1:${PANEL_PORT}"
  else
    echo "Доступ к панели: http://$PANEL_HOST:$PANEL_PORT"
  fi
  echo "============================================================"
}

main() {
  require_root
  banner
  check_os
  install_base_packages
  acquire_source
  prepare_install_dir
  prompt_env_values
  setup_venv
  write_systemd_unit
  maybe_open_panel_port
  maybe_install_warp
  show_summary
}

main "$@"

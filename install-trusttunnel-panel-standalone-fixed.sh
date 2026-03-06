#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="trusttunnel-panel-mvp"
APP_DIR="/opt/${APP_NAME}"
SERVICE_NAME="trusttunnel-panel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="${APP_DIR}/.env"
LOG_FILE="/var/log/${SERVICE_NAME}-installer.log"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT
trap 'echo "[ERR] Ошибка на строке $LINENO. Лог: $LOG_FILE" >&2' ERR

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/${SERVICE_NAME}-installer.log"
exec > >(tee -a "$LOG_FILE") 2>&1

if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

log(){ echo -e "${BLUE}[INFO]${NC} $*"; }
ok(){ echo -e "${GREEN}[ OK ]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERR ]${NC} $*"; }

banner(){
  clear 2>/dev/null || true
  echo -e "${CYAN}${BOLD}"
  cat <<'EOF'
████████╗██████╗ ██╗   ██╗███████╗████████╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗
╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║
   ██║   ██████╔╝██║   ██║███████╗   ██║      ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
   ██║   ██╔══██╗██║   ██║╚════██║   ██║      ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
   ██║   ██║  ██║╚██████╔╝███████║   ██║      ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
EOF
  echo -e "${NC}${BOLD}TrustTunnel Panel Installer${NC}"
  echo "Лог: $LOG_FILE"
  echo
}

require_root(){
  if [[ ${EUID} -ne 0 ]]; then
    err "Запусти от root: sudo bash $0"
    exit 1
  fi
}

tty_readline(){
  local prompt="$1" default="${2:-}" answer=""
  if [[ -e /dev/tty ]]; then
    if [[ -n "$default" ]]; then
      read -r -p "$prompt [$default]: " answer < /dev/tty
    else
      read -r -p "$prompt: " answer < /dev/tty
    fi
  else
    if [[ -n "$default" ]]; then
      read -r -p "$prompt [$default]: " answer
    else
      read -r -p "$prompt: " answer
    fi
  fi
  echo "${answer:-$default}"
}

tty_read_secret_once(){
  local prompt="$1" answer=""
  if [[ -e /dev/tty ]]; then
    read -r -s -p "$prompt: " answer < /dev/tty
    echo > /dev/tty
  else
    read -r -s -p "$prompt: " answer
    echo
  fi
  echo "$answer"
}

ask_default(){
  tty_readline "$1" "$2"
}

gen_secret(){ python3 - <<'PY2'
import secrets
print(secrets.token_urlsafe(32))
PY2
}

gen_password(){ python3 - <<'PY3'
import secrets, string
alphabet = string.ascii_letters + string.digits
print(''.join(secrets.choice(alphabet) for _ in range(16)))
PY3
}

extract_value(){
  local key="$1" file="$2"
  [[ -f "$file" ]] || return 1
  awk -F= -v k="$key" '$1==k {sub(/^[^=]*=/,""); print; exit}' "$file"
}

is_safe_env_value(){
  local value="$1"
  [[ -n "$value" ]] || return 1
  [[ "$value" != *$'\n'* ]] || return 1
  [[ "$value" != *$'\r'* ]] || return 1
  [[ "$value" != *"#"* ]] || return 1
  [[ "$value" != *" "* ]] || return 1
  [[ "$value" != *$'\t'* ]] || return 1
  return 0
}

prompt_password(){
  local p1="" p2="" attempts=0
  while (( attempts < 5 )); do
    p1="$(tty_read_secret_once 'Пароль панели (без пробелов и символа #)')"
    [[ -n "$p1" ]] || { warn "Пароль не может быть пустым"; ((attempts++)); continue; }
    is_safe_env_value "$p1" || { warn "Используй пароль без пробелов, табов и символа #"; ((attempts++)); continue; }
    p2="$(tty_read_secret_once 'Повтори пароль панели')"
    [[ "$p1" == "$p2" ]] || { warn "Пароли не совпадают"; ((attempts++)); continue; }
    echo "$p1"
    return 0
  done
  return 1
}

write_env_file(){
  local panel_host="$1" panel_port="$2" panel_secret="$3" admin_password="$4" tt_dir="$5" tt_service="$6" backup_dir="$7"
  local tmp="${ENV_FILE}.tmp"

  is_safe_env_value "$admin_password" || {
    err "Пароль пустой или содержит неподдерживаемые символы для .env"
    return 1
  }

  cat > "$tmp" <<EOF
PANEL_HOST=$panel_host
PANEL_PORT=$panel_port
PANEL_SECRET_KEY=$panel_secret
PANEL_ADMIN_PASSWORD=$admin_password
TRUSTTUNNEL_DIR=$tt_dir
TRUSTTUNNEL_SERVICE=$tt_service
PANEL_BACKUP_DIR=$backup_dir
EOF

  chmod 600 "$tmp"
  mv "$tmp" "$ENV_FILE"

  local saved_password
  saved_password="$(extract_value PANEL_ADMIN_PASSWORD "$ENV_FILE" || true)"
  [[ -n "$saved_password" ]] || {
    err "После записи .env пароль оказался пустым"
    return 1
  }

  ok ".env создан/обновлён"
}

install_packages(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip ca-certificates curl tar gzip
}

unpack_app(){
  log "Распаковываю встроенные исходники панели..."
  mkdir -p "$TMP_DIR/src"
  cat > "$TMP_DIR/panel.tar.gz.b64" <<'PAYLOAD'
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
PAYLOAD
  base64 -d "$TMP_DIR/panel.tar.gz.b64" > "$TMP_DIR/panel.tar.gz"
  tar -xzf "$TMP_DIR/panel.tar.gz" -C "$TMP_DIR/src"

  local srcdir="$TMP_DIR/src/trusttunnel-panel-mvp"
  [[ -d "$srcdir" ]] || { err "Не удалось распаковать панель"; return 1; }

  mkdir -p "$APP_DIR"

  local keep_env=""
  if [[ -f "$ENV_FILE" ]]; then
    keep_env="$TMP_DIR/.env.keep"
    cp -a "$ENV_FILE" "$keep_env"
  fi

  find "$APP_DIR" -mindepth 1 -maxdepth 1 ! -name '.venv' -exec rm -rf {} +
  cp -a "$srcdir"/. "$APP_DIR"/

  if [[ -n "$keep_env" && -f "$keep_env" ]]; then
    cp -a "$keep_env" "$ENV_FILE"
    ok "Существующий .env сохранён"
  fi
}

setup_env(){
  mkdir -p "$APP_DIR"

  local current_host current_port current_secret current_password current_tt_dir current_tt_service current_backup
  current_host="$(extract_value PANEL_HOST "$ENV_FILE" || true)"
  current_port="$(extract_value PANEL_PORT "$ENV_FILE" || true)"
  current_secret="$(extract_value PANEL_SECRET_KEY "$ENV_FILE" || true)"
  current_password="$(extract_value PANEL_ADMIN_PASSWORD "$ENV_FILE" || true)"
  current_tt_dir="$(extract_value TRUSTTUNNEL_DIR "$ENV_FILE" || true)"
  current_tt_service="$(extract_value TRUSTTUNNEL_SERVICE "$ENV_FILE" || true)"
  current_backup="$(extract_value PANEL_BACKUP_DIR "$ENV_FILE" || true)"

  local panel_host panel_port panel_secret admin_password tt_dir tt_service backup_dir

  panel_host="${current_host:-127.0.0.1}"
  panel_port="${current_port:-8787}"
  tt_dir="${current_tt_dir:-/opt/trusttunnel}"
  tt_service="${current_tt_service:-trusttunnel.service}"
  backup_dir="${current_backup:-/opt/trusttunnel/panel-backups}"

  echo
  log "Настройка панели"
  panel_host="$(ask_default 'Хост панели' "$panel_host")"
  panel_port="$(ask_default 'Порт панели' "$panel_port")"
  tt_dir="$(ask_default 'Путь к TrustTunnel' "$tt_dir")"
  tt_service="$(ask_default 'Имя systemd-сервиса TrustTunnel' "$tt_service")"
  backup_dir="$(ask_default 'Каталог для backup конфигов' "$backup_dir")"

  if [[ -n "${current_password:-}" ]]; then
    local keep_pw
    keep_pw="$(tty_readline 'Сохранить текущий пароль панели? [Y/n]' 'Y')"
    if [[ "$keep_pw" =~ ^[NnНн]$ ]]; then
      admin_password="$(prompt_password)" || {
        admin_password="$(gen_password)"
        warn "Не удалось корректно ввести пароль. Сгенерирован временный пароль: $admin_password"
      }
    else
      admin_password="$current_password"
    fi
  else
    admin_password="$(prompt_password)" || {
      admin_password="$(gen_password)"
      warn "Не удалось корректно ввести пароль. Сгенерирован временный пароль: $admin_password"
    }
  fi

  [[ -n "${current_secret:-}" ]] && panel_secret="$current_secret" || panel_secret="$(gen_secret)"

  mkdir -p "$backup_dir"
  write_env_file "$panel_host" "$panel_port" "$panel_secret" "$admin_password" "$tt_dir" "$tt_service" "$backup_dir"

  echo
  ok "Пароль панели установлен"
  echo "Проверь .env:"
  echo "  sudo grep '^PANEL_ADMIN_PASSWORD=' $ENV_FILE"
}

install_python_deps(){
  log "Создаю virtualenv и ставлю зависимости Python..."
  python3 -m venv "$APP_DIR/.venv"
  "$APP_DIR/.venv/bin/pip" install --upgrade pip wheel
  "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
}

write_service(){
  log "Создаю systemd unit..."
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=TrustTunnel Panel MVP
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=/bin/bash -lc '$APP_DIR/.venv/bin/uvicorn app.main:app --host "\${PANEL_HOST}" --port "\${PANEL_PORT}"'
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
}

maybe_open_firewall(){
  local host port
  host="$(extract_value PANEL_HOST "$ENV_FILE" || echo 127.0.0.1)"
  port="$(extract_value PANEL_PORT "$ENV_FILE" || echo 8787)"

  if [[ "$host" == "127.0.0.1" || "$host" == "localhost" ]]; then
    warn "Панель слушает только localhost; UFW для неё не открываю"
    return 0
  fi

  if command -v ufw >/dev/null 2>&1; then
    local ans
    ans="$(tty_readline "Открыть порт $port/tcp в UFW для веб-панели? [y/N]" "N")"
    if [[ "$ans" =~ ^[YyДд]$ ]]; then
      ufw allow "$port/tcp"
      ok "Порт $port/tcp открыт в UFW"
    fi
  fi
}

start_service(){
  systemctl restart "$SERVICE_NAME"
  sleep 2
  systemctl is-active --quiet "$SERVICE_NAME"
}

show_summary(){
  local host port saved_password
  host="$(extract_value PANEL_HOST "$ENV_FILE" || echo 127.0.0.1)"
  port="$(extract_value PANEL_PORT "$ENV_FILE" || echo 8787)"
  saved_password="$(extract_value PANEL_ADMIN_PASSWORD "$ENV_FILE" || true)"
  echo
  echo "============================================================"
  echo "Панель установлена"
  echo "============================================================"
  echo "Каталог: $APP_DIR"
  echo "Сервис:  $SERVICE_NAME"
  echo "Лог:     $LOG_FILE"
  echo
  echo "Проверки:"
  echo "  sudo systemctl status $SERVICE_NAME --no-pager"
  echo "  sudo journalctl -u $SERVICE_NAME -n 50 --no-pager"
  echo "  sudo grep '^PANEL_ADMIN_PASSWORD=' $ENV_FILE"
  echo
  if [[ "$host" == "127.0.0.1" ]]; then
    echo "Открыть локально: http://127.0.0.1:$port"
    echo "Для доступа снаружи используй reverse proxy или SSH tunnel."
  else
    echo "Панель слушает: http://$host:$port"
  fi
  if [[ -n "$saved_password" ]]; then
    echo
    echo "Пароль панели сохранён в $ENV_FILE"
  fi
  echo "============================================================"
}

main(){
  require_root
  banner
  install_packages
  unpack_app
  setup_env
  install_python_deps
  write_service
  maybe_open_firewall
  start_service
  ok "Сервис $SERVICE_NAME запущен"
  show_summary
}

main "$@"

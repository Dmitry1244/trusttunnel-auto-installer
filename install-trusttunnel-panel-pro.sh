#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/trusttunnel-panel-pro"
SERVICE_NAME="trusttunnel-panel"
LOG_FILE="/var/log/trusttunnel-panel-pro-installer.log"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

log(){ echo -e "${BLUE}[INFO]${NC} $*"; }
ok(){ echo -e "${GREEN}[ OK ]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERR ]${NC} $*"; }

mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

require_root(){ [[ $EUID -eq 0 ]] || { err "Запусти installer от root"; exit 1; }; }

default_or_prompt(){
  local prompt="$1" default="$2" var
  read -r -p "$prompt [$default]: " var < /dev/tty || true
  echo "${var:-$default}"
}

prompt_password(){
  local p1 p2
  while true; do
    read -r -s -p "Пароль панели: " p1 < /dev/tty; echo
    read -r -s -p "Повтори пароль панели: " p2 < /dev/tty; echo
    [[ -n "$p1" ]] || { warn "Пароль не должен быть пустым"; continue; }
    [[ "$p1" == "$p2" ]] || { warn "Пароли не совпадают"; continue; }
    printf '%s' "$p1"
    return 0
  done
}

write_project(){
  log "Распаковываю встроенный проект панели..."
  cat > "$TMP_DIR/panel.tar.gz.b64" <<'EOF_B64'
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
EOF_B64
  base64 -d "$TMP_DIR/panel.tar.gz.b64" > "$TMP_DIR/panel.tar.gz"
  mkdir -p "$TMP_DIR/unpack"
  tar -xzf "$TMP_DIR/panel.tar.gz" -C "$TMP_DIR/unpack"

  local existing_env=""
  if [[ -f "$APP_DIR/.env" ]]; then
    existing_env="$TMP_DIR/.env.backup"
    cp "$APP_DIR/.env" "$existing_env"
  fi

  rm -rf "$APP_DIR"
  mkdir -p "$(dirname "$APP_DIR")"
  cp -a "$TMP_DIR/unpack/trusttunnel-panel-pro" "$APP_DIR"

  if [[ -n "$existing_env" && -f "$existing_env" ]]; then
    warn "Найден существующий .env, переношу его как основу"
    cp "$existing_env" "$APP_DIR/.env"
  fi
}

upsert_env(){
  local key="$1" value="$2" file="$3"
  if grep -q "^${key}=" "$file" 2>/dev/null; then
    sed -i "s#^${key}=.*#${key}=${value}#" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

install_deps(){
  log "Устанавливаю системные зависимости..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip curl ca-certificates git
}

setup_env(){
  log "Настраиваю .env..."
  [[ -f "$APP_DIR/.env" ]] || cp "$APP_DIR/.env.example" "$APP_DIR/.env"

  local host port tt_dir tt_service panel_password secret
  host=$(default_or_prompt "Host панели" "127.0.0.1")
  port=$(default_or_prompt "Port панели" "8787")
  tt_dir=$(default_or_prompt "Путь к TrustTunnel" "/opt/trusttunnel")
  tt_service=$(default_or_prompt "Имя systemd-сервиса TrustTunnel (без .service)" "trusttunnel")
  secret=$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)
  panel_password=$(prompt_password)

  upsert_env PANEL_HOST "$host" "$APP_DIR/.env"
  upsert_env PANEL_PORT "$port" "$APP_DIR/.env"
  upsert_env TRUSTTUNNEL_DIR "$tt_dir" "$APP_DIR/.env"
  upsert_env TRUSTTUNNEL_SERVICE "$tt_service" "$APP_DIR/.env"
  upsert_env PANEL_SECRET_KEY "$secret" "$APP_DIR/.env"
  upsert_env PANEL_ADMIN_PASSWORD "$panel_password" "$APP_DIR/.env"
  upsert_env PANEL_BACKUP_DIR "$tt_dir/panel-backups" "$APP_DIR/.env"

  if ! grep -q '^PANEL_ADMIN_PASSWORD=.' "$APP_DIR/.env"; then
    err "Не удалось записать пароль панели в .env"
    exit 1
  fi
}

build_venv(){
  log "Создаю Python virtualenv и ставлю зависимости..."
  python3 -m venv "$APP_DIR/.venv"
  "$APP_DIR/.venv/bin/pip" install --upgrade pip
  "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
}

write_systemd(){
  log "Создаю systemd unit..."
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF_UNIT
[Unit]
Description=TrustTunnel Panel Pro
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/.venv/bin/uvicorn app.main:app --host \${PANEL_HOST} --port \${PANEL_PORT}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF_UNIT

  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
}

maybe_open_ufw(){
  if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw не установлен, пропускаю открытие порта панели"
    return 0
  fi
  local host port
  host=$(grep '^PANEL_HOST=' "$APP_DIR/.env" | cut -d= -f2-)
  port=$(grep '^PANEL_PORT=' "$APP_DIR/.env" | cut -d= -f2-)
  if [[ "$host" == "127.0.0.1" || "$host" == "localhost" ]]; then
    warn "Панель слушает только localhost; UFW для неё не открываю"
    return 0
  fi
  read -r -p "Открыть порт ${port}/tcp в UFW? [y/N]: " ans < /dev/tty || true
  if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
    ufw allow "${port}/tcp"
  fi
}

show_summary(){
  local host port
  host=$(grep '^PANEL_HOST=' "$APP_DIR/.env" | cut -d= -f2-)
  port=$(grep '^PANEL_PORT=' "$APP_DIR/.env" | cut -d= -f2-)
  echo
  echo "============================================================"
  echo "Панель установлена"
  echo "============================================================"
  echo "Каталог: $APP_DIR"
  echo "Сервис:  $SERVICE_NAME"
  echo "Лог:     $LOG_FILE"
  echo
  echo "Открыть локально: http://${host}:${port}"
  if [[ "$host" == "127.0.0.1" ]]; then
    echo "Для доступа снаружи используй reverse proxy или SSH tunnel."
  fi
  echo
  echo "Проверки:"
  echo "  sudo systemctl status ${SERVICE_NAME} --no-pager"
  echo "  sudo journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
  echo "  sudo grep '^PANEL_ADMIN_PASSWORD=' ${APP_DIR}/.env"
  echo "============================================================"
}

main(){
  require_root
  install_deps
  write_project
  setup_env
  build_venv
  write_systemd
  maybe_open_ufw
  show_summary
}

main "$@"

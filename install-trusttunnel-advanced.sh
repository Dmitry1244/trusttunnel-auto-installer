#!/usr/bin/env bash
set -euo pipefail

RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; RESET="\e[0m"
log_info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
log_err()   { echo -e "${RED}[ERR]${RESET}  $*" >&2; }

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    log_err "Запустите скрипт от root: sudo bash $0"
    exit 1
  fi
}

pause() { read -rp "Нажмите Enter для продолжения..."; }

ask_input() {
  local prompt varname default value
  prompt="$1"; varname="$2"; default="${3:-}"
  if [[ -n "$default" ]]; then
    read -rp "$prompt [$default]: " value || true
    value="${value:-$default}"
  else
    while true; do
      read -rp "$prompt: " value || true
      [[ -n "$value" ]] && break
      log_warn "Поле не может быть пустым."
    done
  fi
  printf -v "$varname" '%s' "$value"
}

enable_bbr() {
  log_info "Включаю BBR..."
  grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
  log_ok "BBR включён."
}

update_system() {
  log_info "Обновляю систему и устанавливаю зависимости..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get upgrade -y
  apt-get install -y git curl wget tar ufw fail2ban certbot cron openssl
  log_ok "Система обновлена, пакеты установлены."
}

configure_ufw() {
  local port="$1"
  log_info "Настраиваю UFW..."
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp
  ufw allow "${port}"/tcp
  ufw allow "${port}"/udp
  ufw deny 80/tcp || true
  yes | ufw enable
  log_ok "UFW настроен (SSH, порт ${port}/tcp+udp)."
}

configure_fail2ban() {
  log_info "Настраиваю Fail2Ban..."
  cat >/etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port    = ssh
logpath = /var/log/auth.log
maxretry = 5
EOF
  systemctl enable fail2ban
  systemctl restart fail2ban
  log_ok "Fail2Ban настроен."
}

install_trusttunnel_binary() {
  log_info "Устанавливаю TrustTunnel Endpoint из GitHub Releases..."
  local base_dir="/opt/trusttunnel"
  local bin_dir="${base_dir}/bin"
  local cfg_dir="${base_dir}/config"
  local cert_dir="${base_dir}/certs"

  mkdir -p "$bin_dir" "$cfg_dir" "$cert_dir" /var/log/trusttunnel

  local tmp_tar="/tmp/trusttunnel-linux-x86_64.tar.gz"
  wget -qO "$tmp_tar" "https://github.com/TrustTunnel/TrustTunnel/releases/latest/download/trusttunnel-linux-x86_64.tar.gz"
  tar -xzf "$tmp_tar" -C /tmp
  if [[ ! -f /tmp/trusttunnel_endpoint ]]; then
    log_err "Не найден бинарник trusttunnel_endpoint в архиве."
    exit 1
  fi
  mv /tmp/trusttunnel_endpoint "${bin_dir}/trusttunnel_endpoint"
  chmod +x "${bin_dir}/trusttunnel_endpoint"
  rm -f "$tmp_tar"
  log_ok "TrustTunnel Endpoint установлен в ${bin_dir}."
}

generate_credentials() {
  log_info "Создаю 10 пользователей TrustTunnel..."
  local cfg_dir="/opt/trusttunnel/config"
  local cred_file="${cfg_dir}/credentials.toml"
  : > "$cred_file"
  for i in $(seq 1 10); do
    local user="user${i}"
    local pass
    pass="$(openssl rand -hex 12)"
    cat >>"$cred_file" <<EOF
[[client]]
username = "${user}"
password = "${pass}"

EOF
    log_info "Создан пользователь: ${user} / ${pass}"
  done
  chmod 600 "$cred_file"
  log_ok "Файл credentials.toml создан: ${cred_file}"
}

generate_vpn_config() {
  local port="$1"
  log_info "Создаю vpn.toml..."
  local cfg_dir="/opt/trusttunnel/config"
  cat >"${cfg_dir}/vpn.toml" <<EOF
listen_address = "0.0.0.0:${port}"
credentials_file = "/opt/trusttunnel/config/credentials.toml"

[listen_protocols]

[listen_protocols.http1]

[listen_protocols.http2]

[listen_protocols.quic]

[forward_protocol]
direct = {}
EOF
  chmod 600 "${cfg_dir}/vpn.toml"
  log_ok "vpn.toml создан: ${cfg_dir}/vpn.toml"
}

generate_hosts_config() {
  local domain="$1"
  log_info "Создаю hosts.toml..."
  local cfg_dir="/opt/trusttunnel/config"
  cat >"${cfg_dir}/hosts.toml" <<EOF
[[main_hosts]]
hostname = "${domain}"
cert_chain_path = "/opt/trusttunnel/certs/cert.pem"
private_key_path = "/opt/trusttunnel/certs/key.pem"
EOF
  chmod 600 "${cfg_dir}/hosts.toml"
  log_ok "hosts.toml создан: ${cfg_dir}/hosts.toml"
}

copy_le_certs() {
  local domain="$1"
  log_info "Копирую сертификаты Let's Encrypt в /opt/trusttunnel/certs..."
  local src_dir="/etc/letsencrypt/live/${domain}"
  local cert_dir="/opt/trusttunnel/certs"
  if [[ ! -f "${src_dir}/fullchain.pem" || ! -f "${src_dir}/privkey.pem" ]]; then
    log_err "Сертификаты Let's Encrypt для домена ${domain} не найдены в ${src_dir}."
    return 1
  fi
  cp "${src_dir}/fullchain.pem" "${cert_dir}/cert.pem"
  cp "${src_dir}/privkey.pem" "${cert_dir}/key.pem"
  chmod 600 "${cert_dir}/cert.pem" "${cert_dir}/key.pem"
  log_ok "Сертификаты скопированы."
}

obtain_initial_certificate() {
  local domain="$1" email="$2"
  if [[ -z "$domain" ]]; then
    log_warn "Домен не указан — пропускаю получение сертификата."
    return 0
  fi
  log_info "Получаю первоначальный сертификат Let's Encrypt для домена ${domain}..."
  ufw allow 80/tcp || true
  certbot certonly --standalone -d "$domain" --agree-tos -m "$email" --non-interactive || {
    log_err "Не удалось получить сертификат для ${domain}."
    ufw deny 80/tcp || true
    return 1
  }
  ufw deny 80/tcp || true
  copy_le_certs "$domain" || true
  log_ok "Первоначальный сертификат обработан."
}

create_trusttunnel_service() {
  log_info "Создаю systemd-сервис TrustTunnel..."
  cat >/etc/systemd/system/trusttunnel.service <<'EOF'
[Unit]
Description=TrustTunnel Endpoint
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/trusttunnel
ExecStart=/opt/trusttunnel/bin/trusttunnel_endpoint \
/opt/trusttunnel/config/vpn.toml \
/opt/trusttunnel/config/hosts.toml \
--loglvl info \
--logfile /var/log/trusttunnel/trusttunnel.log
Restart=always
RestartSec=5
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable trusttunnel.service
  systemctl restart trusttunnel.service || true
  log_ok "systemd-сервис TrustTunnel создан и включён."
}

create_trusttunnel_update_timer() {
  log_info "Создаю таймер еженедельного обновления TrustTunnel..."
  cat >/usr/local/sbin/update-trusttunnel.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/trusttunnel"
BIN_DIR="${BASE_DIR}/bin"
TMP_TAR="/tmp/trusttunnel-linux-x86_64.tar.gz"

wget -qO "$TMP_TAR" "https://github.com/TrustTunnel/TrustTunnel/releases/latest/download/trusttunnel-linux-x86_64.tar.gz"
tar -xzf "$TMP_TAR" -C /tmp
if [[ -f /tmp/trusttunnel_endpoint ]]; then
  mv /tmp/trusttunnel_endpoint "${BIN_DIR}/trusttunnel_endpoint"
  chmod +x "${BIN_DIR}/trusttunnel_endpoint"
fi
rm -f "$TMP_TAR"
/bin/systemctl restart trusttunnel.service || true
EOF
  chmod +x /usr/local/sbin/update-trusttunnel.sh

  cat >/etc/systemd/system/update-trusttunnel.service <<'EOF'
[Unit]
Description=Update TrustTunnel from GitHub Releases

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/update-trusttunnel.sh
EOF

  cat >/etc/systemd/system/update-trusttunnel.timer <<'EOF'
[Unit]
Description=Weekly TrustTunnel update

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable update-trusttunnel.timer
  systemctl start update-trusttunnel.timer
  log_ok "Таймер обновления TrustTunnel настроен."
}

create_system_update_reboot_timer() {
  log_info "Создаю таймер еженедельного обновления системы и перезагрузки..."
  cat >/usr/local/sbin/weekly-system-update-and-reboot.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
reboot
EOF
  chmod +x /usr/local/sbin/weekly-system-update-and-reboot.sh

  cat >/etc/systemd/system/weekly-system-update.service <<'EOF'
[Unit]
Description=Weekly system update and reboot

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/weekly-system-update-and-reboot.sh
EOF

  cat >/etc/systemd/system/weekly-system-update.timer <<'EOF'
[Unit]
Description=Weekly system update and reboot timer

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable weekly-system-update.timer
  systemctl start weekly-system-update.timer
  log_ok "Таймер обновления системы настроен."
}

create_certbot_renew_timer() {
  log_info "Создаю сервис и таймер обновления сертификатов..."
  cat >/usr/local/sbin/certbot-renew-with-ufw-and-copy.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DOMAIN_FILE="/opt/trusttunnel/config/domain.txt"
if [[ ! -f "$DOMAIN_FILE" ]]; then
  exit 0
fi
DOMAIN="$(cat "$DOMAIN_FILE")"

ufw allow 80/tcp || true
certbot renew --quiet || true
ufw deny 80/tcp || true

SRC_DIR="/etc/letsencrypt/live/${DOMAIN}"
CERT_DIR="/opt/trusttunnel/certs"

if [[ -f "${SRC_DIR}/fullchain.pem" && -f "${SRC_DIR}/privkey.pem" ]]; then
  cp "${SRC_DIR}/fullchain.pem" "${CERT_DIR}/cert.pem"
  cp "${SRC_DIR}/privkey.pem" "${CERT_DIR}/key.pem"
  chmod 600 "${CERT_DIR}/cert.pem" "${CERT_DIR}/key.pem"
  /bin/systemctl restart trusttunnel.service || true
fi
EOF
  chmod +x /usr/local/sbin/certbot-renew-with-ufw-and-copy.sh

  cat >/etc/systemd/system/certbot-renew-ufw.service <<'EOF'
[Unit]
Description=Renew Let's Encrypt certificates with temporary UFW 80 open and copy to TrustTunnel

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/certbot-renew-with-ufw-and-copy.sh
EOF

  cat >/etc/systemd/system/certbot-renew-ufw.timer <<'EOF'
[Unit]
Description=Periodic certificate renewal with UFW 80 open

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable certbot-renew-ufw.timer
  systemctl start certbot-renew-ufw.timer
  log_ok "Таймер обновления сертификатов настроен."
}

main() {
  require_root

  echo -e "${GREEN}=== Расширенный установщик TrustTunnel Endpoint ===${RESET}"
  echo "Будет выполнено:"
  echo " - обновление системы, установка зависимостей"
  echo " - включение BBR"
  echo " - настройка UFW, Fail2Ban"
  echo " - установка TrustTunnel Endpoint из GitHub Releases (x86_64)"
  echo " - создание 10 пользователей"
  echo " - создание vpn.toml, hosts.toml, credentials.toml"
  echo " - получение и копирование сертификатов Let's Encrypt"
  echo " - создание systemd-сервиса TrustTunnel"
  echo " - настройка еженедельных обновлений TrustTunnel, Ubuntu и сертификатов"
  echo " - еженедельная перезагрузка сервера"
  echo
  pause

  local SERVER_IP DOMAIN EMAIL PORT
  ask_input "Введите IP сервера" SERVER_IP "$(hostname -I | awk '{print $1}')"
  ask_input "Введите доменное имя (FQDN, например vpn.example.com)" DOMAIN ""
  ask_input "Введите email для Let's Encrypt" EMAIL "admin@${DOMAIN}"
  ask_input "Введите порт для TrustTunnel (TCP+UDP)" PORT "443"

  if [[ -z "$DOMAIN" ]]; then
    log_err "Домен обязателен для работы TLS и Let's Encrypt."
    exit 1
  fi

  echo "$DOMAIN" >/opt/trusttunnel-domain.tmp 2>/dev/null || true

  update_system
  enable_bbr
  configure_ufw "$PORT"
  configure_fail2ban
  install_trusttunnel_binary
  generate_credentials
  generate_vpn_config "$PORT"
  generate_hosts_config "$DOMAIN"

  mkdir -p /opt/trusttunnel/config
  echo "$DOMAIN" >/opt/trusttunnel/config/domain.txt

  obtain_initial_certificate "$DOMAIN" "$EMAIL" || log_warn "Сертификат не был успешно получен, проверьте настройки DNS и порт 80."

  create_trusttunnel_service
  create_trusttunnel_update_timer
  create_system_update_reboot_timer
  create_certbot_renew_timer

  echo
  log_ok "Установка TrustTunnel завершена."
  echo "Проверьте статус сервиса: systemctl status trusttunnel"
  echo "Проверьте таймеры: systemctl list-timers | grep trusttunnel"
}

main "$@"

#!/usr/bin/env bash
set -e

echo "==============================================="
echo "  Установка TrustTunnel VPN (расширенная версия)"
echo "  Ubuntu Server 24.04"
echo "==============================================="
echo

if [[ $EUID -ne 0 ]]; then
  echo "Этот скрипт нужно запускать от root (sudo)."
  exit 1
fi

# ------------------ Ввод параметров ------------------

read -rp "Введите публичный IP сервера: " SERVER_IP
read -rp "Введите доменное имя (FQDN): " DOMAIN
read -rp "Введите email для Let's Encrypt: " EMAIL

echo
read -rp "Включить AntiDPI? [Y/n]: " ADPI
[[ -z "$ADPI" || "$ADPI" =~ ^[Yy]$ ]] && ANTIDPI=true || ANTIDPI=false

echo
echo "Параметры:"
echo "  IP:        $SERVER_IP"
echo "  Домен:     $DOMAIN"
echo "  Email:     $EMAIL"
echo "  AntiDPI:   $ANTIDPI"
echo
read -rp "Продолжить установку? [y/N]: " CONFIRM
[[ "$CONFIRM" =~ ^[Yy]$ ]] || exit 1

# ------------------ Обновление системы ------------------

apt update -y
apt upgrade -y

# ------------------ Установка пакетов ------------------

apt install -y curl git ufw fail2ban certbot python3-certbot-nginx \
  docker.io docker-compose-plugin

systemctl enable --now docker

# ------------------ Включение BBR ------------------

echo "Включение TCP BBR..."
grep -qxF "net.core.default_qdisc=fq" /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
grep -qxF "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

# ------------------ Настройка UFW ------------------

ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 443/tcp
ufw --force enable

# ------------------ Fail2Ban ------------------

systemctl enable --now fail2ban

# ------------------ Сертификат Let's Encrypt ------------------

echo "Получение сертификата для $DOMAIN..."
ufw allow 80/tcp

systemctl stop nginx 2>/dev/null || true
certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --keep-until-expiring

ufw delete allow 80/tcp || true

CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

if [[ ! -f "$CERT_PATH" ]]; then
  echo "Ошибка: сертификат не получен."
  exit 1
fi

# ------------------ Хуки обновления сертификата ------------------

mkdir -p /etc/letsencrypt/renewal-hooks/pre
mkdir -p /etc/letsencrypt/renewal-hooks/post

cat > /etc/letsencrypt/renewal-hooks/pre/open80.sh << 'EOF'
#!/usr/bin/env bash
ufw allow 80/tcp || true
EOF

cat > /etc/letsencrypt/renewal-hooks/post/close80.sh << 'EOF'
#!/usr/bin/env bash
ufw delete allow 80/tcp || true
EOF

chmod +x /etc/letsencrypt/renewal-hooks/pre/open80.sh
chmod +x /etc/letsencrypt/renewal-hooks/post/close80.sh

# ------------------ Установка TrustTunnel ------------------

mkdir -p /opt/trusttunnel/config
mkdir -p /opt/trusttunnel/certs

cp "$CERT_PATH" /opt/trusttunnel/certs/cert.pem
cp "$KEY_PATH"  /opt/trusttunnel/certs/key.pem

# Конфиг VPN
cat > /opt/trusttunnel/config/vpn.toml <<EOF
bind_addr = "0.0.0.0:443"
public_ip = "$SERVER_IP"
domain = "$DOMAIN"
antidpi = $ANTIDPI
EOF

# Конфиг хостов
cat > /opt/trusttunnel/config/hosts.toml <<EOF
[[hosts]]
server_name = "$DOMAIN"
cert_file = "/data/certs/cert.pem"
key_file  = "/data/certs/key.pem"
EOF

# Создание 10 пользователей
CRED="/opt/trusttunnel/config/credentials.toml"
echo "# Пользователи TrustTunnel" > "$CRED"

for i in $(seq 1 10); do
  USER="user$i"
  PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
  echo "$USER:$PASS" >> "$CRED"
done

# Docker Compose
cat > /opt/trusttunnel/docker-compose.yml <<EOF
version: "3.8"

services:
  trusttunnel-endpoint:
    image: ghcr.io/trusttunnel/endpoint:latest
    container_name: trusttunnel-endpoint
    restart: always
    network_mode: host
    volumes:
      - /opt/trusttunnel/config/vpn.toml:/data/vpn.toml:ro
      - /opt/trusttunnel/config/hosts.toml:/data/hosts.toml:ro
      - /opt/trusttunnel/config/credentials.toml:/data/credentials.toml:ro
      - /opt/trusttunnel/certs:/data/certs:ro
EOF

# systemd сервис
cat > /etc/systemd/system/trusttunnel.service << 'EOF'
[Unit]
Description=TrustTunnel VPN Endpoint
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/trusttunnel
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable trusttunnel.service
systemctl start trusttunnel.service

echo
echo "==============================================="
echo "Установка завершена!"
echo "Пользователи сохранены в: $CRED"
echo "Сервис: systemctl status trusttunnel.service"
echo "==============================================="

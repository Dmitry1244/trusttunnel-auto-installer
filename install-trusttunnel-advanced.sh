#!/usr/bin/env bash
set -e

echo "==============================================="
echo "  Установка TrustTunnel VPN (без Docker)"
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
  build-essential pkg-config libssl-dev

# ------------------ Установка Rust ------------------

if ! command -v cargo >/dev/null 2>&1; then
  echo "Установка Rust..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
fi

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

# ------------------ Сборка TrustTunnel ------------------

mkdir -p /opt/trusttunnel
cd /opt/trusttunnel

if [[ ! -d TrustTunnel ]]; then
  git clone https://github.com/TrustTunnel/TrustTunnel.git
fi

cd TrustTunnel
cargo build --release

install -m 755 target/release/endpoint /usr/local/bin/trusttunnel-endpoint

# ------------------ Конфиги ------------------

mkdir -p /opt/trusttunnel/config
mkdir -p /opt/trusttunnel/certs

cp "$CERT_PATH" /opt/trusttunnel/certs/cert.pem
cp "$KEY_PATH"  /opt/trusttunnel/certs/key.pem

# vpn.toml
cat > /opt/trusttunnel/config/vpn.toml <<EOF
bind_addr = "0.0.0.0:443"
public_ip = "$SERVER_IP"
domain = "$DOMAIN"
antidpi = $ANTIDPI
credentials = "/opt/trusttunnel/config/credentials.toml"
hosts = "/opt/trusttunnel/config/hosts.toml"
EOF

# hosts.toml
cat > /opt/trusttunnel/config/hosts.toml <<EOF
[[hosts]]
server_name = "$DOMAIN"
cert_file = "/opt/trusttunnel/certs/cert.pem"
key_file  = "/opt/trusttunnel/certs/key.pem"
EOF

# credentials.toml
CRED="/opt/trusttunnel/config/credentials.toml"
echo "# Пользователи TrustTunnel" > "$CRED"

for i in $(seq 1 10); do
  USER="user$i"
  PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
  echo "$USER:$PASS" >> "$CRED"
done

# ------------------ systemd сервис ------------------

cat > /etc/systemd/system/trusttunnel.service <<EOF
[Unit]
Description=TrustTunnel VPN Endpoint
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/trusttunnel-endpoint --config /opt/trusttunnel/config/vpn.toml
Restart=always
RestartSec=3

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

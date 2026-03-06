#!/usr/bin/env bash
set -e

echo "======================================"
echo " TrustTunnel Advanced Auto Installer"
echo "======================================"

if [ "$EUID" -ne 0 ]; then
  echo "Run as root"
  exit
fi

echo "[1/8] Updating system..."

apt update -y
apt upgrade -y


echo "[2/8] Installing TrustTunnel..."

curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s -

cp trusttunnel.service.template /etc/systemd/system/trusttunnel.service || true
systemctl daemon-reload
systemctl enable --now trusttunnel


echo "[3/8] Enabling BBR..."

cat >/etc/sysctl.d/99-trusttunnel.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.netdev_max_backlog=250000
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
EOF

sysctl --system


echo "[4/8] Installing UFW..."

apt install -y ufw

ufw --force reset

ufw default deny incoming
ufw default allow outgoing

ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp

ufw logging on
ufw --force enable


echo "[5/8] Installing Fail2Ban..."

apt install -y fail2ban

cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 10m
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
maxretry = 5
EOF

systemctl enable fail2ban
systemctl restart fail2ban


echo "[6/8] Enabling TrustTunnel AntiDPI..."

CONFIG="/opt/trusttunnel/vpn.toml"

if [ -f "$CONFIG" ]; then

if grep -q "antidpi" "$CONFIG"; then
sed -i 's/antidpi.*/antidpi = true/' "$CONFIG"
else
echo "antidpi = true" >> "$CONFIG"
fi

systemctl restart trusttunnel

fi


echo "[7/8] Applying network tuning..."

INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

ip link set dev $INTERFACE txqueuelen 10000 || true

for q in /sys/class/net/$INTERFACE/queues/rx-*; do
echo ffffffff > $q/rps_cpus || true
done


echo "[8/8] Done!"

echo "--------------------------------------"
echo "TrustTunnel installed and optimized"
echo "--------------------------------------"

echo
echo "Check service:"
echo "systemctl status trusttunnel"

echo
echo "Speed test:"
echo "curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python3"

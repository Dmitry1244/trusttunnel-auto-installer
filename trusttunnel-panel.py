#!/usr/bin/env python3
import base64
import html
import http.server
import os
import re
import secrets
import shutil
import ssl
import time
import subprocess
import urllib.parse
import zipfile
from pathlib import Path

TT_DIR = Path('/opt/trusttunnel')
CLIENT_DIR = Path('/root/trusttunnel-clients')
SOCKS_ADDR = '127.0.0.1:40000'
PANEL_USER = os.environ.get('PANEL_USER', 'admin')
PANEL_PASSWORD = os.environ.get('PANEL_PASSWORD', '')
PANEL_TLS = os.environ.get('PANEL_TLS', '0') == '1'
PANEL_CERT = os.environ.get('PANEL_CERT', '/opt/trusttunnel/certs/cert.pem')
PANEL_KEY = os.environ.get('PANEL_KEY', '/opt/trusttunnel/certs/key.pem')


def run(cmd, timeout=40, input_text=None):
    try:
        p = subprocess.run(cmd, input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except Exception as exc:
        return 1, str(exc)


def read_text(path):
    try:
        return Path(path).read_text(encoding='utf-8')
    except FileNotFoundError:
        return ''


def write_text(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    os.chmod(path, mode)


def q(value):
    return value.replace('\\', '\\\\').replace('"', '\\"')


def endpoint_port():
    m = re.search(r'listen_address\s*=\s*"[^:"]+:(\d+)"', read_text(TT_DIR / 'vpn.toml'))
    return m.group(1) if m else '443'


def domain():
    m = re.search(r'^hostname\s*=\s*"([^"]+)"', read_text(TT_DIR / 'hosts.toml'), re.M)
    return m.group(1) if m else ''


def quic_enabled():
    return '[listen_protocols.quic]' in read_text(TT_DIR / 'vpn.toml')


def uses_warp():
    return '[forward_protocol.socks5]' in read_text(TT_DIR / 'vpn.toml') and SOCKS_ADDR in read_text(TT_DIR / 'vpn.toml')


def forwarder_label():
    cfg = read_text(TT_DIR / 'vpn.toml')
    m = re.search(r'\[forward_protocol\.socks5\]\s*address\s*=\s*"([^"]+)"', cfg)
    if m:
        return 'WARP/SOCKS' if m.group(1) == SOCKS_ADDR else 'Cascade SOCKS5: ' + m.group(1)
    return 'direct'


def cert_mode():
    cert = TT_DIR / 'certs' / 'cert.pem'
    if not cert.exists():
        return 'unknown'
    rc, out = run(['openssl', 'x509', '-in', str(cert), '-noout', '-issuer', '-subject'], timeout=10)
    if rc != 0:
        return 'unknown'
    issuer = ''
    subject = ''
    for line in out.splitlines():
        if line.startswith('issuer='):
            issuer = line.replace('issuer=', '', 1).strip()
        if line.startswith('subject='):
            subject = line.replace('subject=', '', 1).strip()
    if issuer and issuer == subject:
        return 'self-signed'
    if 'ISRG' in issuer or "Let's Encrypt" in issuer:
        return 'letsencrypt'
    return 'unknown'


def load_clients():
    text = read_text(TT_DIR / 'credentials.toml')
    clients = []
    for block in re.split(r'(?m)^\s*\[\[client\]\]\s*$', text):
        user = re.search(r'^\s*username\s*=\s*"([^"]*)"', block, re.M)
        password = re.search(r'^\s*password\s*=\s*"([^"]*)"', block, re.M)
        if user and password:
            clients.append({'username': user.group(1), 'password': password.group(1)})
    return clients


def client_name_valid(name):
    return bool(re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', name or ''))


def random_password():
    return 'TT-' + secrets.token_hex(12)


def client_profile(username, password, protocol):
    cert = read_text(TT_DIR / 'certs' / 'cert.pem')
    body = f'''# Endpoint host name, used for TLS session establishment
hostname = "{q(domain())}"

# Endpoint addresses in IP:port or hostname:port format
addresses = ["{q(domain())}:{endpoint_port()}"]

# Custom SNI value for TLS handshake.
custom_sni = ""

# Whether IPv6 traffic can be routed through the endpoint
has_ipv6 = true

# Username for authorization
username = "{q(username)}"

# Password for authorization
password = "{q(password)}"

# TLS client random hex prefix for connection filtering.
client_random_prefix = ""

# Skip the endpoint certificate verification?
skip_verification = false
'''
    if cert_mode() == 'self-signed':
        body += f'''\n# Endpoint certificate in PEM format.
certificate = """
{cert}
"""
'''
    body += f'''\n# Protocol to be used to communicate with the endpoint [http2, http3]
upstream_protocol = "{protocol}"

# Is anti-DPI measures should be enabled
anti_dpi = false
'''
    return body


def rebuild_client_files(clients):
    CLIENT_DIR.mkdir(parents=True, exist_ok=True)
    for old in CLIENT_DIR.glob('*.toml'):
        old.unlink()
    write_text(CLIENT_DIR / 'clients-credentials.txt', ''.join(f'{c["username"]} {c["password"]}\n' for c in clients), 0o600)
    cert = TT_DIR / 'certs' / 'cert.pem'
    if cert.exists():
        shutil.copy2(cert, CLIENT_DIR / 'server-cert.pem')
        os.chmod(CLIENT_DIR / 'server-cert.pem', 0o644)
    protocols = ['http2', 'http3'] if quic_enabled() else ['http2']
    for c in clients:
        for protocol in protocols:
            write_text(CLIENT_DIR / f'{c["username"]}-{protocol}.toml', client_profile(c['username'], c['password'], protocol), 0o600)
    archive = Path(f'/root/trusttunnel-clients-{domain() or "trusttunnel"}.zip')
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(CLIENT_DIR.iterdir()):
            if item.is_file():
                zf.write(item, item.name)


def save_clients(clients):
    cred = TT_DIR / 'credentials.toml'
    if cred.exists():
        shutil.copy2(cred, cred.with_suffix('.toml.bak'))
    lines = ['# Managed TrustTunnel users. One user/password per client.']
    for c in clients:
        lines += ['', '[[client]]', f'username = "{q(c["username"])}"', f'password = "{q(c["password"])}"']
    write_text(cred, '\n'.join(lines) + '\n', 0o600)
    rebuild_client_files(clients)
    run(['systemctl', 'restart', 'trusttunnel'], timeout=20)


def switch_forwarder(mode, address=''):
    cfg = TT_DIR / 'vpn.toml'
    text = read_text(cfg)
    text = re.sub(r'\n\[forward_protocol\.(socks5|direct)\][\s\S]*?(?=\n\[|$)', '', text)
    if '[forward_protocol]' not in text:
        text += '\n[forward_protocol]\n'
    if mode == 'direct':
        block = '\n[forward_protocol.direct]\n'
    else:
        block = f'\n[forward_protocol.socks5]\naddress = "{q(address)}"\nextended_auth = false\n'
    text = text.replace('[forward_protocol]\n', '[forward_protocol]\n' + block, 1)
    write_text(cfg, text, 0o644)
    run(['systemctl', 'restart', 'trusttunnel'], timeout=20)


def deeplink(username):
    cmd = [str(TT_DIR / 'trusttunnel_endpoint'), 'vpn.toml', 'hosts.toml', '-c', username, '-a', f'{domain()}:{endpoint_port()}', '--format', 'deeplink']
    rc, out = run(cmd, timeout=10)
    return out if rc == 0 and out.startswith('tt://') else ''


def service_status(name):
    rc, out = run(['systemctl', 'is-active', name], timeout=5)
    return out if out else 'inactive'


def public_ip(args):
    rc, out = run(['curl', *args, '-sS', '--max-time', '10', 'https://ifconfig.me'], timeout=15)
    return out if rc == 0 else 'unavailable'


def speedtest_output():
    lines = ['Direct public IP: ' + public_ip(['-4']), 'WARP public IP: ' + public_ip(['-x', f'socks5h://{SOCKS_ADDR}']), '']
    if shutil.which('speedtest-cli'):
        rc, out = run(['speedtest-cli', '--secure', '--simple'], timeout=90)
        lines.append(out if out else f'speedtest-cli exit code: {rc}')
    else:
        rc, out = run(['curl', '-L', '-o', '/dev/null', '-sS', '--max-time', '60', '-w', 'download=%{speed_download} bytes/sec', 'https://speed.cloudflare.com/__down?bytes=104857600'], timeout=70)
        lines.append(out if out else f'curl exit code: {rc}')
    return '\n'.join(lines)


def human_bytes(value):
    value = float(value)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if value < 1024 or unit == 'TiB':
            return f'{value:.1f} {unit}' if unit != 'B' else f'{int(value)} B'
        value /= 1024


def system_metrics():
    memory = {}
    for line in read_text('/proc/meminfo').splitlines():
        parts = line.replace(':', '').split()
        if len(parts) >= 2:
            memory[parts[0]] = int(parts[1]) * 1024
    total = memory.get('MemTotal', 0)
    available = memory.get('MemAvailable', memory.get('MemFree', 0))
    disk = shutil.disk_usage('/')
    uptime_seconds = int(float(read_text('/proc/uptime').split()[0] or 0))
    days, rest = divmod(uptime_seconds, 86400)
    hours, minutes = divmod(rest, 3600)
    return {
        'cpu': f'load: ' + ' / '.join(f'{item:.2f}' for item in getattr(os, 'getloadavg', lambda: (0.0, 0.0, 0.0))()),
        'memory': f'{human_bytes(max(0, total - available))} / {human_bytes(total)}',
        'disk': f'{human_bytes(disk.used)} / {human_bytes(disk.total)}',
        'uptime': f'{days}d {hours:02d}h {minutes // 60:02d}m',
    }


def traffic_rows():
    rows = []
    for line in read_text('/proc/net/dev').splitlines()[2:]:
        if ':' not in line:
            continue
        name, values = line.split(':', 1)
        values = values.split()
        if name.strip() != 'lo' and len(values) >= 9:
            rows.append((name.strip(), human_bytes(int(values[0])), human_bytes(int(values[8]))))
    return rows


def monitoring_html():
    metrics = system_metrics()
    cards = ''.join(f'<div class="metric"><b>{html.escape(label)}</b>{html.escape(value)}</div>' for label, value in (('CPU', metrics['cpu']), ('RAM', metrics['memory']), ('Disk /', metrics['disk']), ('Uptime', metrics['uptime'])))
    rows = ''.join(f'<tr><td>{html.escape(name)}</td><td>{received}</td><td>{sent}</td></tr>' for name, received, sent in traffic_rows()) or '<tr><td colspan="3">Нет доступных интерфейсов.</td></tr>'
    return f'<section><h2>Мониторинг системы</h2><div class="grid">{cards}</div></section><section><h2>Трафик сервера</h2><p class="hint">Общие счётчики интерфейсов с момента запуска VPS. Loopback не учитывается; по отдельным клиентам TrustTunnel статистика не доступна.</p><table><thead><tr><th>Интерфейс</th><th>Принято</th><th>Отправлено</th></tr></thead><tbody>{rows}</tbody></table></section>'

def diagnostics_output():
    lines = [
        f'Domain: {domain() or "not configured"}',
        f'Endpoint port: {endpoint_port()}',
        f'TrustTunnel: {service_status("trusttunnel")}',
        f'WARP: {service_status("warp-wireproxy")}',
        f'HTTP/3 QUIC: {"enabled" if quic_enabled() else "disabled"}',
        f'Certificate: {cert_mode()}',
        '', 'DNS:',
    ]
    if domain():
        lines.append(run(['getent', 'ahosts', domain()], timeout=10)[1] or 'DNS lookup failed')
    lines += ['', 'Listening ports:', run(['ss', '-lntup'], timeout=10)[1], '', 'Certificate dates:']
    cert = TT_DIR / 'certs' / 'cert.pem'
    if cert.exists():
        lines.append(run(['openssl', 'x509', '-in', str(cert), '-noout', '-dates'], timeout=10)[1])
    else:
        lines.append('certificate file not found')
    lines += ['', 'Direct IP: ' + public_ip(['-4']), 'WARP IP: ' + public_ip(['-x', f'socks5h://{SOCKS_ADDR}'])]
    return '\n'.join(lines)


def recent_logs(service, lines=120):
    allowed = {'trusttunnel': 'trusttunnel', 'warp': 'warp-wireproxy', 'fail2ban': 'fail2ban', 'panel': 'trusttunnel-panel'}
    unit = allowed.get(service, 'trusttunnel')
    return run(['journalctl', '-u', unit, '--no-pager', '-n', str(lines)], timeout=15)[1] or 'No logs available.'


def backup_archive():
    backup_dir = Path('/root/trusttunnel-identity-backup')
    backup_dir.mkdir(parents=True, exist_ok=True)
    for src, dst in [(TT_DIR/'certs'/'cert.pem', backup_dir/'cert.pem'), (TT_DIR/'certs'/'key.pem', backup_dir/'key.pem'), (TT_DIR/'credentials.toml', backup_dir/'credentials.toml'), (TT_DIR/'hosts.toml', backup_dir/'hosts.toml'), (TT_DIR/'vpn.toml', backup_dir/'vpn.toml')]:
        if src.exists():
            shutil.copy2(src, dst)
    archive = Path('/root/trusttunnel-identity-backup.zip')
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for item in backup_dir.iterdir():
            if item.is_file():
                zf.write(item, item.name)
    os.chmod(archive, 0o600)
    return archive
PANEL_AUDIT_LOG = Path('/var/log/trusttunnel-panel-audit.log')
PANEL_TELEGRAM_ENV = Path('/etc/trusttunnel-panel-telegram.env')
PANEL_TIMER_UNIT = Path('/etc/systemd/system/trusttunnel-maintenance.service')
PANEL_TIMER = Path('/etc/systemd/system/trusttunnel-maintenance.timer')


def audit_log(action, detail=''):
    stamp = time.strftime('%Y-%m-%d %H:%M:%S %z')
    try:
        with PANEL_AUDIT_LOG.open('a', encoding='utf-8') as fp:
            fp.write(f'{stamp} {action} {detail}\n')
        os.chmod(PANEL_AUDIT_LOG, 0o600)
    except OSError:
        pass


def telegram_config():
    values = {}
    for line in read_text(PANEL_TELEGRAM_ENV).splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip()
    return values


def send_telegram(text):
    config = telegram_config()
    token, chat_id = config.get('TELEGRAM_BOT_TOKEN', ''), config.get('TELEGRAM_CHAT_ID', '')
    if not token or not chat_id:
        return 'Telegram is not configured.'
    rc, out = run(['curl', '-fsS', '--max-time', '15', '-X', 'POST', f'https://api.telegram.org/bot{token}/sendMessage', '-d', f'chat_id={chat_id}', '--data-urlencode', f'text={text}'], timeout=20)
    return 'Telegram message sent.' if rc == 0 else out


def save_telegram(token, chat_id):
    if not token or not chat_id:
        return 'Bot token and chat ID are required.'
    write_text(PANEL_TELEGRAM_ENV, f'TELEGRAM_BOT_TOKEN={token}\nTELEGRAM_CHAT_ID={chat_id}\n', 0o600)
    audit_log('telegram_configured')
    return send_telegram('TrustTunnel: Telegram notifications are connected.')


def endpoint_version():
    binary = TT_DIR / 'trusttunnel_endpoint'
    if not binary.exists():
        return 'not installed'
    rc, out = run([str(binary), '--version'], timeout=10)
    return out.splitlines()[0] if rc == 0 and out else 'unknown'


def certificate_info():
    cert = TT_DIR / 'certs' / 'cert.pem'
    if not cert.exists():
        return 'Certificate file not found.'
    return run(['openssl', 'x509', '-in', str(cert), '-noout', '-issuer', '-subject', '-dates'], timeout=10)[1]


def renew_certificate():
    if cert_mode() != 'letsencrypt':
        return 'Manual renewal is only available for Let\'s Encrypt certificates.'
    added_rule = False
    try:
        if 'Status: active' in run(['ufw', 'status'], timeout=15)[1]:
            rules = run(['ufw', 'status', 'numbered'], timeout=15)[1]
            if '80/tcp' not in rules:
                run(['ufw', 'allow', '80/tcp', 'comment', "TrustTunnel Let's Encrypt"], timeout=20)
                added_rule = True
        rc, out = run(['certbot', 'renew', '--standalone', '--force-renewal'], timeout=180)
        if rc == 0:
            live = Path('/etc/letsencrypt/live') / domain()
            if (live / 'fullchain.pem').exists() and (live / 'privkey.pem').exists():
                shutil.copy2(live / 'fullchain.pem', TT_DIR / 'certs' / 'cert.pem')
                shutil.copy2(live / 'privkey.pem', TT_DIR / 'certs' / 'key.pem')
                os.chmod(TT_DIR / 'certs' / 'key.pem', 0o600)
                os.chmod(TT_DIR / 'certs' / 'cert.pem', 0o644)
            run(['systemctl', 'restart', 'trusttunnel'], timeout=20)
            audit_log('certificate_renewed')
            return out or 'Certificate renewed and TrustTunnel restarted.'
        return out
    finally:
        if added_rule:
            run(['ufw', 'delete', 'allow', '80/tcp'], timeout=20)


def restart_service(name):
    allowed = {'trusttunnel', 'warp-wireproxy', 'fail2ban'}
    if name not in allowed:
        return 'Unknown service.'
    rc, out = run(['systemctl', 'restart', name], timeout=30)
    audit_log('service_restart', name)
    return out or f'{name} restarted.'


def maintenance_setup(enabled):
    if not enabled:
        run(['systemctl', 'disable', '--now', 'trusttunnel-maintenance.timer'], timeout=20)
        audit_log('maintenance_disabled')
        return 'Scheduled maintenance disabled.'
    service = '''[Unit]\nDescription=TrustTunnel daily maintenance\n\n[Service]\nType=oneshot\nExecStart=/bin/sh -c 'systemctl is-active --quiet trusttunnel || systemctl restart trusttunnel; systemctl is-active --quiet warp-wireproxy || true; /usr/bin/python3 -c ""'\n'''
    timer = '''[Unit]\nDescription=TrustTunnel daily maintenance timer\n\n[Timer]\nOnCalendar=daily\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n'''
    write_text(PANEL_TIMER_UNIT, service, 0o644)
    write_text(PANEL_TIMER, timer, 0o644)
    run(['systemctl', 'daemon-reload'], timeout=20)
    run(['systemctl', 'enable', '--now', 'trusttunnel-maintenance.timer'], timeout=20)
    audit_log('maintenance_enabled')
    return 'Daily health-check timer enabled.'


def maintenance_status():
    return run(['systemctl', 'list-timers', '--all', 'trusttunnel-maintenance.timer'], timeout=20)[1]


def update_system_packages():
    rc, out = run(['apt-get', 'update'], timeout=120)
    if rc != 0:
        return out
    rc, out = run(['apt-get', '-y', 'upgrade'], timeout=600)
    audit_log('system_packages_updated', f'rc={rc}')
    return out or 'System packages updated.'


def audit_output():
    return read_text(PANEL_AUDIT_LOG) or 'No panel actions recorded yet.'
def rules_text():
    return read_text(TT_DIR / 'rules.toml') or '# Empty rules file: all authenticated clients are allowed.\n'



def validate_port(value):
    return bool(re.fullmatch(r'\d{1,5}', value or '')) and 1 <= int(value) <= 65535


def current_ssh_port():
    dropin = Path('/etc/ssh/sshd_config.d/99-trusttunnel-port.conf')
    text = read_text(dropin) or read_text('/etc/ssh/sshd_config')
    ports = re.findall(r'(?m)^\s*Port\s+(\d+)', text)
    return ports[-1] if ports else '22'


def current_panel_env():
    env = {'PANEL_BIND': '127.0.0.1', 'PANEL_PORT': os.environ.get('PANEL_PORT', '8088'), 'PANEL_USER': PANEL_USER, 'PANEL_PASSWORD': PANEL_PASSWORD, 'PANEL_TLS': '0', 'PANEL_CERT': PANEL_CERT, 'PANEL_KEY': PANEL_KEY}
    for line in read_text('/etc/trusttunnel-panel.env').splitlines():
        if '=' in line and not line.strip().startswith('#'):
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip()
    return env


def change_endpoint_port(new_port):
    if not validate_port(new_port):
        return 'Invalid TrustTunnel port.'
    old_port = endpoint_port()
    if new_port == old_port:
        return f'TrustTunnel port already {old_port}.'
    cfg = TT_DIR / 'vpn.toml'
    text = read_text(cfg)
    shutil.copy2(cfg, cfg.with_suffix('.toml.bak'))
    text = re.sub(r'listen_address\s*=\s*"[^"]+"', f'listen_address = "0.0.0.0:{new_port}"', text, count=1)
    write_text(cfg, text, 0o644)
    run(['ufw', 'allow', f'{new_port}/tcp', 'comment', 'TrustTunnel TCP'], timeout=20)
    run(['ufw', 'delete', 'allow', f'{old_port}/tcp'], timeout=20)
    if quic_enabled():
        run(['ufw', 'allow', f'{new_port}/udp', 'comment', 'TrustTunnel QUIC'], timeout=20)
        run(['ufw', 'delete', 'allow', f'{old_port}/udp'], timeout=20)
    rebuild_client_files(load_clients())
    run(['systemctl', 'restart', 'trusttunnel'], timeout=20)
    return f'TrustTunnel port changed: {old_port} -> {new_port}. Client files rebuilt.'


def update_panel_access(mode, port):
    if not validate_port(port):
        return 'Invalid panel port.'
    env = current_panel_env()
    old_port = env.get('PANEL_PORT', '8088')
    if mode == 'https':
        env['PANEL_BIND'] = '0.0.0.0'
        env['PANEL_TLS'] = '1'
        env['PANEL_CERT'] = str(TT_DIR / 'certs' / 'cert.pem')
        env['PANEL_KEY'] = str(TT_DIR / 'certs' / 'key.pem')
        run(['ufw', 'allow', f'{port}/tcp', 'comment', 'TrustTunnel Panel HTTPS'], timeout=20)
    else:
        env['PANEL_BIND'] = '127.0.0.1'
        env['PANEL_TLS'] = '0'
        run(['ufw', 'delete', 'allow', f'{old_port}/tcp'], timeout=20)
    env['PANEL_PORT'] = port
    text = ''.join(f'{k}={v}\n' for k, v in env.items() if k.startswith('PANEL_'))
    write_text('/etc/trusttunnel-panel.env', text, 0o600)
    subprocess.Popen(['sh', '-c', 'sleep 1; systemctl restart trusttunnel-panel >/dev/null 2>&1'])
    scheme = 'https' if mode == 'https' else 'http'
    host = domain() if mode == 'https' and domain() else '127.0.0.1'
    return f'Panel access updated: {scheme}://{host}:{port}. Service will restart now.'


def update_panel_credentials(username, password):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', username or ''):
        return 'Invalid panel username.'
    if len(password or '') < 12 or '\n' in password or '\r' in password or '=' in password:
        return 'Password must be at least 12 characters and cannot contain a newline or =.'
    env = current_panel_env()
    env['PANEL_USER'] = username
    env['PANEL_PASSWORD'] = password
    text = ''.join(f'{key}={value}\n' for key, value in env.items() if key.startswith('PANEL_'))
    write_text('/etc/trusttunnel-panel.env', text, 0o600)
    audit_log('panel_credentials_changed', username)
    subprocess.Popen(['sh', '-c', 'sleep 1; systemctl restart trusttunnel-panel >/dev/null 2>&1'])
    return 'Panel credentials updated. Sign in again with the new credentials.'

def fail2ban_output(action, ip=''):
    if action == 'status':
        return run(['fail2ban-client', 'status', 'sshd'], timeout=15)[1]
    if action == 'enable':
        run(['apt-get', '-o', 'Acquire::Retries=3', 'install', '-y', '--no-install-recommends', '--no-upgrade', 'fail2ban'], timeout=90)
        jail = f'''[sshd]\nenabled = true\nport = {current_ssh_port()}\nfilter = sshd\nbackend = systemd\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\nignoreip = 127.0.0.1/8 ::1\n'''
        write_text('/etc/fail2ban/jail.d/sshd.local', jail, 0o644)
        run(['systemctl', 'enable', '--now', 'fail2ban'], timeout=20)
        run(['systemctl', 'restart', 'fail2ban'], timeout=20)
        return 'fail2ban enabled for SSH.'
    if action == 'disable':
        return run(['systemctl', 'disable', '--now', 'fail2ban'], timeout=20)[1] or 'fail2ban disabled.'
    if action == 'unban' and ip:
        return run(['fail2ban-client', 'set', 'sshd', 'unbanip', ip], timeout=15)[1]
    return 'Unknown fail2ban action.'


def ufw_output(action, port='', proto='tcp'):
    if action == 'status':
        return run(['ufw', 'status', 'verbose'], timeout=20)[1]
    if action in ('allow', 'delete'):
        if not validate_port(port) or proto not in ('tcp', 'udp'):
            return 'Invalid port/proto.'
        if action == 'allow':
            return run(['ufw', 'allow', f'{port}/{proto}'], timeout=20)[1]
        return run(['ufw', 'delete', 'allow', f'{port}/{proto}'], timeout=20)[1]
    if action == 'rebuild':
        ssh_port = current_ssh_port()
        tt_port = endpoint_port()
        cmds = [
            ['ufw', '--force', 'reset'], ['ufw', 'default', 'deny', 'incoming'], ['ufw', 'default', 'allow', 'outgoing'],
            ['ufw', 'allow', f'{ssh_port}/tcp', 'comment', 'SSH'], ['ufw', 'allow', f'{tt_port}/tcp', 'comment', 'TrustTunnel TCP']
        ]
        if quic_enabled():
            cmds.append(['ufw', 'allow', f'{tt_port}/udp', 'comment', 'TrustTunnel QUIC'])
        cmds.append(['ufw', '--force', 'enable'])
        out = []
        for cmd in cmds:
            out.append(run(cmd, timeout=30)[1])
        out.append(run(['ufw', 'status', 'verbose'], timeout=20)[1])
        return '\n'.join(out)
    return 'Unknown UFW action.'
def html_page(message='', log=''):
    env = current_panel_env()
    clients = load_clients()
    protocols = ['http2', 'http3'] if quic_enabled() else ['http2']
    monitor_block = monitoring_html()
    rows = []
    for c in clients:
        links = []
        link = deeplink(c['username'])
        if link:
            links.append(f'<a href="{html.escape(link)}">tt-link</a> <a href="/qr-link/{urllib.parse.quote(c["username"])}.png">QR</a>')
        for protocol in protocols:
            links.append(f'<a href="/client/{urllib.parse.quote(c["username"])}/{protocol}.toml">{protocol}</a> <a href="/qr/{urllib.parse.quote(c["username"])}/{protocol}.png">QR</a>')
        rows.append(f'''<tr><td>{html.escape(c['username'])}</td><td><code>{html.escape(c['password'])}</code></td><td>{' | '.join(links)}</td><td><form method="post" action="/client/password"><input type="hidden" name="username" value="{html.escape(c['username'])}"><button>Новый пароль</button></form><form method="post" action="/client/delete"><input type="hidden" name="username" value="{html.escape(c['username'])}"><button class="danger">Удалить</button></form></td></tr>''')
    msg = f'<div class="message">{html.escape(message)}</div>' if message else ''
    log_block = f'<section><pre>{html.escape(log)}</pre></section>' if log else ''
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TrustTunnel Panel</title><style>body{{margin:0;font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f6f7f9;color:#17202a}}header{{background:#17202a;color:white;padding:16px 24px}}main{{max-width:1180px;margin:0 auto;padding:24px}}section{{background:white;border:1px solid #d8dee6;border-radius:8px;margin-bottom:18px;padding:18px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}}.metric{{border:1px solid #e1e6ee;border-radius:6px;padding:12px;background:#fbfcfe}}.metric b{{display:block;font-size:13px;color:#536171;margin-bottom:6px}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;border-bottom:1px solid #e8edf3;padding:10px;vertical-align:top}}form{{display:inline-block;margin:3px}}input{{padding:8px;border:1px solid #ccd3dc;border-radius:6px}}button{{padding:8px 11px;border:1px solid #b7c0cc;border-radius:6px;background:#f7f9fb;cursor:pointer}}button.primary{{background:#1463ff;color:white;border-color:#1463ff}}button.danger{{background:#fff4f4;color:#a21616;border-color:#edb5b5}}pre{{white-space:pre-wrap;background:#111827;color:#d1e7dd;border-radius:6px;padding:14px;overflow:auto}}.message{{padding:10px 12px;background:#eef6ff;border:1px solid #b8d9ff;border-radius:6px;margin-bottom:14px}}a{{color:#145bd7;text-decoration:none}}.hint{{color:#536171;font-size:14px;line-height:1.45}}</style></head><body><header><h1>TrustTunnel Panel</h1></header><main>{msg}<section><div class="grid"><div class="metric"><b>Domain</b>{html.escape(domain())}:{endpoint_port()}</div><div class="metric"><b>TrustTunnel</b>{html.escape(service_status('trusttunnel'))}</div><div class="metric"><b>WARP</b>{html.escape(service_status('warp-wireproxy'))}</div><div class="metric"><b>Forward</b>{html.escape(forwarder_label())}</div><div class="metric"><b>QUIC/HTTP3</b>{'enabled' if quic_enabled() else 'disabled'}</div><div class="metric"><b>Certificate</b>{html.escape(cert_mode())}</div></div></section>{monitor_block}<section><form method="post" action="/action"><button name="action" value="restart" class="primary">Перезапустить TrustTunnel</button></form><form method="post" action="/action"><button name="action" value="warp">WARP</button></form><form method="post" action="/action"><button name="action" value="direct">Direct</button></form><form method="post" action="/action"><button name="action" value="speedtest">Speedtest</button></form><form method="post" action="/action"><button name="action" value="backup">Backup identity</button></form><a href="/backup/latest.zip">Скачать backup</a><form method="post" action="/action"><button name="action" value="diagnostics">Диагностика</button></form><form method="post" action="/action"><button name="action" value="logs">Логи TrustTunnel</button></form><form method="post" action="/action"><button name="action" value="certificate">Сертификат</button></form><form method="post" action="/action"><button name="action" value="renew-cert">Обновить Let's Encrypt</button></form><form method="post" action="/action"><button name="action" value="restart-warp">Перезапустить WARP</button></form><form method="post" action="/action"><button name="action" value="audit">История действий</button></form></section><section><h2>Обслуживание и уведомления</h2><div class="grid"><div><b>TrustTunnel endpoint</b><br><code>{html.escape(endpoint_version())}</code><form method="post" action="/maintenance"><button name="action" value="packages">Обновить пакеты VPS</button></form></div><div><b>Планировщик</b><form method="post" action="/maintenance"><button name="action" value="status">Статус</button><button name="action" value="enable">Включить daily check</button><button name="action" value="disable" class="danger">Отключить</button></form></div></div><form method="post" action="/telegram"><input name="token" placeholder="Telegram bot token" required><input name="chat_id" placeholder="Chat ID" required><button class="primary">Сохранить и проверить Telegram</button></form><p class="hint">Уведомления Telegram отправляются при тесте настройки. Автоматические сообщения можно безопасно включать после проверки таймера на тестовом VPS.</p></section><section><h2>Каскадный upstream</h2><form method="post" action="/cascade"><input name="address" placeholder="127.0.0.1:1080 или proxy.example:1080" required><button class="primary">Включить SOCKS5 cascade</button></form></section><section><h2>Порты</h2><form method="post" action="/ports/endpoint"><input name="port" value="{endpoint_port()}" required><button class="primary">Сменить порт TrustTunnel</button></form></section><section><h2>Доступ к панели</h2><form method="post" action="/panel/access"><input name="port" value="{html.escape(env.get('PANEL_PORT', '8088'))}" required><button name="mode" value="localhost">Localhost</button><button name="mode" value="https" class="primary">HTTPS</button></form><form method="post" action="/panel/credentials"><input name="username" value="{html.escape(env.get('PANEL_USER', 'admin'))}" required><input name="password" type="password" placeholder="Новый пароль, минимум 12 символов" required><button class="primary">Сменить логин и пароль</button></form></section><section><h2>fail2ban</h2><form method="post" action="/fail2ban"><button name="action" value="status">Статус</button><button name="action" value="enable">Включить</button><button name="action" value="disable" class="danger">Отключить</button><input name="ip" placeholder="IP для разбана"><button name="action" value="unban">Разбанить IP</button></form></section><section><h2>UFW</h2><form method="post" action="/ufw"><button name="action" value="status">Статус</button><button name="action" value="rebuild">Пересобрать базовые правила</button><input name="port" placeholder="порт"><input name="proto" value="tcp"><button name="action" value="allow">Открыть</button><button name="action" value="delete" class="danger">Закрыть</button></form></section><section><h2>Клиенты</h2><form method="post" action="/client/add"><input name="username" placeholder="client22" required><input name="password" placeholder="пароль, можно пусто"><button class="primary">Добавить клиента</button></form><table><thead><tr><th>Логин</th><th>Пароль</th><th>Ссылки/QR</th><th>Действия</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section><section><h2>Rules</h2><form method="post" action="/rules/add-deny"><input name="cidr" placeholder="1.2.3.4/32" required><button>Добавить deny CIDR</button></form><form method="post" action="/rules/reset"><button class="danger">Сбросить rules.toml</button></form><pre>{html.escape(rules_text())}</pre></section>{log_block}</main></body></html>'''


class Handler(http.server.BaseHTTPRequestHandler):
    def authenticated(self):
        if not PANEL_PASSWORD:
            return True
        auth = self.headers.get('Authorization', '')
        expected = 'Basic ' + base64.b64encode(f'{PANEL_USER}:{PANEL_PASSWORD}'.encode()).decode()
        if auth == expected:
            return True
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="TrustTunnel Panel"')
        self.end_headers()
        return False

    def send_html(self, message='', log=''):
        body = html_page(message, log).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def form(self):
        length = int(self.headers.get('Content-Length', '0'))
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(length).decode()).items()}

    def redirect(self, message):
        self.send_response(303)
        self.send_header('Location', '/?msg=' + urllib.parse.quote(message))
        self.end_headers()

    def do_GET(self):
        if self.path == '/health':
            self.send_response(200); self.end_headers(); self.wfile.write(b'ok\n'); return
        if not self.authenticated():
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/':
            self.send_html(urllib.parse.parse_qs(parsed.query).get('msg', [''])[0]); return
        m = re.fullmatch(r'/client/([^/]+)/(http2|http3)\.toml', parsed.path)
        if m:
            path = CLIENT_DIR / f'{urllib.parse.unquote(m.group(1))}-{m.group(2)}.toml'
            if path.exists():
                body = path.read_bytes(); self.send_response(200); self.send_header('Content-Type', 'application/toml; charset=utf-8'); self.send_header('Content-Disposition', f'attachment; filename="{path.name}"'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body); return
        m = re.fullmatch(r'/qr/([^/]+)/(http2|http3)\.png', parsed.path)
        if m:
            path = CLIENT_DIR / f'{urllib.parse.unquote(m.group(1))}-{m.group(2)}.toml'
            if path.exists() and shutil.which('qrencode'):
                p = subprocess.run(['qrencode', '-t', 'PNG', '-o', '-'], input=path.read_bytes(), stdout=subprocess.PIPE)
                self.send_response(200); self.send_header('Content-Type', 'image/png'); self.end_headers(); self.wfile.write(p.stdout); return
        m = re.fullmatch(r'/qr-link/([^/]+)\.png', parsed.path)
        if m and shutil.which('qrencode'):
            link = deeplink(urllib.parse.unquote(m.group(1)))
            if link:
                p = subprocess.run(['qrencode', '-t', 'PNG', '-o', '-'], input=link.encode('utf-8'), stdout=subprocess.PIPE)
                self.send_response(200); self.send_header('Content-Type', 'image/png'); self.end_headers(); self.wfile.write(p.stdout); return
        if parsed.path == '/backup/latest.zip':
            archive = backup_archive()
            body = archive.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Disposition', 'attachment; filename="trusttunnel-identity-backup.zip"')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self):
        if not self.authenticated():
            return
        f = self.form()
        if self.path == '/action':
            action = f.get('action', '')
            if action == 'restart':
                rc, out = run(['systemctl', 'restart', 'trusttunnel'], timeout=20); self.send_html('TrustTunnel restarted.', out); return
            if action == 'warp':
                run(['systemctl', 'enable', '--now', 'warp-wireproxy'], timeout=20); switch_forwarder('socks5', SOCKS_ADDR); self.redirect('TrustTunnel switched to WARP.'); return
            if action == 'direct':
                switch_forwarder('direct'); self.redirect('TrustTunnel switched to direct.'); return
            if action == 'speedtest':
                self.send_html('Speedtest finished.', speedtest_output()); return
            if action == 'backup':
                backup_dir = Path('/root/trusttunnel-identity-backup'); backup_dir.mkdir(parents=True, exist_ok=True)
                for src, dst in [(TT_DIR/'certs'/'cert.pem', backup_dir/'cert.pem'), (TT_DIR/'certs'/'key.pem', backup_dir/'key.pem'), (TT_DIR/'credentials.toml', backup_dir/'credentials.toml'), (TT_DIR/'hosts.toml', backup_dir/'hosts.toml')]:
                    if src.exists(): shutil.copy2(src, dst)
                backup_archive(); self.redirect('Identity backup created.'); return
            if action == 'diagnostics':
                self.send_html('Diagnostics completed.', diagnostics_output()); return
            if action == 'logs':
                self.send_html('TrustTunnel logs.', recent_logs('trusttunnel')); return
            if action == 'certificate':
                self.send_html('Certificate information.', certificate_info()); return
            if action == 'renew-cert':
                self.send_html('Certificate renewal finished.', renew_certificate()); return
            if action == 'restart-warp':
                self.send_html('WARP restart finished.', restart_service('warp-wireproxy')); return
            if action == 'audit':
                self.send_html('Panel action history.', audit_output()); return
        if self.path == '/maintenance':
            action = f.get('action', '')
            if action == 'packages':
                self.send_html('System update finished.', update_system_packages()); return
            if action == 'status':
                self.send_html('Maintenance timer status.', maintenance_status()); return
            if action in ('enable', 'disable'):
                self.send_html('Maintenance scheduler updated.', maintenance_setup(action == 'enable')); return
        if self.path == '/telegram':
            self.send_html('Telegram settings.', save_telegram(f.get('token', '').strip(), f.get('chat_id', '').strip()))
            return
        if self.path == '/cascade':
            address = f.get('address', '').strip()
            if not re.fullmatch(r'[A-Za-z0-9_.:-]{3,255}', address):
                self.redirect('Invalid SOCKS5 address.'); return
            switch_forwarder('socks5', address); self.redirect('Cascade SOCKS5 enabled.'); return
        if self.path == '/client/add':
            username = f.get('username', '').strip(); password = f.get('password', '').strip() or random_password()
            if not client_name_valid(username): self.redirect('Invalid username.'); return
            clients = load_clients()
            if any(c['username'] == username for c in clients): self.redirect('Client already exists.'); return
            clients.append({'username': username, 'password': password}); save_clients(clients); self.redirect(f'Client {username} added.'); return
        if self.path == '/client/delete':
            username = f.get('username', ''); save_clients([c for c in load_clients() if c['username'] != username]); self.redirect(f'Client {username} deleted.'); return
        if self.path == '/client/password':
            username = f.get('username', ''); clients = load_clients()
            for c in clients:
                if c['username'] == username: c['password'] = random_password()
            save_clients(clients); self.redirect(f'Password changed for {username}.'); return
        if self.path == '/ports/endpoint':
            self.redirect(change_endpoint_port(f.get('port', '').strip()))
            return
        if self.path == '/panel/access':
            self.redirect(update_panel_access(f.get('mode', 'localhost'), f.get('port', '8088').strip()))
            return
        if self.path == '/panel/credentials':
            self.send_html('Panel credentials.', update_panel_credentials(f.get('username', '').strip(), f.get('password', '')))
            return
        if self.path == '/fail2ban':
            self.send_html('fail2ban action finished.', fail2ban_output(f.get('action', 'status'), f.get('ip', '').strip()))
            return
        if self.path == '/ufw':
            self.send_html('UFW action finished.', ufw_output(f.get('action', 'status'), f.get('port', '').strip(), f.get('proto', 'tcp').strip()))
            return
        if self.path == '/rules/add-deny':
            cidr = f.get('cidr', '').strip()
            if not re.fullmatch(r'[0-9a-fA-F:.]+/\d{1,3}', cidr): self.redirect('Invalid CIDR.'); return
            with (TT_DIR / 'rules.toml').open('a', encoding='utf-8') as fp: fp.write(f'\n[[rule]]\ncidr = "{cidr}"\naction = "deny"\n')
            run(['systemctl', 'restart', 'trusttunnel'], timeout=20); self.redirect('Deny rule added.'); return
        if self.path == '/rules/reset':
            write_text(TT_DIR / 'rules.toml', '# Empty rules file: all authenticated clients are allowed.\n', 0o644); run(['systemctl', 'restart', 'trusttunnel'], timeout=20); self.redirect('Rules reset.'); return
        self.send_error(404)


def main():
    bind = os.environ.get('PANEL_BIND', '127.0.0.1')
    port = int(os.environ.get('PANEL_PORT', '8088'))
    server = http.server.ThreadingHTTPServer((bind, port), Handler)
    if PANEL_TLS:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(PANEL_CERT, PANEL_KEY)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == '__main__':
    main()

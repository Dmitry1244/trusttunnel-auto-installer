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
import json
import sys
import threading
import tempfile
try:
    import tomllib
except ImportError:
    import tomli as tomllib
import ipaddress
import socket
from contextlib import contextmanager
from pathlib import Path

TT_DIR = Path('/opt/trusttunnel')
CLIENT_DIR = Path('/root/trusttunnel-clients')
SOCKS_ADDR = '127.0.0.1:40000'
PANEL_USER = os.environ.get('PANEL_USER', 'admin')
PANEL_PASSWORD = os.environ.get('PANEL_PASSWORD', '')
PANEL_TLS = os.environ.get('PANEL_TLS', '0') == '1'
PANEL_CERT = os.environ.get('PANEL_CERT', '/opt/trusttunnel/certs/cert.pem')
PANEL_KEY = os.environ.get('PANEL_KEY', '/opt/trusttunnel/certs/key.pem')
DEEPLINK_CACHE = {}
DEEPLINK_CACHE_TTL = 300
ADMIN_VERSION = '2026.09.26'
ADMIN_LOCK = threading.RLock()
CSRF_TOKEN = secrets.token_urlsafe(32)


def run(cmd, timeout=40, input_text=None, env=None, cwd=None):
    try:
        p = subprocess.run(cmd, input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env, cwd=cwd)
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
    return tomllib.loads(read_text(TT_DIR / 'credentials.toml')).get('client', [])


@contextmanager
def admin_lock():
    # Shared by web workers and the terminal CLI, including separate processes.
    import fcntl
    TT_DIR.mkdir(parents=True, exist_ok=True)
    with ADMIN_LOCK, (TT_DIR / '.admin.lock').open('a') as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.admin-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def client_state():
    text = read_text(TT_DIR / 'clients-state.json')
    return json.loads(text) if text else {'disabled': {}, 'notes': {}}


def client_inventory():
    state = client_state()
    active = {c['username']: dict(c, enabled=True) for c in load_clients()}
    for name, record in state.get('disabled', {}).items():
        active.setdefault(name, dict(record, enabled=False))
    return [dict(c, note=state.get('notes', {}).get(name, '')) for name, c in sorted(active.items())]


def client_operation(action, values):
    with admin_lock():
        clients = load_clients()
        state = client_state()
        state.setdefault('disabled', {})
        state.setdefault('notes', {})
        user = values.get('username', '').strip()
        records = {c['username']: c for c in clients}
        all_names = set(records) | set(state['disabled'])
        if action not in ('list', 'batch', 'rebuild') and not client_name_valid(user):
            raise ValueError('Некорректный логин клиента.')
        if action == 'list':
            return '\n'.join(f"{c['username']}\t{'включён' if c['enabled'] else 'отключён'}\t{c['note']}" for c in client_inventory())
        if action == 'link':
            if user not in records:
                raise ValueError('Клиент не найден или отключён.')
            return deeplink(user) or 'Endpoint не смог сформировать ссылку.'
        if action == 'rebuild':
            rebuild_client_files(clients)
            return 'TOML и ZIP пересобраны.'
        if action in ('add', 'batch'):
            count = int(values.get('count', '1')) if action == 'batch' else 1
            prefix = values.get('prefix', 'client').strip()
            if not 1 <= count <= 100 or not client_name_valid(prefix) or len(prefix) > 54:
                raise ValueError('Укажите префикс до 54 символов и количество от 1 до 100.')
            names = [user] if action == 'add' else []
            index = 1
            while len(names) < count:
                candidate = f'{prefix}{index:02d}'
                index += 1
                if candidate not in all_names:
                    names.append(candidate)
            if any(name in all_names for name in names):
                raise ValueError('Такой клиент уже существует, в том числе среди отключённых.')
            password = values.get('password', '').strip()
            if password and not re.fullmatch(r'[A-Za-z0-9._-]{12,128}', password):
                raise ValueError('Пароль: 12–128 букв, цифр или символов ._-')
            clients.extend({'username': name, 'password': password or random_password()} for name in names)
        elif user not in all_names:
            raise ValueError('Клиент не найден.')
        elif action == 'note':
            note = values.get('note', '').strip()
            if len(note) > 300 or '\n' in note or '\r' in note:
                raise ValueError('Заметка: одна строка, до 300 символов.')
            state['notes'][user] = note
            atomic_write(TT_DIR / 'clients-state.json', json.dumps(state, ensure_ascii=False))
            audit_log('client-note', user)
            return 'Заметка сохранена.'
        elif action == 'disable':
            if user not in records:
                return 'Клиент уже отключён.'
            if len(clients) <= 1:
                raise ValueError('Нельзя отключить последнего активного клиента.')
            state['disabled'][user] = records[user]
            clients = [c for c in clients if c['username'] != user]
        elif action == 'enable':
            if user in records:
                return 'Клиент уже включён.'
            clients.append(state['disabled'].pop(user))
        elif action == 'delete':
            if user in records and len(clients) <= 1:
                raise ValueError('Нельзя удалить последнего активного клиента.')
            clients = [c for c in clients if c['username'] != user]
            state['disabled'].pop(user, None)
            state['notes'].pop(user, None)
        elif action == 'password':
            password = values.get('password', '').strip() or random_password()
            if not re.fullmatch(r'[A-Za-z0-9._-]{12,128}', password):
                raise ValueError('Пароль: 12–128 букв, цифр или символов ._-')
            (records.get(user) or state['disabled'][user])['password'] = password
        else:
            raise ValueError('Неизвестное действие клиента.')
        cred = TT_DIR / 'credentials.toml'
        state_path = TT_DIR / 'clients-state.json'
        old_credentials, old_state = read_text(cred), read_text(state_path)
        config = tomllib.loads(old_credentials)
        if set(config) - {'client'} or any(set(c) - {'username', 'password'} for c in config.get('client', [])):
            raise ValueError('Обнаружены дополнительные поля credentials.toml. Автоматическая перезапись отменена.')
        lines = []
        for c in clients:
            lines += ['[[client]]', 'username = ' + json.dumps(c['username']), 'password = ' + json.dumps(c['password']), '']
        candidate = '\n'.join(lines)
        tomllib.loads(candidate)
        backup = TT_DIR / 'backups' / ('clients-' + time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3))
        backup.mkdir(parents=True, mode=0o700)
        atomic_write(backup / 'credentials.toml', old_credentials)
        atomic_write(backup / 'clients-state.json', old_state or '{}')
        try:
            atomic_write(state_path, json.dumps(state, ensure_ascii=False))
            atomic_write(cred, candidate)
            rc, out = run(['systemctl', 'restart', 'trusttunnel'], timeout=30)
            if rc or service_status('trusttunnel') != 'active':
                raise RuntimeError('TrustTunnel не запустился: ' + out)
        except Exception:
            atomic_write(cred, old_credentials)
            if old_state:
                atomic_write(state_path, old_state)
            else:
                state_path.unlink(missing_ok=True)
            run(['systemctl', 'restart', 'trusttunnel'], timeout=30)
            raise
        DEEPLINK_CACHE.clear()
        # Preserve existing profiles; only update new/changed identities.
        before = {c['username']: c['password'] for c in tomllib.loads(old_credentials).get('client', [])}
        for c in clients:
            if before.get(c['username']) != c['password']:
                for protocol in (['http2', 'http3'] if quic_enabled() else ['http2']):
                    write_text(CLIENT_DIR / f"{c['username']}-{protocol}.toml", client_profile(c['username'], c['password'], protocol))
        remaining = {c['username'] for c in clients}
        for name in set(before) - remaining:
            for protocol in ('http2', 'http3'):
                (CLIENT_DIR / f'{name}-{protocol}.toml').unlink(missing_ok=True)
        write_text(CLIENT_DIR / 'clients-credentials.txt', ''.join(f"{c['username']} {c['password']}\n" for c in clients))
        audit_log('client-' + action, user or str(count))
        return 'Изменения сохранены. TrustTunnel работает.'


def admin_operation(action, values):
    if action.startswith('client-'):
        return client_operation(action[7:], values)
    if action == 'monitor':
        return json.dumps(monitor_snapshot(), ensure_ascii=False, indent=2)
    if action == 'logs':
        unit = values.get('unit', 'trusttunnel')
        if unit not in ('trusttunnel', 'warp-wireproxy', 'trusttunnel-panel', 'fail2ban'):
            raise ValueError('Неизвестный сервис.')
        return recent_logs(unit, min(500, max(20, int(values.get('lines', '100')))))
    if action == 'audit':
        return audit_output()
    if action.startswith(('security-', 'routing-', 'dns-')):
        with admin_lock():
            return network_operation(action, values)
    raise ValueError('Неизвестная операция.')


def checked_run(args, timeout=30):
    rc, out = run(args, timeout=timeout)
    if rc:
        raise RuntimeError(out or 'Команда завершилась с ошибкой.')
    return out


def apply_endpoint_file(path, text):
    tomllib.loads(text)
    old = read_text(path)
    atomic_write(Path(str(path) + '.admin-backup'), old)
    atomic_write(path, text)
    try:
        checked_run(['systemctl', 'restart', 'trusttunnel'])
        if service_status('trusttunnel') != 'active':
            raise RuntimeError('TrustTunnel не запустился.')
    except Exception:
        atomic_write(path, old)
        run(['systemctl', 'restart', 'trusttunnel'])
        raise


def validated_dns(value):
    items = [v.strip() for v in value.replace('\n', ',').split(',') if v.strip()]
    if not 1 <= len(items) <= 4:
        raise ValueError('Укажите от 1 до 4 DNS-серверов.')
    for item in items:
        try:
            ipaddress.ip_address(item)
            continue
        except ValueError:
            pass
        parsed = urllib.parse.urlsplit(item)
        if parsed.scheme not in ('https', 'tls', 'quic') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('DNS: IP-адрес либо URL https://, tls:// или quic://.')
        if any(ch.isspace() or ch in '\"\'\\' for ch in item):
            raise ValueError('Недопустимые символы в DNS.')
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError('Некорректный порт DNS.')
    return items


def network_operation(action, values):
    if action == 'security-status':
        return '\n'.join(run(cmd)[1] for cmd in (['ufw', 'status', 'numbered'], ['fail2ban-client', 'status', 'sshd'], ['sshd', '-T']))
    if action in ('security-ban', 'security-unban'):
        address = str(ipaddress.ip_address(values.get('ip', '')))
        if action == 'security-ban':
            caller = values.get('_peer') or os.environ.get('SSH_CONNECTION', '').split(' ')[0]
            if ipaddress.ip_address(address).is_loopback or address == caller:
                raise ValueError('Нельзя заблокировать loopback или IP текущего администратора.')
        return checked_run(['fail2ban-client', 'set', 'sshd', 'banip' if action == 'security-ban' else 'unbanip', address])
    if action == 'security-fail2ban':
        retry, findtime, bantime = (int(values.get(k, default)) for k, default in [('retry', '5'), ('findtime', '600'), ('bantime', '3600')])
        if not 1 <= retry <= 100 or not 60 <= findtime <= 86400 or not 60 <= bantime <= 604800:
            raise ValueError('Попытки: 1–100; окно: 60–86400 с; бан: 60–604800 с.')
        path = Path('/etc/fail2ban/jail.d/sshd.local')
        old = read_text(path)
        import configparser
        config = configparser.ConfigParser(interpolation=None)
        config.read_string(old or '[sshd]\n')
        if not config.has_section('sshd'):
            config.add_section('sshd')
        config['sshd'].update({'enabled': 'true', 'port': current_ssh_port(), 'backend': 'systemd', 'maxretry': str(retry), 'findtime': str(findtime), 'bantime': str(bantime)})
        import io
        output = io.StringIO(); config.write(output)
        atomic_write(path, output.getvalue())
        try:
            checked_run(['fail2ban-client', '-t'])
            checked_run(['systemctl', 'restart', 'fail2ban'])
        except Exception:
            if old: atomic_write(path, old)
            else: path.unlink(missing_ok=True)
            run(['systemctl', 'restart', 'fail2ban'])
            raise
        return 'Параметры SSH jail сохранены.'
    if action in ('security-open', 'security-close'):
        port, proto = values.get('port', ''), values.get('proto', 'tcp')
        if not validate_port(port) or proto not in ('tcp', 'udp'):
            raise ValueError('Некорректный порт или протокол.')
        protected = {int(current_ssh_port()), int(endpoint_port()), int(current_panel_env().get('PANEL_PORT', '8088'))}
        if action == 'security-close' and int(port) in protected:
            raise ValueError('Этот порт используется SSH, TrustTunnel или панелью. Сначала смените порт сервиса.')
        command = ['ufw', 'allow', f'{int(port)}/{proto}'] if action == 'security-open' else ['ufw', '--force', 'delete', 'allow', f'{int(port)}/{proto}']
        return checked_run(command)
    if action == 'routing-check':
        return diagnostics_output()
    if action == 'routing-switch':
        mode = values.get('mode', '')
        address = SOCKS_ADDR if mode == 'warp' else values.get('address', '').strip()
        if mode not in ('direct', 'warp', 'socks5'):
            raise ValueError('Некорректный маршрут.')
        if mode != 'direct':
            target = urllib.parse.urlsplit('socks5://' + address)
            if not target.hostname or not target.port or target.username or target.password or target.path or target.query or target.fragment:
                raise ValueError('Укажите SOCKS5 как host:port, без логина и пароля.')
            if mode == 'warp':
                checked_run(['systemctl', 'enable', '--now', 'warp-wireproxy'])
            check = checked_run(['curl', '-fsS', '--max-time', '15', '--proxy', 'socks5h://' + address, 'https://www.cloudflare.com/cdn-cgi/trace'], timeout=20)
            if mode == 'warp' and 'warp=on' not in check and 'warp=plus' not in check:
                raise RuntimeError('WARP не подтвердил работоспособность. Маршрут не изменён.')
        path = TT_DIR / 'vpn.toml'
        cfg = read_text(path)
        parsed = tomllib.loads(cfg)
        if set(parsed.get('forward_protocol', {})) - {'direct', 'socks5'}:
            raise ValueError('Неподдерживаемый существующий маршрут, изменение отменено.')
        cfg = re.sub(r'(?ms)^\[forward_protocol(?:\.[^\]]+)?\][^\[]*', '', cfg)
        cfg += '\n[forward_protocol]\n' + ('direct = {}\n' if mode == 'direct' else '[forward_protocol.socks5]\naddress = ' + json.dumps(address) + '\nextended_auth = false\n')
        apply_endpoint_file(path, cfg)
        audit_log(action, mode)
        return 'Исходящий маршрут: ' + forwarder_label()
    if action in ('routing-rule-add', 'routing-rule-delete'):
        path = TT_DIR / 'rules.toml'
        parsed = tomllib.loads(read_text(path))
        rules = parsed.get('rule', [])
        if set(parsed) - {'rule'} or any(set(rule) - {'cidr', 'action', 'client_random_prefix'} for rule in rules):
            raise ValueError('Файл содержит дополнительные поля. Автоматическая перезапись отменена.')
        if action.endswith('add'):
            cidr = str(ipaddress.ip_network(values.get('cidr', ''), strict=False))
            decision = values.get('decision', 'deny')
            if decision not in ('allow', 'deny'):
                raise ValueError('Действие: allow или deny.')
            rule = {'cidr': cidr, 'action': decision}
            if rule in rules: raise ValueError('Такое правило уже есть.')
            rules.append(rule)
        else:
            index = int(values.get('index', '0')) - 1
            if not 0 <= index < len(rules): raise ValueError('Правило не найдено.')
            # Reject stale page actions instead of deleting a different rule.
            expected = values.get('fingerprint', '')
            import hashlib
            actual = hashlib.sha256(json.dumps(rules[index], sort_keys=True).encode()).hexdigest()
            if expected and expected != actual: raise ValueError('Правила изменились. Обновите страницу.')
            rules.pop(index)
        text = '\n'.join('[[rule]]\n' + '\n'.join(f'{k} = {json.dumps(v)}' for k, v in rule.items()) + '\n' for rule in rules)
        apply_endpoint_file(path, text)
        audit_log(action)
        return 'Правила доступа сохранены. Первое совпавшее правило имеет приоритет.'
    if action in ('dns-save', 'dns-check', 'dns-apply'):
        if action == 'dns-apply':
            rebuild_client_files(load_clients())
            return 'Профили пересобраны. Импортируйте новый TOML на устройстве.'
        items = validated_dns(values.get('dns', panel_settings()['DNS_UPSTREAMS']))
        if action == 'dns-save':
            net = panel_settings(); net['DNS_UPSTREAMS'] = ','.join(items)
            atomic_write(PANEL_SETTINGS, ''.join(f'{k}={v}\n' for k, v in net.items()))
            audit_log(action, ','.join(items))
            return 'DNS сохранён. Применение к TOML выполняется отдельной командой.'
        lines = []
        for item in items:
            try:
                ipaddress.ip_address(item)
                rc, output = run(['dig', '+time=3', '+tries=1', '@' + item, 'example.com', 'A'], timeout=6)
                status = 'OK' if rc == 0 and 'status: NOERROR' in output else 'Нет успешного DNS-ответа'
                lines.append(item + ': ' + status + '\n' + output)
            except ValueError:
                host = urllib.parse.urlsplit(item).hostname
                try:
                    lines.append(item + ': имя разрешается в ' + ', '.join(sorted({x[4][0] for x in socket.getaddrinfo(host, None)})) + '; DNS-запрос по DoH/DoT/DoQ этим тестом не проверяется.')
                except OSError as exc:
                    lines.append(item + ': ошибка разрешения имени: ' + str(exc))
        return '\n\n'.join(lines)
    raise ValueError('Неизвестная операция сети.')


def monitor_snapshot():
    result = system_metrics()
    result['services'] = {name: service_status(name) for name in ('trusttunnel', 'warp-wireproxy', 'fail2ban')}
    result['route'] = forwarder_label()
    result['interfaces'] = {}
    for line in read_text('/proc/net/dev').splitlines()[2:]:
        if ':' in line:
            name, raw = line.split(':', 1)
            fields = raw.split()
            if name.strip() != 'lo' and len(fields) > 8:
                result['interfaces'][name.strip()] = {'rx': int(fields[0]), 'tx': int(fields[8])}
    memory = {p[0].rstrip(':'): int(p[1]) for p in (line.split() for line in read_text('/proc/meminfo').splitlines()) if len(p) > 1}
    result['memory_percent'] = round(100 * (1 - memory.get('MemAvailable', 0) / max(memory.get('MemTotal', 1), 1)), 1)
    disk = shutil.disk_usage('/')
    result['disk_percent'] = round(100 * disk.used / max(disk.total, 1), 1)
    result['time'] = time.time()
    return result


def client_name_valid(name):
    return bool(re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', name or ''))


def random_password():
    return 'TT-' + secrets.token_hex(12)


PANEL_SETTINGS = Path('/etc/trusttunnel-panel-settings.env')


def panel_settings():
    values = {'DNS_UPSTREAMS': '94.140.14.14,94.140.15.15', 'CLIENT_ANTI_DPI': '0', 'TLS_PROFILE': 'chrome', 'POST_QUANTUM': '0'}
    for line in read_text(PANEL_SETTINGS).splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            if key in values:
                values[key] = value.strip()
    return values


def dns_upstreams():
    return [item.strip() for item in panel_settings()['DNS_UPSTREAMS'].split(',') if re.fullmatch(r'[A-Za-z0-9_.:/?-]{1,253}', item.strip())][:4]


def client_anti_dpi_enabled():
    return panel_settings()['CLIENT_ANTI_DPI'] == '1'


def client_tls_profile():
    profile = panel_settings()['TLS_PROFILE']
    return profile if profile in ('chrome', 'safari', 'firefox', 'okhttp', 'openssl', 'default') else 'chrome'


def save_client_network_settings(dns_value, anti_dpi, tls_profile, post_quantum):
    values = [item.strip() for item in dns_value.replace('\n', ',').split(',') if item.strip()]
    if not values or len(values) > 4 or any(not re.fullmatch(r'[A-Za-z0-9_.:/?-]{1,253}', item) for item in values):
        return 'Введите от 1 до 4 корректных DNS upstream.'
    if tls_profile not in ('chrome', 'safari', 'firefox', 'okhttp', 'openssl', 'default'):
        return 'Некорректный TLS-профиль.'
    write_text(PANEL_SETTINGS, 'DNS_UPSTREAMS=' + ','.join(values) + '\nCLIENT_ANTI_DPI=' + ('1' if anti_dpi else '0') + '\nTLS_PROFILE=' + tls_profile + '\nPOST_QUANTUM=' + ('1' if post_quantum else '0') + '\n', 0o600)
    rebuild_client_files(load_clients())
    audit_log('client_network_settings_changed', ','.join(values))
    return 'DNS, AntiDPI и TLS-профиль сохранены. Все TOML клиентов пересобраны.'

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
    dns_values = ', '.join(f'"{q(item)}"' for item in dns_upstreams())
    post_quantum = panel_settings().get('POST_QUANTUM') == '1'
    body += f'''\n# DNS resolvers for requests sent through the tunnel
dns_upstreams = [{dns_values}]

# Protocol to be used to communicate with the endpoint [http2, http3]
upstream_protocol = "{protocol}"

# TLS ClientHello profile used by the client
tls_profile = "{client_tls_profile()}"

# Enable client AntiDPI measures
anti_dpi = {str(client_anti_dpi_enabled()).lower()}

# Hybrid post-quantum TLS key exchange (requires a current TrustTunnel client)
post_quantum_group_enabled = {str(post_quantum).lower()}
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
    credentials = TT_DIR / 'credentials.toml'
    try:
        credentials_mtime = credentials.stat().st_mtime_ns
    except FileNotFoundError:
        credentials_mtime = 0
    cache_key = (username, domain(), endpoint_port(), tuple(dns_upstreams()), credentials_mtime)
    cached = DEEPLINK_CACHE.get(cache_key)
    if cached and time.monotonic() - cached[0] < DEEPLINK_CACHE_TTL:
        return cached[1]
    cmd = [str(TT_DIR / 'trusttunnel_endpoint'), 'vpn.toml', 'hosts.toml', '-c', username, '-a', f'{domain()}:{endpoint_port()}', '--format', 'deeplink', '--name', username]
    for upstream in dns_upstreams():
        cmd += ['--dns-upstream', upstream]
    rc, out = run(cmd, timeout=8, cwd=str(TT_DIR))
    link = out.strip() if rc == 0 and out.strip().startswith('tt://') else ''
    if link:
        DEEPLINK_CACHE[cache_key] = (time.monotonic(), link)
    return link


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
    state = TT_DIR / 'clients-state.json'
    if state.exists():
        shutil.copy2(state, backup_dir / state.name)
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

def installer_defaults():
    cfg = read_text(TT_DIR / 'vpn.toml')
    cert = cert_mode()
    return {
        'domain': domain(),
        'clients': str(max(1, len(load_clients()))),
        'endpoint_port': endpoint_port(),
        'ssh_port': current_ssh_port(),
        'warp': '1' if uses_warp() else '0',
        'quic': '1' if quic_enabled() else '0',
        'cert_mode': cert if cert in ('self-signed', 'letsencrypt') else 'self-signed',
    }


def installer_operation(action, values):
    allowed = {'install', 'update-trusttunnel', 'install-warp', 'remove-warp', 'reregister-warp', 'enable-warp', 'disable-warp', 'check-warp', 'backup-identity'}
    if action not in allowed:
        return 'Unsupported installer action.'
    dangerous = {'install', 'remove-warp', 'reregister-warp'}
    if action in dangerous and values.get('confirm', '') != 'REINSTALL':
        return 'For this operation type REINSTALL in the confirmation field.'
    env = os.environ.copy()
    env['ACTION'] = action
    env['AUTO_CONFIRM'] = '1'
    if action == 'install':
        defaults = installer_defaults()
        domain_value = values.get('domain', '').strip()
        if not re.fullmatch(r'[A-Za-z0-9.-]{3,253}', domain_value):
            return 'Invalid domain.'
        clients = values.get('clients', defaults['clients']).strip()
        port = values.get('endpoint_port', defaults['endpoint_port']).strip()
        if not clients.isdigit() or not 1 <= int(clients) <= 500:
            return 'Clients must be between 1 and 500.'
        if not validate_port(port):
            return 'Invalid TrustTunnel port.'
        cert = values.get('cert_mode', defaults['cert_mode'])
        if cert not in ('self-signed', 'letsencrypt'):
            return 'Invalid certificate mode.'
        email = values.get('email', '').strip()
        if cert == 'letsencrypt' and not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
            return 'A valid email is required for Let\'s Encrypt.'
        env.update({
            'DOMAIN': domain_value, 'CLIENTS': clients, 'ENDPOINT_PORT': port,
            'SSH_PORT': defaults['ssh_port'], 'CHANGE_SSH_PORT': '0',
            'ENABLE_SYSTEM_UPGRADE': '0', 'ENABLE_WARP': values.get('warp', defaults['warp']),
            'ENABLE_QUIC': values.get('quic', defaults['quic']), 'ENABLE_FAIL2BAN': '1',
            'PRESERVE_CLIENT_CONFIGS': '1', 'CONFIRM_FIREWALL_RESET': '1',
            'CERT_MODE': cert, 'EMAIL': email or 'admin@example.invalid',
        })
    rc, out = run(['/bin/bash', '/usr/local/sbin/trusttunnel-menu'], timeout=900, input_text='', env=env)
    audit_log('installer_operation', action)
    return out or ('Operation finished.' if rc == 0 else f'Operation failed with exit code {rc}.')

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
PANEL_STYLE = r'''
:root{--ink:#172033;--muted:#65728a;--line:#e1e7ef;--canvas:#f4f6f9;--surface:#fff;--nav:#141b2d;--nav-hover:#202c43;--nav-active:#2b4773;--accent:#246bdb;--success:#147c45;--success-bg:#e7f6ec;--danger:#b42318;--danger-bg:#fff0ef;--warn:#9b6200;--warn-bg:#fff7df}*{box-sizing:border-box}body{margin:0;background:var(--canvas);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;font-size:14px;line-height:1.45}button,input,select,textarea{font:inherit}.layout{display:grid;grid-template-columns:248px minmax(0,1fr);min-height:100vh}.sidebar{padding:20px 12px;background:var(--nav);color:#eaf0fb;position:sticky;top:0;height:100vh;overflow:auto}.brand{display:flex;align-items:center;gap:10px;padding:4px 10px 20px;margin-bottom:15px;border-bottom:1px solid #293750;font-size:17px;font-weight:700}.brand:before{content:"T";display:grid;place-items:center;width:29px;height:29px;border:1px solid #6d9ee8;border-radius:7px;background:#1b3156;color:#dce9ff;font-size:14px}.brand small{display:block;margin-top:1px;color:#93a6c7;font-size:11px;font-weight:500}.nav-group{margin:16px 0}.nav-label{display:block;padding:0 10px 7px;color:#8496b8;text-transform:uppercase;letter-spacing:.06em;font-weight:700;font-size:10px}.nav-item{display:block;border-radius:6px;padding:9px 10px;margin:2px 0;color:#bdc9dd;text-decoration:none}.nav-item:hover{background:var(--nav-hover);color:#fff}.nav-item.active{background:var(--nav-active);color:#fff;box-shadow:inset 3px 0 0 #78a9ff}.workspace{min-width:0}.topbar{min-height:62px;padding:0 30px;display:flex;align-items:center;justify-content:space-between;gap:14px;background:var(--surface);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}.endpoint-context{display:flex;align-items:center;gap:9px;color:var(--muted);min-width:0}.endpoint-context:before{content:"";width:8px;height:8px;border-radius:50%;background:#26a35e;flex:none}.endpoint-context strong{color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.command-trigger{min-height:34px;border:1px solid var(--line);border-radius:6px;background:#fff;color:#536176;padding:6px 9px;cursor:pointer}.command-trigger kbd{margin-left:6px;padding:1px 4px;border:1px solid #d9e0e9;border-bottom-width:2px;border-radius:4px;background:#f8fafc;color:#748197;font-size:11px}.content{max-width:1480px;padding:28px 30px 42px;margin:0 auto}.page-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin:0 0 22px}.page-head h2{font-size:25px;line-height:1.2;margin:0;font-weight:720}.page-head p{margin:6px 0 0;color:var(--muted)}h3{font-size:15px;margin:0 0 13px}.surface{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:18px;margin:0 0 16px}.metrics,.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:16px}.metric{min-height:88px;padding:14px;border:1px solid var(--line);border-radius:7px;background:#fff}.metric small{display:block;margin-bottom:8px;color:var(--muted);font-size:11px}.metric strong{display:block;font-size:15px;overflow-wrap:anywhere}.metric b{display:block;margin-bottom:9px;color:var(--muted);font-size:11px;font-weight:600}.badge{display:inline-flex;align-items:center;gap:5px;margin-top:8px;padding:3px 7px;border-radius:999px;background:#eef2f7;color:#59677b;font-size:11px}.badge:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}.badge.active{background:var(--success-bg);color:var(--success)}.badge.inactive,.badge.failed{background:var(--danger-bg);color:var(--danger)}.warning{padding:10px 12px;border-left:3px solid #e6b344;background:var(--warn-bg);color:var(--warn);margin:0 0 14px}.notice{padding:11px 13px;border:1px solid #b7d6fe;background:#edf6ff;color:#164e91;border-radius:7px;margin-bottom:16px}form{display:inline-flex;align-items:end;gap:8px;flex-wrap:wrap;margin:3px 4px 3px 0}label{display:grid;gap:5px;color:#536176;font-size:12px}label.check{display:flex;align-items:center;gap:7px;padding:8px 0;font-size:13px}input,select,textarea,button,.button{min-height:36px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;color:var(--ink);padding:7px 10px}textarea{width:100%;min-height:74px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}input:focus,select:focus,textarea:focus{outline:0;border-color:#5d92e5;box-shadow:0 0 0 3px #e7f0ff}button,.button{cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}button:hover,.button:hover{border-color:#7da6e5}button.primary,.button.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.danger{background:#fff8f7;border-color:#efb3ae;color:var(--danger)}.form-grid{display:grid;grid-template-columns:repeat(3,minmax(180px,1fr));align-items:end;gap:12px}.table-wrap{overflow-x:auto;padding:0}table{width:100%;min-width:700px;border-collapse:collapse}th,td{padding:13px 16px;text-align:left;border-bottom:1px solid var(--line);vertical-align:middle}th{background:#fafbfd;color:#69778c;font-size:11px;text-transform:uppercase;letter-spacing:.04em}tr:last-child td{border-bottom:0}tr.client-row:hover td{background:#f9fbff}.client-cell{display:flex;align-items:center;gap:10px}.avatar{width:29px;height:29px;border-radius:6px;display:grid;place-items:center;background:#e8f1ff;color:#1e5dc8;font-weight:750}.client-cell small,.muted,.hint{display:block;color:var(--muted);margin-top:2px}.protocols{display:flex;gap:5px;flex-wrap:wrap}.protocol{padding:2px 5px;border:1px solid #d7e1f0;border-radius:4px;color:#50627b;font-size:11px}.table-actions{display:flex;justify-content:flex-end;gap:7px}.search{width:min(300px,100%)}.summary-filters{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 14px}.summary-filter{min-height:32px;padding:5px 8px;border:1px solid var(--line);border-radius:6px;background:#fff;color:#536176;cursor:pointer}.summary-filter.active{background:#eaf2ff;border-color:#9dc0f4;color:#1b5ec8}.drawer{display:none;position:fixed;inset:0;z-index:20;background:rgba(16,25,41,.46)}.drawer.open{display:block}.drawer-card{width:min(570px,100vw);height:100%;margin-left:auto;padding:22px;background:#fff;overflow:auto;box-shadow:-16px 0 32px rgba(15,23,42,.18)}.drawer-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;padding-bottom:17px;border-bottom:1px solid var(--line)}.drawer-head h2{font-size:19px;margin:0}.drawer-section{padding:18px 0;border-bottom:1px solid var(--line)}.drawer-section:last-child{border-bottom:0}.copy-row{display:flex;align-items:flex-start;gap:7px}.qr-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.qr-grid img{display:block;max-width:190px;width:100%;margin-top:7px;border:1px solid var(--line);border-radius:6px;padding:6px}.command-layer{display:none;position:fixed;z-index:30;inset:0;padding:12vh 16px 16px;background:rgba(16,25,41,.38)}.command-layer.open{display:block}.command-box{width:min(620px,100%);margin:0 auto;overflow:hidden;background:#fff;border:1px solid #cfd9e8;border-radius:8px;box-shadow:0 18px 45px rgba(15,23,42,.22)}.command-box input{width:100%;min-height:48px;border:0;border-bottom:1px solid var(--line);border-radius:0}.command-list{max-height:360px;overflow:auto;padding:8px}.command-item{display:block;padding:10px 11px;border-radius:5px;color:var(--ink);text-decoration:none}.command-item:hover{background:#f0f5fc}.command-item small{display:block;color:var(--muted);margin-top:2px}pre{margin:0;max-height:560px;overflow:auto;white-space:pre-wrap;background:#111a2a;color:#dce8fb;padding:14px;border-radius:6px;font-size:12px}@media(max-width:1050px){.metrics,.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:900px){.layout{display:block}.sidebar{position:static;height:auto;display:flex;align-items:center;overflow-x:auto;gap:8px;padding:12px}.brand{flex:none;margin:0;padding:0 8px;border:0}.brand small,.nav-label{display:none}.nav-group{display:flex;gap:2px;margin:0}.nav-item{white-space:nowrap;margin:0}.topbar{padding:0 16px}.content{padding:18px 16px 32px}.form-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:560px){.page-head{display:block}.page-head form{margin-top:12px}.metrics,.grid,.form-grid,.qr-grid{grid-template-columns:1fr}.command-trigger{font-size:0}.command-trigger kbd{margin:0;font-size:10px}}
'''

PANEL_SCRIPT = r'''
(function(){const command=document.getElementById('command-layer'),search=document.getElementById('command-search');const open=()=>{command.classList.add('open');setTimeout(()=>search&&search.focus(),0)},close=()=>command.classList.remove('open');document.querySelectorAll('[data-command-open]').forEach(b=>b.addEventListener('click',open));document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();open()}if(e.key==='Escape'){close();document.querySelectorAll('.drawer.open').forEach(x=>x.classList.remove('open'))}});if(command)command.addEventListener('click',e=>{if(e.target===command)close()});if(search)search.addEventListener('input',()=>{const q=search.value.toLowerCase();document.querySelectorAll('.command-item').forEach(x=>x.hidden=!x.textContent.toLowerCase().includes(q))});document.querySelectorAll('[data-drawer]').forEach(b=>b.addEventListener('click',()=>document.getElementById(b.dataset.drawer).classList.add('open')));document.querySelectorAll('[data-drawer-close]').forEach(b=>b.addEventListener('click',()=>b.closest('.drawer').classList.remove('open')));document.querySelectorAll('.drawer').forEach(d=>d.addEventListener('click',e=>{if(e.target===d)d.classList.remove('open')}));document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',async()=>{const t=document.getElementById(b.dataset.copy);if(!t)return;try{await navigator.clipboard.writeText(t.value);b.textContent='Скопировано';setTimeout(()=>b.textContent='Копировать',1200)}catch(_){t.select&&t.select()}}));const clientSearch=document.getElementById('client-search'),filters=document.querySelectorAll('[data-client-filter]');let active='all';const filterRows=()=>{const q=(clientSearch?clientSearch.value:'').toLowerCase();document.querySelectorAll('[data-client-row]').forEach(row=>row.hidden=!(row.dataset.client.includes(q)&&(active==='all'||row.dataset.protocols.includes(active))))};if(clientSearch)clientSearch.addEventListener('input',filterRows);filters.forEach(b=>b.addEventListener('click',()=>{active=b.dataset.clientFilter;filters.forEach(x=>x.classList.toggle('active',x===b));filterRows()}));document.querySelectorAll('form[data-confirm]').forEach(f=>f.addEventListener('submit',e=>{if(!confirm(f.dataset.confirm))e.preventDefault()}));if(document.body.dataset.view==='dashboard')setTimeout(()=>location.reload(),30000)})();
'''
NAV_ITEMS = (
    ('dashboard', 'Обзор'), ('endpoint', 'Endpoint'), ('clients', 'Клиенты'),
    ('warp', 'WARP'), ('routing', 'Маршрутизация'), ('dns', 'DNS и AntiDPI'),
    ('certificates', 'Сертификаты'), ('security', 'Безопасность'),
    ('system', 'Система'), ('panel', 'Панель'),
    ('logs', 'Журналы'),
)


def nav_html(view):
    groups = (
        ('Сервер', ('dashboard', 'endpoint', 'clients')),
        ('Сеть', ('warp', 'routing', 'dns')),
        ('Управление', ('certificates', 'security', 'system', 'logs', 'panel')),
    )
    labels = dict(NAV_ITEMS)
    parts = []
    for group, keys in groups:
        items = []
        for key in keys:
            cls = ' active' if key == view else ''
            items.append(f'<a class="nav-item{cls}" href="/?view={key}">{labels[key]}</a>')
        parts.append(f'<div class="nav-group"><span class="nav-label">{group}</span>{"".join(items)}</div>')
    return ''.join(parts)

def card(label, value, state=''):
    suffix = f' <span class="badge {html.escape(state)}">{html.escape(state)}</span>' if state else ''
    return f'<div class="metric"><small>{html.escape(label)}</small><strong>{html.escape(value)}</strong>{suffix}</div>'


def client_rows():
    rows = []
    protocols = ['http2', 'http3'] if quic_enabled() else ['http2']
    for item in load_clients():
        username = item['username']
        safe = html.escape(username)
        quoted = urllib.parse.quote(username)
        drawer_id = 'client-' + re.sub(r'[^A-Za-z0-9_-]', '-', username)
        link = deeplink(username)
        profile_links = ' '.join(f'<a class="text-link" href="/client/{quoted}/{proto}.toml">{proto.upper()}</a>' for proto in protocols)
        qr = f'<img alt="QR {safe}" src="/qr-link/{quoted}.png">' if link else ''
        link_controls = f'''<div class="copy-row"><input id="link-{drawer_id}" value="{html.escape(link, quote=True)}" readonly><button type="button" data-copy="link-{drawer_id}">Копировать</button></div><a class="text-link" href="{html.escape(link, quote=True)}">Открыть tt://</a>''' if link else '<span class="muted">Ссылка недоступна</span>'
        drawer = f'''<aside class="drawer" id="{drawer_id}"><div class="drawer-card"><div class="drawer-head"><div><h2>{safe}</h2><span class="hint">Профили и доступ клиента</span></div><button type="button" data-drawer-close>Закрыть</button></div><section class="drawer-section"><h3>Пароль</h3><div class="copy-row"><input id="password-{drawer_id}" value="{html.escape(item['password'], quote=True)}" readonly><button type="button" data-copy="password-{drawer_id}">Копировать</button></div></section><section class="drawer-section"><h3>Профили</h3><div>{profile_links}</div></section><section class="drawer-section"><h3>Ссылка и QR</h3>{link_controls}<div class="qr-grid">{qr}</div></section><section class="drawer-section"><h3>Действия</h3><form method="post" action="/client/password" data-confirm="Сменить пароль? Старый TOML и ссылка перестанут работать."><input type="hidden" name="username" value="{safe}"><button>Сменить пароль</button></form><form method="post" action="/client/delete" data-confirm="Удалить клиента {safe}? Доступ будет немедленно отозван."><input type="hidden" name="username" value="{safe}"><button class="danger">Удалить клиента</button></form></section></div></aside>'''
        rows.append(f'''<tr class="client-row" data-client-row data-client="{safe.lower()}" data-protocols="{' '.join(protocols)}"><td><div class="client-cell"><span class="avatar">{safe[:1].upper()}</span><div><strong>{safe}</strong><small>доступ активен</small></div></div></td><td><div class="protocols">{''.join(f'<span class="protocol">{proto.upper()}</span>' for proto in protocols)}</div></td><td>{profile_links}</td><td><div class="table-actions"><button type="button" data-drawer="{drawer_id}">Управлять</button></div>{drawer}</td></tr>''')
    return ''.join(rows) or '<tr><td colspan="4" class="muted">Клиентов пока нет.</td></tr>'

def dashboard_view():
    return f'''<div class="page-head"><div><h2>Обзор</h2><p>Состояние TrustTunnel и сервера в реальном времени.</p></div><form method="post" action="/action"><button class="primary" name="action" value="diagnostics">Диагностика</button></form></div><div class="metrics">{card('TrustTunnel', service_status('trusttunnel'), service_status('trusttunnel'))}{card('WARP', service_status('warp-wireproxy'), service_status('warp-wireproxy'))}{card('Маршрут', forwarder_label())}{card('Endpoint', f'{domain()}:{endpoint_port()}')}{card('QUIC / HTTP3', 'включён' if quic_enabled() else 'выключен')}{card('Сертификат', cert_mode())}</div>{monitoring_html()}<section class="surface"><h3>Быстрые действия</h3><form method="post" action="/action"><button class="primary" name="action" value="restart">Перезапустить TrustTunnel</button><button name="action" value="warp">Включить WARP</button><button name="action" value="direct">Direct</button><button name="action" value="speedtest">Speedtest</button><button name="action" value="logs">Логи</button></form></section>'''


def endpoint_view():
    setup = installer_defaults()
    return f'''<div class="page-head"><div><h2>TrustTunnel Endpoint</h2><p>Установка, версия и транспортные параметры.</p></div><form method="post" action="/installer"><input type="hidden" name="action" value="update-trusttunnel"><button class="primary">Обновить endpoint</button></form></div><section class="surface"><h3>Установка / переустановка</h3><p class="warning">Сохраняются сертификат и текущие пользователи. UFW будет пересобран; для запуска введи REINSTALL.</p><form method="post" action="/installer" class="form-grid"><input type="hidden" name="action" value="install"><label>Домен<input name="domain" value="{html.escape(setup['domain'])}" required></label><label>Количество клиентов<input name="clients" value="{setup['clients']}" required></label><label>Порт endpoint<input name="endpoint_port" value="{setup['endpoint_port']}" required></label><label>Email Let's Encrypt<input name="email" placeholder="только для Let's Encrypt"></label><label>Сертификат<select name="cert_mode"><option value="self-signed" {'selected' if setup['cert_mode'] == 'self-signed' else ''}>self-signed</option><option value="letsencrypt" {'selected' if setup['cert_mode'] == 'letsencrypt' else ''}>Let's Encrypt</option></select></label><label>Подтверждение<input name="confirm" placeholder="REINSTALL" required></label><label class="check"><input type="checkbox" name="warp" value="1" {'checked' if setup['warp'] == '1' else ''}> Включить WARP</label><label class="check"><input type="checkbox" name="quic" value="1" {'checked' if setup['quic'] == '1' else ''}> Включить QUIC/HTTP3</label><div><button class="danger">Установить / переустановить</button></div></form></section><section class="surface"><h3>Порт</h3><form method="post" action="/ports/endpoint"><label>Порт TrustTunnel<input name="port" value="{endpoint_port()}" required></label><button>Сменить порт</button></form></section>'''


def clients_view():
    protocol_filters = '<button type="button" class="summary-filter active" data-client-filter="all">Все</button><button type="button" class="summary-filter" data-client-filter="http2">HTTP/2</button>'
    if quic_enabled():
        protocol_filters += '<button type="button" class="summary-filter" data-client-filter="http3">QUIC / HTTP3</button>'
    return f'''<div class="page-head"><div><h2>Клиенты</h2><p>Доступ, TOML-профили, QR и deep links.</p></div><a class="button" href="/backup/latest.zip">Скачать backup</a></div><section class="surface"><h3>Добавить клиента</h3><form method="post" action="/client/add"><label>Логин<input name="username" placeholder="client02" required></label><label>Пароль<input name="password" placeholder="оставь пустым для генерации"></label><button class="primary">Добавить</button></form></section><section class="surface"><div class="page-head"><div><h3>Пользователи</h3><p>Пароли не показываются в таблице. Открой карточку конкретного клиента.</p></div><input id="client-search" class="search" placeholder="Найти клиента" autocomplete="off"></div><div class="summary-filters">{protocol_filters}</div><div class="table-wrap"><table><thead><tr><th>Клиент</th><th>Транспорт</th><th>Профили</th><th></th></tr></thead><tbody>{client_rows()}</tbody></table></div></section>'''

def warp_view():
    return '''<div class="page-head"><div><h2>WARP</h2><p>Исходящий маршрут TrustTunnel через wireproxy.</p></div></div><section class="surface"><form method="post" action="/installer"><input type="hidden" name="action" value="check-warp"><button>Проверить WARP</button></form><form method="post" action="/action"><button name="action" value="warp" class="primary">Включить WARP</button><button name="action" value="direct">Переключить на direct</button><button name="action" value="restart-warp">Перезапустить WARP</button></form></section><section class="surface"><h3>Обслуживание WARP</h3><p class="warning">Перерегистрация меняет WARP-identity, но не клиентов TrustTunnel. Для опасных действий введи REINSTALL.</p><form method="post" action="/installer"><input type="hidden" name="action" value="install-warp"><button>Установить / переустановить WARP</button></form><form method="post" action="/installer"><input type="hidden" name="action" value="reregister-warp"><input name="confirm" placeholder="REINSTALL"><button class="danger">Перерегистрировать</button></form><form method="post" action="/installer"><input type="hidden" name="action" value="remove-warp"><input name="confirm" placeholder="REINSTALL"><button class="danger">Удалить WARP</button></form></section>'''


def routing_view():
    return f'''<div class="page-head"><div><h2>Маршрутизация</h2><p>Direct, WARP, каскадный SOCKS5 и access rules.</p></div></div><section class="surface"><h3>Каскадный upstream</h3><form method="post" action="/cascade"><label>SOCKS5 адрес<input name="address" placeholder="proxy.example:1080" required></label><button class="primary">Включить cascade</button></form></section><section class="surface"><h3>Access rules</h3><form method="post" action="/rules/add-deny"><label>CIDR<input name="cidr" placeholder="203.0.113.0/24" required></label><button>Добавить deny</button></form><form method="post" action="/rules/reset"><button class="danger">Сбросить rules.toml</button></form><pre>{html.escape(rules_text())}</pre></section>'''


def dns_view():
    net = panel_settings()
    return f'''<div class="page-head"><div><h2>DNS, AntiDPI и TLS</h2><p>Настройки применяются к заново экспортируемым TOML.</p></div></div><section class="surface"><p class="warning">Отключено по умолчанию: сначала проверьте новый TOML на одном устройстве.</p><form method="post" action="/client/network" class="form-grid"><label>DNS upstream<input name="dns" value="{html.escape(net['DNS_UPSTREAMS'])}" required></label><label>TLS profile<select name="tls_profile"><option value="chrome">chrome</option><option value="safari">safari</option><option value="firefox">firefox</option><option value="okhttp">okhttp</option><option value="openssl">openssl</option><option value="default">default</option></select></label><label class="check"><input type="checkbox" name="anti_dpi" value="1" {'checked' if net['CLIENT_ANTI_DPI'] == '1' else ''}> AntiDPI</label><label class="check"><input type="checkbox" name="post_quantum" value="1" {'checked' if net.get('POST_QUANTUM') == '1' else ''}> Post-quantum TLS</label><div><button class="primary">Сохранить и пересобрать профили</button></div></form></section>'''


def certificates_view():
    return '''<div class="page-head"><div><h2>Сертификаты</h2><p>Текущий сертификат endpoint и ручное продление.</p></div></div><section class="surface"><form method="post" action="/action"><button name="action" value="certificate">Показать информацию</button><button class="primary" name="action" value="renew-cert">Обновить Let's Encrypt</button></form></section>'''


def security_view():
    return '''<div class="page-head"><div><h2>Безопасность</h2><p>UFW, fail2ban и доступ к серверу.</p></div></div><section class="surface"><h3>fail2ban</h3><form method="post" action="/fail2ban"><button name="action" value="status">Статус</button><button name="action" value="enable">Включить</button><button class="danger" name="action" value="disable">Отключить</button><input name="ip" placeholder="IP для разбана"><button name="action" value="unban">Разбанить</button></form></section><section class="surface"><h3>UFW</h3><form method="post" action="/ufw"><button name="action" value="status">Статус</button><button name="action" value="rebuild">Пересобрать базовые правила</button><input name="port" placeholder="порт"><select name="proto"><option>tcp</option><option>udp</option></select><button name="action" value="allow">Открыть</button><button class="danger" name="action" value="delete">Закрыть</button></form></section>'''


def system_view():
    return '''<div class="page-head"><div><h2>Система</h2><p>Обновления, диагностика, журнал и уведомления.</p></div></div><section class="surface"><form method="post" action="/maintenance"><button name="action" value="packages">Обновить пакеты VPS</button><button name="action" value="status">Статус планировщика</button><button name="action" value="enable">Включить daily check</button><button class="danger" name="action" value="disable">Отключить daily check</button></form></section><section class="surface"><form method="post" action="/action"><button name="action" value="speedtest">Speedtest</button><button name="action" value="diagnostics">Диагностика</button><button name="action" value="logs">Логи TrustTunnel</button><button name="action" value="audit">Журнал действий</button><button name="action" value="backup">Создать backup</button></form></section><section class="surface"><h3>Telegram</h3><form method="post" action="/telegram"><input name="token" placeholder="Bot token" required><input name="chat_id" placeholder="Chat ID" required><button>Сохранить и проверить</button></form></section>'''


def panel_view():
    env = current_panel_env()
    return f'''<div class="page-head"><div><h2>Панель</h2><p>Доступ, HTTPS и данные администратора.</p></div></div><section class="surface"><h3>Режим доступа</h3><form method="post" action="/panel/access"><label>Порт панели<input name="port" value="{html.escape(env.get('PANEL_PORT', '8088'))}" required></label><button name="mode" value="localhost">Только localhost</button><button class="primary" name="mode" value="https">Публичный HTTPS</button></form></section><section class="surface"><h3>Учётные данные</h3><form method="post" action="/panel/credentials"><label>Логин<input name="username" value="{html.escape(env.get('PANEL_USER', 'admin'))}" required></label><label>Новый пароль<input type="password" name="password" minlength="12" required></label><button class="primary">Сменить данные входа</button></form></section>'''


def admin_form(action, body, username='', view='clients', confirm=''):
    confirmation = f' data-confirm="{html.escape(confirm, quote=True)}"' if confirm else ''
    identity = f'<input type="hidden" name="username" value="{html.escape(username, quote=True)}">' if username else ''
    return f'<form method="post" action="/manage"{confirmation}><input type="hidden" name="action" value="{action}"><input type="hidden" name="view" value="{view}">{identity}{body}</form>'


def clients_console():
    clients = client_inventory()
    rows, drawers = [], []
    for index, client in enumerate(clients):
        name = client['username']
        safe = html.escape(name, quote=True)
        enabled = client['enabled']
        state = 'active' if enabled else 'inactive'
        label = 'Включён' if enabled else 'Отключён'
        drawer_id = f'identity-{index}'
        profiles = ''
        if enabled:
            for proto, title in [('http2', 'HTTP/2')] + ([('http3', 'QUIC')] if quic_enabled() else []):
                profiles += f'<a class="button" href="/client/{urllib.parse.quote(name)}/{proto}.toml">{title} TOML</a> '
        link = deeplink(name) if enabled else ''
        share = f'<label>Ссылка подключения<textarea id="share-{index}" readonly>{html.escape(link)}</textarea></label><button type="button" data-copy="share-{index}">Копировать ссылку</button><img class="share-qr" loading="lazy" alt="QR подключения {safe}" src="/qr-link/{urllib.parse.quote(name)}.png">' if link else '<p class="muted">Ссылка доступна для включённого клиента, если endpoint поддерживает экспорт.</p>'
        toggle = admin_form('client-disable' if enabled else 'client-enable', f'<button role="switch" aria-checked="{str(enabled).lower()}" class="toggle {state}" title="{label}"><span></span></button>', name, confirm='Изменить доступ клиента? Активные подключения TrustTunnel переподключатся.')
        rows.append(f'<tr data-client-row data-client="{safe.lower()} {html.escape(client["note"].lower(), quote=True)}" data-protocols="http2 http3" data-state="{state}"><td>{toggle}</td><td><strong>{safe}</strong><span class="muted">{html.escape(client["note"])}</span></td><td><span class="badge {state}">{label}</span></td><td><span class="protocol">HTTP/2</span> {"<span class=protocol>QUIC</span>" if quic_enabled() else ""}</td><td class="table-actions"><button type="button" data-drawer="{drawer_id}">Управлять</button></td></tr>')
        note = admin_form('client-note', f'<label>Заметка<input name="note" maxlength="300" value="{html.escape(client["note"], quote=True)}"></label><button>Сохранить</button>', name)
        password = admin_form('client-password', '<label>Новый пароль<input name="password" type="password" placeholder="Пусто: случайный" autocomplete="new-password"></label><button>Сменить пароль</button>', name, confirm='Старый пароль перестанет работать. Потребуется обновить профиль клиента.')
        delete = admin_form('client-delete', '<button class="danger">Удалить клиента</button>', name, confirm='Удалить клиента и отозвать доступ?')
        drawers.append(f'<aside class="drawer" id="{drawer_id}" role="dialog" aria-modal="true" aria-label="Клиент {safe}"><div class="drawer-card"><div class="drawer-head"><h2>{safe}</h2><button type="button" data-drawer-close aria-label="Закрыть">×</button></div><section class="drawer-section">{note}</section><section class="drawer-section"><label>Текущий пароль<input type="password" value="{html.escape(client["password"], quote=True)}" id="secret-{index}" readonly></label><button type="button" data-reveal="secret-{index}">Показать / скрыть</button><button type="button" data-copy="secret-{index}">Копировать</button></section><section class="drawer-section"><h3>Подключение</h3>{profiles}{share}</section><section class="drawer-section">{password}{delete}</section></div></aside>')
    create = admin_form('client-add', '<label>Логин<input name="username" pattern="[A-Za-z0-9_.-]{1,64}" required></label><label>Пароль<input name="password" type="password" placeholder="Пусто: случайный"></label><button class="primary">Добавить клиента</button>')
    batch = admin_form('client-batch', '<label>Префикс<input name="prefix" value="client" maxlength="54" required></label><label>Количество<input name="count" type="number" min="1" max="100" value="5" required></label><button>Создать группу</button>', confirm='Создать новых клиентов? TrustTunnel кратковременно перезапустится.')
    active = sum(c['enabled'] for c in clients)
    return f'<div class="page-head"><div><h2>Клиенты</h2><p>{len(clients)} всего · {active} включено · {len(clients)-active} отключено</p></div><button class="primary" data-drawer="add-client">Добавить клиентов</button></div><div class="table-toolbar"><input id="client-search" class="search" aria-label="Поиск клиентов" placeholder="Поиск по логину или заметке"><select id="client-state" aria-label="Состояние клиента"><option value="all">Все состояния</option><option value="active">Включённые</option><option value="inactive">Отключённые</option></select><span id="client-count"></span></div><div class="table-wrap"><table><thead><tr><th>Доступ</th><th>Клиент / заметка</th><th>Состояние</th><th>Транспорт</th><th></th></tr></thead><tbody>{"".join(rows)}</tbody></table></div><div class="pagination"><button id="page-prev" aria-label="Предыдущая страница">←</button><span id="page-label"></span><button id="page-next" aria-label="Следующая страница">→</button><select id="page-size" aria-label="Строк на странице"><option>10</option><option>25</option><option>50</option></select></div>{"".join(drawers)}<aside class="drawer" id="add-client" role="dialog" aria-modal="true" aria-label="Добавление клиентов"><div class="drawer-card"><div class="drawer-head"><h2>Добавление клиентов</h2><button data-drawer-close aria-label="Закрыть">×</button></div><section class="drawer-section"><h3>Один клиент</h3>{create}</section><section class="drawer-section"><h3>Группа клиентов</h3>{batch}</section></div></aside>'


def overview_console():
    stats = monitor_snapshot()
    cards = ''.join(f'<div class="metric"><small>{label}</small><strong id="stat-{key}">{html.escape(stats[key])}</strong></div>' for key, label in [('cpu', 'Нагрузка CPU'), ('memory', 'Оперативная память'), ('disk', 'Диск'), ('uptime', 'Время работы')])
    services = ''.join(f'<tr><td>{name}</td><td id="service-{name}"><span class="badge {status}">{status}</span></td></tr>' for name, status in stats['services'].items())
    return f'<div class="page-head"><div><h2>Обзор</h2><p>{html.escape(domain())}:{endpoint_port()} · {html.escape(endpoint_version())}</p></div><span id="monitor-status" class="badge active">Подключено</span></div><div class="metrics overview-metrics">{cards}</div><div class="resource-bars"><label>RAM <meter id="ram-meter" min="0" max="100" value="{stats["memory_percent"]}"></meter></label><label>Диск <meter id="disk-meter" min="0" max="100" value="{stats["disk_percent"]}"></meter></label></div><section class="surface"><div class="page-head"><h3>Сетевой трафик VPS</h3><span id="network-rate">Ожидание второго измерения</span></div><canvas id="traffic-chart" height="150" aria-label="Скорость входящего и исходящего трафика"></canvas><div class="chart-legend"><span class="rx">● Приём</span><span class="tx">● Отправка</span><span>Последние 60 измерений · байт/с</span></div><div id="interface-totals"></div></section><div class="overview-columns"><section class="surface"><h3>Сервисы</h3><table><tbody>{services}</tbody></table></section><section class="surface"><h3>Подключение</h3><dl><dt>Исходящий маршрут</dt><dd id="stat-route">{html.escape(stats["route"])}</dd><dt>Транспорты</dt><dd>HTTP/2 {"· QUIC / HTTP3" if quic_enabled() else ""}</dd><dt>Сертификат</dt><dd>{cert_mode()}</dd></dl><a class="button" href="/?view=endpoint">Настройки подключения</a></section></div>'


def logs_console():
    controls = admin_form('logs', '<label>Сервис<select name="unit"><option>trusttunnel</option><option>warp-wireproxy</option><option>trusttunnel-panel</option><option>fail2ban</option></select></label><label>Строк<input name="lines" type="number" min="20" max="500" value="100"></label><button class="primary">Показать журнал</button>', view='logs')
    audit = admin_form('audit', '<button>Журнал действий администратора</button>', view='logs')
    return f'<div class="page-head"><h2>Журналы</h2></div><section class="surface">{controls}{audit}</section>'


def security_console():
    status = admin_form('security-status', '<button class="primary">Проверить безопасность</button>', view='security')
    jail = admin_form('security-fail2ban', '<label>Попыток<input name="retry" type="number" min="1" max="100" value="5"></label><label>Окно, с<input name="findtime" type="number" min="60" max="86400" value="600"></label><label>Бан, с<input name="bantime" type="number" min="60" max="604800" value="3600"></label><button>Применить</button>', view='security', confirm='Изменить параметры защиты SSH?')
    bans = ''.join(admin_form('security-' + action, '<label>IP-адрес<input name="ip" required></label><button>' + title + '</button>', view='security', confirm='Изменить блокировку IP в SSH jail?') for action, title in [('ban', 'Забанить'), ('unban', 'Разбанить')])
    ports = ''.join(admin_form('security-' + action, '<label>Порт<input type="number" name="port" min="1" max="65535" required></label><label>Протокол<select name="proto"><option>tcp</option><option>udp</option></select></label><button>' + title + '</button>', view='security', confirm='Изменить правило UFW?') for action, title in [('open', 'Разрешить'), ('close', 'Удалить разрешение')])
    return f'<div class="page-head"><h2>Безопасность сервера</h2>{status}</div><section class="surface"><h3>Защита SSH · fail2ban</h3>{jail}<div>{bans}</div></section><section class="surface"><h3>Сетевой экран · UFW</h3><p class="warning">Порты SSH, TrustTunnel и панели защищены от удаления разрешения. Удаление разрешения не блокирует порт, если его разрешает другое правило.</p>{ports}</section>'


def routing_console():
    switch = admin_form('routing-switch', '<label>Маршрут<select name="mode"><option value="direct">Direct · IP сервера</option><option value="warp">WARP · IP Cloudflare</option><option value="socks5">Каскад SOCKS5</option></select></label><label>SOCKS5 host:port<input name="address" placeholder="proxy.example:1080"></label><button class="primary">Применить маршрут</button>', view='routing', confirm='Переключить маршрут? TrustTunnel кратковременно перезапустится.')
    add = admin_form('routing-rule-add', '<label>IP / подсеть CIDR<input name="cidr" placeholder="203.0.113.0/24" required></label><label>Действие<select name="decision"><option value="deny">Запретить</option><option value="allow">Разрешить</option></select></label><button>Добавить правило</button>', view='routing', confirm='Применить правило доступа и перезапустить TrustTunnel?')
    rules = tomllib.loads(rules_text()).get('rule', [])
    rows = []
    import hashlib
    for index, rule in enumerate(rules, 1):
        fingerprint = hashlib.sha256(json.dumps(rule, sort_keys=True).encode()).hexdigest()
        delete = admin_form('routing-rule-delete', f'<input type="hidden" name="index" value="{index}"><input type="hidden" name="fingerprint" value="{fingerprint}"><button class="danger">Удалить</button>', view='routing', confirm='Удалить это правило доступа?')
        rows.append(f'<tr><td>{index}</td><td>{html.escape(rule.get("cidr", ""))}</td><td>{html.escape(rule.get("client_random_prefix", ""))}</td><td>{html.escape(rule.get("action", ""))}</td><td>{delete}</td></tr>')
    return f'<div class="page-head"><h2>Маршрутизация</h2>{admin_form("routing-check", "<button>Диагностика</button>", view="routing")}</div><section class="surface"><h3>Выход в интернет: {html.escape(forwarder_label())}</h3>{switch}</section><section class="surface"><h3>Правила доступа к TrustTunnel</h3><p class="warning">Правила относятся к входящему IP клиента. Выполняется первое совпадение; без совпадения доступ разрешён. Это не фильтр посещаемых сайтов.</p>{add}<div class="table-wrap"><table><thead><tr><th>№</th><th>CIDR</th><th>Client random</th><th>Действие</th><th></th></tr></thead><tbody>{"".join(rows) or "<tr><td colspan=5>Правил нет</td></tr>"}</tbody></table></div></section>'


def dns_console():
    values = panel_settings()
    saved = html.escape(values['DNS_UPSTREAMS'], quote=True)
    save = admin_form('dns-save', f'<label>DNS: IP, DoH, DoT или DoQ<input name="dns" size="56" value="{saved}" required></label><button class="primary">Сохранить DNS</button>', view='dns')
    check = admin_form('dns-check', '<button>Проверить DNS с VPS</button>', view='dns')
    apply = admin_form('dns-apply', '<button>Пересобрать TOML</button>', view='dns', confirm='Пересобрать профили с сохранённым DNS? На устройствах потребуется импортировать новые TOML.')
    advanced = dns_view()
    advanced = re.sub(r'<div class="page-head">.*?</div></div>', '', advanced, count=1)
    return f'<div class="page-head"><h2>DNS и настройки клиента</h2></div><section class="surface"><h3>DNS-серверы клиентов</h3>{save}<div>{check}{apply}</div><p class="muted">Сохранение не меняет текущие профили. IP DNS проверяется запросом с VPS; для DoH/DoT/DoQ проверяется разрешение имени сервера.</p></section><details class="surface"><summary>TLS и AntiDPI</summary>{advanced}</details>'


PANEL_STYLE += r'''
*{letter-spacing:0} :root{--nav:#fff;--nav-hover:#f1f5f9;--nav-active:#e8f3ff;--ink:#20252b;--accent:#1677ff;--canvas:#f5f5f5;--line:#e8e8e8}
.sidebar{border-right:1px solid var(--line);color:var(--ink)}.brand{color:var(--ink);border-color:var(--line);display:block}.brand:before{display:none}.brand small{color:var(--muted)}.nav-item{color:#4b5563}.nav-item:hover{color:var(--accent)}.nav-item.active{color:var(--accent);box-shadow:none}.nav-label{color:#8b929c}.topbar{position:static}.endpoint-context:before{display:none}.content{max-width:1600px}.surface{border:0;border-radius:0;background:transparent;padding:20px 0;border-top:1px solid var(--line)}.surface .surface{border:0}.table-wrap{background:var(--surface);border:1px solid var(--line);border-radius:6px}th{font-size:12px;text-transform:none;background:#fafafa}table{min-width:0}td,th{padding:12px}th:first-child{width:74px}.table-toolbar,.pagination{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:16px 0}.pagination{justify-content:flex-end}.table-actions{display:table-cell;text-align:right}.toggle{padding:2px;width:36px;min-height:20px;height:20px;border:0;border-radius:10px;background:#c7cbd1;display:flex;justify-content:flex-start}.toggle span{width:16px;height:16px;background:white;border-radius:50%}.toggle.active{background:var(--accent);justify-content:flex-end}.share-qr{display:block;width:180px;height:180px;margin:16px 0}.copy-row input{min-width:0;width:100%}.drawer-card input,.drawer-card textarea{max-width:100%;width:100%}.drawer-card form{display:flex;align-items:end}.drawer-card label{min-width:0;flex:1}.drawer-card{overscroll-behavior:contain}.drawer-section{display:flow-root}.drawer-head button{font-size:24px;line-height:1;width:36px;padding:0}.overview-metrics{grid-template-columns:repeat(4,minmax(0,1fr))}.overview-columns{display:grid;grid-template-columns:1fr 1fr;gap:28px}.metric{box-shadow:0 1px 2px #00000005}.metric strong{font-size:17px}.resource-bars{display:flex;gap:24px}.resource-bars label{flex:1}meter{width:100%;height:8px}.chart-legend{display:flex;flex-wrap:wrap;gap:16px;font-size:12px;color:var(--muted)}.rx{color:#1677ff}.tx{color:#21a366}#traffic-chart{width:100%;height:150px;display:block}dl{display:grid;grid-template-columns:1fr 1fr;gap:10px}dd{margin:0;overflow-wrap:anywhere}.notice{overflow-wrap:anywhere}.text-link{color:var(--accent)}input,select{max-width:100%;min-width:0}input[type=checkbox]{min-height:0}button:disabled{opacity:.55;cursor:wait}.endpoint-context{flex-wrap:wrap}h2{font-size:24px}.theme-toggle{width:36px;padding:0;font-size:20px}.header-actions{display:flex;gap:8px;align-items:center}
html[data-theme=dark]{--ink:#e4e7ec;--muted:#a0a7b2;--canvas:#141414;--surface:#1f1f1f;--line:#343434;--nav:#1f1f1f;--nav-hover:#292929;--nav-active:#112c48}html[data-theme=dark] input,html[data-theme=dark] select,html[data-theme=dark] textarea,html[data-theme=dark] button,html[data-theme=dark] .button,html[data-theme=dark] .metric{background:var(--surface);color:var(--ink);border-color:#414141}html[data-theme=dark] .drawer-card,html[data-theme=dark] .command-box{background:var(--surface)}html[data-theme=dark] th{background:#252525}html[data-theme=dark] .nav-item{color:#b6bdc7}html[data-theme=dark] .primary{background:#1668dc}html[data-theme=dark] .nav-item.active{color:#69b1ff}html[data-theme=dark] tr:hover td{background:#242424}html[data-theme=dark] .toggle.active{background:#1668dc}html[data-theme=dark] .command-item:hover{background:#292929}
@media(max-width:900px){.overview-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.sidebar{border-bottom:1px solid var(--line)}.overview-columns{grid-template-columns:1fr}.endpoint-context span{display:none}}@media(max-width:560px){.content{padding:16px 12px}.overview-metrics{grid-template-columns:1fr 1fr}.metric strong{font-size:14px}.metric{padding:10px}.table-wrap{overflow-x:auto}.table-wrap table{min-width:600px}.page-head h2{font-size:22px}.topbar{padding:0 12px}.page-head>button{margin-top:12px}.resource-bars{gap:12px}}
'''

CONSOLE_SCRIPT = r'''
(() => {
  let theme = 'light'; try { theme = localStorage.getItem('tt-theme') || theme; } catch (_) {}
  document.documentElement.dataset.theme = theme;
  document.getElementById('theme-toggle').onclick = () => { const value = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = value; try { localStorage.setItem('tt-theme', value); } catch (_) {} };
  document.querySelectorAll('[data-reveal]').forEach(b => b.onclick = () => { const input = document.getElementById(b.dataset.reveal); input.type = input.type === 'password' ? 'text' : 'password'; });
  document.querySelectorAll('[data-drawer]').forEach(b => b.addEventListener('click', () => { document.getElementById(b.dataset.drawer).querySelector('button,input')?.focus(); }));
  document.addEventListener('keydown', e => { if(e.key !== 'Tab') return; const d = document.querySelector('.drawer.open'); if(!d) return; const items = [...d.querySelectorAll('button,input:not([type=hidden]),textarea,a[href],select')]; const first = items[0], last = items.at(-1); if(e.shiftKey && document.activeElement === first) {e.preventDefault();last.focus();} else if(!e.shiftKey && document.activeElement === last) {e.preventDefault();first.focus();} });
  document.querySelectorAll('form').forEach(f => f.addEventListener('submit', e => {if(e.defaultPrevented) return; setTimeout(() => f.querySelectorAll('button').forEach(b => b.disabled = true), 0);}));
  const rows = [...document.querySelectorAll('[data-client-row]')]; let page = 0;
  const search = document.getElementById('client-search'), state = document.getElementById('client-state'), size = document.getElementById('page-size');
  function filter() { if(!state) return; const matches = rows.filter(r => r.dataset.client.includes(search.value.toLowerCase()) && (state.value === 'all' || r.dataset.state === state.value)); const pages = Math.max(1, Math.ceil(matches.length / +size.value)); page = Math.min(page,pages-1); rows.forEach(r => r.hidden = true); matches.slice(page*+size.value,(page+1)*+size.value).forEach(r => r.hidden=false); document.getElementById('page-label').textContent = `${page+1} / ${pages}`; document.getElementById('client-count').textContent = `Найдено: ${matches.length}`; document.getElementById('page-prev').disabled = page===0; document.getElementById('page-next').disabled = page===pages-1; }
  if(state) { [search,state,size].forEach(x => x.addEventListener('input', () => {page=0;filter();})); document.getElementById('page-prev').onclick=()=>{page--;filter();};document.getElementById('page-next').onclick=()=>{page++;filter();}; filter(); }
  const canvas = document.getElementById('traffic-chart'); if(!canvas) return;
  let previous=null, history=[];
  const bytes = value => {const units=['B','KiB','MiB','GiB','TiB'];let n=0;while(value>=1024 && n<4){value/=1024;n++;}return value.toFixed(1)+' '+units[n];};
  function draw() { const w=canvas.clientWidth, h=150, ratio=devicePixelRatio||1;canvas.width=w*ratio;canvas.height=h*ratio;const c=canvas.getContext('2d');c.scale(ratio,ratio);c.clearRect(0,0,w,h);c.strokeStyle='#88888830';for(let y=0;y<h;y+=30){c.beginPath();c.moveTo(0,y);c.lineTo(w,y);c.stroke();}const max=Math.max(1024,...history.flat()); ['#1677ff','#21a366'].forEach((color,k)=>{c.strokeStyle=color;c.lineWidth=2;c.beginPath();history.forEach((v,i)=>{let x=i/59*w,y=h-8-v[k]/max*(h-16);i?c.lineTo(x,y):c.moveTo(x,y);});c.stroke();}); }
  async function poll() { try { const response=await fetch('/api/monitor',{cache:'no-store'}); if(!response.ok) throw Error(response.status); const data=await response.json(); for(const key of ['cpu','memory','disk','uptime','route']) document.getElementById('stat-'+key).textContent=data[key];document.getElementById('ram-meter').value=data.memory_percent;document.getElementById('disk-meter').value=data.disk_percent;for(const [name,value] of Object.entries(data.services)){const cell=document.getElementById('service-'+name);cell.textContent=value;}const status=document.getElementById('monitor-status');status.textContent='Обновлено '+new Date().toLocaleTimeString();status.className='badge active';document.getElementById('interface-totals').textContent=Object.entries(data.interfaces).map(([name,v])=>`${name}: принято ${bytes(v.rx)}, отправлено ${bytes(v.tx)}`).join(' · ');if(previous){const dt=data.time-previous.time;if(dt>0){let rx=0,tx=0;for(const [name,v] of Object.entries(data.interfaces)){const old=previous.interfaces[name];if(old){rx+=Math.max(0,v.rx-old.rx)/dt;tx+=Math.max(0,v.tx-old.tx)/dt;}}history.push([rx,tx]);history=history.slice(-60);document.getElementById('network-rate').textContent=`↓ ${bytes(rx)}/с   ↑ ${bytes(tx)}/с`;draw();}}previous=data;} catch(e) {const s=document.getElementById('monitor-status');s.textContent='Нет связи с панелью';s.className='badge failed';} finally {setTimeout(poll,5000);} }
  window.addEventListener('resize',draw);poll();
})();
'''


def page_shell(message='', log='', view='dashboard'):
    views = {'dashboard': overview_console, 'endpoint': endpoint_view, 'clients': clients_console, 'warp': warp_view, 'routing': routing_console, 'dns': dns_console, 'certificates': certificates_view, 'security': security_console, 'system': system_view, 'panel': panel_view, 'logs': logs_console}
    view = view if view in views else 'dashboard'
    content = views[view]()
    notice = f'<div class="notice">{html.escape(message)}</div>' if message else ''
    output = f'<section class="surface"><pre>{html.escape(log)}</pre></section>' if log else ''
    labels = dict(NAV_ITEMS)
    commands = ''.join(f'<a class="command-item" href="/?view={key}">{label}<small>Открыть раздел</small></a>' for key, label in NAV_ITEMS)
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>TrustTunnel Panel</title><style>{PANEL_STYLE}</style></head><body data-view="{view}"><div class="layout"><aside class="sidebar"><div class="brand">TrustTunnel<small>Панель управления сервером</small></div>{nav_html(view)}</aside><div class="workspace"><header class="topbar"><div class="endpoint-context"><strong>{html.escape(domain())}:{endpoint_port()}</strong><span>{html.escape(labels[view])}</span></div><button type="button" class="command-trigger" data-command-open>Команды <kbd>Ctrl K</kbd></button></header><main class="content">{notice}{content}{output}</main></div></div><div class="command-layer" id="command-layer"><div class="command-box"><input id="command-search" placeholder="Перейти к разделу" autocomplete="off"><div class="command-list">{commands}</div></div></div><script>{PANEL_SCRIPT}</script></body></html>'''

def html_page(message='', log='', view='dashboard'):
    page = page_shell(message, log, view)
    page = re.sub(r'(<form\b[^>]*>)', lambda m: m[1] + f'<input type="hidden" name="_csrf" value="{CSRF_TOKEN}">', page)
    page = page.replace('</header>', '<button id="theme-toggle" class="theme-toggle" title="Светлая / тёмная тема" aria-label="Сменить тему">◐</button></header>')
    page = page.replace("if(document.body.dataset.view==='dashboard')setTimeout(()=>location.reload(),30000)", '')
    page = page.replace('</body>', '<script>' + CONSOLE_SCRIPT + '</script></body>')
    # Restore the selected TLS option instead of silently resetting it to Chrome.
    selected = html.escape(client_tls_profile(), quote=True)
    page = page.replace(f'<option value="{selected}">{selected}</option>', f'<option value="{selected}" selected>{selected}</option>')
    return page


class Handler(http.server.BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        super().end_headers()

    def authenticated(self):
        if not PANEL_PASSWORD:
            self.send_error(503, 'Panel password is not configured')
            return False
        auth = self.headers.get('Authorization', '')
        expected = 'Basic ' + base64.b64encode(f'{PANEL_USER}:{PANEL_PASSWORD}'.encode()).decode()
        if secrets.compare_digest(auth, expected):
            return True
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="TrustTunnel Panel"')
        self.end_headers()
        return False

    def send_html(self, message='', log='', view='dashboard'):
        body = html_page(message, log, view).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def form(self):
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 <= length <= 65536:
            raise ValueError('Request body too large')
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(length).decode()).items()}

    def redirect(self, message):
        allowed = {key for key, _ in NAV_ITEMS}
        ref = urllib.parse.urlparse(self.headers.get('Referer', ''))
        candidate = urllib.parse.parse_qs(ref.query).get('view', ['dashboard'])[0]
        view = candidate if candidate in allowed else 'dashboard'
        self.send_response(303)
        self.send_header('Location', '/?view=' + urllib.parse.quote(view) + '&msg=' + urllib.parse.quote(message))
        self.end_headers()

    def do_GET(self):
        if self.path == '/health':
            self.send_response(200); self.end_headers(); self.wfile.write(b'ok\n'); return
        if not self.authenticated():
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/api/monitor':
            body = json.dumps(monitor_snapshot()).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == '/':
            query = urllib.parse.parse_qs(parsed.query)
            self.send_html(query.get('msg', [''])[0], view=query.get('view', ['dashboard'])[0]); return
        m = re.fullmatch(r'/client/([^/]+)/(http2|http3)\.toml', parsed.path)
        if m:
            username = urllib.parse.unquote(m.group(1))
            if not client_name_valid(username) or username not in {c['username'] for c in load_clients()}:
                self.send_error(404); return
            path = CLIENT_DIR / f'{username}-{m.group(2)}.toml'
            if path.exists():
                body = path.read_bytes(); self.send_response(200); self.send_header('Content-Type', 'application/toml; charset=utf-8'); self.send_header('Content-Disposition', f'attachment; filename="{path.name}"'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body); return
        m = re.fullmatch(r'/qr/([^/]+)/(http2|http3)\.png', parsed.path)
        if m:
            username = urllib.parse.unquote(m.group(1))
            if not client_name_valid(username) or username not in {c['username'] for c in load_clients()}:
                self.send_error(404); return
            path = CLIENT_DIR / f'{username}-{m.group(2)}.toml'
            if path.exists() and shutil.which('qrencode'):
                p = subprocess.run(['qrencode', '-t', 'PNG', '-o', '-'], input=path.read_bytes(), stdout=subprocess.PIPE)
                self.send_response(200); self.send_header('Content-Type', 'image/png'); self.end_headers(); self.wfile.write(p.stdout); return
        m = re.fullmatch(r'/qr-link/([^/]+)\.png', parsed.path)
        if m and shutil.which('qrencode'):
            username = urllib.parse.unquote(m.group(1))
            if not client_name_valid(username) or username not in {c['username'] for c in load_clients()}:
                self.send_error(404); return
            link = deeplink(username)
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
        try:
            f = self.form()
        except (ValueError, UnicodeError):
            self.send_error(400, 'Invalid form'); return
        if not secrets.compare_digest(f.get('_csrf', ''), CSRF_TOKEN):
            self.send_error(403, 'Reload page and try again'); return
        if self.path == '/manage':
            try:
                f['_peer'] = self.client_address[0]
                result = admin_operation(f.get('action', ''), f)
                self.send_html('Операция выполнена.', result, f.get('view', 'clients'))
            except (ValueError, RuntimeError, OSError) as exc:
                self.send_html('Операция не выполнена.', str(exc), f.get('view', 'clients'))
            return
        if self.path == '/action':
            action = f.get('action', '')
            if action == 'restart':
                rc, out = run(['systemctl', 'restart', 'trusttunnel'], timeout=20); self.send_html('TrustTunnel restarted.', out); return
            if action == 'warp':
                try: self.redirect(admin_operation('routing-switch', {'mode': 'warp'}))
                except (ValueError, RuntimeError, OSError) as exc: self.send_html('Маршрут не изменён.', str(exc), 'warp')
                return
            if action == 'direct':
                try: self.redirect(admin_operation('routing-switch', {'mode': 'direct'}))
                except (ValueError, RuntimeError, OSError) as exc: self.send_html('Не удалось применить маршрут.', str(exc), 'routing')
                return
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
        if self.path == '/installer':
            action = f.get('action', '')
            self.send_html('Операция установщика завершена.', installer_operation(action, f))
            return
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
        if self.path == '/client/network':
            self.send_html('Настройки клиентов обновлены.', save_client_network_settings(f.get('dns', ''), f.get('anti_dpi') == '1', f.get('tls_profile', 'chrome'), f.get('post_quantum') == '1'))
            return
        if self.path == '/cascade':
            try: self.redirect(admin_operation('routing-switch', {'mode': 'socks5', 'address': f.get('address', '')}))
            except (ValueError, RuntimeError, OSError) as exc: self.send_html('Маршрут не изменён.', str(exc), 'routing')
            return
        if self.path == '/client/add':
            action = 'add'
        elif self.path in ('/client/delete', '/client/password'):
            action = self.path.rsplit('/', 1)[1]
        else:
            action = None
        if action:
            try:
                self.redirect(client_operation(action, f))
            except (ValueError, RuntimeError, OSError) as exc:
                self.send_html('Операция не выполнена.', str(exc), 'clients')
            return
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
    if len(sys.argv) > 1 and sys.argv[1] == '--admin':
        try:
            action = sys.argv[2]
            values = dict(arg.split('=', 1) for arg in sys.argv[3:])
            if not sys.stdin.isatty():
                payload = sys.stdin.read().strip()
                if payload:
                    values.update(json.loads(payload))
            print(admin_operation(action, values))
        except (ValueError, RuntimeError, OSError, IndexError) as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
    else:
        main()

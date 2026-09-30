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
import functools
import hashlib
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
ADMIN_VERSION = '2026.09.30'
ADMIN_LOCK = threading.RLock()
CSRF_TOKEN = secrets.token_urlsafe(32)
CACHE_LOCK = threading.RLock()
SNAPSHOT_CACHE = {}
LOGIN_LOCK = threading.Lock()
LOGIN_FAILURES = {}
CPU_SAMPLE = None
IGNORE_FILE = Path('/etc/fail2ban/jail.d/zz-trusttunnel-ignore.local')


def cached_snapshot(seconds):
    def decorate(fn):
        @functools.wraps(fn)
        def wrapped():
            with CACHE_LOCK:
                cached = SNAPSHOT_CACHE.get(fn.__name__)
                if cached and time.monotonic() - cached[0] < seconds:
                    return cached[1]
                value = fn()
                SNAPSHOT_CACHE[fn.__name__] = (time.monotonic(), value)
                return value
        return wrapped
    return decorate


def login_delay(peer, failed=False, success=False):
    now = time.monotonic()
    with LOGIN_LOCK:
        for address, (_, until) in list(LOGIN_FAILURES.items()):
            if until <= now:
                LOGIN_FAILURES.pop(address, None)
        if success:
            LOGIN_FAILURES.pop(peer, None)
            return 0
        count, until = LOGIN_FAILURES.get(peer, (0, now + 60))
        if failed:
            if len(LOGIN_FAILURES) >= 2048 and peer not in LOGIN_FAILURES:
                LOGIN_FAILURES.pop(next(iter(LOGIN_FAILURES)))
            count += 1
            LOGIN_FAILURES[peer] = (count, until)
        return max(1, int(until - now)) if count >= 5 else 0


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


@cached_snapshot(60)
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
    if action.startswith('system-'):
        with admin_lock():
            return power_operation(action, values)
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
    if action == 'security-audit':
        data = security_snapshot()
        return '\n\n'.join(item['title'] + ': ' + item['detail'] for item in data['checks'])
    if action == 'security-listeners':
        return checked_run(['ss', '-lntup'])
    if action == 'security-logins':
        return recent_logs('ssh', 100) + '\n' + recent_logs('sshd', 100)
    if action == 'security-ignore-list':
        return checked_run(['fail2ban-client', 'get', 'sshd', 'ignoreip'])
    if action in ('security-ignore-add', 'security-ignore-remove'):
        return update_ignore_list(action, values)
    if action == 'security-status':
        report = '\n'.join(run(cmd)[1] for cmd in (['ufw', 'status', 'numbered'], ['fail2ban-client', 'status', 'sshd'], ['sshd', '-T']))
        return report + '\n\nSSH jail: ' + json.dumps(jail_settings(), ensure_ascii=False)
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
        source = values.get('source', '').strip()
        rule = ['allow', f'{int(port)}/{proto}']
        if source:
            source = str(ipaddress.ip_network(source, strict=False))
            rule = ['allow', 'proto', proto, 'from', source, 'to', 'any', 'port', str(int(port))]
        command = ['ufw'] + ([] if action == 'security-open' else ['--force', 'delete']) + rule
        result = checked_run(command)
        audit_log(action, f'{port}/{proto} from {source or "any"}')
        return result
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


@cached_snapshot(5)
def monitor_snapshot():
    result = system_metrics()
    result['services'] = service_snapshot()
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
    result['sample_interval'] = 10
    return result


@cached_snapshot(15)
def service_snapshot():
    units = ('trusttunnel', 'warp-wireproxy', 'fail2ban', 'trusttunnel-panel')
    rc, output = run(['systemctl', 'show', '--property=Id,ActiveState', *units], timeout=5)
    result = {unit: 'unknown' for unit in units}
    for block in output.split('\n\n'):
        fields = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        name = fields.get('Id', '').removesuffix('.service')
        if name in result:
            result[name] = fields.get('ActiveState', 'unknown')
    return result


def update_ignore_list(action, values):
    network = ipaddress.ip_network(values.get('ip', ''), strict=False)
    if network.prefixlen == 0:
        raise ValueError('Нельзя исключить из защиты весь интернет.')
    token = str(network)
    current = checked_run(['fail2ban-client', 'get', 'sshd', 'ignoreip'])
    # Preserve the effective exclusions, including hostnames from other config files.
    tokens = []
    for line in current.splitlines():
        item = line.strip().lstrip('|`- ').strip()
        if not item or any(ch.isspace() for ch in item) or not re.fullmatch(r'[A-Za-z0-9_.:/-]+', item):
            continue
        try: item = str(ipaddress.ip_network(item, strict=False))
        except ValueError: pass
        if item not in tokens: tokens.append(item)
    if action.endswith('add'):
        if token not in tokens: tokens.append(token)
    else:
        if token not in tokens: raise ValueError('Исключение не найдено.')
        loopback = ipaddress.ip_network('127.0.0.0/8' if network.version == 4 else '::1/128')
        if network.overlaps(loopback):
            raise ValueError('Нельзя удалить исключение loopback.')
        tokens.remove(token)
    old = read_text(IGNORE_FILE)
    atomic_write(IGNORE_FILE, '[sshd]\nignoreip = ' + ' '.join(tokens) + '\n')
    try:
        checked_run(['fail2ban-client', '-t'])
        checked_run(['fail2ban-client', 'reload', 'sshd'])
    except Exception:
        if old: atomic_write(IGNORE_FILE, old)
        else: IGNORE_FILE.unlink(missing_ok=True)
        run(['fail2ban-client', 'reload', 'sshd'])
        raise
    audit_log(action, token)
    return 'Исключения SSH jail: ' + ', '.join(tokens) + '. Блокировки других jail не менялись.'


@cached_snapshot(30)
def security_snapshot():
    services = service_snapshot()
    checks = []
    def check(title, state, detail):
        checks.append(dict(title=title, state=state, detail=detail))
    rc, ufw = run(['ufw', 'status'], timeout=5)
    check('Сетевой экран', 'ok' if rc == 0 and 'Status: active' in ufw else 'warn', ufw.splitlines()[0] if ufw else 'UFW недоступен')
    rc, jail = run(['fail2ban-client', 'status', 'sshd'], timeout=5)
    banned = re.search(r'Currently banned:\s*(\d+)', jail)
    check('Защита SSH', 'ok' if rc == 0 else 'warn', ('SSH jail работает' + (' · заблокировано IP: ' + banned[1] if banned else '')) if rc == 0 else 'SSH jail недоступен')
    rc, ssh = run(['sshd', '-T'], timeout=5)
    ssh_cfg = dict(line.split(' ', 1) for line in ssh.splitlines() if ' ' in line) if rc == 0 else {}
    password = ssh_cfg.get('passwordauthentication', 'неизвестно')
    root = ssh_cfg.get('permitrootlogin', 'неизвестно')
    check('Вход по SSH', 'warn' if password != 'no' else 'ok', f'Пароль: {password}; root: {root}. Базовые настройки без учёта Match-блоков.')
    env = current_panel_env()
    local = env.get('PANEL_BIND', '127.0.0.1') in ('127.0.0.1', '::1', 'localhost')
    tls = env.get('PANEL_TLS') == '1'
    check('Доступ к панели', 'ok' if local or tls else 'warn', 'Локальный доступ' if local else ('Публичный HTTPS' if tls else 'Публичный HTTP: учётные данные без TLS'))
    protected = [TT_DIR / 'credentials.toml', TT_DIR / 'certs/key.pem', Path('/etc/trusttunnel-panel.env')]
    exposed = [str(p) for p in protected if p.exists() and p.stat().st_mode & 0o077]
    missing = [str(p) for p in protected if not p.exists()]
    check('Приватные файлы', 'warn' if exposed or missing else 'ok', ('Лишние права: ' + ', '.join(exposed)) if exposed else ('Файлы отсутствуют: ' + ', '.join(missing) if missing else 'Файлы учётных данных и ключа доступны только владельцу'))
    cert = TT_DIR / 'certs/cert.pem'
    rc, expiry = run(['openssl', 'x509', '-in', str(cert), '-noout', '-enddate', '-checkend', '1209600'], timeout=5)
    check('Сертификат VPN', 'ok' if rc == 0 else 'warn', expiry or 'Сертификат не прочитан')
    check('Перезагрузка ОС', 'warn' if Path('/var/run/reboot-required').exists() else 'ok', 'Требуется после обновлений' if Path('/var/run/reboot-required').exists() else 'ОС не сообщает о необходимости перезагрузки')
    return dict(checks=checks, services=services, checked_at=time.time())


@cached_snapshot(30)
def jail_settings():
    result = {}
    for field in ('maxretry', 'findtime', 'bantime'):
        rc, value = run(['fail2ban-client', 'get', 'sshd', field], timeout=5)
        result[field] = value if rc == 0 and re.fullmatch(r'\d+', value) else ''
    return result


def power_operation(action, values):
    if action == 'system-restart':
        checked_run(['systemctl', 'restart', 'trusttunnel'])
        checked_run(['systemctl', 'is-active', '--quiet', 'trusttunnel'])
        audit_log(action)
        return 'TrustTunnel перезапущен.'
    if action == 'system-reboot':
        if values.get('confirm') != 'REBOOT':
            raise ValueError('Для перезагрузки VPS введите REBOOT.')
        checked_run(['systemd-run', '--unit=trusttunnel-panel-reboot', '--on-active=60s', '/usr/bin/systemctl', 'reboot'])
        audit_log(action, 'Scheduled in 60 seconds')
        return 'Перезагрузка VPS запланирована через 60 секунд. Её можно отменить до срабатывания таймера.'
    if action == 'system-reboot-cancel':
        checked_run(['systemctl', 'stop', 'trusttunnel-panel-reboot.timer'])
        audit_log(action)
        return 'Таймер перезагрузки остановлен. Если перезагрузка уже началась, отменить её нельзя.'
    raise ValueError('Неизвестная операция сервера.')


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
    global CPU_SAMPLE
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
    cpu = 'Первое измерение'
    stat = read_text('/proc/stat').splitlines()
    if stat and stat[0].startswith('cpu '):
        ticks = [int(v) for v in stat[0].split()[1:9]]
        total_ticks, idle = sum(ticks), ticks[3] + ticks[4]
        if CPU_SAMPLE and total_ticks > CPU_SAMPLE[0]:
            percent = max(0, min(100, 100 * (1 - (idle - CPU_SAMPLE[1]) / (total_ticks - CPU_SAMPLE[0]))))
            cpu = f'{percent:.1f}%'
        CPU_SAMPLE = total_ticks, idle
    return {
        'cpu': cpu,
        'load': ' / '.join(f'{item:.2f}' for item in getattr(os, 'getloadavg', lambda: (0.0, 0.0, 0.0))()),
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


@cached_snapshot(60)
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
:root{color-scheme:light;--canvas:#f5f7f8;--surface:#fff;--ink:#20292f;--muted:#68757c;--line:#dfe6e9;--accent:#147d71;--accent-soft:#e5f4f0;--danger:#b9323e;--danger-soft:#fff0f1;--warn:#916620;--warn-bg:#fff8e8;--blue:#2586db;--nav-active:#e9f5f1;--nav-hover:#f2f6f6}
html[data-theme=dark]{color-scheme:dark;--canvas:#131818;--surface:#1c2222;--ink:#e7eeec;--muted:#a0afaa;--line:#35403d;--accent:#6acdb5;--accent-soft:#233d35;--nav-active:#243f36;--nav-hover:#283330;--danger:#ff9ca4;--danger-soft:#402a2e;--warn:#e2bd74;--warn-bg:#342e23}
*{box-sizing:border-box;letter-spacing:0}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,-apple-system,sans-serif}button,input,select,textarea{font:inherit}a{color:inherit}button,a,input,select,textarea,summary{-webkit-tap-highlight-color:transparent}button{cursor:pointer}button:disabled{opacity:.5;cursor:not-allowed}button:focus-visible,a:focus-visible,summary:focus-visible,input:focus,select:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:3px}.icon{width:19px;height:19px;flex:none;vertical-align:middle}button,.button{display:inline-flex;gap:8px;align-items:center;justify-content:center;min-height:40px;padding:9px 13px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--ink);text-decoration:none;font-weight:600;font-size:13px;line-height:1.35;transition:background .15s,border-color .15s;white-space:normal}button:hover,.button:hover{background:var(--nav-hover);border-color:var(--muted)}button.primary,.button.primary{background:var(--accent);color:var(--surface);border-color:var(--accent)}html[data-theme=dark] .primary{color:#122921}.danger{color:var(--danger);background:var(--danger-soft)}.icon-button,.theme-toggle{height:40px;width:40px;padding:0;flex:none}
.layout{display:grid;grid-template-columns:230px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100dvh;overflow:auto;background:var(--surface);border-right:1px solid var(--line);padding:26px 16px 16px;display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:10px;text-decoration:none;margin-bottom:28px;font-size:18px;font-weight:700}.brand-mark{height:34px;width:34px;background:var(--accent-soft);color:var(--accent);border-radius:8px;display:grid;place-items:center}.brand small{display:block;font-size:10px;color:var(--muted);font-weight:500;text-transform:uppercase;letter-spacing:1.3px}.nav-group{margin:0 0 24px}.nav-label{display:block;font-size:10px;font-weight:650;color:var(--muted);padding:0 12px 9px;text-transform:uppercase;letter-spacing:1px}.nav-item{display:flex;gap:11px;align-items:center;padding:10px 12px;min-height:42px;margin:3px 0;border-radius:6px;color:var(--muted);text-decoration:none;font-size:13px;font-weight:500}.nav-item:hover{background:var(--nav-hover);color:var(--ink)}.nav-item.active{color:var(--accent);background:var(--nav-active);font-weight:650}.sidebar-footer{border-top:1px solid var(--line);padding:18px 10px 0;margin-top:auto;font-size:11px;color:var(--muted)}.sidebar-footer strong{display:block;color:var(--ink);font-size:12px}.workspace{min-width:0}.topbar{height:70px;padding:0 34px;display:flex;align-items:center;justify-content:space-between;gap:16px;border-bottom:1px solid var(--line);background:var(--surface)}.endpoint-context{min-width:0;display:flex;gap:10px;align-items:center;color:var(--muted);font-size:12px}.endpoint-context strong{font-weight:600;color:var(--ink);white-space:nowrap;text-overflow:ellipsis;overflow:hidden}.endpoint-context .icon{width:15px}.header-actions{display:flex;gap:8px;flex:none}.content{max-width:1450px;margin:auto;padding:30px 34px 50px}.page-head{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:26px}.page-head h2{font-size:27px;font-weight:650;line-height:1.25;margin:0}.page-head p{color:var(--muted);margin:8px 0 0;font-size:13px}.eyebrow{display:block;font-size:10px;letter-spacing:1.2px;font-weight:650;color:var(--accent);margin-bottom:6px}.version-pill{font-size:11px;padding:3px 7px;border:1px solid var(--line);border-radius:4px;margin-left:8px;display:inline-block}.page-actions,.inline-actions,.monitor-controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.section-heading{display:flex;justify-content:space-between;align-items:center;gap:15px;margin-bottom:20px}.section-heading h3{margin:0}h3{font-size:15px;font-weight:650;margin:0 0 16px}.surface{padding:24px 0;border-top:1px solid var(--line);margin:0}.surface .surface{border:0;padding:16px 0}.muted,.hint{color:var(--muted);font-size:12px;overflow-wrap:anywhere}.muted{display:block}.text-link{color:var(--accent);font-size:12px;font-weight:600;text-decoration:none;display:inline-flex;gap:5px;align-items:center}.text-link .icon{width:15px}.metrics,.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-bottom:18px}.overview-metrics{grid-template-columns:repeat(4,minmax(0,1fr))}.metric{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:18px;min-width:0;box-shadow:0 2px 4px #162d2404}.metric small{color:var(--muted);font-size:12px;display:block}.metric strong{display:block;margin:14px 0 7px;font-size:20px;font-weight:650;line-height:1.3;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}.metric-caption{display:block;color:var(--muted);font-size:11px}.resource-bars{display:flex;gap:26px;margin:22px 0}.resource-bars label{flex:1;display:grid;grid-template-columns:auto 1fr;align-items:center;gap:12px;font-size:11px}meter{width:100%;height:7px;border:0}meter::-webkit-meter-bar{background:var(--line);border:0}meter::-webkit-meter-optimum-value{background:var(--accent)}#traffic-chart{width:100%;height:190px;display:block}.network-rate{font-variant-numeric:tabular-nums;font-size:17px;font-weight:600;display:block;margin-top:8px;min-height:26px}.chart-footer{display:flex;justify-content:space-between;gap:12px;align-items:center;margin:12px 0}.chart-legend{display:flex;gap:20px;flex-wrap:wrap;font-size:11px;color:var(--muted)}.rx:before,.tx:before{content:"";display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px;background:var(--blue)}.tx:before{background:#16937a}#interface-totals{margin-top:12px;font-size:11px}.overview-columns{display:grid;grid-template-columns:1fr 1fr;gap:36px}.service-row{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding:12px 0}.service-row:last-child{border:0}.badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;padding:4px 8px;border-radius:4px;background:var(--nav-hover);color:var(--muted);white-space:nowrap}.badge:before{content:"";width:5px;height:5px;border-radius:50%;background:currentColor}.badge.active{color:var(--accent);background:var(--accent-soft)}.badge.failed{color:var(--danger);background:var(--danger-soft)}dl{display:grid;grid-template-columns:1fr 1fr;gap:16px;font-size:13px;margin:0}dt{color:var(--muted)}dd{margin:0;text-align:right;overflow-wrap:anywhere}
form{display:inline-flex;align-items:end;gap:10px;flex-wrap:wrap;margin:4px 12px 12px 0;max-width:100%}.page-head form,.page-actions form,.section-heading form{margin:0}label{display:grid;gap:7px;font-size:12px;color:var(--muted);min-width:0}label.check{display:flex;align-items:center;gap:8px;padding:10px 0}input,select,textarea{min-height:40px;padding:9px 11px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--ink);min-width:0;max-width:100%;font-size:13px}input[type=checkbox]{min-height:0;width:17px;height:17px;accent-color:var(--accent)}textarea{width:100%;resize:vertical;min-height:90px;font-family:ui-monospace,Consolas,monospace;font-size:12px}.form-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;width:100%}.warning,.notice{padding:12px 14px;border-left:3px solid var(--warn);background:var(--warn-bg);color:var(--warn);margin:10px 0 20px;font-size:13px;overflow-wrap:anywhere}.notice{background:var(--accent-soft);color:var(--accent);border-color:var(--accent)}details{padding:18px 0}summary{cursor:pointer;font-weight:600;font-size:13px;color:var(--ink);padding:3px 0;margin-bottom:12px}.error-text{color:var(--danger);font-size:12px}
.table-toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0 0 18px}.search{width:min(330px,100%)}#client-count{margin-left:auto;color:var(--muted);font-size:12px}.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--surface)}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:15px 16px;text-align:left;border-bottom:1px solid var(--line);vertical-align:middle}th{background:var(--nav-hover);font-size:11px;color:var(--muted);font-weight:600;white-space:nowrap}tr:last-child td{border-bottom:0}td strong{font-weight:600}.table-actions{text-align:right}.table-actions button{font-size:12px}.protocol{display:inline-block;font-size:10px;border:1px solid var(--line);border-radius:4px;padding:3px 6px;color:var(--muted);margin:2px}.toggle{padding:3px;width:38px;height:22px;min-height:22px;border:0;border-radius:20px;background:#abb5b5;display:flex;justify-content:flex-start}.toggle span{width:16px;height:16px;background:white;border-radius:50%;box-shadow:0 1px 3px #0002}.toggle.active{background:#168e79;justify-content:flex-end}.toggle:hover{border:0}.pagination{display:flex;gap:12px;justify-content:flex-end;align-items:center;margin-top:18px;font-size:12px}.pagination button{padding:0;width:36px}.pagination select{width:65px}.security-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:20px}.security-check{display:flex;gap:12px;padding:18px;background:var(--surface);border:1px solid var(--line);border-radius:7px;min-width:0}.security-check h3{margin:0 0 7px;font-size:13px}.security-check p{color:var(--muted);font-size:12px;margin:0;overflow-wrap:anywhere}.check-dot{width:8px;height:8px;border-radius:50%;background:var(--accent);flex:none;margin-top:6px}.security-check.warn .check-dot{background:#d19c3c}
.drawer,.command-layer{display:none;position:fixed;inset:0;z-index:50;background:#10252166;backdrop-filter:blur(2px)}.drawer.open,.command-layer.open{display:block}.dialog-open{overflow:hidden}.drawer-card{width:min(550px,100vw);height:100dvh;margin-left:auto;padding:26px;background:var(--surface);overflow:auto;overscroll-behavior:contain;box-shadow:-15px 0 50px #0002}.drawer-head{display:flex;justify-content:space-between;align-items:center;gap:16px;border-bottom:1px solid var(--line);padding-bottom:20px}.drawer-head h2{font-size:21px;margin:0;overflow-wrap:anywhere}.drawer-head button{font-size:22px;width:40px;height:40px;padding:0;flex:none}.drawer-section{padding:22px 0;border-bottom:1px solid var(--line)}.drawer-card form{display:flex;width:100%;margin-right:0}.drawer-card label{flex:1;min-width:0}.drawer-card input{width:100%}.drawer-section>button{margin:10px 6px 0 0}.share-qr{display:block;width:180px;height:180px;margin-top:18px;background:white;padding:6px;border-radius:6px}.link-result{margin-top:14px}.command-layer{padding:14vh 18px 20px}.command-box{background:var(--surface);border:1px solid var(--line);border-radius:8px;width:min(550px,100%);margin:auto;overflow:hidden;box-shadow:0 20px 60px #0003}.command-box input{width:100%;border:0;border-bottom:1px solid var(--line);border-radius:0;min-height:55px}.command-list{padding:8px;max-height:60vh;overflow:auto}.command-item{display:block;padding:11px 14px;border-radius:5px;text-decoration:none}.command-item:hover{background:var(--nav-hover)}.command-item small{display:none}pre{margin:0;background:var(--nav-hover);color:var(--ink);padding:16px;border:1px solid var(--line);border-radius:6px;max-height:65vh;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;line-height:1.6}
#operation-result{background:var(--surface);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:24px;width:min(680px,calc(100vw - 24px));max-height:85dvh;box-shadow:0 20px 80px #0003}#operation-result::backdrop{background:#10252166}#operation-result h3{font-size:18px}#result-close{margin-top:18px}.busy-strip{display:none;position:fixed;bottom:24px;left:50%;transform:translateX(-50%);padding:14px 20px;background:var(--ink);color:var(--surface);border-radius:6px;z-index:80;box-shadow:0 5px 20px #0002;width:max-content;max-width:calc(100vw - 32px);font-size:13px}.busy .busy-strip{display:block}.busy-strip:before{content:"";display:inline-block;width:12px;height:12px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;margin-right:10px;vertical-align:-2px;animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}#mobile-menu,.mobile-nav,#nav-backdrop{display:none}[hidden]{display:none!important}
@media(min-width:1600px){.content{padding-top:38px}}
@media(max-width:1150px){.layout{grid-template-columns:210px minmax(0,1fr)}.content{padding:26px 24px 40px}.topbar{padding:0 24px}.overview-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.security-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.page-head{align-items:flex-start}.page-actions{justify-content:flex-end}.section-heading{flex-wrap:wrap}}
@media(max-width:800px){.layout{display:block}.sidebar{position:fixed;z-index:70;top:0;bottom:0;left:0;width:270px;max-width:85vw;transform:translateX(-100%);transition:transform .2s}.nav-open{overflow:hidden}.nav-open .sidebar{transform:translateX(0)}.nav-open #nav-backdrop{display:block;position:fixed;inset:0;background:#10252166;z-index:60}#mobile-menu{display:inline-flex}.topbar{height:62px;padding:0 16px;position:sticky;top:0;z-index:20}.endpoint-context>span{display:none}.endpoint-context{flex:1;gap:8px}.content{padding:24px 18px 110px}.mobile-nav{display:flex;position:fixed;bottom:0;inset-inline:0;z-index:25;padding:6px 12px calc(6px + env(safe-area-inset-bottom));background:var(--surface);border-top:1px solid var(--line);justify-content:space-around}.mobile-nav a,.mobile-nav button{display:flex;flex-direction:column;gap:2px;flex:1;font-size:10px;min-height:48px;text-decoration:none;color:var(--muted);align-items:center;justify-content:center;border:0;padding:4px;background:transparent}.mobile-nav .active{color:var(--accent)}.mobile-nav .icon{width:21px;height:21px}.overview-columns{gap:20px}.busy-strip{bottom:85px}.form-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:560px){.topbar{gap:10px;padding:0 12px}.topbar .header-actions{gap:4px}.endpoint-context .icon{display:none}.endpoint-context strong{font-size:12px}.content{padding:23px 14px 100px}.page-head{display:block;margin-bottom:22px}.page-head h2{font-size:25px}.page-head p{font-size:12px}.page-actions{justify-content:flex-start;margin-top:16px}.page-head>form{margin-top:16px}.version-pill{margin:5px 0 0}.overview-metrics{gap:10px}.metric{padding:14px 12px}.metric strong{font-size:17px;margin:10px 0 5px}.metric small,.metric-caption{font-size:10px}.resource-bars{gap:18px;margin:20px 0}.network-rate{font-size:16px}.monitor-controls{gap:6px;width:100%}.monitor-controls select{flex:1;width:100px;font-size:12px}.section-heading{gap:14px;margin-bottom:14px}.chart-footer{display:block}.chart-footer>span{margin-top:8px}.overview-columns{grid-template-columns:1fr;gap:0}.security-grid{grid-template-columns:1fr}.security-check{padding:15px}.form-grid{grid-template-columns:1fr}form{display:flex;width:100%;gap:10px;margin-right:0}form label{flex:1 1 140px}input,select,textarea{font-size:16px}button,.button{min-height:44px}.table-toolbar{gap:8px}.table-toolbar .search{width:100%}.table-toolbar select{flex:1}.table-toolbar #client-count{font-size:11px}.table-wrap:has([data-client-row]){background:transparent;border:0;border-radius:0;overflow:visible}.table-wrap:has([data-client-row]) table,.table-wrap:has([data-client-row]) tbody{display:block}.table-wrap:has([data-client-row]) thead{display:none}[data-client-row]{display:grid;grid-template-columns:44px minmax(0,1fr) auto;border:1px solid var(--line);border-radius:7px;background:var(--surface);padding:13px;gap:10px;margin:10px 0}[data-client-row] td{border:0!important;padding:0;min-width:0}[data-client-row] td:nth-child(1){grid-row:1;grid-column:1}[data-client-row] td:nth-child(1) form{margin:0}[data-client-row] td:nth-child(2){grid-column:2/4;overflow-wrap:anywhere}[data-client-row] td:nth-child(3){display:none}[data-client-row] td:nth-child(4){grid-column:1/3;align-self:center}[data-client-row] td:nth-child(5){grid-column:3;grid-row:2}.toggle{min-height:22px;margin:2px 0}.pagination{justify-content:space-between}.table-wrap:not(:has([data-client-row])) table{min-width:540px}.drawer-card{padding:20px 16px}.drawer-card form label{flex:1 1 100%}.drawer-head button{min-height:40px}.header-actions button{width:36px;padding:0}dl{gap:14px;font-size:12px}.page-head>button{margin-top:14px}}
@media(prefers-reduced-motion:reduce){*,*:before{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
'''

NAV_ITEMS = (
    ('dashboard', 'Обзор'), ('endpoint', 'Endpoint'), ('clients', 'Клиенты'),
    ('warp', 'WARP'), ('routing', 'Маршрутизация'), ('dns', 'DNS и AntiDPI'),
    ('certificates', 'Сертификаты'), ('security', 'Безопасность'),
    ('system', 'Система'), ('panel', 'Панель'),
    ('logs', 'Журналы'),
)



# Icon nodes from Lucide 1.8.0, bundled here to avoid a runtime dependency.
LUCIDE_LICENSE = r'''
ISC License

Copyright (c) 2026 Lucide Icons and Contributors

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

---

The following Lucide icons are derived from the Feather project:

airplay, alert-circle, alert-octagon, alert-triangle, aperture, arrow-down-circle, arrow-down-left, arrow-down-right, arrow-down, arrow-left-circle, arrow-left, arrow-right-circle, arrow-right, arrow-up-circle, arrow-up-left, arrow-up-right, arrow-up, at-sign, calendar, cast, check, chevron-down, chevron-left, chevron-right, chevron-up, chevrons-down, chevrons-left, chevrons-right, chevrons-up, circle, clipboard, clock, code, columns, command, compass, corner-down-left, corner-down-right, corner-left-down, corner-left-up, corner-right-down, corner-right-up, corner-up-left, corner-up-right, crosshair, database, divide-circle, divide-square, dollar-sign, download, external-link, feather, frown, hash, headphones, help-circle, info, italic, key, layout, life-buoy, link-2, link, loader, lock, log-in, log-out, maximize, meh, minimize, minimize-2, minus-circle, minus-square, minus, monitor, moon, more-horizontal, more-vertical, move, music, navigation-2, navigation, octagon, pause-circle, percent, plus-circle, plus-square, plus, power, radio, rss, search, server, share, shopping-bag, sidebar, smartphone, smile, square, table-2, tablet, target, terminal, trash-2, trash, triangle, tv, type, upload, x-circle, x-octagon, x-square, x, zoom-in, zoom-out

The MIT License (MIT) (for the icons listed above)

Copyright (c) 2013-present Cole Bemis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
ICONS = json.loads(r'''{"Activity":[["path",{"d":"M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"}]],"Server":[["rect",{"width":"20","height":"8","x":"2","y":"2","rx":"2","ry":"2"}],["rect",{"width":"20","height":"8","x":"2","y":"14","rx":"2","ry":"2"}],["line",{"x1":"6","x2":"6.01","y1":"6","y2":"6"}],["line",{"x1":"6","x2":"6.01","y1":"18","y2":"18"}]],"Users":[["path",{"d":"M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"}],["path",{"d":"M16 3.128a4 4 0 0 1 0 7.744"}],["path",{"d":"M22 21v-2a4 4 0 0 0-3-3.87"}],["circle",{"cx":"9","cy":"7","r":"4"}]],"Cloud":[["path",{"d":"M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"}]],"Route":[["circle",{"cx":"6","cy":"19","r":"3"}],["path",{"d":"M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"}],["circle",{"cx":"18","cy":"5","r":"3"}]],"Globe":[["circle",{"cx":"12","cy":"12","r":"10"}],["path",{"d":"M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"}],["path",{"d":"M2 12h20"}]],"ShieldCheck":[["path",{"d":"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"}],["path",{"d":"m9 12 2 2 4-4"}]],"KeyRound":[["path",{"d":"M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"}],["circle",{"cx":"16.5","cy":"7.5","r":".5","fill":"currentColor"}]],"Settings":[["path",{"d":"M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915"}],["circle",{"cx":"12","cy":"12","r":"3"}]],"Logs":[["path",{"d":"M3 5h1"}],["path",{"d":"M3 12h1"}],["path",{"d":"M3 19h1"}],["path",{"d":"M8 5h1"}],["path",{"d":"M8 12h1"}],["path",{"d":"M8 19h1"}],["path",{"d":"M13 5h8"}],["path",{"d":"M13 12h8"}],["path",{"d":"M13 19h8"}]],"SlidersHorizontal":[["path",{"d":"M10 5H3"}],["path",{"d":"M12 19H3"}],["path",{"d":"M14 3v4"}],["path",{"d":"M16 17v4"}],["path",{"d":"M21 12h-9"}],["path",{"d":"M21 19h-5"}],["path",{"d":"M21 5h-7"}],["path",{"d":"M8 10v4"}],["path",{"d":"M8 12H3"}]],"Menu":[["path",{"d":"M4 5h16"}],["path",{"d":"M4 12h16"}],["path",{"d":"M4 19h16"}]],"X":[["path",{"d":"M18 6 6 18"}],["path",{"d":"m6 6 12 12"}]],"SunMoon":[["path",{"d":"M12 2v2"}],["path",{"d":"M14.837 16.385a6 6 0 1 1-7.223-7.222c.624-.147.97.66.715 1.248a4 4 0 0 0 5.26 5.259c.589-.255 1.396.09 1.248.715"}],["path",{"d":"M16 12a4 4 0 0 0-4-4"}],["path",{"d":"m19 5-1.256 1.256"}],["path",{"d":"M20 12h2"}]],"Search":[["path",{"d":"m21 21-4.34-4.34"}],["circle",{"cx":"11","cy":"11","r":"8"}]],"RotateCw":[["path",{"d":"M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"}],["path",{"d":"M21 3v5h-5"}]],"Power":[["path",{"d":"M12 2v10"}],["path",{"d":"M18.4 6.6a9 9 0 1 1-12.77.04"}]],"ArrowUpRight":[["path",{"d":"M7 7h10v10"}],["path",{"d":"M7 17 17 7"}]],"ChevronRight":[["path",{"d":"m9 18 6-6-6-6"}]],"Copy":[["rect",{"width":"14","height":"14","x":"8","y":"8","rx":"2","ry":"2"}],["path",{"d":"M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"}]],"Eye":[["path",{"d":"M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"}],["circle",{"cx":"12","cy":"12","r":"3"}]],"Plus":[["path",{"d":"M5 12h14"}],["path",{"d":"M12 5v14"}]],"RefreshCw":[["path",{"d":"M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"}],["path",{"d":"M21 3v5h-5"}],["path",{"d":"M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"}],["path",{"d":"M8 16H3v5"}]]}''')


def icon(name):
    parts = []
    for tag, attrs in ICONS.get(name, []):
        attributes = ' '.join(f'{k}="{html.escape(str(v), quote=True)}"' for k, v in attrs.items())
        parts.append(f'<{tag} {attributes}></{tag}>')
    return '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + ''.join(parts) + '</svg>'


def nav_html(view):
    groups = (
        ('Основное', ('dashboard', 'clients', 'endpoint')),
        ('Сеть', ('warp', 'routing', 'dns')),
        ('Администрирование', ('security', 'certificates', 'system', 'logs', 'panel')),
    )
    icons = dict(zip(('dashboard', 'endpoint', 'clients', 'warp', 'routing', 'dns', 'certificates', 'security', 'system', 'panel', 'logs'),
                     ('Activity', 'Server', 'Users', 'Cloud', 'Route', 'Globe', 'KeyRound', 'ShieldCheck', 'Settings', 'SlidersHorizontal', 'Logs')))
    labels = dict(NAV_ITEMS)
    parts = []
    for group, keys in groups:
        items = []
        for key in keys:
            cls = ' active' if key == view else ''
            current = ' aria-current="page"' if key == view else ''
            items.append(f'<a class="nav-item{cls}" href="/?view={key}"{current}>{icon(icons[key])}<span>{labels[key]}</span></a>')
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
    content = system_details_view()
    boundary = content.index('<section')
    return content[:boundary] + power_controls() + content[boundary:]


def power_controls():
    restart = admin_form('system-restart', '<button>' + icon('RotateCw') + 'Перезапустить TrustTunnel</button>', view='system', confirm='Перезапустить VPN? Текущие подключения кратковременно прервутся.')
    reboot = admin_form('system-reboot', '<label>Подтверждение<input name="confirm" required pattern="REBOOT" placeholder="REBOOT" autocomplete="off"></label><button class="danger">' + icon('Power') + 'Перезагрузить VPS</button>', view='system')
    cancel = admin_form('system-reboot-cancel', '<button>Отменить перезагрузку</button>', view='system')
    return f'<section class="surface"><h3>Питание и сервисы</h3>{restart}<p class="muted">Перезагрузка VPS отключит VPN, панель и SSH. Задержка перед перезагрузкой: 60 секунд.</p>{reboot}{cancel}</section>'


def system_details_view():
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
        link = ''
        share = (f'<button type="button" data-load-link="{html.escape(name, quote=True)}" data-link-index="{index}">{icon("KeyRound")}Ссылка и QR-код</button><div id="link-result-{index}" class="link-result" aria-live="polite"></div>' if enabled else '<p class="muted">Доступ отключён. Включите клиента, чтобы получить ссылку.</p>')
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
    cards = ''.join(f'<div class="metric"><small>{label}</small><strong id="stat-{key}">{html.escape(stats[key])}</strong><span class="metric-caption">{caption}</span></div>' for key, label, caption in [('cpu', 'Процессор', 'Загрузка всех ядер'), ('memory', 'Память', 'Использовано / всего'), ('disk', 'Хранилище', 'Корневой раздел'), ('uptime', 'Время работы', 'С последнего запуска')])
    names = {'trusttunnel': 'TrustTunnel', 'warp-wireproxy': 'WARP', 'fail2ban': 'Fail2ban', 'trusttunnel-panel': 'Панель'}
    services = ''.join(f'<div class="service-row"><span>{html.escape(names.get(name, name))}</span><span id="service-{name}" class="badge {html.escape(status)}">{html.escape(status)}</span></div>' for name, status in stats['services'].items())
    restart = admin_form('system-restart', '<button>' + icon('RotateCw') + 'Перезапустить VPN</button>', view='dashboard', confirm='Перезапустить TrustTunnel? VPN кратковременно отключится.')
    return f'''<div class="page-head"><div><span class="eyebrow">СЕРВЕР</span><h2>Обзор</h2><p>{html.escape(domain())}:{endpoint_port()} <span class="version-pill">Endpoint {html.escape(endpoint_version())}</span></p></div><div class="page-actions"><a class="button" href="/?view=clients">{icon('Users')}Клиенты</a>{restart}</div></div>
<div class="metrics overview-metrics">{cards}</div><div class="resource-bars"><label>Память <meter id="ram-meter" min="0" max="100" value="{stats['memory_percent']}"></meter></label><label>Диск <meter id="disk-meter" min="0" max="100" value="{stats['disk_percent']}"></meter></label></div>
<section class="surface traffic-surface"><div class="section-heading"><div><h3>Трафик сервера</h3><span id="network-rate" class="network-rate">Ожидание измерения</span></div><div class="monitor-controls"><label class="sr-only" for="interface-select">Сетевой интерфейс</label><select id="interface-select"></select><label class="sr-only" for="refresh-interval">Частота обновления</label><select id="refresh-interval"><option value="10">Каждые 10 с</option><option value="30">Каждые 30 с</option><option value="0">Пауза</option></select><button type="button" id="monitor-refresh" class="icon-button" title="Обновить" aria-label="Обновить">{icon('RefreshCw')}</button></div></div>
<canvas id="traffic-chart" height="190" aria-label="График скорости выбранного сетевого интерфейса"></canvas><div class="chart-footer"><div class="chart-legend"><span class="rx">Приём</span><span class="tx">Отправка</span><span id="chart-scale"></span></div><span id="monitor-status" class="muted" role="status">Подключено</span></div><div id="interface-totals" class="muted"></div></section>
<div class="overview-columns"><section class="surface"><div class="section-heading"><h3>Сервисы</h3><a class="text-link" href="/?view=logs">Журналы {icon('ArrowUpRight')}</a></div>{services}</section><section class="surface"><div class="section-heading"><h3>Подключение</h3><a class="text-link" href="/?view=endpoint">Настройки {icon('ArrowUpRight')}</a></div><dl><dt>Исходящий маршрут</dt><dd id="stat-route">{html.escape(stats['route'])}</dd><dt>Транспорты</dt><dd>HTTP/2 {"· QUIC" if quic_enabled() else ""}</dd><dt>Сертификат</dt><dd>{cert_mode()}</dd><dt>Панель</dt><dd>{ADMIN_VERSION}</dd></dl></section></div>'''


def logs_console():
    controls = admin_form('logs', '<label>Сервис<select name="unit"><option>trusttunnel</option><option>warp-wireproxy</option><option>trusttunnel-panel</option><option>fail2ban</option></select></label><label>Строк<input name="lines" type="number" min="20" max="500" value="100"></label><button class="primary">Показать журнал</button>', view='logs')
    audit = admin_form('audit', '<button>Журнал действий администратора</button>', view='logs')
    return f'<div class="page-head"><h2>Журналы</h2></div><section class="surface">{controls}{audit}</section>'


def security_console():
    checks = security_snapshot()['checks']
    tiles = ''.join(f'<article class="security-check {c["state"]}"><span class="check-dot"></span><div><h3>{html.escape(c["title"])}</h3><p>{html.escape(c["detail"])}</p></div></article>' for c in checks)
    status = admin_form('security-status', '<button>' + icon('ShieldCheck') + '<span>Полный отчёт</span></button>', view='security')
    settings = jail_settings()
    jail = admin_form('security-fail2ban', f'''<label>Попыток<input name="retry" type="number" min="1" max="100" value="{settings['maxretry']}" required></label><label>Окно, секунд<input name="findtime" type="number" min="60" max="86400" value="{settings['findtime']}" required></label><label>Бан, секунд<input name="bantime" type="number" min="60" max="604800" value="{settings['bantime']}" required></label><button>Применить</button>''', view='security', confirm='Применить указанные параметры SSH jail?')
    bans = admin_form('security-ban', '<label>IP-адрес<input name="ip" placeholder="203.0.113.10" required></label><button class="danger">Заблокировать</button>', view='security', confirm='Заблокировать IP для доступа по SSH?') + admin_form('security-unban', '<label>IP-адрес<input name="ip" required></label><button>Разблокировать</button>', view='security')
    trusted = admin_form('security-ignore-list', '<button>Текущие исключения</button>', view='security')
    trusted += ''.join(admin_form('security-ignore-' + action, '<label>IP или подсеть<input name="ip" placeholder="203.0.113.10/32" required></label><button>' + title + '</button>', view='security', confirm='Изменить постоянные исключения SSH jail?') for action, title in [('add', 'Добавить исключение'), ('remove', 'Удалить исключение')])
    ports = ''.join(admin_form('security-' + action, '<label>Порт<input type="number" name="port" min="1" max="65535" required></label><label>Протокол<select name="proto"><option>tcp</option><option>udp</option></select></label><label>Источник IP / CIDR<input name="source" placeholder="Пусто: любой IP"></label><button>' + title + '</button>', view='security', confirm='Изменить указанное правило UFW?') for action, title in [('open', 'Разрешить'), ('close', 'Удалить разрешение')])
    inspect = admin_form('security-listeners', '<button>' + icon('Globe') + 'Открытые сокеты</button>', view='security') + admin_form('security-logins', '<button>' + icon('Logs') + 'Журнал SSH</button>', view='security')
    return f'''<div class="page-head"><div><span class="eyebrow">ЗАЩИТА И ДОСТУП</span><h2>Безопасность</h2><p>Текущее состояние сервера и контроль входящих подключений.</p></div>{status}</div><div class="security-grid">{tiles}</div><div class="inline-actions">{inspect}</div>
<section class="surface"><h3>Блокировки SSH</h3>{bans}<details><summary>Параметры fail2ban</summary><p class="muted">Значения ниже будут применены после подтверждения. Текущие настройки доступны в полном отчёте.</p>{jail}</details></section>
<section class="surface"><h3>Доверенные IP для SSH</h3><p class="muted">Исключения из блокировок fail2ban для SSH. Правила сетевого экрана остаются отдельными.</p>{trusted}</section>
<section class="surface"><h3>Сетевой экран</h3><p class="muted">Источник ограничивает одно правило. Уже существующее разрешение для всех IP продолжит действовать. Порты SSH, VPN и панели защищены от удаления.</p>{ports}</section>'''


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



CONSOLE_SCRIPT = r'''
(() => {
  const $ = id => document.getElementById(id);
  const store = {get(k, fallback) {try{return localStorage.getItem(k)||fallback;}catch(_){return fallback;}},set(k,v){try{localStorage.setItem(k,v);}catch(_){}}};
  $('theme-toggle').onclick=()=>{const t=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=t;store.set('tt-theme',t);};
  const nav=$('mobile-nav'), menu=$('mobile-menu');
  function closeNav(){document.body.classList.remove('nav-open');menu.setAttribute('aria-expanded','false');}
  function openNav(){document.body.classList.add('nav-open');menu.setAttribute('aria-expanded','true');document.querySelector('.sidebar .nav-item.active')?.focus();}
  menu.onclick=()=>document.body.classList.contains('nav-open')?closeNav():openNav();
  $('nav-backdrop').onclick=closeNav;
  document.querySelectorAll('[data-nav-open]').forEach(b=>b.onclick=openNav);
  let returnFocus=null;
  function closeDrawers(){document.querySelectorAll('.drawer.open').forEach(d=>d.classList.remove('open'));document.body.classList.remove('dialog-open');returnFocus?.focus();}
  function openDrawer(id,button){closeDrawers();const d=$(id);if(!d)return;returnFocus=button;d.classList.add('open');document.body.classList.add('dialog-open');d.querySelector('button,input:not([type=hidden])')?.focus();}
  document.querySelectorAll('[data-drawer]').forEach(b=>b.onclick=()=>openDrawer(b.dataset.drawer,b));
  document.querySelectorAll('[data-drawer-close]').forEach(b=>b.onclick=closeDrawers);
  document.querySelectorAll('.drawer').forEach(d=>d.onclick=e=>{if(e.target===d)closeDrawers();});
  const command=$('command-layer');
  const closeCommand=()=>{command.classList.remove('open');document.body.classList.remove('dialog-open');};
  const openCommand=()=>{command.classList.add('open');document.body.classList.add('dialog-open');$('command-search').focus();};
  document.querySelectorAll('[data-command-open]').forEach(b=>b.onclick=openCommand);
  command.onclick=e=>{if(e.target===command)closeCommand();};
  $('command-search').oninput=e=>document.querySelectorAll('.command-item').forEach(x=>x.hidden=!x.textContent.toLowerCase().includes(e.target.value.toLowerCase()));
  document.addEventListener('keydown',e=>{
    if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();openCommand();}
    if(e.key==='Escape'){closeNav();closeCommand();closeDrawers();}
    if(e.key!=='Tab')return;
    const scope=document.querySelector('.drawer.open,.command-layer.open')||(document.body.classList.contains('nav-open')?document.querySelector('.sidebar'):null);
    if(!scope)return;
    const items=[...scope.querySelectorAll('button:not(:disabled),input:not([type=hidden]),textarea,a[href],select')].filter(x=>x.getClientRects().length);
    const first=items[0],last=items.at(-1);if(!first)return;
    if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}
    else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
  });
  document.addEventListener('click',async e=>{
    const b=e.target.closest('[data-copy],[data-reveal]');if(!b)return;
    const input=$(b.dataset.copy||b.dataset.reveal);if(!input)return;
    if(b.dataset.reveal){input.type=input.type==='password'?'text':'password';return;}
    try{await navigator.clipboard.writeText(input.value);const old=b.innerHTML;b.textContent='Скопировано';setTimeout(()=>b.innerHTML=old,1500);}
    catch(_){input.focus();input.select();showResult('Копирование','Автоматическое копирование недоступно. Текст выделен.',false);}
  });
  document.querySelectorAll('[data-load-link]').forEach(b=>b.onclick=async()=>{
    b.disabled=true;const target=$('link-result-'+b.dataset.linkIndex);target.textContent='Подготовка ссылки…';
    try{
      const r=await fetch('/api/client-link?username='+encodeURIComponent(b.dataset.loadLink),{cache:'no-store'});
      if(!r.ok)throw Error('Не удалось получить ссылку ('+r.status+')');
      const data=await r.json();if(!data.link)throw Error('Endpoint не вернул ссылку.');
      const label=document.createElement('label');label.textContent='Ссылка подключения';
      const text=document.createElement('textarea');text.readOnly=true;text.value=data.link;text.id='lazy-link-'+b.dataset.linkIndex;label.append(text);
      const copy=document.createElement('button');copy.type='button';copy.dataset.copy=text.id;copy.textContent='Копировать ссылку';
      const img=document.createElement('img');img.className='share-qr';img.alt='QR подключения';img.src='/qr-link/'+encodeURIComponent(b.dataset.loadLink)+'.png';img.onerror=()=>{img.remove();};
      target.replaceChildren(label,copy,img);b.hidden=true;
    }catch(e){target.textContent=e.message;}finally{b.disabled=false;}
  });
  const result=$('operation-result');let shouldRefresh=false;
  function showResult(title,output,refresh=false){$('result-title').textContent=title;$('result-output').textContent=output;shouldRefresh=refresh;if(!result.open)result.showModal();}
  result.addEventListener('close',()=>{if(shouldRefresh)location.reload();});
  $('result-close').onclick=()=>result.close();
  document.querySelectorAll('form').forEach(f=>f.addEventListener('submit',async e=>{
    if(f.dataset.confirm&&!confirm(f.dataset.confirm)){e.preventDefault();return;}
    const shared=new URL(f.getAttribute('action'),location.href).pathname==='/manage';
    if(!shared){document.body.classList.add('busy');$('busy-message').textContent='Операция выполняется. Дождитесь результата.';return;}
    e.preventDefault();const data=new URLSearchParams(new FormData(f));
    if(e.submitter?.name)data.set(e.submitter.name,e.submitter.value);
    const buttons=[...f.querySelectorAll('button')];buttons.forEach(b=>b.disabled=true);f.setAttribute('aria-busy','true');
    document.body.classList.add('busy');$('busy-message').textContent='Операция выполняется…';
    try{
      const response=await fetch('/manage',{method:'POST',headers:{'Accept':'application/json','Content-Type':'application/x-www-form-urlencoded'},body:data});
      if(!response.ok&&response.headers.get('Content-Type')?.includes('text/html'))throw Error(response.status===403?'Сессия обновлена. Перезагрузите страницу.':'Ошибка HTTP '+response.status);
      const answer=await response.json();showResult(answer.ok?'Готово':'Операция не выполнена',answer.output,answer.ok&&answer.refresh);
    }catch(error){showResult('Не удалось получить результат',error.message+' Если связь прервалась после запуска, проверьте состояние перед повтором.');}
    finally{document.body.classList.remove('busy');buttons.forEach(b=>b.disabled=false);f.removeAttribute('aria-busy');}
  }));
  window.addEventListener('pageshow',()=>document.body.classList.remove('busy'));
  const rows=[...document.querySelectorAll('[data-client-row]')];let page=0;
  const search=$('client-search'),state=$('client-state'),size=$('page-size');
  function filter(){
    if(!state)return;
    const matches=rows.filter(r=>r.dataset.client.includes(search.value.toLowerCase())&&(state.value==='all'||r.dataset.state===state.value));
    const pages=Math.max(1,Math.ceil(matches.length/+size.value));page=Math.min(page,pages-1);
    rows.forEach(r=>r.hidden=true);matches.slice(page*+size.value,(page+1)*+size.value).forEach(r=>r.hidden=false);
    $('page-label').textContent=`${page+1} / ${pages}`;$('client-count').textContent=`Найдено: ${matches.length}`;$('page-prev').disabled=page===0;$('page-next').disabled=page===pages-1;
  }
  if(state){[search,state,size].forEach(x=>x.addEventListener('input',()=>{page=0;filter();}));$('page-prev').onclick=()=>{page--;filter();};$('page-next').onclick=()=>{page++;filter();};filter();}
  const canvas=$('traffic-chart');if(!canvas)return;
  const interval=$('refresh-interval'),interfaces=$('interface-select'),status=$('monitor-status');
  interval.value=['0','10','30'].includes(store.get('tt-refresh','10'))?store.get('tt-refresh','10'):'10';
  let previous=null,history=[],timer=null,running=false,failures=0;
  const bytes=v=>{let n=0;while(v>=1024&&n<4){v/=1024;n++;}return v.toFixed(1)+' '+['Б','КиБ','МиБ','ГиБ','ТиБ'][n];};
  function draw(){
    const w=canvas.clientWidth,h=190,ratio=Math.min(devicePixelRatio||1,2);canvas.width=w*ratio;canvas.height=h*ratio;
    const c=canvas.getContext('2d');c.scale(ratio,ratio);c.clearRect(0,0,w,h);c.strokeStyle=getComputedStyle(document.body).getPropertyValue('--line');c.setLineDash([3,5]);
    for(let y=12;y<h;y+=42){c.beginPath();c.moveTo(0,y);c.lineTo(w,y);c.stroke();}c.setLineDash([]);
    const max=Math.max(1024,...history.flat());$('chart-scale').textContent='Шкала: '+bytes(max)+'/с';
    ['#2586db','#16937a'].forEach((color,k)=>{c.strokeStyle=color;c.lineWidth=2;c.beginPath();history.forEach((v,i)=>{const x=i/59*w,y=h-12-v[k]/max*(h-28);i?c.lineTo(x,y):c.moveTo(x,y);});c.stroke();});
  }
  function schedule(){clearTimeout(timer);if(!document.hidden&&+interval.value)timer=setTimeout(poll,Math.min(60000,+interval.value*1000*2**Math.min(failures,3)));}
  async function poll(){
    if(running||document.hidden)return;running=true;clearTimeout(timer);
    try{
      const response=await fetch('/api/monitor',{cache:'no-store',signal:AbortSignal.timeout(12000)});if(!response.ok)throw Error(response.status);
      const data=await response.json();failures=0;
      for(const key of ['cpu','memory','disk','uptime','route']){if($('stat-'+key))$('stat-'+key).textContent=data[key];}
      $('ram-meter').value=data.memory_percent;$('disk-meter').value=data.disk_percent;
      for(const [name,value] of Object.entries(data.services)){const cell=$('service-'+name);if(cell){cell.textContent=({active:'Работает',inactive:'Остановлен',failed:'Ошибка',activating:'Запуск'})[value]||value;cell.className='badge '+value;}}
      const keys=Object.keys(data.interfaces);const selected=interfaces.value||store.get('tt-interface','');
      if([...interfaces.options].map(o=>o.value).join()!==keys.join()){
        interfaces.replaceChildren(...keys.map(key=>new Option(key,key)));interfaces.value=keys.includes(selected)?selected:(keys.find(k=>/^(en|eth)/.test(k))||keys[0]||'');
      }
      const name=interfaces.value,v=data.interfaces[name],old=previous?.interfaces[name],dt=previous?data.time-previous.time:0;
      if(v&&old&&dt>0){const rx=Math.max(0,v.rx-old.rx)/dt,tx=Math.max(0,v.tx-old.tx)/dt;history.push([rx,tx]);history=history.slice(-60);$('network-rate').textContent='↓ '+bytes(rx)+'/с   ↑ '+bytes(tx)+'/с';}
      $('interface-totals').textContent=v?'С запуска интерфейса: принято '+bytes(v.rx)+' · отправлено '+bytes(v.tx):'Нет сетевых интерфейсов';
      status.textContent='Обновлено '+new Date(data.time*1000).toLocaleTimeString();status.className='muted';previous=data;draw();
    }catch(e){failures++;status.textContent='Связь недоступна · повтор автоматически';status.className='error-text';}
    finally{running=false;schedule();}
  }
  interval.onchange=()=>{store.set('tt-refresh',interval.value);schedule();if(interval.value==='0')status.textContent='Обновление на паузе';};
  interfaces.onchange=()=>{store.set('tt-interface',interfaces.value);previous=null;history=[];draw();poll();};
  $('monitor-refresh').onclick=poll;
  document.addEventListener('visibilitychange',()=>{clearTimeout(timer);if(document.hidden){previous=null;}else if(+interval.value){poll();}});
  window.addEventListener('resize',draw);
  poll();
})();
'''


ASSET_VERSION = hashlib.sha256((PANEL_STYLE + CONSOLE_SCRIPT).encode()).hexdigest()[:12]


def page_shell(message='', log='', view='dashboard'):
    views = {'dashboard': overview_console, 'endpoint': endpoint_view, 'clients': clients_console, 'warp': warp_view, 'routing': routing_console, 'dns': dns_console, 'certificates': certificates_view, 'security': security_console, 'system': system_view, 'panel': panel_view, 'logs': logs_console}
    view = view if view in views else 'dashboard'
    content = views[view]()
    notice = f'<div class="notice" role="status">{html.escape(message)}</div>' if message else ''
    output = f'<section class="surface"><pre>{html.escape(log)}</pre></section>' if log else ''
    labels = dict(NAV_ITEMS)
    commands = ''.join(f'<a class="command-item" href="/?view={key}">{label}</a>' for key, label in NAV_ITEMS)
    bottom = ''.join(f'<a href="/?view={key}" class="{"active" if key == view else ""}">{icon(symbol)}{labels[key]}</a>' for key, symbol in [('dashboard', 'Activity'), ('clients', 'Users'), ('security', 'ShieldCheck')])
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>{html.escape(labels[view])} · TrustTunnel</title><script>try{{document.documentElement.dataset.theme=localStorage.getItem('tt-theme')||'light'}}catch(_){{}}</script><link rel="stylesheet" href="/assets/{ASSET_VERSION}.css"><script defer src="/assets/{ASSET_VERSION}.js"></script></head><body data-view="{view}">
<div class="layout"><aside class="sidebar" aria-label="Главная навигация"><a class="brand" href="/">{icon('ShieldCheck')}<span>TrustTunnel<small>Server console</small></span></a><nav>{nav_html(view)}</nav><div class="sidebar-footer"><strong>TrustTunnel Panel</strong>Версия {ADMIN_VERSION}</div></aside><div id="nav-backdrop"></div><div class="workspace"><header class="topbar"><button id="mobile-menu" class="icon-button" aria-label="Открыть меню" aria-expanded="false">{icon('Menu')}</button><div class="endpoint-context"><span>{html.escape(labels[view])}</span>{icon('ChevronRight')}<strong>{html.escape(domain())}:{endpoint_port()}</strong></div><div class="header-actions"><button type="button" class="icon-button" data-command-open title="Поиск разделов" aria-label="Поиск разделов">{icon('Search')}</button><button id="theme-toggle" class="icon-button" title="Светлая / тёмная тема" aria-label="Сменить тему">{icon('SunMoon')}</button></div></header><main class="content">{notice}{content}{output}</main></div></div>
<nav class="mobile-nav" id="mobile-nav" aria-label="Быстрая навигация">{bottom}<button data-nav-open>{icon('Menu')}Ещё</button></nav><div class="command-layer" id="command-layer" role="dialog" aria-modal="true" aria-label="Поиск раздела"><div class="command-box"><input id="command-search" aria-label="Поиск раздела" placeholder="Найти раздел…" autocomplete="off"><div class="command-list">{commands}</div></div></div>
<dialog id="operation-result" aria-labelledby="result-title"><h3 id="result-title"></h3><pre id="result-output"></pre><button class="primary" id="result-close">Закрыть</button></dialog><div class="busy-strip" role="status"><span id="busy-message"></span></div></body></html>'''


def html_page(message='', log='', view='dashboard'):
    page = page_shell(message, log, view)
    page = re.sub(r'(<form\b[^>]*>)', lambda m: m[1] + f'<input type="hidden" name="_csrf" value="{CSRF_TOKEN}">', page)
    selected = html.escape(client_tls_profile(), quote=True)
    page = page.replace(f'<option value="{selected}">{selected}</option>', f'<option value="{selected}" selected>{selected}</option>')
    return page


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def end_headers(self):
        self.send_header('Cache-Control', 'private, max-age=86400, immutable' if getattr(self, '_asset_response', False) else 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'same-origin')
        super().end_headers()

    def authenticated(self):
        if not PANEL_PASSWORD:
            self.send_error(503, 'Panel password is not configured')
            return False
        auth = self.headers.get('Authorization', '')
        peer = self.client_address[0]
        delay = login_delay(peer)
        if delay:
            self.send_response(429)
            self.send_header('Retry-After', str(delay))
            self.end_headers()
            return False
        expected = 'Basic ' + base64.b64encode(f'{PANEL_USER}:{PANEL_PASSWORD}'.encode()).decode()
        if secrets.compare_digest(auth.encode('utf-8'), expected.encode('utf-8')):
            login_delay(peer, success=True)
            return True
        if auth:
            login_delay(peer, failed=True)
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="TrustTunnel Panel"')
        self.end_headers()
        return False

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
        if parsed.path in (f'/assets/{ASSET_VERSION}.css', f'/assets/{ASSET_VERSION}.js'):
            self._asset_response = True
            is_css = parsed.path.endswith('.css')
            content = PANEL_STYLE if is_css else CONSOLE_SCRIPT
            etag = '"' + ASSET_VERSION + ('-css' if is_css else '-js') + '"'
            if self.headers.get('If-None-Match') == etag:
                self.send_response(304)
                self.send_header('ETag', etag)
                self.end_headers()
                return
            body = content.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/css; charset=utf-8' if is_css else 'text/javascript; charset=utf-8')
            self.send_header('ETag', etag)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == '/api/client-link':
            username = urllib.parse.parse_qs(parsed.query).get('username', [''])[0]
            if not client_name_valid(username) or username not in {c['username'] for c in load_clients()}:
                self.send_json({'error': 'Клиент не найден'}, 404)
                return
            self.send_json({'link': deeplink(username)})
            return
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
            wants_json = 'application/json' in self.headers.get('Accept', '')
            read_only = {'monitor', 'logs', 'audit', 'security-audit', 'security-status', 'security-listeners', 'security-logins', 'security-ignore-list', 'dns-check', 'routing-check', 'client-list', 'client-link'}
            try:
                f['_peer'] = self.client_address[0]
                result = admin_operation(f.get('action', ''), f)
                refresh = f.get('action') not in read_only
                if refresh:
                    with CACHE_LOCK: SNAPSHOT_CACHE.clear()
                if wants_json:
                    self.send_json({'ok': True, 'output': result, 'refresh': refresh})
                else:
                    self.send_html('Операция выполнена.', result, f.get('view', 'clients'))
            except (ValueError, RuntimeError, OSError) as exc:
                if wants_json:
                    self.send_json({'ok': False, 'output': str(exc), 'refresh': False}, 400)
                else:
                    self.send_html('Операция не выполнена.', str(exc), f.get('view', 'clients'))
            return
        if self.path == '/action':
            action = f.get('action', '')
            if action in ('restart', 'reboot'):
                try:
                    result = admin_operation('system-' + action, f)
                    with CACHE_LOCK: SNAPSHOT_CACHE.clear()
                    self.send_html('Операция выполнена.', result, 'system')
                except (ValueError, RuntimeError, OSError) as exc:
                    self.send_html('Операция не выполнена.', str(exc), 'system')
                return
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


class PanelServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def main():
    bind = os.environ.get('PANEL_BIND', '127.0.0.1')
    port = int(os.environ.get('PANEL_PORT', '8088'))
    server = PanelServer((bind, port), Handler)
    if PANEL_TLS:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(PANEL_CERT, PANEL_KEY)
        # Complete TLS in a bounded worker, under the connection timeout.
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
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

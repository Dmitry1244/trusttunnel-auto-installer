#!/usr/bin/env python3
import base64
import html
import http.server
import http.cookies
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
import struct
import urllib.request
import platform
import sqlite3
import datetime
try:
    import tomllib
except ImportError:
    import tomli as tomllib
import ipaddress
import socket
import configparser
import io
import shlex
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
ADMIN_VERSION = '2026.11.12'
MASQUE_ADDR = '127.0.0.1:40002'
MASQUE_DIR = Path('/opt/warp-masque')
MASQUE_VERSION = 'v4.2.1'
INTERFACE_DIR = Path('/opt/warp-interface')
INTERFACE_DROPIN = Path('/etc/systemd/system/trusttunnel.service.d/40-warp-interface.conf')
INTERFACE_HELPER_SHA256 = '2a6113849b9f905ee475ed84dad44d0a55997143c2a56a5b89ce0f9299f93313'
ADMIN_LOCK = threading.RLock()
ADMIN_CONTEXT = threading.local()
CSRF_TOKEN = secrets.token_urlsafe(32)
CACHE_LOCK = threading.RLock()
SNAPSHOT_CACHE = {}
CACHE_COMPUTE_LOCKS = {}
RELEASE_STATE = {}
RELEASE_LOCK = threading.Lock()
RELEASE_FILE = Path('/var/cache/trusttunnel-panel/releases.json')
LOGIN_LOCK = threading.Lock()
LOGIN_FAILURES = {}
SESSIONS = {}
SESSION_LOCK = threading.Lock()
SESSION_IDLE_SECONDS = 1800
SESSION_MAX_SECONDS = 12 * 3600
CPU_SAMPLE = None
IGNORE_FILE = Path('/etc/fail2ban/jail.d/zz-trusttunnel-ignore.local')
UFW_DIR = Path('/etc/ufw')
UFW_DEFAULTS = Path('/etc/default/ufw')
FIREWALL_PENDING = Path('/var/lib/trusttunnel-panel/firewall-pending.json')
FAIL2BAN_DIR = Path('/etc/fail2ban')
FAIL2BAN_OVERRIDE = FAIL2BAN_DIR / 'jail.d/zzzz-trusttunnel-panel.local'
SCHEDULE_DIR = Path('/etc/systemd/system')
SECURITY_REPORT = Path('/var/cache/trusttunnel-panel/security.json')
SYSCTL_DIR = Path('/etc/sysctl.d')
USAGE_DB = Path('/var/lib/trusttunnel-panel/usage.sqlite3')
GUARD_STATUS = {'checked_at': 0, 'error': ''}
HEALTH_LOCK = threading.RLock()
HEALTH_LAST = {}
PANEL_EVENTS_LOCK = threading.Lock()
PANEL_EVENTS = {}
TORRENT_STATE = Path('/var/lib/trusttunnel-panel/torrent-filter.json')
TORRENT_DROPIN = Path('/etc/systemd/system/trusttunnel.service.d/60-torrent-filter.conf')
TORRENT_LOCK = threading.RLock()
TORRENT_MARKER = 'TrustTunnel BitTorrent filter'
TORRENT_SIGNATURES = [('tcp','13426974546f7272656e742070726f746f636f6c'),
                      ('udp','13426974546f7272656e742070726f746f636f6c'),
                      ('udp','64313a6164323a696432303a'),
                      ('udp','000004172710198000000000')]
SAFE_SYSCTLS = {'net.ipv4.tcp_syncookies': '1', 'net.ipv4.conf.all.accept_redirects': '0',
                'net.ipv4.conf.default.accept_redirects': '0', 'net.ipv4.conf.all.send_redirects': '0',
                'net.ipv4.conf.default.send_redirects': '0', 'net.ipv4.icmp_echo_ignore_broadcasts': '1',
                'fs.protected_hardlinks': '1', 'fs.protected_symlinks': '1'}


def cached_snapshot(seconds):
    def decorate(fn):
        @functools.wraps(fn)
        def wrapped():
            with CACHE_LOCK:
                cached = SNAPSHOT_CACHE.get(fn.__name__)
                if cached and time.monotonic() - cached[0] < seconds:
                    return cached[1]
                compute = CACHE_COMPUTE_LOCKS.setdefault(fn.__name__, threading.Lock())
            with compute:
                with CACHE_LOCK:
                    cached = SNAPSHOT_CACHE.get(fn.__name__)
                    if cached and time.monotonic() - cached[0] < seconds:
                        return cached[1]
                value = fn()
                with CACHE_LOCK: SNAPSHOT_CACHE[fn.__name__] = (time.monotonic(), value)
                return value
        return wrapped
    return decorate


def admin_snapshot(seconds):
    def decorate(fn):
        cached = cached_snapshot(seconds)(fn)
        @functools.wraps(fn)
        def wrapped():
            with admin_lock(): return cached()
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
            panel_event('failures')
            if len(LOGIN_FAILURES) >= 2048 and peer not in LOGIN_FAILURES:
                LOGIN_FAILURES.pop(next(iter(LOGIN_FAILURES)))
            count += 1
            LOGIN_FAILURES[peer] = (count, until)
        return max(1, int(until - now)) if count >= 5 else 0


def run(cmd, timeout=40, input_text=None, env=None, cwd=None):
    try:
        env = dict(os.environ if env is None else env, LC_ALL='C')
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
    atomic_write(path, text, mode)


def q(value):
    return json.dumps(value, ensure_ascii=False)[1:-1]


def endpoint_port():
    cfg = tomllib.loads(read_text(TT_DIR / 'vpn.toml'))
    address = cfg.get('listen_address')
    if address is None: return '443'
    host, separator, port = str(address).rpartition(':')
    if not separator or not host or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError('Некорректный listen_address в vpn.toml: проверьте адрес и порт endpoint.')
    if ':' in host and not (host.startswith('[') and host.endswith(']')):
        raise ValueError('IPv6 listen_address должен иметь вид [::]:8443.')
    return str(int(port))


def domain():
    m = re.search(r'^hostname\s*=\s*"([^"]+)"', read_text(TT_DIR / 'hosts.toml'), re.M)
    return m.group(1) if m else ''


def quic_enabled():
    return 'quic' in tomllib.loads(read_text(TT_DIR / 'vpn.toml')).get('listen_protocols', {})


def uses_warp():
    return interface_enabled() or any(address in read_text(TT_DIR / 'vpn.toml') for address in (SOCKS_ADDR, MASQUE_ADDR))


def forwarder_label():
    if interface_enabled(): return 'WARP · MASQUE TUN' if read_text(INTERFACE_DIR / 'transport').strip() == 'masque' else 'WARP · WireGuard интерфейс'
    cfg = read_text(TT_DIR / 'vpn.toml')
    m = re.search(r'\[forward_protocol\.socks5\]\s*address\s*=\s*"([^"]+)"', cfg)
    if m:
        return {SOCKS_ADDR: 'WARP · WireGuard', MASQUE_ADDR: 'WARP · MASQUE'}.get(m.group(1), 'Cascade SOCKS5: ' + m.group(1))
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
    clients = tomllib.loads(read_text(TT_DIR / 'credentials.toml')).get('client', [])
    if any(not client_name_valid(c.get('username','')) or not isinstance(c.get('password'),str) for c in clients):
        raise ValueError('Некорректные имена или пароли в credentials.toml; автоматическая работа с профилями остановлена.')
    return clients


@contextmanager
def admin_lock():
    # Shared by web workers and the terminal CLI, including separate processes.
    import fcntl
    TT_DIR.mkdir(parents=True, exist_ok=True)
    with ADMIN_LOCK:
        if getattr(ADMIN_CONTEXT, 'held', False):
            yield
            return
        with (TT_DIR / '.admin.lock').open('a') as lock:
            os.chmod(lock.name, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            ADMIN_CONTEXT.held = True
            try:
                yield
            finally:
                ADMIN_CONTEXT.held = False
                fcntl.flock(lock, fcntl.LOCK_UN)


def atomic_write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.admin-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, mode)
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
            return deeplink(user, values.get('protocol', 'http2'), values.get('kind', 'static'))
        if action == 'rebuild':
            rebuild_client_files(clients)
            return 'TOML и ZIP пересобраны.'
        if action == 'refresh-network':
            record = records.get(user)
            if not record: raise ValueError('Клиент не найден или отключён.')
            if values.get('confirm') != 'CONFIRMED': raise ValueError('Подтвердите пересборку профиля клиента.')
            candidates = {CLIENT_DIR/f'{user}-{proto}.toml': client_profile(user, record['password'], proto) for proto in (['http2','http3'] if quic_enabled() else ['http2'])}
            for path, body in candidates.items(): atomic_write(path, body)
            refresh_client_archive(); DEEPLINK_CACHE.clear()
            audit_log('client-refresh-network', user)
            return 'Сетевые параметры этого клиента обновлены. TLS auth key, SNI и дополнительные поля сохранены. Импортируйте профиль повторно. Работающий VPN и остальные профили не менялись.'
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
        elif action == 'limits':
            record = records.get(user) or state['disabled'][user]
            for key in ('max_http2_conns', 'max_http3_conns'):
                value = values.get(key, '').strip()
                if not value:
                    record.pop(key, None)
                elif value.isdigit() and 1 <= int(value) <= 1000:
                    record[key] = int(value)
                else:
                    raise ValueError('Лимит: от 1 до 1000, либо пусто для настройки endpoint.')
        else:
            raise ValueError('Неизвестное действие клиента.')
        if action in ('disable','enable','password','delete'):
            state.setdefault('revisions', {})[user] = secrets.token_hex(16)
        cred = TT_DIR / 'credentials.toml'
        state_path = TT_DIR / 'clients-state.json'
        old_credentials, old_state = read_text(cred), read_text(state_path)
        config = tomllib.loads(old_credentials)
        if set(config) - {'client'} or any(set(c) - {'username', 'password', 'max_http2_conns', 'max_http3_conns'} for c in config.get('client', [])):
            raise ValueError('Обнаружены дополнительные поля credentials.toml. Автоматическая перезапись отменена.')
        lines = []
        for c in clients:
            lines += ['[[client]]', 'username = ' + json.dumps(c['username']), 'password = ' + json.dumps(c['password'])]
            lines += [key + ' = ' + str(c[key]) for key in ('max_http2_conns', 'max_http3_conns') if key in c]
            lines.append('')
        candidate = '\n'.join(lines)
        tomllib.loads(candidate)
        backup = TT_DIR / 'backups' / ('clients-' + time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3))
        backup.mkdir(parents=True, mode=0o700)
        atomic_write(backup / 'credentials.toml', old_credentials)
        atomic_write(backup / 'clients-state.json', old_state or '{}')
        before = {c['username']: c['password'] for c in tomllib.loads(old_credentials).get('client', [])}
        profiles = {CLIENT_DIR/f"{c['username']}-{proto}.toml": client_profile(c['username'], c['password'], proto)
                    for c in clients if before.get(c['username']) != c['password']
                    for proto in (['http2','http3'] if quic_enabled() else ['http2'])}
        removed = {CLIENT_DIR/f'{name}-{proto}.toml' for name in set(before)-{c['username'] for c in clients} for proto in ('http2','http3')}
        affected = set(profiles) | removed | {CLIENT_DIR/'clients-credentials.txt'}
        exports_before = {p:p.read_bytes() if p.exists() else None for p in affected}
        archive = CLIENT_DIR.with_name(CLIENT_DIR.name+'-'+(domain() or 'trusttunnel')+'.zip')
        archive_before = archive.read_bytes() if archive.exists() else None
        try:
            atomic_write(state_path, json.dumps(state, ensure_ascii=False))
            atomic_write(cred, candidate)
            rc, out = run(['systemctl', 'restart', 'trusttunnel'], timeout=30)
            if rc or service_status('trusttunnel') != 'active':
                raise RuntimeError('TrustTunnel не запустился: ' + out)
            for path, body in profiles.items(): atomic_write(path, body)
            for path in removed: path.unlink(missing_ok=True)
            atomic_write(CLIENT_DIR/'clients-credentials.txt', ''.join(f"{c['username']} {c['password']}\n" for c in clients))
            refresh_client_archive()
        except Exception:
            atomic_write(cred, old_credentials)
            if old_state:
                atomic_write(state_path, old_state)
            else:
                state_path.unlink(missing_ok=True)
            for path, body in exports_before.items():
                if body is None: path.unlink(missing_ok=True)
                else:
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_bytes(body); os.chmod(path,0o600)
            if archive_before is None: archive.unlink(missing_ok=True)
            else: archive.write_bytes(archive_before); os.chmod(archive,0o600)
            run(['systemctl', 'restart', 'trusttunnel'], timeout=30)
            raise
        DEEPLINK_CACHE.clear()
        SNAPSHOT_CACHE.pop('client_metrics',None)
        if action == 'delete':
            guards = guard_state(); guards.get('policies', {}).pop(user, None)
            atomic_write(TT_DIR/'client-guard.json', json.dumps(guards))
            if USAGE_DB.exists():
                with usage_database() as db:
                    for table in ('usage', 'daily', 'enrollment', 'source_observations'): db.execute('DELETE FROM '+table+' WHERE username=?', (user,))
                    db.execute('DELETE FROM enrollment_sources WHERE digest NOT IN (SELECT digest FROM enrollment)')
        audit_log('client-' + action, user or str(count))
        return 'Изменения сохранены. TrustTunnel работает.'


def admin_operation(action, values):
    if action in ('health-status','health-check','scanner-status'):
        if action == 'health-check': health_tick()
        return json.dumps(scanner_snapshot() if action == 'scanner-status' else health_snapshot(),ensure_ascii=False,indent=2)
    if action.startswith('torrent-'):
        return torrent_operation(action[8:], values)
    if action.startswith(('ufw-', 'f2b-')):
        with admin_lock():
            result = firewall_operation(action[4:], values) if action.startswith('ufw-') else fail2ban_operation(action[4:], values)
            with CACHE_LOCK: SNAPSHOT_CACHE.clear()
            return result
    if action.startswith('diagnostics-'):
        return diagnostic_report(action[12:], values)
    if action.startswith('guard-'):
        return guard_operation(action[6:], values)
    if action.startswith('enrollment-'):
        return enrollment_operation(action[11:], values)
    if action == 'panel-service':
        if values.get('confirm') != 'CONFIRMED' or values.get('enabled') not in ('0','1'):
            raise ValueError('Подтвердите включение или отключение панели.')
        env = current_panel_env()
        if values['enabled'] == '1':
            if env.get('PANEL_TLS') == '1': panel_firewall(True,env.get('PANEL_PORT','8088'))
            checked_run(['systemctl','enable','--now','trusttunnel-panel'])
            return 'Панель включена. Управляемый HTTPS-порт разрешён в UFW.'
        panel_firewall(False,env.get('PANEL_PORT','8088'))
        subprocess.Popen(['sh','-c','sleep 2; systemctl disable --now trusttunnel-panel >/dev/null 2>&1'])
        return 'Панель будет остановлена. Только наше правило HTTPS удалено из UFW. Включить обратно: ttmenu → управление панелью.'
    if action.startswith('schedule-'):
        with admin_lock():
            return schedule_operation(action[9:], values)
    if action.startswith('protection-'):
        with admin_lock():
            return protection_operation(action[11:], values)
    if action == 'recommendations':
        return recommendations()
    if action == 'warp-operation':
        return warp_operation(values)
    if action.startswith('interface-'):
        with admin_lock():
            return interface_operation(action[10:], values)
    if action == 'certificate-switch':
        return installer_operation('switch-certificate-mode', values)
    if action == 'certificate-status':
        return certificate_info() + '\n\n' + checked_run(['systemctl', 'status', 'trusttunnel-cert-renew.timer', '--no-pager'])
    if action == 'panel-credentials':
        return update_panel_credentials(values.get('username', ''), values.get('password', ''))
    if action.startswith('masque-'):
        with admin_lock():
            return masque_operation(action[7:], values)
    if action == 'endpoint-releases':
        return release_report()
    if action in ('endpoint-metrics', 'endpoint-subscription'):
        with admin_lock():
            return endpoint_feature_operation(action, values)
    if action.startswith('client-'):
        return client_operation(action[7:], values)
    if action == 'monitor':
        return json.dumps(monitor_snapshot(), ensure_ascii=False, indent=2)
    if action == 'logs':
        unit = values.get('unit', 'trusttunnel')
        if unit not in ('trusttunnel', 'warp-wireproxy', 'warp-masque', 'warp-masque-bridge', 'warp-interface', 'warp-masque-tun', 'trusttunnel-panel', 'fail2ban'):
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


def wait_fail2ban():
    for _ in range(30):
        if run(['fail2ban-client','ping'],timeout=2)[0] == 0:return
        time.sleep(.2)
    raise RuntimeError('fail2ban не создал управляющий сокет после перезапуска.')


@cached_snapshot(60)
def endpoint_capabilities():
    rc, help_text = run([str(TT_DIR / 'trusttunnel_endpoint'), '--help'], timeout=8)
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', endpoint_version())
    version = tuple(map(int, match.groups())) if match else (0, 0, 0)
    return {'subscription': rc == 0 and '--subscription-only' in help_text,
            'auth_key': rc == 0 and '--client-random-auth-key' in help_text,
            'metrics': version >= (1, 1, 0),
            'prefix': rc == 0 and '--client-random-prefix' in help_text,
            'stealth_http': version >= (1, 0, 41)}


def protection_state():
    raw = read_text(TT_DIR / 'panel-protection.json')
    return json.loads(raw) if raw else {}


def set_core_setting(text, key, value):
    # Only update root keys, never a similarly named key in a TOML table.
    boundary = re.search(r'(?m)^\s*\[', text)
    head, tail = (text[:boundary.start()], text[boundary.start():]) if boundary else (text, '')
    assignment = key + ' = ' + json.dumps(value) + '\n'
    multiline = r'(?ms)^' + re.escape(key) + r'[ \t]*=[ \t]*(?:""".*?"""|\x27\x27\x27.*?\x27\x27\x27)[ \t]*(?:#[^\n]*)?(?:\n|$)'
    head, count = re.subn(multiline, lambda _: assignment, head)
    if not count:
        head, count = re.subn(r'(?m)^' + re.escape(key) + r'[ \t]*=[^\n]*\n?', lambda _: assignment, head)
    if count > 1: raise ValueError('Повторяющийся параметр ' + key)
    return head + ('' if count else assignment) + tail


def managed_rules_path():
    cfg = tomllib.loads(read_text(TT_DIR/'vpn.toml'))
    configured = cfg.get('rules_file')
    if not isinstance(configured,str) or not configured:
        raise ValueError('В vpn.toml не задан rules_file. Строгая защита не включена.')
    path = Path(configured)
    if not path.is_absolute(): path = TT_DIR/path
    expected = TT_DIR/'rules.toml'
    if path.is_symlink() or expected.is_symlink() or path.resolve() != expected.resolve():
        raise ValueError('Endpoint использует другой файл правил или symlink. Автоматическая защита отменена; проверьте rules_file.')
    return expected


def remove_core_setting(text, key):
    text = set_core_setting(text,key,'')
    return re.sub(r'(?m)^'+re.escape(key)+r'[ \t]*=[ \t]*""\n?', '', text, count=1)


def strict_protection_locked():
    state = protection_state()
    return any(state.get(key) for key in ('enabled','tls_enabled','transition'))


def protection_integrity():
    state = protection_state()
    if state.get('transition'): return False, 'Незавершённое изменение защиты; автоматические изменения заблокированы.'
    active = 'tls_rules_hash' if state.get('tls_enabled') else 'rules_hash' if state.get('enabled') else ''
    if not active: return True, 'Строгая защита не обязательна; это выбранный режим, не подтверждение невидимости.'
    try:
        path = managed_rules_path()
        valid = hashlib.sha256(read_text(path).encode()).hexdigest() == state.get(active)
        if state.get('tls_enabled'): valid = valid and endpoint_capabilities().get('auth_key', False)
        return bool(valid), 'Файл правил и совместимость соответствуют сохранённой политике' if valid else 'Правила или endpoint изменились. Строгую защиту нельзя считать подтверждённой.'
    except (OSError, ValueError):
        return False, 'Не подтверждён фактический rules_file. Проверьте конфигурацию и правила.'


def commit_protection_rules(state, candidate, flag, enabled):
    path = managed_rules_path(); state_path = TT_DIR/'panel-protection.json'
    previous_rules, previous_state = read_text(path), read_text(state_path)
    pending = dict(state, transition={'flag':flag,'enabled':enabled})
    atomic_write(state_path,json.dumps(pending))
    try:
        apply_endpoint_file(path,candidate)
        final = dict(state); final[flag] = enabled; final.pop('transition',None)
        atomic_write(state_path,json.dumps(final))
    except Exception:
        if read_text(path) != previous_rules: apply_endpoint_file(path,previous_rules)
        if previous_state: atomic_write(state_path,previous_state)
        else: state_path.unlink(missing_ok=True)
        raise


def protection_operation(action, values):
    state_path = TT_DIR / 'panel-protection.json'
    state = protection_state()
    rules_path = TT_DIR / 'rules.toml'
    rules = read_text(rules_path)
    capabilities = endpoint_capabilities()
    if action == 'status':
        cfg = tomllib.loads(read_text(TT_DIR / 'vpn.toml'))
        return '\n'.join([
            'Endpoint: ' + endpoint_version(),
            'Строгий фильтр ClientHello: ' + ('включён' if state.get('enabled') else 'выключен'),
            'Совместимость строгого фильтра: ' + ('гарантия защиты от сканирования с QUIC не подтверждена; видимость сертификата не доказывает доступ к VPN' if quic_enabled() else 'только HTTP/2; требуется проверка подготовленных ссылок'),
            'Защищённые ссылки: ' + ('подготовлены' if state.get('prefix') else 'не подготовлены'),
            'HTTP-ответ без авторизации: ' + str(cfg.get('non_connect_auth_failure_status_code', cfg.get('auth_failure_status_code', 407))),
            'Публичный ping / speedtest: ' + str(bool(cfg.get('ping_enable'))) + ' / ' + str(bool(cfg.get('speedtest_enable'))),
            'Ключевой ClientHello: ' + ('есть в endpoint, нужен совместимый новый клиент' if capabilities.get('auth_key') else 'недоступен в установленной стабильной версии'),
            'TLS-auth обязателен: ' + ('да' if state.get('tls_enabled') else 'нет') + '; новые ссылки: ' + ('подготовлены' if state.get('auth_key') else 'не подготовлены'),
            'App v1.3: разработчики подтвердили поддержку 22.10.2026; установленную версию и оба транспорта нужно проверить отдельно.',
            'Незавершённое изменение: ' + ('ДА: проверьте правила и резервную копию состояния вручную, изменения заблокированы' if state.get('transition') else 'нет'),
            'Целостность политики: ' + protection_integrity()[1],
            'Это снижение обнаруживаемости, не гарантия невидимости. Пароли, сертификат и шифрование TLS остаются обязательными.'
        ])
    if values.get('confirm') != 'CONFIRMED':
        raise ValueError('Подтвердите изменение защиты.')
    if state.get('transition'): raise ValueError('Есть незавершённое изменение защиты. Проверьте rules.toml и panel-protection.json; автоматические изменения заблокированы.')
    if action in ('tls-prepare', 'tls-enforce', 'tls-disable'):
        return tls_auth_operation(action[4:], values)
    if action == 'client-preset':
        values = panel_settings()
        values.update(CLIENT_ANTI_DPI='1', TLS_PROFILE='chrome', POST_QUANTUM='0', DNS_UPSTREAMS='https://dns.adguard-dns.com/dns-query')
        atomic_write(PANEL_SETTINGS, ''.join(k+'='+v+'\n' for k,v in values.items()))
        DEEPLINK_CACHE.clear(); audit_log('protection-client-preset')
        return 'Штатный AntiDPI, Chrome ClientHello и DoH включены по умолчанию для новых профилей. Работающие TOML, маршруты и подключения не изменены. Для существующего клиента используйте «Обновить сетевые параметры профиля», затем повторно импортируйте профиль. Нет гарантии обхода блокировки IP или анализа трафика.'
    if action == 'client-settings':
        dns = validated_dns(values.get('dns', ''))
        profile = values.get('tls_profile', '')
        if profile not in ('chrome','safari','firefox','okhttp','openssl','default'): raise ValueError('Выберите допустимый TLS-профиль.')
        settings = panel_settings()
        settings.update(DNS_UPSTREAMS=','.join(dns), TLS_PROFILE=profile, CLIENT_ANTI_DPI='1' if values.get('anti_dpi') == '1' else '0', POST_QUANTUM='1' if values.get('post_quantum') == '1' else '0')
        atomic_write(PANEL_SETTINGS, ''.join(k+'='+v+'\n' for k,v in settings.items()))
        DEEPLINK_CACHE.clear(); audit_log('protection-client-settings')
        return 'Настройки новых профилей сохранены. Старые профили и подключения не менялись. Для выбранного существующего клиента обновите его сетевые параметры и импортируйте TOML повторно. Post-quantum не является маскировкой и требует совместимого клиента.'
    if action in ('camouflage', 'camouflage-restore'):
        if not capabilities.get('stealth_http'): raise ValueError('Нужен endpoint 1.0.41 или новее.')
        path = TT_DIR / 'vpn.toml'; text = read_text(path)
        keys = ('non_connect_auth_failure_status_code', 'ping_enable', 'speedtest_enable')
        if action == 'camouflage':
            if 'http_backup' not in state:
                cfg = tomllib.loads(text)
                state['http_backup'] = {key:cfg.get(key) for key in keys}
            for key, value in zip(keys, (404, False, False)): text = set_core_setting(text, key, value)
        else:
            backup = state.get('http_backup')
            if backup is None: raise ValueError('Сохранённых HTTP-настроек нет.')
            for key, value in backup.items():
                if value is None:
                    boundary = re.search(r'(?m)^\s*\[', text)
                    pos = boundary.start() if boundary else len(text)
                    text = re.sub(r'(?m)^' + re.escape(key) + r'[ \t]*=[^\n]*\n?', '', text[:pos]) + text[pos:]
                else: text = set_core_setting(text, key, value)
        atomic_write(state_path, json.dumps(state))
        apply_endpoint_file(path, text)
        if action.endswith('restore'):
            state.pop('http_backup', None); atomic_write(state_path, json.dumps(state))
        audit_log('protection-' + action)
        return 'HTTP-настройки применены. CONNECT-аутентификация не менялась. Отдельные ping_hosts, speedtest_hosts и сертификат по-прежнему видны сканеру, если настроены.'
    if action == 'prepare':
        if not capabilities.get('prefix'): raise ValueError('Endpoint не поддерживает экспорт client_random_prefix.')
        if not state.get('prefix'):
            state['prefix'] = secrets.token_hex(8)
            state.setdefault('enabled', False)
            atomic_write(state_path, json.dumps(state))
        return 'Подготовлены альтернативные tt-ссылки: Клиенты → Управлять → Защищённая ссылка. Старые ссылки, TOML и подключения не изменены. Сначала проверьте новые ссылки на всех устройствах, затем отдельно включите строгий фильтр.'
    if action == 'enforce':
        if state.get('tls_enabled'): raise ValueError('Сначала отключите обязательную TLS-аутентификацию.')
        if quic_enabled():
            raise ValueError('Строгий фильтр не включён: защита от сканирования через QUIC пока не подтверждена. Проверка сертификата и успешное туннелирование — разные этапы. Автоматически отключать QUIC нельзя.')
        if not capabilities.get('prefix') or not state.get('prefix'): raise ValueError('Сначала подготовьте и проверьте защищённые ссылки.')
        if values.get('clients_ready') != '1': raise ValueError('Подтвердите импорт защищённых ссылок на всех устройствах. Старые профили перестанут подключаться.')
        if state.get('enabled'): return 'Строгий фильтр уже включён.'
        parsed = tomllib.loads(rules)
        existing = parsed.get('rule', [])
        if set(parsed) - {'rule'} or any(rule.get('action') != 'deny' or not (rule.get('cidr') or rule.get('client_random_prefix')) for rule in existing):
            raise ValueError('Существующие allow или сложные правила могут обойти фильтр. Автоматическое изменение отменено; правила сохранены.')
        protected = rules.rstrip() + '\n\n# Managed ClientHello guard; change through ttmenu / panel only.\n[[rule]]\nclient_random_prefix = ' + json.dumps(state['prefix']) + '\naction = "allow"\n\n[[rule]]\naction = "deny"\n'
        state.update({'rules_backup':rules, 'rules_hash':hashlib.sha256(protected.encode()).hexdigest(), 'enabled':False})
        commit_protection_rules(state,protected,'enabled',True)
        DEEPLINK_CACHE.clear()
        audit_log('protection-enforce')
        return 'Строгий фильтр включён. Подключаются только профили с подготовленным ClientHello. SSH и веб-панель не затронуты. Отключить: ttmenu → Защита от сканирования.'
    if action == 'disable':
        if not state.get('enabled'): return 'Строгий фильтр уже выключен.'
        if hashlib.sha256(rules.encode()).hexdigest() != state.get('rules_hash'):
            raise ValueError('Правила изменены вне защиты. Откат отменён, чтобы не потерять чужие изменения; проверьте rules.toml вручную.')
        commit_protection_rules(state,state['rules_backup'],'enabled',False)
        DEEPLINK_CACHE.clear(); audit_log('protection-disable')
        return 'Прежние правила восстановлены. Старые и защищённые профили снова допускаются правилами.'
    raise ValueError('Неизвестная операция защиты.')


def tls_auth_operation(action, values):
    state = protection_state(); path = TT_DIR/'panel-protection.json'
    if action == 'prepare':
        if not state.get('auth_key'): state['auth_key'] = secrets.token_hex(32)
        state.setdefault('tls_enabled', False)
        atomic_write(path, json.dumps(state)); DEEPLINK_CACHE.clear()
        audit_log('protection-tls-prepare')
        return 'TLS-auth ссылки подготовлены: Клиенты → Управлять → TLS-аутентификация v1.3. Нужен совместимый endpoint и графический App v1.3. Текущие правила и профили не менялись. На старом endpoint ссылка не проверяет защиту от сканирования. Сначала обновите endpoint отдельно, проверьте новый профиль и только затем включайте обязательный режим.'
    if action == 'enforce':
        if not endpoint_capabilities().get('auth_key'): raise ValueError('Установленный endpoint не поддерживает TLS auth key. Стабильный 1.1.0 не подходит; обновление выбирается отдельно, beta не устанавливается автоматически.')
        if quic_enabled(): raise ValueError('Обязательная TLS-аутентификация с QUIC ещё не квалифицирована. Включение заблокировано: нельзя рисковать работающими QUIC-клиентами.')
        if state.get('enabled'): raise ValueError('Сначала отключите прежний prefix-фильтр.')
        if state.get('tls_enabled'): return 'TLS-аутентификация уже обязательна.'
        if not state.get('auth_key') or values.get('clients_ready') != '1' or values.get('client_v13') != '1':
            raise ValueError('Подготовьте ссылки и подтвердите проверку всех устройств с App v1.3 и новым TLS-auth профилем.')
        rules_path = managed_rules_path(); original = read_text(rules_path)
        parsed = tomllib.loads(original)
        if set(parsed)-{'rule'} or any(r.get('action') != 'deny' or not r.get('cidr') or set(r)-{'cidr','action'} for r in parsed.get('rule', [])):
            raise ValueError('Автоматическое включение допускает только существующие CIDR deny. Сложные/allow правила сохранены без изменения.')
        candidate = original.rstrip()+'\n\n# Managed TLS authentication: panel / ttmenu only\n[[rule]]\nclient_random_auth_key = '+json.dumps(state['auth_key'])+'\naction = "allow"\n\n[[rule]]\naction = "deny"\n'
        state.update(tls_rules_backup=original, tls_rules_hash=hashlib.sha256(candidate.encode()).hexdigest(), tls_enabled=False)
        commit_protection_rules(state,candidate,'tls_enabled',True)
    elif action == 'disable':
        if not state.get('tls_enabled'): return 'Обязательная TLS-аутентификация выключена.'
        rules_path = TT_DIR/'rules.toml'
        if hashlib.sha256(read_text(rules_path).encode()).hexdigest() != state.get('tls_rules_hash'):
            raise ValueError('Правила изменились вручную; автоматический откат отменён.')
        commit_protection_rules(state,state['tls_rules_backup'],'tls_enabled',False)
    else: raise ValueError('Неизвестная операция TLS-аутентификации.')
    DEEPLINK_CACHE.clear()
    audit_log('protection-tls-' + action)
    return 'TLS-auth политика обновлена. Пароли, сертификат и файлы клиентов сохранены. Ключ защищает от постороннего TLS-зондирования, но скопированный ключ не привязывается к устройству.'


def github_json(path):
    request = urllib.request.Request('https://api.github.com/repos/' + path,
                                     headers={'User-Agent': 'TrustTunnel-Panel', 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=12) as response:
        body = response.read(2 * 1024 * 1024 + 1)
    if len(body) > 2 * 1024 * 1024:
        raise RuntimeError('Слишком большой ответ GitHub.')
    return json.loads(body)


def refresh_releases():
    global RELEASE_STATE
    with RELEASE_LOCK:
        releases = github_json('TrustTunnel/TrustTunnel/releases?per_page=15')
        state = {'checked_at':time.time(), 'error':''}
        for key, prerelease in (('stable', False), ('beta', True)):
            release = next((r for r in releases if bool(r.get('prerelease')) == prerelease and not r.get('draft')), None)
            state[key] = {name:release.get(name, '') for name in ('tag_name','published_at','html_url')} if release else {}
            state[key]['body'] = release.get('body', '')[:6000] if release else ''
        RELEASE_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        atomic_write(RELEASE_FILE, json.dumps(state, ensure_ascii=False))
        RELEASE_STATE = state
        return state


def release_snapshot():
    global RELEASE_STATE
    if not RELEASE_STATE and RELEASE_FILE.exists() and RELEASE_FILE.stat().st_size < 50000:
        try: RELEASE_STATE = json.loads(RELEASE_FILE.read_text())
        except (ValueError, OSError): pass
    data = dict(RELEASE_STATE)
    def number(text):
        match = re.search(r'(\d+)\.(\d+)\.(\d+)', text)
        return tuple(map(int, match.groups())) if match else (0,0,0)
    data['installed'] = endpoint_version()
    latest = data.get('stable', {}).get('tag_name', '')
    data['update_available'] = bool(latest) and number(latest) > number(data['installed'])
    data['panel_update_recommended'] = number(latest) > (1,3,0)
    data['compatibility'] = 'Метрики и лимиты соединений: endpoint 1.1+. Подписки и ClientHello auth key: совместимый endpoint 1.3+ и актуальный клиент. Наличие функций проверяется по установленному бинарному файлу. Новые неизвестные поля не включаются автоматически.'
    if data['panel_update_recommended']:
        data['compatibility'] += ' Выпуск новее карты совместимости панели. Для поддержки его новых функций проверьте обновление самой панели.'
    return data


def release_watcher():
    while True:
        try: refresh_releases()
        except Exception:
            global RELEASE_STATE
            RELEASE_STATE = dict(RELEASE_STATE, error='Не удалось проверить GitHub. Последние сохранённые данные могут быть устаревшими.')
        time.sleep(6 * 3600)


def release_report():
    state = refresh_releases()
    lines = ['Установлено: ' + endpoint_version()]
    for label, release in (('Стабильный выпуск', state['stable']), ('Предварительный выпуск', state['beta'])):
        if release:
            lines += [label + ': ' + release['tag_name'], release['html_url'], release.get('body', '')[:5000], '']
    lines.append(release_snapshot()['compatibility'])
    lines.append('По умолчанию устанавливается стабильный выпуск. Подписки и ClientHello auth key доступны только в совместимой версии; переход на beta выполняется отдельно.')
    return '\n'.join(lines)


def recommendations():
    snapshot = security_snapshot()
    lines = ['Проверка текущего сервера', '']
    for check in snapshot['checks']:
        lines.append(f'[{check["state"]}] {check["title"]}: {check["detail"]}')
    lines += ['', 'Рекомендуемые сочетания',
              '1. Максимальная защита панели: localhost + SSH-туннель, SSH-ключи, fail2ban и минимальные правила UFW. Отключайте вход по паролю только после проверки ключа в отдельной SSH-сессии.',
              '2. Публичная панель: HTTPS + доверенный сертификат, длинный уникальный пароль, ограничение доступа к порту панели по IP. Панель имеет административные права на сервере; пароль панели равносилен доступу к управлению VPS.',
              '3. Игры и звонки: QUIC/HTTP3 до VPS при доступном UDP + WARP через отдельный WireGuard-интерфейс или MASQUE TUN. На сети с блокировкой UDP сравните HTTP/2. Низкий пинг нельзя гарантировать без измерения пути от устройства до игрового сервера.',
              '4. Стабильная эксплуатация: stable endpoint, автоматическое продление Let’s Encrypt, резервная копия identity до обновлений. Beta включается отдельно; новые функции требуют совместимого клиента.',
              '5. Несколько устройств: отдельная учётная запись на каждое. Лимит HTTP/2 или QUIC-соединений не является надёжной аппаратной привязкой.',
              '', 'Текущий маршрут: ' + forwarder_label(), release_snapshot()['compatibility'],
              '', 'Рекомендации ничего не меняют. Это автоматическая проверка ограниченного набора настроек, а не гарантия отсутствия уязвимостей.']
    return '\n'.join(lines)


def replace_config_section(text, name, values):
    pattern = r'(?ms)^\[' + re.escape(name) + r'\][ \t]*(?:#[^\n]*)?\n.*?(?=^\[|\Z)'
    text = re.sub(pattern, '', text)
    if values:
        text += '\n[' + name + ']\n' + '\n'.join(key + ' = ' + json.dumps(value, ensure_ascii=False) for key, value in values.items()) + '\n'
    tomllib.loads(text)
    return text


def endpoint_feature_operation(action, values):
    path = TT_DIR / 'vpn.toml'
    text = read_text(path)
    parsed = tomllib.loads(text)
    enabled = values.get('enabled') == '1'
    if action == 'endpoint-metrics':
        if not endpoint_capabilities()['metrics']:
            raise ValueError('Для метрик пользователей нужен TrustTunnel 1.1.0 или новее.')
        if enabled and 'http1' not in parsed.get('listen_protocols', {}):
            if values.get('http1_ack') != '1':
                raise ValueError('Для локальных метрик нужен HTTP/1.1 codec endpoint. Подтвердите его добавление: HTTP/1.1 станет доступен и на VPN-порту; HTTP/2 и QUIC сохранятся.')
            text = replace_config_section(text, 'listen_protocols.http1', {'upload_buffer_size':32768})
        settings = parsed.get('metrics', {})
        if set(settings) - {'address', 'request_timeout_secs', 'per_client_metrics'}:
            raise ValueError('Метрики содержат дополнительные настройки. Измените их вручную.')
        address = settings.get('address', '127.0.0.1:1987')
        host, port = address.rsplit(':', 1)
        if host != '127.0.0.1' or not validate_port(port):
            if enabled: raise ValueError('Метрики пользователей разрешены только на 127.0.0.1.')
            address = '127.0.0.1:1987'
        settings.update(address=address, request_timeout_secs=3, per_client_metrics=enabled)
        text = replace_config_section(text, 'metrics', settings)
    else:
        if not endpoint_capabilities()['subscription']:
            raise ValueError('Подписки не поддерживаются установленным endpoint. Нужна совместимая версия 1.3+; beta выбирается отдельно.')
        if cert_mode() != 'letsencrypt':
            raise ValueError('Для подписок требуется доверенный HTTPS-сертификат endpoint.')
        settings = parsed.get('subscription', {})
        if set(settings) - {'enabled', 'hostname', 'path', 'address', 'name', 'dns_upstreams', 'custom_sni', 'client_random_prefix'}:
            raise ValueError('Подписка содержит дополнительные поля. Автоматическая перезапись отменена.')
        route = values.get('path', settings.get('path', '/subscription'))
        if not re.fullmatch(r'/[A-Za-z0-9/_-]{1,100}', route):
            raise ValueError('Путь подписки: / и от 1 до 100 букв, цифр, /, _ или -.')
        settings.update(enabled=enabled, hostname=domain(), path=route, address=f'{domain()}:{endpoint_port()}',
                        name='TrustTunnel', dns_upstreams=dns_upstreams())
        text = replace_config_section(text, 'subscription', settings)
    apply_endpoint_file(path, text)
    DEEPLINK_CACHE.clear()
    SNAPSHOT_CACHE.clear()
    audit_log(action, 'enabled' if enabled else 'disabled')
    return 'Настройка применена. Счётчики трафика endpoint сбрасываются при его перезапуске.'


def fetch_client_metrics():
    cfg = tomllib.loads(read_text(TT_DIR / 'vpn.toml')).get('metrics', {})
    address = cfg.get('address', '')
    if not cfg.get('per_client_metrics') or not re.fullmatch(r'127\.0\.0\.1:\d{1,5}', address):
        return {'available': False, 'clients': []}
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open('http://' + address + '/clients', timeout=3) as response:
            body = response.read(1024 * 1024 + 1)
        if len(body) > 1024 * 1024: raise ValueError('Metrics response too large')
        data = json.loads(body)
        rows = data.get('clients', []) if isinstance(data, dict) else data
        if not isinstance(rows, list) or len(rows) > 10000: raise ValueError('Invalid metrics response')
        clean, seen = [], set()
        for row in rows:
            if not isinstance(row, dict): raise ValueError('Invalid metrics record')
            name = row.get('username', '')
            if not name: continue  # An unauthenticated connection has no account identity.
            if not client_name_valid(name) or name in seen: raise ValueError('Invalid metrics identity')
            seen.add(name)
            item = {'username': name}
            for key in ('sessions', 'inbound', 'outbound'):
                value = row.get(key)
                if type(value) is not int or not 0 <= value <= 2**63-1: raise ValueError('Invalid metrics counter')
                item[key] = value
            item['ip'] = str(ipaddress.ip_address(row['ip'])) if row.get('ip') else ''
            clean.append(item)
        return {'available': True, 'clients': clean}
    except (OSError, ValueError):
        return {'available': False, 'clients': []}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Local metrics must not redirect')


@contextmanager
def usage_database():
    USAGE_DB.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if USAGE_DB.parent.is_symlink() or USAGE_DB.parent.stat().st_uid != 0: raise ValueError('Usage directory must belong to root')
    os.chmod(USAGE_DB.parent, 0o700)
    if USAGE_DB.is_symlink(): raise ValueError('Usage database must not be a symlink')
    fd = os.open(USAGE_DB, os.O_CREAT | os.O_RDWR | getattr(os,'O_NOFOLLOW',0), 0o600)
    os.close(fd); os.chmod(USAGE_DB, 0o600)
    connection = sqlite3.connect(USAGE_DB, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript('''
CREATE TABLE IF NOT EXISTS usage (
 username TEXT PRIMARY KEY, epoch TEXT NOT NULL, raw_up INTEGER NOT NULL,
 raw_down INTEGER NOT NULL, upload INTEGER NOT NULL, download INTEGER NOT NULL,
 last_seen REAL NOT NULL, observed_at REAL NOT NULL, last_ip TEXT NOT NULL,
 ip_changes INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS daily (
 username TEXT NOT NULL, day TEXT NOT NULL, upload INTEGER NOT NULL, download INTEGER NOT NULL,
 PRIMARY KEY(username, day));
CREATE TABLE IF NOT EXISTS enrollment (
 digest TEXT PRIMARY KEY, username TEXT NOT NULL, protocol TEXT NOT NULL, kind TEXT NOT NULL,
 identity TEXT NOT NULL, expires REAL NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS source_observations (
 username TEXT NOT NULL, observed_at REAL NOT NULL, ip TEXT NOT NULL,
 PRIMARY KEY(username, ip));
CREATE TABLE IF NOT EXISTS enrollment_sources (
 digest TEXT PRIMARY KEY, source_cidr TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS health_samples (
 ts INTEGER PRIMARY KEY, state TEXT NOT NULL, cpu REAL, ram REAL, disk REAL,
 interface TEXT NOT NULL, boot TEXT NOT NULL, rx INTEGER, tx INTEGER, issues TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS panel_event_counts (
 hour INTEGER PRIMARY KEY, failures INTEGER NOT NULL, rejected INTEGER NOT NULL, throttled INTEGER NOT NULL);
''')
        with connection: yield connection
    finally:
        connection.close()


def record_usage(rows, epoch, now=None):
    # Legacy column names are retained for rollback: upload stores raw inbound, download raw outbound.
    now = time.time() if now is None else now
    today = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime('%Y-%m-%d')
    rates={}
    with usage_database() as db:
        db.execute('BEGIN IMMEDIATE')
        for row in rows:
            old = db.execute('SELECT * FROM usage WHERE username=?', (row['username'],)).fetchone()
            if old and now < old['observed_at']: continue
            up, down = row['inbound'], row['outbound']
            same = old is not None and old['epoch'] == epoch
            delta_up = max(0, up-old['raw_up']) if same and up >= old['raw_up'] else up
            delta_down = max(0, down-old['raw_down']) if same and down >= old['raw_down'] else down
            interval=now-old['observed_at'] if old else 0
            valid_rate=same and 0<interval<=120 and up>=old['raw_up'] and down>=old['raw_down']
            rates[row['username']]=dict(download=delta_up/interval,upload=delta_down/interval) if valid_rate else None
            last_seen = now if row['sessions'] else (old['last_seen'] if old else 0)
            ip = row['ip'] if row['sessions'] and row['ip'] else (old['last_ip'] if old else '')
            changes = (old['ip_changes'] if old else 0) + int(bool(old and old['last_ip'] and ip and ip != old['last_ip']))
            if row['sessions'] and row['ip']:
                db.execute('INSERT INTO source_observations VALUES (?,?,?) ON CONFLICT(username,ip) DO UPDATE SET observed_at=excluded.observed_at', (row['username'], now, str(canonical_ip(row['ip']))))
                db.execute('DELETE FROM source_observations WHERE username=? AND ip NOT IN (SELECT ip FROM source_observations WHERE username=? ORDER BY observed_at DESC,ip LIMIT 256)', (row['username'], row['username']))
            db.execute('INSERT OR REPLACE INTO usage VALUES (?,?,?,?,?,?,?,?,?,?)',
                       (row['username'], epoch, up, down, (old['upload'] if old else 0)+delta_up,
                        (old['download'] if old else 0)+delta_down, last_seen, now, ip, changes))
            # The first sample is an imported baseline, not traffic proven to belong to today.
            if old and same and up >= old['raw_up'] and down >= old['raw_down']:
                db.execute('INSERT INTO daily VALUES (?,?,?,?) ON CONFLICT(username,day) DO UPDATE SET upload=upload+excluded.upload, download=download+excluded.download',
                           (row['username'], today, delta_up, delta_down))
        db.execute('DELETE FROM daily WHERE day < ?', ((datetime.datetime.fromtimestamp(now, datetime.timezone.utc)-datetime.timedelta(days=93)).strftime('%Y-%m-%d'),))
        db.execute('DELETE FROM source_observations WHERE observed_at < ?', (now-86400,))
    return rates


def guard_state():
    raw = read_text(TT_DIR / 'client-guard.json')
    state = json.loads(raw) if raw else {'policies': {}}
    for policy in state.get('policies',{}).values():
        watch = policy.get('source_watch')
        if watch is not None and (not isinstance(watch,dict) or type(watch.get('enabled')) is not bool
                                 or type(watch.get('minutes')) is not int or not 5 <= watch['minutes'] <= 1440
                                 or type(watch.get('threshold')) is not int or not 2 <= watch['threshold'] <= 100
                                 or type(watch.get('ipv6_prefix')) is not int or watch['ipv6_prefix'] not in (64,128)):
            raise ValueError('Некорректная политика наблюдения сетей; автоматическое применение остановлено.')
    return state


def canonical_ip(value):
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id:
        raise ValueError('Scoped IP is not supported')
    return address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address


def guard_capabilities():
    # No inference from aggregated metrics can enforce a per-user concurrent IP limit.
    return dict(source_watch=True, source_watch_enforcement=False, active_ip_limit=False, device_binding=False,
                reason='Штатный endpoint не предоставляет проверенный per-user admission hook и полный список активных IP. Для строгого IP-лимита нужна доработка endpoint; для ключа устройства также нужен клиент. Fail2ban блокирует IP целиком, а не людей или логины за NAT.')


def sharing_observations(db, user, policy, now=None):
    now = time.time() if now is None else now
    watch = policy.get('source_watch', {})
    if not watch.get('enabled'): return dict(enabled=False, alert=False, enforcement=False)
    window, threshold, prefix = watch['minutes'], watch['threshold'], watch['ipv6_prefix']
    rows = db.execute('SELECT observed_at,ip FROM source_observations WHERE username=? AND observed_at>=? AND observed_at<=? ORDER BY observed_at', (user, now-window*60, now)).fetchall()
    networks = set()
    for row in rows:
        address = canonical_ip(row['ip'])
        networks.add(str(ipaddress.ip_network(str(address)+'/'+str(prefix if address.version==6 else 32), strict=False)))
    return dict(enabled=True, alert=len(networks)>=threshold, observed_networks=len(networks), minutes=window,
                threshold=threshold, ipv6_prefix=prefix, retained_ips=len(rows), last_sample=rows[-1]['observed_at'] if rows else 0,
                history_limit=256,
                enforcement=False, simultaneous_ips=None,
                explanation='Наблюдавшиеся сети за окно, НЕ одновременные IP и НЕ число устройств. Это повод проверить доступ, не основание для автоматического бана.')


@admin_snapshot(10)
def client_metrics():
    # Serialize sampling across CLI/web processes; bracket the sample with the service epoch.
    rates={}
    with admin_lock():
        command = ['systemctl', 'show', 'trusttunnel', '--property=InvocationID', '--value']
        before_rc, before_epoch = run(command,timeout=3)
        live = fetch_client_metrics()
        if live['available']:
            rc, epoch = run(command, timeout=3)
            if rc or before_rc or epoch != before_epoch or not re.fullmatch(r'[a-fA-F0-9]{32}', epoch):
                live['accounting_error'] = 'Запуск endpoint неизвестен или изменился во время измерения; этот образец не начисляется.'
            else:
                rates=record_usage(live['clients'], epoch)
    records = {}
    observations = {}
    daily={}
    if USAGE_DB.exists():
        with usage_database() as db:
            records = {r['username']: dict(r) for r in db.execute('SELECT * FROM usage')}
            observations = {name:sharing_observations(db,name,policy) for name,policy in guard_state().get('policies',{}).items()}
            day=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')
            daily={row['username']:dict(row) for row in db.execute('SELECT username,upload,download FROM daily WHERE day=?',(day,))}
    rows = {row['username']: row for row in live['clients']}
    result = []
    for client in client_inventory():
        name = client['username']; current = rows.get(name, {})
        stored = records.get(name, {})
        sessions = current.get('sessions', 0) if live['available'] else None
        result.append(dict(username=name, enabled=client['enabled'], sessions=sessions,
                           online=bool(sessions) if sessions is not None else None,
                           inbound=current.get('inbound', 0), outbound=current.get('outbound', 0),
                           upload=stored.get('download', 0), download=stored.get('upload', 0),
                           total_bytes=stored.get('upload',0)+stored.get('download',0),
                           today_download=daily.get(name,{}).get('upload',0),today_upload=daily.get(name,{}).get('download',0),rate=rates.get(name),
                           observed_ip=current.get('ip','') if sessions else '',
                           last_observed_ip=stored.get('last_ip',''),
                           active_ip_count=0 if sessions==0 else None, ip_evidence='aggregate-only',
                           last_seen=stored.get('last_seen', 0), ip=current.get('ip') or stored.get('last_ip', ''),
                           sharing=observations.get(name, dict(enabled=False, alert=False, enforcement=False)),
                           ip_changes=stored.get('ip_changes', 0), observed_at=stored.get('observed_at', 0)))
    return dict(available=live['available'], clients=result, checked_at=time.time(),
                traffic_basis='Прикладной поток через endpoint, включая заголовки приложений; без внешних TLS/WARP/сетевых накладных расходов. Это не биллинг провайдера.',
                directions='inbound=скачано клиентом; outbound=отправлено клиентом. Проверено на официальном endpoint 1.1.0 по HTTP/2 и QUIC.',
                accounting_error=live.get('accounting_error', ''), guard=dict(GUARD_STATUS))


def guard_operation(action, values):
    if action == 'status':
        return json.dumps(dict(capabilities=guard_capabilities(), policies=guard_state().get('policies', {}), telemetry=client_metrics()), ensure_ascii=False, indent=2)
    if action == 'check':
        if values.get('confirm') != 'CONFIRMED': raise ValueError('Подтвердите немедленную проверку с возможным отзывом доступа.')
        return enforce_client_policies()
    with admin_lock():
        user = values.get('username', '')
        if user not in {c['username'] for c in client_inventory()}: raise ValueError('Клиент не найден.')
        state = guard_state(); policies = state.setdefault('policies', {})
        if values.get('confirm') != 'CONFIRMED': raise ValueError('Подтвердите изменение антишаринга.')
        if action == 'save':
            quota = values.get('quota_gib', '').strip(); until = values.get('expires', '').strip()
            if quota and not re.fullmatch(r'\d{1,6}(?:\.\d{1,3})?', quota): raise ValueError('Квота: 0–999999 ГиБ; пусто или 0 — без лимита.')
            quota_bytes = int(float(quota or '0') * 1073741824)
            expires = 0
            if until:
                try: expires = datetime.datetime.strptime(until, '%Y-%m-%dT%H:%M').replace(tzinfo=datetime.timezone.utc).timestamp()
                except ValueError: raise ValueError('Срок: дата и время UTC.') from None
                if expires <= time.time(): raise ValueError('Срок должен быть в будущем.')
            automatic = values.get('auto_suspend') == '1'
            if automatic and not (quota_bytes or expires): raise ValueError('Для автоотзыва нужна квота или срок.')
            if automatic and values.get('disconnect_ack') != '1': raise ValueError('Подтвердите краткое переподключение VPN при автоматическом отзыве.')
            if quota_bytes and not client_metrics()['available']: raise ValueError('Сначала включите и проверьте метрики клиентов. Без них квота не применяется.')
            policies[user] = dict(policies.get(user, {}), quota_bytes=quota_bytes, expires_at=expires, auto_suspend=automatic)
        elif action == 'remove':
            if user in policies:
                for key in ('quota_bytes','expires_at','auto_suspend'): policies[user].pop(key,None)
                if not policies[user]: policies.pop(user)
        elif action in ('watch-save','watch-remove'):
            if action == 'watch-remove':
                if user in policies:
                    policies[user].pop('source_watch', None)
                    if not policies[user]: policies.pop(user)
            else:
                try:
                    minutes = int(values.get('minutes','60'))
                    threshold = int(values.get('threshold','4'))
                    prefix = int(values.get('ipv6_prefix','64'))
                except ValueError: raise ValueError('Окно и порог должны быть числами.') from None
                if not 5 <= minutes <= 1440 or not 2 <= threshold <= 100 or prefix not in (64,128):
                    raise ValueError('Окно: 5–1440 минут; порог: 2–100 сетей; IPv6: /64 либо /128.')
                if not client_metrics()['available']: raise ValueError('Сначала включите и проверьте метрики клиентов.')
                policies.setdefault(user,{})['source_watch'] = dict(enabled=True, minutes=minutes, threshold=threshold, ipv6_prefix=prefix)
        elif action == 'restrict':
            raise ValueError('Транспортные лимиты не являются антишарингом. Пресет 1 H2 + 1 QUIC удалён: он может нарушить работу клиента. Текущие лимиты не менялись.')
        else: raise ValueError('Неизвестная операция антишаринга.')
        atomic_write(TT_DIR / 'client-guard.json', json.dumps(state))
        audit_log('guard-' + action, user)
        SNAPSHOT_CACHE.pop('client_metrics', None)
        return 'Политика сохранена. Наблюдение сетей только предупреждает: метрики не доказывают одновременное использование или число устройств. Изменение IP не вызывает бан. Квота и срок действуют отдельно; проверка каждые 15 секунд при работающей панели, возможен перерасход.'


def enforce_client_policies():
    global GUARD_STATUS
    with admin_lock():
        collection_error = ''
        try: data = client_metrics()
        except (OSError, ValueError, RuntimeError, sqlite3.Error):
            data = {'available':False, 'clients':[]}
            collection_error = 'Учёт недоступен. Квоты не отзывают доступ; сроки продолжают проверяться.'
        live = {c['username']: c for c in data['clients']}
        names = {c['username'] for c in load_clients()}
        suspended = []; pending = []
        for name, policy in guard_state().get('policies', {}).items():
            if name not in names: continue
            item = live.get(name, {})
            expired = policy.get('expires_at', 0) > 0 and time.time() >= policy['expires_at']
            over = data['available'] and not data.get('accounting_error') and policy.get('quota_bytes', 0) > 0 and item.get('upload', 0)+item.get('download', 0) >= policy['quota_bytes']
            if not (expired or over): continue
            if not policy.get('auto_suspend') or len(names) <= 1:
                pending.append(name); continue
            client_operation('disable', {'username': name})
            names.remove(name); suspended.append(name)
            audit_log('guard-auto-suspend', name + (' expired' if expired else ' quota'))
        GUARD_STATUS = dict(checked_at=time.time(), suspended=suspended, pending=pending, error=collection_error)
        return 'Отозвано учётных записей: '+str(len(suspended))+'. Требуют решения администратора: '+str(len(pending))+'. Последняя активная учётная запись автоматически не отключается.'


def usage_watcher():
    while True:
        try:
            SNAPSHOT_CACHE.pop('client_metrics', None)
            enforce_client_policies()
        except (OSError, ValueError, RuntimeError, sqlite3.Error):
            GUARD_STATUS.update(checked_at=time.time(), error='Проверка учёта/политик не завершена. Автоотзыв не подтверждён; проверьте endpoint и права на хранилище.')
        time.sleep(15)


def enrollment_identity(user, source=''):
    record = next((c for c in load_clients() if c['username'] == user), None)
    if record is None: raise ValueError('Клиент не найден или отключён.')
    body = json.dumps(record, sort_keys=True) + str(client_state().get('revisions',{}).get(user,'')) + read_text(TT_DIR/'hosts.toml') + read_text(TT_DIR/'certs/cert.pem') + read_text(TT_DIR/'panel-protection.json') + str(endpoint_port())
    # Legacy backends reject source-bound invitations rather than ignoring their restriction.
    if source: body += '\0invitation-source\0'+source
    return hashlib.sha256(body.encode()).hexdigest()


def enrollment_operation(action, values):
    with admin_lock():
        user = values.get('username', '')
        if not client_name_valid(user): raise ValueError('Некорректный логин.')
        if values.get('confirm') != 'CONFIRMED': raise ValueError('Подтвердите изменение выдачи профиля.')
        if user not in {c['username'] for c in client_inventory()}: raise ValueError('Клиент не найден.')
        with usage_database() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM enrollment WHERE expires < ? OR consumed=1', (time.time(),))
            db.execute('DELETE FROM enrollment_sources WHERE digest NOT IN (SELECT digest FROM enrollment)')
            if action == 'revoke':
                db.execute('DELETE FROM enrollment WHERE username=?', (user,))
                db.execute('DELETE FROM enrollment_sources WHERE digest NOT IN (SELECT digest FROM enrollment)')
                audit_log('enrollment-revoke', user)
                return 'Неиспользованные приглашения отозваны. Уже импортированный профиль отзывается сменой пароля или отключением клиента.'
            if action != 'issue': raise ValueError('Неизвестная операция выдачи.')
            source = values.get('source_cidr','').strip()
            if source:
                try:
                    if len(source)>64: raise ValueError()
                    if '/' not in source: source = str(canonical_ip(source))
                    network = ipaddress.ip_network(source, strict=False)
                    if network.prefixlen < (16 if network.version==4 else 48) or '%' in source: raise ValueError()
                    source = str(network)
                except ValueError: raise ValueError('Источник приглашения: один IP или CIDR не шире IPv4 /16 либо IPv6 /48.') from None
            identity = enrollment_identity(user,source)
            env = current_panel_env()
            if env.get('PANEL_TLS') != '1': raise ValueError('Для передачи приглашений включите HTTPS-панель.')
            minutes = int(values.get('minutes', '15'))
            protocol, kind = values.get('protocol', 'http2'), values.get('kind', 'static')
            if not 1 <= minutes <= 1440 or protocol not in ('http2','http3') or kind not in ('static','protected','tls-auth'):
                raise ValueError('Срок 1–1440 минут; транспорт и тип профиля выберите из списка.')
            if protocol == 'http3' and not quic_enabled(): raise ValueError('QUIC выключен.')
            if db.execute('SELECT count(*) FROM enrollment').fetchone()[0] >= 512: raise ValueError('Слишком много приглашений. Отзовите неиспользуемые.')
            token = secrets.token_urlsafe(32)
            db.execute('DELETE FROM enrollment WHERE username=?',(user,))
            db.execute('DELETE FROM enrollment_sources WHERE digest NOT IN (SELECT digest FROM enrollment)')
            digest = hashlib.sha256(token.encode()).hexdigest()
            db.execute('INSERT INTO enrollment (digest,username,protocol,kind,identity,expires,consumed) VALUES (?,?,?,?,?,?,0)', (digest, user, protocol, kind, identity, time.time()+minutes*60))
            if source: db.execute('INSERT INTO enrollment_sources VALUES (?,?)',(digest,source))
        audit_log('enrollment-issue', user)
        return 'Одноразовое приглашение ('+str(minutes)+' мин):\nhttps://'+domain()+':'+str(int(env.get('PANEL_PORT','8088')))+'/activate#'+token+'\n\nИсточник получения: '+(source or 'любой IP')+'. Первое нажатие «Получить профиль» погашает приглашение. Полученный tt-профиль можно скопировать: это защита выдачи, не аппаратная привязка. Не публикуйте приглашение.'


def redeem_enrollment(token, peer=''):
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token): raise ValueError('Приглашение недействительно или уже использовано.')
    with admin_lock(), usage_database() as db:
        db.execute('BEGIN IMMEDIATE')
        digest = hashlib.sha256(token.encode()).hexdigest()
        record = db.execute("SELECT e.*,COALESCE(s.source_cidr,'') AS source_cidr FROM enrollment e LEFT JOIN enrollment_sources s USING(digest) WHERE e.digest=? AND e.consumed=0 AND e.expires>?", (digest, time.time())).fetchone()
        if record is None: raise ValueError('Приглашение недействительно или уже использовано.')
        if record['source_cidr']:
            try: permitted = canonical_ip(peer) in ipaddress.ip_network(record['source_cidr'])
            except ValueError: permitted = False
            if not permitted: raise ValueError('Приглашение недействительно для этого источника.')
        if not secrets.compare_digest(record['identity'], enrollment_identity(record['username'],record['source_cidr'])):
            raise ValueError('Настройки изменились; запросите новое приглашение у администратора.')
        link = deeplink(record['username'], record['protocol'], record['kind'])
        picture = base64.b64encode(qr_image(link)).decode('ascii')
        db.execute('UPDATE enrollment SET consumed=1 WHERE digest=?', (digest,))
        audit_log('enrollment-redeem', record['username'])
        return dict(link=link, qr=picture)


def masque_operation(action, values):
    unit = 'warp-masque'
    binary, config = MASQUE_DIR / 'usque', MASQUE_DIR / 'config.json'
    if action == 'status':
        return 'MASQUE: ' + service_status(unit) + '\nSOCKS-совместимость: ' + service_status('warp-masque-bridge') + '\nЛокальный прокси: ' + MASQUE_ADDR + '\nМаршрут TrustTunnel: ' + forwarder_label()
    if action == 'check':
        return warp_probe(MASQUE_ADDR)
    if action == 'enable':
        if not binary.is_file() or not config.is_file():
            raise ValueError('Сначала установите WARP MASQUE.')
        return network_operation('routing-switch', {'mode': 'masque'})
    if action in ('stop', 'remove'):
        if MASQUE_ADDR in read_text(TT_DIR / 'vpn.toml'):
            raise ValueError('Сначала выберите Direct или WireGuard в маршрутизации, затем остановите MASQUE.')
        if action == 'remove' and values.get('confirm') != 'REMOVE':
            raise ValueError('Введите REMOVE для удаления MASQUE. Аккаунт останется в backup.')
        checked_run(['systemctl', 'disable', '--now', 'warp-masque-bridge', unit])
        if action == 'remove':
            (Path('/etc/systemd/system') / (unit + '.service')).unlink(missing_ok=True)
            Path('/etc/systemd/system/warp-masque-bridge.service').unlink(missing_ok=True)
            if MASQUE_DIR.exists():
                backup = MASQUE_DIR.with_name('warp-masque-backup-' + time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3))
                MASQUE_DIR.rename(backup)
            checked_run(['systemctl', 'daemon-reload'])
        audit_log('masque-' + action)
        return 'MASQUE остановлен.' if action == 'stop' else 'MASQUE удалён, аккаунт сохранён в /opt/warp-masque-backup-*.'
    if action == 'restart':
        checked_run(['systemctl', 'restart', unit])
        checked_run(['systemctl', 'restart', 'warp-masque-bridge'])
        return 'Сервис MASQUE перезапущен. Проверьте соединение отдельной командой.'
    if action not in ('install', 'reregister'):
        raise ValueError('Неизвестная операция MASQUE.')
    if action == 'reregister' and values.get('confirm') != 'REREGISTER':
        raise ValueError('Введите REREGISTER для замены аккаунта MASQUE.')
    if action == 'install' and values.get('accept_tos') != '1':
        raise ValueError('Подтвердите условия Cloudflare для регистрации WARP MASQUE.')
    if action == 'reregister' and MASQUE_ADDR in read_text(TT_DIR / 'vpn.toml'):
        raise ValueError('Перед перерегистрацией переключите исходящий маршрут с MASQUE.')
    MASQUE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(MASQUE_DIR, 0o700)
    bridge = MASQUE_DIR / 'bridge.py'
    bundled_bridge = Path(__file__).with_name('trusttunnel-masque-bridge.py')
    if bundled_bridge.exists():
        bridge_source = bundled_bridge.read_bytes().replace(b'\r\n', b'\n')
    else:
        url = 'https://raw.githubusercontent.com/Dmitry1244/trusttunnel-auto-installer/main/trusttunnel-masque-bridge.py'
        with urllib.request.urlopen(url, timeout=15) as response:
            bridge_source = response.read(32769).replace(b'\r\n', b'\n')
    if hashlib.sha256(bridge_source).hexdigest() != '1eba995783e869fb0ed9b34997beb1bd123d6dc7fd17a9331d8e13f0e351660f':
        raise RuntimeError('Контрольная сумма SOCKS-адаптера не совпала. Установка остановлена.')
    compile(bridge_source, str(bridge), 'exec')
    bridge.write_bytes(bridge_source); os.chmod(bridge, 0o600)
    if action == 'install':
        architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
        digests = {'amd64': '4117e20695078af9c11edecd1a826c009bbc7ea0b7f64458612b4198910bc313',
                   'arm64': 'c88b061c2a567f30813d7505637d1fb6fe7ec5898b5b61fd05122409fa5ad925'}
        if architecture not in digests:
            raise ValueError('MASQUE поддерживается установщиком на Linux amd64 и arm64.')
        with tempfile.TemporaryDirectory() as work:
            archive = Path(work) / 'usque.zip'
            url = f'https://github.com/Diniboy1123/usque/releases/download/{MASQUE_VERSION}/usque_{MASQUE_VERSION[1:]}_linux_{architecture}.zip'
            checked_run(['curl', '-fL', '--proto', '=https', '--max-time', '90', '-o', str(archive), url], timeout=100)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != digests[architecture]:
                raise RuntimeError('Контрольная сумма MASQUE не совпала. Установка остановлена.')
            with zipfile.ZipFile(archive) as zf:
                items = [item for item in zf.infolist() if Path(item.filename).name == 'usque' and not item.is_dir()]
                if len(items) != 1 or items[0].file_size > 100 * 1024 * 1024:
                    raise RuntimeError('Неожиданный архив MASQUE.')
                staged = MASQUE_DIR / 'usque.new'
                staged.write_bytes(zf.read(items[0])); os.chmod(staged, 0o755)
            checked_run([str(staged), 'version'])
            if binary.exists():
                shutil.copy2(binary, MASQUE_DIR / 'usque.previous')
            os.replace(staged, binary)
    previous = config.read_bytes() if config.exists() else None
    if action == 'reregister' or not config.exists():
        staged_config = MASQUE_DIR / ('registration-' + secrets.token_hex(5) + '.json')
        try:
            checked_run([str(binary), '-c', str(staged_config), 'register', '--accept-tos', '-n', 'TrustTunnel MASQUE'], timeout=60)
            record = json.loads(staged_config.read_text())
            if not record.get('private_key') or not record.get('endpoint_v4'):
                raise RuntimeError('Регистрация MASQUE не вернула полный конфиг.')
            os.chmod(staged_config, 0o600)
            if previous:
                backup = MASQUE_DIR / ('config-backup-' + time.strftime('%Y%m%d-%H%M%S') + '.json')
                backup.write_bytes(previous); os.chmod(backup, 0o600)
            os.replace(staged_config, config)
        finally:
            staged_config.unlink(missing_ok=True)
    unit_text = f'''[Unit]\nDescription=TrustTunnel WARP MASQUE proxy\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nWorkingDirectory={MASQUE_DIR}\nExecStart={binary} -c {config} socks -b 127.0.0.1 -p 40003 --always-reconnect --keepalive-period 25s --udp-timeout 300s\nRestart=always\nRestartSec=5\nUMask=0077\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nReadWritePaths={MASQUE_DIR}\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\n[Install]\nWantedBy=multi-user.target\n'''
    atomic_write(Path('/etc/systemd/system/warp-masque.service'), unit_text)
    bridge_unit = f'''[Unit]\nDescription=TrustTunnel MASQUE SOCKS compatibility\nAfter=warp-masque.service\nWants=warp-masque.service\nStartLimitIntervalSec=0\n\n[Service]\nExecStart=/usr/bin/python3 {bridge}\nRestart=always\nRestartSec=3\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\n[Install]\nWantedBy=multi-user.target\n'''
    atomic_write(Path('/etc/systemd/system/warp-masque-bridge.service'), bridge_unit)
    checked_run(['systemctl', 'daemon-reload'])
    checked_run(['systemctl', 'enable', '--now', unit])
    checked_run(['systemctl', 'restart', unit])
    checked_run(['systemctl', 'enable', '--now', 'warp-masque-bridge'])
    checked_run(['systemctl', 'restart', 'warp-masque-bridge'])
    audit_log('masque-' + action, MASQUE_VERSION)
    return 'MASQUE установлен и запущен на ' + MASQUE_ADDR + '. Проверьте TCP/UDP, затем включите маршрут MASQUE. Текущий маршрут TrustTunnel не изменён.'


def interface_enabled():
    return INTERFACE_DROPIN.exists()


def current_warp_backend():
    if interface_enabled(): return 'masque-interface' if read_text(INTERFACE_DIR / 'transport').strip() == 'masque' else 'wg-interface'
    cfg = tomllib.loads(read_text(TT_DIR / 'vpn.toml'))
    address = cfg.get('forward_protocol', {}).get('socks5', {}).get('address')
    return {SOCKS_ADDR:'wg-socks', MASQUE_ADDR:'masque-socks'}.get(address, '')


def warp_exit_ip(backend):
    command = ['curl', '-4', '-fsS', '--max-time', '10', 'https://ipv4.icanhazip.com']
    if backend.endswith('interface'):
        if current_warp_backend() != backend: raise ValueError('Сначала включите выбранный интерфейсный маршрут.')
        command = ['systemd-run', '--quiet', '--collect', '--wait', '--pipe', '--unit=tt-warp-ip-' + secrets.token_hex(4), '--slice=ttwarp.slice', *command]
    else:
        command += ['--proxy', 'socks5h://' + (SOCKS_ADDR if backend == 'wg-socks' else MASQUE_ADDR)]
    return str(ipaddress.ip_address(checked_run(command, timeout=20).strip()))


def warp_operation(values):
    backend, operation = values.get('backend', ''), values.get('operation', '')
    if backend not in ('wg-socks', 'masque-socks', 'wg-interface', 'masque-interface'):
        raise ValueError('Выберите вариант WARP.')
    if operation not in ('install', 'check', 'enable', 'disable', 'restart', 'reregister', 'remove', 'status', 'rotate'):
        raise ValueError('Неизвестная операция WARP.')
    if operation not in ('check', 'status') and values.get('confirm') != 'CONFIRMED':
        raise ValueError('Подтвердите изменение WARP кнопкой в диалоге.')
    if operation == 'rotate':
        before = warp_exit_ip(backend)
        warp_operation(dict(values, operation='restart'))
        time.sleep(1)
        after = warp_exit_ip(backend)
        audit_log('warp-ip-reconnect', backend)
        return f'До: {before}\nПосле: {after}\n' + ('IP изменился.' if before != after else 'IP остался прежним. Cloudflare не гарантирует смену адреса при переподключении.') + '\nПроверен один внешний сервис. Для разных сайтов выходной IP может отличаться. Клиенты и сертификаты TrustTunnel не менялись.'
    if backend.endswith('interface'):
        return admin_operation('interface-' + operation, dict(values, transport='masque' if backend == 'masque-interface' else 'wireguard', confirm='REMOVE' if operation == 'remove' else 'REREGISTER' if operation == 'reregister' else 'CONFIRMED'))
    if backend == 'masque-socks':
        if operation == 'disable':
            if current_warp_backend() == backend: admin_operation('routing-switch', {'mode':'direct'})
            return admin_operation('masque-stop', {})
        result = admin_operation('masque-' + operation, dict(values, confirm='REMOVE' if operation == 'remove' else 'REREGISTER' if operation == 'reregister' else 'CONFIRMED'))
        if operation == 'restart' and current_warp_backend() == backend: checked_run(['systemctl', 'restart', 'trusttunnel'])
        return result
    if operation in ('check', 'status'):
        return warp_probe(SOCKS_ADDR) if operation == 'check' else service_status('warp-wireproxy')
    if operation == 'enable': return admin_operation('routing-switch', {'mode':'warp'})
    if operation == 'restart':
        checked_run(['systemctl', 'restart', 'warp-wireproxy'])
        if current_warp_backend() == backend: checked_run(['systemctl', 'restart', 'trusttunnel'])
        return warp_probe(SOCKS_ADDR)
    if operation == 'disable':
        if current_warp_backend() == backend: admin_operation('routing-switch', {'mode':'direct'})
        checked_run(['systemctl', 'disable', '--now', 'warp-wireproxy'])
        return 'WARP SOCKS отключён. Если он был исходящим маршрутом, включён Direct с IP VPS.'
    return installer_operation({'install':'install-warp', 'reregister':'reregister-warp', 'remove':'remove-warp'}[operation], dict(values, confirm='REINSTALL'))


def interface_health():
    unit = 'tt-warp-health-' + secrets.token_hex(4)
    rc, output = run(['systemd-run', '--quiet', '--collect', '--wait', '--pipe', '--unit=' + unit,
                      '--slice=ttwarp.slice', 'curl', '-4', '-fsS', '--max-time', '12', '--noproxy', '*',
                      'https://www.cloudflare.com/cdn-cgi/trace'], timeout=20)
    fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    if rc or fields.get('warp') not in ('on', 'plus'):
        raise RuntimeError('Выход через интерфейс WARP не подтверждён.')
    return 'WARP: ' + fields['warp'] + ' · IP: ' + fields.get('ip', '?') + ' · colo: ' + fields.get('colo', '?')


def interface_operation(action, values):
    configured = read_text(INTERFACE_DIR / 'transport').strip() or 'wireguard'
    transport = values.get('transport', configured)
    if transport not in ('wireguard', 'masque'): raise ValueError('Неизвестный транспорт интерфейса.')
    helper = INTERFACE_DIR / 'policy.py'
    if action == 'status':
        return 'Маршрут: ' + forwarder_label() + '\nСервис: ' + service_status('warp-interface')
    if action == 'check':
        if not interface_enabled():
            raise ValueError('Интерфейсный маршрут сейчас выключен.')
        return interface_health() + '\n' + checked_run(['python3', str(helper), 'status', '--transport', configured])
    if action == 'enable':
        if interface_enabled():
            if transport != configured: raise ValueError('Сначала отключите текущий интерфейсный маршрут, затем включите другой.')
            return interface_operation('check', {})
        if not helper.is_file(): raise ValueError('Сначала установите интерфейсный WARP.')
        if transport != configured: interface_operation('install', {'transport':transport})
        cfg = TT_DIR / 'vpn.toml'
        old = read_text(cfg)
        parsed = tomllib.loads(old)
        if set(parsed.get('forward_protocol', {})) - {'direct', 'socks5'}:
            raise ValueError('Неподдерживаемый существующий forwarder.')
        state = {'previous_forwarder': parsed.get('forward_protocol', {}), 'ipv6_available': parsed.get('ipv6_available')}
        atomic_write(INTERFACE_DIR / 'previous-route.json', json.dumps(state))
        text = re.sub(r'(?ms)^\[forward_protocol(?:\.[^\]]+)?\][ \t]*\n.*?(?=^\[|\Z)', '', old)
        text += '\n[forward_protocol]\ndirect = {}\n'
        if run(['ip', '-6', 'route', 'get', '2606:4700:4700::1111'])[0]:
            text = re.sub(r'(?m)^ipv6_available\s*=.*$', 'ipv6_available = false', text)
        tomllib.loads(text)
        INTERFACE_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        try:
            checked_run(['systemctl', 'enable', '--now', 'warp-interface'])
            interface_health()
            atomic_write(INTERFACE_DROPIN, '[Unit]\nRequires=warp-interface.service\nAfter=warp-interface.service\n\n[Service]\nSlice=ttwarp.slice\n')
            checked_run(['systemctl', 'daemon-reload'])
            atomic_write(cfg, text)
            checked_run(['systemctl', 'restart', 'trusttunnel'])
            time.sleep(1)
            if service_status('trusttunnel') != 'active': raise RuntimeError('TrustTunnel не запустился.')
            checked_run(['systemctl', 'enable', '--now', 'warp-interface-watchdog.timer'])
        except Exception:
            INTERFACE_DROPIN.unlink(missing_ok=True)
            run(['systemctl', 'daemon-reload'])
            atomic_write(cfg, old)
            run(['systemctl', 'restart', 'trusttunnel'])
            run(['systemctl', 'disable', '--now', 'warp-interface'])
            run(['systemctl', 'disable', '--now', 'warp-interface-watchdog.timer'])
            if transport == 'masque': run(['systemctl', 'stop', 'warp-masque-tun'])
            raise
        DEEPLINK_CACHE.clear(); SNAPSHOT_CACHE.clear()
        audit_log('interface-enable')
        return 'TrustTunnel направлен через WARP-интерфейс без SOCKS. SSH и прочие службы используют обычный маршрут. Данные клиентов и сертификат не изменены.'
    if action == 'disable':
        if not interface_enabled(): return 'Интерфейсный маршрут уже выключен.'
        state = json.loads(read_text(INTERFACE_DIR / 'previous-route.json') or '{}')
        previous = state.get('previous_forwarder', {})
        address = previous.get('socks5', {}).get('address', '')
        mode = 'warp' if address == SOCKS_ADDR else 'masque' if address == MASQUE_ADDR else 'socks5' if address else 'direct'
        return network_operation('routing-switch', {'mode':mode, 'address':address})
    if action == 'restart':
        if not interface_enabled(): raise ValueError('Сначала включите интерфейсный маршрут.')
        checked_run(['systemctl', 'restart'] + (['warp-masque-tun'] if configured == 'masque' else []) + ['warp-interface', 'trusttunnel'])
        return interface_health()
    if action == 'remove':
        if interface_enabled(): raise ValueError('Сначала отключите интерфейсный маршрут.')
        if values.get('confirm') != 'REMOVE': raise ValueError('Для удаления введите REMOVE.')
        if configured == transport:
            run(['systemctl', 'disable', '--now', 'warp-interface'])
            run(['systemctl', 'disable', '--now', 'warp-interface-watchdog.timer'])
            for file in ('warp-interface.service', 'warp-interface-watchdog.service', 'warp-interface-watchdog.timer', 'ttwarp.slice'):
                Path('/etc/systemd/system', file).unlink(missing_ok=True)
            (INTERFACE_DIR / 'transport').unlink(missing_ok=True)
        account_dir = Path('/opt/warp-masque-tun') if transport == 'masque' else INTERFACE_DIR / 'wgcf'
        if transport == 'masque':
            run(['systemctl', 'disable', '--now', 'warp-masque-tun'])
            Path('/etc/systemd/system/warp-masque-tun.service').unlink(missing_ok=True)
        if account_dir.exists():
            backup = Path('/root/trusttunnel-warp-account-backups'); backup.mkdir(mode=0o700, exist_ok=True); os.chmod(backup, 0o700)
            shutil.copytree(account_dir, backup / (transport + '-' + time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(3)))
            shutil.rmtree(account_dir)
        checked_run(['systemctl', 'daemon-reload'])
        return 'Интерфейсный WARP удалён. Wireproxy и MASQUE не затронуты.'
    if action not in ('install', 'reregister'):
        raise ValueError('Неизвестная операция интерфейсного WARP.')
    if interface_enabled(): raise ValueError('Перед переустановкой или перерегистрацией сначала отключите интерфейсный маршрут.')
    if transport == 'masque' and run(['ip','link','show','ttmasq0'])[0] == 0 and service_status('warp-masque-tun') != 'active':
        raise ValueError('Имя ttmasq0 уже занято чужим интерфейсом. Его настройки не изменены.')
    if action == 'reregister' and values.get('confirm') != 'REREGISTER':
        raise ValueError('Для новой регистрации введите REREGISTER.')
    account_dir = INTERFACE_DIR / 'wgcf' if transport == 'wireguard' else Path('/opt/warp-masque-tun')
    account_file = account_dir / ('wgcf-account.toml' if transport == 'wireguard' else 'config.json')
    if not account_file.exists() and values.get('accept_tos') != '1':
        raise ValueError('Подтвердите условия Cloudflare WARP.')
    tool = Path('/opt/warp-proxy/bin/wgcf') if transport == 'wireguard' else MASQUE_DIR / 'usque'
    if not tool.exists(): raise ValueError('Сначала установите WARP WireGuard (wgcf) или MASQUE (usque) соответствующего типа.')
    run(['systemctl', 'disable', '--now', 'warp-interface'])
    run(['systemctl', 'stop', 'warp-masque-tun'])
    if transport == 'wireguard' and not shutil.which('wg'):
        checked_run(['apt-get', 'install', '-y', '--no-install-recommends', '--no-upgrade', 'wireguard-tools'], timeout=120)
    INTERFACE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True); os.chmod(INTERFACE_DIR, 0o700)
    if action == 'reregister' or not account_file.exists():
        with tempfile.TemporaryDirectory(prefix='.registration-', dir=INTERFACE_DIR) as staged:
            commands = ([str(tool), 'register', '--accept-tos'], [str(tool), 'generate']) if transport == 'wireguard' else ([str(tool), '-c', str(Path(staged) / 'config.json'), 'register', '--accept-tos', '-n', 'TrustTunnel MASQUE TUN'],)
            for command in commands:
                rc, output = run(command, cwd=staged, timeout=90)
                if rc: raise RuntimeError('Не удалось зарегистрировать отдельный WARP-аккаунт. Текущий аккаунт не изменён.')
            names = ('wgcf-account.toml', 'wgcf-profile.conf') if transport == 'wireguard' else ('config.json',)
            if any(not (Path(staged) / name).is_file() for name in names): raise RuntimeError('Нет нового профиля WARP.')
            if account_dir.exists():
                shutil.copytree(account_dir, INTERFACE_DIR / ('account-backup-' + time.strftime('%Y%m%d-%H%M%S')))
            account_dir.mkdir(mode=0o700, exist_ok=True)
            for name in names:
                atomic_write(account_dir / name, (Path(staged) / name).read_text())
    source = Path(__file__).resolve().with_name('trusttunnel-warp-interface.py')
    payload = source.read_bytes().replace(b'\r\n', b'\n') if source.is_file() else urllib.request.urlopen('https://raw.githubusercontent.com/Dmitry1244/trusttunnel-auto-installer/main/trusttunnel-warp-interface.py', timeout=20).read(100001)
    if hashlib.sha256(payload).hexdigest() != INTERFACE_HELPER_SHA256:
        raise RuntimeError('Контрольная сумма интерфейсного обработчика не совпала.')
    atomic_write(helper, payload.decode(), 0o700)
    atomic_write(Path('/etc/systemd/system/ttwarp.slice'), '[Unit]\nDescription=Isolated TrustTunnel WARP egress\n\n[Slice]\n')
    dependency = ' warp-masque-tun.service' if transport == 'masque' else ''
    if transport == 'masque':
        hook = INTERFACE_DIR / 'masque-up'
        atomic_write(hook, '#!/bin/sh\nexec /usr/bin/python3 /opt/warp-interface/policy.py refresh --transport masque\n', 0o700)
        tun_unit = f'''[Unit]\nDescription=TrustTunnel MASQUE native TUN\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nExecStart={tool} -c {account_file} nativetun -n ttmasq0 --always-reconnect -m 1280 --keepalive-period 25s --on-connect {hook}\nRestart=always\nRestartSec=3\nUMask=0077\nNoNewPrivileges=true\nProtectHome=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n'''
        atomic_write(Path('/etc/systemd/system/warp-masque-tun.service'), tun_unit)
    unit = f'''[Unit]\nDescription=TrustTunnel-only WARP interface policy\nRequires=ttwarp.slice{dependency}\nAfter=network-online.target ttwarp.slice{dependency}\nBefore=trusttunnel.service\nWants=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 {helper} start --transport {transport}\nExecStop=/usr/bin/python3 {helper} stop --transport {transport}\nUMask=0077\nNoNewPrivileges=true\nProtectHome=true\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n'''
    atomic_write(Path('/etc/systemd/system/warp-interface.service'), unit)
    atomic_write(Path('/etc/systemd/system/warp-interface-watchdog.service'), f'[Unit]\nDescription=Check TrustTunnel-only WARP interface\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {helper} watchdog --transport {transport}\n')
    atomic_write(Path('/etc/systemd/system/warp-interface-watchdog.timer'), '[Unit]\nDescription=Check WARP interface every minute\n\n[Timer]\nOnBootSec=1min\nOnUnitActiveSec=1min\n\n[Install]\nWantedBy=timers.target\n')
    atomic_write(INTERFACE_DIR / 'transport', transport + '\n')
    checked_run(['systemctl', 'daemon-reload'])
    audit_log('interface-' + action)
    return 'Интерфейсный WARP установлен с отдельной регистрацией. Текущий маршрут не изменён. Включение выполняется отдельно.'


def detach_interface_route(path, text):
    old = read_text(path); dropin = read_text(INTERFACE_DROPIN)
    state = json.loads(read_text(INTERFACE_DIR / 'previous-route.json') or '{}')
    prior_ipv6 = state.get('ipv6_available')
    if prior_ipv6 is not None:
        text = re.sub(r'(?m)^ipv6_available\s*=.*$', 'ipv6_available = ' + str(bool(prior_ipv6)).lower(), text)
    try:
        INTERFACE_DROPIN.unlink()
        checked_run(['systemctl', 'daemon-reload'])
        atomic_write(path, text)
        checked_run(['systemctl', 'restart', 'trusttunnel'])
        time.sleep(1)
        if service_status('trusttunnel') != 'active': raise RuntimeError('TrustTunnel не запустился.')
    except Exception:
        atomic_write(INTERFACE_DROPIN, dropin)
        atomic_write(path, old)
        run(['systemctl', 'daemon-reload']); run(['systemctl', 'restart', 'trusttunnel'])
        raise
    checked_run(['systemctl', 'disable', '--now', 'warp-interface'])
    run(['systemctl', 'disable', '--now', 'warp-interface-watchdog.timer'])
    run(['systemctl', 'stop', 'warp-masque-tun'])


def socks_udp_request(address, target_ip, target_port, query):
    host, port = address.rsplit(':', 1)
    def receive(sock, size):
        data = b''
        while len(data) < size:
            part = sock.recv(size - len(data))
            if not part:
                raise OSError('SOCKS5 закрыл управляющее соединение.')
            data += part
        return data
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.create_connection((host, int(port)), timeout=5) as control:
        udp.bind(('0.0.0.0', 0))
        control.settimeout(5)
        control.sendall(b'\x05\x01\x00')
        if receive(control, 2) != b'\x05\x00':
            raise OSError('SOCKS5 отклонил авторизацию.')
        # Match TrustTunnel: reserve the UDP port before UDP ASSOCIATE.
        control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00' + struct.pack('!H', udp.getsockname()[1]))
        header = receive(control, 4)
        if header[0] != 5 or header[1] != 0:
            raise OSError('SOCKS5 отклонил UDP ASSOCIATE.')
        if header[3] == 1:
            relay = socket.inet_ntop(socket.AF_INET, receive(control, 4))
        else:
            raise OSError('Неизвестный адрес UDP relay.')
        relay_port = struct.unpack('!H', receive(control, 2))[0]
        if relay in ('0.0.0.0', '::'):
            relay = host
        udp.settimeout(5)
        start = time.monotonic()
        udp.sendto(b'\x00\x00\x00\x01' + socket.inet_aton(target_ip) + struct.pack('!H', target_port) + query, (relay, relay_port))
        packet, _ = udp.recvfrom(8192)
        if len(packet) < 10 or packet[:3] != b'\x00\x00\x00':
            raise OSError('Неверный ответ UDP relay.')
        offset = 10 if packet[3] == 1 else 22 if packet[3] == 4 else 7 + packet[4] if packet[3] == 3 else len(packet)
        reply = packet[offset:]
        return reply, round((time.monotonic() - start) * 1000, 1)


def socks_udp_dns(address):
    token = secrets.token_bytes(2)
    query = token + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
    reply, elapsed = socks_udp_request(address, '1.1.1.1', 53, query)
    if len(reply) < 12 or reply[:2] != token or not reply[2] & 0x80 or reply[3] & 0x0f or reply[6:8] == b'\x00\x00':
        raise OSError('Не получен корректный DNS-ответ через UDP.')
    return elapsed


def socks_udp_stun(address, target_ip):
    token = secrets.token_bytes(12)
    query = struct.pack('!HHI', 1, 0, 0x2112a442) + token
    reply, elapsed = socks_udp_request(address, target_ip, 19302, query)
    if len(reply) < 20 or reply[:2] != b'\x01\x01' or reply[4:8] != b'\x21\x12\xa4\x42' or reply[8:20] != token:
        raise OSError('Не получен корректный ответ STUN.')
    pos, end = 20, 20 + int.from_bytes(reply[2:4], 'big')
    if end > len(reply):
        raise OSError('Оборванный ответ STUN.')
    while pos + 4 <= end:
        tag, size = struct.unpack('!HH', reply[pos:pos + 4])
        value = reply[pos + 4:pos + 4 + size]
        if tag in (1, 0x20) and len(value) >= 8 and value[1] == 1:
            raw = value[4:8]
            if tag == 0x20: raw = bytes(a ^ b for a, b in zip(raw, b'\x21\x12\xa4\x42'))
            return elapsed, socket.inet_ntoa(raw)
        pos += 4 + (size + 3) // 4 * 4
    raise OSError('STUN не вернул внешний IPv4.')


def warp_probe(address):
    rc, trace = run(['curl', '-fsS', '--max-time', '12', '--proxy', 'socks5h://' + address,
                     'https://www.cloudflare.com/cdn-cgi/trace'], timeout=15)
    fields = dict(line.split('=', 1) for line in trace.splitlines() if '=' in line)
    lines = ['Прокси: ' + address]
    if rc == 0 and fields.get('warp') in ('on', 'plus'):
        lines += ['TCP: OK', 'Выходной IP: ' + fields.get('ip', '—'), 'Cloudflare colo: ' + fields.get('colo', '—')]
    else:
        lines.append('TCP: ошибка, выход через WARP не подтверждён.')
    try:
        lines.append('UDP: OK · DNS-ответ за ' + str(socks_udp_dns(address)) + ' мс')
    except OSError as exc:
        lines.append('UDP: ошибка · ' + str(exc))
    lines.append('Тест проверяет выход с VPS. Задержка от устройства и стабильность видеопотока здесь не измеряются.')
    return '\n'.join(lines)


def apply_endpoint_file(path, text):
    tomllib.loads(text)
    old = read_text(path)
    atomic_write(Path(str(path) + '.admin-backup'), old)
    atomic_write(path, text)
    try:
        checked_run(['systemctl', 'restart', 'trusttunnel'])
        time.sleep(0.25)
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
        if len(item) > 2048: raise ValueError('Адрес DNS слишком длинный (максимум 2048 символов).')
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
    aliases = {'security-ban':'ban','security-unban':'unban','security-fail2ban':'settings',
               'security-ignore-add':'ignore-add','security-ignore-remove':'ignore-remove'}
    if action in aliases: return fail2ban_operation(aliases[action],values)
    if action == 'security-open': return firewall_operation('rule',dict(values,decision='allow'))
    if action == 'security-close':
        raise ValueError('Для безопасного удаления выберите конкретную строку в списке UFW; закрытие порта без проверки версии списка запрещено.')
    if action == 'security-remediate':
        return security_remediate(values)
    if action == 'security-scan':
        SNAPSHOT_CACHE.pop('security_snapshot', None)
        result = security_snapshot()
        atomic_write(SECURITY_REPORT, json.dumps(result, ensure_ascii=False))
        return '\n\n'.join(item['title'] + ': ' + item['detail'] for item in result['checks']) + '\n\n' + recommendations()
    if action == 'security-ping':
        return configure_echo_policy(values)
    if action == 'security-audit':
        data = security_snapshot()
        return '\n\n'.join(item['title'] + ': ' + item['detail'] for item in data['checks'])
    if action == 'security-listeners':
        return checked_run(['ss', '-lntup'])
    if action == 'security-logins':
        return recent_logs('ssh', 100) + '\n' + recent_logs('sshd', 100)
    if action == 'security-ignore-list':
        return checked_run(['fail2ban-client', 'get', 'sshd', 'ignoreip'])
    if action == 'security-status':
        report = '\n'.join(run(cmd)[1] for cmd in (['ufw', 'status', 'numbered'], ['fail2ban-client', 'status', 'sshd'], ['sshd', '-T']))
        return report + '\n\nSSH jail: ' + json.dumps(jail_settings(), ensure_ascii=False)
    if action == 'routing-check':
        return diagnostics_output()
    if action == 'routing-current':
        return 'Настроенный исходящий маршрут TrustTunnel: '+forwarder_label()
    if action == 'routing-rule-reset':
        if values.get('confirm') != 'CONFIRMED': raise ValueError('Подтвердите удаление правил.')
        if strict_protection_locked(): raise ValueError('Сначала отключите строгую TLS/ClientHello-защиту.')
        apply_endpoint_file(managed_rules_path(), '# Empty rules file\n')
        audit_log('routing-rule-reset')
        return 'Правила сброшены.'
    if action == 'routing-switch':
        mode = values.get('mode', '')
        current = current_warp_backend()
        expected = {'warp':'wg-socks','masque':'masque-socks','interface':'wg-interface','interface-masque':'masque-interface'}
        cfg = tomllib.loads(read_text(TT_DIR/'vpn.toml'))
        socks = cfg.get('forward_protocol',{}).get('socks5',{}).get('address','')
        if (mode in expected and current == expected[mode]) or (mode == 'direct' and not current and not socks) or (mode == 'socks5' and not current and socks and socks == values.get('address','').strip()):
            return 'Этот маршрут уже настроен; перезапуск VPN не выполнялся. Для проверки доступности используйте диагностику маршрута.'
        if mode in ('interface', 'interface-masque'):
            return interface_operation('enable', dict(values, transport='masque' if mode == 'interface-masque' else 'wireguard'))
        address = {'warp': SOCKS_ADDR, 'masque': MASQUE_ADDR}.get(mode, values.get('address', '').strip())
        if mode not in ('direct', 'warp', 'masque', 'socks5'):
            raise ValueError('Некорректный маршрут.')
        if mode != 'direct':
            target = urllib.parse.urlsplit('socks5://' + address)
            if not target.hostname or not target.port or target.username or target.password or target.path or target.query or target.fragment:
                raise ValueError('Укажите SOCKS5 как host:port, без логина и пароля.')
            if mode in ('warp', 'masque'):
                checked_run(['systemctl', 'enable', '--now'] + (['warp-masque', 'warp-masque-bridge'] if mode == 'masque' else ['warp-wireproxy']))
            check = checked_run(['curl', '-fsS', '--max-time', '15', '--proxy', 'socks5h://' + address, 'https://www.cloudflare.com/cdn-cgi/trace'], timeout=20)
            if mode in ('warp', 'masque') and 'warp=on' not in check and 'warp=plus' not in check:
                raise RuntimeError('WARP не подтвердил работоспособность. Маршрут не изменён.')
            if mode == 'masque':
                try:
                    socks_udp_dns(address)
                except OSError as exc:
                    raise RuntimeError('MASQUE не прошёл проверку UDP. Маршрут не изменён: ' + str(exc)) from None
        path = TT_DIR / 'vpn.toml'
        cfg = read_text(path)
        parsed = tomllib.loads(cfg)
        if set(parsed.get('forward_protocol', {})) - {'direct', 'socks5'}:
            raise ValueError('Неподдерживаемый существующий маршрут, изменение отменено.')
        cfg = re.sub(r'(?ms)^\[forward_protocol(?:\.[^\]]+)?\][^\[]*', '', cfg)
        cfg += '\n[forward_protocol]\n' + ('direct = {}\n' if mode == 'direct' else '[forward_protocol.socks5]\naddress = ' + json.dumps(address) + '\nextended_auth = false\n')
        if interface_enabled(): detach_interface_route(path, cfg)
        else: apply_endpoint_file(path, cfg)
        audit_log(action, mode)
        return 'Исходящий маршрут: ' + forwarder_label()
    if action in ('routing-rule-add', 'routing-rule-delete'):
        if strict_protection_locked():
            raise ValueError('Сначала отключите строгий ClientHello-фильтр. Иначе изменение может обойти защиту или нарушить её откат.')
        path = managed_rules_path()
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


@contextmanager
def torrent_lock(nonblocking=False):
    import fcntl
    TORRENT_STATE.parent.mkdir(parents=True,exist_ok=True)
    with TORRENT_LOCK, TORRENT_STATE.with_suffix('.lock').open('a') as lock:
        os.chmod(lock.name,0o600)
        try: fcntl.flock(lock,fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        except BlockingIOError:
            yield False
            return
        try: yield True
        finally: fcntl.flock(lock,fcntl.LOCK_UN)


def torrent_ports(value):
    entries = value.split(',') if value.strip() else []
    if len(entries)>12: raise ValueError('Не более 12 портов или диапазонов.')
    result=[]
    reserved={53,80,443} | {port for port,proto in protected_ports()}
    for item in entries:
        match=re.fullmatch(r'([0-9]{1,5})(?::([0-9]{1,5}))?',item.strip())
        if not match: raise ValueError('Порты: числа или диапазоны через запятую, например 6881:6889,6969,51413.')
        lo,hi=int(match[1]),int(match[2] or match[1])
        if not 1<=lo<=hi<=65535 or any(lo<=port<=hi for port in reserved):
            raise ValueError('Диапазон некорректен или включает DNS, HTTP(S), SSH, VPN либо панель.')
        token=str(lo) if lo==hi else f'{lo}:{hi}'
        if token not in result: result.append(token)
    return result


def torrent_state():
    raw=read_text(TORRENT_STATE)
    state=json.loads(raw) if raw else {'enabled':False,'mode':'signatures','ports':[]}
    if not isinstance(state,dict) or state.get('mode') not in ('signatures','ports') or type(state.get('enabled')) is not bool:
        raise ValueError('Повреждены настройки фильтра BitTorrent; автоматическое изменение остановлено.')
    if not isinstance(state.get('ports',[]),list) or len(state.get('ports',[]))>12 or any(not isinstance(v,str) or not re.fullmatch(r'[0-9]{1,5}(?::[0-9]{1,5})?',v) for v in state.get('ports',[])):
        raise ValueError('Некорректные сохранённые порты BitTorrent.')
    if not isinstance(state.get('retired',[]),list) or len(state.get('retired',[]))>4: raise ValueError('Некорректный журнал фильтра BitTorrent.')
    for ctx in [state.get('active'),state.get('pending'),*state.get('retired',[])]:
        if ctx:
            if not isinstance(ctx,dict): raise ValueError('Некорректный контекст фильтра BitTorrent.')
            if not re.fullmatch(r'TT_BT_[0-9a-f]{12}',ctx.get('chain','')): raise ValueError('Некорректная управляемая цепочка BitTorrent.')
            torrent_cgroup_valid(ctx.get('cgroup',''))
    return state


def torrent_cgroup_valid(value):
    if not re.fullmatch(r'[A-Za-z0-9_./@:-]{1,256}/trusttunnel\.service',value) or any(part in ('','..','.') for part in value.split('/')):
        raise ValueError('Не удалось определить отдельный cgroup TrustTunnel; весь сервер фильтроваться не будет.')
    return value


def torrent_context():
    data=checked_run(['systemctl','show','trusttunnel','--property=ControlGroup','--property=InvocationID','--property=MainPID'])
    values=dict(line.split('=',1) for line in data.splitlines() if '=' in line)
    cgroup=torrent_cgroup_valid(values.get('ControlGroup','').lstrip('/'))
    if not values.get('MainPID','').isdigit() or int(values['MainPID'])<=0: raise ValueError('TrustTunnel не запущен; фильтр не применяется к другим процессам.')
    invocation=values.get('InvocationID','')
    if not re.fullmatch(r'[0-9a-f]{32}',invocation): raise ValueError('Не удалось проверить текущий запуск TrustTunnel.')
    return {'cgroup':cgroup,'invocation':invocation}


def torrent_jump(ctx):
    return ['OUTPUT','-m','cgroup','--path',torrent_cgroup_valid(ctx['cgroup']),'-m','comment','--comment',TORRENT_MARKER,'-j',ctx['chain']]


def torrent_program(ctx,mode,ports):
    chain=ctx['chain']
    if not re.fullmatch(r'TT_BT_[0-9a-f]{12}',chain): raise ValueError('Некорректная цепочка.')
    rules=[['-N',chain]]
    # Service replies are not tunneled client egress, including QUIC replies.
    for proto in ('tcp','udp'):
        rules.append(['-A',chain,'-p',proto,'--sport',str(int(endpoint_port())),'-m','comment','--comment',TORRENT_MARKER,'-j','RETURN'])
    for proto,signature in TORRENT_SIGNATURES:
        rules.append(['-A',chain,'-p',proto,'-m','string','--algo','kmp','--to','256','--hex-string','|'+signature+'|',
                      '-m','comment','--comment',TORRENT_MARKER,'-j','DROP'])
    if mode=='ports':
        for proto in ('tcp','udp'):
            for port in ports:
                rules.append(['-A',chain,'-p',proto,'--dport',port,'-m','comment','--comment',TORRENT_MARKER,'-j','DROP'])
    rules.append(['-A',chain,'-m','comment','--comment',TORRENT_MARKER,'-j','RETURN'])
    def argument(value): return json.dumps(value) if ' ' in value else value
    return '*mangle\n'+'\n'.join(' '.join(argument(value) for value in args) for args in rules)+'\nCOMMIT\n'


def torrent_remove(ctx):
    if not ctx: return
    for tool in ('iptables','ip6tables'):
        base=[tool,'-w','5','-t','mangle']
        all_rules=checked_run(base+['-S'])
        parsed=[shlex.split(line) for line in all_rules.splitlines()]
        if ['-N',ctx['chain']] not in parsed: continue
        for parts in parsed:
            if parts[:2]!=['-A',ctx['chain']]: continue
            if parts[:1]==['-A'] and ('--comment' not in parts or parts[parts.index('--comment')+1]!=TORRENT_MARKER):
                raise ValueError('Управляемая цепочка изменена извне; чужие правила не удаляются.')
        output=checked_run(base+['-S','OUTPUT'])
        numbers=[]; number=0
        for line in output.splitlines():
            parts=shlex.split(line)
            if parts[:2]!=['-A','OUTPUT']: continue
            number+=1
            if parts[-2:]!=['-j',ctx['chain']]: continue
            if '--comment' not in parts or parts[parts.index('--comment')+1]!=TORRENT_MARKER:
                raise ValueError('Есть внешняя ссылка на цепочку BitTorrent; автоматическое удаление остановлено.')
            numbers.append(number)
        # A private mangle transaction does not flush UFW, WARP or other chains.
        lines=[f'-D OUTPUT {n}' for n in reversed(numbers)]+['-F '+ctx['chain'],'-X '+ctx['chain']]
        rc,out=run([tool+'-restore','--wait','5','--noflush'],input_text='*mangle\n'+'\n'.join(lines)+'\nCOMMIT\n')
        if rc: raise RuntimeError('Не удалось убрать только цепочку BitTorrent: '+out)


def torrent_script():
    script=str(Path(__file__).resolve())
    if script not in ('/usr/local/sbin/trusttunnel-panel.py','/usr/local/lib/trusttunnel/admin.py'):
        raise ValueError('Сначала установите актуальный backend панели в штатный путь; staging не включается в автозапуск.')
    return script


def torrent_units():
    script=torrent_script()
    marker='# Managed by TrustTunnel torrent filter\n'
    command='/usr/bin/python3 '+script+' --torrent-reconcile'
    files={TORRENT_DROPIN:marker+'[Service]\nExecStartPost=-'+command+'\n',
           SCHEDULE_DIR/'trusttunnel-torrent-filter.service':marker+'[Unit]\nDescription=Reconcile TrustTunnel BitTorrent restrictions\nAfter=trusttunnel.service\n[Service]\nType=oneshot\nExecStart='+command+'\nUMask=0077\n',
           SCHEDULE_DIR/'trusttunnel-torrent-filter.timer':marker+'[Unit]\nDescription=Check TrustTunnel BitTorrent restrictions\n[Timer]\nOnBootSec=20s\nOnUnitActiveSec=30s\nAccuracySec=5s\n[Install]\nWantedBy=timers.target\n'}
    originals={path:read_text(path) for path in files}
    if any(text and not text.startswith(marker) for text in originals.values()): raise ValueError('Имя unit/drop-in занято; чужие файлы не перезаписываются.')
    try:
        for path,text in files.items(): atomic_write(path,text,0o644)
        checked_run(['systemctl','daemon-reload'])
        checked_run(['systemctl','enable','--now','trusttunnel-torrent-filter.timer'])
    except Exception:
        if not originals.get(SCHEDULE_DIR/'trusttunnel-torrent-filter.timer'):
            run(['systemctl','disable','--now','trusttunnel-torrent-filter.timer'])
        for path,text in originals.items():
            if text: atomic_write(path,text,0o644)
            else: path.unlink(missing_ok=True)
        run(['systemctl','daemon-reload'])
        raise


def torrent_apply(state,context,mode,ports,install_units=False):
    candidate=dict(context,chain='TT_BT_'+secrets.token_hex(6))
    program=torrent_program(candidate,mode,ports)
    for tool in ('iptables','ip6tables'):
        rc,out=run([tool+'-restore','--wait','5','--noflush','--test'],input_text=program)
        if rc: raise RuntimeError('Ядро/iptables не поддерживает нужный фильтр IPv4/IPv6; изменения не применены: '+out)
    staged=dict(state,pending=candidate)
    atomic_write(TORRENT_STATE,json.dumps(staged))
    try:
        for tool in ('iptables','ip6tables'):
            rc,out=run([tool+'-restore','--wait','5','--noflush'],input_text=program)
            if rc: raise RuntimeError(out)
        for tool in ('iptables','ip6tables'):
            checked_run([tool,'-w','5','-t','mangle','-I','OUTPUT','1',*torrent_jump(candidate)[1:]])
        if install_units: torrent_units()
        retired=[state['active']] if state.get('active') else []
        updated={'enabled':True,'mode':mode,'ports':ports,'active':candidate,'retired':retired}
        atomic_write(TORRENT_STATE,json.dumps(updated))
    except Exception:
        try:
            torrent_remove(candidate)
            atomic_write(TORRENT_STATE,json.dumps(state))
        except Exception:
            raise RuntimeError('Применение прервано; журнал восстановления сохранён. Проверьте состояние фильтра, основной firewall не сбрасывался.') from None
        raise
    for old in retired: torrent_remove(old)
    updated.pop('retired',None)
    atomic_write(TORRENT_STATE,json.dumps(updated))
    return updated


def torrent_reconcile():
    with torrent_lock(nonblocking=True) as acquired:
        if not acquired: return
        state=torrent_state()
        recovering=bool(state.get('pending') or state.get('retired'))
        for ctx in [state.get('pending'),*state.get('retired',[])]:
            if ctx: torrent_remove(ctx)
        state.pop('pending',None); state.pop('retired',None)
        if recovering: atomic_write(TORRENT_STATE,json.dumps(state))
        if not state['enabled']: return
        context=torrent_context()
        active=state.get('active')
        if active and all(active.get(key)==value for key,value in context.items()):
            if all(run([tool,'-w','5','-t','mangle','-C',*torrent_jump(active)])[0]==0 for tool in ('iptables','ip6tables')):
                return
        torrent_apply(state,context,state['mode'],state.get('ports',[]))


@cached_snapshot(10)
def torrent_snapshot():
    state=torrent_state()
    result={'enabled':state['enabled'],'active':False,'mode':state['mode'],'ports':state.get('ports',[]),'dropped':0,
            'warning':'Частичная защита: не блокирует весь зашифрованный, фрагментированный или инкапсулированный P2P-трафик.'}
    result['recovering']=bool(state.get('pending') or state.get('retired'))
    if result['recovering']: result['error']='Нужно завершить восстановление управляемых цепочек; состояние не подтверждено.'
    if not state['enabled']: return result
    try:
        context=torrent_context(); active=state.get('active',{})
        if not active or any(active.get(k)!=v for k,v in context.items()): raise ValueError('Ожидается применение к текущему запуску TrustTunnel.')
        for tool in ('iptables','ip6tables'):
            if run([tool,'-w','5','-t','mangle','-C',*torrent_jump(active)])[0]: raise ValueError('Правила отсутствуют; фильтрация не подтверждена.')
            counters=checked_run([tool,'-w','5','-t','mangle','-n','-v','-x','-L',active['chain']])
            result['dropped']+=sum(int(m[1]) for m in re.finditer(r'(?m)^\s*(\d+)\s+\d+\s+DROP\s',counters))
        result['active']=not state.get('pending') and not state.get('retired')
        if not result['active']: result['error']='Нужно завершить восстановление управляемых цепочек.'
    except (ValueError,RuntimeError,OSError) as exc: result['error']=str(exc)
    return result


def torrent_operation(action,values):
    if action=='status': return json.dumps(torrent_snapshot(),ensure_ascii=False,indent=2)
    if action not in ('save','disable'): raise ValueError('Неизвестная операция фильтра BitTorrent.')
    confirmed(values)
    require_no_firewall_pending()
    with admin_lock(),torrent_lock() as acquired:
        state=torrent_state()
        for ctx in [state.get('pending'),*state.get('retired',[])]:
            if ctx: torrent_remove(ctx)
        state.pop('pending',None); state.pop('retired',None)
        if action=='disable':
            torrent_remove(state.get('active'))
            disabled=dict(state,enabled=False)
            disabled.pop('active',None); atomic_write(TORRENT_STATE,json.dumps(disabled))
            if read_text(SCHEDULE_DIR/'trusttunnel-torrent-filter.timer').startswith('# Managed by TrustTunnel torrent filter\n'):
                checked_run(['systemctl','disable','--now','trusttunnel-torrent-filter.timer'])
            message='Ограничение BitTorrent отключено. Удалены только его управляемые цепочки; WARP и UFW не сбрасывались.'
        else:
            if values.get('limits_ack')!='1': raise ValueError('Подтвердите ограничения частичной защиты от BitTorrent.')
            mode=values.get('mode','signatures')
            if mode not in ('signatures','ports'): raise ValueError('Неизвестный режим BitTorrent.')
            ports=torrent_ports(values.get('ports','6881:6889,6969,51413')) if mode=='ports' else []
            if mode=='ports' and not ports: raise ValueError('Выберите хотя бы один порт или режим только сигнатур.')
            context=torrent_context()
            torrent_apply(state,context,mode,ports,install_units=True)
            message='Ограничение BitTorrent применено только к выходу TrustTunnel. Маршрут, сертификаты и клиентские профили не менялись. Полная блокировка всех торрентов не гарантируется.'
        SNAPSHOT_CACHE.pop('torrent_snapshot',None)
        audit_log('torrent-'+action)
        return message


def configure_echo_policy(values):
    require_no_firewall_pending()
    if values.get('confirm') != 'CONFIRMED': raise ValueError('Подтвердите настройку входящего ping.')
    if values.get('enabled') not in ('0','1'): raise ValueError('Выберите разрешение или блокировку ping.')
    if 'Status: active' not in checked_run(['ufw','status']): raise ValueError('Для управляемого ping нужен активный UFW. Правила не изменены.')
    block = values['enabled'] == '0'
    files = [(UFW_DIR/'before.rules','iptables-restore','ufw-before-input','icmp','echo-request'),
             (UFW_DIR/'before6.rules','ip6tables-restore','ufw6-before-input','ipv6-icmp','echo-request')]
    originals = {}
    try:
        for path,tool,chain,protocol,kind in files:
            text = read_text(path)
            if not text: raise ValueError('Не найден файл правил UFW: '+path.name)
            originals[path] = text
            text = ''.join(line for line in text.splitlines(keepends=True) if '--comment TT_PANEL_PING' not in line)
            if block:
                rule = '-A '+chain+' ! -i lo -p '+protocol+' --icmp'+('v6' if protocol=='ipv6-icmp' else '')+'-type '+kind+' -m comment --comment TT_PANEL_PING -j DROP\n'
                boundary = re.search(r'(?m)^-A ',text)
                if not boundary: raise ValueError('Не распознана структура UFW; автоматическое изменение отменено.')
                text = text[:boundary.start()] + rule + text[boundary.start():]
            rc,_ = run([tool,'--test'],input_text=text,timeout=10)
            if rc: raise ValueError('Проверка '+path.name+' не прошла. Правила не применены.')
            atomic_write(path,text)
        checked_run(['ufw','reload'])
    except Exception:
        for path,text in originals.items(): atomic_write(path,text)
        if originals: run(['ufw','reload'])
        raise
    SNAPSHOT_CACHE.clear(); audit_log('security-ping','allow' if not block else 'block')
    return 'Входящие echo-request '+('заблокированы' if block else 'возвращены к исходной политике UFW')+'. Необходимые ICMPv6, Path MTU Discovery, loopback, SSH и VPN-порты не изменялись.'


def security_watcher():
    while True:
        try:
            SNAPSHOT_CACHE.pop('security_snapshot',None)
            atomic_write(SECURITY_REPORT,json.dumps(security_snapshot(),ensure_ascii=False))
        except (OSError,ValueError,RuntimeError):
            pass
        time.sleep(6*3600)


SCHEDULE_KINDS = {'reboot':'Перезагрузка VPS', 'packages':'Обновление пакетов ОС', 'security':'Проверка безопасности', 'releases':'Проверка версий endpoint'}


def schedule_operation(action, values):
    if action == 'status':
        return checked_run(['systemctl','list-timers','--all','trusttunnel-scheduled-*.timer','--no-pager'])
    kind = values.get('kind','')
    if kind not in SCHEDULE_KINDS: raise ValueError('Неизвестная задача расписания.')
    if values.get('confirm') != 'CONFIRMED': raise ValueError('Подтвердите изменение расписания.')
    unit = 'trusttunnel-scheduled-'+kind
    if action == 'disable':
        checked_run(['systemctl','disable','--now',unit+'.timer'])
        audit_log('schedule-disable',kind)
        return 'Расписание отключено. Уже выполняющаяся задача не прерывается.'
    if action != 'save': raise ValueError('Неизвестная операция расписания.')
    clock = values.get('time','03:30'); day = values.get('day','daily')
    if not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d',clock) or day not in ('daily','Mon','Tue','Wed','Thu','Fri','Sat','Sun'):
        raise ValueError('Задайте время ЧЧ:ММ и день из списка.')
    if kind == 'packages' and values.get('updates_ack') != '1': raise ValueError('Подтвердите, что обновления ОС могут перезапускать службы.')
    calendar = ('' if day=='daily' else day+' ')+'*-*-* '+clock+':00'
    checked_run(['systemd-analyze','calendar',calendar],timeout=5)
    command = {'reboot':'/usr/bin/systemctl reboot',
               'packages':'/usr/local/sbin/trusttunnel-os-maintenance',
               'security':'/usr/bin/python3 /usr/local/sbin/trusttunnel-panel.py --admin security-scan',
               'releases':'/usr/bin/python3 /usr/local/sbin/trusttunnel-panel.py --admin endpoint-releases'}[kind]
    if kind == 'packages':
        script = '#!/bin/bash\nset -euo pipefail\nexport DEBIAN_FRONTEND=noninteractive\nexport NEEDRESTART_MODE=a\nexec 9>/run/trusttunnel-packages.lock\nflock -n 9 || exit 0\napt-get -o DPkg::Lock::Timeout=300 update\napt-get -y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confold upgrade\n'
        atomic_write(Path('/usr/local/sbin/trusttunnel-os-maintenance'),script,0o700)
    service = '[Unit]\nDescription=TrustTunnel scheduled '+kind+'\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nExecStart='+command+'\nTimeoutStartSec='+('1800' if kind=='packages' else '120')+'\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\n'
    timer = '[Unit]\nDescription=TrustTunnel scheduled '+kind+'\n\n[Timer]\nOnCalendar='+calendar+'\nPersistent=false\nAccuracySec=1min\nRandomizedDelaySec='+('5min' if kind=='packages' else '0')+'\n\n[Install]\nWantedBy=timers.target\n'
    files = {SCHEDULE_DIR/(unit+'.service'):service,SCHEDULE_DIR/(unit+'.timer'):timer}
    old = {path:read_text(path) for path in files}
    try:
        for path,text in files.items(): atomic_write(path,text,0o644)
        checked_run(['systemctl','daemon-reload'])
        checked_run(['systemctl','enable','--now',unit+'.timer'])
        checked_run(['systemctl','restart',unit+'.timer'])
    except Exception:
        for path,text in old.items():
            if text:atomic_write(path,text,0o644)
            else:path.unlink(missing_ok=True)
        run(['systemctl','daemon-reload']); raise
    audit_log('schedule-save',kind+' '+calendar)
    return SCHEDULE_KINDS[kind]+': '+calendar+' · часовой пояс сервера. Пропущенный запуск не выполняется сразу при включении. Endpoint и панель не обновляются автоматически.\n'+checked_run(['timedatectl','show','--property=Timezone','--value'])


def panel_event(kind):
    if kind not in ('failures','rejected','throttled'): return
    hour=int(time.time()//3600)*3600
    with PANEL_EVENTS_LOCK:
        item=PANEL_EVENTS.setdefault(hour,dict(failures=0,rejected=0,throttled=0,flushed={}))
        item[kind]+=1
        for old in list(PANEL_EVENTS):
            if old<hour-86400: PANEL_EVENTS.pop(old,None)


def health_checks(stats):
    checks=[]
    def service(key,title):
        state=stats.get('services',{}).get(key,'unknown')
        checks.append(dict(id=key,title=title,state='ok' if state=='active' else 'unknown' if state=='unknown' else 'error',detail={'active':'Служба работает','inactive':'Служба остановлена','failed':'Ошибка службы'}.get(state,'Нет подтверждённого состояния')))
    service('trusttunnel','TrustTunnel')
    backend=current_warp_backend()
    warp_units={'wg-interface':'warp-interface','masque-interface':'warp-masque-tun','wg-socks':'warp-wireproxy','masque-socks':'warp-masque'}
    if backend in warp_units: service(warp_units[backend],'Выбранный выход WARP')
    for key,title,warning,critical in [('cpu_percent','Процессор',85,98),('memory_percent','Память',85,95),('disk_percent','Диск',85,95)]:
        value=stats.get(key)
        valid=type(value) in (int,float) and 0<=value<=100
        state='unknown' if not valid else 'error' if value>=critical else 'warn' if value>=warning else 'ok'
        checks.append(dict(id=key,title=title,state=state,detail=f'{value:.1f}% · предупреждение от {warning}%' if valid else 'Нужно следующее измерение'))
    failed=any(c['state']=='error' for c in checks)
    state='error' if failed else 'warn' if any(c['state']=='warn' for c in checks) else 'unknown' if any(c['state']=='unknown' for c in checks) else 'ok'
    return state,checks


def primary_interface(stats):
    for line in read_text('/proc/net/route').splitlines()[1:]:
        fields=line.split()
        if len(fields)>3 and fields[1]=='00000000' and fields[0] in stats.get('interfaces',{}): return fields[0]
    return next(iter(stats.get('interfaces',{})),'')


def health_tick():
    global HEALTH_LAST
    with HEALTH_LOCK:
        stats=monitor_snapshot(); now=time.time(); state,checks=health_checks(stats)
        interface=primary_interface(stats); counters=stats.get('interfaces',{}).get(interface,{})
        with PANEL_EVENTS_LOCK:
            pending={hour:{key:item[key]-item['flushed'].get(key,0) for key in ('failures','rejected','throttled')} for hour,item in PANEL_EVENTS.items()}
        with usage_database() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT OR REPLACE INTO health_samples VALUES (?,?,?,?,?,?,?,?,?,?)',
                       (int(now//60)*60,state,stats.get('cpu_percent'),stats.get('memory_percent'),stats.get('disk_percent'),interface,
                        read_text('/proc/sys/kernel/random/boot_id').strip(),counters.get('rx'),counters.get('tx'),json.dumps([c['id'] for c in checks if c['state']!='ok'])))
            for hour,counts in pending.items():
                db.execute('INSERT INTO panel_event_counts VALUES (?,?,?,?) ON CONFLICT(hour) DO UPDATE SET failures=failures+excluded.failures,rejected=rejected+excluded.rejected,throttled=throttled+excluded.throttled',
                           (hour,counts['failures'],counts['rejected'],counts['throttled']))
            db.execute('DELETE FROM health_samples WHERE ts<?',(now-30*86400,))
            db.execute('DELETE FROM panel_event_counts WHERE hour<?',(now-30*86400,))
        with PANEL_EVENTS_LOCK:
            for hour,counts in pending.items():
                if hour in PANEL_EVENTS:
                    for key,value in counts.items(): PANEL_EVENTS[hour]['flushed'][key]=PANEL_EVENTS[hour]['flushed'].get(key,0)+value
        HEALTH_LAST=dict(checked_at=now,state=state,checks=checks,error='')
        SNAPSHOT_CACHE.pop('health_snapshot',None); SNAPSHOT_CACHE.pop('scanner_snapshot',None)
    return health_snapshot()


@cached_snapshot(15)
def health_snapshot():
    now=time.time(); today=int(now//86400)*86400
    with HEALTH_LOCK: current=dict(HEALTH_LAST)
    groups={}; points=[]; latest=None
    if USAGE_DB.exists():
        with usage_database() as db:
            latest=db.execute('SELECT * FROM health_samples ORDER BY ts DESC LIMIT 1').fetchone()
            groups={row['day']:dict(row) for row in db.execute("SELECT CAST(ts/86400 AS INTEGER)*86400 AS day,COUNT(*) AS samples,SUM(state='ok') AS ok,SUM(state='warn') AS warn,SUM(state='error') AS errors FROM health_samples WHERE ts>=? GROUP BY day",(today-29*86400,))}
            points=[dict(row) for row in db.execute('SELECT ts,interface,boot,rx,tx FROM health_samples WHERE ts>=? ORDER BY ts',(now-86400,))]
    if not current and latest:
        current=dict(checked_at=latest['ts'],state=latest['state'],checks=[],error='')
    current.setdefault('checked_at',0); current.setdefault('checks',[])
    current['stale']=bool(current.get('error')) or not current['checked_at'] or now-current['checked_at']>150 or current['checked_at']>now+30
    if current['stale']: current['state']='unknown'
    current['history']=[dict(groups.get(day,dict(samples=0,ok=0,warn=0,errors=0)),day=day) for day in range(today-29*86400,today+1,86400)]
    current['scope']='Локальное наблюдение: ресурсы и выбранные службы. Не проверяет доступность из интернета или весь клиентский VPN-путь. Пробелы истории не считаются успешными проверками.'
    rates=[]
    for old,new in zip(points,points[1:]):
        dt=new['ts']-old['ts']
        valid=0<dt<=180 and old['interface']==new['interface'] and old['boot']==new['boot'] and all(type(old[k]) is int and type(new[k]) is int and new[k]>=old[k] for k in ('rx','tx'))
        rates.append(dict(time=new['ts'],rx=(new['rx']-old['rx'])/dt if valid else None,tx=(new['tx']-old['tx'])/dt if valid else None,interface=new['interface']))
    current['traffic_history']=rates
    return current


@cached_snapshot(10)
def scanner_snapshot():
    start=int((time.time()-86400)//3600)*3600
    counts={k:0 for k in ('failures','rejected','throttled')}; hourly={}
    if USAGE_DB.exists():
        with usage_database() as db:
            hourly={row['hour']:dict(row) for row in db.execute('SELECT * FROM panel_event_counts WHERE hour>=?',(start,))}
    with PANEL_EVENTS_LOCK:
        for hour,item in PANEL_EVENTS.items():
            if hour>=start:
                row=hourly.setdefault(hour,dict(hour=hour,failures=0,rejected=0,throttled=0))
                for key in counts: row[key]+=item[key]-item['flushed'].get(key,0)
    for row in hourly.values():
        for key in counts: counts[key]+=row[key]
    return dict(counts=counts,hourly=sorted(hourly.values(),key=lambda x:x['hour']),scope='Только HTTP-панель: ошибки входа, отклонённые запросы и ответы ограничения частоты. Один запрос может попасть в несколько категорий. Это не число сканеров и не статистика всех портов VPS.',outbound_scans=None,checked_at=time.time())


def health_watcher():
    while True:
        try: health_tick()
        except (OSError,ValueError,RuntimeError,sqlite3.Error):
            with HEALTH_LOCK: HEALTH_LAST.update(error='Не удалось обновить наблюдение; состояние не подтверждено.')
        time.sleep(60)


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
    units = ('trusttunnel', 'warp-wireproxy', 'warp-masque', 'warp-interface', 'warp-masque-tun', 'fail2ban', 'trusttunnel-panel')
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
    tokens = fail2ban_ignores(current)
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
    rc, sync = run(['timedatectl','show','--property=NTPSynchronized','--value'],timeout=5)
    check('Синхронизация времени','ok' if rc == 0 and sync == 'yes' else 'warn','Системное время синхронизировано' if sync == 'yes' else 'Проверьте NTP: неверное время мешает TLS и обновлению сертификатов')
    rc, syn = run(['sysctl','-n','net.ipv4.tcp_syncookies'],timeout=5)
    check('SYN cookies','ok' if rc == 0 and syn in ('1','2') else 'warn','Защита TCP включена' if syn in ('1','2') else 'Рекомендуется проверить net.ipv4.tcp_syncookies; автоматически не меняется')
    echo_blocked = all('--comment TT_PANEL_PING' in read_text(UFW_DIR/name) for name in ('before.rules','before6.rules'))
    check('Входящий ping','info','Echo-request заблокирован нашим правилом UFW' if echo_blocked else 'Исходная политика UFW. Разрешённый ping сам по себе не является уязвимостью')
    rc, unattended = run(['systemctl','is-enabled','apt-daily-upgrade.timer'],timeout=5)
    check('Обновления ОС','info','Системный APT-таймер: '+(unattended or 'неизвестно')+'. Дополнительное расписание управляется отдельно; не включайте дублирующие обновления без необходимости.')
    cfg = tomllib.loads(read_text(TT_DIR/'vpn.toml'))
    metrics = cfg.get('metrics', {})
    address = metrics.get('address', '127.0.0.1:1987')
    private_metrics = bool(re.fullmatch(r'127\.0\.0\.1:\d{1,5}', address))
    check('Приватность метрик', 'ok' if private_metrics else 'warn', 'Метрики доступны только loopback' if private_metrics else 'Метрики слушают не loopback. Они могут раскрывать логины и IP клиентов; перенесите listener на 127.0.0.1.')
    check('Доступ VPN к приватным сетям', 'warn' if cfg.get('allow_private_network_connections', False) else 'ok', 'Разрешён: клиент может обращаться к локальным сервисам VPS. Отключение изменит маршрутизацию и должно быть осознанным.' if cfg.get('allow_private_network_connections', False) else 'Приватные назначения запрещены настройкой endpoint; reverse_proxy проверяется отдельно.')
    configured_password = env.get('PANEL_PASSWORD', PANEL_PASSWORD)
    check('Пароль панели', 'ok' if len(configured_password) >= 20 else 'warn', 'Не менее 20 символов' if len(configured_password) >= 20 else 'Рекомендуется уникальный случайный пароль от 20 символов. Длина не доказывает стойкость или отсутствие утечки.')
    extra = [TT_DIR/name for name in ('clients-state.json','panel-protection.json','client-guard.json')]
    extra += list(CLIENT_DIR.glob('*.toml')) + [CLIENT_DIR/'clients-credentials.txt', USAGE_DB]
    unsafe = sum(1 for p in extra if p.exists() and (p.is_symlink() or p.stat().st_mode & 0o077 or p.stat().st_uid != 0))
    check('Профили и учёт', 'warn' if unsafe else 'ok', 'Файлов с небезопасными правами/владельцем/ссылками: '+str(unsafe)+'. Содержимое и секреты не включаются в отчёт.')
    integrity, integrity_text = protection_integrity()
    check('TLS-аутентификация VPN', 'info' if integrity else 'warn', integrity_text+' App v1.3 поддерживает ключевую TLS-аутентификацию; нужен совместимый endpoint. Не защищает от копирования ключа.')
    check('Контроль передачи доступа', 'warn' if GUARD_STATUS.get('error') else 'info', GUARD_STATUS.get('error') or 'Квоты, сроки, одноразовая выдача и наблюдение сетей управляются по клиентам. Наблюдавшиеся сети не равны одновременным IP. Строгий IP admission и ключ устройства пока не реализованы; автоматического IP-бана нет.')
    rc, verbose = run(['ufw','status','verbose'],timeout=5)
    check('Политика входящих соединений', 'ok' if not rc and 'deny (incoming)' in verbose else 'warn', 'UFW запрещает входящие по умолчанию' if 'deny (incoming)' in verbose else 'Проверьте default incoming и правила. Автоматическая смена политики не выполняется: можно потерять доступ к VPS.')
    rc, kernel = run(['sysctl','-n',*SAFE_SYSCTLS],timeout=5)
    actual = kernel.splitlines()
    differences = sum(value != desired for value,desired in zip(actual,SAFE_SYSCTLS.values())) if not rc and len(actual)==len(SAFE_SYSCTLS) else None
    check('Базовая защита ядра', 'ok' if differences == 0 else 'warn', 'Безопасный набор sysctl применён' if differences == 0 else 'Требуют проверки: '+str(differences if differences is not None else 'неизвестно')+'. Профиль не меняет rp_filter, IP forwarding, MTU, UDP или маршруты WARP.')
    rc, failed = run(['systemctl','--failed','--no-legend','--no-pager'],timeout=5)
    failed_count = len([line for line in failed.splitlines() if line.strip()]) if not rc else None
    check('Ошибки служб ОС','ok' if failed_count == 0 else 'warn','Служб в состоянии failed: '+str(failed_count if failed_count is not None else 'неизвестно')+'. Для просмотра используйте раздел журналов; автоматического перезапуска неизвестных служб нет.')
    fixes = {'Синхронизация времени': ('ntp','Неверное время нарушает TLS. Включите NTP и повторите проверку.'),
             'SYN cookies':('syn-cookies','Включите штатную защиту TCP от SYN flood; это не полная DDoS-защита.'),
             'Приватность метрик':('metrics-private','Перенесите listener на loopback, затем перезапустите endpoint с подтверждением.'),
             'Приватные файлы':('private-files','Закройте доступ к ключам и паролям для группы/остальных.'),
             'Профили и учёт':('private-files','Проверьте владельца и ссылки. Исправление прав выполняется только для root-файлов.'),
             'Базовая защита ядра':('kernel-baseline','Примените ограниченный безопасный профиль с откатом при ошибке.')}
    for item in checks:
        if item['state'] == 'warn' and item['title'] in fixes:
            item['remediation'], item['recommendation'] = fixes[item['title']]
    return dict(checks=checks, services=services, checked_at=time.time())


def security_remediate(values):
    if values.get('confirm') != 'CONFIRMED': raise ValueError('Подтвердите конкретное исправление безопасности.')
    kind = values.get('check', '')
    if kind == 'ntp':
        checked_run(['timedatectl','set-ntp','true'])
    elif kind == 'syn-cookies':
        path = SYSCTL_DIR/'61-trusttunnel-security.conf'; old = read_text(path)
        if path.is_symlink(): raise ValueError('Настройка sysctl является symlink; изменение отменено.')
        rc, previous = run(['sysctl','-n','net.ipv4.tcp_syncookies'], timeout=5)
        if rc or previous not in ('0','1','2'): raise ValueError('Не прочитано текущее значение SYN cookies.')
        try:
            atomic_write(path, 'net.ipv4.tcp_syncookies = 1\n', 0o644)
            checked_run(['sysctl','-w','net.ipv4.tcp_syncookies=1'])
        except Exception:
            if old: atomic_write(path, old, 0o644)
            else: path.unlink(missing_ok=True)
            run(['sysctl','-w','net.ipv4.tcp_syncookies='+previous]); raise
    elif kind == 'kernel-baseline':
        path = SYSCTL_DIR/'62-trusttunnel-baseline.conf'; old = read_text(path)
        if path.is_symlink(): raise ValueError('Настройка sysctl является symlink; изменение отменено.')
        rc, output = run(['sysctl','-n',*SAFE_SYSCTLS],timeout=5)
        previous = output.splitlines()
        if rc or len(previous) != len(SAFE_SYSCTLS) or any(not re.fullmatch(r'\d{1,2}',v) for v in previous): raise ValueError('Не удалось прочитать исходные значения; изменения отменены.')
        changed = []
        try:
            atomic_write(path, ''.join(k+' = '+v+'\n' for k,v in SAFE_SYSCTLS.items()), 0o644)
            for key, value in SAFE_SYSCTLS.items():
                changed.append(key); checked_run(['sysctl','-w',key+'='+value])
        except Exception:
            if old: atomic_write(path,old,0o644)
            else: path.unlink(missing_ok=True)
            prior = dict(zip(SAFE_SYSCTLS,previous))
            for key in reversed(changed): run(['sysctl','-w',key+'='+prior[key]])
            raise
    elif kind == 'private-files':
        files = [TT_DIR/name for name in ('credentials.toml','clients-state.json','panel-protection.json','client-guard.json','certs/key.pem')]
        files += [Path('/etc/trusttunnel-panel.env'), CLIENT_DIR/'clients-credentials.txt', USAGE_DB] + list(CLIENT_DIR.glob('*.toml'))
        existing = [p for p in files if p.exists() or p.is_symlink()]
        if any(p.is_symlink() or not p.is_file() or p.stat().st_uid != 0 for p in existing):
            raise ValueError('Символическая ссылка, не файл или владелец не root: автоматическое исправление отменено.')
        for path in existing: os.chmod(path, 0o600)
    elif kind == 'metrics-private':
        path = TT_DIR/'vpn.toml'; text = read_text(path)
        settings = tomllib.loads(text).get('metrics', {})
        if set(settings)-{'address','per_client_metrics','request_timeout_secs'}: raise ValueError('Неизвестные параметры метрик: изменение отменено.')
        port = settings.get('address','127.0.0.1:1987').rsplit(':',1)[-1]
        if not validate_port(port): raise ValueError('Некорректный порт метрик.')
        settings['address'] = '127.0.0.1:'+port
        apply_endpoint_file(path, replace_config_section(text,'metrics',settings))
    else: raise ValueError('Неизвестное исправление; произвольные команды запрещены.')
    SNAPSHOT_CACHE.clear(); audit_log('security-remediate', kind)
    return 'Запрошенное исправление применено. Запустите проверку повторно для подтверждения результата. SSH-аутентификация и правила доступа администратора не менялись.'


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
    return validated_dns(panel_settings()['DNS_UPSTREAMS'])


def client_anti_dpi_enabled():
    return panel_settings()['CLIENT_ANTI_DPI'] == '1'


def client_tls_profile():
    profile = panel_settings()['TLS_PROFILE']
    return profile if profile in ('chrome', 'safari', 'firefox', 'okhttp', 'openssl', 'default') else 'chrome'


def save_client_network_settings(dns_value, anti_dpi, tls_profile, post_quantum):
    values = validated_dns(dns_value)
    if tls_profile not in ('chrome', 'safari', 'firefox', 'okhttp', 'openssl', 'default'):
        raise ValueError('Некорректный TLS-профиль.')
    write_text(PANEL_SETTINGS, 'DNS_UPSTREAMS=' + ','.join(values) + '\nCLIENT_ANTI_DPI=' + ('1' if anti_dpi else '0') + '\nTLS_PROFILE=' + tls_profile + '\nPOST_QUANTUM=' + ('1' if post_quantum else '0') + '\n', 0o600)
    rebuild_client_files(load_clients())
    audit_log('client_network_settings_changed', ','.join(values))
    return 'DNS, AntiDPI и TLS-профиль сохранены. Все TOML клиентов пересобраны.'

def client_profile(username, password, protocol):
    cert = read_text(TT_DIR / 'certs' / 'cert.pem').strip()
    body = f'''# Endpoint host name, used for TLS session establishment
hostname = "{q(domain())}"

# Endpoint addresses in IP:port or hostname:port format
addresses = ["{q(domain())}:{endpoint_port()}"]

# Custom SNI value for TLS handshake.
custom_sni = ""

# Whether IPv6 traffic can be routed through the endpoint
has_ipv6 = {str(tomllib.loads(read_text(TT_DIR / 'vpn.toml')).get('ipv6_available', True)).lower()}

# Username for authorization
username = "{q(username)}"

# Password for authorization
password = "{q(password)}"

# TLS client random hex prefix for connection filtering.
client_random_prefix = "{protection_state().get('prefix', '') if protection_state().get('enabled') else ''}"

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
    guard = protection_state()
    if guard.get('tls_enabled'):
        body = set_core_setting(body, 'client_random_auth_key', guard['auth_key'])
        body = set_core_setting(body, 'client_random_prefix', '')
    old = read_text(CLIENT_DIR / f'{username}-{protocol}.toml')
    if old:
        previous = tomllib.loads(old)
        defaults = tomllib.loads(body)
        # Keep custom SNI, TLS-auth keys and unknown future fields on explicit rebuilds.
        for key in ('hostname','addresses','has_ipv6','username','password','dns_upstreams','upstream_protocol','tls_profile','anti_dpi','post_quantum_group_enabled','skip_verification'):
            old = set_core_setting(old, key, defaults[key])
        if guard.get('tls_enabled'):
            old = set_core_setting(old, 'client_random_auth_key', guard['auth_key'])
            old = set_core_setting(old, 'client_random_prefix', '')
        elif guard.get('enabled'):
            if previous.get('client_random_auth_key'): raise ValueError('Профиль использует TLS auth key; prefix-пересборка отменена.')
            old = set_core_setting(old, 'client_random_prefix', guard['prefix'])
        if defaults.get('certificate'): old = set_core_setting(old, 'certificate', defaults['certificate'])
        elif cert_mode() == 'letsencrypt' and 'certificate' in previous: old = remove_core_setting(old,'certificate')
        tomllib.loads(old)
        return old
    return body


def rebuild_client_files(clients):
    CLIENT_DIR.mkdir(parents=True, exist_ok=True)
    protocols = ['http2', 'http3'] if quic_enabled() else ['http2']
    candidates = {CLIENT_DIR/f'{c["username"]}-{protocol}.toml': client_profile(c['username'], c['password'], protocol) for c in clients for protocol in protocols}
    for old in CLIENT_DIR.glob('*.toml'):
        if old not in candidates: old.unlink()
    write_text(CLIENT_DIR / 'clients-credentials.txt', ''.join(f'{c["username"]} {c["password"]}\n' for c in clients), 0o600)
    cert = TT_DIR / 'certs' / 'cert.pem'
    if cert.exists():
        shutil.copy2(cert, CLIENT_DIR / 'server-cert.pem')
        os.chmod(CLIENT_DIR / 'server-cert.pem', 0o644)
    for path, body in candidates.items(): atomic_write(path, body)
    refresh_client_archive()


def refresh_client_archive():
    archive = CLIENT_DIR.with_name(CLIENT_DIR.name+'-'+(domain() or 'trusttunnel')+'.zip')
    fd,name = tempfile.mkstemp(prefix='.client-archive-',dir=archive.parent)
    os.close(fd)
    try:
        with zipfile.ZipFile(name,'w',compression=zipfile.ZIP_DEFLATED) as zf:
            for item in sorted(CLIENT_DIR.iterdir()):
                if item.is_file() and not item.is_symlink():zf.write(item,item.name)
        os.chmod(name,0o600); os.replace(name,archive)
    finally:
        if os.path.exists(name):os.unlink(name)


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


def link_varint(value):
    # TrustTunnel DEEP_LINK.md uses the QUIC varint, not a byte-sized length.
    for size, bits, prefix in ((1, 6, 0), (2, 14, 0x4000), (4, 30, 0x80000000), (8, 62, 0xc000000000000000)):
        if 0 <= value < 1 << bits:
            return (value | prefix).to_bytes(size, 'big')
    raise ValueError('Слишком большое поле ссылки.')


def link_fields(uri):
    if not re.fullmatch(r'tt://\??[A-Za-z0-9_-]+', uri) or len(uri) > 16384:
        raise ValueError('Некорректный формат tt-ссылки.')
    encoded = uri.split('://', 1)[1].lstrip('?')
    try:
        data = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
    except ValueError:
        raise ValueError('Повреждённая tt-ссылка.') from None
    fields, offset = [], 0
    def number():
        nonlocal offset
        if offset >= len(data):
            raise ValueError('Оборванное поле tt-ссылки.')
        size = 1 << (data[offset] >> 6)
        raw = data[offset:offset + size]
        if len(raw) != size:
            raise ValueError('Оборванная длина tt-ссылки.')
        offset += size
        return int.from_bytes(raw, 'big') & ((1 << (size * 8 - 2)) - 1)
    while offset < len(data):
        tag, length = number(), number()
        value = data[offset:offset + length]
        if len(value) != length:
            raise ValueError('Оборванное значение tt-ссылки.')
        fields.append((tag, value))
        offset += length
    tags = dict(fields)
    if not all(tags.get(tag) for tag in (1, 2, 5, 6)) and not tags.get(14, b'').startswith(b'https://'):
        raise ValueError('В ссылке нет параметров подключения.')
    if tags.get(0, b'\x00') not in (b'\x00', b'\x01', b'\x02'):
        raise ValueError('Неподдерживаемая версия tt-ссылки.')
    return fields


def clean_deeplink(output):
    plain = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
    candidates = [line.strip() for line in plain.splitlines() if re.fullmatch(r'tt://\??[A-Za-z0-9_-]+', line.strip())]
    if len(candidates) != 1:
        raise ValueError('Endpoint не вернул одну корректную tt-ссылку.')
    link_fields(candidates[0])
    return candidates[0]


def deeplink(username, protocol='http2', kind='static'):
    if protocol not in ('http2', 'http3') or (protocol == 'http3' and not quic_enabled()):
        raise ValueError('Выбранный транспорт не включён на endpoint.')
    if kind not in ('static', 'subscription', 'protected', 'tls-auth'):
        raise ValueError('Неизвестный тип ссылки.')
    if username not in {c['username'] for c in load_clients()}:
        raise ValueError('Клиент не найден или отключён.')
    paths = [TT_DIR / name for name in ('credentials.toml', 'hosts.toml', 'vpn.toml', 'rules.toml', 'certs/cert.pem', 'trusttunnel_endpoint')]
    profile_path = CLIENT_DIR / f'{username}-{protocol}.toml'
    paths.append(profile_path)
    stamps = tuple((p.stat().st_mtime_ns, p.stat().st_size) if p.exists() else (0, 0) for p in paths)
    guard = protection_state()
    cache_key = (username, protocol, kind, domain(), endpoint_port(), tuple(dns_upstreams()), client_anti_dpi_enabled(), guard.get('prefix'), guard.get('enabled'), guard.get('auth_key'), guard.get('tls_enabled'), stamps)
    cached = DEEPLINK_CACHE.get(cache_key)
    if cached and time.monotonic() - cached[0] < DEEPLINK_CACHE_TTL:
        return cached[1]
    cmd = [str(TT_DIR / 'trusttunnel_endpoint'), 'vpn.toml', 'hosts.toml', '-c', username, '-a', f'{domain()}:{endpoint_port()}', '--format', 'deeplink', '--name', username]
    profile = tomllib.loads(read_text(profile_path))
    tls_auth = kind == 'tls-auth' or guard.get('tls_enabled')
    if tls_auth:
        if not guard.get('auth_key'): raise ValueError('Сначала подготовьте TLS-auth ссылки в разделе безопасности.')
        if kind == 'subscription': raise ValueError('TLS-auth подписка не квалифицирована. Используйте статический TLS-auth профиль.')
        profile.pop('client_random_prefix', None)
        profile['client_random_auth_key'] = guard['auth_key']
    if kind == 'protected' or guard.get('enabled'):
        if not guard.get('prefix'): raise ValueError('Сначала подготовьте защиту от сканирования в разделе безопасности.')
        if profile.get('client_random_auth_key'): raise ValueError('Префикс несовместим с клиентским auth key. Профиль сохранён без изменений.')
        profile['client_random_prefix'] = guard['prefix']
    for key, flag in (('client_random_prefix', '--client-random-prefix'), ('client_random_auth_key', '--client-random-auth-key')):
        if profile.get(key):
            if key == 'client_random_prefix' and kind == 'protected' and not guard.get('enabled'):
                continue
            if key == 'client_random_auth_key' and tls_auth and not guard.get('tls_enabled'):
                continue
            cmd += [flag, profile[key]]
    if kind == 'subscription':
        cfg = tomllib.loads(read_text(TT_DIR / 'vpn.toml'))
        if not endpoint_capabilities()['subscription'] or not cfg.get('subscription', {}).get('enabled'):
            raise ValueError('Подписки не включены или не поддерживаются этой версией endpoint.')
        cmd += ['--subscription-only']
    for upstream in dns_upstreams():
        cmd += ['--dns-upstream', upstream]
    rc, out = run(cmd, timeout=8, cwd=str(TT_DIR))
    if rc:
        raise RuntimeError('Endpoint не смог экспортировать профиль. Проверьте правила ClientHello и журнал сервиса.')
    link = clean_deeplink(out)
    fields = link_fields(link)
    if kind != 'subscription':
        fields = [(tag, value) for tag, value in fields if tag not in (9, 10)]
        fields += [(9, link_varint(1 if protocol == 'http2' else 2)), (10, bytes([bool(profile.get('anti_dpi', client_anti_dpi_enabled()))]))]
        if profile.get('client_random_prefix'):
            prefix = profile['client_random_prefix']
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,32}(?:/(?:[0-9a-fA-F]{2}){1,32})?', prefix):
                raise ValueError('Некорректный ClientHello-префикс в профиле.')
            fields = [(tag, value) for tag, value in fields if tag != 11] + [(11, prefix.encode('ascii'))]
        if profile.get('client_random_auth_key'):
            key = profile['client_random_auth_key']
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){16,64}', key): raise ValueError('TLS auth key должен содержать 16–64 байта в hex.')
            fields = [(tag, value) for tag, value in fields if tag not in (11,15)] + [(15,key.encode('ascii'))]
        payload = b''.join(link_varint(tag) + link_varint(len(value)) + value for tag, value in fields)
        link = 'tt://?' + base64.urlsafe_b64encode(payload).rstrip(b'=').decode('ascii')
    link_fields(link)
    if len(DEEPLINK_CACHE) >= 256:
        DEEPLINK_CACHE.clear()
    DEEPLINK_CACHE[cache_key] = (time.monotonic(), link)
    return link


def qr_image(link):
    link_fields(link)
    if not shutil.which('qrencode'):
        raise RuntimeError('qrencode не установлен. Установите пакет qrencode или используйте ссылку.')
    process = subprocess.run(['qrencode', '-t', 'PNG', '-l', 'L', '-s', '7', '-m', '4', '-o', '-'],
                             input=link.encode('ascii'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
    if process.returncode or not process.stdout.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ValueError('Профиль слишком большой для QR. Используйте tt-ссылку или TOML; для self-signed в QR включается сертификат.')
    return process.stdout


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
    cpu_percent = None
    stat = read_text('/proc/stat').splitlines()
    if stat and stat[0].startswith('cpu '):
        ticks = [int(v) for v in stat[0].split()[1:9]]
        total_ticks, idle = sum(ticks), ticks[3] + ticks[4]
        if CPU_SAMPLE and total_ticks > CPU_SAMPLE[0]:
            percent = max(0, min(100, 100 * (1 - (idle - CPU_SAMPLE[1]) / (total_ticks - CPU_SAMPLE[0]))))
            cpu = f'{percent:.1f}%'
            cpu_percent = round(percent,1)
        CPU_SAMPLE = total_ticks, idle
    return {
        'cpu': cpu,
        'cpu_percent': cpu_percent,
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

def diagnostic_report(kind, values):
    if kind == 'client':
        user = values.get('username','')
        item = next((c for c in client_metrics()['clients'] if c['username'] == user), None)
        if item is None: raise ValueError('Клиент не найден.')
        item = {k:v for k,v in item.items() if k != 'ip'}
        item['last_seen_utc'] = datetime.datetime.fromtimestamp(item['last_seen'], datetime.timezone.utc).isoformat() if item['last_seen'] else 'Ещё не наблюдался'
        return json.dumps(item, ensure_ascii=False, indent=2)+'\nСессия подтверждает подключение к endpoint, но не доступ к конкретному сайту/игре. IP не доказывает число устройств. История до включения сборщика неизвестна.'
    if kind == 'egress':
        target = values.get('target','cloudflare')
        targets = {'cloudflare':'https://www.cloudflare.com/cdn-cgi/trace', 'github':'https://api.github.com/zen'}
        if target not in targets: raise ValueError('Выберите диагностическое направление из списка.')
        rc, output = run(['curl','-4','--noproxy','*','--silent','--show-error','--fail','--connect-timeout','4','--max-time','10','--output','/dev/null','--write-out', 'HTTP=%{http_code}\nDNS=%{time_namelookup}\nTCP=%{time_connect}\nTLS=%{time_appconnect}\nTotal=%{time_total}',targets[target]], timeout=12)
        return 'Прямой выход самого VPS: '+('OK' if not rc else 'ОШИБКА')+'\n'+output[:2000]+'\nВремя в секундах. Это не пинг игры и не проверка трафика телефона. WARP для TrustTunnel использует отдельный маршрут.'
    if kind == 'warp':
        if interface_enabled(): return interface_health()+'\nПроверка выполнена в том же cgroup-маршруте, что и TrustTunnel. Это HTTP-проверка, не измерение потерь игрового UDP.'
        backend = current_warp_backend()
        if backend in ('wg-socks','masque-socks'): return warp_probe(SOCKS_ADDR if backend=='wg-socks' else MASQUE_ADDR)
        return 'WARP сейчас не является исходящим маршрутом TrustTunnel.'
    if kind != 'stack': raise ValueError('Неизвестная диагностика.')
    port = endpoint_port(); lines = ['Endpoint: '+endpoint_version(), 'Сервис: '+service_status('trusttunnel'), 'Маршрут: '+forwarder_label()]
    rc, sockets = run(['ss','-H','-lntup'],timeout=5)
    for proto in ('tcp','udp'):
        present = not rc and any(line.startswith(proto) and re.search(r':'+re.escape(port)+r'\s',line) for line in sockets.splitlines())
        lines.append(proto.upper()+' порт '+port+': '+('слушает' if present else 'не подтверждён'))
    rc, check = run(['openssl','s_client','-connect','127.0.0.1:'+port,'-servername',domain(),'-verify_hostname',domain(),'-verify_return_error','-CAfile',str(TT_DIR/'certs/cert.pem')], timeout=8, input_text='')
    verified = rc == 0 and ('Verify return code: 0' in check or 'Verification: OK' in check)
    lines.append('TLS и SNI по loopback: '+('проверены' if verified else 'не подтверждены; проверьте сертификат, имя host и цепочку'))
    data = client_metrics()
    lines += ['Метрики пользователей: '+('доступны' if data['available'] else 'не доступны; статус online неизвестен'), 'Онлайн по живым сессиям: '+str(sum(c['online'] is True for c in data['clients'])), 'Учёт трафика: '+(data.get('accounting_error') or 'постоянное локальное хранилище, интервал 15 с'), '', 'Следующий шаг: проверьте новый вход с телефона и внешний firewall провайдера. Loopback не проверяет прохождение TCP/UDP извне. QUIC и HTTP/2 проверяются отдельно. Содержимое профилей и ключей в отчёт не включается.']
    return '\n'.join(lines)


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
    allowed = {'warp-interface':'warp-interface', 'warp-masque-tun':'warp-masque-tun', 'trusttunnel': 'trusttunnel', 'warp': 'warp-wireproxy', 'warp-wireproxy': 'warp-wireproxy',
               'warp-masque': 'warp-masque', 'warp-masque-bridge': 'warp-masque-bridge', 'fail2ban': 'fail2ban',
               'panel': 'trusttunnel-panel', 'trusttunnel-panel': 'trusttunnel-panel', 'ssh': 'ssh', 'sshd': 'sshd'}
    if service not in allowed:
        raise ValueError('Неизвестный сервис журнала.')
    output = run(['journalctl', '-u', allowed[service], '--no-pager', '-n', str(min(500, max(1, int(lines))))], timeout=15)[1]
    output = re.sub(r'tt://\??[A-Za-z0-9_-]+', '[tt-ссылка скрыта]', output)
    output = re.sub(r'(https://[^\s/:]+:)[^@\s]+@', r'\1[скрыто]@', output)
    output = re.sub(r'(/activate#)[A-Za-z0-9_-]{43}', r'\1[скрыто]', output)
    output = re.sub(r'(?i)(authorization\s*:\s*(?:basic|bearer)\s+)\S+', r'\1[скрыто]', output)
    output = re.sub(r'(?i)((?:client_random_auth_key|password|privatekey)\s*[=:]\s*)[^\s,;]+', r'\1[скрыто]', output)
    return output or 'Записей пока нет.'


def backup_archive():
    installer_operation('backup-identity', {'confirm':'REINSTALL'})
    backup_dir = Path('/root/trusttunnel-identity-backup')
    archive = Path('/root/trusttunnel-identity-backup.zip')
    fd,name = tempfile.mkstemp(prefix='.identity-backup-',dir=archive.parent);os.close(fd)
    try:
        with zipfile.ZipFile(name, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for item in backup_dir.rglob('*'):
                relative = str(item.relative_to(backup_dir)).replace('\\','/')
                allowed = relative in ('certs/cert.pem','certs/key.pem','credentials.toml','hosts.toml','rules.toml','clients-state.json','panel-protection.json','client-guard.json','identity.env') or relative.startswith('client-files/')
                if allowed and item.is_file() and not item.is_symlink(): zf.write(item, relative)
        os.chmod(name,0o600);os.replace(name,archive)
    finally:
        if os.path.exists(name):os.unlink(name)
    return archive
PANEL_AUDIT_LOG = Path('/var/log/trusttunnel-panel-audit.log')
PANEL_TELEGRAM_ENV = Path('/etc/trusttunnel-panel-telegram.env')
PANEL_TIMER_UNIT = Path('/etc/systemd/system/trusttunnel-maintenance.service')
PANEL_TIMER = Path('/etc/systemd/system/trusttunnel-maintenance.timer')


def audit_log(action, detail=''):
    stamp = time.strftime('%Y-%m-%d %H:%M:%S %z')
    action = re.sub(r'[\x00-\x1f\x7f]', ' ', str(action))[:80]
    detail = re.sub(r'[\x00-\x1f\x7f]', ' ', str(detail))[:2000]
    try:
        fd = os.open(PANEL_AUDIT_LOG,os.O_WRONLY|os.O_CREAT|os.O_APPEND|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'a',encoding='utf-8') as fp:
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
    if not re.fullmatch(r'[0-9]{5,20}:[A-Za-z0-9_-]{20,100}', token) or not re.fullmatch(r'-?[0-9]{1,20}', chat_id):
        raise ValueError('Некорректный токен Telegram или Chat ID.')
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
        raise ValueError('Ручное продление доступно для Let\'s Encrypt. Новый self-signed меняет доверенный сертификат клиентов.')
    output = checked_run(['timeout', '--signal=TERM', '--kill-after=20s', '240s', '/usr/local/sbin/trusttunnel-cert-renew', '--force-renewal'], timeout=270)
    DEEPLINK_CACHE.clear()
    audit_log('certificate_renewed')
    return output or 'Сертификат обновлён общим обработчиком меню и панели.'


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
    if not PANEL_AUDIT_LOG.is_file(): return 'No panel actions recorded yet.'
    with PANEL_AUDIT_LOG.open('rb') as fp:
        size = fp.seek(0,os.SEEK_END)
        fp.seek(max(0,size-262144))
        output = fp.read(262144).decode('utf-8',errors='replace')
    return ('Показаны последние 256 КиБ журнала.\n' if size > 262144 else '')+output
def rules_text():
    try: path = managed_rules_path()
    except ValueError:
        return '# Используется нестандартный rules_file: управление из панели отключено.\n'
    return read_text(path) or '# Правил нет: разрешены все аутентифицированные клиенты.\n'



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
    require_no_firewall_pending()
    if interface_enabled():
        raise ValueError('Перед сменой VPN-порта временно переключите маршрут с интерфейсного WARP на SOCKS или Direct, затем включите интерфейс снова.')
    if not validate_port(new_port):
        raise ValueError('Некорректный порт TrustTunnel.')
    new_port = str(int(new_port))
    old_port = endpoint_port()
    if new_port == old_port:
        return f'TrustTunnel port already {old_port}.'
    if new_port in (current_ssh_port(), current_panel_env().get('PANEL_PORT', '8088')):
        raise ValueError('Порт уже используется SSH или панелью.')
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(socket.AF_INET, kind) as test:
            try: test.bind(('0.0.0.0', int(new_port)))
            except OSError: raise ValueError('Выбранный порт уже занят.') from None
    with admin_lock():
        cfg = TT_DIR / 'vpn.toml'
        old = read_text(cfg)
        parsed = tomllib.loads(old)
        listen = parsed.get('listen_address', '')
        if not listen or ':' not in listen:
            raise ValueError('Не найден адрес прослушивания endpoint.')
        host = listen.rsplit(':', 1)[0]
        text = re.sub(r'(?m)^listen_address\s*=\s*"[^"]+"', 'listen_address = ' + json.dumps(host + ':' + new_port), old, count=1)
        profiles = {}
        users = {c['username'] for c in load_clients()}
        for path in CLIENT_DIR.glob('*.toml'):
            body = read_text(path)
            data = tomllib.loads(body)
            if data.get('username') in users:
                updated, count = re.subn(r'(?m)^addresses[ \t]*=[ \t]*\[[^\]]*\]', 'addresses = ' + json.dumps([domain() + ':' + new_port]), body, count=1)
                if not count or tomllib.loads(updated).get('addresses') != [domain() + ':' + new_port]:
                    raise ValueError('Не удалось безопасно обновить адрес в ' + path.name)
                profiles[path] = (body, updated)
        protocols = ['tcp', 'udp'] if quic_enabled() else ['tcp']
        for proto in protocols:
            checked_run(['ufw', 'allow', f'{new_port}/{proto}', 'comment', 'TrustTunnel'])
        try:
            apply_endpoint_file(cfg, text)
            for path, (_, updated) in profiles.items():
                atomic_write(path, updated)
        except Exception:
            atomic_write(cfg, old)
            for path, (body, _) in profiles.items(): atomic_write(path, body)
            run(['systemctl', 'restart', 'trusttunnel'])
            raise
        DEEPLINK_CACHE.clear()
        SNAPSHOT_CACHE.clear()
        refresh_client_archive()
        audit_log('endpoint-port', old_port + ' -> ' + new_port)
        return f'Порт TrustTunnel: {old_port} → {new_port}. Адреса в профилях обновлены; прочие параметры сохранены. Старое правило UFW оставлено для ручной проверки.'


def update_panel_access(mode, port):
    require_no_firewall_pending()
    if not validate_port(port) or mode not in ('https', 'localhost'):
        raise ValueError('Некорректный режим или порт панели.')
    port = str(int(port))
    if port in (current_ssh_port(), endpoint_port()):
        raise ValueError('Этот порт уже используется SSH или VPN.')
    env = current_panel_env()
    old_port = env.get('PANEL_PORT', '8088')
    if port != old_port:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try: probe.bind(('0.0.0.0', int(port)))
            except OSError: raise ValueError('Порт панели уже занят.') from None
    if mode == 'https':
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(TT_DIR / 'certs/cert.pem', TT_DIR / 'certs/key.pem')
        except (OSError, ssl.SSLError):
            raise ValueError('Сертификат или ключ панели не прошёл проверку.') from None
        env['PANEL_BIND'] = '0.0.0.0'
        env['PANEL_TLS'] = '1'
        env['PANEL_CERT'] = str(TT_DIR / 'certs' / 'cert.pem')
        env['PANEL_KEY'] = str(TT_DIR / 'certs' / 'key.pem')
        panel_firewall(True,port)
    else:
        env['PANEL_BIND'] = '127.0.0.1'
        env['PANEL_TLS'] = '0'
        panel_firewall(False,old_port)
    if mode == 'https' and port != old_port:panel_firewall(False,old_port)
    env['PANEL_PORT'] = port
    text = ''.join(f'{k}={v}\n' for k, v in env.items() if k.startswith('PANEL_'))
    atomic_write('/etc/trusttunnel-panel.env', text)
    subprocess.Popen(['sh', '-c', 'sleep 1; systemctl restart trusttunnel-panel >/dev/null 2>&1'])
    scheme = 'https' if mode == 'https' else 'http'
    host = domain() if mode == 'https' and domain() else '127.0.0.1'
    return f'Panel access updated: {scheme}://{host}:{port}. Service will restart now.'


def panel_firewall(open_port, port):
    require_no_firewall_pending()
    if not validate_port(port):raise ValueError('Некорректный порт панели.')
    port = str(int(port))
    status = checked_run(['ufw','status'])
    lines = [line for line in status.splitlines() if re.match(r'^'+re.escape(port)+r'/tcp(?:\s|\()',line) and 'ALLOW' in line]
    if open_port:
        if not lines:checked_run(['ufw','allow',port+'/tcp','comment','TrustTunnel Panel HTTPS'])
    elif lines and all('# TrustTunnel Panel HTTPS' in line for line in lines):
        checked_run(['ufw','--force','delete','allow',port+'/tcp'])


def update_panel_credentials(username, password):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', username or ''):
        raise ValueError('Некорректный логин панели.')
    if not re.fullmatch(r'[A-Za-z0-9._~!@%+,:/-]{12,128}', password or ''):
        raise ValueError('Пароль: 12–128 букв, цифр или . _ ~ ! @ % + , : / -; без пробелов и кавычек.')
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
    require_no_firewall_pending()
    if action in ('install','update-trusttunnel') and strict_protection_locked():
        raise ValueError('Сначала явно отключите строгую TLS/ClientHello-защиту. Переустановка/смена версии может удалить правила или установить несовместимый endpoint.')
    allowed = {'install', 'update-trusttunnel', 'install-warp', 'remove-warp', 'reregister-warp', 'enable-warp', 'disable-warp', 'check-warp', 'backup-identity', 'switch-certificate-mode'}
    if action not in allowed:
        raise ValueError('Неподдерживаемая операция установщика.')
    dangerous = {'install', 'remove-warp', 'reregister-warp'}
    if action in dangerous and values.get('confirm', '') != 'REINSTALL':
        raise ValueError('Подтвердите операцию переустановки или удаления.')
    env = os.environ.copy()
    env['ACTION'] = action
    env['AUTO_CONFIRM'] = '1'
    channel = values.get('channel', 'stable')
    if channel not in ('stable', 'beta'):
        raise ValueError('Неизвестный канал обновлений.')
    if channel == 'beta' and values.get('beta_confirm') != 'BETA':
        raise ValueError('Предварительный выпуск: введите BETA для явного выбора этого канала.')
    env['TT_CHANNEL'] = channel
    if action == 'switch-certificate-mode':
        if values.get('confirm') != 'SWITCH':
            raise ValueError('Смена сертификата может потребовать новый профиль на устройствах. Введите SWITCH.')
        mode = values.get('cert_mode')
        if mode not in ('letsencrypt', 'self-signed'):
            raise ValueError('Неизвестный режим сертификата.')
        email = values.get('email', '').strip()
        if mode == 'letsencrypt' and not re.fullmatch(r'[A-Za-z0-9.!#$%&*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', email):
            raise ValueError('Укажите email для Let\'s Encrypt.')
        env.update(CERT_MODE=mode, EMAIL=email, PRESERVE_CLIENT_CONFIGS='1')
    if action == 'install':
        defaults = installer_defaults()
        domain_value = values.get('domain', '').strip()
        if not re.fullmatch(r'[A-Za-z0-9.-]{3,253}', domain_value):
            raise ValueError('Некорректный домен.')
        clients = values.get('clients', defaults['clients']).strip()
        port = values.get('endpoint_port', defaults['endpoint_port']).strip()
        if not clients.isdigit() or not 1 <= int(clients) <= 500:
            raise ValueError('Количество клиентов: 1–500.')
        if not validate_port(port):
            raise ValueError('Некорректный порт TrustTunnel.')
        cert = values.get('cert_mode', defaults['cert_mode'])
        if cert not in ('self-signed', 'letsencrypt'):
            raise ValueError('Некорректный режим сертификата.')
        email = values.get('email', '').strip()
        if cert == 'letsencrypt' and not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
            raise ValueError('Укажите email для Let\'s Encrypt.')
        env.update({
            'DOMAIN': domain_value, 'CLIENTS': clients, 'ENDPOINT_PORT': port,
            'SSH_PORT': defaults['ssh_port'], 'CHANGE_SSH_PORT': '0',
            'ENABLE_SYSTEM_UPGRADE': '0', 'ENABLE_WARP': '1' if values.get('warp') == '1' else '0',
            'ENABLE_QUIC': '1' if values.get('quic') == '1' else '0', 'ENABLE_FAIL2BAN': '1',
            'PRESERVE_CLIENT_CONFIGS': '1', 'CONFIRM_FIREWALL_RESET': '1',
            'CERT_MODE': cert, 'EMAIL': email or 'admin@example.invalid',
        })
    rc, out = run(['/bin/bash', '/usr/local/sbin/trusttunnel-menu'], timeout=900, input_text='', env=env)
    audit_log('installer_operation', action)
    if rc:
        raise RuntimeError(out or f'Установщик завершился с кодом {rc}.')
    SNAPSHOT_CACHE.clear()
    return out or 'Операция завершена.'

def confirmed(values):
    if values.get('confirm') != 'CONFIRMED':
        raise ValueError('Подтвердите действие кнопкой; из CLI укажите confirm=CONFIRMED.')


def normalized_ip(value):
    address = ipaddress.ip_address(value)
    return address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address


def admin_peer(values):
    value = values.get('_peer') or os.environ.get('SSH_CONNECTION', '').split(' ')[0]
    return normalized_ip(value) if value else None


def ssh_listener_ports():
    ports = {(int(current_ssh_port()), 'tcp')}
    rc, output = run(['sshd', '-T'], timeout=5)
    if rc == 0:
        ports.update((int(p), 'tcp') for p in re.findall(r'(?m)^port (\d+)$', output) if validate_port(p))
    rc, output = run(['ss', '-H', '-lntp'], timeout=5)
    if rc == 0:
        for line in output.splitlines():
            if '"sshd"' in line and len(line.split()) >= 4:
                port = line.split()[3].rsplit(':', 1)[-1]
                if validate_port(port): ports.add((int(port), 'tcp'))
    rc, output = run(['systemctl','show','ssh.socket','sshd.socket','--property=Listen','--value'],timeout=5)
    if rc == 0:
        ports.update((int(p),'tcp') for p in re.findall(r':(\d+) \(Stream\)',output) if validate_port(p))
    return sorted(ports)


def protected_ports():
    ports = set(ssh_listener_ports()) | {(int(endpoint_port()),'tcp')}
    if quic_enabled(): ports.add((int(endpoint_port()),'udp'))
    panel_port = current_panel_env().get('PANEL_PORT','8088')
    if validate_port(panel_port): ports.add((int(panel_port),'tcp'))
    return sorted(ports)


def firewall_files():
    names = ('user.rules', 'user6.rules', 'ufw.conf', 'before.rules', 'before6.rules', 'after.rules', 'after6.rules')
    return {**{name: UFW_DIR/name for name in names}, 'defaults': UFW_DEFAULTS}


def firewall_pending():
    text = read_text(FIREWALL_PENDING)
    return json.loads(text) if text else None


def require_no_firewall_pending():
    if firewall_pending(): raise ValueError('Сначала подтвердите или откатите ожидающее изменение UFW; смена портов и обслуживание пока заблокированы.')


def firewall_rollback(token):
    with admin_lock():
        pending = firewall_pending()
        if not pending or not secrets.compare_digest(pending['token'], token): return 'Ожидающего отката нет.'
        for name, path in firewall_files().items():
            saved = pending['files'][name]
            if path.is_symlink(): raise RuntimeError('Откат остановлен: символическая ссылка '+str(path))
            if saved is None: path.unlink(missing_ok=True)
            else: atomic_write(path, saved['text'], saved['mode'])
        checked_run(['ufw', '--force', 'enable' if pending['active'] else 'disable'])
        FIREWALL_PENDING.unlink()
        SNAPSHOT_CACHE.clear()
        audit_log('ufw-rollback', token[:12])
        return 'Прежние файлы и состояние UFW восстановлены.'


def firewall_transaction(commands, values):
    if firewall_pending(): raise ValueError('Сначала подтвердите или откатите предыдущее изменение UFW.')
    if run(['systemctl','is-active','--quiet','trusttunnel-cert-renew.service'],timeout=5)[0] == 0:
        raise ValueError('Сейчас выполняется обновление сертификата. Дождитесь завершения работы с временным портом ACME.')
    files = {}
    for name, path in firewall_files().items():
        if path.is_symlink(): raise ValueError('Настройки UFW содержат символическую ссылку. Изменения отменены.')
        if path.exists() and (not path.is_file() or path.stat().st_size > 2*1024*1024): raise ValueError('Некорректный файл UFW.')
        files[name] = {'text': read_text(path), 'mode': path.stat().st_mode & 0o777} if path.exists() else None
    token = secrets.token_hex(16)
    unit = 'trusttunnel-ufw-rollback-'+token
    pending = {'token': token, 'unit': unit, 'deadline': time.time()+120, 'files': files,
               'active': 'Status: active' in checked_run(['ufw', 'status']), 'peer': str(admin_peer(values) or '')}
    atomic_write(FIREWALL_PENDING, json.dumps(pending))
    try:
        # The independent systemd timer survives a hung or stopped panel process.
        checked_run(['systemd-run', '--quiet', '--unit='+unit, '--on-active=120s',
                     '--property=Restart=on-failure', '--property=RestartSec=5s',
                     sys.executable, str(Path(__file__).resolve()), '--firewall-rollback', token])
    except Exception:
        FIREWALL_PENDING.unlink(missing_ok=True)
        raise RuntimeError('Не удалось запустить независимый таймер отката; UFW не изменён.') from None
    try:
        output = '\n'.join(checked_run(cmd) for cmd in commands)
    except Exception as exc:
        try: firewall_rollback(token)
        except Exception: raise RuntimeError('Ошибка UFW; автоматический откат ещё ожидается. Проверьте доступ через консоль хостинга.') from exc
        run(['systemctl', 'stop', unit+'.timer'])
        raise RuntimeError('Ошибка UFW; прежние настройки восстановлены: '+str(exc)) from None
    audit_log('ufw-change', str(commands))
    return output+'\n\nИзменения временные: подтвердите сохранность доступа в течение 120 секунд. Иначе UFW восстановится автоматически.'


@cached_snapshot(5)
def firewall_snapshot():
    rc, verbose = run(['ufw', 'status', 'verbose'], timeout=5)
    rc2, numbered = run(['ufw', 'status', 'numbered'], timeout=5)
    rc3, added = run(['ufw', 'show', 'added'], timeout=5)
    version = hashlib.sha256((numbered+'\n'+added+'\n'+''.join(read_text(p) for p in firewall_files().values())).encode()).hexdigest()
    rows = [{'number': int(m[1]), 'text': m[2]} for m in re.finditer(r'(?m)^\[\s*(\d+)\]\s+(.+)$', numbered)]
    return {'available': rc == rc2 == rc3 == 0, 'active': 'Status: active' in verbose,
            'verbose': verbose, 'added': added, 'rules': rows, 'version': version}


def firewall_rule(values):
    decision, direction, proto = (values.get(k, default) for k, default in [('decision','allow'),('direction','in'),('proto','tcp')])
    if decision not in ('allow','deny','reject','limit') or direction not in ('in','out') or proto not in ('tcp','udp'):
        raise ValueError('Недопустимое действие, направление или протокол UFW.')
    if decision == 'limit' and (proto != 'tcp' or direction != 'in'): raise ValueError('Limit поддерживается только для входящего TCP.')
    port = values.get('port','').strip()
    match = re.fullmatch(r'([0-9]{1,5})(?::([0-9]{1,5}))?', port)
    if not match: raise ValueError('Укажите порт или диапазон вида 10000:10100.')
    low, high = int(match[1]), int(match[2] or match[1])
    if not 1 <= low <= high <= 65535: raise ValueError('Некорректный диапазон портов.')
    source, destination = (values.get(k,'').strip() for k in ('source','destination'))
    source = str(ipaddress.ip_network(source,strict=False)) if source else 'any'
    destination = str(ipaddress.ip_network(destination,strict=False)) if destination else 'any'
    if source != 'any' and destination != 'any' and ipaddress.ip_network(source).version != ipaddress.ip_network(destination).version:
        raise ValueError('Источник и назначение должны быть одной версии IP.')
    if decision != 'allow' and any(low <= p <= high and proto == pr for p,pr in protected_ports()):
        raise ValueError('Нельзя ограничивать порты SSH, VPN или панели. Сначала измените настройки соответствующего сервиса.')
    interface = values.get('interface','').strip()
    if interface and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',interface): raise ValueError('Некорректное имя интерфейса.')
    comment = values.get('comment','').strip()
    if len(comment) > 80 or any(ord(c) < 32 or ord(c) == 127 or c in "'\"" for c in comment): raise ValueError('Комментарий: до 80 символов без кавычек и управляющих знаков.')
    rule = [decision,direction]+(['on',interface] if interface else [])
    rule += ['proto',proto,'from',source,'to',destination,'port',str(low) if low == high else f'{low}:{high}']
    if comment: rule += ['comment',comment]
    position = values.get('position','append')
    if position not in ('append','prepend'): raise ValueError('Неизвестное положение правила.')
    return ['ufw']+(['prepend'] if position == 'prepend' else [])+rule


def firewall_delete(values):
    SNAPSHOT_CACHE.pop('firewall_snapshot',None)
    snapshot = firewall_snapshot()
    if not snapshot['available']: raise ValueError('Не удалось перечитать правила UFW.')
    if not values.get('version') or not secrets.compare_digest(values['version'],snapshot['version']):
        raise ValueError('Правила изменились или форма устарела. Обновите список и повторите действие.')
    number = values.get('number','')
    if not re.fullmatch(r'[0-9]{1,5}',number): raise ValueError('Некорректный номер правила.')
    row = next((r for r in snapshot['rules'] if r['number'] == int(number)),None)
    if row is None: raise ValueError('Правило не найдено.')
    # Unknown application profiles and broad permits are fail-closed on deletion.
    if re.search(r'\b(?:ALLOW|LIMIT)\b',row['text']):
        target = re.split(r'\s{2,}',row['text'])[0]
        tokens = re.findall(r'(?<![\w.:])([0-9]{1,5})(?::([0-9]{1,5}))?(?:/(tcp|udp))?(?![\w.:])',target)
        if not tokens or any(int(lo) <= p <= int(hi or lo) and (not pr or pr == proto)
                             for lo,hi,pr in tokens for p,proto in protected_ports()):
            raise ValueError('Это разрешение может обеспечивать SSH, VPN или панель. Удаление из панели запрещено.')
    return ['ufw','--force','delete',str(int(number))]


def firewall_baseline_commands():
    SNAPSHOT_CACHE.pop('firewall_snapshot',None)
    data = firewall_snapshot()
    if not data['available']: raise ValueError('Не удалось прочитать существующие правила. Базовые разрешения не изменены.')
    permitted = []
    for row in data['rules']:
        if not re.search(r'\b(?:ALLOW|LIMIT) IN\b',row['text']): continue
        target = re.split(r'\s{2,}',row['text'])[0].replace(' (v6)','')
        if target == 'Anywhere': return []
        match = re.fullmatch(r'(\d+)(?::(\d+))?(?:/(tcp|udp))?',target)
        if not match: raise ValueError('Есть разрешение с профилем приложения или сложным назначением. Автоматическое добавление широких разрешений отменено; сначала проверьте правила вручную.')
        permitted.append((int(match[1]),int(match[2] or match[1]),match[3]))
    return [['ufw','insert','1','allow',f'{p}/{proto}','comment','TrustTunnel protected access']
            for p,proto in protected_ports() if not any(lo <= p <= hi and (not pr or pr == proto) for lo,hi,pr in permitted)]


def firewall_operation(action, values):
    if action == 'snapshot':
        SNAPSHOT_CACHE.pop('firewall_snapshot',None)
        return json.dumps(firewall_snapshot(),ensure_ascii=False)
    if action == 'pending':
        pending = firewall_pending()
        return pending['token'] if pending else ''
    if action == 'status':
        SNAPSHOT_CACHE.pop('firewall_snapshot',None)
        data = firewall_snapshot()
        return data['verbose']+'\n\n'+data['added']
    if action == 'applications': return checked_run(['ufw','app','list'])
    if action == 'logs': return checked_run(['journalctl','-k','--no-pager','-n','200','--grep=\\[UFW '])
    if action in ('confirm','rollback'):
        confirmed(values)
        pending = firewall_pending()
        if not pending or not secrets.compare_digest(values.get('token',''),pending['token']): raise ValueError('Ожидающее изменение уже завершено или устарело.')
        if action == 'rollback': return firewall_rollback(pending['token'])
        if time.time() >= pending['deadline']:
            firewall_rollback(pending['token']); raise ValueError('Срок подтверждения истёк; настройки восстановлены.')
        checked_run(['systemctl','stop',pending['unit']+'.timer'])
        FIREWALL_PENDING.unlink()
        audit_log('ufw-confirm',pending['token'][:12])
        return 'Сохранность доступа подтверждена. Изменения UFW сохранены.'
    if action == 'preview': return checked_run(['ufw','--dry-run',*firewall_rule(values)[1:]])
    confirmed(values)
    if action == 'install':
        require_no_firewall_pending()
        return checked_run(['apt-get','-o','Acquire::Retries=3','install','-y','--no-install-recommends','--no-upgrade','ufw'],timeout=180)
    if action == 'rule': commands = [firewall_rule(values)]
    elif action == 'source-block':
        network = ipaddress.ip_network(values.get('source',''),strict=False)
        if isinstance(network,ipaddress.IPv6Network) and network.prefixlen >= 96 and network.network_address.ipv4_mapped:
            network = ipaddress.ip_network((network.network_address.ipv4_mapped,network.prefixlen-96),strict=False)
        peer = admin_peer(values)
        loopback = ipaddress.ip_network('127.0.0.0/8' if network.version == 4 else '::1/128')
        if network.prefixlen == 0 or network.overlaps(loopback) or (peer and peer.version == network.version and peer in network):
            raise ValueError('Нельзя заблокировать весь интернет, loopback или адрес текущего администратора.')
        commands = [['ufw','prepend','deny','in','from',str(network),'to','any','comment','TrustTunnel blocked source']]
    elif action == 'delete': commands = [firewall_delete(values)]
    elif action in ('enable','baseline'):
        commands = firewall_baseline_commands()
        if action == 'enable': commands.append(['ufw','--force','enable'])
    elif action in ('disable','reload'): commands = [['ufw','--force',action]]
    elif action == 'logging':
        level = values.get('level','')
        if level not in ('off','low','medium','high','full'): raise ValueError('Некорректный уровень журналирования.')
        commands = [['ufw','logging',level]]
    elif action == 'default':
        policy, direction = values.get('policy',''), values.get('direction','')
        if direction not in ('incoming','outgoing','routed') or policy not in ('allow','deny','reject'): raise ValueError('Некорректная политика UFW.')
        if direction != 'incoming' and policy != 'allow': raise ValueError('Блокировка исходящего/маршрутизируемого трафика может отключить WARP и DNS. Настройте отдельные адресные правила.')
        commands = firewall_baseline_commands()
        commands.append(['ufw','default',policy,direction])
    else: raise ValueError('Неизвестная операция UFW. Полный сброс правил из панели запрещён.')
    if not commands: return 'Необходимые разрешения уже существуют; ограничения источников сохранены. UFW не изменён.'
    return firewall_transaction(commands,values)


@cached_snapshot(10)
def fail2ban_snapshot():
    rc, status = run(['fail2ban-client','status'],timeout=5)
    match = re.search(r'Jail list:\s*([^\n]*)',status)
    active = [v.strip() for v in match[1].split(',') if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',v.strip())] if match else []
    configured = {'sshd'}
    for path in [FAIL2BAN_DIR/'jail.conf',FAIL2BAN_DIR/'jail.local',*sorted((FAIL2BAN_DIR/'jail.d').glob('*.conf')),*sorted((FAIL2BAN_DIR/'jail.d').glob('*.local'))]:
        if path.is_file() and path.stat().st_size <= 1024*1024:
            configured.update(s for s in re.findall(r'(?m)^\[([A-Za-z0-9][A-Za-z0-9_.-]{0,63})\]\s*$',read_text(path)) if s not in ('DEFAULT','INCLUDES'))
    return {'available':rc == 0,'active':active,'configured':sorted(configured),'status':status,
            'service':service_status('fail2ban')}


def jail_name(values):
    jail = values.get('jail','sshd')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',jail) or jail not in set(fail2ban_snapshot()['configured']+fail2ban_snapshot()['active']):
        raise ValueError('Выберите существующий jail; произвольные имена запрещены.')
    return jail


def save_jail_override(jail, updates):
    old = read_text(FAIL2BAN_OVERRIDE)
    config = configparser.ConfigParser(interpolation=None)
    if old:
        try: config.read_string(old)
        except configparser.Error: raise ValueError('Управляемый override fail2ban повреждён. Исправьте его вручную; файл не изменён.') from None
    if not config.has_section(jail): config.add_section(jail)
    config[jail].update(updates)
    output = io.StringIO(); config.write(output)
    atomic_write(FAIL2BAN_OVERRIDE,output.getvalue())
    try:
        checked_run(['fail2ban-client','-t'])
        if service_status('fail2ban') == 'active': checked_run(['fail2ban-client','reload'])
    except Exception:
        if old: atomic_write(FAIL2BAN_OVERRIDE,old)
        else: FAIL2BAN_OVERRIDE.unlink(missing_ok=True)
        if service_status('fail2ban') == 'active': run(['fail2ban-client','reload'])
        raise


def fail2ban_ignores(output):
    tokens = []
    for line in output.splitlines():
        line = line.strip().lstrip('|`- ').strip()
        if not line or line.endswith(':'): continue
        for value in re.split(r'[\s,]+',line):
            try: value = str(ipaddress.ip_network(value,strict=False))
            except ValueError:
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',value): raise ValueError('Неподдерживаемый формат исключений; автоматическая перезапись отменена.') from None
            if value not in tokens: tokens.append(value)
    return tokens


def fail2ban_operation(action, values):
    if action == 'status':
        data = fail2ban_snapshot()
        return 'Сервис: '+data['service']+'\n'+data['status']+'\nНастроенные jail: '+', '.join(data['configured'])
    if action == 'test': return checked_run(['fail2ban-client','-t'])
    if action == 'logs': return recent_logs('fail2ban',200)
    if action in ('install','enable','disable','restart','reload'):
        confirmed(values)
        if action == 'install':
            result = checked_run(['apt-get','-o','Acquire::Retries=3','install','-y','--no-install-recommends','--no-upgrade','fail2ban'],timeout=180)
        elif action == 'disable': result = checked_run(['systemctl','disable','--now','fail2ban'])
        else:
            checked_run(['fail2ban-client','-t'])
            if action == 'reload': result = checked_run(['fail2ban-client','reload'])
            else:
                result = checked_run(['systemctl',*(['enable','--now'] if action == 'enable' else ['restart']),'fail2ban'])
                wait_fail2ban()
        audit_log('f2b-'+action)
        return result or 'Операция fail2ban завершена; включение службы не включает автоматически все jail.'
    jail = jail_name(values)
    if action == 'jail-status':
        return checked_run(['fail2ban-client','status',jail])+'\n\n'+'\n'.join(k+': '+checked_run(['fail2ban-client','get',jail,k]) for k in ('maxretry','findtime','bantime','ignoreip'))
    confirmed(values)
    if action in ('ban','unban'):
        address = normalized_ip(values.get('ip',''))
        if action == 'ban' and (address.is_loopback or address.is_unspecified or address.is_multicast or address == admin_peer(values)):
            raise ValueError('Нельзя заблокировать текущего администратора, loopback или служебный адрес.')
        result = checked_run(['fail2ban-client','set',jail,'banip' if action == 'ban' else 'unbanip',str(address)])
    elif action == 'settings':
        retry, window, ban = (int(values.get(k,'')) for k in ('retry','findtime','bantime'))
        if not 1 <= retry <= 100 or not 60 <= window <= 86400 or not 60 <= ban <= 604800: raise ValueError('Попытки 1–100, окно 60–86400 с, бан 60–604800 с.')
        updates = {'maxretry':str(retry),'findtime':str(window),'bantime':str(ban)}
        if 'increment' in values:
            if values['increment'] not in ('0','1'): raise ValueError('Некорректный режим нарастающего бана.')
            maximum = int(values.get('maxtime','604800'))
            if not ban <= maximum <= 2592000: raise ValueError('Максимальный бан: от начального срока до 30 дней.')
            updates.update({'bantime.increment':'true' if values['increment'] == '1' else 'false','bantime.maxtime':str(maximum)})
        save_jail_override(jail,updates)
        result = 'Параметры jail сохранены; чужие файлы и остальные jail не переписаны.'
    elif action in ('jail-enable','jail-disable'):
        updates = {'enabled':'true' if action.endswith('enable') else 'false'}
        if jail == 'sshd' and action.endswith('enable'): updates.update({'port':','.join(str(p) for p,proto in ssh_listener_ports()),'backend':'systemd'})
        save_jail_override(jail,updates)
        result = 'Состояние jail сохранено. Если служба остановлена, включите её отдельно.'
    elif action in ('ignore-add','ignore-remove'):
        network = ipaddress.ip_network(values.get('ip',''),strict=False)
        if network.prefixlen == 0: raise ValueError('Нельзя исключить из защиты весь интернет.')
        tokens = fail2ban_ignores(checked_run(['fail2ban-client','get',jail,'ignoreip']))
        token = str(network)
        if action == 'ignore-add': tokens = list(dict.fromkeys(tokens+[token]))
        else:
            peer = admin_peer(values)
            loopback = ipaddress.ip_network('127.0.0.0/8' if network.version == 4 else '::1/128')
            if network.overlaps(loopback) or (peer and peer.version == network.version and peer in network): raise ValueError('Нельзя удалить исключение loopback или текущего администратора.')
            if token not in tokens: raise ValueError('Исключение не найдено.')
            tokens.remove(token)
        save_jail_override(jail,{'ignoreip':' '.join(tokens)})
        result = 'Постоянные исключения '+jail+': '+', '.join(tokens)
    else: raise ValueError('Неизвестная операция fail2ban.')
    audit_log('f2b-'+action,jail)
    return result


def fail2ban_output(action, ip='', values=None):
    values = dict(values or {}, ip=ip)
    with admin_lock(): return fail2ban_operation(action,values)


def ufw_output(action, port='', proto='tcp', values=None):
    values = dict(values or {},port=port,proto=proto)
    if action == 'allow': action = 'rule'
    if action == 'rebuild': action = 'baseline'
    with admin_lock(): return firewall_operation(action,values)
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
:root{--canvas:#edf1f3;--surface:#ffffff;--ink:#20252d;--muted:#606d77;--line:#d7dfe4;--accent:#08786c;--accent-soft:#e0f2ed;--glass:#ffffffc9;--glass-edge:#ffffff;--shadow:0 5px 18px #23363d08,0 1px 2px #23363d08}
html[data-theme=dark]{--canvas:#181a1e;--surface:#23262b;--ink:#eef1f5;--muted:#a9b2bf;--line:#3c4149;--accent:#67d5b6;--accent-soft:#214139;--glass:#24272de0;--glass-edge:#ffffff16;--nav-hover:#30343b;--nav-active:#23443c;--shadow:0 5px 22px #00000020}
body{background-image:linear-gradient(#78899507 1px,transparent 1px),linear-gradient(90deg,#78899507 1px,transparent 1px);background-size:40px 40px}
.sidebar{background:var(--glass);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);padding-top:30px;box-shadow:inset -1px 0 0 var(--glass-edge)}
.brand{gap:11px;padding:0 8px;margin-bottom:34px}.brand>.icon{width:32px;height:32px;color:var(--accent)}.brand small,.nav-label,.eyebrow{letter-spacing:0}.brand small{font-size:10px;margin-top:1px}.nav-label{font-size:11px;font-weight:500}.nav-item{position:relative;transition:background .16s,color .16s}.nav-item.active{box-shadow:inset 3px 0 0 var(--accent)}.nav-item:hover .icon{color:var(--accent)}
.topbar{background:var(--glass);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);box-shadow:0 1px 0 var(--glass-edge);height:76px}.endpoint-context{gap:14px}.endpoint-context>span{font-size:12px}.content{padding-top:32px}.page-head h2{font-size:29px}.eyebrow{font-size:10px;color:var(--muted);margin-bottom:8px}.page-head p{margin-top:9px}.version-pill{background:var(--glass);font-variant-numeric:tabular-nums}.page-actions{gap:10px}
.metric{position:relative;background:var(--glass);border-color:var(--glass-edge);box-shadow:var(--shadow);padding:22px 20px;overflow:hidden}.metric::before{content:"";position:absolute;top:0;left:20px;right:20px;height:2px;background:#137e7180}.metric:nth-child(2)::before{background:#3e85b7a8}.metric:nth-child(3)::before{background:#ba864da8}.metric:nth-child(4)::before{background:#a76a85a8}.metric strong{font-size:23px;margin:17px 0 9px;font-weight:650}.metric small{font-size:12px}.metric-caption{font-size:11px}.resource-bars{padding:4px 0 8px}.surface{padding:28px 0}.surface h3{font-size:15px}.traffic-surface{border-top:0;padding-top:20px}.section-heading{margin-bottom:24px}.network-rate{font-size:19px;margin-top:10px}.service-row{padding:15px 0}.overview-columns{gap:40px}
button,.button{box-shadow:0 1px 1px #152b3508;transition:background .16s,border-color .16s,box-shadow .16s,transform .16s}button:hover:not(:disabled),.button:hover{transform:translateY(-1px);box-shadow:0 3px 8px #152b3512}button:active:not(:disabled),.button:active{transform:translateY(0);box-shadow:none}.primary{box-shadow:inset 0 1px 0 #ffffff25,0 2px 4px #0d67541a}button.primary{color:#ffffff}html[data-theme=dark] button.primary{color:#153329}.icon-button{box-shadow:none;background:transparent}.table-wrap{border-color:var(--glass-edge);background:var(--glass);box-shadow:var(--shadow)}th{padding-top:13px;padding-bottom:13px;background:#7386910b}tbody tr{transition:background .15s}tbody tr:hover{background:#728d9d09}.table-actions button{min-width:110px}.table-toolbar{padding-top:8px;margin-bottom:16px}.pagination button{width:38px}.pagination .icon{width:16px}.client-usage{margin-top:4px;font-variant-numeric:tabular-nums}.security-check{background:var(--glass);border-color:var(--glass-edge);box-shadow:var(--shadow)}
input,select,textarea{box-shadow:inset 0 1px 2px #1b354205;transition:border-color .15s,box-shadow .15s}input:hover,select:hover,textarea:hover{border-color:var(--muted)}input:focus,select:focus,textarea:focus{box-shadow:0 0 0 3px var(--accent-soft);outline:1px solid var(--accent);outline-offset:0}input[type=checkbox]{box-shadow:none}.share-options{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:18px 0 12px}.link-result:empty{margin:0}.link-result textarea{min-height:100px;word-break:break-all;font-size:11px;line-height:1.5}.link-result>.inline-actions{margin-top:12px}.share-qr{width:280px;height:280px;max-width:100%;object-fit:contain;background:#fff;border:1px solid #e1e7eb;padding:0;border-radius:6px;image-rendering:pixelated}.drawer-card{background:var(--surface);padding:28px;box-shadow:-12px 0 45px #00000020}.drawer-head{padding-bottom:22px}.drawer-head .eyebrow{margin-bottom:5px}.drawer-section{padding:24px 0}.drawer-head button{border:0;background:var(--nav-hover);box-shadow:none}.drawer.open .drawer-card{animation:drawer-in .18s ease-out}@keyframes drawer-in{from{transform:translateX(20px);opacity:.7}to{transform:translateX(0);opacity:1}}#operation-result{padding:28px;background:var(--glass);backdrop-filter:blur(18px)}#operation-result pre{background:var(--surface)}.provider-strip{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:12px}.provider-strip>div{display:flex;gap:12px;align-items:center;padding:19px 0;border-bottom:1px solid var(--line)}.provider-strip>.icon{color:var(--accent)}.provider-strip small{display:block;font-size:11px;color:var(--muted);margin-top:3px}.provider-strip .badge{margin-left:auto}.busy-strip{background:var(--ink);color:var(--canvas)}form[aria-busy=true]{opacity:.7;pointer-events:none}#clients-metrics-status{margin-bottom:12px}
html[data-effects=flat] .sidebar,html[data-effects=flat] .topbar,html[data-effects=flat] .mobile-nav,html[data-effects=flat] #operation-result{background:var(--surface);backdrop-filter:none;-webkit-backdrop-filter:none}html[data-effects=flat] body{background-image:none}html[data-effects=flat] .metric,html[data-effects=flat] .security-check,html[data-effects=flat] .table-wrap{background:var(--surface);border-color:var(--line);box-shadow:none}
@media(max-width:800px){.topbar{height:64px}.sidebar{padding-top:25px}.mobile-nav{background:var(--glass);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}.content{padding-top:26px}.page-head h2{font-size:27px}.metric strong{font-size:21px}.metric{padding:18px 16px}.overview-columns{gap:24px}.provider-strip{gap:16px}}
@media(max-width:560px){.header-actions{gap:2px}.topbar .header-actions button{width:32px}.endpoint-context strong{font-size:11px}.page-head h2{font-size:26px}.metric{padding:17px 12px}.metric strong{font-size:18px}.metric::before{left:12px;right:12px}.metric small{font-size:11px}.metric-caption{font-size:10px}.drawer-card{padding:22px 16px}.share-options{gap:10px}.share-qr{width:280px;height:280px;max-width:100%}.provider-strip{grid-template-columns:1fr;gap:0}.provider-strip>div{padding:16px 0}.overview-columns{gap:0}.surface{padding:23px 0}.page-actions{gap:8px}.page-actions button{font-size:12px}.network-rate{font-size:17px}.topbar .endpoint-context{gap:0}.security-check{padding:16px}.share-options select{width:100%}.share-options label{font-size:11px}}
@media(prefers-reduced-transparency:reduce){.sidebar,.topbar,.mobile-nav,#operation-result{background:var(--surface);backdrop-filter:none;-webkit-backdrop-filter:none}}
@media(prefers-reduced-motion:reduce){*,*:before{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
'''

NAV_ITEMS = (
    ('dashboard', 'Обзор'), ('endpoint', 'VPN-сервер'), ('clients', 'Клиенты'),
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


ICONS.update({
    'Download': [('path', {'d':'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'}), ('path', {'d':'m7 10 5 5 5-5'}), ('path', {'d':'M12 15V3'})],
    'Info': [('circle', {'cx':'12','cy':'12','r':'10'}), ('path', {'d':'M12 16v-4'}), ('path', {'d':'M12 8h.01'})],
})


def icon(name):
    aliases = {'Settings2': 'SlidersHorizontal', 'RefreshCw': 'RotateCw', 'Check': 'ArrowUpRight'}
    name = aliases.get(name, name)
    if name == 'Plus':
        nodes = [('path', {'d': 'M12 5v14'}), ('path', {'d': 'M5 12h14'})]
    elif name == 'ChevronLeft':
        nodes = [('path', {'d': 'm15 18-6-6 6-6'})]
    else:
        nodes = ICONS.get(name, [])
    parts = []
    for tag, attrs in nodes:
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
    return f'''<div class="page-head"><div><h2>TrustTunnel Endpoint</h2><p>Установка, версия и транспортные параметры.</p></div><form method="post" action="/installer"><input type="hidden" name="action" value="update-trusttunnel"><button class="primary">Обновить VPN-сервер</button></form></div><section class="surface"><h3>Установка / переустановка</h3><p class="warning">Сохраняются сертификат и текущие пользователи. UFW будет пересобран; для запуска введи REINSTALL.</p><form method="post" action="/installer" class="form-grid"><input type="hidden" name="action" value="install"><label>Домен<input name="domain" value="{html.escape(setup['domain'])}" required></label><label>Количество клиентов<input name="clients" value="{setup['clients']}" required></label><label>Порт endpoint<input name="endpoint_port" value="{setup['endpoint_port']}" required></label><label>Email Let's Encrypt<input name="email" placeholder="только для Let's Encrypt"></label><label>Сертификат<select name="cert_mode"><option value="self-signed" {'selected' if setup['cert_mode'] == 'self-signed' else ''}>self-signed</option><option value="letsencrypt" {'selected' if setup['cert_mode'] == 'letsencrypt' else ''}>Let's Encrypt</option></select></label><label>Подтверждение<input name="confirm" placeholder="REINSTALL" required></label><label class="check"><input type="checkbox" name="warp" value="1" {'checked' if setup['warp'] == '1' else ''}> Включить WARP</label><label class="check"><input type="checkbox" name="quic" value="1" {'checked' if setup['quic'] == '1' else ''}> Включить QUIC/HTTP3</label><div><button class="danger">Установить / переустановить</button></div></form></section><section class="surface"><h3>Порт</h3><form method="post" action="/ports/endpoint"><label>Порт TrustTunnel<input name="port" value="{endpoint_port()}" required></label><button>Сменить порт</button></form></section>'''


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
    status = admin_form('certificate-status', f'<button>{icon("ShieldCheck")}Сертификат и таймер</button>', view='certificates')
    switch = admin_form('certificate-switch', '<label>Режим<select name="cert_mode"><option value="letsencrypt">Let\'s Encrypt</option><option value="self-signed">Самоподписанный</option></select></label><label>Email<input type="email" name="email" autocomplete="email"></label><label>Подтверждение<input name="confirm" placeholder="SWITCH" required></label><button class="danger">Сменить сертификат</button>', view='certificates')
    return f'''<div class="page-head"><div><h2>Сертификаты</h2><p>Текущий режим: {html.escape(cert_mode())}</p></div></div><section class="surface"><div class="inline-actions">{status}<form method="post" action="/action"><button class="primary" name="action" value="renew-cert">{icon('RefreshCw')}Продлить Let's Encrypt</button></form></div></section><section class="surface"><h3>Сменить режим</h3><p>Let's Encrypt доверен устройствами и продлевается автоматически. Для проверки домена нужен доступ извне к 80/tcp; добавленное установщиком правило UFW удаляется после проверки.</p><p>Самоподписанный сертификат не требует 80/tcp, но его нужно передать клиенту. После замены потребуется новый профиль или сертификат на устройстве. Пароли пользователей не меняются.</p>{switch}</section>'''


def security_view():
    return '''<div class="page-head"><div><h2>Безопасность</h2><p>UFW, fail2ban и доступ к серверу.</p></div></div><section class="surface"><h3>fail2ban</h3><form method="post" action="/fail2ban"><button name="action" value="status">Статус</button><button name="action" value="enable">Включить</button><button class="danger" name="action" value="disable">Отключить</button><input name="ip" placeholder="IP для разбана"><button name="action" value="unban">Разбанить</button></form></section><section class="surface"><h3>UFW</h3><form method="post" action="/ufw"><button name="action" value="status">Статус</button><button name="action" value="rebuild">Пересобрать базовые правила</button><input name="port" placeholder="порт"><select name="proto"><option>tcp</option><option>udp</option></select><button name="action" value="allow">Открыть</button><button class="danger" name="action" value="delete">Закрыть</button></form></section>'''


def system_view():
    content = system_details_view()
    boundary = content.index('<section')
    return content[:boundary] + power_controls() + content[boundary:] + diagnostic_console() + schedule_console()


def diagnostic_console():
    stack = admin_form('diagnostics-stack','<button>'+icon('Activity')+'Endpoint, порты и TLS</button>',view='system')
    warp = admin_form('diagnostics-warp','<button>Выход через текущий WARP</button>',view='system')
    egress = admin_form('diagnostics-egress','<label>Направление<select name="target"><option value="cloudflare">Cloudflare</option><option value="github">GitHub</option></select></label><button>Проверить DNS / TCP / TLS</button>',view='system')
    return '<section class="surface"><h3>Диагностика по уровням</h3><p class="muted">Проверки не меняют клиентские профили, firewall и маршрут. WARP проверяется отдельно от прямого выхода VPS. Время DNS/TCP/TLS не является пингом Brawl Stars; внешнюю доступность и DPI нужно дополнительно проверить с устройства.</p>'+stack+warp+egress+'</section>'


def schedule_console():
    options = ''.join('<option value="'+key+'">'+label+'</option>' for key,label in SCHEDULE_KINDS.items())
    days = ''.join('<option value="'+key+'">'+label+'</option>' for key,label in [('daily','Ежедневно'),('Mon','Понедельник'),('Tue','Вторник'),('Wed','Среда'),('Thu','Четверг'),('Fri','Пятница'),('Sat','Суббота'),('Sun','Воскресенье')])
    save = admin_form('schedule-save','<input type="hidden" name="confirm" value="CONFIRMED"><label>Задача<select name="kind">'+options+'</select></label><label>Повторение<select name="day">'+days+'</select></label><label>Время сервера<input type="time" name="time" value="03:30" required></label><label class="check"><input type="checkbox" name="updates_ack" value="1">Для обновления ОС: допускаю перезапуск служб</label><button class="primary">Сохранить расписание</button>',view='system',confirm='Включить автоматическое выполнение выбранной задачи по времени сервера? Перезагрузка разорвёт все подключения, обновление ОС может перезапустить службы.')
    disable = admin_form('schedule-disable','<input type="hidden" name="confirm" value="CONFIRMED"><label>Задача<select name="kind">'+options+'</select></label><button>Отключить расписание</button>',view='system',confirm='Отключить таймер выбранной задачи?')
    status = admin_form('schedule-status','<button>Показать расписания</button>',view='system')
    return '<section class="surface"><h3>Расписания обслуживания</h3><p class="warning">По умолчанию выключены. Время берётся с VPS, а не с телефона. При пропуске задачи немедленного запуска после включения не будет. Новые версии VPN и панели только проверяются, не устанавливаются без решения администратора.</p>'+status+save+disable+'</section>'


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
    vpn_identity = action.startswith(('client-', 'guard-', 'enrollment-')) or action == 'diagnostics-client'
    field = 'vpn_client_name' if vpn_identity else 'username'
    identity = f'<input type="hidden" name="{field}" value="{html.escape(username, quote=True)}">' if username else ''
    if vpn_identity:
        body = body.replace('name="username"', 'name="vpn_client_name" autocomplete="off"')
        if 'name="password" type="password" autocomplete=' not in body:
            body = body.replace('name="password" type="password"', 'name="password" type="password" autocomplete="new-password"')
    return f'<form method="post" action="/manage"{confirmation}><input type="hidden" name="action" value="{action}"><input type="hidden" name="view" value="{view}">{identity}{body}</form>'


def client_source_watch_controls(name, policy):
    watch = policy.get('source_watch', {})
    controls = '<input type="hidden" name="confirm" value="CONFIRMED">'
    controls += f'<label>Окно наблюдения, минут<input name="minutes" type="number" min="5" max="1440" value="{watch.get("minutes",60)}" required></label>'
    controls += f'<label>Предупредить от N сетей<input name="threshold" type="number" min="2" max="100" value="{watch.get("threshold",4)}" required></label>'
    controls += '<label>Считать IPv6<select name="ipv6_prefix">'+''.join(f'<option value="{prefix}" {"selected" if watch.get("ipv6_prefix",64)==prefix else ""}>{title}</option>' for prefix,title in [(64,'По сети /64 (меньше ложных тревог)'),(128,'По каждому адресу /128')])+'</select></label><button>Включить наблюдение сетей</button>'
    save = admin_form('guard-watch-save',controls,name,confirm='Включить предупреждения по наблюдаемым сетям? Автобана и ограничения числа устройств не будет; наблюдение не меняет VPN-профиль.')
    remove = admin_form('guard-watch-remove','<input type="hidden" name="confirm" value="CONFIRMED"><button>Выключить наблюдение</button>',name,confirm='Выключить наблюдение сетей? Квота, срок и доступ клиента останутся прежними.')
    return '<h3>Подозрительное использование</h3><p class="muted" data-client-watch="'+html.escape(name,quote=True)+'">Ожидание отчёта о сетях</p><p class="muted">Это наблюдавшиеся сети за период, не одновременные IP и не число устройств. Wi-Fi, мобильная связь и IPv6 могут дать ложную тревогу. При предупреждении проверьте владельца; не блокируйте общий NAT автоматически.</p>'+save+remove+'<p class="warning">Строгий лимит активных IP пока недоступен: требуется доработка аутентификации endpoint. Привязка к ключу устройства дополнительно требует совместимого клиента. Fail2ban блокирует весь IP и не заменяет эти механизмы.</p>'


def clients_console():
    clients = client_inventory()
    policies = guard_state().get('policies', {})
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
        transports = '<option value="http2">HTTP/2</option>' + ('<option value="http3">QUIC / HTTP3</option>' if quic_enabled() else '')
        kinds = '<option value="static">Обычная ссылка</option>' + ('<option value="protected">ClientHello-префикс</option>' if protection_state().get('prefix') else '') + ('<option value="tls-auth">TLS-аутентификация v1.3</option>' if protection_state().get('auth_key') else '')
        share = (f'<div class="share-options"><label>Транспорт<select id="link-protocol-{index}">{transports}</select></label><label>Профиль<select id="link-kind-{index}">{kinds}' + ('<option value="subscription">Подписка</option>' if endpoint_capabilities()['subscription'] else '') + f'</select></label></div><button type="button" data-load-link="{safe}" data-link-index="{index}">{icon("KeyRound")}Создать ссылку и QR</button><div id="link-result-{index}" class="link-result" aria-live="polite"></div>' if enabled else '<p class="muted">Доступ отключён. Включите клиента, чтобы получить ссылку.</p>')
        toggle = admin_form('client-disable' if enabled else 'client-enable', f'<button role="switch" aria-checked="{str(enabled).lower()}" class="toggle {state}" title="{label}"><span></span></button>', name, confirm='Изменить доступ клиента? Активные подключения TrustTunnel переподключатся.')
        rows.append(f'<tr data-client-row data-online="unknown" data-client="{safe.lower()} {html.escape(client["note"].lower(), quote=True)}" data-protocols="http2 http3" data-state="{state}"><td>{toggle}</td><td><strong>{safe}</strong><span class="muted">{html.escape(client["note"])}</span><span class="badge" data-client-online="{safe}">Статус неизвестен</span><span class="muted client-usage" data-client-metrics="{safe}">Ожидание статистики</span><span class="muted" data-client-seen="{safe}">Последний онлайн: ещё не наблюдался</span></td><td><span class="badge {state}">{label}</span></td><td><span class="protocol">HTTP/2</span> {"<span class=protocol>QUIC</span>" if quic_enabled() else ""}</td><td class="table-actions"><button type="button" data-drawer="{drawer_id}">{icon("Settings2")}Управлять</button></td></tr>')
        note = admin_form('client-note', f'<label>Заметка<input name="note" maxlength="300" value="{html.escape(client["note"], quote=True)}"></label><button>Сохранить</button>', name)
        password = admin_form('client-password', '<label>Новый пароль<input name="password" type="password" placeholder="Пусто: случайный" autocomplete="new-password"></label><button>Сменить пароль</button>', name, confirm='Старый пароль перестанет работать. Потребуется обновить профиль клиента.')
        delete = admin_form('client-delete', '<button class="danger">Удалить клиента</button>', name, confirm='Удалить клиента и отозвать доступ?')
        limits = admin_form('client-limits', ''.join(f'<label>{title}<input name="{key}" type="number" min="1" max="1000" placeholder="Пусто: значение endpoint" value="{client.get(key, "")}"></label>' for key, title in [('max_http2_conns', 'Транспортных туннелей HTTP/2'), ('max_http3_conns', 'Транспортных туннелей QUIC')]) + '<button>Сохранить технические лимиты</button>', name, confirm='Изменить технические лимиты туннелей и перезапустить TrustTunnel? Это не ограничение IP или устройств; малое значение может лишить клиента интернета.')
        policy = policies.get(name, {})
        expiry = datetime.datetime.fromtimestamp(policy['expires_at'], datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M') if policy.get('expires_at') else ''
        quota = str(round(policy.get('quota_bytes',0)/1073741824,3)) if policy.get('quota_bytes') else ''
        guard = admin_form('guard-save', '<input type="hidden" name="confirm" value="CONFIRMED">'+f'<label>Общий трафик, ГиБ<input name="quota_gib" type="number" min="0" max="999999" step="0.001" value="{quota}" placeholder="Без ограничения"></label><label>Действует до, UTC<input type="datetime-local" name="expires" value="{expiry}"></label><label class="check"><input type="checkbox" name="auto_suspend" value="1" {"checked" if policy.get("auto_suspend") else ""}>Автоматически отозвать доступ</label><label class="check"><input type="checkbox" name="disconnect_ack" value="1">Допускаю краткий перезапуск VPN при автоотзыве</label><button>Сохранить политику</button>', name, confirm='Сохранить квоту/срок? Автоотзыв отключит учётную запись при превышении и переподключит VPN-клиентов.')
        guard += admin_form('guard-remove','<input type="hidden" name="confirm" value="CONFIRMED"><button>Убрать квоту и срок</button>',name,confirm='Убрать политику? Уже отключённый доступ не включается автоматически.')
        guard += client_source_watch_controls(name,policy)
        invite = admin_form('enrollment-issue','<input type="hidden" name="confirm" value="CONFIRMED"><label>Срок приглашения, минут<input type="number" min="1" max="1440" name="minutes" value="15" required></label><label>Транспорт<select name="protocol">'+transports+'</select></label><label>Тип профиля<select name="kind">'+kinds+'</select></label><label>IP/CIDR получателя (необязательно)<input name="source_cidr" maxlength="64" placeholder="Например 198.51.100.27/32"><small>Ограничивает только получение. Смена сети может помешать активации; импортированный профиль остаётся копируемым. За reverse proxy проверяется IP прокси, не X-Forwarded-For.</small></label><button>Создать одноразовое приглашение</button>',name,confirm='Создать одноразовую HTTPS-выдачу профиля? Если задан IP/CIDR, получить её можно только из этой сети. Полученный профиль всё ещё можно переслать.')
        invite += admin_form('enrollment-revoke','<input type="hidden" name="confirm" value="CONFIRMED"><button>Отозвать приглашения</button>',name,confirm='Отозвать все неиспользованные приглашения этого клиента?')
        extra = admin_form('diagnostics-client','<button>'+icon('Activity')+'Диагностика клиента</button>',name)
        extra += admin_form('client-refresh-network','<input type="hidden" name="confirm" value="CONFIRMED"><button>Обновить настройки файла подключения</button>',name,confirm='Применить текущие DNS/AntiDPI/TLS-профиль к TOML этого клиента? Потребуется повторный импорт; ключи и SNI сохраняются.')
        controls = '<section class="drawer-section"><h3>Подключения и трафик</h3><p class="muted" data-client-details="'+safe+'">Ожидание статистики</p>'+extra+'</section><details class="drawer-section"><summary>Антишаринг: квота, срок и отзыв</summary><p class="muted">Каждому устройству нужна отдельная учётная запись. Квота: сумма загрузки и отдачи с начала учёта, без сброса за месяц. При недоступных метриках квота не отключает доступ. Срок проверяется независимо. Последний активный клиент автоматически не отключается.</p>'+guard+'</details><details class="drawer-section"><summary>Одноразовая выдача профиля</summary><p class="muted">Секрет приглашения хранится только в виде SHA-256. Открытие страницы не погашает ссылку; её погашает кнопка получения. Повторная выдача, просрочка и смена пароля блокируют старое приглашение. Это не аппаратная привязка.</p>'+invite+'</details>'
        drawers.append(f'<aside class="drawer" id="{drawer_id}" role="dialog" aria-modal="true" aria-label="Клиент {safe}"><div class="drawer-card"><div class="drawer-head"><div><span class="eyebrow">ПРОФИЛЬ КЛИЕНТА</span><h2>{safe}</h2></div><button type="button" data-drawer-close aria-label="Закрыть">×</button></div><section class="drawer-section">{note}</section>{controls}<section class="drawer-section"><label>Текущий пароль<input type="password" value="{html.escape(client["password"], quote=True)}" id="secret-{index}" readonly></label><button type="button" data-reveal="secret-{index}">Показать / скрыть</button><button type="button" data-copy="secret-{index}">{icon("Copy")}Копировать</button></section><section class="drawer-section"><h3>Подключение</h3>{profiles}{share}</section><details class="drawer-section"><summary>Лимиты соединений</summary><p class="muted">Лимиты HTTP/2 и QUIC независимы. Это ограничение соединений, а не привязка к устройству.</p>{limits}</details><section class="drawer-section">{password}{delete}</section></div></aside>')
    create = admin_form('client-add', '<label>Логин<input name="username" pattern="[A-Za-z0-9_.-]{1,64}" required></label><label>Пароль<input name="password" type="password" placeholder="Пусто: случайный"></label><button class="primary">Добавить клиента</button>')
    batch = admin_form('client-batch', '<label>Префикс<input name="prefix" value="client" maxlength="54" required></label><label>Количество<input name="count" type="number" min="1" max="100" value="5" required></label><button>Создать группу</button>', confirm='Создать новых клиентов? TrustTunnel кратковременно перезапустится.')
    active = sum(c['enabled'] for c in clients)
    return f'<div class="page-head"><div><span class="eyebrow">ДОСТУП И ПОДКЛЮЧЕНИЯ</span><h2>Клиенты</h2><p>{len(clients)} всего · {active} включено · {len(clients)-active} отключено</p></div><div class="page-actions"><button type="button" id="clients-refresh">{icon("RefreshCw")}Обновить статистику</button><button class="primary" data-drawer="add-client">{icon("Plus")}Добавить клиентов</button></div></div><div id="clients-metrics-status" class="muted" role="status"></div><div class="table-toolbar"><input id="client-search" class="search" aria-label="Поиск клиентов" placeholder="Поиск по логину или заметке"><select id="client-state" aria-label="Состояние клиента"><option value="all">Все состояния</option><option value="active">Включённые</option><option value="inactive">Отключённые</option></select><span id="client-count"></span></div><div class="table-wrap"><table><thead><tr><th>Доступ</th><th>Клиент / заметка</th><th>Состояние</th><th>Транспорт</th><th></th></tr></thead><tbody>{"".join(rows)}</tbody></table></div><div class="pagination"><button id="page-prev" aria-label="Предыдущая страница">{icon("ChevronLeft")}</button><span id="page-label"></span><button id="page-next" aria-label="Следующая страница">{icon("ChevronRight")}</button><select id="page-size" aria-label="Строк на странице"><option>10</option><option>25</option><option>50</option></select></div>{"".join(drawers)}<aside class="drawer" id="add-client" role="dialog" aria-modal="true" aria-label="Добавление клиентов"><div class="drawer-card"><div class="drawer-head"><h2>Добавление клиентов</h2><button data-drawer-close aria-label="Закрыть">×</button></div><section class="drawer-section"><h3>Один клиент</h3>{create}</section><section class="drawer-section"><h3>Группа клиентов</h3>{batch}</section></div></aside>'


def health_console():
    data=health_snapshot(); labels={'ok':'Работает нормально','warn':'Требует внимания','error':'Есть проблема','unknown':'Недостаточно свежих данных'}
    days=''
    for row in data['history']:
        state='unknown' if not row['samples'] else 'error' if row['errors'] else 'warn' if row['warn'] else 'ok' if row['ok']==row['samples'] else 'unknown'
        date=datetime.datetime.fromtimestamp(row['day'],datetime.timezone.utc).strftime('%d.%m')
        title=f'{date} UTC · проверок: {row["samples"]}; с проблемой: {row["errors"]}; предупреждений: {row["warn"]}'
        days+=f'<span class="health-day {state}" title="{title}" aria-label="{title}"></span>'
    rows=''.join(f'<div class="health-check"><span>{html.escape(c["title"])}</span><span class="badge {c["state"]}">{html.escape(c["detail"])}</span></div>' for c in data['checks'])
    check=admin_form('health-check','<button>'+icon('RefreshCw')+'Проверить сейчас</button>',view='dashboard')
    when=datetime.datetime.fromtimestamp(data['checked_at'],datetime.timezone.utc).strftime('%d.%m %H:%M UTC') if data['checked_at'] else 'История начнётся после первого фонового измерения'
    return f'<section class="surface health-surface" id="server-health"><div class="section-heading"><div><h3>Здоровье сервера</h3><strong id="health-state" class="health-title">{labels.get(data.get("state"),labels["unknown"])}</strong><span id="health-updated" class="muted">{when}</span></div>{check}</div><div id="health-days" class="health-days" aria-label="Наблюдения за 30 дней">{days}</div><div class="health-legend"><span class="ok">Норма</span><span class="warn">Предупреждение</span><span class="error">Проблема</span><span class="unknown">Нет данных</span></div><div id="health-checks" class="health-checks">{rows}</div><p class="muted">{html.escape(data["scope"])}</p></section>'


def scanner_console():
    data=scanner_snapshot()
    values=''.join(f'<div><span class="muted">{title}</span><strong data-panel-event="{key}">{data["counts"][key]}</strong></div>' for key,title in [('failures','Ошибок входа'),('rejected','Отклонённых запросов'),('throttled','Ограничений частоты')])
    report=admin_form('scanner-status','<button>'+icon('ShieldCheck')+'Отчёт об ошибках входа</button>',view='security')
    return '<section class="surface" id="panel-protection"><div class="section-heading"><div><h3>Защита панели от перебора и некорректных запросов</h3><p class="muted" id="protection-updated">Наблюдения за последние 24 часа. Пустая старая история не восстанавливается.</p></div>'+report+'</div><div class="protection-metrics">'+values+'</div><p class="muted">'+html.escape(data['scope'])+'</p><p class="muted">Сканирование исходящего трафика VPS: нет источника данных. VPN-фильтры ClientHello и TLS-аутентификации настраиваются ниже, с проверкой совместимости. Глобальные баны по этим счётчикам не выполняются.</p></section>'


def overview_console():
    stats = monitor_snapshot()
    cards = ''.join(f'<div class="metric"><small>{label}</small><strong id="stat-{key}">{html.escape(stats[key])}</strong><span class="metric-caption">{caption}</span></div>' for key, label, caption in [('cpu', 'Процессор', 'Загрузка всех ядер'), ('memory', 'Память', 'Использовано / всего'), ('disk', 'Хранилище', 'Корневой раздел'), ('uptime', 'Время работы', 'С последнего запуска')])
    names = {'trusttunnel': 'TrustTunnel', 'warp-wireproxy': 'WARP WireGuard', 'warp-masque': 'WARP MASQUE', 'warp-interface': 'WARP интерфейс', 'fail2ban': 'Fail2ban', 'trusttunnel-panel': 'Панель'}
    services = ''.join(f'<div class="service-row"><span>{html.escape(names.get(name, name))}</span><span id="service-{name}" class="badge {html.escape(status)}">{html.escape(status)}</span></div>' for name, status in stats['services'].items())
    restart = admin_form('system-restart', '<button>' + icon('RotateCw') + 'Перезапустить VPN</button>', view='dashboard', confirm='Перезапустить TrustTunnel? VPN кратковременно отключится.')
    return f'''<div class="page-head"><div><span class="eyebrow">СЕРВЕР</span><h2>Обзор</h2><p>{html.escape(domain())}:{endpoint_port()} <span class="version-pill">Endpoint {html.escape(endpoint_version())}</span></p></div><div class="page-actions"><a class="button" href="/?view=clients">{icon('Users')}Клиенты</a>{restart}</div></div>
{health_console()}
<div class="metrics overview-metrics">{cards}</div><div class="resource-bars"><label>Память <meter id="ram-meter" min="0" max="100" value="{stats['memory_percent']}"></meter></label><label>Диск <meter id="disk-meter" min="0" max="100" value="{stats['disk_percent']}"></meter></label></div>
<section class="surface traffic-surface"><div class="section-heading"><div><h3>Трафик сервера</h3><span id="network-rate" class="network-rate">Ожидание измерения</span></div><div class="monitor-controls"><label class="sr-only" for="interface-select">Сетевой интерфейс</label><select id="interface-select"></select><label class="sr-only" for="refresh-interval">Частота обновления</label><select id="refresh-interval"><option value="10">Каждые 10 с</option><option value="30">Каждые 30 с</option><option value="0">Пауза</option></select><button type="button" id="monitor-refresh" class="icon-button" title="Обновить" aria-label="Обновить">{icon('RefreshCw')}</button></div></div>
<canvas id="traffic-chart" height="190" aria-label="График скорости выбранного сетевого интерфейса"></canvas><div class="chart-footer"><div class="chart-legend"><span class="rx">Приём</span><span class="tx">Отправка</span><span id="chart-scale"></span></div><span id="monitor-status" class="muted" role="status">Подключено</span></div><div id="interface-totals" class="muted"></div></section>
<div class="overview-columns"><section class="surface"><div class="section-heading"><h3>Сервисы</h3><a class="text-link" href="/?view=logs">Журналы {icon('ArrowUpRight')}</a></div>{services}</section><section class="surface"><div class="section-heading"><h3>Подключение</h3><a class="text-link" href="/?view=routing">Сменить маршрут {icon('ArrowUpRight')}</a></div><dl><dt>Исходящий маршрут</dt><dd id="stat-route">{html.escape(stats['route'])}</dd><dt>Транспорты</dt><dd>HTTP/2 {"· QUIC" if quic_enabled() else ""}</dd><dt>Сертификат</dt><dd>{cert_mode()}</dd><dt>Панель</dt><dd>{ADMIN_VERSION}</dd></dl></section></div>'''


def logs_console():
    controls = admin_form('logs', '<label>Сервис<select name="unit"><option>trusttunnel</option><option>warp-wireproxy</option><option>warp-masque</option><option>warp-masque-bridge</option><option>trusttunnel-panel</option><option>fail2ban</option></select></label><label>Строк<input name="lines" type="number" min="20" max="500" value="100"></label><button class="primary">Показать журнал</button>', view='logs')
    audit = admin_form('audit', '<button>Журнал действий администратора</button>', view='logs')
    return f'<div class="page-head"><h2>Журналы</h2></div><section class="surface">{controls}{audit}</section>'


def security_console():
    checks = security_snapshot()['checks']
    tiles = ''
    for c in checks:
        advice = '<p>'+html.escape(c['recommendation'])+'</p>' if c.get('recommendation') else ''
        action = admin_form('security-remediate','<input type="hidden" name="confirm" value="CONFIRMED"><input type="hidden" name="check" value="'+c['remediation']+'"><button>Применить рекомендацию</button>',view='security',confirm=c['recommendation']+' Для изменения метрик VPN перезапустится; перед применением проверьте назначение настройки.') if c.get('remediation') else ''
        tiles += f'<article class="security-check {c["state"]}"><span class="check-dot"></span><div><h3>{html.escape(c["title"])}</h3><p>{html.escape(c["detail"])}</p>{advice}{action}</div></article>'
    status = admin_form('security-status', '<button>' + icon('ShieldCheck') + '<span>Состояние защиты VPS</span></button>', view='security')
    status += admin_form('recommendations', '<button>' + icon('Info') + 'Рекомендации</button>', view='security')
    inspect = admin_form('security-listeners', '<button>' + icon('Globe') + 'Прослушиваемые порты</button>', view='security') + admin_form('security-logins', '<button>' + icon('Logs') + 'Журнал SSH</button>', view='security')
    return f'''<div class="page-head"><div><span class="eyebrow">ЗАЩИТА И ДОСТУП</span><h2>Безопасность</h2><p>Текущее состояние сервера и контроль входящих подключений.</p></div>{status}</div><div class="security-grid">{tiles}</div><div class="inline-actions">{inspect}</div>
{scanner_console()}{network_security_console()}{server_security_controls()}{protection_console()}'''


def network_security_console():
    def form(action, body, warning=''):
        if warning: body = '<input type="hidden" name="confirm" value="CONFIRMED">'+body
        return admin_form(action,body,view='security',confirm=warning)
    firewall = firewall_snapshot()
    pending = firewall_pending()
    rollback = ''
    if pending:
        token = '<input type="hidden" name="token" value="'+html.escape(pending['token'],quote=True)+'">'
        remaining = max(0,int(pending['deadline']-time.time()))
        rollback = '<div class="warning" role="alert"><strong>Ожидается подтверждение UFW</strong><p>Автоматический откат через '+str(remaining)+' с. Проверьте новую SSH-сессию, VPN и доступ к панели.</p><div class="inline-actions">'
        rollback += form('ufw-confirm',token+'<button class="primary">Доступ сохранён, оставить изменения</button>','Проверены SSH, VPN и доступ к панели? Остановить автоматический откат?')
        rollback += form('ufw-rollback',token+'<button class="danger">Вернуть прежние настройки</button>','Восстановить настройки UFW до последнего изменения?')+'</div></div>'
    controls = form('ufw-status','<button>'+icon('RefreshCw')+'Обновить правила</button>')
    for action,label in [('install','Установить пакет UFW'),('enable','Включить UFW'),('disable','Отключить UFW'),('reload','Перезагрузить правила'),('baseline','Добавить разрешения SSH / VPN / панели')]:
        controls += form('ufw-'+action,'<button>'+label+'</button>','Изменить UFW? Полного сброса не будет. Для сохранения потребуется подтверждение доступа за 120 секунд. При отключении UFW порты сервера станут доступны извне.')
    rows = ''
    for row in firewall['rules']:
        body = '<input type="hidden" name="version" value="'+firewall['version']+'"><input type="hidden" name="number" value="'+str(row['number'])+'">'
        body += '<button class="danger" title="Удалить именно эту строку UFW">'+icon('X')+'Удалить</button>'
        rows += '<tr><td>'+str(row['number'])+'</td><td>'+html.escape(row['text'])+'</td><td>'+form('ufw-delete',body,'Удалить выбранную строку? Парное правило IPv4/IPv6 удаляется отдельно. Защищённые разрешения удалять нельзя.')+'</td></tr>'
    rule_fields = '''<label>Действие<select name="decision"><option value="allow">Разрешить</option><option value="deny">Отбросить</option><option value="reject">Отклонить с ответом</option><option value="limit">Лимит новых TCP-подключений</option></select></label><label>Направление<select name="direction"><option value="in">Входящее</option><option value="out">Исходящее</option></select></label><label>Порт или диапазон<input name="port" placeholder="9000 или 10000:10100" required></label><label>Протокол<select name="proto"><option>tcp</option><option>udp</option></select></label><label>Источник IP / CIDR<input name="source" placeholder="Пусто: любой IP"></label><label>Назначение IP / CIDR<input name="destination" placeholder="Пусто: любой IP"></label><label>Интерфейс<input name="interface" placeholder="Пусто: все интерфейсы" maxlength="15"></label><label>Положение<select name="position"><option value="append">В конце</option><option value="prepend">В начале</option></select></label><label>Комментарий<input name="comment" maxlength="80"></label>'''
    create = form('ufw-rule',rule_fields+'<button class="primary">Применить правило</button>','Применить правило UFW? Проверьте направление и адреса; более раннее правило имеет приоритет. Подтвердите доступ после применения.')
    source_block = form('ufw-source-block','<label>Источник IP / CIDR<input name="source" required placeholder="192.0.2.10/32"></label><button class="danger">Заблокировать источник на всех портах</button>','Запретить входящий трафик указанного источника на всех портах? Для удаления блокировки используйте её строку в таблице UFW.')
    preview = form('ufw-preview',rule_fields+'<button>Проверить без применения</button>')
    logging = form('ufw-logging','<label>Журналирование<select name="level"><option>off</option><option selected>low</option><option>medium</option><option>high</option><option>full</option></select></label><button>Сохранить</button>','Изменить журналирование UFW? High / full могут существенно увеличить нагрузку и объём журналов.')
    policy = form('ufw-default','<label>Направление<select name="direction"><option value="incoming">Входящие</option><option value="outgoing">Исходящие</option><option value="routed">Транзитные</option></select></label><label>Политика<select name="policy"><option>deny</option><option>reject</option><option>allow</option></select></label><button>Изменить политику</button>','Изменить политику по умолчанию? Исключения SSH / VPN / панели будут добавлены. Для исходящего и транзитного трафика допускается только allow, чтобы не нарушить WARP / DNS.')
    reports = form('ufw-applications','<button>Профили приложений</button>')+form('ufw-logs','<button>'+icon('Logs')+'События UFW</button>')
    data = fail2ban_snapshot()
    options = ''.join('<option'+(' selected' if name == 'sshd' else '')+'>'+html.escape(name)+'</option>' for name in sorted(set(data['configured']+data['active'])))
    selector = '<label>Jail<select name="jail">'+options+'</select></label>'
    f2b_controls = form('f2b-status','<button>'+icon('RefreshCw')+'Состояние службы и jail</button>')
    for action,label in [('install','Установить пакет'),('enable','Включить службу'),('disable','Отключить службу'),('restart','Перезапустить службу'),('reload','Применить конфигурацию')]:
        f2b_controls += form('f2b-'+action,'<button>'+label+'</button>','Выполнить действие fail2ban? Остановка службы снимает её защиту; перезапуск может временно изменить блокировки.')
    f2b_controls += form('f2b-test','<button>Проверить конфигурацию</button>')+form('f2b-logs','<button>'+icon('Logs')+'Журнал fail2ban</button>')
    jail = form('f2b-jail-status',selector+'<button>Статистика, блокировки и настройки</button>')
    for action,label in [('jail-enable','Включить jail'),('jail-disable','Отключить jail')]:
        jail += form('f2b-'+action,selector+'<button>'+label+'</button>','Изменить постоянное состояние выбранного jail? Отключение снимает его защиту. Фильтры и команды действий не редактируются.')
    settings = form('f2b-settings',selector+'''<label>Попыток<input name="retry" type="number" min="1" max="100" value="5" required></label><label>Окно, секунд<input name="findtime" type="number" min="60" max="86400" value="600" required></label><label>Бан, секунд<input name="bantime" type="number" min="60" max="604800" value="3600" required></label><label>Увеличивать повторный бан<select name="increment"><option value="0">Нет</option><option value="1">Да</option></select></label><label>Предел бана, секунд<input name="maxtime" type="number" min="60" max="2592000" value="604800" required></label><button>Сохранить параметры</button>''','Применить указанные значения к выбранному jail? Это предлагаемые значения, не считанные настройки; текущие параметры доступны в статистике jail.')
    bans = ''
    for action,label in [('ban','Заблокировать IP'),('unban','Разблокировать IP'),('ignore-add','Добавить постоянное исключение'),('ignore-remove','Удалить исключение')]:
        bans += form('f2b-'+action,selector+'<label>IP'+(' / CIDR' if action.startswith('ignore') else '')+'<input name="ip" required></label><button>'+label+'</button>','Изменить блокировку или исключение только выбранного jail? Текущий IP администратора и loopback защищены.')
    return f'''<section class="surface" id="ufw-controls"><div class="section-heading"><h3>UFW · сетевой экран</h3><span class="badge {'active' if firewall['active'] else ''}">{'Включён' if firewall['active'] else 'Отключён / недоступен'}</span></div>{rollback}<div class="inline-actions">{controls}</div><details><summary>Текущая политика</summary><pre>{html.escape(firewall['verbose'])}</pre></details><div class="table-wrap"><table><thead><tr><th>№</th><th>Правило</th><th>Действие</th></tr></thead><tbody>{rows or '<tr><td colspan="3">Нет доступных правил</td></tr>'}</tbody></table></div><p class="hint">Удаление затрагивает одну строку, не всю пару IPv4 / IPv6. Правила SSH, VPN и панели защищены. Существующие широкие разрешения не отменяются добавлением адресного разрешения.</p><details><summary>Новое правило</summary>{create}<details><summary>Предварительная проверка</summary>{preview}</details></details><details><summary>Блокировка IP / подсети</summary>{source_block}</details><details><summary>Политика и журналирование</summary>{policy}{logging}{reports}</details></section>
<section class="surface" id="fail2ban-controls"><div class="section-heading"><h3>Fail2ban · защита служб</h3><span class="badge {'active' if data['service'] == 'active' else ''}">{html.escape(data['service'])}</span></div><p class="muted">Работающие jail: {html.escape(', '.join(data['active']) or 'нет подтверждённых')}. Изменения сохраняются отдельным override-файлом; чужие настройки не стираются.</p><div class="inline-actions">{f2b_controls}</div><details><summary>Управление jail</summary>{jail}</details><details><summary>Время и усиление блокировок</summary>{settings}</details><details><summary>Блокировки и доверенные адреса</summary>{bans}</details><p class="hint">Блокировка применяется к портам, указанным в выбранном jail. Исключение fail2ban не является разрешением UFW. Для диагностики сначала проверьте конфигурацию и журнал; отключение fail2ban не устраняет причину атак.</p></section>'''


def server_security_controls():
    scan = admin_form('security-scan','<button class="primary">Проверить сервер и получить рекомендации</button>',view='security')
    ping = ''.join(admin_form('security-ping','<input type="hidden" name="confirm" value="CONFIRMED"><input type="hidden" name="enabled" value="'+value+'"><button>'+label+'</button>',view='security',confirm='Изменить только входящие ICMP echo-request через UFW? Нужные ICMPv6 и диагностика MTU сохраняются.') for value,label in [('0','Запретить входящий ping'),('1','Вернуть политику ping')])
    previous = ''
    try:
        data = json.loads(read_text(SECURITY_REPORT) or '{}')
        if data.get('checked_at'):previous = '<p class="muted">Последняя сохранённая проверка: '+time.strftime('%Y-%m-%d %H:%M',time.localtime(data['checked_at']))+' · время VPS</p>'
    except (ValueError,TypeError):pass
    fixes = ''.join(admin_form('security-remediate','<input type="hidden" name="confirm" value="CONFIRMED"><input type="hidden" name="check" value="'+key+'"><button>'+label+'</button>',view='security',confirm=detail) for key,label,detail in [('ntp','Включить синхронизацию времени','Включить системную синхронизацию NTP? Сервер времени выбирается ОС.'),('syn-cookies','Включить SYN cookies','Включить net.ipv4.tcp_syncookies и сохранить настройку? Это не защита от любого DDoS.'),('private-files','Закрыть права приватных файлов','Оставить доступ к профилям, учётным данным, ключам и хранилищу только root? Символические ссылки и чужой владелец вызовут отказ.'),('metrics-private','Изолировать listener метрик','Перенести метрики на 127.0.0.1 с тем же портом и перезапустить VPN? Внешние сборщики метрик перестанут подключаться.')])
    fixes += admin_form('security-remediate','<input type="hidden" name="confirm" value="CONFIRMED"><input type="hidden" name="check" value="kernel-baseline"><button>Базовая защита ядра</button>',view='security',confirm='Настроить SYN cookies, отключить ICMP redirects и включить защиту hardlinks/symlinks? Маршруты, rp_filter, UDP, MTU и WARP не меняются. При ошибке будет выполнен откат значений.')
    return '<section class="surface"><h3>Проверка и защита VPS</h3><p class="muted">Панель проверяет конфигурацию при запуске и каждые 6 часов. Это не внешний пентест и не гарантия отсутствия уязвимостей. Изменения применяются только по отдельному подтверждению. Другое время дополнительной проверки можно задать в Система → Расписания.</p>'+previous+scan+ping+'<details><summary>Исправить рекомендованные настройки</summary><p class="muted">Выберите только необходимые исправления по результату отчёта. Вход по SSH-паролю не отключается: сначала отдельно проверяются ключи и резервный доступ. Изоляция метрик потребует краткого перезапуска VPN.</p>'+fixes+'</details></section>'


def protection_console():
    state = protection_state()
    inspect = admin_form('protection-status', '<button>Проверить совместимость и защиту</button>', view='security')
    camo = admin_form('protection-camouflage', '<input type="hidden" name="confirm" value="CONFIRMED"><button>Скрыть служебные HTTP-ответы</button>', view='security', confirm='Отключить публичные ping/speedtest на основном VPN-host и возвращать 404 вместо ошибки прокси для посторонних HTTP-запросов? Клиентские настройки не меняются.')
    if state.get('http_backup') is not None:
        camo += admin_form('protection-camouflage-restore', '<input type="hidden" name="confirm" value="CONFIRMED"><button>Вернуть HTTP-настройки</button>', view='security', confirm='Восстановить сохранённые настройки HTTP-ответов?')
    prepare = admin_form('protection-prepare', '<input type="hidden" name="confirm" value="CONFIRMED"><button>Подготовить защищённые ссылки</button>', view='security', confirm='Подготовить альтернативные ссылки с ClientHello-префиксом, не меняя текущие подключения?')
    strict = admin_form('protection-enforce', '<input type="hidden" name="confirm" value="CONFIRMED"><label class="check"><input type="checkbox" name="clients_ready" value="1" required>Все устройства уже проверены с защищёнными ссылками</label><button class="danger">Включить строгий фильтр</button>', view='security', confirm='Старые профили без ClientHello-префикса перестанут подключаться. Включить строгий фильтр?')
    if state.get('enabled'):
        strict = admin_form('protection-disable', '<input type="hidden" name="confirm" value="CONFIRMED"><button>Отключить строгий фильтр</button>', view='security', confirm='Восстановить исходные правила и разрешить прежние профили?')
    tls_prepare = admin_form('protection-tls-prepare','<input type="hidden" name="confirm" value="CONFIRMED"><button>Подготовить TLS-auth ссылки v1.3</button>',view='security',confirm='Создать криптографически случайный ключ TLS-auth и альтернативные ссылки? Работающие правила, TOML и подключения не меняются.')
    tls = admin_form('protection-tls-enforce','<input type="hidden" name="confirm" value="CONFIRMED"><label class="check"><input type="checkbox" name="clients_ready" value="1" required>Все устройства проверены с новым TLS-auth профилем</label><label class="check"><input type="checkbox" name="client_v13" value="1" required>Установлен совместимый App v1.3</label><button class="danger">Сделать TLS-аутентификацию обязательной</button>',view='security',confirm='Старые профили без ключа будут отклоняться. Endpoint должен поддерживать auth-key; пока QUIC включён, операция будет безопасно отклонена. Продолжить?')
    if state.get('tls_enabled'): tls = admin_form('protection-tls-disable','<input type="hidden" name="confirm" value="CONFIRMED"><button>Отключить обязательную TLS-аутентификацию</button>',view='security',confirm='Вернуть правила, действовавшие до TLS-auth?')
    preset = admin_form('protection-client-preset','<input type="hidden" name="confirm" value="CONFIRMED"><button>AntiDPI + Chrome TLS + DoH для новых профилей</button>',view='security',confirm='Изменить параметры по умолчанию без изменения существующих TOML? Новые и явно пересобранные профили используют штатный AntiDPI, Chrome ClientHello и DoH.')
    compatibility = 'Ключ поддерживается установленным endpoint.' if endpoint_capabilities().get('auth_key') else 'Установленный endpoint не поддерживает auth-key. Стабильная версия 1.1.0 не подходит; переход на beta не выполняется автоматически.'
    defaults = panel_settings()
    tls_options = ''.join('<option value="'+value+'"'+(' selected' if value == defaults['TLS_PROFILE'] else '')+'>'+value+'</option>' for value in ('chrome','safari','firefox','okhttp','openssl','default'))
    custom = admin_form('protection-client-settings','<input type="hidden" name="confirm" value="CONFIRMED"><label>DNS новых профилей<input name="dns" value="'+html.escape(defaults['DNS_UPSTREAMS'],quote=True)+'" required></label><label>TLS ClientHello<select name="tls_profile">'+tls_options+'</select></label><label class="check"><input type="checkbox" name="anti_dpi" value="1" '+('checked' if defaults['CLIENT_ANTI_DPI']=='1' else '')+'>Штатный AntiDPI клиента</label><label class="check"><input type="checkbox" name="post_quantum" value="1" '+('checked' if defaults['POST_QUANTUM']=='1' else '')+'>Post-quantum TLS (не маскировка)</label><button>Сохранить параметры новых профилей</button>',view='security',confirm='Сохранить только параметры по умолчанию? Действующие TOML не переписываются. Проверьте поддержку настроек вашим клиентом.')
    return '<section class="surface"><h3>AntiDPI и защита от активного зондирования</h3><p class="muted">Нативная защита TrustTunnel: проверка сертификата, клиентский AntiDPI и аутентификация ClientHello. Не скрывает IP сервера и не гарантирует обход DPI. Новые параметры требуют повторного импорта профиля.</p>'+inspect+preset+camo+'<details><summary>Гибкая настройка клиентского AntiDPI</summary><p class="muted">При блокировке UDP сравните HTTP/2. При доступном UDP сравните QUIC. Не меняйте одновременно все параметры: проверяйте один новый профиль на одном устройстве. Для игр предпочтителен уже проверенный WARP-интерфейс; AntiDPI не исправляет плохой маршрут.</p>'+custom+'</details><details><summary>TLS-аутентификация · '+('обязательна' if state.get('tls_enabled') else 'не обязательна')+'</summary><p class="muted">Разработчики подтвердили функцию в App v1.3 22 октября. Наличие версии в магазине и совместимость проверяются на устройстве. '+compatibility+' Сначала подготовьте альтернативные ссылки и проверьте клиент. QUIC-enforcement пока заблокирован до отдельной квалификации. Ключ переносим вместе с профилем и не является идентификатором устройства.</p>'+tls_prepare+tls+'</details><details><summary>Прежний prefix-фильтр · '+('включён' if state.get('enabled') else 'выключен')+'</summary><p class="warning">Только HTTP/2: требуемая защита от активного сканирования с QUIC пока не подтверждена. Видимый сертификат сам по себе не означает доступ к VPN. Автоматического отключения QUIC нет.</p>'+prepare+strict+'</details></section>'


def routing_console():
    configured = tomllib.loads(read_text(TT_DIR/'vpn.toml')).get('forward_protocol',{}).get('socks5',{}).get('address','')
    current = {'wg-socks':'warp','masque-socks':'masque','wg-interface':'interface','masque-interface':'interface-masque'}.get(current_warp_backend(), 'socks5' if configured else 'direct')
    options = [('direct','Direct','IP VPS, без WARP'),('interface','WARP · WireGuard интерфейс','Без SOCKS; проверенный вариант для игр'),('interface-masque','WARP · MASQUE TUN','Без SOCKS; отдельная регистрация'),('warp','WARP · WireGuard SOCKS','Локальный прокси; возможны ограничения UDP'),('masque','WARP · MASQUE SOCKS','MASQUE через локальный прокси'),('socks5','Каскад SOCKS5','Ваш внешний прокси, а не VPN-адрес')]
    choices = ''.join('<label class="route-choice"><input type="radio" name="mode" value="'+mode+'" '+('checked' if mode == current else '')+' required><span><strong>'+title+'</strong><small>'+detail+'</small>'+('<b class="route-current">Текущий</b>' if mode == current else '')+'</span></label>' for mode,title,detail in options)
    switch = admin_form('routing-switch','<fieldset class="route-picker"><legend>Выберите исходящий маршрут</legend>'+choices+'</fieldset><label data-cascade-address '+('' if current=='socks5' else 'hidden')+'>SOCKS5 host:port<input name="address" value="'+html.escape(configured if current=='socks5' else '',quote=True)+'" placeholder="proxy.example:1080"></label><p class="muted" data-route-summary>Изменения ещё не применены. Выберите маршрут и подтвердите переключение.</p><button class="primary">'+icon('Check')+'Применить выбранный маршрут</button>',view='routing',confirm='Переключить только исходящий маршрут TrustTunnel? VPN кратко переподключится; SSH и основной маршрут VPS не меняются. Неустановленный WARP сначала нужно настроить в разделе WARP.')
    switch += '<div class="inline-actions">'+admin_form('diagnostics-stack','<button>'+icon('Activity')+'Проверить VPN и маршрут</button>',view='routing')+admin_form('diagnostics-warp','<button>Проверить выход WARP</button>',view='routing')+'<a class="button" href="/?view=warp">Настроить WARP</a></div>'
    add = admin_form('routing-rule-add', '<label>IP / подсеть CIDR<input name="cidr" placeholder="203.0.113.0/24" required></label><label>Действие<select name="decision"><option value="deny">Запретить</option><option value="allow">Разрешить</option></select></label><button>Добавить правило</button>', view='routing', confirm='Применить правило доступа и перезапустить TrustTunnel?')
    rules = tomllib.loads(rules_text()).get('rule', [])
    rows = []
    import hashlib
    for index, rule in enumerate(rules, 1):
        fingerprint = hashlib.sha256(json.dumps(rule, sort_keys=True).encode()).hexdigest()
        delete = admin_form('routing-rule-delete', f'<input type="hidden" name="index" value="{index}"><input type="hidden" name="fingerprint" value="{fingerprint}"><button class="danger">Удалить</button>', view='routing', confirm='Удалить это правило доступа?')
        rows.append(f'<tr><td>{index}</td><td>{html.escape(rule.get("cidr", ""))}</td><td>{html.escape(rule.get("client_random_prefix", ""))}</td><td>{html.escape(rule.get("action", ""))}</td><td>{delete}</td></tr>')
    return f'<div class="page-head"><div><h2>Маршрутизация</h2><p>Настроенный выход: {html.escape(forwarder_label())}</p></div>{admin_form("routing-check", "<button>Полная диагностика</button>", view="routing")}</div><section class="surface"><h3>Выход TrustTunnel в интернет</h3><p class="muted">Маршрут применяется ко всем клиентам этого endpoint. Их логины, пароли и сертификаты не меняются. Интерфейсный WARP не меняет основной маршрут SSH.</p>{switch}</section>{torrent_console()}<section class="surface"><h3>Правила входящего доступа к TrustTunnel</h3><p class="warning">Эти правила проверяют входящий IP клиента, а не посещаемые сайты. Первое совпадение имеет приоритет. При строгой TLS-защите редактирование заблокировано.</p>{add}<div class="table-wrap"><table><thead><tr><th>№</th><th>CIDR</th><th>Client random</th><th>Действие</th><th></th></tr></thead><tbody>{"".join(rows) or "<tr><td colspan=5>Правил нет</td></tr>"}</tbody></table></div></section>'


def torrent_console():
    state=torrent_snapshot()
    selected=state['mode']
    label='Нужно восстановление' if state.get('recovering') else 'Активно · частичная защита' if state['active'] else 'Не подтверждено' if state['enabled'] else 'Выключено'
    fields='<input type="hidden" name="confirm" value="CONFIRMED"><label>Режим<select name="mode">'
    fields+=''.join('<option value="'+key+'"'+(' selected' if selected==key else '')+'>'+title+'</option>' for key,title in [('signatures','Открытые сигнатуры BitTorrent'),('ports','Сигнатуры и выбранные порты')])
    fields+='</select></label><label>Порты дополнительного режима<input name="ports" value="'+html.escape(','.join(state.get('ports') or ['6881:6889','6969','51413']),quote=True)+'" maxlength="160"></label>'
    fields+='<label class="check"><input type="checkbox" name="limits_ack" value="1" required>Понимаю: это не полная блокировка всех торрентов; выбранные порты могут использовать другие приложения</label><button class="primary">Применить ограничение</button>'
    save=admin_form('torrent-save',fields,view='routing',confirm='Ограничить выходящий BitTorrent всех клиентов TrustTunnel? Изменятся только выделенные цепочки по cgroup; SSH, UFW, маршрут WARP и профили не меняются. Возможны пропуски зашифрованного/фрагментированного P2P и ложные совпадения открытых данных.')
    status=admin_form('torrent-status','<button>'+icon('RefreshCw')+'Проверить фильтр и счётчики</button>',view='routing')
    off=admin_form('torrent-disable','<input type="hidden" name="confirm" value="CONFIRMED"><button>Отключить ограничение</button>',view='routing',confirm='Удалить только управляемые правила BitTorrent и остановить их таймер проверки?') if state['enabled'] or state.get('recovering') else ''
    error='<p class="warning">'+html.escape(state['error'])+'</p>' if state.get('error') else ''
    return '<section class="surface" id="torrent-controls"><div class="section-heading"><h3>Ограничение торрентов на выходе</h3><span class="badge'+(' active' if state['active'] else '')+'">'+label+'</span></div><p class="warning">'+html.escape(state['warning'])+' Это не DPI-классификатор со сборкой потока: сегментированный TCP, MSE/PE, VPN поверх VPN и часть uTP могут пройти.</p><p class="muted">Только сокеты процесса TrustTunnel, до WARP/прямого выхода. Обычный UDP и HTTPS не запрещаются целиком. Нового SOCKS-прокси нет. Счётчик показывает пакеты совпадений, а не количество загрузок; после пересоздания правил он обнуляется.</p>'+error+'<p class="hint">Совпавших отброшенных пакетов: '+str(state['dropped'])+'</p><div class="inline-actions">'+status+off+'</div>'+save+'</section>'


def dns_console():
    values = panel_settings()
    saved = html.escape(values['DNS_UPSTREAMS'], quote=True)
    save = admin_form('dns-save', f'<label>DNS: IP, DoH, DoT или DoQ<input name="dns" size="56" value="{saved}" required></label><button class="primary">Сохранить DNS</button>', view='dns')
    check = admin_form('dns-check', '<button>Проверить DNS с VPS</button>', view='dns')
    apply = admin_form('dns-apply', '<button>Обновить файлы подключения</button>', view='dns', confirm='Пересобрать профили с сохранённым DNS? На устройствах потребуется импортировать новые TOML.')
    advanced = dns_view()
    advanced = re.sub(r'<div class="page-head">.*?</div></div>', '', advanced, count=1)
    return f'<div class="page-head"><h2>DNS и настройки клиента</h2></div><section class="surface"><h3>DNS-серверы клиентов</h3>{save}<div>{check}{apply}</div><p class="muted">Сохранение не меняет текущие профили. IP DNS проверяется запросом с VPS; для DoH/DoT/DoQ проверяется разрешение имени сервера.</p></section><details class="surface"><summary>TLS и AntiDPI</summary>{advanced}</details>'



CONSOLE_SCRIPT = r'''
(() => {
  let lifecycle=null,cleanup=()=>{};
  async function refreshContent(){
    const position=scrollY;
    const response=await fetch(location.href,{cache:'no-store'});
    if(response.status===401){location.assign('/login');return;}
    if(!response.ok)throw Error('Не удалось обновить состояние: HTTP '+response.status);
    const doc=new DOMParser().parseFromString(await response.text(),'text/html');
    const main=doc.querySelector('main.content');if(!main)throw Error('Сервер не вернул содержимое раздела.');
    lifecycle?.abort();cleanup();main.dataset.refreshed=String(Date.now());document.querySelector('main.content').replaceWith(main);
    const context=doc.querySelector('.endpoint-context');if(context)document.querySelector('.endpoint-context').replaceChildren(...context.childNodes);
    init();scrollTo(0,Math.min(position,document.documentElement.scrollHeight-innerHeight));
  }
  function init(){
  lifecycle?.abort();cleanup();lifecycle=new AbortController();const signal=lifecycle.signal;cleanup=()=>{};
  const $ = id => document.getElementById(id);
  const hints={dns:'DNS используется в новых профилях. Сохранение не меняет настройки уже подключённых устройств.',mode:'Direct показывает сайтам IP VPS. WARP меняет исходящий маршрут только TrustTunnel.',address:'Адрес внешнего SOCKS5-прокси в формате host:port. Не указывайте здесь адрес VPN-сервера.',max_http2_conns:'Это лимит соединений HTTP/2, а не привязка к одному физическому устройству.',max_http3_conns:'Это лимит соединений QUIC, а не число людей. Слишком маленькое значение может мешать переподключению.',cert_mode:'Let’s Encrypt доверен устройствами и обновляется автоматически. Замена self-signed требует обновить доверенный сертификат клиента.',transport:'WireGuard и MASQUE — разные транспорты WARP. У каждого интерфейсного режима отдельная регистрация.',channel:'Stable — основной канал. Beta может содержать новые функции и несовместимые изменения.',port:'Выбранный порт не должен быть занят SSH, VPN или другим сервисом.',source:'Пустое значение разрешает любой источник. CIDR ограничивает доступ указанной сетью.',retry:'Число неудачных SSH-входов до блокировки. Не отключайте рабочую SSH-сессию при изменении защиты.',enabled:'Изменение серверного параметра может кратковременно перезапустить TrustTunnel.'};
  Object.assign(hints,{quota_gib:'Сумма загруженного и отправленного трафика с начала наблюдения. 1 ГиБ = 1 073 741 824 байта. Старая история неизвестна; возможен перерасход между проверками. Пусто или 0 снимает квоту.',expires:'Дата и время в UTC, не в часовом поясе телефона. После срока учётная запись помечается для отзыва или отключается при включённом автоотзыве.',auto_suspend:'Если выключено, лимит только отображается. Если включено, панель отключит учётную запись и кратко перезапустит endpoint. Нужна работающая панель; последняя активная запись автоматически не отключается.',minutes:'Приглашение погашается только нажатием кнопки получения, не просмотром страницы. Скопированный после получения профиль остаётся переносимым.',kind:'TLS-auth нужен совместимый App v1.3 и endpoint с auth-key. Подготовка ссылки не включает обязательную проверку на сервере.',disconnect_ack:'Отзыв требует перезапуска endpoint: подключения остальных пользователей кратко прервутся. Это ограничение нативного endpoint, а не панели.',client_v13:'Комментарий разработчиков подтверждает функцию в App v1.3, но фактически установленную версию надо проверить на каждом устройстве.',check:'Исправляется только выбранный пункт. Панель не отключает SSH-пароль и не закрывает порт администратора автоматически.'});
  Object.assign(hints,{threshold:'Порог предупреждения: сколько разных наблюдавшихся сетей увидела панель за выбранный период. Это не одновременные IP. Начните с наблюдения; смена Wi-Fi и мобильной сети не доказывает передачу профиля.',ipv6_prefix:'Группировка /64 уменьшает ложные тревоги от временных IPv6-адресов одного устройства. /128 считает каждый адрес отдельно и может давать больше предупреждений.',source_cidr:'Ограничивает только получение одноразового приглашения с указанного IP или сети. После выдачи профиль остаётся копируемым; это не ограничение IP VPN-клиента.',maxretry:'Количество подтверждённых ошибок для выбранного jail. Это не число VPN-сессий и не число устройств.',findtime:'За какой период Fail2ban считает ошибки. Учитывайте общий NAT и сохраните отдельный доступ по SSH перед изменением.',bantime:'Срок блокировки адреса для выбранного jail. Бан может затронуть других людей за тем же внешним IP.',http1_ack:'В endpoint 1.1.0 локальные метрики используют HTTP/1.1 codec. Его добавление также разрешает HTTP/1.1 на VPN-порту. Без согласия конфигурация не меняется.'});
  Object.assign(hints,{retry:'Число подтверждённых ошибок в выбранном jail до блокировки. Для SSH это ошибки SSH-входа; другой jail может защищать другую службу. Не связано с числом VPN-клиентов.',increment:'Увеличивает длительность блокировки при повторных нарушениях выбранного jail. Начните с умеренного срока; чужие ошибки за общим NAT могут затронуть законного пользователя.',maxtime:'Максимальная длительность растущей блокировки. Само значение не создаёт бан, пока jail не зарегистрирует нарушение.',direction:'Входящее — соединения к VPS; исходящее — соединения с VPS. Не путайте с загрузкой и отправкой данных конкретного VPN-клиента.',position:'Порядок правил важен: более раннее подходящее правило может определить решение раньше нового. Разрешение для одного IP не отменяет старое широкое разрешение.',destination:'Для какого адреса назначения применяется правило. Пусто означает любой адрес в выбранном направлении; это не DNS-имя сайта.',interface:'Ограничивает правило выбранным сетевым интерфейсом VPS. Пусто означает любой интерфейс. Не меняет маршрут WARP.',policy:'Правило по умолчанию для соединений, которым не подошло ни одно отдельное правило. Перед запретом входящих сначала разрешите SSH, VPN и панель.'});
  document.querySelectorAll('main label').forEach((label,index)=>{const input=label.querySelector('input,select');const action=label.closest('form')?.querySelector('input[name="action"]')?.value;const text=input&&(input.name==='minutes'&&action==='guard-watch-save'?'Окно наблюдения сетей: от 5 минут до суток. При редком опросе часть адресов не видна. Окно не превращает историю в список одновременно активных IP.':hints[input.name]);if(!text||label.hidden)return;label.classList.add('has-help');const button=document.createElement('button');button.type='button';button.className='help-button';button.title=text;button.setAttribute('aria-label','Пояснение');button.setAttribute('aria-expanded','false');button.append($('help-icon').content.cloneNode(true));const tip=document.createElement('small');tip.className='field-help';tip.id='field-help-'+index;tip.hidden=true;tip.textContent=text;button.setAttribute('aria-controls',tip.id);button.onclick=e=>{e.preventDefault();tip.hidden=!tip.hidden;button.setAttribute('aria-expanded',String(!tip.hidden));};label.append(button,tip);});
  const routeForm=document.querySelector('.route-picker')?.closest('form');
  if(routeForm){const update=()=>{const chosen=routeForm.querySelector('input[name="mode"]:checked'),field=routeForm.querySelector('[data-cascade-address]');if(field){field.hidden=chosen?.value!=='socks5';field.querySelector('input').disabled=field.hidden;}const summary=routeForm.querySelector('[data-route-summary]');if(summary&&chosen)summary.textContent='Выбран: '+chosen.closest('label').querySelector('strong').textContent+'. Переключение только после кнопки и подтверждения.';};routeForm.querySelectorAll('[name="mode"]').forEach(input=>input.addEventListener('change',update,{signal}));update();}
  const actionDescriptions={
    'client-add':'Создаёт отдельный логин и пароль VPN, а также файлы подключения. Endpoint кратковременно перезапускается: подключения остальных пользователей могут прерваться.',
    'client-batch':'Создаёт несколько независимых учётных записей с разными паролями. Префикс и количество определяют имена. Применение кратковременно перезапускает VPN.',
    'client-note':'Сохраняет только заметку администратора. Пароль, сертификат, профиль и работающий VPN не меняются.',
    'client-password':'Меняет пароль выбранного клиента. Старые файлы, ссылки и приглашения больше не подходят; пользователю потребуется новый профиль. VPN кратковременно перезапускается.',
    'client-delete':'Удаляет учётную запись и её файлы подключения. Сохранённый на устройстве профиль больше не даст доступ. Другие пользователи могут кратко переподключиться.',
    'client-disable':'Временно отзывает доступ, сохраняя учётную запись и профиль. VPN кратковременно перезапускается. Это не блокировка общего внешнего IP.',
    'client-enable':'Возвращает доступ существующему клиенту с сохранёнными данными. Endpoint применяет список пользователей через перезапуск.',
    'client-limits':'Ограничивает технические туннели HTTP/2 и QUIC, не сайты, IP или устройства. Малые значения могут полностью нарушить интернет клиента. Для антишаринга не рекомендуется.',
    'client-refresh-network':'Обновляет DNS, AntiDPI и TLS-параметры в файлах выбранного клиента. Ключ и SNI сохраняются; на устройстве нужен повторный импорт. Сама кнопка не доставляет изменения на телефон.',
    'client-rebuild':'Заново создаёт экспортируемые файлы из текущих серверных данных. Не является переустановкой VPN. Существующий профиль на телефоне сам не изменится.',
    'guard-save':'Сохраняет общую квоту трафика и срок доступа. Автоматический отзыв действует только с включённой опцией и работающей панелью; он может перезапустить VPN для всех. Аппаратной привязки здесь нет.',
    'guard-remove':'Снимает квоту и срок для клиента. Не включает ранее отключённую учётную запись и не меняет её пароль.',
    'guard-watch-save':'Включает предупреждения о разных замеченных сетях за период. Это не полный список одновременных IP и не доказательство шаринга. Автоматические баны не выполняются.',
    'guard-watch-remove':'Выключает предупреждения о смене сетей выбранного клиента. Доступ VPN и пароль сохраняются.',
    'enrollment-issue':'Создаёт временное одноразовое приглашение на получение профиля. Можно ограничить IP/CIDR получателя. После выдачи сам профиль всё ещё можно скопировать.',
    'enrollment-revoke':'Отзывает ещё не использованные приглашения. Уже скачанный профиль остаётся рабочим: для отзыва доступа отключите клиента или смените пароль.',
    'health-check':'Собирает локальные ресурсы и состояние выбранных служб и обновляет историю. Не перезапускает службы, не меняет настройки и не проверяет весь путь с телефона.',
    'scanner-status':'Показывает ошибки входа, отклонённые HTTP-запросы и ограничения панели. Категории могут пересекаться. Это не число сканеров всех портов VPS.',
    'endpoint-releases':'Проверяет официальные стабильные и предварительные выпуски TrustTunnel и совместимость панели. Ничего не устанавливает и не переводит сервер на beta.',
    'endpoint-metrics':'Включает локальные метрики сессий и трафика пользователей. Нужен перезапуск VPN. Listener остаётся на loopback; это не публичный API статистики.',
    'endpoint-subscription':'Настраивает HTTPS-выдачу профилей для совместимого endpoint и клиента. Нужен доверенный сертификат. Ссылка содержит доступ к VPN; серверная функция может быть недоступна в stable.',
    'dns-save':'Сохраняет DNS по умолчанию для новых файлов подключения. Уже подключённые телефоны и существующие файлы не меняются.',
    'dns-check':'Проверяет DNS с самого VPS. Для обычного IP выполняется DNS-запрос; для DoH/DoT/DoQ проверка имени не доказывает работу всего зашифрованного протокола или пути с телефона.',
    'dns-apply':'Пересоздаёт файлы подключения с сохранёнными DNS-параметрами. На устройствах нужен повторный импорт. Это не изменение DNS операционной системы VPS.',
    'routing-switch':'Меняет выходящий маршрут только TrustTunnel: Direct, выбранный WARP или внешний SOCKS5. Direct показывает IP VPS. Переключение прерывает VPN-сессии; интерфейсный режим не должен менять маршрут SSH.',
    'routing-check':'Проверяет настроенный маршрут и доступность его компонентов. Не меняет маршрут. HTTP-проверка не доказывает качество игрового UDP, DNS и IPv6.',
    'routing-rule-add':'Добавляет правило допуска входящих клиентов по IP/подсети. Это не правило выбора выхода для сайта. Порядок правил имеет значение; применение перезапускает endpoint.',
    'routing-rule-delete':'Удаляет только выбранное правило доступа. Защита от устаревшей страницы не позволяет удалить другую строку. Нестандартный файл правил автоматически не переписывается.',
    'routing-rule-reset':'Удаляет управляемые правила доступа. Не является сбросом UFW. Требуется подтверждение; при строгой TLS-защите сброс заблокирован.',
    'warp-operation':'Управляет выбранным вариантом WARP. Установка не равна включению маршрута. Отключение SOCKS возвращает Direct, а интерфейсного режима — предыдущий выход. Перерегистрация меняет WARP-аккаунт, не пользователей VPN.',
    'torrent-save':'Включает частичное ограничение BitTorrent только для процесса TrustTunnel. Сигнатуры и выбранные порты не гарантируют блокировку шифрованного P2P; возможны ложные совпадения. Общий UDP и SSH не блокируются.',
    'torrent-disable':'Удаляет только управляемые правила ограничения BitTorrent. Не сбрасывает UFW и маршруты WARP.',
    'torrent-status':'Проверяет установленное ограничение BitTorrent и его счётчики пакетов. Пакеты не равны людям или числу скачанных файлов.',
    'certificate-status':'Показывает режим, срок и состояние сертификата. Не перевыпускает его и не меняет клиентские настройки.',
    'certificate-switch':'Меняет режим сертификата. Let’s Encrypt доверен устройствами; self-signed требует доверенного сертификата в профиле. Замена может потребовать повторного импорта и краткого перезапуска.',
    'system-restart':'Перезапускает только TrustTunnel, не весь VPS. Активные VPN-подключения кратковременно разорвутся; SSH и панель должны продолжить работу.',
    'system-reboot':'Планирует перезагрузку всего VPS через 60 секунд. Прервутся VPN, панель и SSH. До срабатывания таймера перезагрузку можно отменить.',
    'system-reboot-cancel':'Останавливает наш таймер предстоящей перезагрузки. Уже начавшуюся перезагрузку отменить нельзя.',
    'schedule-save':'Сохраняет расписание выбранной задачи в часовом поясе сервера. Обновления ОС могут перезапускать службы, перезагрузка отключит всё. Endpoint и сама панель автоматически этим расписанием не обновляются.',
    'schedule-disable':'Отключает только выбранное расписание панели. Не отменяет уже начавшееся обновление и не удаляет системные таймеры других программ.',
    'schedule-status':'Показывает наши таймеры и время следующего запуска. Наличие расписания не доказывает успешное выполнение прошлой задачи.',
    'security-scan':'Читает состояние защиты VPS и выдаёт рекомендации. Проверка сама не меняет SSH, UFW, маршруты или настройки VPN. Предупреждение нужно оценить перед исправлением.',
    'security-audit':'Формирует read-only отчёт о защите сервера. Это автоматические проверки конфигурации, не полноценный внешний пентест.',
    'security-status':'Показывает текущие UFW, SSH и fail2ban. Не применяет настройки; журнал и информация могут относиться к разным моментам проверки.',
    'security-remediate':'Применяет только выбранную рекомендацию, а не все сразу. Изоляция метрик перезапустит VPN. Парольный вход SSH и маршруты автоматически не отключаются.',
    'security-ping':'Меняет только входящие echo-request через управляемые правила UFW. Это не запрет всего ICMP/ICMPv6: служебные сообщения нужны сети. Выключенный ping не скрывает открытые TCP/UDP-порты.',
    'security-listeners':'Показывает порты, которые слушают процессы VPS. Слушающий порт не обязательно доступен из интернета: доступ также зависит от UFW и firewall провайдера.',
    'security-logins':'Показывает ограниченный фрагмент журналов SSH. Ошибка входа не всегда атака; перед баном проверьте адрес и время.',
    'logs':'Показывает последние строки выбранного разрешённого журнала. Не запускает введённые команды. Секреты маскируются, но перед отправкой отчёта его всё равно стоит проверить.',
    'audit':'Показывает действия администраторов, записанные панелью. Это не полный журнал всех действий root по SSH.',
    'recommendations':'Показывает советы по текущим проверкам. Настройки не меняются, пока вы отдельно не подтвердите конкретное исправление.',
    'diagnostics-client':'Показывает наблюдаемые сессии, трафик и параметры выбранного клиента без пароля. Не воспроизводит автоматически работу его Android-приложения.',
    'diagnostics-stack':'Проверяет endpoint, слушающие порты и сертификат по уровням. TCP/UDP listener не доказывает, что клиентский интернет работает целиком.',
    'diagnostics-egress':'Проверяет разрешённую внешнюю цель по DNS, TCP и TLS напрямую с VPS. Это не проверка выхода через WARP или с телефона.',
    'diagnostics-warp':'Проверяет HTTP-выход через выбранный WARP, для интерфейса — в маршруте cgroup TrustTunnel. Не измеряет игровой пинг и потери UDP.',
    'protection-status':'Проверяет подготовленные и включённые способы защиты VPN от активного зондирования и их совместимость. Ничего не включает.',
    'protection-camouflage':'Меняет служебные HTTP-ответы endpoint, не клиентские пароли. Это уменьшение явных признаков сервиса, а не невидимость IP, TLS-сертификата или полная защита от DPI.',
    'protection-camouflage-restore':'Возвращает сохранённые служебные HTTP-настройки. Не выключает UFW и не снимает парольную аутентификацию VPN.',
    'protection-prepare':'Готовит альтернативные профили с ClientHello-prefix. Старые клиенты не блокируются. Сначала проверьте новый профиль на одном устройстве.',
    'protection-enforce':'Делает подготовленный ClientHello-фильтр обязательным. Старые профили могут перестать работать. С QUIC строгий режим пока не допускается без подтверждённой квалификации.',
    'protection-disable':'Снимает наш строгий prefix-фильтр и восстанавливает сохранённые правила, если они не изменены посторонним инструментом. Пароль VPN остаётся необходимым.',
    'protection-tls-prepare':'Готовит профили с ключевой TLS-аутентификацией для совместимого клиента и endpoint. Не включает обязательную проверку на сервере. Ключ можно скопировать вместе с профилем.',
    'protection-tls-enforce':'Требует совместимые endpoint и клиент и отдельное подтверждение миграции. Неподготовленные устройства потеряют доступ. Это не привязка к устройству; строгий QUIC пока не квалифицирован.',
    'protection-tls-disable':'Отключает обязательную ключевую проверку ClientHello и возвращает сохранённые правила. Не отключает обычный пароль VPN.',
    'protection-client-preset':'Сохраняет рекомендованный набор DNS/AntiDPI/TLS для новых экспортируемых профилей. Он не является гарантированным обходом DPI и не меняет настройки телефонов удалённо.',
    'protection-client-settings':'Позволяет настроить штатные параметры клиента: AntiDPI, TLS-профиль, DNS и post-quantum. Совместимость зависит от версии приложения. Меняйте по одному параметру и проверяйте новый профиль.',
    '/ports/endpoint':'Меняет VPN-порт и адрес в экспортируемых профилях. Нужен повторный импорт на устройствах и перезапуск VPN. Убедитесь, что порт свободен; активный интерфейсный WARP сначала требуется безопасно отключить.',
    '/panel/access':'Меняет способ доступа и порт панели. Localhost доступен через SSH-туннель, HTTPS — через выбранный публичный порт. После перезапуска старый адрес может перестать работать.',
    '/panel/credentials':'Меняет логин/пароль администратора панели, не VPN-клиентов. После применения потребуется новый вход; сохраните новые данные до закрытия страницы.',
    '/installer':'Запускает выбранную установку, переустановку, обновление или удаление. Это не просто перезапуск: внимательно проверьте сохранение identity и подтверждение операции.',
    '/backup/identity':'Сохраняет сертификат, ключ и клиентские данные для восстановления без перенастройки устройств. Backup содержит секреты: держите его только в защищённом месте.',
    '/backup/latest.zip':'Скачивает архив клиентских настроек. Он содержит доступ к VPN; не публикуйте его и не отправляйте посторонним.'
  };
  const securityDescriptions={
    'Сетевой экран':'UFW фильтрует соединения по IP, портам и направлению. Inactive означает, что он выключен. Перед включением разрешите SSH, VPN и HTTPS-панель и проверьте сохранность доступа. Это не AntiDPI и не полная защита от сканеров.',
    'Политика входящих соединений':'Default incoming применяется к новым входящим соединениям, для которых не подошло отдельное правило UFW. Обычно рекомендуют deny: разрешены только явно открытые службы. Сначала создайте разрешения SSH, VPN и панели, иначе можно потерять доступ. Эта карточка ничего не изменяет.',
    'Защита SSH':'Fail2ban временно блокирует адреса после подтверждённых повторных ошибок SSH-входа. Это не число VPN-клиентов и не защита от всех сетевых атак. Общий NAT может объединять разных людей за одним IP.',
    'Вход по SSH':'Вход ключом обычно предпочтительнее пароля. Не отключайте пароль или root, пока не проверен другой пользователь с sudo и вход по ключу в новой сессии. Проверка базовых параметров не учитывает все Match-исключения.',
    'Доступ к панели':'Localhost не выставляет веб-панель в интернет: используйте SSH-туннель. Публичный HTTPS шифрует соединение, но не заменяет сильный пароль, обновления и ограничение доверенных IP.',
    'Приватные файлы':'В этих файлах хранятся пароли VPN, ключ сертификата и пароль панели. Они должны принадлежать root и не читаться группой или другими пользователями ОС. Открытые права могут раскрыть доступ.',
    'Сертификат VPN':'Сертификат подтверждает сервер и защищает TLS. Проверяется чтение и срок действия. Let’s Encrypt должен своевременно обновляться; замена самоподписанного сертификата требует обновить доверие на устройствах.',
    'Перезагрузка ОС':'ОС может запросить перезагрузку после обновления ядра или системных библиотек. Перезагрузка остановит SSH, VPN и панель; назначьте подходящее время и сохраните доступ к консоли провайдера.',
    'Синхронизация времени':'NTP поддерживает правильное время. Ошибка часов мешает TLS, сертификатам и журналам. Применение рекомендации включает синхронизацию, но не доказывает, что источник времени уже доступен.',
    'SYN cookies':'Штатный механизм ядра помогает TCP переживать переполнение очереди установления соединений. Он не защищает от перегрузки канала, TLS или любых DDoS-атак и не ускоряет игровой UDP.',
    'Входящий ping':'Ping помогает диагностировать доступность. Запрет echo-request не скрывает открытые порты. Нельзя блокировать весь ICMP/ICMPv6: это может нарушить IPv6 и определение размера пакета.',
    'Обновления ОС':'Обновления закрывают известные уязвимости, но могут перезапустить службы. Не создавайте конфликтующие APT-расписания. Обновление ОС не равно обновлению TrustTunnel или панели.',
    'Приватность метрик':'Статистика endpoint содержит логины и IP клиентов. Listener должен быть на loopback, доступном только локальным процессам, а веб-API панели — требовать входа. Не открывайте порт метрик в интернет.',
    'Доступ VPN к приватным сетям':'Разрешение даёт VPN-клиентам доступ к локальным/приватным назначениям, в том числе некоторым службам VPS. При SOCKS поведение зависит и от удалённого прокси; настройка не доказывает полную изоляцию DNS и приватных сетей.',
    'Пароль панели':'Используйте уникальный случайный пароль от 20 символов и не применяйте его для SSH или VPN-клиентов. Одна длина не доказывает отсутствие утечки. Доступ к панели даёт административные возможности.',
    'Профили и учёт':'TOML, файлы состояний и база учёта могут содержать секреты и персональные адреса. Проверяются права, владелец и ссылки. Backup тоже должен храниться приватно.',
    'TLS-аутентификация VPN':'Ключевая проверка ClientHello затрудняет активное зондирование endpoint, но требует совместимости обеих сторон. Это не mTLS, не аппаратная привязка и не защита от копирования профиля. Строгий QUIC пока не квалифицирован.',
    'Контроль передачи доступа':'Сроки, квоты и одноразовые приглашения уменьшают неконтролируемую выдачу. История сетей служит только сигналом для проверки владельца. Официальный endpoint не даёт надёжного полного списка одновременных IP.',
    'Базовая защита ядра':'Набор ограниченных sysctl защищает от некоторых небезопасных сетевых перенаправлений и файловых ссылок. Он не заменяет обновления и firewall. Профиль не меняет MTU, маршруты WARP или UDP.',
    'Ошибки служб ОС':'Показывает службы в состоянии failed. Причины могут быть разными; сначала изучите журнал и назначение службы. Панель не перезапускает все неизвестные службы автоматически.'
  };
  Object.assign(actionDescriptions,{
    'ufw-status':'Показывает текущие правила и состояние UFW. Ничего не включает и не меняет. Сравните разрешённые порты с SSH, VPN и панелью.',
    'ufw-enable':'Включает фильтрацию UFW с существующими правилами. Проверьте разрешения SSH, VPN и панели. После применения проверьте новый вход и подтвердите доступ за 120 секунд; иначе наш таймер вернёт прежние настройки.',
    'ufw-disable':'Выключает фильтрацию UFW. Открытые процессы VPS могут стать доступны извне, если их не ограничивает другой firewall. Это не отключает VPN. Изменение требует проверки сохранности доступа.',
    'ufw-install':'Устанавливает пакет UFW через APT. Установка пакета не равна включению firewall; откат сетевого правила не удаляет установленный пакет.',
    'ufw-baseline':'Добавляет разрешения текущих SSH, VPN и панели без полного сброса чужих правил. Уже существующие широкие разрешения остаются. Проверьте доступ и подтвердите изменение.',
    'ufw-rule':'Добавляет выбранное правило по направлению, порту и адресам. Не заменяет все прежние правила. После применения требуется подтверждение доступа за 120 секунд.',
    'ufw-delete':'Удаляет только выбранную строку UFW с проверкой версии списка. IPv4 и IPv6 могут быть отдельными строками. Защищённые разрешения SSH, VPN и панели удалить этим действием нельзя.',
    'ufw-source-block':'Запрещает входящий трафик указанного IP или подсети на всех портах. Может затронуть нескольких людей за NAT. Не является баном одного VPN-логина; адрес администратора и loopback защищены.',
    'ufw-preview':'Выполняет предварительную проверку команды UFW без применения правила. Успешная проверка синтаксиса не доказывает, что после реального применения сохранится доступ.',
    'ufw-confirm':'Сохраняет уже применённое изменение и отменяет наш таймер отката. Нажимайте только после проверки новой SSH-сессии, VPN и панели, а не только старого открытого соединения.',
    'ufw-rollback':'Возвращает сохранённые настройки UFW до ожидающего подтверждения изменения. Не переустанавливает VPN и не откатывает пакеты ОС.',
    'ufw-default':'Меняет политику UFW по умолчанию. Для входящих обычно нужен запрет с отдельными разрешениями. Неправильный запрет может закрыть SSH, VPN и панель; автоматический откат не отменяет необходимость проверки.',
    'ufw-logging':'Меняет подробность журналов UFW. Высокая подробность увеличивает расход диска и процессора; для обычной работы предпочтителен умеренный уровень.',
    'f2b-settings':'Меняет порог ошибок, окно наблюдения и сроки блокировки выбранного jail. Значения формы — предложенные, не обязательно фактически действующие. Сначала посмотрите статистику этого jail.',
    'f2b-ban':'Временно блокирует внешний IP на портах выбранного jail. Это затрагивает адрес целиком, не отдельного пользователя за NAT. Не используйте как автоматический антишаринг.',
    'f2b-unban':'Снимает бан только в выбранном jail. UFW или другой jail может продолжать блокировку. Повторные ошибки могут вызвать новый бан.',
    'f2b-ignore-add':'Добавляет постоянное исключение для выбранного jail. Оно не является разрешением UFW и не отменяет все другие средства защиты.',
    'f2b-ignore-remove':'Удаляет исключение выбранного jail. Последующие нарушения с этого адреса снова могут приводить к бану. Не удаляйте доверенный доступ без резервной сессии.'
  });
  const helpDialog=document.createElement('dialog');helpDialog.id='feature-help';helpDialog.className='explain-dialog';helpDialog.setAttribute('aria-labelledby','feature-help-title');
  const helpTitle=document.createElement('h3');helpTitle.id='feature-help-title';const helpBody=document.createElement('p'),helpClose=document.createElement('button');helpClose.type='button';helpClose.textContent='Понятно';helpDialog.append(helpTitle,helpBody,helpClose);document.body.append(helpDialog);
  let helpTrigger=null;helpClose.onclick=()=>helpDialog.close();helpDialog.onclose=()=>{if(helpTrigger?.isConnected)helpTrigger.focus();};helpDialog.onclick=e=>{if(e.target===helpDialog){const r=helpDialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)helpDialog.close();}};
  signal.addEventListener('abort',()=>helpDialog.remove(),{once:true});
  function infoButton(title,text){const b=document.createElement('button');b.type='button';b.className='help-button action-help';b.title=text;b.setAttribute('aria-label','Пояснение: '+title);b.append($('help-icon').content.cloneNode(true));b.onclick=()=>{helpTrigger=b;helpTitle.textContent=title;helpBody.textContent=text;helpDialog.showModal();helpClose.focus();};return b;}
  document.querySelectorAll('.security-check h3').forEach(heading=>{const title=heading.textContent.trim(),text=securityDescriptions[title];if(text){heading.title=text;heading.classList.add('check-explanation');heading.append(infoButton(title,text));}});
  document.querySelectorAll('main form').forEach(form=>{
    const action=form.querySelector('input[name="action"]')?.value||form.getAttribute('action');
    let text=actionDescriptions[action];
    if(!text&&action?.startsWith('ufw-'))text='UFW управляет сетевыми разрешениями VPS. Проверьте направление, IP и порядок правил, сохранив SSH, VPN и панель. Изменения правил требуют подтверждения доступа за 120 секунд; установка пакета не откатывается как правило.';
    if(!text&&(action?.startsWith('fail2ban-')||action?.startsWith('f2b-')))text='Операция относится к выбранному jail Fail2ban. Бан действует на внешний IP целиком, а не на один VPN-логин; за общим NAT могут быть другие люди. Сначала проверьте адрес, исключения и сохранность доступа администратора.';
    if(!text&&action?.startsWith('panel-'))text='Управление самой веб-панелью, не паролями VPN-клиентов. Изменение доступа или остановка могут закрыть текущую страницу. Держите рабочий SSH-доступ для восстановления через ttmenu.';
    if(!text&&action?.startsWith('certificate-'))text='Управление сертификатом VPN. Перевыпуск и смена режима могут перезапустить endpoint; самоподписанный сертификат нужно доверить на устройстве. Для Let’s Encrypt требуется доступность домена и временного HTTP challenge.';
    if(!text&&form.dataset.confirm)text=form.dataset.confirm;
    if(!text)text='Выполняет выбранное действие: '+(form.querySelector('button')?.textContent.trim()||action)+'. Проверьте параметры формы. Результат появится в отдельном окне; опасное изменение требует подтверждения.';
    const buttons=[...form.querySelectorAll('button:not([type="button"])')];buttons.forEach(b=>b.title=text+(form.dataset.confirm?'\n\nПеред применением: '+form.dataset.confirm:''));
    const primary=buttons[0];if(primary){const wrap=document.createElement('span');wrap.className='action-control';primary.before(wrap);wrap.append(primary,infoButton(primary.textContent.trim(),primary.title));}
  });
  document.querySelectorAll('[data-load-link],[data-copy],[data-reveal],[data-drawer]').forEach(button=>{if(!button.title)button.title=button.hasAttribute('data-copy')?'Копирует выбранный секрет или профиль в буфер обмена. Не отправляйте его посторонним.':button.hasAttribute('data-reveal')?'Показывает или скрывает уже сохранённый пароль выбранного клиента. Учитывайте, кто видит экран.':button.hasAttribute('data-load-link')?'Создаёт ссылку и QR для выбранного клиента и транспорта. Ссылка содержит доступ к VPN; передавайте её только владельцу.':'Открывает карточку клиента или форму добавления. Само открытие не меняет доступ и не перезапускает VPN.';});
  const store = {get(k, fallback) {try{return localStorage.getItem(k)||fallback;}catch(_){return fallback;}},set(k,v){try{localStorage.setItem(k,v);}catch(_){}}};
  $('theme-toggle').onclick=()=>{const t=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=t;store.set('tt-theme',t);};
  if($('effects-toggle'))$('effects-toggle').onclick=()=>{const flat=document.documentElement.dataset.effects!=='flat';document.documentElement.dataset.effects=flat?'flat':'glass';store.set('tt-effects',flat?'flat':'glass');$('effects-toggle').setAttribute('aria-pressed',String(!flat));};
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
    if(e.key==='Escape'&&helpDialog.open){e.preventDefault();helpDialog.close();return;}
    if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();openCommand();}
    if(e.key==='Escape'){closeNav();closeCommand();closeDrawers();}
    if(e.key!=='Tab')return;
    const scope=document.querySelector('.drawer.open,.command-layer.open')||(document.body.classList.contains('nav-open')?document.querySelector('.sidebar'):null);
    if(!scope)return;
    const items=[...scope.querySelectorAll('button:not(:disabled),input:not([type=hidden]),textarea,a[href],select')].filter(x=>x.getClientRects().length);
    const first=items[0],last=items.at(-1);if(!first)return;
    if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}
    else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
  },{signal});
  document.addEventListener('click',async e=>{
    const b=e.target.closest('[data-copy],[data-reveal]');if(!b)return;
    const input=$(b.dataset.copy||b.dataset.reveal);if(!input)return;
    if(b.dataset.reveal){input.type=input.type==='password'?'text':'password';return;}
    try{await navigator.clipboard.writeText(input.value);const old=b.innerHTML;b.textContent='Скопировано';setTimeout(()=>b.innerHTML=old,1500);}
    catch(_){input.focus();input.select();showResult('Копирование','Автоматическое копирование недоступно. Текст выделен.',false);}
  },{signal});
  document.querySelectorAll('[data-load-link]').forEach(b=>b.onclick=async()=>{
    b.disabled=true;const target=$('link-result-'+b.dataset.linkIndex);target.textContent='Подготовка ссылки…';
    try{
      const query=new URLSearchParams({username:b.dataset.loadLink,protocol:$('link-protocol-'+b.dataset.linkIndex)?.value||'http2',kind:$('link-kind-'+b.dataset.linkIndex)?.value||'static'});
      const r=await fetch('/api/client-link?'+query,{cache:'no-store'});
      const data=await r.json();if(!r.ok||!data.link)throw Error(data.error||'Endpoint не вернул ссылку.');
      const label=document.createElement('label');label.textContent='Ссылка подключения';
      const text=document.createElement('textarea');text.readOnly=true;text.value=data.link;text.id='lazy-link-'+b.dataset.linkIndex;label.append(text);
      const copy=document.createElement('button');copy.type='button';copy.dataset.copy=text.id;copy.textContent='Копировать ссылку';
      const qrUrl='/qr-link/'+encodeURIComponent(b.dataset.loadLink)+'.png?'+query;
      const img=document.createElement('img');img.className='share-qr';img.alt='QR подключения '+b.dataset.loadLink;img.width=280;img.height=280;img.src=qrUrl;
      const error=document.createElement('p');error.className='error-text';error.hidden=true;
      img.onerror=async()=>{img.hidden=true;error.hidden=false;error.textContent='QR недоступен. Используйте ссылку или TOML.';try{const q=await fetch(qrUrl,{cache:'no-store'});const answer=await q.json();error.textContent=answer.error||error.textContent;}catch(_){}};
      const actions=document.createElement('div');actions.className='inline-actions';
      const open=document.createElement('a');open.href=data.link;open.className='button primary';open.textContent='Открыть TrustTunnel';
      const download=document.createElement('a');download.href=qrUrl;download.download=b.dataset.loadLink+'-'+data.protocol+'.png';download.className='button';download.textContent='Скачать QR';
      actions.append(copy,open,download);target.replaceChildren(label,actions,img,error);
    }catch(e){target.textContent=e.message;}finally{b.disabled=false;}
  });
  const result=$('operation-result');let shouldRefresh=false,resultText='';
  function showResult(title,output,refresh=false){resultText=String(output||'');$('result-search').value='';$('result-title').textContent=title;$('result-output').textContent=resultText;shouldRefresh=refresh;if(!result.open)result.showModal();}
  $('result-search').oninput=()=>{const query=$('result-search').value.toLocaleLowerCase();$('result-output').textContent=resultText.split('\n').filter(line=>line.toLocaleLowerCase().includes(query)).join('\n');};
  $('result-copy').onclick=async()=>{try{await navigator.clipboard.writeText($('result-output').textContent);$('result-copy').setAttribute('title','Скопировано');}catch(_){const range=document.createRange();range.selectNodeContents($('result-output'));const selection=getSelection();selection.removeAllRanges();selection.addRange(range);}};
  $('result-download').onclick=()=>{const url=URL.createObjectURL(new Blob([$('result-output').textContent],{type:'text/plain;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download='trusttunnel-report.txt';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
  result.onclose=()=>{document.dispatchEvent(new Event('tt-refresh-state'));if(shouldRefresh)refreshContent().catch(error=>{const notice=document.createElement('div');notice.className='notice';notice.textContent=error.message;document.querySelector('main.content').prepend(notice);});};
  $('result-close').onclick=()=>result.close();
  const releases=$('release-status');
  async function loadReleases(attempt=0){
    try{const response=await fetch('/api/releases',{cache:'no-store'});if(!response.ok)throw Error();const data=await response.json();if(signal.aborted)return;
      releases.classList.toggle('has-update',!!data.update_available||!!data.panel_update_recommended);releases.title=data.panel_update_recommended?'Проверьте обновление панели':data.update_available?'Доступен новый endpoint: '+data.stable.tag_name:'Обновления и совместимость';
      const report=['Установлен: '+data.installed,'Stable: '+(data.stable?.tag_name||'проверяется'),'Beta: '+(data.beta?.tag_name||'не проверена'),'',data.compatibility,'',data.error||'','',data.stable?.body||'','',data.beta?.body||''].join('\n');
      releases.onclick=()=>showResult('Обновления TrustTunnel',report,false);
      if((!data.checked_at||data.error)&&attempt<3){const id=setTimeout(()=>loadReleases(attempt+1),10000);const previousCleanup=cleanup;cleanup=()=>{previousCleanup();clearTimeout(id);};}
    }catch(_){releases.title='Проверка обновлений недоступна';}
  }
  loadReleases();
  const confirmation=$('action-confirm');let resolveConfirm=null;
  confirmation.onclose=()=>{resolveConfirm?.(confirmation.returnValue==='confirm');resolveConfirm=null;};
  $('confirm-cancel').onclick=()=>confirmation.close('cancel');
  $('confirm-accept').onclick=()=>confirmation.close('confirm');
  document.querySelectorAll('input[name="confirm"],input[name="beta_confirm"]').forEach(input=>{const value=input.getAttribute('pattern')||input.placeholder||input.value;input.type='hidden';input.required=false;input.value=/^[A-Z]+$/.test(value)?value:'REINSTALL';const label=input.closest('label');if(label)label.hidden=true;});
  function askConfirmation(form,submitter){return new Promise(resolve=>{resolveConfirm=resolve;$('confirm-title').textContent=submitter?.textContent.trim()||'Подтвердить действие';$('confirm-detail').textContent=form.dataset.confirm||'Операция изменит настройки сервера и может кратковременно прервать VPN-подключения. Продолжить?';confirmation.returnValue='';confirmation.showModal();$('confirm-cancel').focus();});}
  document.querySelectorAll('form').forEach(f=>f.addEventListener('submit',async e=>{
    if(f.getAttribute('action')==='/logout')return;
    e.preventDefault();if(document.body.classList.contains('busy')||confirmation.open)return;
    const warp=f.querySelector('[name="action"][value="warp-operation"]'),warpMutation=warp&&!['check','status'].includes(e.submitter?.value);
    const path=f.getAttribute('action'),choice=e.submitter?.value||f.querySelector('[name="action"]')?.value;
    const sensitive=['/panel/access','/panel/credentials','/client/network','/ports/endpoint','/rules/reset','/cascade'].includes(path)||path==='/maintenance'&&choice!=='status'||['/ufw','/fail2ban'].includes(path)&&choice!=='status';
    if((sensitive||warpMutation||f.dataset.confirm||f.querySelector('input[name="confirm"]')||f.querySelector('[name="channel"]')?.value==='beta')&&!await askConfirmation(f,e.submitter))return;
    const data=new URLSearchParams(new FormData(f));
    if(warpMutation)data.set('confirm','CONFIRMED');
    if(e.submitter?.name)data.set(e.submitter.name,e.submitter.value);
    const buttons=[...f.querySelectorAll('button')];buttons.forEach(b=>b.disabled=true);f.setAttribute('aria-busy','true');
    document.body.classList.add('busy');const started=Date.now();$('busy-message').textContent='Операция выполняется…';const elapsed=setInterval(()=>{$('busy-message').textContent='Операция выполняется · '+Math.floor((Date.now()-started)/1000)+' с';},1000);
    try{
      const response=await fetch(f.getAttribute('action'),{method:'POST',headers:{'Accept':'application/json','Content-Type':'application/x-www-form-urlencoded'},body:data});
      if(response.status===401){location.assign('/login');return;}
      if(!response.ok&&response.headers.get('Content-Type')?.includes('text/html'))throw Error(response.status===403?'Сессия обновлена. Перезагрузите страницу.':'Ошибка HTTP '+response.status);
      const answer=await response.json();showResult(answer.ok?'Готово':'Операция не выполнена',answer.output,answer.ok&&answer.refresh);
    }catch(error){showResult('Не удалось получить результат',error.message+' Если связь прервалась после запуска, проверьте состояние перед повтором.');}
    finally{clearInterval(elapsed);document.body.classList.remove('busy');buttons.forEach(b=>b.disabled=false);f.removeAttribute('aria-busy');}
  },{signal}));
  window.addEventListener('pageshow',()=>document.body.classList.remove('busy'),{signal});
  const rows=[...document.querySelectorAll('[data-client-row]')];let page=0;
  const search=$('client-search'),state=$('client-state'),size=$('page-size');
  function filter(){
    if(!state)return;
    const matches=rows.filter(r=>r.dataset.client.includes(search.value.toLowerCase())&&(state.value==='all'||r.dataset.state===state.value||r.dataset.online===state.value));
    const pages=Math.max(1,Math.ceil(matches.length/+size.value));page=Math.min(page,pages-1);
    rows.forEach(r=>r.hidden=true);matches.slice(page*+size.value,(page+1)*+size.value).forEach(r=>r.hidden=false);
    $('page-label').textContent=`${page+1} / ${pages}`;$('client-count').textContent=`Найдено: ${matches.length}`;$('page-prev').disabled=page===0;$('page-next').disabled=page===pages-1;
  }
  if(state){[['online','Сейчас онлайн'],['offline','Сейчас офлайн'],['unknown','Статус неизвестен']].forEach(([v,t])=>state.add(new Option(t,v)));[search,state,size].forEach(x=>x.addEventListener('input',()=>{page=0;filter();}));$('page-prev').onclick=()=>{page--;filter();};$('page-next').onclick=()=>{page++;filter();};filter();}
  if($('clients-refresh')){
    let reading=false;
    const date=value=>value?new Date(value*1000).toLocaleString():'ещё не наблюдался';
    const format=value=>{let n=Math.max(0,Number(value)||0),i=0;while(n>=1024&&i<4){n/=1024;i++;}return n.toFixed(1)+' '+['Б','КиБ','МиБ','ГиБ','ТиБ'][i];};
    async function refreshClients(){
      if(reading||document.hidden||signal.aborted)return;reading=true;
      const b=$('clients-refresh'),status=$('clients-metrics-status');b.disabled=true;
      function unknown(){document.querySelectorAll('[data-client-online]').forEach(cell=>{cell.className='badge';cell.textContent='Статус неизвестен';cell.closest('[data-client-row]').dataset.online='unknown';});}
      try{const response=await fetch('/api/clients-metrics',{cache:'no-store',signal});if(!response.ok)throw Error('Статистика недоступна; прежний трафик сохранён, online не подтверждён.');const data=await response.json();
        const byName=new Map(data.clients.map(x=>[x.username,x]));
        document.querySelectorAll('[data-client-online]').forEach(cell=>{const item=byName.get(cell.dataset.clientOnline),online=data.available?item?.online:null;cell.textContent=online===true?'Онлайн · '+item.sessions+' тунн.':online===false?'Офлайн':'Статус неизвестен';cell.title='VPN-приложение может держать несколько туннелей. Это не число устройств или IP-адресов.';cell.className='badge'+(online===true?' active':'');cell.closest('[data-client-row]').dataset.online=online===true?'online':online===false?'offline':'unknown';});
        document.querySelectorAll('[data-client-metrics]').forEach(cell=>{const item=byName.get(cell.dataset.clientMetrics);cell.replaceChildren();if(!item){cell.textContent='Нет сохранённых измерений';return;}for(const [label,value] of [['Скачано',item.download],['Отправлено',item.upload],['Всего',item.total_bytes??item.download+item.upload]]){const span=document.createElement('span');span.textContent=label+': '+format(value);cell.append(span);}cell.title=data.traffic_basis||'С точки зрения устройства клиента. Накопленные счётчики, не тарификация провайдера.';let peer=cell.parentElement.querySelector('[data-client-address]');if(!peer){peer=document.createElement('span');peer.className='muted client-address';peer.dataset.clientAddress=cell.dataset.clientMetrics;cell.after(peer);}const current=data.available&&item.online&&item.observed_ip;peer.textContent=(current?'IP сейчас: '+current:'Последний замеченный IP: '+(item.last_observed_ip||'ещё не зафиксирован'))+'. Одновременных IP: '+(item.active_ip_count===0?'0':'неизвестно');peer.title='Последний адрес из наблюдений панели. Официальный endpoint возвращает один агрегированный IP, не полный список подключений; при нескольких IP это не обязательно адрес самого последнего подключения.';});
        document.querySelectorAll('[data-client-seen]').forEach(cell=>{const item=byName.get(cell.dataset.clientSeen);cell.textContent='Последний онлайн: '+(item?.online===true?'сейчас':date(item?.last_seen));});
        document.querySelectorAll('[data-client-watch]').forEach(cell=>{const item=byName.get(cell.dataset.clientWatch)?.sharing;cell.classList.toggle('warning',Boolean(item?.alert));cell.textContent=!item?.enabled?'Наблюдение сетей выключено.':(!data.available?'Метрики сейчас недоступны. Последние наблюдения: ':item.alert?'Проверьте доступ: ':'Наблюдение: ')+item.observed_networks+' сетей за '+item.minutes+' мин; последний образец '+date(item.last_sample)+'. Это не одновременные IP; автоматического бана нет.';});
        document.querySelectorAll('[data-client-details]').forEach(cell=>{const item=byName.get(cell.dataset.clientDetails);cell.textContent=item?'Последний онлайн: '+date(item.last_seen)+'. Скачано: '+format(item.download)+'. Отправлено: '+format(item.upload)+'. За сегодня (UTC), без начального исторического остатка: скачано '+format(item.today_download)+' / отправлено '+format(item.today_upload)+'. VPN-туннелей: '+(data.available?item.sessions:'неизвестно')+'. Это не число устройств. Полный список одновременных IP недоступен. История до начала наблюдения неизвестна.':'Нет измерений';});
        status.textContent=(data.available?'Обновлено '+new Date(data.checked_at*1000).toLocaleTimeString()+' · автообновление 15 с.':'Метрики недоступны. Статус неизвестен, сохранённый трафик не сброшен. Включение: Endpoint.')+' '+(data.accounting_error||'')+' '+(data.guard?.error||'');
        if(data.guard?.pending?.length)status.append(document.createTextNode(' Квота/срок требуют решения администратора: '+data.guard.pending.join(', ')+'. Проверьте политики в карточках клиентов.'));
        filter();
      }catch(error){if(error.name!=='AbortError'){unknown();status.textContent=error.message;filter();}}finally{reading=false;if(!signal.aborted)b.disabled=false;}
    }
    $('clients-refresh').onclick=refreshClients;refreshClients();const timer=setInterval(refreshClients,15000);const previousCleanup=cleanup;cleanup=()=>{previousCleanup();clearInterval(timer);};document.addEventListener('visibilitychange',refreshClients,{signal});
    document.addEventListener('tt-refresh-state',refreshClients,{signal});
  }
  if($('server-health')||$('panel-protection')){
    let checking=false;
    async function refreshSafety(){
      if(checking||document.hidden||signal.aborted)return;checking=true;
      try{
        if($('server-health')){
          const response=await fetch('/api/server-health',{cache:'no-store',signal});if(!response.ok)throw Error();const data=await response.json();
          const labels={ok:'Работает нормально',warn:'Требует внимания',error:'Есть проблема',unknown:'Недостаточно свежих данных'};
          $('health-state').textContent=labels[data.stale?'unknown':data.state]||labels.unknown;
          $('health-updated').textContent=data.checked_at?'Измерение: '+new Date(data.checked_at*1000).toLocaleString()+(data.stale?' · устарело или недоступно':' · каждые 60 с'):'Ожидание первого фонового измерения';
          $('health-days').replaceChildren(...data.history.map(row=>{const span=document.createElement('span');const state=!row.samples?'unknown':row.errors?'error':row.warn?'warn':row.ok===row.samples?'ok':'unknown';span.className='health-day '+state;span.title=new Date(row.day*1000).toISOString().slice(0,10)+' UTC · проверок '+row.samples+'; с проблемой '+row.errors+'; предупреждений '+row.warn;span.setAttribute('aria-label',span.title);return span;}));
          $('health-checks').replaceChildren(...data.checks.map(item=>{const row=document.createElement('div');row.className='health-check';const title=document.createElement('span'),detail=document.createElement('span');title.textContent=item.title;detail.className='badge '+(['ok','warn','error','unknown'].includes(item.state)?item.state:'unknown');detail.textContent=item.detail;row.append(title,detail);return row;}));
        }
        if($('panel-protection')){
          const response=await fetch('/api/panel-protection',{cache:'no-store',signal});if(!response.ok)throw Error();const data=await response.json();
          document.querySelectorAll('[data-panel-event]').forEach(cell=>cell.textContent=String(data.counts[cell.dataset.panelEvent]??'нет данных'));
          $('protection-updated').textContent='За последние 24 часа · обновлено '+new Date(data.checked_at*1000).toLocaleTimeString()+'. Категории могут пересекаться.';
        }
      }catch(error){if(error.name!=='AbortError'){if($('health-state'))$('health-state').textContent='Свежие данные недоступны';if($('protection-updated'))$('protection-updated').textContent='Нет свежих данных. Показаны последние полученные счётчики.';}}
      finally{checking=false;}
    }
    refreshSafety();const safetyTimer=setInterval(refreshSafety,60000);const safetyCleanup=cleanup;cleanup=()=>{safetyCleanup();clearInterval(safetyTimer);};document.addEventListener('visibilitychange',refreshSafety,{signal});
    document.addEventListener('tt-refresh-state',refreshSafety,{signal});
  }
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
    ['#2586db','#16937a'].forEach((color,k)=>{c.strokeStyle=color;c.lineWidth=2;c.beginPath();history.forEach((v,i)=>{const x=i/Math.max(1,history.length-1)*w,y=h-12-v[k]/max*(h-28);i?c.lineTo(x,y):c.moveTo(x,y);});c.stroke();if(history.length===1){c.beginPath();c.arc(3,h-12-history[0][k]/max*(h-28),3,0,Math.PI*2);c.fillStyle=color;c.fill();}});
  }
  const releaseCleanup=cleanup;cleanup=()=>{releaseCleanup();clearTimeout(timer);};
  function schedule(){clearTimeout(timer);if(!signal.aborted&&!document.hidden&&+interval.value)timer=setTimeout(poll,Math.min(60000,+interval.value*1000*2**Math.min(failures,3)));}
  async function poll(){
    if(running||document.hidden)return;running=true;clearTimeout(timer);
    try{
      const response=await fetch('/api/monitor',{cache:'no-store',signal:AbortSignal.timeout(12000)});if(!response.ok)throw Error(response.status);
      const data=await response.json();if(signal.aborted)return;failures=0;
      for(const key of ['cpu','memory','disk','uptime','route']){if($('stat-'+key))$('stat-'+key).textContent=data[key];}
      $('ram-meter').value=data.memory_percent;$('disk-meter').value=data.disk_percent;
      for(const [name,value] of Object.entries(data.services)){const cell=$('service-'+name);if(cell){cell.textContent=({active:'Работает',inactive:'Остановлен',failed:'Ошибка',activating:'Запуск'})[value]||value;cell.className='badge '+value;}}
      const keys=Object.keys(data.interfaces);const selected=interfaces.value||store.get('tt-interface','');
      if([...interfaces.options].map(o=>o.value).join()!==keys.join()){
        interfaces.replaceChildren(...keys.map(key=>new Option(key,key)));interfaces.value=keys.includes(selected)?selected:(keys.find(k=>/^(en|eth)/.test(k))||keys[0]||'');
      }
      const name=interfaces.value,v=data.interfaces[name],old=previous?.interfaces[name],dt=previous?data.time-previous.time:0;
      if(v&&old&&dt>0&&dt<=180&&v.rx>=old.rx&&v.tx>=old.tx){const rx=(v.rx-old.rx)/dt,tx=(v.tx-old.tx)/dt;history.push([rx,tx]);history=history.slice(-60);$('network-rate').textContent='Приём VPS: '+bytes(rx)+'/с · отправка VPS: '+bytes(tx)+'/с';}else if(previous){history=[];$('network-rate').textContent='Новое начало измерения; ожидаем следующий образец';}
      $('interface-totals').textContent=v?'С запуска интерфейса: принято '+bytes(v.rx)+' · отправлено '+bytes(v.tx):'Нет сетевых интерфейсов';
      status.textContent='Обновлено '+new Date(data.time*1000).toLocaleTimeString();status.className='muted';previous=data;draw();
    }catch(e){failures++;status.textContent='Связь недоступна · повтор автоматически';status.className='error-text';}
    finally{running=false;schedule();}
  }
  interval.onchange=()=>{store.set('tt-refresh',interval.value);schedule();if(interval.value==='0')status.textContent='Обновление на паузе';};
  interfaces.onchange=()=>{store.set('tt-interface',interfaces.value);previous=null;history=[];draw();poll();};
  $('monitor-refresh').onclick=poll;
  document.addEventListener('visibilitychange',()=>{clearTimeout(timer);if(document.hidden){previous=null;}else if(+interval.value){poll();}},{signal});
  window.addEventListener('resize',draw,{signal});
  poll();
  }
  init();
})();
'''


def endpoint_console():
    capabilities = endpoint_capabilities()
    cfg = tomllib.loads(read_text(TT_DIR / 'vpn.toml'))
    releases = admin_form('endpoint-releases', '<button>' + icon('RefreshCw') + 'Проверить выпуски</button>', view='endpoint')
    update = '''<form method="post" action="/installer" data-confirm="Обновить endpoint? VPN кратковременно перезапустится."><input type="hidden" name="action" value="update-trusttunnel"><label>Канал<select name="channel"><option value="stable">Стабильный</option><option value="beta">Beta · предварительный</option></select></label><label>Подтверждение beta<input name="beta_confirm" placeholder="Только для beta: BETA" autocomplete="off"></label><button class="primary">Обновить VPN-сервер</button></form>'''
    metrics = cfg.get('metrics', {}).get('per_client_metrics', False)
    http1 = '' if 'http1' in cfg.get('listen_protocols', {}) else '<label class="check"><input type="checkbox" name="http1_ack" value="1">Разрешаю добавить HTTP/1.1 для работы локальных метрик. Он также будет доступен на VPN-порту; HTTP/2 и QUIC сохранятся.</label>'
    stats = admin_form('endpoint-metrics', f'<label class="check"><input type="checkbox" name="enabled" value="1" {"checked" if metrics else ""}> Сессии и трафик по клиентам</label>{http1}<button {"" if capabilities["metrics"] else "disabled"}>Применить</button>', view='endpoint', confirm='Перезапустить endpoint для изменения метрик?')
    subscription = cfg.get('subscription', {})
    sub = admin_form('endpoint-subscription', f'<label>Путь HTTPS<input name="path" value="{html.escape(subscription.get("path", "/subscription"), quote=True)}"></label><label class="check"><input type="checkbox" name="enabled" value="1" {"checked" if subscription.get("enabled") else ""}> Включить подписки</label><button {"" if capabilities["subscription"] else "disabled"}>Применить</button>', view='endpoint', confirm='Применить HTTPS-подписки и перезапустить endpoint?')
    availability = 'Доступны в установленной версии.' if capabilities['subscription'] else 'Нужен совместимый endpoint 1.3+ и клиент с поддержкой подписок. В 1.1.0 функция недоступна.'
    details = endpoint_view()
    details = details[details.index('<section'):]
    return f'<div class="page-head"><div><span class="eyebrow">ЯДРО VPN</span><h2>VPN-сервер</h2><p>Установлен {html.escape(endpoint_version())}</p></div>{releases}</div><section class="surface"><h3>Обновления TrustTunnel</h3>{update}</section><section class="surface"><h3>Статистика пользователей</h3><p class="muted">Доступна панели через локальный адрес 127.0.0.1. Счётчики хранятся в памяти endpoint и сбрасываются при его перезапуске.</p>{stats}</section><section class="surface"><h3>HTTPS-подписки</h3><p class="muted">{availability} Для включения требуется доверенный сертификат. Ссылка содержит данные доступа клиента.</p>{sub}</section><details class="surface"><summary>Установка, переустановка и порт</summary>{details}</details>'


def warp_console():
    status = service_snapshot()
    active = current_warp_backend()
    modes = [('wg-socks','WireGuard · SOCKS','wireproxy · 127.0.0.1:40000','warp-wireproxy'), ('masque-socks','MASQUE · SOCKS','usque · 127.0.0.1:40002','warp-masque'), ('wg-interface','WireGuard · интерфейс','Без SOCKS · отдельная регистрация','warp-interface'), ('masque-interface','MASQUE · TUN','Без SOCKS · отдельная регистрация','warp-masque-tun')]
    providers = ''.join(f'<article class="warp-provider {"selected" if active == key else ""}">{icon("ShieldCheck" if key.endswith("interface") else "Cloud")}<h3>{title}</h3><p>{subtitle}</p><span class="badge {status.get(unit, "inactive")}">{"Активный маршрут" if active == key else {"active":"Сервис запущен","inactive":"Остановлен"}.get(status.get(unit),status.get(unit,"Не установлен"))}</span></article>' for key,title,subtitle,unit in modes)
    options = ''.join(f'<option value="{key}" {"selected" if key == active else ""}>{title}</option>' for key,title,_,_ in modes)
    buttons = ''.join(f'<button name="operation" value="{key}" class="{style}">{icon(symbol)}{title}</button>' for key,title,style,symbol in [('check','Проверить','','Activity'),('enable','Включить маршрут','primary','ArrowUpRight'),('disable','Отключить','','Power'),('restart','Перезапустить','','RotateCw'),('install','Установить / переустановить','','Download'),('rotate','Попробовать сменить IP','','RefreshCw'),('reregister','Новая регистрация','','KeyRound'),('remove','Удалить','danger','X')])
    form = admin_form('warp-operation', f'<label>Вариант WARP<select name="backend">{options}</select></label><label class="check"><input type="checkbox" name="accept_tos" value="1">Принимаю условия Cloudflare WARP</label><div class="inline-actions warp-actions">{buttons}</div>', view='warp')
    return f'''<div class="page-head"><div><span class="eyebrow">ИСХОДЯЩИЙ ТРАФИК</span><h2>Cloudflare WARP</h2><p>Активный маршрут: {html.escape(forwarder_label())}</p></div><a class="button" href="/?view=routing">{icon('Route')}Маршрутизация</a></div><div class="warp-providers">{providers}</div><section class="surface"><h3>Управление выбранным вариантом</h3>{form}<p class="muted">Установка не переключает маршрут. Отключение активного SOCKS-варианта включает Direct с IP VPS. Интерфейсный режим возвращает предыдущий маршрут. Новая регистрация меняет только WARP-аккаунт и прерывает текущие сессии.</p><a class="text-link" href="https://www.cloudflare.com/application/terms/" target="_blank" rel="noreferrer">Условия Cloudflare</a></section><section class="surface"><h3>Стабильность соединения</h3><p>При нескольких UDP-потоках SOCKS-forwarder TrustTunnel 1.1.0 может задерживать ответы. Для игр доступны интерфейсные варианты без этого участка. MASQUE не гарантирует меньший пинг; проверяйте маршрут в своей сети.</p><p class="muted">Переподключение не гарантирует новый IP или другую страну. Автоматической подмены WARP на Direct при сбое нет.</p></section>'''


PANEL_STYLE += r'''
.drawer-card{width:min(550px,100%)}
.drawer-card form{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,16em),1fr));align-items:end;gap:14px}
.drawer-card form>:is(label.check,button,.inline-actions),.drawer-card form>label:has(input[type="datetime-local"]){grid-column:1/-1}
.drawer-card form>label{min-width:0;overflow-wrap:anywhere}
.drawer-card form>label.has-help{grid-template-columns:minmax(0,1fr) 20px;padding-right:0}
.drawer-card form>label.has-help>:is(input,select,textarea,.field-help){grid-column:1/-1}
.drawer-card form>label>.help-button{position:static;grid-column:2;grid-row:1;justify-self:end;align-self:start}
.drawer-card form>label.check{display:grid;grid-template-columns:17px minmax(0,1fr);align-items:start}
.drawer-card form>label.check.has-help{grid-template-columns:17px minmax(0,1fr) 20px}
.drawer-card form>label.check>input[type="checkbox"]{grid-column:1;grid-row:1;width:17px;min-width:17px;height:17px;min-height:17px}
.drawer-card form>label.check>.help-button{grid-column:3}
.drawer-card form :is(input:not([type="checkbox"]):not([type="hidden"]),select,textarea){width:100%}
.client-usage{display:flex;flex-wrap:wrap;gap:4px 16px;line-height:1.7}
.client-usage>span{white-space:nowrap}.client-address{max-width:60ch;font-size:11px;line-height:1.6;margin:5px 0;overflow-wrap:anywhere}
.action-control{display:inline-flex;align-items:center;gap:5px;max-width:100%;min-width:0}.action-control>button:first-child{min-width:0;white-space:normal;overflow-wrap:anywhere}
.help-button.action-help{position:static;width:32px;min-width:32px;height:40px;min-height:40px;flex:none;padding:0;align-self:center}
.drawer-card form>.action-control{grid-column:1/-1}.drawer-card form>.action-control>button:first-child{flex:1}
.check-explanation{display:flex;align-items:center;gap:8px;justify-content:space-between}.check-explanation .action-help{height:26px;min-height:26px;width:26px;min-width:26px}
.explain-dialog{width:min(540px,calc(100% - 28px));max-height:85dvh;overflow:auto;padding:26px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--ink);box-shadow:0 20px 70px #0004}
.explain-dialog::backdrop{background:#101b2370}.explain-dialog h3{font-size:18px;line-height:1.4;overflow-wrap:anywhere}.explain-dialog p{white-space:pre-line;font-size:14px;line-height:1.7;color:var(--muted);margin:18px 0 24px;overflow-wrap:anywhere}
.explain-dialog>button{display:block;margin-left:auto}
dialog button:hover:not(:disabled),dialog button:active:not(:disabled){transform:none}
.health-title{display:block;font-size:21px;font-weight:650;line-height:1.4;margin-bottom:6px;overflow-wrap:anywhere}
.health-days{display:grid;grid-template-columns:repeat(30,minmax(0,1fr));gap:4px;min-height:22px}
.health-day{height:20px;border-radius:2px;background:var(--line)}
.health-day.ok{background:#22a98b}.health-day.warn{background:#d5a343}.health-day.error{background:#d96977}
.health-legend{display:flex;flex-wrap:wrap;gap:10px 20px;font-size:11px;color:var(--muted);margin:12px 0 22px}
.health-legend>span:before{content:"";display:inline-block;width:7px;height:7px;border-radius:2px;margin-right:6px;background:var(--line)}
.health-legend>.ok:before{background:#22a98b}.health-legend>.warn:before{background:#d5a343}.health-legend>.error:before{background:#d96977}
.health-checks{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0 24px}
.health-check{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;border-top:1px solid var(--line);padding:12px 0;font-size:12px;min-width:0}
.health-check .badge{white-space:normal;overflow-wrap:anywhere}.badge.ok{color:var(--accent);background:var(--accent-soft)}
.badge.error{color:var(--danger);background:var(--danger-soft)}.badge.warn{color:#ae7c20;background:#a8841815}
.protection-metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
.protection-metrics>div{border-left:2px solid var(--line);padding:0 16px;min-width:0}
.protection-metrics strong{display:block;font-size:25px;font-variant-numeric:tabular-nums;margin-top:6px}
@media(max-width:1000px){.health-checks{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:560px){.health-surface .section-heading{align-items:start;flex-wrap:wrap}.health-title{font-size:19px}.health-days{gap:2px}.health-checks{grid-template-columns:1fr}.protection-metrics{grid-template-columns:1fr;gap:18px}.protection-metrics>div{display:flex;align-items:center;justify-content:space-between;gap:10px}.protection-metrics strong{margin:0;font-size:22px}}
.has-help{position:relative;padding-right:22px}.help-button{position:absolute;right:0;top:-2px;width:20px;height:20px;min-height:20px;padding:0;border:0;background:transparent;box-shadow:none;color:var(--muted)}.help-button .icon{width:15px;height:15px}.field-help{font-size:11px;line-height:1.5;max-width:280px;color:var(--ink);padding:10px;background:var(--accent-soft);border-radius:4px;grid-column:1/-1}.field-help[hidden],label[hidden]{display:none!important}
#action-confirm{width:min(480px,calc(100% - 28px));max-height:85dvh;padding:28px;border:1px solid var(--glass-edge);border-radius:8px;background:var(--glass);color:var(--ink);box-shadow:0 20px 80px #0004;backdrop-filter:blur(20px)}#action-confirm::backdrop{background:#101b2380;backdrop-filter:blur(3px)}#action-confirm h3{font-size:18px}#action-confirm p{font-size:13px;color:var(--muted);margin:18px 0 24px}#action-confirm .inline-actions{justify-content:flex-end}
.warp-providers{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:22px}.warp-provider{padding:20px 16px;background:var(--glass);border:1px solid var(--glass-edge);border-radius:8px;box-shadow:var(--shadow);min-width:0}.warp-provider.selected{border-color:var(--accent);box-shadow:inset 0 2px 0 var(--accent),var(--shadow)}.warp-provider>.icon{color:var(--accent);width:23px;height:23px;margin-bottom:14px}.warp-provider:nth-child(2)>.icon{color:#478fce}.warp-provider:nth-child(3)>.icon{color:#b27d4c}.warp-provider:nth-child(4)>.icon{color:#b26b91}.warp-provider h3{font-size:13px;margin-bottom:6px}.warp-provider p{font-size:11px;color:var(--muted);min-height:34px;margin:0 0 15px;overflow-wrap:anywhere}.warp-provider .badge{white-space:normal}.warp-actions{width:100%;margin-top:8px}.warp-actions button{font-size:12px}.warp-actions .danger{margin-left:auto}#operation-result .inline-actions input{flex:1}#operation-result pre{min-height:100px;max-height:55dvh;overflow:auto}
#release-status{position:relative}#release-status.has-update::after{content:"";position:absolute;top:4px;right:4px;width:6px;height:6px;background:var(--accent);border-radius:50%;box-shadow:0 0 0 2px var(--surface)}
@media(max-width:1000px){.warp-providers{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:560px){.warp-provider{padding:16px 12px}.warp-provider h3{font-size:12px}.warp-provider>.icon{margin-bottom:10px}.warp-actions{display:grid;grid-template-columns:1fr 1fr;align-items:stretch}.warp-actions button{min-height:44px}.warp-actions .danger{margin:0}#action-confirm{padding:22px}}
@media(max-width:560px){.header-actions [data-command-open]{display:none}}
'''
PANEL_STYLE += '\n.logout-form{margin:0!important;display:flex;align-items:center}.logout-form .icon-button{margin:0}@media(max-width:360px){.context h1{font-size:14px}.context .icon-button{width:32px;min-width:32px;height:34px}.context-actions{gap:3px}}\n'
PANEL_STYLE += '''
.route-picker{border:0;padding:0;margin:0 0 16px;min-width:0;width:100%;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;flex-basis:100%}.route-picker legend{font-size:12px;color:var(--muted);padding:0 0 12px}.route-choice{display:flex;align-items:flex-start;gap:12px;margin:0;padding:16px 30px 16px 14px;border:1px solid var(--line);border-radius:7px;cursor:pointer;min-width:0;background:var(--surface);position:relative}.route-choice:has(input:checked){border-color:var(--accent);background:var(--accent-soft)}.route-choice input{width:18px;height:18px;min-height:18px;flex:0 0 18px;margin:3px 0 0;padding:0;accent-color:var(--accent)}.route-choice span{min-width:0}.route-choice strong{display:block;font-size:13px;color:var(--ink);overflow-wrap:anywhere}.route-choice small{display:block;font-size:11px;line-height:1.5;color:var(--muted);margin-top:5px;overflow-wrap:anywhere}.route-current{display:inline-block;margin-top:8px;font-size:10px;color:var(--accent);font-weight:600}.route-choice .help-button{top:8px;right:5px}.security-check form{margin:12px 0 0}.security-check form button{font-size:11px}.client-usage{line-height:1.6}[data-client-seen]{font-size:11px}@media(max-width:560px){.route-picker{grid-template-columns:1fr}.route-choice{padding:14px 30px 14px 12px}}
'''
PANEL_STYLE += '''
#torrent-controls form:has(input[value="torrent-save"]){display:grid;grid-template-columns:repeat(2,minmax(0,1fr));width:100%;gap:14px;align-items:start}
#torrent-controls label.check{grid-column:1/-1;align-items:flex-start;font-size:13px;line-height:1.5}
#torrent-controls label.check input,.drawer-card label.check input{flex:0 0 17px;width:17px;height:17px;margin-top:2px}
#torrent-controls form button{justify-self:start}
@media(max-width:560px){#torrent-controls form:has(input[value="torrent-save"]){grid-template-columns:1fr}#torrent-controls input,#torrent-controls select{width:100%}}
'''
ASSET_VERSION = hashlib.sha256((PANEL_STYLE + CONSOLE_SCRIPT).encode()).hexdigest()[:12]


def page_shell(message='', log='', view='dashboard'):
    views = {'dashboard': overview_console, 'endpoint': endpoint_console, 'clients': clients_console, 'warp': warp_console, 'routing': routing_console, 'dns': dns_console, 'certificates': certificates_view, 'security': security_console, 'system': system_view, 'panel': panel_view, 'logs': logs_console}
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
<dialog id="operation-result" aria-labelledby="result-title"><h3 id="result-title"></h3><div class="inline-actions"><label class="sr-only" for="result-search">Найти в результате</label><input type="search" id="result-search" placeholder="Поиск"><button type="button" id="result-copy" class="icon-button" title="Копировать" aria-label="Копировать результат">{icon('Copy')}</button><button type="button" id="result-download" class="icon-button" title="Скачать TXT" aria-label="Скачать результат">{icon('Download')}</button></div><pre id="result-output"></pre><button class="primary" id="result-close">Закрыть</button></dialog><div class="busy-strip" role="status"><span id="busy-message"></span></div></body></html>'''


def html_page(message='', log='', view='dashboard'):
    page = page_shell(message, log, view)
    dialogs = '<template id="help-icon">' + icon('Info') + '</template><dialog id="action-confirm" aria-labelledby="confirm-title"><h3 id="confirm-title"></h3><p id="confirm-detail"></p><div class="inline-actions"><button type="button" id="confirm-cancel">Отмена</button><button type="button" class="primary" id="confirm-accept">Подтвердить</button></div></dialog>'
    page = page.replace('<dialog id="operation-result"', dialogs + '<dialog id="operation-result"', 1)
    page = page.replace("localStorage.getItem('tt-theme')||'light'", "localStorage.getItem('tt-theme')||'light';document.documentElement.dataset.effects=localStorage.getItem('tt-effects')||'glass'", 1)
    effects = '<button type="button" id="effects-toggle" class="icon-button" title="Переключить прозрачность" aria-label="Переключить прозрачность" aria-pressed="true">' + icon('SlidersHorizontal') + '</button>'
    effects = '<button type="button" id="release-status" class="icon-button" title="Обновления и совместимость" aria-label="Обновления TrustTunnel">' + icon('Download') + '</button>' + effects
    effects += '<form method="post" action="/logout" class="logout-form"><button class="icon-button" title="Выйти" aria-label="Выйти из панели">' + icon('Power') + '</button></form>'
    page = page.replace('<button id="theme-toggle"', effects + '<button id="theme-toggle"', 1)
    page = re.sub(r'(<form\b[^>]*>)', lambda m: m[1] + f'<input type="hidden" name="_csrf" value="{CSRF_TOKEN}">', page)
    selected = html.escape(client_tls_profile(), quote=True)
    page = page.replace(f'<option value="{selected}">{selected}</option>', f'<option value="{selected}" selected>{selected}</option>')
    return page


LOGIN_STYLE = r'''
*{box-sizing:border-box;letter-spacing:0}body{margin:0;min-height:100dvh;font:14px/1.5 "Segoe UI",system-ui,sans-serif;background:#edf1f4;color:#202b34;background-image:linear-gradient(#76939b08 1px,transparent 1px),linear-gradient(90deg,#76939b08 1px,transparent 1px);background-size:44px 44px}.login-layout{min-height:100dvh;display:grid;grid-template-rows:auto 1fr auto;padding:30px 38px}.login-brand{display:flex;align-items:center;gap:12px;font-size:15px;font-weight:650}.icon{width:20px;height:20px;vertical-align:middle;flex:none}.login-brand .icon{width:29px;height:29px;color:#118579}.login-center{display:grid;place-items:center;padding:35px 0}.login-box{width:min(420px,100%);padding:36px;background:#ffffffd9;border:1px solid #fff;border-radius:8px;box-shadow:0 16px 60px #17323a12,0 1px 3px #17323a0a;backdrop-filter:blur(20px)}.login-mark{width:48px;height:48px;display:grid;place-items:center;color:#108373;background:#e8f5ef;border:1px solid #cce8dd;border-radius:8px;margin-bottom:24px}.login-mark .icon{width:27px;height:27px}h1{font-size:29px;line-height:1.2;margin:0 0 8px;font-weight:650}h2{font-size:14px;color:#73808c;font-weight:400;margin:0 0 30px}label{display:block;font-size:12px;color:#657581;margin:18px 0 8px}.login-input{position:relative}.login-input>.icon{position:absolute;left:13px;top:15px;color:#8b99a4;width:18px;height:18px}input{height:48px;width:100%;border:1px solid #d7e0e5;border-radius:6px;background:#ffffffcc;font:inherit;color:inherit;padding:12px 43px 12px 42px;outline:0}input:focus{border-color:#238d7b;box-shadow:0 0 0 3px #21857015}button{font:inherit;cursor:pointer}.password-toggle{position:absolute;right:6px;top:5px;height:38px;width:35px;border:0;background:transparent;color:#748792;border-radius:4px}.login-submit{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;min-height:48px;margin-top:26px;background:#148371;border:1px solid #148371;border-radius:6px;color:#fff;font-weight:600;box-shadow:inset 0 1px 0 #ffffff26,0 3px 9px #14837122;transition:background .15s,transform .15s}.login-submit:hover{background:#106e5f}.login-submit:active{transform:translateY(1px)}button:focus-visible,summary:focus-visible{outline:2px solid #168c7b;outline-offset:3px}.login-error{font-size:12px;color:#a53a43;background:#fbecee;padding:12px;border-left:2px solid #b74750;margin:0 0 18px;overflow-wrap:anywhere}.login-footer{text-align:center;color:#8a98a1;font-size:11px;padding-top:20px}.login-footer span{display:inline-flex;gap:6px;align-items:center}.login-footer .icon{width:13px;height:13px}details{margin-top:23px;color:#7a8893;font-size:11px}summary{cursor:pointer;list-style:none}details p{line-height:1.6;margin-bottom:0}code{font-size:11px;color:#377d88}.login-topline{display:flex;justify-content:space-between;gap:12px;align-items:center}.login-topline>span{font-size:11px;color:#8a98a1}.login-key{display:block;width:26px;height:2px;background:#5c99bb;margin-top:26px}
html[data-theme=dark] body{background-color:#181b20;color:#edf2f4}html[data-theme=dark] .login-box{background:#252a30dd;border-color:#ffffff16;box-shadow:0 20px 70px #0005}html[data-theme=dark] .login-mark{background:#213c35;border-color:#34564c;color:#75d8bc}html[data-theme=dark] input{background:#1d2228;color:#eef2f5;border-color:#404a54}html[data-theme=dark] .login-submit{background:#67cfb2;border-color:#67cfb2;color:#142e28}html[data-theme=dark] .login-error{background:#482c31;color:#f0afb5}
@media(max-width:560px){.login-layout{padding:22px 18px}.login-box{padding:29px 24px}.login-center{padding:28px 0}.login-topline>span{display:none}.login-footer{font-size:10px}.login-box h1{font-size:27px}}
@media(prefers-reduced-transparency:reduce){.login-box{backdrop-filter:none;background:#fff}html[data-theme=dark] .login-box{background:#252a30}}@media(prefers-reduced-motion:reduce){*{transition:none!important}}
'''


LOGIN_STYLE += '''
.login-card{width:min(440px,calc(100% - 28px));margin:40px auto;padding:28px;background:#ffffffed;border:1px solid #fff;border-radius:8px;box-shadow:0 16px 60px #17323a12}.login-card p{font-size:13px;color:#647480;line-height:1.65}.login-card textarea{display:block;width:100%;min-height:90px;margin:16px 0;padding:12px;border:1px solid #d7e0e5;border-radius:5px;font:12px/1.5 monospace;overflow-wrap:anywhere;resize:vertical}.login-card img{display:block;width:260px;height:auto;max-width:100%;margin:16px auto;background:white}.login-card a{display:block;padding:12px;border-radius:6px;background:#148371;color:#fff;text-align:center;text-decoration:none;font-weight:600}.login-card [hidden]{display:none!important}
'''


def login_page(token, nonce, error=''):
    warning = '<div class="login-error" role="alert">' + html.escape(error) + '</div>' if error else ''
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>Вход · TrustTunnel</title><link rel="stylesheet" href="/public/login.css"><script nonce="{nonce}">try{{document.documentElement.dataset.theme=localStorage.getItem('tt-theme')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light')}}catch(_){{}}</script></head><body><div class="login-layout"><header class="login-topline"><div class="login-brand">{icon('ShieldCheck')}TrustTunnel</div><span>Server console</span></header><main class="login-center"><section class="login-box"><div class="login-mark">{icon('KeyRound')}</div><h1>TrustTunnel</h1><h2>Вход в панель управления</h2>{warning}<form method="post" action="/login"><input type="hidden" name="_login_token" value="{token}"><label for="login-user">Логин</label><div class="login-input">{icon('Users')}<input id="login-user" name="username" autocomplete="username" maxlength="64" required autofocus></div><label for="login-password">Пароль</label><div class="login-input">{icon('KeyRound')}<input id="login-password" name="password" type="password" autocomplete="current-password" maxlength="128" required><button class="password-toggle" type="button" id="login-eye" title="Показать пароль" aria-label="Показать пароль" aria-pressed="false">{icon('Eye')}</button></div><button class="login-submit" type="submit">Войти в панель{icon('ArrowUpRight')}</button></form><details><summary>Не получается войти?</summary><p>Данные входа можно изменить по SSH: <code>ttmenu → управление веб-панелью</code>. Пароль на этой странице не восстанавливается.</p></details><span class="login-key"></span></section></main><footer class="login-footer"><span>{icon('ShieldCheck')}Сессия защищена · выход после 30 минут бездействия</span></footer></div><script nonce="{nonce}">document.getElementById('login-eye').onclick=function(){{const input=document.getElementById('login-password');input.type=input.type==='password'?'text':'password';this.setAttribute('aria-pressed',String(input.type==='text'));this.setAttribute('aria-label',input.type==='text'?'Скрыть пароль':'Показать пароль')}};</script></body></html>'''


def activation_page(token, nonce):
    return '''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Профиль TrustTunnel</title><link rel="stylesheet" href="/public/login.css"></head><body><main class="login-card"><h1>Ваше подключение</h1><p>Приглашение используется один раз. Получите профиль только на нужном устройстве. Не отправляйте ссылку и QR другим людям.</p><form id="activation-form"><input type="hidden" name="_csrf" value="'''+html.escape(token, quote=True)+'''"><button class="login-submit" type="submit">Получить профиль</button></form><p id="activation-status" role="status"></p><section id="activation-result" hidden><a id="activation-open">Открыть TrustTunnel</a><p>Сохраните профиль сейчас: после закрытия страницы получить его повторно нельзя.</p><textarea id="activation-link" readonly aria-label="Ссылка подключения"></textarea><img id="activation-qr" alt="QR для импорта профиля" width="260" height="260"><p>Профиль содержит секретные данные. Одноразовая выдача не запрещает его дальнейшее копирование.</p></section></main><script nonce="'''+nonce+'''">
(()=>{const token=location.hash.slice(1);history.replaceState(null,'','/activate');const form=document.getElementById('activation-form'),status=document.getElementById('activation-status');
if(!/^[A-Za-z0-9_-]{43}$/.test(token)){status.textContent='Откройте полную ссылку приглашения от администратора.';form.hidden=true;return;}
form.onsubmit=async e=>{e.preventDefault();const button=form.querySelector('button');button.disabled=true;status.textContent='Получаем профиль…';
try{const body=new URLSearchParams(new FormData(form));body.set('token',token);const response=await fetch('/activate',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});const data=await response.json();if(!response.ok)throw Error(data.error||'Приглашение недействительно.');
document.getElementById('activation-link').value=data.link;document.getElementById('activation-open').href=data.link;document.getElementById('activation-qr').src='data:image/png;base64,'+data.qr;document.getElementById('activation-result').hidden=false;form.hidden=true;status.textContent='Готово. Приглашение погашено.';
}catch(error){status.textContent=error.message+' Если ответ потерян, запросите новое приглашение.';button.disabled=false;}};})();
</script></body></html>'''


class DeadlineReader(io.RawIOBase):
    def __init__(self, connection, seconds=20):
        super().__init__()
        self.connection = connection
        self.deadline = time.monotonic() + seconds

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError('Total HTTP read deadline exceeded')
        self.connection.settimeout(min(20, remaining))
        return self.connection.recv_into(buffer)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'TrustTunnelPanel'
    sys_version = ''
    def setup(self):
        super().setup()
        self.connection.settimeout(20)
        self.rfile.close()
        self.rfile = io.BufferedReader(DeadlineReader(self.connection))

    def parse_request(self):
        if not super().parse_request(): return False
        if not self.valid_host():
            self.send_error(400, 'Invalid panel authority')
            return False
        return True

    def valid_host(self):
        authorities = self.headers.get_all('Host', [])
        if len(authorities) != 1: return False
        authority = authorities[0]
        if re.search(r'[\s/@?#\\]', authority): return False
        try:
            parsed = urllib.parse.urlsplit('//' + authority)
            host = (parsed.hostname or '').lower().rstrip('.')
            port = parsed.port or (443 if isinstance(self.connection, ssl.SSLSocket) else 80)
            local_host, local_port = self.connection.getsockname()[:2]
            allowed = {'localhost', '127.0.0.1', '::1', str(local_host).lower(), domain().lower().rstrip('.')}
            return bool(host) and host in allowed and port == local_port
        except (ValueError, OSError):
            return False

    def send_error(self, code, message=None, explain=None):
        if code in (400,401,403,404,405,413,414,431,501): panel_event('rejected')
        if code==429: panel_event('throttled')
        # Avoid a TCP reset hiding a rejection when a small POST body is in flight.
        if self.command=='POST' and hasattr(self,'headers') and not getattr(self,'_post_body_read',False) and not self.headers.get_all('Transfer-Encoding',[]):
            lengths=self.headers.get_all('Content-Length',[])
            if len(lengths)==1 and re.fullmatch(r'[0-9]{1,5}',lengths[0]) and int(lengths[0])<=65536:
                timeout=self.connection.gettimeout()
                try:
                    self.connection.settimeout(1)
                    self.rfile.read(int(lengths[0]))
                    self._post_body_read=True
                except OSError: pass
                finally: self.connection.settimeout(timeout)
        super().send_error(code,message,explain)

    def end_headers(self):
        self.send_header('Cache-Control', 'private, max-age=86400, immutable' if getattr(self, '_asset_response', False) else 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'same-origin')
        nonce = getattr(self, '_csp_nonce', '')
        scripts = "'self'" + (" 'nonce-" + nonce + "'" if nonce else '')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src " + scripts + "; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        if isinstance(self.connection, ssl.SSLSocket): self.send_header('Strict-Transport-Security', 'max-age=86400')
        super().end_headers()

    def authenticated(self):
        if not PANEL_PASSWORD:
            self.send_error(503, 'Panel password is not configured')
            return False
        token = self.cookie('session')
        if token:
            now = time.monotonic()
            with SESSION_LOCK:
                for key, session in list(SESSIONS.items()):
                    if now-session['seen'] > SESSION_IDLE_SECONDS or now-session['created'] > SESSION_MAX_SECONDS: SESSIONS.pop(key, None)
                session = SESSIONS.get(hashlib.sha256(token.encode()).hexdigest())
                if session:
                    session['seen'] = now
                    return True
        auth = self.headers.get('Authorization', '') if 'text/html' not in self.headers.get('Accept','') else ''
        peer = self.client_address[0]
        delay = login_delay(peer)
        if delay:
            panel_event('throttled')
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
        if not auth and 'text/html' in self.headers.get('Accept', ''):
            self.send_response(303); self.send_header('Location', '/login'); self.end_headers(); return False
        self.send_response(401)
        if auth:self.send_header('WWW-Authenticate', 'Basic realm="TrustTunnel Panel"')
        self.end_headers()
        return False

    def cookie_name(self, kind):
        return ('__Host-' if isinstance(self.connection, ssl.SSLSocket) else '') + 'tt_' + kind

    def cookie(self, kind):
        try:
            cookies = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
            item = cookies.get(self.cookie_name(kind))
            return item.value if item else ''
        except http.cookies.CookieError:
            return ''

    def set_cookie(self, kind, value, lifetime):
        secure = '; Secure' if isinstance(self.connection, ssl.SSLSocket) else ''
        self.send_header('Set-Cookie', f'{self.cookie_name(kind)}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={lifetime}{secure}')

    def send_login(self, error='', status=200):
        self._csp_nonce = secrets.token_urlsafe(18)
        token = secrets.token_urlsafe(32)
        page=login_page(token,self._csp_nonce,error)
        page=page.replace('name="username" autocomplete="username"','name="panel_login" autocomplete="section-tt-admin username"')
        page=page.replace('name="password" type="password" autocomplete="current-password"','name="panel_password" type="password" autocomplete="section-tt-admin current-password"')
        body = page.encode('utf-8')
        self.send_response(status)
        self.set_cookie('login', token, 600)
        self.send_header('Content-Type','text/html; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def handle_login(self):
        delay = login_delay(self.client_address[0])
        if delay:
            panel_event('throttled'); self.send_login('Слишком много попыток. Подождите минуту.',429); return
        origin = self.headers.get('Origin')
        expected = ('https://' if isinstance(self.connection, ssl.SSLSocket) else 'http://') + self.headers.get('Host','')
        if origin and origin != expected:
            self.send_error(403); return
        try:
            if not 0 <= int(self.headers.get('Content-Length','0')) <= 4096: raise ValueError()
            data = self.form()
        except (ValueError, UnicodeError): self.send_error(400); return
        token = self.cookie('login')
        if not token or not secrets.compare_digest(token.encode(), data.get('_login_token','').encode()):
            self.send_login('Форма устарела. Попробуйте ещё раз.', 403); return
        username, password = data.get('username',''), data.get('password','')
        valid_user = secrets.compare_digest(username.encode(), PANEL_USER.encode())
        valid_password = secrets.compare_digest(password.encode(), PANEL_PASSWORD.encode())
        if not PANEL_PASSWORD or not (valid_user and valid_password):
            login_delay(self.client_address[0], failed=True)
            self.send_login('Неверный логин или пароль.', 401); return
        login_delay(self.client_address[0], success=True)
        session = secrets.token_urlsafe(32); now = time.monotonic()
        with SESSION_LOCK:
            if len(SESSIONS) >= 128: SESSIONS.pop(next(iter(SESSIONS)))
            SESSIONS[hashlib.sha256(session.encode()).hexdigest()] = {'created':now,'seen':now}
        self.send_response(303)
        self.set_cookie('session', session, SESSION_MAX_SECONDS)
        self.set_cookie('login','',0)
        self.send_header('Location','/')
        self.end_headers()

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, message='', log='', view='dashboard'):
        if self.command == 'POST' and 'application/json' in self.headers.get('Accept', ''):
            with CACHE_LOCK:
                SNAPSHOT_CACHE.clear()
            self.send_json({'ok': True, 'output': log or message, 'refresh': getattr(self, '_legacy_refresh', False)})
            return
        self._csp_nonce = secrets.token_urlsafe(18)
        body = html_page(message, log, view).replace('<script>', '<script nonce="' + self._csp_nonce + '">', 1).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def form(self):
        if self.headers.get_all('Transfer-Encoding', []) or len(self.headers.get_all('Content-Length', [])) != 1:
            raise ValueError('Ambiguous request framing')
        if self.headers.get_content_type() != 'application/x-www-form-urlencoded':
            raise ValueError('Expected a URL-encoded form')
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 <= length <= 65536:
            raise ValueError('Request body too large')
        self._post_body_read=True
        body = self.rfile.read(length)
        if len(body) != length: raise ValueError('Incomplete request body')
        parsed = urllib.parse.parse_qs(body.decode('utf-8'),keep_blank_values=True,max_num_fields=80)
        if any(len(v) != 1 for v in parsed.values()): raise ValueError('Duplicate form fields')
        values = {k:v[0] for k,v in parsed.items()}
        for source,target in (('vpn_client_name','username'),('panel_login','username'),('panel_password','password')):
            if source in values:
                if target in values: raise ValueError('Ambiguous identity fields')
                values[target] = values.pop(source)
        return values

    def redirect(self, message):
        if 'application/json' in self.headers.get('Accept', ''):
            with CACHE_LOCK:
                SNAPSHOT_CACHE.clear()
            self.send_json({'ok': True, 'output': message, 'refresh': True})
            return
        allowed = {key for key, _ in NAV_ITEMS}
        ref = urllib.parse.urlparse(self.headers.get('Referer', ''))
        candidate = urllib.parse.parse_qs(ref.query).get('view', ['dashboard'])[0]
        view = candidate if candidate in allowed else 'dashboard'
        self.send_response(303)
        self.send_header('Location', '/?view=' + urllib.parse.quote(view) + '&msg=' + urllib.parse.quote(message))
        self.end_headers()

    def do_GET(self):
        try: self.handle_get()
        except (ValueError,RuntimeError,OSError,sqlite3.Error):
            self.send_json({'error':'Не удалось прочитать состояние панели. Проверьте журнал службы и конфигурацию.'},503)

    def handle_get(self):
        if self.path == '/activate':
            self._csp_nonce = secrets.token_urlsafe(18)
            token = secrets.token_urlsafe(32)
            body = activation_page(token, self._csp_nonce).encode()
            self.send_response(200); self.set_cookie('activation', token, 900)
            self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        if self.path == '/login': self.send_login(); return
        if self.path == '/public/login.css':
            body = LOGIN_STYLE.encode('utf-8'); self.send_response(200)
            self.send_header('Content-Type','text/css; charset=utf-8'); self.send_header('Content-Length',str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        if self.path == '/health':
            self.send_response(200); self.end_headers(); self.wfile.write(b'ok\n'); return
        if not self.authenticated():
            return
        if self.path in ('/api/server-health','/api/panel-protection'):
            self.send_json(health_snapshot() if self.path=='/api/server-health' else scanner_snapshot()); return
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
            query = urllib.parse.parse_qs(parsed.query)
            username = query.get('username', [''])[0]
            if not client_name_valid(username) or username not in {c['username'] for c in load_clients()}:
                self.send_json({'error': 'Клиент не найден'}, 404)
                return
            try:
                protocol = query.get('protocol', ['http2'])[0]
                kind = query.get('kind', ['static'])[0]
                link = deeplink(username, protocol, kind)
                self.send_json({'link': link, 'protocol': protocol, 'kind': kind})
            except (ValueError, RuntimeError, OSError) as exc:
                self.send_json({'error': str(exc)}, 400)
            return
        if parsed.path == '/api/clients-metrics':
            self.send_json(client_metrics())
            return
        if parsed.path == '/api/releases':
            self.send_json(release_snapshot())
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
        m = re.fullmatch(r'/qr-link/([^/]+)\.png', parsed.path) or re.fullmatch(r'/qr/([^/]+)/(http2|http3)\.png', parsed.path)
        if m:
            username = urllib.parse.unquote(m.group(1))
            if not client_name_valid(username) or username not in {c['username'] for c in load_clients()}:
                self.send_error(404); return
            query = urllib.parse.parse_qs(parsed.query)
            protocol = m.group(2) if m.lastindex == 2 else query.get('protocol', ['http2'])[0]
            try:
                body = qr_image(deeplink(username, protocol, query.get('kind', ['static'])[0]))
                self.send_response(200)
                self.send_header('Content-Type', 'image/png')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Content-Disposition', 'inline; filename="trusttunnel-qr.png"')
                self.end_headers(); self.wfile.write(body)
            except (ValueError, RuntimeError, OSError) as exc:
                self.send_json({'error': str(exc)}, 400)
            return
        if parsed.path == '/backup/latest.zip':
            archive = Path('/root/trusttunnel-identity-backup.zip')
            if not archive.is_file(): self.send_error(404,'Create an identity backup from System first'); return
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
        self._post_body_read=False
        try:
            if self.path == '/activate': self.handle_activation(); return
            if self.path == '/login': self.handle_login(); return
            self.handle_post()
        except (ValueError, RuntimeError, OSError, sqlite3.Error) as exc:
            if self.path in ('/activate','/login'):
                self.send_json({'error':'Некорректный запрос.'},400); return
            if 'application/json' in self.headers.get('Accept', ''):
                self.send_json({'ok': False, 'output': str(exc), 'refresh': False}, 400)
            else:
                self.send_html('Операция не выполнена.', str(exc))

    def handle_activation(self):
        peer = 'activation:' + self.client_address[0]
        origin = ('https://' if isinstance(self.connection,ssl.SSLSocket) else 'http://')+self.headers.get('Host','')
        if self.headers.get('Origin') != origin: self.send_json({'error':'Неверный источник запроса.'},403); return
        if not isinstance(self.connection,ssl.SSLSocket) and not ipaddress.ip_address(self.client_address[0]).is_loopback:
            self.send_json({'error':'Требуется HTTPS.'},403); return
        if not 0 < int(self.headers.get('Content-Length','0')) <= 4096: self.send_json({'error':'Некорректный запрос.'},400); return
        values = self.form(); csrf = values.get('_csrf','')
        if login_delay(peer): self.send_json({'error':'Слишком много попыток. Повторите через минуту.'},429); return
        if not csrf or not secrets.compare_digest(csrf.encode(),self.cookie('activation').encode()):
            self.send_json({'error':'Откройте приглашение повторно.'},403); return
        try:
            result = redeem_enrollment(values.get('token',''), self.client_address[0])
        except (ValueError, RuntimeError, OSError, sqlite3.Error):
            login_delay(peer,failed=True)
            self.send_json({'error':'Приглашение истекло, использовано или отозвано. Запросите новое у администратора.'},400); return
        login_delay(peer,success=True); self.send_json(result)

    def handle_post(self):
        if not self.authenticated():
            return
        origin = self.headers.get('Origin')
        expected_origin = ('https://' if isinstance(self.connection, ssl.SSLSocket) else 'http://') + self.headers.get('Host', '')
        if origin and origin != expected_origin:
            self.send_error(403, 'Cross-origin request rejected'); return
        try:
            f = self.form()
        except (ValueError, UnicodeError):
            self.send_error(400, 'Invalid form'); return
        if not secrets.compare_digest(f.get('_csrf', '').encode(), CSRF_TOKEN.encode()):
            self.send_error(403, 'Reload page and try again'); return
        if self.path == '/logout':
            token = self.cookie('session')
            with SESSION_LOCK: SESSIONS.pop(hashlib.sha256(token.encode()).hexdigest(), None)
            self.send_response(303); self.set_cookie('session','',0); self.send_header('Location','/login'); self.end_headers(); return
        self._legacy_refresh = self.path not in ('/action', '/maintenance') or f.get('action') in ('restart', 'reboot', 'warp', 'direct', 'restart-warp', 'renew-cert', 'enable', 'disable')
        if self.path == '/manage':
            wants_json = 'application/json' in self.headers.get('Accept', '')
            read_only = {'monitor', 'logs', 'audit', 'security-audit', 'security-scan', 'security-status', 'security-listeners', 'security-logins', 'security-ignore-list', 'dns-check', 'routing-check', 'client-list', 'client-link', 'endpoint-releases', 'masque-status', 'masque-check', 'certificate-status', 'recommendations', 'interface-status', 'interface-check', 'protection-status', 'schedule-status', 'guard-status'}
            read_only |= {'diagnostics-stack','diagnostics-client','diagnostics-egress','diagnostics-warp','routing-current'}
            read_only |= {'ufw-applications','ufw-logs','ufw-preview','f2b-status','f2b-test','f2b-logs','f2b-jail-status'}
            read_only.add('torrent-status')
            read_only |= {'health-status','health-check','scanner-status'}
            try:
                f['_peer'] = self.client_address[0]
                result = admin_operation(f.get('action', ''), f)
                refresh = f.get('action') not in read_only and not (f.get('action') == 'warp-operation' and f.get('operation') in ('status','check'))
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
                result = admin_operation('system-' + action, f)
                with CACHE_LOCK: SNAPSHOT_CACHE.clear()
                self.send_html('Операция выполнена.', result, 'system')
                return
            if action == 'warp':
                self.redirect(admin_operation('routing-switch', {'mode': 'warp'}))
                return
            if action == 'direct':
                self.redirect(admin_operation('routing-switch', {'mode': 'direct'}))
                return
            if action == 'speedtest':
                self.send_html('Speedtest finished.', speedtest_output()); return
            if action == 'backup':
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
            self.redirect(admin_operation('routing-switch', {'mode': 'socks5', 'address': f.get('address', '')}))
            return
        if self.path == '/client/add':
            action = 'add'
        elif self.path in ('/client/delete', '/client/password'):
            action = self.path.rsplit('/', 1)[1]
        else:
            action = None
        if action:
            self.redirect(client_operation(action, f))
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
            self.send_html('fail2ban action finished.', fail2ban_output(f.get('action', 'status'), f.get('ip', '').strip(), dict(f,_peer=self.client_address[0])))
            return
        if self.path == '/ufw':
            self.send_html('UFW action finished.', ufw_output(f.get('action', 'status'), f.get('port', '').strip(), f.get('proto', 'tcp').strip(), dict(f,_peer=self.client_address[0])))
            return
        if self.path == '/rules/add-deny':
            self.redirect(admin_operation('routing-rule-add', {'cidr':f.get('cidr', ''), 'decision':'deny'})); return
        if self.path == '/rules/reset':
            if f.get('confirm') != 'RESET':
                raise ValueError('Для удаления всех правил введите RESET.')
            with admin_lock():
                if strict_protection_locked():raise ValueError('Сначала отключите строгую TLS/ClientHello-защиту через раздел безопасности.')
                apply_endpoint_file(managed_rules_path(), '# Empty rules file\n')
            self.redirect('Правила сброшены.'); return
        self.send_error(404)


class PanelServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        self.peers_lock = threading.Lock()
        self.peers = {}
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        peer = client_address[0]
        with self.peers_lock:
            if self.peers.get(peer, 0) >= 4:
                panel_event('throttled')
                self.shutdown_request(request)
                return
            self.peers[peer] = self.peers.get(peer, 0) + 1
        if not self.slots.acquire(blocking=False):
            self.release_peer(peer)
            panel_event('throttled')
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            self.release_peer(peer)
            raise

    def release_peer(self, peer):
        with self.peers_lock:
            count = self.peers.get(peer, 1) - 1
            if count: self.peers[peer] = count
            else: self.peers.pop(peer, None)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()
            self.release_peer(client_address[0])


def main():
    bind = os.environ.get('PANEL_BIND', '127.0.0.1')
    port = int(os.environ.get('PANEL_PORT', '8088'))
    if bind not in ('127.0.0.1', '::1', 'localhost') and not PANEL_TLS:
        raise RuntimeError('Для публичного доступа к панели требуется HTTPS.')
    server = PanelServer((bind, port), Handler)
    if PANEL_TLS:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(PANEL_CERT, PANEL_KEY)
        # Complete TLS in a bounded worker, under the connection timeout.
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=release_watcher, name='release-watcher', daemon=True).start()
    threading.Thread(target=security_watcher, name='security-watcher', daemon=True).start()
    threading.Thread(target=usage_watcher, name='usage-watcher', daemon=True).start()
    threading.Thread(target=health_watcher,name='health-watcher',daemon=True).start()
    server.serve_forever()


if __name__ == '__main__':
    if sys.argv[1:] == ['--torrent-reconcile']:
        try: torrent_reconcile()
        except (ValueError,RuntimeError,OSError) as exc:
            print('BitTorrent filter: '+str(exc),file=sys.stderr)
            sys.exit(1)
    elif len(sys.argv) == 3 and sys.argv[1] == '--firewall-rollback':
        print(firewall_rollback(sys.argv[2]))
    elif len(sys.argv) > 1 and sys.argv[1] == '--admin':
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

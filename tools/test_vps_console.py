"""Candidate checks on the explicitly authorized test VPS. No reboot or VPN restart."""
import hashlib
import importlib.util
import os
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

source = os.environ.get('TT_PANEL_SOURCE', '/usr/local/sbin/trusttunnel-panel.py')
spec = importlib.util.spec_from_file_location('panel', source)
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)


def identity():
    paths = list(Path('/opt/trusttunnel/certs').glob('*'))
    paths += list(Path('/root/trusttunnel-clients').glob('*.toml'))
    paths += [Path('/opt/trusttunnel') / n for n in ('vpn.toml', 'hosts.toml', 'credentials.toml', 'rules.toml')]
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}


before = identity()
start = time.monotonic()
first = panel.monitor_snapshot()
cold = time.monotonic() - start
with ThreadPoolExecutor(max_workers=8) as pool:
    snapshots = list(pool.map(lambda _: panel.monitor_snapshot(), range(20)))
assert all(item['time'] == first['time'] for item in snapshots)
assert first['services']['trusttunnel'] == 'active'
print('Shared monitoring cache: PASS, cold sample %.3fs' % cold)
audit = panel.security_snapshot()
assert len(audit['checks']) >= 6
print('Security audit, checks:', len(audit['checks']))

ignore = panel.IGNORE_FILE
old = ignore.read_bytes() if ignore.exists() else None
mode = ignore.stat().st_mode & 0o777 if ignore.exists() else 0o600
test_ip = '192.0.2.247'
assert test_ip not in panel.network_operation('security-ignore-list', {})
try:
    panel.network_operation('security-ignore-add', {'ip': test_ip})
    assert test_ip in panel.network_operation('security-ignore-list', {})
    panel.network_operation('security-ignore-remove', {'ip': test_ip})
    assert test_ip not in panel.network_operation('security-ignore-list', {})
    print('Persistent fail2ban exclusion add/remove: PASS')
finally:
    if old is None:
        ignore.unlink(missing_ok=True)
    else:
        ignore.write_bytes(old)
        ignore.chmod(mode)
    panel.checked_run(['fail2ban-client', 'reload', 'sshd'])

port = '59178'
assert port not in panel.checked_run(['ufw', 'status'])
values = {'port': port, 'proto': 'tcp', 'source': '198.51.100.0/24'}
try:
    panel.network_operation('security-open', values)
    assert port in panel.checked_run(['ufw', 'status'])
    print('Source-scoped UFW allowance: PASS')
finally:
    panel.network_operation('security-close', values)
assert port not in panel.checked_run(['ufw', 'status'])
assert before == identity(), 'VPN identity/config/profile files changed'
print('VPN settings, credentials, certificates and profiles: unchanged')

"""Exercise temporary firewall/jail changes on the test VPS, then undo them."""
import configparser
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('panel', '/tmp/trusttunnel-panel.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
jail = Path('/etc/fail2ban/jail.d/sshd.local')
old = jail.read_text() if jail.exists() else None
address = '192.0.2.247'
port = '59177'
added_port = added_ban = False
try:
    p.network_operation('security-fail2ban', {'retry':'5','findtime':'600','bantime':'3600'})
    assert p.checked_run(['fail2ban-client','get','sshd','maxretry']).strip() == '5'
    print('LIVE fail2ban settings validated and applied: PASS')
    banned = p.checked_run(['fail2ban-client','get','sshd','banip'])
    if address not in banned.split():
        added_ban = True
        p.network_operation('security-ban', {'ip':address})
        assert address in p.checked_run(['fail2ban-client','get','sshd','banip'])
        p.network_operation('security-unban', {'ip':address})
        added_ban = False
        print('LIVE ban/unban documentation IP: PASS')
    status = p.checked_run(['ufw','status'])
    if port not in status:
        added_port = True
        p.network_operation('security-open', {'port':port,'proto':'tcp'})
        assert port in p.checked_run(['ufw','status'])
        p.network_operation('security-close', {'port':port,'proto':'tcp'})
        added_port = False
        assert port not in p.checked_run(['ufw','status'])
        print('LIVE temporary UFW allow/delete: PASS')
finally:
    if added_port: p.network_operation('security-close', {'port':port,'proto':'tcp'})
    if added_ban: p.network_operation('security-unban', {'ip':address})
    if old is not None: p.atomic_write(jail,old)
    else: jail.unlink(missing_ok=True)
    p.checked_run(['systemctl','restart','fail2ban'])
    print('Original jail restored; temporary ban and firewall rule removed')

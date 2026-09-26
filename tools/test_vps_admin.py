"""Run only on the designated test VPS. Preserves existing user identities."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets

spec = importlib.util.spec_from_file_location('candidate', '/tmp/trusttunnel-panel.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
original_clients = p.load_clients()
original_files = [p.TT_DIR/'credentials.toml', p.TT_DIR/'clients-state.json', p.TT_DIR/'vpn.toml', p.TT_DIR/'rules.toml', p.PANEL_SETTINGS]
saved = {file: file.read_bytes() if file.exists() else None for file in original_files}
protected = [p.TT_DIR/'certs/cert.pem', p.TT_DIR/'certs/key.pem'] + list(p.CLIENT_DIR.glob('*.toml'))
hashes = {file: hashlib.sha256(file.read_bytes()).hexdigest() for file in protected}
username = 'qa-' + secrets.token_hex(5)
try:
    p.client_operation('add', {'username': username})
    password = next(c['password'] for c in p.load_clients() if c['username'] == username)
    p.client_operation('note', {'username': username, 'note': 'QA temporary client'})
    p.client_operation('disable', {'username': username})
    assert username not in {c['username'] for c in p.load_clients()}
    p.client_operation('enable', {'username': username})
    assert next(c['password'] for c in p.load_clients() if c['username'] == username) == password
    link = p.client_operation('link', {'username': username})
    assert link.startswith('tt://'), 'Endpoint deep link failed'
    p.client_operation('delete', {'username': username})
    assert sorted(p.load_clients(), key=lambda c:c['username']) == sorted(original_clients,key=lambda c:c['username'])
    for file, expected in hashes.items():
        assert hashlib.sha256(file.read_bytes()).hexdigest() == expected, 'Protected file changed: ' + str(file)
    print('LIVE CLIENT add/note/disable/enable/link/delete: PASS; existing users/certificates/profiles unchanged')
    print('DNS CHECK:', 'status: NOERROR' in p.network_operation('dns-check', {}))
    p.network_operation('routing-switch', {'mode': 'warp'})
    assert 'WARP' in p.forwarder_label()
    trace = p.checked_run(['curl','-fsS','--max-time','15','--proxy','socks5h://127.0.0.1:40000','https://www.cloudflare.com/cdn-cgi/trace'])
    assert 'warp=on' in trace or 'warp=plus' in trace
    print('LIVE WARP health and route switch: PASS')
    rules = p.tomllib.loads(p.read_text(p.TT_DIR/'rules.toml')).get('rule', [])
    p.network_operation('routing-rule-add', {'cidr': '192.0.2.247/32', 'decision': 'deny'})
    p.network_operation('routing-rule-delete', {'index': str(len(rules) + 1)})
    assert p.tomllib.loads(p.read_text(p.TT_DIR/'rules.toml')).get('rule', []) == rules
    print('LIVE access rule add/delete: PASS')
    for port in (p.current_ssh_port(), p.endpoint_port(), p.current_panel_env().get('PANEL_PORT','8088')):
        try: p.network_operation('security-close', {'port':port})
        except ValueError: pass
        else: raise AssertionError('Protected port not rejected')
    print('LIVE protected ports: PASS')
finally:
    # Exact configuration restoration, even when an assertion fails.
    for file, data in saved.items():
        if data is None: file.unlink(missing_ok=True)
        else: p.atomic_write(file, data.decode())
    for protocol in ('http2','http3'):
        (p.CLIENT_DIR / f'{username}-{protocol}.toml').unlink(missing_ok=True)
    p.write_text(p.CLIENT_DIR/'clients-credentials.txt',''.join(f"{c['username']} {c['password']}\n" for c in original_clients))
    p.checked_run(['systemctl','restart','trusttunnel'])
    assert p.service_status('trusttunnel') == 'active'
    print('Original configuration restored; TrustTunnel active')

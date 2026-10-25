"""Opt-in read-only qualification on the designated test VPS; no service changes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    if sys.argv[1:] != ['--read-only-test-vps']: raise SystemExit('Explicit --read-only-test-vps required')
    root=Path(__file__).resolve().parents[1]
    spec=importlib.util.spec_from_file_location('candidate',root/'trusttunnel-panel.py')
    p=importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
    assert p.domain()=='mysdfd.duckdns.org' and p.endpoint_port()=='8443','Unexpected target'
    paths=[p.TT_DIR/n for n in ('credentials.toml','hosts.toml','vpn.toml','rules.toml','certs/cert.pem','certs/key.pem')]
    paths+=list(p.CLIENT_DIR.glob('*'))+list(p.firewall_files().values())
    paths+=list((p.FAIL2BAN_DIR/'jail.d').glob('*'))
    def hashes(): return {str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths if path.is_file()}
    before=hashes()
    for name in ('test_admin.py','test_client_protection.py','test_activation_http.py','test_firewall_fail2ban.py','test_panel_security_http.py','test_installer_sandbox.py'):
        subprocess.run([sys.executable,str(root/'tools'/name)],check=True,timeout=120)
    subprocess.run(['bash','-n',str(root/'install-trusttunnel-warp.sh')],check=True)
    data=p.firewall_snapshot(); assert data['available'] and data['active'] and len(data['rules'])>=4
    assert {(49222,'tcp'),(8443,'tcp'),(8443,'udp'),(8088,'tcp')} <= set(p.protected_ports())
    for rule in data['rules']:
        try: p.firewall_delete({'number':str(rule['number']),'version':data['version']})
        except ValueError: pass
        else: raise AssertionError('Existing service permit not protected')
    p.firewall_operation('preview',{'port':'59178','source':'192.0.2.0/24','comment':'read-only candidate check'})
    p.fail2ban_operation('test',{})
    jail=p.fail2ban_operation('jail-status',{'jail':'sshd'})
    assert 'sshd' in jail
    report=p.security_snapshot()
    assert before==hashes(),'Live configuration changed during read-only verification'
    print('Linux unit/HTTP/installer tests and real UFW dry-run: PASS')
    print('Live firewall, jail, identity and client files unchanged: PASS')
    print(json.dumps({'security_checks':report['checks'],'ufw_rules':len(data['rules']),
                      'fail2ban':p.fail2ban_snapshot()['active']},ensure_ascii=False,indent=2))


if __name__=='__main__': main()

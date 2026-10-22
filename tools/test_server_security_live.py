"""Authorized test VPS: reversible echo policy and a non-destructive timer only."""
import importlib.util
import json
from pathlib import Path
import subprocess

root=Path('/root/trusttunnel-staging-20261022')
spec=importlib.util.spec_from_file_location('security_live',root/'trusttunnel-panel.py')
panel=importlib.util.module_from_spec(spec);spec.loader.exec_module(panel)
files=[Path('/etc/ufw/before.rules'),Path('/etc/ufw/before6.rules')]
original={path:path.read_bytes() for path in files}
timer='trusttunnel-scheduled-releases'
unit_files=[Path('/etc/systemd/system')/(timer+suffix) for suffix in ('.service','.timer')]
assert not any(path.exists() for path in unit_files),'Do not overwrite an existing schedule'
try:
    panel.configure_echo_policy({'enabled':'0','confirm':'CONFIRMED'})
    assert all('--comment TT_PANEL_PING' in path.read_text() for path in files)
    assert subprocess.run(['systemctl','is-active','--quiet','trusttunnel']).returncode==0
    assert subprocess.run(['systemctl','is-active','--quiet','ssh']).returncode==0
    panel.configure_echo_policy({'enabled':'1','confirm':'CONFIRMED'})
    assert all(path.read_bytes()==body for path,body in original.items())
    print('Live UFW echo-only IPv4/IPv6 policy, syntax checks, reload and exact rollback: PASS')
    panel.schedule_operation('save',{'kind':'releases','day':'Sun','time':'23:58','confirm':'CONFIRMED'})
    assert subprocess.run(['systemctl','is-active','--quiet',timer+'.timer']).returncode==0
    assert subprocess.run(['systemctl','is-active','--quiet',timer+'.service'],capture_output=True).returncode!=0
    panel.schedule_operation('disable',{'kind':'releases','confirm':'CONFIRMED'})
    print('Real calendar validation, timer enable/status/disable without running an update or reboot: PASS')
    panel.network_operation('security-scan',{})
    report=json.loads(panel.SECURITY_REPORT.read_text())
    assert len(report['checks'])>=11
    print('Local server security report: '+str(len(report['checks']))+' checks saved; no automatic remediation')
finally:
    for path,body in original.items():path.write_bytes(body)
    subprocess.run(['ufw','reload'],check=True,capture_output=True)
    subprocess.run(['systemctl','disable','--now',timer+'.timer'],capture_output=True)
    for path in unit_files:path.unlink(missing_ok=True)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    assert all(path.read_bytes()==body for path,body in original.items())
    print('Original firewall configuration restored; temporary timer removed: PASS')

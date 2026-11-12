"""Jailless native filter/config test in a new, root-private staging directory."""
import ast
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    if sys.argv[1:] != ['--isolated-config-test'] or os.geteuid() != 0:
        raise SystemExit('Explicit --isolated-config-test on Linux as root required')
    root = Path(__file__).resolve().parents[1]
    if not root.is_relative_to('/root') or root.is_symlink():
        raise SystemExit('Use a private /root staging tree')
    spec = importlib.util.spec_from_file_location('candidate', root/'trusttunnel-panel.py')
    p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
    lab = Path(tempfile.mkdtemp(prefix='native-panel-login-lab-',dir=root))
    (lab/'filter.d').mkdir(mode=0o700)
    (lab/'jail.d').mkdir(mode=0o700)
    (lab/'action.d').mkdir(mode=0o700)
    for name in ('iptables-multiport.conf', 'iptables.conf'):
        source = Path('/etc/fail2ban/action.d')/name
        assert source.is_file() and not source.is_symlink()
        shutil.copyfile(source, lab/'action.d'/name)
    filter_path = lab/'filter.d/trusttunnel-panel.conf'
    p.atomic_write(filter_path, p._panel_login_filter_text())
    p.atomic_write(lab/'fail2ban.conf','[Definition]\nloglevel = INFO\nlogtarget = STDOUT\nsyslogsocket = auto\nsocket = '+str(lab/'unused.sock')+'\npidfile = '+str(lab/'unused.pid')+'\ndbfile = None\ndbmaxmatches = 10\ndbpurgeage = 1d\nallowipv6 = auto\n')
    p.atomic_write(lab/'jail.conf', '[DEFAULT]\nbackend = systemd\nlogencoding = auto\nallowipv6 = auto\n\n'+p._panel_login_jail_text('8088', True))
    p._panel_login_check_path(filter_path)
    p._panel_login_filter_check(filter_path)
    subprocess.run(['fail2ban-client','-c',str(lab),'-t'],check=True,timeout=30)
    dump = subprocess.check_output(['fail2ban-client','-c',str(lab),'-d'],text=True,timeout=30)
    commands = [ast.literal_eval(line) for line in dump.splitlines() if line.startswith('[')]
    assert [c for c in commands if c[0]=='add'] == [['add',p.PANEL_LOGIN_JAIL,'systemd']]
    assert [c for c in commands if c[0]=='start'] == [['start',p.PANEL_LOGIN_JAIL]]
    assert all(command[1] == p.PANEL_LOGIN_JAIL for command in commands if command[0]=='multi-set')
    actions = [str(command) for command in commands if 'actionstart' in str(command)]
    assert actions and all('--dports 8088' in value and '-p $proto' in value and 'INPUT' in value for value in actions)
    assert not any('--dports 49222' in value or '--dports 8443' in value or 'allports' in value for value in actions)
    print('Native Fail2ban filter: five positive/negative IPv4/IPv6/injection cases PASS')
    print('Isolated config -t / -d: only one jail, TCP 8088 INPUT action; no daemon or ban executed: PASS')


if __name__ == '__main__': main()

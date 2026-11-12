"""Native UFW argv parsing with --dry-run only; never enable/default/reset."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys


def main():
    if sys.argv[1:] != ['--read-only-native-ufw']:
        raise SystemExit('Explicit --read-only-native-ufw required')
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('candidate', root/'trusttunnel-panel.py')
    p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
    assert p.domain()=='mysdfd.duckdns.org' and p.endpoint_port()=='8443'
    def state():
        return {str(path):hashlib.sha256(path.read_bytes()).hexdigest()
                for path in p.firewall_files().values() if path.is_file()}
    before = state()
    cases = [['--force','delete','allow','8443/tcp','comment','TrustTunnel TCP'],
             ['--force','delete','allow','from','192.0.2.0/24','to','any','port','9000','proto','tcp','comment','QA'],
             ['allow','8088/tcp','comment','TrustTunnel reviewed access']]
    for args in cases:
        result = subprocess.run(['ufw','--dry-run',*args],capture_output=True,text=True,timeout=15)
        assert result.returncode == 0, 'UFW native dry-run syntax rejected'
    assert state()==before,'UFW files changed during dry-run'
    print('Native UFW --dry-run: exact deletion/comment, CIDR-scoped deletion, protected allowance PASS')
    print('UFW files unchanged; no enable/default/reset operation executed: PASS')


if __name__=='__main__':main()

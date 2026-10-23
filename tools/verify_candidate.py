"""Run candidate HTTPS read/security tests on loopback without replacing the live panel."""
import os
from pathlib import Path
import ssl
import subprocess
import time
import urllib.request


def main():
    root=Path('/root/trusttunnel-staging-20261023')
    settings=dict(line.split('=',1) for line in Path('/etc/trusttunnel-panel.env').read_text().splitlines() if line.startswith('PANEL_') and '=' in line)
    env=dict(os.environ,**settings)
    env.update(PANEL_BIND='127.0.0.1',PANEL_PORT='18090',TT_PANEL_TEST_PORT='18090',TT_PANEL_SOURCE=str(root/'trusttunnel-panel.py'))
    env['TT_INTERFACE_SOURCE']=str(root/'trusttunnel-warp-interface.py')
    log=(root/'private-candidate-http.log').open('wb'); process=None
    try:
        process=subprocess.Popen(['python3',str(root/'trusttunnel-panel.py')],env=env,stdout=log,stderr=subprocess.STDOUT)
        for attempt in range(40):
            try:
                with urllib.request.urlopen('https://127.0.0.1:18090/health',context=ssl._create_unverified_context(),timeout=2) as response: assert response.read().strip()==b'ok'
                break
            except (OSError,AssertionError):
                if process.poll() is not None or attempt==39: raise RuntimeError('Candidate HTTPS did not become ready')
                time.sleep(.2)
        for test in ('test_admin.py','test_client_protection.py','test_activation_http.py','test_panel_http.py','test_panel_login.py'):
            result=subprocess.run(['python3',str(root/test)],env=env,capture_output=True,text=True,timeout=90)
            if result.returncode:
                (root/('private-'+test+'.log')).write_text(result.stdout+result.stderr)
                raise RuntimeError('Candidate test failed: '+test+'; diagnostics stay in private staging')
            print(test+': PASS')
    finally:
        if process:
            process.terminate()
            try: process.wait(8)
            except subprocess.TimeoutExpired: process.kill(); process.wait(3)
        log.close()


if __name__=='__main__': main()

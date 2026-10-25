"""Candidate HTTPS smoke tests on loopback, without maintenance or policy workers."""
import importlib.util
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading


def main():
    if sys.argv[1:] != ['--read-only-test-vps']: raise SystemExit('Explicit --read-only-test-vps required')
    root=Path(__file__).resolve().parents[1]
    settings=dict(line.split('=',1) for line in Path('/etc/trusttunnel-panel.env').read_text().splitlines() if line.startswith('PANEL_') and '=' in line)
    os.environ.update(settings)
    os.environ.update(PANEL_BIND='127.0.0.1',PANEL_PORT='18094',TT_PANEL_TEST_PORT='18094')
    spec=importlib.util.spec_from_file_location('https_candidate',root/'trusttunnel-panel.py')
    p=importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
    assert p.domain()=='mysdfd.duckdns.org' and p.endpoint_port()=='8443','Unexpected target'
    p.USAGE_DB=root/'https-synthetic-usage.sqlite3'
    operation=p.admin_operation
    def readonly(action,values):
        if action not in ('monitor','security-audit'): raise ValueError('Candidate HTTPS harness is read-only')
        return operation(action,values)
    p.admin_operation=readonly
    class ReadOnlyHandler(p.Handler):
        def do_POST(self):
            if self.path not in ('/manage','/login','/logout'): self.send_error(405); return
            super().do_POST()
        def log_message(self,*args): pass
    server=p.PanelServer(('127.0.0.1',18094),ReadOnlyHandler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(p.PANEL_CERT,p.PANEL_KEY)
    server.socket=context.wrap_socket(server.socket,server_side=True,do_handshake_on_connect=False)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        for test in ('test_panel_http.py','test_panel_login.py'):
            result=subprocess.run([sys.executable,str(root/'tools'/test)],env=os.environ,capture_output=True,text=True,timeout=120)
            if result.returncode:
                (root/('private-'+test+'.log')).write_text(result.stdout+result.stderr)
                raise RuntimeError(test+' failed; diagnostics retained in private staging')
            print(test+': PASS (loopback HTTPS, read-only candidate)')
    finally:
        server.shutdown(); server.server_close(); thread.join(5)


if __name__=='__main__': main()

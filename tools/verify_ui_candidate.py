"""Explicit, read-only candidate qualification on the designated test VPS."""
import base64
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import threading
import urllib.parse


def main():
    if sys.argv[1:] != ['--read-only-test-vps']:
        raise SystemExit('Explicit --read-only-test-vps required')
    root=Path(__file__).resolve().parents[1]
    settings=dict(line.split('=',1) for line in Path('/etc/trusttunnel-panel.env').read_text().splitlines()
                  if line.startswith('PANEL_') and '=' in line)
    os.environ.update(settings)
    spec=importlib.util.spec_from_file_location('candidate',root/'trusttunnel-panel.py')
    p=importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
    assert p.domain()=='mysdfd.duckdns.org' and p.endpoint_port()=='8443','Unexpected test VPS'
    protected=[p.TT_DIR/name for name in ('credentials.toml','hosts.toml','vpn.toml','rules.toml','clients-state.json',
                                         'client-guard.json','panel-protection.json','certs/cert.pem','certs/key.pem')]
    protected+=list(p.CLIENT_DIR.glob('*'))+list(p.firewall_files().values())
    protected+=list((p.FAIL2BAN_DIR/'jail.d').glob('*'))+[Path('/etc/trusttunnel-panel.env'),p.INTERFACE_DROPIN]
    def hashes(): return {str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in protected if path.is_file()}
    def epochs(): return {unit:p.checked_run(['systemctl','show',unit,'--property=InvocationID','--value'])
                         for unit in ('trusttunnel','ssh','warp-interface','fail2ban')}
    before=hashes(); invocations=epochs()
    tests=['test_admin','test_client_protection','test_sharing_controls','test_firewall_fail2ban',
           'test_torrent_filter','test_panel_security_http','test_activation_http','test_health_metrics','test_network_compatibility',
           'test_firewall_hardening','test_panel_login_protection','test_panel_login_integration']
    env=dict(os.environ,TT_PANEL_SOURCE=str(root/'trusttunnel-panel.py'),TT_INSTALLER_SOURCE=str(root/'install-trusttunnel-warp.sh'))
    subprocess.run([sys.executable,'-m','unittest',*tests],cwd=root/'tools',env=env,check=True,timeout=180)
    subprocess.run([sys.executable,str(root/'tools/test_security_review_20261112.py')],env=env,check=True,timeout=30)
    subprocess.run([sys.executable,str(root/'tools/test_installer_sandbox.py')],env=env,check=True,timeout=120)
    subprocess.run(['bash','-n',str(root/'install-trusttunnel-warp.sh')],check=True)
    p.USAGE_DB=root/'candidate-synthetic-usage.sqlite3'
    operation=p.admin_operation
    def readonly(action,values):
        if action not in ('monitor','security-audit','health-status','health-check','scanner-status','login-protection-status'):
            raise ValueError('Read-only candidate: mutation refused')
        return operation(action,values)
    p.admin_operation=readonly
    class Quiet(p.Handler):
        def log_message(self,*args): pass
    server=p.PanelServer(('127.0.0.1',18094),Quiet)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(p.PANEL_CERT,p.PANEL_KEY)
    server.socket=context.wrap_socket(server.socket,server_side=True,do_handshake_on_connect=False)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    class LocalTLS(http.client.HTTPSConnection):
        def connect(self):
            sock=socket.create_connection(('127.0.0.1',18094),timeout=25)
            self.sock=self._context.wrap_socket(sock,server_hostname=self.host)
    auth='Basic '+base64.b64encode((p.PANEL_USER+':'+p.PANEL_PASSWORD).encode()).decode()
    def request(path,values=None,authenticated=True,extra=None):
        connection=LocalTLS(p.domain(),18094,timeout=25,context=ssl.create_default_context())
        headers={'Accept':'application/json'}
        if authenticated: headers['Authorization']=auth
        headers.update(extra or {})
        body=urllib.parse.urlencode(values) if values is not None else None
        if body is not None:headers['Content-Type']='application/x-www-form-urlencoded'
        try:
            connection.request('POST' if body is not None else 'GET',path,body=body,headers=headers)
            response=connection.getresponse()
            return response.status,dict(response.getheaders()),response.read().decode()
        finally:connection.close()
    try:
        for view in ('dashboard','clients','endpoint','warp','routing','dns','security','system','certificates','panel','logs'):
            status,headers,page=request('/?view='+view)
            assert status==200 and '<script nonce=' in page,view
            assert "'unsafe-inline'" not in headers['Content-Security-Policy']
            if view=='clients':assert 'name="vpn_client_name"' in page
        p.health_tick()
        for path in ('/api/clients-metrics','/api/server-health','/api/panel-protection','/api/firewall-plan'):
            assert request(path,authenticated=False)[0]==401
            status,_,body=request(path);assert status==200 and isinstance(json.loads(body),dict)
        status,_,body=request('/api/clients-metrics')
        metrics=json.loads(body)
        assert all(item['total_bytes']==item['upload']+item['download'] for item in metrics['clients'])
        assert all(item['active_ip_count'] is None or item['active_ip_count']==0 for item in metrics['clients'])
        status,headers,page=request('/login',authenticated=False)
        assert status==200 and 'name="panel_login"' in page and 'name="panel_password"' in page
        assert request('/login',authenticated=False,extra={'Host':'attacker.invalid:18094'})[0]==400
        assert request('/manage',{'action':'health-status'})[0]==403
        assert request('/manage',{'action':'ufw-disable','_csrf':p.CSRF_TOKEN})[0]==400
        assert before==hashes(),'Protected configuration changed'
        assert invocations==epochs(),'VPN/SSH/WARP/fail2ban restarted'
        print('Trusted loopback HTTPS: eleven views, namespaced login, private metrics/health, CSRF and Host checks: PASS')
        print('Candidate health storage isolated; VPN identities, firewall and protected service invocations unchanged: PASS')
    finally:
        server.shutdown();server.server_close();thread.join(5)


if __name__=='__main__': main()

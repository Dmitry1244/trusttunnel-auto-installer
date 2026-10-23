"""Opt-in native TLS-auth qualification, isolated from the installed VPN.

Run only on the authorized Linux test VPS with TT_NATIVE_AUTH_TEST=1.
Official pinned release binaries; synthetic credentials and certificate;
loopback-only listeners. No firewall, route or system-service changes.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time


def main():
    if os.environ.get('TT_NATIVE_AUTH_TEST') != '1' or platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise SystemExit('Explicit authorized Linux x86_64 test required.')
    os.umask(0o077)
    root=Path('/root/trusttunnel-native-tls-20261023'); root.mkdir(mode=0o700,exist_ok=True)
    sources=[('TrustTunnel','v1.3.0-beta.2','trusttunnel','trusttunnel_endpoint','496a27ff72014b883438efab55ffd237183b5ff95d9c341cc0de9d18342a9b11'),
             ('TrustTunnelClient','v1.3.0-rc.2','trusttunnel_client','trusttunnel_client','2f4e57b866588ff48cae70ee217b0a420222b265986b1c999543332dac38c08d')]
    for repo,version,prefix,binary,digest in sources:
        archive=root/(prefix+'.tar.gz')
        if not archive.exists():
            subprocess.run(['curl','--fail','--silent','--show-error','--location','--max-time','90','--output',str(archive),f'https://github.com/TrustTunnel/{repo}/releases/download/{version}/{prefix}-{version}-linux-x86_64.tar.gz'],check=True,capture_output=True,timeout=100)
        assert hashlib.sha256(archive.read_bytes()).hexdigest()==digest, 'Official archive digest mismatch'
        with tarfile.open(archive) as bundle:
            member=next(m for m in bundle.getmembers() if Path(m.name).name==binary and m.isfile())
            with bundle.extractfile(member) as source,(root/binary).open('wb') as target: shutil.copyfileobj(source,target)
        (root/binary).chmod(0o700)
    source=Path(os.environ.get('TT_PANEL_SOURCE','/usr/local/sbin/trusttunnel-panel.py'))
    spec=importlib.util.spec_from_file_location('native_panel',source); panel=importlib.util.module_from_spec(spec); spec.loader.exec_module(panel)
    files=[panel.TT_DIR/n for n in ('vpn.toml','hosts.toml','credentials.toml','rules.toml','certs/cert.pem','certs/key.pem')]+list(panel.CLIENT_DIR.glob('*.toml'))
    def identity(): return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files if p.is_file()}
    before=identity()
    for port in (18447,18891):
        for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET,kind) as sock: sock.bind(('127.0.0.1',port))
    endpoint=None
    try:
        with tempfile.TemporaryDirectory(prefix='case-',dir=root) as tmp:
            work=Path(tmp); key=secrets.token_hex(32)
            subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-days','2','-subj','/CN=auth.example.test','-addext','subjectAltName=DNS:auth.example.test','-keyout',str(work/'key.pem'),'-out',str(work/'cert.pem')],check=True,capture_output=True)
            (work/'hosts.toml').write_text('[[main_hosts]]\nhostname="auth.example.test"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
            (work/'credentials.toml').write_text('[[client]]\nusername="synthetic"\npassword="synthetic-native-password"\n')
            base='listen_address="127.0.0.1:18447"\ncredentials_file="credentials.toml"\nrules_file="rules.toml"\nallow_private_network_connections=true\nipv6_available=false\n[listen_protocols.http2]\n[listen_protocols.quic]\n[forward_protocol]\ndirect={}\n'
            (work/'vpn.toml').write_text(base)
            (work/'rules.toml').write_text('[[rule]]\nclient_random_auth_key='+json.dumps(key)+'\naction="allow"\n[[rule]]\naction="deny"\n')
            log=(root/'private-native.log').open('wb')
            endpoint=subprocess.Popen([str(root/'trusttunnel_endpoint'),'vpn.toml','hosts.toml'],cwd=work,stdout=log,stderr=subprocess.STDOUT)
            time.sleep(.6); assert endpoint.poll() is None, 'Native endpoint startup failed'
            results=[]
            for protocol in ('http2','http3'):
                for antidpi in (False,True):
                    for choice,expected in (('correct',True),('wrong',False),('missing',False)):
                        settings={'hostname':'auth.example.test','addresses':['127.0.0.1:18447'],'has_ipv6':False,'username':'synthetic','password':'synthetic-native-password','upstream_protocol':protocol,'skip_verification':False,'certificate':(work/'cert.pem').read_text(),'anti_dpi':antidpi}
                        if choice!='missing': settings['client_random_auth_key']=key if choice=='correct' else '55'*32
                        body='loglevel="error"\nvpn_mode="general"\n[endpoint]\n'+''.join(k+'='+json.dumps(v)+'\n' for k,v in settings.items())+'\n[listener.socks]\naddress="127.0.0.1:18891"\n'
                        path=work/'client.toml'; path.write_text(body)
                        client=subprocess.Popen([str(root/'trusttunnel_client'),'--config',str(path)],cwd=work,stdout=log,stderr=subprocess.STDOUT)
                        try:
                            time.sleep(.4)
                            probe=subprocess.run(['curl','--silent','--show-error','--fail','--noproxy','','--max-time','4','--proxy','socks5h://127.0.0.1:18891','https://www.cloudflare.com/cdn-cgi/trace'],capture_output=True,timeout=6)
                            ok=probe.returncode==0 and b'warp=' in probe.stdout
                            results.append(dict(protocol=protocol,anti_dpi=antidpi,key=choice,accepted=ok,expected=expected,pass_test=ok==expected))
                        finally:
                            client.terminate()
                            try: client.wait(5)
                            except subprocess.TimeoutExpired: client.kill(); client.wait(3)
            endpoint.terminate(); endpoint.wait(5); endpoint=None; log.close()
            assert before==identity(), 'Installed identity/config changed'
            report=dict(endpoint='1.3.0-beta.2',client='1.3.0-rc.2',results=results,identity_unchanged=True)
            (root/'qualification.json').write_text(json.dumps(report,indent=2))
            print(json.dumps(report,indent=2))
            assert all(r['pass_test'] for r in results), 'Native auth behavior did not match the expected matrix'
    finally:
        if endpoint:
            endpoint.terminate()
            try: endpoint.wait(5)
            except subprocess.TimeoutExpired: endpoint.kill(); endpoint.wait(3)
        assert before==identity(), 'Installed identity/config changed'


if __name__ == '__main__': main()

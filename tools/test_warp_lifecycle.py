"""Authorized test-VPS only: real shared WARP controls with identity preservation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import subprocess
import time

root = Path('/root/trusttunnel-staging-20261022')
spec = importlib.util.spec_from_file_location('lifecycle',root/'trusttunnel-panel.py')
panel = importlib.util.module_from_spec(spec);spec.loader.exec_module(panel)
config = panel.TT_DIR/'vpn.toml'
original = config.read_bytes()
assert not panel.interface_enabled(), 'Do not overwrite an existing interface deployment'
identity_paths = [panel.TT_DIR/name for name in ('hosts.toml','credentials.toml','rules.toml','certs/cert.pem','certs/key.pem')]
identity_paths += list(panel.CLIENT_DIR.glob('*'))
def identity(): return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in identity_paths if p.is_file()}
before = identity()
routes = {family:subprocess.run(['ip',family,'route','show','default','table','main'],capture_output=True).stdout for family in ('-4','-6')}
for src,dst in [(root/'interface-wgcf',Path('/opt/warp-interface/wgcf')),(root/'masque-tun',Path('/opt/warp-masque-tun'))]:
    if not dst.exists():
        dst.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        shutil.copytree(src,dst)
        dst.chmod(0o700)
        for path in dst.iterdir():
            if path.is_file():path.chmod(0o600)
client = panel.load_clients()[0]
stun_ip = socket.gethostbyname('stun.l.google.com')
def probe(backend, protocol):
    profile = {'hostname':panel.domain(),'addresses':['127.0.0.1:'+panel.endpoint_port()],'username':client['username'],'password':client['password'],'has_ipv6':False,'skip_verification':False,'upstream_protocol':protocol}
    body = 'loglevel="error"\nvpn_mode="general"\n[endpoint]\n'+''.join(k+'='+json.dumps(v)+'\n' for k,v in profile.items())+'\n[listener.socks]\naddress="127.0.0.1:18885"\n'
    path=root/'lifecycle-client.toml';path.write_text(body);path.chmod(0o600)
    with (root/'lifecycle-private.log').open('ab') as log:
        process=subprocess.Popen([str(root/'trusttunnel_client'),'--config',str(path)],stdout=log,stderr=subprocess.STDOUT)
        try:
            ok=False
            for _ in range(6):
                result=subprocess.run(['curl','-4','-fsS','--max-time','5','--proxy','socks5://127.0.0.1:18885','https://www.cloudflare.com/cdn-cgi/trace'],capture_output=True,text=True)
                if result.returncode==0 and ('warp=on' in result.stdout or 'warp=plus' in result.stdout):ok=True;break
                time.sleep(.2)
            assert ok,'Main endpoint TCP failed: '+backend+'/'+protocol
            delays=[]
            for _ in range(20):
                delay,ip=panel.socks_udp_stun('127.0.0.1:18885',stun_ip)
                assert ip != '195.206.234.157','WARP bypass'
                delays.append(delay)
                time.sleep(.1)
            print(json.dumps({'backend':backend,'protocol':protocol,'tcp':'PASS','udp_new_flows':'20/20','median_ms':sorted(delays)[10],'max_ms':max(delays)}),flush=True)
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
try:
    for backend in ('wg-interface','masque-interface'):
        panel.warp_operation({'backend':backend,'operation':'install','accept_tos':'1','confirm':'CONFIRMED'})
        panel.warp_operation({'backend':backend,'operation':'enable','confirm':'CONFIRMED'})
        assert panel.current_warp_backend()==backend
        assert panel.service_status('trusttunnel')=='active'
        for protocol in ('http2','http3'):probe(backend,protocol)
        panel.warp_operation({'backend':backend,'operation':'restart','confirm':'CONFIRMED'})
        assert 'WARP:' in panel.warp_operation({'backend':backend,'operation':'check'})
        assert before==identity()
        for family,route in routes.items():assert subprocess.run(['ip',family,'route','show','default','table','main'],capture_output=True).stdout==route,'Host default route changed'
        panel.warp_operation({'backend':backend,'operation':'disable','confirm':'CONFIRMED'})
        assert not panel.interface_enabled()
        assert panel.tomllib.loads(config.read_text())==panel.tomllib.loads(original.decode()),'Original forwarder/IPv6 not restored'
        print(backend+': install/enable/check/restart/disable and main routing unchanged: PASS',flush=True)
finally:
    if panel.interface_enabled():
        try:panel.interface_operation('disable',{})
        except Exception:pass
    config.write_bytes(original)
    panel.INTERFACE_DROPIN.unlink(missing_ok=True)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','restart','trusttunnel'],check=True)
    subprocess.run(['systemctl','disable','--now','warp-interface-watchdog.timer','warp-interface','warp-masque-tun'],capture_output=True)
    assert before==identity(),'Original clients/certificate/exports changed'
    print('Original identity and selected outbound restored: PASS',flush=True)

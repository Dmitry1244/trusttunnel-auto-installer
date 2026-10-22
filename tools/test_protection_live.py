"""Exercise native ClientHello filtering only on private loopback test listeners."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

root = Path('/root/trusttunnel-staging-20261022')
spec = importlib.util.spec_from_file_location('protection_test', root / 'trusttunnel-panel.py')
panel = importlib.util.module_from_spec(spec); spec.loader.exec_module(panel)
original_dir = panel.TT_DIR
identity_paths = [original_dir / name for name in ('vpn.toml','hosts.toml','credentials.toml','rules.toml','certs/cert.pem','certs/key.pem')]
identity_paths += list(Path('/root/trusttunnel-clients').glob('*'))
def identity(): return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in identity_paths if p.is_file()}
before = identity()
work = root / 'protection-test'; work.mkdir(mode=0o700,exist_ok=True)
(work / 'panel-protection.json').unlink(missing_ok=True)
panel.TT_DIR = work; panel.CLIENT_DIR = work / 'profiles'; panel.CLIENT_DIR.mkdir(mode=0o700,exist_ok=True)
panel.audit_log = lambda *args:None
for name in ('trusttunnel_endpoint','certs'):
    target = work / name
    if not target.exists(): target.symlink_to(original_dir / name, target_is_directory=name=='certs')
for name in ('credentials.toml','hosts.toml'): shutil.copy2(original_dir / name,work / name)
config = (original_dir / 'vpn.toml').read_text()
config = re.sub(r'(?m)^listen_address\s*=.*$', 'listen_address = "127.0.0.1:18444"',config)
config = re.sub(r'(?m)^credentials_file\s*=.*$', 'credentials_file = "credentials.toml"',config)
config = re.sub(r'(?m)^rules_file\s*=.*$', 'rules_file = "rules.toml"',config)
config = panel.replace_config_section(config,'metrics',{})
config = panel.replace_config_section(config,'subscription',{})
config = re.sub(r'(?ms)^\[forward_protocol(?:\.[^\]]+)?\][ \t]*\n.*?(?=^\[|\Z)','',config)
(work / 'vpn.toml').write_text(config+'\n[forward_protocol]\ndirect={}\n')
(work / 'rules.toml').write_text('# Isolated rules\n')
client = panel.load_clients()[0]
endpoint = None
private_log = (work / 'private.log').open('wb')
original_run = panel.run
def restart():
    global endpoint
    if endpoint:
        endpoint.terminate(); endpoint.wait(timeout=5)
    endpoint = subprocess.Popen([str(work / 'trusttunnel_endpoint'),'vpn.toml','hosts.toml'],cwd=work,stdout=private_log,stderr=subprocess.STDOUT)
    time.sleep(.3)
    return 0 if endpoint.poll() is None else 1
def isolated_run(args,**kwargs):
    if args[:2] == ['systemctl','restart']: return restart(), 'isolated restart'
    return original_run(args,**kwargs)
panel.run = isolated_run
panel.service_status = lambda unit:'active' if endpoint and endpoint.poll() is None else 'failed'
def probe(protocol,prefix='',expected=True):
    profile = {'hostname':panel.domain(),'addresses':['127.0.0.1:18444'],'has_ipv6':True,'username':client['username'],'password':client['password'],'upstream_protocol':protocol,'skip_verification':False}
    if prefix: profile['client_random'] = prefix
    body = 'loglevel="error"\nvpn_mode="general"\n[endpoint]\n'+''.join(k+'='+json.dumps(v)+'\n' for k,v in profile.items())+'\n[listener.socks]\naddress="127.0.0.1:18887"\n'
    settings = work / 'client.toml'; settings.write_text(body); settings.chmod(0o600)
    process = subprocess.Popen([str(root / 'trusttunnel_client'),'--config',str(settings)],stdout=private_log,stderr=subprocess.STDOUT)
    try:
        time.sleep(.25)
        result = subprocess.run(['curl','-fsS','--max-time','5','--proxy','socks5://127.0.0.1:18887','https://www.cloudflare.com/cdn-cgi/trace'],capture_output=True,text=True)
        ok = result.returncode == 0 and 'warp=off' in result.stdout
        assert ok == expected, 'Unexpected native filter result: '+protocol+' '+str(expected)
    finally:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill(); process.wait()

try:
    assert restart() == 0
    panel.protection_operation('prepare',{'confirm':'CONFIRMED'})
    prefix = panel.protection_state()['prefix']
    for protocol in ('http2','http3'):
        link = panel.deeplink(client['username'],protocol,'protected')
        assert dict(panel.link_fields(link))[11].decode() == prefix
        probe(protocol,prefix)
    panel.protection_operation('camouflage',{'confirm':'CONFIRMED'})
    result = subprocess.run(['curl','-ksS','--max-time','5','--resolve',panel.domain()+':18444:127.0.0.1','-o','/dev/null','-w','%{http_code}','https://'+panel.domain()+':18444/'],capture_output=True,text=True)
    assert result.stdout == '404', 'Non-CONNECT response is not 404'
    try: panel.protection_operation('enforce',{'confirm':'CONFIRMED','clients_ready':'1'})
    except ValueError: pass
    else: raise AssertionError('QUIC compatibility guard missing')
    path = work / 'vpn.toml'
    original_quic = path.read_text()
    path.write_text(panel.replace_config_section(original_quic,'listen_protocols.quic',{}))
    assert restart() == 0
    panel.protection_operation('enforce',{'confirm':'CONFIRMED','clients_ready':'1'})
    probe('http2',prefix)
    probe('http2',expected=False)
    print('Native HTTP/2 filter: protected profile accepted; original profile rejected; QUIC guard enforced')
    panel.protection_operation('disable',{'confirm':'CONFIRMED'})
    panel.protection_operation('camouflage-restore',{'confirm':'CONFIRMED'})
    path.write_text(config+'\n[forward_protocol]\ndirect={}\n'); assert restart() == 0
    for protocol in ('http2','http3'): probe(protocol)
    print('Native HTTP camouflage, clean protected links, strict guard and rollback: PASS')
finally:
    if endpoint:
        endpoint.terminate(); endpoint.wait(timeout=5)
    private_log.close()
    assert before == identity(), 'Live identity/config changed'
    print('Original VPN users, certificate and profiles unchanged: PASS')

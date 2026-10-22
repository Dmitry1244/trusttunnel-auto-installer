"""Isolated real HTTP/2 and QUIC checks on the authorized test VPS.

Creates only loopback listeners and private staging files. Does not create a TUN
device or modify VPN users, certificates, firewall rules or system routes.
"""
import hashlib
import importlib.util
import json
import os
import re
import shutil
import socket
import struct
import secrets
import statistics
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

ROOT = Path('/root/trusttunnel-staging-20261022')
SOURCE = Path(os.environ.get('TT_PANEL_SOURCE', ROOT / 'trusttunnel-panel.py'))
spec = importlib.util.spec_from_file_location('panel_tunnel_test', SOURCE)
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)
CLIENT_DIGEST = '00e0546a6b35840dbb92b741dff3da6732a74bf2d6c581e044bb4567c0d96825'
CLIENT_URL = 'https://github.com/TrustTunnel/TrustTunnelClient/releases/download/v1.1.11/trusttunnel_client-v1.1.11-linux-x86_64.tar.gz'
CLIENT = ROOT / 'trusttunnel_client'
if not CLIENT.exists():
    archive = ROOT / 'client.tar.gz'
    subprocess.run(['curl', '-fL', '--max-time', '90', '-o', str(archive), CLIENT_URL], check=True, capture_output=True)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == CLIENT_DIGEST
    with tarfile.open(archive) as tar:
        member = next(m for m in tar.getmembers() if Path(m.name).name == 'trusttunnel_client' and m.isfile())
        with tar.extractfile(member) as src, CLIENT.open('wb') as dst:
            shutil.copyfileobj(src, dst)
    CLIENT.chmod(0o700)

for port in (18443, 18884):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.bind(('127.0.0.1', port))

paths = list(Path('/root/trusttunnel-clients').glob('*'))
paths += [panel.TT_DIR / n for n in ('vpn.toml', 'hosts.toml', 'credentials.toml', 'rules.toml', 'certs/cert.pem', 'certs/key.pem')]
def identity():
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
before = identity()
client = panel.load_clients()[0]
vpn = panel.read_text(panel.TT_DIR / 'vpn.toml')
vpn = panel.replace_config_section(vpn, 'metrics', {})
vpn = panel.replace_config_section(vpn, 'subscription', {})
vpn = re.sub(r'(?m)^listen_address\s*=.*$', 'listen_address = "127.0.0.1:18443"', vpn)
vpn = re.sub(r'(?m)^credentials_file\s*=.*$', 'credentials_file = "/opt/trusttunnel/credentials.toml"', vpn)
vpn = re.sub(r'(?m)^rules_file\s*=.*$', 'rules_file = ' + json.dumps(str(ROOT / 'test-rules.toml')), vpn)
vpn = re.sub(r'(?ms)^\[forward_protocol(?:\.[^\]]+)?\][ \t]*\n.*?(?=^\[|\Z)', '', vpn)
(ROOT / 'test-rules.toml').write_text('# Isolated loopback test rules.\n')
results = []
stun_ip = socket.gethostbyname('stun.l.google.com')

def persistent_stun(address, target, count=30):
    """One persistent game-like UDP flow, without intercepted DNS traffic."""
    def exact(sock, length):
        data = b''
        while len(data) < length:
            part = sock.recv(length - len(data))
            if not part: raise OSError('SOCKS control closed')
            data += part
        return data
    timings, lost = [], 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.create_connection(('127.0.0.1', address), timeout=5) as control:
        udp.bind(('0.0.0.0', 0)); udp.settimeout(1)
        control.sendall(b'\x05\x01\x00'); assert exact(control, 2) == b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00' + struct.pack('!H', udp.getsockname()[1]))
        response = exact(control, 4); assert response == b'\x05\x00\x00\x01'
        relay = socket.inet_ntoa(exact(control, 4)); relay_port = struct.unpack('!H', exact(control, 2))[0]
        relay = '127.0.0.1' if relay == '0.0.0.0' else relay
        header = b'\x00\x00\x00\x01' + socket.inet_aton(target) + struct.pack('!H', 19302)
        for _ in range(count):
            token = secrets.token_bytes(12); start = time.monotonic()
            udp.sendto(header + struct.pack('!HHI', 1, 0, 0x2112a442) + token, (relay, relay_port))
            try:
                while True:
                    packet = udp.recv(8192)
                    offset = 10 if packet[3] == 1 else 22
                    if packet[offset + 8:offset + 20] == token:
                        timings.append(round((time.monotonic() - start) * 1000, 1)); break
            except TimeoutError: lost += 1
            time.sleep(.1)
    return dict(received=len(timings), lost=lost, median_ms=statistics.median(timings) if timings else None, max_ms=max(timings) if timings else None)

for mode, address in (('direct', ''), ('wireguard', panel.SOCKS_ADDR), ('masque', panel.MASQUE_ADDR), ('interface', ''), ('interface-masque', '')):
    if os.environ.get('TT_TEST_MODES') and mode not in os.environ['TT_TEST_MODES'].split(','):
        continue
    forwarder = '\n[forward_protocol]\ndirect = {}\n' if not address else '\n[forward_protocol.socks5]\naddress = ' + json.dumps(address) + '\nextended_auth = false\n'
    config = vpn + forwarder
    if mode.startswith('interface'):
        config = re.sub(r'(?m)^ipv6_available\s*=.*$', 'ipv6_available = false', config)
    panel.tomllib.loads(config)
    endpoint_config = ROOT / 'test-vpn.toml'
    endpoint_config.write_text(config); endpoint_config.chmod(0o600)
    endpoint_log = (ROOT / ('tunnel-' + mode + '.log')).open('wb')
    command = [str(panel.TT_DIR / 'trusttunnel_endpoint'), str(endpoint_config), str(panel.TT_DIR / 'hosts.toml')]
    policy = None
    tun_process = None
    if mode.startswith('interface'):
        command += ['-l', 'trace']
        module = importlib.util.spec_from_file_location('interface_policy', ROOT / 'trusttunnel-warp-interface.py')
        interface = importlib.util.module_from_spec(module); module.loader.exec_module(interface)
        policy = interface.Policy(test=True, transport='masque' if mode == 'interface-masque' else 'wireguard')
        if mode == 'interface-masque':
            tun_log = (ROOT / 'masque-tun-private.log').open('wb')
            tun_process = subprocess.Popen(['/opt/warp-masque/usque', '-c', str(ROOT / 'masque-tun/config.json'), 'nativetun', '-n', policy.nic, '--always-reconnect', '-m', '1280', '--keepalive-period', '25s'], stdout=tun_log, stderr=subprocess.STDOUT)
        command = ['systemd-run', '--scope', '--quiet', '--unit=tt-warp-probe', '--slice=ttwarptest.slice', *command]
    endpoint = subprocess.Popen(command, cwd=panel.TT_DIR, stdout=endpoint_log, stderr=subprocess.STDOUT)
    try:
        time.sleep(.3)
        assert endpoint.poll() is None, 'Isolated endpoint failed; see private staging log'
        if policy:
            policy.start()
            for family in ('-4', '-6'):
                direct_probe = subprocess.run(['systemd-run', '--quiet', '--collect', '--wait', '--pipe', '--unit=tt-warp-curl-probe', '--slice=ttwarptest.slice', 'curl', family, '-fsS', '--max-time', '8', 'https://www.cloudflare.com/cdn-cgi/trace'], capture_output=True, text=True)
                values = dict(line.split('=', 1) for line in direct_probe.stdout.splitlines() if '=' in line)
                print(json.dumps(dict(interface_tcp_family=family, exit_code=direct_probe.returncode, warp=values.get('warp'), ip=values.get('ip'))), flush=True)
        for protocol in ('http2', 'http3'):
            profile = {'hostname':panel.domain(), 'addresses':['127.0.0.1:18443'], 'has_ipv6':not bool(policy),
                       'username':client['username'], 'password':client['password'], 'skip_verification':False,
                       'upstream_protocol':protocol, 'dns_upstreams':['1.1.1.1']}
            body = 'loglevel = "debug"\nvpn_mode = "general"\nkillswitch_enabled = true\n[endpoint]\n'
            body += ''.join(k + ' = ' + json.dumps(v) + '\n' for k,v in profile.items())
            body += '\n[listener.socks]\naddress = "127.0.0.1:18884"\n'
            settings = ROOT / 'test-client.toml'; settings.write_text(body); settings.chmod(0o600)
            client_log = (ROOT / ('client-' + mode + '-' + protocol + '.log')).open('wb')
            process = subprocess.Popen([str(CLIENT), '--config', str(settings)], cwd=ROOT, stdout=client_log, stderr=subprocess.STDOUT)
            try:
                trace = ''
                for _ in range(5 if policy else 15):
                    p = subprocess.run(['curl','-fsS','--max-time','3','--proxy', ('socks5://' if policy else 'socks5h://') + '127.0.0.1:18884','https://www.cloudflare.com/cdn-cgi/trace'], text=True, capture_output=True)
                    if p.returncode == 0:
                        trace = p.stdout; break
                    if process.poll() is not None:
                        raise AssertionError('CLI client failed; see private staging log')
                    time.sleep(.3)
                if not trace and policy and policy.transport == 'wireguard':
                    print(json.dumps(dict(last_curl_exit_code=p.returncode)), flush=True)
                    for field in ('latest-handshakes', 'transfer', 'endpoints'):
                        rows = policy.run('wg', 'show', policy.nic, field).stdout.splitlines()
                        print(json.dumps({'interface_diagnostic':field, 'values':[row.split('\t')[1:] for row in rows]}), flush=True)
                    print(policy.run('ip', '-4', 'route', 'get', '1.1.1.1', 'mark', policy.mark).stdout, flush=True)
                    print(policy.run('iptables', '-t', 'mangle', '-nvL', policy.chain).stdout, flush=True)
                assert 'warp=' + ('off' if mode == 'direct' else 'on') in trace or (mode != 'direct' and 'warp=plus' in trace), 'Incorrect tunnel exit'
                if policy:
                    domain_probe = subprocess.run(['curl', '-4', '-fsS', '--max-time', '15', '--proxy', 'socks5h://127.0.0.1:18884', 'https://www.cloudflare.com/cdn-cgi/trace'], text=True, capture_output=True)
                    domain_ok = domain_probe.returncode == 0 and ('warp=on' in domain_probe.stdout or 'warp=plus' in domain_probe.stdout)
                    print(json.dumps(dict(mode=mode, protocol=protocol, remote_dns_tcp='PASS' if domain_ok else 'FAIL', curl_exit=domain_probe.returncode)), flush=True)
                    if not domain_ok:
                        for filename in (ROOT / ('tunnel-' + mode + '.log'), ROOT / ('client-' + mode + '-' + protocol + '.log')):
                            content=filename.read_text(errors='replace').lower()
                            print(json.dumps({'diagnostic':filename.name,'counts':{phrase:content.count(phrase) for phrase in ('resolving peer','selected address','unreachable','resolve','unsupported','invalid socks','dns','error','connection refused')}}),flush=True)
                    assert domain_ok, 'Native remote DNS/TCP probe failed'
                continuous = persistent_stun(18884, stun_ip)
                print(json.dumps(dict(mode=mode, protocol=protocol, persistent_udp=continuous)), flush=True)
                probes, errors = [], 0
                for number in range(20):
                    try:
                        probes.append(panel.socks_udp_stun('127.0.0.1:18884', stun_ip))
                    except OSError:
                        errors += 1
                        print(json.dumps(dict(mode=mode, protocol=protocol, unanswered_sample=number + 1)), flush=True)
                        if errors >= 3: break
                    time.sleep(.15)
                delays = [item[0] for item in probes]
                ips = sorted({item[1] for item in probes})
                assert all((ip == '195.206.234.157') == (mode == 'direct') for ip in ips), 'UDP bypasses selected outbound'
                row = dict(mode=mode, protocol=protocol, tcp='PASS', persistent_udp=continuous, udp_stun=f'{len(probes)}/{len(probes)+errors}', exit_ips=ips, median_ms=statistics.median(delays) if delays else None, max_ms=max(delays) if delays else None)
                results.append(row)
                print(json.dumps(row), flush=True)
                if errors:
                    print('FAIL: multiple UDP flows have unanswered packets', flush=True)
            finally:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
                client_log.close()
                time.sleep(.15)
    finally:
        if policy:
            subprocess.run(['systemctl', 'stop', 'tt-warp-probe.scope'], capture_output=True)
            policy.stop()
        if tun_process:
            tun_process.terminate()
            try: tun_process.wait(timeout=5)
            except subprocess.TimeoutExpired: tun_process.kill(); tun_process.wait()
            tun_log.close()
        endpoint.terminate()
        try: endpoint.wait(timeout=5)
        except subprocess.TimeoutExpired: endpoint.kill(); endpoint.wait()
        endpoint_log.close()
        assert before == identity(), 'Production identity/config changed'

(ROOT / 'tunnel-results.json').write_text(json.dumps(results, indent=2))
print('Original VPN files unchanged. Individual TCP/UDP results above; any unanswered sample is a failed check.')
if any(row['persistent_udp']['lost'] or row['udp_stun'].split('/')[0] != row['udp_stun'].split('/')[1] for row in results):
    raise SystemExit(1)

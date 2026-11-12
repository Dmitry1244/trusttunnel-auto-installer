"""Opt-in loopback traffic calibration using installed official binaries, never live identities."""
import hashlib
import http.server
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


def main():
    if sys.argv[1:] != ['--isolated-netns-test']: raise SystemExit('Run only under unshare --net with --isolated-netns-test')
    assert os.geteuid()==0 and os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'Refusing the host network namespace'
    assert subprocess.check_output(['hostname'],text=True).strip()=='deluxe-ryzen'
    os.umask(0o077)
    root=Path(__file__).parents[1]
    endpoint=Path('/opt/trusttunnel/trusttunnel_endpoint')
    native=Path('/root/trusttunnel-native-tls-20261023/trusttunnel_client')
    assert native.is_file()
    subprocess.run(['ip','link','set','lo','up'],check=True)
    # This address exists only inside the isolated namespace; no Internet traffic is sent.
    subprocess.run(['ip','address','add','8.8.8.8/32','dev','lo'],check=True)
    files=[Path('/opt/trusttunnel')/p for p in ('credentials.toml','vpn.toml','hosts.toml','rules.toml','certs/cert.pem','certs/key.pem')]
    files+=list(Path('/root/trusttunnel-clients').glob('*'))
    def protected(): return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files if p.is_file()}
    before=protected()
    for port in (18459,18899,18903,19891):
        for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET,kind) as sock:
                if kind==socket.SOCK_STREAM: sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                sock.bind(('8.8.8.8' if port==18903 else '127.0.0.1',port))
    download=b'D'*(4*1024*1024); upload=b'U'*(3*1024*1024)
    class Target(http.server.BaseHTTPRequestHandler):
        def do_GET(self): self.reply(download if self.path=='/download' else b'ready')
        def do_POST(self):
            size=int(self.headers.get('Content-Length','0'))
            assert size==len(upload) and self.rfile.read(size)==upload
            self.reply(b'uploaded')
        def reply(self,body):
            self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self,*args): pass
    origin=http.server.ThreadingHTTPServer(('8.8.8.8',18903),Target)
    thread=threading.Thread(target=origin.serve_forever,daemon=True); thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='traffic-calibration-',dir=root) as folder:
            work=Path(folder)
            subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-days','2',
                            '-subj','/CN=traffic.example.test','-addext','subjectAltName=DNS:traffic.example.test',
                            '-keyout',str(work/'key.pem'),'-out',str(work/'cert.pem')],check=True,capture_output=True)
            (work/'hosts.toml').write_text('[[main_hosts]]\nhostname="traffic.example.test"\ncert_chain_path="cert.pem"\nprivate_key_path="key.pem"\n')
            (work/'credentials.toml').write_text('[[client]]\nusername="calibration"\npassword="synthetic-traffic-password"\n')
            (work/'vpn.toml').write_text('listen_address="127.0.0.1:18459"\ncredentials_file="credentials.toml"\nallow_private_network_connections=true\nipv6_available=false\n[listen_protocols.http1]\n[listen_protocols.http2]\n[listen_protocols.quic]\n[forward_protocol]\ndirect={}\n[metrics]\naddress="127.0.0.1:19891"\nper_client_metrics=true\n')
            def sample():
                connection=http.client.HTTPConnection('127.0.0.1',19891,timeout=3)
                try:
                    connection.request('GET','/clients',headers={'Connection':'keep-alive'})
                    response=connection.getresponse(); assert response.status==200
                    data=json.loads(response.read(1048576))
                finally: connection.close()
                rows=data['clients'] if isinstance(data,dict) else data
                return next(r for r in rows if r['username']=='calibration')
            def curl(path,body=None):
                args=['curl','-fsS','--max-time','10','--noproxy','','--proxy','socks5h://127.0.0.1:18899']
                if body is not None: args+=['--data-binary','@-']
                return subprocess.run(args+['http://8.8.8.8:18903/'+path],input=body,capture_output=True,timeout=12)
            with (work/'private-native.log').open('wb') as log:
                server=subprocess.Popen([str(endpoint),'vpn.toml','hosts.toml'],cwd=work,stdout=log,stderr=subprocess.STDOUT)
                try:
                    time.sleep(.4); assert server.poll() is None
                    for protocol in ('http2','http3'):
                        fields=dict(hostname='traffic.example.test',addresses=['127.0.0.1:18459'],has_ipv6=False,
                                    username='calibration',password='synthetic-traffic-password',certificate=(work/'cert.pem').read_text(),
                                    skip_verification=False,upstream_protocol=protocol,anti_dpi=False)
                        config='loglevel="error"\nvpn_mode="general"\n[endpoint]\n'+''.join(k+'='+json.dumps(v)+'\n' for k,v in fields.items())
                        config+='\n[listener.socks]\naddress="127.0.0.1:18899"\n'; (work/'client.toml').write_text(config)
                        client=subprocess.Popen([str(native),'--config',str(work/'client.toml')],cwd=work,stdout=log,stderr=subprocess.STDOUT)
                        try:
                            for attempt in range(20):
                                if curl('ready').returncode==0: break
                                time.sleep(.1)
                            else: raise AssertionError('Synthetic client not ready')
                            time.sleep(.1)
                            for label,payload_size,path,body in [('download',len(download),'download',None),('upload',len(upload),'upload',upload)]:
                                old=sample(); response=curl(path,body); assert response.returncode==0
                                assert response.stdout==(download if body is None else b'uploaded')
                                for attempt in range(30):
                                    new=sample(); delta={k:new[k]-old[k] for k in ('inbound','outbound')}
                                    if max(delta.values())>=payload_size: break
                                    time.sleep(.05)
                                expected='inbound' if label=='download' else 'outbound'
                                other='outbound' if expected=='inbound' else 'inbound'
                                if not (payload_size<=delta[expected]<=payload_size+16384 and 0<=delta[other]<16384):
                                    print('Synthetic before/after: '+json.dumps(dict(before=old,after=new,delta=delta)),flush=True)
                                    connection=http.client.HTTPConnection('127.0.0.1',19891,timeout=3)
                                    try:
                                        connection.request('GET','/clients'); response=connection.getresponse()
                                        print('Synthetic aggregate: '+response.read(1048576).decode(),flush=True)
                                    finally: connection.close()
                                    raise AssertionError('Per-user calibration did not match transferred payload')
                                print(json.dumps(dict(protocol=protocol,operation=label,application_bytes=payload_size,raw_delta=delta,verified=True)),flush=True)
                            if protocol=='http3':
                                server.terminate(); server.wait(timeout=10)
                                assert curl('ready').returncode!=0,'Negative control failed: traffic bypassed endpoint'
                                print('Negative control: stopping synthetic endpoint prevents application traffic: PASS',flush=True)
                        finally:
                            client.terminate(); client.wait(timeout=10)
                finally:
                    server.terminate(); server.wait(timeout=10)
    finally:
        origin.shutdown(); origin.server_close(); thread.join(5)
        assert before==protected(),'Live identities/configurations changed'
    print('Known-size HTTP/2 + QUIC upload/download calibrated; real VPN identities/configuration unchanged: PASS')


if __name__=='__main__': main()

"""Opt-in synthetic packet tests; refuses the host network namespace."""
import base64
from contextlib import nullcontext
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading


def client():
    group,host,port,kind,payload,source=sys.argv[2:]
    group=Path(group)
    assert group.name=='trusttunnel.service' and group.parent.name.startswith('ttbtqa-') and group.resolve().parent.parent==Path('/sys/fs/cgroup')
    (group/'cgroup.procs').write_text(str(os.getpid()))
    family=socket.AF_INET6 if ':' in host else socket.AF_INET
    sock=socket.socket(family,socket.SOCK_STREAM if kind=='tcp' else socket.SOCK_DGRAM)
    sock.settimeout(.8)
    if source!='0':
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); sock.bind((host,int(source)))
    try:
        data=base64.b64decode(payload)
        try:
            if kind=='tcp': sock.connect((host,int(port))); sock.sendall(data)
            else: sock.sendto(data,(host,int(port)))
            received=sock.recv(4096)==data
        except (socket.timeout,PermissionError): received=False
        print(json.dumps({'received':received}))
    finally: sock.close()


def main():
    assert sys.argv[1:]==['--isolated-netns-test']
    assert os.geteuid()==0 and os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'Refusing host network namespace'
    subprocess.run(['ip','link','set','lo','up'],check=True)
    source=Path(__file__).parents[1]/'trusttunnel-panel.py'
    spec=importlib.util.spec_from_file_location('isolated_panel',source)
    p=importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
    group_root=Path('/sys/fs/cgroup')/('ttbtqa-'+str(os.getpid()))
    group=group_root/'trusttunnel.service'
    group_root.mkdir(); group.mkdir()
    with tempfile.TemporaryDirectory(prefix='ttbt-packet-test-') as directory:
        p.TORRENT_STATE=Path(directory)/'state.json'; p.SCHEDULE_DIR=Path(directory)/'units'
        p.admin_lock=nullcontext; p.torrent_units=lambda:None; p.audit_log=lambda *args:None
        p.protected_ports=lambda:[(8443,'tcp'),(49222,'tcp'),(8088,'tcp')]
        p.endpoint_port=lambda:'8443'
        p.torrent_context=lambda:dict(cgroup=group.relative_to('/sys/fs/cgroup').as_posix(),invocation='1'*32)
        before={tool:p.checked_run([tool,'-t','mangle','-S']) for tool in ('iptables','ip6tables')}
        def packet(host,kind,payload,allowed,port=0,scoped=True,source_port=0):
            family=socket.AF_INET6 if ':' in host else socket.AF_INET
            peer=socket.socket(family,socket.SOCK_STREAM if kind=='tcp' else socket.SOCK_DGRAM)
            peer.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); peer.bind((host,port)); peer.settimeout(1.2)
            if kind=='tcp': peer.listen(1)
            port=peer.getsockname()[1]
            def echo():
                try:
                    if kind=='tcp':
                        connection,_=peer.accept(); connection.settimeout(1.2)
                        with connection:
                            data=connection.recv(4096)
                            if data: connection.sendall(data)
                    else:
                        data,address=peer.recvfrom(4096); peer.sendto(data,address)
                except (TimeoutError,OSError): pass
                finally: peer.close()
            thread=threading.Thread(target=echo); thread.start()
            try:
                if scoped:
                    result=subprocess.run([sys.executable,__file__,'--client',str(group),host,str(port),kind,
                                           base64.b64encode(payload).decode(),str(source_port)],capture_output=True,text=True,timeout=5)
                    if result.returncode: raise RuntimeError('Synthetic client failed: '+result.stderr)
                    received=json.loads(result.stdout)['received']
                else:
                    sock=socket.socket(family,socket.SOCK_STREAM if kind=='tcp' else socket.SOCK_DGRAM); sock.settimeout(1)
                    with sock:
                        if kind=='tcp': sock.connect((host,port)); sock.sendall(payload)
                        else: sock.sendto(payload,(host,port))
                        received=sock.recv(4096)==payload
                assert received==allowed,f'{host} {kind}: expected allowed={allowed}, got {received}'
            finally: thread.join(2)
        values={'confirm':'CONFIRMED','limits_ack':'1'}
        try:
            p.torrent_operation('save',values)
            for host in ('127.0.0.1','::1'):
                for proto,hex_payload in p.TORRENT_SIGNATURES:
                    packet(host,proto,bytes.fromhex(hex_payload)+b'synthetic-only',False)
                packet(host,'tcp',b'GET /ordinary HTTP/1.0\r\n\r\n',True)
                packet(host,'tcp',b'\x16\x03\x03\x00\x10synthetic-tls-record',True)
                packet(host,'udp',b'\x00\x01\x00\x00\x21\x12\xa4\x42'+b'0'*12,True)
                packet(host,'udp',b'game-voice-video-udp',True)
                # Honest limitation: encrypted/non-matching P2P is not identified.
                packet(host,'tcp',b'encrypted-or-unrecognized-stream',True,port=6881)
                packet(host,'tcp',bytes.fromhex(p.TORRENT_SIGNATURES[0][1]),True,scoped=False)
            print('IPv4/IPv6: open BitTorrent TCP/uTP, DHT and UDP tracker blocked; HTTP/TLS/STUN/game UDP and other cgroups pass: PASS')
            assert p.torrent_snapshot()['active'] and p.torrent_snapshot()['dropped']>=8
            p.torrent_operation('save',dict(values,mode='ports',ports='6881:6889,6969,51413'))
            for host in ('127.0.0.1','::1'):
                packet(host,'tcp',b'non-matching-payload',False,port=6881)
                packet(host,'udp',b'non-matching-payload',False,port=6969)
            print('Optional port mode blocks both TCP and UDP; counter and mode change: PASS')
            p.torrent_operation('disable',values)
            for host in ('127.0.0.1','::1'):
                packet(host,'tcp',bytes.fromhex(p.TORRENT_SIGNATURES[0][1]),True)
            assert before=={tool:p.checked_run([tool,'-t','mangle','-S']) for tool in before}
            print('Disable restores original namespace mangle tables; host namespace never modified: PASS')
        finally:
            try: p.torrent_operation('disable',values)
            finally:
                group.rmdir(); group_root.rmdir()


if __name__=='__main__':
    assert sys.platform.startswith('linux') and os.geteuid()==0
    assert os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'Refusing host network namespace'
    if len(sys.argv)>1 and sys.argv[1]=='--client': client()
    else: main()

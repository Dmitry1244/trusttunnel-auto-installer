"""Linux-only syntax qualification. Every UFW invocation uses --dry-run."""
import os
import subprocess
import sys


if __name__=='__main__':
    assert sys.platform.startswith('linux')
    cases=[
        ('reload-force',['--force','reload']),
        ('disable-force',['--force','disable']),
        ('allow-range',['allow','in','proto','tcp','from','192.0.2.0/24','to','any','port','59100:59110']),
        ('limit-in',['limit','in','proto','tcp','from','192.0.2.1','to','any','port','59178']),
        ('source-block',['prepend','deny','in','from','192.0.2.1/32','to','any','comment','TrustTunnel blocked source']),
        ('acme-safe',['insert','1','allow','80/tcp','comment','TrustTunnel ACME']),
        ('acme-legacy',['insert','1','allow','80/tcp','comment',"TrustTunnel Let's Encrypt"]),
    ]
    for name,args in cases:
        result=subprocess.run(['ufw','--dry-run',*args],capture_output=True,text=True,timeout=15,env=dict(os.environ,LC_ALL='C'))
        print(name+': rc='+str(result.returncode)+(' '+result.stderr.strip() if result.returncode else ''))
        if name=='acme-legacy': assert result.returncode != 0,'Legacy quote hypothesis not reproduced'
        else: assert result.returncode==0,result.stdout+result.stderr

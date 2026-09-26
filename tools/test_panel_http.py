"""Authenticated read-only smoke tests against the VPS panel."""
import base64
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

env = dict(line.split('=',1) for line in Path('/etc/trusttunnel-panel.env').read_text().splitlines() if '=' in line and not line.startswith('#'))
base = ('https' if env.get('PANEL_TLS')=='1' else 'http') + '://127.0.0.1:' + env.get('PANEL_PORT','8088')
auth = 'Basic ' + base64.b64encode((env['PANEL_USER']+':'+env['PANEL_PASSWORD']).encode()).decode()
context = ssl._create_unverified_context()


def request(path, data=None, authenticated=True):
    headers={'Authorization':auth} if authenticated else {}
    req=urllib.request.Request(base+path, headers=headers, data=urllib.parse.urlencode(data).encode() if data is not None else None)
    return urllib.request.urlopen(req,context=context,timeout=30).read().decode()


for view in ('dashboard','clients','endpoint','warp','routing','dns','security','system','certificates','panel','logs'):
    page=request('/?view='+view)
    assert '<script>' in page and 'id="theme-toggle"' in page, view
    assert 'name="_csrf"' in page or view=='dashboard', view
    print(view+': HTTP OK')
page=request('/?view=clients')
assert 'data-drawer=' in page and 'id="client-state"' in page
token=re.search(r'name="_csrf" value="([^"]+)"',page)[1]
monitor=json.loads(request('/api/monitor'))
assert 'interfaces' in monitor and 'services' in monitor
for path,data,authenticated,expected in [('/api/monitor',None,False,401),('/manage',{'action':'monitor'},True,403)]:
    try: request(path,data,authenticated)
    except urllib.error.HTTPError as exc: assert exc.code==expected
    else: raise AssertionError('Missing authentication or CSRF enforcement')
assert 'Операция выполнена.' in request('/manage',{'action':'monitor','_csrf':token,'view':'dashboard'})
print('Auth, CSRF, shared read operation and live monitoring: PASS')

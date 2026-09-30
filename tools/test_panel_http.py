"""Authenticated read-only smoke tests against the VPS panel."""
import base64
import json
import re
import ssl
import socket
import time
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


for attempt in range(20):
    try:
        assert request('/health', authenticated=False).strip() == 'ok'
        break
    except urllib.error.URLError:
        if attempt == 19: raise
        time.sleep(0.25)

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

page = request('/?view=dashboard')
asset = re.search(r'href="(/assets/[^"]+\.css)"', page)[1]
req = urllib.request.Request(base + asset, headers={'Authorization': auth})
with urllib.request.urlopen(req, context=context) as response:
    etag = response.headers['ETag']
    assert 'private' in response.headers['Cache-Control']
    assert len(response.read()) > 1000
req = urllib.request.Request(base + asset, headers={'Authorization': auth, 'If-None-Match': etag})
try: urllib.request.urlopen(req, context=context)
except urllib.error.HTTPError as exc: assert exc.code == 304
else: raise AssertionError('Asset was not revalidated with 304')
req = urllib.request.Request(base + '/manage', headers={'Authorization': auth, 'Accept': 'application/json'}, data=urllib.parse.urlencode({'action': 'security-audit', '_csrf': token}).encode())
answer = json.loads(urllib.request.urlopen(req, context=context, timeout=30).read())
assert answer['ok'] and not answer['refresh']
req = urllib.request.Request(base + '/manage', headers={'Authorization': auth, 'Accept': 'application/json'}, data=urllib.parse.urlencode({'action': 'system-reboot', 'confirm': 'wrong', '_csrf': token}).encode())
try: urllib.request.urlopen(req, context=context)
except urllib.error.HTTPError as exc:
    assert exc.code == 400
    assert not json.loads(exc.read())['ok']
else: raise AssertionError('Reboot confirmation was bypassed')
print('Private asset caching, asynchronous read action and reboot confirmation: PASS')

if env.get('PANEL_TLS') == '1':
    # An idle TCP peer must not block the HTTPS listener's accept loop.
    with socket.create_connection(('127.0.0.1', int(env.get('PANEL_PORT', '8088'))), timeout=3):
        started = time.monotonic()
        assert request('/health', authenticated=False).strip() == 'ok'
        assert time.monotonic() - started < 5
    print('Idle TLS peer does not block other requests: PASS')

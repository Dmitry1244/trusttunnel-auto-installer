"""Browser login/session checks over loopback; never print credentials or cookies."""
import http.client
import http.cookies
import os
import re
import ssl
import urllib.parse
from pathlib import Path

env = dict(line.split('=',1) for line in Path('/etc/trusttunnel-panel.env').read_text().splitlines() if '=' in line and not line.startswith('#'))
port = int(os.environ.get('TT_PANEL_TEST_PORT',env.get('PANEL_PORT','8088')))
tls = env.get('PANEL_TLS') == '1'
cookies = {}

def request(path, data=None, extra=None, use_cookies=True):
    cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
    options = {'context':ssl._create_unverified_context()} if tls else {}
    connection = cls('127.0.0.1',port,timeout=15,**options)
    headers = {'Accept':'text/html'}
    if use_cookies: headers['Cookie'] = '; '.join(k+'='+v for k,v in cookies.items())
    if extra: headers.update(extra)
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    if body is not None: headers['Content-Type'] = 'application/x-www-form-urlencoded'
    connection.request('POST' if data is not None else 'GET',path,body=body,headers=headers)
    response = connection.getresponse(); status = response.status; response_headers = response.getheaders(); body = response.read().decode()
    for key,value in response_headers:
        if key.lower() == 'set-cookie' and use_cookies:
            parsed = http.cookies.SimpleCookie(value)
            for name,item in parsed.items():
                assert item['httponly'] and item['samesite'] == 'Strict' and item['path'] == '/'
                if tls: assert item['secure'] and name.startswith('__Host-')
                if item['max-age'] == '0': cookies.pop(name,None)
                else: cookies[name] = item.value
    connection.close()
    return status,dict(response_headers),body

assert request('/')[0] == 303
status,headers,page = request('/login')
assert status == 200 and 'id="login-user"' in page and 'id="login-eye"' in page
assert "'unsafe-inline'" not in headers['Content-Security-Policy']
token = re.search(r'name="_login_token" value="([^"]+)"',page)[1]
payload = {'username':env['PANEL_USER'],'password':env['PANEL_PASSWORD'],'_login_token':token}
assert request('/login',payload,{'Origin':'https://untrusted.example'})[0] == 403
assert request('/login',dict(payload,_login_token='wrong'))[0] == 403
status,_,page = request('/login'); token = re.search(r'name="_login_token" value="([^"]+)"',page)[1]
payload['_login_token'] = token
assert request('/login',dict(payload,password='wrong-password'))[0] == 401
status,_,page = request('/login'); payload['_login_token'] = re.search(r'name="_login_token" value="([^"]+)"',page)[1]
status,headers,_ = request('/login',payload)
assert status == 303 and headers['Location'] == '/'
status,_,page = request('/')
assert status == 200 and '/logout' in page
csrf = re.search(r'name="_csrf" value="([^"]+)"',page)[1]
assert request('/logout',{'_csrf':'wrong'})[0] == 403
assert request('/logout',{'_csrf':csrf})[0] == 303
assert request('/')[0] == 303
assert not cookies
print('Browser login, generic error, pre-auth CSRF, cross-origin rejection, secure cookies, session and logout: PASS')

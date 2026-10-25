"""Loopback-only HTTP audit with synthetic admin credentials and no OS commands."""
import base64
import http.client
import http.cookies
import json
import re
import threading
import unittest
import urllib.parse
from unittest.mock import patch

from test_firewall_fail2ban import p


class PanelHTTPAudit(unittest.TestCase):
    def setUp(self):
        self.patches=[patch.object(p,'PANEL_USER','audit'),patch.object(p,'PANEL_PASSWORD','synthetic-audit-password'),
                      patch.object(p,'admin_operation',return_value='safe result'),patch.object(p,'html_page',return_value='<html>synthetic</html>')]
        for item in self.patches: item.start()
        class Quiet(p.Handler):
            def log_message(self,*args): pass
        self.server=p.PanelServer(('127.0.0.1',0),Quiet)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        p.LOGIN_FAILURES.clear(); p.SESSIONS.clear()
        self.auth='Basic '+base64.b64encode(b'audit:synthetic-audit-password').decode()
        self.origin='http://127.0.0.1:'+str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(3)
        for item in reversed(self.patches): item.stop()

    def request(self,path='/',body=None,headers=None,authenticated=True):
        data={'Accept':'application/json'}
        if authenticated: data['Authorization']=self.auth
        if body is not None: data['Content-Type']='application/x-www-form-urlencoded'
        data.update(headers or {})
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
        try:
            connection.request('POST' if body is not None else 'GET',path,body=body,headers=data)
            response=connection.getresponse(); return response.status,response.headers,response.read()
        finally: connection.close()

    def post(self,values,**kwargs):
        return self.request('/manage',urllib.parse.urlencode(values),**kwargs)

    def test_private_routes_require_authentication(self):
        for path in ('/','/api/client-link?username=alice','/api/clients-metrics','/api/monitor','/backup/latest.zip','/client/alice/http2.toml','/qr-link/alice.png'):
            with self.subTest(path=path): self.assertEqual(self.request(path,authenticated=False)[0],401)
        p.admin_operation.assert_not_called()

    def test_cross_origin_and_missing_csrf_do_not_execute(self):
        self.assertEqual(self.post({'action':'ufw-disable','_csrf':p.CSRF_TOKEN},headers={'Origin':'https://attacker.invalid'})[0],403)
        self.assertEqual(self.post({'action':'ufw-disable'})[0],403)
        p.admin_operation.assert_not_called()

    def test_unicode_csrf_is_rejected_without_worker_exception(self):
        self.assertEqual(self.post({'action':'ufw-disable','_csrf':'неверно'})[0],403)
        p.admin_operation.assert_not_called()

    def test_duplicate_fields_are_rejected(self):
        body=urllib.parse.urlencode([('_csrf',p.CSRF_TOKEN),('action','monitor'),('action','ufw-disable')])
        self.assertEqual(self.request('/manage',body)[0],400)
        p.admin_operation.assert_not_called()

    def test_too_many_fields_are_rejected(self):
        self.assertEqual(self.post({str(i):str(i) for i in range(90)})[0],400)

    def test_json_and_text_bodies_are_rejected(self):
        for mime in ('text/plain','application/json'):
            self.assertEqual(self.request('/manage','{"action":"ufw-disable"}',headers={'Content-Type':mime})[0],400)
        p.admin_operation.assert_not_called()

    def test_chunked_and_duplicate_content_length_are_rejected(self):
        for headers in ([('Transfer-Encoding','chunked')],[('Content-Length','1'),('Content-Length','2')]):
            connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
            try:
                connection.putrequest('POST','/manage'); connection.putheader('Authorization',self.auth)
                connection.putheader('Content-Type','application/x-www-form-urlencoded')
                for name,value in headers: connection.putheader(name,value)
                connection.endheaders(b'x')
                response=connection.getresponse(); self.assertEqual(response.status,400); response.read()
            finally: connection.close()
        p.admin_operation.assert_not_called()

    def test_headers_do_not_disclose_python_and_disable_caching_and_framing(self):
        status,headers,body=self.request('/health',authenticated=False)
        self.assertEqual(status,200); self.assertNotIn('Python',headers['Server'])
        self.assertEqual(headers['Cache-Control'],'no-store'); self.assertEqual(headers['X-Frame-Options'],'DENY')
        self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])
        self.assertNotIn("'unsafe-inline'",headers['Content-Security-Policy'])

    def test_real_peer_cannot_be_forged_by_form_or_forwarded_header(self):
        status,_,body=self.post({'action':'f2b-ban','_csrf':p.CSRF_TOKEN,'_peer':'192.0.2.5'},headers={'X-Forwarded-For':'192.0.2.8'})
        self.assertEqual(status,200); self.assertTrue(json.loads(body)['ok'])
        self.assertEqual(p.admin_operation.call_args.args[1]['_peer'],'127.0.0.1')

    def test_backend_error_is_returned_as_failure(self):
        p.admin_operation.side_effect=ValueError('confirmation required')
        status,_,body=self.post({'action':'ufw-disable','_csrf':p.CSRF_TOKEN})
        self.assertEqual(status,400); self.assertFalse(json.loads(body)['ok'])

    def login_form(self):
        status,headers,body=self.request('/login',authenticated=False)
        self.assertEqual(status,200)
        cookies=http.cookies.SimpleCookie(headers['Set-Cookie'])
        token=re.search(rb'name="_login_token" value="([^"]+)"',body)[1].decode()
        return token,'; '.join(name+'='+item.value for name,item in cookies.items())

    def test_unicode_login_token_is_rejected_safely(self):
        token,cookie=self.login_form()
        body=urllib.parse.urlencode({'username':'audit','password':'synthetic-audit-password','_login_token':'неверно'})
        self.assertEqual(self.request('/login',body,headers={'Cookie':cookie},authenticated=False)[0],403)

    def test_login_rate_limit_is_per_peer(self):
        for i in range(6):
            token,cookie=self.login_form()
            body=urllib.parse.urlencode({'username':'audit','password':'wrong','_login_token':token})
            self.assertEqual(self.request('/login',body,headers={'Cookie':cookie},authenticated=False)[0],401 if i<5 else 429)

    def test_session_cookie_and_logout_invalidate_access(self):
        token,cookie=self.login_form()
        body=urllib.parse.urlencode({'username':'audit','password':'synthetic-audit-password','_login_token':token})
        status,headers,_=self.request('/login',body,headers={'Cookie':cookie},authenticated=False)
        self.assertEqual(status,303); self.assertEqual(len(p.SESSIONS),1)
        cookies=http.cookies.SimpleCookie()
        for value in headers.get_all('Set-Cookie',[]): cookies.load(value)
        session=cookies['tt_session']
        self.assertTrue(session['httponly']); self.assertEqual(session['samesite'],'Strict')
        self.assertEqual(session['path'],'/')
        cookie='tt_session='+session.value
        self.assertEqual(self.request('/',headers={'Cookie':cookie},authenticated=False)[0],200)
        token_hash=next(iter(p.SESSIONS))
        # The random raw token, not a stored hash, is required to authenticate.
        self.assertEqual(self.request('/',headers={'Cookie':'tt_session='+token_hash},authenticated=False)[0],401)
        self.assertNotIn('synthetic-audit-password',str(p.SESSIONS))
        status,_,_=self.request('/logout',urllib.parse.urlencode({'_csrf':p.CSRF_TOKEN}),headers={'Cookie':cookie},authenticated=False)
        self.assertEqual(status,303); self.assertFalse(p.SESSIONS)
        self.assertEqual(self.request('/',headers={'Cookie':cookie},authenticated=False)[0],401)

    def test_expired_sessions_are_removed(self):
        token='synthetic-expired-session'
        digest=p.hashlib.sha256(token.encode()).hexdigest()
        now=p.time.monotonic()
        for values in ({'created':now,'seen':now-p.SESSION_IDLE_SECONDS-1},
                       {'created':now-p.SESSION_MAX_SECONDS-1,'seen':now}):
            p.SESSIONS[digest]=values
            self.assertEqual(self.request('/',headers={'Cookie':'tt_session='+token},authenticated=False)[0],401)
            self.assertNotIn(digest,p.SESSIONS)

    def test_missing_panel_password_fails_closed(self):
        with patch.object(p,'PANEL_PASSWORD',''):
            self.assertEqual(self.request('/')[0],503)
        p.admin_operation.assert_not_called()

    def test_public_cleartext_listener_is_refused(self):
        with patch.dict(p.os.environ,{'PANEL_BIND':'0.0.0.0'}),patch.object(p,'PANEL_TLS',False),patch.object(p,'PanelServer') as server:
            with self.assertRaises(RuntimeError): p.main()
            server.assert_not_called()

    def test_large_content_length_rejected_before_reading_body(self):
        self.assertEqual(self.request('/manage','x',headers={'Content-Length':'65537'})[0],400)
        p.admin_operation.assert_not_called()


if __name__ == '__main__': unittest.main()

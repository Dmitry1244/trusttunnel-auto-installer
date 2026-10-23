"""Local HTTP security checks using synthetic accounts and a temporary database."""
import http.cookiejar
import http.client
import json
import re
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest.mock import patch

import test_client_protection as fixtures
panel = fixtures.panel


class ActivationHTTPTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.ProtectionTests(); self.fixture.setUp()
        self.password=patch.object(panel,'PANEL_PASSWORD','synthetic-admin-password-only')
        self.password.start()
        class QuietHandler(panel.Handler):
            def log_message(self,*args): pass
        self.server=panel.PanelServer(('127.0.0.1',0),QuietHandler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        self.base='http://127.0.0.1:'+str(self.server.server_port)
        self.cookies=http.cookiejar.CookieJar()
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(self.cookies))
        panel.LOGIN_FAILURES.clear()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(3)
        self.password.stop(); self.fixture.tearDown()

    def request(self,path,values=None,origin=None):
        headers={}
        if values is not None: headers['Origin']=origin or self.base
        data=urllib.parse.urlencode(values).encode() if values is not None else None
        return self.opener.open(urllib.request.Request(self.base+path,data=data,headers=headers),timeout=8)

    def csrf(self):
        with self.request('/activate') as response:
            self.assertIn('no-store',response.headers['Cache-Control'])
            self.assertIn('nonce-',response.headers['Content-Security-Policy'])
            page=response.read().decode()
        return re.search('name="_csrf" value="([^"]+)"',page)[1]

    def test_get_does_not_consume_and_post_requires_cookie_csrf_and_origin(self):
        token=self.fixture.issue(); csrf=self.csrf()
        for values,origin in (({'token':token},None),({'token':token,'_csrf':csrf},'https://attacker.invalid')):
            with self.assertRaises(urllib.error.HTTPError) as caught: self.request('/activate',values,origin)
            self.assertEqual(caught.exception.code,403)
        with panel.usage_database() as db: self.assertEqual(db.execute('SELECT consumed FROM enrollment').fetchone()[0],0)
        with patch.object(panel,'deeplink',return_value='tt://?synthetic'),patch.object(panel,'qr_image',return_value=b'image'):
            with self.request('/activate',{'token':token,'_csrf':csrf}) as response:
                body=json.loads(response.read()); self.assertEqual(body['link'],'tt://?synthetic')
            with self.assertRaises(urllib.error.HTTPError) as caught: self.request('/activate',{'token':token,'_csrf':csrf})
            self.assertEqual(caught.exception.code,400)

    def test_public_activation_does_not_expose_admin_apis(self):
        self.csrf()
        for path in ('/api/clients-metrics','/api/client-link?username=alice','/client/alice/http2.toml','/backup/latest.zip'):
            with self.assertRaises(urllib.error.HTTPError) as caught: self.request(path)
            self.assertEqual(caught.exception.code,401)

    def test_repeated_bad_tokens_are_throttled(self):
        csrf=self.csrf()
        codes=[]
        for _ in range(6):
            try: self.request('/activate',{'token':'x'*43,'_csrf':csrf})
            except urllib.error.HTTPError as caught: codes.append(caught.code)
        self.assertEqual(codes,[400]*5+[429])

    def test_oversized_activation_body_is_rejected(self):
        csrf=self.csrf()
        with self.assertRaises(urllib.error.HTTPError) as caught: self.request('/activate',{'token':'x'*5000,'_csrf':csrf})
        self.assertEqual(caught.exception.code,400)

    def test_malformed_public_content_length_cannot_render_admin_dashboard(self):
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
        try:
            connection.request('POST','/activate',body='x',headers={'Origin':self.base,'Content-Length':'invalid'})
            response=connection.getresponse(); body=response.read()
            self.assertEqual(response.status,400)
            self.assertIn('application/json',response.headers['Content-Type'])
            self.assertNotIn(panel.CSRF_TOKEN.encode(),body)
            self.assertNotIn(b'<main',body)
        finally: connection.close()


if __name__ == '__main__': unittest.main()

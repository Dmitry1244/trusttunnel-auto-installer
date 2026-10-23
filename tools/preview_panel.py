"""Local UI fixture with synthetic data and no server-management commands."""
from test_admin import panel
import http.server
import io
import sys
from pathlib import Path
import urllib.parse
sys.path.insert(0, str(Path(__file__).parent / 'qa-deps'))
import qrcode

panel.domain = lambda: 'vpn.example.test'
panel.endpoint_port = lambda: '8443'
panel.quic_enabled = lambda: True
panel.cert_mode = lambda: 'letsencrypt'
panel.endpoint_version = lambda: 'TrustTunnel test fixture'
panel.client_tls_profile = lambda: 'chrome'
panel.jail_settings = lambda: {'maxretry':'5','findtime':'600','bantime':'3600'}
panel.forwarder_label = lambda: 'WARP · WireGuard интерфейс'
panel.current_warp_backend = lambda: 'wg-interface'
fixture_clients = [dict(username=f'client{i:02}', password='synthetic-password', enabled=i % 3 != 0, note='Тестовый профиль') for i in range(1, 28)]
panel.client_inventory = lambda: [dict(c) for c in fixture_clients]
panel.load_clients = lambda: [c for c in panel.client_inventory() if c['enabled']]
panel.security_snapshot = lambda: dict(checks=[dict(title=title, state=state, detail=detail) for title,state,detail in [('Сетевой экран','ok','Status: active'),('Защита SSH','ok','SSH jail работает'),('Вход по SSH','warn','Пароль: yes; root: yes. Базовые настройки без учёта Match-блоков.'),('Доступ к панели','ok','Публичный HTTPS'),('Приватные файлы','ok','Файлы учётных данных и ключа доступны только владельцу'),('Сертификат VPN','ok','Действителен ещё 58 дней'),('Перезагрузка ОС','ok','Не требуется')]])
def synthetic_link(name, protocol='http2', kind='static'):
    import base64
    fields = [(0,b'\x01'),(1,b'vpn.example.test'),(2,b'vpn.example.test:8443'),(5,name.encode()),(6,b'synthetic-password'),(9,b'\x01' if protocol == 'http2' else b'\x02')]
    data = b''.join(panel.link_varint(tag)+panel.link_varint(len(value))+value for tag,value in fields)
    return 'tt://?' + base64.urlsafe_b64encode(data).rstrip(b'=').decode()
panel.deeplink = synthetic_link
panel.endpoint_capabilities = lambda: {'subscription':False, 'auth_key':False, 'metrics':True}
panel.service_snapshot = lambda: {'trusttunnel':'active', 'warp-wireproxy':'active', 'warp-masque':'inactive', 'trusttunnel-panel':'active', 'fail2ban':'active'}
panel.panel_settings = lambda: {'DNS_UPSTREAMS': '1.1.1.1', 'CLIENT_ANTI_DPI': '0', 'TLS_PROFILE': 'chrome', 'POST_QUANTUM': '0'}
panel.PANEL_USER = 'preview'
panel.PANEL_PASSWORD = 'synthetic-preview-password'
panel.rules_text = lambda: '[[rule]]\ncidr="192.0.2.0/24"\naction="deny"\n'
panel.monitor_snapshot = lambda: dict(cpu='2.4%', memory='512 МиБ / 2 ГиБ', disk='8 ГиБ / 40 ГиБ', uptime='14д 02ч', memory_percent=25, disk_percent=20, services=panel.service_snapshot(), route='WARP · WireGuard', interfaces={'ens3':{'rx':int(panel.time.time()*12345),'tx':int(panel.time.time()*6789)}}, time=panel.time.time())
panel.client_metrics = lambda: dict(available=True,checked_at=panel.time.time(),clients=[dict(username=c['username'],online=c['enabled'],sessions=1 if c['enabled'] else 0,upload=123456789,download=987654321,last_seen=panel.time.time()-(0 if c['enabled'] else 3600)) for c in fixture_clients],guard={},accounting_error='')


class Preview(panel.Handler):
    def authenticated(self): return True
    def do_POST(self):
        if self.path == '/manage':
            data = urllib.parse.parse_qs(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode())
            action = data.get('action',[''])[0]
            if action == 'client-note':
                for item in fixture_clients:
                    if item['username'] == data.get('username',[''])[0]: item['note'] = data.get('note',[''])[0]
            self.send_json({'ok':True,'output':'Тестовый отчёт: изменений на сервере нет.','refresh':action.startswith('client-')})
        elif self.path in ('/login','/logout'): super().do_POST()
        else: self.send_error(405)
    def log_message(self, *args): pass
    def do_GET(self):
        if self.path.startswith('/qr-link/'):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            picture = qrcode.make(synthetic_link('client01', query.get('protocol',['http2'])[0]))
            output=io.BytesIO(); picture.save(output, format='PNG'); body=output.getvalue()
            self.send_response(200); self.send_header('Content-Type','image/png'); self.send_header('Content-Length',str(len(body))); self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


http.server.ThreadingHTTPServer(('127.0.0.1', 18089), Preview).serve_forever()

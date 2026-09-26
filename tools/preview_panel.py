"""Local UI fixture with synthetic data and no server-management commands."""
from test_admin import panel
import http.server

panel.domain = lambda: 'vpn.example.test'
panel.endpoint_port = lambda: '8443'
panel.quic_enabled = lambda: True
panel.cert_mode = lambda: 'letsencrypt'
panel.endpoint_version = lambda: 'TrustTunnel test fixture'
panel.client_tls_profile = lambda: 'chrome'
panel.forwarder_label = lambda: 'WARP/SOCKS'
panel.client_inventory = lambda: [dict(username=f'client{i:02}', password='synthetic-password', enabled=i % 3 != 0, note='Тестовый профиль') for i in range(1, 28)]
panel.deeplink = lambda name: 'tt://synthetic-preview-' + name
panel.panel_settings = lambda: {'DNS_UPSTREAMS': '1.1.1.1', 'CLIENT_ANTI_DPI': '0', 'TLS_PROFILE': 'chrome', 'POST_QUANTUM': '0'}
panel.rules_text = lambda: '[[rule]]\ncidr="192.0.2.0/24"\naction="deny"\n'
panel.monitor_snapshot = lambda: dict(cpu='load: 0.11 / 0.22 / 0.18', memory='512 MiB / 2 GiB', disk='8 GiB / 40 GiB', uptime='14d 02h', memory_percent=25, disk_percent=20, services={'trusttunnel':'active','warp-wireproxy':'active','fail2ban':'active'}, route='WARP/SOCKS', interfaces={'ens3':{'rx':int(panel.time.time()*12345),'tx':int(panel.time.time()*6789)}}, time=panel.time.time())


class Preview(panel.Handler):
    def authenticated(self): return True
    def do_POST(self): self.send_error(405)
    def log_message(self, *args): pass
    def do_GET(self):
        if self.path.startswith('/qr-link/'):
            import base64
            self.send_response(200); self.send_header('Content-Type','image/png'); self.end_headers()
            self.wfile.write(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aYuoAAAAASUVORK5CYII='))
            return
        super().do_GET()


http.server.ThreadingHTTPServer(('127.0.0.1', 18089), Preview).serve_forever()

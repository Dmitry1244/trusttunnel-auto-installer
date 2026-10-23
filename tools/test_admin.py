"""Regression checks for shared CLI/web operations; never use real VPS files."""
import importlib.util
import json
import os
import tempfile
import unittest
import base64
from pathlib import Path
from contextlib import nullcontext
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('panel', os.environ.get('TT_PANEL_SOURCE') or Path(__file__).parents[1] / 'trusttunnel-panel.py')
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [patch.object(panel, 'TT_DIR', self.root), patch.object(panel, 'CLIENT_DIR', self.root / 'exports'),
                        patch.object(panel, 'PANEL_SETTINGS', self.root / 'settings'), patch.object(panel, 'admin_lock', nullcontext),
                        patch.object(panel, 'audit_log'), patch.object(panel, 'run', return_value=(0, 'ok')),
                        patch.object(panel, 'service_status', return_value='active'),
                        patch.object(panel, 'client_profile', side_effect=lambda u, p, protocol: f'{u}:{p}:{protocol}')]
        for item in self.patches: item.start()
        (self.root / 'credentials.toml').write_text('[[client]]\nusername="original"\npassword="original-password"\n')
        (self.root / 'vpn.toml').write_text('rules_file="rules.toml"\n[listen_protocols.http2]\n[forward_protocol]\ndirect={}\n')
        (self.root / 'exports').mkdir()
        (self.root / 'exports/original-http2.toml').write_text('original custom profile')

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()

    def test_suspend_restore_preserves_password_and_existing_profile(self):
        panel.client_operation('add', {'username': 'extra'})
        password = panel.load_clients()[1]['password']
        panel.client_operation('disable', {'username': 'extra'})
        self.assertEqual(len(panel.load_clients()), 1)
        self.assertFalse(next(c for c in panel.client_inventory() if c['username'] == 'extra')['enabled'])
        panel.client_operation('enable', {'username': 'extra'})
        self.assertEqual(panel.load_clients()[1]['password'], password)
        self.assertEqual((self.root / 'exports/original-http2.toml').read_text(), 'original custom profile')

    def test_last_client_cannot_be_deleted_or_disabled(self):
        for action in ('delete', 'disable'):
            with self.assertRaises(ValueError): panel.client_operation(action, {'username': 'original'})

    def test_failed_restart_rolls_back_credentials_and_state(self):
        original = (self.root / 'credentials.toml').read_bytes()
        panel.run.return_value = (1, 'failed')
        with self.assertRaises(RuntimeError): panel.client_operation('batch', {'count': '3'})
        self.assertEqual((self.root / 'credentials.toml').read_bytes(), original)
        self.assertFalse((self.root / 'clients-state.json').exists())

    def test_notes_do_not_restart_or_rewrite_profiles(self):
        panel.client_operation('note', {'username': 'original', 'note': 'Телефон'})
        panel.run.assert_not_called()
        self.assertEqual(panel.client_inventory()[0]['note'], 'Телефон')

    def test_batch_skips_existing_and_disabled_names(self):
        panel.client_operation('batch', {'prefix': 'test', 'count': '2'})
        panel.client_operation('disable', {'username': 'test01'})
        panel.client_operation('batch', {'prefix': 'test', 'count': '2'})
        self.assertEqual(len(panel.client_inventory()), 5)
        self.assertEqual(len({c['password'] for c in panel.client_inventory()}), 5)

    def test_unknown_credential_fields_are_not_discarded(self):
        path = self.root / 'credentials.toml'
        path.write_text(path.read_text() + 'custom="preserve"\n')
        original = path.read_bytes()
        with self.assertRaises(ValueError): panel.client_operation('add', {'username': 'test'})
        self.assertEqual(path.read_bytes(), original)

    def test_dns_validation_and_save_does_not_rebuild(self):
        for invalid in ('bad host', 'http://dns.test', 'https://user:pass@dns.test', '1.2.3.999'):
            with self.assertRaises(ValueError): panel.validated_dns(invalid)
        panel.network_operation('dns-save', {'dns': '1.1.1.1,https://dns.google/dns-query'})
        self.assertEqual(panel.panel_settings()['DNS_UPSTREAMS'], '1.1.1.1,https://dns.google/dns-query')
        panel.run.assert_not_called()

    def test_route_health_failure_keeps_config(self):
        original = (self.root / 'vpn.toml').read_bytes()
        panel.run.return_value = (1, 'timeout')
        with self.assertRaises(RuntimeError): panel.network_operation('routing-switch', {'mode': 'socks5', 'address': '127.0.0.1:40000'})
        self.assertEqual((self.root / 'vpn.toml').read_bytes(), original)

    def test_dns_failure_does_not_hide_other_results(self):
        panel.run.side_effect = [(1, 'timeout'), (0, 'status: NOERROR')]
        output = panel.network_operation('dns-check', {'dns': '1.1.1.1,8.8.8.8'})
        self.assertIn('1.1.1.1: Нет успешного', output)
        self.assertIn('8.8.8.8: OK', output)

    def test_protected_ports_cannot_be_closed(self):
        with patch.object(panel, 'current_ssh_port', return_value='49222'), patch.object(panel, 'current_panel_env', return_value={'PANEL_PORT':'8088'}):
            for port in ('49222', '443', '8088'):
                with self.assertRaises(ValueError): panel.network_operation('security-close', {'port': port})
        panel.run.assert_not_called()

    def test_rule_deletion_rejects_stale_fingerprint(self):
        path = self.root / 'rules.toml'
        path.write_text('[[rule]]\ncidr="192.0.2.0/24"\naction="deny"\n')
        with self.assertRaises(ValueError): panel.network_operation('routing-rule-delete', {'index': '1', 'fingerprint': 'stale'})
        self.assertIn('192.0.2.0', path.read_text())

    def test_clients_page_does_not_generate_links(self):
        with patch.object(panel, 'deeplink') as exporter:
            result = panel.clients_console()
            self.assertIn('data-load-link=', result)
            exporter.assert_not_called()

    def test_scoped_firewall_rule_validation(self):
        with patch.object(panel, 'current_ssh_port', return_value='49222'), patch.object(panel, 'current_panel_env', return_value={'PANEL_PORT': '8088'}):
            panel.network_operation('security-open', {'port': '59177', 'proto': 'tcp', 'source': '192.0.2.7/24'})
            self.assertEqual(panel.run.call_args.args[0], ['ufw', 'allow', 'proto', 'tcp', 'from', '192.0.2.0/24', 'to', 'any', 'port', '59177'])
            with self.assertRaises(ValueError):
                panel.network_operation('security-open', {'port': '59177', 'source': 'any; reboot'})

    def test_fail2ban_exclusion_preserves_existing_and_rolls_back(self):
        target = self.root / 'ignore.local'
        target.write_text('[sshd]\nignoreip=127.0.0.1/8\n')
        old = target.read_text()
        with patch.object(panel, 'IGNORE_FILE', target):
            panel.run.side_effect = [(0, 'These IP addresses/networks are ignored:\n|- 127.0.0.1/8\n|- ::1\n`- 198.51.100.1'), (0, 'OK'), (0, 'OK')]
            panel.update_ignore_list('security-ignore-add', {'ip': '192.0.2.17'})
            self.assertIn('198.51.100.1/32', target.read_text())
            self.assertIn('192.0.2.17/32', target.read_text())
            saved = target.read_text()
            panel.run.side_effect = [(0, '127.0.0.1/8'), (1, 'invalid config'), (0, 'restored')]
            with self.assertRaises(RuntimeError): panel.update_ignore_list('security-ignore-add', {'ip': '192.0.2.18'})
            self.assertEqual(saved, target.read_text())
            with self.assertRaises(ValueError): panel.update_ignore_list('security-ignore-add', {'ip': '0.0.0.0/0'})

    def test_reboot_requires_confirmation(self):
        for value in ('', 'yes', 'reboot'):
            with self.assertRaises(ValueError): panel.power_operation('system-reboot', {'confirm': value})
        panel.run.assert_not_called()
        panel.power_operation('system-reboot', {'confirm': 'REBOOT'})
        self.assertIn('--on-active=60s', panel.run.call_args.args[0])
        panel.power_operation('system-reboot-cancel', {})
        self.assertEqual(panel.run.call_args.args[0], ['systemctl', 'stop', 'trusttunnel-panel-reboot.timer'])

    def test_login_throttle_expires_and_is_per_peer(self):
        panel.LOGIN_FAILURES.clear()
        with patch.object(panel.time, 'monotonic', return_value=100):
            for _ in range(4): self.assertEqual(panel.login_delay('a', failed=True), 0)
            self.assertGreater(panel.login_delay('a', failed=True), 0)
            self.assertEqual(panel.login_delay('b'), 0)
        with patch.object(panel.time, 'monotonic', return_value=161):
            self.assertEqual(panel.login_delay('a'), 0)

    def test_monitor_cache_coalesces_multiple_visitors(self):
        panel.SNAPSHOT_CACHE.clear()
        with patch.object(panel, 'system_metrics', return_value={}) as metrics, patch.object(panel, 'service_snapshot', return_value={}):
            panel.monitor_snapshot()
            panel.monitor_snapshot()
            metrics.assert_called_once()

    def test_limits_preserve_other_clients_and_rollback_on_restart_failure(self):
        panel.client_operation('limits', {'username': 'original', 'max_http2_conns': '2', 'max_http3_conns': '3'})
        client = panel.load_clients()[0]
        self.assertEqual((client['max_http2_conns'], client['max_http3_conns']), (2, 3))
        panel.client_operation('add', {'username': 'extra'})
        self.assertEqual(panel.load_clients()[0]['max_http3_conns'], 3)
        saved = (self.root / 'credentials.toml').read_bytes()
        panel.run.return_value = (1, 'restart failed')
        with self.assertRaises(RuntimeError):
            panel.client_operation('limits', {'username': 'extra', 'max_http2_conns': '1'})
        self.assertEqual((self.root / 'credentials.toml').read_bytes(), saved)

    def test_subscription_cannot_be_enabled_on_incompatible_endpoint(self):
        saved = (self.root / 'vpn.toml').read_bytes()
        with patch.object(panel, 'endpoint_capabilities', return_value={'subscription': False}):
            with self.assertRaises(ValueError):
                panel.endpoint_feature_operation('endpoint-subscription', {'enabled': '1'})
        self.assertEqual((self.root / 'vpn.toml').read_bytes(), saved)

    def test_private_metrics_reject_public_listener(self):
        (self.root / 'vpn.toml').write_text('[metrics]\naddress="0.0.0.0:1987"\n')
        with patch.object(panel, 'endpoint_capabilities', return_value={'metrics': True}):
            with self.assertRaises(ValueError):
                panel.endpoint_feature_operation('endpoint-metrics', {'enabled': '1'})
        panel.run.assert_not_called()

    def test_masque_udp_failure_keeps_route(self):
        saved = (self.root / 'vpn.toml').read_bytes()
        panel.run.return_value = (0, 'warp=on\nip=104.28.0.1')
        with patch.object(panel, 'socks_udp_dns', side_effect=OSError('UDP timeout')):
            with self.assertRaises(RuntimeError):
                panel.network_operation('routing-switch', {'mode': 'masque'})
        self.assertEqual((self.root / 'vpn.toml').read_bytes(), saved)

    def test_masque_stop_cannot_break_active_route(self):
        (self.root / 'vpn.toml').write_text('[forward_protocol.socks5]\naddress="127.0.0.1:40002"\n')
        with self.assertRaises(ValueError):
            panel.masque_operation('stop', {})
        panel.run.assert_not_called()

    def test_log_units_are_not_silently_replaced_and_links_are_redacted(self):
        panel.run.return_value = (0, 'line tt://?AAEBsecret\nnext')
        result = panel.recent_logs('warp-wireproxy')
        self.assertEqual(panel.run.call_args.args[0][2], 'warp-wireproxy')
        self.assertNotIn('AAEBsecret', result)
        panel.recent_logs('sshd')
        self.assertEqual(panel.run.call_args.args[0][2], 'sshd')
        with self.assertRaises(ValueError): panel.recent_logs('../../etc/shadow')

    def test_env_password_cannot_inject_shell_or_systemd_syntax(self):
        for password in ('LongPassword$(id)', 'LongPassword;id', 'LongPassword|id', 'LongPassword\nX=1', 'LongPassword\\x', 'LongPassword"x', 'Long Password'):
            with self.assertRaises(ValueError):
                panel.update_panel_credentials('admin', password)
        panel.run.assert_not_called()

    def test_legacy_firewall_obeys_protected_port_guard(self):
        with patch.object(panel, 'current_ssh_port', return_value='49222'), patch.object(panel, 'current_panel_env', return_value={'PANEL_PORT':'8088'}):
            for port in ('49222', '443', '8088'):
                with self.assertRaises(ValueError): panel.ufw_output('delete', port)

    def test_section_replacement_does_not_leave_array_fragments(self):
        text = '[subscription]\nenabled=true\ndns_upstreams=["1.1.1.1","8.8.8.8"]\n[metrics]\naddress="127.0.0.1:1987"\n'
        changed = panel.replace_config_section(text, 'subscription', {'enabled':False,'dns_upstreams':['9.9.9.9']})
        self.assertEqual(panel.tomllib.loads(changed)['subscription']['dns_upstreams'], ['9.9.9.9'])
        self.assertEqual(panel.tomllib.loads(changed)['metrics']['address'], '127.0.0.1:1987')

    def test_clienthello_prepare_does_not_change_existing_profiles_or_rules(self):
        before = (self.root / 'exports/original-http2.toml').read_bytes()
        with patch.object(panel, 'endpoint_capabilities', return_value={'prefix':True}):
            panel.protection_operation('prepare', {'confirm':'CONFIRMED'})
            prefix = panel.protection_state()['prefix']
            panel.protection_operation('prepare', {'confirm':'CONFIRMED'})
        self.assertEqual(prefix, panel.protection_state()['prefix'])
        self.assertFalse(panel.protection_state().get('enabled'))
        self.assertEqual(before, (self.root / 'exports/original-http2.toml').read_bytes())
        self.assertFalse((self.root / 'rules.toml').exists())
        panel.run.assert_not_called()

    def test_strict_clienthello_requires_migration_and_preserves_existing_denies(self):
        rules = self.root / 'rules.toml'
        original = '[[rule]]\ncidr="192.0.2.0/24"\naction="deny"\n'
        rules.write_text(original)
        with patch.object(panel, 'endpoint_capabilities', return_value={'prefix':True}):
            panel.protection_operation('prepare', {'confirm':'CONFIRMED'})
            with self.assertRaises(ValueError): panel.protection_operation('enforce', {'confirm':'CONFIRMED'})
            panel.protection_operation('enforce', {'confirm':'CONFIRMED','clients_ready':'1'})
            self.assertTrue(panel.protection_state()['enabled'])
            self.assertTrue(rules.read_text().startswith(original))
            self.assertEqual(panel.tomllib.loads(rules.read_text())['rule'][-1], {'action':'deny'})
            with self.assertRaises(ValueError): panel.network_operation('routing-rule-add', {'cidr':'198.51.100.0/24'})
            panel.protection_operation('disable', {'confirm':'CONFIRMED'})
        self.assertEqual(rules.read_text(), original)

    def test_strict_filter_rejects_allow_bypass_and_stale_rollback(self):
        rules = self.root / 'rules.toml'
        with patch.object(panel, 'endpoint_capabilities', return_value={'prefix':True}):
            panel.protection_operation('prepare', {'confirm':'CONFIRMED'})
            rules.write_text('[[rule]]\naction="allow"\n')
            with self.assertRaises(ValueError): panel.protection_operation('enforce', {'confirm':'CONFIRMED','clients_ready':'1'})
            rules.write_text('')
            panel.protection_operation('enforce', {'confirm':'CONFIRMED','clients_ready':'1'})
            rules.write_text(rules.read_text() + '\n# Manual change\n')
            with self.assertRaises(ValueError): panel.protection_operation('disable', {'confirm':'CONFIRMED'})
        self.assertIn('Manual change', rules.read_text())

    def test_camouflage_keeps_connect_auth_and_restores_only_managed_root_keys(self):
        path = self.root / 'vpn.toml'
        path.write_text('auth_failure_status_code=407\nping_enable=true\n[listen_protocols.http2]\n')
        with patch.object(panel, 'endpoint_capabilities', return_value={'stealth_http':True}):
            panel.protection_operation('camouflage', {'confirm':'CONFIRMED'})
            cfg = panel.tomllib.loads(path.read_text())
            self.assertEqual(cfg['auth_failure_status_code'], 407)
            self.assertEqual(cfg['non_connect_auth_failure_status_code'], 404)
            self.assertFalse(cfg['ping_enable'])
            panel.protection_operation('camouflage-restore', {'confirm':'CONFIRMED'})
        cfg = panel.tomllib.loads(path.read_text())
        self.assertTrue(cfg['ping_enable'])
        self.assertNotIn('non_connect_auth_failure_status_code', cfg)
        self.assertEqual(cfg['auth_failure_status_code'], 407)

    def test_failed_guard_restart_keeps_rules_and_disabled_state(self):
        with patch.object(panel, 'endpoint_capabilities', return_value={'prefix':True}):
            panel.protection_operation('prepare', {'confirm':'CONFIRMED'})
            panel.run.return_value = (1, 'failed')
            with self.assertRaises(RuntimeError): panel.protection_operation('enforce', {'confirm':'CONFIRMED','clients_ready':'1'})
        self.assertEqual(panel.read_text(self.root / 'rules.toml'), '')
        self.assertFalse(panel.protection_state()['enabled'])

    def test_protection_confirmation_and_version_guards(self):
        with patch.object(panel, 'endpoint_capabilities', return_value={}):
            for op in ('prepare','camouflage','enforce'):
                with self.assertRaises(ValueError): panel.protection_operation(op, {})
                with self.assertRaises(ValueError): panel.protection_operation(op, {'confirm':'CONFIRMED'})
        panel.run.assert_not_called()

    def test_strict_guard_does_not_claim_quic_protection(self):
        with patch.object(panel, 'quic_enabled', return_value=True), patch.object(panel, 'endpoint_capabilities', return_value={'prefix':True}):
            panel.protection_operation('prepare', {'confirm':'CONFIRMED'})
            with self.assertRaisesRegex(ValueError, 'QUIC'):
                panel.protection_operation('enforce', {'confirm':'CONFIRMED','clients_ready':'1'})
        panel.run.assert_not_called()

    def test_pinned_interface_helper_matches_source(self):
        import hashlib
        body = Path(os.environ.get('TT_INTERFACE_SOURCE', Path(__file__).parents[1] / 'trusttunnel-warp-interface.py')).read_bytes().replace(b'\r\n',b'\n')
        self.assertEqual(hashlib.sha256(body).hexdigest(), panel.INTERFACE_HELPER_SHA256)

    def test_warp_unified_mutations_require_confirmation(self):
        for backend in ('wireguard','masque','interface','interface-masque'):
            with self.assertRaises(ValueError): panel.warp_operation({'backend':backend,'operation':'rotate'})
        panel.run.assert_not_called()

    def test_release_compatibility_does_not_need_github_network(self):
        with patch.object(panel, 'RELEASE_STATE', {'checked_at':1, 'stable':{'tag_name':'v9.0.0'}, 'beta':{}}), patch.object(panel, 'endpoint_version', return_value='1.1.0'), patch.object(panel, 'endpoint_capabilities', return_value={'subscription':False,'auth_key':False,'metrics':True}), patch.object(panel, 'github_json') as github:
            result = panel.release_snapshot()
        self.assertTrue(result['update_available'])
        self.assertTrue(result['panel_update_recommended'])
        github.assert_not_called()

    def test_ping_policy_changes_only_echo_and_rolls_back(self):
        ufw = self.root / 'ufw'; ufw.mkdir()
        template = '*filter\n:ufw-before-input - [0:0]\n-A ufw-before-input -i lo -j ACCEPT\nCOMMIT\n'
        for name in ('before.rules','before6.rules'): (ufw/name).write_text(template)
        with patch.object(panel, 'UFW_DIR', ufw):
            panel.run.return_value = (0,'Status: active')
            panel.configure_echo_policy({'enabled':'0','confirm':'CONFIRMED'})
            text = (ufw/'before6.rules').read_text()
            self.assertIn('--icmpv6-type echo-request',text)
            self.assertNotIn('DROP\n-A ufw-before-input -p ipv6-icmp',text)
            self.assertIn('! -i lo',text)
            panel.configure_echo_policy({'enabled':'1','confirm':'CONFIRMED'})
            self.assertEqual((ufw/'before.rules').read_text(),template)
            panel.run.side_effect = [(0,'Status: active'),(0,'valid'),(1,'invalid ipv6'),(0,'restored')]
            with self.assertRaises(ValueError):panel.configure_echo_policy({'enabled':'0','confirm':'CONFIRMED'})
            self.assertEqual((ufw/'before.rules').read_text(),template)

    def test_schedule_validation_confirmation_and_no_missed_reboot(self):
        with patch.object(panel, 'SCHEDULE_DIR', self.root):
            for values in ({'kind':'reboot'}, {'kind':'reboot','confirm':'CONFIRMED','time':'03:30\nExecStart=bad'}, {'kind':'packages','confirm':'CONFIRMED'}):
                with self.assertRaises(ValueError):panel.schedule_operation('save',values)
            panel.run.assert_not_called()
            panel.schedule_operation('save',{'kind':'reboot','confirm':'CONFIRMED','day':'Sun','time':'04:15'})
            text = (self.root/'trusttunnel-scheduled-reboot.timer').read_text()
            self.assertIn('OnCalendar=Sun *-*-* 04:15:00',text)
            self.assertIn('Persistent=false',text)
            self.assertNotIn('OnBootSec',text)
            panel.schedule_operation('disable',{'kind':'reboot','confirm':'CONFIRMED'})
            self.assertEqual(panel.run.call_args.args[0],['systemctl','disable','--now','trusttunnel-scheduled-reboot.timer'])

    def test_panel_firewall_never_deletes_an_unowned_rule(self):
        panel.run.return_value = (0,'Status: active\n8088/tcp ALLOW Anywhere # User-owned rule')
        panel.panel_firewall(False,'8088')
        self.assertEqual(panel.run.call_count,1)
        panel.run.reset_mock()
        panel.run.return_value = (0,'Status: active\n8088/tcp ALLOW Anywhere # TrustTunnel Panel HTTPS')
        panel.panel_firewall(False,'8088')
        self.assertEqual(panel.run.call_args.args[0],['ufw','--force','delete','allow','8088/tcp'])

    def test_atomic_writer_supports_private_executable_mode(self):
        path=self.root/'helper'
        panel.atomic_write(path,'#!/bin/sh\nexit 0\n',0o700)
        self.assertEqual(path.read_text(),'#!/bin/sh\nexit 0\n')

    def test_fail2ban_readiness_retries_then_reports_failure(self):
        with patch.object(panel.time,'sleep') as pause:
            panel.run.side_effect=[(1,'not ready'),(0,'Server replied: pong')]
            panel.wait_fail2ban()
            pause.assert_called_once()
            panel.run.side_effect=None;panel.run.return_value=(1,'not ready')
            with self.assertRaises(RuntimeError):panel.wait_fail2ban()


class LinkTests(unittest.TestCase):
    # Fixed independent bytes: format v1, hostname, address, username, password.
    PAYLOAD = b'\x00\x01\x01\x01\x0bexample.org\x02\x0fexample.org:443\x05\x05alice\x06\x0cpassword1234'
    LINK = 'tt://?' + base64.urlsafe_b64encode(PAYLOAD).rstrip(b'=').decode()

    def test_exporter_hint_and_ansi_are_not_in_uri(self):
        noisy = '\x1b[32m' + self.LINK + '\x1b[0m\n\nScan QR: https://trusttunnel.org/qr.html#tt=unrelated\n'
        self.assertEqual(panel.clean_deeplink(noisy), self.LINK)

    def test_corrupt_payload_and_ambiguous_output_are_rejected(self):
        for value in ('tt://?garbage', self.LINK + '\n' + self.LINK, self.LINK[:-4], 'tt://?AAAA'):
            with self.assertRaises(ValueError):
                panel.clean_deeplink(value)

    def test_multi_byte_length_and_unknown_tags(self):
        value = b'x' * 300
        raw = self.PAYLOAD + b'\x3f\x41\x2c' + value
        uri = 'tt://?' + base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
        self.assertEqual(panel.link_fields(uri)[-1], (63, value))

    def test_deeplink_protocol_and_cache_invalidate_after_certificate_change(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root / 'certs').mkdir()
            cert = root / 'certs/cert.pem'; cert.write_text('old certificate')
            with patch.object(panel, 'TT_DIR', root), patch.object(panel, 'CLIENT_DIR', root), \
                 patch.object(panel, 'load_clients', return_value=[{'username':'alice'}]), \
                 patch.object(panel, 'domain', return_value='example.org'), patch.object(panel, 'endpoint_port', return_value='443'), \
                 patch.object(panel, 'dns_upstreams', return_value=['1.1.1.1']), patch.object(panel, 'quic_enabled', return_value=True), \
                 patch.object(panel, 'client_anti_dpi_enabled', return_value=False), \
                 patch.object(panel, 'run', return_value=(0, self.LINK + '\nScan QR here')) as exporter:
                panel.DEEPLINK_CACHE.clear()
                h2 = panel.deeplink('alice', 'http2')
                h3 = panel.deeplink('alice', 'http3')
                self.assertEqual(dict(panel.link_fields(h2))[9], b'\x01')
                self.assertEqual(dict(panel.link_fields(h3))[9], b'\x02')
                panel.deeplink('alice', 'http2')
                self.assertEqual(exporter.call_count, 2)
                cert.write_text('renewed certificate data')
                panel.deeplink('alice', 'http2')
                self.assertEqual(exporter.call_count, 3)

    def test_qr_process_failure_is_not_reported_as_png(self):
        with patch.object(panel.shutil, 'which', return_value='/usr/bin/qrencode'), \
             patch.object(panel.subprocess, 'run', return_value=type('Result', (), {'returncode':1, 'stdout':b'', 'stderr':b'large'})()):
            with self.assertRaises(ValueError):
                panel.qr_image(self.LINK)


if __name__ == '__main__': unittest.main()

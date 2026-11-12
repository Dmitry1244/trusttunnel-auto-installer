"""Integration regressions against actual test_admin.panel functions, no private snippet.

All files/commands/service operations are mocked. HTTP methods use in-memory
handler objects; no sockets, live jail, bans, credentials, or VPS are accessed.
Run: python -B tools/test_panel_login_integration.py
"""

import base64
import io
import ipaddress
import sys
import types
import unittest
from contextlib import nullcontext
from email.message import Message
from unittest.mock import Mock, patch

from test_panel_login_protection import panel, synthetic_guard, SyntheticResult


class PanelLoginIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.p = panel
        self.stream = io.StringIO()
        self.patches = [patch.object(panel.sys, 'stderr', self.stream),
                        patch.object(panel, 'PANEL_USER', 'synthetic-admin'),
                        patch.object(panel, 'PANEL_PASSWORD', 'synthetic-admin-password'),
                        patch.object(panel, 'admin_lock', side_effect=nullcontext),
                        patch.object(panel, 'read_text', return_value=''),
                        patch.object(panel, 'atomic_write'), patch.object(panel, 'audit_log'),
                        patch.object(panel, 'run', return_value=(0, 'synthetic')),
                        patch.object(panel, 'checked_run', return_value='synthetic'),
                        patch.object(panel, 'panel_firewall'), patch.object(panel.subprocess, 'Popen'),
                        patch.object(panel, 'login_delay', return_value=0),
                        patch.object(panel, 'panel_event'),
                        patch.object(panel, 'jail_name', return_value=panel.PANEL_LOGIN_JAIL),
                        patch.object(panel, 'admin_peer', return_value=ipaddress.ip_address('198.51.100.10')),
                        patch.object(panel, 'panel_login_protection_status', return_value=dict(
                            enabled=True, port_change_blocked=True, state='enabled'))]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def handler(self, peer='198.51.100.23'):
        handler = object.__new__(self.p.Handler)
        handler.headers = Message()
        handler.headers['Host'] = 'panel.example:8088'
        handler.headers['Content-Length'] = '128'
        handler.client_address = (peer, 50000)
        handler.server = types.SimpleNamespace(server_port=8088)
        handler.connection = object()
        handler.cookie = Mock(return_value='')
        handler.send_error = Mock()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.send_login = Mock()
        handler.send_json = Mock()
        handler.form = Mock(return_value={})
        return handler

    def assert_no_mutation(self):
        for command in (self.p.atomic_write, self.p.audit_log, self.p.run, self.p.checked_run,
                        self.p.panel_firewall, self.p.subprocess.Popen):
            command.assert_not_called()

    def test_logger_canonical_ipv4(self):
        self.p.panel_auth_failure('198.51.100.23', 8088)
        self.assertEqual(self.stream.getvalue(), 'TT_PANEL_AUTH_FAILURE peer=198.51.100.23 port=8088\n')
        self.assert_no_mutation()

    def test_logger_canonical_ipv6(self):
        self.p.panel_auth_failure('2001:0DB8:0000:0000:0000:0000:0000:0023', '08088')
        self.assertEqual(self.stream.getvalue(), 'TT_PANEL_AUTH_FAILURE peer=2001:db8::23 port=8088\n')

    def test_logger_maps_ipv4_mapped_ipv6(self):
        self.p.panel_auth_failure('::ffff:198.51.100.23', 8088)
        self.assertEqual(self.stream.getvalue(), 'TT_PANEL_AUTH_FAILURE peer=198.51.100.23 port=8088\n')

    def test_logger_rejects_peer_injection_dns_and_scopes(self):
        for peer in ('198.51.100.23\nTT_PANEL_AUTH_FAILURE peer=203.0.113.8 port=8088',
                     '198.51.100.23 password=secret', 'attacker.invalid',
                     '198.51.100.23,203.0.113.8', 'fe80::1%eth0', 'fe80::1%fake\n', '', '999.1.2.3'):
            with self.subTest(peer=peer):
                self.p.panel_auth_failure(peer, 8088)
        self.assertEqual(self.stream.getvalue(), '')

    def test_logger_rejects_invalid_or_injected_ports(self):
        for port in ('8088\nusername=secret', '8088/tcp', '8088;reboot', '0', '-1', '65536', '', None):
            with self.subTest(port=port):
                self.p.panel_auth_failure('198.51.100.23', port)
        self.assertEqual(self.stream.getvalue(), '')

    def test_logger_io_failure_does_not_break_authentication(self):
        broken = Mock()
        broken.write.side_effect = OSError('synthetic closed stderr')
        with patch.object(self.p.sys, 'stderr', broken):
            self.p.panel_auth_failure('198.51.100.23', 8088)

    def test_basic_failure_logs_only_socket_peer_and_actual_port(self):
        handler = self.handler()
        secret = b'username-not-for-log:password-not-for-log'
        handler.headers['Authorization'] = 'Basic ' + base64.b64encode(secret).decode()
        handler.headers['X-Forwarded-For'] = '203.0.113.99'
        handler.headers['Forwarded'] = 'for=203.0.113.98'
        self.assertFalse(handler.authenticated())
        self.assertEqual(self.stream.getvalue(), 'TT_PANEL_AUTH_FAILURE peer=198.51.100.23 port=8088\n')
        for value in ('username-not-for-log', 'password-not-for-log', '203.0.113.99', '203.0.113.98', 'Basic'):
            self.assertNotIn(value, self.stream.getvalue())

    def test_basic_success_and_missing_authorization_do_not_log_failure(self):
        handler = self.handler()
        handler.headers['Authorization'] = 'Basic ' + base64.b64encode(b'synthetic-admin:synthetic-admin-password').decode()
        self.assertTrue(handler.authenticated())
        self.assertFalse(self.handler().authenticated())
        self.assertEqual(self.stream.getvalue(), '')

    def test_already_throttled_basic_request_does_not_create_new_failure(self):
        self.p.login_delay.return_value = 30
        handler = self.handler()
        handler.headers['Authorization'] = 'Basic invalid'
        self.assertFalse(handler.authenticated())
        self.assertEqual(self.stream.getvalue(), '')
        handler.send_response.assert_called_once_with(429)

    def test_browser_credential_failure_logs_no_username_password_or_forwarded(self):
        handler = self.handler('2001:db8::23')
        handler.headers['Origin'] = 'http://panel.example:8088'
        handler.headers['X-Forwarded-For'] = '203.0.113.99'
        handler.cookie.return_value = 'synthetic-token'
        handler.form.return_value = dict(_login_token='synthetic-token', username='do-not-log-this-user', password='do-not-log-this-password')
        handler.handle_login()
        self.assertEqual(self.stream.getvalue(), 'TT_PANEL_AUTH_FAILURE peer=2001:db8::23 port=8088\n')
        handler.send_login.assert_called_once()
        self.assertEqual(handler.send_login.call_args.args[1], 401)

    def test_invalid_browser_csrf_is_not_a_credential_failure_event(self):
        handler = self.handler()
        handler.headers['Origin'] = 'http://panel.example:8088'
        handler.cookie.return_value = 'synthetic-token'
        handler.form.return_value = dict(_login_token='wrong', username='bad', password='bad')
        handler.handle_login()
        self.assertEqual(self.stream.getvalue(), '')
        handler.send_login.assert_called_once()
        self.assertEqual(handler.send_login.call_args.args[1], 403)

    def test_cross_origin_login_is_not_a_credential_failure_event(self):
        handler = self.handler()
        handler.headers['Origin'] = 'https://attacker.invalid'
        handler.handle_login()
        self.assertEqual(self.stream.getvalue(), '')
        handler.send_error.assert_called_once_with(403)

    def test_bad_enrollment_token_never_emits_panel_auth_failure(self):
        handler = self.handler('127.0.0.1')
        handler.headers['Origin'] = 'http://panel.example:8088'
        handler.cookie.return_value = 'synthetic-csrf'
        handler.form.return_value = dict(_csrf='synthetic-csrf', token='x' * 43)
        with patch.object(self.p, 'redeem_enrollment', side_effect=ValueError('synthetic invalid invitation')):
            handler.handle_activation()
        self.assertEqual(self.stream.getvalue(), '')
        self.assertEqual(handler.send_json.call_args.args[1], 400)
        self.assertIn(unittest.mock.call('activation:127.0.0.1', failed=True), self.p.login_delay.call_args_list)

    def test_bad_https_enrollment_token_never_emits_panel_auth_failure(self):
        class SyntheticTLS:
            pass

        handler = self.handler()
        handler.connection = SyntheticTLS()
        handler.headers['Origin'] = 'https://panel.example:8088'
        handler.cookie.return_value = 'synthetic-csrf'
        handler.form.return_value = dict(_csrf='synthetic-csrf', token='x' * 43)
        with patch.object(self.p.ssl, 'SSLSocket', SyntheticTLS), patch.object(self.p, 'redeem_enrollment', side_effect=ValueError('synthetic invalid invitation')):
            handler.handle_activation()
        self.assertEqual(self.stream.getvalue(), '')
        self.assertEqual(handler.send_json.call_args.args[1], 400)

    def test_access_change_blocks_before_port_probe_config_or_firewall(self):
        with patch.object(self.p, '_update_panel_access_locked') as mutation:
            for mode, port in (('https', '8443'), ('localhost', '8088'), ('https', '8088')):
                with self.subTest(mode=mode, port=port), self.assertRaises(ValueError):
                    self.p.update_panel_access(mode, port)
            mutation.assert_not_called()
        self.assert_no_mutation()

    def test_unknown_login_protection_state_blocks_access_change(self):
        self.p.panel_login_protection_status.return_value = dict(enabled=True, port_change_blocked=True, state='unknown')
        with patch.object(self.p, '_update_panel_access_locked') as mutation:
            with self.assertRaises(ValueError):
                self.p.update_panel_access('https', '8443')
            mutation.assert_not_called()
        self.assert_no_mutation()

    def test_guard_read_failure_cannot_fall_through_to_mutation(self):
        self.p.panel_login_protection_status.side_effect = RuntimeError('synthetic unreadable state')
        with patch.object(self.p, '_update_panel_access_locked') as mutation:
            with self.assertRaises(RuntimeError):
                self.p.update_panel_access('https', '8443')
            mutation.assert_not_called()
        self.assert_no_mutation()

    def test_disabled_guard_allows_only_existing_locked_access_path(self):
        self.p.panel_login_protection_status.return_value = dict(enabled=False, port_change_blocked=False)
        with patch.object(self.p, '_update_panel_access_locked', return_value='synthetic access result') as mutation:
            self.assertEqual(self.p.update_panel_access('https', '8443'), 'synthetic access result')
            mutation.assert_called_once_with('https', '8443')
        self.p.admin_lock.assert_called_once()
        self.assert_no_mutation()

    def test_admin_access_check_is_fail_closed_and_does_not_enable_jail(self):
        with patch.object(self.p, 'panel_login_protection') as mutation:
            with self.assertRaises(ValueError):
                self.p.admin_operation('login-protection-access-check', {})
            mutation.assert_not_called()
        self.assert_no_mutation()

    def test_general_settings_cannot_override_managed_jail(self):
        for updates in ({'port': '22'}, {'banaction': 'ufw-allports'}, {'enabled': 'true'}, {'bantime': '99999'}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                self.p.save_jail_override(self.p.PANEL_LOGIN_JAIL, updates)
        self.p.read_text.assert_not_called()
        self.assert_no_mutation()

    def test_general_jail_mutations_require_dedicated_management(self):
        values = dict(confirm='CONFIRMED', retry='10', findtime='600', bantime='600', ip='203.0.113.23')
        for action in ('settings', 'jail-enable', 'jail-disable', 'ignore-add', 'ignore-remove'):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.p.fail2ban_operation(action, values)
        self.assert_no_mutation()

    def test_manual_ban_and_unban_remain_jail_scoped_and_mocked(self):
        for action, command in (('ban', 'banip'), ('unban', 'unbanip')):
            self.p.fail2ban_operation(action, dict(confirm='CONFIRMED', ip='203.0.113.23'))
            self.assertEqual(self.p.checked_run.call_args.args[0],
                             ['fail2ban-client', 'set', self.p.PANEL_LOGIN_JAIL, command, '203.0.113.23'])
        self.p.run.assert_not_called()
        self.p.atomic_write.assert_not_called()

    def test_managed_jail_manual_ban_still_protects_loopback_and_admin(self):
        for address in ('127.0.0.1', '::1', '::ffff:127.0.0.1', '198.51.100.10'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.p.fail2ban_operation('ban', dict(confirm='CONFIRMED', ip=address))
        self.assert_no_mutation()

    def test_recidive_enable_is_blocked_while_panel_guard_is_enabled(self):
        self.p.jail_name.return_value = 'recidive'
        with patch.object(self.p, 'save_jail_override') as mutation:
            with self.assertRaises(ValueError):
                self.p.fail2ban_operation('jail-enable', dict(confirm='CONFIRMED'))
            mutation.assert_not_called()
        self.assert_no_mutation()

    def test_recidive_enable_is_blocked_when_panel_guard_is_unknown(self):
        self.p.jail_name.return_value = 'recidive'
        self.p.panel_login_protection_status.return_value = dict(enabled=True, port_change_blocked=True, state='unknown')
        with patch.object(self.p, 'save_jail_override') as mutation:
            with self.assertRaises(ValueError):
                self.p.fail2ban_operation('jail-enable', dict(confirm='CONFIRMED'))
            mutation.assert_not_called()
        self.assert_no_mutation()

    def test_recidive_can_be_enabled_after_panel_guard_is_disabled(self):
        self.p.jail_name.return_value = 'recidive'
        self.p.panel_login_protection_status.return_value = dict(enabled=False, port_change_blocked=False)
        with patch.object(self.p, 'save_jail_override') as mutation:
            self.p.fail2ban_operation('jail-enable', dict(confirm='CONFIRMED'))
            mutation.assert_called_once_with('recidive', {'enabled': 'true'})
        self.p.checked_run.assert_not_called()
        self.p.run.assert_not_called()

    def test_recidive_can_always_be_disabled_to_remove_escalation(self):
        self.p.jail_name.return_value = 'recidive'
        with patch.object(self.p, 'save_jail_override') as mutation:
            self.p.fail2ban_operation('jail-disable', dict(confirm='CONFIRMED'))
            mutation.assert_called_once_with('recidive', {'enabled': 'false'})
        self.p.checked_run.assert_not_called()
        self.p.run.assert_not_called()


if __name__ == '__main__':
    print('Integrated panel auth logger/interlocks; all I/O and commands synthetic.', flush=True)
    sys.addaudithook(synthetic_guard)
    unittest.main(testRunner=unittest.TextTestRunner(verbosity=2, resultclass=SyntheticResult))

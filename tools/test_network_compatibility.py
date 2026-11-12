"""Synthetic network contracts; no installed configuration or network access."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import nullcontext
from unittest.mock import patch


source = os.environ.get('TT_PANEL_SOURCE') or Path(__file__).parents[1] / 'trusttunnel-panel.py'
spec = importlib.util.spec_from_file_location('network_compatibility_panel', source)
panel = importlib.util.module_from_spec(spec)
with patch.dict(os.environ, {'PANEL_USER': 'synthetic', 'PANEL_PASSWORD': ''}):
    spec.loader.exec_module(panel)


def blocked_external_io(*args, **kwargs):
    raise AssertionError('Synthetic tests forbid subprocesses and network access')


class NetworkCompatibilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='tt-network-compatibility-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.endpoint = self.root / 'endpoint'
        self.endpoint.mkdir()
        self.config = self.endpoint / 'vpn.toml'
        self.managed_rules = self.endpoint / 'rules.toml'
        self.custom_rules = self.endpoint / 'policies/custom.toml'
        self.custom_rules.parent.mkdir()
        self.settings = self.root / 'panel-settings.env'
        self.rule = {'cidr': '192.0.2.0/24', 'action': 'deny'}
        self.managed_rules.write_text(
            '[[rule]]\ncidr="192.0.2.0/24"\naction="deny"\n', encoding='utf-8')
        self.custom_rules.write_text(
            '[[rule]]\ncidr="203.0.113.0/24"\naction="deny"\n', encoding='utf-8')
        self.settings.write_text('DNS_UPSTREAMS=192.0.2.53\n', encoding='utf-8')
        self.configure()

        original_read_text = panel.read_text

        def read_synthetic(path):
            if not Path(path).resolve().is_relative_to(self.root):
                raise AssertionError('Configuration read outside synthetic fixtures')
            return original_read_text(path)

        patches = [
            patch.object(panel, 'TT_DIR', self.endpoint),
            patch.object(panel, 'CLIENT_DIR', self.root / 'exports'),
            patch.object(panel, 'PANEL_SETTINGS', self.settings),
            patch.object(panel, 'admin_lock', nullcontext),
            patch.object(panel, 'read_text', side_effect=read_synthetic),
            patch.object(panel, 'audit_log'),
            patch.object(panel, 'run', side_effect=blocked_external_io),
            patch.object(panel, 'checked_run', side_effect=blocked_external_io),
            patch.object(panel.subprocess, 'Popen', side_effect=blocked_external_io),
            patch.object(panel.socket, 'socket', side_effect=blocked_external_io),
            patch.object(panel.socket, 'create_connection', side_effect=blocked_external_io),
            patch.object(panel.socket, 'getaddrinfo', side_effect=blocked_external_io),
            patch.object(panel.urllib.request, 'urlopen', side_effect=blocked_external_io),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def configure(self, listener='0.0.0.0:8443', rules_file='rules.toml'):
        self.config.write_text(
            'listen_address = ' + json.dumps(listener) + '\n'
            'rules_file = ' + json.dumps(rules_file) + '\n'
            '[listen_protocols.http2]\n', encoding='utf-8')

    def snapshot(self):
        return {path.relative_to(self.root).as_posix(): path.read_bytes()
                for path in self.root.rglob('*') if path.is_file()}

    def test_ipv6_wildcard_listener_port(self):
        self.configure('[::]:8443')
        self.assertEqual(str(panel.endpoint_port()), '8443')

    def test_ipv6_literal_listener_port(self):
        self.configure('[2001:db8::1]:9443')
        self.assertEqual(str(panel.endpoint_port()), '9443')

    def test_ipv4_listener_ports(self):
        for listener, expected in (('0.0.0.0:8443', '8443'),
                                   ('192.0.2.1:9443', '9443'),
                                   ('127.0.0.1:443', '443')):
            with self.subTest(listener=listener):
                self.configure(listener)
                self.assertEqual(str(panel.endpoint_port()), expected)

    def test_listener_uses_actual_toml_value(self):
        self.config.write_text(
            '# listen_address = "0.0.0.0:443"\n'
            "listen_address = '[::]:8443' # synthetic listener\n",
            encoding='utf-8')
        self.assertEqual(str(panel.endpoint_port()), '8443')

    def test_malformed_listeners_are_explicitly_rejected(self):
        for listener in ('', '0.0.0.0', ':8443', '[::]:', '[::]:not-a-port',
                         '[::]:0', '0.0.0.0:65536', '2001:db8::1:9443'):
            with self.subTest(listener=listener):
                self.configure(listener)
                before = self.snapshot()
                with self.assertRaises((ValueError, RuntimeError)):
                    panel.endpoint_port()
                self.assertEqual(self.snapshot(), before)

    def test_malformed_toml_does_not_fall_back_to_443(self):
        self.config.write_text('listen_address = "[::]:8443\n', encoding='utf-8')
        with self.assertRaises((ValueError, RuntimeError)):
            panel.endpoint_port()

    def assert_dns_round_trip(self, value):
        accepted = panel.validated_dns(value)
        panel.network_operation('dns-save', {'dns': value})
        self.assertEqual(panel.dns_upstreams(), accepted,
                         'Every validated upstream must survive saving and export')

    def test_ipv6_secure_dns_urls_round_trip(self):
        for value in ('tls://[2001:db8::53]:853',
                      'quic://[2001:db8::53]:8853',
                      'https://[2001:db8::53]:443/dns-query'):
            with self.subTest(upstream=value):
                self.assert_dns_round_trip(value)

    def test_dns_url_query_round_trip(self):
        self.assert_dns_round_trip(
            'https://resolver.example.test/dns-query?profile=synthetic&mode=strict')

    def test_mixed_dns_round_trip_preserves_all_validated_upstreams(self):
        self.assert_dns_round_trip(
            '192.0.2.53,2001:db8::53,tls://[2001:db8::54]:853,'
            'https://resolver.example.test/dns-query?profile=synthetic')

    def assert_custom_rules_refused(self, configured_path):
        self.configure(rules_file=configured_path)
        fingerprint = hashlib.sha256(
            json.dumps(self.rule, sort_keys=True).encode()).hexdigest()
        operations = (
            ('routing-rule-add', {'cidr': '198.51.100.0/24', 'decision': 'deny'}),
            ('routing-rule-delete', {'index': '1', 'fingerprint': fingerprint}),
            ('routing-rule-reset', {}),
        )
        for action, values in operations:
            with self.subTest(action=action, rules_file=configured_path):
                before = self.snapshot()
                with patch.object(panel, 'apply_endpoint_file') as apply, \
                        patch.object(panel, 'atomic_write') as atomic, \
                        patch.object(panel, 'write_text') as write:
                    try:
                        with self.assertRaises((ValueError, RuntimeError)):
                            panel.network_operation(
                                action, dict(values, confirm='CONFIRMED'))
                    finally:
                        self.assertEqual(self.snapshot(), before)
                    apply.assert_not_called()
                    atomic.assert_not_called()
                    write.assert_not_called()

    def test_relative_custom_rules_path_refused_before_mutations(self):
        self.assert_custom_rules_refused('policies/custom.toml')

    def test_absolute_custom_rules_path_refused_before_mutations(self):
        self.assert_custom_rules_refused(self.custom_rules.as_posix())


if __name__ == '__main__':
    unittest.main()

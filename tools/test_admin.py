"""Regression checks for shared CLI/web operations; never use real VPS files."""
import importlib.util
import json
import os
import tempfile
import unittest
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
        (self.root / 'vpn.toml').write_text('[listen_protocols.http2]\n[forward_protocol]\ndirect={}\n')
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


if __name__ == '__main__': unittest.main()

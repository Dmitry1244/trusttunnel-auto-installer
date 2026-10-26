"""Synthetic anti-sharing safeguards; never touches installed services or identities."""
import json
from contextlib import closing, nullcontext
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from test_admin import panel


class SharingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [patch.object(panel, 'TT_DIR', self.root),
                        patch.object(panel, 'USAGE_DB', self.root/'state/usage.sqlite3'),
                        patch.object(panel, 'admin_lock', nullcontext), patch.object(panel, 'audit_log'),
                        patch.object(panel, 'domain', return_value='vpn.example.test'),
                        patch.object(panel, 'client_metrics', return_value={'available':True, 'clients':[]}),
                        patch.object(panel, 'current_panel_env', return_value={'PANEL_TLS':'1','PANEL_PORT':'8088'})]
        for item in self.patches: item.start()
        (self.root/'credentials.toml').write_text('[[client]]\nusername="alice"\npassword="synthetic-password"\n')
        panel.SNAPSHOT_CACHE.clear()
        self.values = {'username':'alice', 'confirm':'CONFIRMED'}

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()

    def sample(self, ip='192.0.2.7', now=1000, sessions=1):
        panel.record_usage([dict(username='alice', inbound=100, outbound=200, sessions=sessions, ip=ip)], 'a', now)

    def watch(self, **values):
        panel.guard_operation('watch-save', dict(self.values, **values))
        return panel.guard_state()['policies']['alice']

    def report(self, policy=None, now=1100):
        with panel.usage_database() as db:
            return panel.sharing_observations(db, 'alice', policy or panel.guard_state()['policies']['alice'], now)

    def issue(self, **values):
        response = panel.enrollment_operation('issue', dict(self.values, **values))
        return response.split('/activate#',1)[1].split('\n',1)[0]

    def test_watch_needs_confirmation_and_valid_metrics(self):
        with self.assertRaises(ValueError): panel.guard_operation('watch-save', {'username':'alice'})
        panel.client_metrics.return_value = {'available':False,'clients':[]}
        with self.assertRaises(ValueError): self.watch()

    def test_watch_bounds_and_injection_are_rejected(self):
        for values in ({'minutes':'0'}, {'minutes':'1441'}, {'minutes':'NaN'}, {'threshold':'1'},
                       {'threshold':'101'}, {'ipv6_prefix':'0'}, {'ipv6_prefix':'64;reboot'}):
            with self.subTest(values=values), self.assertRaises(ValueError): self.watch(**values)
        self.assertFalse((self.root/'client-guard.json').exists())

    def test_legacy_transport_preset_is_not_an_antisharing_action(self):
        with patch.object(panel, 'client_operation') as operation:
            with self.assertRaisesRegex(ValueError, 'не являются антишарингом'):
                panel.guard_operation('restrict', self.values)
            operation.assert_not_called()

    def test_server_capabilities_do_not_claim_unimplemented_enforcement(self):
        caps = panel.guard_capabilities()
        self.assertTrue(caps['source_watch'])
        for key in ('active_ip_limit', 'device_binding', 'source_watch_enforcement'): self.assertFalse(caps[key])

    def test_window_is_distinct_observed_networks_not_sessions(self):
        self.watch(threshold='2', minutes='5')
        self.sample(now=1000, sessions=99)
        self.sample(now=1001, ip='198.51.100.9')
        data = self.report(now=1100)
        self.assertEqual(data['observed_networks'], 2)
        self.assertTrue(data['alert']); self.assertFalse(data['enforcement'])
        self.assertIsNone(data['simultaneous_ips'])
        self.assertEqual(self.report(now=1400)['observed_networks'], 0)

    def test_inactive_samples_do_not_count_as_source_observations(self):
        policy = self.watch()
        self.sample(sessions=0)
        self.assertEqual(self.report(policy)['observed_networks'], 0)

    def test_one_ip_is_refreshed_instead_of_creating_rows_per_sample(self):
        self.watch()
        for now in (1000, 1010, 1020): self.sample(now=now)
        with panel.usage_database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM source_observations').fetchone()[0], 1)
        self.assertEqual(self.report()['last_sample'], 1020)

    def test_ipv4_mapped_and_native_ipv4_share_one_observation(self):
        self.watch()
        self.sample('::ffff:192.0.2.7', 1000)
        self.sample('192.0.2.7', 1010)
        self.assertEqual(self.report()['observed_networks'], 1)

    def test_ipv6_privacy_addresses_default_to_64_but_can_use_128(self):
        policy = self.watch()
        self.sample('2001:db8:1::1',1000); self.sample('2001:db8:1::2',1010)
        self.assertEqual(self.report(policy)['observed_networks'], 1)
        policy = self.watch(ipv6_prefix='128')
        self.assertEqual(self.report(policy)['observed_networks'], 2)

    def test_observations_expire_and_are_bounded_per_account(self):
        self.watch()
        for i in range(260): self.sample('198.18.'+str(i//256)+'.'+str(i%256), 1000+i)
        with panel.usage_database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM source_observations').fetchone()[0], 256)
        self.sample(now=90000)
        with panel.usage_database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM source_observations').fetchone()[0], 1)

    def test_watch_never_auto_bans_or_revokes_a_changed_ip(self):
        self.watch(threshold='2')
        self.sample(); self.sample('198.51.100.9',1010)
        with patch.object(panel, 'load_clients', return_value=[{'username':'alice'}, {'username':'bob'}]), patch.object(panel,'client_operation') as operation, patch.object(panel,'run') as run:
            panel.enforce_client_policies()
            operation.assert_not_called(); run.assert_not_called()

    def test_quota_and_watch_settings_are_independent(self):
        self.watch()
        panel.guard_operation('save', dict(self.values,quota_gib='1'))
        policy = panel.guard_state()['policies']['alice']
        self.assertEqual(policy['quota_bytes'], 1073741824); self.assertTrue(policy['source_watch']['enabled'])
        panel.guard_operation('remove', self.values)
        self.assertIn('source_watch', panel.guard_state()['policies']['alice'])
        panel.guard_operation('save', dict(self.values,quota_gib='2'))
        panel.guard_operation('watch-remove', self.values)
        self.assertEqual(panel.guard_state()['policies']['alice']['quota_bytes'], 2147483648)

    def test_malformed_persisted_watch_policy_cannot_silently_enforce(self):
        (self.root/'client-guard.json').write_text(json.dumps({'policies':{'alice':{'source_watch':{'enabled':True}}}}))
        with self.assertRaises(ValueError): panel.guard_state()

    def test_invitation_source_is_not_trusted_from_the_token_or_forwarded_header(self):
        token = self.issue(source_cidr='192.0.2.7')
        with self.assertRaises(ValueError): panel.redeem_enrollment(token, '198.51.100.9')
        with panel.usage_database() as db:
            self.assertEqual(db.execute('SELECT consumed FROM enrollment').fetchone()[0], 0)
        with patch.object(panel,'deeplink',return_value='tt://?synthetic'),patch.object(panel,'qr_image',return_value=b'synthetic'):
            self.assertIn('link', panel.redeem_enrollment(token,'::ffff:192.0.2.7'))
            with self.assertRaises(ValueError): panel.redeem_enrollment(token,'192.0.2.7')

    def test_invitation_cidr_allows_only_its_network(self):
        token = self.issue(source_cidr='2001:db8:1::/64')
        for peer in ('', '2001:db8:2::1', '192.0.2.1', 'fe80::1%eth0'):
            with self.subTest(peer=peer), self.assertRaises(ValueError): panel.redeem_enrollment(token,peer)
        with patch.object(panel,'deeplink',return_value='tt://?synthetic'),patch.object(panel,'qr_image',return_value=b'synthetic'):
            self.assertIn('link', panel.redeem_enrollment(token,'2001:db8:1::123'))

    def test_invitation_rejects_broad_or_invalid_source_networks(self):
        for source in ('0.0.0.0/0', '::/0', '192.0.0.0/8', '2001:db8::/32', '1.2.3.4;id', 'fe80::1%eth0'):
            with self.subTest(source=source), self.assertRaises(ValueError): self.issue(source_cidr=source)

    def test_existing_invitation_database_migrates_without_invalidating_tokens(self):
        panel.USAGE_DB.parent.mkdir()
        with closing(sqlite3.connect(panel.USAGE_DB)) as db, db:
            db.execute('CREATE TABLE enrollment (digest TEXT PRIMARY KEY, username TEXT, protocol TEXT, kind TEXT, identity TEXT, expires REAL, consumed INTEGER)')
            db.execute('INSERT INTO enrollment VALUES (?,?,?,?,?,?,?)', ('existing','alice','http2','static','old-identity',9999999999,0))
        with panel.usage_database() as db:
            row = dict(db.execute('SELECT * FROM enrollment WHERE digest=?',('existing',)).fetchone())
            self.assertEqual(row['identity'],'old-identity')
            self.assertEqual(len(row),7)
            self.assertEqual(db.execute('SELECT count(*) FROM enrollment_sources').fetchone()[0],0)

    def test_network_restriction_cannot_be_removed_without_invalidating_invite(self):
        token = self.issue(source_cidr='192.0.2.7')
        with panel.usage_database() as db:
            saved=db.execute('SELECT identity FROM enrollment').fetchone()[0]
            self.assertNotEqual(saved,panel.enrollment_identity('alice'))
            db.execute('DELETE FROM enrollment_sources')
        with self.assertRaises(ValueError): panel.redeem_enrollment(token,'192.0.2.7')

    def test_reissuing_invitation_cleans_old_network_binding(self):
        self.issue(source_cidr='192.0.2.7'); self.issue()
        with panel.usage_database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM enrollment_sources').fetchone()[0],0)

    def test_deleting_client_removes_source_history_and_invitation_binding(self):
        self.sample(); self.issue(source_cidr='192.0.2.7')
        with (self.root/'credentials.toml').open('a') as stream:
            stream.write('\n[[client]]\nusername="bob"\npassword="synthetic-password-bob"\n')
        exports=self.root/'exports'; exports.mkdir()
        with patch.object(panel,'CLIENT_DIR',exports),patch.object(panel,'run',return_value=(0,'')),patch.object(panel,'service_status',return_value='active'),patch.object(panel,'refresh_client_archive'):
            panel.client_operation('delete',{'username':'alice'})
        with panel.usage_database() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM source_observations').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM enrollment_sources').fetchone()[0],0)


if __name__ == '__main__': unittest.main()

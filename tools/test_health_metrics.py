"""Synthetic accounting, health and passive panel-event regressions."""
import datetime
import json
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from test_admin import panel


class HealthMetricsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [patch.object(panel, 'USAGE_DB', self.root/'usage.sqlite3'),
                        patch.object(panel, 'TT_DIR', self.root),
                        patch.object(panel, 'admin_lock', nullcontext),
                        patch.object(panel, 'current_warp_backend', return_value=''),
                        patch.object(panel, 'primary_interface', return_value='ens3'),
                        patch.object(panel, 'read_text', return_value='synthetic-boot')]
        for item in self.patches: item.start()
        panel.SNAPSHOT_CACHE.clear()
        panel.HEALTH_LAST.clear()
        panel.PANEL_EVENTS.clear()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        panel.SNAPSHOT_CACHE.clear()
        panel.HEALTH_LAST.clear()
        panel.PANEL_EVENTS.clear()
        self.temp.cleanup()

    @staticmethod
    def stats(**values):
        return dict(dict(cpu_percent=12, memory_percent=25, disk_percent=30,
                         services={'trusttunnel':'active', 'warp-interface':'active',
                                   'warp-wireproxy':'inactive', 'warp-masque':'inactive'},
                         interfaces={'ens3':{'rx':1000, 'tx':2000}}), **values)

    @staticmethod
    def row(inbound=100, outbound=200, sessions=1):
        return dict(username='alice', inbound=inbound, outbound=outbound,
                    sessions=sessions, ip='192.0.2.7')

    def test_client_directions_normalized_without_migrating_legacy_database(self):
        panel.record_usage([self.row()], 'a'*32, 1000)
        with patch.object(panel, 'fetch_client_metrics', return_value={'available':False,'clients':[]}), \
             patch.object(panel, 'run', return_value=(0,'a'*32)), \
             patch.object(panel, 'client_inventory', return_value=[dict(username='alice',enabled=True)]), \
             patch.object(panel, 'guard_state', return_value={'policies':{}}):
            data = panel.client_metrics()
        client = data['clients'][0]
        self.assertEqual((client['download'], client['upload'], client['total_bytes']), (100,200,300))
        self.assertIsNone(client['active_ip_count'])
        self.assertIsNone(client['online'])
        self.assertEqual(client['last_observed_ip'],'192.0.2.7')
        with panel.usage_database() as db:
            raw = db.execute('SELECT upload,download FROM usage').fetchone()
        self.assertEqual(tuple(raw), (100,200))

    def test_rate_requires_two_monotonic_same_epoch_samples(self):
        self.assertIsNone(panel.record_usage([self.row()], 'a',1000)['alice'])
        rate=panel.record_usage([self.row(1100,700)],'a',1010)['alice']
        self.assertEqual(rate, dict(download=100,upload=50))
        self.assertIsNone(panel.record_usage([self.row(10,20)],'b',1020)['alice'])
        self.assertIsNone(panel.record_usage([self.row(50,70)],'b',1400)['alice'])

    def test_offline_is_zero_ips_but_online_is_not_claimed_as_one(self):
        for sessions in (0,3):
            panel.SNAPSHOT_CACHE.clear()
            with patch.object(panel, 'fetch_client_metrics', return_value={'available':True,'clients':[self.row(sessions=sessions)]}), \
                 patch.object(panel, 'run', return_value=(0,'a'*32)), \
                 patch.object(panel, 'client_inventory', return_value=[dict(username='alice',enabled=True)]), \
                 patch.object(panel, 'guard_state', return_value={'policies':{}}):
                item=panel.client_metrics()['clients'][0]
            self.assertEqual(item['active_ip_count'],0 if sessions==0 else None)
            self.assertEqual(item['online'],bool(sessions))

    def test_offline_sample_keeps_last_observed_ip_without_claiming_it_current(self):
        panel.record_usage([self.row()], 'a'*32,1000)
        with patch.object(panel,'fetch_client_metrics',return_value={'available':True,'clients':[dict(self.row(sessions=0),ip='')]}), \
             patch.object(panel,'run',return_value=(0,'a'*32)), \
             patch.object(panel,'client_inventory',return_value=[dict(username='alice',enabled=True)]), \
             patch.object(panel,'guard_state',return_value={'policies':{}}):
            item=panel.client_metrics()['clients'][0]
        self.assertEqual(item['last_observed_ip'],'192.0.2.7')
        self.assertEqual(item['observed_ip'],'')
        self.assertFalse(item['online'])

    def test_unused_warp_is_not_a_health_failure(self):
        state,checks=panel.health_checks(self.stats())
        self.assertEqual(state,'ok')
        self.assertFalse(any(c['id']=='warp-wireproxy' for c in checks))

    def test_selected_warp_failure_is_reported(self):
        with patch.object(panel,'current_warp_backend',return_value='wg-socks'):
            state,checks=panel.health_checks(self.stats())
        self.assertEqual(state,'error')
        self.assertTrue(any(c['id']=='warp-wireproxy' and c['state']=='error' for c in checks))

    def test_missing_numeric_resources_are_unknown_not_zero(self):
        state,_=panel.health_checks(self.stats(cpu_percent=None))
        self.assertEqual(state,'unknown')
        state,_=panel.health_checks(self.stats(memory_percent=96))
        self.assertEqual(state,'error')
        state,_=panel.health_checks(self.stats(disk_percent=88))
        self.assertEqual(state,'warn')

    def test_fresh_install_has_no_fake_success_history_or_database_creation(self):
        result=panel.health_snapshot()
        self.assertTrue(result['stale'])
        self.assertEqual(result['state'],'unknown')
        self.assertTrue(all(day['samples']==0 for day in result['history']))
        self.assertFalse(panel.USAGE_DB.exists())

    def test_stale_error_and_future_clock_are_unknown(self):
        for when,error in ((1000,''),(1999,'unavailable'),(3000,'')):
            panel.HEALTH_LAST.update(state='ok',checked_at=when,checks=[],error=error)
            panel.SNAPSHOT_CACHE.clear()
            with patch.object(panel.time,'time',return_value=2000):
                result=panel.health_snapshot()
            self.assertTrue(result['stale'])
            self.assertEqual(result['state'],'unknown')

    def test_samples_are_bounded_to_one_row_per_minute(self):
        with patch.object(panel,'monitor_snapshot',return_value=self.stats()),patch.object(panel.time,'time',return_value=2000):
            panel.health_tick()
            panel.health_tick()
        with panel.usage_database() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM health_samples').fetchone()[0],1)

    def test_history_keeps_gaps_boot_changes_and_counter_resets_unknown(self):
        with panel.usage_database() as db:
            for stamp,boot,rx,tx in ((1000,'a',100,200),(1060,'a',700,500),(1120,'b',900,600),(1400,'b',1200,700),(1460,'b',1,2)):
                db.execute('INSERT INTO health_samples VALUES (?,?,?,?,?,?,?,?,?,?)',(stamp,'ok',1,2,3,'ens3',boot,rx,tx,'[]'))
        with patch.object(panel.time,'time',return_value=1500):
            history=panel.health_snapshot()['traffic_history']
        self.assertEqual(history[0]['rx'],10)
        self.assertTrue(all(row['rx'] is None for row in history[1:]))

    def test_events_flush_once_and_do_not_store_addresses_or_secrets(self):
        with patch.object(panel,'monitor_snapshot',return_value=self.stats()),patch.object(panel.time,'time',return_value=2000):
            panel.panel_event('failures');panel.panel_event('rejected')
            panel.health_tick();panel.health_tick()
            panel.panel_event('failures')
            panel.SNAPSHOT_CACHE.clear()
            result=panel.scanner_snapshot()
            self.assertEqual(result['counts'],dict(failures=2,rejected=1,throttled=0))
            panel.health_tick()
            self.assertEqual(panel.scanner_snapshot()['counts'],result['counts'])
        with panel.usage_database() as db:
            stored=dict(db.execute('SELECT * FROM panel_event_counts').fetchone())
        self.assertEqual(set(stored),{'hour','failures','rejected','throttled'})
        self.assertIsNone(result['outbound_scans'])

    def test_database_failure_does_not_mark_events_as_flushed(self):
        panel.panel_event('throttled')
        with patch.object(panel,'monitor_snapshot',return_value=self.stats()),patch.object(panel,'usage_database',side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError): panel.health_tick()
        self.assertTrue(all(not item['flushed'] for item in panel.PANEL_EVENTS.values()))

    def test_metrics_missing_http1_requires_explicit_consent(self):
        text='[listen_protocols.http2]\n'
        with patch.object(panel,'read_text',return_value=text),patch.object(panel,'endpoint_capabilities',return_value={'metrics':True}),patch.object(panel,'apply_endpoint_file') as apply:
            with self.assertRaises(ValueError): panel.endpoint_feature_operation('endpoint-metrics',{'enabled':'1'})
            apply.assert_not_called()
            with patch.object(panel,'audit_log'):
                panel.endpoint_feature_operation('endpoint-metrics',{'enabled':'1','http1_ack':'1'})
            cfg=panel.tomllib.loads(apply.call_args.args[1])
            self.assertIn('http1',cfg['listen_protocols'])
            self.assertIn('http2',cfg['listen_protocols'])
            self.assertEqual(cfg['metrics']['address'],'127.0.0.1:1987')


if __name__ == '__main__':
    unittest.main()

"""Synthetic protection/accounting tests. Never reads real VPS credentials."""
import base64
import concurrent.futures
import datetime
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import threading
import time
from contextlib import nullcontext
from unittest.mock import patch

from test_admin import panel


class ProtectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.exports = self.root/'exports'; self.exports.mkdir()
        self.patches = [patch.object(panel,'TT_DIR',self.root), patch.object(panel,'CLIENT_DIR',self.exports),
                        patch.object(panel,'USAGE_DB',self.root/'state/usage.sqlite3'),
                        patch.object(panel,'PANEL_SETTINGS',self.root/'settings.env'),
                        patch.object(panel,'admin_lock',nullcontext), patch.object(panel,'audit_log'),
                        patch.object(panel,'domain',return_value='vpn.example.test'),
                        patch.object(panel,'service_status',return_value='active'),
                        patch.object(panel,'cert_mode',return_value='letsencrypt'),
                        patch.object(panel,'run',return_value=(0,'a'*32)),
                        patch.object(panel,'current_panel_env',return_value={'PANEL_TLS':'1','PANEL_PORT':'8088'})]
        for item in self.patches: item.start()
        (self.root/'credentials.toml').write_text('[[client]]\nusername="alice"\npassword="synthetic-password"\n')
        (self.root/'vpn.toml').write_text('listen_address="0.0.0.0:8443"\nrules_file="rules.toml"\n[listen_protocols.http2]\n')
        (self.exports/'alice-http2.toml').write_text('username="alice"\npassword="synthetic-password"\n')
        panel.SNAPSHOT_CACHE.clear(); panel.DEEPLINK_CACHE.clear()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()

    def row(self, up=100, down=200, sessions=1):
        return dict(username='alice',inbound=up,outbound=down,sessions=sessions,ip='192.0.2.7')

    def record(self):
        with panel.usage_database() as db: return dict(db.execute('SELECT * FROM usage WHERE username=?',('alice',)).fetchone())

    def issue(self):
        response = panel.enrollment_operation('issue',dict(username='alice',confirm='CONFIRMED'))
        return response.split('/activate#',1)[1].split('\n',1)[0]

    def test_counter_growth_duplicate_samples_and_endpoint_restart(self):
        panel.record_usage([self.row()], 'epoch-a',1000)
        panel.record_usage([self.row()], 'epoch-a',1015)
        panel.record_usage([self.row(160,290)], 'epoch-a',1030)
        panel.record_usage([self.row(900,1000)], 'epoch-b',1045)
        record=self.record()
        self.assertEqual((record['upload'],record['download']), (1060,1290))

    def test_counter_reset_without_epoch_is_not_subtracted(self):
        panel.record_usage([self.row()], 'a',1000)
        panel.record_usage([self.row(10,20)], 'a',1015)
        self.assertEqual((self.record()['upload'],self.record()['download']),(110,220))

    def test_baseline_is_not_claimed_as_today_traffic(self):
        panel.record_usage([self.row()], 'a',1000)
        with panel.usage_database() as db: self.assertEqual(db.execute('SELECT count(*) FROM daily').fetchone()[0],0)
        panel.record_usage([self.row(120,250)], 'a',1015)
        with panel.usage_database() as db:
            row=db.execute('SELECT * FROM daily').fetchone()
            self.assertEqual((row['upload'],row['download']),(20,50))

    def test_last_online_survives_offline_and_database_reopen(self):
        panel.record_usage([self.row()], 'a',1000)
        panel.record_usage([self.row(sessions=0)], 'a',1015)
        self.assertEqual(self.record()['last_seen'],1000)
        self.assertEqual(self.record()['upload'],100)

    def test_missing_metrics_produces_unknown_not_offline_and_keeps_totals(self):
        panel.record_usage([self.row()], 'a',1000)
        with patch.object(panel,'fetch_client_metrics',return_value={'available':False,'clients':[]}):
            data=panel.client_metrics()
        self.assertIsNone(data['clients'][0]['online'])
        self.assertEqual(data['clients'][0]['download'],200)
        self.assertEqual(data['clients'][0]['last_seen'],1000)

    def test_missing_epoch_never_guesses_accounting_continuity(self):
        panel.run.return_value=(1,'unavailable')
        with patch.object(panel,'fetch_client_metrics',return_value={'available':True,'clients':[self.row()]}):
            result=panel.client_metrics()
        self.assertTrue(result['accounting_error'])
        self.assertTrue(result['clients'][0]['online'])
        self.assertFalse(panel.USAGE_DB.exists())

    def test_metrics_reject_malformed_and_negative_values(self):
        (self.root/'vpn.toml').write_text('[metrics]\naddress="127.0.0.1:1987"\nper_client_metrics=true\n')
        for rows in ([None],[dict(self.row(),sessions=-1)],[dict(self.row(),inbound=True)],[self.row(),self.row()],[dict(self.row(),ip='not-ip')]):
            response=io.BytesIO(json.dumps(rows).encode())
            with patch.object(panel.urllib.request,'build_opener') as opener:
                opener.return_value.open.return_value.__enter__.return_value=response
                self.assertFalse(panel.fetch_client_metrics()['available'])

    def test_metrics_cannot_redirect_or_use_environment_proxy(self):
        with self.assertRaises(ValueError): panel.NoRedirect().redirect_request(None,None,302,'',{},'http://169.254.169.254/')

    def test_ip_change_does_not_disable_account(self):
        panel.record_usage([self.row()], 'a',1000)
        panel.record_usage([dict(self.row(),ip='198.51.100.9')], 'a',1015)
        self.assertEqual(self.record()['ip_changes'],1)
        with patch.object(panel,'client_metrics',return_value={'available':True,'clients':[]}), patch.object(panel,'client_operation') as operation:
            panel.enforce_client_policies(); operation.assert_not_called()

    def test_policy_requires_confirmation_metrics_and_future_expiry(self):
        with self.assertRaises(ValueError): panel.guard_operation('save',{'username':'alice'})
        with patch.object(panel,'client_metrics',return_value={'available':False,'clients':[]}):
            with self.assertRaises(ValueError): panel.guard_operation('save',dict(username='alice',confirm='CONFIRMED',quota_gib='1'))
        with self.assertRaises(ValueError): panel.guard_operation('save',dict(username='alice',confirm='CONFIRMED',expires='2000-01-01T00:00'))

    def test_monitor_mode_and_last_client_are_not_auto_suspended(self):
        (self.root/'client-guard.json').write_text(json.dumps({'policies':{'alice':{'expires_at':1,'auto_suspend':True}}}))
        with patch.object(panel,'client_metrics',return_value={'available':False,'clients':[]}),patch.object(panel,'client_operation') as operation:
            panel.enforce_client_policies(); operation.assert_not_called()
        self.assertIn('alice',panel.GUARD_STATUS['pending'])

    def test_expiry_can_revoke_without_metrics_but_quota_cannot(self):
        clients=[{'username':'alice'},{'username':'bob'}]
        policy={'policies':{'alice':{'expires_at':1,'quota_bytes':1,'auto_suspend':True}}}
        (self.root/'client-guard.json').write_text(json.dumps(policy))
        with patch.object(panel,'load_clients',return_value=clients),patch.object(panel,'client_metrics',return_value={'available':False,'clients':[]}),patch.object(panel,'client_operation') as operation:
            panel.enforce_client_policies(); operation.assert_called_once_with('disable',{'username':'alice'})
        policy['policies']['alice']['expires_at']=0
        (self.root/'client-guard.json').write_text(json.dumps(policy))
        with patch.object(panel,'load_clients',return_value=clients),patch.object(panel,'client_metrics',return_value={'available':False,'clients':[dict(username='alice',upload=100,download=100)]}),patch.object(panel,'client_operation') as operation:
            panel.enforce_client_policies(); operation.assert_not_called()

    def test_enrollment_stores_only_hash_and_redeems_once(self):
        token=self.issue()
        with panel.usage_database() as db:
            saved=dict(db.execute('SELECT * FROM enrollment').fetchone())
        self.assertNotIn(token,json.dumps(saved))
        with patch.object(panel,'deeplink',return_value='tt://?synthetic'),patch.object(panel,'qr_image',return_value=b'synthetic-image'):
            self.assertIn('link',panel.redeem_enrollment(token))
            with self.assertRaises(ValueError): panel.redeem_enrollment(token)

    def test_simultaneous_redemption_has_one_winner(self):
        token=self.issue()
        def claim():
            try: panel.redeem_enrollment(token); return True
            except ValueError: return False
        with patch.object(panel,'deeplink',return_value='tt://?synthetic'),patch.object(panel,'qr_image',return_value=b'image'),concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sum(executor.map(lambda _:claim(),range(2))),1)

    def test_password_change_expiry_and_explicit_revoke_invalidate_invitation(self):
        token=self.issue()
        (self.root/'credentials.toml').write_text('[[client]]\nusername="alice"\npassword="changed-password"\n')
        with self.assertRaises(ValueError): panel.redeem_enrollment(token)
        token=self.issue()
        with panel.usage_database() as db: db.execute('UPDATE enrollment SET expires=0')
        with self.assertRaises(ValueError): panel.redeem_enrollment(token)
        token=self.issue()
        panel.enrollment_operation('revoke',dict(username='alice',confirm='CONFIRMED'))
        with self.assertRaises(ValueError): panel.redeem_enrollment(token)

    def test_qr_failure_does_not_consume_invitation(self):
        token=self.issue()
        with patch.object(panel,'deeplink',return_value='tt://?synthetic'),patch.object(panel,'qr_image',side_effect=RuntimeError('failed')):
            with self.assertRaises(RuntimeError): panel.redeem_enrollment(token)
        with panel.usage_database() as db: self.assertEqual(db.execute('SELECT consumed FROM enrollment').fetchone()[0],0)

    def test_invitation_requires_https_and_bounded_expiry(self):
        with patch.object(panel,'current_panel_env',return_value={'PANEL_TLS':'0'}):
            with self.assertRaises(ValueError): self.issue()
        for minutes in ('0','1441','bad'):
            with self.assertRaises(ValueError): panel.enrollment_operation('issue',dict(username='alice',confirm='CONFIRMED',minutes=minutes))

    def test_tls_preparation_preserves_profiles_rules_and_credentials(self):
        before={p:p.read_bytes() for p in (self.root/'credentials.toml',self.root/'vpn.toml',self.exports/'alice-http2.toml')}
        panel.protection_operation('tls-prepare',{'confirm':'CONFIRMED'})
        self.assertEqual(len(panel.protection_state()['auth_key']),64)
        for path,body in before.items(): self.assertEqual(path.read_bytes(),body)
        self.assertFalse((self.root/'rules.toml').exists())

    def test_auth_enforcement_requires_supported_binary_client_and_no_quic(self):
        panel.protection_operation('tls-prepare',{'confirm':'CONFIRMED'})
        for capabilities,quic in (({'auth_key':False},False),({'auth_key':True},True)):
            with patch.object(panel,'endpoint_capabilities',return_value=capabilities),patch.object(panel,'quic_enabled',return_value=quic):
                with self.assertRaises(ValueError): panel.protection_operation('tls-enforce',dict(confirm='CONFIRMED',clients_ready='1',client_v13='1'))
        with patch.object(panel,'endpoint_capabilities',return_value={'auth_key':True}):
            with self.assertRaises(ValueError): panel.protection_operation('tls-enforce',dict(confirm='CONFIRMED',clients_ready='1'))

    def test_tls_rules_enforcement_preserves_denies_and_cannot_be_bypassed_by_ui(self):
        original='[[rule]]\ncidr="192.0.2.0/24"\naction="deny"\n'
        (self.root/'rules.toml').write_text(original)
        panel.protection_operation('tls-prepare',{'confirm':'CONFIRMED'})
        with patch.object(panel,'endpoint_capabilities',return_value={'auth_key':True}):
            panel.protection_operation('tls-enforce',dict(confirm='CONFIRMED',clients_ready='1',client_v13='1'))
            self.assertTrue(panel.protection_state()['tls_enabled'])
            with self.assertRaises(ValueError): panel.network_operation('routing-rule-add',{'cidr':'198.51.100.0/24'})
            panel.protection_operation('tls-disable',{'confirm':'CONFIRMED'})
        self.assertEqual((self.root/'rules.toml').read_text(),original)

    def test_auth_key_and_custom_sni_survive_profile_network_refresh(self):
        path=self.exports/'alice-http2.toml'
        path.write_text('username="alice"\npassword="synthetic-password"\nclient_random_auth_key="'+'ab'*32+'"\ncustom_sni="custom.example.test"\nfuture_setting="keep"\n')
        parsed=panel.tomllib.loads(panel.client_profile('alice','new-password','http2'))
        self.assertEqual(parsed['client_random_auth_key'],'ab'*32)
        self.assertEqual(parsed['custom_sni'],'custom.example.test')
        self.assertEqual(parsed['future_setting'],'keep')
        self.assertEqual(parsed['password'],'new-password')

    def test_staged_auth_deeplink_has_tag15_no_prefix_and_no_exporter_flag(self):
        panel.protection_operation('tls-prepare',{'confirm':'CONFIRMED'})
        fields=[(0,b'\x01'),(1,b'vpn.example.test'),(2,b'vpn.example.test:8443'),(5,b'alice'),(6,b'synthetic-password')]
        encoded=b''.join(panel.link_varint(k)+panel.link_varint(len(v))+v for k,v in fields)
        panel.run.return_value=(0,'tt://?'+base64.urlsafe_b64encode(encoded).rstrip(b'=').decode())
        link=panel.deeplink('alice','http2','tls-auth')
        result=dict(panel.link_fields(link))
        self.assertEqual(result[15].decode(),panel.protection_state()['auth_key'])
        self.assertNotIn(11,result)
        self.assertNotIn('--client-random-auth-key',panel.run.call_args.args[0])

    def test_public_metrics_can_be_disabled_not_enabled(self):
        (self.root/'vpn.toml').write_text('[metrics]\naddress="0.0.0.0:1987"\nper_client_metrics=true\n')
        with patch.object(panel,'endpoint_capabilities',return_value={'metrics':True}):
            panel.endpoint_feature_operation('endpoint-metrics',{'enabled':'0'})
        config=panel.tomllib.loads((self.root/'vpn.toml').read_text())['metrics']
        self.assertEqual(config['address'],'127.0.0.1:1987')
        self.assertFalse(config['per_client_metrics'])

    def test_diagnostic_target_is_whitelisted(self):
        with self.assertRaises(ValueError): panel.diagnostic_report('egress',{'target':'http://169.254.169.254/'})
        panel.run.assert_not_called()

    def test_security_fixes_need_confirmation_and_whitelist(self):
        for values in ({'check':'ntp'},{'confirm':'CONFIRMED','check':'shell:reboot'}):
            with self.assertRaises(ValueError): panel.security_remediate(values)
        panel.run.assert_not_called()

    def test_client_export_failure_rolls_back_live_credentials(self):
        before=(self.root/'credentials.toml').read_bytes()
        export_before=(self.exports/'alice-http2.toml').read_bytes()
        with patch.object(panel,'refresh_client_archive',side_effect=OSError('disk full')):
            with self.assertRaises(OSError): panel.client_operation('password',{'username':'alice','password':'changed-password'})
        self.assertEqual((self.root/'credentials.toml').read_bytes(),before)
        self.assertEqual((self.exports/'alice-http2.toml').read_bytes(),export_before)

    def test_service_epoch_change_during_fetch_never_charges_usage(self):
        panel.run.side_effect=[(0,'a'*32),(0,'b'*32)]
        with patch.object(panel,'fetch_client_metrics',return_value={'available':True,'clients':[self.row()]}):
            result=panel.client_metrics()
        self.assertTrue(result['accounting_error'])
        self.assertFalse(panel.USAGE_DB.exists())

    def test_older_sample_is_not_misinterpreted_as_a_counter_reset(self):
        panel.record_usage([self.row(500,600)],'a',1020)
        panel.record_usage([self.row(200,300)],'a',1015)
        self.assertEqual((self.record()['upload'],self.record()['download']),(500,600))

    def test_expiry_still_runs_when_database_collection_fails(self):
        (self.root/'client-guard.json').write_text(json.dumps({'policies':{'alice':{'expires_at':1,'auto_suspend':True}}}))
        with patch.object(panel,'load_clients',return_value=[{'username':'alice'},{'username':'bob'}]),patch.object(panel,'client_metrics',side_effect=panel.sqlite3.OperationalError('locked')),patch.object(panel,'client_operation') as operation:
            panel.enforce_client_policies(); operation.assert_called_once_with('disable',{'username':'alice'})

    def test_replacement_invitation_invalidates_previous_invitation(self):
        first=self.issue(); second=self.issue()
        with self.assertRaises(ValueError): panel.redeem_enrollment(first)
        with patch.object(panel,'deeplink',return_value='tt://?synthetic'),patch.object(panel,'qr_image',return_value=b'image'):
            self.assertIn('link',panel.redeem_enrollment(second))

    def test_account_disable_enable_does_not_resurrect_invitation(self):
        panel.client_operation('add',{'username':'bob'})
        token=self.issue()
        panel.client_operation('disable',{'username':'alice'})
        panel.client_operation('enable',{'username':'alice'})
        with self.assertRaises(ValueError): panel.redeem_enrollment(token)

    def test_invitation_can_be_revoked_while_account_disabled(self):
        panel.client_operation('add',{'username':'bob'}); self.issue()
        panel.client_operation('disable',{'username':'alice'})
        panel.enrollment_operation('revoke',{'username':'alice','confirm':'CONFIRMED'})
        with panel.usage_database() as db: self.assertEqual(db.execute('SELECT count(*) FROM enrollment').fetchone()[0],0)

    def test_missing_or_different_rules_file_cannot_claim_tls_enforcement(self):
        panel.protection_operation('tls-prepare',{'confirm':'CONFIRMED'})
        for text in ('[listen_protocols.http2]\n','rules_file="other.toml"\n[listen_protocols.http2]\n'):
            (self.root/'vpn.toml').write_text(text)
            with patch.object(panel,'endpoint_capabilities',return_value={'auth_key':True}):
                with self.assertRaises(ValueError): panel.protection_operation('tls-enforce',dict(confirm='CONFIRMED',clients_ready='1',client_v13='1'))
        self.assertFalse(panel.protection_state()['tls_enabled'])

    def test_failed_final_state_write_rolls_back_rules(self):
        panel.protection_operation('tls-prepare',{'confirm':'CONFIRMED'})
        state=(self.root/'panel-protection.json').read_bytes()
        original_write=panel.atomic_write
        def fail_final(path,text,mode=0o600):
            if Path(path).name=='panel-protection.json' and json.loads(text).get('tls_enabled') and 'transition' not in json.loads(text): raise OSError('disk full')
            original_write(path,text,mode)
        with patch.object(panel,'endpoint_capabilities',return_value={'auth_key':True}),patch.object(panel,'atomic_write',side_effect=fail_final):
            with self.assertRaises(OSError): panel.protection_operation('tls-enforce',dict(confirm='CONFIRMED',clients_ready='1',client_v13='1'))
        self.assertEqual(panel.read_text(self.root/'rules.toml'),'')
        self.assertEqual((self.root/'panel-protection.json').read_bytes(),state)

    def test_reinstall_and_downgrade_blocked_under_strict_protection(self):
        (self.root/'panel-protection.json').write_text('{"tls_enabled":true}')
        for action in ('install','update-trusttunnel'):
            with self.assertRaises(ValueError): panel.installer_operation(action,{'confirm':'REINSTALL'})
        panel.run.assert_not_called()

    def test_multiline_certificate_and_unsafe_verification_are_refreshed_safely(self):
        cert='-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n'
        (self.root/'certs').mkdir(); (self.root/'certs/cert.pem').write_text(cert)
        (self.exports/'alice-http2.toml').write_text('username="alice"\npassword="synthetic-password"\nskip_verification=true\ncertificate="""\nold\n"""\n')
        with patch.object(panel,'cert_mode',return_value='self-signed'):
            body=panel.client_profile('alice','changed-password','http2')
        parsed=panel.tomllib.loads(body)
        self.assertEqual(parsed['certificate'],cert)
        self.assertFalse(parsed['skip_verification'])

    def test_kernel_baseline_rolls_back_file_and_runtime_on_error(self):
        folder=self.root/'sysctl'; folder.mkdir()
        path=folder/'62-trusttunnel-baseline.conf'; path.write_text('# Original\n')
        calls=[]
        def run(args,**kwargs):
            calls.append(args)
            if args[:2]==['sysctl','-n']: return 0,'\n'.join('0' for _ in panel.SAFE_SYSCTLS)
            if len(calls)==3: return 1,'synthetic failure'
            return 0,'OK'
        with patch.object(panel,'SYSCTL_DIR',folder),patch.object(panel,'run',side_effect=run):
            with self.assertRaises(RuntimeError): panel.security_remediate({'confirm':'CONFIRMED','check':'kernel-baseline'})
        self.assertEqual(path.read_text(),'# Original\n')
        self.assertIn(['sysctl','-w','net.ipv4.tcp_syncookies=0'],calls)
        for key in panel.SAFE_SYSCTLS:
            self.assertNotIn('rp_filter',key)
            self.assertNotIn('forwarding',key)

    def test_protection_integrity_detects_manually_changed_rules(self):
        (self.root/'panel-protection.json').write_text(json.dumps({'tls_enabled':True,'tls_rules_hash':'wrong'}))
        (self.root/'rules.toml').write_text('[[rule]]\naction="allow"\n')
        with patch.object(panel,'endpoint_capabilities',return_value={'auth_key':True}):
            self.assertFalse(panel.protection_integrity()[0])

    def test_advanced_client_defaults_do_not_rewrite_existing_profiles(self):
        path=self.exports/'alice-http2.toml'; old=path.read_bytes()
        panel.protection_operation('client-settings',{'confirm':'CONFIRMED','dns':'https://dns.adguard-dns.com/dns-query','tls_profile':'firefox','anti_dpi':'1'})
        self.assertEqual(path.read_bytes(),old)
        self.assertEqual(panel.panel_settings()['TLS_PROFILE'],'firefox')

    def test_private_secret_patterns_are_redacted_from_logs(self):
        panel.run.return_value=(0,'client_random_auth_key=abcdef password=secret\nAuthorization: Basic abc123\nhttps://vpn.example.test:8088/activate#'+'x'*43)
        out=panel.recent_logs('trusttunnel')
        for secret in ('abcdef','secret','abc123','x'*43): self.assertNotIn(secret,out)

    def test_reapplying_configured_route_does_not_restart_vpn(self):
        with patch.object(panel,'interface_enabled',return_value=True),patch.object(panel,'read_text',side_effect=lambda p: 'wireguard' if Path(p).name=='transport' else (self.root/'vpn.toml').read_text()):
            result=panel.network_operation('routing-switch',{'mode':'interface'})
        self.assertIn('перезапуск VPN не выполнялся',result)
        panel.run.assert_not_called()

    def test_routing_picker_preselects_current_route(self):
        with patch.object(panel,'current_warp_backend',return_value='wg-interface'):
            page=panel.routing_console()
        self.assertIn('value="interface" checked',page)
        self.assertIn('data-cascade-address hidden',page)

    def test_structured_quic_detection_handles_legal_spaced_header(self):
        (self.root/'vpn.toml').write_text('rules_file="rules.toml"\n[listen_protocols . quic]\n')
        self.assertTrue(panel.quic_enabled())
        panel.protection_operation('tls-prepare',{'confirm':'CONFIRMED'})
        with patch.object(panel,'endpoint_capabilities',return_value={'auth_key':True}):
            with self.assertRaisesRegex(ValueError,'QUIC'): panel.protection_operation('tls-enforce',dict(confirm='CONFIRMED',clients_ready='1',client_v13='1'))

    def test_metrics_and_policy_use_consistent_lock_order(self):
        lock=threading.RLock(); held=threading.Event(); proceed=threading.Event(); errors=[]
        def policy():
            try:
                with lock:
                    held.set(); proceed.wait(2); panel.enforce_client_policies()
            except Exception as error: errors.append(type(error).__name__)
        def request():
            try: panel.client_metrics()
            except Exception as error: errors.append(type(error).__name__)
        with patch.object(panel,'admin_lock',side_effect=lambda:lock),patch.object(panel,'fetch_client_metrics',return_value={'available':False,'clients':[]}):
            first=threading.Thread(target=policy,daemon=True); first.start(); self.assertTrue(held.wait(2))
            second=threading.Thread(target=request,daemon=True); second.start(); time.sleep(.08); proceed.set()
            first.join(3); second.join(3)
            self.assertFalse(first.is_alive() or second.is_alive(),'Lock-order deadlock')
        self.assertFalse(errors)

    def test_backend_rule_reset_cannot_remove_strict_rules(self):
        (self.root/'panel-protection.json').write_text('{"tls_enabled":true}')
        with self.assertRaises(ValueError): panel.admin_operation('routing-rule-reset',{'confirm':'CONFIRMED'})
        self.assertFalse((self.root/'rules.toml').exists())

    def test_switch_to_trusted_certificate_removes_old_pin_not_auth_key(self):
        (self.exports/'alice-http2.toml').write_text('username="alice"\npassword="synthetic-password"\ncertificate="""\nold self-signed\n"""\nclient_random_auth_key="'+'aa'*32+'"\n')
        body=panel.tomllib.loads(panel.client_profile('alice','synthetic-password','http2'))
        self.assertNotIn('certificate',body)
        self.assertEqual(body['client_random_auth_key'],'aa'*32)


if __name__ == '__main__': unittest.main()

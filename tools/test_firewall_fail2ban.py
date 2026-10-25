"""Offline security regression tests; never touch a real firewall or jail."""
import configparser
import importlib.util
import json
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('panel',Path(__file__).parents[1]/'trusttunnel-panel.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


class SecurityAdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.patches = [patch.object(p,'UFW_DIR',self.root/'ufw'),patch.object(p,'UFW_DEFAULTS',self.root/'defaults'),
                        patch.object(p,'FIREWALL_PENDING',self.root/'state/pending.json'),
                        patch.object(p,'FAIL2BAN_DIR',self.root/'fail2ban'),
                        patch.object(p,'FAIL2BAN_OVERRIDE',self.root/'fail2ban/jail.d/zzzz-trusttunnel-panel.local'),
                        patch.object(p,'admin_lock',nullcontext),patch.object(p,'audit_log'),
                        patch.object(p,'protected_ports',return_value=[(49222,'tcp'),(8443,'tcp'),(8443,'udp'),(8088,'tcp')]),
                        patch.object(p,'service_status',return_value='active'),patch.object(p,'run',side_effect=self.command)]
        for item in self.patches: item.start()
        p.SNAPSHOT_CACHE.clear()
        self.commands=[]
        self.numbered='Status: active\n[ 1] 49222/tcp                 ALLOW IN    Anywhere\n[ 2] 9000/tcp                  ALLOW IN    192.0.2.0/24\n[ 3] 9000/tcp (v6)             ALLOW IN    Anywhere (v6)\n'
        self.added='ufw allow 49222/tcp\nufw allow from 192.0.2.0/24 to any port 9000 proto tcp\n'
        for path in p.firewall_files().values():
            path.parent.mkdir(parents=True,exist_ok=True); path.write_text('original '+path.name+'\n')
        (p.FAIL2BAN_DIR/'jail.d').mkdir(parents=True)
        (p.FAIL2BAN_DIR/'jail.conf').write_text('[DEFAULT]\n[sshd]\n[nginx-http-auth]\n')
        self.values={'confirm':'CONFIRMED','_peer':'198.51.100.8'}

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        p.SNAPSHOT_CACHE.clear(); self.tmp.cleanup()

    def command(self,args,**kwargs):
        self.commands.append(args)
        if args == ['systemctl','is-active','--quiet','trusttunnel-cert-renew.service']: return 3,'inactive'
        if args == ['ufw','status']: return 0,'Status: active'
        if args == ['ufw','status','verbose']: return 0,'Status: active\nDefault: deny (incoming), allow (outgoing)'
        if args == ['ufw','status','numbered']: return 0,self.numbered
        if args == ['ufw','show','added']: return 0,self.added
        if args == ['fail2ban-client','status']: return 0,'Status\n|- Number of jail: 2\n`- Jail list: sshd, nginx-http-auth'
        if args[-1:] == ['ignoreip']: return 0,'These IP addresses/networks are ignored:\n|- 127.0.0.1/8\n|- ::1\n`- 198.51.100.8'
        return 0,'OK'

    def test_all_mutations_require_confirmation_before_commands(self):
        for action in ('rule','delete','enable','baseline','disable','reload','default','logging','install','source-block'):
            with self.subTest(action=action),self.assertRaises(ValueError): p.firewall_operation(action,{})
        for action in ('install','enable','disable','restart','reload','ban','unban','settings','jail-enable','jail-disable','ignore-add','ignore-remove'):
            with self.subTest(action=action),self.assertRaises(ValueError): p.fail2ban_operation(action,{})
        self.assertFalse(any(cmd[0] in ('apt-get','systemctl','ufw') for cmd in self.commands))

    def test_rule_ipv4_range_and_order(self):
        args=p.firewall_rule(dict(port='10000:10100',source='192.0.2.3/24',position='prepend',comment='QA'))
        self.assertEqual(args,['ufw','prepend','allow','in','proto','tcp','from','192.0.2.0/24','to','any','port','10000:10100','comment','QA'])

    def test_ipv6_outbound_rule(self):
        args=p.firewall_rule(dict(port='9000',decision='reject',direction='out',proto='udp',destination='2001:db8::1',interface='eth0'))
        self.assertIn('2001:db8::1/128',args); self.assertIn('eth0',args)

    def test_rule_input_injection_and_invalid_combinations(self):
        for values in (dict(port='80;id'),dict(port='0'),dict(port='65536'),dict(port='100:50'),dict(port='90',decision='reset'),
                       dict(port='90',source='any;id'),dict(port='90',interface='--help'),dict(port='90',comment='a\nb'),dict(port='90',comment="Let's Encrypt"),
                       dict(port='90',proto='udp',decision='limit'),dict(port='90',source='::1',destination='192.0.2.1'),
                       dict(port='90',position='insert 1')):
            with self.subTest(values=values),self.assertRaises(ValueError): p.firewall_rule(values)

    def test_protected_port_denies_and_ranges_rejected(self):
        for port in ('49222','8443','8088','8000:9000'):
            with self.subTest(port=port),self.assertRaises(ValueError): p.firewall_rule(dict(port=port,decision='deny'))

    def test_preview_never_arms_timer_or_writes_state(self):
        p.firewall_operation('preview',{'port':'9000'})
        self.assertEqual(self.commands[-1][0:2],['ufw','--dry-run'])
        self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_timer_is_armed_before_mutation_and_second_change_is_blocked(self):
        result=p.firewall_operation('rule',dict(self.values,port='9000'))
        timer=next(i for i,c in enumerate(self.commands) if c[0]=='systemd-run')
        mutation=next(i for i,c in enumerate(self.commands) if c[:2]==['ufw','allow'])
        self.assertLess(timer,mutation); self.assertIn('120',result)
        self.assertIn('--on-active=120s',self.commands[timer]); self.assertTrue(p.firewall_pending())
        with self.assertRaises(ValueError): p.firewall_operation('reload',self.values)

    def test_timer_failure_does_not_modify_ufw(self):
        real=self.command
        p.run.side_effect=lambda args,**kw: (1,'systemd unavailable') if args[0]=='systemd-run' else real(args,**kw)
        with self.assertRaises(RuntimeError): p.firewall_operation('disable',self.values)
        self.assertNotIn(['ufw','--force','disable'],self.commands)
        self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_active_acme_service_blocks_firewall_transaction(self):
        real=self.command
        p.run.side_effect=lambda args,**kw: (0,'') if args == ['systemctl','is-active','--quiet','trusttunnel-cert-renew.service'] else real(args,**kw)
        with self.assertRaises(ValueError): p.firewall_operation('reload',self.values)
        self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_rollback_restores_bytes_and_is_idempotent(self):
        before={path:path.read_bytes() for path in p.firewall_files().values()}
        p.firewall_operation('reload',self.values); token=p.firewall_pending()['token']
        for path in before: path.write_text('modified')
        p.firewall_rollback(token)
        for path,data in before.items(): self.assertEqual(path.read_bytes(),data)
        self.assertFalse(p.FIREWALL_PENDING.exists()); self.assertIn('нет',p.firewall_rollback(token))

    def test_partial_failure_restores_immediately(self):
        def command(args,**kwargs):
            if args[:2]==['ufw','logging']:
                (p.UFW_DIR/'ufw.conf').write_text('modified'); return 1,'failed'
            return self.command(args,**kwargs)
        p.run.side_effect=command
        before=(p.UFW_DIR/'ufw.conf').read_bytes()
        with self.assertRaises(RuntimeError): p.firewall_operation('logging',dict(self.values,level='low'))
        self.assertEqual((p.UFW_DIR/'ufw.conf').read_bytes(),before)
        self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_confirmation_stops_timer_and_wrong_token_does_not(self):
        p.firewall_operation('reload',self.values); pending=p.firewall_pending()
        with self.assertRaises(ValueError): p.firewall_operation('confirm',dict(self.values,token='wrong'))
        self.assertTrue(p.FIREWALL_PENDING.exists())
        p.firewall_operation('confirm',dict(self.values,token=pending['token']))
        self.assertIn(['systemctl','stop',pending['unit']+'.timer'],self.commands)
        self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_expired_confirmation_rolls_back(self):
        p.firewall_operation('reload',self.values); pending=p.firewall_pending()
        with patch.object(p.time,'time',return_value=pending['deadline']+1):
            with self.assertRaises(ValueError): p.firewall_operation('confirm',dict(self.values,token=pending['token']))
        self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_delete_checks_full_snapshot_and_exact_number(self):
        version=p.firewall_snapshot()['version']
        self.assertEqual(p.firewall_delete({'number':'2','version':version}),['ufw','--force','delete','2'])
        self.numbered+='[ 4] 8888/tcp                  DENY IN     Anywhere\n'
        with self.assertRaises(ValueError): p.firewall_delete({'number':'2','version':version})

    def test_delete_protected_permits_and_unknown_profiles_rejected(self):
        self.numbered+='[ 4] OpenSSH                   ALLOW IN    Anywhere\n[ 5] Anywhere                  ALLOW IN    192.0.2.0/24\n'
        version=p.firewall_snapshot()['version']
        for number in ('1','4','5'):
            with self.subTest(number=number),self.assertRaises(ValueError): p.firewall_delete({'number':number,'version':version})

    def test_delete_ipv6_only_does_not_delete_pair(self):
        command=p.firewall_delete({'number':'3','version':p.firewall_snapshot()['version']})
        self.assertEqual(command,['ufw','--force','delete','3'])

    def test_baseline_does_not_reset_or_remove_foreign_rules(self):
        p.firewall_operation('baseline',self.values)
        self.assertFalse(any('reset' in c or 'delete' in c for c in self.commands))
        self.assertTrue(any(c[:4]==['ufw','insert','1','allow'] for c in self.commands))

    def test_baseline_does_not_broaden_existing_scoped_permit(self):
        self.numbered=self.numbered.replace('49222/tcp                 ALLOW IN    Anywhere','49222/tcp                 ALLOW IN    198.51.100.8')
        commands=p.firewall_baseline_commands()
        self.assertFalse(any('49222/tcp' in cmd for cmd in commands))

    def test_baseline_refuses_unknown_application_permit(self):
        self.numbered+='[ 4] OpenSSH                   ALLOW IN    198.51.100.8\n'
        with self.assertRaises(ValueError): p.firewall_baseline_commands()

    def test_unsafe_outgoing_default_is_rejected(self):
        with self.assertRaises(ValueError): p.firewall_operation('default',dict(self.values,direction='outgoing',policy='deny'))
        self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_source_block_rejects_self_network_and_mapped_addresses(self):
        for source in ('198.51.100.0/24','::ffff:198.51.100.8','0.0.0.0/0','::/0','127.0.0.0/8'):
            with self.subTest(source=source),self.assertRaises(ValueError): p.firewall_operation('source-block',dict(self.values,source=source))
        self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_source_block_uses_explicit_cidr_and_rollback(self):
        p.firewall_operation('source-block',dict(self.values,source='192.0.2.9'))
        self.assertIn(['ufw','prepend','deny','in','from','192.0.2.9/32','to','any','comment','TrustTunnel blocked source'],self.commands)
        self.assertTrue(p.firewall_pending())

    def test_port_and_service_maintenance_blocked_during_pending_change(self):
        p.firewall_operation('reload',self.values)
        with self.assertRaises(ValueError): p.change_endpoint_port('9443')
        with self.assertRaises(ValueError): p.update_panel_access('localhost','8088')
        with self.assertRaises(ValueError): p.installer_operation('reinstall',{})

    def test_jails_discovered_from_configuration_and_runtime(self):
        snapshot=p.fail2ban_snapshot()
        self.assertEqual(snapshot['active'],['sshd','nginx-http-auth'])
        self.assertIn('nginx-http-auth',snapshot['configured']); self.assertNotIn('DEFAULT',snapshot['configured'])

    def test_unknown_and_injected_jail_rejected(self):
        for jail in ('missing','--help','sshd;id','../sshd'):
            with self.subTest(jail=jail),self.assertRaises(ValueError): p.fail2ban_operation('ban',dict(self.values,jail=jail,ip='192.0.2.1'))

    def test_self_ban_and_ipv4_mapped_self_ban_rejected(self):
        for address in ('198.51.100.8','::ffff:198.51.100.8','127.0.0.1','::1','0.0.0.0','ff02::1'):
            with self.subTest(address=address),self.assertRaises(ValueError): p.fail2ban_operation('ban',dict(self.values,ip=address))

    def test_ban_and_unban_are_scoped_to_selected_jail(self):
        p.fail2ban_operation('ban',dict(self.values,jail='nginx-http-auth',ip='192.0.2.1'))
        self.assertIn(['fail2ban-client','set','nginx-http-auth','banip','192.0.2.1'],self.commands)
        p.fail2ban_operation('unban',dict(self.values,jail='nginx-http-auth',ip='192.0.2.1'))
        self.assertIn(['fail2ban-client','set','nginx-http-auth','unbanip','192.0.2.1'],self.commands)

    def test_settings_persist_in_separate_override_and_preserve_other_jails(self):
        p.FAIL2BAN_OVERRIDE.write_text('[nginx-http-auth]\nmaxretry=8\n')
        original=(p.FAIL2BAN_DIR/'jail.conf').read_bytes()
        p.fail2ban_operation('settings',dict(self.values,retry='6',findtime='600',bantime='3600',increment='1',maxtime='604800'))
        data=configparser.ConfigParser(); data.read(p.FAIL2BAN_OVERRIDE)
        self.assertEqual(data['nginx-http-auth']['maxretry'],'8'); self.assertEqual(data['sshd']['maxretry'],'6')
        self.assertEqual(data['sshd']['bantime.increment'],'true'); self.assertNotIn('enabled',data['sshd'])
        self.assertEqual((p.FAIL2BAN_DIR/'jail.conf').read_bytes(),original)

    def test_invalid_config_restores_previous_override(self):
        old='[sshd]\nmaxretry=7\n'; p.FAIL2BAN_OVERRIDE.write_text(old)
        real=self.command
        p.run.side_effect=lambda args,**kw: (1,'bad config') if args==['fail2ban-client','-t'] else real(args,**kw)
        with self.assertRaises(RuntimeError): p.save_jail_override('sshd',{'maxretry':'4'})
        self.assertEqual(p.FAIL2BAN_OVERRIDE.read_text(),old)

    def test_malformed_override_is_not_overwritten(self):
        old='this is not an ini file\n'; p.FAIL2BAN_OVERRIDE.write_text(old)
        with self.assertRaises(ValueError): p.save_jail_override('sshd',{'maxretry':'4'})
        self.assertEqual(p.FAIL2BAN_OVERRIDE.read_text(),old)

    def test_secret_write_failure_preserves_prior_file(self):
        target=self.root/'secret.conf'; target.write_text('original secret')
        with patch.object(p.os,'replace',side_effect=OSError('replace failed')):
            with self.assertRaises(OSError): p.write_text(target,'replacement secret')
        self.assertEqual(target.read_text(),'original secret')
        self.assertEqual(list(self.root.glob('.admin-*')),[])

    def test_ignore_parser_preserves_single_line_and_tree_outputs(self):
        for text in ('127.0.0.1/8 ::1 192.0.2.4','These IP addresses/networks are ignored:\n|- 127.0.0.1/8\n|- ::1\n`- 192.0.2.4'):
            self.assertEqual(p.fail2ban_ignores(text),['127.0.0.0/8','::1/128','192.0.2.4/32'])

    def test_ignore_change_preserves_effective_addresses(self):
        p.fail2ban_operation('ignore-add',dict(self.values,ip='192.0.2.17'))
        text=p.FAIL2BAN_OVERRIDE.read_text()
        self.assertIn('198.51.100.8/32',text); self.assertIn('192.0.2.17/32',text); self.assertIn('::1/128',text)

    def test_cannot_remove_current_admin_exception_or_whitelist_world(self):
        for action,address in [('ignore-remove','198.51.100.8'),('ignore-remove','127.0.0.1/8'),('ignore-add','0.0.0.0/0'),('ignore-add','::/0')]:
            with self.subTest(action=action,address=address),self.assertRaises(ValueError): p.fail2ban_operation(action,dict(self.values,ip=address))

    def test_legacy_mutation_cannot_bypass_new_confirmation(self):
        for action in ('security-open','security-ban','security-unban','security-fail2ban','security-ignore-add'):
            with self.subTest(action=action),self.assertRaises(ValueError): p.network_operation(action,{'port':'9000','ip':'192.0.2.1'})

    def test_settings_ranges_and_increment_validation(self):
        for values in (dict(retry='0',findtime='600',bantime='3600'),dict(retry='5',findtime='1',bantime='3600'),
                       dict(retry='5',findtime='600',bantime='3600',increment='yes'),
                       dict(retry='5',findtime='600',bantime='3600',increment='1',maxtime='60')):
            with self.subTest(values=values),self.assertRaises(ValueError): p.fail2ban_operation('settings',dict(self.values,**values))

    def test_ssh_port_discovery_handles_socket_activation(self):
        def command(args,**kw):
            if args==['sshd','-T']: return 0,'port 22\nport 2222'
            if args==['ss','-H','-lntp']: return 0,'LISTEN 0 128 0.0.0.0:3222 0.0.0.0:* users:(("sshd",pid=1,fd=1))'
            return 0,'[::]:49222 (Stream)'
        with patch.object(p,'current_ssh_port',return_value='22'),patch.object(p,'run',side_effect=command):
            self.assertEqual(p.ssh_listener_ports(),[(22,'tcp'),(2222,'tcp'),(3222,'tcp'),(49222,'tcp')])


if __name__ == '__main__': unittest.main()

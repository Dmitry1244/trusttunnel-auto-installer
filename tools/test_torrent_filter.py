"""Offline routing-filter tests with a synthetic xtables backend."""
import copy
import importlib.util
import json
from pathlib import Path
import shlex
import tempfile
import unittest
from contextlib import contextmanager, nullcontext
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('torrent_panel',Path(__file__).parents[1]/'trusttunnel-panel.py')
p=importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


@contextmanager
def lock(**kwargs): yield True


class TorrentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.context={'cgroup':'ttwarp.slice/trusttunnel.service','invocation':'a'*32}
        self.rules={tool:{'OUTPUT':[]} for tool in ('iptables','ip6tables')}; self.calls=[]
        self.patches=[patch.object(p,'TORRENT_STATE',self.root/'torrent.json'),patch.object(p,'TORRENT_DROPIN',self.root/'dropins/60-torrent.conf'),
                      patch.object(p,'SCHEDULE_DIR',self.root/'units'),patch.object(p,'torrent_lock',lock),patch.object(p,'admin_lock',nullcontext),
                      patch.object(p,'torrent_context',side_effect=lambda:copy.deepcopy(self.context)),patch.object(p,'torrent_units'),
                      patch.object(p,'require_no_firewall_pending'),patch.object(p,'endpoint_port',return_value='8443'),
                      patch.object(p,'protected_ports',return_value=[(8443,'tcp'),(49222,'tcp'),(8088,'tcp')]),
                      patch.object(p,'audit_log'),patch.object(p,'run',side_effect=self.command)]
        for item in self.patches: item.start()
        p.SNAPSHOT_CACHE.clear(); self.values={'confirm':'CONFIRMED','limits_ack':'1'}

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        p.SNAPSHOT_CACHE.clear(); self.temp.cleanup()

    def command(self,args,input_text=None,**kwargs):
        self.calls.append((args,input_text))
        tool=args[0].replace('-restore','')
        if tool not in self.rules: return 0,'OK'
        if args[0].endswith('-restore'):
            if '--test' in args: return 0,'validated'
            table=copy.deepcopy(self.rules[tool])
            for line in input_text.splitlines():
                if line.startswith('*') or line=='COMMIT': continue
                parts=shlex.split(line); action,chain=parts[:2]
                if action=='-N':
                    if chain in table: return 1,'exists'
                    table[chain]=[]
                elif action=='-A': table[chain].append(parts[2:])
                elif action=='-D': table[chain].pop(int(parts[2])-1)
                elif action=='-F': table[chain]=[]
                elif action=='-X': del table[chain]
                else: raise AssertionError(line)
            self.rules[tool]=table; return 0,'OK'
        table=self.rules[tool]
        if '-S' in args:
            idx=args.index('-S'); selected=args[idx+1] if idx+1<len(args) else None
            if selected and selected not in table: return 1,'missing'
            lines=[]
            for chain,entries in table.items():
                if selected and selected!=chain: continue
                lines.append(('-P OUTPUT ACCEPT' if chain=='OUTPUT' else '-N '+chain))
                lines += [' '.join(shlex.quote(v) for v in ['-A',chain,*entry]) for entry in entries]
            return 0,'\n'.join(lines)
        if '-I' in args:
            idx=args.index('-I'); table[args[idx+1]].insert(int(args[idx+2])-1,args[idx+3:]); return 0,'OK'
        if '-C' in args:
            idx=args.index('-C'); return (0,'present') if args[idx+2:] in table[args[idx+1]] else (1,'absent')
        if '-L' in args: return 0,'Chain mock\n 3 150 DROP tcp -- * * 0.0.0.0/0 0.0.0.0/0\n 5 300 DROP udp -- * * 0.0.0.0/0 0.0.0.0/0'
        raise AssertionError(args)

    def save(self,**values): return p.torrent_operation('save',dict(self.values,**values))

    def test_disabled_default_does_not_touch_firewall(self):
        data=p.torrent_snapshot(); self.assertFalse(data['enabled']); self.assertFalse(data['active']); self.assertEqual(self.calls,[])

    def test_confirm_and_limitation_ack_are_required(self):
        for values in ({},{'confirm':'CONFIRMED'},{'limits_ack':'1'}):
            with self.subTest(values=values),self.assertRaises(ValueError): p.torrent_operation('save',values)
        self.assertEqual(self.calls,[])

    def test_default_uses_signatures_without_a_port_block_or_blanket_udp(self):
        self.save()
        self.assertTrue(p.torrent_state()['enabled'])
        for args,program in self.calls:
            if program and '-N TT_BT_' in program:
                self.assertNotIn('--dport',program)
                self.assertIn('--algo kmp --to 256',program)
                self.assertIn('--sport 8443',program)
                for signature in p.TORRENT_SIGNATURES: self.assertIn(signature[1],program)
        self.assertFalse(any('ufw' in c[0] or 'ip'==c[0][0] or 'restart' in c[0] for c in self.calls))

    def test_all_jumps_are_scoped_to_trusttunnel_cgroup(self):
        self.save()
        for table in self.rules.values():
            self.assertEqual(len(table['OUTPUT']),1)
            jump=table['OUTPUT'][0]
            self.assertEqual(jump[jump.index('--path')+1],self.context['cgroup'])
            self.assertIn(p.TORRENT_MARKER,jump)

    def test_optional_ports_are_validated_and_used_for_both_families(self):
        self.save(mode='ports',ports='6881:6889,6969,51413')
        self.assertEqual(p.torrent_state()['ports'],['6881:6889','6969','51413'])
        for table in self.rules.values():
            chain=p.torrent_state()['active']['chain']; ports=[r[r.index('--dport')+1] for r in table[chain] if '--dport' in r]
            self.assertEqual(ports.count('6969'),2)

    def test_invalid_ports_cannot_block_common_services_or_inject_options(self):
        for ports in ('80','443','53','49222','8088','8443','1:65535','9;reboot','--dport','65536','999:1',','.join(str(100+i) for i in range(13))):
            with self.subTest(ports=ports),self.assertRaises(ValueError): self.save(mode='ports',ports=ports)
        self.assertFalse(p.TORRENT_STATE.exists())

    def test_disabling_removes_only_owned_chains_and_keeps_foreign_rules(self):
        foreign=['-p','tcp','--dport','9999','-j','ACCEPT']
        for table in self.rules.values(): table['OUTPUT'].append(list(foreign)); table['TT_WARP']=[['-j','RETURN']]
        self.save(); p.torrent_operation('disable',{'confirm':'CONFIRMED'})
        for table in self.rules.values(): self.assertEqual(table,{'OUTPUT':[foreign],'TT_WARP':[['-j','RETURN']]})
        self.assertFalse(p.torrent_state()['enabled'])

    def test_unsupported_ipv6_preflight_changes_nothing(self):
        original=self.command
        p.run.side_effect=lambda args,**kw:(1,'unsupported') if args[0]=='ip6tables-restore' and '--test' in args else original(args,**kw)
        with self.assertRaises(RuntimeError): self.save()
        self.assertEqual(self.rules,{'iptables':{'OUTPUT':[]},'ip6tables':{'OUTPUT':[]}})
        p.torrent_units.assert_not_called()

    def test_failed_second_family_rolls_back_new_chain(self):
        original=self.command
        p.run.side_effect=lambda args,**kw:(1,'failure') if args[0]=='ip6tables-restore' and '--test' not in args and '-N TT_BT_' in kw.get('input_text','') else original(args,**kw)
        with self.assertRaises(RuntimeError): self.save()
        self.assertEqual(self.rules,{'iptables':{'OUTPUT':[]},'ip6tables':{'OUTPUT':[]}})
        self.assertFalse(p.torrent_state()['enabled'])

    def test_failed_jump_keeps_existing_working_filter(self):
        self.save(); before=copy.deepcopy(self.rules); state=p.torrent_state()
        original=self.command
        p.run.side_effect=lambda args,**kw:(1,'failure') if args[0]=='ip6tables' and '-I' in args else original(args,**kw)
        with self.assertRaises(RuntimeError): self.save(mode='ports',ports='6969')
        self.assertEqual(p.torrent_state(),state); self.assertEqual(self.rules,before)

    def test_mode_change_removes_old_chains(self):
        self.save(mode='ports',ports='6969'); old=p.torrent_state()['active']['chain']
        self.save(); new=p.torrent_state()['active']['chain']
        self.assertNotEqual(old,new)
        for table in self.rules.values(): self.assertNotIn(old,table); self.assertEqual(len(table['OUTPUT']),1)

    def test_status_checks_both_families_and_counts_drop_packets(self):
        self.save(); data=p.torrent_snapshot()
        self.assertTrue(data['active']); self.assertEqual(data['dropped'],16)
        self.rules['ip6tables']['OUTPUT']=[]; p.SNAPSHOT_CACHE.clear()
        self.assertFalse(p.torrent_snapshot()['active'])

    def test_reconcile_is_idempotent_without_restarting_or_recreating(self):
        self.save(); before=copy.deepcopy(self.rules); state=p.TORRENT_STATE.read_bytes(); self.calls=[]
        p.torrent_reconcile()
        self.assertEqual(self.rules,before); self.assertEqual(p.TORRENT_STATE.read_bytes(),state)
        self.assertFalse(any(c[0][0].endswith('-restore') for c in self.calls))

    def test_reconcile_handles_new_cgroup_after_route_change(self):
        self.save(); self.context={'cgroup':'system.slice/trusttunnel.service','invocation':'b'*32}
        p.torrent_reconcile(); self.assertEqual(p.torrent_state()['active']['cgroup'],self.context['cgroup'])
        for table in self.rules.values(): self.assertEqual(len(table['OUTPUT']),1)

    def test_reconcile_restores_missing_jumps(self):
        self.save(); self.rules['iptables']['OUTPUT']=[]
        p.torrent_reconcile()
        for table in self.rules.values(): self.assertEqual(len(table['OUTPUT']),1)

    def test_external_chain_edits_are_not_flushed(self):
        self.save(); chain=p.torrent_state()['active']['chain']
        self.rules['iptables'][chain].append(['-p','tcp','-j','RETURN'])
        with self.assertRaises(ValueError): p.torrent_operation('disable',{'confirm':'CONFIRMED'})
        self.assertTrue(p.torrent_state()['enabled']); self.assertIn(chain,self.rules['iptables'])

    def test_firewall_read_failure_cannot_falsely_confirm_disabled(self):
        self.save(); original=self.command
        p.run.side_effect=lambda args,**kw:(1,'permission denied') if args[0]=='iptables' and args[-1:] == ['-S'] else original(args,**kw)
        with self.assertRaises(RuntimeError): p.torrent_operation('disable',{'confirm':'CONFIRMED'})
        self.assertTrue(p.torrent_state()['enabled'])

    def test_invalid_cgroup_does_not_become_a_global_filter(self):
        for path in ('','system.slice','../trusttunnel.service','/system.slice/trusttunnel.service','a/../trusttunnel.service','a/sshd.service','a/;id/trusttunnel.service'):
            with self.subTest(path=path),self.assertRaises(ValueError): p.torrent_cgroup_valid(path)

    def test_corrupt_state_rejects_foreign_chain_names(self):
        p.TORRENT_STATE.write_text(json.dumps({'enabled':True,'mode':'signatures','active':{'chain':'OUTPUT','cgroup':self.context['cgroup']}}))
        with self.assertRaises(ValueError): p.torrent_state()
        self.assertEqual(self.calls,[])

    def test_unknown_modes_and_operations_are_rejected(self):
        with self.assertRaises(ValueError): self.save(mode='drop-all-udp')
        with self.assertRaises(ValueError): p.torrent_operation('shell',self.values)

    def test_no_client_configuration_or_ufw_files_are_written(self):
        with patch.object(p,'apply_endpoint_file') as endpoint,patch.object(p,'rebuild_client_files') as profiles:
            self.save(); p.torrent_operation('disable',{'confirm':'CONFIRMED'})
            endpoint.assert_not_called(); profiles.assert_not_called()

    def test_pending_candidate_cleanup_survives_a_failed_previous_apply(self):
        self.save(); original=p.torrent_state()
        pending=dict(self.context,chain='TT_BT_'+'f'*12)
        for table in self.rules.values(): table[pending['chain']]=[['-m','comment','--comment',p.TORRENT_MARKER,'-j','RETURN']]
        p.TORRENT_STATE.write_text(json.dumps(dict(original,pending=pending)))
        p.torrent_reconcile()
        self.assertEqual(p.torrent_state(),original)
        for table in self.rules.values(): self.assertNotIn(pending['chain'],table)

    def test_cleanup_pending_while_disabled_never_claims_active(self):
        pending=dict(self.context,chain='TT_BT_'+'f'*12)
        for table in self.rules.values(): table[pending['chain']]=[]
        p.TORRENT_STATE.write_text(json.dumps(dict(enabled=False,mode='signatures',ports=[],pending=pending)))
        self.assertTrue(p.torrent_snapshot()['recovering'])
        p.torrent_reconcile(); p.SNAPSHOT_CACHE.clear()
        self.assertFalse(p.torrent_snapshot()['recovering'])
        for table in self.rules.values(): self.assertEqual(table,{'OUTPUT':[]})


class TorrentUnitTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.units=self.root/'units'; self.units.mkdir()
        self.dropin=self.root/'dropin/60-filter.conf'
        self.patches=[patch.object(p,'SCHEDULE_DIR',self.units),patch.object(p,'TORRENT_DROPIN',self.dropin),
                      patch.object(p,'torrent_script',return_value='/usr/local/sbin/trusttunnel-panel.py'),
                      patch.object(p,'run',return_value=(0,'OK'))]
        for item in self.patches: item.start()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()

    def test_units_reconcile_without_restarting_vpn_or_global_firewall(self):
        p.torrent_units()
        self.assertIn('ExecStartPost=-/usr/bin/python3 /usr/local/sbin/trusttunnel-panel.py --torrent-reconcile',self.dropin.read_text())
        self.assertIn('OnUnitActiveSec=30s',(self.units/'trusttunnel-torrent-filter.timer').read_text())
        commands=[call.args[0] for call in p.run.call_args_list]
        self.assertIn(['systemctl','enable','--now','trusttunnel-torrent-filter.timer'],commands)
        self.assertFalse(any('restart' in cmd or 'ufw' in cmd for cmd in commands))

    def test_foreign_unit_is_not_overwritten(self):
        path=self.units/'trusttunnel-torrent-filter.timer'; path.write_text('foreign-owner')
        with self.assertRaises(ValueError): p.torrent_units()
        self.assertEqual(path.read_text(),'foreign-owner'); self.assertFalse(self.dropin.exists())
        p.run.assert_not_called()

    def test_systemd_failure_restores_prior_owned_files(self):
        old='# Managed by TrustTunnel torrent filter\nprior-config'
        path=self.units/'trusttunnel-torrent-filter.timer'; path.write_text(old)
        p.run.return_value=(1,'test-failure')
        with self.assertRaises(RuntimeError): p.torrent_units()
        self.assertEqual(path.read_text(),old); self.assertFalse(self.dropin.exists())

    def test_failed_new_units_are_removed_without_leaving_a_timer_enabled(self):
        p.run.return_value=(1,'test-failure')
        with self.assertRaises(RuntimeError): p.torrent_units()
        self.assertEqual(list(self.units.iterdir()),[]); self.assertFalse(self.dropin.exists())
        self.assertTrue(any(call.args[0]==['systemctl','disable','--now','trusttunnel-torrent-filter.timer'] for call in p.run.call_args_list))


if __name__=='__main__': unittest.main()

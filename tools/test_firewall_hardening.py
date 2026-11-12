"""Offline reviewed-allowlist regressions; no real firewall commands."""
import unittest
from unittest.mock import patch
import test_firewall_fail2ban as base
p=base.p


class HardeningTests(unittest.TestCase):
    command=base.SecurityAdminTests.command
    def setUp(self):
        base.SecurityAdminTests.setUp(self)
        self.original_required_ports=p.hardening_required_ports
        for item in (patch.object(p,'hardening_required_ports',return_value={(49222,'tcp'),(8443,'tcp'),(8443,'udp'),(8088,'tcp')}),
                     patch.object(p,'DOCKER_SOCKET',self.root/'docker.sock')):
            item.start();self.patches.append(item)

    def tearDown(self):base.SecurityAdminTests.tearDown(self)

    def plan(self,extra=''):return p.firewall_hardening_plan({'extra_ports':extra})

    def apply(self,plan=None,extra=''):
        return p.firewall_operation('hardening',dict(self.values,extra_ports=extra,fingerprint=(plan or self.plan(extra))['fingerprint']))

    def test_preview_is_read_only_and_lists_exact_removed_permits(self):
        plan=self.plan()
        self.assertFalse(plan['blockers'])
        self.assertEqual(plan['removed'],['ufw allow from 192.0.2.0/24 to any port 9000 proto tcp'])
        self.assertFalse(p.FIREWALL_PENDING.exists())
        self.assertFalse(any(command[0]=='systemd-run' for command in self.commands))

    def test_extra_ports_are_explicit_and_keep_existing_source_scope(self):
        plan=self.plan('9000/tcp')
        self.assertFalse(plan['removed'])
        self.assertFalse(any('9000/tcp' in command for command in plan['commands']))
        self.assertIn('9000/tcp',plan['allowed'])

    def test_scoped_ssh_is_not_broadened(self):
        self.added='ufw allow from 198.51.100.0/24 to any port 49222 proto tcp\n'
        plan=self.plan()
        self.assertFalse(any('49222/tcp' in command for command in plan['commands']))
        self.assertEqual(plan['kept'],[self.added.strip()])

    def test_unknown_profiles_ranges_and_all_port_permits_block(self):
        for line in ('ufw allow OpenSSH','ufw allow 8000:9000/tcp','ufw allow from 192.0.2.0/24','ufw route allow 9000/tcp'):
            self.added=line+'\n';p.SNAPSHOT_CACHE.clear()
            with self.subTest(line=line):
                plan=self.plan();self.assertTrue(plan['blockers'])
                with self.assertRaises(ValueError):self.apply(plan)
                self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_combined_protocol_needing_only_tcp_is_not_silently_replaced(self):
        self.added='ufw allow 49222\n';p.SNAPSHOT_CACHE.clear()
        self.assertTrue(self.plan()['blockers'])
        self.assertFalse(self.plan('49222/udp')['blockers'])

    def test_inactive_ufw_uses_saved_rules_not_an_empty_numbered_list(self):
        self.numbered='Status: inactive\n';p.SNAPSHOT_CACHE.clear()
        self.assertTrue(self.plan()['removed'])

    def test_plan_and_extra_port_changes_invalidate_fingerprint(self):
        plan=self.plan()
        with self.assertRaises(ValueError):self.apply(plan,'9000/tcp')
        self.added+='ufw allow 9001/tcp\n';p.SNAPSHOT_CACHE.clear()
        with self.assertRaises(ValueError):self.apply(plan)
        self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_mutation_requires_confirmation(self):
        with self.assertRaises(ValueError):p.firewall_operation('hardening',{})
        self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_transaction_timer_precedes_deletion_and_does_not_touch_egress(self):
        self.apply()
        timer=next(index for index,c in enumerate(self.commands) if c[0]=='systemd-run')
        deletion=next(index for index,c in enumerate(self.commands) if c[:3]==['ufw','--force','delete'])
        self.assertLess(timer,deletion)
        self.assertIn(['ufw','default','deny','incoming'],self.commands)
        self.assertIn(['ufw','--force','enable'],self.commands)
        self.assertFalse(any('outgoing' in c or 'routed' in c or 'reset' in c for c in self.commands))

    def test_docker_and_excessive_batches_require_manual_review(self):
        p.DOCKER_SOCKET.touch();self.assertTrue(self.plan()['blockers']);p.DOCKER_SOCKET.unlink()
        self.added+=''.join('ufw allow '+str(port)+'/tcp\n' for port in range(10000,10040))
        p.SNAPSHOT_CACHE.clear();self.assertTrue(self.plan()['blockers'])

    def test_invalid_extra_ports_do_not_arm_timer(self):
        for value in ('443','80/tcp;id','0/tcp','65536/udp','80:90/tcp','80/tcp\n--force',','.join(str(i)+'/tcp' for i in range(1,18))):
            with self.subTest(value=value),self.assertRaises(ValueError):self.plan(value)
        self.assertFalse(p.FIREWALL_PENDING.exists())

    def test_localhost_panel_is_not_opened_automatically(self):
        with patch.object(p,'hardening_required_ports',self.original_required_ports),patch.object(p,'ssh_listener_ports',return_value=[(49222,'tcp')]),patch.object(p,'endpoint_port',return_value='8443'), \
             patch.object(p,'quic_enabled',return_value=True),patch.object(p,'current_panel_env',return_value={'PANEL_BIND':'127.0.0.1','PANEL_PORT':'8088'}):
            self.assertNotIn((8088,'tcp'),p.hardening_required_ports())


if __name__=='__main__':unittest.main()

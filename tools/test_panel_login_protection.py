"""Synthetic panel-jail regressions. No real files/services/firewall are mutated.

After manual integration:
    python -B tools/test_panel_login_protection.py
Before integration, explicitly test the snippet AST with test_admin.panel APIs:
    python -B tools/test_panel_login_protection.py --snippet

Optional jailless Linux qualification, against a PREPARED filter in a private
isolated /root/staging tree (never a live journal): add
    --qualify-linux-filter /root/staging/filter.d/trusttunnel-panel.conf
Only fail2ban-regex executes in that explicit mode. No daemon is started, no
fail2ban-client or iptables command executes. The Python regex model below is
synthetic evidence, not a substitute for this native qualification.
"""

import ast
import configparser
import io
import ipaddress
import os
import re
import runpy
import shutil
import stat
import sys
import types
import unittest
from contextlib import nullcontext
from pathlib import Path, PurePosixPath
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SNIPPET = ROOT / 'tools/private-panel-fail2ban-snippet.py'
SNIPPET_CODE = None
SNIPPET_MODE = '--snippet' in sys.argv
if SNIPPET_MODE:
    sys.argv.remove('--snippet')
NATIVE_FILTER = None
if '--qualify-linux-filter' in sys.argv:
    index = sys.argv.index('--qualify-linux-filter')
    if index + 1 >= len(sys.argv):
        raise SystemExit('--qualify-linux-filter requires an existing prepared filter path')
    NATIVE_FILTER = Path(sys.argv[index + 1])
    del sys.argv[index:index + 2]

# The production module sees only synthetic credentials during its initialization.
with patch.object(os, 'environ', {'TT_PANEL_SOURCE': str(ROOT / 'trusttunnel-panel.py'),
                                 'PANEL_USER': 'synthetic-admin', 'PANEL_PASSWORD': 'synthetic-only'}):
    from test_admin import panel


def snippet_namespace():
    global SNIPPET_CODE
    if SNIPPET_CODE is None:
        tree = ast.parse(SNIPPET.read_text(encoding='utf-8-sig'), filename=str(SNIPPET))
        definitions = [node for node in tree.body
                       if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))]
        SNIPPET_CODE = compile(ast.Module(body=definitions, type_ignores=[]), str(SNIPPET), 'exec')
    module = types.ModuleType('synthetic_panel_login')
    module.__dict__.update(vars(panel))
    exec(SNIPPET_CODE, module.__dict__)
    return module


class MemoryPath:
    def __init__(self, fs, path):
        self.fs = fs
        self.path = PurePosixPath(str(path))

    def __str__(self):
        return str(self.path)

    def __hash__(self):
        return hash((id(self.fs), self.path))

    def __eq__(self, other):
        return isinstance(other, MemoryPath) and self.fs is other.fs and self.path == other.path

    def __truediv__(self, value):
        return MemoryPath(self.fs, self.path / str(value))

    @property
    def parent(self):
        return MemoryPath(self.fs, self.path.parent)

    @property
    def parents(self):
        return tuple(MemoryPath(self.fs, path) for path in self.path.parents)

    def is_absolute(self):
        return self.path.is_absolute()

    def exists(self):
        return str(self) in self.fs.nodes and not self.is_symlink()

    def is_symlink(self):
        return stat.S_ISLNK(self.fs.nodes.get(str(self), {}).get('mode', 0))

    def lstat(self):
        node = self.fs.nodes[str(self)]
        return types.SimpleNamespace(st_mode=node['mode'], st_uid=node.get('uid', 0),
                                     st_nlink=node.get('links', 1), st_size=len(node.get('text', '').encode()))

    def mkdir(self, mode=0o777, exist_ok=False, parents=False):
        if str(self) in self.fs.nodes:
            if exist_ok and stat.S_ISDIR(self.lstat().st_mode):
                return
            raise FileExistsError(str(self))
        if not self.parent.exists():
            if not parents:
                raise FileNotFoundError(str(self.parent))
            self.parent.mkdir(mode=0o755, exist_ok=True, parents=True)
        self.fs.nodes[str(self)] = dict(mode=stat.S_IFDIR | mode, uid=0)
        self.fs.mutations.append(('mkdir', str(self), mode))

    def unlink(self, missing_ok=False):
        if str(self) not in self.fs.nodes and not missing_ok:
            raise FileNotFoundError(str(self))
        self.fs.nodes.pop(str(self), None)
        self.fs.mutations.append(('unlink', str(self)))


class MemoryFS:
    def __init__(self):
        self.nodes = {path: dict(mode=stat.S_IFDIR | 0o755, uid=0)
                      for path in ('/', '/etc', '/etc/fail2ban', '/etc/fail2ban/filter.d', '/etc/fail2ban/jail.d')}
        self.mutations = []

    def path(self, value):
        return MemoryPath(self, value)

    def write(self, path, text, mode=0o600):
        path = self.path(path)
        if not path.parent.exists():
            path.parent.mkdir(mode=0o755, exist_ok=True, parents=True)
        self.nodes[str(path)] = dict(mode=stat.S_IFREG | mode, uid=0, text=text)
        self.mutations.append(('write', str(path), mode))

    def read(self, path):
        return self.nodes.get(str(path), {}).get('text', '')


class PanelLoginProtectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SNIPPET_MODE:
            missing = [name for name in ('panel_login_protection', 'panel_login_protection_status')
                       if not callable(getattr(panel, name, None))]
            if missing:
                raise AssertionError('Integrate the snippet into test_admin.panel first, or explicitly run --snippet. Missing: ' + ', '.join(missing))

    def setUp(self):
        self.p = snippet_namespace() if SNIPPET_MODE else panel
        self.fs = MemoryFS()
        self.active = False
        self.service = True
        self.other_jails = ['sshd', 'synthetic-mail']
        self.commands = []
        self.fail_test = False
        self.fail_regex = False
        self.fail_reload = False
        self.fail_stop = False
        self.fail_status = False
        self.env = dict(PANEL_BIND='0.0.0.0', PANEL_PORT='8088', PANEL_TLS='1')
        self.patches = [patch.object(self.p, 'FAIL2BAN_DIR', self.fs.path('/etc/fail2ban')),
                        patch.object(self.p, 'atomic_write', side_effect=self.fs.write),
                        patch.object(self.p, 'read_text', side_effect=self.fs.read),
                        patch.object(self.p, 'admin_lock', side_effect=nullcontext),
                        patch.object(self.p, 'audit_log'),
                        patch.object(self.p, 'current_panel_env', side_effect=lambda: dict(self.env)),
                        patch.object(self.p, 'fail2ban_snapshot', side_effect=lambda: dict(
                            available=self.service, service='active' if self.service else 'inactive',
                            active=self.other_jails + ([self.p.PANEL_LOGIN_JAIL] if self.active else []), configured=['sshd'])),
                        patch.object(self.p, 'run', side_effect=self.command),
                        patch.object(self.p, 'checked_run', side_effect=self.checked_command),
                        patch.object(self.p, 'endpoint_port', return_value='443'),
                        patch.object(self.p, 'ssh_listener_ports', return_value=[(22, 'tcp'), (49222, 'tcp')]),
                        patch.object(self.p.os, 'geteuid', return_value=0, create=True)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.filter_path, self.jail_path = self.p._panel_login_paths()

    def checked_command(self, args, **kwargs):
        rc, output = self.p.run(args, **kwargs)
        if rc:
            raise RuntimeError(output)
        return output

    def command(self, args, **kwargs):
        self.commands.append(list(args))
        if args == ['fail2ban-client', 'status']:
            if self.fail_status:
                return 1, 'synthetic connection failure'
            return 0, 'Status\nJail list: ' + ', '.join(self.other_jails + ([self.p.PANEL_LOGIN_JAIL] if self.active else []))
        if args == ['fail2ban-client', '-t']:
            return (1, 'synthetic config failure') if self.fail_test else (0, 'OK')
        if args == ['fail2ban-client', 'reload', '--if-exists', self.p.PANEL_LOGIN_JAIL]:
            self.active = True
            if self.fail_reload:
                self.fail_reload = False
                return 1, 'synthetic partial reload failure'
            return 0, 'OK'
        if args == ['fail2ban-client', 'stop', self.p.PANEL_LOGIN_JAIL]:
            self.active = False
            if self.fail_stop:
                self.fail_stop = False
                return 1, 'synthetic partial stop failure'
            return 0, 'OK'
        if args[0] == 'fail2ban-regex':
            self.assertEqual(args[1:3], ['--usedns=no', '--datepattern={NONE}'])
            count = self.model_matches(args[3], self.fs.read(args[4]))
            if self.fail_regex:
                count = 1 - count
            return 0, 'Lines: 1 lines, 0 ignored, %s matched, %s missed\n' % (count, 1 - count)
        raise AssertionError('Unexpected command; no real command was executed: ' + repr(args))

    @staticmethod
    def model_matches(line, filter_text):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(filter_text)
        definition = parser['Definition']
        prefregex = definition['prefregex'].replace('<F-CONTENT>', '(?P<content>').replace('</F-CONTENT>', ')')
        match = re.fullmatch(prefregex, line)
        if not match:
            return 0
        regex = definition['failregex'].replace('<HOST>', '(?P<peer>[0-9A-Fa-f:.]+)')
        match = re.fullmatch(regex, match['content'])
        if not match:
            return 0
        try:
            ipaddress.ip_address(match['peer'])
        except ValueError:
            return 0
        return 1

    def operation(self, action, **values):
        return self.p.panel_login_protection(action, dict(confirm='CONFIRMED', **values))

    def seed(self, enabled=False):
        self.fs.write(self.filter_path, self.p._panel_login_filter_text())
        self.fs.write(self.jail_path, self.p._panel_login_jail_text('8088', enabled))
        self.fs.mutations.clear()

    def owned_contents(self):
        return (self.fs.nodes.get(str(self.filter_path)), self.fs.nodes.get(str(self.jail_path)))

    def test_default_is_off_and_status_is_read_only(self):
        result = self.p.panel_login_protection_status()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['state'], 'off')
        self.assertFalse(self.fs.mutations)
        self.p.admin_lock.assert_not_called()
        self.p.audit_log.assert_not_called()
        self.assertEqual(self.commands, [['fail2ban-client', 'status']])

    def test_public_module_does_not_read_the_private_snippet(self):
        original = Path.read_text

        def reject_private_read(path, *args, **kwargs):
            if path == SNIPPET:
                raise AssertionError('Public tests must not read the private snippet')
            return original(path, *args, **kwargs)

        with patch.object(sys, 'argv', [__file__]), patch.object(Path, 'read_text', reject_private_read):
            loaded = runpy.run_path(__file__, run_name='public_dependency_probe')
        self.assertFalse(loaded['SNIPPET_MODE'])
        self.assertIsNone(loaded['SNIPPET_CODE'])

    def test_status_action_requires_no_confirmation(self):
        self.assertEqual(self.p.panel_login_protection('status', {})['state'], 'off')
        self.assertFalse(self.fs.mutations)

    def test_stopped_service_with_no_files_stays_off(self):
        self.service = False
        self.assertFalse(self.p.panel_login_protection_status()['enabled'])
        self.assertFalse(self.fs.mutations)

    def test_all_mutations_require_confirmation_before_io(self):
        for action in ('prepare', 'enable', 'disable'):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.p.panel_login_protection(action, {})
        self.assertFalse(self.commands)
        self.assertFalse(self.fs.mutations)
        self.p.admin_lock.assert_not_called()

    def test_unknown_actions_cannot_run_commands(self):
        for action in ('ban', 'unban', '--all', 'restart', 'prepare;reboot'):
            with self.assertRaises(ValueError):
                self.operation(action)
        self.assertFalse(self.commands)
        self.assertFalse(self.fs.mutations)

    def test_scope_and_duration_overrides_are_rejected(self):
        for values in ({'port': '22'}, {'banaction': 'ufw-allports'}, {'backend': 'polling'},
                       {'protocol': 'all'}, {'ignoreip': '0.0.0.0/0'}, {'journalmatch': ''},
                       {'bantime': '601'}, {'findtime': '99999'}, {'maxretry': '0'}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.operation('enable', **values)
        self.assertFalse(self.commands)
        self.assertFalse(self.fs.mutations)

    def test_non_root_mutation_is_rejected_before_io(self):
        self.p.os.geteuid.return_value = 1000
        with self.assertRaises(PermissionError):
            self.operation('prepare')
        self.assertFalse(self.commands)
        self.assertFalse(self.fs.mutations)

    def test_prepare_stays_disabled_and_never_reloads(self):
        result = self.operation('prepare')
        self.assertEqual(result['state'], 'prepared')
        self.assertFalse(result['enabled'])
        self.assertFalse(self.active)
        self.assertIn('enabled = false', self.fs.read(self.jail_path))
        self.assertEqual(sum(args[0] == 'fail2ban-regex' for args in self.commands), 5)
        self.assertFalse(any(args[1] in ('reload', 'stop') for args in self.commands if args[0] == 'fail2ban-client'))

    def test_prepare_can_validate_without_starting_stopped_fail2ban(self):
        self.service = False
        result = self.operation('prepare')
        self.assertFalse(result['enabled'])
        self.assertFalse(self.active)
        self.assertNotIn(['systemctl', 'start', 'fail2ban'], self.commands)

    def test_enable_scopes_action_to_current_tcp_port(self):
        result = self.operation('enable')
        self.assertTrue(result['enabled'])
        self.assertTrue(result['active'])
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(self.fs.read(self.jail_path))
        self.assertEqual(parser.sections(), [self.p.PANEL_LOGIN_JAIL])
        cfg = parser[self.p.PANEL_LOGIN_JAIL]
        self.assertEqual(cfg['port'], '8088')
        self.assertEqual(cfg['protocol'], 'tcp')
        self.assertEqual(cfg['banaction'], 'iptables-multiport')
        self.assertEqual(cfg['action'], 'iptables-multiport[name=trusttunnel-panel-login, port="8088", protocol=tcp, chain=INPUT]')
        self.assertEqual((cfg['maxretry'], cfg['findtime'], cfg['bantime']), ('10', '600', '600'))
        self.assertEqual(cfg['bantime.increment'], 'false')
        self.assertEqual(self.other_jails, ['sshd', 'synthetic-mail'])

    def test_loopback_and_cleartext_enable_are_rejected(self):
        for bind, tls in (('127.0.0.1', '1'), ('::1', '1'), ('localhost', '1'), ('0.0.0.0', '0')):
            self.env.update(PANEL_BIND=bind, PANEL_TLS=tls)
            with self.subTest(bind=bind, tls=tls), self.assertRaisesRegex(ValueError, 'SSH tunnel'):
                self.operation('enable')
        self.assertFalse(self.fs.mutations)

    def test_ssh_and_vpn_ports_are_rejected(self):
        for port in ('22', '49222', '443'):
            self.env['PANEL_PORT'] = port
            with self.assertRaisesRegex(ValueError, 'SSH or VPN'):
                self.operation('enable')
        self.assertFalse(self.fs.mutations)

    def test_bad_ports_cannot_reach_configuration(self):
        for value in ('0', '65536', '8088/tcp', '8088;reboot', '8088\nport=22'):
            self.env['PANEL_PORT'] = value
            with self.assertRaises(ValueError):
                self.operation('enable')
        self.assertFalse(self.fs.mutations)

    def test_no_daemon_start_when_service_is_stopped(self):
        self.service = False
        with self.assertRaisesRegex(ValueError, 'already be running'):
            self.operation('enable')
        self.assertFalse(self.fs.mutations)
        self.assertFalse(self.commands)

    def test_recidive_cannot_escalate_panel_bans_to_all_ports(self):
        self.other_jails.append('recidive')
        with self.assertRaisesRegex(ValueError, 'recidive'):
            self.operation('enable')
        self.assertFalse(self.fs.mutations)
        self.assertIn('recidive', self.other_jails)

    def test_disable_only_stops_our_jail_even_after_localhost_switch(self):
        self.seed(enabled=True)
        self.active = True
        self.env.update(PANEL_BIND='127.0.0.1', PANEL_TLS='0')
        result = self.operation('disable')
        self.assertFalse(result['enabled'])
        self.assertIn(['fail2ban-client', 'stop', self.p.PANEL_LOGIN_JAIL], self.commands)
        self.assertEqual(self.other_jails, ['sshd', 'synthetic-mail'])

    def test_disabled_empty_state_is_idempotent_without_file_writes(self):
        self.assertFalse(self.operation('disable')['enabled'])
        self.assertFalse(self.fs.mutations)

    def test_prepare_cannot_silently_disable_existing_protection(self):
        self.seed(enabled=True)
        with self.assertRaises(ValueError):
            self.operation('prepare')
        self.assertFalse(self.fs.mutations)

    def test_enabled_flag_blocks_port_change_if_daemon_is_down(self):
        self.seed(enabled=True)
        self.service = False
        self.assertTrue(self.p.panel_login_protection_status()['enabled'])
        self.assertTrue(self.p.panel_login_protection_status()['port_change_blocked'])

    def test_unknown_runtime_blocks_port_change_for_managed_state(self):
        self.seed(enabled=False)
        self.fail_status = True
        result = self.p.panel_login_protection_status()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['state'], 'unknown')
        self.assertFalse(self.fs.mutations)

    def test_unknown_runtime_is_fail_closed_even_without_local_files(self):
        self.fail_status = True
        result = self.p.panel_login_protection_status()
        self.assertTrue(result['enabled'])
        self.assertTrue(result['port_change_blocked'])
        self.assertEqual(result['state'], 'unknown')
        self.assertFalse(self.fs.mutations)

    def test_live_state_blocks_port_change_even_if_file_says_disabled(self):
        self.seed(enabled=False)
        self.active = True
        self.assertTrue(self.p.panel_login_protection_status()['enabled'])

    def test_active_port_drift_requires_disable_before_reenable(self):
        self.seed(enabled=True)
        self.active = True
        self.env['PANEL_PORT'] = '8443'
        with self.assertRaisesRegex(ValueError, 'disable protection first'):
            self.operation('enable')
        self.assertFalse(self.fs.mutations)

    def test_unknown_runtime_cannot_mutate_configuration(self):
        self.fail_status = True
        with self.assertRaises(RuntimeError):
            self.operation('enable')
        self.assertFalse(self.fs.mutations)

    def test_live_foreign_jail_without_owned_file_is_not_stopped(self):
        self.active = True
        with self.assertRaisesRegex(ValueError, 'no owned configuration'):
            self.operation('disable')
        self.assertFalse(self.fs.mutations)
        self.assertFalse(any(args[1] == 'stop' for args in self.commands))

    def test_foreign_files_are_not_overwritten(self):
        for path in (self.filter_path, self.jail_path):
            with self.subTest(path=str(path)):
                self.fs.write(path, '# foreign operator config\n')
                self.fs.mutations.clear()
                with self.assertRaisesRegex(ValueError, 'Foreign'):
                    self.operation('prepare')
                self.assertFalse(self.fs.mutations)
                self.assertTrue(self.p.panel_login_protection_status()['enabled'])
                self.fs.nodes.pop(str(path))

    def test_tampered_owned_filter_is_not_silently_overwritten(self):
        self.seed()
        self.fs.nodes[str(self.filter_path)]['text'] += 'failregex = .*\n'
        with self.assertRaisesRegex(ValueError, 'differs'):
            self.operation('enable')
        self.assertFalse(self.fs.mutations)

    def test_foreign_filter_local_override_is_not_used_or_removed(self):
        override = self.fs.path('/etc/fail2ban/filter.d/trusttunnel-panel.local')
        self.fs.write(override, '[Definition]\nfailregex=.*\n')
        self.fs.mutations.clear()
        with self.assertRaisesRegex(ValueError, 'override'):
            self.operation('enable')
        self.assertTrue(self.p.panel_login_protection_status()['enabled'])
        self.assertIn('failregex=.*', self.fs.read(override))
        self.assertFalse(self.fs.mutations)

    def test_tampered_jail_and_extra_sections_are_rejected(self):
        self.seed()
        self.fs.nodes[str(self.jail_path)]['text'] += '\n[sshd]\nenabled=false\n'
        with self.assertRaises(ValueError):
            self.operation('enable')
        self.assertFalse(self.fs.mutations)

    def test_symlinks_are_rejected_before_any_mutation(self):
        for target in ('/etc', '/etc/fail2ban', str(self.filter_path.parent), str(self.jail_path.parent),
                       str(self.filter_path), str(self.jail_path), '/etc/fail2ban/.trusttunnel-panel-login-backups'):
            with self.subTest(target=target):
                previous = self.fs.nodes.get(target)
                self.fs.nodes[target] = dict(mode=stat.S_IFLNK | 0o777, uid=0)
                with self.assertRaisesRegex(ValueError, 'Symlink'):
                    self.operation('prepare')
                self.assertFalse(self.fs.mutations)
                if previous is None:
                    self.fs.nodes.pop(target)
                else:
                    self.fs.nodes[target] = previous

    def test_non_root_files_and_insecure_modes_are_rejected(self):
        self.seed()
        for field, value in (('uid', 1000), ('mode', stat.S_IFREG | 0o644), ('links', 2)):
            with self.subTest(field=field):
                before = dict(self.fs.nodes[str(self.filter_path)])
                self.fs.nodes[str(self.filter_path)][field] = value
                with self.assertRaises(ValueError):
                    self.operation('enable')
                self.assertFalse(self.fs.mutations)
                self.fs.nodes[str(self.filter_path)] = before

    def test_world_writable_parent_is_rejected(self):
        self.fs.nodes['/etc']['mode'] = stat.S_IFDIR | 0o1777
        with self.assertRaises(ValueError):
            self.operation('prepare')
        self.assertFalse(self.fs.mutations)

    def test_created_configs_and_backups_are_private(self):
        result = self.operation('prepare')
        for path in (self.filter_path, self.jail_path, self.fs.path(result['backup'])):
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o600)
            self.assertEqual(path.lstat().st_uid, 0)
        self.assertEqual(stat.S_IMODE(self.fs.path(result['backup']).parent.lstat().st_mode), 0o700)

    def test_backup_contains_only_owned_pre_operation_files(self):
        self.seed()
        old_filter, old_jail = self.fs.read(self.filter_path), self.fs.read(self.jail_path)
        result = self.operation('enable')
        import json
        backup = json.loads(self.fs.read(result['backup']))
        self.assertEqual(backup['files'], {str(self.filter_path): old_filter, str(self.jail_path): old_jail})

    def test_config_test_failure_restores_owned_files_without_reload(self):
        self.seed()
        original = self.owned_contents()
        self.fail_test = True
        with self.assertRaisesRegex(RuntimeError, 'owned files restored'):
            self.operation('enable')
        self.assertEqual(self.owned_contents(), original)
        self.assertFalse(self.active)
        self.assertFalse(any(args[1] == 'reload' for args in self.commands))

    def test_failed_new_install_removes_only_new_configs(self):
        self.fs.write(self.fs.path('/etc/fail2ban/jail.d/operator.local'), '[sshd]\nenabled=true\n')
        self.fail_test = True
        with self.assertRaises(RuntimeError):
            self.operation('prepare')
        self.assertIsNone(self.owned_contents()[0])
        self.assertIsNone(self.owned_contents()[1])
        self.assertIn('/etc/fail2ban/jail.d/operator.local', self.fs.nodes)

    def test_regex_qualification_failure_never_enables_jail(self):
        self.fail_regex = True
        with self.assertRaises(RuntimeError):
            self.operation('enable')
        self.assertFalse(self.active)
        self.assertIsNone(self.owned_contents()[1])
        self.assertFalse(any(args[1] == 'reload' for args in self.commands))

    def test_partial_reload_failure_rolls_back_files_and_only_our_runtime(self):
        self.seed()
        original = self.owned_contents()
        self.fail_reload = True
        with self.assertRaises(RuntimeError):
            self.operation('enable')
        self.assertEqual(self.owned_contents(), original)
        self.assertFalse(self.active)
        self.assertIn(['fail2ban-client', 'stop', self.p.PANEL_LOGIN_JAIL], self.commands)
        self.assertEqual(self.other_jails, ['sshd', 'synthetic-mail'])

    def test_successful_reload_reply_without_active_jail_is_not_success(self):
        original = self.command

        def no_activation(args, **kwargs):
            if args == ['fail2ban-client', 'reload', '--if-exists', self.p.PANEL_LOGIN_JAIL]:
                self.commands.append(list(args))
                return 0, 'synthetic OK without activation'
            return original(args, **kwargs)

        self.p.run.side_effect = no_activation
        with self.assertRaises(RuntimeError):
            self.operation('enable')
        self.assertFalse(self.active)
        self.assertIsNone(self.owned_contents()[1])

    def test_runtime_rollback_failure_is_reported_unknown_and_keeps_guard(self):
        self.seed()
        self.fail_reload = True
        original = self.command

        def cannot_stop(args, **kwargs):
            if args == ['fail2ban-client', 'stop', self.p.PANEL_LOGIN_JAIL]:
                self.commands.append(list(args))
                return 1, 'synthetic stop failure'
            return original(args, **kwargs)

        self.p.run.side_effect = cannot_stop
        with self.assertRaisesRegex(RuntimeError, 'runtime rollback UNKNOWN'):
            self.operation('enable')
        self.assertTrue(self.p.panel_login_protection_status()['enabled'])
        self.assertEqual(self.other_jails, ['sshd', 'synthetic-mail'])

    def test_failed_disable_restores_previous_configured_active_state(self):
        self.seed(enabled=True)
        self.active = True
        original = self.owned_contents()
        self.fail_stop = True
        with self.assertRaises(RuntimeError):
            self.operation('disable')
        self.assertEqual(self.owned_contents(), original)
        self.assertTrue(self.active)
        self.assertIn(['fail2ban-client', 'reload', '--if-exists', self.p.PANEL_LOGIN_JAIL], self.commands)

    def test_filter_uses_strict_message_and_trusted_unit(self):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(self.p._panel_login_filter_text())
        cfg = parser['Definition']
        self.assertEqual(cfg['failregex'], '^TT_PANEL_AUTH_FAILURE peer=<HOST> port=[0-9]{1,5}$')
        self.assertEqual(cfg['journalmatch'], '_SYSTEMD_UNIT=trusttunnel-panel.service')
        self.assertEqual(cfg['maxlines'], '1')
        self.assertIn('<F-CONTENT>', cfg['prefregex'])

    def test_raw_and_journal_formatted_ipv4_ipv6_failures_match(self):
        for prefix in ('', 'python3[42]: ', 'qa-host python3[42]: ', 'qa-host trusttunnel-panel[42]: '):
            for peer in ('198.51.100.23', '2001:db8::23', '::ffff:198.51.100.23'):
                with self.subTest(prefix=prefix, peer=peer):
                    self.assertEqual(self.model_matches(prefix + 'TT_PANEL_AUTH_FAILURE peer=' + peer + ' port=8088',
                                                        self.p._panel_login_filter_text()), 1)

    def test_untrusted_request_fragments_and_extra_fields_do_not_match(self):
        lines = ['GET /TT_PANEL_AUTH_FAILURE peer=198.51.100.23 port=8088',
                 'username=TT_PANEL_AUTH_FAILURE peer=198.51.100.23 port=8088',
                 'TT_PANEL_AUTH_FAILURE peer=198.51.100.23 port=8088 password=secret',
                 'TT_PANEL_AUTH_FAILURE peer=198.51.100.23 port=8088 X-Forwarded-For=203.0.113.2',
                 'TT_PANEL_AUTH_FAILURE peer=attacker.invalid port=8088',
                 'TT_PANEL_AUTH_FAILURE peer=999.999.999.999 port=8088',
                 'TT_PANEL_AUTH_FAILURE peer=198.51.100.23 port=808888',
                 'GET /\nTT_PANEL_AUTH_FAILURE peer=198.51.100.23 port=8088']
        for prefix in ('', 'qa-host python3[42]: '):
            for line in lines:
                with self.subTest(line=prefix + line):
                    self.assertEqual(self.model_matches(prefix + line, self.p._panel_login_filter_text()), 0)

    def test_loopback_is_explicitly_ignored(self):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(self.p._panel_login_jail_text('8088', True))
        cfg = parser[self.p.PANEL_LOGIN_JAIL]
        networks = [ipaddress.ip_network(value) for value in cfg['ignoreip'].split()]
        for value in ('127.0.0.1', '127.2.3.4', '::1', '::ffff:127.0.0.1'):
            address = ipaddress.ip_address(value)
            self.assertTrue(any(address.version == net.version and address in net for net in networks))
        self.assertEqual(cfg['usedns'], 'no')

    def test_forwarded_identity_is_never_added_to_ignore_list(self):
        self.operation('enable', _peer='203.0.113.99', forwarded='203.0.113.98')
        self.assertNotIn('203.0.113.', self.fs.read(self.jail_path))

    def test_no_global_service_restart_stop_reload_or_direct_ban(self):
        self.operation('prepare')
        self.operation('enable')
        self.operation('disable')
        for args in self.commands:
            self.assertIn(args[0], ('fail2ban-client', 'fail2ban-regex'))
            if args[0] == 'fail2ban-client':
                self.assertIn(args, [['fail2ban-client', 'status'], ['fail2ban-client', '-t'],
                                     ['fail2ban-client', 'reload', '--if-exists', self.p.PANEL_LOGIN_JAIL],
                                     ['fail2ban-client', 'stop', self.p.PANEL_LOGIN_JAIL]])


@unittest.skipUnless(NATIVE_FILTER is not None, 'Native Linux filter qualification is explicit and separate.')
class NativeLinuxFilterQualification(unittest.TestCase):
    def test_real_fail2ban_regex_without_any_jail_or_journal(self):
        self.assertEqual(os.name, 'posix', 'Use an isolated Linux environment, not production.')
        self.assertIsNotNone(shutil.which('fail2ban-regex'), 'Install distro Fail2ban in the isolated lab first.')
        p = snippet_namespace() if SNIPPET_MODE else panel
        p._panel_login_check_path(NATIVE_FILTER)
        self.assertEqual(NATIVE_FILTER.name, 'trusttunnel-panel.conf')
        self.assertEqual(NATIVE_FILTER.read_text(), p._panel_login_filter_text())
        p._panel_login_filter_check(NATIVE_FILTER)


class SyntheticResult(unittest.TextTestResult):
    def _exc_info_to_string(self, err, test):
        kind, error, traceback = err
        frames = []
        while traceback:
            code = traceback.tb_frame.f_code
            frames.append('%s:%s in %s' % (code.co_filename, traceback.tb_lineno, code.co_name))
            traceback = traceback.tb_next
        return '\n'.join(frames + [kind.__name__ + ': ' + str(error)]) + '\n'


def synthetic_guard(event, args):
    if event == 'open':
        name, mode, flags = args
        if mode is None or any(letter in mode for letter in 'wax+'):
            raise RuntimeError('Real filesystem write blocked by synthetic test guard')
    if event.startswith('subprocess.'):
        if NATIVE_FILTER is not None and event == 'subprocess.Popen':
            argv = args[1]
            if isinstance(argv, list) and argv[0] == 'fail2ban-regex' and str(NATIVE_FILTER) == argv[-1]:
                return
        raise RuntimeError('Only explicit jailless fail2ban-regex qualification may execute a process')
    if event.startswith(('socket.', 'shutil.')) or event in {
        'os.system', 'os.mkdir', 'os.remove', 'os.rename', 'os.rmdir', 'os.chmod',
        'os.chown', 'os.link', 'os.symlink', 'os.truncate', 'os.utime', 'os.startfile',
    }:
        raise RuntimeError('Real filesystem/network mutation blocked: ' + event)


if __name__ == '__main__':
    print('Target: ' + ('snippet AST with test_admin.panel globals' if SNIPPET_MODE else 'integrated test_admin.panel functions'), flush=True)
    print('All runtime/config mutations mocked; native filter check is separate and opt-in.', flush=True)
    sys.addaudithook(synthetic_guard)
    unittest.main(testRunner=unittest.TextTestRunner(verbosity=2, resultclass=SyntheticResult))

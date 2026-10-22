#!/usr/bin/env python3
"""Route only an explicitly assigned systemd slice through a WARP interface.

No host default routes, forwarding rules, SSH rules, or user accounts are changed.
The separate table retains a blackhole route if the WireGuard device disappears.
"""
import argparse
import configparser
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


class Policy:
    def __init__(self, test=False, transport='wireguard'):
        if transport not in ('wireguard', 'masque'): raise ValueError('Unknown interface transport')
        self.transport, self.test = transport, test
        self.nic = 'ttwarptest' if test else 'ttwarp0'
        self.slice = 'ttwarptest.slice' if test else 'ttwarp.slice'
        self.table = '51889' if test else '51888'
        self.mark = '0x5455' if test else '0x5454'
        self.outer_mark = '0x5457' if test else '0x5456'
        self.priority = '10545' if test else '10544'
        self.chain = 'TT_WARP_TEST' if test else 'TT_WARP'
        if transport == 'masque':
            self.nic = 'ttmasqtest' if test else 'ttmasq0'
            self.table = '51891' if test else '51890'
            self.mark = '0x5459' if test else '0x5458'
            self.outer_mark = '0x545b' if test else '0x545a'
            self.priority = '10547' if test else '10546'
            self.chain = 'TT_MASQ_TEST' if test else 'TT_MASQUE'
        self.port = 18443 if test else None
        self.state = Path('/run/trusttunnel-warp-interface') / (self.nic + '.json')

    def run(self, *args, check=True):
        result = subprocess.run(list(args), capture_output=True, text=True, timeout=20)
        if check and result.returncode:
            # Never include wg setconf input or account material in error output.
            raise RuntimeError('Не выполнена команда: ' + ' '.join(args[:3]))
        return result

    def profile(self):
        if self.transport == 'masque':
            filename = '/root/trusttunnel-staging-20261022/masque-tun/config.json' if self.test else '/opt/warp-masque-tun/config.json'
            data = json.loads(Path(filename).read_text())
            return None, [ipaddress.ip_interface(data[key]) for key in ('ipv4', 'ipv6') if data.get(key)]
        config = configparser.ConfigParser(interpolation=None, strict=True)
        # Separate registration prevents peer-endpoint roaming between the
        # always-on wireproxy service and the kernel WireGuard interface.
        filename = '/root/trusttunnel-staging-20261022/interface-wgcf/wgcf-profile.conf' if self.nic == 'ttwarptest' else '/opt/warp-interface/wgcf/wgcf-profile.conf'
        config.read(filename)
        interface, peer = config['Interface'], config['Peer']
        addresses = [ipaddress.ip_interface(v.strip()) for v in interface['Address'].split(',')]
        body = '[Interface]\nPrivateKey = ' + interface['PrivateKey'] + '\nFwMark = ' + self.outer_mark + '\n\n[Peer]\n'
        body += ''.join(key + ' = ' + peer[key] + '\n' for key in ('PublicKey', 'Endpoint', 'AllowedIPs'))
        body += 'PersistentKeepalive = 25\n'
        if peer.get('PresharedKey'): body += 'PresharedKey = ' + peer['PresharedKey'] + '\n'
        return body, addresses

    def preflight(self):
        if not Path('/sys/fs/cgroup/' + self.slice).is_dir():
            raise RuntimeError('Нет выделенного systemd slice. Запускайте интерфейс через меню или systemd.')
        if Path('/proc/sys/net/ipv4/conf/all/rp_filter').read_text().strip() == '1':
            raise RuntimeError('Глобальный strict rp_filter несовместим с этим режимом. Настройка ОС не изменена.')
        if self.state.exists(): return
        if self.transport == 'wireguard' and self.run('ip', 'link', 'show', self.nic, check=False).returncode == 0:
            raise RuntimeError('Имя интерфейса уже занято; автоматическое удаление отменено.')
        for family, tool in (('-4', 'iptables'), ('-6', 'ip6tables')):
            if self.run('ip', family, 'route', 'show', 'table', self.table, check=False).stdout.strip():
                raise RuntimeError('Таблица маршрутизации занята.')
            rules = self.run('ip', family, 'rule', 'show').stdout.splitlines()
            if any(line.split(':', 1)[0].strip() == self.priority or self.mark in line for line in rules):
                raise RuntimeError('Приоритет или метка маршрутизации заняты.')
            if self.run(tool, '-w', '5', '-t', 'mangle', '-S', self.chain, check=False).returncode == 0:
                raise RuntimeError('Имя цепочки firewall уже занято.')

    def start(self):
        self.preflight()
        if self.state.exists():
            raise RuntimeError('Политика уже установлена. Используйте управляемый перезапуск, чтобы не очищать активную цепочку.')
        body, addresses = self.profile()
        if self.port is None:
            try: import tomllib
            except ImportError: import tomli as tomllib
            address = tomllib.loads(Path('/opt/trusttunnel/vpn.toml').read_text())['listen_address']
            self.port = int(address.rsplit(':', 1)[1])
        self.state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state.parent, 0o700)
        self.state.write_text(json.dumps({'interface': self.nic, 'table': self.table, 'port': self.port}))
        os.chmod(self.state, 0o600)
        try:
            if self.transport == 'wireguard':
                if self.run('ip', 'link', 'show', self.nic, check=False).returncode:
                    self.run('ip', 'link', 'add', self.nic, 'type', 'wireguard')
                fd, filename = tempfile.mkstemp(dir=self.state.parent)
                try:
                    with os.fdopen(fd, 'w') as output: output.write(body)
                    self.run('wg', 'setconf', self.nic, filename)
                finally:
                    Path(filename).unlink(missing_ok=True)
            else:
                for _ in range(50):
                    if self.run('ip', 'link', 'show', self.nic, check=False).returncode == 0: break
                    time.sleep(.2)
                else: raise RuntimeError('MASQUE TUN не появился.')
            for address in addresses:
                self.run('ip', 'address', 'replace', str(address), 'dev', self.nic)
            self.run('ip', 'link', 'set', self.nic, 'mtu', '1280', 'up')
            Path('/proc/sys/net/ipv4/conf/' + self.nic + '/rp_filter').write_text('0')
            for family, tool, loopback in (('-4', 'iptables', '127.0.0.0/8'), ('-6', 'ip6tables', '::1/128')):
                self.run('ip', family, 'route', 'replace', 'blackhole', 'default', 'table', self.table, 'metric', '32760')
                version = 4 if family == '-4' else 6
                if any(a.version == version for a in addresses):
                    self.run('ip', family, 'route', 'replace', 'default', 'dev', self.nic, 'table', self.table, 'metric', '10')
                existing = self.run('ip', family, 'rule', 'show').stdout
                if not any(line.split(':', 1)[0].strip() == self.priority for line in existing.splitlines()):
                    self.run('ip', family, 'rule', 'add', 'priority', self.priority, 'fwmark', self.mark + '/0xffffffff', 'lookup', self.table)
                base = [tool, '-w', '5', '-t', 'mangle']
                self.run(*base, '-N', self.chain, check=False)
                self.run(*base, '-F', self.chain)
                self.run(*base, '-A', self.chain, '-m', 'mark', '--mark', self.outer_mark + '/0xffffffff', '-j', 'RETURN')
                self.run(*base, '-A', self.chain, '-d', loopback, '-j', 'RETURN')
                for protocol in ('tcp', 'udp'):
                    self.run(*base, '-A', self.chain, '-p', protocol, '--sport', str(self.port), '-j', 'RETURN')
                self.run(*base, '-A', self.chain, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', '-j', 'TCPMSS', '--set-mss', '1200')
                self.run(*base, '-A', self.chain, '-j', 'MARK', '--set-xmark', self.mark + '/0xffffffff')
                jump = ['OUTPUT', '-m', 'cgroup', '--path', self.slice, '-j', self.chain]
                if self.run(*base, '-C', *jump, check=False).returncode:
                    self.run(*base, '-A', *jump)
                # OUTPUT marking reroutes an already source-selected socket. Use
                # the WARP address, never the VPS source address inside the tunnel.
                nat = [tool, '-w', '5', '-t', 'nat']
                translation = ['POSTROUTING', '-o', self.nic, '-m', 'mark', '--mark', self.mark + '/0xffffffff', '-j', 'MASQUERADE']
                if self.run(*nat, '-C', *translation, check=False).returncode:
                    self.run(*nat, '-A', *translation)
        except Exception:
            self.stop()
            raise

    def stop(self):
        if not self.state.exists(): return
        for family, tool in (('-4', 'iptables'), ('-6', 'ip6tables')):
            base = [tool, '-w', '5', '-t', 'mangle']
            jump = ['OUTPUT', '-m', 'cgroup', '--path', self.slice, '-j', self.chain]
            for _ in range(4):
                if self.run(*base, '-D', *jump, check=False).returncode: break
            self.run(*base, '-F', self.chain, check=False)
            self.run(*base, '-X', self.chain, check=False)
            self.run(tool, '-w', '5', '-t', 'nat', '-D', 'POSTROUTING', '-o', self.nic, '-m', 'mark', '--mark', self.mark + '/0xffffffff', '-j', 'MASQUERADE', check=False)
            self.run('ip', family, 'rule', 'del', 'priority', self.priority, 'fwmark', self.mark + '/0xffffffff', 'lookup', self.table, check=False)
            self.run('ip', family, 'route', 'flush', 'table', self.table, check=False)
        if self.transport == 'wireguard': self.run('ip', 'link', 'delete', self.nic, check=False)
        self.state.unlink(missing_ok=True)

    def refresh(self):
        if not self.state.exists(): return
        _, addresses = self.profile()
        for family, version in (('-4', 4), ('-6', 6)):
            if any(a.version == version for a in addresses):
                self.run('ip', family, 'route', 'replace', 'default', 'dev', self.nic, 'table', self.table, 'metric', '10')

    def watchdog(self):
        if not self.state.exists(): return
        if self.run('ip', 'link', 'show', self.nic, check=False).returncode:
            self.run('systemctl', 'restart', 'warp-interface', 'trusttunnel')
        else:
            self.refresh()

    def status(self):
        print('Интерфейс: ' + self.nic)
        if self.transport == 'wireguard':
            stamps = [line.split()[-1] for line in self.run('wg', 'show', self.nic, 'latest-handshakes', check=False).stdout.splitlines()]
            print('Последние handshake: ' + ', '.join(stamps))
        print(self.run('ip', '-4', 'route', 'show', 'table', self.table, check=False).stdout.strip() or 'Нет маршрута')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('start', 'stop', 'status', 'refresh', 'watchdog'))
    parser.add_argument('--test', action='store_true')
    parser.add_argument('--transport', choices=('wireguard', 'masque'), default='wireguard')
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Нужны права root')
    policy = Policy(args.test, args.transport)
    try:
        getattr(policy, args.action)()
    except (OSError, ValueError, KeyError, configparser.Error, RuntimeError, subprocess.TimeoutExpired) as exc:
        print('Ошибка интерфейсного WARP: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__': main()

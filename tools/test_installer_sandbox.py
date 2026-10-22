"""Linux-only installer tests in a temporary tree; no live certificate/firewall changes."""
import os
from pathlib import Path
import subprocess
import tempfile

source = Path(os.environ.get('TT_INSTALLER_SOURCE', Path(__file__).parents[1] / 'install-trusttunnel-warp.sh')).read_text()
library = source.rsplit('\nmain "$@"', 1)[0]
with tempfile.TemporaryDirectory(prefix='tt-installer-test-') as directory:
    root = Path(directory)
    (root / 'bin').mkdir(); (root / 'certs').mkdir()
    systemctl = root / 'bin/systemctl'
    systemctl.write_text('#!/bin/sh\nif [ "$1" = restart ] && [ -f "$TT_TEST_ROOT/fail-restart" ]; then rm "$TT_TEST_ROOT/fail-restart"; exit 1; fi\nexit 0\n')
    systemctl.chmod(0o700)
    env = dict(os.environ, PATH=str(root / 'bin') + ':' + os.environ['PATH'], TT_TEST_ROOT=str(root))
    def bash(body, check=True):
        code = library + '\nTT_DIR="$TT_TEST_ROOT"\nDOMAIN=example.test\n' + body
        return subprocess.run(['bash', '-c', code], env=env, check=check, text=True, capture_output=True, timeout=15)
    for name in ('first', 'second'):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', str(root / (name + '.key')), '-out', str(root / (name + '.pem')), '-days', '2', '-subj', '/CN=example.test', '-addext', 'subjectAltName=DNS:example.test'], check=True, capture_output=True)
    hosts = root / 'hosts.toml'
    hosts.write_text('ping_hosts=[]\n[[main_hosts]]\nhostname="example.test"\ncert_chain_path="old.pem"\nprivate_key_path="old.key"\nallowed_sni=[]\n[[main_hosts]]\nhostname="other.test"\ncert_chain_path="other.pem"\nprivate_key_path="other.key"\n')
    bash('deploy_certificate_pair "$TT_DIR/first.pem" "$TT_DIR/first.key"')
    assert 'cert_chain_path = "certs/cert.pem"' in hosts.read_text()
    assert 'cert_chain_path="other.pem"' in hosts.read_text()
    files = [hosts, root / 'certs/cert.pem', root / 'certs/key.pem']
    before = [p.read_bytes() for p in files]
    assert bash('deploy_certificate_pair "$TT_DIR/second.pem" "$TT_DIR/first.key"', check=False).returncode != 0
    assert before == [p.read_bytes() for p in files]
    (root / 'fail-restart').touch()
    assert bash('deploy_certificate_pair "$TT_DIR/second.pem" "$TT_DIR/second.key"', check=False).returncode != 0
    assert before == [p.read_bytes() for p in files]
    print('Certificate pair validation, matching-host references and restart rollback: PASS')
    result = bash('''
load_current_trusttunnel_context() { CERT_MODE=letsencrypt; }
ask_cert_mode() { CERT_MODE=self-signed; }
confirm_action() { :; }
write_self_signed_cert() { echo switched-self-signed; }
write_clients() { :; }
remove_certificate_automation() { :; }
CERT_MODE=""
switch_certificate_mode
'''.replace('switch_certificate_mode\n', 'switch_certificate_mode </dev/null\n'))
    assert 'switched-self-signed' in result.stdout
    print('Interactive certificate mode selection: PASS')
    unit_root = root / 'units'; unit_root.mkdir()
    command_root = root / 'commands'; command_root.mkdir()
    remapped = library.replace('/usr/local/sbin/', str(command_root) + '/').replace('/etc/systemd/system/', str(unit_root) + '/')
    subprocess.run(['bash', '-c', remapped + '\nTT_DIR="$TT_TEST_ROOT"\nDOMAIN=example.test\nCERT_MODE=letsencrypt\nEMAIL=test@example.test\nwrite_certificate_automation\n'], env=env, check=True, capture_output=True)
    for filename in ('trusttunnel-cert-renew', 'trusttunnel-cert-deploy'):
        subprocess.run(['bash', '-n', str(command_root / filename)], check=True)
    renew = (command_root / 'trusttunnel-cert-renew').read_text()
    assert '--cert-name "${DOMAIN}" "$@"' in renew
    assert '"$RENEWED_LINEAGE"' in renew
    assert 'trap cleanup EXIT' in renew and '--no-random-sleep-on-renew' in renew
    print('Generated renewal/deploy scripts, quoting, cleanup trap and cert-name scoping: PASS')
    (root / 'bin/ufw').write_text('#!/bin/sh\nif [ "$1" = status ]; then echo "Status: active"; else echo "$*" >> "$TT_TEST_ROOT/ufw-actions"; fi\n')
    (root / 'bin/ufw').chmod(0o700)
    (root / 'bin/certbot').write_text('#!/bin/sh\nexit 42\n'); (root / 'bin/certbot').chmod(0o700)
    result = subprocess.run(['bash', str(command_root / 'trusttunnel-cert-renew')], env=env, capture_output=True)
    assert result.returncode == 42
    actions = (root / 'ufw-actions').read_text()
    assert 'insert 1 allow 80/tcp' in actions and '--force delete allow 80/tcp' in actions
    print('Failed ACME renewal removes only its temporary 80/tcp allowance: PASS')
    backup = root/'bad-backup'; (backup/'certs').mkdir(parents=True)
    (backup/'certs/cert.pem').write_bytes((root/'second.pem').read_bytes())
    (backup/'certs/key.pem').write_bytes((root/'first.key').read_bytes())
    (backup/'credentials.toml').write_text('[[client]]\nusername="test"\npassword="test-secret"\n')
    result = bash('IDENTITY_BACKUP_DIR="$TT_TEST_ROOT/bad-backup"\nCLIENT_DIR="$TT_TEST_ROOT/exports"\nrestore_identity\n',check=False)
    assert result.returncode != 0 and before == [p.read_bytes() for p in files]
    print('Identity restore rejects mismatched backup certificates before replacing live files: PASS')
    result=bash('prompt_value "Test: " </dev/null\n',check=False)
    assert result.returncode != 0
    print('Closed stdin does not choose installation or loop indefinitely: PASS')
    tools_root=root/'tool-commands';tools_root.mkdir()
    library_root=root/'tool-library';library_root.mkdir()
    target=tools_root/'trusttunnel-menu';target.write_text('# old command\n')
    (tools_root/'ttmenu').symlink_to(target)
    tool_library=library.replace('/usr/local/sbin/',str(tools_root)+'/').replace('/usr/local/lib/trusttunnel',str(library_root))
    # The test source is a full private file so BASH_SOURCE points to a real installer.
    test_source=root/'tool-source.sh';test_source.write_text(tool_library+'\nwrite_tools\n')
    subprocess.run(['bash',str(test_source)],env=env,check=True,capture_output=True,timeout=10)
    assert not (tools_root/'ttmenu').is_symlink()
    assert 'exec bash "$INSTALLED"' in (tools_root/'ttmenu').read_text()
    assert 'exec '+str(tools_root)+'/ttmenu' in target.read_text()
    result=subprocess.run(['bash',str(tools_root/'ttmenu')],env=dict(env,ACTION='exit'),capture_output=True,timeout=5)
    assert result.returncode==0
    print('Legacy symlink menu upgrade creates separate commands without an exec loop: PASS')

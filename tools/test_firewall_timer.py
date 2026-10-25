"""Opt-in Linux/systemd integration: only synthetic files, never real UFW commands."""
import importlib.util
import json
import os
from pathlib import Path
import sys

source=Path(os.environ.get('TT_PANEL_SOURCE',Path(__file__).parents[1]/'trusttunnel-panel.py')).resolve()
spec=importlib.util.spec_from_file_location('timer_panel',source)
p=importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
root=Path(__file__).resolve().with_name('timer-fixture')
p.UFW_DIR=root/'ufw'; p.UFW_DEFAULTS=root/'defaults'; p.FIREWALL_PENDING=root/'state/pending.json'
p.TT_DIR=root/'tt'; p.PANEL_AUDIT_LOG=root/'audit.log'; p.__file__=__file__
real_run=p.run


def synthetic_run(args,**kwargs):
    if args[0]=='ufw':
        return (0,'Status: active') if args==['ufw','status'] else (0,'Synthetic UFW: no real firewall changes')
    return real_run(args,**kwargs)


p.run=synthetic_run


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--firewall-rollback':
        p.firewall_rollback(sys.argv[2])
    elif sys.argv[1:]==['--allow-systemd-timer-test']:
        assert sys.platform.startswith('linux') and os.geteuid()==0
        assert not root.exists(),'Existing fixture: inspect it instead of overwriting'
        root.mkdir(mode=0o700)
        for path in p.firewall_files().values():
            path.parent.mkdir(parents=True,exist_ok=True); path.write_text('original synthetic file\n')
        with p.admin_lock(): p.firewall_operation('reload',{'confirm':'CONFIRMED'})
        pending=p.firewall_pending()
        (root/'timer-unit.json').write_text(json.dumps({'unit':pending['unit'],'deadline':pending['deadline']}))
        for path in p.firewall_files().values(): path.write_text('modified synthetic file\n')
        print('Independent 120s systemd rollback armed; process exits now. Real UFW untouched.')
    elif sys.argv[1:]==['--verify']:
        assert root.exists()
        unit=json.loads((root/'timer-unit.json').read_text())['unit']
        assert not p.firewall_pending(),'Rollback has not completed'
        assert all(path.read_text()=='original synthetic file\n' for path in p.firewall_files().values())
        assert p.checked_run(['systemctl','show',unit+'.service','--property=Result','--value'])=='success'
        print('Independent systemd timer restored all synthetic files after the initiating process exited: PASS')
    else:
        raise SystemExit('Explicit --allow-systemd-timer-test or --verify required')

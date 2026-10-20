#!/usr/bin/env python3
"""Reproduce the VM matrix and retain JSON/JUnit logs, including failures."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
import traceback
import xml.etree.ElementTree as ET

import lab

REPORTS = lab.ROOT / '.build/reports/vm'


def main():
    REPORTS.mkdir(parents=True, exist_ok=True)
    report = {'started_utc': datetime.now(timezone.utc).isoformat(), 'image_sha512': lab.BASE_SHA512, 'checks': []}
    suite = ET.Element('testsuite', name='debian13-qemu')
    completed = False
    def phase(name, function):
        print(name, flush=True)
        started = time.monotonic()
        entry = {'name': name, 'status': 'failed'}
        case = ET.SubElement(suite, 'testcase', classname='debian13.qemu', name=name)
        try:
            function()
            entry['status'] = 'passed'
        except Exception:
            entry['error'] = traceback.format_exc()
            ET.SubElement(case, 'failure').text = entry['error']
            raise
        finally:
            elapsed = time.monotonic() - started
            entry['seconds'] = elapsed
            case.set('time', str(elapsed))
            report['checks'].append(entry)
    def guest(script, *args):
        name = Path(script).name
        lab.run(sys.executable, str(lab.ROOT/'tests/vm/lab.py'), 'copy', str(lab.ROOT/script), '/tmp/'+name)
        result = lab.ssh('sudo env D13DP_ISOLATED_QA=1 /opt/d13dp/bin/python /tmp/' + name + (' ' + ' '.join(args) if args else ''), check=False, timeout=1200)
        (REPORTS / (name + ('-'.join(args) if args else '') + '.log')).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        print(result.stdout, flush=True)
    try:
        phase('runner-image', lambda: lab.run('docker', 'build', '-t', lab.IMAGE, '-f', str(lab.ROOT/'tests/vm/Dockerfile.runner'), str(lab.ROOT), timeout=600))
        phase('prepare', lab.prepare)
        phase('boot', lab.start)
        phase('cloud-init', lab.wait_guest)
        def install():
            lab.run(sys.executable, '-m', 'build', '--wheel', '--outdir', str(lab.WORK/'wheels'), str(lab.ROOT), timeout=300)
            wheel = next((lab.WORK/'wheels').glob('*.whl'))
            lab.run(sys.executable, str(lab.ROOT/'tests/vm/lab.py'), 'copy', str(wheel), '/tmp/'+wheel.name)
            lab.ssh('sudo python3 -m venv /opt/d13dp && sudo /opt/d13dp/bin/pip install --no-index --no-deps /tmp/'+wheel.name, timeout=120)
        phase('install-wheel', install)
        phase('network-transactions', lambda: guest('tests/vm/network_transactions.py'))
        phase('debian-parsers', lambda: guest('tests/vm/parsers.py'))
        phase('recognized-migration', lambda: guest('tests/vm/migration_transactions.py'))
        phase('sigkill-boundaries', lambda: guest('tests/vm/crash_recovery.py'))
        phase('prepare-pending-migration-boot', lambda: guest('tests/vm/crash_recovery.py', '--prepare-migration-boot'))
        phase('cold-boot-initial-migration', lambda: lab.run(sys.executable, str(lab.ROOT/'tests/vm/lab.py'), 'cold-boot', timeout=600))
        # /tmp is cleared at boot: refresh helper modules before recovery assertions.
        def refresh_helpers():
            for name in ('network_transactions.py','migration_transactions.py'):
                lab.run(sys.executable, str(lab.ROOT/'tests/vm/lab.py'), 'copy', str(lab.ROOT/'tests/vm'/name), '/tmp/'+name)
        phase('refresh-boot-helpers', refresh_helpers)
        phase('verify-initial-migration-recovery', lambda: guest('tests/vm/crash_recovery.py', '--check-migration-boot'))
        phase('prepare-pending-boot', lambda: guest('tests/vm/network_transactions.py', '--prepare-boot'))
        phase('cold-boot-pending', lambda: lab.run(sys.executable, str(lab.ROOT/'tests/vm/lab.py'), 'cold-boot', timeout=600))
        phase('verify-boot-rollback', lambda: guest('tests/vm/network_transactions.py', '--check-boot'))
        phase('cold-boot-committed', lambda: lab.run(sys.executable, str(lab.ROOT/'tests/vm/lab.py'), 'cold-boot', timeout=600))
        phase('verify-committed-persistence', lambda: guest('tests/vm/network_transactions.py', '--check-boot'))
        completed = True
    finally:
        for name, command in {
            'nftables.json': 'sudo nft -j list ruleset',
            'status.json': 'sudo /opt/d13dp/bin/d13dp network status',
            'services.log': 'sudo systemctl --no-pager status d13dp-network nftables fail2ban ssh docker',
            'journal.log': 'sudo journalctl -b -u d13dp-network.service -u nftables.service --no-pager',
            'packages.log': 'dpkg-query -W python3 systemd nftables openssh-server fail2ban docker.io linux-image-cloud-amd64',
            'fail2ban.log': 'sudo fail2ban-client status sshd',
        }.items():
            try:
                result = lab.ssh(command, check=False, timeout=30)
                (REPORTS / name).write_text(result.stdout + result.stderr)
            except Exception as exc:
                (REPORTS / name).write_text(str(exc))
        report['passed'] = completed and all(entry['status'] == 'passed' for entry in report['checks'])
        (REPORTS/'matrix.json').write_text(json.dumps(report, indent=2)+'\n')
        suite.set('tests', str(len(report['checks'])))
        suite.set('failures', str(sum(entry['status'] != 'passed' for entry in report['checks'])))
        ET.ElementTree(suite).write(REPORTS/'junit.xml', encoding='utf-8', xml_declaration=True)
        lab.run('docker', 'stop', '--time', '20', lab.NAME, check=False, timeout=40)
    print('VM matrix passed; reports: ' + str(REPORTS), flush=True)


if __name__ == '__main__':
    main()

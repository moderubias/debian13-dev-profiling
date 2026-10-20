"""Validate candidate files with Debian tools inside the disposable QEMU guest."""
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, '/tmp')
from network_transactions import guard, run

CLI = '/opt/d13dp/bin/d13dp'


def main():
    guard()
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        for profile in ('minimal', 'web', 'docker'):
            output = base/profile
            run(CLI, 'render', '--profile', profile, '--output', str(output))
            assert 'written' not in run(CLI, 'render', '--profile', profile, '--output', str(output)).stdout
            manifest = json.loads(run(CLI, 'manifest', '--profile', profile).stdout)
            assert all(sha256((output/name).read_bytes()).hexdigest() == digest for name,digest in manifest.items())
            ssh = output/'ssh/00-d13dp-hardening.conf'
            run('/usr/sbin/sshd', '-t', '-f', str(ssh))
            effective = run('/usr/sbin/sshd', '-T', '-f', str(ssh)).stdout
            assert 'passwordauthentication no' in effective
            f2b = output/'f2b-fixture'
            shutil.copytree('/etc/fail2ban', f2b)
            (f2b/'jail.d/52-d13dp-sshd.local').write_bytes((output/'fail2ban/52-d13dp-sshd.local').read_bytes())
            run('fail2ban-client', '-c', str(f2b), '-t')
            combined = output/'apt-candidate.conf'
            combined.write_text(''.join(candidate.read_text() for candidate in sorted((output/'apt').iterdir())))
            apt = run('apt-config', '-c', str(combined), 'dump').stdout
            assert 'APT::Periodic::Unattended-Upgrade "1";' in apt
            assert 'Unattended-Upgrade::Automatic-Reboot "false";' in apt
            if profile != 'docker':
                candidate = output/'nft/d13dp.nft'
                run('nft', '-c', '-f', str(candidate))
                try:
                    run('nft', '-f', str(candidate))
                    run('nft', '-f', str(candidate))
                finally:
                    run('nft', 'destroy', 'table', 'inet', 'd13dp_filter')
    print('Debian parser and candidate idempotence checks passed', flush=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Disposable QEMU Debian 13 guest; never execute test networking on the host."""
import argparse
from hashlib import sha512
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / '.build/vm'
IMAGE = 'd13dp-vm-runner:local'
NAME = 'd13dp-debian13-vm'
BASE_URL = 'https://cloud.debian.org/images/cloud/trixie/20261017-2634/debian-13-genericcloud-amd64-20261017-2634.qcow2'
BASE_SHA512 = 'ec584ccabfef7120b4c4f7482adf0e615894d9292cedec446b64194b951ebe5dd97c336b5dcbae458333764b0edd516334506017f33c4f2020ef8d38b569ffe3'


def download():
    WORK.mkdir(parents=True, exist_ok=True)
    WORK.chmod(0o700)
    target = WORK / 'base.qcow2'
    if not target.exists():
        temporary = WORK / 'base.download'
        with urllib.request.urlopen(BASE_URL, timeout=60) as response, temporary.open('wb') as stream:
            while chunk := response.read(1024 * 1024):
                stream.write(chunk)
        temporary.replace(target)
    digest = sha512()
    with target.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != BASE_SHA512:
        raise RuntimeError('Pinned Debian image checksum mismatch')
    (WORK / 'verified.sha512').write_text(BASE_SHA512 + '\n')
    print('Pinned Debian 13 cloud image verified', flush=True)


def run(*args, check=True, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f'{shlex.join(map(str,args))}: {result.stderr or result.stdout}')
    return result


def config():
    return json.loads((WORK/'lab.json').read_text())


def ssh_args():
    return ['ssh', '-F', '/dev/null', '-i', str(WORK/'id_ed25519'), '-p', str(config()['ssh_port']),
            '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', f'UserKnownHostsFile={WORK / "known_hosts"}', '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=5', 'qa@127.0.0.1']


def ssh(command, **kwargs):
    return run(*ssh_args(), command, **kwargs)


def prepare():
    download()
    if (WORK/'lab.json').exists():
        raise RuntimeError('Existing VM state: retain it for debugging or explicitly remove .build/vm/lab.json and disks')
    if not (WORK/'id_ed25519').exists():
        run('ssh-keygen','-q','-t','ed25519','-N','','-f',str(WORK/'id_ed25519'))
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port=sock.getsockname()[1]
    metadata={'instance-id':'d13dp-'+secrets.token_hex(12),'local-hostname':'d13dp-qa'}
    user={'users':[{'name':'qa','groups':'sudo','shell':'/bin/bash','sudo':'ALL=(ALL) NOPASSWD:ALL',
                   'lock_passwd':True,'ssh_authorized_keys':[(WORK/'id_ed25519.pub').read_text().strip()]}],
          'ssh_pwauth':False,'disable_root':False,
          'write_files':[{'path':'/etc/d13dp-qa-vm','permissions':'0600','content':metadata['instance-id']}],
          'package_update':True,'packages':['python3-venv','python3-build','python3-setuptools','python3-wheel',
              'nftables','iproute2','conntrack','fail2ban','docker.io','unattended-upgrades','apparmor-utils','auditd','caddy','curl'],
          'runcmd':[['sh','-c','date -u +%FT%TZ > /var/lib/cloud/instance/d13dp-ready']]}
    (WORK/'user-data').write_text('#cloud-config\n'+json.dumps(user))
    (WORK/'meta-data').write_text(json.dumps(metadata))
    for path in (WORK/'user-data',WORK/'meta-data'):
        path.chmod(0o600)
    digest=sha512()
    with (WORK/'base.qcow2').open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):
            digest.update(chunk)
    if digest.hexdigest() != (WORK/'verified.sha512').read_text().strip():
        raise RuntimeError('Base image verification failed')
    docker=['docker','run','--rm','--user',f'{os.getuid()}:{os.getgid()}', '-v',f'{WORK}:/work',IMAGE]
    run(*docker,'cloud-localds','/work/seed.iso','/work/user-data','/work/meta-data')
    run(*docker,'qemu-img','create','-f','qcow2','-F','qcow2','-b','/work/base.qcow2','/work/guest.qcow2','12G')
    (WORK/'lab.json').write_text(json.dumps({'ssh_port':port,'image_sha512':digest.hexdigest(),'instance':metadata['instance-id']}))
    print(json.dumps(config()))


def start():
    run('docker','run','-d','--name',NAME,'--network','host','--user',f'{os.getuid()}:{os.getgid()}',
        '--read-only','--tmpfs','/tmp','-v',f'{WORK}:/work',IMAGE,
        'qemu-system-x86_64','-machine','q35','-accel','tcg,thread=multi','-m','1024','-smp','2',
        '-display','none','-serial','file:/work/console.log','-monitor','none',
        '-qmp','unix:/work/qmp.sock,server=on,wait=off',
        '-drive','file=/work/guest.qcow2,if=virtio,format=qcow2',
        '-drive','file=/work/seed.iso,media=cdrom,readonly=on',
        '-device','virtio-net-pci,netdev=net0','-netdev',
        f'user,id=net0,hostfwd=tcp:127.0.0.1:{config()["ssh_port"]}-:22')
    print(f'QEMU VM started; SSH loopback port {config()["ssh_port"]}')


def wait_guest():
    deadline=time.monotonic()+900
    while time.monotonic()<deadline:
        try:
            result=ssh('sudo test -f /var/lib/cloud/instance/d13dp-ready',check=False,timeout=10)
        except subprocess.TimeoutExpired:
            time.sleep(3)
            continue
        if result.returncode==0:
            result = ssh('sudo cloud-init status --format json', check=False)
            report = json.loads(result.stdout)
            (WORK / 'cloud-init.json').write_text(json.dumps(report, indent=2))
            if report.get('status') == 'running':
                time.sleep(3)
                continue
            if result.returncode or report.get('status') != 'done' or report.get('errors') or report.get('recoverable_errors'):
                raise RuntimeError('cloud-init reported provisioning errors')
            print(ssh('sudo cat /etc/os-release; uname -r; systemd-detect-virt --vm').stdout)
            return
        time.sleep(3)
    raise RuntimeError('VM provisioning timed out; inspect .build/vm/console.log and cloud-init-output.log')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('operation',choices=['download','prepare','start','wait','ssh','copy','stop','cold-boot'])
    parser.add_argument('arguments',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    if args.operation=='download': download()
    elif args.operation=='prepare': prepare()
    elif args.operation=='start': start()
    elif args.operation=='wait': wait_guest()
    elif args.operation=='ssh':
        result=ssh(shlex.join(args.arguments),check=False)
        print(result.stdout,end='')
        print(result.stderr,end='',file=__import__('sys').stderr)
        raise SystemExit(result.returncode)
    elif args.operation=='copy':
        source,target=args.arguments
        run('scp','-F','/dev/null','-i',str(WORK/'id_ed25519'),'-P',str(config()['ssh_port']),
            '-o',f'UserKnownHostsFile={WORK/"known_hosts"}','-o','BatchMode=yes',source,'qa@127.0.0.1:'+target)
    elif args.operation=='stop': run('docker','stop','--time','30',NAME)
    else:
        # Power-off, discard the emulator process, then boot the SAME persistent disk.
        ssh('sudo systemctl poweroff',check=False)
        run('docker','wait',NAME,timeout=60)
        run('docker','rm',NAME)
        start()
        wait_guest()


if __name__=='__main__': main()

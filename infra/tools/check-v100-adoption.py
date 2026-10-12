#!/usr/bin/env python3
"""Read-only post-install gate. Does not install, repair, mount or configure."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

NODES = {'g003': ('EXSERIAL03', '10.88.0.4'),
         'g004': ('EXSERIAL04', '10.88.0.5')}
FOREIGN = {'60050000a346210d311ce34853176ea6',
           '600605b0000000000000000000000002'}
PACKAGES = ['openssh-server', 'chrony', 'firewalld', 'python3-firewall',
            'python3-libselinux', 'ethtool', 'tmux', 'git', 'python3']

def require(ok, why):
    if not ok:
        raise RuntimeError(why)

def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30,
                            env=dict(os.environ, LC_ALL='C'))
    require(result.returncode == 0, 'Read-only command failed: ' + args[0] + ': ' + result.stderr.strip())
    return result.stdout.strip()

def validate_identity(node, serial, hostname, release, wwn):
    require(node in NODES, 'Unknown node')
    require(serial == NODES[node][0], 'Chassis serial mismatch')
    require(hostname == 'lab-' + node, 'Installed hostname mismatch')
    require(release.get('ID') == 'rocky' and release.get('VERSION_ID', '').split('.')[0] == '9',
            'Rocky 9 is required')
    require(re.fullmatch(r'(?:[0-9a-f]{16}|[0-9a-f]{32})', wwn), 'Use a discovered lowercase exact WWN')
    require(wwn not in FOREIGN and len(set(wwn)) > 1, 'Foreign/placeholder disk WWN rejected')

def validate_network(node, iface, mac, permanent, current, addresses, routes4, routes6):
    require(permanent.lower() == mac.lower() == current.lower(), 'Private NIC MAC mismatch')
    actual = [(nic['ifname'], a['family'], a['local'], a['prefixlen'])
              for nic in addresses for a in nic.get('addr_info', []) if a.get('scope') == 'global']
    require(actual == [(iface, 'inet', NODES[node][1], 24)],
            'Expected only the bootstrapped private IPv4 address; other global addresses are not allowed')
    require(not any(r.get('dst') == 'default' for r in routes4 + routes6), 'Default route is forbidden')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', choices=NODES, required=True)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--mac', required=True)
    parser.add_argument('--wwn', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'Root required to read installed chassis/root identity')
    require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}', args.interface), 'Invalid interface')
    require(re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', args.mac), 'Invalid MAC')
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, val = line.split('=', 1)
            release[key] = val.strip('"')
    serial = Path('/sys/class/dmi/id/product_serial').read_text().strip()
    validate_identity(args.node, serial, run('hostname'), release, args.wwn)
    require(Path('/sys/firmware/efi').is_dir(), 'Installed OS is not UEFI booted')
    aliases = [Path('/dev/disk/by-id') / name for name in
               ['wwn-0x' + args.wwn, 'scsi-3' + args.wwn]]
    targets = {str(p.resolve(strict=True)) for p in aliases if p.exists()}
    require(len(targets) == 1, 'WWN must resolve to one whole disk')
    target = targets.pop()
    require(stat.S_ISBLK(os.stat(target).st_mode), 'WWN target is not a block device')
    require(run('lsblk', '-dn', '-o', 'TYPE', target) == 'disk' and not Path(target).name.startswith('nvme'),
            'OS target must be the discovered SCSI RAID logical disk')
    root_source = run('findmnt', '-n', '-o', 'SOURCE', '/')
    ancestry = run('lsblk', '-snrp', '-o', 'NAME,TYPE', root_source)
    disks = {line.split()[0] for line in ancestry.splitlines() if line.split()[-1] == 'disk'}
    require(disks == {target}, 'Installed root does not reside solely on the selected disk')
    require(run('lvs', '--noheadings', '-o', 'vg_name', root_source).strip() == args.node + '_vg',
            'Installed root VG mismatch')
    nic = Path('/sys/class/net') / args.interface
    require((nic / 'carrier').read_text().strip() == '1', 'Private NIC has no carrier')
    require(not (nic / 'master').exists(), 'Private NIC must not be enslaved')
    permanent = run('ethtool', '-P', args.interface).split()[-1]
    validate_network(args.node, args.interface, args.mac, permanent,
                     (nic / 'address').read_text().strip(),
                     json.loads(run('ip', '-j', 'address', 'show')),
                     json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all')),
                     json.loads(run('ip', '-j', '-6', 'route', 'show', 'table', 'all')))
    route = json.loads(run('ip', '-j', 'route', 'get', '10.88.0.1'))
    require(len(route) == 1 and route[0].get('dev') == args.interface and not route[0].get('gateway'),
            'NTP peer must be directly connected on the private interface')
    require(run('nmcli', '-g', 'GENERAL.CONNECTION', 'device', 'show', args.interface) == 'private-' + args.interface,
            'Bootstrap profile is not the expected active profile')
    run('rpm', '-q', *PACKAGES)
    require(run('systemctl', 'is-active', 'firewalld') == 'active', 'firewalld must already be active')
    require(run('firewall-cmd', '--get-zone-of-interface=' + args.interface) == 'public', 'Private zone mismatch')
    require(run('getenforce') == 'Enforcing', 'SELinux must be enforcing')
    print(json.dumps({'ok': True, 'node': args.node, 'serial': serial,
                      'os_disk': target, 'wwn': args.wwn,
                      'private_ip': NODES[args.node][1], 'interface': args.interface}))

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print('ADOPTION PREFLIGHT REFUSED: ' + str(exc), file=sys.stderr)
        sys.exit(1)

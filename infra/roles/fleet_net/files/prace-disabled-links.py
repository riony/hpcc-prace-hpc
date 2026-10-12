#!/usr/bin/python3
"""D43: exact Ethernet targets only. The HTTP observation never changes a link.

OS policy is not containment against host root. Physically unplug before hostile work.
"""
import argparse
import configparser
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

POLICY = Path('/etc/prace-network/disabled-links.json')
SYS = Path('/sys/class/net')
OWNER = 0


class Refused(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    require(result.returncode == 0, 'observation_or_command_failed:' + args[0])
    return result.stdout


def validate_policy(p):
    require(isinstance(p, dict) and type(p.get('schema')) is int and p.get('schema') == 1, 'bad_policy')
    require(p.get('host') == os.uname().nodename.split('.')[0], 'wrong_host')
    require(isinstance(p.get('interfaces'), list) and len(p['interfaces']) == 2, 'two_exact_ports_required')
    protected = p.get('protected')
    require(isinstance(protected, dict) and protected, 'protected_ports_required')
    seen = set()
    for row in p['interfaces']:
        require(isinstance(row, dict) and set(row) == {'name', 'mac', 'pci'}, 'bad_interface')
        name = row['name']
        require(isinstance(name, str) and re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', name), 'bad_name')
        require(name not in seen and name not in protected, 'duplicate_or_protected_target')
        require(re.fullmatch(r'[0-9a-f]{2}(:[0-9a-f]{2}){5}', row['mac']) is not None, 'bad_mac')
        require(re.fullmatch(r'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]', row['pci']) is not None, 'bad_pci')
        seen.add(name)
    for name, address in protected.items():
        require(re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', name) is not None, 'bad_protected_name')
        ipaddress.IPv4Interface(address)
    return p


def load_policy():
    s = POLICY.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == OWNER and not s.st_mode & 0o022, 'unsafe_policy_file')
    return validate_policy(json.loads(POLICY.read_text()))


def inspect(p, protected=False):
    """Check ALL target identities before any mutation; query real host namespace."""
    validate_policy(p)
    entries = json.loads(command(['ip', '-j', 'address', 'show']))
    by_name = {x['ifname']: x for x in entries}
    rows = {}
    for target in p['interfaces']:
        name = target['name']
        d = SYS / name
        require(d.exists() and (d / 'device').exists(), 'missing_physical_target:' + name)
        require((d / 'device').resolve().name == target['pci'], 'pci_changed:' + name)
        require((d / 'address').read_text().strip().lower() == target['mac'], 'mac_changed:' + name)
        require((d / 'type').read_text().strip() == '1', 'not_ethernet:' + name)
        require(not (d / 'master').exists() and not list(d.glob('upper_*')), 'target_in_use:' + name)
        e = by_name.get(name)
        require(isinstance(e, dict), 'missing_link_observation:' + name)
        require(isinstance(e.get('flags'), list) and isinstance(e.get('addr_info'), list)
                and isinstance(e.get('operstate'), str), 'incomplete_link_observation:' + name)
        state = command(['nmcli', '-g', 'GENERAL.STATE', 'device', 'show', name]).strip()
        require(re.fullmatch(r'[0-9]+(?: \([^\n]*\))?', state) is not None, 'bad_nm_state:' + name)
        rows[name] = {'mac': target['mac'], 'pci': target['pci'], 'admin_up': 'UP' in e.get('flags', []),
                      'carrier': 'LOWER_UP' in e.get('flags', []), 'operstate': e.get('operstate'),
                      'addresses': e.get('addr_info', []), 'nm_managed': state.split()[0] != '10'}
    if protected:
        for name, address in p['protected'].items():
            e = by_name.get(name, {})
            require('UP' in e.get('flags', []) and 'LOWER_UP' in e.get('flags', []), 'protected_link_down:' + name)
            want = ipaddress.IPv4Interface(address)
            require(any(a.get('family') == 'inet' and a.get('local') == str(want.ip)
                        and a.get('prefixlen') == want.network.prefixlen for a in e.get('addr_info', [])),
                    'protected_address_changed:' + name)
    return rows


def preflight(p, boot=False):
    rows = inspect(p, protected=not boot)
    require(all(not x['addresses'] for x in rows.values()), 'target_has_address')
    routes = json.loads(command(['ip', '-j', 'route', 'show', 'table', 'all']))
    kernel_multicast = []
    for r in routes:
        uses_target = r.get('dev') in rows or any(n.get('dev') in rows for n in r.get('nexthops', []))
        if not uses_target:
            continue
        # An address-free UP interface can still have Linux's automatic IPv6
        # multicast route. Only this exact kernel/local route may disappear as
        # part of bringing the unused link down. Defaults, unicast, static,
        # multipath and any route with a gateway/source remain a hard refusal.
        harmless = (r.get('dev') in rows and r.get('type') == 'multicast'
                    and r.get('dst') == 'ff00::/8' and r.get('protocol') == 'kernel'
                    and r.get('table') == 'local'
                    and not any(k in r for k in ('gateway', 'via', 'src', 'prefsrc', 'nexthops')))
        require(harmless, 'target_has_route')
        kernel_multicast.append(r)
    # Preserve existing strict-unmanaged entries; unfamiliar selectors require review.
    cfg = configparser.ConfigParser(interpolation=None, strict=False)
    cfg.read_string(command(['NetworkManager', '--print-config']))
    prior = [s for s in cfg.get('keyfile', 'unmanaged-devices', fallback='').split(';') if s]
    require(all(re.fullmatch(r'interface-name:[a-zA-Z0-9_.-]{1,15}', s) for s in prior), 'unsupported_existing_unmanaged_selector')
    require(not any(s.split(':', 1)[1] in p['protected'] for s in prior), 'protected_port_unmanaged')
    return {'interfaces': rows, 'kernel_multicast_routes': kernel_multicast,
            'unmanaged': sorted(set(prior + ['interface-name:' + n for n in rows]))}


def hold_down(p, boot=False):
    before = preflight(p, boot)
    require(all(not x['nm_managed'] for x in before['interfaces'].values()), 'targets_still_managed')
    changed = False
    for name, row in before['interfaces'].items():
        if row['admin_up']:
            command(['ip', 'link', 'set', 'dev', name, 'down'])
            changed = True
    after = preflight(p, boot)
    require(disabled(after['interfaces']), 'link_disable_not_confirmed')
    require(not after['kernel_multicast_routes'], 'kernel_multicast_route_remains')
    return {'changed': changed, 'interfaces': after['interfaces']}


def disabled(rows):
    return bool(rows) and all(not r['admin_up'] and not r['carrier'] and r['operstate'] == 'DOWN'
                              and not r['addresses'] and not r['nm_managed'] for r in rows.values())


def snapshot():
    try:
        p = load_policy()
        rows = inspect(p)
        return {'schema': 1, 'host': p['host'], 'time': int(time.time()), 'interfaces': rows,
                'disabled': disabled(rows), 'errors': []}
    except (OSError, ValueError, KeyError, TypeError, Refused, subprocess.TimeoutExpired):
        return {'schema': 1, 'host': os.uname().nodename.split('.')[0], 'time': int(time.time()),
                'interfaces': {}, 'disabled': False, 'errors': ['link_observation_failed']}


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def do_GET(self):
        if self.path != '/v1/disabled-links':
            self.send_error(404)
            return
        raw = (json.dumps(snapshot(), sort_keys=True) + '\n').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['preflight', 'hold-down', 'check', 'serve'])
    parser.add_argument('--stdin-policy', action='store_true')
    parser.add_argument('--boot', action='store_true')
    parser.add_argument('--address')
    args = parser.parse_args()
    if args.action == 'serve':
        require(not args.stdin_policy and not args.boot and args.address, 'bad_serve_arguments')
        ipaddress.IPv4Address(args.address)
        # Single request at a time: no unbounded thread/process creation.
        server = http.server.HTTPServer((args.address, 9187), Handler)
        server.serve_forever()
        return
    p = validate_policy(json.load(sys.stdin)) if args.stdin_policy else load_policy()
    if args.action == 'preflight':
        result = preflight(p, args.boot)
    elif args.action == 'hold-down':
        result = hold_down(p, args.boot)
    else:
        result = snapshot()
        print(json.dumps(result))
        return 0 if result['disabled'] and not result['errors'] else 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, Refused, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'error': type(exc).__name__}), file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Host-storage functional acceptance core; no implicit production transport.

An adapter must implement guard(), observe(host), call(host, operation, payload).
It owns one exclusive, fenced acceptance window. Every mutation is guarded and
recorded before dispatch. This core never acquires another tool's lease, reopens
admission, releases a lease, restarts a service or changes a mount. A fleet adapter
and its lease/identity/timeout guarantees live in storage-acceptance.py and its
private remote module; this module alone performs no fleet operations.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

HOSTS = ('lab-dl380', 'lab-lenovo', 'lab-g003', 'lab-g004', 'lab-g005')
SERVER, CLIENTS = HOSTS[0], HOSTS[1:]
SHARES = {'/home': ('home', 'usrquota', 'rw'), '/projects': ('projects', 'prjquota', 'rw'),
          '/apps': ('apps', '', 'ro')}
USERS = {'syn-probe': (30091, 30091, {30000, 31003}), 'syn-alice': (30001, 30001, {30000, 31001}),
         'syn-carol': (30003, 30003, {30000, 31001}), 'syn-bob': (30002, 30002, {30000, 31002}),
         'agent-perm01': (40001, 40001, {40000, 31002}), 'team-user01': (20001, 20001, {20000, 31003})}
USERS.update({name: (uid, uid, groups) for name, uid, groups in (
    ('team-user02', 20002, {20000, 31003}), ('team-user03', 20003, {20000, 31003}), ('team-user04', 20004, {20000, 31003}),
    ('syn-dave', 30004, {30000, 31002}), ('syn-smoke', 30005, {30000, 31003}),
    ('syn-tracer', 30006, {30000, 31003}), ('syn-observer', 30007, {30000, 31003}),
    ('syn-nologin', 30092, {30000}),
    ('agent-cleanup01', 40002, {40000, 31002}), ('agent-resource01', 40003, {40000, 31002}),
    ('agent-team01', 40011, {40000, 31002}), ('agent-team02', 40012, {40000, 31002}),
    ('agent-team03', 40013, {40000, 31002}), ('agent-spare01', 40091, {40000, 31002}))})
PROJECTS = {'proj-alpha': (31001, 'syn-alice', 'syn-carol', 'syn-bob'),
            'proj-beta': (31002, 'syn-bob', 'agent-perm01', 'syn-alice'),
            'proj-ops': (31003, 'syn-probe', 'team-user01', 'syn-alice')}
PROJECT_ID = 39999
MIB = 1024 * 1024
PROJECT_ACL = ['user::rwx', 'group::rwx', 'mask::rwx', 'other::---', 'default:user::rwx',
               'default:group::rwx', 'default:mask::rwx', 'default:other::---']
EXCLUDED = ('NFS restart/remount', 'missing-mount/export refusal', 'pod mounts', 'restore proof')


def expected_home_quota():
    """Reviewed 20-user declaration, not values supplied by the remote host."""
    ordinary = {'bsoft': '4608m', 'bhard': '5g', 'isoft': 45000, 'ihard': 50000}
    team = {'bsoft': '18g', 'bhard': '20g', 'isoft': 180000, 'ihard': 200000}
    probe = {'bsoft': '200m', 'bhard': '256m', 'isoft': 1500, 'ihard': 2000}
    accounts = [('team-user01', 20001), ('team-user02', 20002), ('team-user03', 20003), ('team-user04', 20004),
                ('syn-alice', 30001), ('syn-bob', 30002), ('syn-carol', 30003), ('syn-dave', 30004),
                ('syn-smoke', 30005), ('syn-tracer', 30006), ('syn-observer', 30007),
                ('syn-probe', 30091), ('syn-nologin', 30092), ('agent-perm01', 40001),
                ('agent-cleanup01', 40002), ('agent-resource01', 40003), ('agent-team01', 40011),
                ('agent-team02', 40012), ('agent-team03', 40013), ('agent-spare01', 40091)]
    return {'path': '/home', 'grace_s': 604800,
            'default': {'bsoft': '900m', 'bhard': '1g', 'isoft': 9000, 'ihard': 10000},
            'users': [dict(team if uid < 30000 else probe if uid in (30006, 30007, 30091) else ordinary,
                           name=name, uid=uid)
                      for name, uid in accounts]}


class Refused(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def source_hashes():
    root = Path(__file__).resolve().parent
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ('prace_storage_acceptance.py', 'prace_storage_probe.py')}


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def validate_observation(host, observation):
    """Require explicit mount/export/quota/account evidence, never a bare PASS."""
    require(observation['hostname'] == host and observation['boot_id'] and observation['machine_id'],
            'host_identity')
    mounts = observation['mounts']
    require(set(mounts) == set(SHARES), 'mount_membership')
    for path, (lv, quota, mode) in SHARES.items():
        found = mounts[path]
        options = set(found['options'])
        require(found['target'] == path and {'nodev', 'nosuid'} <= options, 'mount_options')
        if host == SERVER:
            require(found['source'] == '/dev/mapper/hpe_vg-' + lv and found['fstype'] == 'xfs', 'server_mount')
            require(not quota or quota in options or {'usrquota': 'uquota', 'prjquota': 'pquota'}[quota] in options,
                    'quota_mount')
        else:
            require(found['source'] == '10.90.10.1:' + path and found['fstype'] in ('nfs', 'nfs4'), 'client_mount')
            require({'hard', mode} <= options and ('vers=4.2' in options or 'nfsvers=4.2' in options), 'client_options')
            require(('ro' not in options if mode == 'rw' else 'rw' not in options), 'client_options')
    for user, (uid, gid, groups) in USERS.items():
        actual = observation['accounts'][user]
        require((actual['uid'], actual['gid']) == (uid, gid) and set(actual['groups']) == groups | {gid},
                'numeric_identity')
    require(all(type(value) is int and value >= 2 * 1024 * MIB for value in observation['free_bytes'].values())
            and set(observation['free_bytes']) == set(SHARES), 'space_reserve')
    if host == SERVER:
        require(set(observation['storage_config']) == set(SHARES), 'storage_config')
        for path, (lv, quota, _) in SHARES.items():
            require(observation['storage_config'][path] == {'source': '/dev/mapper/hpe_vg-' + lv, 'quota': quota},
                    'storage_config')
        exports = observation['exports']
        require(len(exports) == 3 and {row['path'] for row in exports} == set(SHARES), 'export_membership')
        for row in exports:
            opts = set(row['options'])
            require(row['client'] == '10.90.10.0/25' and
                    {SHARES[row['path']][2], 'sync', 'secure', 'root_squash'} <= opts and
                    not {'async', 'insecure', 'no_root_squash'} & opts and
                    not ({'ro', 'rw'} - {SHARES[row['path']][2]}) & opts, 'export_options')
            mount_guards = {value for value in opts if value.split('=', 1)[0] in ('mountpoint', 'mp')}
            require(mount_guards and mount_guards <= {'mountpoint', 'mp',
                    'mountpoint=' + row['path'], 'mp=' + row['path']}, 'export_mountpoint_guard')
        require(observation['quota_state'] == {'user': {'accounting': True, 'enforcement': True},
                                             'project': {'accounting': True, 'enforcement': True}}, 'quota_state')
        require(observation['project_roots'] == {
            name: {'uid': 0, 'gid': gid, 'mode': 0o2770, 'acl': PROJECT_ACL}
            for name, (gid, *_) in PROJECTS.items()}, 'project_root_acl')
        require(observation['quota_check'] == {'returncode': 0, 'stderr': '',
                                             'stdout': 'quotas match the declaration'}, 'quota_policy')
        declaration = observation['quota_declaration']
        require(isinstance(declaration, dict) and set(declaration) == {'home', 'projects'} and
                isinstance(declaration['home'], dict) and isinstance(declaration['projects'], dict), 'quota_declaration')
        require(declaration['home'].get('path') == '/home' and declaration['projects'].get('path') == '/projects'
                and declaration['home'].get('grace_s') == 604800 and declaration['projects'].get('grace_s') == 604800,
                'quota_declaration')
        users = declaration['home'].get('users', [])
        require(isinstance(users, list) and all(isinstance(item, dict) and type(item.get('uid')) is int
                                               for item in users), 'quota_declaration')
        require(dict(declaration['home'], users=sorted(users, key=lambda item: item['uid'])) ==
                expected_home_quota(), 'quota_declaration')
        projects = declaration['projects'].get('projects', [])
        require({(item['name'], item['id'], item['dir']) for item in projects} ==
                {(name, values[0], '/projects/' + name) for name, values in PROJECTS.items()}
                and len(projects) == len(PROJECTS) and all(item['bsoft'] == '45g' and item['bhard'] == '50g'
                and item['isoft'] == 450000 and item['ihard'] == 500000 for item in projects), 'quota_declaration')


class FunctionalRun:
    """Serial functional checks plus explicit same-source cleanup.

    The injected window must fail guard() unless the exact saved host identities,
    source hashes, owned lease, operation lock, admission fence, empty queue and
    synthetic-account quiescence are established. Its RPCs require hard process
    deadlines, verified mounts, UID switching and process cancellation proof.
    This interface is not itself an implementation of those fleet guarantees.
    """
    def __init__(self, directory, window, *, run_id=None):
        self.directory, self.window = Path(directory), window
        require(self.directory.is_absolute() and self.directory.parent.resolve() == self.directory.parent,
                'private_run_directory')
        self.file = self.directory / 'acceptance.json'
        if self.file.is_symlink():
            raise Refused('private_run_record')
        if self.file.exists():
            require(run_id is None, 'existing_run')
            info = self.file.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                    stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 1024 * 1024, 'private_run_record')
            self.state = json.loads(self.file.read_text())
            require(self.state['sources'] == source_hashes(), 'source_changed')
        else:
            require(isinstance(run_id, str) and re.fullmatch('[a-f0-9]{32}', run_id), 'run_id')
            self.directory.mkdir(mode=0o700)
            sync_dir(self.directory.parent)
            self.state = {'schema': 1, 'id': run_id, 'sources': source_hashes(), 'phase': 'new',
                          'cleanup': [], 'results': [], 'excluded': list(EXCLUDED)}
        info = self.directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not self.directory.is_symlink() and
                self.directory.resolve() == self.directory and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o700, 'private_run_directory')
        self.save()

    def save(self):
        fd, name = tempfile.mkstemp(prefix='.acceptance-', dir=self.directory)
        with os.fdopen(fd, 'w') as out:
            json.dump(self.state, out, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, self.file)
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def guard(self):
        require(self.state['sources'] == source_hashes(), 'source_changed')
        result = self.window.guard(self.state['id'], self.state['sources'])
        require(result == {'owned': True, 'fenced': True, 'exclusive': True, 'quiescent': True}, 'window_not_ready')

    def call(self, host, operation, **payload):
        require(host in HOSTS, 'host_scope')
        self.guard()
        result = self.window.call(host, operation, dict(payload, run_id=self.state['id']))
        require(isinstance(result, dict), 'malformed_response')
        return result

    def mutate(self, host, operation, cleanup, **payload):
        ticket = {'host': host, 'operation': cleanup, 'payload': dict(payload, created_by=operation), 'state': 'intent'}
        self.state['cleanup'].append(ticket)
        self.save()
        result = self.call(host, operation, **payload)
        require(isinstance(result.get('receipt'), dict) and result['receipt'], 'cleanup_receipt_missing')
        ticket.update(state='pending', receipt=result['receipt'])
        self.save()
        return result

    def result(self, name):
        self.state['results'].append(name)
        self.save()

    def preflight(self):
        self.guard()
        observations = {host: self.window.observe(host) for host in HOSTS}
        for host, data in observations.items():
            validate_observation(host, data)
        if 'identities' in self.state:
            require(self.state['identities'] == {host: {key: data[key] for key in
                    ('hostname', 'boot_id', 'machine_id')} for host, data in observations.items()}, 'identity_changed')
        else:
            self.state['identities'] = {host: {key: data[key] for key in ('hostname', 'boot_id', 'machine_id')}
                                        for host, data in observations.items()}
            self.save()
        self.result('exact-host-mount-export-quota-contract')

    def sharing(self):
        for project, (gid, creator, collaborator, outsider) in PROJECTS.items():
            content = (self.state['id'] + ':' + project).encode().hex()
            fixture = self.mutate(SERVER, 'create_project_fixture', 'remove_fixture',
                                  project=project, user=creator, content_hex=content, umask=0o077)
            require(fixture['file'] == {'uid': USERS[creator][0], 'gid': gid, 'mode': 0o660} and
                    fixture['directory'] == {'uid': USERS[creator][0], 'gid': gid, 'mode': 0o2770, 'acl': PROJECT_ACL},
                    'project_default_acl')
            for host in HOSTS:
                read = self.call(host, 'read_fixture', project=project, user=collaborator)
                require(read.get('content_hex') == content, 'cross_host_content')
                append = self.call(host, 'append_fixture', project=project, user=collaborator, content_hex='2b')
                require(append.get('written') == 1, 'cross_host_append')
                content += '2b'
                denied = self.call(host, 'deny_project_access', project=project, user=outsider)
                require(denied.get('read_errno') == errno.EACCES and denied.get('create_errno') == errno.EACCES,
                        'outsider_denial')
            require(self.call(SERVER, 'read_fixture', project=project, user=creator).get('content_hex') == content,
                    'cross_host_content')
            self.result(project + '-cross-host-sharing-default-acl-outsider')

    def read_only_and_squash(self):
        # Writable test directory makes a client EROFS distinguishable from
        # ordinary mode-bit denial. Only the unique fixture is chmodded.
        content = self.state['id'].encode().hex()
        self.mutate(SERVER, 'create_apps_fixture', 'remove_fixture', user='root', directory_mode=0o777, content_hex=content)
        self.mutate(SERVER, 'create_squash_fixture', 'remove_fixture', user='root', directory_mode=0o700)
        for host in CLIENTS:
            result = self.call(host, 'apps_read_only', user='syn-probe')
            require(result.get('content_hex') == content and result.get('create_errno') == errno.EROFS, 'apps_read_only')
            denied = self.call(host, 'root_squash', user='root')
            require(denied.get('create_errno') == errno.EACCES, 'root_squash')
        self.result('all-client-apps-ro-and-root-squash')

    def exhaustion(self, kind, *, inodes=False):
        key = 'user' if kind == 'user' else 'project'
        before = self.call(SERVER, 'quota_snapshot', kind=key, target=30091 if key == 'user' else PROJECT_ID)
        require(before['used_bytes'] >= 0 and before['used_inodes'] >= 0, 'quota_usage')
        if key == 'project':
            require(all(before.get(name) == value for name, value in
                        {'used_bytes': 0, 'used_inodes': 0, 'limits': [0, 0, 0, 0], 'mapped': False}.items()),
                    'temporary_project_in_use')
            prepared = self.mutate(SERVER, 'prepare_project_quota', 'restore_project_quota', target=PROJECT_ID,
                                   limits=[8 * MIB, 10 * MIB, 0, 0], original=before)
            require(prepared.get('project_id') == PROJECT_ID and prepared.get('inherit') is True, 'project_tag')
            configured = self.call(SERVER, 'quota_snapshot', kind='project', target=PROJECT_ID)
            require(configured['limits'] == [8 * MIB, 10 * MIB, 0, 0], 'project_limit_readback')
            hard = 10 * MIB
        else:
            require(before['limits'] == [200 * MIB, 256 * MIB, 1500, 2000], 'user_quota_policy')
            require(before['used_bytes'] < 240 * MIB and before['used_inodes'] < 1900, 'user_quota_headroom')
            hard = 2000 if inodes else 256 * MIB
        cap = 2100 if inodes else (272 * MIB if key == 'user' else 12 * MIB)
        result = self.mutate(CLIENTS[0], 'exhaust_inodes' if inodes else 'exhaust_bytes', 'quota_remove_fixture',
                             kind=key, inodes=inodes, user='syn-probe' if key == 'user' else 'syn-alice', cap=cap, seconds=60,
                             original_quota=before)
        after = self.call(SERVER, 'quota_snapshot', kind=key, target=30091 if key == 'user' else PROJECT_ID)
        require(after['limits'] == (before['limits'] if key == 'user' else [8 * MIB, 10 * MIB, 0, 0]),
                'quota_limits_changed')
        used = after['used_inodes'] if inodes else after['used_bytes']
        require(result.get('timed_out', False) is False and
                result.get('errno') in (errno.EDQUOT, errno.ENOSPC) and 0 < result.get('created' if inodes else 'written', 0) <= cap,
                'quota_not_exhausted')
        require(hard - (1 if inodes else MIB) <= used <= hard and
                after.get('filesystem_free_bytes', 0) >= 2 * 1024 * MIB and
                after.get('filesystem_free_inodes', 0) >= 10000, 'quota_not_corroborated')
        for host in CLIENTS[1:]:
            denied = self.call(host, 'quota_denial', kind=key, inodes=inodes,
                               user='syn-probe' if key == 'user' else 'syn-alice')
            require(denied.get('errno') in (errno.EDQUOT, errno.ENOSPC), 'cross_client_quota')
        self.result(key + ('-inode' if inodes else '-byte') + '-quota-enforcement')
        self.cleanup()
        restored = self.call(SERVER, 'quota_snapshot', kind=key, target=30091 if key == 'user' else PROJECT_ID)
        require(all(restored[name] == before[name] for name in ('used_bytes', 'used_inodes', 'limits')) and
                (key != 'project' or restored.get('mapped') is False), 'quota_cleanup_mismatch')

    def cleanup(self):
        self.guard()
        for ticket in reversed(self.state['cleanup']):
            if ticket['state'] == 'clean':
                continue
            # A lost creation response requires adapter-side inspection of its
            # durable receipt. Never infer that an unacknowledged write failed.
            result = self.call(ticket['host'], ticket['operation'], **ticket['payload'],
                               receipt=ticket.get('receipt'))
            require(result == {'clean': True, 'verified': True}, 'cleanup_unverified')
            project = ticket['operation'] == 'restore_project_quota'
            if project or ticket['payload'].get('kind') == 'user':
                expected = ticket['payload']['original' if project else 'original_quota']
                current = self.call(SERVER, 'quota_snapshot', kind='project' if project else 'user',
                                    target=PROJECT_ID if project else 30091)
                require(all(current[name] == expected[name] for name in ('used_bytes', 'used_inodes', 'limits')) and
                        (not project or current.get('mapped') is False), 'quota_cleanup_mismatch')
            ticket['state'] = 'clean'
            self.save()
        self.state['phase'] = 'clean'
        self.save()

    def run(self):
        require(self.state['phase'] == 'new', 'run_not_fresh')
        self.state['phase'] = 'running'
        self.save()
        try:
            self.preflight()
            self.sharing()
            self.read_only_and_squash()
            self.cleanup()
            self.exhaustion('user')
            self.exhaustion('user', inodes=True)
            self.exhaustion('project')
            self.preflight()
            self.state['phase'] = 'functional_pass_cleanup_verified'
            self.save()
            return {'functional': 'PASS', 'cleanup': 'verified', 'excluded': list(EXCLUDED),
                    'window': 'still_owned_and_fenced'}
        except BaseException:
            self.state['phase'] = 'failed_explicit_cleanup_required'
            self.save()
            raise

    def run_quota(self):
        require(self.state['phase'] == 'new', 'run_not_fresh')
        self.state['phase'] = 'running_quota'
        self.save()
        try:
            self.preflight()
            self.exhaustion('user')
            self.exhaustion('user', inodes=True)
            self.exhaustion('project')
            self.preflight()
            self.state['phase'] = 'quota_pass_cleanup_verified'
            self.save()
            return {'quota': 'PASS', 'cleanup': 'verified', 'excluded': list(EXCLUDED),
                    'window': 'still_owned_and_fenced'}
        except BaseException:
            self.state['phase'] = 'failed_explicit_cleanup_required'
            self.save()
            raise

    def run_basic(self):
        """The split handover gate: quota policy only; no exhaustion/disruption."""
        require(self.state['phase'] == 'new', 'run_not_fresh')
        pending = ['user/project quota exhaustion', *EXCLUDED, 'underlying-directory mount guard']
        self.state.update(phase='running_basic', pending=pending)
        self.save()
        try:
            self.preflight()
            self.sharing()
            self.read_only_and_squash()
            self.cleanup()
            self.preflight()
            self.state['phase'] = 'basic_host_pass_cleanup_verified'
            self.save()
            return {'basic_host_functional': 'PASS', 'quota': 'policy/readback only',
                    'cleanup': 'verified', 'pending': pending, 'window': 'still_owned_and_fenced'}
        except BaseException:
            self.state['phase'] = 'failed_explicit_cleanup_required'
            self.save()
            raise

    def run_underlay(self, mode, preservation_id=None):
        """Separate explicit preparation/check gate; never undo preserved data.

        An uncertain preparation is not fixture cleanup. Its intent remains in
        both ledgers and requires operator inspection before window closure.
        """
        require(self.state['phase'] == 'new' and mode in ('check', 'prepare'), 'run_not_fresh')
        require((mode == 'check' and preservation_id is None) or
                (mode == 'prepare' and isinstance(preservation_id, str) and
                 re.fullmatch('[a-z0-9-]{8,64}', preservation_id)), 'preservation_id')
        self.state.update(phase='underlay_running', underlay=[], underlay_mode=mode)
        self.save()
        self.preflight()
        for host in CLIENTS:
            ticket = {'host': host, 'mode': mode, 'preservation_id': preservation_id, 'state': 'intent'}
            self.state['underlay'].append(ticket)
            self.save()
            result = self.call(host, 'underlay_' + mode, preservation_id=preservation_id)
            require(result.get('mode') == mode and result.get('parent_namespace_unchanged') is True
                    and result.get('parent_mounts_unchanged') is True and
                    set(result.get('paths', {})) == set(SHARES), 'underlay_unverified')
            for path, value in result['paths'].items():
                require(value.get('guarded') is True and type(value.get('changed')) is bool
                        and (mode != 'check' or value['changed'] is False), 'underlay_unverified')
                require(value.get('archive') is None or
                        (mode == 'prepare' and path == '/home' and value['archive'] ==
                         '/var/lib/prace-home-premigration/worker-underlay-' + preservation_id), 'underlay_archive')
            ticket.update(state='verified', result=result)
            self.save()
        self.guard()
        self.state['phase'] = 'underlay_' + mode + '_verified'
        self.save()
        return {'worker_underlay': 'PASS', 'mode': mode, 'workers': list(CLIENTS),
                'preserved_data': 'retained; no automatic deletion or rollback',
                'window': 'still_owned_and_fenced'}


if __name__ == '__main__':
    raise SystemExit('Use storage-acceptance.py with explicit --bench or --fleet; the core does not execute directly.')

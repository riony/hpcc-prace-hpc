#!/usr/bin/env python3
"""Bounded W1/W2 capture. No SSH without --execute; never deploys storage.

capture creates a private, durable workstation record. recover restores services but
KEEPS admission fenced. finish verifies all copies and explicitly reopens. backout
closes a failed capture window without accepting the recovery point. With
--window/--lease-id, all actions retain the outer owner's closed fence and lease.
"""
import argparse
import ast
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import types
import uuid

TOOLS = Path(__file__).resolve().parent
LOGIN = '192.0.2.205'
WORKERS = ['lab-lenovo', 'lab-g003', 'lab-g004', 'lab-g005']
STAGES = ('pre-w1', 'pre-w2', 'post-w2')
GIB = 1024 ** 3
OPERATIONS = frozenset(('inspect', 'acquire', 'fence', 'capture', 'services', 'manifest',
                       'manifest_read', 'reopen', 'backout', 'verify_original', 'release',
                       'lease_check', 'closing_status', 'window_status'))
# Only reviewed static protocol codes may enter the workstation failure record.
# In particular, exception messages, subprocess arguments/output and metadata paths
# are not diagnostics that this record is allowed to retain.
REMOTE_ERROR_CODES = frozenset('''
abandon_ack_required admin_attestation_required api_unready artifact_changed
artifact_missing artifact_unsafe capture_already_attempted capture_failed
capture_incomplete command_failed control_duplicate_member control_entry_limit
control_size_limit control_special_file control_token_mismatch control_unsafe_link
control_unsafe_member control_unsafe_record controller_changed controller_identity
controller_not_stopped controller_unusable data_size_limit entry_limit fence_incomplete
helper_missing host_identity identity_changed insufficient_remote_space k3s_inactive
k3s_not_stopped lease_changed lease_exists lease_not_owned lease_unreadable
login_pods_present login_pods_unready loginset_query loginset_replaced loginset_admission manifest_mismatch
manifest_missing membership_changed metadata_proof_failed metadata_proof_missing
mount_query nested_mount original_service_state original_state_changed
original_state_changed_under_lease original_state_not_restored partition_query
private_directory private_record queue_not_empty record_mismatch
reopen_failed_refence_required request_id request_limit request_scope
required_root_missing root_required service_recovery_required unknown_operation
worker_membership writable_descriptor remote_operation_failed operation_busy
operation_timeout operation_interrupted operation_lock_invalid operation_record_invalid
closing_state_invalid closing_purpose_mismatch command_timeout data_scope_invalid
persistent_fence_requires_capture_adapter
shared_window_invalid shared_overlay_invalid shared_lease_not_owned
shared_intent_changed shared_membership_changed shared_lock_invalid
shared_window_busy shared_helper_missing shared_owner_operation
native_scope_invalid native_scope_changed native_helper_missing native_repo_preflight_failed
native_repo_capture_failed
'''.split())
TRANSPORT_GRACE_SECONDS = 60


class CaptureError(RuntimeError):
    pass


_spec = importlib.util.spec_from_file_location('capture_window_contract', TOOLS / 'prace_capture_window.py')
WINDOW = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(WINDOW)
WINDOW.C = types.SimpleNamespace(Refused=CaptureError)


def native_module():
    spec = importlib.util.spec_from_file_location('capture_native', TOOLS / 'prace_native_capture.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def read_window(path, lease_id):
    path = Path(path).absolute()
    st = path.lstat()
    if (path.resolve() != path or not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
            or stat.S_IMODE(st.st_mode) != 0o600 or st.st_size > 1024 * 1024):
        raise CaptureError('window must be an owned private regular file')
    record = json.loads(path.read_text())
    if WINDOW.normalize(record)['id'] != lease_id:
        raise CaptureError('explicit lease id differs from the closed window')
    return record


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def atomic_json(path, value):
    """A failed durable write must prevent the next remote mutation."""
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd, tmp = tempfile.mkstemp(prefix='.record-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
        d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def private_dir(path):
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise CaptureError('run directory must be an owned, private directory, not a symlink')
    if path.resolve() != path.absolute():
        raise CaptureError('run directory must not contain symlink components')


def validate_state(s):
    if s.get('schema') != 1 or not re.fullmatch(r'[0-9a-f]{32}', s.get('id', '')):
        raise CaptureError('invalid run record')
    if s.get('stage') not in STAGES or s.get('workers') != WORKERS or s.get('login') != LOGIN:
        raise CaptureError('run record target/stage differs from this bounded tool')
    if not re.fullmatch(r'[0-9a-f]{40,64}', s.get('revision', '')):
        raise CaptureError('missing source revision')
    if not isinstance(s.get('tool_hashes'), dict) or not s['tool_hashes']:
        raise CaptureError('missing tool provenance')
    if 'native' in s:
        native_module().validate_options(s)
    if 'window' in s or 'window_record' in s:
        if WINDOW.normalize(s.get('window_record')) != s.get('window'):
            raise CaptureError('shared window baseline differs from its record')


class Run:
    def __init__(self, directory, remote, state=None, reserve=100 * GIB):
        self.directory = Path(directory).absolute()
        private_dir(self.directory)
        self.file = self.directory / 'run.json'
        self.remote = remote
        self.reserve = reserve
        self.attest_no_admin_writers = False
        if state is None:
            st = self.file.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                raise CaptureError('run record is not an owned private regular file')
            self.state = json.loads(self.file.read_text())
        else:
            self.state = state
        validate_state(self.state)

    @classmethod
    def create(cls, directory, remote, stage, revision, tool_hashes,
               max_data_bytes=2 * GIB, reserve=100 * GIB, window_record=None, native=None):
        window = WINDOW.normalize(window_record) if window_record is not None else None
        directory = Path(directory).absolute()
        # Explicit run directory; refuse all pre-existing paths, including symlinks.
        directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.mkdir(mode=0o700)
        state = {'schema': 1, 'id': uuid.uuid4().hex, 'stage': stage,
                 'revision': revision, 'tool_hashes': tool_hashes, 'login': LOGIN,
                 'workers': WORKERS, 'max_data_bytes': max_data_bytes,
                 'created_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                 'phase': 'created', 'intent': None, 'history': [], 'accepted': False}
        if window is not None:
            state.update(window=window, window_record=json.loads(json.dumps(window_record)))
        if native is not None:
            state['native'] = native
        obj = cls(directory, remote, state, reserve)
        obj.save()
        return obj

    def save(self):
        atomic_json(self.file, self.state)

    def record_failure(self, op, result=None, *, source='remote', code=None):
        result = result if isinstance(result, dict) else {}
        candidate = result.get('error')
        failure = {'source': source, 'operation': op if isinstance(op, str) and op in OPERATIONS else 'driver',
                   'code': code or (candidate if isinstance(candidate, str) and
                                    candidate in REMOTE_ERROR_CODES else 'remote_operation_failed')}
        operation_id = result.get('operation_id')
        if isinstance(operation_id, str) and re.fullmatch(r'[0-9a-f]{32}', operation_id):
            failure['operation_id'] = operation_id
        self.state.setdefault('failures', []).append(failure)
        self.state['last_error'] = failure
        return failure

    def call(self, op):
        if op not in OPERATIONS:
            raise CaptureError('unknown driver operation')
        self.state['intent'] = op
        self.state['history'].append({'op': op, 'at': dt.datetime.now(dt.timezone.utc).isoformat()})
        self.save()  # always before the possibly disruptive RPC
        request = {k: self.state[k] for k in ('id', 'stage', 'workers', 'max_data_bytes')}
        request.update(op=op, identity=self.state.get('identity'), original=self.state.get('original'),
                       attest_no_admin_writers=self.attest_no_admin_writers, abandon=(op == 'backout'))
        if 'native' in self.state:
            request['native'] = self.state['native']
        if 'window' in self.state:
            request.update(window=self.state['window'], window_record=self.state['window_record'])
        try:
            result = self.remote.call(request)
        except (Exception, KeyboardInterrupt) as exc:
            code = 'transport_timeout' if isinstance(exc, subprocess.TimeoutExpired) else 'transport_failed'
            self.record_failure(op, source='transport', code=code)
            self.save()
            raise
        if not isinstance(result, dict) or result.get('ok') is not True:
            failure = self.record_failure(op, result)
            errors = result.get('errors') if isinstance(result, dict) else None
            if isinstance(errors, list):
                for error in errors[:10]:
                    if (isinstance(error, dict) and isinstance(error.get('operation'), str)
                            and error['operation'] in OPERATIONS):
                        self.record_failure(error['operation'], error)
            self.state['last_result'] = {'ok': False, **failure}
            self.save()  # retain refusal evidence even if the caller never catches it
            raise CaptureError('remote operation refused: ' + op)
        # Record the result and intent completion together. Raw diagnostics stay off stdout.
        self.state['last_result'] = result
        self.state['intent'] = None
        self.state['phase'] = op
        self.save()
        return result

    def mark_failed(self, error=None):
        self.state['accepted'] = False
        self.state['phase'] = 'failed-fenced-or-unknown'
        if error is not None:
            # Preserve earlier RPC failures; a later recovery failure must not mask them.
            code = 'driver_interrupted' if isinstance(error, KeyboardInterrupt) else 'driver_operation_failed'
            self.record_failure(self.state.get('intent'), source='driver', code=code)
        self.save()

    def start(self):
        if self.state['phase'] != 'created':
            raise CaptureError('capture cannot overwrite or resume a prior point; recover explicitly')
        info = self.call('inspect')
        identity = info.get('identity', {})
        if identity.get('hostname') != 'lab-dl380' or identity.get('chassis_serial') != 'EXSERIAL01':
            raise CaptureError('target identity mismatch')
        if not all(identity.get(k) for k in ('machine_id', 'boot_id')):
            raise CaptureError('target identity incomplete')
        original = info.get('original', {})
        if not original.get('partitions') or not original.get('loginsets') or original.get('k3s_active') is not True:
            raise CaptureError('original admission/service state incomplete')
        self.state.update(identity=identity, original=original, roots=info.get('roots'))
        self.save()
        self.call('acquire')
        self.call('fence')
        if 'native' in self.state:
            native_module().before(self)
        self.call('capture')
        self.call('services')  # recover services and read back a CLOSED admission fence
        manifest = self.call('manifest')
        self.validate_manifest(manifest)
        self.state['manifest'] = manifest
        self.save()
        self.copy_all()
        self.complete()

    def validate_manifest(self, m):
        if m.get('complete') is not True or m.get('id') != self.state['id'] or m.get('stage') != self.state['stage']:
            raise CaptureError('capture is not a complete matched recovery point')
        artifacts = m.get('artifacts')
        if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 1000:
            raise CaptureError('invalid artifact inventory')
        names = set()
        for a in artifacts:
            name = a.get('path', '')
            p = PurePosixPath(name)
            if (not re.fullmatch(r'[A-Za-z0-9_./-]+', name) or p.is_absolute()
                    or '..' in p.parts or '.' in p.parts or str(p) != name or name in names):
                raise CaptureError('unsafe or duplicate artifact name')
            if not re.fullmatch(r'[0-9a-f]{64}', a.get('sha256', '')):
                raise CaptureError('missing artifact digest')
            if type(a.get('size')) is not int or not 0 <= a['size'] <= 32 * GIB:
                raise CaptureError('invalid artifact size')
            names.add(name)
        required = {'control.tgz', 'home.tar'}
        if 'native' in self.state:
            required |= {'native-repo.tar', 'native-repo.json'}
        if 'window' in self.state:
            required.add('slurm-window.json')
        if self.state['stage'] != 'pre-w1':
            required |= {'local-home.tar', 'projects.tar', 'apps.tar'}
        if not required <= names:
            raise CaptureError('required control/data archive is missing')
        # Forbid files that are also another file's directory.
        if any(str(parent) in names for name in names for parent in PurePosixPath(name).parents if str(parent) != '.'):
            raise CaptureError('artifact file/directory collision')

    def verify_copies(self, allow_missing=False):
        m = self.state.get('manifest', {})
        self.validate_manifest(m)
        for a in m['artifacts']:
            p = self.directory / 'artifacts' / a['path']
            if p.resolve() != p.absolute():
                raise CaptureError('artifact path traverses a symlink')
            if allow_missing and not p.exists() and not p.is_symlink():
                continue
            st = p.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.getuid():
                raise CaptureError('artifact is not a private regular file')
            if st.st_size != a['size'] or digest(p) != a['sha256']:
                raise CaptureError('artifact copy integrity failure')
            if a['path'] == 'slurm-window.json' and 'window' in self.state:
                if st.st_size > 1024 * 1024 or json.loads(p.read_text()) != self.state['window_record']:
                    raise CaptureError('copied shared-window baseline differs from the frozen record')

        if 'native' in self.state and self.state.get('accepted') is True:
            native_module().verify(self.directory, self.state)

    def copy_all(self):
        m = self.state['manifest']; self.validate_manifest(m)
        free = os.statvfs(self.directory)
        if free.f_bavail * free.f_frsize < sum(a['size'] for a in m['artifacts']) + self.reserve:
            raise CaptureError('workstation capacity reserve would be exceeded')
        self.state['intent'] = 'copy'; self.save()
        root = self.directory / 'artifacts'
        root.mkdir(mode=0o700, exist_ok=True)
        private_dir(root)
        for a in m['artifacts']:
            dest = root / a['path']
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if dest.parent.resolve() != dest.parent.absolute():
                raise CaptureError('artifact parent traverses a symlink')
            if dest.exists() or dest.is_symlink():
                st = dest.lstat()
                if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077
                        or st.st_size != a['size'] or digest(dest) != a['sha256']):
                    raise CaptureError('existing artifact differs; refusing replacement')
                continue
            part = dest.with_name(dest.name + '.partial')
            if part.exists() or part.is_symlink():
                st = part.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                    raise CaptureError('unsafe partial artifact')
                # Preserve failed transfer evidence; never overwrite a partial silently.
                os.rename(part, part.with_name(part.name + '.failed-' + uuid.uuid4().hex))
            self.remote.copy(self.state['id'], a['path'], part)
            st = part.lstat()
            if not stat.S_ISREG(st.st_mode):
                raise CaptureError('copy did not produce a regular file')
            part.chmod(0o600)
            if st.st_size != a['size'] or digest(part) != a['sha256']:
                raise CaptureError('artifact copy integrity failure')
            with part.open('rb') as f:
                os.fsync(f.fileno())
            os.replace(part, dest)
            d = os.open(dest.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(d)
            finally: os.close(d)
        self.verify_copies()
        self.state.update(phase='copies-verified', intent=None)
        self.save()

    def settle_release(self):
        """A lost release reply is settled read-only; never adopt a missing lease."""
        if not self.state.get('release_pending'):
            return False
        check = self.call('lease_check')
        if check.get('lease') == 'owned':
            return False
        if check.get('lease') != 'missing':
            raise CaptureError('cannot settle release while a foreign/unknown lease exists')
        closing = self.state.get('closing_as')
        if closing not in ('complete', 'aborted'):
            raise CaptureError('no durable release purpose')
        if closing == 'complete':
            self.verify_copies()
            if self.call('manifest_read') != self.state.get('manifest'):
                raise CaptureError('remote point changed after release')
        self.call('verify_original')
        self.state.update(phase=closing, accepted=(closing == 'complete'), release_pending=False)
        self.save()
        return True

    def release(self, closing):
        self.state.update(release_pending=True, closing_as=closing)
        self.save()
        self.call('release')
        self.state.update(phase=closing, accepted=(closing == 'complete'), release_pending=False)
        self.save()

    def settle_closing(self):
        """Observe completed reopening before any operation that may close admission.

        A saved purpose or an owned lease says nothing about whether reopening
        finished. Only the remote completion marker plus current original-state
        verification permits closure without invoking services again.
        """
        if self.settle_release():
            return True
        result = self.call('closing_status')
        closing = result.get('closing')
        reopened = result.get('reopened')
        if closing not in (None, 'complete', 'aborted') or type(reopened) is not bool:
            raise CaptureError('invalid remote closing observation')
        if not reopened:
            if self.state.get('release_pending'):
                raise CaptureError('completed reopening marker is missing')
            return False
        if closing not in ('complete', 'aborted') or closing != self.state.get('closing_as'):
            raise CaptureError('remote closing purpose differs from durable purpose')
        if closing == 'complete':
            self.verify_copies()
            if self.call('manifest_read') != self.state.get('manifest'):
                raise CaptureError('remote point changed after reopening')
        self.call('verify_original')
        lease = self.call('lease_check').get('lease')
        if lease == 'owned':
            self.release(closing)
        elif lease == 'missing':
            self.state.update(phase=closing, accepted=(closing == 'complete'), release_pending=False)
            self.save()
        else:
            raise CaptureError('cannot settle closing while a foreign/unknown lease exists')
        return True

    def begin_closing(self, closing):
        self.state['closing_as'] = closing
        self.save()  # must precede both successful and partially executed reopen requests

    def complete(self):
        if 'window' in self.state:
            self.verify_copies(allow_missing=True)
            self.call('services')
            if self.call('manifest') != self.state.get('manifest'):
                raise CaptureError('remote artifact manifest changed')
            self.copy_all()
            self.borrowed_complete(accepted=True)
            return
        # Refuse corrupt completed transfers before any remote state change. Missing
        # files remain resumable; copy_all preserves and replaces failed partials.
        # An aborted closure may have no manifest at all. Its completed backout
        # must still be settled without closing admission again.
        if self.state.get('closing_as') != 'aborted':
            self.verify_copies(allow_missing=True)
        if self.settle_closing():
            return
        if self.state.get('closing_as') == 'aborted':
            raise CaptureError('an aborted closure cannot accept a recovery point')
        self.call('services')
        m = self.call('manifest')
        if m != self.state.get('manifest'):
            raise CaptureError('remote artifact manifest changed')
        self.copy_all()  # verified existing files are kept; interrupted transfers can resume
        self.verify_copies()
        self.begin_closing('complete')
        self.call('reopen')
        self.release('complete')

    def recover(self):
        if 'window' in self.state:
            self.call('services')
            self.borrowed_status()
            self.state.update(phase='recovered-fenced', accepted=False)
            self.save()
            return
        if self.settle_closing():
            return
        # Services and lease ownership are re-observed remotely, never inferred from intent.
        self.call('services')
        self.state.update(phase='recovered-fenced', accepted=False)
        self.save()

    def backout(self):
        if 'window' in self.state:
            self.call('services')
            self.borrowed_complete(accepted=False)
            return
        if self.settle_closing():
            return
        self.call('services')
        self.begin_closing('aborted')
        self.call('backout')
        self.release('aborted')

    def borrowed_status(self):
        result = self.call('window_status')
        if result != {'ok': True, 'window_id': self.state['window']['id'],
                      'fenced': True, 'lease_retained': True}:
            raise CaptureError('shared window closure was not proven')

    def borrowed_complete(self, *, accepted):
        self.borrowed_status()
        if accepted and 'native' in self.state:
            native_module().finish(self)
            self.borrowed_status()
        self.state.update(phase='complete' if accepted else 'aborted', accepted=accepted,
                          outer_window_retained=True)
        self.save()


class SSHRemote:
    """Fixed single-host transport. Payload goes on stdin; no secret in argv/logs.

    Tests never instantiate this class. No environment fallback chooses a real host.
    """
    def __init__(self, tools=TOOLS, expected_hashes=None):
        self.tools = tools
        # Freeze the transported implementation for this process. Recovery also
        # checks these files against the durable capture hashes before connecting.
        self.helper = (tools / 'prace_metadata_archive.py').read_text()
        self.remote_source = (tools / 'prace_capture_remote.py').read_text()
        self.tree = (tools.parent / 'roles/login_storage/files/prace-tree-listing').read_text()
        self.window_source = (tools / 'prace_capture_window.py').read_text()
        self.native_repo_source = (tools / 'prace_native_repo.py').read_text()
        if expected_hashes is not None:
            sources = {'prace_metadata_archive.py': self.helper,
                       'prace_capture_remote.py': self.remote_source, 'prace-tree-listing': self.tree,
                       'prace_capture_window.py': self.window_source, 'prace_native_repo.py': self.native_repo_source}
            if any(hashlib.sha256(source.encode()).hexdigest() != expected_hashes.get(name)
                   for name, source in sources.items()):
                raise CaptureError('transport source changed since provenance check')
        # Read literal budgets from the exact frozen source sent over SSH, without
        # executing that module locally. Capture has a separate finally/recovery
        # allowance; the transport grace is not a claim that disconnected work stops.
        constants = {}
        try:
            for node in ast.parse(self.remote_source).body:
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    name = node.targets[0].id
                    if name in ('RPC_TIMEOUTS', 'RECOVERY_GRACE_SECONDS'):
                        constants[name] = ast.literal_eval(node.value)
            budgets = constants['RPC_TIMEOUTS']
            grace = constants['RECOVERY_GRACE_SECONDS']
            if (not isinstance(budgets, dict) or set(budgets) != {'capture', 'default'} or
                    any(type(n) is not int or not 0 < n <= 86400 for n in budgets.values()) or
                    type(grace) is not int or not 0 < grace <= 3600):
                raise ValueError('invalid operation budgets')
        except (KeyError, TypeError, ValueError, SyntaxError) as exc:
            raise CaptureError('remote source lacks valid operation budgets') from exc
        self.rpc_timeouts = budgets
        self.recovery_grace = grace
        self.started = False
        self.mux = tempfile.TemporaryDirectory(prefix='prace-cap-')
        self.options = ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                        '-o', 'ConnectTimeout=10', '-o', 'ControlMaster=auto',
                        '-o', 'ControlPath=' + self.mux.name + '/login', '-o', 'ControlPersist=60']

    def call(self, request):
        helper, remote, tree = self.helper, self.remote_source, self.tree
        payload = ('import types,json,sys,signal\n'
                   'signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))\n'
                   'm=types.ModuleType("prace_metadata_archive")\n'
                   'm.__file__="<prace-metadata-bundle>"\n'
                   'sys.modules[m.__name__]=m\n'
                   f'exec(compile({helper!r},m.__file__,"exec"),m.__dict__)\n'
                   'r=types.ModuleType("prace_capture_remote")\n'
                   'r.__file__="<prace-capture-bundle>"\n'
                   'sys.modules[r.__name__]=r\n'
                   f'exec(compile({remote!r},r.__file__,"exec"),r.__dict__)\n'
                   'n=types.ModuleType("prace_native_repo")\n'
                   f'exec(compile({self.native_repo_source!r},"<prace-native-repo>","exec"),n.__dict__)\n'
                   f'r.METADATA_HELPER=m; r.TREE_SOURCE={tree!r}; r.NATIVE_REPO_HELPER=n\n'
                   'w=types.ModuleType("prace_capture_window")\n'
                   f'exec(compile({self.window_source!r},"<prace-window-bundle>","exec"),w.__dict__)\n'
                   'r.WINDOW_HELPER=w; w.C=r\n'
                   f'print(json.dumps(r.handle(json.loads({json.dumps(request)!r}))))\n')
        self.started = True
        timeout = self.rpc_timeouts.get(request['op'], self.rpc_timeouts['default']) + TRANSPORT_GRACE_SECONDS
        if request['op'] == 'capture':
            timeout += self.recovery_grace
        result = subprocess.run(['ssh', *self.options, 'root@' + LOGIN, 'python3', '-'],
                                input=payload, text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            raise CaptureError('SSH operation failed or was interrupted: ' + request['op'])
        try:
            return json.loads(result.stdout)
        except ValueError as e:
            raise CaptureError('remote operation returned no valid result') from e

    def copy(self, run_id, name, dest):
        remote = f'root@{LOGIN}:/root/prace-capture/{run_id}/{name}'
        # run_id/name were validated; no shell interpolation or user source paths.
        with open(dest, 'xb') as f:
            os.chmod(dest, 0o600)
        result = subprocess.run(['scp', *self.options, remote, str(dest)],
                                capture_output=True, timeout=1200)
        if result.returncode:
            raise CaptureError('artifact copy failed; partial retained')

    def close(self):
        try:
            if self.started:
                subprocess.run(['ssh', *self.options, '-O', 'exit', 'root@' + LOGIN],
                               capture_output=True, timeout=15)
        finally:
            self.mux.cleanup()


def provenance():
    repo = TOOLS.parent.parent
    revision = subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'],
                              check=True, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(['git', '-C', str(repo), 'status', '--porcelain'],
                           check=True, capture_output=True, text=True).stdout
    if dirty:
        raise CaptureError('capture requires a clean reviewed checkout')
    paths = [TOOLS / n for n in ('session-a-capture.py', 'prace_capture_remote.py', 'prace_metadata_archive.py',
                               'prace_capture_window.py', 'prace_native_capture.py', 'prace_native_repo.py')]
    for name in ('native-state-record.py', 'slurm-window.py', 'fleet_audit.py'):
        if (TOOLS / name).is_file():
            paths.append(TOOLS / name)
    paths.append(TOOLS.parent / 'roles/login_storage/files/prace-tree-listing')
    return revision, {p.name: digest(p) for p in paths}


@contextlib.contextmanager
def locked(directory):
    path = Path(directory) / '.lock'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['capture', 'recover', 'finish', 'backout'])
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--stage', choices=STAGES, default='pre-w1')
    parser.add_argument('--window', type=Path, help='private closed slurm-window record; borrow its fence and lease')
    parser.add_argument('--lease-id', help='explicit id of the borrowed closed window')
    parser.add_argument('--native', action='store_true', help='capture mixed topology with the reviewed native record; post-w2 borrowed window only')
    parser.add_argument('--max-native-repo-bytes', type=int, default=8 * GIB)
    parser.add_argument('--execute', action='store_true', help='explicitly enable fleet SSH')
    parser.add_argument('--ack-exclusive-window', action='store_true')
    parser.add_argument('--ack-no-admin-writers', action='store_true')
    parser.add_argument('--ack-invalid-capture', action='store_true', help='backout accepts no recovery point')
    args = parser.parse_args(argv)
    if not args.execute:
        print('PLAN ONLY: no SSH; build/test and review before --execute. Action: ' + args.action)
        return 0
    if bool(args.window) != bool(args.lease_id) or (args.action != 'capture' and args.window):
        parser.error('capture accepts --window and --lease-id together; recovery uses the frozen run record')
    if args.native and (args.action != 'capture' or args.stage != 'post-w2' or not args.window):
        parser.error('--native requires a post-w2 capture borrowing a closed window')
    if not args.ack_exclusive_window or not args.ack_no_admin_writers:
        parser.error('execution requires exclusive-window and no-admin-writers attestations')
    if args.action == 'backout' and not args.ack_invalid_capture:
        parser.error('backout requires --ack-invalid-capture')
    allowed = (Path.home() / 'prace-recovery/session-a').absolute()
    if not args.run_dir.absolute().is_relative_to(allowed) or args.run_dir.absolute() == allowed:
        parser.error('run-dir must be a new point under ~/prace-recovery/session-a/')
    remote = None; run = None
    try:
        revision, hashes = provenance()
        if args.action == 'capture':
            window_record = read_window(args.window, args.lease_id) if args.window else None
            run = Run.create(args.run_dir, None, args.stage, revision, hashes, window_record=window_record,
                             native=native_module().options(args.max_native_repo_bytes) if args.native else None)
        else:
            private_dir(args.run_dir.absolute())
        with locked(args.run_dir.absolute()):
            # Read only AFTER acquiring the lock; another process may have advanced the run.
            run = Run(args.run_dir, None)
            if run.state['tool_hashes'] != hashes or run.state['revision'] != revision:
                raise CaptureError('use the exact capture checkout/tools for recovery')
            if run.state['phase'] in ('complete', 'aborted'):
                raise CaptureError('window is already closed')
            remote = SSHRemote(expected_hashes=hashes)
            run.remote = remote
            run.attest_no_admin_writers = args.ack_no_admin_writers
            try:
                run.state['operator_attestation_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
                run.save()
                if args.action == 'capture': run.start()
                elif args.action == 'recover': run.recover()
                elif args.action == 'finish': run.complete()
                else: run.backout()
            except (Exception, KeyboardInterrupt) as e:
                # Only this lock holder, after beginning work, may record an operation failure.
                try: run.mark_failed(e)
                except OSError: pass
                raise
        print('CAPTURE STATUS: ' + run.state['phase'] + '; accepted=' + str(run.state['accepted']).lower())
        return 0
    except (Exception, KeyboardInterrupt):
        print('REFUSED/FAILED: admission is not automatically reopened. Use the private run record and recovery runbook.', file=sys.stderr)
        return 1
    finally:
        if remote is not None:
            try: remote.close()
            except Exception: pass


if __name__ == '__main__':
    raise SystemExit(main())

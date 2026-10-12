#!/usr/bin/env python3
"""Synthetic, unprivileged checks for the fleet installer profiles (FLEET-REBUILD).

Never runs the builder, creates credentials/media, contacts BMCs, or opens disks.
Extracts the real profile/mode, menu and locking blocks; evaluates the nonsecret
renderer with a dummy hash/key and the local first-address helper source. %pre uses temporary by-id symlinks,
DMI files, a stubbed lsblk and a mocked block-device predicate. These are logic
checks, not QEMU, Anaconda, firmware or physical-media installation proof.
"""
import ast
import base64
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

SOURCE = Path(__file__).with_name('build-ks.sh').read_text()
PROFILE = SOURCE[SOURCE.index('# Profile values'):SOURCE.index('# The first-address helper must be embedded')]
LOCK = SOURCE[SOURCE.index('# --- build locks:'):SOURCE.index('# --- secret handling:')]
MENU = SOURCE[SOURCE.index('# --- grub:'):SOURCE.index('# --- patch efiboot.img')]
PYTHON = SOURCE.split("python3 - <<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
KS_EXPR = next(n.value for n in ast.parse(PYTHON).body
               if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'ks' for t in n.targets))
FIELDS = ('KS_HOSTNAME', 'SELECTOR', 'VG', 'LV_ROOT_MB', 'LV_LIBVIRT_MB',
          'SERIAL_UNIT', 'SERIAL_TTY', 'EXACT_WWN', 'EXPECTED_CHASSIS',
          'ALLOW_INTERACTIVE_INSTALL', 'MODE', 'KS_DEFAULT_ENTRY', 'KS_END_ACTION', 'TARGET_SERIAL',
          'FLEET_ROLE', 'KS_NETWORK', 'LOGIN_PRIV_MAC', 'LOGIN_PRIV_IP')
WWN = '6005000081ea6ba17e7c0a052503cf6d'  # synthetic, never real hardware
G005 = '60050000a346210d311ce34853176ea6'
OWN = {'hpe': 'EXNVME00000001', 'lenovo': '600605b0000000000000000000000002',
       'hpe-v100-g003': '60050000b0c10242afbfcad3f5cafb3d', 'hpe-v100-g004': '60050000f7fca2d55eb51600d6e1fa5c',
       'hpe-v100-g005': G005}
CHASSIS = {'hpe': 'EXSERIAL01', 'lenovo': 'EXSER02', 'hpe-v100-g003': 'EXSERIAL03',
           'hpe-v100-g004': 'EXSERIAL04', 'hpe-v100-g005': 'EXSERIAL05'}
COMPUTE = ('lenovo', 'hpe-v100-g003', 'hpe-v100-g004', 'hpe-v100-g005')


def shell(script, env=None):
    base = {'PATH': os.environ['PATH'], 'LANG': 'C', 'HOME': '/nonexistent-test-home'}
    base.update(env or {})
    return subprocess.run(['bash', '-eu', '-c', script], env=base, text=True, capture_output=True, timeout=10)


def profile(host='hpe-v100-g003', exact=None, default='0', extra=None):
    env = {'HOST': host, 'KS_DEFAULT_ENTRY': default}
    if exact is not None:
        env['EXACT_WWN'] = exact
    env.update(extra or {})
    result = shell(PROFILE + '\nprintf "%s\\0" ' + ' '.join('"${' + f + ':-}"' for f in FIELDS), env)
    # Split on the terminators only: trailing empty fields (e.g. KS_NETWORK on compute) are kept.
    values = dict(zip(FIELDS, result.stdout.split('\0')[:-1])) if result.returncode == 0 else {}
    return result, values


def kickstart(values, helper_file=None):
    helper_file = helper_file or Path(__file__).parents[1]/'tools/fleet-first-address.py'
    values = dict(values, KS_PUBKEY='ssh-ed25519 SYNTHETIC_TEST_KEY', KS_CFG='/unused',
                  BOOTSTRAP_HELPER=str(helper_file))
    scope = {'os': SimpleNamespace(environ=values), 'h': 'SYNTHETIC_TEST_HASH',
             'base64': base64, 'hashlib': hashlib, 'Path': Path}
    # Evaluate the real renderer's nonsecret prelude only; skip imports, password
    # hashing and all post-render writes. No source builder shell is executed.
    prelude = []
    for node in ast.parse(PYTHON).body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'ks' for t in node.targets):
            break
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'h' for t in node.targets):
            continue
        prelude.append(node)
    exec(compile(ast.Module(body=prelude, type_ignores=[]), '<renderer prelude>', 'exec'), scope)
    return eval(compile(ast.Expression(KS_EXPR), '<builder KS expression>', 'eval'), scope)


class Profiles(unittest.TestCase):
    def test_every_profile_is_chassis_bound_with_its_own_disk(self):
        for host, own in OWN.items():
            with self.subTest(host=host):
                result, p = profile(host)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('wget', SOURCE.split('%packages', 1)[1].split('%end', 1)[0])
                self.assertEqual((p['MODE'], p['EXACT_WWN'], p['EXPECTED_CHASSIS']), ('install', own, CHASSIS[host]))
                self.assertEqual((p['ALLOW_INTERACTIVE_INSTALL'], p['LV_LIBVIRT_MB'], p['KS_END_ACTION']), ('0', '0', 'poweroff'))
                self.assertEqual(p['FLEET_ROLE'], 'login' if host == 'hpe' else 'compute')

    def test_explicit_empty_identity_is_diagnostic(self):
        for host in OWN:
            with self.subTest(host=host):
                result, p = profile(host, exact='')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((p['MODE'], p['EXACT_WWN']), ('diagnostic', ''))

    def test_valid_exact_enables_install_but_defaults_rescue(self):
        result, p = profile(exact=WWN)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((p['MODE'], p['KS_DEFAULT_ENTRY']), ('install', '0'))
        _, selected = profile(exact=WWN, default='2')
        self.assertEqual(selected['KS_DEFAULT_ENTRY'], '2')

    def test_chassis_environment_cannot_override_profile(self):
        _, p = profile(exact=WWN, extra={'EXPECTED_CHASSIS': 'EXSERIAL05', 'FLEET_ROLE': 'login'})
        self.assertEqual((p['EXPECTED_CHASSIS'], p['FLEET_ROLE']), ('EXSERIAL03', 'compute'))

    def test_another_nodes_identity_and_invalid_input_rejected(self):
        for host, own in OWN.items():
            for value in [v for h, v in OWN.items() if h != host]:
                with self.subTest(host=host, other=value):
                    self.assertNotEqual(profile(host, exact=value)[0].returncode, 0)
        for value in ('0'*32, 'f'*32, '0'*16, 'f'*16, 'scsi-3'+WWN, 'wwn-0x'+WWN, 'nvme-sample',
                      'BAD;touch /tmp/never', '$(id)', '123', 'ABCDEF0123456789'):
            for host in ('hpe-v100-g003', 'hpe-v100-g004', 'lenovo'):
                with self.subTest(value=value, host=host):
                    self.assertNotEqual(profile(host, exact=value)[0].returncode, 0)

    def test_install_default_needs_identity_and_no_interactive_entry(self):
        for exact, default in (('', '2'), (WWN, '3'), (None, '3')):
            self.assertNotEqual(profile(exact=exact, default=default)[0].returncode, 0)
        result, p = profile(default='2')       # unset -> the node's own disk, install entry allowed
        self.assertEqual((result.returncode, p['EXACT_WWN']), (0, OWN['hpe-v100-g003']))

    def test_menus_have_no_unguarded_install(self):
        for host in OWN:
            for exact in ('', None, WWN if host != 'hpe' else 'EXNVME00000001'):
                with self.subTest(host=host, exact=exact), tempfile.TemporaryDirectory() as tmp:
                    _, p = profile(host, exact)
                    tree = Path(tmp)
                    (tree/'EFI/BOOT').mkdir(parents=True)
                    (tree/'isolinux').mkdir()
                    result = shell(MENU, dict(p, TREE=tmp))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    grub = (tree/'EFI/BOOT/grub.cfg').read_text()
                    bios = (tree/'isolinux/isolinux.cfg').read_text()
                    self.assertNotIn('interactive, DESTRUCTIVE', grub)
                    self.assertNotIn('label installtext', bios)
                    self.assertEqual('DESTRUCTIVE' in grub, exact != '')
                    self.assertEqual('label install\n' in bios, exact != '')

    def test_host_key_fingerprints_reach_the_install_console(self):
        for host, tty in (('hpe', 'ttyS0'), ('lenovo', 'ttyS1'), *((h, 'ttyS0') for h in COMPUTE if h != 'lenovo')):
            with self.subTest(host=host):
                _, p = profile(host)
                post = kickstart(p).split('%post --erroronfail\n', 1)[1]
                self.assertIn('ssh-keygen -A\nrestorecon -R /etc/ssh /root/.ssh /home/admin/.ssh\n', post)
                self.assertIn('for k in /etc/ssh/ssh_host_*_key.pub; do echo "host key: $(ssh-keygen -lf "$k")" >/dev/%s; done' % tty, post)

    def test_first_address_helper_exact_bytes_on_compute_profiles(self):
        helper = Path(__file__).parents[1]/'tools/fleet-first-address.py'
        expected = helper.read_bytes()
        required = {'python3','iproute','iputils','NetworkManager','firewalld','ethtool','policycoreutils','procps-ng'}
        for host in COMPUTE:
            with self.subTest(host=host):
                _, p = profile(host)
                ks = kickstart(p)
                payload = ks.split("<<'PRACE_BOOTSTRAP_BASE64'\n",1)[1].split('\nPRACE_BOOTSTRAP_BASE64',1)[0]
                self.assertEqual(base64.b64decode(payload,validate=True),expected)
                self.assertIn(hashlib.sha256(expected).hexdigest(),ks)
                self.assertIn('chmod 0700 /usr/local/sbin/fleet-first-address.py',ks)
                self.assertIn('ExecStart=/usr/local/sbin/fleet-first-address.py --auto --apply --retry-minutes 45',ks)
                self.assertIn('systemctl enable prace-first-address.service',ks)
                self.assertIn('no-auto-default=*',ks)
                self.assertNotIn('LOGIN_PRIV', ks)
                packages = ks.split('%packages\n',1)[1].split('\n%end',1)[0].splitlines()
                self.assertTrue(required.issubset(set(packages)))
                self.assertNotIn('--ignoremissing',ks)
                self.assertNotIn('network --device',ks)
                self.assertNotIn('libvirt_images',ks)
                self.assertNotIn('bootstrap-v100-private.py',ks)

    def test_login_node_gets_fixed_addresses_by_mac_and_no_helper(self):
        _, p = profile('hpe')
        ks = kickstart(p, helper_file=Path('/does-not-exist'))
        self.assertIn('network --device=02:00:00:00:00:02 --bootproto=static --ip=192.0.2.205 --netmask=255.255.255.0 --gateway=192.0.2.254', ks)
        self.assertNotIn('network --device=02:00:00:00:00:01', ks)       # private port: private_net format instead
        self.assertIn('= "02:00:00:00:00:01" ] && priv=', ks)
        self.assertIn("'address1=10.90.10.1/25' 'never-default=true'", ks)
        self.assertIn('"id=private-$priv"', ks)
        self.assertIn('network --hostname=lab-dl380', ks)
        self.assertIn('no-auto-default=*', ks)
        self.assertNotIn('fleet-first-address', ks)
        self.assertNotIn('--ignoremissing', ks)

    def test_bootstrap_embedding_treats_shell_and_format_bytes_as_data(self):
        unusual = b'#!/usr/bin/env python3\n# quotes " \' ${HOME} %post {braces} \\n\n'
        with tempfile.TemporaryDirectory() as tmp:
            helper = Path(tmp)/'helper.py'
            helper.write_bytes(unusual)
            _, p = profile(exact=WWN)
            ks = kickstart(p, helper_file=helper)
            payload = ks.split("<<'PRACE_BOOTSTRAP_BASE64'\n",1)[1].split('\nPRACE_BOOTSTRAP_BASE64',1)[0]
            self.assertEqual(base64.b64decode(payload,validate=True),unusual)
            self.assertNotIn('${HOME}',ks)

    def test_profile_local_output_and_secret_paths(self):
        self.assertIn('export KS_CFG="$TREE/ks.cfg"', SOURCE)
        self.assertIn("open(os.environ['KS_CFG'], 'w').write(ks)", SOURCE)
        self.assertNotIn("open('/tmp/ks-built.cfg'", SOURCE)
        self.assertIn('${HOST}-bootstrap.pw', SOURCE)
        self.assertIn('isotree-$HOST', SOURCE)


class Selector(unittest.TestCase):
    def probe(self, *, host='hpe-v100-g003', chassis='EXSERIAL03', exact=WWN,
              aliases=None, kind='disk', block='yes', capacity=str(447*1024**3)):
        _, p = profile(host, exact=exact)
        script = kickstart(p).split('%pre --erroronfail\n',1)[1].split('\n%end',1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            byid = base/'by-id'; byid.mkdir()
            (base/'serial').write_text(chassis + '\n')
            for name, target in (aliases if aliases is not None else [('scsi-3'+WWN,'sda'), ('wwn-0x'+WWN,'sda')]):
                (base/target).touch()
                (byid/name).symlink_to(base/target)
            script = script.replace('/dev/disk/by-id/', str(byid)+'/')
            script = script.replace('/sys/class/dmi/id/product_serial', str(base/'serial'))
            script = script.replace('/tmp/disk-storage.ks', str(base/'disk-storage.ks'))
            script = script.replace('/dev/$TTY', str(base/'console'))
            # Explicitly mocked OS predicates: no real device is ever opened.
            self.assertIn('[ -b "$resolved" ]', script)
            script = script.replace('[ -b "$resolved" ]', '[ "$TEST_BLOCK" = yes ]')
            stub = 'lsblk() { case "$2" in TYPE) printf "%s\\n" "$TEST_KIND";; SIZE) printf "%s\\n" "$TEST_CAPACITY";; *) return 1;; esac; }\n'
            result = shell(stub + script, {'TEST_BLOCK':block,'TEST_KIND':kind,'TEST_CAPACITY':capacity})
            recipe = (base/'disk-storage.ks').read_text() if (base/'disk-storage.ks').exists() else ''
            log = (base/'console').read_text() if (base/'console').exists() else ''
            return result.returncode, recipe, log

    def test_exact_aliases_deduplicate(self):
        code, recipe, log = self.probe()
        self.assertEqual(code, 0, log)
        self.assertIn('clearpart --all --initlabel --drives=sda', recipe)
        self.assertIn('ignoredisk --only-use=sda', recipe)

    def test_g004_bound_to_own_serial(self):
        self.assertEqual(self.probe(host='hpe-v100-g004', chassis='EXSERIAL04')[0], 0)
        self.assertNotEqual(self.probe(host='hpe-v100-g004')[0], 0)

    def test_wrong_or_absent_chassis_cannot_write_storage_recipe(self):
        for chassis in ('EXSERIAL05','EXSERIAL04',''):
            with self.subTest(chassis=chassis):
                code, recipe, log = self.probe(chassis=chassis)
                self.assertNotEqual(code, 0)
                self.assertEqual(recipe, '')
                self.assertIn('chassis mismatch', log)

    def test_missing_identity_is_noninstalling_even_if_ks_manually_selected(self):
        code, recipe, _ = self.probe(exact='')
        self.assertNotEqual(code, 0)
        self.assertEqual(recipe, '')

    def test_zero_wrong_partition_and_ambiguous_targets_fail_closed(self):
        cases = [[], [('wwn-0x'+'1'*32,'sda')], [('wwn-0x'+WWN+'-part1','sda1')],
                 [('wwn-0x'+WWN,'sda'),('scsi-3'+WWN,'sdb')]]
        for aliases in cases:
            with self.subTest(aliases=aliases):
                code, recipe, _ = self.probe(aliases=aliases)
                self.assertNotEqual(code, 0)
                self.assertEqual(recipe, '')

    def test_nonblock_partition_nvme_and_small_disks_rejected(self):
        for kwargs in ({'block':'no'}, {'kind':'part'}, {'aliases':[('wwn-0x'+WWN,'nvme0n1')]},
                       {'capacity':str(90*1024**3)}, {'capacity':''}, {'capacity':'bad'}):
            with self.subTest(kwargs=kwargs):
                code, recipe, _ = self.probe(**kwargs)
                self.assertNotEqual(code, 0)
                self.assertEqual(recipe, '')


    def test_login_node_nvme_exact_serial_only(self):
        nvme = [('nvme-MO001600KWVNB_EXNVME00000001', 'nvme0n1'), ('nvme-eui.eeee0000000000000000000000000001', 'nvme0n1')]
        code, recipe, log = self.probe(host='hpe', chassis='EXSERIAL01', exact=None, aliases=nvme, capacity=str(1600*1000**3))
        self.assertEqual(code, 0, log)
        self.assertIn('--drives=nvme0n1', recipe)
        for aliases in ([('nvme-MO001600KWVNB_S4FZNE0M600803', 'nvme0n1')],             # another serial
                        [('nvme-MO001600KWVNB_EXNVME00000001', 'sda')]):                # not an NVMe namespace
            with self.subTest(aliases=aliases):
                code, recipe, _ = self.probe(host='hpe', chassis='EXSERIAL01', exact=None, aliases=aliases, capacity=str(1600*1000**3))
                self.assertNotEqual(code, 0)
                self.assertEqual(recipe, '')


class Locking(unittest.TestCase):
    def test_profile_and_output_locks(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, HOME=tmp, HOST='hpe-v100-g003', OUT=tmp+'/g003.iso')
            # Only the lock block runs; read keeps the first holder alive.
            holder = subprocess.Popen(['bash','-eu','-c',LOCK+'\nprintf "READY\\n"; read -r release'],
                                      env=env, text=True, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertEqual(holder.stdout.readline().strip(),'READY')
                self.assertNotEqual(shell(LOCK,dict(env,OUT=tmp+'/other.iso')).returncode,0)
                self.assertNotEqual(shell(LOCK,dict(env,HOST='hpe-v100-g004')).returncode,0)
                self.assertEqual(shell(LOCK,dict(env,HOST='hpe-v100-g004',OUT=tmp+'/g004.iso')).returncode,0)
            finally:
                holder.communicate('release\n',timeout=5)
            self.assertEqual(shell(LOCK,env).returncode,0)


if __name__ == '__main__':
    unittest.main(verbosity=2)

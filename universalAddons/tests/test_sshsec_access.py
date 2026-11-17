"""SSH Security: login options (managed block, rollback, lockout guard, commit-confirm) and
authorized_keys management. Every key here is generated in a temporary directory; nothing touches
the real sshd, /etc/ssh or /root."""
import base64
import json
import os
import pwd
import shutil
import stat
import subprocess
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import include, path

from universalAddons.sshsec import actions, authkeys as ak, manage, sshconf as sc, views
from universalAddons.sshsec.service import SSHSecError, parse_sshd_t

from CyberCP.urls import urlpatterns as _base_urls  # noqa: E402
urlpatterns = list(_base_urls) + [path('addons/ssh-security/', include('universalAddons.sshsec.urls'))]

EL8_CONFIG = """#\t$OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $

# This is the sshd server system-wide configuration file.

# If you want to change the port on a SELinux system, you have to tell
# SELinux about this change.
#Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTHPRIV
PermitRootLogin yes
AuthorizedKeysFile\t.ssh/authorized_keys
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
Subsystem\tsftp\t/usr/libexec/openssh/sftp-server
Match User backup
\tPasswordAuthentication yes
\tPermitRootLogin yes
"""

SETTINGS_OFF = {'password': 'no', 'root': 'prohibit-password', 'port': None, 'maxauthtries': 3,
                'logingracetime': 60}
SUPPORTED = {'passwordauthentication', 'kbdinteractiveauthentication', 'challengeresponseauthentication'}


def keygen(directory, name, kind='ed25519', bits=None, passphrase='', comment='test@example'):
    path = os.path.join(directory, name)
    argv = ['ssh-keygen', '-q', '-t', kind, '-N', passphrase, '-C', comment, '-f', path]
    if bits:
        argv[4:4] = ['-b', str(bits)]
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(path) as private, open(path + '.pub') as public:
        return private.read(), public.read().strip()


def simulated_sshd_t(text):
    """A small model of `sshd -T` (OpenSSH 8.0 on EL8): first value wins, Port is cumulative,
    Match blocks are skipped, prohibit-password prints as without-password."""
    values, ports, in_match = {}, [], False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        key, _, value = stripped.replace('=', ' ', 1).partition(' ') if '=' in stripped.split()[0] else \
            stripped.partition(' ')
        key, value = key.lower(), value.strip()
        if key == 'match':
            in_match = True
        if in_match:
            continue
        if key == 'port':
            ports.append(value)
        else:
            values.setdefault(key, value)
    out = dict({'passwordauthentication': 'yes', 'permitrootlogin': 'yes', 'maxauthtries': '6',
                'logingracetime': '120', 'pubkeyauthentication': 'yes', 'challengeresponseauthentication': 'yes',
                'authorizedkeysfile': '.ssh/authorized_keys', 'authenticationmethods': 'any'}, **values)
    out.setdefault('kbdinteractiveauthentication', out['challengeresponseauthentication'])
    if out['challengeresponseauthentication'] == 'yes':
        out['kbdinteractiveauthentication'] = 'yes'
    if out['permitrootlogin'] == 'prohibit-password':
        out['permitrootlogin'] = 'without-password'
    lines = ['port %s' % p for p in (ports or ['22'])] + ['%s %s' % kv for kv in out.items()]
    return '\n'.join(lines) + '\n'


class Host:
    """A fake root environment: sshd_config, state dir and a login user's home in a temp dir."""

    def __init__(self, config=EL8_CONFIG):
        self.root = tempfile.mkdtemp(prefix='ic-sshsec-')
        self.etc = os.path.join(self.root, 'etc-ssh')
        self.home = os.path.join(self.root, 'root-home')
        self.keys = os.path.join(self.root, 'keys')
        for d in (self.etc, self.home, self.keys):
            os.makedirs(d)
        self.config = os.path.join(self.etc, 'sshd_config')
        with open(self.config, 'w') as handle:
            handle.write(config)
        os.chmod(self.config, 0o600)
        self.calls = []
        self.fail_test = None        # 'all': every sshd -t fails; 'live': only the live file
        self.reload_code = 0
        self.timer_code = 0
        self.entry = pwd.struct_passwd(('root', 'x', os.getuid(), os.getgid(), 'root', self.home, '/bin/bash'))
        self.patches = [
            mock.patch.object(manage, 'SSHD_CONFIG', self.config),
            mock.patch.object(manage, 'DROPIN_DIR', os.path.join(self.etc, 'sshd_config.d')),
            mock.patch.object(manage, 'STATE_DIR', os.path.join(self.root, 'state')),
            mock.patch.object(manage, 'pwd_lookup', lambda name: self.entry if name == 'root' else
                              (_ for _ in ()).throw(KeyError(name))),
            mock.patch.object(manage, 'login_users', lambda: ['root']),
            mock.patch.object(manage, 'has_password', lambda name: True),
        ]

    def __enter__(self):
        for patch in self.patches:
            patch.start()
        return self

    def __exit__(self, *exc):
        for patch in reversed(self.patches):
            patch.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    def text(self):
        with open(self.config) as handle:
            return handle.read()

    def authorized(self):
        try:
            with open(os.path.join(self.home, '.ssh', 'authorized_keys')) as handle:
                return handle.read()
        except FileNotFoundError:
            return None

    def install_keys(self, *lines):
        os.makedirs(os.path.join(self.home, '.ssh'), mode=0o700, exist_ok=True)
        with open(os.path.join(self.home, '.ssh', 'authorized_keys'), 'w') as handle:
            handle.write(''.join(line + '\n' for line in lines))

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        name = os.path.basename(argv[0])
        if name == 'ssh-keygen':
            return subprocess.run(argv, **kwargs)
        if name == 'sshd':
            target = argv[argv.index('-f') + 1] if '-f' in argv else self.config
            if '-t' in argv and (self.fail_test == 'all' or (self.fail_test == 'live' and target == self.config)):
                return SimpleNamespace(returncode=255, stdout='%s line 3: Bad configuration option' % target)
            if '-t' in argv:
                return SimpleNamespace(returncode=0, stdout='')
            with open(target) as handle:
                return SimpleNamespace(returncode=0, stdout=simulated_sshd_t(handle.read()))
        if name == 'systemctl':
            if argv[1] == 'is-active':
                return SimpleNamespace(returncode=0 if argv[2] == 'sshd' else 3, stdout='active\n' if argv[2] == 'sshd'
                                       else 'inactive\n')
            if argv[1] == 'reload':
                return SimpleNamespace(returncode=self.reload_code, stdout='' if not self.reload_code else 'failed')
            return SimpleNamespace(returncode=0, stdout='')
        if name == 'systemd-run':
            return SimpleNamespace(returncode=self.timer_code, stdout='Running timer as unit' if not self.timer_code
                                   else 'Failed to start transient timer unit')
        if name == 'getenforce':
            return SimpleNamespace(returncode=0, stdout='Disabled\n')
        if name == 'ss':
            return SimpleNamespace(returncode=0, stdout='LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\n')
        return SimpleNamespace(returncode=0, stdout='')

    def apply(self, settings=None, tested=True, **kwargs):
        return manage.login_apply(dict(settings or SETTINGS_OFF), 'root', tested, ['198.51.100.20'], 'admin',
                                  runner=self.run, sleep=lambda s: None, **kwargs)

    def ran(self, prefix):
        return [c for c in self.calls if os.path.basename(c[0]) == prefix[0] and c[1:len(prefix)] == prefix[1:]]


# ----------------------------------------------------------------------------- rendering

class BlockRendering(SimpleTestCase):
    def test_block_before_first_directive_and_match(self):
        settings = sc.validate_settings(SETTINGS_OFF)
        out = sc.render_main(EL8_CONFIG, settings, SUPPORTED)
        lines = out.splitlines()
        begin = next(i for i, l in enumerate(lines) if l.startswith(sc.BEGIN))
        end = lines.index(sc.END)
        first_directive = next(i for i, l in enumerate(lines) if l.strip() and not l.lstrip().startswith('#'))
        match = next(i for i, l in enumerate(lines) if l.startswith('Match '))
        self.assertLess(begin, first_directive)
        self.assertLess(end, match)
        block = lines[begin:end + 1]
        for line in ('PasswordAuthentication no', 'KbdInteractiveAuthentication no',
                     'ChallengeResponseAuthentication no', 'PermitRootLogin prohibit-password', 'MaxAuthTries 3',
                     'LoginGraceTime 60'):
            self.assertIn(line, block)
        self.assertIn(sc.SUPERSEDED + 'PermitRootLogin yes', lines, 'the old global line is marked, not deleted')
        self.assertIn('\tPermitRootLogin yes', lines, 'Match blocks are never touched')
        self.assertIn('\tPasswordAuthentication yes', lines)
        self.assertTrue(lines[0].startswith('#\t$OpenBSD'), 'header comments stay on top')
        self.assertEqual(sc.read_block(out), {'present': True, 'edited': False, 'values': {
            'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
            'challengeresponseauthentication': 'no', 'permitrootlogin': 'prohibit-password', 'maxauthtries': '3',
            'logingracetime': '60'}})
        effective = parse_sshd_t(simulated_sshd_t(out))
        self.assertEqual(sc.mismatches(effective, settings), [])

    def test_idempotent_and_reversible(self):
        settings = sc.validate_settings(SETTINGS_OFF)
        once = sc.render_main(EL8_CONFIG, settings, SUPPORTED)
        self.assertEqual(sc.render_main(once, settings, SUPPORTED), once)
        self.assertEqual(once.count(sc.BEGIN), 1)
        self.assertEqual(sc.strip_main(once), EL8_CONFIG, 'removing the block restores the file byte for byte')
        other = sc.validate_settings(dict(SETTINGS_OFF, password='yes', root='yes', maxauthtries=None))
        twice = sc.render_main(once, other, SUPPORTED)
        self.assertEqual(twice.count(sc.BEGIN), 1)
        self.assertNotIn('KbdInteractiveAuthentication no', twice)
        self.assertNotIn('MaxAuthTries', twice.split(sc.END)[0].split(sc.BEGIN)[1])

    def test_port_is_cumulative_so_other_port_lines_are_disabled(self):
        config = EL8_CONFIG.replace('#Port 22\n', 'Port 22\n')
        settings = sc.validate_settings(dict(SETTINGS_OFF, port='2222'))
        out = sc.render_main(config, settings, SUPPORTED)
        self.assertIn(sc.SUPERSEDED + 'Port 22', out)
        effective = parse_sshd_t(simulated_sshd_t(out))
        self.assertEqual(effective['port'], '2222')
        back = sc.render_main(out, sc.validate_settings(dict(SETTINGS_OFF)), SUPPORTED)
        self.assertIn('\nPort 22\n', back, 'a line no longer superseded is restored')

    def test_edit_by_cyberpanel_page_is_detected(self):
        out = sc.render_main(EL8_CONFIG, sc.validate_settings(SETTINGS_OFF), SUPPORTED)
        # plogical/sshConfigUtilities.render_ssh_config rewrites the first PermitRootLogin line: ours.
        from plogical.sshConfigUtilities import render_ssh_config
        edited = render_ssh_config(out.encode(), 22, 'yes').decode()
        state = sc.read_block(edited)
        self.assertTrue(state['edited'])
        self.assertEqual(state['values']['permitrootlogin'], 'yes')
        self.assertEqual(edited.count(sc.BEGIN), 1, 'CyberPanel\'s page keeps the block intact')

    def test_validation_and_damaged_block(self):
        for bad in ({}, {'password': 'maybe', 'root': 'yes'}, {'password': 'no', 'root': 'sometimes'},
                    dict(SETTINGS_OFF, port='0'), dict(SETTINGS_OFF, port='70000'), dict(SETTINGS_OFF, port='8090'),
                    dict(SETTINGS_OFF, port='22;'), dict(SETTINGS_OFF, maxauthtries='50'),
                    dict(SETTINGS_OFF, logingracetime='5')):
            with self.assertRaises(SSHSecError, msg=bad):
                sc.validate_settings(bad)
        self.assertEqual(sc.validate_settings({'password': 'no', 'root': 'without-password'})['root'],
                         'prohibit-password')
        with self.assertRaises(SSHSecError):
            sc.render_main(sc.BEGIN + '\nPort 22\n', sc.validate_settings(SETTINGS_OFF))
        self.assertTrue(sc.includes_dropins('Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n'))
        self.assertFalse(sc.includes_dropins(EL8_CONFIG))
        self.assertEqual(sc.match_blocks(EL8_CONFIG)[0]['sets'], ['PasswordAuthentication yes',
                                                                   'PermitRootLogin yes'])


# ----------------------------------------------------------------------------- keys

class KeyParsing(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.dir = tempfile.mkdtemp(prefix='ic-keys-')
        cls.ed_private, cls.ed_public = keygen(cls.dir, 'ed')
        cls.rsa_private, cls.rsa_public = keygen(cls.dir, 'rsa', 'rsa', 3072, comment='ops key')
        cls.ec_private, cls.ec_public = keygen(cls.dir, 'ec', 'ecdsa', 384)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)
        super().tearDownClass()

    def keygen_l(self, name):
        out = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', os.path.join(self.dir, name + '.pub')],
                             stdout=subprocess.PIPE, universal_newlines=True, check=True).stdout.split()
        return int(out[0]), out[1]

    def test_fingerprint_and_bits_match_ssh_keygen(self):
        for name, line, kind in (('ed', self.ed_public, 'ssh-ed25519'), ('rsa', self.rsa_public, 'ssh-rsa'),
                                 ('ec', self.ec_public, 'ecdsa-sha2-nistp384')):
            entry = ak.parse_line(line)
            bits, fingerprint = self.keygen_l(name)
            self.assertEqual((entry['type'], entry['bits'], entry['fingerprint']), (kind, bits, fingerprint), name)
        self.assertEqual(ak.parse_line(self.rsa_public)['comment'], 'ops key')

    def test_options_and_file_parsing(self):
        line = 'from="10.0.0.0/8,192.0.2.1",command="echo \\"hi there\\"",no-pty ' + self.ed_public
        entry = ak.parse_line(line)
        self.assertEqual(entry['options'], ['from="10.0.0.0/8,192.0.2.1"', 'command="echo \\"hi there\\""', 'no-pty'])
        self.assertEqual(entry['fingerprint'], self.keygen_l('ed')[1])
        text = '# comment\n\n%s\nnot a key at all\n%s\n' % (self.rsa_public, line)
        entries, problems = ak.parse_file(text)
        self.assertEqual([e['line'] for e in entries], [3, 5])
        self.assertEqual([p['line'] for p in problems], [4])
        public = ak.public(entries[0])
        self.assertNotIn('data', public, 'the key text is never sent to the browser')
        self.assertNotIn(self.rsa_public.split()[1], json.dumps([ak.public(e) for e in entries]))
        removed = ak.without(text, {entries[0]['fingerprint']})
        self.assertEqual(removed, '# comment\n\nnot a key at all\n%s\n' % line, 'other lines kept byte for byte')
        self.assertEqual(ak.with_key(removed, ak.parse_line(line)), removed, 'no duplicate keys')

    def test_validation_rejects(self):
        with self.assertRaises(SSHSecError):
            ak.validate_new('ssh-ed25519 AAAAnotbase64!!')
        tampered = self.ed_public.split()
        tampered[0] = 'ssh-rsa'
        for bad in (' '.join(tampered), self.ed_public + '\n' + self.rsa_public, '', 'hello world',
                    'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00').decode()):
            with self.assertRaises(SSHSecError, msg=bad):
                ak.validate_new(bad)
        self.assertEqual(ak.validate_new('  ' + self.ed_public + '\n')['type'], 'ssh-ed25519')

    def test_private_keys_rejected(self):
        for private in (self.ed_private, self.rsa_private, self.ec_private, 'PuTTY-User-Key-File-3: ssh-ed25519\n',
                        '-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----'):
            with self.assertRaises(SSHSecError) as caught:
                ak.validate_new(private)
            self.assertIn('PRIVATE', str(caught.exception))

    def test_options_need_opt_in(self):
        line = 'no-pty,from="192.0.2.1" ' + self.ed_public
        with self.assertRaises(SSHSecError) as caught:
            ak.validate_new(line)
        self.assertIn('Allow key options', str(caught.exception))
        self.assertEqual(ak.validate_new(line, allow_options=True)['options'], ['no-pty', 'from="192.0.2.1"'])
        self.assertEqual(ak.key_line(ak.validate_new(line, True)), line)

    def test_weak_keys(self):
        _, weak = keygen(self.dir, 'weak', 'rsa', 1024)
        with self.assertRaises(SSHSecError):
            ak.validate_new(weak)

    def test_fingerprint_wire_format(self):
        fp = ak.parse_line(self.ed_public)['fingerprint']
        self.assertEqual(ak.decode_fingerprint(fp[7:]), fp)
        for bad in ('x', '../etc', fp[7:] + ';', None):
            with self.assertRaises(SSHSecError):
                ak.decode_fingerprint(bad)


class KeyFiles(SimpleTestCase):
    def setUp(self):
        self.keydir = tempfile.mkdtemp(prefix='ic-kf-')
        _, self.key1 = keygen(self.keydir, 'k1', comment='one')
        _, self.key2 = keygen(self.keydir, 'k2', comment='two')
        with open(os.path.join(self.keydir, 'k1')) as handle:
            self.private1 = handle.read()

    def tearDown(self):
        shutil.rmtree(self.keydir)

    def test_add_creates_private_files_and_backups(self):
        with Host() as host:
            result = manage.keys_add('root', self.key1, runner=host.run)
            self.assertEqual(result['added']['comment'], 'one')
            ssh = os.path.join(host.home, '.ssh')
            self.assertEqual(stat.S_IMODE(os.stat(ssh).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(ssh, 'authorized_keys')).st_mode), 0o600)
            self.assertEqual(host.authorized(), self.key1 + '\n')
            self.assertTrue(host.ran(['ssh-keygen', '-l']), 'ssh-keygen validated the key')
            self.assertTrue(any(os.path.basename(c[0]) == 'restorecon' for c in host.calls)
                            or not actions._which('restorecon'))
            with self.assertRaises(SSHSecError):
                manage.keys_add('root', self.key1, runner=host.run)
            with self.assertRaises(SSHSecError):
                manage.keys_add('root', self.private1, runner=host.run)
            for i in range(7):
                _, extra = keygen(self.keydir, 'x%d' % i)
                manage.keys_add('root', extra, runner=host.run)
            backups = os.listdir(os.path.join(host.root, 'state', 'backups', 'keys', 'root'))
            self.assertEqual(len(backups), manage.KEEP_BACKUPS)
            self.assertEqual(len(manage.keys_list('root', runner=host.run)['keys']), 8)
            self.assertEqual([f for f in os.listdir(ssh) if f != 'authorized_keys'], [], 'no temp files left')

    def test_symlinked_ssh_dir_refused(self):
        with Host() as host:
            os.symlink(host.keys, os.path.join(host.home, '.ssh'))
            with self.assertRaises(SSHSecError):
                manage.keys_add('root', self.key1, runner=host.run)
            self.assertEqual(os.listdir(host.keys), [])

    def test_last_key_guard(self):
        with Host(EL8_CONFIG.replace('PasswordAuthentication yes\n', 'PasswordAuthentication no\n', 1)) as host:
            host.install_keys(self.key1)
            fp1 = ak.parse_line(self.key1)['fingerprint']
            with self.assertRaises(SSHSecError) as caught:
                manage.keys_remove('root', [fp1[7:]], runner=host.run)
            self.assertIn('last key', str(caught.exception))
            self.assertEqual(host.authorized(), self.key1 + '\n')
            self.assertEqual(manage.keys_list('root', runner=host.run)['key_only'], 'password login is off')
            # rotate: the new key goes in before the old one goes out
            result = manage.keys_rotate('root', self.key2, [fp1[7:]], runner=host.run)
            self.assertEqual(result['removed'], [fp1])
            self.assertEqual(host.authorized(), self.key2 + '\n')
        with Host() as host:   # password login on: the last key may go
            host.install_keys(self.key1)
            manage.keys_remove('root', [ak.parse_line(self.key1)['fingerprint']], runner=host.run)
            self.assertEqual(host.authorized(), '')

    def test_root_keys_only_counts_as_key_only(self):
        with Host(EL8_CONFIG.replace('PermitRootLogin yes\n', 'PermitRootLogin prohibit-password\n', 1)) as host:
            host.install_keys(self.key1)
            with self.assertRaises(SSHSecError):
                manage.keys_remove('root', [ak.parse_line(self.key1)['fingerprint']], runner=host.run)

    def test_generate_once(self):
        with Host() as host:
            host.install_keys(self.key1)
            fp1 = ak.parse_line(self.key1)['fingerprint']
            result = manage.keys_generate('root', 'admin@laptop', 'correct horse battery', [fp1[7:]], runner=host.run)
            self.assertTrue(result['encrypted'])
            self.assertIn('BEGIN OPENSSH PRIVATE KEY', result['private_key'])
            self.assertEqual(result['removed'], [fp1])
            self.assertEqual(host.authorized(), result['public_key'] + '\n')
            self.assertTrue(result['public_key'].startswith('ssh-ed25519 ') and
                            result['public_key'].endswith(' admin@laptop'))
            # nothing of the private key stays on the "server"
            leftovers = []
            for directory, _, files in os.walk(host.root):
                for name in files:
                    with open(os.path.join(directory, name), 'rb') as handle:
                        if b'PRIVATE KEY' in handle.read():
                            leftovers.append(name)
            self.assertEqual(leftovers, [])
            self.assertEqual(os.listdir(os.path.join(host.root, 'state', 'tmp')), [])
            # the download is encrypted with the passphrase
            check = os.path.join(self.keydir, 'downloaded')
            with open(check, 'w') as handle:
                handle.write(result['private_key'])
            os.chmod(check, 0o600)
            wrong = subprocess.run(['ssh-keygen', '-y', '-P', 'wrong passphrase', '-f', check],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(wrong.returncode, 0)
            right = subprocess.run(['ssh-keygen', '-y', '-P', 'correct horse battery', '-f', check],
                                   stdout=subprocess.PIPE, universal_newlines=True, check=True)
            self.assertEqual(right.stdout.split()[:2], result['public_key'].split()[:2])
            with self.assertRaises(SSHSecError):
                manage.keys_generate('root', '', 'short', runner=host.run)
            with self.assertRaises(SSHSecError):
                manage.keys_generate('root', 'bad comment;', '', runner=host.run)

    def test_generate_cleans_up_when_install_fails(self):
        with Host() as host:
            with mock.patch.object(manage, 'keys_add', side_effect=SSHSecError('disk full')):
                with self.assertRaises(SSHSecError):
                    manage.keys_generate('root', '', '', runner=host.run)
            self.assertEqual(os.listdir(os.path.join(host.root, 'state', 'tmp')), [])


# ----------------------------------------------------------------------------- login settings

class LockoutGuard(SimpleTestCase):
    def test_pure_guard(self):
        off = sc.validate_settings(SETTINGS_OFF)
        self.assertTrue(any('no public key' in r for r in manage.lockout_refusals(off, 'root', 0, True)))
        self.assertTrue(any('tested' in r for r in manage.lockout_refusals(off, 'root', 1, False)))
        self.assertEqual(manage.lockout_refusals(off, 'root', 1, True), [])
        root_keys = sc.validate_settings({'password': 'yes', 'root': 'prohibit-password'})
        self.assertTrue(any('lock root out' in r for r in manage.lockout_refusals(root_keys, 'root', 0, True)))
        never = sc.validate_settings({'password': 'yes', 'root': 'no'})
        self.assertTrue(any('Never' in r for r in manage.lockout_refusals(never, 'root', 3, True)))
        self.assertEqual(manage.lockout_refusals(never, 'alice', 0, True, password_set=True), [])
        self.assertTrue(manage.lockout_refusals(never, 'alice', 0, True, password_set=False))
        loosen = sc.validate_settings({'password': 'yes', 'root': 'yes'})
        self.assertEqual(manage.lockout_refusals(loosen, 'root', 0, False), [], 'loosening needs no tick')

    def test_apply_refused_without_keys_changes_nothing(self):
        with Host() as host:
            with self.assertRaises(SSHSecError) as caught:
                host.apply()
            self.assertIn('no public key', str(caught.exception))
            self.assertEqual(host.text(), EL8_CONFIG)
            self.assertFalse(host.ran(['systemctl', 'reload']))
            self.assertFalse(host.ran(['systemd-run']))

    def test_sshd_view_of_the_user_is_checked(self):
        keydir = tempfile.mkdtemp(prefix='ic-lg-')
        try:
            _, key = keygen(keydir, 'k')
            with Host(EL8_CONFIG.replace('AuthorizedKeysFile\t.ssh/authorized_keys',
                                         'AuthorizedKeysFile /etc/ssh/keys/%u')) as host:
                host.install_keys(key)
                with self.assertRaises(SSHSecError) as caught:
                    host.apply()
                self.assertIn('AuthorizedKeysFile', str(caught.exception))
                self.assertIn('AuthorizedKeysFile /etc/ssh/keys/%u', host.text())
                self.assertNotIn(sc.BEGIN, host.text())
        finally:
            shutil.rmtree(keydir)


class ApplyRollbackConfirm(SimpleTestCase):
    def setUp(self):
        self.keydir = tempfile.mkdtemp(prefix='ic-ap-')
        _, self.key = keygen(self.keydir, 'k')

    def tearDown(self):
        shutil.rmtree(self.keydir)

    def test_apply_then_confirm(self):
        with Host() as host:
            host.install_keys(self.key)
            result = host.apply()
            self.assertTrue(result['changed'])
            text = host.text()
            self.assertIn('PasswordAuthentication no', text)
            self.assertLess(text.index(sc.BEGIN), text.index('Match User backup'))
            self.assertEqual(stat.S_IMODE(os.stat(host.config).st_mode), 0o600, 'mode kept')
            self.assertEqual([f for f in os.listdir(host.etc) if f != 'sshd_config'], [], 'no candidate left')
            timer = host.ran(['systemd-run'])
            self.assertEqual(len(timer), 1)
            self.assertIn('--on-active=300', timer[0])
            self.assertEqual(timer[0][-3:-1], ['sshsec', 'login_revert'])
            self.assertTrue(host.ran(['systemctl', 'reload', 'sshd']))
            self.assertFalse(host.ran(['systemctl', 'restart']), 'reload, never restart')
            pending = result['pending']
            self.assertIn(pending['seconds_left'], (299, 300))
            with self.assertRaises(SSHSecError, msg='a second change waits for the first'):
                host.apply()
            confirmed = manage.login_confirm(pending['token'], runner=host.run)
            self.assertTrue(confirmed['confirmed'])
            self.assertTrue(host.ran(['systemctl', 'stop']))
            self.assertIsNone(manage.load_pending())
            self.assertEqual(manage.login_revert(pending['token'], 'timer', runner=host.run)['reverted'], False,
                             'a late timer does nothing after Confirm')
            self.assertEqual(host.text(), text)
            self.assertFalse(host.apply()['changed'], 'applying the same settings again is a no-op')

    def test_timer_reverts_unconfirmed_change(self):
        with Host() as host:
            host.install_keys(self.key)
            pending = host.apply()['pending']
            reloads = len(host.ran(['systemctl', 'reload']))
            result = manage.login_revert(pending['token'], 'timer', runner=host.run, sleep=lambda s: None)
            self.assertTrue(result['reverted'])
            self.assertEqual(host.text(), EL8_CONFIG)
            self.assertEqual(len(host.ran(['systemctl', 'reload'])), reloads + 1)
            self.assertIsNone(manage.load_pending())
            self.assertEqual(manage._load_json('login-last.json')['result'], 'reverted')

    def test_revert_leaves_later_edits_alone(self):
        with Host() as host:
            host.install_keys(self.key)
            pending = host.apply()['pending']
            with open(host.config, 'a') as handle:
                handle.write('# edited by hand\n')
            with self.assertRaises(SSHSecError):
                manage.login_revert(pending['token'], 'button', runner=host.run, sleep=lambda s: None)
            self.assertIn('# edited by hand', host.text())

    def test_sshd_t_failure_on_candidate_leaves_file_untouched(self):
        with Host() as host:
            host.install_keys(self.key)
            host.fail_test = 'all'
            with self.assertRaises(SSHSecError) as caught:
                host.apply()
            self.assertIn('sshd rejected', str(caught.exception))
            self.assertEqual(host.text(), EL8_CONFIG)
            self.assertFalse(host.ran(['systemctl', 'reload']))

    def test_sshd_t_failure_after_write_rolls_back(self):
        with Host() as host:
            host.install_keys(self.key)
            host.fail_test = 'live'
            with self.assertRaises(SSHSecError) as caught:
                host.apply()
            self.assertIn('previous configuration is back', str(caught.exception))
            self.assertEqual(host.text(), EL8_CONFIG)
            self.assertIsNone(manage.load_pending())
            self.assertFalse(host.ran(['systemctl', 'reload']))
            self.assertFalse(host.ran(['systemd-run']))

    def test_reload_failure_rolls_back(self):
        with Host() as host:
            host.install_keys(self.key)
            host.reload_code = 1
            with self.assertRaises(SSHSecError):
                host.apply()
            self.assertEqual(host.text(), EL8_CONFIG)
            self.assertIsNone(manage.load_pending())
            self.assertTrue(host.ran(['systemctl', 'stop']), 'the safety timer is cancelled')

    def test_no_safety_timer_no_change(self):
        with Host() as host:
            host.install_keys(self.key)
            host.timer_code = 1
            with self.assertRaises(SSHSecError) as caught:
                host.apply()
            self.assertIn('safety timer', str(caught.exception))
            self.assertEqual(host.text(), EL8_CONFIG)
            self.assertFalse(host.ran(['systemctl', 'reload']))

    def test_port_change_without_selinux(self):
        with Host() as host:
            host.install_keys(self.key)
            result = host.apply(dict(SETTINGS_OFF, port=2222))
            self.assertIn('Port 2222', host.text())
            self.assertFalse(any(os.path.basename(c[0]) == 'semanage' for c in host.calls), 'SELinux is disabled')
            self.assertTrue(host.ran(['ss']), 'the new port is checked after the reload')
            self.assertTrue(result['notes'])
            # leaving the port empty later keeps the managed value
            manage.login_confirm(result['pending']['token'], runner=host.run)
            host.apply(dict(SETTINGS_OFF, port=None, maxauthtries=4))
            self.assertIn('Port 2222', host.text())

    def test_dropin_mode(self):
        with Host('Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\n') as host:
            os.makedirs(os.path.join(host.etc, 'sshd_config.d'))
            host.install_keys(self.key)

            real_run = host.run

            def run(argv, **kwargs):   # model the Include: drop-in first, then sshd_config
                if os.path.basename(argv[0]) == 'sshd' and '-T' in argv and '-f' not in argv:
                    dropin = os.path.join(host.etc, 'sshd_config.d', sc.DROPIN_NAME)
                    text = (open(dropin).read() if os.path.exists(dropin) else '') + host.text()
                    host.calls.append(list(argv))
                    return SimpleNamespace(returncode=0, stdout=simulated_sshd_t(text))
                return real_run(argv, **kwargs)
            result = manage.login_apply(dict(SETTINGS_OFF), 'root', True, [], 'admin', runner=run,
                                        sleep=lambda s: None)
            dropin = os.path.join(host.etc, 'sshd_config.d', sc.DROPIN_NAME)
            self.assertIn('PasswordAuthentication no', open(dropin).read())
            self.assertIn(sc.SUPERSEDED + 'PermitRootLogin yes', host.text())
            manage.login_revert(result['pending']['token'], 'button', runner=run, sleep=lambda s: None)
            self.assertFalse(os.path.exists(dropin))
            self.assertEqual(host.text(), 'Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n'
                                          'PasswordAuthentication yes\n')


# ----------------------------------------------------------------------------- views

class Views(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.dir = tempfile.mkdtemp(prefix='ic-v-')
        cls.private, cls.public = keygen(cls.dir, 'k')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)
        super().tearDownClass()

    def post(self, view, body, admin=1):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json',
                                        REMOTE_ADDR='198.51.100.20')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('universalAddons.privileged.call', return_value={'ok': 1}) as call, \
                mock.patch('universalAddons.privileged.call_private',
                           return_value={'private_key': 'x'}) as private, \
                mock.patch.object(views, '_actor', return_value='admin'):
            response = view(request)
        return response, json.loads(response.content), call, private

    def b64(self, text):
        return base64.b64encode(text.encode()).decode()

    def test_admin_only(self):
        for name in ('login_state', 'login_apply', 'login_confirm', 'login_revert', 'keys_list', 'keys_add',
                     'keys_remove', 'keys_rotate', 'keys_generate'):
            response, _, call, private = self.post(getattr(views, name), {
                'settings': SETTINGS_OFF, 'token': 'a' * 32, 'key_b64': self.b64(self.public), 'fps': ['x'],
                'understood': True}, admin=0)
            self.assertEqual(response.status_code, 403, name)
            call.assert_not_called()
            private.assert_not_called()

    def test_private_key_never_forwarded(self):
        response, body, call, _ = self.post(views.keys_add, {'key_b64': self.b64(self.private)})
        self.assertEqual(response.status_code, 400)
        self.assertIn('PRIVATE', body['error_message'])
        call.assert_not_called()

    def test_forwarding(self):
        _, _, call, _ = self.post(views.keys_add, {'user': 'root', 'key_b64': self.b64(self.public)})
        call.assert_called_once_with('sshsec', 'keys_add', user='root', key=self.public, allow_options=False)
        fp = ak.parse_line(self.public)['fingerprint']
        _, _, call, _ = self.post(views.keys_remove, {'fps': [fp[7:]]})
        call.assert_called_once_with('sshsec', 'keys_remove', user='root', fingerprints=[fp[7:]])
        for bad in ({'fps': []}, {'fps': ['../x']}, {'fps': 'x'}, {'user': 'Root;', 'fps': [fp[7:]]}):
            self.assertEqual(self.post(views.keys_remove, bad)[0].status_code, 400, bad)
        _, _, call, _ = self.post(views.login_apply, {'settings': SETTINGS_OFF, 'login_user': 'root', 'tested': True})
        call.assert_called_once_with('sshsec', 'login_apply', settings=sc.validate_settings(SETTINGS_OFF),
                                     login_user='root', tested=True, client=['198.51.100.20'], by='admin')
        self.assertEqual(self.post(views.login_apply, {'settings': {'password': 'no'}})[0].status_code, 400)
        self.assertEqual(self.post(views.login_confirm, {'token': 'zz'})[0].status_code, 400)
        _, _, call, _ = self.post(views.login_revert, {'token': 'b' * 32})
        call.assert_called_once_with('sshsec', 'login_revert', token='b' * 32, reason='button')

    def test_generate_uses_private_channel(self):
        response, _, call, _ = self.post(views.keys_generate, {})
        self.assertEqual(response.status_code, 400, 'the "shown once" tick is required')
        response, body, call, private = self.post(views.keys_generate, {
            'understood': True, 'comment': 'me@laptop', 'secret_b64': self.b64('pässphrase $;|')})
        call.assert_not_called()
        private.assert_called_once_with('sshsec', 'keys_generate', user='root', comment='me@laptop',
                                        passphrase='pässphrase $;|', remove=[])
        self.assertEqual(response['Cache-Control'], 'no-store')

    def test_runner_actions_registered(self):
        for name in ('login_state', 'login_apply', 'login_confirm', 'login_revert', 'keys_list', 'keys_add',
                     'keys_remove', 'keys_rotate', 'keys_generate'):
            self.assertIn(name, actions.ACTIONS)
            self.assertIn(name, manage.ACTIONS)


@override_settings(ROOT_URLCONF='universalAddons.tests.test_sshsec_access')
class PageRenders(SimpleTestCase):
    def test_page(self):
        request = RequestFactory().get('/addons/ssh-security/')
        request.session = {}
        html = render_to_string('universalAddons/sshsec.html', {'request': request, 'admin': 1})
        for marker in ('id="ss-login"', 'name="ss-pw"', 'value="prohibit-password"', 'id="ss-tested"',
                       'I have tested key login', 'id="ss-keys"', 'id="ss-gen"', 'id="ss-key-options"',
                       'shown only once', 'IndiansCloud'):
            self.assertIn(marker, html)
        self.assertNotIn('sshd_config is never edited', html)
        page = html[html.index('id="ua-sshsec"'):html.index('id="ss-blocklist"')]
        self.assertNotIn('CyberPanel', page, 'user-visible text says IndiansCloud')


class CyberPanelSSHPageReadsEffectiveValues(SimpleTestCase):
    """Security > Secure SSH reads sshd -T, so superseded and commented lines do not fool it into
    writing PermitRootLogin yes back when the admin saves there."""

    def test_get_ssh_configs(self):
        from firewall.firewallManager import FirewallManager
        config = sc.render_main(EL8_CONFIG, sc.validate_settings(dict(SETTINGS_OFF, port='2222')), SUPPORTED)

        def execute(command, *args, **kwargs):
            return simulated_sshd_t(config) if 'sshd -T' in command else config

        with mock.patch('firewall.firewallManager.ACLManager.loadedACL', return_value={'admin': 1}), \
                mock.patch('firewall.firewallManager.ProcessUtilities.outputExecutioner', side_effect=execute):
            response = FirewallManager().getSSHConfigs(1, {'type': '1'})
        self.assertEqual(json.loads(response.content), {'status': 1, 'permitRootLogin': 0, 'sshPort': '2222'})

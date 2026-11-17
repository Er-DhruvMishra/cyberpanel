"""Root-side SSH login settings and authorized_keys management (dispatched through actions.ACTIONS).

Login settings (PasswordAuthentication, PermitRootLogin, Port, MaxAuthTries, LoginGraceTime):
  1. lockout guard: refuse to turn off passwords / restrict root unless the account the admin
     logs in with has a valid key, the admin ticked "I have tested key login", and sshd's own
     view of that account (sshd -T -C user=...) still allows a key login;
  2. the new file is checked with `sshd -t` and `sshd -T` before it replaces the live one (block
     mode) and again afterwards; any failure restores the previous bytes;
  3. a transient systemd timer (systemd-run --on-active=300) runs `login_revert` unless the admin
     clicks Confirm within 5 minutes, like a router's commit-confirm;
  4. sshd is reloaded (SIGHUP: running sessions stay up), not restarted.

Keys: root's (or another login user's) ~/.ssh/authorized_keys, backed up (last 5 kept) before
every change and replaced atomically with mode 600 in a mode 700 .ssh owned by the user. Every
file operation inside a non-root home goes through directory file descriptors with O_NOFOLLOW,
so a user cannot redirect the root-side write with a symlink.
"""
import base64
import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import time

from universalAddons.sshsec import actions as ac
from universalAddons.sshsec import authkeys as ak
from universalAddons.sshsec import sshconf as sc
from universalAddons.sshsec import service as sv
from universalAddons.sshsec.service import SSHSecError

SSHD_CONFIG = '/etc/ssh/sshd_config'
DROPIN_DIR = '/etc/ssh/sshd_config.d'
STATE_DIR = '/etc/cyberpanel/sshsec'
REVERT_SECONDS = 300
KEEP_BACKUPS = 5
SSH_KEYGEN = '/usr/bin/ssh-keygen'
NO_LOGIN_SHELLS = ('nologin', 'false', 'sync', 'shutdown', 'halt')
_USER_RE = re.compile(r'^[a-z_][a-z0-9_.-]{0,31}$')
_TOKEN_RE = re.compile(r'^[0-9a-f]{32}$')


def _state(name):
    return os.path.join(STATE_DIR, name)


def _private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


class _Lock:
    def __enter__(self):
        _private_dir(STATE_DIR)
        self.handle = open(_state('.login.lock'), 'w')
        fcntl.flock(self.handle, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        self.handle.close()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _restorecon(path, runner):
    """Give a replaced file back its default SELinux label (no-op where SELinux is off or absent)."""
    tool = ac._which('restorecon')
    if tool:
        ac._run([tool, path], 20, runner)


def _selinux_enabled(runner):
    tool = ac._which('getenforce')
    if not tool:
        return False
    code, out = ac._run([tool], 10, runner)
    return code == 0 and out.strip() in ('Enforcing', 'Permissive')


# ----------------------------------------------------------------------------- files

def _read_bytes(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise SSHSecError('%s is not a regular file.' % path)
        return handle.read()


def _atomic_write(path, data, runner, mode=0o600):
    """Replace `path` atomically, keeping owner and mode of the existing file."""
    directory = os.path.dirname(path)
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise SSHSecError('%s is not a regular file.' % path)
        mode, uid, gid = stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid
    except FileNotFoundError:
        uid = gid = None
    temporary = os.path.join(directory, '.indianscloud-%s.tmp' % os.urandom(6).hex())
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            if uid is not None and os.geteuid() == 0:
                os.fchown(handle.fileno(), uid, gid)
            os.fchmod(handle.fileno(), mode)
        os.replace(temporary, path)
    except BaseException:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise
    _fsync_dir(directory)
    _restorecon(path, runner)


def _fsync_dir(directory, dir_fd=None):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY, dir_fd=dir_fd) if dir_fd is None else os.dup(dir_fd)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _backup(kind, name, data):
    """Keep a private copy of `data`; the newest KEEP_BACKUPS per (kind, name) survive."""
    directory = _private_dir(os.path.join(_private_dir(os.path.join(_private_dir(_state('backups')), kind)), name))
    stamp = time.strftime('%Y%m%d-%H%M%S')
    path = os.path.join(directory, '%s.%s.%s' % (name, stamp, os.urandom(3).hex()))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    copies = sorted((os.path.getmtime(os.path.join(directory, f)), f) for f in os.listdir(directory))
    for _, old in copies[:-KEEP_BACKUPS]:
        if os.path.join(directory, old) != path:
            os.unlink(os.path.join(directory, old))
    return path


# ----------------------------------------------------------------------------- users

def pwd_lookup(name):
    return pwd.getpwnam(name)


def login_shell(entry):
    return bool(entry.pw_shell) and os.path.basename(entry.pw_shell) not in NO_LOGIN_SHELLS


def user_entry(name):
    """The passwd entry of an SSH login user: root, or an account with a login shell."""
    name = str(name or 'root')
    if not _USER_RE.match(name):
        raise SSHSecError('Invalid user name.')
    try:
        entry = pwd_lookup(name)
    except KeyError:
        raise SSHSecError('There is no system user %s.' % name)
    if name != 'root' and (not login_shell(entry) or (entry.pw_uid != 0 and entry.pw_uid < 1000)):
        raise SSHSecError('%s is a system account without a login shell.' % name)
    if not entry.pw_dir or not os.path.isabs(entry.pw_dir) or entry.pw_dir == '/':
        raise SSHSecError('%s has no usable home directory.' % name)
    return entry


def login_users():
    """Accounts that can log in over SSH: root first, then uid >= 1000 with a real shell."""
    out = ['root']
    for entry in sorted(pwd.getpwall(), key=lambda e: e.pw_uid):
        if entry.pw_name != 'root' and entry.pw_uid >= 1000 and entry.pw_uid != 65534 and login_shell(entry) \
                and _USER_RE.match(entry.pw_name):
            out.append(entry.pw_name)
    return out[:200]


def has_password(name):
    """True/False when /etc/shadow says whether the account has a usable password, None if unknown."""
    try:
        with open('/etc/shadow') as handle:
            for line in handle:
                fields = line.split(':')
                if fields[0] == name and len(fields) > 1:
                    return not (fields[1] == '' or fields[1][0] in '!*')
    except OSError:
        return None
    return None


# ----------------------------------------------------------------------------- authorized_keys I/O

class KeyDir:
    """~user/.ssh, opened through directory descriptors (no symlinks followed inside home)."""

    def __init__(self, entry, create=False):
        self.entry = entry
        self.path = os.path.join(entry.pw_dir, '.ssh')
        home = os.open(entry.pw_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            try:
                self.fd = os.open('.ssh', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
            except FileNotFoundError:
                if not create:
                    self.fd = None
                    return
                os.mkdir('.ssh', 0o700, dir_fd=home)
                self.fd = os.open('.ssh', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
                self._own(self.fd)
            except OSError as exc:
                raise SSHSecError('%s is not a directory (%s).' % (self.path, exc.strerror))
        finally:
            os.close(home)
        info = os.fstat(self.fd)
        if info.st_uid != entry.pw_uid:
            self.close()
            raise SSHSecError('%s is not owned by %s; fix it by hand.' % (self.path, entry.pw_name))
        if create and stat.S_IMODE(info.st_mode) != 0o700:
            os.fchmod(self.fd, 0o700)

    def _own(self, fd):
        if os.geteuid() == 0:
            os.fchown(fd, self.entry.pw_uid, self.entry.pw_gid)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def read(self):
        if self.fd is None:
            return None
        try:
            fd = os.open('authorized_keys', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SSHSecError('Cannot read %s/authorized_keys (%s).' % (self.path, exc.strerror))
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SSHSecError('%s/authorized_keys is not a plain file.' % self.path)
            data = handle.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise SSHSecError('authorized_keys is larger than 4 MB.')
        return data.decode('utf-8', 'surrogateescape')

    def write(self, text, runner):
        name = '.authorized_keys.indianscloud-%s' % os.urandom(6).hex()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(text.encode('utf-8', 'surrogateescape'))
                handle.flush()
                os.fsync(handle.fileno())
                self._own(handle.fileno())
                os.fchmod(handle.fileno(), 0o600)
            os.replace(name, 'authorized_keys', src_dir_fd=self.fd, dst_dir_fd=self.fd)
        except BaseException:
            try:
                os.unlink(name, dir_fd=self.fd)
            except OSError:
                pass
            raise
        _fsync_dir(None, self.fd)
        _restorecon(self.path, runner)
        _restorecon(os.path.join(self.path, 'authorized_keys'), runner)


def _summary(text):
    entries, problems = ak.parse_file(text or '')
    return [ak.public(e) for e in entries], problems


def read_keys(name):
    entry = user_entry(name)
    with KeyDir(entry) as directory:
        text = directory.read()
    keys, problems = _summary(text)
    return entry, text, keys, problems


def _write_keys(entry, old_text, new_text, runner):
    with KeyDir(entry, create=True) as directory:
        current = directory.read()
        if current != old_text:
            raise SSHSecError('authorized_keys changed while you were editing it; reload and try again.')
        backup = _backup('keys', entry.pw_name, (current or '').encode('utf-8', 'surrogateescape')) \
            if current is not None else None
        directory.write(new_text, runner)
    return backup


def keygen_fingerprint(line, runner=subprocess.run):
    """Fingerprint `ssh-keygen -l -f` reports for one public key line (validation by OpenSSH itself)."""
    work = _private_dir(_state('tmp'))
    path = os.path.join(work, 'check-%s.pub' % os.urandom(6).hex())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(line + '\n')
    try:
        code, out = ac._run([ac._which('ssh-keygen') or SSH_KEYGEN, '-l', '-E', 'sha256', '-f', path], 20, runner)
    finally:
        os.unlink(path)
    match = re.search(r'^(\d+) (SHA256:[A-Za-z0-9+/]{43}) ', out or '', re.M)
    if code != 0 or not match:
        raise SSHSecError('ssh-keygen does not accept this key: %s' % (out or '').strip()[-200:])
    return match.group(2), int(match.group(1))


def _checked(text, allow_options, runner):
    entry = ak.validate_new(text, allow_options)
    fingerprint, bits = keygen_fingerprint(ak.key_line(entry), runner)
    if fingerprint != entry['fingerprint']:
        raise SSHSecError('ssh-keygen reports a different fingerprint for this key; refused.')
    return entry


# ----------------------------------------------------------------------------- sshd state

def _sshd():
    return ac._which('sshd') or '/usr/sbin/sshd'


def sshd_t(runner, config=None, user=None, addr=None, test_only=False):
    argv = [_sshd(), '-t' if test_only else '-T']
    if config:
        argv += ['-f', config]
    if user and not test_only:
        argv += ['-C', 'user=%s,host=localhost,addr=%s' % (user, addr or '127.0.0.1')]
    code, out = ac._run(argv, 30, runner)
    if code != 0:
        raise SSHSecError('sshd rejected the configuration: %s' % out.strip()[-400:])
    return out if test_only else sv.parse_sshd_t(out)


def service_name(runner):
    for name in ('sshd', 'ssh'):
        if ac._active(name, runner):
            return name
    return 'sshd'


def socket_activated(runner):
    return any(ac._active(unit, runner) for unit in ('ssh.socket', 'sshd.socket'))


def key_only_reason(name, effective):
    """Why `name` can only log in with a key under `effective` (sshd -T -C for that user), or None."""
    if effective.get('passwordauthentication') == 'no' and effective.get('kbdinteractiveauthentication', 'no') == 'no':
        return 'password login is off'
    if name == 'root' and sc.normalise_root(effective.get('permitrootlogin')) in ('prohibit-password',
                                                                               'forced-commands-only'):
        return 'root may log in with a key only'
    return None


def access_problems(name, effective, needs_key):
    """Reasons sshd itself would refuse `name` (from sshd -T -C user=name ...)."""
    import fnmatch
    problems = []
    if needs_key:
        if effective.get('pubkeyauthentication', 'yes') != 'yes':
            problems.append('PubkeyAuthentication is off for %s' % name)
        files = effective.get('authorizedkeysfile', '.ssh/authorized_keys').split()
        if not any(f in ('.ssh/authorized_keys', '%h/.ssh/authorized_keys') for f in files):
            problems.append('AuthorizedKeysFile is "%s", which does not read ~/.ssh/authorized_keys'
                            % ' '.join(files))
        methods = effective.get('authenticationmethods', 'any')
        if methods != 'any' and 'publickey' not in methods.split():
            problems.append('AuthenticationMethods "%s" needs more than a key' % methods)
    allow = effective.get('allowusers', '').split()
    if allow and not any(fnmatch.fnmatch(name, p.split('@')[0]) for p in allow):
        problems.append('%s is not in AllowUsers' % name)
    if any(fnmatch.fnmatch(name, p.split('@')[0]) for p in effective.get('denyusers', '').split()):
        problems.append('%s is in DenyUsers' % name)
    if name == 'root' and sc.normalise_root(effective.get('permitrootlogin')) == 'no':
        problems.append('PermitRootLogin is no')
    return problems


def lockout_refusals(settings, login_user, key_count, tested, password_set=None):
    """Pure lockout guard. key_count: valid keys in login_user's authorized_keys."""
    refusals = []
    restricts = settings['password'] == 'no' or settings['root'] != 'yes'
    if settings['root'] == 'no' and login_user == 'root':
        refusals.append('"Never" blocks every root login. Choose the user you will log in as instead (then use '
                        'su or sudo), or pick "Keys only".')
    if settings['password'] == 'no' and key_count == 0:
        refusals.append('%s has no public key in authorized_keys. Add a key and test a key login before you turn '
                        'password login off.' % login_user)
    elif login_user == 'root' and settings['root'] == 'prohibit-password' and key_count == 0:
        refusals.append('root has no public key in authorized_keys, so "Keys only" would lock root out. Add a '
                        'key and test it first.')
    if settings['password'] == 'yes' and key_count == 0 and password_set is False:
        refusals.append('%s has neither a key nor a password, so it cannot log in at all.' % login_user)
    if restricts and not tested:
        refusals.append('Tick "I have tested key login" after you have logged in as %s with a key in a second '
                        'terminal.' % login_user)
    return refusals


# ----------------------------------------------------------------------------- pending change

def load_pending():
    try:
        with open(_state('login-pending.json')) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) and _TOKEN_RE.match(str(data.get('token', ''))) else None
    except (OSError, ValueError):
        return None


def _save_json(name, data):
    _private_dir(STATE_DIR)
    path = _state(name)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, indent=1)
    os.replace(path + '.tmp', path)


def _drop(name):
    try:
        os.unlink(_state(name))
    except FileNotFoundError:
        pass


def _load_json(name):
    try:
        with open(_state(name)) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _public_pending(pending, now=None):
    if not pending:
        return None
    now = now or time.time()
    return {'token': pending['token'], 'deadline': pending['deadline'],
            'seconds_left': max(0, int(pending['deadline'] - now)), 'expired': now > pending['deadline'] + 30,
            'settings': pending.get('settings'), 'login_user': pending.get('login_user'), 'by': pending.get('by'),
            'port_opened': pending.get('firewall_added')}


def _arm_timer(token, runner):
    from universalAddons.privileged import PYTHON, RUNNER, encode_args
    unit = 'indianscloud-ssh-revert-%s' % token[:12]
    code, out = ac._run([ac._which('systemd-run') or '/usr/bin/systemd-run', '--unit=' + unit,
                         '--on-active=%d' % REVERT_SECONDS, '--timer-property=AccuracySec=1s',
                         '--description=IndiansCloud: undo the SSH login change unless confirmed',
                         PYTHON, RUNNER, 'sshsec', 'login_revert', encode_args({'token': token, 'reason': 'timer'})],
                        30, runner)
    if code != 0:
        raise SSHSecError('Could not start the 5-minute safety timer (systemd-run: %s).' % out.strip()[-200:])
    return unit


def _restore(files, runner):
    """Put back the previous bytes of every file (delete the ones that did not exist)."""
    for item in reversed(files):
        if item.get('backup'):
            with open(item['backup'], 'rb') as handle:
                _atomic_write(item['path'], handle.read(), runner)
        elif os.path.lexists(item['path']):
            os.unlink(item['path'])


def _reload(service, runner, port=None, sleep=time.sleep):
    code, out = ac._run(['systemctl', 'reload', service], 60, runner)
    if code != 0:
        return 'systemctl reload %s failed: %s' % (service, out.strip()[-200:])
    for _ in range(8):
        sleep(1)
        if not ac._active(service, runner):
            continue
        if port is None:
            return None
        code, out = ac._run(['ss', '-H', '-ltn', 'sport = :%d' % port], 10, runner)
        if code == 0 and out.strip():
            return None
    return 'sshd is not running' if port is None else 'sshd is not listening on port %d' % port


def _firewall_open(port, runner):
    """Open port/tcp in firewalld's default zone (permanent and runtime). Returns what was added."""
    state = ac.firewall_state(runner)
    if not state['running']:
        return None
    zone = state['zone']
    code, _ = ac._run(['firewall-cmd', '--zone=' + zone, '--query-port=%d/tcp' % port], 20, runner)
    if code == 0:
        return None
    for argv in (['firewall-cmd', '--permanent', '--zone=' + zone, '--add-port=%d/tcp' % port],
                 ['firewall-cmd', '--zone=' + zone, '--add-port=%d/tcp' % port]):
        code, out = ac._run(argv, 30, runner)
        if code != 0:
            raise SSHSecError('firewall-cmd could not open port %d: %s' % (port, out.strip()[-200:]))
    return {'zone': zone, 'port': port}


def _firewall_close(added, runner):
    if not added:
        return
    for argv in (['firewall-cmd', '--permanent', '--zone=' + added['zone'], '--remove-port=%d/tcp' % added['port']],
                 ['firewall-cmd', '--zone=' + added['zone'], '--remove-port=%d/tcp' % added['port']]):
        ac._run(argv, 30, runner)


def _selinux_port(port, runner):
    if port == 22 or not _selinux_enabled(runner):
        return
    tool = ac._which('semanage')
    if not tool:
        raise SSHSecError('SELinux is on but semanage is missing (dnf install policycoreutils-python-utils), so '
                          'sshd could not bind port %d.' % port)
    code, out = ac._run([tool, 'port', '-a', '-t', 'ssh_port_t', '-p', 'tcp', str(port)], 120, runner)
    if code != 0 and 'already defined' not in out:
        code, out = ac._run([tool, 'port', '-m', '-t', 'ssh_port_t', '-p', 'tcp', str(port)], 120, runner)
        if code != 0:
            raise SSHSecError('semanage could not label port %d for sshd: %s' % (port, out.strip()[-200:]))


# ----------------------------------------------------------------------------- login settings

def _targets():
    """('block'|'dropin', main text, file the block lives in)."""
    main = _read_bytes(SSHD_CONFIG)
    if main is None:
        raise SSHSecError('%s does not exist.' % SSHD_CONFIG)
    text = main.decode('utf-8', 'surrogateescape')
    if sc.includes_dropins(text) and os.path.isdir(DROPIN_DIR):
        return 'dropin', text, os.path.join(DROPIN_DIR, sc.DROPIN_NAME)
    return 'block', text, SSHD_CONFIG


def login_state(client=(), runner=subprocess.run):
    mode, main_text, block_path = _targets()
    block_text = main_text if mode == 'block' else (_read_bytes(block_path) or b'').decode('utf-8', 'replace')
    effective = sshd_t(runner)
    root = {}
    try:
        _, _, keys, problems = read_keys('root')
        root = {'keys': keys, 'problems': problems}
    except SSHSecError as exc:
        root = {'keys': [], 'problems': [], 'error': str(exc)}
    last = _load_json('login-last.json')
    return {
        'mode': mode, 'file': block_path,
        'effective': {k: effective.get(k, '') for k in ('passwordauthentication', 'kbdinteractiveauthentication',
                                                        'challengeresponseauthentication', 'permitrootlogin', 'port',
                                                        'maxauthtries', 'logingracetime', 'pubkeyauthentication',
                                                        'authenticationmethods', 'allowusers', 'listenaddress')},
        'block': sc.read_block(block_text),
        'match_blocks': sc.match_blocks(main_text),
        'pending': _public_pending(load_pending()),
        'last': last,
        'root': root,
        'users': login_users(),
        'selinux': _selinux_enabled(runner),
        'firewall': ac.firewall_state(runner),
        'socket_activated': socket_activated(runner),
        'csf': os.path.exists('/etc/csf'),
        'revert_seconds': REVERT_SECONDS,
    }


def _candidate_check(text, settings, login_user, client, needs_key, runner):
    """Validate a candidate sshd_config next to the live one before it replaces it."""
    path = os.path.join(os.path.dirname(SSHD_CONFIG), '.indianscloud-candidate-%s' % os.urandom(4).hex())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(text.encode('utf-8', 'surrogateescape'))
    try:
        _verify(settings, login_user, client, needs_key, runner, config=path)
    finally:
        os.unlink(path)


def _verify(settings, login_user, client, needs_key, runner, config=None):
    sshd_t(runner, config=config, test_only=True)
    problems = sc.mismatches(sshd_t(runner, config=config), settings)
    addr = next((ip for ip in client if sv.parse_address(ip) is not None), None)
    problems += access_problems(login_user, sshd_t(runner, config=config, user=login_user, addr=addr), needs_key)
    if problems:
        raise SSHSecError('The new settings would not work as intended: %s.' % '; '.join(problems))


def login_apply(settings, login_user='root', tested=False, client=(), by='', runner=subprocess.run,
                sleep=time.sleep):
    settings = sc.validate_settings(settings)
    entry = user_entry(login_user)
    with _Lock():
        if load_pending():
            raise SSHSecError('An earlier change is still waiting for confirmation. Confirm or undo it first.')
        with KeyDir(entry) as directory:
            keys, _ = _summary(directory.read())
        refusals = lockout_refusals(settings, entry.pw_name, len(keys), tested is True,
                                    has_password(entry.pw_name))
        if refusals:
            raise SSHSecError(' '.join(refusals))
        mode, main_text, block_path = _targets()
        block_source = main_text if mode == 'block' else (_read_bytes(block_path) or b'').decode('utf-8', 'replace')
        settings = sc.keep_unset(settings, sc.read_block(block_source)['values'])
        current = sshd_t(runner)
        port_change = settings['port'] is not None and current.get('port', '').split() != [str(settings['port'])]
        if port_change and socket_activated(runner):
            raise SSHSecError('sshd is started by systemd socket activation here, so the port is set in ssh.socket, '
                              'not in sshd_config. Leave the port empty.')
        if port_change and os.path.exists('/etc/csf'):
            raise SSHSecError('CSF manages this firewall. Change the port in CSF and sshd by hand, or leave it empty.')
        supported = set(current)
        needs_key = settings['password'] == 'no' or (entry.pw_name == 'root' and settings['root'] != 'yes')
        if mode == 'block':
            new_main = sc.render_main(main_text, settings, supported)
            writes = [(SSHD_CONFIG, main_text, new_main)]
        else:
            old_drop = _read_bytes(block_path)
            writes = [(block_path, None if old_drop is None else old_drop.decode('utf-8', 'surrogateescape'),
                       sc.render_dropin(settings, supported)),
                      (SSHD_CONFIG, main_text, sc.render_main_for_dropin(main_text, settings, supported))]
        writes = [w for w in writes if w[1] != w[2]]
        if not writes:
            return {'changed': False, 'message': 'The SSH configuration already has these settings.'}
        if mode == 'block':
            _candidate_check(writes[0][2], settings, entry.pw_name, client, needs_key, runner)
        if port_change:
            _selinux_port(settings['port'], runner)
            opened = _firewall_open(settings['port'], runner)
        else:
            opened = None
        files = []
        try:
            for path, old, new in writes:
                backup = _backup('sshd', os.path.basename(path), old.encode('utf-8', 'surrogateescape')) \
                    if old is not None else None
                files.append({'path': path, 'backup': backup})
                _atomic_write(path, new.encode('utf-8', 'surrogateescape'), runner)
                files[-1]['applied'] = _sha(new.encode('utf-8', 'surrogateescape'))
            _verify(settings, entry.pw_name, client, needs_key, runner)
        except Exception as exc:
            _restore(files, runner)
            _firewall_close(opened, runner)
            raise SSHSecError('%s Nothing was changed: the previous configuration is back in place.'
                              % str(exc).rstrip('.') + '.')
        token = os.urandom(16).hex()
        service = service_name(runner)
        pending = {'token': token, 'created': int(time.time()), 'deadline': int(time.time()) + REVERT_SECONDS,
                   'files': files, 'settings': settings, 'login_user': entry.pw_name, 'by': str(by)[:64],
                   'firewall_added': opened, 'service': service}
        _save_json('login-pending.json', pending)
        try:
            pending['unit'] = _arm_timer(token, runner)
            _save_json('login-pending.json', pending)
        except SSHSecError as exc:
            _restore(files, runner)
            _firewall_close(opened, runner)
            _drop('login-pending.json')
            raise SSHSecError('%s The change was undone; sshd was not reloaded.' % exc)
        problem = _reload(service, runner, settings['port'] if port_change else None, sleep)
        if problem:
            _restore(files, runner)
            _reload(service, runner, None, sleep)
            _firewall_close(opened, runner)
            _stop_timer(pending.get('unit'), runner)
            _drop('login-pending.json')
            raise SSHSecError('%s. The previous configuration was restored and sshd reloaded again.' % problem)
    notes = []
    if port_change:
        notes.append('Port %d was opened in firewalld%s. The old port stays open; close it in the firewall after '
                     'you have confirmed.' % (settings['port'], '' if opened else ' (it was already open, or firewalld '
                                                                                   'is off)'))
        if os.path.exists(ac.F2B_JAIL_FILE):
            notes.append('Update the port in %s so fail2ban watches the new port.' % ac.F2B_JAIL_FILE)
    return {'changed': True, 'pending': _public_pending(pending), 'notes': notes,
            'message': 'Applied and sshd reloaded; open sessions stay connected. Test a NEW SSH login now, then click '
                       'Confirm. Without confirmation the previous settings come back in %d minutes.'
                       % (REVERT_SECONDS // 60)}


def _stop_timer(unit, runner):
    if unit and re.match(r'^indianscloud-ssh-revert-[0-9a-f]{12}$', unit):
        ac._run(['systemctl', 'stop', unit + '.timer'], 30, runner)


def login_confirm(token, runner=subprocess.run):
    with _Lock():
        pending = load_pending()
        if not pending or pending['token'] != token:
            raise SSHSecError('There is no change waiting for confirmation (it may have been undone already).')
        _stop_timer(pending.get('unit'), runner)
        _drop('login-pending.json')
        _save_json('login-last.json', {'result': 'confirmed', 'time': int(time.time()),
                                       'settings': pending.get('settings')})
    return {'confirmed': True, 'message': 'Confirmed. The new SSH settings stay.'}


def login_revert(token, reason='button', runner=subprocess.run, sleep=time.sleep):
    """Put the previous configuration back (the timer's action, and the Undo button)."""
    with _Lock():
        pending = load_pending()
        if not pending or pending['token'] != token:
            return {'reverted': False, 'message': 'Nothing to undo.'}
        changed = []
        for item in pending['files']:
            data = _read_bytes(item['path'])
            if (_sha(data) if data is not None else None) != item.get('applied'):
                changed.append(item['path'])
        if changed:
            _drop('login-pending.json')
            _save_json('login-last.json', {'result': 'not-reverted', 'time': int(time.time()), 'reason': reason,
                                           'detail': '%s changed after the panel wrote it, so it was left alone.'
                                                     % ', '.join(changed)})
            if reason != 'timer':
                _stop_timer(pending.get('unit'), runner)
            raise SSHSecError('%s was changed by someone else after this change; not undone.' % ', '.join(changed))
        _restore(pending['files'], runner)
        problem = None
        try:
            sshd_t(runner, test_only=True)
        except SSHSecError as exc:
            problem = str(exc)
        problem = problem or _reload(pending.get('service') or 'sshd', runner, None, sleep)
        _firewall_close(pending.get('firewall_added'), runner)
        if reason != 'timer':
            _stop_timer(pending.get('unit'), runner)
        _drop('login-pending.json')
        _save_json('login-last.json', {'result': 'reverted', 'time': int(time.time()), 'reason': reason,
                                       'detail': problem or ''})
    return {'reverted': True, 'message': 'The previous SSH settings are back.' + (' ' + problem if problem else '')}


# ----------------------------------------------------------------------------- keys

def _last_key_guard(name, remaining, runner):
    if remaining > 0:
        return
    if load_pending():
        raise SSHSecError('An SSH login change is waiting for confirmation; confirm or undo it before removing the '
                          'last key.')
    reason = key_only_reason(name, sshd_t(runner, user=name))
    if reason:
        raise SSHSecError('Refusing to remove the last key of %s: %s, so nobody could log in as %s any more.'
                          % (name, reason, name))


def keys_list(user='root', runner=subprocess.run):
    entry, _, keys, problems = read_keys(user)
    reason = None
    try:
        reason = key_only_reason(entry.pw_name, sshd_t(runner, user=entry.pw_name))
    except SSHSecError:
        pass
    return {'user': entry.pw_name, 'path': os.path.join(entry.pw_dir, '.ssh', 'authorized_keys'), 'keys': keys,
            'problems': problems, 'key_only': reason, 'users': login_users()}


def keys_add(user, key, allow_options=False, runner=subprocess.run):
    entry, text, keys, _ = read_keys(user)
    new = _checked(key, allow_options is True, runner)
    if any(k['fingerprint'] == new['fingerprint'] for k in keys):
        raise SSHSecError('This key is already in %s\'s authorized_keys.' % entry.pw_name)
    with _Lock():
        _write_keys(entry, text, ak.with_key(text or '', new), runner)
    return {'added': ak.public(new), 'user': entry.pw_name}


def keys_remove(user, fingerprints, runner=subprocess.run):
    entry, text, keys, _ = read_keys(user)
    wanted = {ak.decode_fingerprint(f) for f in (fingerprints or [])}
    if not wanted:
        raise SSHSecError('Select the keys to remove.')
    missing = wanted - {k['fingerprint'] for k in keys}
    if missing:
        raise SSHSecError('Not in authorized_keys: %s' % ', '.join(sorted(missing)))
    with _Lock():
        _last_key_guard(entry.pw_name, len([k for k in keys if k['fingerprint'] not in wanted]), runner)
        _write_keys(entry, text, ak.without(text, wanted), runner)
    return {'removed': sorted(wanted), 'user': entry.pw_name}


def keys_rotate(user, key, remove, allow_options=False, runner=subprocess.run):
    """Add the new key, then drop the selected old ones, in one atomic replacement of the file:
    there is no moment at which neither key is present."""
    entry, text, keys, _ = read_keys(user)
    new = _checked(key, allow_options is True, runner) if isinstance(key, str) else key
    wanted = {ak.decode_fingerprint(f) for f in (remove or [])} - {new['fingerprint']}
    missing = wanted - {k['fingerprint'] for k in keys}
    if missing:
        raise SSHSecError('Not in authorized_keys: %s' % ', '.join(sorted(missing)))
    with _Lock():
        added = ak.with_key(text or '', new)
        _write_keys(entry, text, ak.without(added, wanted), runner)
    return {'added': ak.public(new), 'removed': sorted(wanted), 'user': entry.pw_name}


def validate_passphrase(secret):
    secret = secret if isinstance(secret, str) else ''
    if secret and (len(secret) < 8 or len(secret) > 256 or any(ord(c) < 32 for c in secret)):
        raise SSHSecError('The passphrase must be 8 to 256 characters (or empty for none).')
    return secret


def keys_generate(user='root', comment='', passphrase='', remove=(), runner=subprocess.run):
    """Make an ed25519 key pair, install the public half, return the private half once and
    leave no copy of it on the server."""
    entry = user_entry(user)
    comment = ak.validate_comment(comment) or '%s@indianscloud-%s' % (entry.pw_name, time.strftime('%Y%m%d'))
    passphrase = validate_passphrase(passphrase)
    work = _private_dir(os.path.join(_private_dir(_state('tmp')), 'gen-%s' % os.urandom(8).hex()))
    keyfile = os.path.join(work, 'id_ed25519')
    try:
        code, out = ac._run([ac._which('ssh-keygen') or SSH_KEYGEN, '-q', '-t', 'ed25519', '-a', '100', '-N',
                             passphrase, '-C', comment, '-f', keyfile], 60, runner)
        if code != 0 or not os.path.exists(keyfile):
            raise SSHSecError('ssh-keygen failed: %s' % out.strip()[-200:])
        with open(keyfile) as handle:
            private = handle.read()
        with open(keyfile + '.pub') as handle:
            public_line = handle.read().strip()
    finally:
        _shred_tree(work)
    new = _checked(public_line, False, runner)
    if remove:
        result = keys_rotate(entry.pw_name, new, remove, runner=runner)
    else:
        result = keys_add(entry.pw_name, public_line, runner=runner)
    result.update(private_key=private, public_key=public_line, encrypted=bool(passphrase),
                  filename='%s-%s-ed25519' % (entry.pw_name, time.strftime('%Y%m%d')))
    return result


def _shred_tree(path):
    """Overwrite and delete every file under `path`, then the directory."""
    for name in os.listdir(path) if os.path.isdir(path) else []:
        full = os.path.join(path, name)
        try:
            size = os.path.getsize(full)
            with open(full, 'r+b') as handle:
                handle.write(b'\0' * size)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            pass
    shutil.rmtree(path, ignore_errors=True)


def _decode_key(key_b64):
    try:
        return base64.b64decode(str(key_b64 or ''), validate=True).decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise SSHSecError('Invalid key encoding.')


ACTIONS = {
    'login_state': lambda client=(): login_state(client),
    'login_apply': lambda settings, login_user='root', tested=False, client=(), by='':
        login_apply(settings, login_user, tested, client, by),
    'login_confirm': lambda token: login_confirm(token),
    'login_revert': lambda token, reason='button': login_revert(token, reason),
    'keys_list': lambda user='root': keys_list(user),
    'keys_add': lambda user, key, allow_options=False: keys_add(user, key, allow_options),
    'keys_remove': lambda user, fingerprints: keys_remove(user, fingerprints),
    'keys_rotate': lambda user, key, remove, allow_options=False: keys_rotate(user, key, remove, allow_options),
    'keys_generate': lambda user='root', comment='', passphrase='', remove=():
        keys_generate(user, comment, passphrase, remove),
}

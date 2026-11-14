"""Building and starting the terminal's shell (root side).

build_spawn() turns a consumed ticket into a SpawnSpec: who to become, which shell, which home and
a minimal environment. It refuses root unless the ticket and the current policy both allow it, and
refuses accounts that are not ordinary site users (system accounts, the panel's own users, members
of groups that are root-equivalent). spawn() forks a pty and drops privileges in the child.
"""
import grp
import os
import pwd
import re
import signal
from collections import namedtuple

SpawnSpec = namedtuple('SpawnSpec', 'user uid gid groups home shell argv env')

USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
UID_MIN = 1000
# Never a terminal for these, even if a site record pointed at them.
DENIED_USERS = frozenset({'root', 'cyberpanel', 'lscpd', 'vmail', 'docker', 'ftpuser', 'nobody', 'mysql',
                          'named', 'postfix', 'dovecot', 'opendkim', 'lsadm', 'pdns', 'redis', 'memcached'})
# Membership makes an account root-equivalent or lets it read panel secrets.
DENIED_GROUPS = frozenset({'root', 'wheel', 'sudo', 'admin', 'adm', 'docker', 'disk', 'lxd', 'libvirt',
                           'cyberpanel', 'lscpd', 'lsadm', 'shadow', 'mysql', 'systemd-journal'})
SHELLS_FILE = '/etc/shells'
FALLBACK_SHELL = '/bin/bash'
USER_PATH = '/usr/local/bin:/usr/bin:/bin'
ROOT_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


class ShellError(PermissionError):
    pass


def allowed_shells(path=SHELLS_FILE):
    try:
        with open(path) as handle:
            shells = {line.strip() for line in handle if line.strip().startswith('/')}
    except OSError:
        shells = set()
    return {s for s in shells if not s.endswith(('nologin', '/false'))}


def pick_shell(login_shell, shells, exists=os.path.exists):
    """The account's login shell if it is a real one from /etc/shells, otherwise /bin/bash
    (site users are often created with /sbin/nologin to keep them off SSH)."""
    if login_shell in shells and exists(login_shell):
        return login_shell
    return FALLBACK_SHELL


def build_spawn(record, policy, getpwnam=pwd.getpwnam, getgrouplist=os.getgrouplist, getgrgid=grp.getgrgid,
                shells=None, exists=os.path.exists):
    """record: a consumed ticket; policy: service.terminal_policy() read now (not at issue time)."""
    shells = allowed_shells() if shells is None else shells
    if record.get('root'):
        if not (record.get('is_admin') is True and policy.get('terminal_root_for_admins') is True):
            raise ShellError('Root shells are not allowed.')
        entry = getpwnam('root')
        env = _environment('root', entry.pw_dir, '/bin/bash', ROOT_PATH)
        return SpawnSpec('root', 0, 0, [0], entry.pw_dir, '/bin/bash', ['-bash'], env)
    if not record.get('is_admin') and policy.get('terminal_for_users') is not True:
        raise ShellError('The administrator has not enabled the terminal for users.')
    name = record.get('system_user')
    if not isinstance(name, str) or not USER_RE.match(name) or name in DENIED_USERS:
        raise ShellError('This site has no usable Linux user.')
    try:
        entry = getpwnam(name)
    except KeyError:
        raise ShellError('The Linux user of this site does not exist.')
    if entry.pw_uid < UID_MIN or entry.pw_gid == 0 or entry.pw_uid == 0:
        raise ShellError('Refusing a terminal for a system account.')
    home = os.path.normpath(entry.pw_dir or '')
    if not home.startswith('/home/') or home.count('/') != 2:
        raise ShellError('The site user has an unexpected home directory.')
    groups = sorted(set(getgrouplist(name, entry.pw_gid)))
    for gid in groups:
        if gid == 0:
            raise ShellError('Refusing a terminal for a member of a privileged group.')
        try:
            group_name = getgrgid(gid).gr_name
        except KeyError:
            continue
        if group_name in DENIED_GROUPS:
            raise ShellError('Refusing a terminal for a member of the %s group.' % group_name)
    shell = pick_shell(entry.pw_shell, shells, exists)
    env = _environment(name, home, shell, USER_PATH)
    return SpawnSpec(name, entry.pw_uid, entry.pw_gid, groups, home, shell, ['-' + os.path.basename(shell)], env)


def _environment(user, home, shell, path):
    return {'HOME': home, 'USER': user, 'LOGNAME': user, 'SHELL': shell, 'PATH': path,
            'TERM': 'xterm-256color', 'COLORTERM': 'truecolor', 'LANG': 'C.UTF-8', 'TERMINAL_ORIGIN': 'cyberpanel-web'}


# ----------------------------------------------------------------------------- session limits

class SessionLimits:
    """Concurrent-session accounting for one service process (the only place shells start)."""

    def __init__(self, per_user=3, total=10):
        self.per_user, self.total = per_user, total
        self.active = {}

    def count(self):
        return sum(self.active.values())

    def acquire(self, key):
        if self.count() >= self.total:
            raise ShellError('The server already has the maximum of %d terminal sessions.' % self.total)
        if self.active.get(key, 0) >= self.per_user:
            raise ShellError('You already have the maximum of %d terminal sessions open.' % self.per_user)
        self.active[key] = self.active.get(key, 0) + 1

    def release(self, key):
        if self.active.get(key, 0) <= 1:
            self.active.pop(key, None)
        else:
            self.active[key] -= 1


def clamp_size(cols, rows):
    try:
        cols, rows = int(cols), int(rows)
    except (TypeError, ValueError):
        return None
    if not (2 <= cols <= 500 and 1 <= rows <= 200):
        return None
    return cols, rows


# ----------------------------------------------------------------------------- spawning

def set_size(fd, cols, rows):
    import fcntl
    import struct
    import termios
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))


def _become(spec):
    """Child side, after pty.fork(): drop to spec's identity or die. Never returns on failure."""
    if spec.uid != 0:
        os.setgroups(spec.groups)
        os.setgid(spec.gid)
        os.setuid(spec.uid)
        if os.getuid() != spec.uid or os.geteuid() != spec.uid or os.getegid() != spec.gid:
            raise OSError('privilege drop did not take effect')
        try:
            os.setuid(0)
        except PermissionError:
            pass
        else:
            raise OSError('privileges could be regained')
    os.umask(0o022)
    try:
        os.chdir(spec.home)
    except OSError:
        os.chdir('/')


def spawn(spec, cols=80, rows=24):
    """Start the shell on a new pty. Returns (pid, master_fd). The child is a session leader
    (pty.fork calls setsid), so its process group can be signalled as a whole."""
    import pty
    pid, fd = pty.fork()
    if pid == 0:  # child: no Python-level cleanup, no return
        try:
            os.closerange(3, 65536)
            for number in range(1, 32):
                if number not in (signal.SIGKILL, signal.SIGSTOP):
                    try:
                        signal.signal(number, signal.SIG_DFL)
                    except (OSError, ValueError, RuntimeError):
                        pass
            signal.pthread_sigmask(signal.SIG_SETMASK, [])
            _become(spec)
            os.execve(spec.shell, spec.argv, spec.env)
        except BaseException:
            pass
        os._exit(127)
    try:
        set_size(fd, cols, rows)
    except OSError:
        pass
    return pid, fd


def terminate(pid, fd, wait=None):
    """Close the pty and end the shell's process group: SIGHUP, then SIGKILL. Returns the exit status."""
    try:
        os.close(fd)
    except OSError:
        pass
    for sig in (signal.SIGHUP, signal.SIGCONT):
        try:
            os.killpg(pid, sig)
        except OSError:
            pass
    return (wait or _reap)(pid)


def _reap(pid, grace=3.0):
    import time
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        try:
            done, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return None
        if done:
            return status
        time.sleep(0.05)
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        return os.waitpid(pid, 0)[1]
    except ChildProcessError:
        return None

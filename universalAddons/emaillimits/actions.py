"""Root-side Email Limits actions (dispatched by universalAddons/runner.py).

Delivering a cache command to cpecs
  cpecs reads /home/cyberpanel/purgeCache (one command per file) whenever a connection arrives on
  its socket, runs it, deletes the file and writes its counters back to the database. The socket
  belongs to postfix (mode 0755), so only root can connect besides Postfix. Each command is
  written, then a harmless policy request (empty sasl_username, which cpecs answers with DUNNO
  without counting anything) wakes cpecs; we wait until the file is gone before writing the next
  one, so a bulk change never overwrites a command cpecs has not read yet.

  If cpecs is not running nothing is delivered: it rebuilds its cache from the database when it
  starts, so the saved rows already take effect.

Nothing here restarts or reconfigures Postfix or cpecs.
"""
import json
import os
import socket
import stat
import subprocess
import time

from universalAddons.emaillimits import service as svc
from universalAddons.emaillimits.service import LimitError

POKE = b'request=smtpd_access_policy\nprotocol_state=DATA\nsasl_username=\n\n'
POLICY_FILE_KEY = 'email_limits_for_users'


def _run(argv, input=None, timeout=30):
    try:
        out = subprocess.run(argv, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True, timeout=timeout)
    except FileNotFoundError:
        return 127, '', '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '', '%s: timed out' % argv[0]
    return out.returncode, out.stdout or '', out.stderr or ''


def service_state():
    code, out, err = _run(['systemctl', 'is-active', 'cpecs'])
    return (out.strip() or err.strip() or 'unknown').splitlines()[0]


def _is_socket(path):
    try:
        return stat.S_ISSOCK(os.lstat(path).st_mode)
    except OSError:
        return False


# ----------------------------------------------------------------------------- cache delivery

class Cpecs:
    def __init__(self, purge_file=svc.PURGE_FILE, socket_path=svc.POLICY_SOCKET, wait=3.0, settle=0.3):
        self.purge_file, self.socket_path, self.wait, self.settle = purge_file, socket_path, wait, settle

    def _connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.wait + 2)
        try:
            sock.connect(self.socket_path)
        except OSError as exc:
            sock.close()
            raise LimitError('Could not reach cpecs at %s: %s' % (self.socket_path, exc))
        return sock

    def _gone(self):
        deadline = time.time() + self.wait
        while os.path.lexists(self.purge_file):
            if time.time() > deadline:
                return False
            time.sleep(0.02)
        return True

    def _write(self, text):
        # O_EXCL + O_NOFOLLOW: never follow a link the panel user may have planted in its home.
        fd = os.open(self.purge_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'w') as handle:
            handle.write(text)

    def _exchange(self, sock):
        sock.sendall(POKE)
        try:
            sock.recv(256)  # cpecs reads the purge file before it answers
        except socket.timeout:
            pass

    def poke(self):
        sock = self._connect()
        try:
            self._exchange(sock)
        finally:
            sock.close()

    def deliver(self, text, flush=False):
        if os.path.lexists(self.purge_file):
            # A command from elsewhere (e.g. the hourly cron) is waiting: let cpecs take it first.
            self.poke()
            if not self._gone():
                raise LimitError('cpecs is not reading %s; leaving the pending command alone.' % self.purge_file)
        sock = self._connect()
        try:
            if flush:
                # cpecs' accept loop also checks the file, but only its connection thread flushes the
                # counters afterwards. Let the accept loop go back to waiting before the file appears.
                time.sleep(self.settle)
            try:
                self._write(text)
            except OSError as exc:
                raise LimitError('Could not write %s: %s' % (self.purge_file, exc))
            self._exchange(sock)
        finally:
            sock.close()
        if not self._gone():
            try:
                os.unlink(self.purge_file)  # a root-owned leftover would block the panel's own writes
            except OSError:
                pass
            raise LimitError('cpecs did not pick up the cache update.')


def sync(commands, cpecs=None, state=None):
    if not isinstance(commands, list) or len(commands) > svc.MAX_COMMANDS:
        raise LimitError('Invalid cache commands.')
    texts = [svc.cache_command(c) for c in commands]  # validate everything before delivering anything
    if not texts:
        return {'delivered': 0}
    if (state or service_state)() != 'active':
        return {'delivered': 0, 'note': 'cpecs is not running; it loads the saved limits from the database when it starts.'}
    cpecs = cpecs or Cpecs()
    for number, text in enumerate(texts):
        try:
            cpecs.deliver(text)
        except LimitError as exc:
            raise LimitError('Saved, but only %d of %d cache updates reached cpecs: %s' % (number, len(texts), exc))
    return {'delivered': len(texts)}


def refresh(cpecs=None, state=None):
    """Ask cpecs to write its in-memory counters to the database."""
    if (state or service_state)() != 'active':
        return {'flushed': False, 'note': 'cpecs is not running; the counters shown are the last ones it saved.'}
    (cpecs or Cpecs()).deliver(svc.cache_command(['flush']), flush=True)
    return {'flushed': True}


# ----------------------------------------------------------------------------- health and cron

def _postconf(param):
    code, out, err = _run(['postconf', '-h', param])
    return out.strip() if code == 0 else ''


def read_crontab():
    code, out, err = _run(['crontab', '-l', '-u', 'root'])
    if code != 0 and 'no crontab' not in err.lower():
        raise LimitError('Could not read the root crontab: %s' % (err.strip() or code))
    return out if code == 0 else ''


def health():
    values = {param: _postconf(param) for param in svc.RESTRICTION_PARAMS}
    crontab = read_crontab()
    rows = svc.health_report(service_state(), _is_socket(svc.POLICY_SOCKET), values, crontab,
                             os.path.lexists(svc.PURGE_FILE), _postconf('smtpd_policy_service_default_action'))
    return {'results': rows, 'cron': svc.cron_present(crontab), 'postconf': values}


def repair_cron():
    current = read_crontab()
    text, added = svc.cron_repaired(current)
    if added:
        code, out, err = _run(['crontab', '-u', 'root', '-'], input=text)
        if code != 0:
            raise LimitError('Could not write the root crontab: %s' % (err.strip() or code))
    return {'added': added, 'cron': svc.cron_present(text)}


# ----------------------------------------------------------------------------- policy

def set_policy(enabled, path=None):
    """Change only email_limits_for_users in the shared policy file, keeping every other key."""
    from universalAddons.access import POLICY_FILE
    if not isinstance(enabled, bool):
        raise LimitError('enabled must be true or false.')
    path = path or POLICY_FILE
    try:
        with open(path) as handle:
            stored = json.load(handle)
        if not isinstance(stored, dict):
            stored = {}
    except (OSError, ValueError):
        stored = {}
    stored[POLICY_FILE_KEY] = enabled
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + '.tmp', 'w') as handle:
        json.dump(stored, handle, indent=2, sort_keys=True)
    os.chmod(path + '.tmp', 0o644)  # read by the panel process; contains no secrets
    os.replace(path + '.tmp', path)
    return {POLICY_FILE_KEY: enabled}


ACTIONS = {
    'sync': lambda commands: sync(commands),
    'refresh': lambda: refresh(),
    'health': health,
    'repair_cron': repair_cron,
    'set_policy': lambda enabled: set_policy(enabled),
}

"""Root side of Autoresponders & Spam Rules: writes each mailbox's managed Sieve script as vmail.

Only reads Dovecot and MailScanner configuration; never changes or restarts either. Files are
written below /home/vmail/<domain>/<local>/sieve-managed through directory descriptors opened
with O_NOFOLLOW, each checked to belong to vmail, so a link planted in the mail tree cannot
redirect a root write. The script is compiled with sievec as vmail before it replaces the
previous one; a script that does not compile is never installed.
"""
import datetime
import json
import os
import pwd
import shutil
import stat
import subprocess

from universalAddons.autoresponder import service as svc
from universalAddons.autoresponder.service import SieveError

SIEVEC_PATHS = ('/usr/bin/sievec', '/usr/local/bin/sievec')


def _django():
    from universalAddons import django_env
    django_env.setup()


def _vmail():
    entry = pwd.getpwnam(svc.VMAIL_USER)
    return entry.pw_uid, entry.pw_gid


def _require_mailbox(email):
    """The mailbox must exist in the panel (ownership was checked by the web side)."""
    email = svc.clean_email(email)
    _django()
    from mailServer.models import EUsers
    if not EUsers.objects.filter(email=email).exists():
        raise SieveError('Unknown mailbox %s.' % email)
    return email


def sievec_path(exists=os.path.exists):
    for path in SIEVEC_PATHS:
        if exists(path):
            return path
    return None


# ----------------------------------------------------------------------------- files, as vmail

def _open_managed_dir(email, create, uid, gid, root=None):
    """A descriptor of <mailbox>/sieve-managed (created 0700 vmail when `create`), or None."""
    local, domain = email.split('@')
    root = root or svc.VMAIL_ROOT
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in (domain, local):
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                raise SieveError('The mailbox directory of %s does not exist yet (it is created with the first '
                                 'delivery or login).' % email)
            os.close(fd)
            fd = next_fd
            if os.fstat(fd).st_uid != uid:
                raise SieveError('The mailbox directory of %s does not belong to %s.' % (email, svc.VMAIL_USER))
        try:
            managed = os.open(svc.MANAGED_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        except FileNotFoundError:
            if not create:
                return None
            os.mkdir(svc.MANAGED_DIR, 0o700, dir_fd=fd)
            managed = os.open(svc.MANAGED_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.fchown(managed, uid, gid)
        info = os.fstat(managed)
        if info.st_uid != uid:
            os.close(managed)
            raise SieveError('%s of %s does not belong to %s.' % (svc.MANAGED_DIR, email, svc.VMAIL_USER))
        return managed
    finally:
        os.close(fd)


def _read(dir_fd, name, limit=256 * 1024):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return None
        return handle.read(limit).decode('utf-8', 'replace')


def _write(dir_fd, name, data, uid, gid):
    temporary = name + '.tmp'
    try:
        os.unlink(temporary, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data if isinstance(data, bytes) else data.encode('utf-8'))
        os.fchown(handle.fileno(), uid, gid)
    return temporary


def _remove(dir_fd, name):
    try:
        os.unlink(name, dir_fd=dir_fd)
        return True
    except FileNotFoundError:
        return False


def compile_script(sievec, directory, source, target, uid, gid, runner=subprocess.run):
    """Compile `source` into `target` with sievec as vmail. Returns (ok, output)."""
    argv = [sievec, os.path.join(directory, source), os.path.join(directory, target)]
    try:
        out = runner(argv, user=uid, group=gid, extra_groups=[], cwd=directory, stdin=subprocess.DEVNULL,
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=60,
                     env={'PATH': '/usr/bin:/bin', 'HOME': directory, 'LANG': 'C'})
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return out.returncode == 0, (out.stdout or '').strip()[-2000:]


# ----------------------------------------------------------------------------- actions

def status(email, root=None, today=None):
    email = _require_mailbox(email) if root is None else svc.clean_email(email)
    uid, gid = _vmail() if root is None else (os.getuid(), os.getgid())
    today = today or datetime.date.today()
    managed = _open_managed_dir(email, False, uid, gid, root)
    settings = {'vacation': dict(svc.DEFAULT_VACATION), 'spam': dict(svc.DEFAULT_SPAM)}
    script = None
    compiled = False
    if managed is not None:
        try:
            text = _read(managed, svc.SETTINGS_NAME)
            if text:
                settings = svc.load_settings(text)
            script = _read(managed, svc.SCRIPT_NAME)
            compiled = _read(managed, svc.BINARY_NAME, 16) is not None
        finally:
            os.close(managed)
    return {'email': email, 'settings': settings, 'script': script, 'compiled': compiled,
            'vacation_active': svc.vacation_active(settings['vacation'], today)}


def save(email, settings, root=None, today=None, sievec=None, runner=subprocess.run, headers=None):
    email = _require_mailbox(email) if root is None else svc.clean_email(email)
    uid, gid = _vmail() if root is None else (os.getuid(), os.getgid())
    today = today or datetime.date.today()
    clean = svc.clean_settings(settings, today)
    headers = headers or svc.mailscanner_headers(_read_text(svc.MAILSCANNER_CONF))
    script = svc.render(clean, email, headers)
    sievec = sievec_path() if sievec is None else (sievec or None)
    directory = os.path.join(root or svc.VMAIL_ROOT, *reversed(email.split('@')), svc.MANAGED_DIR)
    managed = _open_managed_dir(email, True, uid, gid, root)
    try:
        result = {'email': email, 'settings': clean, 'script': script, 'compiled': False, 'compiler': bool(sievec)}
        if script is None:
            removed = _remove(managed, svc.SCRIPT_NAME)
            _remove(managed, svc.BINARY_NAME)
            result['note'] = 'No rule is on; the managed script was removed.' if removed else 'No rule is on.'
        else:
            source = _write(managed, svc.SCRIPT_NAME, script, uid, gid)
            if sievec:
                binary = svc.BINARY_NAME + '.tmp'
                ok, output = compile_script(sievec, directory, source, binary, uid, gid, runner)
                if not ok:
                    _remove(managed, source)
                    _remove(managed, binary)
                    raise SieveError('The script did not compile, nothing was changed: %s' % output)
                os.rename(binary, svc.BINARY_NAME, src_dir_fd=managed, dst_dir_fd=managed)
                result['compiled'] = True
            else:
                _remove(managed, svc.BINARY_NAME)   # never leave a binary of an older script
                result['note'] = ('Saved, but Pigeonhole (sievec) is not installed, so Dovecot does not run it yet. '
                                  'See the administrator notes.')
            os.rename(source, svc.SCRIPT_NAME, src_dir_fd=managed, dst_dir_fd=managed)
        settings_tmp = _write(managed, svc.SETTINGS_NAME, json.dumps(clean, indent=1, sort_keys=True), uid, gid)
        os.rename(settings_tmp, svc.SETTINGS_NAME, src_dir_fd=managed, dst_dir_fd=managed)
    finally:
        os.close(managed)
    result['vacation_active'] = svc.vacation_active(clean['vacation'], today)
    return result


def _read_text(path, limit=2 * 1024 * 1024):
    try:
        with open(path, 'rb') as handle:
            return handle.read(limit).decode('utf-8', 'replace')
    except OSError:
        return ''


def _doveconf(runner=subprocess.run):
    tool = shutil.which('doveconf') or '/usr/bin/doveconf'
    try:
        out = runner([tool, '-n'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return '', str(exc)
    return (out.stdout or ''), ('' if out.returncode == 0 else (out.stdout or '').strip()[-500:])


def health(runner=subprocess.run):
    """Read-only checks; returns the problems and the Dovecot drop-in to apply by hand."""
    text, problem = _doveconf(runner)
    sievec = sievec_path()
    problems = ([('doveconf -n failed: %s' % problem)] if problem else []) + \
        svc.dovecot_problems(text, bool(sievec), _read_text('/etc/dovecot/dovecot.conf'))
    headers = svc.mailscanner_headers(_read_text(svc.MAILSCANNER_CONF))
    rows = [{'status': 'fail', 'title': 'Dovecot Sieve', 'detail': p, 'fix': ''} for p in problems]
    if not problems:
        rows.append({'status': 'pass', 'title': 'Dovecot Sieve', 'detail': 'Managed scripts run before personal '
                     'filters (sieve_before).', 'fix': ''})
    rows.append({'status': 'info', 'title': 'Spam headers', 'detail': 'Spam flag: %s. Score header: %s (%s). '
                 'MailScanner marks spam from %g and handles %g and above with "%s".' % (
                     ', '.join('%s: %s' % tuple(f) for f in headers['flags']), headers['score_header'],
                     'number' if headers['score_numeric'] else 'one "%s" per point' % headers['score_char'],
                     headers['required'], headers['high'], headers['high_actions']), 'fix': ''})
    return {'results': rows, 'problems': problems, 'dropin': svc.dovecot_dropin(), 'dropin_path': svc.DROPIN_PATH,
            'headers': headers, 'sievec': sievec or ''}


ACTIONS = {
    'status': lambda email: status(email),
    'save': lambda email, settings: save(email, settings),
    'health': lambda: health(),
}

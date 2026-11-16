"""Root side: resolve a panel site, and read its files and run its commands as the site's own user.

Used by the Laravel Toolkit and Git deploy add-ons. Rules:
- Paths come from the panel database (websites and child domains), never from the request; the
  request only names a domain and a relative path inside the site, both validated here.
- Root never follows a link the site owner controls: files are opened component by component with
  O_NOFOLLOW below the site's home, must stay inside it and must belong to the site user.
- Commands run as the site user with a clean environment and a hard timeout, argv lists only.
  Secrets (tokens) travel in that environment, never on a command line.
"""
import os
import pwd
import re
import stat
import subprocess

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
# A relative path inside a site: plain components, no '.', '..' or empty ones, at most 8 deep.
_COMPONENT = r'(?!\.\.?(/|$))[A-Za-z0-9._-]{1,100}'
REL_RE = re.compile(r'^%s(/%s){0,7}$' % (_COMPONENT, _COMPONENT))
# Absolute paths that may appear in crontab lines and systemd units.
ABS_RE = re.compile(r'^/[A-Za-z0-9._/-]{1,400}$')
VHOSTS = '/usr/local/lsws/conf/vhosts'
USER_PATH = '/usr/local/bin:/usr/bin:/bin'


class SiteError(ValueError):
    pass


def check_rel(rel, allow_empty=True):
    """A validated relative path ('' = the base itself when allowed)."""
    rel = str(rel if rel is not None else '').strip().rstrip('/')
    if rel == '' and allow_empty:
        return ''
    if not REL_RE.match(rel):
        raise SiteError('Invalid path %r: use letters, digits, . _ - and / only.' % rel[:80])
    return rel


class Site:
    """A website or child domain: Linux user, home, document root, vhost name and PHP binary."""

    def __init__(self, domain, user, home, docroot, vhost=None, php='/usr/bin/php'):
        if not DOMAIN_RE.match(domain or '') or not USER_RE.match(user or ''):
            raise SiteError('Invalid site.')
        home = os.path.normpath(home or '')
        docroot = os.path.normpath(docroot or '')
        if not re.match(r'^/home/[A-Za-z0-9._-]+$', home) or not (docroot == home or docroot.startswith(home + '/')) \
                or '..' in docroot.split('/') or not ABS_RE.match(docroot):
            raise SiteError('The site must live in its own home under /home.')
        self.domain, self.user, self.home, self.docroot = domain, user, home, docroot
        self.vhost, self.php = vhost or domain, php

    @property
    def uid(self):
        return pwd.getpwnam(self.user).pw_uid

    @property
    def gid(self):
        return pwd.getpwnam(self.user).pw_gid

    def path(self, rel='', base=None):
        """Absolute path of `rel` below the document root (or `base`), validated."""
        rel = check_rel(rel)
        root = base or self.docroot
        return os.path.join(root, rel) if rel else root

    def home_rel(self, rel):
        """Absolute path of `rel` below the home directory."""
        return os.path.join(self.home, check_rel(rel, allow_empty=False))

    def inside(self, path):
        """The real path of `path`, which must stay inside the home directory."""
        real = os.path.realpath(path)
        if real != self.home and not real.startswith(self.home + '/'):
            raise SiteError('That path leaves the site.')
        return real


def php_version(php):
    match = re.search(r'lsphp(\d)(\d+)', php or '')
    return '%s.%s' % match.groups() if match else ''


def resolve(domain):
    """The Site for a website or child domain known to the panel."""
    from universalAddons import django_env
    django_env.setup()
    from websiteFunctions.models import ChildDomains, Websites
    from universalAddons.wordpress.service import php_for_vhost
    domain = (domain or '').strip().lower()
    if not DOMAIN_RE.match(domain):
        raise SiteError('Invalid domain.')
    try:
        site = Websites.objects.get(domain=domain)
        return Site(domain, site.externalApp, '/home/%s' % site.domain, '/home/%s/public_html' % site.domain, domain,
                    php_for_vhost(domain))
    except Websites.DoesNotExist:
        pass
    try:
        child = ChildDomains.objects.select_related('master').get(domain=domain)
    except ChildDomains.DoesNotExist:
        raise SiteError('Unknown site.')
    return Site(domain, child.master.externalApp, '/home/%s' % child.master.domain, child.path.rstrip('/'), domain,
                php_for_vhost(domain))


# ----------------------------------------------------------------------------- files, without following links

def open_owned(site, path, uid=None, flags=os.O_RDONLY):
    """Open `path` (inside the site's home) for reading, refusing links and files of other users.

    The real path must stay inside the home. It is then opened one component at a time with
    O_NOFOLLOW, so a link swapped in after the check makes the open fail instead of escaping.
    """
    real = site.inside(path)
    uid = site.uid if uid is None else uid
    parts = [p for p in real[len(site.home):].split('/') if p]
    if not parts:
        raise SiteError('Not a file.')
    fd = os.open(site.home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        file_fd = os.open(parts[-1], flags | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0), dir_fd=fd)
    finally:
        os.close(fd)
    info = os.fstat(file_fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid:
        os.close(file_fd)
        raise SiteError('%s is not a regular file of the site user.' % os.path.basename(real))
    return file_fd


def read_owned(site, path, max_bytes=256 * 1024, tail=False, uid=None):
    """Text of a site file (at most max_bytes; the last ones when tail=True), or None if missing."""
    try:
        fd = open_owned(site, path, uid)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as handle:
        if tail:
            size = os.fstat(handle.fileno()).st_size
            handle.seek(max(0, size - max_bytes))
        data = handle.read(max_bytes)
    return data.decode('utf-8', 'replace')


def exists_nofollow(path):
    try:
        os.lstat(path)
        return True
    except OSError:
        return False


# ----------------------------------------------------------------------------- commands as the site user

def user_env(site, extra=None, path=None):
    env = {'HOME': site.home, 'USER': site.user, 'LOGNAME': site.user, 'LANG': 'C.UTF-8',
           'PATH': path or (os.path.dirname(site.php) + ':' + USER_PATH)}
    env.update(extra or {})
    return env


def run_as(site, argv, cwd=None, extra_env=None, timeout=600, input=None, runner=subprocess.run, path=None):
    """Run argv as the site user (never root). Returns (exit code, output).

    The process drops to the site user's uid/gid with no supplementary groups, gets a clean
    environment and umask 022, and `timeout` kills its whole process group after `timeout` s.
    """
    argv = list(argv)
    for token in argv:
        if not isinstance(token, str) or '\x00' in token:
            raise SiteError('Invalid command argument.')
    full = ['timeout', '-k', '10', str(int(timeout))] + argv
    try:
        out = runner(full, cwd=cwd, env=user_env(site, extra_env, path), user=site.uid, group=site.gid,
                     extra_groups=[], umask=0o022, stdin=None if input is not None else subprocess.DEVNULL,
                     input=input, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout + 30)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    code = out.returncode
    output = out.stdout or ''
    if code == 124:
        output += '\n(stopped after %d seconds)' % timeout
    return code, output


def run(argv, runner=subprocess.run, timeout=120, input=None):
    """Run a root-side helper (systemctl, crontab, curl). Returns (exit code, output)."""
    try:
        out = runner(list(argv), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout, input=input)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


def write_as(site, path, text, mode_like=None, runner=subprocess.run):
    """Replace a site file with `text`, as the site user: write a sibling, copy the mode, rename."""
    directory, name = os.path.dirname(path), os.path.basename(path)
    temporary = os.path.join(directory, '.%s.ic-new' % name)
    code, out = run_as(site, ['tee', temporary], input=text, runner=runner, timeout=60)
    if code != 0:
        raise SiteError('Could not write %s: %s' % (name, out.strip()[-300:]))
    if mode_like:
        run_as(site, ['chmod', '--reference=' + mode_like, temporary], runner=runner, timeout=30)
    code, out = run_as(site, ['mv', '-f', '--', temporary, path], runner=runner, timeout=30)
    if code != 0:
        raise SiteError('Could not replace %s: %s' % (name, out.strip()[-300:]))


# ----------------------------------------------------------------------------- site crontab

def crontab_lines(site, runner=subprocess.run):
    code, out = run(['crontab', '-l', '-u', site.user], runner, timeout=30)
    return [line for line in out.splitlines() if line.strip()] if code == 0 else []


def set_cron_line(site, marker, line, enable, runner=subprocess.run):
    """Add or remove the line tagged `# <marker>` in the site user's crontab.

    This is the same per-user spool file (/var/spool/cron[/crontabs]/<user>) that the panel's
    Cron Jobs page reads and edits, so the line shows up there.
    """
    tag = '# ' + marker
    lines = [l for l in crontab_lines(site, runner) if not l.rstrip().endswith(tag)]
    if enable:
        lines.append('%s %s' % (line, tag))
    code, out = run(['crontab', '-u', site.user, '-'], runner, timeout=30, input='\n'.join(lines) + '\n')
    if code != 0:
        raise SiteError('Could not update the site crontab: ' + out.strip()[-300:])
    return enable


def has_cron_line(site, marker, runner=subprocess.run):
    tag = '# ' + marker
    return any(l.rstrip().endswith(tag) for l in crontab_lines(site, runner))


# ----------------------------------------------------------------------------- systemd

def systemd_version(runner=subprocess.run):
    code, out = run(['systemctl', '--version'], runner, timeout=30)
    match = re.search(r'systemd (\d+)', out)
    return int(match.group(1)) if match else 239


def cgroup_v2():
    return os.path.exists('/sys/fs/cgroup/cgroup.controllers')


def unit_state(unit, runner=subprocess.run):
    code, out = run(['systemctl', 'show', unit, '--property=ActiveState,SubState,UnitFileState,MemoryCurrent,'
                     'NRestarts'], runner, timeout=30)
    values = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
    memory = values.get('MemoryCurrent', '')
    return {'state': values.get('ActiveState', 'unknown'), 'sub': values.get('SubState', ''),
            'enabled': values.get('UnitFileState', '') == 'enabled', 'restarts': values.get('NRestarts', '0'),
            'memory_mb': round(int(memory) / 1048576, 1) if memory.isdigit() else None}

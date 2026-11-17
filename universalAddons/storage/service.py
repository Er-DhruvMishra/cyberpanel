"""Storage Cleaner: analyse disk usage and reclaim safe-to-delete space.

Port of the author's server-space-reclaim.sh (gist aeff2dd6dac150ac3fa4dacc26ae9c89), keeping its
safety rules, plus categories found on a real CyberPanel server.

Safety rules (from the script)
- Scan first, read-only; nothing is changed until the administrator picks categories.
- Path guard: never delete /, top-level system directories, relative paths or anything with "..".
- Active logs are truncated (never deleted) so processes keep valid file handles.
- InnoDB rebuild: the table is dumped first, the dump is verified (gzip integrity and the
  "Dump completed" footer), OPTIMIZE runs only on a verified backup, and row counts are compared.
  Refused below MYSQL_MIN_FREE_MB free disk.
- Docker data is only touched when Docker is not installed; for an installed Docker only the
  space Docker itself reports as reclaimable is offered (docker system prune).
- Kernels are removed by the package manager, which cannot remove the running kernel.
- Single run: no cron jobs, no configuration changes, no services enabled or disabled.

Risk levels shown in the panel
  safe     caches, rotated logs, temporary and superseded files
  review   real data the owner may still want (archives, trash, backups, table rebuilds)
  report   shown for information; no automatic action (e.g. orphaned InnoDB temporary tables)
"""
import fnmatch
import glob
import gzip
import os
import re
import shutil
import stat
import subprocess
import time

SESSION_AGE_DAYS = 7
ROTATED_LOG_AGE_DAYS = 30
TMP_AGE_DAYS = 14
ACTIVE_LOG_MAX_MB = 200
EDITOR_AGE_DAYS = 60
TRASH_DAY_CHOICES = (0, 7, 30)      # file manager and desktop trash; 0 = everything
TRASH_DEFAULT_DAYS = 0
MAIL_TRASH_DAY_CHOICES = (7, 30, 90)
MAIL_TRASH_DEFAULT_DAYS = 30
BACKUP_AGE_DAYS = 30
PUBLIC_ARCHIVE_MIN_MB = 50
MYSQL_BLOAT_MIN_MB = 50
MYSQL_TABLE_OVERHEAD_MB = 6
MYSQL_MIN_FREE_MB = 3072
BACKUP_ROOT = '/root/storage-clean-backups'

UNSAFE_TARGETS = {'/', '/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/lib64', '/proc', '/root', '/run', '/sbin',
                  '/srv', '/sys', '/usr', '/var', '/opt', '/tmp', '/usr/local', '/var/lib', '/var/log',
                  '/usr/local/CyberCP', '/usr/local/lsws', '/var/lib/mysql', '/home/vmail'}


class CleanError(ValueError):
    pass


def run(argv, runner=subprocess.run, timeout=3600, env=None, input=None):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout, env=env, input=input)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


def have(binary):
    return shutil.which(binary) is not None


# ----------------------------------------------------------------------------- guarded file operations

def path_is_sane(path):
    if not isinstance(path, str) or not path.startswith('/') or '\x00' in path:
        return False
    if '..' in path.split('/'):
        return False
    normal = os.path.normpath(path)
    if normal in UNSAFE_TARGETS or re.match(r'^/home/[^/]+$', normal):
        return False
    return True


def safe_rm(path, dry_run=False):
    if not path_is_sane(path):
        raise CleanError('Refusing unsafe path %s' % path)
    if not os.path.lexists(path):
        return 0
    size = tree_kb(path)
    if dry_run:
        return size
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.unlink(path)
    return size


def safe_truncate(path, dry_run=False):
    if not path_is_sane(path) or not os.path.isfile(path) or os.path.islink(path):
        raise CleanError('Refusing to truncate %s' % path)
    size = os.lstat(path).st_size // 1024
    if not dry_run:
        with open(path, 'r+b') as handle:
            handle.truncate(0)
    return size


def tree_kb(path, same_device=True):
    """Disk usage of a path in KB (allocated blocks, no symlink following, one filesystem)."""
    try:
        info = os.lstat(path)
    except OSError:
        return 0
    if not os.path.isdir(path) or os.path.islink(path):
        return info.st_blocks // 2
    device, total = info.st_dev, info.st_blocks // 2
    for current, dirs, files in os.walk(path):
        kept = []
        for name in dirs:
            try:
                sub = os.lstat(os.path.join(current, name))
            except OSError:
                continue
            if same_device and sub.st_dev != device:
                continue
            total += sub.st_blocks // 2
            kept.append(name)
        dirs[:] = kept
        for name in files:
            try:
                total += os.lstat(os.path.join(current, name)).st_blocks // 2
            except OSError:
                pass
    return total


def old_files(roots, days, patterns=('*',), max_depth=None, exclude=()):
    """Yield (path, kb) for regular files older than `days` whose name matches a pattern."""
    cutoff = time.time() - days * 86400
    for root in roots:
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip('/').count('/')
        device = os.lstat(root).st_dev
        for current, dirs, files in os.walk(root):
            if max_depth is not None and current.rstrip('/').count('/') - base_depth >= max_depth:
                dirs[:] = []
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(current, d))
                       and _same_device(os.path.join(current, d), device)
                       and not any(fnmatch.fnmatch(d, e) for e in exclude)]
            for name in files:
                if not any(fnmatch.fnmatch(name, p) for p in patterns):
                    continue
                if any(fnmatch.fnmatch(name, e) for e in exclude):
                    continue
                path = os.path.join(current, name)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                if os.path.islink(path) or not os.path.isfile(path) or info.st_mtime > cutoff:
                    continue
                yield path, info.st_blocks // 2


def _same_device(path, device):
    try:
        return os.lstat(path).st_dev == device
    except OSError:
        return False


def delete_files(entries, dry_run=False):
    count = kb = 0
    for path, size in entries:
        if not path_is_sane(path):
            continue
        if not dry_run:
            try:
                os.unlink(path)
            except OSError:
                continue
        count += 1
        kb += size
    return count, kb


# ----------------------------------------------------------------------------- discovery

SESSION_DIRS = ('/var/lib/lsphp/session', '/var/lib/php/session', '/var/lib/php/sessions', '/var/lib/php5/sessions',
                '/var/lib/php7/sessions', '/var/opt/remi/php*/lib/php/session', '/opt/alt/php*/var/lib/php/session',
                '/usr/local/lsws/*/tmp/sess')
WEBLOG_DIRS = ('/usr/local/lsws/logs', '/usr/local/lsws/admin/logs', '/var/log/httpd', '/var/log/apache2',
               '/var/log/nginx', '/var/log/php-fpm')
ACTIVE_LOG_CANDIDATES = ('/home/cyberpanel/error-logs.txt', '/usr/local/lsws/logs/error.log',
                         '/usr/local/lsws/logs/stderr.log', '/var/log/messages', '/var/log/syslog', '/var/log/secure',
                         '/var/log/auth.log', '/var/log/maillog', '/var/log/mail.log', '/var/log/btmp', '/var/log/wtmp')
CACHE_SUBDIRS = ('.npm/_cacache', '.cache/yarn', '.cache/pip', '.cache/composer', '.composer/cache', '.cache/puppeteer',
                 '.cache/typescript', '.cache/ms-playwright', '.cargo/registry/cache', '.gradle/caches',
                 '.m2/repository/.cache')


def expand(patterns):
    out = []
    for pattern in patterns:
        out.extend(p for p in sorted(glob.glob(pattern)) if os.path.isdir(p))
    return out


def user_homes(passwd='/etc/passwd'):
    homes = ['/root']
    try:
        with open(passwd) as handle:
            for line in handle:
                parts = line.split(':')
                if len(parts) > 5 and parts[2].isdigit() and int(parts[2]) >= 1000 and parts[5].startswith('/home/'):
                    homes.append(parts[5])
    except OSError:
        pass
    return [h for h in dict.fromkeys(homes) if os.path.isdir(h)]


def site_homes():
    return [h for h in sorted(glob.glob('/home/*')) if os.path.isdir(h) and not os.path.islink(h)
            and os.path.basename(h) not in ('vmail', 'backup', 'cyberpanel', 'docker')]


def docker_is_absent(runner=subprocess.run):
    if any(have(b) for b in ('docker', 'dockerd', 'containerd')):
        return False
    code, out = run(['systemctl', 'list-unit-files', 'docker.service'], runner, timeout=30)
    if 'docker.service' in out:
        return False
    if have('rpm'):
        code, out = run(['rpm', '-qa'], runner, timeout=120)
        if re.search(r'^docker', out, re.M | re.I):
            return False
    return True


# ----------------------------------------------------------------------------- categories

def _item(path, kb, note=''):
    return {'path': path, 'kb': kb, 'note': note}


def probe_php_sessions():
    files = list(old_files(expand(SESSION_DIRS), SESSION_AGE_DAYS, ('sess_*',)))
    return {'kb': sum(k for _, k in files), 'count': len(files), 'items': []}


def run_php_sessions(dry_run, log, items=None, **_):
    count, kb = delete_files(old_files(expand(SESSION_DIRS), SESSION_AGE_DAYS, ('sess_*',)), dry_run)
    log('PHP sessions: %d files older than %dd (%s)' % (count, SESSION_AGE_DAYS, human(kb)))
    return kb


PKG_CACHE_DIRS = ('/var/cache/dnf', '/var/cache/yum', '/var/cache/apt/archives')


def probe_pkg_cache():
    return {'kb': sum(tree_kb(d) for d in PKG_CACHE_DIRS if os.path.isdir(d)), 'items': []}


def run_pkg_cache(dry_run, log, runner=subprocess.run, **_):
    before = probe_pkg_cache()['kb']
    if dry_run:
        return before
    if have('dnf'):
        run(['dnf', 'clean', 'all'], runner)
    elif have('yum'):
        run(['yum', 'clean', 'all'], runner)
    elif have('apt-get'):
        run(['apt-get', 'clean'], runner)
    freed = before - probe_pkg_cache()['kb']
    log('package cache cleaned (%s)' % human(freed))
    return freed


def probe_journal():
    if not os.path.isdir('/var/log/journal'):
        return {'kb': 0, 'items': [], 'note': 'journal is kept in RAM'}
    return {'kb': tree_kb('/var/log/journal'), 'items': [], 'note': 'vacuumed to %d days' % ROTATED_LOG_AGE_DAYS}


def run_journal(dry_run, log, runner=subprocess.run, **_):
    if not os.path.isdir('/var/log/journal') or dry_run:
        return 0
    before = tree_kb('/var/log/journal')
    run(['journalctl', '--vacuum-time=%dd' % ROTATED_LOG_AGE_DAYS], runner)
    freed = before - tree_kb('/var/log/journal')
    log('journal vacuumed (%s)' % human(freed))
    return freed


ROTATED_PATTERNS = ('*.gz', '*.xz', '*.bz2', '*.old', '*.[0-9]', '*-20[0-9][0-9][0-9][0-9][0-9][0-9]')


def probe_rotated_logs():
    files = list(old_files(['/var/log'], ROTATED_LOG_AGE_DAYS, ROTATED_PATTERNS, exclude=('journal',)))
    return {'kb': sum(k for _, k in files), 'count': len(files), 'items': []}


def run_rotated_logs(dry_run, log, **_):
    count, kb = delete_files(old_files(['/var/log'], ROTATED_LOG_AGE_DAYS, ROTATED_PATTERNS, exclude=('journal',)),
                             dry_run)
    log('rotated system logs: %d files (%s)' % (count, human(kb)))
    return kb


WEBLOG_PATTERNS = ('*.log.*', '*.gz', '*_log-*', '*.[0-9]')


def probe_web_logs():
    files = list(old_files([d for d in WEBLOG_DIRS if os.path.isdir(d)], ROTATED_LOG_AGE_DAYS, WEBLOG_PATTERNS))
    return {'kb': sum(k for _, k in files), 'count': len(files), 'items': []}


def run_web_logs(dry_run, log, **_):
    count, kb = delete_files(old_files([d for d in WEBLOG_DIRS if os.path.isdir(d)], ROTATED_LOG_AGE_DAYS,
                                       WEBLOG_PATTERNS), dry_run)
    log('rotated web server logs: %d files (%s)' % (count, human(kb)))
    return kb


def big_logs():
    candidates = list(ACTIVE_LOG_CANDIDATES)
    for home in site_homes():
        for current, dirs, files in os.walk(home):
            if current.rstrip('/').count('/') - home.count('/') >= 3:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d not in ('.trash', 'mail', '.cp-wp-snapshots', 'node_modules')]
            for name in files:
                if name.endswith('.log') or name in ('server.log', 'error_log', 'debug.log'):
                    candidates.append(os.path.join(current, name))
    found = []
    for path in candidates:
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if os.path.isfile(path) and not os.path.islink(path) and info.st_size >= ACTIVE_LOG_MAX_MB * 1048576:
            found.append(_item(path, info.st_blocks // 2, 'truncated to 0 bytes, not deleted'))
    return found


def probe_big_logs():
    items = big_logs()
    return {'kb': sum(i['kb'] for i in items), 'items': items}


def run_big_logs(dry_run, log, items=None, **_):
    allowed = {i['path'] for i in big_logs()}
    total = 0
    for path in (items or allowed):
        if path not in allowed:
            continue
        kb = safe_truncate(path, dry_run)
        log('truncated %s (%s)' % (path, human(kb)))
        total += kb
    return total


def probe_panel_tmp():
    files = list(old_files(['/usr/local/CyberCP/tmp'], ROTATED_LOG_AGE_DAYS))
    stale = [_item(d, tree_kb(d), 'stale copy') for d in sorted(glob.glob('/usr/local/CyberCP/public/imunifyav.old.*'))]
    return {'kb': sum(k for _, k in files) + sum(i['kb'] for i in stale), 'count': len(files), 'items': stale}


def run_panel_tmp(dry_run, log, **_):
    count, kb = delete_files(old_files(['/usr/local/CyberCP/tmp'], ROTATED_LOG_AGE_DAYS), dry_run)
    for path in sorted(glob.glob('/usr/local/CyberCP/public/imunifyav.old.*')):
        kb += safe_rm(path, dry_run)
    log('IndiansCloud temporary files and stale copies (%s)' % human(kb))
    return kb


def _superseded_sigs():
    base = '/var/imunify360/files/sigs'
    current = os.path.realpath(os.path.join(base, 'v1'))
    if not os.path.isdir(base) or not os.path.exists(current):
        return []
    return [d for d in sorted(glob.glob(os.path.join(base, 'v1_*')))
            if os.path.isdir(d) and os.path.realpath(d) != current]


def probe_av_sigs():
    items = [_item(d, tree_kb(d)) for d in _superseded_sigs()]
    return {'kb': sum(i['kb'] for i in items), 'items': items}


def run_av_sigs(dry_run, log, **_):
    kb = sum(safe_rm(d, dry_run) for d in _superseded_sigs())
    log('superseded antivirus signature sets (%s)' % human(kb))
    return kb


def _docker_size_kb(text):
    match = re.match(r'^\s*([\d.]+)\s*([kKMGT]?B)', text or '')
    if not match:
        return 0
    return int(float(match.group(1)) * {'B': 1 / 1024, 'kB': 1, 'KB': 1, 'MB': 1024, 'GB': 1048576,
                                        'TB': 1073741824}.get(match.group(2), 0))


def probe_docker(runner=subprocess.run):
    if os.path.isdir('/var/lib/docker') and docker_is_absent(runner):
        return {'kb': tree_kb('/var/lib/docker'), 'items': [], 'note': 'Docker is not installed: /var/lib/docker is orphaned'}
    if not have('docker'):
        return {'kb': 0, 'items': []}
    # Only data no container can use: dangling images and the build cache. Stopped containers,
    # volumes and tagged images are left alone (they may hold data someone wants).
    code, out = run(['docker', 'images', '--filter', 'dangling=true', '--format', '{{.Size}}'], runner, timeout=120)
    dangling = sum(_docker_size_kb(line) for line in out.splitlines())
    code, out = run(['docker', 'system', 'df', '--format', '{{.Type}}|{{.Reclaimable}}'], runner, timeout=120)
    cache = sum(_docker_size_kb(line.split('|', 1)[1]) for line in out.splitlines()
                if line.startswith('Build Cache|'))
    return {'kb': dangling + cache, 'items': [], 'note': 'Docker is installed: only dangling images and build cache'}


def run_docker(dry_run, log, runner=subprocess.run, **_):
    before = probe_docker(runner)['kb']
    if dry_run:
        return before
    if os.path.isdir('/var/lib/docker') and docker_is_absent(runner):
        freed = safe_rm('/var/lib/docker')
        log('removed orphaned /var/lib/docker (%s)' % human(freed))
        return freed
    if have('docker'):
        run(['docker', 'image', 'prune', '-f'], runner)
        run(['docker', 'builder', 'prune', '-f'], runner)
        log('removed dangling Docker images and build cache')
    return before


def _dev_caches():
    return [p for home in user_homes() for p in (os.path.join(home, s) for s in CACHE_SUBDIRS) if os.path.isdir(p)]


def probe_dev_caches():
    items = [_item(p, tree_kb(p)) for p in _dev_caches()]
    return {'kb': sum(i['kb'] for i in items), 'items': items}


def run_dev_caches(dry_run, log, **_):
    kb = sum(safe_rm(p, dry_run) for p in _dev_caches())
    log('build tool caches (%s)' % human(kb))
    return kb


def probe_old_kernels(runner=subprocess.run):
    running = os.uname().release
    if have('rpm'):
        code, out = run(['rpm', '-q', 'kernel'], runner, timeout=60)
        others = [l for l in out.splitlines() if l.strip() and running not in l and 'not installed' not in l]
    elif have('dpkg'):
        code, out = run(['dpkg-query', '-W', '-f', '${Package} ${Status}\n', 'linux-image-*'], runner, timeout=60)
        others = [l.split()[0] for l in out.splitlines() if 'installed' in l and running not in l and 'generic' in l]
    else:
        others = []
    keep_extra = 1  # the running kernel plus one fallback
    removable = others[:-keep_extra] if len(others) > keep_extra else []
    return {'kb': len(removable) * 150 * 1024, 'items': [_item(k, 150 * 1024, 'estimate') for k in removable],
            'note': 'running kernel %s and one fallback are kept' % running}


def run_old_kernels(dry_run, log, runner=subprocess.run, **_):
    estimate = probe_old_kernels(runner)['kb']
    if dry_run or not estimate:
        return estimate
    if have('dnf'):
        run(['dnf', '-y', 'remove', '--oldinstallonly', '--setopt', 'installonly_limit=2'], runner)
    elif have('apt-get'):
        run(['apt-get', '-y', 'autoremove', '--purge'], runner)
    log('old kernels removed by the package manager (running kernel kept)')
    return estimate


def _source_trees():
    paths = [p for p in ('/usr/lib/debug', '/usr/src/debug', '/usr/share/doc/HTML') if os.path.isdir(p)]
    for pattern in ('/usr/src/Python-*', '/opt/Python-*', '/usr/local/src/Python-*', '/usr/src/openssl-*',
                    '/usr/src/node-v*'):
        paths += [p for p in sorted(glob.glob(pattern)) if os.path.isdir(p) and os.path.isfile(os.path.join(p, 'Makefile'))]
    return paths


def probe_src_debug():
    items = [_item(p, tree_kb(p), 'debug symbols' if 'debug' in p else 'leftover source build tree')
             for p in _source_trees()]
    return {'kb': sum(i['kb'] for i in items), 'items': items}


def run_src_debug(dry_run, log, items=None, **_):
    allowed = set(_source_trees())
    kb = 0
    for path in (items or allowed):
        if path in allowed:
            kb += safe_rm(path, dry_run)
            log('removed %s' % path)
    return kb


def _editor_servers():
    cutoff = time.time() - EDITOR_AGE_DAYS * 86400
    out = []
    for home in ['/root'] + sorted(glob.glob('/home/*')):
        for sub in ('.vscode-server/bin', '.cursor-server/bin', '.vscode-server/cli/servers'):
            base = os.path.join(home, sub)
            if not os.path.isdir(base):
                continue
            for version in sorted(os.listdir(base)):
                path = os.path.join(base, version)
                if os.path.isdir(path) and not os.path.islink(path) and os.lstat(path).st_mtime < cutoff:
                    out.append(path)
    return out


def probe_editor_servers():
    items = [_item(p, tree_kb(p)) for p in _editor_servers()]
    return {'kb': sum(i['kb'] for i in items), 'items': items}


def run_editor_servers(dry_run, log, **_):
    kb = sum(safe_rm(p, dry_run) for p in _editor_servers())
    log('stale editor remote servers (%s)' % human(kb))
    return kb


TMP_EXCLUDE = ('*.sock', 'systemd-private-*', '.X11-unix', '.ICE-unix', 'lshttpd', 'cp-*', '.cp-*')


def probe_tmp_files():
    files = list(old_files(['/tmp', '/var/tmp'], TMP_AGE_DAYS, exclude=TMP_EXCLUDE))
    return {'kb': sum(k for _, k in files), 'count': len(files), 'items': []}


def run_tmp_files(dry_run, log, **_):
    count, kb = delete_files(old_files(['/tmp', '/var/tmp'], TMP_AGE_DAYS, exclude=TMP_EXCLUDE), dry_run)
    log('temporary files older than %dd: %d (%s)' % (TMP_AGE_DAYS, count, human(kb)))
    return kb


def _core_dumps():
    files = []
    if os.path.isdir('/var/lib/systemd/coredump'):
        files += [(p, k) for p, k in old_files(['/var/lib/systemd/coredump'], 0)]
    for root in ('/', '/root', '/home'):
        for path in glob.glob(os.path.join(root, 'core.[0-9]*')):
            if os.path.isfile(path) and not os.path.islink(path):
                files.append((path, os.lstat(path).st_blocks // 2))
    return files


def probe_core_dumps():
    files = _core_dumps()
    return {'kb': sum(k for _, k in files), 'count': len(files), 'items': [_item(p, k) for p, k in files[:50]]}


def run_core_dumps(dry_run, log, **_):
    count, kb = delete_files(_core_dumps(), dry_run)
    log('core dumps: %d (%s)' % (count, human(kb)))
    return kb


BACKUP_PATTERNS = ('*.tar.gz', '*.tar', '*.tgz', '*.zip', '*.sql', '*.sql.gz')


def _old_backups():
    roots = ['/home/backup'] + [os.path.join(h, 'backup') for h in site_homes()]
    return [_item(p, k, 'older than %d days' % BACKUP_AGE_DAYS)
            for p, k in old_files([r for r in roots if os.path.isdir(r)], BACKUP_AGE_DAYS, BACKUP_PATTERNS, max_depth=3)]


def probe_old_backups():
    items = _old_backups()
    return {'kb': sum(i['kb'] for i in items), 'items': items}


def run_old_backups(dry_run, log, items=None, **_):
    allowed = {i['path']: i['kb'] for i in _old_backups()}
    kb = 0
    for path in (items or []):  # never "all": each backup must be picked
        if path in allowed:
            kb += safe_rm(path, dry_run)
            log('removed backup %s' % path)
    return kb


ARCHIVE_PATTERNS = ('*.zip', '*.tar', '*.tar.gz', '*.tgz', '*.rar', '*.7z', '*.sql', '*.sql.gz', '*.bak', '*.wpress')


def _public_archives():
    items = []
    for home in site_homes():
        docroot = os.path.join(home, 'public_html')
        for path, kb in old_files([docroot], 0, ARCHIVE_PATTERNS, max_depth=3):
            if kb >= PUBLIC_ARCHIVE_MIN_MB * 1024:
                items.append(_item(path, kb, 'publicly downloadable from the website'))
    return items


def probe_public_archives():
    items = _public_archives()
    return {'kb': sum(i['kb'] for i in items), 'items': items}


def run_public_archives(dry_run, log, items=None, **_):
    allowed = {i['path'] for i in _public_archives()}
    kb = 0
    for path in (items or []):  # never "all": each archive must be picked
        if path in allowed:
            kb += safe_rm(path, dry_run)
            log('removed public archive %s' % path)
    return kb


def _claude_versions():
    """Old Claude Code CLI versions; the newest and the one ~/.local/bin/claude points to are kept."""
    items = []
    for home in user_homes():
        base = os.path.join(home, '.local/share/claude/versions')
        if not os.path.isdir(base):
            continue
        versions = sorted((v for v in os.listdir(base) if re.match(r'^\d+(\.\d+)+$', v)),
                          key=lambda v: [int(x) for x in v.split('.')])
        active = os.path.realpath(os.path.join(home, '.local/bin/claude'))
        for version in versions[:-1]:
            path = os.path.join(base, version)
            if os.path.realpath(path) != active and not active.startswith(os.path.realpath(path) + os.sep):
                items.append(_item(path, tree_kb(path), 'superseded by %s' % versions[-1]))
    return items


def probe_cli_versions():
    items = _claude_versions()
    return {'kb': sum(i['kb'] for i in items), 'items': items}


def run_cli_versions(dry_run, log, **_):
    kb = 0
    for item in _claude_versions():
        kb += safe_rm(item['path'], dry_run)
        log('removed %s' % item['path'])
    return kb


# ----------------------------------------------------------------------------- Trash
#
# Three kinds of trash, all 'review' (somebody deleted these on purpose and may want them back):
#   trash        /home/<site>/.trash, filled by the file manager; the Trash table remembers where each item came from
#   mail_trash   Trash/Junk folders of every mailbox, expunged through Dovecot (never by deleting maildir files)
#   desktop_trash  ~/.local/share/Trash (freedesktop.org trash used by gio, trash-cli and desktop tools)
#
# Deletion runs as root but never follows a symlink: every directory is opened relative to its parent with
# O_NOFOLLOW, its inode is re-checked after opening, entries are removed with unlink/rmdir relative to that
# descriptor, and nothing on another filesystem is entered. A symlink inside a trash is removed as a link; its
# target is never touched.

TRASH_MAX_DEPTH = 400
TRASH_TOP_SITES = 20
MAIL_ROOT = '/home/vmail'
MAIL_TRASH_FOLDERS = ('Trash', 'Junk', 'Spam', 'Deleted Items', 'Deleted Messages', 'Junk E-mail')
_EMAIL_PART = re.compile(r'^[A-Za-z0-9._%+=-]{1,128}$')
_DOMAIN = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)


def day_choices(cid):
    """Age choices (days) a category offers, or None."""
    return {'trash': TRASH_DAY_CHOICES, 'desktop_trash': TRASH_DAY_CHOICES,
            'mail_trash': MAIL_TRASH_DAY_CHOICES}.get(cid)


def _days(cid, days):
    choices = day_choices(cid)
    default = MAIL_TRASH_DEFAULT_DAYS if cid == 'mail_trash' else TRASH_DEFAULT_DAYS
    if days is None:
        return default
    if isinstance(days, bool) or days not in choices:
        raise CleanError('Age must be one of %s days.' % ', '.join(str(c) for c in choices))
    return days


def open_dir_chain(base, parts):
    """fd of base/parts[0]/parts[1]/..., refusing a symlink or another filesystem at every step."""
    if not os.path.isabs(base) or os.path.islink(base):
        raise CleanError('Refusing %s: not a real directory.' % base)
    fd = os.open(base, _DIR_FLAGS)
    try:
        device = os.fstat(fd).st_dev
        for part in parts:
            if not part or '/' in part or part in ('.', '..'):
                raise CleanError('Invalid path component %r.' % part)
            info = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise CleanError('Refusing %s/%s: symlink or not a directory.' % (base, part))
            if info.st_dev != device:
                raise CleanError('Refusing %s/%s: on another filesystem.' % (base, part))
            child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                os.close(child)
                raise CleanError('Refusing %s/%s: changed while opening.' % (base, part))
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def remove_at(parent_fd, name, device, depth=0):
    """Remove parent_fd/name (file, link or whole tree) without following symlinks. Returns KB removed."""
    if not name or '/' in name or name in ('.', '..'):
        raise CleanError('Invalid name %r.' % name)
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):  # regular file, symlink (the link only), socket, fifo...
        os.unlink(name, dir_fd=parent_fd)
        return info.st_blocks // 2
    if info.st_dev != device:
        raise CleanError('%s is a mount point; left alone.' % name)
    if depth >= TRASH_MAX_DEPTH:
        raise CleanError('%s is nested too deeply; left alone.' % name)
    fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    kb = 0
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise CleanError('%s changed while opening; left alone.' % name)
        for child in os.listdir(fd):
            kb += remove_at(fd, child, device, depth + 1)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent_fd)
    return kb + info.st_blocks // 2


def _entry_kb(path):
    return tree_kb(path)


def trashed_at(info):
    """When an item reached the trash: its inode change time (set by the rename into the trash; mv keeps the
    modification time). Patched in the tests, where ctime cannot be set."""
    return info.st_ctime


def _age_buckets(entries, choices, now=None):
    """entries: [(stamp, kb, count)] -> {str(days): {'kb', 'count'}} for every choice."""
    now = now or time.time()
    out = {}
    for days in choices:
        cutoff = now - days * 86400
        chosen = [e for e in entries if days == 0 or e[0] <= cutoff]
        out[str(days)] = {'kb': sum(e[1] for e in chosen), 'count': sum(e[2] for e in chosen)}
    return out


def _category(cid, items, entries, note):
    days = _days(cid, None)
    buckets = _age_buckets(entries, day_choices(cid))
    oldest = min((e[0] for e in entries), default=None)
    return {'kb': buckets[str(days)]['kb'], 'count': buckets[str(days)]['count'], 'oldest': int(oldest) if oldest else None,
            'items': items, 'note': note, 'choices': list(day_choices(cid)), 'days': days, 'by_days': buckets}


# --- file manager trash (/home/<site>/.trash) -----------------------------------------------------------------

def quote_trash_name(name):
    """How filemanager.py stores Trash.fileName (returnPathEnclosed: a single-quoted shell word)."""
    return "'" + str(name).replace("'", "'\"'\"'") + "'"


def unquote_trash_name(value):
    value = str(value or '')
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1].replace("'\"'\"'", "'")
    return value


class TrashRows:
    """The file manager's Trash table (filemanager.models.Trash). Replaced by a fake in the tests."""

    def rows(self, domain):
        from universalAddons import django_env
        django_env.setup()
        from filemanager.models import Trash
        return list(Trash.objects.filter(website__domain=domain).values_list('pk', 'fileName'))

    def delete(self, pks):
        from filemanager.models import Trash
        Trash.objects.filter(pk__in=list(pks)).delete()


def sync_trash_rows(domain, remaining, db, dry_run=False):
    """Drop Trash rows whose item is no longer in the site's .trash. Returns the number of rows."""
    stale = [pk for pk, name in db.rows(domain) if unquote_trash_name(name) not in remaining]
    if stale and not dry_run:
        db.delete(stale)
    return len(stale)


def fm_trash_entries(home):
    """[(name, stamp, kb)] for the top-level items of home/.trash. stamp is the inode change time, which the
    file manager's mv into .trash sets (mv keeps the modification time of the file itself)."""
    fd = open_dir_chain(home, ['.trash'])
    try:
        names = sorted(os.listdir(fd))
        out = []
        for name in names:
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError:
                continue
            out.append((name, trashed_at(info), _entry_kb(os.path.join(home, '.trash', name))))
        return out
    finally:
        os.close(fd)


def _fm_trash_sites():
    sites = []
    for home in site_homes():
        if not os.path.isdir(os.path.join(home, '.trash')) or os.path.islink(os.path.join(home, '.trash')):
            continue
        try:
            entries = fm_trash_entries(home)
        except (OSError, CleanError):
            continue
        if entries:
            sites.append((home, entries))
    return sites


def probe_fm_trash():
    sites = _fm_trash_sites()
    entries = [(stamp, kb, 1) for _, items in sites for _, stamp, kb in items]
    per_site = []
    for home, items in sites:
        oldest = min(s for _, s, _ in items)
        per_site.append(_item(os.path.join(home, '.trash'), sum(k for _, _, k in items), '%d item(s), oldest %s' % (
            len(items), time.strftime('%Y-%m-%d', time.localtime(oldest)))))
    per_site.sort(key=lambda i: -i['kb'])
    note = 'Items the file manager moved to each website\'s .trash; their restore records are removed too.'
    if len(per_site) > TRASH_TOP_SITES:
        note += ' %d websites have trash; the %d biggest are listed.' % (len(per_site), TRASH_TOP_SITES)
    return _category('trash', per_site[:TRASH_TOP_SITES], entries, note)


def clean_fm_trash(home, days, dry_run, log, db, now=None):
    """Empty home/.trash of items older than `days` (0 = all) and drop their Trash rows. Returns KB freed."""
    domain = os.path.basename(home.rstrip('/'))
    trash = os.path.join(home, '.trash')
    if not path_is_sane(trash):
        raise CleanError('Refusing unsafe path %s' % trash)
    cutoff = (now or time.time()) - days * 86400
    fd = open_dir_chain(home, ['.trash'])
    freed = removed = 0
    try:
        device = os.fstat(fd).st_dev
        for name in sorted(os.listdir(fd)):
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError:
                continue
            if days and trashed_at(info) > cutoff:
                continue
            if dry_run:
                freed += _entry_kb(os.path.join(trash, name))
                removed += 1
                continue
            try:
                freed += remove_at(fd, name, device)
                removed += 1
            except (OSError, CleanError) as exc:
                log('%s/%s: %s' % (trash, name, exc))
        remaining = set(os.listdir(fd))
    finally:
        os.close(fd)
    try:
        if dry_run:
            # rows that would be orphaned once the chosen items are gone
            entries = {n: s for n, s, _ in fm_trash_entries(home)}
            remaining = {n for n, s in entries.items() if days and s > cutoff}
        rows = sync_trash_rows(domain, remaining, db, dry_run)
    except Exception as exc:  # the panel database being unavailable must not hide what was deleted
        rows = 0
        log('%s: could not update the file manager restore list: %s' % (domain, exc))
    log('%s%s: %d item(s), %s; %d restore record(s) removed' % (
        'would empty ' if dry_run else '', trash, removed, human(freed), rows))
    return freed


def run_fm_trash(dry_run, log, items=None, days=None, db=None, **_):
    days = _days('trash', days)
    db = db or TrashRows()
    homes = [h for h, _ in _fm_trash_sites()]
    if items:  # optional restriction to some websites (paths re-checked against discovery)
        wanted = set(items)
        homes = [h for h in homes if os.path.join(h, '.trash') in wanted]
    log('file manager trash: items %s' % ('of any age' if not days else 'trashed more than %d days ago' % days))
    total = 0
    for home in homes:
        try:
            total += clean_fm_trash(home, days, dry_run, log, db)
        except (OSError, CleanError) as exc:
            log('%s: skipped (%s)' % (home, exc))
    return total


# --- mailbox Trash / Junk -------------------------------------------------------------------------------------

def mail_trash_folders(root=None):
    """[(path, email, folder)] for Maildir/.<Trash|Junk|...> under /home/vmail/<domain>/<user>/Maildir."""
    root = root or MAIL_ROOT
    out = []
    for domain_dir in sorted(glob.glob(os.path.join(root, '*'))):
        domain = os.path.basename(domain_dir)
        if os.path.islink(domain_dir) or not os.path.isdir(domain_dir) or not _DOMAIN.match(domain):
            continue
        for user_dir in sorted(glob.glob(os.path.join(domain_dir, '*'))):
            user = os.path.basename(user_dir)
            maildir = os.path.join(user_dir, 'Maildir')
            if os.path.islink(user_dir) or os.path.islink(maildir) or not os.path.isdir(maildir) \
                    or not _EMAIL_PART.match(user):
                continue
            for folder in MAIL_TRASH_FOLDERS:
                path = os.path.join(maildir, '.' + folder)
                if os.path.isdir(path) and not os.path.islink(path):
                    out.append((path, '%s@%s' % (user, domain), folder))
    return out


def maildir_messages(path):
    """[(stamp, kb)] of the message files in cur/ and new/. stamp is ctime, which Dovecot uses as the
    maildir save date (what `savedbefore` compares)."""
    out = []
    for sub in ('cur', 'new'):
        folder = os.path.join(path, sub)
        if os.path.islink(folder) or not os.path.isdir(folder):
            continue
        for name in os.listdir(folder):
            try:
                info = os.lstat(os.path.join(folder, name))
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode):
                out.append((trashed_at(info), info.st_blocks // 2))
    return out


def probe_mail_trash(root=None):
    entries, items = [], []
    default = str(MAIL_TRASH_DEFAULT_DAYS)
    for path, email, folder in mail_trash_folders(root):
        messages = maildir_messages(path)
        if not messages:
            continue
        mine = [(s, k, 1) for s, k in messages]
        entries += mine
        buckets = _age_buckets(mine, MAIL_TRASH_DAY_CHOICES)
        oldest = min(s for s, _ in messages)
        item = _item(path, buckets[default]['kb'], '%s %s: %d message(s), oldest %s' % (
            email, folder, len(messages), time.strftime('%Y-%m-%d', time.localtime(oldest))))
        item['by_days'] = buckets
        items.append(item)
    items.sort(key=lambda i: -i['kb'])
    return _category('mail_trash', items, entries,
                     'Messages are expunged through Dovecot (doveadm expunge ... savedbefore), never deleted from '
                     'disk directly. Pick the mailboxes.')


def doveadm_expunge_argv(email, mailbox, days):
    if not isinstance(days, int) or isinstance(days, bool) or days < 1:
        raise CleanError('Mailbox trash needs an age of at least one day.')
    return ['doveadm', 'expunge', '-u', email, 'mailbox', mailbox, 'savedbefore', '%dd' % days]


def dovecot_mailbox_name(email, folder, runner=subprocess.run):
    """The Dovecot name of a maildir folder (e.g. 'INBOX.Trash' with the INBOX. namespace prefix)."""
    code, out = run(['doveadm', 'mailbox', 'list', '-u', email], runner, timeout=60)
    if code != 0:
        raise CleanError('doveadm mailbox list failed for %s: %s' % (email, out.strip()[-200:]))
    names = [line.strip() for line in out.splitlines() if line.strip()]
    for name in names:
        if name == folder:
            return name
    for name in names:
        if name.startswith('INBOX') and len(name) > 6 and name[6:] == folder and name[5] in './':
            return name
    raise CleanError('%s has no mailbox %s.' % (email, folder))


def run_mail_trash(dry_run, log, items=None, days=None, runner=subprocess.run, root=None, **_):
    days = _days('mail_trash', days)
    known = {p: (email, folder) for p, email, folder in mail_trash_folders(root)}
    chosen = [p for p in (items or []) if p in known]  # never "all": each mailbox must be picked
    if not chosen:
        log('no mailbox picked')
        return 0
    if not dry_run and not have('doveadm'):
        raise CleanError('doveadm is not installed; mailbox trash is only emptied through Dovecot.')
    cutoff = time.time() - days * 86400
    total = 0
    for path in chosen:
        email, folder = known[path]
        estimate = sum(k for s, k in maildir_messages(path) if s <= cutoff)
        if dry_run:
            log('would expunge %s %s older than %d days (%s)' % (email, folder, days, human(estimate)))
            total += estimate
            continue
        try:
            mailbox = dovecot_mailbox_name(email, folder, runner)
            before = sum(k for _, k in maildir_messages(path))
            code, out = run(doveadm_expunge_argv(email, mailbox, days), runner, timeout=1800)
            if code != 0:
                log('%s %s: doveadm expunge failed: %s' % (email, mailbox, out.strip()[-200:]))
                continue
            freed = max(0, before - sum(k for _, k in maildir_messages(path)))
            log('%s %s: expunged messages older than %d days (%s)' % (email, mailbox, days, human(freed)))
            total += freed
        except CleanError as exc:
            log('%s: %s' % (path, exc))
    return total


# --- desktop trash (~/.local/share/Trash) ---------------------------------------------------------------------

DESKTOP_TRASH_PARTS = ('.local', 'share', 'Trash')


def all_homes(passwd='/etc/passwd'):
    """Home directories of root, system users and website users that exist (desktop trash may be anywhere)."""
    homes = ['/root']
    try:
        with open(passwd) as handle:
            for line in handle:
                parts = line.strip().split(':')
                if len(parts) > 5 and parts[5].startswith('/') and parts[5] not in ('/', '/nonexistent'):
                    homes.append(os.path.normpath(parts[5]))
    except OSError:
        pass
    homes += site_homes()
    return [h for h in dict.fromkeys(homes) if os.path.isdir(h) and not os.path.islink(h)]


def _deletion_date(info_fd, name):
    """DeletionDate from info/<name>.trashinfo as epoch seconds, or None."""
    try:
        fd = os.open(name + '.trashinfo', os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), dir_fd=info_fd)
    except OSError:
        return None
    try:
        with os.fdopen(fd, 'r', errors='replace') as handle:
            text = handle.read(8192)
    except OSError:
        return None
    match = re.search(r'^DeletionDate=(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)', text, re.M)
    if not match:
        return None
    try:
        return time.mktime(time.strptime(match.group(1), '%Y-%m-%dT%H:%M:%S'))
    except (ValueError, OverflowError):
        return None


def desktop_trash_entries(home):
    """[(name, stamp, kb)] for files/<name> in home/.local/share/Trash (stamp from the .trashinfo)."""
    fd = open_dir_chain(home, list(DESKTOP_TRASH_PARTS) + ['files'])
    try:
        info_fd = None
        try:
            info_fd = open_dir_chain(home, list(DESKTOP_TRASH_PARTS) + ['info'])
        except (OSError, CleanError):
            pass
        out = []
        for name in sorted(os.listdir(fd)):
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError:
                continue
            stamp = _deletion_date(info_fd, name) if info_fd is not None else None
            out.append((name, stamp or trashed_at(info),
                        _entry_kb(os.path.join(home, *DESKTOP_TRASH_PARTS, 'files', name))))
        if info_fd is not None:
            os.close(info_fd)
        return out
    finally:
        os.close(fd)


def _desktop_trashes(homes=None):
    found = []
    for home in (homes if homes is not None else all_homes()):
        if not os.path.isdir(os.path.join(home, *DESKTOP_TRASH_PARTS, 'files')):
            continue
        try:
            entries = desktop_trash_entries(home)
        except (OSError, CleanError):
            continue
        if entries:
            found.append((home, entries))
    return found


def probe_desktop_trash(homes=None):
    found = _desktop_trashes(homes)
    entries = [(s, k, 1) for _, items in found for _, s, k in items]
    items = sorted((_item(os.path.join(home, *DESKTOP_TRASH_PARTS), sum(k for _, _, k in e), '%d item(s)' % len(e))
                    for home, e in found), key=lambda i: -i['kb'])
    return _category('desktop_trash', items[:TRASH_TOP_SITES], entries,
                     'Files deleted with gio, trash-cli or a desktop file manager for root and other users.')


def clean_desktop_trash(home, days, dry_run, log, now=None):
    cutoff = (now or time.time()) - days * 86400
    trash = os.path.join(home, *DESKTOP_TRASH_PARTS)
    if not path_is_sane(trash):
        raise CleanError('Refusing unsafe path %s' % trash)
    files_fd = open_dir_chain(home, list(DESKTOP_TRASH_PARTS) + ['files'])
    info_fd = None
    freed = removed = 0
    try:
        try:
            info_fd = open_dir_chain(home, list(DESKTOP_TRASH_PARTS) + ['info'])
        except (OSError, CleanError):
            info_fd = None
        device = os.fstat(files_fd).st_dev
        for name in sorted(os.listdir(files_fd)):
            try:
                info = os.stat(name, dir_fd=files_fd, follow_symlinks=False)
            except OSError:
                continue
            stamp = (_deletion_date(info_fd, name) if info_fd is not None else None) or trashed_at(info)
            if days and stamp > cutoff:
                continue
            if dry_run:
                freed += _entry_kb(os.path.join(trash, 'files', name))
                removed += 1
                continue
            try:
                freed += remove_at(files_fd, name, device)
                removed += 1
                if info_fd is not None:
                    try:
                        os.unlink(name + '.trashinfo', dir_fd=info_fd)
                    except FileNotFoundError:
                        pass
            except (OSError, CleanError) as exc:
                log('%s/files/%s: %s' % (trash, name, exc))
    finally:
        os.close(files_fd)
        if info_fd is not None:
            os.close(info_fd)
    log('%s%s: %d item(s), %s' % ('would empty ' if dry_run else '', trash, removed, human(freed)))
    return freed


def run_desktop_trash(dry_run, log, items=None, days=None, homes=None, **_):
    days = _days('desktop_trash', days)
    total = 0
    for home, _entries in _desktop_trashes(homes):
        try:
            total += clean_desktop_trash(home, days, dry_run, log)
        except (OSError, CleanError) as exc:
            log('%s: skipped (%s)' % (home, exc))
    return total


# ----------------------------------------------------------------------------- MySQL / MariaDB

def mysql_argv(defaults_file):
    return ['mysql', '--defaults-extra-file=' + defaults_file, '-N', '-B']


def mysql_query(sql, defaults_file, runner=subprocess.run):
    code, out = run(mysql_argv(defaults_file) + ['-e', sql], runner, timeout=600)
    if code != 0:
        raise CleanError('MySQL error: %s' % out.strip()[-300:])
    return [line.split('\t') for line in out.splitlines() if line.strip()]


def mysql_datadir(defaults_file, runner=subprocess.run):
    rows = mysql_query('SELECT @@datadir', defaults_file, runner)
    return rows[0][0].rstrip('/') if rows else '/var/lib/mysql'


IDENT_RE = re.compile(r'^[A-Za-z0-9_$-]{1,64}$')


def mysql_bloat(defaults_file, runner=subprocess.run):
    """Tables whose .ibd file is much bigger than their live data (the script's reliable method)."""
    datadir = mysql_datadir(defaults_file, runner)
    sizes = {(r[0], r[1]): (int(float(r[2] or 0)), r[3]) for r in mysql_query(
        "SELECT table_schema, table_name, ROUND((data_length+index_length)/1048576), table_rows "
        "FROM information_schema.tables WHERE engine='InnoDB'", defaults_file, runner)}
    items, orphans = [], []
    for path in glob.glob(os.path.join(datadir, '*', '*.ibd')):
        db, table = os.path.basename(os.path.dirname(path)), os.path.basename(path)[:-4]
        if db in ('mysql', 'sys', 'performance_schema', 'information_schema'):
            continue
        file_mb = os.lstat(path).st_blocks // 2048
        if '#' in table:
            if file_mb >= 10:
                orphans.append(_item(path, file_mb * 1024, 'InnoDB temporary table left by an interrupted ALTER/OPTIMIZE'))
            continue
        if file_mb < MYSQL_BLOAT_MIN_MB or (db, table) not in sizes or not IDENT_RE.match(db) or not IDENT_RE.match(table):
            continue
        data_mb, rows = sizes[(db, table)]
        waste = file_mb - data_mb - MYSQL_TABLE_OVERHEAD_MB
        if waste >= MYSQL_BLOAT_MIN_MB:
            items.append({'path': '%s.%s' % (db, table), 'kb': waste * 1024, 'db': db, 'table': table,
                          'note': 'file %d MB, live data %d MB, ~%s rows' % (file_mb, data_mb, rows)})
    return sorted(items, key=lambda i: -i['kb']), sorted(orphans, key=lambda i: -i['kb'])


def rebuild_table(db, table, defaults_file, backup_dir, log, runner=subprocess.run, popen=subprocess.Popen,
                  datadir='/var/lib/mysql'):
    """Back up, verify, OPTIMIZE, compare row counts. Returns KB freed (0 if skipped)."""
    if not IDENT_RE.match(db) or not IDENT_RE.match(table):
        raise CleanError('Invalid table name.')
    quoted = '`%s`.`%s`' % (db, table)
    before_rows = mysql_query('SELECT COUNT(*) FROM %s' % quoted, defaults_file, runner)[0][0]
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    dump_path = os.path.join(backup_dir, '%s.%s.sql.gz' % (db, table))
    dump = popen(['mysqldump', '--defaults-extra-file=' + defaults_file, '--single-transaction', '--quick', db, table],
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with gzip.open(dump_path, 'wb') as output:
        shutil.copyfileobj(dump.stdout, output, 1 << 20)
    dump.wait()
    if dump.returncode != 0 or not _dump_verified(dump_path):
        log('%s: backup did not verify, NOT rebuilding' % quoted)
        return 0
    path = os.path.join(datadir, db, table + '.ibd')
    size_before = os.lstat(path).st_blocks // 2 if os.path.exists(path) else 0
    mysql_query('OPTIMIZE TABLE %s' % quoted, defaults_file, runner)
    after_rows = mysql_query('SELECT COUNT(*) FROM %s' % quoted, defaults_file, runner)[0][0]
    size_after = os.lstat(path).st_blocks // 2 if os.path.exists(path) else size_before
    if after_rows != before_rows:
        log('%s: ROW COUNT CHANGED (%s -> %s). Backup kept at %s' % (quoted, before_rows, after_rows, dump_path))
        return 0
    log('%s: %s -> %s, %s rows intact; backup %s' % (quoted, human(size_before), human(size_after), after_rows, dump_path))
    return max(0, size_before - size_after)


def _dump_verified(path):
    try:
        with gzip.open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            end = handle.tell()
            handle.seek(max(0, end - 4096))
            return b'Dump completed' in handle.read()
    except (OSError, EOFError):
        return False


def free_mb(path='/'):
    while not os.path.exists(path):
        path = os.path.dirname(path)
    return shutil.disk_usage(path).free // 1048576


# ----------------------------------------------------------------------------- registry

def human(kb):
    kb = float(kb or 0)
    for unit in ('KB', 'MB', 'GB', 'TB'):
        if kb < 1024 or unit == 'TB':
            return '%.0f %s' % (kb, unit) if unit in ('KB', 'MB') else '%.1f %s' % (kb, unit)
        kb /= 1024


CATEGORIES = [
    # id, title, risk, probe, run, per-item selection
    ('php_sessions', 'Stale PHP session files (>%dd)' % SESSION_AGE_DAYS, 'safe', probe_php_sessions, run_php_sessions, False),
    ('pkg_cache', 'Package manager cache (dnf/yum/apt)', 'safe', probe_pkg_cache, run_pkg_cache, False),
    ('journal', 'systemd journal (keep %d days)' % ROTATED_LOG_AGE_DAYS, 'safe', probe_journal, run_journal, False),
    ('rotated_logs', 'Rotated system logs (>%dd)' % ROTATED_LOG_AGE_DAYS, 'safe', probe_rotated_logs, run_rotated_logs, False),
    ('web_logs', 'Rotated web server logs (>%dd)' % ROTATED_LOG_AGE_DAYS, 'safe', probe_web_logs, run_web_logs, False),
    ('big_logs', 'Oversized active logs (>%d MB, truncated)' % ACTIVE_LOG_MAX_MB, 'review', probe_big_logs, run_big_logs, True),
    ('panel_tmp', 'IndiansCloud temporary files and stale copies', 'safe', probe_panel_tmp, run_panel_tmp, False),
    ('av_sigs', 'Superseded antivirus signature sets', 'safe', probe_av_sigs, run_av_sigs, False),
    ('docker', 'Docker: unused data / orphaned /var/lib/docker', 'review', probe_docker, run_docker, False),
    ('dev_caches', 'Build tool caches (npm, pip, composer, yarn...)', 'safe', probe_dev_caches, run_dev_caches, False),
    ('old_kernels', 'Old kernels (running kernel kept)', 'safe', probe_old_kernels, run_old_kernels, False),
    ('src_debug', 'Debug symbols and leftover source build trees', 'review', probe_src_debug, run_src_debug, True),
    ('editor_servers', 'Stale VS Code / Cursor remote servers (>%dd)' % EDITOR_AGE_DAYS, 'safe', probe_editor_servers, run_editor_servers, False),
    ('cli_versions', 'Old Claude Code CLI versions (newest kept)', 'safe', probe_cli_versions, run_cli_versions, False),
    ('tmp_files', 'Old files in /tmp and /var/tmp (>%dd)' % TMP_AGE_DAYS, 'safe', probe_tmp_files, run_tmp_files, False),
    ('core_dumps', 'Core dumps', 'safe', probe_core_dumps, run_core_dumps, False),
    ('trash', 'File manager trash (all websites)', 'review', probe_fm_trash, run_fm_trash, False),
    ('mail_trash', 'Mailbox Trash and Junk folders (old messages)', 'review', probe_mail_trash, run_mail_trash, True),
    ('desktop_trash', 'Desktop trash (~/.local/share/Trash) of root and users', 'review', probe_desktop_trash,
     run_desktop_trash, False),
    ('old_backups', 'Panel backup archives (>%dd)' % BACKUP_AGE_DAYS, 'review', probe_old_backups, run_old_backups, True),
    ('public_archives', 'Large archives inside public_html (also a security risk)', 'review', probe_public_archives,
     run_public_archives, True),
]
CATEGORY_IDS = [c[0] for c in CATEGORIES] + ['mysql_bloat', 'mysql_orphans']

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
import subprocess
import time

SESSION_AGE_DAYS = 7
ROTATED_LOG_AGE_DAYS = 30
TMP_AGE_DAYS = 14
ACTIVE_LOG_MAX_MB = 200
EDITOR_AGE_DAYS = 60
TRASH_AGE_DAYS = 30
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


def _old_trash():
    items = []
    for home in site_homes():
        trash = os.path.join(home, '.trash')
        files = list(old_files([trash], TRASH_AGE_DAYS))
        if files:
            items.append(_item(trash, sum(k for _, k in files), '%d files older than %d days' % (len(files), TRASH_AGE_DAYS)))
    return items


def probe_trash():
    items = _old_trash()
    return {'kb': sum(i['kb'] for i in items), 'items': items}


def run_trash(dry_run, log, items=None, **_):
    allowed = {i['path'] for i in _old_trash()}
    kb = 0
    for trash in (items or allowed):
        if trash in allowed:
            count, freed = delete_files(old_files([trash], TRASH_AGE_DAYS), dry_run)
            log('emptied %d old files from %s' % (count, trash))
            kb += freed
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
    ('trash', 'File manager trash (>%dd)' % TRASH_AGE_DAYS, 'review', probe_trash, run_trash, True),
    ('old_backups', 'Panel backup archives (>%dd)' % BACKUP_AGE_DAYS, 'review', probe_old_backups, run_old_backups, True),
    ('public_archives', 'Large archives inside public_html (also a security risk)', 'review', probe_public_archives,
     run_public_archives, True),
]
CATEGORY_IDS = [c[0] for c in CATEGORIES] + ['mysql_bloat', 'mysql_orphans']

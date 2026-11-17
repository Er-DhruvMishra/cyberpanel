"""Root-side Storage Cleaner actions (dispatched by universalAddons/runner.py)."""
import os
import shutil
import time

from universalAddons import jobs
from universalAddons.storage import service as st
from universalAddons.storage.service import CleanError

ANALYSIS_DIRS = ('/home', '/var', '/usr', '/root', '/opt', '/srv', '/boot')


def _defaults_file():
    try:
        from universalAddons.backupv2.service import mysql_defaults_file
        return mysql_defaults_file()
    except Exception:
        return None


def filesystems():
    seen, out = set(), []
    with open('/proc/mounts') as handle:
        for line in handle:
            device, mount, fstype = line.split()[:3]
            if not device.startswith('/dev/') or mount in seen or fstype in ('squashfs', 'iso9660'):
                continue
            seen.add(mount)
            usage = shutil.disk_usage(mount)
            out.append({'mount': mount, 'device': device, 'type': fstype, 'size_mb': usage.total // 1048576,
                        'used_mb': (usage.total - usage.free) // 1048576, 'free_mb': usage.free // 1048576})
    return out


def top_directories(min_mb=200, depth=2):
    """Biggest directories down to `depth` levels under the analysis roots (one filesystem)."""
    rows = []

    def walk(path, level):
        try:
            children = [os.path.join(path, n) for n in os.listdir(path)]
        except OSError:
            return
        for child in children:
            if os.path.islink(child) or not os.path.isdir(child) or child in ('/proc', '/sys', '/dev', '/run'):
                continue
            kb = st.tree_kb(child)
            if kb >= min_mb * 1024:
                rows.append({'path': child, 'kb': kb, 'level': level})
                if level < depth:
                    walk(child, level + 1)

    for root in ANALYSIS_DIRS:
        if os.path.isdir(root):
            rows.append({'path': root, 'kb': st.tree_kb(root), 'level': 0})
            walk(root, 1)
    return sorted(rows, key=lambda r: -r['kb'])


def large_files(min_mb=200, limit=40):
    found = []
    device = os.lstat('/').st_dev
    for current, dirs, files in os.walk('/'):
        dirs[:] = [d for d in dirs if st._same_device(os.path.join(current, d), device)
                   and os.path.join(current, d) not in ('/proc', '/sys', '/dev', '/run')]
        for name in files:
            path = os.path.join(current, name)
            try:
                info = os.lstat(path)
            except OSError:
                continue
            if info.st_size >= min_mb * 1048576 and not os.path.islink(path):
                found.append({'path': path, 'kb': info.st_blocks // 2, 'mtime': int(info.st_mtime)})
    return sorted(found, key=lambda f: -f['kb'])[:limit]


EXPLAIN = [
    ('/var/lib/mysql/ibdata1', 'MariaDB system tablespace. It never shrinks; reclaiming it needs a full dump and reload of all databases.'),
    ('/cyberpanel.swap', 'Swap file in use by the system. Keep it.'),
    ('/usr/.tempdisk', 'Disk image that backs /tmp. Keep it.'),
    ('/.git/objects/pack/', 'Git repository history. Run "git gc" inside the repository to compact it.'),
]


def explain(path):
    for needle, text in EXPLAIN:
        if needle in path:
            return text
    import fnmatch
    if '/public_html/' in path and any(fnmatch.fnmatch(os.path.basename(path), p) for p in st.ARCHIVE_PATTERNS):
        return 'Archive inside a website: downloadable by anyone who guesses the name.'
    if path.endswith('.ibd'):
        return 'MariaDB table file; see the InnoDB section for reclaimable space.'
    return ''


def scan_run(job_id):
    def categories(job):
        result = {}
        for cid, title, risk, probe, _, selectable in st.CATEGORIES:
            started = time.time()
            try:
                data = probe()
            except Exception as exc:
                data = {'kb': 0, 'items': [], 'error': str(exc)[:200]}
            data.update(id=cid, title=title, risk=risk, selectable=selectable)
            data['items'] = data.get('items', [])[:200]
            result[cid] = data
            job.log('%-48s %10s  (%.1fs)' % (title, st.human(data['kb']), time.time() - started))
        defaults = _defaults_file()
        if defaults:
            try:
                bloat, orphans = st.mysql_bloat(defaults)
                result['mysql_bloat'] = {'id': 'mysql_bloat', 'title': 'Bloated InnoDB tables (rebuilt with OPTIMIZE after a verified backup)',
                                         'risk': 'review', 'selectable': True, 'kb': sum(i['kb'] for i in bloat), 'items': bloat}
                result['mysql_orphans'] = {'id': 'mysql_orphans', 'title': 'Orphaned InnoDB temporary tables (#sql-*)',
                                           'risk': 'report', 'selectable': False, 'kb': sum(i['kb'] for i in orphans),
                                           'items': orphans, 'note': 'Left by an interrupted ALTER/OPTIMIZE. Check that the '
                                           'original table is complete before dropping one manually with '
                                           'DROP TABLE `#mysql50##sql-...` in that database.'}
                job.log('InnoDB: %s reclaimable in %d tables; %d orphaned temporary tables' % (
                    st.human(result['mysql_bloat']['kb']), len(bloat), len(orphans)))
            except Exception as exc:
                job.log('InnoDB analysis skipped: %s' % exc)
            finally:
                os.unlink(defaults)
        return result

    def usage(job):
        job.log('measuring directories (this can take a few minutes)…')
        files = large_files()
        for item in files:
            item['explain'] = explain(item['path'])
        return {'filesystems': filesystems(), 'directories': top_directories(), 'large_files': files}

    return jobs.run_job(job_id, [('Disk usage', usage), ('Reclaimable space', categories)])


def clean_run(job_id, selection, dry_run=False, options=None):
    """options: {category: {'days': n}} for the trash categories (see service.day_choices)."""
    options = options or {}
    stamp = time.strftime('%Y%m%d-%H%M%S')
    log_path = '/var/log/cyberpanel-storage-clean-%s.log' % stamp

    def body(job):
        def log(text):
            job.log(text)
            with open(log_path, 'a') as handle:
                handle.write('%s %s\n' % (time.strftime('%F %T'), text))
        before = st.free_mb('/')
        freed = {}
        table = {c[0]: c for c in st.CATEGORIES}
        for cid, choice in selection.items():
            if cid not in st.CATEGORY_IDS or choice in (None, False, []):
                continue
            try:
                if cid == 'mysql_bloat':
                    freed[cid] = _rebuild_tables(choice, dry_run, log, stamp)
                elif cid in table:
                    _, title, risk, probe, run_fn, selectable = table[cid]
                    items = choice if isinstance(choice, list) else None
                    log('== %s%s' % (title, ' (dry run)' if dry_run else ''))
                    extra = {'days': options[cid]['days']} if isinstance(options.get(cid), dict) and 'days' in options[cid] else {}
                    freed[cid] = run_fn(dry_run=dry_run, log=log, items=items, **extra)
            except Exception as exc:  # task isolation: one failure does not stop the rest
                log('ERROR in %s: %s' % (cid, exc))
        after = st.free_mb('/')
        log('free space: %s -> %s (log: %s)' % (st.human(before * 1024), st.human(after * 1024), log_path))
        return {'freed_kb': freed, 'free_before_mb': before, 'free_after_mb': after, 'log': log_path, 'dry_run': dry_run}

    return jobs.run_job(job_id, [('Reclaim space' + (' (dry run)' if dry_run else ''), body)])


def _rebuild_tables(choice, dry_run, log, stamp):
    if not isinstance(choice, list):
        raise CleanError('Pick the tables to rebuild.')
    defaults = _defaults_file()
    if not defaults:
        raise CleanError('MySQL is not reachable.')
    try:
        datadir = st.mysql_datadir(defaults)
        if st.free_mb(datadir) < st.MYSQL_MIN_FREE_MB:
            raise CleanError('Only %d MB free on the MySQL volume; %d MB are needed to rebuild safely.' % (
                st.free_mb(datadir), st.MYSQL_MIN_FREE_MB))
        bloat = {i['path']: i for i in st.mysql_bloat(defaults)[0]}
        total = 0
        for name in choice:
            item = bloat.get(name)
            if not item:
                log('%s: no longer bloated, skipped' % name)
                continue
            if dry_run:
                log('would rebuild %s (%s)' % (name, item['note']))
                total += item['kb']
                continue
            total += st.rebuild_table(item['db'], item['table'], defaults, os.path.join(st.BACKUP_ROOT, stamp), log,
                                      datadir=datadir)
        return total
    finally:
        os.unlink(defaults)


ACTIONS = {
    'scan': lambda: jobs.spawn('storage', 'scan_run', {}),
    'scan_run': scan_run,
    'clean': lambda selection, dry_run=False, options=None: jobs.spawn('storage', 'clean_run', dict(
        {'selection': selection, 'dry_run': bool(dry_run)}, **({'options': options} if options else {}))),
    'clean_run': clean_run,
    'job': lambda job_id: jobs.status(job_id),
    'filesystems': filesystems,
}

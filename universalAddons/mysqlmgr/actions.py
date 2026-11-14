"""Root-side MySQL Manager actions (dispatched by universalAddons/runner.py)."""
import glob
import os
import shutil
import subprocess
import time
from contextlib import contextmanager

from universalAddons import jobs
from universalAddons.mysqlmgr import service as sv
from universalAddons.mysqlmgr.service import GB, MySQLError

MY_CNF_CANDIDATES = ('/etc/my.cnf', '/etc/mysql/my.cnf')
MYSQLD_CANDIDATES = ('/usr/sbin/mariadbd', '/usr/sbin/mysqld', '/usr/libexec/mariadbd', '/usr/libexec/mysqld')
SERVICE_CANDIDATES = ('mariadb', 'mysqld', 'mysql')
STATE_DIR = os.environ.get('UA_MYSQLMGR_DIR', '/var/lib/cyberpanel-universal/mysqlmgr')
BACKUP_DIR = os.path.join(STATE_DIR, 'dropin-backups')
MAX_BACKUPS = 30
SHIM = '/usr/local/CyberCP/CyberCP/mariadb_compat.py'
DEFAULT_PANEL_USERS = ('cyberpanel',)


def run(argv, timeout=120, runner=subprocess.run):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=timeout,
                     stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


@contextmanager
def credentials():
    from universalAddons.backupv2.service import mysql_defaults_file
    try:
        path = mysql_defaults_file()
    except OSError as exc:
        raise MySQLError('Cannot read the MySQL root credentials: %s' % exc)
    try:
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def query(sql, defaults, timeout=60):
    code, out = run(['mysql', '--defaults-extra-file=' + defaults, '-N', '-B', '-e', sql], timeout=timeout)
    if code != 0:
        raise MySQLError('MySQL error: %s' % out.strip()[-300:])
    return sv.parse_rows(out)


def query_sets(statements, defaults, timeout=60):
    return sv.split_results(query(sv.multi_sql(statements), defaults, timeout), len(statements))


def _read(path):
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return ''


def host_memory():
    mem = sv.parse_meminfo(_read('/proc/meminfo'))
    mem['oom_kills'] = sv.parse_vmstat_oom(_read('/proc/vmstat'))
    return mem


def fs_type(path):
    best, kind = '', ''
    for line in _read('/proc/mounts').splitlines():
        parts = line.split()
        if len(parts) >= 3 and (path == parts[1] or path.startswith(parts[1].rstrip('/') + '/')) and \
                len(parts[1]) > len(best):
            best, kind = parts[1], parts[2]
    return kind


DATABASE_SQL = ("SELECT s.schema_name, COUNT(t.table_name), IFNULL(SUM(t.data_length+t.index_length),0), "
                "IFNULL(SUM(t.data_free),0) FROM information_schema.schemata s LEFT JOIN information_schema.tables t "
                "ON t.table_schema = s.schema_name GROUP BY s.schema_name")


def _snapshot(defaults, extra=()):
    """Global variables and status (read first, so later queries do not skew the counters), plus extra queries."""
    sets = query_sets(['SHOW GLOBAL VARIABLES', 'SHOW GLOBAL STATUS'] + list(extra), defaults, timeout=180)
    return [sv.as_dict(sets[0]), sv.as_dict(sets[1])] + sets[2:]


def _datadir(v):
    return v.get('datadir', '/var/lib/mysql').rstrip('/') or '/var/lib/mysql'


def datadir_files(datadir):
    """(database, file name, bytes) for the table files in the datadir; reading them opens no tables."""
    try:
        names = os.listdir(datadir)
    except OSError:
        return
    for name in names:
        folder = os.path.join(datadir, name)
        if os.path.islink(folder) or not os.path.isdir(folder):
            continue
        for entry in os.scandir(folder):
            try:
                yield name, entry.name, entry.stat(follow_symlinks=False).st_size
            except OSError:
                pass


# ----------------------------------------------------------------------------- config files

def my_cnf():
    for path in MY_CNF_CANDIDATES:
        if os.path.isfile(path):
            return path, _read(path)
    return None, ''


def include_dir():
    path, text = my_cnf()
    if not path:
        raise MySQLError('No /etc/my.cnf found.')
    directory = sv.choose_include_dir(text, os.path.isdir)
    if not directory:
        raise MySQLError('%s has no !includedir line, so a drop-in file would not be read. Add '
                         '"!includedir /etc/my.cnf.d" to it first.' % path)
    return directory


def dropin_path():
    return os.path.join(include_dir(), sv.DROPIN_NAME)


def config_files():
    path, text = my_cnf()
    files = [(path, text)] if path else []
    try:
        directory = include_dir()
        files += [(p, _read(p)) for p in sorted(glob.glob(os.path.join(directory, '*.cnf')))]
    except MySQLError:
        pass
    return files


def overrides():
    path, text = my_cnf()
    try:
        directory = include_dir()
    except MySQLError:
        return {}
    found = {k: '%s line %d' % (path, line) for k, line in sv.overridden_after_include(text, directory).items()}
    for other in sorted(glob.glob(os.path.join(directory, '*.cnf'))):
        if os.path.basename(other) > sv.DROPIN_NAME:
            for key in sv.parse_dropin(_read(other)):
                found[key] = other
    return found


def backups():
    try:
        names = sorted(n for n in os.listdir(BACKUP_DIR) if n.endswith('.cnf') or n.endswith('.absent'))
    except OSError:
        return []
    return [os.path.join(BACKUP_DIR, n) for n in names]


def _backup_current(target, replaced=False):
    """Keep the drop-in as it is now. Revert candidates end in .cnf (a copy) or .absent (there was none);
    files replaced by a revert end in .reverted and are kept only for reference."""
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    stamp, n = time.strftime('%Y%m%d-%H%M%S'), 0
    while glob.glob(os.path.join(BACKUP_DIR, '%s-%03d.*' % (stamp, n))):
        n += 1
    base = os.path.join(BACKUP_DIR, '%s-%03d' % (stamp, n))
    saved = None
    if os.path.isfile(target):
        saved = base + ('.reverted' if replaced else '.cnf')
        shutil.copy2(target, saved)
    elif not replaced:
        saved = base + '.absent'
        open(saved, 'w').close()
    for old in backups()[:-MAX_BACKUPS] + sorted(glob.glob(os.path.join(BACKUP_DIR, '*.reverted')))[:-MAX_BACKUPS]:
        os.unlink(old)
    return saved


def _write_atomic(target, text):
    directory = os.path.dirname(target)
    temporary = os.path.join(directory, '.%s.tmp' % sv.DROPIN_NAME)   # not *.cnf: never read by the server
    with open(temporary, 'w') as handle:
        handle.write(text)
    os.chmod(temporary, 0o644)
    os.replace(temporary, target)


def mysqld_binary():
    for path in MYSQLD_CANDIDATES:
        if os.access(path, os.X_OK):
            return path
    raise MySQLError('The mysqld binary was not found.')


def check_config(settings=None):
    """Parse the complete configuration the way the server will at its next start (changes nothing)."""
    code, out = run([mysqld_binary(), '--user=mysql', '--help', '--verbose'], timeout=60)
    effective, errors = sv.parse_help_verbose(out)
    if code != 0 and not errors:
        errors = [out.strip()[-500:] or 'mysqld exited with status %d' % code]
    mismatches = sv.compare_effective(settings or {}, effective) if not errors else []
    return {'ok': code == 0 and not errors, 'errors': errors, 'mismatches': mismatches,
            'method': 'mysqld --help --verbose (MariaDB has no --validate-config)'}


def current_dropin():
    try:
        path = dropin_path()
    except MySQLError as exc:
        return {'path': None, 'error': str(exc), 'settings': {}, 'exists': False}
    text = _read(path)
    return {'path': path, 'exists': os.path.isfile(path), 'settings': sv.parse_dropin(text), 'text': text}


# ----------------------------------------------------------------------------- actions

def status():
    with credentials() as defaults:
        v, s = _snapshot(defaults)
    return {'metrics': sv.metrics(v, s)}


def databases():
    """Sizes from information_schema. This opens every table once, so it runs only on request."""
    with credentials() as defaults:
        rows, = query_sets([DATABASE_SQL], defaults, timeout=300)
    return {'databases': sv.database_rows(rows)}


def processes(panel_users=DEFAULT_PANEL_USERS):
    with credentials() as defaults:
        own, rows = query_sets(['SELECT CONNECTION_ID()', sv.PROCESS_SQL], defaults)
    own_id = int(own[0][0])
    out = []
    for item in sv.process_rows(rows):
        item['protected'] = sv.kill_refusal(item, own_id, tuple(panel_users))
        out.append(item)
    return {'processes': out, 'own_id': own_id}


def kill(thread, mode='query', panel_users=DEFAULT_PANEL_USERS):
    tid = sv.thread_id(thread)
    sql = sv.kill_sql(tid, mode)
    with credentials() as defaults:
        own, rows = query_sets(['SELECT CONNECTION_ID()', sv.PROCESS_SQL + ' WHERE ID = %d' % tid], defaults)
        found = sv.process_rows(rows)
        reason = sv.kill_refusal(found[0] if found else None, int(own[0][0]), tuple(panel_users))
        if reason:
            raise MySQLError(reason)
        query(sql, defaults)
    return {'killed': tid, 'mode': mode, 'user': found[0]['user']}


def advise():
    with credentials() as defaults:
        v, s = _snapshot(defaults)
    datadir = _datadir(v)
    engines, tables = sv.datadir_summary(datadir_files(datadir))
    result = sv.advise(v, s, host_memory(), engines, tables, fs_type(datadir))
    found = sv.find_option(config_files(), 'innodb_force_recovery')
    for rec in result['recommendations']:
        if rec['variable'] == 'innodb_force_recovery' and found:
            rec['reason'] += ' Set in: ' + ', '.join('%s line %d' % (f['path'], f['line']) for f in found) + '.'
    over = overrides()
    for rec in result['recommendations']:
        if rec['variable'] in over:
            rec['overridden'] = over[rec['variable']]
    try:
        ibdata = os.path.getsize(os.path.join(datadir, 'ibdata1'))
    except OSError:
        ibdata = 0
    if ibdata > GB:
        result['notes'].append('The InnoDB system tablespace ibdata1 is %s. It holds undo history and never shrinks; '
                               'it grows fast while purge cannot run (innodb_force_recovery 2 or more, or very long '
                               'transactions). Only a full dump and reload into a fresh datadir reclaims it.' %
                               sv.human(ibdata))
    result['dropin'] = current_dropin()
    result['overrides'] = over
    result['backups'] = [os.path.basename(p) for p in backups()]
    result['running'] = {name: v.get(name) for name in sv.SPEC if name in v}
    return result


def apply(settings):
    with credentials() as defaults:
        v, _ = _snapshot(defaults)
    clean, warnings = sv.validate_settings(settings, v, host_memory()['total'])
    over = overrides()
    for name in clean:
        if name in over:
            warnings.append('%s is also set in %s, which wins over the drop-in.' % (name, over[name]))
    target = dropin_path()
    text = sv.render_dropin(clean, time.strftime('%Y-%m-%d %H:%M:%S'))
    previous = _read(target) if os.path.isfile(target) else None
    saved = _backup_current(target)
    _write_atomic(target, text)
    check = check_config(clean)
    if not check['ok']:
        if previous is None:
            os.unlink(target)
        else:
            _write_atomic(target, previous)
        if saved:
            os.unlink(saved)
        raise MySQLError('The server rejected the new configuration, so the previous drop-in was restored: %s' %
                         '; '.join(check['errors'])[:800])
    return {'path': target, 'settings': clean, 'warnings': warnings, 'check': check, 'restart_needed': True}


def revert():
    target = dropin_path()
    candidates = backups()
    if not candidates:
        raise MySQLError('There is no earlier tuning to go back to.')
    source = candidates[-1]
    _backup_current(target, replaced=True)
    if source.endswith('.absent'):
        if os.path.isfile(target):
            os.unlink(target)
        restored = None
    else:
        _write_atomic(target, _read(source))
        restored = sv.parse_dropin(_read(source))
    os.unlink(source)
    check = check_config(restored or {})
    return {'path': target, 'restored': restored, 'removed': restored is None, 'check': check,
            'from': os.path.basename(source), 'restart_needed': True}


def check():
    return check_config(current_dropin()['settings'])


def service_name():
    for name in SERVICE_CANDIDATES:
        if run(['systemctl', 'is-active', '--quiet', name], timeout=20)[0] == 0:
            return name
    for name in SERVICE_CANDIDATES:
        if run(['systemctl', 'cat', name], timeout=20)[0] == 0:
            return name
    raise MySQLError('No MariaDB/MySQL systemd service found.')


def _wait_ready(seconds=90):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with credentials() as defaults:
                code, out = run(['mysqladmin', '--defaults-extra-file=' + defaults, 'ping'], timeout=20)
            if code == 0 and 'alive' in out:
                return True
        except MySQLError:
            pass
        time.sleep(3)
    return False


def restart_run(job_id, auto_revert=True):
    state = {}

    def validate(job):
        dropin = current_dropin()
        job.log('drop-in: %s (%s)' % (dropin['path'], 'present' if dropin['exists'] else 'absent'))
        result = check_config(dropin['settings'])
        for line in result['errors']:
            job.log(line)
        for item in result['mismatches']:
            job.log('NOTE: %(variable)s will be %(effective)s, not %(wanted)s (overridden by another file)' % item)
        if not result['ok']:
            raise MySQLError('Configuration check failed; MariaDB was NOT restarted.')
        job.log('configuration OK (%s)' % result['method'])
        state['service'] = service_name()
        return result

    def restart(job):
        name = state['service']
        job.log('systemctl restart %s' % name)
        code, out = run(['systemctl', 'restart', name], timeout=900)
        if out.strip():
            job.log(out)
        if code == 0 and _wait_ready():
            job.log('%s is running and answering' % name)
            return {'service': name, 'restarted': True, 'reverted': False}
        job.log('ERROR: %s did not come back (status %d)' % (name, code))
        job.log(run(['journalctl', '-u', name, '-n', '30', '--no-pager'], timeout=30)[1])
        if not auto_revert or not backups():
            raise MySQLError('%s failed to start. Use "Revert to previous tuning" and restart again.' % name)
        job.log('reverting to the previous tuning and starting again')
        revert()
        code, out = run(['systemctl', 'restart', name], timeout=900)
        if code == 0 and _wait_ready():
            raise MySQLError('%s failed with the new tuning; the previous tuning was restored and the server is '
                             'running again.' % name)
        raise MySQLError('%s still does not start after reverting the tuning. Check journalctl -u %s.' % (name, name))

    return jobs.run_job(job_id, [('Check configuration', validate), ('Restart MariaDB', restart)])


def _tree_bytes(path):
    total = 0
    for current, dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(current, name)).st_blocks * 512
            except OSError:
                pass
    return total


def upgrade():
    with credentials() as defaults:
        v, _, rows = _snapshot(defaults, [DATABASE_SQL])
    datadir = _datadir(v)
    engines, _ = sv.datadir_summary(datadir_files(datadir))
    report = sv.upgrade_report(
        v.get('version', ''), sv.parse_os_release(_read('/etc/os-release')), sv.database_rows(rows), _tree_bytes(datadir),
        shutil.disk_usage(datadir).free, time.strftime('%Y-%m-%d'), int(sv.num(v, 'innodb_force_recovery')),
        os.path.exists(SHIM), engines.get('MyISAM', {}).get('tables', 0))
    report['datadir'] = datadir
    return report


ACTIONS = {
    'status': status,
    'databases': databases,
    'processes': processes,
    'kill': kill,
    'advise': advise,
    'apply': apply,
    'revert': revert,
    'check': check,
    'restart': lambda auto_revert=True: jobs.spawn('mysqlmgr', 'restart_run', {'auto_revert': bool(auto_revert)}),
    'restart_run': restart_run,
    'upgrade': upgrade,
    'job': lambda job_id: jobs.status(job_id),
}

"""Root-side Applications actions (dispatched by universalAddons/runner.py). Administrator-only.

Install and remove reuse manageServices/serviceManager.py for Elasticsearch and Redis (so the old
Applications page, its install lock and its progress file keep working); Memcached uses the OS
package; PostgreSQL, MongoDB, RabbitMQ and Oracle Instant Client come from their vendors' signed
repositories (cp-*.repo). SQL Server is installed by the SQL Server add-on; here it gets status, its
memory cap, service controls and uninstall through that add-on's own functions.

Every configuration change runs as a job: back up, write the managed files, restart, health-check,
and restore the previous files if the service does not come back. Uninstalling first runs
`dnf remove --assumeno` in a job to show what would go; the removal itself only proceeds with that
same package list, and data directories go only with a typed confirmation.
"""
import fcntl
import glob
import grp
import json
import os
import platform
import pwd
import re
import secrets as _secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from contextlib import contextmanager

from universalAddons import jobs
from universalAddons.appsvc import more as mo
from universalAddons.appsvc import s3
from universalAddons.appsvc import service as sv
from universalAddons.appsvc.service import AppError

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SERVICE_MANAGER = os.path.join(ROOT, 'manageServices', 'serviceManager.py')
LEGACY_STATUS = '/home/cyberpanel/switchLSWSStatus'    # ServerStatusUtil.lswsInstallStatusPath
HEALTH_TIMEOUT = {'elasticsearch': 240, 'redis': 30, 'memcached': 20, 'mssql': 180, 'postgresql': 90,
                  'mongodb': 120, 'rabbitmq': 120, 'oracle_client': 10, 'docker': 30, 's3': 60}
LEGACY_FUNCTIONS = {('elasticsearch', 'install'): 'InstallElasticSearch', ('elasticsearch', 'remove'): 'RemoveElasticSearch',
                    ('redis', 'install'): 'InstallRedis', ('redis', 'remove'): 'RemoveRedis'}
CONTROL_OPS = ('start', 'stop', 'restart', 'enable', 'disable')
ORIGINAL = ('elasticsearch', 'redis', 'memcached')          # removable without a preview (old page's API)
NEW_PACKAGED = ('postgresql', 'mongodb', 'rabbitmq', 'oracle_client')
PORTS = {'postgresql': 5432, 'mongodb': mo.MONGO_PORT, 'rabbitmq': mo.RABBIT_PORT}
PREVIEW_MAX_AGE = 1800
DNF_ENV = dict(os.environ, LC_ALL='C', LANG='C')


def _read(path, default=''):
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return default


def _mssql():
    from universalAddons.mssql import actions as ma
    return ma


def _mssql_service():
    from universalAddons.mssql import service as sq
    return sq


# ----------------------------------------------------------------------------- locks

def _lock_path(key):
    return os.path.join(sv.WORK_DIR, '%s.lock' % key)


@contextmanager
def app_lock(key):
    """One change at a time per application (held by the job process for its whole run)."""
    os.makedirs(sv.WORK_DIR, mode=0o700, exist_ok=True)
    handle = open(_lock_path(key), 'a')
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise AppError('Another change to %s is still running; wait for it to finish.' % sv.app_info(key)['title'])
    try:
        yield
    finally:
        handle.close()


def _is_locked(path):
    if not os.path.exists(path):
        return False
    try:
        with open(path, 'a') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(handle, fcntl.LOCK_UN)
        return False
    except OSError:
        return True


def _busy(key):
    return _is_locked(_lock_path(key)) or (key == 'elasticsearch' and _is_locked(sv.ES_INSTALL_LOCK))


def _require_idle(key):
    if _busy(key):
        raise AppError('Another change to %s is still running; wait for it to finish.' % sv.app_info(key)['title'])


# ----------------------------------------------------------------------------- facts

def _rpm_version(package):
    code, out = sv.run(['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}', package], timeout=30)
    out = out.strip()
    return out if code == 0 and out and 'not installed' not in out else None


def _pg_major():
    """The PGDG major installed here (newest first), or None."""
    for major in sv.PG_MAJORS:
        if _rpm_version('postgresql%d-server' % major):
            return major
    return None


_VERSION_CACHE = None   # a dict only while one read-only overview runs (never during jobs)


@contextmanager
def _cached_versions():
    global _VERSION_CACHE
    _VERSION_CACHE = {}
    try:
        yield
    finally:
        _VERSION_CACHE = None


def _version(key):
    if _VERSION_CACHE is not None:
        if key not in _VERSION_CACHE:
            _VERSION_CACHE[key] = _version_uncached(key)
        return _VERSION_CACHE[key]
    return _version_uncached(key)


def _version_uncached(key):
    if key == 's3':
        return _s3_version()
    if key == 'postgresql':
        major = _pg_major()
        return _rpm_version('postgresql%d-server' % major) if major else None
    package = sv.app_info(key)['package']
    if shutil.which('rpm'):
        return _rpm_version(package)
    if key not in ORIGINAL:
        return None
    code, out = sv.run(['dpkg-query', '-W', '-f', '${Version}', package if key != 'redis' else 'redis-server'], timeout=30)
    out = out.strip()
    return out if code == 0 and out and 'not installed' not in out else None


def _unit(key, major=None):
    if key == 'postgresql':
        major = major or _pg_major() or sv.PG_DEFAULT_MAJOR
        return sv.pg_unit(major)
    return sv.app_info(key)['unit']


def _data_dir(key, major=None):
    if key == 's3':
        return s3.current(_read(s3.CONF))['data_dir']
    if key == 'postgresql':
        major = major or _pg_major()
        return mo.pg_paths(major)['base'] if major else None
    return sv.app_info(key)['data_dir']


def _el():
    return mo.el_version()[1]


def _systemd(unit):
    code, out = sv.run(['systemctl', 'show', unit, '-p',
                        'ActiveState,SubState,UnitFileState,MemoryCurrent,MainPID,LoadState'], timeout=30)
    return sv.parse_systemctl_show(out if code == 0 else '')


def _memory(values):
    current = sv.memory_current(values)
    if current is not None:
        return current, 'systemd MemoryCurrent'
    pid = values.get('MainPID', '0')
    if pid.isdigit() and int(pid) > 0:
        code, out = sv.run(['ps', '-o', 'rss=', '-p', pid], timeout=15)
        if code == 0 and out.strip().isdigit():
            return int(out.strip()) * 1024, 'RSS (ps)'
    return None, None


def _ss():
    code, out = sv.run(['ss', '-Hltnp'], timeout=15)
    return out if code == 0 else ''


def _du(path):
    if not path or not os.path.isdir(path):
        return None
    code, out = sv.run(['du', '-sb', '--', path], timeout=120)
    try:
        return int(out.split()[0]) if code == 0 else None
    except (IndexError, ValueError):
        return None


def _installed_packages(names):
    return [name for name in names if _rpm_version(name)]


def _package_bytes(names):
    total = 0
    for name in names:
        code, out = sv.run(['rpm', '-q', '--qf', '%{SIZE}\n', name], timeout=30)
        if code == 0:
            total += sum(int(v) for v in out.split() if v.isdigit())
    return total


def _packages(key, major=None):
    """The packages this application consists of (removal candidates), installed or not."""
    if key == 's3':
        return []          # a single binary, not a package
    if key == 'postgresql':
        major = major or _pg_major()
        return mo.pg_packages(major) if major else []
    return list(sv.app_info(key).get('packages') or [sv.app_info(key)['package']])


def _install_bytes(key, major=None):
    """Size on disk of what the application installed (packages, or Garage's binary)."""
    if key == 's3':
        try:
            return os.path.getsize(s3.BIN)
        except OSError:
            return None
    return _package_bytes(_installed_packages(_packages(key, major)))


def _redis_conf():
    return next((p for p in sv.REDIS_CONFS if os.path.isfile(p)), sv.REDIS_CONFS[0])


def _redis_texts():
    conf = _redis_conf()
    return conf, _read(conf), _read(sv.redis_dropin_path(conf), None)


def _current(key, ram_mb):
    if key == 'elasticsearch':
        return sv.es_current(_read(sv.ES_YML), _read(sv.ES_HEAP, None), ram_mb)
    if key == 'redis':
        _, main, dropin = _redis_texts()
        return sv.redis_current(main, dropin)
    if key == 'memcached':
        if not os.path.isfile(sv.MEMCACHED_SYSCONFIG):
            return dict(sv.memcached_current(''), managed=False)
        return sv.memcached_current(_read(sv.MEMCACHED_SYSCONFIG))
    if key == 'mssql':
        ma = _mssql()
        return {'memory_limit_mb': ma._meta().get('memory_limit_mb') or 0, 'managed': ma._installed()}
    if key == 'postgresql':
        major = _pg_major()
        if not major:
            return dict(mo.pg_defaults(ram_mb), managed=False, hba_managed=False)
        paths = mo.pg_paths(major)
        return mo.pg_current(_read(paths['conf']), _read(paths['panel'], None), _read(paths['hba']), ram_mb)
    if key == 'mongodb':
        return mo.mongo_current(_read(mo.MONGO_DROPIN, None), _read(mo.MONGO_CONF))
    if key == 'rabbitmq':
        return mo.rabbit_current(_read(mo.RABBIT_DROPIN))
    if key == 's3':
        return dict(s3.current(_read(s3.CONF), _read(s3.DROPIN, None)), endpoint=_s3_state().get('endpoint'))
    return {}


def _has_password(key, current):
    if key == 'elasticsearch':
        return bool(current.get('security'))
    if key == 'redis':
        return bool(current.get('password'))
    if key == 'mongodb':
        return bool(current.get('auth'))
    return False


def _password_state(key, current):
    has = _has_password(key, current)
    stored = sv.secret_status(key)
    return {'set': has, 'by_panel': has and stored['stored'], 'reveal_pending': has and stored['reveal_pending']}


def _live_password(key):
    """The password the service runs with (root side only)."""
    if key == 'redis':
        _, main, dropin = _redis_texts()
        return sv.redis_password_in(main, dropin) or None
    if key in ('elasticsearch', 'mongodb'):
        data = sv.load_secret(key)
        return data['password'] if data else None
    return None


# ----------------------------------------------------------------------------- per-application helpers

def _psql(major, sql=None, stdin=None, timeout=60):
    """psql as the postgres superuser over the local socket (peer authentication)."""
    argv = ['runuser', '-u', 'postgres', '--', os.path.join(mo.pg_paths(major)['bin'], 'psql'),
            '-X', '-q', '-At', '-F', '|', '-v', 'ON_ERROR_STOP=1', '-d', 'postgres']
    if sql is not None:
        argv += ['-c', sql]
    return sv.run(argv, timeout=timeout, input_text=stdin)


def _pg_databases(major):
    code, out = _psql(major, "SELECT datname, pg_get_userbyid(datdba), pg_database_size(oid) FROM pg_database "
                             "WHERE NOT datistemplate ORDER BY datname", timeout=30)
    if code != 0:
        return None
    rows = []
    for line in out.splitlines():
        parts = line.split('|')
        if len(parts) == 3 and parts[2].isdigit():
            rows.append({'name': parts[0], 'owner': parts[1], 'bytes': int(parts[2])})
    return rows


def _mongosh(script, host, timeout=60):
    """Run a mongosh script from a root-only file (passwords never appear on a command line)."""
    os.makedirs(sv.WORK_DIR, mode=0o700, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix='mongosh-', suffix='.js', dir=sv.WORK_DIR)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(script)
        return sv.run([mo.MONGOSH, '--quiet', '--norc', mo.mongo_uri(host), '--file', path], timeout=timeout)
    finally:
        os.unlink(path)


def _sqlplus():
    found = sorted(glob.glob(os.path.join(mo.ORACLE_CLIENT_ROOT, '*', 'client64', 'bin', 'sqlplus')))
    return found[-1] if found else (shutil.which('sqlplus') or None)


def _health_once(key, ram_mb=None):
    """One health check against the configuration currently on disk."""
    ram_mb = ram_mb or sv.meminfo_mb()[0]
    current = _current(key, ram_mb)
    password = _live_password(key) if _has_password(key, current) else None
    if key == 'elasticsearch':
        ok, detail = sv.es_health(*sv.es_health_target(current), password=password)
        if ok and password and detail.startswith('HTTP 401'):
            return False, detail   # a password the panel set must work
        return ok, detail
    if key == 'redis':
        return sv.redis_health(sv.redis_target(current), password)
    if key == 'memcached':
        return sv.memcached_health(sv.memcached_target(current))
    if key == 'mssql':
        return _mssql().ping()
    if key == 'postgresql':
        major = _pg_major()
        code, out = _psql(major, 'SELECT 1', timeout=20) if major else (1, 'not installed')
        return (code == 0 and out.strip() == '1'), ('SELECT 1 answered' if code == 0 else out.strip()[-200:])
    if key == 'mongodb':
        host = mo.mongo_target(current)
        code, out = _mongosh('print(db.adminCommand({ping: 1}).ok);\n', host, timeout=40)
        if code != 0 or out.strip().splitlines()[-1:] != ['1']:
            return False, 'no ping reply (%s)' % out.strip()[-200:]
        if password:
            code, out = _mongosh(mo.mongo_auth_check_script(password), host, timeout=40)
            if code != 0 or out.strip().splitlines()[-1:] != ['1']:
                return False, 'answering, but the stored admin password was not accepted'
            return True, 'ping ok, admin login ok'
        return True, 'ping ok'
    if key == 'rabbitmq':
        return mo.amqp_probe(mo.rabbit_target(current))
    if key == 's3':
        return _s3_health_once()
    if key == 'oracle_client':
        binary = _sqlplus()
        code, out = sv.run([binary, '-V'], timeout=30) if binary else (127, 'sqlplus not found')
        return code == 0, out.strip()[-200:]
    values = _systemd(_unit(key))
    return values.get('ActiveState') == 'active', 'service %s' % values.get('ActiveState', 'unknown')


def _wait_healthy(key):
    return sv.wait_healthy(lambda: _health_once(key), HEALTH_TIMEOUT[key])


def _systemctl(op, unit, timeout=120):
    code, out = sv.run(['systemctl', op, unit], timeout=timeout)
    if code != 0:
        raise AppError('systemctl %s %s failed: %s' % (op, unit, out.strip()[-500:]))
    return out


def _restart(key):
    if key in ('redis', 'mongodb', 'rabbitmq', 'mssql', 's3'):
        sv.run(['systemctl', 'daemon-reload'], timeout=60)   # their panel drop-ins
    _systemctl('restart', _unit(key), timeout=960 if key == 'elasticsearch' else 300)


def _logs(key, current, count=50):
    lines = None
    if key == 'elasticsearch':
        name = current.get('cluster_name') or 'elasticsearch'
        lines = sv.tail_lines(os.path.join(sv.ES_LOG_DIR, '%s.log' % name), count)
        if lines is None:
            candidates = [p for p in glob.glob(os.path.join(sv.ES_LOG_DIR, '*.log'))
                          if not os.path.basename(p).startswith(('gc', 'deprecation')) and '_' not in os.path.basename(p)]
            if candidates:
                lines = sv.tail_lines(max(candidates, key=os.path.getmtime), count)
    elif key == 'redis':
        _, main, dropin = _redis_texts()
        logfile = (sv._last(sv.redis_effective(main, dropin), 'logfile') or [sv.REDIS_LOG])[0]
        if logfile and logfile.startswith('/'):
            lines = sv.tail_lines(logfile, count)
    elif key == 'postgresql':
        major = _pg_major()
        candidates = glob.glob(os.path.join(mo.pg_paths(major)['log'], '*.log')) if major else []
        if candidates:
            lines = sv.tail_lines(max(candidates, key=os.path.getmtime), count)
    elif key == 'mongodb':
        lines = sv.tail_lines('/var/log/mongodb/mongod.log', count)
    if lines is None:
        code, out = sv.run(['journalctl', '-u', _unit(key), '-n', str(count), '--no-pager',
                            '-o', 'short-iso'], timeout=30)
        lines = out.splitlines()[-count:]
    hidden = [_live_password(key)] + ([_s3_token()] if key == 's3' else [])
    return [sv.redact(line, hidden) for line in lines]


def _connection(key, current, major=None):
    if key in ('elasticsearch', 'redis', 'memcached'):
        return sv.connection_info(key, current, _has_password(key, current))
    if key == 'postgresql':
        return mo.pg_connection_info(current, major or sv.PG_DEFAULT_MAJOR)
    if key == 'mongodb':
        return mo.mongo_connection_info(current, _has_password(key, current))
    if key == 'rabbitmq':
        return mo.rabbit_connection_info(current)
    if key == 's3':
        return s3.connection_info(current, current.get('endpoint'))
    if key == 'oracle_client':
        sqlplus = _sqlplus()
        return mo.oracle_client_connection_info(os.path.join(os.path.dirname(os.path.dirname(sqlplus)), 'lib')
                                                if sqlplus else None)
    if key == 'mssql':
        return {'host': '127.0.0.1', 'port': 1433, 'auth': 'a login per database (SQL Server add-on)',
                'examples': [], 'note': 'Create databases and their logins in the SQL Server add-on.'}
    return {}


# ----------------------------------------------------------------------------- memory budget

def _caps(ram_mb, exclude=None):
    """{title: MB} of the memory caps of every installed application (except `exclude`)."""
    caps = {}
    for key in sv.ORDER:
        if key == exclude or sv.app_info(key)['kind'] in ('client', 'status') or not _version(key):
            continue
        mb = sv.cap_mb(key, _current(key, ram_mb))
        if mb:
            caps[sv.app_info(key)['title']] = mb
    return caps


def _default_cap(key, ram_mb):
    return {'elasticsearch': sv.es_default_heap(ram_mb), 'memcached': 64,
            'postgresql': mo.pg_default_shared_buffers(ram_mb) + 64,
            'mongodb': int(mo.mongo_defaults(ram_mb)['cache_gb'] * 1024),
            'rabbitmq': mo.rabbit_defaults(ram_mb)['memory_mb'], 's3': s3.defaults(ram_mb)['memory_mb']}.get(key, 0)


# ----------------------------------------------------------------------------- status

def _app_status(key, ram_total, ram_available, disk_mb, with_logs=False):
    info = sv.app_info(key)
    version = _version(key)
    status = {'key': key, 'title': info['title'], 'about': info['about'], 'installed': bool(version),
              'version': version, 'busy': _busy(key), 'unit': info['unit'], 'fields': sv.FIELDS[key],
              'kind': info['kind'], 'link': info.get('link'), 'link_title': info.get('link_title')}
    if key == 'postgresql':
        status['install_options'] = {'major': [str(m) for m in sv.PG_MAJORS]}
    if not version:
        if info['kind'] in ('service', 'client'):
            status['preflight'] = _preflight_checks(key, ram_total, ram_available, disk_mb, False)
        return status
    major = _pg_major() if key == 'postgresql' else None
    unit = _unit(key, major)
    status.update({'unit': unit if info['kind'] != 'client' else None, 'major': major,
                   'package_bytes': _install_bytes(key, major)})
    if info['kind'] == 'status':
        values = _systemd(unit)
        status.update({'active': values.get('ActiveState', 'unknown'), 'sub': values.get('SubState', ''),
                       'enabled': values.get('UnitFileState', 'unknown'), 'settings': {}})
        return status
    current = _current(key, ram_total)
    status.update({'settings': {k: v for k, v in current.items() if k != 'socket_path'},
                   'password': _password_state(key, current), 'connection': _connection(key, current, major),
                   'backups': len(sv.list_snapshots(sv.backup_root(key)))})
    if info['kind'] == 'client':
        status['sqlplus'] = _sqlplus()
        return status
    values = _systemd(unit)
    pid = values.get('MainPID', '0')
    memory, source = _memory(values)
    data_dir = _data_dir(key, major)
    status.update({
        'active': values.get('ActiveState', 'unknown'), 'sub': values.get('SubState', ''),
        'enabled': values.get('UnitFileState', 'unknown'),
        'memory_bytes': memory, 'memory_source': source,
        'listen': sv.parse_ss(_ss(), int(pid)) if pid.isdigit() and int(pid) > 0 else [],
        'data_dir': data_dir, 'data_bytes': _du(data_dir),
    })
    running = status['active'] == 'active'
    if key == 'elasticsearch':
        status['heap_bounds'] = sv.es_heap_bounds(ram_total)
        status['conflicts'] = sv.yml_conflicts(_read(sv.ES_YML), list(sv.ES_KEYS.values()))
    if key == 'memcached' and not os.path.isfile(sv.MEMCACHED_SYSCONFIG):
        status['config_problem'] = '%s is missing; the panel configures Memcached only through it (EL).' % sv.MEMCACHED_SYSCONFIG
    if key == 'mssql':
        sq = _mssql_service()
        status['memory_bounds'] = sq.memory_limit_bounds(ram_total)
        if not current['managed']:
            status['config_problem'] = ('SQL Server was set up outside the panel (no sa password stored), so the panel '
                                        'does not change its settings.')
        elif running:
            status['settings']['max_server_memory_mb'] = _mssql().memory_state()['max_server_memory_mb']
    if key == 'postgresql' and running:
        status['databases'] = _pg_databases(major)
    if key == 's3':
        status.update(_s3_status_extras(current, running, ram_total))
    if key == 'mongodb' and mo.mongo_sysconfig_conflict(_read(mo.MONGO_SYSCONFIG)):
        status['config_problem'] = ('%s sets OPTIONS, which overrides the panel\'s drop-in; remove that line first.'
                                    % mo.MONGO_SYSCONFIG)
    if with_logs:
        status['logs'] = _logs(key, current)
    return status


# ----------------------------------------------------------------------------- read-only actions

def overview():
    with _cached_versions():
        return _overview()


def _overview():
    total, available = sv.meminfo_mb()
    disk = sv.disk_free_mb()
    caps = _caps(total)
    return {'ram_mb': total, 'ram_available_mb': available, 'disk_free_mb': disk,
            'apps': [_app_status(k, total, available, disk) for k in sv.ORDER], 'skipped': sv.SKIPPED,
            'budget': {'caps': caps, 'total_mb': sum(caps.values()), 'limit_mb': int(total * sv.BUDGET_SHARE),
                       'warning': sv.budget_warning(caps, total)},
            'oracle_db': _oracle_db(False, caps)}


def logs(app):
    sv.app_info(app)
    if sv.app_info(app)['kind'] == 'client':
        raise AppError('%s has no service and no log.' % sv.app_info(app)['title'])
    if not _version(app):
        raise AppError('%s is not installed.' % sv.app_info(app)['title'])
    return {'app': app, 'lines': _logs(app, _current(app, sv.meminfo_mb()[0]))}


def _preflight_checks(app, total, available, disk, installed):
    checks = sv.preflight_checks(app, total, available, disk, installed)
    info = sv.app_info(app)
    if info['kind'] in ('bridge', 'status'):
        checks.insert(0, {'id': 'where', 'ok': False, 'hard': True,
                          'detail': '%s is installed from the %s.' % (info['title'], info.get('link_title') or 'add-on')})
    if app in NEW_PACKAGED or app == 's3':
        checks.insert(0, mo.os_check(app, _el()))
    if app == 's3':
        machine = platform.machine()
        checks.insert(1, {'id': 'arch', 'ok': machine == 'x86_64', 'hard': True,
                          'detail': 'Garage %s is installed here as the x86_64 static binary (this server: %s).'
                          % (s3.VERSION, machine or '?')})
    default = _default_cap(app, total)
    if default:
        caps = dict(_caps(total, exclude=app), **{info['title']: default})
        warning = sv.budget_warning(caps, total)
        checks.append({'id': 'budget', 'ok': warning is None, 'hard': False,
                       'detail': warning or 'The applications\' memory caps, with %s at %d MB, stay within %d%% of RAM.'
                       % (info['title'], default, int(sv.BUDGET_SHARE * 100))})
    return checks


def preflight(app):
    total, available = sv.meminfo_mb()
    checks = _preflight_checks(app, total, available, sv.disk_free_mb(), bool(_version(app)))
    return {'app': app, 'checks': checks, 'refusal': sv.preflight_refusal(checks, False),
            'blocked': sv.preflight_refusal(checks, True)}


def reveal(app):
    """The generated password, once."""
    return {'app': app, 'password': sv.reveal_secret(app)}


def _oracle_db(confirm_ram, caps):
    total, available = sv.meminfo_mb()
    os_id, el = mo.el_version()
    checks = mo.oracle_db_checks(os_id, el, total, available, sum(caps.values()), sv.disk_free_mb('/opt'))
    return {'checks': checks, 'refusal': mo.oracle_db_refusal(checks, confirm_ram is True)}


def oracle_db_check(confirm_ram=False):
    """Whether Oracle Database 23ai Free could be installed here. It is not offered on this panel's
    CentOS servers (see SKIPPED); Oracle Instant Client is offered instead."""
    return _oracle_db(confirm_ram, _caps(sv.meminfo_mb()[0]))


def runtimes():
    """Read-only summary of the per-site app runtimes (managed in Universal Apps)."""
    try:
        from universalAddons.apps import runtimes as rt
        installed = rt.installed()
    except Exception as exc:  # the runtime manager is optional here
        return {'kinds': [], 'error': 'Could not read the runtimes: %s' % str(exc)[:200]}
    kinds = []
    for kind in ('dotnet', 'node', 'java', 'python'):
        entries = installed.get(kind) or []
        kinds.append({'kind': kind, 'versions': [e.get('version') for e in entries],
                      'sources': sorted({e.get('source') or 'system' for e in entries}),
                      'bytes': sum(e.get('size') or 0 for e in entries) if any(e.get('size') for e in entries) else None})
    return {'kinds': kinds, 'root': getattr(rt, 'RUNTIME_ROOT', '/opt/cp-runtimes'), 'bytes': _du(rt.RUNTIME_ROOT)}


CACHE_DIRS = (('dnf package cache', '/var/cache/dnf'),)


def disk():
    """Size on disk of each installed application (packages, data, logs), runtime and cache."""
    rows = []
    for key in sv.ORDER:
        info = sv.app_info(key)
        if not _version(key):
            continue
        major = _pg_major() if key == 'postgresql' else None
        packages = _installed_packages(_packages(key, major)) if key != 's3' else [s3.BIN]
        row = {'key': key, 'title': info['title'], 'packages': packages, 'package_bytes': _install_bytes(key, major),
               'data_dir': _data_dir(key, major), 'data_bytes': _du(_data_dir(key, major)),
               'logs': [{'path': p, 'bytes': _du(p)} for p in info.get('log_dirs') or () if os.path.isdir(p)],
               'removable': info['kind'] in ('service', 'client', 'bridge')}
        for path in info.get('install_dirs') or ():
            row['logs'].append({'path': path, 'bytes': _du(path), 'install': True})
        rows.append(row)
    caches = [{'title': title, 'path': path, 'bytes': _du(path)} for title, path in CACHE_DIRS if os.path.isdir(path)]
    return {'apps': rows, 'runtimes': runtimes(), 'caches': caches}


# ----------------------------------------------------------------------------- install

def install(app, force=False, major=None):
    info = sv.app_info(app)
    _require_idle(app)
    report = preflight(app)
    refusal = sv.preflight_refusal(report['checks'], force)
    if refusal:
        raise AppError('Cannot install %s: %s' % (info['title'], refusal))
    args = {'app': app}
    if app == 'postgresql':
        major = int(major or sv.PG_DEFAULT_MAJOR)
        if major not in sv.PG_MAJORS:
            raise AppError('Choose PostgreSQL %s.' % ' or '.join(map(str, sv.PG_MAJORS)))
        args['major'] = major
    return jobs.spawn('appsvc', 'install_run', args)


def _run_service_manager(job, function, timeout=3600):
    """Run the panel's own installer (ServiceManager) and copy its progress file into the job log."""
    seen = 0
    with open(os.devnull, 'rb') as devnull:
        process = subprocess.Popen([sys.executable, SERVICE_MANAGER, '--function', function], cwd=ROOT,
                                   stdin=devnull, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    deadline = time.time() + timeout

    def copy_progress():
        nonlocal seen
        text = _read(LEGACY_STATUS)
        if len(text) < seen:
            seen = 0
        if text[seen:].strip():
            job.log(text[seen:][-6000:])
        seen = len(text)
    while process.poll() is None:
        if time.time() > deadline:
            process.kill()
            raise AppError('%s did not finish within %d minutes.' % (function, timeout // 60))
        time.sleep(3)
        copy_progress()
    copy_progress()
    output = process.stdout.read().decode('utf-8', 'replace') if process.stdout else ''
    if output.strip():
        job.log(output[-3000:])


def _package_command(op, package):
    if shutil.which('dnf') or shutil.which('yum'):
        tool = 'dnf' if shutil.which('dnf') else 'yum'
        return [tool, '-y', 'install' if op == 'install' else 'remove', package]
    return ['apt-get', '-y', 'install' if op == 'install' else 'remove', package]


def _command_step(argv, timeout=1800, env=None):
    def step(job):
        code, out = sv.run(argv, timeout=timeout, env=env)
        job.log(out[-4000:])
        if code != 0:
            raise AppError('%s failed (exit %d).' % (' '.join(argv[:4]), code))
    return step


def _memcached_loopback(job):
    """A fresh Memcached must not listen beyond loopback: it has no authentication."""
    if not os.path.isfile(sv.MEMCACHED_SYSCONFIG):
        return
    current = sv.memcached_current(_read(sv.MEMCACHED_SYSCONFIG))
    if all(sv.is_loopback(a) for a in current['listen']):
        return
    cfg = dict(current, listen=['127.0.0.1'])
    text = sv.render_sysconfig(_read(sv.MEMCACHED_SYSCONFIG), cfg)
    sv.snapshot([sv.MEMCACHED_SYSCONFIG], sv.backup_root('memcached'))
    sv.write_file(sv.MEMCACHED_SYSCONFIG, text)
    job.log('Memcached listened on %s; set it to 127.0.0.1 (backup kept).' % ','.join(current['listen']))


def _write_repo(path, text):
    def step(job):
        sv.write_file(path, text, new_mode=0o644)
        job.log('Wrote %s (GPG checking on)' % path)
    return step


def _vendor_steps(app, major):
    """Repository and package steps for the applications from vendor repositories."""
    el = _el()
    if el not in (8, 9):
        raise AppError('%s is offered here only on EL 8 or 9.' % sv.app_info(app)['title'])
    dnf = lambda *packages: _command_step(['dnf', '-y', 'install'] + list(packages), timeout=3600)
    if app == 'postgresql':
        paths = mo.pg_paths(major)

        def initdb(job):
            if os.path.isfile(os.path.join(paths['data'], 'PG_VERSION')):
                job.log('%s already holds a cluster; keeping it (no initdb).' % paths['data'])
                return
            env = dict(os.environ, PGSETUP_INITDB_OPTIONS='--auth-local=peer --auth-host=scram-sha-256 '
                                                          '--encoding=UTF8 --locale=C.UTF-8')
            _command_step([paths['setup'], 'initdb'], timeout=600, env=env)(job)
        return [('Add the PGDG repository', _write_repo(mo.pg_repo_file(major), mo.pg_repo_text(major, el))),
                ('Disable the OS PostgreSQL module', _command_step(['dnf', '-qy', 'module', 'disable', 'postgresql'])),
                ('Install PostgreSQL %d' % major, dnf('postgresql%d-server' % major)),
                ('Initialise the cluster', initdb),
                ('Start PostgreSQL', _command_step(['systemctl', 'enable', '--now', sv.pg_unit(major)], timeout=300))]
    if app == 'mongodb':
        def safe_start(job):
            if mo.mongo_sysconfig_conflict(_read(mo.MONGO_SYSCONFIG)):
                raise AppError('%s sets OPTIONS; remove that line so the panel can manage MongoDB.' % mo.MONGO_SYSCONFIG)
            cfg = dict(mo.mongo_defaults(0), auth=False)   # auth goes on next, once the admin user exists
            sv.write_file(mo.MONGO_DROPIN, mo.render_mongo_dropin(cfg), new_mode=0o644)
            sv.run(['systemctl', 'daemon-reload'], timeout=60)
            _command_step(['systemctl', 'enable', '--now', 'mongod'], timeout=300)(job)
        return [('Add the MongoDB repository', _write_repo(mo.MONGO_REPO_FILE, mo.mongo_repo_text(el))),
                ('Install MongoDB %s' % mo.MONGO_SERIES, dnf('mongodb-org-server', 'mongodb-mongosh')),
                ('Start MongoDB on 127.0.0.1 with a %g GB cache' % mo.mongo_defaults(0)['cache_gb'], safe_start)]
    if app == 'rabbitmq':
        def safe_start(job):
            # loopback and a memory watermark before the very first start
            sv.write_file(mo.RABBIT_DROPIN, mo.render_rabbit_conf(mo.rabbit_defaults(0)), new_mode=0o644)
            sv.write_file(mo.RABBIT_SYSTEMD_DROPIN, mo.RABBIT_SYSTEMD_TEXT, new_mode=0o644)
            sv.run(['systemctl', 'daemon-reload'], timeout=60)
            _command_step(['systemctl', 'enable', '--now', 'rabbitmq-server'], timeout=300)(job)
        steps = [('Import Team RabbitMQ signing key %d' % (i + 1), _command_step(['rpm', '--import', key]))
                 for i, key in enumerate(mo.RABBIT_KEYS)]
        return steps + [('Add the RabbitMQ and Erlang repositories', _write_repo(mo.RABBIT_REPO_FILE, mo.rabbit_repo_text(el))),
                        ('Install Erlang and RabbitMQ', dnf('socat', 'logrotate', 'erlang', 'rabbitmq-server')),
                        ('Start RabbitMQ on 127.0.0.1', safe_start)]
    if app == 'oracle_client':
        return [('Add the Oracle Instant Client repository',
                 _write_repo(mo.ORACLE_CLIENT_REPO_FILE, mo.oracle_client_repo_text(el))),
                ('Install Instant Client Basic and SQL*Plus', dnf('oracle-instantclient-basic', 'oracle-instantclient-sqlplus'))]
    raise AppError('Unknown application.')


def install_run(job_id, app, major=None):
    info = sv.app_info(app)

    def install_step(job):
        function = LEGACY_FUNCTIONS.get((app, 'install'))
        if function:
            _run_service_manager(job, function)
        else:
            _command_step(_package_command('install', info['package']))(job)
            _memcached_loopback(job)
            _command_step(['systemctl', 'enable', '--now', info['unit']], timeout=120)(job)
        version = _version(app)
        if not version:
            raise AppError('%s is not installed after the installer ran (is another install running? see the log).'
                           % info['title'])
        job.log('Installed %s %s' % (info['title'], version))

    def health_step(job):
        ok, detail = _wait_healthy(app)
        if not ok:
            raise AppError('%s is installed but not answering: %s' % (info['title'], detail))
        return {'health': detail}

    if app == 's3':
        return _locked_job(job_id, app, _s3_install_steps())
    if app in NEW_PACKAGED:
        steps = list(_vendor_steps(app, major or sv.PG_DEFAULT_MAJOR))

        def check_installed(job):
            version = _version(app)
            if not version:
                raise AppError('%s is not installed after dnf ran; see the log.' % info['title'])
            job.log('Installed %s %s' % (info['title'], version))
        steps += [('Check the packages', check_installed), ('Health check', health_step)]
        if app in ('postgresql', 'mongodb'):
            defaults = dict(mo.pg_defaults(sv.meminfo_mb()[0]) if app == 'postgresql' else mo.mongo_defaults(0))
            steps.append(('Apply the panel\'s safe defaults', lambda job: _apply_settings(job, app, defaults, False)))
        return _locked_job(job_id, app, steps)
    return _locked_job(job_id, app, [('Install %s' % info['title'], install_step), ('Health check', health_step)])


def _locked_job(job_id, app, steps):
    try:
        with app_lock(app):
            return jobs.run_job(job_id, steps)
    except AppError as exc:   # the lock was taken by another job
        job = jobs.Job(job_id)
        job.log('ERROR: %s' % exc)
        job.fail(exc)
        return job.data


# ----------------------------------------------------------------------------- uninstall

def _dnf_preview(packages):
    code, out = sv.run(['dnf', 'remove', '--assumeno'] + list(packages), timeout=600, env=DNF_ENV)
    parsed = sv.parse_dnf_removal(out)
    if not parsed['packages']:
        raise AppError('dnf would remove nothing (exit %d): %s' % (code, out.strip()[-500:]))
    return parsed, out


def remove_preview(app):
    info = sv.app_info(app)
    if info['kind'] == 'status':
        raise AppError('%s is managed in the %s.' % (info['title'], info.get('link_title')))
    if not _version(app):
        raise AppError('%s is not installed.' % info['title'])
    _require_idle(app)
    return jobs.spawn('appsvc', 'remove_preview_run', {'app': app})


def remove_preview_run(job_id, app):
    info = sv.app_info(app)

    if app == 's3':
        return jobs.run_job(job_id, [('Preview removal', lambda job: _s3_removal_plan())])

    def step(job):
        major = _pg_major() if app == 'postgresql' else None
        packages = _installed_packages(_packages(app, major))
        if not packages:
            raise AppError('None of %s\'s packages is installed.' % info['title'])
        parsed, out = _dnf_preview(packages)
        job.log(out[-4000:])
        data_dir = _data_dir(app, major)
        return {'app': app, 'requested': packages, 'packages': parsed['packages'], 'freed': parsed['freed'],
                'data_dir': data_dir, 'data_bytes': _du(data_dir)}
    return jobs.run_job(job_id, [('Preview removal', step)])


def _previewed(app, preview_job):
    """The package list of a finished, recent removal preview for `app`."""
    try:
        data = jobs.status(preview_job)
    except ValueError:
        raise AppError('Unknown preview; preview the removal again.')
    result = (data.get('result') or {}).get('Preview removal') or {}
    if data.get('module') != 'appsvc' or data.get('action') != 'remove_preview_run' or result.get('app') != app:
        raise AppError('That preview is for something else; preview the removal again.')
    if data.get('state') != 'done' or time.time() - data.get('updated', 0) > PREVIEW_MAX_AGE:
        raise AppError('The preview is not finished or is older than %d minutes; preview again.' % (PREVIEW_MAX_AGE // 60))
    return result


def removal_confirmation(app, confirm, delete_data, confirm_name, preview_job):
    """Validate an uninstall request; returns the packages previewed (or None for the old page's API)."""
    info = sv.app_info(app)
    if confirm is not True:
        raise AppError('Confirm removing %s.' % info['title'])
    if delete_data is True and str(confirm_name or '').strip().lower() != app:
        raise AppError('Type %s to confirm deleting its data.' % app)
    if info['kind'] == 'status':
        raise AppError('%s is managed in the %s.' % (info['title'], info.get('link_title')))
    if preview_job is None:
        if app not in ORIGINAL:
            raise AppError('Preview what will be removed first.')
        return None
    return _previewed(app, preview_job)['packages']


def remove(app, confirm=False, delete_data=False, confirm_name='', preview_job=None):
    info = sv.app_info(app)
    packages = removal_confirmation(app, confirm, delete_data, confirm_name, preview_job)
    if not _version(app):
        raise AppError('%s is not installed.' % info['title'])
    _require_idle(app)
    args = {'app': app, 'delete_data': delete_data is True}
    if packages is not None:
        args['packages'] = packages
    return jobs.spawn('appsvc', 'remove_run', args)


PANEL_FILES = {'redis': (), 'mongodb': (mo.MONGO_DROPIN,), 'rabbitmq': (mo.RABBIT_DROPIN, mo.RABBIT_SYSTEMD_DROPIN)}


def remove_run(job_id, app, delete_data=False, packages=None):
    info = sv.app_info(app)
    if app == 's3':
        return _locked_job(job_id, app, _s3_remove_steps(delete_data is True, packages))
    major = _pg_major() if app == 'postgresql' else None
    data_dir = _data_dir(app, major)

    def stop_step(job):
        if info['kind'] != 'client':
            sv.run(['systemctl', 'disable', '--now', _unit(app, major)], timeout=300)

    def remove_step(job):
        function = LEGACY_FUNCTIONS.get((app, 'remove'))
        if packages is not None:
            installed = _installed_packages(_packages(app, major))
            parsed, out = _dnf_preview(installed)
            job.log(out[-3000:])
            if sorted(parsed['packages']) != sorted(packages):
                raise AppError('dnf would now remove a different set of packages than the preview showed (%s); '
                               'nothing was removed. Preview again.' % ', '.join(parsed['packages'])[:500])
            if function:
                _run_service_manager(job, function)
            else:
                _command_step(['dnf', '-y', 'remove'] + installed, timeout=1800)(job)
        elif function:
            _run_service_manager(job, function)
        else:
            _command_step(['systemctl', 'disable', '--now', info['unit']], timeout=120)(job)
            _command_step(_package_command('remove', info['package']))(job)
        if _version(app):
            raise AppError('%s is still installed after removal; see the log.' % info['title'])

    def cleanup_step(job):
        reload = False
        if app == 'redis':
            conf = _redis_conf()
            for path in (sv.redis_dropin_path(conf), sv.REDIS_SYSTEMD_DROPIN):
                if os.path.isfile(path):
                    os.unlink(path)
                    job.log('Removed %s' % path)
            reload = True
            sv.drop_secret('redis')
        for path in PANEL_FILES.get(app, ()) + ((_mssql_service().PROTECT_DROPIN,) if app == 'mssql' else ()):
            if os.path.isfile(path):
                os.unlink(path)
                job.log('Removed %s' % path)
                reload = True
        if reload:
            sv.run(['systemctl', 'daemon-reload'], timeout=60)
        result = {'data_dir': data_dir, 'data_deleted': False}
        if delete_data:
            sv.drop_secret(app)
            if data_dir and os.path.isdir(data_dir) and not os.path.islink(data_dir):
                shutil.rmtree(data_dir)
                job.log('Deleted the data directory %s' % data_dir)
                result['data_deleted'] = True
            if app == 'mssql':
                state = _mssql_service().STATE_DIR
                for name in ('sa.json', 'databases.json'):
                    if os.path.isfile(os.path.join(state, name)):
                        os.unlink(os.path.join(state, name))
                job.log('Forgot the sa password and the database list (the databases are gone).')
        elif data_dir and os.path.isdir(data_dir):
            job.log('Kept the data directory %s' % data_dir)
        return result

    steps = [('Remove %s' % info['title'], remove_step), ('Clean up', cleanup_step)]
    if packages is not None:
        steps.insert(0, ('Stop %s' % info['title'], stop_step))
    return _locked_job(job_id, app, steps)


# ----------------------------------------------------------------------------- configuration

def _validate(app, settings, ram_mb, confirm_exposed):
    info = sv.app_info(app)
    if info['kind'] in ('client', 'status'):
        raise AppError('%s has no settings here.' % info['title'])
    if not _version(app):
        raise AppError('%s is not installed.' % info['title'])
    port = None
    if app == 'elasticsearch':
        cfg, warnings = sv.validate_es(settings, ram_mb, _read(sv.ES_YML), confirm_exposed)
        port = cfg['http_port']
    elif app == 'redis':
        cfg, warnings = sv.validate_redis(settings, ram_mb, confirm_exposed)
        port = cfg['port']
    elif app == 'memcached':
        if not os.path.isfile(sv.MEMCACHED_SYSCONFIG):
            raise AppError('%s is missing; the panel configures Memcached only through it.' % sv.MEMCACHED_SYSCONFIG)
        cfg, warnings = sv.validate_memcached(settings, ram_mb, confirm_exposed)
        port = cfg['port']
    elif app == 'mssql':
        if not _mssql()._installed():
            raise AppError('SQL Server was set up outside the panel; the panel does not change its settings.')
        cfg, warnings = validate_mssql(settings, ram_mb)
    elif app == 'postgresql':
        cfg, warnings = mo.validate_pg(settings, ram_mb, confirm_exposed)
    elif app == 'mongodb':
        if mo.mongo_sysconfig_conflict(_read(mo.MONGO_SYSCONFIG)):
            raise AppError('%s sets OPTIONS, which would override the panel; remove that line first.' % mo.MONGO_SYSCONFIG)
        cfg, warnings = mo.validate_mongo(settings, ram_mb, confirm_exposed)
    elif app == 's3':
        cfg, warnings = _s3_validate(settings, ram_mb, confirm_exposed)
    else:
        cfg, warnings = mo.validate_rabbit(settings, ram_mb, confirm_exposed)
    port = port or PORTS.get(app)
    pid = _systemd(_unit(app)).get('MainPID', '0')
    if port and port in sv.ports_in_use(_ss(), int(pid) if pid.isdigit() and int(pid) > 0 else None):
        raise AppError('Port %d is already used by another program.' % port)
    caps = dict(_caps(ram_mb, exclude=app))
    mine = sv.cap_mb(app, cfg)
    if mine:
        caps[info['title']] = mine
    warning = sv.budget_warning(caps, ram_mb)
    if warning:
        warnings.append(warning)
    return cfg, warnings


def validate_mssql(settings, ram_mb):
    """The SQL Server memory cap, within the SQL Server add-on's own bounds."""
    sq = _mssql_service()
    if not isinstance(settings, dict):
        raise AppError('Settings must be an object.')
    try:
        limit = sq.validate_memory_limit(settings.get('memory_limit_mb'), ram_mb)
    except sq.SQLError as exc:
        raise AppError(str(exc))
    warnings = []
    if limit > 2048:
        warnings.append('SQL Server Express uses at most about 1.4 GB for its buffer pool; a cap above 2 GB mostly '
                        'reserves memory it will not use.')
    return {'memory_limit_mb': limit, 'max_server_memory_mb': sq.max_server_memory_mb(limit)}, warnings


def configure(app, settings, confirm_exposed=False):
    sv.app_info(app)
    _require_idle(app)
    cfg, warnings = _validate(app, settings, sv.meminfo_mb()[0], confirm_exposed)
    started = jobs.spawn('appsvc', 'configure_run', {'app': app, 'settings': settings,
                                                     'confirm_exposed': confirm_exposed is True})
    return dict(started, warnings=warnings)


def _keystore_set(password, log):
    """bootstrap.password: the elastic user's password while none is stored in the .security index."""
    env = dict(os.environ, ES_PATH_CONF=os.path.dirname(sv.ES_YML))
    before = os.stat(sv.ES_KEYSTORE) if os.path.isfile(sv.ES_KEYSTORE) else None
    if before is None:
        code, out = sv.run([sv.ES_KEYSTORE_TOOL, 'create'], timeout=120, env=env)
        if code != 0:
            raise AppError('Could not create the Elasticsearch keystore: %s' % out.strip()[-300:])
    code, out = sv.run([sv.ES_KEYSTORE_TOOL, 'add', '-x', '-f', 'bootstrap.password'], timeout=120,
                       input_text=password + '\n', env=env)
    if code != 0:
        raise AppError('Could not store the elastic password in the keystore: %s'
                       % sv.redact(out.strip()[-300:], [password]))
    try:
        if before is not None:
            os.chown(sv.ES_KEYSTORE, before.st_uid, before.st_gid)
            os.chmod(sv.ES_KEYSTORE, before.st_mode & 0o7777)
        else:
            os.chown(sv.ES_KEYSTORE, 0, grp.getgrnam('elasticsearch').gr_gid)
            os.chmod(sv.ES_KEYSTORE, 0o660)
    except (OSError, KeyError):
        pass
    log('Stored bootstrap.password in the keystore.')


def _es_change(cfg, log):
    yml = _read(sv.ES_YML)
    if not yml:
        raise AppError('%s is missing or unreadable.' % sv.ES_YML)
    stored = sv.load_secret('elasticsearch')
    password, generated = None, False
    if cfg['security']:
        if stored and not cfg['rotate_password']:
            password = stored['password']
        else:
            password, generated = sv.new_password(), True
    paths = [sv.ES_YML, sv.ES_HEAP, sv.ES_KEYSTORE, sv.secret_path('elasticsearch')]

    def write():
        sv.write_file(sv.ES_YML, sv.apply_block(yml, sv.render_es_block(cfg)))
        sv.write_file(sv.ES_HEAP, sv.heap_text(cfg['heap_mb']), new_mode=0o644)
        log('Wrote the managed block in %s and %s (heap %d MB)' % (sv.ES_YML, sv.ES_HEAP, cfg['heap_mb']))
        if password:
            _keystore_set(password, log)
            if generated:
                sv.store_secret('elasticsearch', password)
    return paths, write, generated, [password]


def _redis_persistence_switch(current, cfg, password, log):
    """Switching to or from AOF on restart would load an empty or stale file: sync the data first."""
    if current['persistence'] == cfg['persistence'] or _systemd('redis').get('ActiveState') != 'active':
        return
    target = sv.redis_target(current)

    def info():
        return sv.redis_info(sv.redis_command([('INFO', 'persistence')], password=password, **target)[0])
    if cfg['persistence'] == 'aof':
        sv.redis_command([('CONFIG', 'SET', 'appendonly', 'yes')], password=password, **target)
        done = lambda i: i.get('aof_rewrite_in_progress') == '0' and i.get('aof_rewrite_scheduled') == '0' \
            and i.get('aof_enabled') == '1' and i.get('aof_last_bgrewrite_status') == 'ok'
        what = 'Wrote the current data to the append-only file'
    elif current['persistence'] == 'aof':
        sv.redis_command([('BGSAVE',)], password=password, **target)
        done = lambda i: i.get('rdb_bgsave_in_progress') == '0' and i.get('rdb_last_bgsave_status') == 'ok'
        what = 'Saved the current data to dump.rdb'
    else:
        return
    deadline = time.time() + 600
    time.sleep(1)
    while not done(info()):
        if time.time() > deadline:
            raise AppError('Redis did not finish writing its data within 10 minutes; nothing was changed.')
        time.sleep(2)
    log(what + ' before switching persistence to %s' % cfg['persistence'])


def _redis_change(cfg, log):
    conf, main, dropin = _redis_texts()
    if not main:
        raise AppError('%s is missing or unreadable.' % conf)
    current = sv.redis_current(main, dropin)
    live = sv.redis_password_in(main, dropin)
    password, generated = None, False
    if cfg['password']:
        if live and not cfg['rotate_password']:
            password = live
        else:
            password, generated = sv.new_password(), True
    _redis_persistence_switch(current, cfg, live or None, log)
    dropin_path = sv.redis_dropin_path(conf)
    paths = [conf, dropin_path, sv.REDIS_SYSTEMD_DROPIN, sv.secret_path('redis')]
    try:
        gid = grp.getgrnam('redis').gr_gid
    except KeyError:
        gid = 0

    def write():
        sv.write_file(dropin_path, sv.render_redis_dropin(cfg, password), mode=0o640, uid=0, gid=gid)
        sv.write_file(conf, sv.apply_block(main, sv.redis_include_block(conf)))
        sv.write_file(sv.REDIS_SYSTEMD_DROPIN, sv.REDIS_SYSTEMD_TEXT, new_mode=0o644)
        log('Wrote %s, the include block in %s and %s' % (dropin_path, conf, sv.REDIS_SYSTEMD_DROPIN))
        if generated:
            sv.store_secret('redis', password)
        elif not cfg['password']:
            sv.drop_secret('redis')
    return paths, write, generated, [password, live]


def _memcached_change(cfg, log):
    text = _read(sv.MEMCACHED_SYSCONFIG)

    def write():
        sv.write_file(sv.MEMCACHED_SYSCONFIG, sv.render_sysconfig(text, cfg))
        log('Updated PORT, MAXCONN, CACHESIZE and -l in %s' % sv.MEMCACHED_SYSCONFIG)
    return [sv.MEMCACHED_SYSCONFIG], write, False, []


def _mssql_change(cfg, log):
    sq = _mssql_service()
    paths = [sq.MSSQL_CONF_FILE, sq.PROTECT_DROPIN, os.path.join(sq.STATE_DIR, 'sa.json')]

    def write():
        limit = _mssql().write_memory_limit(cfg['memory_limit_mb'])
        log('Set memory.memorylimitmb to %d MB and the systemd ceiling to %d MB' % (limit, limit + 512))
    return paths, write, False, []


def _owner(user):
    try:
        entry = pwd.getpwnam(user)
        return entry.pw_uid, entry.pw_gid
    except KeyError:
        return None, None


def _pg_change(cfg, log):
    major = _pg_major()
    paths = mo.pg_paths(major)
    conf, hba = _read(paths['conf']), _read(paths['hba'])
    if not conf or not hba:
        raise AppError('%s or pg_hba.conf is missing or unreadable.' % paths['conf'])
    uid, gid = _owner('postgres')

    def write():
        sv.write_file(paths['panel'], mo.render_pg_panel(cfg), mode=0o600, uid=uid, gid=gid)
        sv.write_file(paths['conf'], sv.apply_block(conf, mo.pg_include_block()))
        sv.write_file(paths['hba'], sv.apply_block_top(hba, mo.render_pg_hba_block(cfg)))
        log('Wrote %s, the include block in postgresql.conf and the panel block at the top of pg_hba.conf'
            % paths['panel'])
    return [paths['panel'], paths['conf'], paths['hba']], write, False, []


def _mongo_change(cfg, log):
    current = mo.mongo_current(_read(mo.MONGO_DROPIN, None), _read(mo.MONGO_CONF))
    stored = sv.load_secret('mongodb')
    password, generated = None, False
    if cfg['auth']:
        if stored and not cfg['rotate_password']:
            password = stored['password']
        else:
            password, generated = sv.new_password(), True
    if generated:
        # create (or re-key) the admin user on the running server first; with no users yet, the
        # localhost exception allows this even when authorization is already on
        old = stored['password'] if stored and current['auth'] else None
        code, out = _mongosh(mo.mongo_user_script(password, old), mo.mongo_target(current), timeout=60)
        if code != 0 or not any(w in out for w in ('created', 'changed')):
            raise AppError('Could not create the MongoDB admin user (is MongoDB running, and were users added '
                           'outside the panel?): %s' % sv.redact(out.strip()[-300:], [password, old]))
        log('Admin user %s %s' % (mo.MONGO_ADMIN, 'created' if 'created' in out else 'given a new password'))
        sv.store_secret('mongodb', password)   # the user now has this password, whatever happens next

    def write():
        sv.write_file(mo.MONGO_DROPIN, mo.render_mongo_dropin(cfg), new_mode=0o644)
        log('Wrote %s (cache %g GB, bindIp %s, authorization %s)' % (
            mo.MONGO_DROPIN, cfg['cache_gb'], ','.join(cfg['bind_ip']), 'on' if cfg['auth'] else 'off'))
    return [mo.MONGO_DROPIN], write, generated, [password]


def _rabbit_change(cfg, log):
    def write():
        sv.write_file(mo.RABBIT_DROPIN, mo.render_rabbit_conf(cfg), new_mode=0o644)
        sv.write_file(mo.RABBIT_SYSTEMD_DROPIN, mo.RABBIT_SYSTEMD_TEXT, new_mode=0o644)
        log('Wrote %s and %s' % (mo.RABBIT_DROPIN, mo.RABBIT_SYSTEMD_DROPIN))
    return [mo.RABBIT_DROPIN, mo.RABBIT_SYSTEMD_DROPIN], write, False, []


CHANGES = {'elasticsearch': _es_change, 'redis': _redis_change, 'memcached': _memcached_change,
           'mssql': _mssql_change, 'postgresql': _pg_change, 'mongodb': _mongo_change, 'rabbitmq': _rabbit_change,
           's3': lambda cfg, log: _s3_change(cfg, log)}


def _healthy_after(app, cfg):
    ok, detail = _wait_healthy(app)
    if ok and app == 'mssql':
        mb = _mssql().apply_max_server_memory(cfg['memory_limit_mb'])   # a failure here rolls back too
        detail += '; max server memory %d MB' % mb
    return ok, detail


def _apply_settings(job, app, settings, confirm_exposed):
    hidden = []
    log = lambda text: job.log(sv.redact(text, hidden))
    cfg, warnings = _validate(app, settings, sv.meminfo_mb()[0], confirm_exposed)
    for warning in warnings:
        log('Warning: %s' % warning)
    paths, write, generated, secrets = CHANGES[app](cfg, log)
    hidden.extend(s for s in secrets if s)
    try:
        _, detail = sv.apply_with_rollback(paths, write, lambda: _restart(app), lambda: _healthy_after(app, cfg),
                                           sv.backup_root(app), log=log)
    except Exception as exc:
        raise AppError(sv.redact(exc, hidden))
    # Never the password itself: the page fetches it once through `reveal`.
    return {'health': detail, 'password_generated': generated}


def configure_run(job_id, app, settings, confirm_exposed=False):
    info = sv.app_info(app)
    return _locked_job(job_id, app, [('Apply %s settings' % info['title'],
                                      lambda job: _apply_settings(job, app, settings, confirm_exposed))])


def revert(app):
    sv.app_info(app)
    if not sv.list_snapshots(sv.backup_root(app)):
        raise AppError('There is no earlier configuration to go back to.')
    _require_idle(app)
    return jobs.spawn('appsvc', 'revert_run', {'app': app})


def revert_run(job_id, app):
    info = sv.app_info(app)

    def revert_step(job):
        root = sv.backup_root(app)
        names = sv.list_snapshots(root)
        if not names:
            raise AppError('There is no earlier configuration to go back to.')
        latest = os.path.join(root, names[-1])
        with open(os.path.join(latest, 'manifest.json')) as handle:
            paths = sorted(json.load(handle)['files'])
        job.log('Restoring the configuration saved at %s' % names[-1])
        _, detail = sv.apply_with_rollback(paths, lambda: sv.restore(latest), lambda: _restart(app),
                                           lambda: _wait_healthy(app), root, log=job.log, keep_snapshot=False)
        shutil.rmtree(latest, ignore_errors=True)
        if app == 'mssql':   # sp_configure lives in master, not in a file: set it for the restored cap
            limit = _mssql()._meta().get('memory_limit_mb')
            if limit:
                detail += '; max server memory %d MB' % _mssql().apply_max_server_memory(limit)
        return {'health': detail, 'restored': names[-1]}

    return _locked_job(job_id, app, [('Revert %s settings' % info['title'], revert_step)])


# ----------------------------------------------------------------------------- PostgreSQL databases

def pg_create(database, user):
    """Create a database and its owner with a generated password, which is returned once (not stored)."""
    major = _pg_major()
    if not major:
        raise AppError('PostgreSQL is not installed.')
    _require_idle('postgresql')
    password = sv.new_password()
    sql = mo.pg_create_sql(database, user, password)
    code, out = _psql(major, stdin=sql, timeout=120)
    if code != 0:
        raise AppError('PostgreSQL refused: %s' % sv.redact(out.strip()[-300:], [password]))
    current = _current('postgresql', sv.meminfo_mb()[0])
    host = mo.pg_connection_info(current, major)['host']
    return {'database': database, 'user': user, 'password': password, 'host': host, 'port': 5432}


# ----------------------------------------------------------------------------- service controls

def control(app, op):
    info = sv.app_info(app)
    if op not in CONTROL_OPS:
        raise AppError('Unknown service action.')
    if info['kind'] == 'client':
        raise AppError('%s has no service.' % info['title'])
    if info['kind'] == 'status':
        raise AppError('%s is controlled in the %s.' % (info['title'], info.get('link_title')))
    if not _version(app):
        raise AppError('%s is not installed.' % info['title'])
    _require_idle(app)
    if op in ('start', 'restart'):
        return jobs.spawn('appsvc', 'control_run', {'app': app, 'op': op})
    if app == 'mssql' and op == 'stop':
        try:
            _mssql().service('stop')
        except ValueError as exc:
            raise AppError(str(exc))
    else:
        _systemctl(op, _unit(app))
    return {'app': app, 'op': op, 'done': True}


def control_run(job_id, app, op):
    info = sv.app_info(app)

    def step(job):
        if app == 'mssql':
            _mssql().service(op)   # the SQL Server add-on's own start/restart
        else:
            if app in ('redis', 'mongodb', 'rabbitmq', 's3'):
                sv.run(['systemctl', 'daemon-reload'], timeout=60)
            _systemctl(op, _unit(app), timeout=960 if app == 'elasticsearch' else 300)
        ok, detail = _wait_healthy(app)
        if not ok:
            raise AppError('%s did not come up healthy: %s' % (info['title'], detail))
        job.log('Healthy: %s' % detail)
        return {'health': detail}

    return _locked_job(job_id, app, [('%s %s' % (op.capitalize(), info['title']), step)])


# ----------------------------------------------------------------------------- S3 object storage (Garage)

def _s3_state_path():
    return os.path.join(sv.STATE_DIR, s3.STATE_FILE)


def _s3_state():
    try:
        with open(_s3_state_path()) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _s3_save_state(**changes):
    data = dict(_s3_state(), **changes)
    sv._private_write(_s3_state_path(), data)
    return data


def _s3_token():
    """The admin API token (root side only; never returned or logged)."""
    return _read(s3.ADMIN_TOKEN).strip() or None


def _s3_version():
    if not os.path.isfile(s3.BIN):
        return None
    version = _s3_state().get('version')
    if version:
        return version
    code, out = sv.run([s3.BIN, '--version'], timeout=20)
    match = re.search(r'v?\d+\.\d+\.\d+', out or '')
    return match.group(0) if code == 0 and match else 'unknown'


def _s3_capacity(data_dir=None):
    try:
        return shutil.disk_usage(data_dir or _data_dir('s3')).total
    except OSError:
        return 1024 ** 3


def _s3_health_once():
    """Give the node its layout role if it has none yet (first start, new data directory), then /health."""
    token = _s3_token()
    if not token:
        return False, '%s is missing' % s3.ADMIN_TOKEN
    try:
        s3.bootstrap(token, _s3_capacity())
    except AppError as exc:
        return False, str(exc)
    return s3.health(token)


def _s3_require_running():
    if not _version('s3'):
        raise AppError('S3 Object Storage is not installed.')
    _require_idle('s3')
    if _systemd(s3.UNIT).get('ActiveState') != 'active':
        raise AppError('Start S3 Object Storage first.')
    token = _s3_token()
    if not token:
        raise AppError('%s is missing; reinstall S3 Object Storage.' % s3.ADMIN_TOKEN)
    return token


def _s3_status_extras(current, running, ram_total):
    extras = {'memory_bounds': s3.memory_bounds(ram_total), 'endpoint': current.get('endpoint'),
              'offered_version': s3.VERSION, 'conflicts': s3.outside_conflicts(_read(s3.CONF))}
    if running and _s3_token():
        try:
            extras['inventory'] = s3.inventory(_s3_token())
        except AppError as exc:
            extras['inventory_error'] = sv.redact(exc, [_s3_token()])
    return extras


def _s3_validate(settings, ram_mb, confirm_exposed):
    cfg, warnings = s3.validate(settings, ram_mb, confirm_exposed, _s3_state().get('endpoint'))
    conflicts = s3.outside_conflicts(_read(s3.CONF))
    if conflicts:
        raise AppError('%s sets %s outside the panel block; remove those lines first (TOML refuses a key given '
                       'twice).' % (s3.CONF, ', '.join(conflicts)))
    now = s3.current(_read(s3.CONF), _read(s3.DROPIN, None))
    if cfg['data_dir'] != now['data_dir']:
        token = _s3_token()
        if _systemd(s3.UNIT).get('ActiveState') == 'active' and token and s3.inventory(token)['buckets']:
            raise AppError('The data directory can only be changed while there are no buckets: the panel does not '
                           'move object data. Stop Garage and move %s by hand if you need to.' % now['data_dir'])
        if os.path.isdir(cfg['data_dir']) and os.listdir(cfg['data_dir']) and \
                not os.path.isdir(os.path.join(cfg['data_dir'], 'meta')):
            raise AppError('%s already holds other files; choose an empty or new directory.' % cfg['data_dir'])
        warnings.append('A new data directory starts empty: Garage gets a new node identity there, and the access '
                        'keys of the old directory do not carry over.')
    pid = _systemd(s3.UNIT).get('MainPID', '0')
    used = sv.ports_in_use(_ss(), int(pid) if pid.isdigit() and int(pid) > 0 else None)
    for port in (cfg['s3_port'], cfg['web_port']):
        if port and port in used:
            raise AppError('Port %d is already used by another program.' % port)
    return cfg, warnings


def _s3_dirs(data_dir, log=lambda text: None):
    """meta/ and data/ owned by the garage user (a kept directory gets the new uid after a reinstall)."""
    uid, gid = _owner(s3.USER)
    if uid is None:
        raise AppError('The %s system user is missing.' % s3.USER)
    for path in (data_dir, os.path.join(data_dir, 'meta'), os.path.join(data_dir, 'data')):
        os.makedirs(path, mode=0o750, exist_ok=True)
        info = os.stat(path)
        if (info.st_uid, info.st_gid) != (uid, gid):
            code, out = sv.run(['chown', '-R', '--no-dereference', '%d:%d' % (uid, gid), '--', path], timeout=3600)
            if code != 0:
                raise AppError('Could not give %s to the %s user: %s' % (path, s3.USER, out.strip()[-300:]))
            log('Gave %s to the %s user' % (path, s3.USER))
        os.chmod(path, 0o750)


def _s3_unified():
    return os.path.exists('/sys/fs/cgroup/cgroup.controllers')


def _s3_change(cfg, log):
    text = _read(s3.CONF)
    endpoint = _s3_state().get('endpoint')

    def write():
        _s3_dirs(cfg['data_dir'], log)
        sv.write_file(s3.CONF, s3.render_conf(text, cfg, endpoint), mode=0o640, uid=0,
                      gid=_owner(s3.USER)[1] or 0)
        sv.write_file(s3.DROPIN, s3.render_dropin(cfg, _s3_unified()), new_mode=0o644)
        log('Wrote the managed block in %s and %s (S3 on %s:%d, region %s, memory cap %d MB)' % (
            s3.CONF, s3.DROPIN, cfg['bind'], cfg['s3_port'], cfg['region'], cfg['memory_mb']))
    return [s3.CONF, s3.DROPIN], write, False, []


# --- downloads (HTTPS with certificate checks; every byte is hashed and compared)

def _http_get(url, headers=None, limit=4 * 1024 * 1024, timeout=60):
    """(bytes, response headers) of a small HTTPS document."""
    request = urllib.request.Request(url, headers=dict({'User-Agent': 'IndiansCloud-panel'}, **(headers or {})))
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            data = response.read(limit + 1)
            got = {k.lower(): v for k, v in response.headers.items()}
    except OSError as exc:
        raise AppError('Download failed: %s (%s)' % (url.split('?')[0], exc))
    if len(data) > limit:
        raise AppError('%s is larger than expected.' % url.split('?')[0])
    return data, got


def _http_download(url, target, limit, headers=None, timeout=900):
    """Stream url to target (0600); returns the SHA-256 (hex) of what was written."""
    import hashlib
    request = urllib.request.Request(url, headers=dict({'User-Agent': 'IndiansCloud-panel'}, **(headers or {})))
    digest, size = hashlib.sha256(), 0
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                for chunk in iter(lambda: response.read(1024 * 1024), b''):
                    size += len(chunk)
                    if size > limit:
                        raise AppError('%s is larger than expected.' % url)
                    digest.update(chunk)
                    handle.write(chunk)
    except OSError as exc:
        raise AppError('Download failed: %s (%s)' % (url, exc))
    return digest.hexdigest()


MANIFEST_TYPES = ('application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, '
                  'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json')


def _s3_fetch(job, work):
    """Download Garage from both official channels and verify them; returns the verified binary path."""
    repo = s3.REGISTRY_REPO
    base = s3.REGISTRY_BASE % repo
    token = json.loads(_http_get(s3.REGISTRY_TOKEN_URL % repo)[0].decode())['token']
    auth = {'Authorization': 'Bearer %s' % token, 'Accept': MANIFEST_TYPES}
    index, headers = _http_get('%s/manifests/%s' % (base, s3.VERSION), auth)
    if headers.get('docker-content-digest'):
        s3.check_digest(index, headers['docker-content-digest'])
    amd64 = s3.pick_amd64(json.loads(index.decode()))
    manifest, _ = _http_get('%s/manifests/%s' % (base, amd64), auth)
    s3.check_digest(manifest, amd64)
    layer = s3.single_layer(json.loads(manifest.decode()))
    job.log('Docker Hub %s:%s linux/amd64 manifest %s verified; layer %s' % (repo, s3.VERSION, amd64, layer))
    layer_path = os.path.join(work, 'layer.tar.gz')
    got = _http_download('%s/blobs/%s' % (base, layer), layer_path, s3.MAX_LAYER, {'Authorization': auth['Authorization']})
    if 'sha256:' + got != layer:
        raise AppError('Checksum mismatch on the image layer: expected %s, got sha256:%s. Nothing was installed.'
                       % (layer, got))
    image_sha = s3.extract_binary(layer_path, os.path.join(work, 'garage.image'))
    os.unlink(layer_path)
    job.log('Layer checksum verified; /garage in the image: sha256 %s' % image_sha)
    direct = os.path.join(work, 'garage.release')
    direct_sha = _http_download(s3.RELEASE_URL % (s3.VERSION, s3.ARCH), direct, s3.MAX_BINARY)
    job.log('Release binary from garagehq.deuxfleurs.fr: sha256 %s' % direct_sha)
    detail = s3.verify_agreement(direct_sha, image_sha)
    os.unlink(os.path.join(work, 'garage.image'))
    job.log(detail)
    return direct, direct_sha, detail


def _s3_write_secret(path, value, gid):
    fd = os.open(path + '.panel-tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(value + '\n')
    os.chown(path + '.panel-tmp', 0, gid)
    os.chmod(path + '.panel-tmp', 0o640)
    os.replace(path + '.panel-tmp', path)


def _s3_install_steps():
    work = os.path.join(sv.WORK_DIR, 'garage-download')
    found = {}

    def fetch(job):
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work, mode=0o700)
        found['path'], found['sha'], detail = _s3_fetch(job, work)
        return {'verified': detail}

    def user(job):
        if _owner(s3.USER)[0] is not None:
            job.log('The %s user exists already.' % s3.USER)
            return
        _command_step(['useradd', '--system', '--user-group', '--home-dir', s3.DEFAULT_DATA_DIR, '--no-create-home',
                       '--shell', '/sbin/nologin', '--comment', 'Garage S3 object storage', s3.USER])(job)

    def files(job):
        temporary = s3.BIN + '.panel-tmp'
        shutil.copyfile(found['path'], temporary)
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o755)
        os.replace(temporary, s3.BIN)
        shutil.rmtree(work, ignore_errors=True)
        if s3.sha256_file(s3.BIN) != found['sha']:
            raise AppError('%s changed while being installed.' % s3.BIN)
        code, out = sv.run([s3.BIN, '--version'], timeout=30)
        job.log('Installed %s: %s' % (s3.BIN, out.strip()[:200]))
        if code != 0:
            raise AppError('%s does not run on this server: %s' % (s3.BIN, out.strip()[-300:]))
        gid = _owner(s3.USER)[1]
        os.makedirs(s3.SECRET_DIR, mode=0o750, exist_ok=True)
        os.chown(s3.SECRET_DIR, 0, gid)
        os.chmod(s3.SECRET_DIR, 0o750)
        _s3_write_secret(s3.RPC_SECRET, _secrets.token_hex(32), gid)
        _s3_write_secret(s3.ADMIN_TOKEN, _secrets.token_urlsafe(32), gid)
        _s3_write_secret(s3.METRICS_TOKEN, _secrets.token_urlsafe(32), gid)
        job.log('Generated the RPC secret and admin token in %s (root:%s 0640; never shown)' % (s3.SECRET_DIR, s3.USER))
        cfg, _ = s3.validate(s3.defaults(), sv.meminfo_mb()[0] or 1024)
        _s3_dirs(cfg['data_dir'], job.log)
        sv.write_file(s3.CONF, s3.render_conf(_read(s3.CONF), cfg), mode=0o640, uid=0, gid=gid)
        from universalAddons.apps import service as app_service
        sv.write_file(s3.UNIT_FILE, s3.render_unit(app_service.systemd_version()), new_mode=0o644)
        sv.write_file(s3.DROPIN, s3.render_dropin(cfg, _s3_unified()), new_mode=0o644)
        job.log('Wrote %s, %s and %s (127.0.0.1:%d, %d MB cap)' % (s3.CONF, s3.UNIT_FILE, s3.DROPIN, cfg['s3_port'],
                                                                   cfg['memory_mb']))
        _s3_save_state(version=s3.VERSION, sha256=found['sha'], installed=int(time.time()))
        sv.run(['systemctl', 'daemon-reload'], timeout=60)
        _command_step(['systemctl', 'enable', '--now', s3.UNIT], timeout=120)(job)

    def health(job):
        ok, detail = _wait_healthy('s3')
        if not ok:
            raise AppError('Garage is installed but not healthy: %s' % detail)
        return {'health': detail}

    return [('Download and verify Garage %s' % s3.VERSION, fetch), ('Create the %s system user' % s3.USER, user),
            ('Install the binary, secrets, configuration and unit', files),
            ('Assign the storage layout and health check', health)]


def _s3_removal_plan():
    files = [p for p in (s3.BIN, s3.UNIT_FILE, s3.DROPIN, s3.CONF, s3.SECRET_DIR) if os.path.exists(p)]
    if _owner(s3.USER)[0] is not None:
        files.append('user %s' % s3.USER)
    data_dir = _data_dir('s3')
    return {'app': 's3', 'requested': files, 'packages': files, 'files': files,
            'freed': '%d MB' % ((_install_bytes('s3') or 0) // (1024 * 1024)),
            'endpoint': _s3_state().get('endpoint'), 'data_dir': data_dir, 'data_bytes': _du(data_dir)}


def _s3_remove_steps(delete_data, packages):
    data_dir = _data_dir('s3')

    def stop(job):
        plan = _s3_removal_plan()
        if packages is not None and sorted(plan['files']) != sorted(packages):
            raise AppError('What would be removed changed since the preview (%s); nothing was removed. Preview again.'
                           % ', '.join(plan['files'])[:400])
        sv.run(['systemctl', 'disable', '--now', s3.UNIT], timeout=300)

    def endpoint(job):
        domain = _s3_state().get('endpoint')
        if domain:
            _s3_vhost(domain, None)
            job.log('Removed the S3 proxy from the %s vhost' % domain)

    def remove(job):
        for path in (s3.UNIT_FILE, s3.DROPIN, s3.CONF, s3.BIN):
            if os.path.isfile(path):
                os.unlink(path)
                job.log('Removed %s' % path)
        if os.path.isdir(os.path.dirname(s3.DROPIN)) and not os.listdir(os.path.dirname(s3.DROPIN)):
            os.rmdir(os.path.dirname(s3.DROPIN))
        if os.path.isdir(s3.SECRET_DIR):
            shutil.rmtree(s3.SECRET_DIR)
            job.log('Removed %s (RPC secret, admin token)' % s3.SECRET_DIR)
        sv.run(['systemctl', 'daemon-reload'], timeout=60)
        sv.run(['systemctl', 'reset-failed', s3.UNIT], timeout=30)
        if _owner(s3.USER)[0] is not None:
            _command_step(['userdel', s3.USER])(job)
        try:
            os.unlink(_s3_state_path())
        except OSError:
            pass
        if os.path.exists(s3.BIN):
            raise AppError('%s is still there after removal; see the log.' % s3.BIN)

    def data(job):
        result = {'data_dir': data_dir, 'data_deleted': False}
        if delete_data and data_dir and os.path.isdir(data_dir) and not os.path.islink(data_dir):
            shutil.rmtree(s3.clean_data_dir(data_dir))
            job.log('Deleted the data directory %s (every bucket and object)' % data_dir)
            result['data_deleted'] = True
        elif data_dir and os.path.isdir(data_dir):
            job.log('Kept the data directory %s (buckets and keys come back on reinstall)' % data_dir)
        return result

    return [('Stop S3 Object Storage', stop), ('Remove the HTTPS endpoint', endpoint),
            ('Remove Garage', remove), ('Clean up', data)]


# --- buckets, keys and permissions (admin API on 127.0.0.1, token from a root-only file)

def _s3_bucket(token, name):
    info = s3.api('GET', '/v2/GetBucketInfo?globalAlias=%s' % s3.bucket_name(name), token)
    return s3.bucket_id(info.get('id')), info


def s3_bucket_create(name, max_size_mb=None, max_objects=None):
    name = s3.bucket_name(name)
    limits = s3.quotas(max_size_mb, max_objects)
    token = _s3_require_running()
    created = s3.api('POST', '/v2/CreateBucket', token, {'globalAlias': name})
    if limits['maxSize'] or limits['maxObjects']:
        s3.api('POST', '/v2/UpdateBucket?id=%s' % s3.bucket_id(created.get('id')), token, {'quotas': limits})
    return {'bucket': name, 'id': created.get('id'), 'quotas': limits}


def s3_bucket_delete(name, confirm_name=''):
    name = s3.bucket_name(name)
    if str(confirm_name or '').strip() != name:
        raise AppError('Type the bucket name to confirm deleting it.')
    token = _s3_require_running()
    bucket, info = _s3_bucket(token, name)
    if info.get('objects'):
        raise AppError('Bucket %s still holds %d object(s); empty it first (Garage deletes only empty buckets).'
                       % (name, info['objects']))
    s3.api('POST', '/v2/DeleteBucket?id=%s' % bucket, token)
    return {'bucket': name, 'deleted': True}


def s3_bucket_quota(name, max_size_mb=None, max_objects=None):
    limits = s3.quotas(max_size_mb, max_objects)
    token = _s3_require_running()
    bucket, _ = _s3_bucket(token, name)
    s3.api('POST', '/v2/UpdateBucket?id=%s' % bucket, token, {'quotas': limits})
    return {'bucket': s3.bucket_name(name), 'quotas': limits}


def s3_key_create(name):
    """A new access key. Its secret is returned in this reply only: the panel neither stores nor logs it."""
    name = s3.key_name(name)
    token = _s3_require_running()
    created = s3.api('POST', '/v2/CreateKey', token, {'name': name, 'neverExpires': True})
    secret = created.get('secretAccessKey')
    if not secret:
        raise AppError('Garage created the key but returned no secret; delete it and try again.')
    return {'id': s3.key_id(created.get('accessKeyId')), 'name': name, 'secret': secret,
            'note': 'Copy the secret now: it is shown only this once.'}


def s3_key_delete(key):
    key = s3.key_id(key)
    token = _s3_require_running()
    s3.api('POST', '/v2/DeleteKey?id=%s' % key, token)
    return {'key': key, 'deleted': True}


def s3_permission(bucket, key, read=False, write=False, owner=False):
    """Set exactly these permissions of `key` on `bucket` (allow the ticked ones, deny the others)."""
    key = s3.key_id(key)
    wanted = s3.permissions(read, write, owner)
    token = _s3_require_running()
    bucket_id, _ = _s3_bucket(token, bucket)
    allow = {k: v for k, v in wanted.items()}
    deny = {k: not v for k, v in wanted.items()}
    if any(allow.values()):
        s3.api('POST', '/v2/AllowBucketKey', token, {'bucketId': bucket_id, 'accessKeyId': key, 'permissions': allow})
    if any(deny.values()):
        s3.api('POST', '/v2/DenyBucketKey', token, {'bucketId': bucket_id, 'accessKeyId': key, 'permissions': deny})
    return {'bucket': s3.bucket_name(bucket), 'key': key, 'permissions': wanted}


# --- the HTTPS endpoint: an OpenLiteSpeed proxy on a dedicated panel site, with the site's SSL

def _s3_vhost(domain, port):
    """Write (port) or remove (None) the proxy block in the site's vhost.conf; restart OLS, restore on failure."""
    from universalAddons.htaccess import service as hs
    path = os.path.join(hs.VHOSTS, s3.clean_domain(domain), 'vhost.conf')
    if not os.path.isfile(path):
        raise AppError('No OpenLiteSpeed vhost for %s: create the site (or subdomain) in the panel first.' % domain)
    text = _read(path)
    if port is None:
        updated = s3.strip_vhost_block(text)
    else:
        problems = s3.vhost_problems(text)
        if problems:
            raise AppError('%s cannot carry the S3 endpoint: %s.' % (domain, '; '.join(problems)))
        updated = s3.apply_vhost(text, port)
    if updated == text:
        return False
    saved = hs._backup([path])
    hs._write_atomic(path, updated)
    if not hs.restart():
        hs._restore(saved)
        hs.restart()
        raise AppError('OpenLiteSpeed did not restart with the S3 proxy; the previous vhost was restored.')
    return True


def s3_endpoint(op, domain=None):
    if op not in ('set', 'remove'):
        raise AppError('Unknown endpoint action.')
    if not _version('s3'):
        raise AppError('S3 Object Storage is not installed.')
    _require_idle('s3')
    current = _current('s3', sv.meminfo_mb()[0])
    if op == 'remove':
        if not current.get('endpoint'):
            raise AppError('There is no HTTPS endpoint to remove.')
        if not sv.is_loopback(current['bind']):
            raise AppError('Set the listen address back to 127.0.0.1 first: without the HTTPS endpoint the S3 API '
                           'must not listen on the network.')
        return jobs.spawn('appsvc', 's3_endpoint_run', {'op': 'remove'})
    domain = s3.clean_domain(domain)
    from universalAddons.htaccess import service as hs
    path = os.path.join(hs.VHOSTS, domain, 'vhost.conf')
    if not os.path.isfile(path):
        raise AppError('No OpenLiteSpeed vhost for %s: create the site (or subdomain) in the panel first.' % domain)
    problems = s3.vhost_problems(_read(path))
    if problems:
        raise AppError('%s cannot carry the S3 endpoint: %s.' % (domain, '; '.join(problems)))
    return jobs.spawn('appsvc', 's3_endpoint_run', {'op': 'set', 'domain': domain})


def s3_endpoint_run(job_id, op, domain=None):
    def step(job):
        current = _current('s3', sv.meminfo_mb()[0])
        old = current.get('endpoint')
        settings = {k: current[k] for k in ('s3_port', 'bind', 'region', 'data_dir', 'memory_mb',
                                            'replication_factor', 'web_port')}
        if op == 'set':
            if old and old != domain:
                _s3_vhost(old, None)
                job.log('Removed the S3 proxy from %s' % old)
            _s3_vhost(domain, current['s3_port'])
            job.log('Proxied https://%s/ to Garage on 127.0.0.1:%d (the site\'s own SSL certificate)'
                    % (domain, current['s3_port']))
            _s3_save_state(endpoint=domain)
        else:
            _s3_vhost(old, None)
            job.log('Removed the S3 proxy from %s' % old)
            _s3_save_state(endpoint=None)
        try:
            result = _apply_settings(job, 's3', settings, True)   # public_endpoint in garage.toml
        except AppError:
            _s3_save_state(endpoint=old)
            if op == 'set':
                _s3_vhost(domain, None)
            if old:
                _s3_vhost(old, current['s3_port'])
            raise
        return dict(result, endpoint=domain if op == 'set' else None)

    return _locked_job(job_id, 's3', [('%s the HTTPS endpoint' % ('Set up' if op == 'set' else 'Remove'), step)])


def _job(job_id):
    data = jobs.status(job_id)
    if data.get('module') != 'appsvc':
        raise AppError('Unknown job.')
    return data


ACTIONS = {
    'overview': overview,
    'logs': logs,
    'preflight': preflight,
    'reveal': reveal,
    'install': install,
    'install_run': install_run,
    'remove_preview': remove_preview,
    'remove_preview_run': remove_preview_run,
    'remove': remove,
    'remove_run': remove_run,
    'configure': configure,
    'configure_run': configure_run,
    'revert': revert,
    'revert_run': revert_run,
    'control': control,
    'control_run': control_run,
    'pg_create': pg_create,
    'disk': disk,
    'runtimes': runtimes,
    'oracle_db_check': oracle_db_check,
    's3_bucket_create': s3_bucket_create,
    's3_bucket_delete': s3_bucket_delete,
    's3_bucket_quota': s3_bucket_quota,
    's3_key_create': s3_key_create,
    's3_key_delete': s3_key_delete,
    's3_permission': s3_permission,
    's3_endpoint': s3_endpoint,
    's3_endpoint_run': s3_endpoint_run,
    'job': _job,
}

"""Root-side Applications actions (dispatched by universalAddons/runner.py). Administrator-only.

Install and remove reuse manageServices/serviceManager.py for Elasticsearch and Redis (so the old
Applications page, its install lock and its progress file keep working); Memcached uses the OS
package. Every configuration change runs as a job: back up, write the managed files, restart,
health-check, and restore the previous files if the service does not come back.
"""
import fcntl
import glob
import grp
import os
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager

from universalAddons import jobs
from universalAddons.appsvc import service as sv
from universalAddons.appsvc.service import AppError

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SERVICE_MANAGER = os.path.join(ROOT, 'manageServices', 'serviceManager.py')
LEGACY_STATUS = '/home/cyberpanel/switchLSWSStatus'    # ServerStatusUtil.lswsInstallStatusPath
HEALTH_TIMEOUT = {'elasticsearch': 240, 'redis': 30, 'memcached': 20}
LEGACY_FUNCTIONS = {('elasticsearch', 'install'): 'InstallElasticSearch', ('elasticsearch', 'remove'): 'RemoveElasticSearch',
                    ('redis', 'install'): 'InstallRedis', ('redis', 'remove'): 'RemoveRedis'}
CONTROL_OPS = ('start', 'stop', 'restart', 'enable', 'disable')


def _read(path, default=''):
    try:
        with open(path) as handle:
            return handle.read()
    except OSError:
        return default


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

def _version(key):
    package = sv.app_info(key)['package']
    if shutil.which('rpm'):
        code, out = sv.run(['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}', package], timeout=30)
    else:
        code, out = sv.run(['dpkg-query', '-W', '-f', '${Version}', package if key != 'redis' else 'redis-server'], timeout=30)
    out = out.strip()
    return out if code == 0 and out and 'not installed' not in out else None


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
    code, out = sv.run(['du', '-sb', '--', path], timeout=60)
    try:
        return int(out.split()[0]) if code == 0 else None
    except (IndexError, ValueError):
        return None


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
    if not os.path.isfile(sv.MEMCACHED_SYSCONFIG):
        return dict(sv.memcached_current(''), managed=False)
    return sv.memcached_current(_read(sv.MEMCACHED_SYSCONFIG))


def _has_password(key, current):
    return bool(current.get('security') if key == 'elasticsearch' else current.get('password'))


def _password_state(key, current):
    has = _has_password(key, current)
    stored = sv.secret_status(key)
    return {'set': has, 'by_panel': has and stored['stored'], 'reveal_pending': has and stored['reveal_pending']}


def _live_password(key):
    """The password the service runs with (root side only)."""
    if key == 'redis':
        _, main, dropin = _redis_texts()
        return sv.redis_password_in(main, dropin) or None
    if key == 'elasticsearch':
        data = sv.load_secret('elasticsearch')
        return data['password'] if data else None
    return None


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
    return sv.memcached_health(sv.memcached_target(current))


def _wait_healthy(key):
    return sv.wait_healthy(lambda: _health_once(key), HEALTH_TIMEOUT[key])


def _systemctl(op, unit, timeout=120):
    code, out = sv.run(['systemctl', op, unit], timeout=timeout)
    if code != 0:
        raise AppError('systemctl %s %s failed: %s' % (op, unit, out.strip()[-500:]))
    return out


def _restart(key):
    if key == 'redis':
        sv.run(['systemctl', 'daemon-reload'], timeout=60)
    _systemctl('restart', sv.app_info(key)['unit'], timeout=960 if key == 'elasticsearch' else 120)


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
    if lines is None:
        code, out = sv.run(['journalctl', '-u', sv.app_info(key)['unit'], '-n', str(count), '--no-pager',
                            '-o', 'short-iso'], timeout=30)
        lines = out.splitlines()[-count:]
    return [sv.redact(line, [_live_password(key)]) for line in lines]


def _app_status(key, ram_total, ram_available, disk_mb, with_logs=False):
    info = sv.app_info(key)
    version = _version(key)
    status = {'key': key, 'title': info['title'], 'about': info['about'], 'installed': bool(version),
              'version': version, 'busy': _busy(key), 'unit': info['unit'], 'fields': sv.FIELDS[key]}
    if not version:
        status['preflight'] = sv.preflight_checks(key, ram_total, ram_available, disk_mb, False)
        return status
    values = _systemd(info['unit'])
    pid = values.get('MainPID', '0')
    memory, source = _memory(values)
    current = _current(key, ram_total)
    status.update({
        'active': values.get('ActiveState', 'unknown'), 'sub': values.get('SubState', ''),
        'enabled': values.get('UnitFileState', 'unknown'),
        'memory_bytes': memory, 'memory_source': source,
        'listen': sv.parse_ss(_ss(), int(pid)) if pid.isdigit() and int(pid) > 0 else [],
        'data_dir': info['data_dir'], 'data_bytes': _du(info['data_dir']),
        'settings': {k: v for k, v in current.items() if k != 'socket_path'},
        'password': _password_state(key, current),
        'connection': sv.connection_info(key, current, _has_password(key, current)),
        'backups': len(sv.list_snapshots(sv.backup_root(key))),
    })
    if key == 'elasticsearch':
        status['heap_bounds'] = sv.es_heap_bounds(ram_total)
        status['conflicts'] = sv.yml_conflicts(_read(sv.ES_YML), list(sv.ES_KEYS.values()))
    if key == 'memcached' and not os.path.isfile(sv.MEMCACHED_SYSCONFIG):
        status['config_problem'] = '%s is missing; the panel configures Memcached only through it (EL).' % sv.MEMCACHED_SYSCONFIG
    if with_logs:
        status['logs'] = _logs(key, current)
    return status


# ----------------------------------------------------------------------------- read-only actions

def overview():
    total, available = sv.meminfo_mb()
    disk = sv.disk_free_mb()
    return {'ram_mb': total, 'ram_available_mb': available, 'disk_free_mb': disk,
            'apps': [_app_status(k, total, available, disk) for k in sv.ORDER], 'skipped': sv.SKIPPED}


def logs(app):
    sv.app_info(app)
    if not _version(app):
        raise AppError('%s is not installed.' % sv.app_info(app)['title'])
    return {'app': app, 'lines': _logs(app, _current(app, sv.meminfo_mb()[0]))}


def preflight(app):
    total, available = sv.meminfo_mb()
    checks = sv.preflight_checks(app, total, available, sv.disk_free_mb(), bool(_version(app)))
    return {'app': app, 'checks': checks, 'refusal': sv.preflight_refusal(checks, False),
            'blocked': sv.preflight_refusal(checks, True)}


def reveal(app):
    """The generated password, once."""
    return {'app': app, 'password': sv.reveal_secret(app)}


# ----------------------------------------------------------------------------- install / remove

def install(app, force=False):
    info = sv.app_info(app)
    _require_idle(app)
    report = preflight(app)
    refusal = sv.preflight_refusal(report['checks'], force)
    if refusal:
        raise AppError('Cannot install %s: %s' % (info['title'], refusal))
    return jobs.spawn('appsvc', 'install_run', {'app': app})


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


def install_run(job_id, app):
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


def remove(app, confirm=False, delete_data=False, confirm_name=''):
    info = sv.app_info(app)
    if confirm is not True:
        raise AppError('Confirm removing %s.' % info['title'])
    if delete_data is True and str(confirm_name or '').strip().lower() != app:
        raise AppError('Type %s to confirm deleting its data.' % app)
    if not _version(app):
        raise AppError('%s is not installed.' % info['title'])
    _require_idle(app)
    return jobs.spawn('appsvc', 'remove_run', {'app': app, 'delete_data': delete_data is True})


def remove_run(job_id, app, delete_data=False):
    info = sv.app_info(app)

    def remove_step(job):
        function = LEGACY_FUNCTIONS.get((app, 'remove'))
        if function:
            _run_service_manager(job, function)
        else:
            _command_step(['systemctl', 'disable', '--now', info['unit']], timeout=120)(job)
            _command_step(_package_command('remove', info['package']))(job)
        if _version(app):
            raise AppError('%s is still installed after removal; see the log.' % info['title'])

    def cleanup_step(job):
        if app == 'redis':
            conf = _redis_conf()
            for path in (sv.redis_dropin_path(conf), sv.REDIS_SYSTEMD_DROPIN):
                if os.path.isfile(path):
                    os.unlink(path)
                    job.log('Removed %s' % path)
            sv.run(['systemctl', 'daemon-reload'], timeout=60)
            sv.drop_secret('redis')
        result = {'data_dir': info['data_dir'], 'data_deleted': False}
        if delete_data:
            sv.drop_secret(app)
            path = info['data_dir']
            if path and os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
                job.log('Deleted the data directory %s' % path)
                result['data_deleted'] = True
        elif info['data_dir'] and os.path.isdir(info['data_dir']):
            job.log('Kept the data directory %s' % info['data_dir'])
        return result

    return _locked_job(job_id, app, [('Remove %s' % info['title'], remove_step), ('Clean up', cleanup_step)])


# ----------------------------------------------------------------------------- configuration

def _validate(app, settings, ram_mb, confirm_exposed):
    if not _version(app):
        raise AppError('%s is not installed.' % sv.app_info(app)['title'])
    if app == 'elasticsearch':
        cfg, warnings = sv.validate_es(settings, ram_mb, _read(sv.ES_YML), confirm_exposed)
        port = cfg['http_port']
    elif app == 'redis':
        cfg, warnings = sv.validate_redis(settings, ram_mb, confirm_exposed)
        port = cfg['port']
    else:
        if not os.path.isfile(sv.MEMCACHED_SYSCONFIG):
            raise AppError('%s is missing; the panel configures Memcached only through it.' % sv.MEMCACHED_SYSCONFIG)
        cfg, warnings = sv.validate_memcached(settings, ram_mb, confirm_exposed)
        port = cfg['port']
    pid = _systemd(sv.app_info(app)['unit']).get('MainPID', '0')
    if port and port in sv.ports_in_use(_ss(), int(pid) if pid.isdigit() and int(pid) > 0 else None):
        raise AppError('Port %d is already used by another program.' % port)
    budget = {'elasticsearch': ('heap_mb', 'Elasticsearch heap'), 'redis': ('maxmemory_mb', 'Redis maxmemory'),
              'memcached': ('memory_mb', 'Memcached memory')}
    committed = cfg[budget[app][0]]
    for other in sv.ORDER:
        if other != app and _version(other):
            committed += _current(other, ram_mb).get(budget[other][0]) or 0
    if committed > ram_mb * 0.6:
        warnings.append('Together these applications may take %d MB, over 60%% of the %d MB of RAM.' % (committed, ram_mb))
    return cfg, warnings


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


CHANGES = {'elasticsearch': _es_change, 'redis': _redis_change, 'memcached': _memcached_change}


def configure_run(job_id, app, settings, confirm_exposed=False):
    info = sv.app_info(app)
    hidden = []

    def apply_step(job):
        log = lambda text: job.log(sv.redact(text, hidden))
        cfg, warnings = _validate(app, settings, sv.meminfo_mb()[0], confirm_exposed)
        for warning in warnings:
            log('Warning: %s' % warning)
        paths, write, generated, secrets = CHANGES[app](cfg, log)
        hidden.extend(s for s in secrets if s)
        try:
            _, detail = sv.apply_with_rollback(paths, write, lambda: _restart(app), lambda: _wait_healthy(app),
                                               sv.backup_root(app), log=log)
        except Exception as exc:
            raise AppError(sv.redact(exc, hidden))
        # Never the password itself: the page fetches it once through `reveal`.
        return {'health': detail, 'password_generated': generated}

    return _locked_job(job_id, app, [('Apply %s settings' % info['title'], apply_step)])


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
        import json
        with open(os.path.join(latest, 'manifest.json')) as handle:
            paths = sorted(json.load(handle)['files'])
        job.log('Restoring the configuration saved at %s' % names[-1])
        _, detail = sv.apply_with_rollback(paths, lambda: sv.restore(latest), lambda: _restart(app),
                                           lambda: _wait_healthy(app), root, log=job.log, keep_snapshot=False)
        shutil.rmtree(latest, ignore_errors=True)
        return {'health': detail, 'restored': names[-1]}

    return _locked_job(job_id, app, [('Revert %s settings' % info['title'], revert_step)])


# ----------------------------------------------------------------------------- service controls

def control(app, op):
    info = sv.app_info(app)
    if op not in CONTROL_OPS:
        raise AppError('Unknown service action.')
    if not _version(app):
        raise AppError('%s is not installed.' % info['title'])
    _require_idle(app)
    if op in ('start', 'restart'):
        return jobs.spawn('appsvc', 'control_run', {'app': app, 'op': op})
    _systemctl(op, info['unit'])
    return {'app': app, 'op': op, 'done': True}


def control_run(job_id, app, op):
    info = sv.app_info(app)

    def step(job):
        if app == 'redis':
            sv.run(['systemctl', 'daemon-reload'], timeout=60)
        _systemctl(op, info['unit'], timeout=960 if app == 'elasticsearch' else 120)
        ok, detail = _wait_healthy(app)
        if not ok:
            raise AppError('%s did not come up healthy: %s' % (info['title'], detail))
        job.log('Healthy: %s' % detail)
        return {'health': detail}

    return _locked_job(job_id, app, [('%s %s' % (op.capitalize(), info['title']), step)])


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
    'remove': remove,
    'remove_run': remove_run,
    'configure': configure,
    'configure_run': configure_run,
    'revert': revert,
    'revert_run': revert_run,
    'control': control,
    'control_run': control_run,
    'job': _job,
}

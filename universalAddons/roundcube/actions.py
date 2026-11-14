"""Root-side Roundcube actions (dispatched by universalAddons/runner.py). Administrator-only."""
import grp
import json
import os
import pwd
import shutil
import time
from contextlib import contextmanager

from universalAddons import jobs
from universalAddons.roundcube import service as rc
from universalAddons.roundcube.service import RoundcubeError


@contextmanager
def credentials():
    from universalAddons.backupv2.service import mysql_defaults_file
    try:
        path = mysql_defaults_file()
    except OSError as exc:
        raise RoundcubeError('Cannot read the MySQL root credentials: %s' % exc)
    try:
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _read(path):
    with open(path) as handle:
        return handle.read()


def _site(domain):
    """Everything we need about a site's OpenLiteSpeed vhost; raises if it is unusable."""
    domain = rc.validate_domain(domain)
    vhost_path = os.path.join(rc.VHOSTS, domain, 'vhost.conf')
    if not os.path.isfile(vhost_path):
        raise RoundcubeError('No OpenLiteSpeed vhost for %s.' % domain)
    declaration = rc.parse_vhost_declaration(_read(rc.HTTPD_CONFIG), domain)
    text = _read(vhost_path)
    php = rc.parse_php_handler(text)
    return dict(declaration, domain=domain, vhost_path=vhost_path, php=php, ssl=rc.has_ssl(text),
                block=rc.block_present(text))


def _mail_settings():
    values = {}
    for name in ('ssl', 'protocols'):
        code, out = rc.run(['doveconf', '-h', name], timeout=30)
        values[name] = out.strip() if code == 0 else ''
    dovecot = rc.parse_doveconf(values)
    code, out = rc.run(['postconf', '-M'], timeout=30)
    return {'imap_host': rc.choose_imap(dovecot, rc.port_is_open),
            'smtp_host': rc.choose_smtp(rc.parse_postconf_services(out if code == 0 else '')),
            'sieve': dovecot['sieve'] and rc.port_is_open(4190)}


def _db_status():
    try:
        with credentials() as defaults:
            tables = int((rc.mysql(rc.TABLES_SQL, defaults).strip() or '0').split()[0])
            user = int((rc.mysql(rc.USER_SQL, defaults).strip() or '0').split()[0])
    except (RoundcubeError, ValueError, IndexError) as exc:
        return {'ok': False, 'tables': 0, 'user': False, 'detail': str(exc)[:200]}
    return {'ok': tables > 0 and user > 0, 'tables': tables, 'user': user > 0,
            'detail': '%d tables in %s' % (tables, rc.DB_NAME)}


def _release_dir(version):
    return os.path.join(rc.ROOT, version)


def _swap_vhost(site, text):
    """Write vhost text with backup, graceful restart; restore and raise on failure."""
    from universalAddons.htaccess import service as hs
    with open(site['vhost_path']) as handle:
        current = handle.read()
    if text == current:
        return False
    saved = hs._backup([site['vhost_path']])
    hs._write_atomic(site['vhost_path'], text)
    if not hs.restart():
        hs._restore(saved)
        hs.restart()
        raise RoundcubeError('OpenLiteSpeed did not come back after the restart; the previous vhost was restored.')
    return saved


def _publish(site, version, log=None):
    """Mirror, config ownership, vhost block, restart, health check. Rolls the vhost back on failure."""
    from universalAddons.htaccess import service as hs
    log = log or (lambda text: None)
    release = _release_dir(version)
    php = site['php']
    uid, gid = pwd.getpwnam(php['user']).pw_uid, grp.getgrnam(php['group']).gr_gid
    report = rc.check_php(php['php_cli'])
    if not report['ok']:
        raise RoundcubeError('%s is not suitable for Roundcube: %s' % (php['lsphp'], _php_problem(report)))
    secret = rc.load_secrets()
    mail = _mail_settings()
    log('IMAP %s, SMTP %s, managesieve %s' % (mail['imap_host'], mail['smtp_host'], 'on' if mail['sieve'] else 'off'))
    rc.write_config(release, rc.render_config(secret, mail['imap_host'], mail['smtp_host'], site['domain'],
                                              site['ssl'], mail['sieve']), gid)
    rc.set_runtime_ownership(release, uid, gid)
    count = rc.build_mirror(release, rc.mirror_dir(site['vh_root']))
    log('Web mirror: %d static files in %s' % (count, rc.mirror_dir(site['vh_root'])))
    with open(site['vhost_path']) as handle:
        current = handle.read()
    saved = _swap_vhost(site, rc.apply_block(current, site['vh_root'], release))
    ok, status = rc.health_check(site['domain'], site['ssl'])
    denied = rc.deny_check(site['domain'], site['ssl']) if ok else {}
    exposed = [name for name, code in denied.items() if code == '200']
    if not ok or exposed:
        if saved:
            hs._restore(saved)
            hs.restart()
        problem = ('%s answered HTTP %s' % (rc.URL_PREFIX, status)) if not ok else \
            ('%s is reachable' % ', '.join(exposed))
        raise RoundcubeError('Health check failed (%s); the previous vhost was restored.' % problem)
    log('Health check: HTTP %s; denied paths: %s' % (status, ', '.join('%s=%s' % kv for kv in sorted(denied.items()))))
    return {'url': '%s://%s%s' % ('https' if site['ssl'] else 'http', site['domain'], rc.URL_PREFIX)}


def _php_problem(report):
    parts = []
    if not report.get('version_ok'):
        parts.append('PHP %s (needs %d.%d or newer)' % (report.get('version') or '?', rc.MIN_PHP[0], rc.MIN_PHP[1]))
    if report.get('missing'):
        parts.append('missing extensions: %s' % ', '.join(report['missing']))
    return '; '.join(parts) or report.get('error', 'unknown problem')


def _unpublish(domain):
    """Remove the block from a site's vhost (restart only if it changed) and its mirror."""
    site = _site(domain)
    with open(site['vhost_path']) as handle:
        current = handle.read()
    changed = bool(_swap_vhost(site, rc.remove_block(current)))
    removed = rc.remove_mirror(rc.mirror_dir(site['vh_root']))
    return {'vhost_changed': changed, 'mirror_removed': removed}


# ----------------------------------------------------------------------------- actions

def overview():
    state = rc.load_state()
    version = rc.installed_version()
    result = {'installed': bool(version), 'version': version, 'pinned': rc.VERSION, 'prefix': rc.URL_PREFIX,
              'site': state.get('site'), 'enabled': bool(state.get('enabled')), 'db_name': rc.DB_NAME}
    if version:
        result['db'] = _db_status()
    if state.get('site'):
        try:
            site = _site(state['site'])
            result.update(block_present=site['block'], php_handler=site['php']['lsphp'],
                          url='%s://%s%s' % ('https' if site['ssl'] else 'http', site['domain'], rc.URL_PREFIX))
        except RoundcubeError as exc:
            result['site_problem'] = str(exc)
    return result


def preflight(site):
    """What installing on (or switching to) this site would use, and whether it can work."""
    info = _site(site)
    php = rc.check_php(info['php']['php_cli'])
    checks = [
        {'id': 'php', 'ok': php['ok'], 'detail': '%s (PHP %s): %s' % (
            info['php']['lsphp'], php.get('version') or '?',
            'all required extensions present' if php['ok'] else _php_problem(php))},
        {'id': 'conflict', 'ok': not rc.conflicts(_read(info['vhost_path'])),
         'detail': 'No other %s context in the vhost.' % rc.URL_PREFIX},
        {'id': 'disk', 'ok': shutil.disk_usage('/usr/local').free > 300 * 1024 * 1024,
         'detail': 'At least 300 MB free under /usr/local.'},
    ]
    try:
        mail = _mail_settings()
        checks.append({'id': 'mail', 'ok': True, 'detail': 'IMAP %s, SMTP %s%s' % (
            mail['imap_host'], mail['smtp_host'], ', managesieve' if mail['sieve'] else '')})
    except RoundcubeError as exc:
        checks.append({'id': 'mail', 'ok': False, 'detail': str(exc)})
    return {'site': info['domain'], 'php': dict(php, lsphp=info['php']['lsphp'], user=info['php']['user']),
            'ssl': info['ssl'], 'checks': checks, 'ready': all(c['ok'] for c in checks)}


def install(site):
    if rc.installed_version():
        raise RoundcubeError('Roundcube is already installed.')
    report = preflight(site)
    if not report['ready']:
        raise RoundcubeError('Cannot install: ' + ' '.join(c['detail'] for c in report['checks'] if not c['ok']))
    return jobs.spawn('roundcube', 'install_run', {'site': report['site']})


def install_run(job_id, site):
    version = rc.VERSION
    release = _release_dir(version)
    try:
        secret, reused = rc.load_secrets(), True   # database kept by an earlier uninstall
    except RoundcubeError:
        secret, reused = rc.new_secrets(), False
    hidden = [secret['db_password'], secret['des_key']]
    work = {}

    def prepare(job):
        os.makedirs(rc.ROOT, mode=0o755, exist_ok=True)
        os.chmod(rc.ROOT, 0o755)
        work['dir'] = os.path.join(rc.ROOT, '.download')
        shutil.rmtree(work['dir'], ignore_errors=True)
        os.makedirs(work['dir'], mode=0o700)
        work['tarball'] = os.path.join(work['dir'], rc.TARBALL)
        if os.path.lexists(release):
            raise RoundcubeError('%s already exists; uninstall first.' % release)

    def download(job):
        size = rc.download(rc.DOWNLOAD_URL, work['tarball'])
        job.log('Downloaded %s (%d bytes)' % (rc.TARBALL, size))

    def verify(job):
        try:
            digest = rc.verify_checksum(work['tarball'])
        except RoundcubeError:
            shutil.rmtree(work['dir'], ignore_errors=True)
            raise
        job.log('SHA256 %s matches the pinned value' % digest)

    def extract(job):
        rc.extract_release(work['tarball'], release, version)
        shutil.rmtree(work['dir'], ignore_errors=True)
        rc.point_current(rc.ROOT, version)
        job.log('Extracted to %s (installer/ removed)' % release)

    def database(job):
        with credentials() as defaults:
            rc.mysql(rc.create_db_sql(secret['db_password']), defaults)
            tables = int((rc.mysql(rc.TABLES_SQL, defaults).strip() or '0').split()[0])
            if tables and not reused:
                raise RoundcubeError('%s already has %d tables that the panel did not create; drop or rename it '
                                     'first.' % (rc.DB_NAME, tables))
            if tables:
                job.log('Kept the existing %d tables of %s from the earlier install' % (tables, rc.DB_NAME))
            else:
                rc.load_schema(os.path.join(release, 'SQL', 'mysql.initial.sql'), defaults)
        rc.save_secrets(secret)
        job.log('Database %s and user %s@localhost ready' % (rc.DB_NAME, rc.DB_USER))

    def publish(job):
        info = _site(site)
        rc.save_state({'site': info['domain'], 'enabled': False, 'version': version, 'installed': int(time.time())})
        result = _publish(info, version, log=job.log)
        rc.save_state(dict(rc.load_state(), enabled=True))
        return result

    steps = [('Prepare', prepare), ('Download Roundcube %s' % version, download), ('Verify SHA256', verify),
             ('Extract', extract), ('Create the database', database), ('Serve at %s on %s' % (rc.URL_PREFIX, site), publish)]
    # Wrap steps so nothing secret can reach the job log, even inside an error message.
    guarded = [(title, _guard(func, hidden)) for title, func in steps]
    return jobs.run_job(job_id, guarded)


def _guard(func, hidden):
    def step(job):
        log = job.log
        job.log = lambda text: log(rc.redact(text, hidden))
        try:
            return func(job)
        except Exception as exc:
            raise RoundcubeError(rc.redact(exc, hidden))
        finally:
            job.log = log
    return step


def enable(site):
    if not rc.installed_version():
        raise RoundcubeError('Roundcube is not installed.')
    info = _site(site)
    return jobs.spawn('roundcube', 'enable_run', {'site': info['domain']})


def enable_run(job_id, site):
    def publish(job):
        version = rc.installed_version()
        if not version:
            raise RoundcubeError('Roundcube is not installed.')
        state = rc.load_state()
        info = _site(site)
        if state.get('site') and state['site'] != info['domain']:
            job.log('Removing Roundcube from %s' % state['site'])
            _unpublish(state['site'])
        rc.save_state(dict(state, site=info['domain'], enabled=False))
        result = _publish(info, version, log=job.log)
        rc.save_state(dict(rc.load_state(), enabled=True))
        return result

    try:
        hidden = list(rc.load_secrets().values())
    except RoundcubeError:
        hidden = []
    return jobs.run_job(job_id, [('Serve at %s on %s' % (rc.URL_PREFIX, site), _guard(publish, hidden))])


def disable():
    state = rc.load_state()
    if not state.get('site'):
        return {'vhost_changed': False}
    result = _unpublish(state['site'])
    rc.save_state(dict(state, enabled=False))
    return result


def uninstall(drop_database=False, confirm_name=''):
    if drop_database is True and confirm_name != rc.DB_NAME:
        raise RoundcubeError('Type %s to confirm dropping the database.' % rc.DB_NAME)
    state = rc.load_state()
    result = {}
    if state.get('site'):
        try:
            result.update(_unpublish(state['site']))
        except RoundcubeError as exc:
            if 'No OpenLiteSpeed vhost' not in str(exc):
                raise
    if os.path.isdir(rc.ROOT) and not os.path.islink(rc.ROOT):
        shutil.rmtree(rc.ROOT)
    result['files_removed'] = True
    result['database_dropped'] = False
    if drop_database is True:
        with credentials() as defaults:
            rc.mysql(rc.drop_db_sql(), defaults)
        result['database_dropped'] = True
    for name in ('state.json',) + (('secrets.json',) if drop_database is True else ()):
        try:
            os.unlink(os.path.join(rc.STATE_DIR, name))
        except OSError:
            pass
    return result


def check_upgrade(opener=None):
    import urllib.request
    opener = opener or urllib.request.urlopen
    request = urllib.request.Request(rc.RELEASES_API, headers={'User-Agent': 'cp-ua-roundcube',
                                                               'Accept': 'application/vnd.github+json'})
    try:
        with opener(request, timeout=20) as response:
            releases = json.loads(response.read(2 * 1024 * 1024).decode('utf-8'))
    except Exception as exc:
        raise RoundcubeError('Could not reach GitHub to check for releases: %s' % exc)
    return rc.upgrade_report(rc.installed_version(), rc.latest_in_branch(releases if isinstance(releases, list) else []))


ACTIONS = {
    'overview': overview,
    'preflight': preflight,
    'install': install,
    'install_run': install_run,
    'enable': enable,
    'enable_run': enable_run,
    'disable': disable,
    'uninstall': uninstall,
    'check_upgrade': check_upgrade,
    'job': lambda job_id: jobs.status(job_id),
}

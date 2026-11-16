"""Root-side Laravel Toolkit actions (dispatched by universalAddons/runner.py).

The web layer has checked that the caller manages `domain`; here the site's user, home and
document root come from the panel database, and the app path is re-validated against them.
"""
import hashlib
import os
import secrets
import shutil
import subprocess

from universalAddons import jobs, siteinfo
from universalAddons.access import load_policy
from universalAddons.laravel import service as lv
from universalAddons.laravel.service import LaravelError
from universalAddons.siteinfo import SiteError


def _site(domain):
    return siteinfo.resolve(domain)


def _composer():
    path = lv.find_composer()
    if not path:
        raise LaravelError('Composer is not installed on this server. An administrator can install it from this page.')
    return path


# ----------------------------------------------------------------------------- read

def list_apps(domains=None):
    """Laravel apps of the given sites (all sites for administrators: domains=None)."""
    from universalAddons.wordpress.actions import _docroots
    rows = _docroots()
    if domains is not None:
        wanted = {str(d).lower() for d in domains}
        rows = [r for r in rows if r[0] in wanted]
    apps, sites = [], []
    for domain, user, docroot, vhost in rows:
        sites.append(domain)
        try:
            site = _site(domain)
        except SiteError:
            continue
        for found in lv.scan(site):
            directory = os.path.realpath(site.path(found['path']))
            apps.append({'domain': domain, 'path': found['path'], 'constraint': found['constraint'],
                         'laravel': lv.framework_version(site, directory)})
    composer = lv.find_composer()
    return {'apps': apps, 'sites': sorted(sites), 'composer': composer, 'commands': lv.command_catalogue()}


def info(domain, path):
    return lv.info(_site(domain), siteinfo.check_rel(path))


def env_list(domain, path):
    site = _site(domain)
    directory = lv.app_dir(site, siteinfo.check_rel(path))
    text = lv.read_env(site, directory)
    if text is None:
        return {'exists': False, 'entries': []}
    return {'exists': True, 'entries': lv.masked_env(text), 'backups': _env_backups(directory)}


def _env_backups(directory):
    try:
        return sorted((n for n in os.listdir(directory) if n.startswith('.env.backup-')), reverse=True)
    except OSError:
        return []


def env_set(domain, path, key, value):
    site = _site(domain)
    directory = lv.app_dir(site, siteinfo.check_rel(path))
    env_path = os.path.join(directory, '.env')
    current = lv.read_env(site, directory)
    if current is None:
        raise LaravelError('There is no .env file; copy .env.example to .env first.')
    updated = lv.env_with(current, key, value)
    if updated == current:
        return {'changed': False, 'key': key}
    backup = lv.backup_name()
    code, out = siteinfo.run_as(site, ['cp', '-p', '--', env_path, os.path.join(directory, backup)], timeout=30)
    if code != 0:
        raise LaravelError('Could not back up .env; nothing was changed: ' + out.strip()[-300:])
    siteinfo.write_as(site, env_path, updated, mode_like=os.path.join(directory, backup))
    for old in _env_backups(directory)[lv.MAX_ENV_BACKUPS:]:
        siteinfo.run_as(site, ['rm', '-f', '--', os.path.join(directory, old)], timeout=30)
    entry = [e for e in lv.masked_env(updated) if e['key'] == key]
    return {'changed': True, 'key': key, 'backup': backup, 'entry': entry[0] if entry else None,
            'note': 'Run config:cache again if the configuration is cached.'}


def logs(domain, path, lines=200):
    site = _site(domain)
    return lv.log_tail(site, lv.app_dir(site, siteinfo.check_rel(path)), max(10, min(int(lines), 200)))


# ----------------------------------------------------------------------------- commands (background jobs)

def command(domain, path, tool, name, options=None, confirmed=False):
    site = _site(domain)
    lv.app_dir(site, siteinfo.check_rel(path))
    lv.build_command(tool, name, options, confirmed)  # refuse before starting a job
    if tool == 'composer':
        _composer()
    return jobs.spawn('laravel', 'command_run', {'domain': domain, 'path': path, 'tool': tool, 'name': name,
                                                 'options': options or {}, 'confirmed': confirmed is True})


def run_tool(site, directory, tool, argv, log, timeout=1800):
    if tool == 'artisan':
        full = [site.php, 'artisan'] + argv
    else:
        full = [site.php, _composer()] + argv
    log('$ %s %s' % ('php artisan' if tool == 'artisan' else 'composer', ' '.join(argv)))
    code, out = siteinfo.run_as(site, full, cwd=directory, timeout=timeout,
                                extra_env={'COMPOSER_NO_INTERACTION': '1'} if tool == 'composer' else None)
    log(out.strip()[-20000:] or '(no output)')
    if code != 0:
        raise LaravelError('%s %s exited with status %d.' % (tool, argv[0], code))
    return {'exit': code}


def command_run(job_id, domain, path, tool, name, options=None, confirmed=False):
    site = _site(domain)
    directory = lv.app_dir(site, siteinfo.check_rel(path))
    argv = lv.build_command(tool, name, options, confirmed)
    return jobs.run_job(job_id, [('%s %s on %s' % (tool, name, domain),
                                  lambda job: run_tool(site, directory, tool, argv, job.log))])


# ----------------------------------------------------------------------------- scheduler, worker

def scheduler(domain, path, enable):
    site = _site(domain)
    return lv.set_scheduler(site, lv.app_dir(site, siteinfo.check_rel(path)), bool(enable))


def worker(domain, path, enable, memory_mb=None, queue='default'):
    site = _site(domain)
    directory = lv.app_dir(site, siteinfo.check_rel(path))
    state = lv.load_state()
    workers = state.setdefault('workers', {})
    wid = lv.worker_id(site.domain, directory)
    unit = lv.unit_name(wid)
    unit_path = os.path.join(lv.UNIT_DIR, unit)
    if not enable:
        siteinfo.run(['systemctl', 'disable', '--now', unit], timeout=90)
        if os.path.exists(unit_path):
            os.unlink(unit_path)
        siteinfo.run(['systemctl', 'daemon-reload'], timeout=60)
        siteinfo.run(['systemctl', 'reset-failed', unit], timeout=30)
        workers.pop(wid, None)
        lv.save_state(state)
        return {'enabled': False}
    policy = load_policy()
    limit = int(policy.get('max_memory_mb', 1024))
    memory = int(memory_mb or min(256, limit))
    if not 64 <= memory <= limit:
        raise LaravelError('Memory must be between 64 and %d MB.' % limit)
    record = {'domain': site.domain, 'dir': directory, 'user': site.user, 'home': site.home, 'php': site.php,
              'memory_mb': memory, 'queue': queue or 'default'}
    text = lv.render_worker_unit(record, siteinfo.systemd_version(), siteinfo.cgroup_v2())
    with open(unit_path + '.tmp', 'w') as handle:
        handle.write(text)
    os.chmod(unit_path + '.tmp', 0o644)
    os.replace(unit_path + '.tmp', unit_path)
    siteinfo.run(['systemctl', 'daemon-reload'], timeout=60)
    code, out = siteinfo.run(['systemctl', 'enable', '--now', unit], timeout=90)
    if code != 0:
        raise LaravelError('systemd could not start the worker: ' + out.strip()[-400:])
    siteinfo.run(['systemctl', 'restart', unit], timeout=90)  # pick up a changed memory limit
    workers[wid] = record
    lv.save_state(state)
    return {'enabled': True, 'unit': siteinfo.unit_state(unit), 'memory_mb': memory}


def worker_logs(domain, path):
    site = _site(domain)
    directory = lv.app_dir(site, siteinfo.check_rel(path))
    unit = lv.unit_name(lv.worker_id(site.domain, directory))
    code, out = siteinfo.run(['journalctl', '-u', unit, '-n', '200', '--no-pager', '-o', 'short-iso'], timeout=60)
    return {'lines': out.splitlines()[-200:]}


# ----------------------------------------------------------------------------- public/ as the web root

def point_public(domain, path, method='auto', restart=None, vhosts=siteinfo.VHOSTS, apache_dirs=lv.APACHE_CONF_DIRS):
    """Serve the app's public/ directory: move the vhost document root, or add an .htaccess rewrite."""
    site = _site(domain)
    directory = lv.app_dir(site, siteinfo.check_rel(path))
    public = os.path.join(directory, 'public')
    if not os.path.isdir(public) or os.path.islink(public):
        raise LaravelError('The app has no public/ directory.')
    method = lv.choose_method(site, directory, method)
    if method == 'htaccess':
        htaccess = os.path.join(directory, '.htaccess')
        current = siteinfo.read_owned(site, htaccess, 256 * 1024) if siteinfo.exists_nofollow(htaccess) else ''
        siteinfo.write_as(site, htaccess, lv.with_block(current or ''))
        return {'method': 'htaccess', 'detail': 'Added a rewrite to public/ at the top of %s/.htaccess. The document '
                                                 'root is unchanged.' % (path or 'the document root')}
    return _move_docroot(site, public, restart, vhosts, apache_dirs)


def _move_docroot(site, new_root, restart=None, vhosts=siteinfo.VHOSTS, apache_dirs=lv.APACHE_CONF_DIRS):
    from universalAddons.htaccess import service as hs
    conf = lv.vhost_conf(site, vhosts)
    with open(conf) as handle:
        text = handle.read()
    updated, previous = lv.replace_docroot(text, new_root)
    paths = [conf]
    apache = lv.apache_conf(site, apache_dirs)
    if apache:
        paths.append(apache)
    if updated == text:
        return {'method': 'vhost', 'detail': 'The document root already is %s.' % new_root}
    saved = hs._backup(paths)
    hs._write_atomic(conf, updated)
    if apache:
        with open(apache) as handle:
            hs._write_atomic(apache, lv.replace_apache_docroot(handle.read(), new_root))
    state = lv.load_state()
    state.setdefault('docroots', {}).setdefault(site.vhost, previous)
    lv.save_state(state)
    if not (restart or hs.restart)():
        hs._restore(saved)
        (restart or hs.restart)()
        raise LaravelError('OpenLiteSpeed did not restart with the new document root; the previous one was restored.')
    return {'method': 'vhost', 'previous': previous,
            'detail': 'The vhost document root now is %s (the same docRoot edit as the panel\'s ACLManager.ReplaceDocRoot%s).'
                      % (new_root, ', and the Apache backend DocumentRoot' if apache else '')}


def restore_public(domain, path, restart=None, vhosts=siteinfo.VHOSTS, apache_dirs=lv.APACHE_CONF_DIRS):
    """Undo point_public: the original document root, and/or the .htaccess block removed."""
    site = _site(domain)
    directory = lv.app_dir(site, siteinfo.check_rel(path))
    done = []
    htaccess = os.path.join(directory, '.htaccess')
    if siteinfo.exists_nofollow(htaccess):
        current = siteinfo.read_owned(site, htaccess, 256 * 1024) or ''
        if lv.HTACCESS_BEGIN in current:
            siteinfo.write_as(site, htaccess, lv.strip_block(current))
            done.append('removed the .htaccess rewrite')
    previous = lv.load_state().get('docroots', {}).get(site.vhost)
    if previous and lv.public_state(site, directory, vhosts) == 'vhost':
        result = _move_docroot(site, previous, restart, vhosts, apache_dirs)
        state = lv.load_state()
        state.get('docroots', {}).pop(site.vhost, None)
        lv.save_state(state)
        done.append('restored the document root %s' % previous)
        del result
    return {'done': done or ['nothing to undo']}


# ----------------------------------------------------------------------------- install

def install(domain, path, version='', point='auto'):
    site = _site(domain)
    rel = siteinfo.check_rel(path)
    _composer()
    _empty_target(site, rel)
    if version and not (isinstance(version, str) and version.isdigit() and 8 <= int(version) <= 30):
        raise LaravelError('Invalid Laravel version.')
    if point not in ('auto', 'vhost', 'htaccess', 'none'):
        raise LaravelError('Invalid choice for public/.')
    return jobs.spawn('laravel', 'install_run', {'domain': domain, 'path': rel, 'version': version, 'point': point})


def _empty_target(site, rel):
    target = site.path(rel)
    site.inside(os.path.dirname(target) if not os.path.exists(target) else target)
    if os.path.islink(target):
        raise LaravelError('The target is a link; choose a real directory.')
    if os.path.isdir(target):
        extra = [n for n in os.listdir(target) if n not in lv.DEFAULT_FILES]
        if extra:
            raise LaravelError('The directory is not empty (%s). Choose an empty one.' % ', '.join(sorted(extra)[:5]))
    elif os.path.exists(target):
        raise LaravelError('The target exists and is not a directory.')
    return target


def install_run(job_id, domain, path, version='', point='auto'):
    site = _site(domain)

    def create(job):
        target = _empty_target(site, path)
        staging = os.path.join(site.home, '.ic-laravel-new-' + secrets.token_hex(4))
        package = 'laravel/laravel' + (':^%s.0' % version if version else '')
        job.log('$ composer create-project %s' % package)
        code, out = siteinfo.run_as(site, [site.php, _composer(), 'create-project', package, staging,
                                           '--no-interaction', '--prefer-dist', '--no-ansi'], cwd=site.home,
                                    timeout=1800, extra_env={'COMPOSER_NO_INTERACTION': '1'})
        job.log(out.strip()[-20000:])
        try:
            if code != 0:
                raise LaravelError('composer create-project failed (status %d).' % code)
            for argv in (['mkdir', '-p', '--', target], ['rm', '-f', '--', os.path.join(target, 'index.html')],
                         ['cp', '-a', '--', staging + '/.', target + '/']):
                code, out = siteinfo.run_as(site, argv, timeout=600)
                if code != 0:
                    raise LaravelError('%s failed: %s' % (argv[0], out.strip()[-300:]))
        finally:
            siteinfo.run_as(site, ['rm', '-rf', '--one-file-system', '--', staging], timeout=600)
        return {'dir': target}

    def public(job):
        if point == 'none':
            return {'method': 'none', 'detail': 'public/ was not set as the web root.'}
        result = point_public(domain, path, point)
        job.log(result['detail'])
        return result

    return jobs.run_job(job_id, [('Create a Laravel app in %s' % (path or 'the document root'), create),
                                 ('Serve public/', public)])


# ----------------------------------------------------------------------------- composer itself (administrators)

def composer_install():
    if lv.find_composer():
        raise LaravelError('Composer is already installed at %s.' % lv.find_composer())
    return jobs.spawn('laravel', 'composer_install_run', {})


def install_composer(runner=subprocess.run, target=lv.COMPOSER_TARGET, workdir=None, log=None):
    """Download the Composer installer, verify its SHA-384 against composer.github.io, install it."""
    import tempfile
    say = log or (lambda text: None)
    base = workdir or '/var/lib/cyberpanel-universal'
    os.makedirs(base, mode=0o700, exist_ok=True)
    directory = tempfile.mkdtemp(dir=base)
    installer = os.path.join(directory, 'composer-setup.php')
    try:
        code, out = siteinfo.run(['curl', '-fsSL', '--max-time', '120', '-o', installer, lv.COMPOSER_INSTALLER_URL],
                                 runner, timeout=180)
        if code != 0:
            raise LaravelError('Could not download the Composer installer: ' + out.strip()[-300:])
        code, signature = siteinfo.run(['curl', '-fsSL', '--max-time', '60', lv.COMPOSER_SIG_URL], runner, timeout=90)
        expected = signature.strip().lower()
        if code != 0 or len(expected) != 96 or any(c not in '0123456789abcdef' for c in expected):
            raise LaravelError('Could not read the installer signature from composer.github.io.')
        digest = hashlib.sha384()
        with open(installer, 'rb') as handle:
            for block in iter(lambda: handle.read(1 << 20), b''):
                digest.update(block)
        if digest.hexdigest() != expected:
            raise LaravelError('The Composer installer does not match its published SHA-384; nothing was installed.')
        say('Installer SHA-384 verified.')
        code, out = siteinfo.run(['/usr/bin/php', installer, '--no-ansi', '--install-dir=' + os.path.dirname(target),
                                  '--filename=' + os.path.basename(target)], runner, timeout=300)
        say(out.strip()[-2000:])
        if code != 0:
            raise LaravelError('The Composer installer failed (status %d).' % code)
        os.chmod(target, 0o755)
        return {'path': target}
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def composer_install_run(job_id):
    return jobs.run_job(job_id, [('Install Composer to %s' % lv.COMPOSER_TARGET,
                                  lambda job: install_composer(log=job.log))])


ACTIONS = {
    'list': list_apps,
    'info': info,
    'env_list': env_list,
    'env_set': env_set,
    'logs': logs,
    'command': command,
    'command_run': command_run,
    'scheduler': scheduler,
    'worker': worker,
    'worker_logs': worker_logs,
    'point_public': lambda domain, path, method='auto': point_public(domain, path, method),
    'restore_public': lambda domain, path: restore_public(domain, path),
    'install': install,
    'install_run': install_run,
    'composer_install': composer_install,
    'composer_install_run': composer_install_run,
    'job': lambda job_id: jobs.status(job_id),
}

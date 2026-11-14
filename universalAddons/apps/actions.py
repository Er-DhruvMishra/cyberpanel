"""Root-side app hosting actions (dispatched by universalAddons/runner.py).

The web layer has already checked that the caller manages `domain`; every action here
re-checks that the app it touches belongs to that domain.
"""
import os
import shutil

from universalAddons import jobs
from universalAddons.access import DEFAULT_POLICY, POLICY_FILE, load_policy
from universalAddons.apps import runtimes as rt
from universalAddons.apps import service as svc
from universalAddons.apps.service import AppError


def _site(domain):
    from universalAddons import django_env
    django_env.setup()
    from websiteFunctions.models import ChildDomains, Websites
    domain = (domain or '').lower()
    if not svc.DOMAIN_RE.match(domain):
        raise AppError('Invalid domain.')
    try:
        site = Websites.objects.get(domain=domain)
        return {'domain': domain, 'user': site.externalApp, 'home': '/home/%s' % site.domain}
    except Websites.DoesNotExist:
        pass
    try:
        child = ChildDomains.objects.select_related('master').get(domain=domain)
    except ChildDomains.DoesNotExist:
        raise AppError('Unknown site.')
    return {'domain': domain, 'user': child.master.externalApp, 'home': '/home/%s' % child.master.domain}


def _app(app_id, domain):
    app = svc.load_apps().get(app_id)
    if not app or app['domain'] != (domain or '').lower():
        raise AppError('Unknown app.')
    return app


def _runtime(app):
    return rt.find(app['kind'], app['runtime'])


# ----------------------------------------------------------------------------- runtimes / policy (admin)

def runtimes_overview(include_catalogue=False):
    apps = svc.load_apps().values()
    installed = rt.installed()
    for kind, entries in installed.items():
        for entry in entries:
            entry['used_by'] = sorted(a['id'] for a in apps if a['kind'] == kind and a['runtime'] == entry['version'])
    result = {'installed': installed, 'policy': load_policy(), 'disk_free_mb': _disk_free_mb(rt.RUNTIME_ROOT)}
    if include_catalogue:
        result['catalogue'] = rt.catalogue()
    return result


def _disk_free_mb(path):
    while not os.path.exists(path):
        path = os.path.dirname(path)
    usage = shutil.disk_usage(path)
    return usage.free // (1024 * 1024)


def runtime_install(kind, version):
    if _disk_free_mb(rt.RUNTIME_ROOT) < 1024:
        raise AppError('Less than 1 GB of disk is free; free some space first.')
    return jobs.spawn('apps', 'runtime_install_run', {'kind': kind, 'version': version})


def runtime_install_run(job_id, kind, version):
    return jobs.run_job(job_id, [('Install %s %s' % (kind, version), lambda job: rt.install(kind, version, log=job.log))])


def runtime_uninstall(kind, version):
    in_use = [a['id'] for a in svc.load_apps().values() if a['kind'] == kind and a['runtime'] == version]
    return rt.uninstall(kind, version, in_use)


def save_policy(policy):
    import json
    clean = dict(DEFAULT_POLICY)
    current = load_policy()  # keys this page does not send (other modules' settings) are kept
    for key, default in DEFAULT_POLICY.items():
        value = policy.get(key, current.get(key, default))
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise AppError('%s must be true or false.' % key)
        else:
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise AppError('%s must be a number.' % key)
        clean[key] = value
    limits = {'max_apps_per_site': (0, 50), 'max_memory_mb': (64, 65536), 'default_memory_mb': (64, 65536),
              'max_cpu_percent': (5, 6400), 'max_mssql_dbs_per_site': (0, 50)}
    for key, (low, high) in limits.items():
        if not low <= clean[key] <= high:
            raise AppError('%s must be between %d and %d.' % (key, low, high))
    clean['default_memory_mb'] = min(clean['default_memory_mb'], clean['max_memory_mb'])
    os.makedirs(os.path.dirname(POLICY_FILE), exist_ok=True)
    with open(POLICY_FILE + '.tmp', 'w') as handle:
        json.dump(clean, handle, indent=2, sort_keys=True)
    os.chmod(POLICY_FILE + '.tmp', 0o644)  # read by the panel process; contains no secrets
    os.replace(POLICY_FILE + '.tmp', POLICY_FILE)
    return clean


# ----------------------------------------------------------------------------- apps

def list_apps(domains=None):
    apps = [a for a in svc.load_apps().values() if domains is None or a['domain'] in domains]
    result = []
    for app in sorted(apps, key=lambda a: (a['domain'], a['id'])):
        entry = {k: v for k, v in app.items() if k != 'env'}
        entry['env_keys'] = sorted(app.get('env', {}))
        entry['status'] = svc.status(app)
        result.append(entry)
    return {'apps': result, 'runtimes': {k: [r['version'] for r in v] for k, v in rt.installed().items()}}


def save_app(domain, spec):
    site = _site(domain)
    apps = svc.load_apps()
    app = svc.validate(spec, site, load_policy(), apps, rt.installed())
    previous = apps.get(app['id'])
    if previous:
        app['enabled'] = previous.get('enabled', True)
    else:
        app['port'] = svc.allocate_port(apps)
        app['enabled'] = True
    if not os.path.isdir(app['dir']):
        code, out = svc.run(['sudo', '-u', app['user'], '--', 'mkdir', '-p', '-m', '0750', app['dir']])
        if code != 0:
            raise AppError('Could not create %s: %s' % (app['dir'], out.strip()))
    apps[app['id']] = app
    svc.save_apps(apps)
    _write_unit(app)
    return {'app': {k: v for k, v in app.items() if k != 'env'}, 'created': previous is None}


def _write_unit(app):
    runtime = _runtime(app)
    unit = svc.render_unit(app, runtime, svc.systemd_version(), svc.cgroup_v2())
    env_path = os.path.join(svc.APPS_DIR, 'env', app['id'] + '.env')
    fd = os.open(env_path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(svc.render_env_file(app.get('env', {})))
    os.replace(env_path + '.tmp', env_path)
    with open(os.path.join(svc.UNIT_DIR, svc.unit_name(app['id'])), 'w') as handle:
        handle.write(unit)
    svc.run(['systemctl', 'daemon-reload'])


def _sync_vhost(domain):
    """Rewrite the managed proxy block of one site's vhost and gracefully restart OpenLiteSpeed."""
    from universalAddons.htaccess import service as hs
    vhost_path = os.path.join(hs.VHOSTS, domain, 'vhost.conf')
    if not os.path.isfile(vhost_path):
        raise AppError('No OpenLiteSpeed vhost for %s.' % domain)
    apps = [a for a in svc.load_apps().values() if a['domain'] == domain]
    with open(vhost_path) as handle:
        current = handle.read()
    clashes = svc.vhost_conflicts(current, apps)
    if clashes:
        raise AppError('vhost.conf already defines %s; remove it or choose another URL path.' % ', '.join(clashes))
    updated = svc.apply_to_vhost(current, apps)
    if updated == current:
        return False
    saved = hs._backup([vhost_path])
    hs._write_atomic(vhost_path, updated)
    if not hs.restart():
        hs._restore(saved)
        hs.restart()
        raise AppError('OpenLiteSpeed did not restart with the new proxy settings; the previous vhost was restored.')
    return True


def deploy_run(job_id, app_id, domain):
    app = _app(app_id, domain)

    def dependencies(job):
        return svc.install_dependencies(app, _runtime(app), log=job.log)

    def start(job):
        _write_unit(app)
        code, out = svc.run(['systemctl', 'enable', svc.unit_name(app['id'])])
        code, out = svc.run(['systemctl', 'restart', svc.unit_name(app['id'])])
        if code != 0:
            raise AppError('systemd could not start the app: %s' % out.strip()[-500:])
        if not svc.wait_listening(app['port']):
            job.log('\n'.join(svc.logs(app, 40)))
            raise AppError('The app did not start listening on its port within 30 s. See the log above.')
        return svc.status(app)

    def proxy(job):
        return {'vhost_changed': _sync_vhost(app['domain'])}

    return jobs.run_job(job_id, [('Install dependencies', dependencies), ('Start %s' % app['id'], start),
                                 ('Route %s%s to the app' % (app['domain'], app['prefix']), proxy)])


def deploy(app_id, domain):
    _app(app_id, domain)
    return jobs.spawn('apps', 'deploy_run', {'app_id': app_id, 'domain': domain})


def control(app_id, domain, action):
    app = _app(app_id, domain)
    if action not in ('start', 'stop', 'restart'):
        raise AppError('Invalid action.')
    if action == 'stop':
        svc.run(['systemctl', 'disable', svc.unit_name(app_id)])
    else:
        svc.run(['systemctl', 'enable', svc.unit_name(app_id)])
    code, out = svc.run(['systemctl', action, svc.unit_name(app_id)])
    if code != 0:
        raise AppError(out.strip()[-500:] or 'systemctl %s failed' % action)
    return svc.status(app)


def delete(app_id, domain, remove_files=False):
    app = _app(app_id, domain)
    svc.run(['systemctl', 'disable', '--now', svc.unit_name(app_id)])
    for path in (os.path.join(svc.UNIT_DIR, svc.unit_name(app_id)), os.path.join(svc.APPS_DIR, 'env', app_id + '.env')):
        if os.path.exists(path):
            os.unlink(path)
    svc.run(['systemctl', 'daemon-reload'])
    apps = svc.load_apps()
    apps.pop(app_id, None)
    svc.save_apps(apps)
    _sync_vhost(app['domain'])
    if remove_files and app['dir'].startswith(app['home'] + '/apps/'):
        svc.run(['sudo', '-u', app['user'], '--', 'rm', '-rf', '--one-file-system', app['dir']])
    return {'deleted': app_id, 'files_removed': bool(remove_files)}


ACTIONS = {
    'runtimes': runtimes_overview,
    'runtime_install': runtime_install,
    'runtime_install_run': runtime_install_run,
    'runtime_uninstall': runtime_uninstall,
    'save_policy': save_policy,
    'list': list_apps,
    'save': save_app,
    'deploy': deploy,
    'deploy_run': deploy_run,
    'control': control,
    'status': lambda app_id, domain: svc.status(_app(app_id, domain)),
    'logs': lambda app_id, domain, lines=200: {'lines': svc.logs(_app(app_id, domain), lines)},
    'delete': delete,
    'job': lambda job_id: jobs.status(job_id),
}

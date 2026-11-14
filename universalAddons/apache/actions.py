"""Root-side Apache Manager actions (dispatched by universalAddons/runner.py).

Root is needed to read vhost.conf and /proc (hidepid=2), to write the Apache/PHP-FPM/OpenLiteSpeed files,
run dnf and reload services. The web layer is admin-only; every action re-validates its arguments.
"""
import fcntl
import os
import re
import time

from universalAddons import jobs
from universalAddons.apache import service as sv
from universalAddons.apache.service import ApacheError


def _sites():
    """[{domain, user, state}] of every website (child domains have their own vhosts and are not offered)."""
    from universalAddons import django_env
    django_env.setup()
    from websiteFunctions.models import Websites
    return [{'domain': w.domain, 'user': w.externalApp or '', 'state': w.state}
            for w in Websites.objects.order_by('domain')]


def _site(domain):
    domain = sv.validate_domain(domain)
    for site in _sites():
        if site['domain'] == domain:
            if site['state'] != 1:
                raise ApacheError('%s is suspended.' % domain)
            return site
    raise ApacheError('Unknown site.')


def _stored_pool(state, domain, total_mb):
    stored = state['sites'].get(domain, {}).get('pool')
    try:
        return sv.validate_pool(stored if isinstance(stored, dict) else None, total_mb)
    except ApacheError:  # e.g. stored for more RAM than the server has now
        return sv.default_pool(total_mb)


def _pool_files(layout):
    try:
        return len([n for n in os.listdir(layout['pool_dir']) if n.startswith('cp-ua-') and n.endswith('.conf')])
    except OSError:
        return 0


def _units_active(units, services=None):
    services = services or sv.Services()
    return {unit: services.active(unit) for unit in units}


def _enabled(unit):
    code, out = sv.run(['systemctl', 'is-enabled', unit], timeout=30)
    return out.strip()


def _backend():
    """Everything a plan needs about this host's Apache and PHP-FPM."""
    httpd = os.path.exists(sv.HTTPD)
    user, group = sv.httpd_run_identity() if httpd else ('apache', 'apache')
    state = sv.load_state()
    base_path = sv.base_conf_path()
    base_ok = bool(state['port']) and sv._read(base_path) == sv.render_base_conf(state['port'])
    return {'httpd': httpd, 'run_user': user, 'run_group': group, 'state': state, 'port': state['port'],
            'base_ok': base_ok, 'layouts': sv.installed_fpm()}


# ----------------------------------------------------------------------------- read

def overview():
    mem = sv.meminfo()
    backend = _backend()
    layouts = backend['layouts']
    services = sv.Services()
    units = ['httpd'] + sorted({layout['service'] for layout in layouts.values()})
    active = _units_active(units, services) if backend['httpd'] or layouts else {}
    workers = sv.pool_workers()
    listens = sv.httpd_listens() if backend['httpd'] else []
    try:
        import grp
        run_gid = grp.getgrnam(backend['run_group']).gr_gid
    except (KeyError, ImportError):
        run_gid = -1
    rows, in_use = [], set()
    for site in _sites():
        row = {'domain': site['domain'], 'user': site['user'], 'state': site['state'], 'mode': '', 'php': '',
               'pool': _stored_pool(backend['state'], site['domain'], mem['total_mb']),
               'pool_file': False, 'socket': False, 'httpd_conf': False, 'workers': 0, 'fpm': '', 'fpm_active': None,
               'warnings': [], 'error': ''}
        try:
            facts = sv.site_facts(site)
            row.update(mode=facts['mode'], php=facts['php'], docroot=facts['docroot'])
            in_use.add(facts['php'])
            layout = layouts.get(facts['php'])
            row['httpd_conf'] = os.path.exists(sv.site_conf_path(site['domain']))
            if layout:
                row.update(fpm=layout['service'], fpm_active=active.get(layout['service']),
                           pool_file=os.path.exists(sv.pool_path(site['domain'], layout)),
                           socket=os.path.exists(sv.socket_path(site['domain'], layout)),
                           workers=workers.get(sv.pool_name(site['domain']), 0))
            if facts['mode'] == 'apache' and not (row['httpd_conf'] and row['pool_file']):
                row['mode'] = 'partial'
                row['warnings'].append('The OpenLiteSpeed proxy block is present but the Apache vhost or the pool is '
                                       'missing. Switch the site again or back to OpenLiteSpeed.')
            if facts['mode'] == 'ols' and (row['httpd_conf'] or row['pool_file']):
                row['warnings'].append('Leftover Apache files for this site; switching back to OpenLiteSpeed removes them.')
            note = sv.docroot_warning(facts['docroot'], run_gid) if run_gid >= 0 else ''
            if note:
                row['warnings'].append(note)
        except ApacheError as exc:
            row['error'] = str(exc) + (' (suspended)' if site['state'] != 1 else '')
        rows.append(row)
    suggested = sorted(in_use)
    shared = [('%s:%d' % (address, port)) for address, port in listens
              if address in ('*', '0.0.0.0', '::') and port != backend['port']]
    notes = []
    if shared:
        notes.append('Apache also listens on %s on every interface (from httpd.conf, e.g. an earlier CyberPanel Apache '
                     'setup). This module does not change that; block those ports in the firewall if they are not used.'
                     % ', '.join(shared))
    return {
        'host': mem,
        'httpd': {'installed': backend['httpd'], 'active': active.get('httpd'), 'enabled': _enabled('httpd') if backend['httpd'] else '',
                  'run_user': backend['run_user'], 'run_group': backend['run_group'], 'port': backend['port'],
                  'base_conf': sv.base_conf_path(), 'base_ok': backend['base_ok'],
                  'listens': ['%s:%d' % item for item in listens]},
        'fpm': [{'version': v, 'dotted': sv.dotted(v), 'kind': layout['kind'], 'service': layout['service'],
                 'active': active.get(layout['service']), 'pools': _pool_files(layout)}
                for v, layout in sorted(layouts.items())],
        'versions': list(sv.PHP_VERSIONS), 'in_use': suggested,
        'install': sv.install_plan(suggested, layouts, backend['httpd'], bool(active.get('httpd')), mem),
        'defaults': sv.default_pool(mem['total_mb']), 'bounds': sv.pool_bounds(mem['total_mb']),
        'pm_modes': list(sv.PM_MODES), 'sites': rows, 'notes': notes,
        'remi_key': os.path.exists(sv.REMI_KEY),
    }


# ----------------------------------------------------------------------------- preview / apply

def _plan(site, mode, pool):
    record = _site(site)
    backend = _backend()
    mem = sv.meminfo()
    clean = sv.validate_pool(pool, mem['total_mb']) if mode != 'ols' else None
    if mode != 'ols':
        if not backend['httpd']:
            raise ApacheError('Apache httpd is not installed; run the prerequisite job first.')
        if not backend['base_ok']:
            raise ApacheError('The Apache backend (%s) is missing or was edited; run the prerequisite job first.'
                              % sv.base_conf_path())
    result = sv.plan(record, mode, clean, backend['port'], backend['layouts'], backend['run_user'], backend['run_group'])
    if mode == 'apache':
        try:
            import grp
            note = sv.docroot_warning(result['docroot'], grp.getgrnam(backend['run_group']).gr_gid)
        except KeyError:
            note = 'Apache\'s group %s does not exist.' % backend['run_group']
        if note:
            result['warnings'].append(note)
        ram = result['ram']
        result['warnings'].append('This pool idles at about %d MB and can peak at about %d MB (worst case %d MB if every '
                                  'child reaches memory_limit). %d MB of RAM is available now.'
                                  % (ram['idle_mb'], ram['peak_mb'], ram['worst_mb'], mem['available_mb']))
    return result


def preview(site, mode, pool=None):
    result = _plan(site, mode, pool)
    return sv.public_plan(result)


def apply(site, mode, token, pool=None):
    if not isinstance(token, str) or not re.match(r'^[0-9a-f]{32}$', token):
        raise ApacheError('Preview the change first.')
    result = _plan(site, mode, pool)
    if result['token'] != token:
        raise ApacheError('The configuration changed since the preview; preview again.')
    if not result['changed']:
        raise ApacheError('Nothing to change.')
    return jobs.spawn('apache', 'apply_run', {'site': site, 'mode': mode, 'token': token, 'pool': pool})


def _busy(job):
    raise ApacheError('Another Apache Manager change is running; try again in a minute.')


def _run_locked(job_id, steps):
    """Run the job's steps while holding the module lock, so two changes never interleave."""
    os.makedirs(sv.STATE_DIR, mode=0o700, exist_ok=True)
    with open(sv.LOCK_FILE, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            steps = [('Wait for the other change', _busy)]
        return jobs.run_job(job_id, steps)


def apply_run(job_id, site, mode, token, pool=None):
    def body(job):
        result = _plan(site, mode, pool)
        if result['token'] != token:
            raise ApacheError('The configuration changed since the preview; preview again.')
        for warning in result['warnings']:
            job.log('note: %s' % warning)
        outcome = sv.apply_plan(result, log=job.log)
        state = sv.load_state()
        entry = state['sites'].setdefault(result['domain'], {})
        if result['pool']:
            entry['pool'] = result['pool']
        entry.update(mode='apache' if mode != 'ols' else 'ols', php=result['php'], updated=int(time.time()))
        sv.save_state(state)
        return outcome

    titles = {'apache': 'Switch %s to Apache', 'ols': 'Switch %s back to OpenLiteSpeed', 'tune': 'Tune the PHP-FPM pool of %s'}
    return _run_locked(job_id, [(titles.get(mode, '%s') % site, body)])


# ----------------------------------------------------------------------------- prerequisites

def install(versions, confirm=False):
    versions = sv.validate_versions(versions)
    mem = sv.meminfo()
    if mem['available_mb'] < sv.MIN_AVAILABLE_MB and confirm is not True:
        raise ApacheError('Only %d MB RAM is available (under %d MB). Free memory first or confirm the install.'
                          % (mem['available_mb'], sv.MIN_AVAILABLE_MB))
    layouts = sv.installed_fpm()
    if [v for v in versions if v not in layouts] and not os.path.exists(sv.REMI_KEY):
        raise ApacheError('The remi signing key %s is missing; it is needed to verify the PHP-FPM packages.' % sv.REMI_KEY)
    return jobs.spawn('apache', 'install_run', {'versions': versions, 'confirm': confirm is True})


def _dnf(job, args, timeout=1800):
    code, out = sv.run(['nice', '-n', '10', 'dnf', '-y', '--setopt=install_weak_deps=False'] + args, timeout=timeout)
    job.log(out[-4000:])
    return code


def _repo_versions(text):
    return sorted(set(re.findall(r'\bphp(\d{2})-\*', text or '')))


def install_run(job_id, versions, confirm=False):
    versions = sv.validate_versions(versions)
    steps = []

    def memory(job):
        mem = sv.meminfo()
        job.log('RAM: %d MB total, %d MB available, %d MB swap free' % (mem['total_mb'], mem['available_mb'], mem['swap_free_mb']))
        if mem['available_mb'] < sv.MIN_AVAILABLE_MB and not confirm:
            raise ApacheError('Only %d MB RAM is available; not installing.' % mem['available_mb'])

    steps.append(('Check memory', memory))

    if not os.path.exists(sv.HTTPD):
        def httpd(job):
            if _dnf(job, ['install', 'httpd']) != 0 or not os.path.exists(sv.HTTPD):
                raise ApacheError('dnf could not install httpd; see the log.')
        steps.append(('Install Apache httpd', httpd))

    missing = [v for v in versions if v not in sv.installed_fpm()]
    if missing:
        def repo(job):
            wanted = sorted(set(missing) | set(_repo_versions(sv._read(sv.REPO_FILE))))
            from universalAddons.htaccess import service as hs
            if os.path.exists(sv.REPO_FILE):
                hs._backup([sv.REPO_FILE], sv.BACKUP_DIR)
            with open(sv.REPO_FILE + '.tmp', 'w') as handle:
                handle.write(sv.repo_text(wanted))
            os.chmod(sv.REPO_FILE + '.tmp', 0o644)
            os.replace(sv.REPO_FILE + '.tmp', sv.REPO_FILE)
            job.log('wrote %s (includepkgs: PHP %s only)' % (sv.REPO_FILE, ', '.join(sv.dotted(v) for v in wanted)))
        steps.append(('Add the restricted remi-safe repository', repo))

        for version in missing:
            def fpm(job, version=version):
                required, optional = sv.install_packages(version)
                if _dnf(job, ['install'] + required) != 0:
                    raise ApacheError('dnf could not install %s; see the log.' % ' '.join(required))
                # Extensions one version lacks are skipped instead of failing the whole transaction.
                if _dnf(job, ['--setopt=strict=0', 'install'] + optional) != 0:
                    job.log('some PHP %s extensions could not be installed; PHP-FPM itself is installed.' % sv.dotted(version))
                layout = sv.fpm_layout(version)
                www = os.path.join(layout['pool_dir'], 'www.conf')
                text = sv._read(www)
                if text is not None and sv.www_pool_ondemand(text) != text:
                    from universalAddons.htaccess import service as hs
                    hs._backup([www], sv.BACKUP_DIR)
                    hs._write_atomic(www, sv.www_pool_ondemand(text))
                    job.log('set the stock www pool of PHP %s to pm = ondemand (no idle workers)' % sv.dotted(version))
                job.log('PHP-FPM %s installed; it starts when the first site switches to it.' % sv.dotted(version))
            steps.append(('Install PHP-FPM %s' % sv.dotted(version), fpm))

    def backend(job):
        state = sv.load_state()
        listens = sv.httpd_listens()
        port = state['port'] or sv.choose_port(listens, preferred=sv.DEFAULT_PORT)
        sv.validate_port(port, listens)
        path = sv.base_conf_path()
        text = sv.render_base_conf(port)
        services = sv.Services()
        if sv._read(path) != text:
            from universalAddons.htaccess import service as hs
            saved = hs._backup([path], sv.BACKUP_DIR)
            hs._write_atomic(path, text)
            job.log('wrote %s (Listen 127.0.0.1:%d)' % (path, port))
            ok, output = services.httpd_test()
            job.log('httpd -t: %s' % output)
            if not ok or not services.reload_or_start('httpd'):
                hs._restore(saved)
                services.reload_or_start('httpd')
                raise ApacheError('Apache did not accept the backend configuration; it was removed again.')
        elif not services.active('httpd') and not services.reload_or_start('httpd'):
            raise ApacheError('Apache httpd did not start.')
        state['port'] = port
        sv.save_state(state)
        return {'port': port}

    steps.append(('Configure the Apache backend on 127.0.0.1', backend))
    return _run_locked(job_id, steps)


ACTIONS = {
    'overview': overview,
    'preview': preview,
    'apply': apply,
    'apply_run': apply_run,
    'install': install,
    'install_run': install_run,
    'job': lambda job_id: jobs.status(job_id),
}

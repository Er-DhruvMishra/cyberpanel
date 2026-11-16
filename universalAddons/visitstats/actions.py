"""Root-side visitor statistics actions (dispatched by universalAddons/runner.py)."""
import os
import resource
import shutil
import subprocess
import time

from universalAddons import jobs, privileged
from universalAddons.visitstats import service
from universalAddons.visitstats.service import StatsError

CRON_FILE = '/etc/cron.d/cyberpanel-universal-visitstats'
GOACCESS_PATHS = ('/usr/bin/goaccess', '/usr/local/bin/goaccess')


def _goaccess():
    for path in GOACCESS_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _version(binary):
    try:
        output = subprocess.run([binary, '--version'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return service.goaccess_version(output)


def _site(domain):
    from universalAddons.siteinfo import SiteError, resolve
    try:
        return resolve(domain)
    except SiteError as exc:
        raise StatsError(str(exc))


def _panel_sites():
    from universalAddons import django_env
    django_env.setup()
    from websiteFunctions.models import ChildDomains, Websites
    names = list(Websites.objects.values_list('domain', flat=True)) + \
        list(ChildDomains.objects.values_list('domain', flat=True))
    return sorted({n.lower() for n in names if service.DOMAIN_RE.match(n.lower())})


def _row(domain):
    meta = service.load_meta(domain)
    path = service.report_path(domain)
    return {'domain': domain, 'report': os.path.isfile(path), 'generated': meta.get('generated'),
            'engine': meta.get('engine', ''), 'anonymize': meta['anonymize'], 'error': meta.get('error', ''),
            'wait': service.rate_limited(meta, time.time())}


def status(domains=None):
    """Report state of the given sites (all panel sites when None), and whether GoAccess is there."""
    names = _panel_sites()
    if domains is not None:
        wanted = {str(d).lower() for d in domains}
        names = [n for n in names if n in wanted]
    binary = _goaccess()
    version = _version(binary) if binary else None
    return {'goaccess': '.'.join(map(str, version)) if version else ('installed' if binary else None),
            'persist': bool(version and version >= (1, 4, 0)), 'sites': [_row(n) for n in names],
            'nightly': os.path.exists(CRON_FILE)}


def check_available():
    """Is goaccess installable from the configured repositories (EPEL)? Read-only."""
    try:
        result = subprocess.run(['nice', '-n', '19', 'dnf', '-q', '--assumeno', 'info', 'goaccess'],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as exc:
        return {'available': False, 'detail': str(exc)[:300]}
    text = result.stdout or ''
    version = next((line.split(':', 1)[1].strip() for line in text.splitlines() if line.startswith('Version')), '')
    repo = next((line.split(':', 1)[1].strip() for line in text.splitlines() if line.startswith('Repository')), '')
    return {'available': bool(version), 'version': version, 'repository': repo,
            'detail': '' if version else text.strip()[-300:]}


def install():
    if _goaccess():
        raise StatsError('GoAccess is already installed.')
    return jobs.spawn('visitstats', 'install_run', {})


def install_run(job_id):
    def do_install(job):
        result = subprocess.run(['dnf', '-y', 'install', 'goaccess'], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, universal_newlines=True, timeout=1800)
        job.log(result.stdout[-4000:])
        if result.returncode != 0 or not _goaccess():
            raise StatsError('dnf could not install goaccess (exit %d). Is EPEL enabled?' % result.returncode)
        return {'goaccess': _goaccess()}
    return jobs.run_job(job_id, [('Install GoAccess from EPEL', do_install)])


def set_options(domain, anonymize):
    if not isinstance(anonymize, bool):
        raise StatsError('Invalid option.')
    _site(domain)
    meta = service.load_meta(domain)
    if meta['anonymize'] != anonymize:
        # The GoAccess database already holds addresses in the old form: start it again.
        shutil.rmtree(os.path.join(service.site_dir(domain), 'db'), ignore_errors=True)
        meta.pop('since', None)
    meta['anonymize'] = anonymize
    service.save_meta(domain, meta)
    return _row(domain)


def generate(domain, rate_limit=True):
    """Start a report build now (site owners: once per ON_DEMAND_INTERVAL per site)."""
    _site(domain)
    meta = service.load_meta(domain)
    now = time.time()
    wait = service.rate_limited(meta, now)
    if rate_limit and wait:
        raise StatsError('A report for %s was requested recently; try again in %d minute(s).'
                         % (domain, max(1, wait // 60)))
    meta['requested'] = now
    service.save_meta(domain, meta)
    return jobs.spawn('visitstats', 'generate_run', {'domain': domain})


def _limits():
    resource.setrlimit(resource.RLIMIT_AS, (service.MEMORY_LIMIT, service.MEMORY_LIMIT))


def build(domain, log=lambda text: None):
    """Build the report of one site now (root). Returns its row."""
    site = _site(domain)
    meta = service.load_meta(domain)
    directory = service.ensure_dir(domain)
    started = time.time()
    fds = service.open_logs(site.home, since=meta.get('since', 0))
    output = os.path.join(directory, 'report.tmp.html')
    try:
        binary = _goaccess()
        if binary:
            version = _version(binary)
            db_dir = os.path.join(directory, 'db')
            os.makedirs(db_dir, mode=0o700, exist_ok=True)
            argv = service.goaccess_command(binary, version, fds, db_dir, output, meta['anonymize'],
                                            '%s - IndiansCloud' % domain)
            log('Running GoAccess on %d log file(s).' % len(fds))
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    universal_newlines=True, timeout=service.GOACCESS_TIMEOUT, pass_fds=fds,
                                    preexec_fn=_limits)
            if result.returncode != 0 or not os.path.isfile(output):
                raise StatsError('GoAccess failed (exit %d): %s' % (result.returncode, result.stdout.strip()[-500:]))
            engine = 'goaccess'
        else:
            log('GoAccess is not installed: building the built-in summary.')
            summary = service.summarise(service.read_lines(fds), meta['anonymize'])
            with open(output, 'w') as handle:
                handle.write(service.summary_html(summary, domain))
            engine = 'builtin'
        os.chmod(output, 0o600)
        os.replace(output, service.report_path(domain))
        meta.update(generated=int(time.time()), engine=engine, error='', since=int(started))
    except Exception as exc:
        meta['error'] = str(exc)[:500]
        raise
    finally:
        for fd in fds:
            os.close(fd)
        service.save_meta(domain, meta)
    return _row(domain)


def generate_run(job_id, domain):
    return jobs.run_job(job_id, [('Build the report of %s' % domain, lambda job: build(domain, job.log))])


def nightly():
    """Cron: rebuild every site's report, one after the other, at idle priority."""
    built, failed = 0, 0
    for domain in _panel_sites():
        try:
            build(domain)
            built += 1
        except StatsError:
            failed += 1   # no log yet, or not a plain file: recorded in the site's meta
        except Exception:
            failed += 1
    return {'built': built, 'skipped': failed}


def stage_report(domain):
    """Copy the site's report into the panel spool for the web process to stream."""
    if not service.DOMAIN_RE.match(domain or ''):
        raise StatsError('Invalid site.')
    path = service.report_path(domain)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise StatsError('No report yet for %s. Build one first.' % domain)
    uid = privileged.panel_uid()
    spool_dir = privileged.SPOOL_DIR
    os.makedirs(spool_dir, mode=0o700, exist_ok=True)
    os.chown(spool_dir, uid, uid)
    spool_id = privileged.new_spool_id()
    target = privileged.spool_path(spool_id)
    out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'rb') as source, os.fdopen(out, 'wb') as handle:
        shutil.copyfileobj(source, handle, 1024 * 1024)
    os.chown(target, uid, uid)
    return {'spool_id': spool_id}


def job(job_id):
    return jobs.status(job_id)


ACTIONS = {
    'status': status,
    'check_available': check_available,
    'install': install,
    'install_run': install_run,
    'set_options': set_options,
    'generate': generate,
    'generate_run': generate_run,
    'nightly': nightly,
    'stage_report': stage_report,
    'job': job,
}

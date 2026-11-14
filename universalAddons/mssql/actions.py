"""Root-side SQL Server actions (dispatched by universalAddons/runner.py)."""
import os
import platform
import subprocess
import time

from universalAddons import jobs
from universalAddons.access import load_policy
from universalAddons.mssql import service as sq
from universalAddons.mssql.service import SQLError


def _profile():
    from cyberpanel_os_profile import detect
    profile = detect()
    if profile is None:
        raise SQLError('Unsupported operating system.')
    return {'family': profile.family, 'version': profile.version}


def _installed():
    return os.path.exists('/opt/mssql/bin/sqlservr')


def _site_user(domain):
    from universalAddons import django_env
    django_env.setup()
    from websiteFunctions.models import ChildDomains, Websites
    try:
        return Websites.objects.get(domain=domain).externalApp
    except Websites.DoesNotExist:
        try:
            return ChildDomains.objects.select_related('master').get(domain=domain).master.externalApp
        except ChildDomains.DoesNotExist:
            raise SQLError('Unknown site.')


def overview():
    ram = sq.total_ram_mb()
    profile = _profile()
    installed = _installed()
    state = {'installed': installed, 'ram_mb': ram, 'disk_free_mb': sq.disk_free_mb(),
             'preflight': sq.preflight(profile, platform.machine(), ram, sq.disk_free_mb(), installed),
             'eula_url': sq.EULA_URL, 'default_memory_limit_mb': sq.default_memory_limit_mb(ram)}
    if installed:
        code, out = sq.run(['systemctl', 'is-active', 'mssql-server'])
        state['running'] = out.strip() == 'active'
        meta = sq._load(os.path.join(sq.STATE_DIR, 'sa.json'), {})
        state.update(product=meta.get('product'), memory_limit_mb=meta.get('memory_limit_mb'))
    return state


def install(accept_eula, memory_limit_mb=None):
    if accept_eula is not True:
        raise SQLError('You must accept the Microsoft SQL Server licence terms to install it.')
    state = overview()
    failed = [c['detail'] for c in state['preflight'] if not c['ok']]
    if failed:
        raise SQLError('Cannot install: ' + ' '.join(failed))
    limit = int(memory_limit_mb or state['default_memory_limit_mb'])
    if not 512 <= limit <= max(512, state['ram_mb'] - 512):
        raise SQLError('Memory limit must leave at least 512 MB for the rest of the server.')
    return jobs.spawn('mssql', 'install_run', {'memory_limit_mb': limit})


def install_run(job_id, memory_limit_mb):
    profile = _profile()
    kind, repo, product = sq.repo_for(profile['family'], profile['version'])
    password = sq.strong_password()

    def command(argv, env=None, timeout=1800):
        def step(job):
            code, out = sq.run(argv, timeout=timeout, env=dict(os.environ, **(env or {})) if env else None)
            job.log(out[-3000:])
            if code != 0:
                raise SQLError('%s failed (exit %d)' % (' '.join(argv[:3]), code))
        return step

    steps = []
    if kind == 'rpm':
        steps += [
            ('Add Microsoft repository', command(['curl', '-fsSL', '-o', '/etc/yum.repos.d/mssql-server-%s.repo' % product, repo])),
            ('Add Microsoft tools repository', command(['curl', '-fsSL', '-o', '/etc/yum.repos.d/msprod.repo',
                                                        sq.tools_repo_for(profile['family'], profile['version'])])),
            ('Install SQL Server %s' % product, command(['dnf', '-y', 'install', 'mssql-server'], timeout=3600)),
            ('Install sqlcmd', command(['dnf', '-y', 'install', 'mssql-tools18', 'unixODBC'], env={'ACCEPT_EULA': 'Y'})),
        ]
    else:
        steps += [
            ('Add Microsoft signing key', command(['sh', '-c', 'curl -fsSL https://packages.microsoft.com/keys/microsoft.asc '
                                                   '| gpg --dearmor --yes -o /usr/share/keyrings/microsoft-prod.gpg'])),
            ('Add Microsoft repository', command(['curl', '-fsSL', '-o', '/etc/apt/sources.list.d/mssql-server-%s.list' % product, repo])),
            ('Add Microsoft tools repository', command(['curl', '-fsSL', '-o', '/etc/apt/sources.list.d/msprod.list',
                                                        sq.tools_repo_for(profile['family'], profile['version'])])),
            ('Refresh packages', command(['apt-get', 'update'])),
            ('Install SQL Server %s' % product, command(['apt-get', '-y', 'install', 'mssql-server'], timeout=3600)),
            ('Install sqlcmd', command(['apt-get', '-y', 'install', 'mssql-tools18', 'unixodbc'], env={'ACCEPT_EULA': 'Y'})),
        ]
    # Licence accepted by the administrator in the panel; the sa password goes through the environment.
    steps.append(('Configure Express edition', command([sq.MSSQL_CONF, '-n', 'setup'], env={
        'ACCEPT_EULA': 'Y', 'MSSQL_PID': 'Express', 'MSSQL_SA_PASSWORD': password})))
    steps.append(('Listen on 127.0.0.1 only', command([sq.MSSQL_CONF, 'set', 'network.ipaddress', '127.0.0.1'])))
    steps.append(('Cap memory at %d MB' % memory_limit_mb,
                  command([sq.MSSQL_CONF, 'set', 'memory.memorylimitmb', str(memory_limit_mb)])))
    steps.append(('Restart SQL Server', command(['systemctl', 'restart', 'mssql-server'])))

    def save_secret(job):
        sq._private_write(os.path.join(sq.STATE_DIR, 'sa.json'), {'password': password, 'product': product,
                                                                    'memory_limit_mb': memory_limit_mb,
                                                                    'installed': int(time.time())})

    def verify(job):
        for _ in range(30):
            try:
                out = sq.sqlcmd('SET NOCOUNT ON; SELECT SERVERPROPERTY(\'Edition\');\nGO\n', password)
                job.log(out.strip())
                return {'edition': out.strip()}
            except SQLError:
                time.sleep(2)
        raise SQLError('SQL Server did not accept connections after the restart.')

    steps += [('Store the sa password (root-only)', save_secret), ('Verify', verify)]
    return jobs.run_job(job_id, steps)


def list_databases(domains=None):
    entries = sq.registry()
    usage = {}
    if entries and _installed():
        try:
            usage = sq.sizes(sq.sa_password())
        except SQLError:
            usage = {}
    return {'databases': [dict(e, name=name, size_mb=usage.get(name)) for name, e in sorted(entries.items())
                          if domains is None or e['domain'] in domains]}


def create(domain, name, password=''):
    if not _installed():
        raise SQLError('SQL Server is not installed.')
    entries = sq.registry()
    policy = load_policy()
    if sum(1 for e in entries.values() if e['domain'] == domain) >= policy['max_mssql_dbs_per_site']:
        raise SQLError('This site already has the maximum of %d SQL Server databases.' % policy['max_mssql_dbs_per_site'])
    db = sq.database_name(_site_user(domain), name)
    if db in entries:
        raise SQLError('%s already exists.' % db)
    password = sq.validate_password(password) if password else sq.strong_password()
    sq.sqlcmd(sq.create_sql(db, password), sq.sa_password())
    entries[db] = {'domain': domain, 'login': db, 'created': int(time.time())}
    sq.save_registry(entries)
    return {'name': db, 'login': db, 'password': password, 'connection_string': sq.connection_string(db, password)}


def _owned(name, domain):
    entry = sq.registry().get(name)
    if not entry or entry['domain'] != domain:
        raise SQLError('Unknown database.')
    return entry


def reset_password(name, domain, password=''):
    _owned(name, domain)
    password = sq.validate_password(password) if password else sq.strong_password()
    sq.sqlcmd(sq.password_sql(name, password), sq.sa_password())
    return {'name': name, 'password': password, 'connection_string': sq.connection_string(name, password)}


def drop(name, domain):
    _owned(name, domain)
    sq.sqlcmd(sq.drop_sql(name), sq.sa_password())
    entries = sq.registry()
    entries.pop(name, None)
    sq.save_registry(entries)
    return {'dropped': name}


def service(action):
    if action not in ('start', 'stop', 'restart'):
        raise SQLError('Invalid action.')
    code, out = sq.run(['systemctl', action, 'mssql-server'])
    if code != 0:
        raise SQLError(out.strip()[-300:])
    return overview()


ACTIONS = {
    'overview': overview,
    'install': install,
    'install_run': install_run,
    'list': list_databases,
    'create': create,
    'reset_password': reset_password,
    'drop': drop,
    'service': service,
    'job': lambda job_id: jobs.status(job_id),
}

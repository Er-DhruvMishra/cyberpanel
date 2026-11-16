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
    """SQL Server is set up by the panel (package present and the panel holds its sa password)."""
    return os.path.exists('/opt/mssql/bin/sqlservr') and os.path.exists(os.path.join(sq.STATE_DIR, 'sa.json'))


def _foreign_install():
    """A SQL Server initialised outside the panel: never re-run setup over its databases."""
    return (os.path.exists('/opt/mssql/bin/sqlservr') and not os.path.exists(os.path.join(sq.STATE_DIR, 'sa.json'))
            and os.path.exists(os.path.join(sq.DATA_DIR, 'data', 'master.mdf')))


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
    if _foreign_install():
        raise SQLError('SQL Server is already set up outside the panel; the panel will not reconfigure it.')
    state = overview()
    failed = [c['detail'] for c in state['preflight'] if not c['ok']]
    if failed:
        raise SQLError('Cannot install: ' + ' '.join(failed))
    limit = int(memory_limit_mb or state['default_memory_limit_mb'])
    low, high = sq.memory_limit_bounds(state['ram_mb'])
    if not low <= limit <= high:
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
            # Own repo id: hosts often carry an older microsoft-prod.repo (e.g. the CentOS 7 one) with
            # Microsoft's default id, which would shadow the right repository.
            ('Add Microsoft tools repository', lambda job: sq.write_tools_repo(profile['version'])),
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
    steps.append(('Let SQL Server give way first when memory runs out',
                  lambda job: sq.write_protect_dropin(memory_limit_mb)))
    steps.append(('Reload systemd', command(['systemctl', 'daemon-reload'])))
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


# ----------------------------------------------------------------------------- viewer and row editing

def _viewer(name, domain):
    """(login, sa password) for a database the caller's site owns; the views check site ownership."""
    if not _installed():
        raise SQLError('SQL Server is not installed.')
    entry = _owned(name, domain)
    return entry.get('login') or name, sq.sa_password()


def _columns(name, login, password, schema, table):
    docs = sq.viewer_run(sq.columns_sql(login, schema, table), password, name)
    columns = sq.records(docs[0] if docs else None)
    if not columns:
        raise SQLError('Unknown table or view.')
    return columns


def tables(name, domain):
    login, password = _viewer(name, domain)
    docs = sq.viewer_run(sq.tables_sql(login), password, name)
    return {'name': name, 'tables': sq.records(docs[0] if docs else None)}


def _column_info(c):
    return {'name': c['name'], 'type': sq.display_type(c), 'base': c.get('base'), 'nullable': bool(c.get('nullable')),
            'pk': bool(c.get('pk')), 'identity': bool(c.get('identity')), 'computed': bool(c.get('computed')),
            'default': c.get('default'), 'editable': sq.editable(c), 'max_chars': sq.char_limit(c)}


def columns(name, domain, schema, table):
    login, password = _viewer(name, domain)
    cols = _columns(name, login, password, schema, table)
    keyed = bool(cols) and cols[0].get('kind', 'table') == 'table' and any(c.get('pk') for c in cols)
    return {'name': name, 'schema': schema, 'table': table, 'kind': cols[0].get('kind', 'table'),
            'editable': keyed and all(sq.param_type(c) is not None for c in cols if c.get('pk')),
            'columns': [_column_info(c) for c in cols]}


def structure(name, domain, schema, table):
    login, password = _viewer(name, domain)
    cols = _columns(name, login, password, schema, table)
    docs = sq.viewer_run(sq.structure_sql(login, schema, table), password, name)
    if len(docs) != 3:
        raise SQLError('Could not read the result from SQL Server.')
    stats = sq.records(docs[2])
    return {'name': name, 'schema': schema, 'table': table,
            'columns': [dict(_column_info(c), length=c.get('max_length'), precision=c.get('precision'),
                             scale=c.get('scale'), computed_definition=c.get('computed_definition'),
                             seed=c.get('seed'), increment=c.get('increment'), collation=c.get('collation'))
                        for c in cols],
            'indexes': sq.records(docs[0]), 'foreign_keys': sq.records(docs[1]),
            'stats': stats[0] if stats else {}}


def rows(name, domain, schema, table, page=0, page_size=sq.PAGE_SIZE, sort=None, descending=False,
         filter_column=None, filter_text=None):
    login, password = _viewer(name, domain)
    cols = _columns(name, login, password, schema, table)
    sql = sq.rows_sql(login, schema, table, cols, page, page_size, sort, descending, filter_column, filter_text)
    docs = sq.viewer_run(sql, password, name)
    data = docs[0] if docs else None
    width = len(cols)
    values, keys = [], []
    for row in (data or []):
        cells = [v for _, v in row]
        values.append([sq.display_value(v) for v in cells[:width]])
        keys.append(cells[width:])
    has_keys = any(c.get('pk') for c in cols)
    return sq.check_size({'name': name, 'schema': schema, 'table': table, 'page': int(page),
                          'page_size': page_size, 'columns': [c['name'] for c in cols], 'rows': values,
                          'keys': keys if has_keys else None,
                          'key_columns': [c['name'] for c in sorted((c for c in cols if c.get('pk')), key=lambda c: c['pk'])],
                          'sort': sort or None, 'descending': descending is True,
                          'filter_column': filter_column if filter_text else None, 'filter_text': filter_text or None})


def query(name, domain, sql, write=False, confirm_all=False):
    """A SELECT (always rolled back) or, with write=True, one committed INSERT/UPDATE/DELETE/MERGE."""
    if write is not True:
        try:
            sq.readonly_query(sql)  # refuse before touching the server
        except SQLError as refused:
            sq.refuse_readonly(sql, refused)
        login, password = _viewer(name, domain)
        docs = sq.viewer_run(sq.query_sql(login, sql), password, name)
        if len(docs) != 2:
            raise SQLError('Could not read the result from SQL Server.')
        return sq.check_size(dict(sq.result_table(docs[0], docs[1]), name=name))
    info = sq.change_query(sql)
    if info['verb'] == 'SELECT':
        return query(name, domain, sql)
    if sq.needs_confirmation(info) and confirm_all is not True:
        raise SQLError('%s without WHERE changes every row; confirm to run it.' % info['verb'])
    login, password = _viewer(name, domain)
    docs = sq.viewer_run(sq.dml_sql(login, sql), password, name)
    return sq.check_size(dict(sq.change_result(docs, info['verb'].lower()), name=name))


def _change_row(action, name, domain, schema, table, key=None, values=None):
    login, password = _viewer(name, domain)
    cols = _columns(name, login, password, schema, table)
    docs = sq.viewer_run(sq.row_sql(login, schema, table, cols, action, key, values), password, name)
    result = sq.change_result(docs, action)
    return {'name': name, 'schema': schema, 'table': table, 'action': action, 'affected': result['affected']}


def update_row(name, domain, schema, table, key, values):
    return _change_row('update', name, domain, schema, table, key, values)


def delete_row(name, domain, schema, table, key):
    return _change_row('delete', name, domain, schema, table, key)


def insert_row(name, domain, schema, table, values):
    return _change_row('insert', name, domain, schema, table, values=values)


def service(action):
    if action not in ('start', 'stop', 'restart'):
        raise SQLError('Invalid action.')
    code, out = sq.run(['systemctl', action, 'mssql-server'])
    if code != 0:
        raise SQLError(out.strip()[-300:])
    return overview()


def protect():
    """Apply the memory-safety drop-in to an existing panel-managed SQL Server (idempotent)."""
    if not _installed():
        raise SQLError('SQL Server is not installed.')
    meta = sq._load(os.path.join(sq.STATE_DIR, 'sa.json'), {})
    limit = int(meta.get('memory_limit_mb') or sq.default_memory_limit_mb(sq.total_ram_mb()))
    sq.write_protect_dropin(limit)
    for argv in (['systemctl', 'daemon-reload'], ['systemctl', 'restart', 'mssql-server']):
        code, out = sq.run(argv, timeout=300)
        if code != 0:
            raise SQLError('%s failed: %s' % (' '.join(argv), out.strip()[-300:]))
    return {'dropin': sq.PROTECT_DROPIN, 'memory_limit_mb': limit}


def _meta():
    return sq._load(os.path.join(sq.STATE_DIR, 'sa.json'), {})


def memory_state():
    """The panel's memory cap and, when SQL Server answers, the max server memory in use."""
    meta = _meta()
    state = {'memory_limit_mb': meta.get('memory_limit_mb'), 'max_server_memory_mb': None}
    if meta.get('password'):
        try:
            out = sq.sqlcmd(sq.MAX_SERVER_MEMORY_QUERY, meta['password'], timeout=15)
            numbers = [line.strip() for line in out.splitlines() if line.strip().isdigit()]
            state['max_server_memory_mb'] = int(numbers[-1]) if numbers else None
        except SQLError:
            pass
    return state


def write_memory_limit(memory_limit_mb):
    """Store a new memory cap: mssql-conf memory.memorylimitmb, the systemd ceiling drop-in and the
    panel's record. Takes effect when SQL Server restarts (Applications restarts and checks it)."""
    if not _installed():
        raise SQLError('SQL Server is not set up by the panel.')
    limit = sq.validate_memory_limit(memory_limit_mb, sq.total_ram_mb())
    code, out = sq.run([sq.MSSQL_CONF, 'set', 'memory.memorylimitmb', str(limit)], timeout=120)
    if code != 0:
        raise SQLError('mssql-conf set memory.memorylimitmb failed: %s' % out.strip()[-300:])
    sq.write_protect_dropin(limit)
    meta = _meta()
    meta['memory_limit_mb'] = limit
    sq._private_write(os.path.join(sq.STATE_DIR, 'sa.json'), meta)
    return limit


def apply_max_server_memory(memory_limit_mb):
    """sp_configure 'max server memory' for the cap (needs SQL Server running); returns the value in use."""
    mb = sq.max_server_memory_mb(memory_limit_mb)
    out = sq.sqlcmd(sq.max_server_memory_sql(mb), sq.sa_password(), timeout=60)
    numbers = [line.strip() for line in out.splitlines() if line.strip().isdigit()]
    if not numbers or int(numbers[-1]) != mb:
        raise SQLError('max server memory is not %d MB after sp_configure: %s' % (mb, out.strip()[-300:]))
    return mb


def ping():
    """(healthy, detail): SQL Server accepts the panel's sa login."""
    try:
        out = sq.sqlcmd("SET NOCOUNT ON; SELECT 'ok';\nGO\n", sq.sa_password(), timeout=20)
    except SQLError as exc:
        return False, str(exc)[-200:]
    return 'ok' in out, 'sa login answered'


ACTIONS = {
    'protect': protect,
    'overview': overview,
    'install': install,
    'install_run': install_run,
    'list': list_databases,
    'create': create,
    'reset_password': reset_password,
    'drop': drop,
    'service': service,
    'tables': tables,
    'columns': columns,
    'structure': structure,
    'rows': rows,
    'query': query,
    'update_row': update_row,
    'delete_row': delete_row,
    'insert_row': insert_row,
    'job': lambda job_id: jobs.status(job_id),
}

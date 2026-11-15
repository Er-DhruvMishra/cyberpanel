import re

from plogical.acl import ACLManager
from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, load_policy, ok, site_api
from universalAddons.mssql import service as sq

_NAME = re.compile(r'^[a-z][a-z0-9_]{1,30}$')
_DB = re.compile(r'^[A-Za-z][A-Za-z0-9_]{1,63}$')


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('mssql', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def page(request):
    try:
        user_id = request.session['userID']
        acl = ACLManager.loadedACL(user_id)
        is_admin = acl.get('admin') == 1
        sites = ACLManager.findAllSites(acl, user_id, 1)
    except Exception:
        is_admin, sites = False, []
    enabled = is_admin or load_policy().get('mssql_for_users')
    return httpProc(request, 'universalAddons/mssql.html', {'is_admin': is_admin, 'sites': sites if enabled else [],
                                                             'enabled': enabled}).render()


@admin_api
def overview(request, data):
    return _call('overview')


@admin_api
def install(request, data):
    limit = data.get('memoryLimitMb')
    if limit is not None and not isinstance(limit, int):
        return error('Memory limit must be a number.', status=400)
    return _call('install', accept_eula=data.get('acceptEula') is True, memory_limit_mb=limit)


@admin_api
def service(request, data):
    if data.get('action') not in ('start', 'stop', 'restart'):
        return error('Invalid action.', status=400)
    return _call('service', action=data['action'])


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)


@site_api('mssql_for_users')
def databases(request, data, context):
    return _call('list', domains=None if context.is_admin else ACLManager.findAllSites(context.acl, context.user_id, 1))


def _password(data):
    # 'passwordByPass' is the key CyberPanel's input filter reserves for passwords.
    password = data.get('passwordByPass', '')
    if not isinstance(password, str):
        raise ValueError('Invalid password.')
    return password


@site_api('mssql_for_users')
def create(request, data, context):
    domain = context.require_site(str(data.get('domain', '')).strip().lower())
    name = str(data.get('name', '')).strip().lower()
    if not _NAME.match(name):
        return error('Database name: 2-31 lowercase letters, digits or _, starting with a letter.', status=400)
    return _call('create', domain=domain, name=name, password=_password(data))


@site_api('mssql_for_users')
def reset(request, data, context):
    domain = context.require_site(str(data.get('domain', '')).strip().lower())
    name = str(data.get('name', ''))
    if not _DB.match(name):
        return error('Invalid database.', status=400)
    return _call('reset_password', name=name, domain=domain, password=_password(data))


@site_api('mssql_for_users')
def drop(request, data, context):
    domain = context.require_site(str(data.get('domain', '')).strip().lower())
    name = str(data.get('name', ''))
    if not _DB.match(name):
        return error('Invalid database.', status=400)
    return _call('drop', name=name, domain=domain)


# ----------------------------------------------------------------------------- viewer (read-only)

def _viewed(data, context):
    """(domain, database) after the site-ownership and name checks shared by every viewer call."""
    domain = context.require_site(str(data.get('domain', '')).strip().lower())
    name = str(data.get('name', ''))
    if not _DB.match(name):
        raise ValueError('Invalid database.')
    return domain, name


def _object(data):
    schema, table = data.get('schema'), data.get('table')
    for value in (schema, table):
        if not isinstance(value, str) or not sq.OBJECT_RE.match(value):
            raise ValueError('Invalid schema or table name.')
    return schema, table


@site_api('mssql_for_users')
def tables(request, data, context):
    domain, name = _viewed(data, context)
    return _call('tables', name=name, domain=domain)


@site_api('mssql_for_users')
def columns(request, data, context):
    domain, name = _viewed(data, context)
    schema, table = _object(data)
    return _call('columns', name=name, domain=domain, schema=schema, table=table)


@site_api('mssql_for_users')
def rows(request, data, context):
    domain, name = _viewed(data, context)
    schema, table = _object(data)
    page = data.get('page', 0)
    if not isinstance(page, int) or isinstance(page, bool) or not 0 <= page <= 10 ** 7:
        return error('Invalid page.', status=400)
    return _call('rows', name=name, domain=domain, schema=schema, table=table, page=page)


@site_api('mssql_for_users')
def query(request, data, context):
    domain, name = _viewed(data, context)
    # 'content' is a key CyberPanel's input filter leaves unscreened (SQL needs ; ' ( [ and so on).
    sql = data.get('content', '')
    if not isinstance(sql, str):
        return error('Invalid query.', status=400)
    sq.readonly_query(sql)  # SQLError is a ValueError: a refused query is a 400
    return _call('query', name=name, domain=domain, sql=sql)

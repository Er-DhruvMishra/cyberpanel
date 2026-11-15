import re

from django.http import HttpResponse

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


# ----------------------------------------------------------------------------- viewer and row editing

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
def structure(request, data, context):
    domain, name = _viewed(data, context)
    schema, table = _object(data)
    return _call('structure', name=name, domain=domain, schema=schema, table=table)


def _column_name(value, what):
    if value is None or value == '':
        return None
    if not isinstance(value, str) or len(value) > 128 or '\x00' in value:
        raise ValueError('Invalid %s.' % what)
    return value


def _browse(data):
    """Paging, sorting and filtering options. They travel inside the 'browse' object: CyberPanel's
    input filter skips object values, and column names or filter text may contain [ ] ; ( ) etc."""
    page = data.get('page', 0)
    if not isinstance(page, int) or isinstance(page, bool) or not 0 <= page <= 10 ** 7:
        raise ValueError('Invalid page.')
    options = data.get('browse')
    if options is None:
        return {'page': page}
    if not isinstance(options, dict):
        raise ValueError('Invalid browse options.')
    size = options.get('pageSize', sq.PAGE_SIZE)
    if isinstance(size, bool) or size not in sq.PAGE_SIZES:
        raise ValueError('Page size must be 25, 50 or 100.')
    text = options.get('filterText')
    if text is not None and (not isinstance(text, str) or len(text) > sq.MAX_FILTER_CHARS or '\x00' in text):
        raise ValueError('The filter is at most %d characters.' % sq.MAX_FILTER_CHARS)
    column = _column_name(options.get('filterColumn'), 'filter column')
    if text and not column:
        raise ValueError('Choose the column to filter.')
    args = {'page': page, 'page_size': size, 'sort': _column_name(options.get('sort'), 'sort column'),
            'descending': options.get('desc') is True}
    if text:
        args.update(filter_column=column, filter_text=text)
    return args


@site_api('mssql_for_users')
def rows(request, data, context):
    domain, name = _viewed(data, context)
    schema, table = _object(data)
    return _call('rows', name=name, domain=domain, schema=schema, table=table, **_browse(data))


def _sql(data):
    # 'content' is a key CyberPanel's input filter leaves unscreened (SQL needs ; ' ( [ and so on).
    sql = data.get('content', '')
    if not isinstance(sql, str):
        raise ValueError('Invalid query.')
    return sql


@site_api('mssql_for_users')
def query(request, data, context):
    domain, name = _viewed(data, context)
    sql = _sql(data)
    if data.get('write') is not True:
        try:
            sq.readonly_query(sql)  # SQLError is a ValueError: a refused query is a 400
        except sq.SQLError as refused:
            sq.refuse_readonly(sql, refused)
        return _call('query', name=name, domain=domain, sql=sql)
    info = sq.change_query(sql)
    confirm = data.get('confirm_all') is True
    if sq.needs_confirmation(info) and not confirm:
        # Not an error: the page asks the user, then sends the query again with confirm_all.
        return ok(result={'needs_confirm': True, 'verb': info['verb'],
                          'message': '%s without WHERE changes every row of the table.' % info['verb']})
    return _call('query', name=name, domain=domain, sql=sql, write=True, confirm_all=confirm)


def _row(data, need_key, need_values):
    """(key, values) from the 'row' object (object values are not screened by CyberPanel's input
    filter, and row values may contain any character)."""
    row = data.get('row')
    if not isinstance(row, dict):
        raise ValueError('Invalid row.')
    parts = []
    for part, needed in (('key', need_key), ('values', need_values)):
        value = row.get(part)
        if not needed:
            parts.append(None)
            continue
        if not isinstance(value, dict) or len(value) > 1024:
            raise ValueError('Invalid row %s.' % part)
        for column, cell in value.items():
            _column_name(column, 'column')
            if cell is not None and not isinstance(cell, (str, int, float, bool)):
                raise ValueError('Invalid value for %s.' % column)
        parts.append(value)
    if need_values:
        sq._check_size(parts[1])
    return parts


@site_api('mssql_for_users')
def update_row(request, data, context):
    domain, name = _viewed(data, context)
    schema, table = _object(data)
    key, values = _row(data, True, True)
    if not values:
        return error('Nothing was changed.', status=400)
    return _call('update_row', name=name, domain=domain, schema=schema, table=table, key=key, values=values)


@site_api('mssql_for_users')
def delete_row(request, data, context):
    domain, name = _viewed(data, context)
    schema, table = _object(data)
    key, _ = _row(data, True, False)
    return _call('delete_row', name=name, domain=domain, schema=schema, table=table, key=key)


@site_api('mssql_for_users')
def insert_row(request, data, context):
    domain, name = _viewed(data, context)
    schema, table = _object(data)
    _, values = _row(data, False, True)
    return _call('insert_row', name=name, domain=domain, schema=schema, table=table, values=values)


def _filename(*parts):
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', '_'.join(str(p) for p in parts if p not in (None, '')))[:120]


@site_api('mssql_for_users')
def export(request, data, context):
    """The current table page or query result as a CSV or JSON download, built from the same result
    the page shows. Query exports re-run the query, so only read-only queries are exported."""
    domain, name = _viewed(data, context)
    fmt = data.get('format')
    if fmt not in ('csv', 'json'):
        return error('Format must be csv or json.', status=400)
    if data.get('source') == 'rows':
        schema, table = _object(data)
        args = dict(_browse(data), name=name, domain=domain, schema=schema, table=table)
        action, filename = 'rows', _filename(name, schema, table, 'page%d' % (args['page'] + 1))
    elif data.get('source') == 'query':
        sql = _sql(data)
        sq.readonly_query(sql)
        action, args, filename = 'query', {'name': name, 'domain': domain, 'sql': sql}, _filename(name, 'query')
    else:
        return error('Invalid export source.', status=400)
    try:
        result = privileged.call('mssql', action, **args)
    except RuntimeError as exc:
        return error(str(exc))
    if fmt == 'csv':
        body, kind = sq.to_csv(result['columns'], result['rows']), 'text/csv; charset=utf-8'
    else:
        body, kind = sq.to_json(result['columns'], result['rows']), 'application/json; charset=utf-8'
    response = HttpResponse(body.encode('utf-8'), content_type=kind)
    response['Content-Disposition'] = 'attachment; filename="%s.%s"' % (filename, fmt)
    response['Cache-Control'] = 'no-store'
    return response

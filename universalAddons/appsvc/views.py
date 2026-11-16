"""Applications page (server-wide software: caches, search, databases, brokers, clients) and its JSON
endpoints. Administrator-only."""
import re

from universalAddons import privileged
from universalAddons.access import admin_api, admin_page, error, ok
from universalAddons.appsvc import more as mo
from universalAddons.appsvc import service as sv

OPS = ('start', 'stop', 'restart', 'enable', 'disable')


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('appsvc', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _app(data):
    app = str(data.get('app', '')).strip().lower()
    if app not in sv.APPS:
        raise ValueError('Choose an application.')
    return app


def _job_id(value):
    job_id = str(value or '')
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        raise ValueError('Invalid job.')
    return job_id


def page(request):
    return admin_page(request, 'universalAddons/appsvc.html', lambda: {
        'apps': [dict(sv.APPS[k], key=k) for k in sv.ORDER], 'skipped': sv.SKIPPED})


@admin_api
def overview(request, data):
    return _call('overview')


@admin_api
def logs(request, data):
    return _call('logs', app=_app(data))


@admin_api
def preflight(request, data):
    return _call('preflight', app=_app(data))


@admin_api
def install(request, data):
    app = _app(data)
    if app == 'postgresql':
        major = str(data.get('major', sv.PG_DEFAULT_MAJOR))
        if major not in [str(m) for m in sv.PG_MAJORS]:
            return error('Choose PostgreSQL %s.' % ' or '.join(map(str, sv.PG_MAJORS)), status=400)
        return _call('install', app=app, force=data.get('force') is True, major=int(major))
    return _call('install', app=app, force=data.get('force') is True)


@admin_api
def remove_preview(request, data):
    return _call('remove_preview', app=_app(data))


@admin_api
def remove(request, data):
    app = _app(data)
    if data.get('confirm') is not True:
        return error('Confirm removing %s.' % sv.APPS[app]['title'], status=400)
    delete = data.get('deleteData') is True
    confirm_name = data.get('confirmName', '')
    if not isinstance(confirm_name, str) or len(confirm_name) > 64:
        return error('Invalid confirmation.', status=400)
    if delete and confirm_name.strip().lower() != app:
        return error('Type %s to confirm deleting its data.' % app, status=400)
    args = {'app': app, 'confirm': True, 'delete_data': delete, 'confirm_name': confirm_name.strip().lower() if delete else ''}
    if data.get('previewJob') is not None:
        args['preview_job'] = _job_id(data.get('previewJob'))
    elif app not in ('elasticsearch', 'redis', 'memcached'):
        return error('Preview what will be removed first.', status=400)
    return _call('remove', **args)


@admin_api
def configure(request, data):
    app = _app(data)
    settings = data.get('settings')
    if not isinstance(settings, dict) or len(settings) > 20:
        return error('Send the settings as an object.', status=400)
    allowed = {f['name'] for f in sv.FIELDS[app]}
    unknown = sorted(set(settings) - allowed)
    if unknown:
        return error('Unknown setting(s): %s.' % ', '.join(unknown)[:200], status=400)
    for value in settings.values():
        items = value if isinstance(value, list) else [value]
        if len(items) > 8 or any(not isinstance(v, (str, int, float, bool)) or (isinstance(v, str) and len(v) > 128)
                                 for v in items):
            return error('Invalid setting value.', status=400)
    return _call('configure', app=app, settings=settings, confirm_exposed=data.get('confirmExposed') is True)


@admin_api
def revert(request, data):
    app = _app(data)
    if data.get('confirm') is not True:
        return error('Confirm going back to the previous configuration.', status=400)
    return _call('revert', app=app)


@admin_api
def control(request, data):
    op = str(data.get('op', ''))
    if op not in OPS:
        return error('Unknown service action.', status=400)
    return _call('control', app=_app(data), op=op)


@admin_api
def reveal(request, data):
    return _call('reveal', app=_app(data))


@admin_api
def pg_create(request, data):
    database, user = str(data.get('database', '')).strip(), str(data.get('user', '')).strip()
    for name in (database, user):
        mo.pg_ident(name)   # ValueError (AppError) -> 400 before anything runs as root
    return _call('pg_create', database=database, user=user)


@admin_api
def disk(request, data):
    return _call('disk')


@admin_api
def runtimes(request, data):
    return _call('runtimes')


@admin_api
def oracle_db_check(request, data):
    return _call('oracle_db_check', confirm_ram=data.get('confirmRam') is True)


@admin_api
def job(request, data):
    return _call('job', job_id=_job_id(data.get('job')))


# ----------------------------------------------------------------------------- the old page's API

LEGACY_NAMES = {info['legacy']: key for key, info in sv.APPS.items() if info.get('legacy')}


def legacy_remove_install(app_name, status, call=None):
    """/manageservices/removeInstall: start the same install/remove job as this page.

    The old page sends no confirmation; removing through it keeps the data directory."""
    call = call or privileged.call
    app = LEGACY_NAMES.get(app_name)
    if not app:
        raise ValueError('Unknown application.')
    if status == 'Installing':
        return call('appsvc', 'install', app=app, force=False)
    return call('appsvc', 'remove', app=app, confirm=True, delete_data=False, confirm_name='')

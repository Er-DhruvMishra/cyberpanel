import re


from universalAddons import privileged
from universalAddons.access import admin_api, admin_page, error, ok
from universalAddons.mysqlmgr.service import SPEC, MySQLError, thread_id

_SETTING_VALUE = re.compile(r'^[A-Za-z0-9_.]{1,32}$')


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('mysqlmgr', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def panel_users():
    """Database users the panel itself connects as; their threads are never killed."""
    from django.conf import settings
    user = settings.DATABASES.get('default', {}).get('USER')
    return sorted({'cyberpanel', user} if user else {'cyberpanel'})


def page(request):
    return admin_page(request, 'universalAddons/mysqlmgr.html')


@admin_api
def status(request, data):
    return _call('status')


@admin_api
def databases(request, data):
    return _call('databases')


@admin_api
def processes(request, data):
    return _call('processes', panel_users=panel_users())


@admin_api
def kill(request, data):
    try:
        tid = thread_id(data.get('thread'))
    except MySQLError as exc:
        return error(str(exc), status=400)
    mode = data.get('mode', 'query')
    if mode not in ('query', 'connection'):
        return error('Invalid kill mode.', status=400)
    return _call('kill', thread=tid, mode=mode, panel_users=panel_users())


@admin_api
def advise(request, data):
    return _call('advise')


@admin_api
def apply(request, data):
    settings = data.get('settings')
    if not isinstance(settings, dict) or not settings:
        return error('Choose at least one setting to apply.', status=400)
    clean = {}
    for name, value in settings.items():
        if name not in SPEC:
            return error('%s cannot be set from the panel.' % name, status=400)
        if isinstance(value, bool) or not isinstance(value, (str, int)) or not _SETTING_VALUE.match(str(value)):
            return error('Invalid value for %s.' % name, status=400)
        clean[name] = value
    return _call('apply', settings=clean)


@admin_api
def revert(request, data):
    return _call('revert')


@admin_api
def check(request, data):
    return _call('check')


@admin_api
def restart(request, data):
    if data.get('confirm') is not True:
        return error('Confirm the restart.', status=400)
    return _call('restart', auto_revert=data.get('autoRevert') is not False)


@admin_api
def upgrade(request, data):
    return _call('upgrade')


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)

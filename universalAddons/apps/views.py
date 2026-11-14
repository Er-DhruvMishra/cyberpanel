import re

from plogical.acl import ACLManager
from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, load_policy, ok, site_api

_ID = re.compile(r'^[a-z][a-z0-9-]{1,30}$')
_VERSION = re.compile(r'^\d{1,3}(\.\d{1,4}){1,3}(-[a-z0-9.]+)?$')
APP_FIELDS = ('id', 'kind', 'runtime', 'entry', 'mode', 'workers', 'prefix', 'websocket', 'memory_mb', 'cpu_percent')


def _call(action, **args):
    try:
        return ok(result=privileged.call('apps', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _owned_sites(context):
    return ACLManager.findAllSites(context.acl, context.user_id, 1)


def _app_args(data, context):
    app_id = str(data.get('app', '')).strip().lower()
    if not _ID.match(app_id):
        raise ValueError('Invalid app.')
    return {'app_id': app_id, 'domain': context.require_site(str(data.get('domain', '')).strip().lower())}


def page(request):
    """Open to every logged-in user; what they can do is decided per request (see site_api)."""
    try:
        user_id = request.session['userID']
        acl = ACLManager.loadedACL(user_id)
        is_admin = acl.get('admin') == 1
        sites = ACLManager.findAllSites(acl, user_id, 1)
    except Exception:
        is_admin, sites = False, []
    enabled = is_admin or load_policy().get('apps_for_users')
    return httpProc(request, 'universalAddons/apps.html', {'is_admin': is_admin, 'sites': sites if enabled else [],
                                                            'enabled': enabled}).render()


# --- administrator: runtimes and policy

@admin_api
def runtimes(request, data):
    return _call('runtimes', include_catalogue=data.get('catalogue') is True)


@admin_api
def runtime_install(request, data):
    kind, version = data.get('kind'), str(data.get('version', ''))
    if kind not in ('node', 'dotnet', 'python') or not _VERSION.match(version):
        return error('Invalid runtime.', status=400)
    return _call('runtime_install', kind=kind, version=version)


@admin_api
def runtime_uninstall(request, data):
    kind, version = data.get('kind'), str(data.get('version', ''))
    if kind not in ('node', 'dotnet', 'python') or not _VERSION.match(version):
        return error('Invalid runtime.', status=400)
    return _call('runtime_uninstall', kind=kind, version=version)


@admin_api
def policy(request, data):
    return _call('save_policy', policy={k: v for k, v in data.items() if not isinstance(v, (dict, list))})


# --- site owners (and administrators)

@site_api('apps_for_users')
def apps(request, data, context):
    return _call('list', domains=None if context.is_admin else _owned_sites(context))


@site_api('apps_for_users')
def save(request, data, context):
    domain = context.require_site(str(data.get('domain', '')).strip().lower())
    spec = {key: data[key] for key in APP_FIELDS if key in data}
    if not context.is_admin and data.get('dir'):
        raise ValueError('Only administrators can choose a custom app directory.')
    if context.is_admin and data.get('dir'):
        spec['dir'] = str(data['dir'])
    env = data.get('env')
    if env is not None:
        if not isinstance(env, list):
            raise ValueError('Invalid environment.')
        spec['env'] = {}
        for item in env:
            if not isinstance(item, dict):
                raise ValueError('Invalid environment.')
            spec['env'][str(item.get('key', ''))] = str(item.get('value', ''))
    return _call('save', domain=domain, spec=spec)


@site_api('apps_for_users')
def deploy(request, data, context):
    return _call('deploy', **_app_args(data, context))


@site_api('apps_for_users')
def control(request, data, context):
    if data.get('action') not in ('start', 'stop', 'restart'):
        return error('Invalid action.', status=400)
    return _call('control', action=data['action'], **_app_args(data, context))


@site_api('apps_for_users')
def logs(request, data, context):
    return _call('logs', lines=200, **_app_args(data, context))


@site_api('apps_for_users')
def delete(request, data, context):
    return _call('delete', remove_files=data.get('removeFiles') is True, **_app_args(data, context))


@site_api('apps_for_users')
def job(request, data, context):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)

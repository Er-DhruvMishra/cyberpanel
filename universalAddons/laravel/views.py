"""Laravel Toolkit pages and endpoints: administrators, resellers and site owners (when opened to them)
on the sites they manage. Ownership is checked here through the panel ACL (SiteContext); the root
side re-resolves the site from the database and re-validates the app path and the command."""
import re

from universalAddons import privileged
from universalAddons.access import (admin_api, error, ok, owned_sites, remember_job, require_job, site_api,
                                    site_page)
from universalAddons.laravel import service as lv
from universalAddons.siteinfo import DOMAIN_RE, SiteError, check_rel

FEATURE = 'laravel_for_users'


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('laravel', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _start(request, action, /, **args):
    try:
        result = privileged.call('laravel', action, **args)
    except RuntimeError as exc:
        return error(str(exc))
    remember_job(request, 'laravel', result)
    return ok(result=result)


def _domain(data, context):
    value = str(data.get('domain', '')).strip().lower()
    if not DOMAIN_RE.match(value):
        raise ValueError('Invalid domain.')
    return context.require_site(value)


def _target(data, context):
    """(domain, app path) for a request; the path is relative to the site's document root."""
    try:
        return _domain(data, context), check_rel(data.get('path', ''))
    except SiteError as exc:
        raise ValueError(str(exc))


def page(request):
    def values(is_admin):
        wanted = str(request.GET.get('site', '')).strip().lower()
        return {'site': wanted if DOMAIN_RE.match(wanted) else ''}
    return site_page(request, 'universalAddons/laravel.html', FEATURE, values)


@site_api(FEATURE)
def apps(request, data, context):
    return _call('list', domains=owned_sites(context))


@site_api(FEATURE)
def info(request, data, context):
    domain, path = _target(data, context)
    return _call('info', domain=domain, path=path)


@site_api(FEATURE)
def command(request, data, context):
    """{"domain", "path", "command": {"tool", "name", "options", "confirmed"}}: nested, because command
    names such as migrate:status contain ':' (the panel's request filter screens top-level strings)."""
    domain, path = _target(data, context)
    spec = data.get('command')
    if not isinstance(spec, dict):
        return error('Send the command in "command".', status=400)
    tool, name, options = spec.get('tool'), spec.get('name'), spec.get('options') or {}
    confirmed = spec.get('confirmed') is True
    try:
        lv.build_command(tool, name, options, confirmed)
    except SiteError as exc:
        return error(str(exc), status=400)
    return _start(request, 'command', domain=domain, path=path, tool=tool, name=name, options=options,
                  confirmed=confirmed)


@site_api(FEATURE)
def scheduler(request, data, context):
    domain, path = _target(data, context)
    if data.get('enable') not in (True, False):
        return error('Invalid setting.', status=400)
    return _call('scheduler', domain=domain, path=path, enable=data['enable'])


@site_api(FEATURE)
def worker(request, data, context):
    domain, path = _target(data, context)
    if data.get('enable') not in (True, False):
        return error('Invalid setting.', status=400)
    memory = data.get('memory_mb')
    if memory is not None and (isinstance(memory, bool) or not isinstance(memory, int) or not 64 <= memory <= 65536):
        return error('Invalid memory limit.', status=400)
    queue = str(data.get('queue') or 'default')
    if not re.match(r'^[A-Za-z0-9_,-]{1,100}$', queue):
        return error('Invalid queue name.', status=400)
    return _call('worker', domain=domain, path=path, enable=data['enable'], memory_mb=memory, queue=queue)


@site_api(FEATURE)
def worker_logs(request, data, context):
    domain, path = _target(data, context)
    return _call('worker_logs', domain=domain, path=path)


@site_api(FEATURE)
def env(request, data, context):
    domain, path = _target(data, context)
    return _call('env_list', domain=domain, path=path)


@site_api(FEATURE)
def env_set(request, data, context):
    """One key at a time. The value travels inside a nested object (the panel's request filter
    screens top-level strings, and .env values legitimately contain : $ and quotes)."""
    domain, path = _target(data, context)
    entry = data.get('entry')
    if not isinstance(entry, dict):
        return error('Send {"entry": {"key": ..., "value": ...}}.', status=400)
    key, value = str(entry.get('key', '')).strip(), entry.get('value', '')
    if not lv.ENV_KEY_RE.match(key) or not isinstance(value, str) or len(value) > 4096 or \
            any(c in value for c in '\r\n\x00'):
        return error('Invalid key or value.', status=400)
    return privileged_private('env_set', domain=domain, path=path, key=key, value=value)


def privileged_private(action, /, **args):
    """Values that may be secrets go through a private spool file, not the command line."""
    try:
        return ok(result=privileged.call_private('laravel', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


@site_api(FEATURE)
def logs(request, data, context):
    domain, path = _target(data, context)
    return _call('logs', domain=domain, path=path)


@site_api(FEATURE)
def public(request, data, context):
    domain, path = _target(data, context)
    if data.get('undo') is True:
        return _call('restore_public', domain=domain, path=path)
    method = data.get('method', 'auto')
    if method not in ('auto', 'vhost', 'htaccess'):
        return error('Invalid method.', status=400)
    return _call('point_public', domain=domain, path=path, method=method)


@site_api(FEATURE)
def install(request, data, context):
    domain, path = _target(data, context)
    version = str(data.get('version') or '')
    if version and not re.match(r'^\d{1,2}$', version):
        return error('Invalid Laravel version.', status=400)
    point = data.get('point', 'auto')
    if point not in ('auto', 'vhost', 'htaccess', 'none'):
        return error('Invalid choice for public/.', status=400)
    return _start(request, 'install', domain=domain, path=path, version=version, point=point)


@site_api(FEATURE)
def job(request, data, context):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=require_job(request, context, 'laravel', job_id))


# --- administrators only: server-wide

@admin_api
def composer(request, data):
    try:
        result = privileged.call('laravel', 'composer_install')
    except RuntimeError as exc:
        return error(str(exc))
    remember_job(request, 'laravel', result)
    return ok(result=result)

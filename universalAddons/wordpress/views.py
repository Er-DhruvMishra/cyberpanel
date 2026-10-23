import re

from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, ok

_DOMAIN = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
_SLUG = re.compile(r'^[a-z0-9][a-z0-9._-]{0,99}$')
_SNAP = re.compile(r'^\d{8}-\d{6}-[0-9a-f]{4}$')
FLAGS = ('WP_DEBUG', 'DISALLOW_FILE_EDIT', 'DISABLE_WP_CRON', 'indexing', 'maintenance')
FIXES = ('DISALLOW_FILE_EDIT', 'WP_DEBUG', 'xmlrpc', 'config_perms', 'salts')


def _call(action, **args):
    try:
        return ok(result=privileged.call('wordpress', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _domain(data, key='domain'):
    value = str(data.get(key, '')).strip().lower()
    if not _DOMAIN.match(value):
        raise ValueError('Invalid %s.' % key)
    return value


def page(request):
    return httpProc(request, 'universalAddons/wordpress.html', {}, 'admin').render()


@admin_api
def sites(request, data):
    return _call('list')


@admin_api
def info(request, data):
    return _call('info', domain=_domain(data))


@admin_api
def item(request, data):
    kind, action, slug = data.get('kind'), data.get('action'), str(data.get('slug', ''))
    if kind not in ('plugin', 'theme') or action not in ('activate', 'deactivate', 'update', 'delete', 'install') \
            or not _SLUG.match(slug):
        return error('Invalid plugin/theme action.', status=400)
    return _call('item', domain=_domain(data), kind=kind, action=action, slug=slug)


@admin_api
def flag(request, data):
    if data.get('flag') not in FLAGS or data.get('enable') not in (True, False):
        return error('Invalid setting.', status=400)
    return _call('flag', domain=_domain(data), flag=data['flag'], enable=data['enable'])


@admin_api
def autoupdates(request, data):
    if data.get('kind') not in ('plugin', 'theme') or data.get('enable') not in (True, False):
        return error('Invalid setting.', status=400)
    return _call('autoupdates', domain=_domain(data), kind=data['kind'], enable=data['enable'])


@admin_api
def hardening(request, data):
    return _call('hardening', domain=_domain(data))


@admin_api
def fix(request, data):
    if data.get('fix') not in FIXES:
        return error('Unknown fix.', status=400)
    return _call('fix', domain=_domain(data), fix=data['fix'])


@admin_api
def performance(request, data):
    what = data.get('what')
    if what not in ('lscache', 'objectcache'):
        return error('Unknown option.', status=400)
    return _call(what, domain=_domain(data))


@admin_api
def login(request, data):
    return _call('login', domain=_domain(data))


@admin_api
def snapshots(request, data):
    return _call('snapshots', domain=_domain(data))


@admin_api
def update(request, data):
    if data.get('scope') not in ('core', 'plugins', 'themes', 'all'):
        return error('Invalid update scope.', status=400)
    return _call('update', domain=_domain(data), scope=data['scope'])


@admin_api
def snapshot(request, data):
    return _call('snapshot', domain=_domain(data))


@admin_api
def rollback(request, data):
    snap = str(data.get('snapshot', ''))
    if not _SNAP.match(snap):
        return error('Invalid snapshot.', status=400)
    return _call('rollback', domain=_domain(data), snap_id=snap)


@admin_api
def clone(request, data):
    source, target = _domain(data, 'source'), _domain(data, 'target')
    if source == target:
        return error('Choose a different target site.', status=400)
    return _call('clone', source=source, target=target)


@admin_api
def push(request, data):
    staging, production = _domain(data, 'staging'), _domain(data, 'production')
    if staging == production:
        return error('Staging and production must differ.', status=400)
    return _call('push', staging=staging, production=production)


@admin_api
def install(request, data):
    return _call('install', domain=_domain(data), title=str(data.get('title', ''))[:120],
                 admin_user=str(data.get('adminUser', '')), admin_email=str(data.get('adminEmail', '')),
                 locale=str(data.get('locale', 'en_US')))


@admin_api
def wpcli(request, data):
    return _call('wpcli_update')


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)

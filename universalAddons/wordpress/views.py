import re

from universalAddons import privileged
from universalAddons.access import (admin_api, error, ok, owned_sites, remember_job, require_job, site_api,
                                    site_page)

_DOMAIN = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
_SLUG = re.compile(r'^[a-z0-9][a-z0-9._-]{0,99}$')
_SNAP = re.compile(r'^\d{8}-\d{6}-[0-9a-f]{4}$')
FLAGS = ('WP_DEBUG', 'DISALLOW_FILE_EDIT', 'DISABLE_WP_CRON', 'indexing', 'maintenance')
FIXES = ('DISALLOW_FILE_EDIT', 'WP_DEBUG', 'xmlrpc', 'config_perms', 'salts')


FEATURE = 'wordpress_for_users'


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('wordpress', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _start(request, context, action, /, **args):
    """Start a background job and let this session (only) poll it."""
    try:
        result = privileged.call('wordpress', action, **args)
    except RuntimeError as exc:
        return error(str(exc))
    remember_job(request, 'wordpress', result)
    return ok(result=result)


def _domain(data, key='domain', context=None):
    """The validated domain named by `key`; with a context, only a site the caller manages."""
    value = str(data.get(key, '')).strip().lower()
    if not _DOMAIN.match(value):
        raise ValueError('Invalid %s.' % key)
    return context.require_site(value) if context is not None else value


def page(request):
    """Administrators: every site. Site owners (when allowed): their own sites only."""
    return site_page(request, 'universalAddons/wordpress.html', FEATURE)


# --- administrators, and site owners on their own sites (when the policy allows it)

@site_api(FEATURE)
def sites(request, data, context):
    return _call('list', domains=owned_sites(context))


@site_api(FEATURE)
def info(request, data, context):
    return _call('info', domain=_domain(data, context=context))


@site_api(FEATURE)
def item(request, data, context):
    kind, action, slug = data.get('kind'), data.get('action'), str(data.get('slug', ''))
    if kind not in ('plugin', 'theme') or action not in ('activate', 'deactivate', 'update', 'delete', 'install') \
            or not _SLUG.match(slug):
        return error('Invalid plugin/theme action.', status=400)
    return _call('item', domain=_domain(data, context=context), kind=kind, action=action, slug=slug)


@site_api(FEATURE)
def flag(request, data, context):
    if data.get('flag') not in FLAGS or data.get('enable') not in (True, False):
        return error('Invalid setting.', status=400)
    return _call('flag', domain=_domain(data, context=context), flag=data['flag'], enable=data['enable'])


@site_api(FEATURE)
def autoupdates(request, data, context):
    if data.get('kind') not in ('plugin', 'theme') or data.get('enable') not in (True, False):
        return error('Invalid setting.', status=400)
    return _call('autoupdates', domain=_domain(data, context=context), kind=data['kind'], enable=data['enable'])


@site_api(FEATURE)
def hardening(request, data, context):
    return _call('hardening', domain=_domain(data, context=context))


@site_api(FEATURE)
def fix(request, data, context):
    if data.get('fix') not in FIXES:
        return error('Unknown fix.', status=400)
    return _call('fix', domain=_domain(data, context=context), fix=data['fix'])


@site_api(FEATURE)
def performance(request, data, context):
    what = data.get('what')
    if what not in ('lscache', 'objectcache'):
        return error('Unknown option.', status=400)
    return _call(what, domain=_domain(data, context=context))


@site_api(FEATURE)
def login(request, data, context):
    return _call('login', domain=_domain(data, context=context))


@site_api(FEATURE)
def snapshots(request, data, context):
    return _call('snapshots', domain=_domain(data, context=context))


@site_api(FEATURE)
def update(request, data, context):
    if data.get('scope') not in ('core', 'plugins', 'themes', 'all'):
        return error('Invalid update scope.', status=400)
    return _start(request, context, 'update', domain=_domain(data, context=context), scope=data['scope'])


@site_api(FEATURE)
def snapshot(request, data, context):
    return _start(request, context, 'snapshot', domain=_domain(data, context=context))


@site_api(FEATURE)
def rollback(request, data, context):
    snap = str(data.get('snapshot', ''))
    if not _SNAP.match(snap):
        return error('Invalid snapshot.', status=400)
    return _start(request, context, 'rollback', domain=_domain(data, context=context), snap_id=snap)


@site_api(FEATURE)
def clone(request, data, context):
    source, target = _domain(data, 'source', context), _domain(data, 'target', context)
    if source == target:
        return error('Choose a different target site.', status=400)
    # Site owners stay within their package's database allowance; administrators do not.
    return _start(request, context, 'clone', source=source, target=target, quota=not context.is_admin)


@site_api(FEATURE)
def push(request, data, context):
    staging, production = _domain(data, 'staging', context), _domain(data, 'production', context)
    if staging == production:
        return error('Staging and production must differ.', status=400)
    return _start(request, context, 'push', staging=staging, production=production)


@site_api(FEATURE)
def install(request, data, context):
    return _start(request, context, 'install', domain=_domain(data, context=context),
                  title=str(data.get('title', ''))[:120], admin_user=str(data.get('adminUser', '')),
                  admin_email=str(data.get('adminEmail', '')), locale=str(data.get('locale', 'en_US')),
                  quota=not context.is_admin)


@site_api(FEATURE)
def job(request, data, context):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=require_job(request, context, 'wordpress', job_id))


# --- administrators only: server-wide

@admin_api
def wpcli(request, data):
    return _call('wpcli_update')

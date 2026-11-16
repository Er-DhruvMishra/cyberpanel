"""Site Tools pages and endpoints: administrators, resellers (their sites) and site owners (their own
sites) when the administrator opens the add-on to users. Every endpoint checks ownership of each
domain it names through the panel ACL (SiteContext.require_site); the root side re-resolves the site
from the panel database and re-validates every path, rule and name."""
import re

from universalAddons import privileged
from universalAddons.access import error, ok, owned_sites, remember_job, require_job, site_api, site_page
from universalAddons.siteinfo import DOMAIN_RE

FEATURE = 'sitetools_for_users'
USER_MIN_INTERVAL = 20   # seconds between two OpenLiteSpeed restarts caused by one site owner on one site


def _call(action, /, private=False, **args):
    try:
        result = (privileged.call_private if private else privileged.call)('sitetools', action, **args)
    except RuntimeError as exc:
        return error(str(exc))
    return ok(result=result)


def _start(request, action, /, **args):
    try:
        result = privileged.call('sitetools', action, **args)
    except RuntimeError as exc:
        return error(str(exc))
    remember_job(request, 'sitetools', result)
    return ok(result=result)


def _domain(data, context, key='domain'):
    value = str(data.get(key, '')).strip().lower()
    if not DOMAIN_RE.match(value):
        raise ValueError('Invalid %s.' % key)
    return context.require_site(value)


def _interval(context):
    return 0 if context.is_admin else USER_MIN_INTERVAL


def _text(data, key, limit=200):
    value = data.get(key, '')
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError('Invalid %s.' % key)
    return value


def _names(data, key, limit=50):
    values = data.get(key) or []
    if not isinstance(values, list) or len(values) > limit or not all(isinstance(v, str) and len(v) <= 200
                                                                      for v in values):
        raise ValueError('Invalid %s.' % key)
    return values


def page(request):
    def values(is_admin):
        wanted = str(request.GET.get('site', '')).strip().lower()
        return {'site': wanted if DOMAIN_RE.match(wanted) else ''}
    return site_page(request, 'universalAddons/sitetools.html', FEATURE, values)


@site_api(FEATURE)
def sites(request, data, context):
    return _call('list', domains=owned_sites(context))


@site_api(FEATURE)
def overview(request, data, context):
    return _call('overview', domain=_domain(data, context), domains=owned_sites(context))


@site_api(FEATURE)
def redirects(request, data, context):
    rules = data.get('rules')
    if not isinstance(rules, list):
        return error('Send the list of redirects.', status=400)
    return _call('redirects', domain=_domain(data, context), rules=rules, min_interval=_interval(context))


@site_api(FEATURE)
def hotlink(request, data, context):
    config = data.get('config')
    if not isinstance(config, dict):
        return error('Send the hotlink settings.', status=400)
    return _call('hotlink', domain=_domain(data, context), config=config, min_interval=_interval(context))


def _code(data):
    code = str(data.get('code', ''))
    if code not in ('403', '404', '500', '502', '503'):
        raise ValueError('Invalid error code.')
    return code


@site_api(FEATURE)
def errorpage_get(request, data, context):
    return _call('errorpage_get', domain=_domain(data, context), code=_code(data))


@site_api(FEATURE)
def errorpage_save(request, data, context):
    return _call('errorpage_save', domain=_domain(data, context), code=_code(data),
                 html=_text(data, 'html', 256 * 1024), min_interval=_interval(context))


@site_api(FEATURE)
def errorpage_remove(request, data, context):
    return _call('errorpage_remove', domain=_domain(data, context), code=_code(data),
                 delete_file=data.get('delete') is True, min_interval=_interval(context))


def _scheme(data):
    scheme = data.get('scheme', 'bcrypt')
    if scheme not in ('bcrypt', 'apr1'):
        raise ValueError('Choose bcrypt or apr1.')
    return scheme


@site_api(FEATURE)
def protect(request, data, context):
    # The password travels in a private spool file, never on a command line.
    return _call('protect', private=True, domain=_domain(data, context), path=_text(data, 'path', 400),
                 name=_text(data, 'name', 60), username=_text(data, 'username', 64),
                 password=_text(data, 'password', 128), scheme=_scheme(data), min_interval=_interval(context))


@site_api(FEATURE)
def unprotect(request, data, context):
    return _call('unprotect', domain=_domain(data, context), path=_text(data, 'path', 400),
                 min_interval=_interval(context))


@site_api(FEATURE)
def user_set(request, data, context):
    return _call('user_set', private=True, domain=_domain(data, context), path=_text(data, 'path', 400),
                 username=_text(data, 'username', 64), password=_text(data, 'password', 128), scheme=_scheme(data))


@site_api(FEATURE)
def user_remove(request, data, context):
    return _call('user_remove', domain=_domain(data, context), path=_text(data, 'path', 400),
                 username=_text(data, 'username', 64))


@site_api(FEATURE)
def clone(request, data, context):
    source = _domain(data, context, 'source')
    mode = data.get('mode', 'subdomain')
    if mode not in ('subdomain', 'site'):
        return error('Copy into a staging subdomain or into another site.', status=400)
    target = _domain(data, context, 'target') if mode == 'site' else None
    # Site owners and resellers stay within their package's database allowance; administrators do not.
    return _start(request, 'clone', source=source, mode=mode, label=_text(data, 'label', 42) or 'staging',
                  target=target, databases=_names(data, 'databases'), exclude_cache=data.get('exclude_cache') is not False,
                  excludes=_names(data, 'excludes'), domains=owned_sites(context), quota=not context.is_admin)


@site_api(FEATURE)
def push(request, data, context):
    flag = lambda key, default=True: data.get(key, default) is True
    return _start(request, 'push', staging=_domain(data, context, 'staging'), push_files=flag('push_files'),
                  push_db=flag('push_db'), backup_files=flag('backup_files'), backup_db=flag('backup_db'),
                  exclude_cache=flag('exclude_cache'), exclude_uploads=flag('exclude_uploads', False),
                  excludes=_names(data, 'excludes'), domains=owned_sites(context))


@site_api(FEATURE)
def restore(request, data, context):
    backup = str(data.get('backup', ''))
    if not re.match(r'^\d{8}-\d{6}-[0-9a-f]{4}$', backup):
        return error('Invalid backup.', status=400)
    return _start(request, 'restore', domain=_domain(data, context), backup_id=backup)


@site_api(FEATURE)
def job(request, data, context):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=require_job(request, context, 'sitetools', job_id))

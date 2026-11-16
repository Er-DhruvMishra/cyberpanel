"""App catalogue pages and endpoints: administrators, resellers (their sites) and site owners (their own
sites) when the administrator opens the add-on to users. Every endpoint checks ownership of the site it
names (SiteContext.require_site); the root side re-resolves the site and re-validates the request."""
import re

from universalAddons import access, privileged
from universalAddons.access import error, ok, owned_sites, remember_job, require_job, site_api, site_page
from universalAddons.appcatalog import service as svc
from universalAddons.siteinfo import DOMAIN_RE

FEATURE = 'appcatalog_for_users'


def _call(action, **args):
    try:
        return ok(result=privileged.call('appcatalog', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _domain(data, context):
    value = str(data.get('domain', '')).strip().lower()
    if not DOMAIN_RE.match(value):
        raise ValueError('Invalid domain.')
    return context.require_site(value)


def page(request):
    def values(is_admin):
        wanted = str(request.GET.get('site', '')).strip().lower()
        return {'site': wanted if DOMAIN_RE.match(wanted) else ''}
    return site_page(request, 'universalAddons/appcatalog.html', FEATURE, values)


@site_api(FEATURE)
def sites(request, data, context):
    owned = owned_sites(context)
    if owned is None:
        from websiteFunctions.models import ChildDomains, Websites
        owned = sorted(set(Websites.objects.values_list('domain', flat=True)) |
                       set(ChildDomains.objects.values_list('domain', flat=True)))
    return ok(result={'sites': owned})


@site_api(FEATURE)
def catalogue(request, data, context):
    return _call('catalogue', domain=_domain(data, context))


@site_api(FEATURE)
def check(request, data, context):
    return _call('check_target', domain=_domain(data, context), app=str(data.get('app', '')),
                 path=str(data.get('path', '')))


@site_api(FEATURE)
def install(request, data, context):
    domain = _domain(data, context)
    clean = svc.clean_request(data, domain)
    if clean['app'] == 'ghost' and not context.is_admin and not access.load_policy().get('apps_for_users'):
        raise PermissionError('Ghost runs as a Universal App, which the administrator has not enabled for users.')
    try:
        result = privileged.call('appcatalog', 'install', domain=domain, request=clean)
    except RuntimeError as exc:
        return error(str(exc))
    remember_job(request, 'appcatalog', result)
    return ok(result=result)


@site_api(FEATURE)
def job(request, data, context):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=require_job(request, context, 'appcatalog', job_id))

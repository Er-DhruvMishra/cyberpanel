""".htaccess translator endpoints.

Administrators: every site, and the brute-force block list. Site owners (when the policy allows
it): preview, enable and disable the translation of their own sites only. Each apply restarts
OpenLiteSpeed, so owners are rate-limited per site, and the brute-force guard never blocks IPs in
the firewall for a site an owner enabled (it only logs) until an administrator enables it.
"""
import re

from universalAddons import privileged
from universalAddons.access import error, ok, owned_sites, site_api, site_page

FEATURE = 'htaccess_for_users'
USER_MIN_INTERVAL = 120  # seconds between two applies of one site by its owner
_DOMAIN = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
MARK_BEGIN, MARK_END = '# BEGIN cp-ua-htaccess', '# END cp-ua-htaccess'


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('htaccess', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _domain(data, context):
    value = str(data.get('domain', '')).strip().lower()
    if not _DOMAIN.match(value):
        raise ValueError('Invalid domain.')
    return context.require_site(value)


def _managed_part(text):
    """Only the block this module generates (site owners do not see the rest of vhost.conf)."""
    text = text or ''
    start, end = text.find(MARK_BEGIN), text.find(MARK_END)
    return text[start:end + len(MARK_END)] if start >= 0 and end > start else ''


def page(request):
    return site_page(request, 'universalAddons/htaccess.html', FEATURE)


@site_api(FEATURE)
def overview(request, data, context):
    return _call('overview', domains=owned_sites(context))


@site_api(FEATURE)
def preview(request, data, context):
    domain = _domain(data, context)
    try:
        result = privileged.call('htaccess', 'preview', domain=domain)
    except RuntimeError as exc:
        return error(str(exc))
    if not context.is_admin:
        result['vhost_after'] = _managed_part(result.get('vhost_after'))
        result.pop('vhost_path', None)
    return ok(result=result)


@site_api(FEATURE)
def enable(request, data, context):
    if context.is_admin:
        return _call('enable', domain=_domain(data, context))
    return _call('enable', domain=_domain(data, context), by_user=True, min_interval=USER_MIN_INTERVAL)


@site_api(FEATURE)
def disable(request, data, context):
    if context.is_admin:
        return _call('disable', domain=_domain(data, context))
    return _call('disable', domain=_domain(data, context), min_interval=USER_MIN_INTERVAL)

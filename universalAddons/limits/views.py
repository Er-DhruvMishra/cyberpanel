"""Resource Limits endpoints. Site owners (when the policy allows it) may only read the limits and
current usage of their own sites; every change stays with administrators."""
import re

from universalAddons import privileged
from universalAddons.access import admin_api, error, ok, owned_sites, site_api, site_page
from universalAddons.limits.service import DOMAIN_RE, OVERRIDES, PACKAGE_RE, validate_limits

SCOPES = ('package', 'site')
FEATURE = 'limits_for_users'


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('limits', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _target(data):
    """Validated (scope, name). Request keys avoid names secMiddleware treats specially."""
    scope = data.get('scope')
    name = data.get('name')
    if scope not in SCOPES or not isinstance(name, str):
        raise ValueError('Choose a package or a site.')
    name = name.strip()
    if scope == 'site':
        name = name.lower()
        if not DOMAIN_RE.match(name):
            raise ValueError('Invalid site.')
    elif not PACKAGE_RE.match(name) or name == OVERRIDES:
        raise ValueError('Invalid package name.')
    return scope, name


def page(request):
    return site_page(request, 'universalAddons/limits.html', FEATURE)


@site_api(FEATURE)
def overview(request, data, context):
    if context.is_admin:
        return _call('overview')
    return _call('site_usage', domains=owned_sites(context))


@admin_api
def save(request, data):
    scope, name = _target(data)
    limits = validate_limits(data.get('limits') if data.get('limits') is not None else {})
    return _call('save', scope=scope, name=name, limits=limits)


@admin_api
def preview(request, data):
    scope, name = _target(data)
    return _call('preview', scope=scope, name=name)


@admin_api
def apply(request, data):
    scope, name = _target(data)
    token = str(data.get('token', ''))
    if not re.match(r'^[0-9a-f]{32}$', token):
        return error('Preview the change first.', status=400)
    return _call('apply', scope=scope, name=name, token=token)


@admin_api
def du_scan(request, data):
    return _call('du_scan')


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)

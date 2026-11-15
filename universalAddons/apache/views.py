import re


from universalAddons import privileged
from universalAddons.access import admin_api, admin_page, error, ok
from universalAddons.apache import service as sv

MODES = ('apache', 'ols', 'tune')


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('apache', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _site_mode(data):
    """Validated (site, mode). Request keys avoid names CyberPanel's secMiddleware treats specially."""
    mode = data.get('mode')
    if mode not in MODES:
        raise ValueError('Choose Apache, OpenLiteSpeed or pool tuning.')
    return sv.validate_domain(data.get('site')), mode


def _pool(data, mode):
    if mode == 'ols':
        return None
    return sv.validate_pool(data.get('pool'), sv.meminfo()['total_mb'])


def page(request):
    return admin_page(request, 'universalAddons/apache.html')


@admin_api
def overview(request, data):
    return _call('overview')


@admin_api
def preview(request, data):
    site, mode = _site_mode(data)
    return _call('preview', site=site, mode=mode, pool=_pool(data, mode))


@admin_api
def apply(request, data):
    site, mode = _site_mode(data)
    pool = _pool(data, mode)
    token = str(data.get('token', ''))
    if not re.match(r'^[0-9a-f]{32}$', token):
        return error('Preview the change first.', status=400)
    return _call('apply', site=site, mode=mode, token=token, pool=pool)


@admin_api
def install(request, data):
    versions = sv.validate_versions(data.get('versions'))
    confirm = data.get('confirm', False)
    if not isinstance(confirm, bool):
        raise ValueError('confirm must be true or false.')
    return _call('install', versions=versions, confirm=confirm)


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)

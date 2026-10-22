import re

from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, ok

_ID = re.compile(r'^[a-z0-9][a-z0-9-]{0,31}$')
_DOMAIN = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
_SNAP = re.compile(r'^[0-9a-f]{8,64}$')
REPO_FIELDS = ('id', 'type', 'name', 'path', 'host', 'user', 'port', 'endpoint', 'bucket', 'prefix', 'region', 'remote')


def _call(action, **args):
    try:
        return ok(result=privileged.call('backupv2', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _id(data, key):
    value = str(data.get(key, '')).strip().lower()
    if not _ID.match(value):
        raise ValueError('Invalid %s.' % key)
    return value


def page(request):
    return httpProc(request, 'universalAddons/backupv2.html', {}, 'admin').render()


@admin_api
def overview(request, data):
    return _call('overview')


@admin_api
def save_repo(request, data):
    spec = {key: data[key] for key in REPO_FIELDS if key in data}
    return _call('save_repo', spec=spec, access_key=str(data.get('accessKey', '')),
                 secret_key=str(data.get('secretKey', '')))


@admin_api
def export_key(request, data):
    return _call('export_key', repo_id=_id(data, 'repo'))


@admin_api
def ssh_key(request, data):
    return _call('ssh_key')


@admin_api
def save_policy(request, data):
    sites = data.get('sites', 'all')
    spec = {'id': data.get('id'), 'repo': data.get('repo'), 'sites': sites, 'units': data.get('units'),
            'schedule': data.get('schedule'), 'hour': data.get('hour', 2), 'check': data.get('check') is not False,
            'notify': data.get('notify') is not False,
            'keep': {k: data.get('keep_' + k) for k in ('last', 'hourly', 'daily', 'weekly', 'monthly')
                     if data.get('keep_' + k) not in (None, '', 0)}}
    return _call('save_policy', spec=spec)


@admin_api
def delete_policy(request, data):
    return _call('delete_policy', policy_id=_id(data, 'policy'))


@admin_api
def run_now(request, data):
    return _call('run_now', policy_id=_id(data, 'policy'))


@admin_api
def snapshots(request, data):
    domain = str(data.get('domain', '')).strip().lower()
    if domain and not _DOMAIN.match(domain):
        return error('Invalid domain.', status=400)
    return _call('snapshots', repo_id=_id(data, 'repo'), domain=domain)


@admin_api
def ls(request, data):
    snapshot = str(data.get('snapshot', ''))
    path = str(data.get('path', '/')) or '/'
    if not _SNAP.match(snapshot) or not path.startswith('/'):
        return error('Invalid snapshot or path.', status=400)
    return _call('ls', repo_id=_id(data, 'repo'), snapshot=snapshot, path=path)


@admin_api
def restore(request, data):
    kind = data.get('kind')
    snapshot = str(data.get('snapshot', ''))
    domain = str(data.get('domain', '')).strip().lower()
    if kind not in ('files', 'db') or not _SNAP.match(snapshot) or not _DOMAIN.match(domain):
        return error('Invalid restore request.', status=400)
    target = str(data.get('target', 'original')) or 'original'
    if target != 'original' and not target.startswith('/'):
        return error('Restore target must be "original" or an absolute directory.', status=400)
    return _call('restore', repo_id=_id(data, 'repo'), snapshot=snapshot, domain=domain, kind=kind, target=target,
                 include=str(data.get('include', '')), database=str(data.get('database', '')))


@admin_api
def check(request, data):
    return _call('check', repo_id=_id(data, 'repo'))


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)

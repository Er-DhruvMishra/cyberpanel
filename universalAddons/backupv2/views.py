"""Backup V2 endpoints.

Administrators manage repositories and schedules and may restore anything. When the policy allows
it, site owners may back up their own sites now and restore their own files and databases in
place, using only the repositories the administrator marked "available to users". Each of those
requests names the site; the caller must own it, and the root side re-checks that the repository
is open to users and that the snapshot is the site's own.
"""
import re

from universalAddons import privileged
from universalAddons.access import (admin_api, error, ok, owned_sites, remember_job, require_job, site_api,
                                    site_page)

FEATURE = 'backup_for_users'
_ID = re.compile(r'^[a-z0-9][a-z0-9-]{0,31}$')
_DOMAIN = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
_SNAP = re.compile(r'^[0-9a-f]{8,64}$')
_DBNAME = re.compile(r'^[A-Za-z0-9_]{1,64}$')
REPO_FIELDS = ('id', 'type', 'name', 'path', 'host', 'user', 'port', 'endpoint', 'bucket', 'prefix', 'region', 'remote',
               'for_users')


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('backupv2', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _start(request, action, /, **args):
    """Start a background job and let this session (only) poll it."""
    try:
        result = privileged.call('backupv2', action, **args)
    except RuntimeError as exc:
        return error(str(exc))
    remember_job(request, 'backupv2', result)
    return ok(result=result)


def _id(data, key):
    value = str(data.get(key, '')).strip().lower()
    if not _ID.match(value):
        raise ValueError('Invalid %s.' % key)
    return value


def _own_domain(data, context):
    """The site named in the request; site owners must name one of their own."""
    domain = str(data.get('domain', '')).strip().lower()
    if not _DOMAIN.match(domain):
        raise ValueError('Choose a site.')
    return context.require_site(domain)


def page(request):
    return site_page(request, 'universalAddons/backupv2.html', FEATURE)


# --- administrators, and site owners on their own sites (when the policy allows it)

@site_api(FEATURE)
def overview(request, data, context):
    if context.is_admin:
        return _call('overview')
    return _call('user_overview', domains=owned_sites(context))


@site_api(FEATURE)
def backup_now(request, data, context):
    """Back up one site (files and databases) now, to a repository open to users."""
    return _start(request, 'user_backup', repo_id=_id(data, 'repo'), domain=_own_domain(data, context))


@site_api(FEATURE)
def snapshots(request, data, context):
    if context.is_admin:
        domain = str(data.get('domain', '')).strip().lower()
        if domain and not _DOMAIN.match(domain):
            return error('Invalid domain.', status=400)
        return _call('snapshots', repo_id=_id(data, 'repo'), domain=domain)
    return _call('user_snapshots', repo_id=_id(data, 'repo'), domain=_own_domain(data, context))


@site_api(FEATURE)
def ls(request, data, context):
    snapshot = str(data.get('snapshot', ''))
    path = str(data.get('path', '/')) or '/'
    if not _SNAP.match(snapshot) or not path.startswith('/'):
        return error('Invalid snapshot or path.', status=400)
    if context.is_admin:
        return _call('ls', repo_id=_id(data, 'repo'), snapshot=snapshot, path=path)
    return _call('user_ls', repo_id=_id(data, 'repo'), domain=_own_domain(data, context), snapshot=snapshot,
                 path=path)


@site_api(FEATURE)
def restore(request, data, context):
    kind = data.get('kind')
    snapshot = str(data.get('snapshot', ''))
    domain = str(data.get('domain', '')).strip().lower()
    if kind not in ('files', 'db') or not _SNAP.match(snapshot) or not _DOMAIN.match(domain):
        return error('Invalid restore request.', status=400)
    target = str(data.get('target', 'original')) or 'original'
    if target != 'original' and not target.startswith('/'):
        return error('Restore target must be "original" or an absolute directory.', status=400)
    include, database = str(data.get('include', '')), str(data.get('database', ''))
    if context.is_admin:
        return _start(request, 'restore', repo_id=_id(data, 'repo'), snapshot=snapshot, domain=domain, kind=kind,
                      target=target, include=include, database=database)
    context.require_site(domain)
    if target != 'original':
        raise PermissionError('Only administrators can restore to another directory.')
    if kind == 'db' and not _DBNAME.match(database):
        return error('Choose a database.', status=400)
    if kind == 'files' and include.rstrip('/') == '/home/%s' % domain:
        include = ''  # the whole site
    if kind == 'files' and include and not include.startswith('/home/%s/' % domain):
        raise PermissionError('You can only restore paths inside /home/%s.' % domain)
    return _start(request, 'user_restore', repo_id=_id(data, 'repo'), snapshot=snapshot, domain=domain, kind=kind,
                  include=include, database=database if kind == 'db' else '')


@site_api(FEATURE)
def job(request, data, context):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=require_job(request, context, 'backupv2', job_id))


# --- administrators only: repositories, keys, schedules, verification

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
def check(request, data):
    return _call('check', repo_id=_id(data, 'repo'))

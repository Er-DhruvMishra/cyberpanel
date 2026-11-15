"""Roundcube manager pages and JSON endpoints. Administrator-only throughout."""
import re
import socket

from plogical.acl import ACLManager
from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, ok
from universalAddons.roundcube.service import DB_NAME, DOMAIN_RE, URL_PREFIX, VERSION


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('roundcube', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def default_site(sites, hostname=None):
    """The site matching the server hostname, if there is one."""
    hostname = (hostname or socket.gethostname() or '').lower()
    return hostname if hostname in sites else ''


def page(request):
    try:
        user_id = request.session['userID']
        acl = ACLManager.loadedACL(user_id)
        is_admin = acl.get('admin') == 1
        sites = sorted(ACLManager.findAllSites(acl, user_id, 1)) if is_admin else []
    except Exception:
        is_admin, sites = False, []
    # 'admin' makes httpProc refuse the page to anyone who is not an administrator.
    return httpProc(request, 'universalAddons/roundcube.html',
                    {'is_admin': is_admin, 'sites': sites, 'default_site': default_site(sites),
                     'version': VERSION, 'prefix': URL_PREFIX, 'db_name': DB_NAME}, 'admin').render()


def _site(data):
    # 'site', not 'domains': secMiddleware skips validation for the latter.
    site = str(data.get('site', '')).strip().lower()
    if not DOMAIN_RE.match(site):
        raise ValueError('Choose a site.')
    return site


@admin_api
def overview(request, data):
    return _call('overview')


@admin_api
def preflight(request, data):
    return _call('preflight', site=_site(data))


@admin_api
def install(request, data):
    return _call('install', site=_site(data))


@admin_api
def enable(request, data):
    return _call('enable', site=_site(data))


@admin_api
def disable(request, data):
    return _call('disable')


@admin_api
def uninstall(request, data):
    drop = data.get('dropDatabase') is True
    confirm = data.get('confirmName', '')
    if not isinstance(confirm, str) or len(confirm) > 64:
        return error('Invalid confirmation.', status=400)
    if drop and confirm != DB_NAME:
        return error('Type %s to confirm dropping the database.' % DB_NAME, status=400)
    return _call('uninstall', drop_database=drop, confirm_name=confirm if drop else '')


@admin_api
def upgrade(request, data):
    return _call('check_upgrade')


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)

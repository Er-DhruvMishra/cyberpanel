"""PostgreSQL databases for site owners (/addons/postgresql/). See service.py for the rules."""
import os
import re

from django.http import FileResponse, HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST

from plogical.acl import ACLManager

from universalAddons import privileged
from universalAddons.access import (SiteContext, admin_api, error, forbidden, is_admin, load_policy, ok,
                                    remember_job, require_job, site_api)
from universalAddons.pgsql import service as pg

FEATURE = 'pgsql_for_users'
_JOB = re.compile(r'^[0-9a-f]{24}$')


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('pgsql', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _job(request, action, /, **args):
    try:
        result = privileged.call('pgsql', action, **args)
    except RuntimeError as exc:
        return error(str(exc))
    remember_job(request, 'pgsql', result)
    return ok(result=result)


def _sites(context):
    """Websites (not child domains) the caller manages: databases belong to websites, as in MySQL."""
    return sorted({d.lower() for d in ACLManager.findAllSites(context.acl, context.user_id)})


def _domain(data, context):
    domain = str(data.get('domain', '')).strip().lower()
    if domain not in _sites(context):
        raise PermissionError('You do not manage %s.' % domain)
    return context.require_site(domain)


def _name(data, key='name'):
    return pg.check_name(str(data.get(key, '')).strip())


def page(request):
    admin = is_admin(request)
    installed = pg.installed_major() is not None
    if admin is False:
        if load_policy().get(FEATURE) is not True:
            return forbidden(request, 'The administrator has not enabled this add-on for your account.')
        if not installed:
            return forbidden(request, 'PostgreSQL is not available on this server.')
    sites = []
    try:
        user_id = request.session['userID']
        sites = sorted(ACLManager.findAllSites(ACLManager.loadedACL(user_id), user_id))
    except Exception:
        pass
    from plogical.httpProc import httpProc
    return httpProc(request, 'universalAddons/pgsql.html', {
        'is_admin': admin is True, 'installed': installed, 'sites': sites, 'for_users': load_policy().get(FEATURE) is True,
        'adminer': pg.adminer_installed(), 'adminer_version': pg.ADMINER_VERSION}).render()


@site_api(FEATURE)
def overview(request, data, context):
    return _call('overview', domains=None if context.is_admin else _sites(context))


@site_api(FEATURE)
def create_db(request, data, context):
    domain = _domain(data, context)
    pg.full_name(domain, data.get('name'))  # early, friendly validation
    return _call('create_db', domain=domain, name=str(data.get('name')).strip().lower())


@site_api(FEATURE)
def drop_db(request, data, context):
    return _call('drop_db', domain=_domain(data, context), name=_name(data), drop_owner=data.get('dropOwner') is not False)


@site_api(FEATURE)
def create_role(request, data, context):
    domain = _domain(data, context)
    pg.full_name(domain, data.get('name'))
    return _call('create_role', domain=domain, name=str(data.get('name')).strip().lower())


@site_api(FEATURE)
def drop_role(request, data, context):
    return _call('drop_role', domain=_domain(data, context), name=_name(data))


@site_api(FEATURE)
def reset_password(request, data, context):
    return _call('reset_password', domain=_domain(data, context), role=_name(data, 'role'))


@site_api(FEATURE)
def grant(request, data, context):
    level = data.get('level', 'all')
    if level not in pg.LEVELS:
        return error('Access must be all or read.', status=400)
    return _call('grant', domain=_domain(data, context), db=_name(data, 'db'), role=_name(data, 'role'), level=level)


@site_api(FEATURE)
def revoke(request, data, context):
    return _call('revoke', domain=_domain(data, context), db=_name(data, 'db'), role=_name(data, 'role'))


@site_api(FEATURE)
def backups(request, data, context):
    return _call('backups', domain=_domain(data, context))


@site_api(FEATURE)
def backup(request, data, context):
    return _job(request, 'backup', domain=_domain(data, context), db=_name(data, 'db'))


@site_api(FEATURE)
def delete_backup(request, data, context):
    name = str(data.get('file', ''))
    if not pg.BACKUP_RE.match(name):
        return error('Invalid backup name.', status=400)
    return _call('delete_backup', domain=_domain(data, context), file=name)


@site_api(FEATURE)
def job(request, data, context):
    job_id = str(data.get('job', ''))
    if not _JOB.match(job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=require_job(request, context, 'pgsql', job_id))


@admin_api
def adminer_install(request, data):
    return _job(request, 'adminer_install')


@admin_api
def adminer_remove(request, data):
    return _call('adminer_remove')


# ----------------------------------------------------------------------------- non-JSON endpoints

def _context(request):
    """SiteContext for a GET or multipart request, or an error response."""
    try:
        user_id = request.session['userID']
    except KeyError:
        return None, HttpResponse('Not logged in.', status=401, content_type='text/plain')
    try:
        from loginSystem.models import Administrator
        context = SiteContext(user_id, ACLManager.loadedACL(user_id), Administrator.objects.get(pk=user_id))
    except Exception:
        return None, HttpResponse('Could not load your account.', status=403, content_type='text/plain')
    if not context.is_admin and load_policy().get(FEATURE) is not True:
        return None, HttpResponse('The administrator has not enabled this feature for users.', status=403,
                                  content_type='text/plain')
    return context, None


def download(request):
    context, refusal = _context(request)
    if refusal:
        return refusal
    name = request.GET.get('file', '')
    try:
        domain = _domain({'domain': request.GET.get('domain', '')}, context)
    except PermissionError as exc:
        return HttpResponse(str(exc), status=403, content_type='text/plain')
    if not pg.BACKUP_RE.match(name):
        return HttpResponse('Invalid backup name.', status=400, content_type='text/plain')
    try:
        staged = privileged.call('pgsql', 'stage_download', domain=domain, file=name)
    except RuntimeError as exc:
        return HttpResponse(str(exc), status=400, content_type='text/plain')
    spool = privileged.spool_path(staged['spool_id'])
    handle = open(spool, 'rb')
    os.unlink(spool)  # the open handle keeps the data until the response is sent
    response = FileResponse(handle, as_attachment=True, filename=staged['name'])
    response['Cache-Control'] = 'no-store'
    return response


@require_POST
def restore(request):
    """Multipart upload of a .sql or .dump file, spooled privately, restored by a background job."""
    context, refusal = _context(request)
    if refusal:
        return error(refusal.content.decode(), status=refusal.status_code)
    try:
        domain = _domain({'domain': request.POST.get('domain', '')}, context)
        db = pg.check_name(request.POST.get('db', ''))
    except PermissionError as exc:
        return error(str(exc), status=403)
    except ValueError as exc:
        return error(str(exc), status=400)
    if request.POST.get('confirm') != '1':
        return error('Tick the box to confirm that the restore may overwrite data in %s.' % db, status=400)
    uploaded = request.FILES.get('file')
    if not uploaded or not re.search(r'\.(sql|dump)$', uploaded.name or '', re.I):
        return error('Choose a .sql or .dump file.', status=400)
    if uploaded.size > pg.MAX_UPLOAD_BYTES:
        return error('Uploads are limited to 512 MB; restore larger dumps over SSH.', status=400)
    os.makedirs(privileged.SPOOL_DIR, mode=0o700, exist_ok=True)
    spool_id = privileged.new_spool_id()
    fd = os.open(privileged.spool_path(spool_id), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        for chunk in uploaded.chunks():
            handle.write(chunk)
    try:
        result = privileged.call('pgsql', 'restore', domain=domain, db=db, spool_id=spool_id)
    except RuntimeError as exc:
        try:
            os.unlink(privileged.spool_path(spool_id))
        except OSError:
            pass
        return error(str(exc))
    remember_job(request, 'pgsql', result)
    return ok(result=result)


@require_POST
def adminer_login(request):
    """One click into Adminer: a 30-minute login that acts as the database owner, posted to Adminer
    by an auto-submitting form (the password reaches only the caller's browser, never a URL)."""
    context, refusal = _context(request)
    if refusal:
        return refusal
    try:
        domain = _domain({'domain': request.POST.get('domain', '')}, context)
        db = pg.check_name(request.POST.get('db', ''))
        login = privileged.call('pgsql', 'adminer_login', domain=domain, db=db)
    except PermissionError as exc:
        return HttpResponse(str(exc), status=403, content_type='text/plain')
    except (ValueError, RuntimeError) as exc:
        return HttpResponse(str(exc), status=400, content_type='text/plain')
    response = render(request, 'universalAddons/pgsql_adminer_login.html', {'login': login})
    response['Cache-Control'] = 'no-store'
    response['Referrer-Policy'] = 'no-referrer'
    return response

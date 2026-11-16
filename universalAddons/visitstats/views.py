"""Visitor statistics pages and endpoints. Site owners (when the administrator opens the add-on to
users) see and rebuild the reports of their own sites; installing GoAccess is for administrators.
Reports are served only through `report`, which checks ownership of the site first."""
import os
import re

from django.http import FileResponse, HttpResponse
from django.views.decorators.clickjacking import xframe_options_sameorigin

from universalAddons import access, privileged
from universalAddons.access import (SiteContext, admin_api, error, ok, owned_sites, remember_job, require_job,
                                    site_api, site_page)
from universalAddons.siteinfo import DOMAIN_RE
from universalAddons.visitstats.service import REPORT_HEADERS

FEATURE = 'visitstats_for_users'


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('visitstats', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _domain(value, context):
    value = str(value or '').strip().lower()
    if not DOMAIN_RE.match(value):
        raise ValueError('Invalid site.')
    return context.require_site(value)


def page(request):
    def values(is_admin):
        wanted = str(request.GET.get('site', '')).strip().lower()
        return {'site': wanted if DOMAIN_RE.match(wanted) else ''}
    return site_page(request, 'universalAddons/visitstats.html', FEATURE, values)


@site_api(FEATURE)
def overview(request, data, context):
    return _call('status', domains=owned_sites(context))


@site_api(FEATURE)
def generate(request, data, context):
    domain = _domain(data.get('site'), context)
    try:
        result = privileged.call('visitstats', 'generate', domain=domain, rate_limit=not context.is_admin)
    except RuntimeError as exc:
        return error(str(exc))
    remember_job(request, 'visitstats', result)
    return ok(result=result)


@site_api(FEATURE)
def options(request, data, context):
    domain = _domain(data.get('site'), context)
    anonymize = data.get('anonymize')
    if not isinstance(anonymize, bool):
        return error('Invalid option.', status=400)
    return _call('set_options', domain=domain, anonymize=anonymize)


@site_api(FEATURE)
def job(request, data, context):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=require_job(request, context, 'visitstats', job_id))


@admin_api
def check_available(request, data):
    return _call('check_available')


@admin_api
def install(request, data):
    try:
        result = privileged.call('visitstats', 'install')
    except RuntimeError as exc:
        return error(str(exc))
    remember_job(request, 'visitstats', result)
    return ok(result=result)


def _text(message, status):
    return HttpResponse(message, status=status, content_type='text/plain; charset=utf-8')


def report_refusal(request, domain):
    """None if the caller may read the report of `domain`, else the refusal response."""
    try:
        user_id = request.session['userID']
    except KeyError:
        return _text('Not logged in.', 401)
    try:
        from loginSystem.models import Administrator
        acl = access.ACLManager.loadedACL(user_id)
        context = SiteContext(user_id, acl, Administrator.objects.get(pk=user_id))
    except Exception:
        return _text('Could not load your account.', 403)
    if not context.is_admin and access.load_policy().get(FEATURE) is not True:
        return _text('The administrator has not enabled visitor statistics for your account.', 403)
    if not DOMAIN_RE.match(domain) or not context.owns(domain):
        return _text('You do not manage this site.', 403)
    return None


@xframe_options_sameorigin
def report(request):
    domain = str(request.GET.get('site', '')).strip().lower()
    refusal = report_refusal(request, domain)
    if refusal is not None:
        return refusal
    try:
        staged = privileged.call('visitstats', 'stage_report', domain=domain)
    except RuntimeError as exc:
        return _text(str(exc), 404)
    spool = privileged.spool_path(staged['spool_id'])
    handle = open(spool, 'rb')
    os.unlink(spool)  # the open handle keeps the data until the response is sent
    response = FileResponse(handle, content_type='text/html; charset=utf-8')
    for name, value in REPORT_HEADERS.items():
        response[name] = value
    return response

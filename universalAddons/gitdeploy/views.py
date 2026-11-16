"""Git deploy pages and endpoints, plus the public webhook receiver.

Site endpoints: administrators, resellers and site owners (when opened to them), on the sites
they manage (SiteContext). Repository settings travel in a nested "repo" object and the token in
a nested "secrets" object: the panel's request filter screens top-level strings, and URLs contain
':'. The token goes to the root side in a private spool file and is never sent back.

The webhook (/addons/git-deploy/hook/<id>/) needs no session and is CSRF-exempt; it is
authenticated by the delivery's signature, checked on the root side with constant-time compares.
Unknown ids, missing and wrong signatures all get the same empty 404.
"""
import base64
import re
import threading
import time

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from universalAddons import privileged
from universalAddons.access import error, ok, remember_job, require_job, site_api, site_page
from universalAddons.gitdeploy import service as svc
from universalAddons.siteinfo import DOMAIN_RE, SiteError

FEATURE = 'gitdeploy_for_users'
HOOK_HEADERS = ('X-Hub-Signature-256', 'X-Hub-Signature', 'X-Gitlab-Token', 'X-Gitea-Signature', 'X-Gogs-Signature',
                'X-GitHub-Event', 'X-Gitlab-Event', 'X-Gitea-Event', 'X-Gogs-Event', 'X-Event-Key')
SIGNATURE_HEADERS = HOOK_HEADERS[:5]
WEB_RATE = {'per_hook': (20, 60), 'global': (120, 60)}  # (deliveries, seconds) before the root side is asked
_seen = {}
_seen_lock = threading.Lock()


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('gitdeploy', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _start(request, action, /, **args):
    try:
        result = privileged.call('gitdeploy', action, **args)
    except RuntimeError as exc:
        return error(str(exc))
    remember_job(request, 'gitdeploy', result)
    return ok(result=result)


def _domain(data, context):
    value = str(data.get('domain', '')).strip().lower()
    if not DOMAIN_RE.match(value):
        raise ValueError('Invalid domain.')
    return context.require_site(value)


def page(request):
    def values(is_admin):
        wanted = str(request.GET.get('site', '')).strip().lower()
        return {'site': wanted if DOMAIN_RE.match(wanted) else ''}
    return site_page(request, 'universalAddons/gitdeploy.html', FEATURE, values)


@site_api(FEATURE)
def sites(request, data, context):
    from universalAddons.access import owned_sites
    from plogical.acl import ACLManager
    listed = owned_sites(context)
    if listed is None:
        listed = sorted({d.lower() for d in ACLManager.findAllSites(context.acl, context.user_id, 1)})
    return ok(result={'sites': listed})


@site_api(FEATURE)
def status(request, data, context):
    domain = _domain(data, context)
    try:
        result = privileged.call('gitdeploy', 'status', domain=domain)
    except RuntimeError as exc:
        return error(str(exc))
    if result.get('hook_path'):
        result['hook_url'] = request.build_absolute_uri(result['hook_path'])
    return ok(result=result)


@site_api(FEATURE)
def save(request, data, context):
    domain = _domain(data, context)
    repo = data.get('repo')
    if not isinstance(repo, dict):
        return error('Send the repository settings in "repo".', status=400)
    try:
        svc.check_repo(repo.get('url'))
        svc.check_branch(repo.get('branch') or 'main')
        token = (data.get('secrets') or {}).get('token') if isinstance(data.get('secrets'), dict) else None
        if token:
            svc.check_token(token)
    except SiteError as exc:
        return error(str(exc), status=400)
    try:
        result = privileged.call_private('gitdeploy', 'save', domain=domain, spec=repo, token=token or None)
    except RuntimeError as exc:
        return error(str(exc))
    if result.get('hook_path'):
        result['hook_url'] = request.build_absolute_uri(result['hook_path'])
    return ok(result=result)


@site_api(FEATURE)
def key(request, data, context):
    return _call('key', domain=_domain(data, context), replace=data.get('replace') is True)


@site_api(FEATURE)
def secret(request, data, context):
    return _call('secret', domain=_domain(data, context), regenerate=data.get('regenerate') is True)


@site_api(FEATURE)
def disconnect(request, data, context):
    return _call('disconnect', domain=_domain(data, context))


@site_api(FEATURE)
def deploy(request, data, context):
    return _start(request, 'deploy', domain=_domain(data, context))


@site_api(FEATURE)
def rollback(request, data, context):
    return _start(request, 'rollback', domain=_domain(data, context))


@site_api(FEATURE)
def log(request, data, context):
    n = data.get('n')
    if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= 10 ** 9:
        return error('Invalid deploy.', status=400)
    return _call('log', domain=_domain(data, context), n=n)


@site_api(FEATURE)
def job(request, data, context):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=require_job(request, context, 'gitdeploy', job_id))


# ----------------------------------------------------------------------------- webhook

def _nothing():
    return HttpResponse(b'', status=404)


def _web_rate_ok(hook_id, now=None):
    """A cheap in-process limit, so floods never reach the root runner."""
    now = time.time() if now is None else now
    with _seen_lock:
        for key, (limit, window) in (('h:' + hook_id, WEB_RATE['per_hook']), ('global', WEB_RATE['global'])):
            stamps = [t for t in _seen.get(key, []) if now - t < window]
            if len(stamps) >= limit:
                _seen[key] = stamps
                return False
            _seen[key] = stamps
        for key in ('h:' + hook_id, 'global'):
            _seen[key].append(now)
        if len(_seen) > 5000:  # forget idle ids
            for key in [k for k, v in _seen.items() if not v or now - v[-1] > 600]:
                _seen.pop(key, None)
    return True


@csrf_exempt
def hook(request, hook_id):
    if request.method != 'POST' or not svc.HOOK_ID_RE.match(hook_id or ''):
        return _nothing()
    length = request.META.get('CONTENT_LENGTH') or '0'
    if not length.isdigit() or int(length) > svc.MAX_BODY:
        return _nothing()
    if not any(name in request.headers for name in SIGNATURE_HEADERS):
        return _nothing()
    if not _web_rate_ok(hook_id):
        return HttpResponse(b'', status=429)
    try:
        body = request.body
    except Exception:  # larger than Django accepts
        return _nothing()
    if len(body) > svc.MAX_BODY:
        return _nothing()
    headers = {name: request.headers[name][:300] for name in HOOK_HEADERS if name in request.headers}
    try:
        result = privileged.call_private('gitdeploy', 'hook', hook_id=hook_id, headers=headers,
                                         body=base64.b64encode(body).decode('ascii'))
    except RuntimeError:
        return _nothing()
    code = result.get('http') if isinstance(result, dict) else 404
    if code not in (200, 202, 400, 429):
        return _nothing()
    return JsonResponse({k: v for k, v in result.items() if k in ('status', 'reason')}, status=code)

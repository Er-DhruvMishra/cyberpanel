"""Access control and request helpers shared by every add-on module.

Add-on endpoints are administrator-only (admin_api) unless the administrator opens a module to
site owners with a policy switch (site_api): then non-administrators may act on the sites they
own, and only those. JSON endpoints accept POST with a JSON body (CSRF-protected by Django's
middleware); CyberPanel's secMiddleware still screens the body.
"""
import json
from functools import wraps

from django.http import HttpResponse, JsonResponse

from plogical.acl import ACLManager


def is_admin(request):
    try:
        user_id = request.session['userID']
    except KeyError:
        return None
    try:
        return ACLManager.loadedACL(user_id).get('admin') == 1
    except Exception:
        return False


def error(message, status=200, **extra):
    data = {'status': 0, 'error_message': message}
    data.update(extra)
    return JsonResponse(data, status=status)


def ok(**data):
    data['status'] = 1
    return JsonResponse(data)


def admin_api(view):
    """POST-only JSON endpoint for administrators. Passes the parsed body as `data`."""
    @wraps(view)
    def checked(request, *args, **kwargs):
        admin = is_admin(request)
        if admin is None:
            return error('Not logged in. Refresh the page and sign in again.', status=401)
        if not admin:
            return error('Administrator access is required.', status=403)
        if request.method != 'POST':
            return error('POST required.', status=405)
        try:
            data = json.loads(request.body or b'{}')
        except ValueError:
            return error('Invalid JSON body.', status=400)
        if not isinstance(data, dict):
            return error('Invalid JSON body.', status=400)
        try:
            return view(request, data, *args, **kwargs)
        except ValueError as exc:  # validation errors raised by service code
            return error(str(exc), status=400)
    return checked


# ----------------------------------------------------------------------------- site-level access

POLICY_FILE = '/etc/cyberpanel/universal-apps.json'
DEFAULT_POLICY = {
    'apps_for_users': False,       # may non-administrators run apps on sites they own?
    'mssql_for_users': False,      # may non-administrators create SQL Server databases?
    'max_apps_per_site': 3,
    'max_memory_mb': 1024,
    'default_memory_mb': 256,
    'max_cpu_percent': 100,
    'max_mssql_dbs_per_site': 2,
    'email_limits_for_users': False,   # may non-administrators manage mailbox limits of domains they own?
    'terminal_for_users': False,       # may website owners open a terminal for their own sites?
    'terminal_root_for_admins': False,  # may administrators open a root shell?
    'wordpress_for_users': False,      # may website owners manage WordPress on their own sites?
    'backup_for_users': False,         # may website owners back up / restore their own sites?
    'ssl_for_users': False,            # may website owners issue certificates for their own domains?
    'htaccess_for_users': False,       # may website owners turn on .htaccess translation for their sites?
    'email_debug_for_users': False,    # may website owners run DNS checks for their own mail domains?
    'limits_for_users': False,         # may website owners see the limits and usage of their sites?
    'cloudflare_for_users': False,     # may resellers and users manage Cloudflare with their own token?
    'laravel_for_users': False,        # may website owners use the Laravel Toolkit on their own sites?
    'gitdeploy_for_users': False,      # may website owners deploy their own sites from Git (with webhooks)?
    'sitetools_for_users': False,      # may resellers/website owners use Site Tools (staging, redirects...) on their sites?
}

# Add-ons that have something for non-administrators, and the policy switch that opens each one
# to users. Every other add-on is for administrators only and is never shown to users.
USER_FEATURES = (
    ('wordpress', 'wordpress_for_users'),
    ('backupv2', 'backup_for_users'),
    ('sslv2', 'ssl_for_users'),
    ('htaccess', 'htaccess_for_users'),
    ('emaildebug', 'email_debug_for_users'),
    ('limits', 'limits_for_users'),
    ('apps', 'apps_for_users'),
    ('mssql', 'mssql_for_users'),
    ('emaillimits', 'email_limits_for_users'),
    ('webterm', 'terminal_for_users'),
    ('cloudflare', 'cloudflare_for_users'),
    ('laravel', 'laravel_for_users'),
    ('gitdeploy', 'gitdeploy_for_users'),
    ('sitetools', 'sitetools_for_users'),
)

# What a site owner gets from each switch (shown next to its checkbox on the hub).
USER_FEATURE_HELP = {
    'wordpress': 'Manage WordPress on their own sites: updates, plugins, snapshots, staging, hardening, wp-admin login.',
    'backupv2': 'Back up their own sites now and restore their own files and databases, using repositories you mark '
                'as available to users.',
    'sslv2': "Issue Let's Encrypt certificates (wildcard over DNS-01) for domains they own.",
    'htaccess': 'Preview and turn on .htaccess translation for their own sites (brute-force blocking stays '
                'administrator-only).',
    'emaildebug': 'DNS and reputation checks (MX, SPF, DKIM, DMARC, PTR, blocklists) for their own domains.',
    'limits': 'See, read-only, the resource limits and current usage of their own sites.',
    'apps': 'Run Node.js, Python, .NET, Java/Kotlin, Ruby, Go, Deno and Bun apps on their own sites, within the limits you set.',
    'mssql': 'Create SQL Server databases for their own sites.',
    'emaillimits': 'Set mailbox sending limits on their own mail domains.',
    'webterm': "Open a browser terminal as their website's Linux user.",
    'cloudflare': 'Manage their own Cloudflare zones with their own API token (DNS, cache, SSL/TLS, security, '
                  'analytics) and link zones to sites they own.',
    'laravel': 'Laravel Toolkit on their own sites: install Laravel, whitelisted artisan/composer commands, scheduler, '
               'queue worker, .env editing and logs, as the site user.',
    'gitdeploy': 'Deploy their own sites from GitHub, GitLab, Bitbucket or Gitea (deploy key or token, signed '
                 'webhooks, releases with rollback), as the site user.',
    'sitetools': 'Site Tools on their own sites: staging copies of any site with push back, password-protected '
                 'directories, redirects, custom error pages and hotlink protection.',
}


def user_modules(policy=None):
    """Keys of the add-ons the administrator has opened to users."""
    policy = load_policy() if policy is None else policy
    return [key for key, switch in USER_FEATURES if policy.get(switch) is True]


def save_policy_keys(values, path=None):
    """Root side: update the given boolean switches of the policy file, keeping every other key."""
    import os
    allowed = {switch for _, switch in USER_FEATURES} | {'terminal_root_for_admins'}
    path = path or POLICY_FILE
    try:
        with open(path) as handle:
            stored = json.load(handle)
        if not isinstance(stored, dict):
            stored = {}
    except (OSError, ValueError):
        stored = {}
    for key, value in values.items():
        if key not in allowed or not isinstance(value, bool):
            raise ValueError('Unknown or invalid setting %r.' % key)
        stored[key] = value
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + '.tmp', 'w') as handle:
        json.dump(stored, handle, indent=2, sort_keys=True)
    os.chmod(path + '.tmp', 0o644)
    os.replace(path + '.tmp', path)
    return load_policy(path)


def load_policy(path=None):
    import os
    policy = dict(DEFAULT_POLICY)
    try:
        with open(path or POLICY_FILE) as handle:
            stored = json.load(handle)
        for key, default in DEFAULT_POLICY.items():
            if isinstance(stored.get(key), type(default)):
                policy[key] = stored[key]
    except (OSError, ValueError):
        pass
    return policy


class SiteContext:
    """Who is calling, and which sites they may manage."""

    def __init__(self, user_id, acl, admin_obj):
        self.user_id, self.acl, self.admin_obj = user_id, acl, admin_obj
        self.is_admin = acl.get('admin') == 1

    def owns(self, domain):
        if self.is_admin:
            return True
        try:
            return ACLManager.checkOwnership(domain, self.admin_obj, self.acl) == 1
        except Exception:  # unknown domain
            return False

    def require_site(self, domain):
        if not self.owns(domain):
            raise PermissionError('You do not manage %s.' % domain)
        return domain


def owned_sites(context):
    """Websites and child domains the caller manages (lower case), or None for administrators (all)."""
    if context.is_admin:
        return None
    return sorted({d.lower() for d in ACLManager.findAllSites(context.acl, context.user_id, 1)})


# ----------------------------------------------------------------------------- background jobs

JOBS_SESSION_KEY = 'ua_jobs'
MAX_REMEMBERED_JOBS = 50


def remember_job(request, module, result):
    """Note in the caller's session that it started this job, so only it can poll the job."""
    job_id = result.get('job_id') if isinstance(result, dict) else None
    if not job_id:
        return
    known = list(request.session.get(JOBS_SESSION_KEY) or [])
    known.append('%s:%s' % (module, job_id))
    request.session[JOBS_SESSION_KEY] = known[-MAX_REMEMBERED_JOBS:]


def require_job(request, context, module, job_id):
    """Administrators may poll any job; users only the jobs they started in this session."""
    if context.is_admin:
        return job_id
    if '%s:%s' % (module, job_id) not in (request.session.get(JOBS_SESSION_KEY) or []):
        raise PermissionError('Unknown job.')
    return job_id


# ----------------------------------------------------------------------------- pages

def forbidden(request, message='Administrator access is required.'):
    """A 403 page (the panel's error template when it can be rendered)."""
    try:
        from django.shortcuts import render
        return render(request, 'baseTemplate/error.html', {'error_message': message}, status=403)
    except Exception:
        return HttpResponse(message, status=403, content_type='text/plain; charset=utf-8')


def page_refusal(request, feature=None):
    """None when the caller may open the page; otherwise a 403 response.

    Administrators may open every add-on page. Others only the pages of add-ons whose `feature`
    switch is on (feature=None: administrators only). Visitors who are not logged in get None, so
    httpProc sends them to the login page as usual.
    """
    admin = is_admin(request)
    if admin is None or admin:
        return None
    if feature and load_policy().get(feature) is True:
        return None
    if feature:
        return forbidden(request, 'The administrator has not enabled this add-on for your account.')
    return forbidden(request)


def admin_page(request, template, data=None):
    """Render an administrator-only add-on page; anyone else gets 403."""
    refusal = page_refusal(request)
    if refusal is not None:
        return refusal
    from plogical.httpProc import httpProc
    return httpProc(request, template, data() if callable(data) else (data or {}), 'admin').render()


def site_page(request, template, feature, data=None):
    """Render a page opened to site owners by `feature`; `data(is_admin)` adds template values."""
    refusal = page_refusal(request, feature)
    if refusal is not None:
        return refusal
    admin = is_admin(request) is True
    values = {'is_admin': admin, 'for_users': load_policy().get(feature) is True}
    if callable(data):
        values.update(data(admin) or {})
    elif data:
        values.update(data)
    from plogical.httpProc import httpProc
    return httpProc(request, template, values).render()


def site_api(feature):
    """POST JSON endpoint for administrators, and for site owners when `feature` is allowed."""
    def decorate(view):
        @wraps(view)
        def checked(request, *args, **kwargs):
            try:
                user_id = request.session['userID']
            except KeyError:
                return error('Not logged in. Refresh the page and sign in again.', status=401)
            if request.method != 'POST':
                return error('POST required.', status=405)
            try:
                from loginSystem.models import Administrator
                acl = ACLManager.loadedACL(user_id)
                context = SiteContext(user_id, acl, Administrator.objects.get(pk=user_id))
            except Exception:
                return error('Could not load your account.', status=403)
            if not context.is_admin and not load_policy().get(feature):
                return error('The administrator has not enabled this feature for users.', status=403)
            try:
                data = json.loads(request.body or b'{}')
            except ValueError:
                return error('Invalid JSON body.', status=400)
            if not isinstance(data, dict):
                return error('Invalid JSON body.', status=400)
            try:
                return view(request, data, context, *args, **kwargs)
            except PermissionError as exc:
                return error(str(exc), status=403)
            except ValueError as exc:
                return error(str(exc), status=400)
        return checked
    return decorate

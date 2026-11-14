"""Access control and request helpers shared by every add-on module.

Every add-on endpoint is administrator-only. JSON endpoints accept POST with a JSON body
(CSRF-protected by Django's middleware); CyberPanel's secMiddleware still screens the body.
"""
import json
from functools import wraps

from django.http import JsonResponse

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
    'email_limits_for_users': False,
    'terminal_for_users': False,       # may website owners open a terminal for their own sites?
    'terminal_root_for_admins': False, # may administrators open a root shell?  # may non-administrators manage mailbox limits of domains they own?
}


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

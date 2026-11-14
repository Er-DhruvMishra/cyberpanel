from plogical.acl import ACLManager
from plogical.httpProc import httpProc

from . import privileged
from .access import USER_FEATURES, admin_api, error, load_policy, ok, user_modules
from .registry import module_status


def hub(request):
    """Administrators see every add-on and choose which ones users may use; users see only those."""
    try:
        is_admin = ACLManager.loadedACL(request.session['userID']).get('admin') == 1
    except Exception:
        is_admin = False
    policy = load_policy()
    modules = module_status()
    switches = dict(USER_FEATURES)
    if is_admin:
        access = [{'key': m['key'], 'title': m['title'], 'switch': switches[m['key']],
                   'enabled': policy.get(switches[m['key']]) is True}
                  for m in modules if m['key'] in switches]
    else:
        allowed = set(user_modules(policy))
        modules = [m for m in modules if m['key'] in allowed]
        access = []
    return httpProc(request, 'universalAddons/hub.html',
                    {'modules': modules, 'is_admin': is_admin, 'user_access': access}).render()


@admin_api
def user_access(request, data):
    switches = {switch for _, switch in USER_FEATURES}
    values = {key: value for key, value in data.items() if key in switches}
    if not values or any(not isinstance(v, bool) for v in values.values()):
        return error('Send one or more add-on switches as true/false.', status=400)
    return ok(result=privileged.call('hub', 'set_user_access', values=values))

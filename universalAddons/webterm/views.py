"""Web Terminal endpoints. The shell itself runs in cp-webterm.service; the panel only issues tickets."""
from plogical.acl import ACLManager
from plogical.httpProc import httpProc

from universalAddons import privileged
from universalAddons.access import admin_api, error, load_policy, ok, site_api

FEATURE = 'terminal_for_users'


def _sites(user_id):
    try:
        acl = ACLManager.loadedACL(user_id)
        return sorted(ACLManager.findAllSites(acl, user_id, 1))
    except Exception:
        return []


def page(request):
    try:
        user_id = request.session['userID']
        is_admin = ACLManager.loadedACL(user_id).get('admin') == 1
    except Exception:
        user_id, is_admin = None, False
    enabled = is_admin or bool(load_policy().get(FEATURE))
    sites = _sites(user_id) if (user_id and enabled) else []
    chosen = request.GET.get('domain', '')
    # Default carrier site for the websocket route: the site the panel itself is opened on
    # (panel at https://example.com:8090 -> example.com), so the browser already trusts its certificate.
    panel_host = request.get_host().rsplit(':', 1)[0].lower() if request.get_host() else ''
    carrier = panel_host if panel_host in sites else next((s for s in sites if panel_host.endswith('.' + s)), '')
    return httpProc(request, 'universalAddons/webterm.html', {
        'is_admin': is_admin, 'enabled': enabled, 'sites': sites, 'carrier': carrier,
        'chosen': chosen if chosen in sites else (sites[0] if sites else '')}).render()


@site_api(FEATURE)
def ticket(request, data, context):
    from CyberCP.sessionSecurity import get_client_ip
    from loginSystem.models import Administrator
    from websiteFunctions.models import Websites
    domain = str(data.get('domain') or '').strip().lower()
    root = data.get('root') is True
    if root:
        if not context.is_admin:
            return error('Only administrators can open a root shell.', status=403)
        system_user = 'root'
    else:
        context.require_site(domain)
        try:
            system_user = Websites.objects.get(domain=domain).externalApp
        except Websites.DoesNotExist:
            return error('Unknown site.', status=404)
    record = {'user_id': context.user_id, 'username': Administrator.objects.get(pk=context.user_id).userName,
              'is_admin': context.is_admin, 'domain': domain if not root else '', 'system_user': system_user,
              'root': root, 'ip': get_client_ip(request), 'host': request.get_host()}
    try:
        return ok(result=privileged.call('webterm', 'ticket', record=record))
    except RuntimeError as exc:
        return error(str(exc), status=409)


@admin_api
def status(request, data):
    return ok(result=privileged.call('webterm', 'overview'))


@admin_api
def setup(request, data):
    site = str(data.get('site') or '').strip().lower()
    if not site:
        return error('Choose the site that will carry the terminal connection.', status=400)
    try:
        return ok(result=privileged.call('webterm', 'setup', site=site))
    except RuntimeError as exc:
        return error(str(exc), status=409)


@admin_api
def teardown(request, data):
    return ok(result=privileged.call('webterm', 'teardown'))


@admin_api
def policy(request, data):
    values = {k: data[k] for k in ('terminal_for_users', 'terminal_root_for_admins') if k in data}
    if any(not isinstance(v, bool) for v in values.values()):
        return error('Policy values must be true or false.', status=400)
    return ok(result=privileged.call('webterm', 'save_policy', values=values))

"""Free subdomain settings (administrators) and a name check for the website-creation page.

Tokens travel inside a nested "secrets" object (CyberPanel's request filter screens top-level
strings only) and are never sent back: the page only learns whether one is saved.
"""
import json

from django.http import JsonResponse

from universalAddons.access import admin_api, admin_page, error, ok
from freeSubdomains import service
from freeSubdomains.service import FreeSubdomainError


def page(request):
    return admin_page(request, 'freeSubdomains/settings.html')


def _body(data):
    return service.validate_config(data.get('config') or {}), service.clean_secrets(data.get('secrets'))


@admin_api
def overview(request, data):
    return ok(config=service.public_config(), subdomains=service.listing())


@admin_api
def test(request, data):
    config, secrets = _body(data)
    try:
        return ok(message=service.apply_test(config, secrets))
    except FreeSubdomainError as exc:
        return error(str(exc))


@admin_api
def save(request, data):
    config, secrets = _body(data)
    return ok(config=service.save(config, secrets))


@admin_api
def forget(request, data):
    service.forget_token(data.get('provider'))
    return ok(config=service.public_config())


@admin_api
def release(request, data):
    try:
        service.release(data.get('fqdn'), request.session.get('userID'), is_admin=True)
    except FreeSubdomainError as exc:
        return error(str(exc))
    return ok(subdomains=service.listing())


def _manages_a_website(acl, user_id):
    """Child domains need no ACL permission, only a website of one's own (submitDomainCreation)."""
    from plogical.acl import ACLManager
    try:
        return bool(ACLManager.findAllSites(acl, user_id))
    except Exception:
        return False


def check(request):
    """Is <label>.<base> free? For any logged-in user who may create websites or child domains."""
    from plogical.acl import ACLManager
    try:
        user_id = request.session['userID']
    except KeyError:
        return error('Not logged in.', status=401)
    if request.method != 'POST':
        return error('POST required.', status=405)
    try:
        acl = ACLManager.loadedACL(user_id)
    except Exception:
        return error('Could not load your account.', status=403)
    if ACLManager.currentContextPermission(acl, 'createWebsite') == 0 and not _manages_a_website(acl, user_id):
        return error('You may not create websites or domains.', status=403)
    try:
        body = json.loads(request.body or b'{}')
    except ValueError:
        return error('Invalid JSON body.', status=400)
    config = service.load_config()
    if not service.offered_base(config):
        return error('Free subdomains are not available on this server.')
    fqdn, reason = service.availability(body.get('label') if isinstance(body, dict) else None, config)
    return JsonResponse({'status': 1, 'available': reason is None, 'fqdn': fqdn, 'message': reason or ''})

"""Branding settings page (resellers edit their own; administrators edit any reseller's) and the
public logo endpoint."""
import base64
import json

from django.http import HttpResponse, Http404
from django.views.decorators.http import require_POST

from . import service


def _json(payload, status=200):
    response = HttpResponse(json.dumps(payload), status=status, content_type='application/json')
    response['Cache-Control'] = 'no-store'
    return response


def _caller(request):
    from loginSystem.models import Administrator
    try:
        return Administrator.objects.get(pk=request.session['userID'])
    except Exception:
        return None


def _payload(request):
    """Fields arrive nested under "payload": the panel's request filter rejects ':' in top-level
    values, which URLs need. Every field is validated in service.py."""
    try:
        body = json.loads(request.body or b'{}')
    except ValueError:
        return {}
    if isinstance(body, dict) and isinstance(body.get('payload'), dict):
        return body['payload']
    return body if isinstance(body, dict) else {}


def _resellers():
    from loginSystem.models import Administrator
    return [a for a in Administrator.objects.all().order_by('userName') if service.is_reseller(a)]


def _target(caller, username):
    """The reseller whose branding ``caller`` edits. Raises PermissionError / LookupError."""
    from loginSystem.models import Administrator
    if service._is_admin(caller):
        target = Administrator.objects.filter(userName=str(username or '')).first()
        if target is None or not service.is_reseller(target):
            raise LookupError('Choose a reseller account.')
        return target
    if not service.is_reseller(caller):
        raise PermissionError('Only reseller accounts have white-label branding.')
    if username and username != caller.userName:
        raise PermissionError('You can only edit your own branding.')
    return caller


def _describe(target):
    from .models import ResellerBranding
    branding = ResellerBranding.objects.filter(reseller_id=target.pk).first()
    data = {'reseller': target.userName, 'configured': branding is not None}
    if branding is not None:
        data.update(name=branding.name, primary_color=branding.primary_color,
                    support_url=branding.support_url, support_email=branding.support_email,
                    hostname=branding.hostname or '', logo_url=service.brand_dict(branding)['logo_url'])
    return data


def _guard(handler):
    def view(request):
        caller = _caller(request)
        if caller is None:
            return _json({'status': 0, 'error_message': 'Please log in.'}, 401)
        try:
            return handler(request, caller)
        except PermissionError as error:
            return _json({'status': 0, 'error_message': str(error)}, 403)
        except (LookupError, ValueError) as error:
            return _json({'status': 0, 'error_message': str(error)})
    view.__name__ = handler.__name__
    return require_POST(view)


def settings_page(request):
    from plogical.httpProc import httpProc
    caller = _caller(request)
    if caller is None:
        from django.shortcuts import redirect
        return redirect('/')
    is_admin = service._is_admin(caller)
    if not is_admin and not service.is_reseller(caller):
        from plogical.acl import ACLManager
        return ACLManager.loadError()
    proc = httpProc(request, 'resellerBranding/settings.html', {
        'is_admin_view': is_admin,
        'resellers': [a.userName for a in _resellers()] if is_admin else [caller.userName],
        'max_kb': service.MAX_LOGO_BYTES // 1024,
    })
    return proc.render()


@_guard
def fetch(request, caller):
    target = _target(caller, _payload(request).get('reseller'))
    return _json(dict(_describe(target), status=1, can_set_hostname=service._is_admin(caller)))


@_guard
def save(request, caller):
    from .models import ResellerBranding
    data = _payload(request)
    target = _target(caller, data.get('reseller'))
    branding = ResellerBranding.objects.filter(reseller_id=target.pk).first() or ResellerBranding(reseller_id=target.pk)
    branding.name = service.clean_name(data.get('name'))
    branding.primary_color = service.clean_color(data.get('primary_color'))
    branding.support_url = service.clean_support_url(data.get('support_url'))
    branding.support_email = service.clean_support_email(data.get('support_email'))
    if service._is_admin(caller):     # a hostname decides who sees a login page: administrators only
        hostname = service.clean_hostname(data.get('hostname'))
        if hostname and ResellerBranding.objects.filter(hostname=hostname).exclude(reseller_id=target.pk).exists():
            raise ValueError('Another reseller already uses this hostname.')
        branding.hostname = hostname
    branding.save()
    return _json(dict(_describe(target), status=1))


@_guard
def upload_logo(request, caller):
    from .models import ResellerBranding
    target = _target(caller, request.POST.get('reseller'))
    branding = ResellerBranding.objects.filter(reseller_id=target.pk).first()
    if branding is None:
        raise ValueError('Save the brand name first, then upload the logo.')
    upload = request.FILES.get('logo')
    if upload is None:
        raise ValueError('Choose a logo file.')
    if upload.size > service.MAX_LOGO_BYTES:
        raise ValueError('The logo must be at most %d KB.' % (service.MAX_LOGO_BYTES // 1024))
    service.store_logo(branding, upload.read(service.MAX_LOGO_BYTES + 1))
    branding.save()
    return _json(dict(_describe(target), status=1))


@_guard
def remove_logo(request, caller):
    from .models import ResellerBranding
    target = _target(caller, _payload(request).get('reseller'))
    ResellerBranding.objects.filter(reseller_id=target.pk).update(logo_data='', logo_mime='', logo_hash='')
    return _json(dict(_describe(target), status=1))


@_guard
def reset(request, caller):
    from .models import ResellerBranding
    target = _target(caller, _payload(request).get('reseller'))
    ResellerBranding.objects.filter(reseller_id=target.pk).delete()
    return _json(dict(_describe(target), status=1))


def logo(request, reseller_id, digest):
    from .models import ResellerBranding
    branding = ResellerBranding.objects.filter(reseller_id=reseller_id).first()
    if branding is None or not branding.logo_data or branding.logo_hash != digest:
        raise Http404()
    response = HttpResponse(base64.b64decode(branding.logo_data), content_type=branding.logo_mime)
    # The file was validated on upload; this policy also stops it from running anything if it
    # is opened directly.
    response['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    response['X-Content-Type-Options'] = 'nosniff'
    response['Content-Disposition'] = 'inline'
    response['Cache-Control'] = 'public, max-age=86400'
    return response

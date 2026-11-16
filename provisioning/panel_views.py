"""The "API tokens" page: every account manages its own tokens; administrators can revoke any."""
import json

from django.http import HttpResponse
from django.views.decorators.http import require_POST

from . import accounts, tokens


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
    values, which IPv6 allowlists need. Every field is validated here."""
    try:
        body = json.loads(request.body or b'{}')
    except ValueError:
        return {}
    if isinstance(body, dict) and isinstance(body.get('payload'), dict):
        return body['payload']
    return body if isinstance(body, dict) else {}


def tokens_page(request):
    from plogical.httpProc import httpProc
    caller = _caller(request)
    if caller is None:
        from django.shortcuts import redirect
        return redirect('/')
    proc = httpProc(request, 'provisioning/apiTokens.html', {
        'is_admin_view': accounts.is_admin(caller),
        'api_enabled': bool(caller.api),
        'scope_labels': tokens.SCOPE_LABELS,
        'max_days': tokens.MAX_EXPIRY_DAYS,
    })
    return proc.render()


def _visible_tokens(caller, show_all):
    from loginSystem.models import Administrator
    from .models import ApiToken
    if show_all and accounts.is_admin(caller):
        rows = ApiToken.objects.all()[:500]
    else:
        rows = ApiToken.objects.filter(owner_id=caller.pk)[:200]
    names = dict(Administrator.objects.filter(pk__in={t.owner_id for t in rows}).values_list('pk', 'userName'))
    return [tokens.describe(t, names.get(t.owner_id, '#%d' % t.owner_id)) for t in rows]


@require_POST
def list_tokens(request):
    caller = _caller(request)
    if caller is None:
        return _json({'status': 0, 'error_message': 'Please log in.'}, 401)
    data = _payload(request)
    return _json({'status': 1, 'tokens': _visible_tokens(caller, bool(data.get('all'))),
                  'api_enabled': bool(caller.api)})


@require_POST
def create_token(request):
    caller = _caller(request)
    if caller is None:
        return _json({'status': 0, 'error_message': 'Please log in.'}, 401)
    data = _payload(request)
    try:
        token, plaintext = tokens.create_token(
            caller, data.get('name'), data.get('scopes') or [tokens.SCOPE_READ],
            expires_days=data.get('expires_days'), allowed_ips=data.get('allowed_ips'), created_by=caller)
    except ValueError as error:
        return _json({'status': 0, 'error_message': str(error)})
    # The only time the secret is ever returned.
    return _json({'status': 1, 'token': plaintext, 'details': tokens.describe(token, caller.userName),
                  'api_enabled': bool(caller.api)})


@require_POST
def revoke_token(request):
    from .models import ApiToken
    caller = _caller(request)
    if caller is None:
        return _json({'status': 0, 'error_message': 'Please log in.'}, 401)
    data = _payload(request)
    try:
        token = ApiToken.objects.get(pk=int(data.get('id')))
    except (TypeError, ValueError, ApiToken.DoesNotExist):
        return _json({'status': 0, 'error_message': 'Token not found.'}, 404)
    if token.owner_id != caller.pk and not accounts.is_admin(caller):
        return _json({'status': 0, 'error_message': 'Token not found.'}, 404)
    tokens.revoke_token(token, caller)
    return _json({'status': 1, 'details': tokens.describe(token)})

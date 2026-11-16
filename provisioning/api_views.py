"""IndiansCloud provisioning API v2 (``/api/v2/``). JSON in, JSON out.

Authentication, either:
  * ``Authorization: Bearer ictk_...`` (a personal API token, see provisioning/tokens.py), or
  * ``adminUser`` + ``adminPass`` in the body (plus the OTP for accounts with 2FA), as in v1.

Every response is ``{"status": 1, ...}`` or ``{"status": 0, "error_message": "..."}``.
Passwords may be sent base64-encoded as ``passwordB64`` so that characters such as ``$`` or ``;``
pass the panel's request filter.
"""
import base64
import binascii
import json

from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt

from . import accounts, tokens
from .accounts import AccountError


def _response(payload, status=200):
    response = HttpResponse(json.dumps(payload), status=status, content_type='application/json')
    response['Cache-Control'] = 'no-store'
    return response


def ok(**payload):
    payload['status'] = 1
    payload.setdefault('error_message', 'None')
    return _response(payload)


def fail(message, status=400):
    return _response({'status': 0, 'error_message': message}, status)


def _body(request):
    try:
        data = json.loads(request.body or b'{}')
    except (ValueError, UnicodeDecodeError):
        raise AccountError('The request body must be JSON.')
    if not isinstance(data, dict):
        raise AccountError('The request body must be a JSON object.')
    return data


def password_field(data, key='password'):
    encoded = data.get(key + 'B64')
    if encoded not in (None, ''):
        try:
            return base64.b64decode(str(encoded), validate=True).decode('utf-8')
        except (binascii.Error, ValueError, UnicodeDecodeError):
            raise AccountError('%sB64 is not valid base64 UTF-8.' % key)
    return str(data.get(key) or '')


def authenticate(request, data, scope):
    """Returns (actor, token or None). Raises AccountError."""
    if tokens.has_personal_token(request):
        try:
            return tokens.authenticate(request, scope)
        except tokens.TokenError as error:
            raise AccountError(error.message, error.status)
    if tokens.rate_limited(request):
        raise AccountError('Too many failed attempts. Try again later.', 429)
    from api.views import get_api_admin
    admin, auth_error = get_api_admin(request, data, allow_token=False)
    if auth_error is not None:
        tokens._record_failure(request)
        message = json.loads(auth_error.content.decode()).get('error_message')
        raise AccountError(message or 'Could not authorize access to API.', 401)
    return admin, None


def endpoint(scope):
    """Decorator: POST only, JSON body, authenticated actor, errors mapped to JSON."""
    def wrap(func):
        @csrf_exempt
        def view(request):
            if request.method != 'POST':
                return fail('Only POST method allowed.', 405)
            try:
                data = _body(request)
                actor, token = authenticate(request, data, scope)
                return func(request, data, actor, token)
            except AccountError as error:
                return fail(error.message, error.status)
            except Exception as error:   # never leak a traceback to the billing system
                from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging
                logging.writeToFile('provisioning API %s: %s' % (func.__name__, error))
                return fail('Internal error; see the panel log.', 500)
        view.__name__ = func.__name__
        return view
    return wrap


def _target(data, actor):
    target = accounts.get_account(data.get('username'))
    accounts.require_manage(actor, target)
    return target


@endpoint(tokens.SCOPE_READ)
def verify(request, data, actor, token):
    return ok(username=actor.userName, admin=accounts.is_admin(actor),
              reseller=accounts.is_reseller(actor),
              scopes=token.scope_list() if token else list(tokens.SCOPES),
              auth='token' if token else 'password')


@endpoint(tokens.SCOPE_READ)
def list_accounts(request, data, actor, token):
    return ok(accounts=accounts.list_accounts(actor))


@endpoint(tokens.SCOPE_READ)
def account_info(request, data, actor, token):
    return ok(account=accounts.account_info(_target(data, actor)))


@endpoint(tokens.SCOPE_READ)
def account_usage(request, data, actor, token):
    if data.get('username'):
        return ok(usage=[accounts.account_usage(_target(data, actor))])
    return ok(usage=[accounts.account_usage(a) for a in accounts.managed_accounts(actor)])


@endpoint(tokens.SCOPE_READ)
def list_packages(request, data, actor, token):
    from packages.models import Package
    packages = Package.objects.all() if accounts.is_admin(actor) else Package.objects.filter(admin=actor)
    return ok(packages=[{'name': p.packageName, 'disk_mb': p.diskSpace, 'bandwidth_mb': p.bandwidth,
                         'domains': p.allowedDomains, 'emails': p.emailAccounts,
                         'databases': p.dataBases, 'ftp': p.ftpAccounts}
                        for p in packages.order_by('packageName')])


@endpoint(tokens.SCOPE_PROVISIONING)
def create_account(request, data, actor, token):
    data = dict(data, password=password_field(data))
    return ok(**accounts.create_account(actor, data))


@endpoint(tokens.SCOPE_PROVISIONING)
def suspend_account(request, data, actor, token):
    target = accounts.get_account(data.get('username'))
    return ok(**accounts.suspend_account(actor, target, data.get('reason', '')))


@endpoint(tokens.SCOPE_PROVISIONING)
def unsuspend_account(request, data, actor, token):
    target = accounts.get_account(data.get('username'))
    return ok(**accounts.unsuspend_account(actor, target))


@endpoint(tokens.SCOPE_PROVISIONING)
def terminate_account(request, data, actor, token):
    from loginSystem.models import Administrator
    username = str(data.get('username') or '').strip()
    if username and not Administrator.objects.filter(userName=username).exists():
        # Idempotent for billing systems that retry: an absent account is already terminated.
        return ok(username=username, deleted=False, already_absent=True)
    return ok(**accounts.terminate_account(actor, accounts.get_account(username)))


@endpoint(tokens.SCOPE_PROVISIONING)
def change_password(request, data, actor, token):
    target = accounts.get_account(data.get('username'))
    return ok(**accounts.change_password(actor, target, password_field(data)))


@endpoint(tokens.SCOPE_PROVISIONING)
def change_package(request, data, actor, token):
    target = accounts.get_account(data.get('username'))
    return ok(**accounts.change_package(actor, target, data.get('package'), data.get('domain')))


@endpoint(tokens.SCOPE_PROVISIONING)
def create_sso(request, data, actor, token):
    username = data.get('username') or actor.userName
    target = accounts.get_account(username)
    ticket = accounts.issue_sso_ticket(actor, target, data.get('redirect'), token)
    from django.urls import reverse
    url = request.build_absolute_uri(reverse('icSsoRedeem')) + '?ticket=' + ticket
    return ok(url=url, expires_in=accounts.SSO_TTL_SECONDS, username=target.userName)


def redeem_sso(request):
    """GET /api/v2/sso/redeem?ticket=...: log the browser in and redirect into the panel."""
    from CyberCP.sessionSecurity import get_client_ip, session_ip_key

    def plain(message, status):
        response = HttpResponse(message, status=status, content_type='text/plain; charset=utf-8')
        response['Cache-Control'] = 'no-store'
        response['Referrer-Policy'] = 'no-referrer'
        return response

    if request.method not in ('GET', 'HEAD'):
        return plain('Method not allowed.', 405)
    if request.method == 'HEAD':     # link scanners must not burn the ticket
        return plain('', 200)
    if tokens.rate_limited(request):
        return plain('Too many attempts. Try again later.', 429)
    ip_key = session_ip_key(get_client_ip(request))
    if ip_key is None:
        return plain('A valid client address is required.', 400)
    try:
        account, target = accounts.redeem_sso_ticket(request.GET.get('ticket'), tokens.client_ip(request))
    except AccountError as error:
        tokens._record_failure(request)
        return plain(error.message, error.status)
    request.session.cycle_key()
    request.session['userID'] = account.pk
    request.session['ipAddr'] = ip_key
    request.session.set_expiry(43200)
    request.session.save()
    response = HttpResponseRedirect(target)
    response['Cache-Control'] = 'no-store'
    response['Referrer-Policy'] = 'no-referrer'
    return response

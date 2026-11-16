"""OAuth sign-in for backup destinations (Google Drive, OneDrive, Dropbox, Box, pCloud).

Flow, for every provider, using the administrator's own app registration (clients.py):
1. ``begin`` (POST, CSRF + same-origin) stores a random state, a PKCE verifier (providers that
   support PKCE) and what is being connected in the server-side session; it returns the
   provider's authorization URL.
2. The provider redirects to ``callback`` (GET). The state must match a pending record of this
   session and user, younger than TTL, for this provider and redirect URI. The code is kept in
   the session record (never echoed into the page) and a confirmation form is shown.
3. The confirmation POST (CSRF + same-origin) exchanges the code directly with the provider,
   then stores the tokens, in rclone's token form, in the root-only store.
"""
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.utils.html import format_html
from django.views.decorators.csrf import csrf_protect

from universalAddons.destinations import clients, policy, providers

SESSION_KEY = 'ua_dest_oauth'
TTL = 600
MAX_PENDING = 4
_STATE = re.compile(r'^[A-Za-z0-9_-]{43,128}$')
_CODE = re.compile(r'^[A-Za-z0-9/_.~+!*=-]{8,4096}$')
_TOKEN = re.compile(r'^[\x21-\x7e]{1,8192}$')

OAUTH = {
    'gdrive': {'auth': 'https://accounts.google.com/o/oauth2/v2/auth', 'token': 'https://oauth2.googleapis.com/token',
               'scope': 'https://www.googleapis.com/auth/drive.file', 'pkce': True,
               'extra': {'access_type': 'offline', 'prompt': 'consent', 'include_granted_scopes': 'false'},
               'returns': {'scope', 'authuser', 'prompt', 'hd', 'iss', 'session_state'}},
    'onedrive': {'auth': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                 'token': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                 'scope': 'Files.ReadWrite offline_access', 'pkce': True,
                 'extra': {'response_mode': 'query', 'prompt': 'select_account'},
                 'returns': {'session_state'}},
    'dropbox': {'auth': 'https://www.dropbox.com/oauth2/authorize', 'token': 'https://api.dropboxapi.com/oauth2/token',
                'scope': None, 'pkce': True, 'extra': {'token_access_type': 'offline'}, 'returns': set()},
    'box': {'auth': 'https://account.box.com/api/oauth2/authorize', 'token': 'https://api.box.com/oauth2/token',
            'scope': None, 'pkce': False, 'extra': {}, 'returns': set()},
    'pcloud': {'auth': 'https://my.pcloud.com/oauth2/authorize', 'token': None,
               'scope': None, 'pkce': False, 'extra': {}, 'returns': {'hostname', 'locationid'}},
}
GRAPH_DRIVE = 'https://graph.microsoft.com/v1.0/me/drive'
PCLOUD_HOSTS = ('api.pcloud.com', 'eapi.pcloud.com')


def callback_path(provider):
    return '/addons/destinations/oauth/%s/callback' % provider


def redirect_uri(request, provider):
    """The exact redirect URI to register with the provider (https + the panel's host:port)."""
    return 'https://' + request.get_host() + callback_path(provider)


def _headers(response):
    response['Cache-Control'] = 'no-store'
    response['Referrer-Policy'] = 'strict-origin'
    response['Content-Security-Policy'] = ("default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; "
                                           "base-uri 'none'; form-action 'self'")
    response['X-Content-Type-Options'] = 'nosniff'
    return response


def _json_error(message, status=400):
    return _headers(JsonResponse({'status': 0, 'error_message': message}, status=status))


def _page(title, message, status=200, extra=''):
    html = format_html(
        '<!doctype html><html><head><meta charset="utf-8"><title>{} - IndiansCloud</title></head>'
        '<body style="font-family:sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem">'
        '<h1>{}</h1><p>{}</p>{}</body></html>', title, title, message, extra)
    return _headers(HttpResponse(html, status=status))


def _failed(status=400, detail=''):
    return _page('Connection failed',
                 detail or 'The storage could not be connected. Close this window and click Connect again. If it '
                           'keeps failing, check that the redirect URI shown on the Backup destinations page is '
                           'registered with the provider.', status)


def _origin_ok(request):
    return request.META.get('HTTP_ORIGIN') == 'https://' + request.get_host()


def _sessions_ok():
    return not getattr(settings, 'SESSION_ENGINE', '').endswith('signed_cookies')


def _binding(session):
    if not session.session_key:
        session.save()
    return hashlib.sha256(session.session_key.encode()).hexdigest()


def _pending(session):
    pending = session.get(SESSION_KEY) or {}
    return {key: value for key, value in pending.items()
            if isinstance(value, dict) and 0 <= time.time() - value.get('created', 0) < TTL}


def _client(provider):
    try:
        return clients.load(provider)
    except clients.ClientError:
        return None


def authorization_url(provider, client, callback, state, challenge=None):
    spec = OAUTH[provider]
    params = {'client_id': client['client_id'], 'redirect_uri': callback, 'response_type': 'code', 'state': state}
    if spec['scope']:
        params['scope'] = spec['scope']
    params.update(spec['extra'])
    if challenge:
        params.update(code_challenge=challenge, code_challenge_method='S256')
    return spec['auth'] + '?' + urlencode(params)


@csrf_protect
def begin(request, provider):
    """POST {name, folder} for a new destination, or {destination: id} to reconnect one."""
    if request.method != 'POST':
        return _json_error('POST required.', 405)
    if provider not in OAUTH or not _sessions_ok():
        return _json_error('Unknown provider.', 404)
    if not _origin_ok(request):
        return _json_error('Open the panel over https and try again.')
    try:
        actor = policy.load_actor(request.session.get('userID'))
        data = json.loads(request.body or b'{}')
        if not isinstance(data, dict):
            raise ValueError()
        client = _client(provider)
        if not client:
            return _json_error('The administrator has not set up %s sign-in yet (Backup destinations > '
                               'Sign-in apps).' % providers.PROVIDERS[provider]['title'], 503)
        dest_id = None
        if data.get('destination') not in (None, ''):
            dest = policy.require_owner(actor, policy.get_destination(data['destination']))
            if dest.provider != provider:
                return _json_error('This destination uses another provider.')
            dest_id, name, public = dest.pk, dest.name, policy.public_config(dest)
        else:
            name = providers.valid_name(data.get('name'))
            public = providers.validate_public(provider, {'folder': data.get('folder')})
            from universalAddons.models import BackupDestination
            if BackupDestination.objects.filter(owner_id=actor.pk, name=name).exists():
                return _json_error('You already have a destination named %s.' % name, 409)
        pending = _pending(request.session)
        if len(pending) >= MAX_PENDING:
            return _json_error('Too many sign-ins in progress. Wait a few minutes.', 429)
        state = secrets.token_urlsafe(32)
        verifier = challenge = None
        if OAUTH[provider]['pkce']:
            verifier = secrets.token_urlsafe(64)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        callback = redirect_uri(request, provider)
        pending[state] = {'provider': provider, 'verifier': verifier, 'created': time.time(), 'user_id': actor.pk,
                          'binding': _binding(request.session), 'callback': callback,
                          'client_id': client['client_id'], 'dest_id': dest_id, 'name': name, 'public': public}
        request.session[SESSION_KEY] = pending
        return _headers(JsonResponse({'status': 1, 'reconnect': dest_id is not None,
                                      'authorization_url': authorization_url(provider, client, callback, state,
                                                                             challenge)}))
    except PermissionError as exc:
        return _json_error(str(exc), 403)
    except providers.ProviderError as exc:
        return _json_error(str(exc))
    except (KeyError, TypeError, ValueError):
        return _json_error('Invalid request.')


def exchange(provider, record, code, client, extra=None, post=None, get=None):
    """Exchange the code directly with the provider; return the secrets to store."""
    post = post or requests.post
    get = get or requests.get
    extra = extra or {}
    body = {'code': code, 'client_id': client['client_id'], 'client_secret': client['client_secret'],
            'redirect_uri': record['callback'], 'grant_type': 'authorization_code'}
    if record.get('verifier'):
        body['code_verifier'] = record['verifier']
    if provider == 'pcloud':
        host = extra.get('hostname') or 'api.pcloud.com'
        if host not in PCLOUD_HOSTS:
            raise ValueError('Unexpected pCloud region.')
        response = get('https://%s/oauth2_token' % host, params={
            'client_id': client['client_id'], 'client_secret': client['client_secret'], 'code': code},
            headers={'Accept': 'application/json'}, timeout=(5, 20), allow_redirects=False)
    else:
        response = post(OAUTH[provider]['token'], data=body, headers={'Accept': 'application/json'},
                        timeout=(5, 20), allow_redirects=False)
    if response.status_code != 200:
        raise ValueError('The provider refused the sign-in code.')
    data = response.json()
    if not isinstance(data, dict) or (provider == 'pcloud' and data.get('result') not in (0, None)):
        raise ValueError('Unexpected token response.')
    access, refresh, expires = data.get('access_token'), data.get('refresh_token'), data.get('expires_in')
    if not isinstance(access, str) or not _TOKEN.match(access) or \
            str(data.get('token_type', 'bearer')).lower() != 'bearer':
        raise ValueError('Unexpected token response.')
    if provider != 'pcloud':
        if not isinstance(refresh, str) or not _TOKEN.match(refresh):
            raise ValueError('The provider did not return a refresh token (offline access).')
        if type(expires) is not int or not 60 <= expires <= 7 * 86400:
            raise ValueError('Unexpected token lifetime.')
    else:
        refresh, expires = None, None
    if provider == 'gdrive' and OAUTH['gdrive']['scope'] not in str(data.get('scope', OAUTH['gdrive']['scope'])).split():
        raise ValueError('Google did not grant Drive access.')
    result = {'token': providers.rclone_token(access, refresh, expires - 30 if expires else None)}
    if provider == 'onedrive':
        drive = get(GRAPH_DRIVE, headers={'Authorization': 'Bearer ' + access, 'Accept': 'application/json'},
                    timeout=(5, 20), allow_redirects=False)
        if drive.status_code != 200:
            raise ValueError('Could not read the OneDrive drive of this account.')
        info = drive.json()
        result['drive_id'] = str(info.get('id', ''))
        result['drive_type'] = str(info.get('driveType', ''))
    if provider == 'pcloud':
        result['hostname'] = extra.get('hostname') or 'api.pcloud.com'
    return providers.validate_oauth_secrets(provider, result)


def _store(actor_id, record, stored, call_private=None):
    """Create or update the destination row, and hand the tokens to the root-only store."""
    from django.db import transaction
    from universalAddons.models import BackupDestination
    if call_private is None:
        from universalAddons.privileged import call_private
    created = False
    with transaction.atomic():
        if record.get('dest_id'):
            dest = BackupDestination.objects.select_for_update().get(pk=record['dest_id'], owner_id=actor_id)
        else:
            if BackupDestination.objects.filter(owner_id=actor_id, name=record['name']).exists():
                raise ValueError('You already have a destination named %s.' % record['name'])
            dest = BackupDestination.objects.create(owner_id=actor_id, name=record['name'],
                                                    provider=record['provider'],
                                                    public_config=json.dumps(record['public'], sort_keys=True))
            created = True
    try:
        call_private('destinations', 'save_secrets', dest_id=dest.pk, secrets=stored)
    except Exception:
        if created:
            dest.delete()
        raise ValueError('The tokens could not be stored.')
    dest.connected = True
    dest.save(update_fields=['connected', 'updated'])
    return dest


@csrf_protect
def callback(request, provider):
    if provider not in OAUTH or not _sessions_ok():
        return _failed(404)
    if request.method not in ('GET', 'POST'):
        return _failed(405)
    try:
        if request.method == 'POST' and (not _origin_ok(request) or
                                         request.content_type != 'application/x-www-form-urlencoded'):
            return _failed()
        data = request.GET if request.method == 'GET' else request.POST
        if any(len(data.getlist(key)) != 1 for key in data):
            return _failed()
        allowed = ({'state', 'code', 'error', 'error_description', 'error_uri'} | OAUTH[provider]['returns']
                   if request.method == 'GET' else {'state', 'csrfmiddlewaretoken'})
        if set(data) - allowed:
            return _failed()
        state = data.get('state')
        if not isinstance(state, str) or not _STATE.match(state):
            return _failed()
        pending = _pending(request.session)
        record = pending.get(state)
        if (not record or record.get('user_id') != request.session.get('userID') or
                not hmac.compare_digest(record['binding'], _binding(request.session)) or
                record.get('provider') != provider or record['callback'] != redirect_uri(request, provider)):
            return _failed()
        actor = policy.load_actor(record['user_id'])
        if request.method == 'GET':
            if 'error' in data:
                del pending[state]
                request.session[SESSION_KEY] = pending
                return _page('Not connected', 'Access was not granted, so nothing was saved. Close this window.')
            code = data.get('code')
            if not isinstance(code, str) or not _CODE.match(code):
                return _failed()
            extra = {}
            if provider == 'pcloud':
                host = data.get('hostname', 'api.pcloud.com')
                if host not in PCLOUD_HOSTS:
                    return _failed()
                extra['hostname'] = host
            # Keep the code server-side; the page carries only the state.
            record.update(code=code, extra=extra)
            pending[state] = record
            request.session[SESSION_KEY] = pending
            action = 'Reconnect' if record.get('dest_id') else 'Save'
            form = format_html(
                '<form method="post" action="{}"><input type="hidden" name="csrfmiddlewaretoken" value="{}">'
                '<input type="hidden" name="state" value="{}"><button type="submit">{} {}</button></form>',
                callback_path(provider), get_token(request), state, action, record['name'])
            return _page('Connect %s' % providers.PROVIDERS[provider]['title'],
                         format_html('{} the backup destination "{}" for account {}?', action, record['name'],
                                     actor.obj.userName), extra=form)
        code = record.get('code')
        del pending[state]
        request.session[SESSION_KEY] = pending
        if not code:
            return _failed()
        client = _client(provider)
        if not client or client['client_id'] != record['client_id']:
            return _failed()
        stored = exchange(provider, record, code, client, record.get('extra'))
        dest = _store(actor.pk, record, stored)
        return _page('Connected', format_html(
            'The backup destination "{}" is connected. Close this window and reload the Backup destinations page.',
            dest.name))
    except PermissionError:
        return _failed(403)
    except Exception:
        # Never echo provider responses, codes or tokens.
        return _failed()


def provider_status(request):
    """Per OAuth provider: configured or not, the exact redirect URI and setup steps (no secrets)."""
    result = []
    for key in providers.OAUTH_PROVIDERS:
        status = clients.public_status(key)
        result.append({'provider': key, 'title': providers.PROVIDERS[key]['title'],
                       'configured': status['configured'], 'client_id': status['client_id'],
                       'client_secret': status['client_secret'], 'error': status['error'],
                       'redirect_uri': redirect_uri(request, key), 'pkce': OAUTH[key]['pkce'],
                       'console': providers.OAUTH_SETUP[key]['console'],
                       'steps': providers.OAUTH_SETUP[key]['steps']})
    return result

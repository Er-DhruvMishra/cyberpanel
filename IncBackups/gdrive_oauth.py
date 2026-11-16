"""Google Drive connection done directly with Google, using the admin's own OAuth client.

Flow (no vendor service involved):
1. An admin saves a Google OAuth client ID and secret (``client_settings``); the
   secret goes to /home/cyberpanel/gdrive-oauth.json (0600) and is never returned.
2. ``begin`` stores a random state and a PKCE verifier in the server-side session
   and returns a https://accounts.google.com/o/oauth2/v2/auth URL.
3. Google redirects back to the panel (``complete``). A GET only shows a
   confirmation form; the POST checks state, session, user and age, then
   exchanges the code at https://oauth2.googleapis.com/token.
4. Tokens are saved in the existing GDrive record (normal backups) or written to
   the website's rclone.conf (incremental v2 backups).
"""
import base64
from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import hmac
import json
from pathlib import Path
import pwd
import re
import secrets
import subprocess
import sys
import time
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.utils.html import format_html
from django.views.decorators.csrf import csrf_protect

SESSION_KEY = 'gdrive_oauth_v3'
TTL = 600
OPAQUE = re.compile(r'^[A-Za-z0-9_-]{43,128}$')
CODE = re.compile(r'^[A-Za-z0-9/_.~+-]{10,2048}$')
ACCOUNT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
TOKEN = re.compile(r'^[A-Za-z0-9._~+/=-]{1,8192}$')
SCOPE = 'https://www.googleapis.com/auth/drive.file'
GOOGLE_AUTH_URI = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URI = 'https://oauth2.googleapis.com/token'
CALLBACKS = {'v2': '/IncrementalBackups/ConfigureV2BackupSetup', 'normal': '/backup/gDriveSetup'}
NORMAL_DOMAIN = 'normal-backup-account'
# Parameters Google may add to the redirect besides state and code.
GOOGLE_RETURN_EXTRA = {'scope', 'authuser', 'prompt', 'hd', 'iss', 'session_state'}
NOT_CONFIGURED = ('Google Drive is not connected to an OAuth client yet. An administrator must '
                  'save a Google OAuth client ID and secret under "Google OAuth client" on the '
                  'Google Drive Backups page. Existing backups are unchanged.')


class AccessDenied(Exception):
    pass


def _response(response):
    response['Cache-Control'] = 'no-store'
    # no-referrer turns basic form POST Origin into null in browsers, defeating
    # normal CSRF validation. strict-origin still never discloses paths/codes.
    response['Referrer-Policy'] = 'strict-origin'
    response['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    response['X-Content-Type-Options'] = 'nosniff'
    return response


def _error(status=400, message='Google Drive setup could not be completed. Start again or contact support.'):
    return _response(JsonResponse({'status': 0, 'error_message': message}, status=status))


def _page(title, message, status=200, extra=''):
    html = format_html(
        '<!doctype html><html><head><meta charset="utf-8"><title>{} - IndiansCloud</title></head>'
        '<body style="font-family:sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem">'
        '<h1>{}</h1><p>{}</p>{}</body></html>', title, title, message, extra)
    return _response(HttpResponse(html, status=status))


def _failed_page(status=400):
    return _page('Google Drive setup failed',
                 'The connection could not be completed. Close this window and click '
                 '"Connect Google Drive" again. If it keeps failing, check that the redirect URI '
                 'shown on the Google Drive Backups page is registered in Google Cloud Console.',
                 status)


def _secured(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        return _response(view(*args, **kwargs))
    return wrapped


def _client():
    """The admin's own OAuth client, or None. Never raises."""
    from plogical.gdriveClient import load_client
    try:
        return load_client()
    except Exception:
        return None


def _sessions_ok():
    return not getattr(settings, 'SESSION_ENGINE', '').endswith('signed_cookies')


def redirect_uri(request, mode):
    """Exact redirect URI to register in Google Cloud Console (https + request host)."""
    return 'https://' + request.get_host() + CALLBACKS[mode]


def _data(request):
    if request.content_type == 'application/json':
        if len(request.body) > 32768:
            raise ValueError()
        data = json.loads(request.body)
        if not isinstance(data, dict):
            raise ValueError()
        return data
    if request.content_type == 'application/x-www-form-urlencoded':
        if any(len(request.POST.getlist(key)) != 1 for key in request.POST):
            raise ValueError()
        return request.POST
    raise ValueError()


def _check_access(request, website, mode='v2', status_only=False):
    from loginSystem.models import Administrator
    from plogical.acl import ACLManager
    user_id = request.session.get('userID')
    if type(user_id) is not int:
        raise AccessDenied()
    try:
        admin = Administrator.objects.get(pk=user_id)
        acl = ACLManager.loadedACL(user_id)
        if ACLManager.currentContextPermission(acl, 'createBackup') != 1:
            raise AccessDenied()
        if mode == 'v2':
            if not status_only and ACLManager.checkOwnership(website, admin, acl) != 1:
                raise AccessDenied()
            entitlement = ACLManager.CheckForPremFeature('all')
            if type(entitlement) is not int or entitlement != 1:
                raise AccessDenied()
        elif mode != 'normal':
            raise AccessDenied()
    except Exception:
        raise AccessDenied() from None


def _is_admin(request):
    from plogical.acl import ACLManager
    user_id = request.session.get('userID')
    if type(user_id) is not int:
        return False
    try:
        return ACLManager.loadedACL(user_id).get('admin') == 1
    except Exception:
        return False


def _binding(session):
    if not session.session_key:
        session.save()
    return hashlib.sha256(session.session_key.encode()).hexdigest()


def capability(mode='v2'):
    """New connections need the admin's own OAuth client."""
    if mode not in CALLBACKS:
        return False, NOT_CONFIGURED
    if not _sessions_ok():
        return False, 'Google Drive setup needs server-side sessions.'
    if not _client():
        return False, NOT_CONFIGURED
    return True, ''


def _origin_ok(request):
    # Explicitly reject null/missing origins; the panel must be used over https.
    return request.META.get('HTTP_ORIGIN') == 'https://' + request.get_host()


def _account_states(user_id):
    """Per-account connection type for the current user's normal Drive accounts."""
    from plogical.gdriveRefresh import connection_kind
    from websiteFunctions.models import GDrive
    client = _client()
    states = []
    for item in GDrive.objects.filter(owner_id=user_id).order_by('name'):
        try:
            auth = json.loads(item.auth)
        except Exception:
            auth = None
        kind = connection_kind(auth)
        needs = bool(isinstance(auth, dict) and auth.get('auth_failed'))
        if kind == 'panel' and (not client or client.get('client_id') != auth.get('client_id')):
            needs = True
        if kind == 'unknown':
            needs = True
        states.append({'name': item.name, 'connection': kind, 'reconnect': needs})
    return states


@_secured
def status(request, mode='v2'):
    if request.method != 'GET':
        return _error(405)
    try:
        _check_access(request, None, mode, status_only=True)
    except AccessDenied:
        return _error(403)
    enabled, reason = capability(mode)
    data = {'status': 1, 'enabled': enabled, 'reason': reason, 'is_admin': _is_admin(request),
            'redirect_uri': redirect_uri(request, mode)}
    if mode == 'normal':
        try:
            data['accounts'] = _account_states(request.session['userID'])
        except Exception:
            data['accounts'] = []
    return JsonResponse(data)


def _client_view_data(request):
    from plogical.gdriveClient import public_status
    data = public_status()
    data.update(status=1, scope=SCOPE,
                redirect_uris=[redirect_uri(request, 'normal'), redirect_uri(request, 'v2')],
                javascript_origin='https://' + request.get_host())
    return data


@_secured
@csrf_protect
def client_settings(request):
    """Admin only. GET shows status, POST saves. The secret is never returned."""
    from plogical.gdriveClient import ClientConfigError, clear_client, save_client
    if request.method not in ('GET', 'POST'):
        return _error(405)
    if not _is_admin(request):
        return _error(403, 'Only an administrator can change the Google OAuth client.')
    if request.method == 'GET':
        return JsonResponse(_client_view_data(request))
    if not _origin_ok(request):
        return _error(400, 'Open the panel over https and try again.')
    try:
        data = _data(request)
        if data.get('clear') is True:
            clear_client()
        else:
            save_client(data.get('client_id', ''), data.get('client_secret', ''))
    except ClientConfigError as error:
        return _error(400, str(error))
    except Exception:
        return _error(400, 'The Google OAuth client could not be saved.')
    return JsonResponse(_client_view_data(request))


def _account_owner(account):
    from websiteFunctions.models import GDrive
    item = GDrive.objects.filter(name=account).first()
    return None if item is None else item.owner_id


@_secured
@csrf_protect
def begin(request, mode='v2'):
    if request.method != 'POST':
        return _error(405)
    if mode not in CALLBACKS or not _sessions_ok():
        return _error(503, NOT_CONFIGURED)
    try:
        if not _origin_ok(request):
            return _error(400, 'Open the panel over https and try again.')
        data = _data(request)
        website = data['Selectedwebsite'] if mode == 'v2' else NORMAL_DOMAIN
        account = data['accountName']
        if (not isinstance(website, str) or len(website) > 253 or
                not isinstance(account, str) or not ACCOUNT.fullmatch(account) or
                (mode == 'normal' and len(account) > 50)):
            return _error(400, 'Use 1-50 letters, digits, "-" or "_" for the account name.')
        _check_access(request, website, mode)
        client = _client()
        if not client:
            return _error(503, NOT_CONFIGURED)
        reconnect = False
        if mode == 'normal':
            owner = _account_owner(account)
            if owner is not None and owner != request.session['userID']:
                return _error(409, 'This account name is already in use. Choose another name.')
            reconnect = owner is not None
        pending = request.session.get(SESSION_KEY, {})
        pending = {key: value for key, value in pending.items()
                   if 0 <= time.time() - value.get('created', 0) < TTL}
        if len(pending) >= 4:
            return _error(429, 'Too many Google Drive setups in progress. Wait a few minutes.')
        verifier = secrets.token_urlsafe(64)
        state = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        callback = redirect_uri(request, mode)
        authorization_url = GOOGLE_AUTH_URI + '?' + urlencode({
            'client_id': client['client_id'], 'redirect_uri': callback, 'response_type': 'code',
            'scope': SCOPE, 'access_type': 'offline', 'prompt': 'consent', 'state': state,
            'code_challenge': challenge, 'code_challenge_method': 'S256'})
        pending[state] = {'verifier': verifier, 'created': time.time(),
                          'user_id': request.session['userID'], 'website': website,
                          'account': account, 'callback': callback, 'client_id': client['client_id'],
                          'binding': _binding(request.session), 'mode': mode, 'reconnect': reconnect}
        request.session[SESSION_KEY] = pending
        return JsonResponse({'status': 1, 'authorization_url': authorization_url, 'reconnect': reconnect})
    except AccessDenied:
        return _error(403)
    except (KeyError, TypeError, ValueError):
        return _error()
    except Exception:
        return _error(502)


def _exchange(record, code, client):
    """Exchange the authorization code directly with Google."""
    response = requests.post(GOOGLE_TOKEN_URI, data={
        'code': code, 'client_id': client['client_id'], 'client_secret': client['client_secret'],
        'redirect_uri': record['callback'], 'grant_type': 'authorization_code',
        'code_verifier': record['verifier']}, headers={'Accept': 'application/json'},
        timeout=(5, 20), allow_redirects=False)
    if response.status_code != 200:
        raise ValueError()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError()
    access, refresh = data.get('access_token'), data.get('refresh_token')
    expires = data.get('expires_in')
    granted = data.get('scope', SCOPE)
    if (not isinstance(access, str) or not TOKEN.fullmatch(access) or
            not isinstance(refresh, str) or not TOKEN.fullmatch(refresh) or
            type(expires) is not int or not 60 <= expires <= 86400 or
            str(data.get('token_type', '')).lower() != 'bearer' or
            not isinstance(granted, str) or SCOPE not in granted.split()):
        raise ValueError()
    expiry = datetime.now(timezone.utc) + timedelta(seconds=expires - 30)
    return {'token': access, 'refresh_token': refresh, 'token_uri': GOOGLE_TOKEN_URI,
            'scopes': [SCOPE], 'client_id': client['client_id'],
            'expiry': expiry.isoformat().replace('+00:00', 'Z')}


def _valid_credentials(credentials):
    from plogical.gdriveConfig import validate_credentials
    validate_credentials(credentials)
    if (credentials.get('token_uri') != GOOGLE_TOKEN_URI or
            credentials.get('scopes') != [SCOPE]):
        raise ValueError()


def _install_backend(website, account, credentials):
    from websiteFunctions.models import Websites
    site = Websites.objects.get(domain=website)
    if (not re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', site.domain) or
            not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,63}', site.externalApp)):
        raise ValueError()
    owner = pwd.getpwnam(site.externalApp)
    if owner.pw_uid == 0 or owner.pw_dir != '/home/' + site.domain:
        raise ValueError()
    # No constructor-driven installer, shell interpolation, tokens in argv, or debug logging.
    helper = Path(__file__).resolve().parents[1] / 'plogical' / 'gdriveConfig.py'
    result = subprocess.run(
        ['sudo', '-n', '-u', site.externalApp, sys.executable, str(helper), '--home', '/home/' + site.domain],
        input=json.dumps({'account': account, 'credentials': credentials}).encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False,
    )
    if result.returncode:
        raise ValueError()


def _install_normal(user_id, account, credentials):
    """Save tokens in the GDrive record: insert, or reconnect the user's own record.

    The client secret is not stored here; it stays in the 0600 client file.
    A name owned by another user is never updated.
    """
    from django.db import transaction
    from websiteFunctions.models import GDrive
    from plogical.gdriveRefresh import PANEL_CLIENT_VERSION
    auth = {key: value for key, value in credentials.items() if key != 'client_secret'}
    auth['handoff_version'] = PANEL_CLIENT_VERSION
    with transaction.atomic():
        existing = GDrive.objects.select_for_update().filter(name=account).first()
        if existing is None:
            GDrive.objects.create(owner_id=user_id, name=account,
                                  auth=json.dumps(auth, sort_keys=True), runTime='NEVER')
            return 'created'
        if existing.owner_id != user_id:
            raise ValueError()
        try:
            old = json.loads(existing.auth)
        except Exception:
            old = {}
        if isinstance(old, dict):
            if 'FileRetentiontime' in old:
                auth['FileRetentiontime'] = old['FileRetentiontime']
            # drive.file: a different client cannot see the old folder, so a new
            # one is created on the next run unless the client is unchanged.
            if old.get('client_id') == auth['client_id'] and 'folderIDIP' in old:
                auth['folderIDIP'] = old['folderIDIP']
        existing.auth = json.dumps(auth, sort_keys=True)
        existing.save(update_fields=['auth'])
        return 'reconnected'


@_secured
@csrf_protect
def complete(request, mode='v2'):
    if mode not in CALLBACKS or not _sessions_ok():
        return _failed_page(503)
    if request.method not in ('GET', 'POST'):
        return _error(405)
    try:
        if request.method == 'POST' and not _origin_ok(request):
            return _failed_page()
        data = request.GET if request.method == 'GET' else _data(request)
        if request.method == 'GET' and any(len(data.getlist(key)) != 1 for key in data):
            return _failed_page()
        allowed = {'state', 'code', 'csrfmiddlewaretoken', 'error'} | GOOGLE_RETURN_EXTRA
        if set(data) - allowed:
            return _failed_page()
        state = data.get('state')
        if not isinstance(state, str) or not OPAQUE.fullmatch(state):
            return _failed_page()
        pending = request.session.get(SESSION_KEY, {})
        record = pending.get(state)
        if (not record or record['user_id'] != request.session.get('userID') or
                not hmac.compare_digest(record['binding'], _binding(request.session)) or
                not 0 <= time.time() - record['created'] < TTL or
                record.get('mode') != mode or
                record['callback'] != redirect_uri(request, mode)):
            return _failed_page()
        if 'error' in data:
            del pending[state]
            request.session[SESSION_KEY] = pending
            return _page('Google Drive not connected',
                         'Google did not grant access, so nothing was saved. Close this window to go back.')
        code = data.get('code')
        if not isinstance(code, str) or not CODE.fullmatch(code):
            return _failed_page()
        _check_access(request, record['website'], mode)
        if request.method == 'GET':
            action = 'Reconnect' if record.get('reconnect') else 'Save'
            form = format_html(
                '<form method="post" action="{}">'
                '<input type="hidden" name="csrfmiddlewaretoken" value="{}">'
                '<input type="hidden" name="state" value="{}">'
                '<input type="hidden" name="code" value="{}">'
                '<button type="submit">{} Google Drive account</button></form>',
                CALLBACKS[mode], get_token(request), state, code, action)
            if mode == 'normal':
                message = format_html('{} Google Drive account {}?', action, record['account'])
            else:
                message = format_html('Save Google Drive account {} for website {}?',
                                      record['account'], record['website'])
            return _page('Complete Google Drive setup', message, extra=form)
        del pending[state]
        request.session[SESSION_KEY] = pending
        client = _client()
        if not client or client['client_id'] != record['client_id']:
            return _failed_page()
        credentials = _exchange(record, code, client)
        if mode == 'normal':
            _install_normal(record['user_id'], record['account'], credentials)
        else:
            credentials['client_secret'] = client['client_secret']
            _valid_credentials(credentials)
            _install_backend(record['website'], record['account'], credentials)
        return _page('Google Drive connected',
                     'The Google Drive account is connected. No backup job or schedule was started. '
                     'Close this window and reload the Google Drive Backups page.')
    except AccessDenied:
        return _failed_page(403)
    except Exception:
        # Do not include exceptions, response bodies, or request URLs in logs/errors.
        return _failed_page()

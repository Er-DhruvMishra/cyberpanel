import base64
import re

from universalAddons import privileged
from universalAddons.access import admin_api, admin_page, error, ok
from universalAddons.sshsec import authkeys as ak
from universalAddons.sshsec import service as sv
from universalAddons.sshsec import sshconf as sc

_USER_RE = re.compile(r'^[a-z_][a-z0-9_.-]{0,31}$')
_TOKEN_RE = re.compile(r'^[0-9a-f]{32}$')


def _call(action, /, **args):
    try:
        return ok(result=privileged.call('sshsec', action, **args))
    except RuntimeError as exc:
        return error(str(exc))


def _call_private(action, /, **args):
    """Arguments travel in a private spool file (passphrases); the response is never cached."""
    try:
        response = ok(result=privileged.call_private('sshsec', action, **args))
    except RuntimeError as exc:
        return error(str(exc))
    response['Cache-Control'] = 'no-store'
    return response


def _actor(request):
    try:
        from loginSystem.models import Administrator
        return Administrator.objects.get(pk=request.session['userID']).userName
    except Exception:
        return ''


def _target(data):
    """Address/CIDR from the page ('addr', with ':' sent as '-'), strictly validated here and again as root."""
    try:
        return str(sv.parse_target(sv.decode_target(data.get('addr'))))
    except sv.SSHSecError as exc:
        raise ValueError(str(exc))


def page(request):
    return admin_page(request, 'universalAddons/sshsec.html')


@admin_api
def overview(request, data):
    return _call('overview')


@admin_api
def analyze(request, data):
    window = data.get('window')
    if window not in sv.WINDOWS:
        return error('Choose 24h, 7d or 30d.', status=400)
    return _call('analyze', window=window, client=sv.client_ips(request.META))


@admin_api
def audit(request, data):
    return _call('audit', client=sv.client_ips(request.META))


@admin_api
def blocklist(request, data):
    return _call('blocklist')


@admin_api
def block(request, data):
    target = _target(data)
    try:
        reason = sv.validate_reason(data.get('reason', ''))
    except sv.SSHSecError as exc:
        return error(str(exc), status=400)
    client = sv.client_ips(request.META)
    refusals, _ = sv.block_checks(sv.parse_target(target), client)
    if refusals:  # checked again as root, with the server's own addresses
        return error(' '.join(refusals), status=400)
    return _call('block', target=target, reason=reason, client=client, confirm=data.get('confirm') is True,
                 by=_actor(request))


@admin_api
def unblock(request, data):
    return _call('unblock', target=_target(data))


@admin_api
def enable_jail(request, data):
    if data.get('confirm') is not True:
        return error('Confirmation required.', status=400)
    return _call('enable_f2b_sshd')


@admin_api
def job(request, data):
    job_id = str(data.get('job', ''))
    if not re.match(r'^[0-9a-f]{24}$', job_id):
        return error('Invalid job.', status=400)
    return _call('job', job_id=job_id)


# ----------------------------------------------------------------------------- login settings & keys

def _user(data):
    user = str(data.get('user') or 'root')
    if not _USER_RE.match(user):
        raise ValueError('Invalid user name.')
    return user


def _b64_text(data, field, limit=16384):
    """Pasted keys and passphrases arrive base64-encoded: the panel's request filter rejects
    characters that keys and passphrases legitimately contain."""
    value = data.get(field) or ''
    if not isinstance(value, str) or len(value) > limit * 2:
        raise ValueError('Invalid %s.' % field)
    try:
        return base64.b64decode(value, validate=True).decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise ValueError('Invalid %s.' % field)


def _fingerprints(data, field='fps'):
    values = data.get(field) or []
    if not isinstance(values, list) or len(values) > 200:
        raise ValueError('Invalid key selection.')
    try:
        return [ak.decode_fingerprint(v)[7:] for v in values]
    except sv.SSHSecError as exc:
        raise ValueError(str(exc))


def _public_key(data):
    """Checked here as well, so a pasted private key never travels on to the root side."""
    text = _b64_text(data, 'key_b64')
    try:
        ak.validate_new(text, allow_options=True)   # the options opt-in is enforced as root
    except sv.SSHSecError as exc:
        raise ValueError(str(exc))
    return text


@admin_api
def login_state(request, data):
    return _call('login_state', client=sv.client_ips(request.META))


@admin_api
def login_apply(request, data):
    try:
        settings = sc.validate_settings(data.get('settings'))
    except sv.SSHSecError as exc:
        return error(str(exc), status=400)
    login_user = str(data.get('login_user') or 'root')
    if not _USER_RE.match(login_user):
        return error('Invalid login user.', status=400)
    return _call('login_apply', settings=settings, login_user=login_user, tested=data.get('tested') is True,
                 client=sv.client_ips(request.META), by=_actor(request))


def _token(data):
    token = str(data.get('token', ''))
    if not _TOKEN_RE.match(token):
        raise ValueError('Invalid confirmation token.')
    return token


@admin_api
def login_confirm(request, data):
    return _call('login_confirm', token=_token(data))


@admin_api
def login_revert(request, data):
    return _call('login_revert', token=_token(data), reason='button')


@admin_api
def keys_list(request, data):
    return _call('keys_list', user=_user(data))


@admin_api
def keys_add(request, data):
    return _call('keys_add', user=_user(data), key=_public_key(data), allow_options=data.get('allow_options') is True)


@admin_api
def keys_remove(request, data):
    fps = _fingerprints(data)
    if not fps:
        return error('Select the keys to remove.', status=400)
    return _call('keys_remove', user=_user(data), fingerprints=fps)


@admin_api
def keys_rotate(request, data):
    fps = _fingerprints(data)
    if not fps:
        return error('Select the old keys to replace.', status=400)
    return _call('keys_rotate', user=_user(data), key=_public_key(data), remove=fps,
                 allow_options=data.get('allow_options') is True)


@admin_api
def keys_generate(request, data):
    if data.get('understood') is not True:
        return error('Tick that you understand the private key is shown only once.', status=400)
    passphrase = _b64_text(data, 'secret_b64', 512) if data.get('secret_b64') else ''
    try:
        comment = ak.validate_comment(data.get('comment', ''))
    except sv.SSHSecError as exc:
        return error(str(exc), status=400)
    return _call_private('keys_generate', user=_user(data), comment=comment, passphrase=passphrase,
                         remove=_fingerprints(data))

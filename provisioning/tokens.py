"""Personal API tokens: creation, hashing, verification, scopes, expiry, IP allowlists, revocation.

Token format: ``ictk_<key id>_<secret>``.

* The key id (16 lowercase hex characters) is public. It locates the row and is shown in lists.
* The secret (43 URL-safe characters, 256 bits) is shown once at creation. Only its SHA-256
  digest is stored; verification compares digests in constant time.

Two-factor authentication: a personal token is accepted *instead of* password + TOTP. It is a
high-entropy possession factor of its own, it can be created only from a logged-in panel session
(which already passed the account's 2FA), and it can be limited by scope, expiry and source IP
and revoked at any time. The legacy ``apiToken`` (verifyConn) keeps its old rules, including the
OTP requirement for accounts with 2FA enabled.
"""
import hashlib
import hmac
import ipaddress
import re
import secrets
from datetime import timedelta

from django.core.cache import cache
from django.utils import timezone

TOKEN_PREFIX = 'ictk_'
TOKEN_RE = re.compile(r'^ictk_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$')
SCOPE_READ = 'read'
SCOPE_PROVISIONING = 'provisioning'
SCOPES = (SCOPE_READ, SCOPE_PROVISIONING)
SCOPE_LABELS = {SCOPE_READ: 'Read-only', SCOPE_PROVISIONING: 'Provisioning (create, suspend, terminate, SSO)'}
MAX_ACTIVE_TOKENS = 25
MAX_ALLOWED_IPS = 32
MAX_EXPIRY_DAYS = 3650
FAILURE_LIMIT = 20
FAILURE_WINDOW = 5 * 60
LAST_USED_GRANULARITY = 60   # seconds; avoids a database write on every request
_DUMMY_HASH = hashlib.sha256(b'indianscloud-dummy').hexdigest()
NAME_RE = re.compile(r'^[^\x00-\x1f\x7f<>]{1,64}$')


class TokenError(Exception):
    def __init__(self, message, status=401):
        super().__init__(message)
        self.message = message
        self.status = status


def hash_secret(secret):
    return hashlib.sha256(secret.encode('utf-8')).hexdigest()


def extract_bearer(request):
    """Return the raw personal token from ``Authorization: Bearer ictk_...``, or ''."""
    header = str(request.META.get('HTTP_AUTHORIZATION', '') or '').strip()
    if header[:7].lower() == 'bearer ':
        candidate = header[7:].strip()
        if candidate.startswith(TOKEN_PREFIX):
            return candidate
    return ''


def has_personal_token(request):
    return bool(extract_bearer(request))


def client_ip(request):
    """The TCP peer address. Forwarded headers are ignored so an allowlist cannot be spoofed."""
    return str(request.META.get('REMOTE_ADDR', '') or '')


def _failure_key(request):
    return 'ic_api_token_fail_%s' % hashlib.sha256(client_ip(request).encode()).hexdigest()


def _record_failure(request):
    key = _failure_key(request)
    if cache.add(key, 1, FAILURE_WINDOW):
        return
    try:
        cache.incr(key)
    except ValueError:
        cache.set(key, 1, FAILURE_WINDOW)


def rate_limited(request):
    return cache.get(_failure_key(request), 0) >= FAILURE_LIMIT


def normalize_scopes(scopes):
    if isinstance(scopes, str):
        scopes = [s.strip() for s in scopes.split(',')]
    cleaned = []
    for scope in scopes or []:
        scope = str(scope).strip().lower()
        if not scope:
            continue
        if scope not in SCOPES:
            raise ValueError('Unknown scope: %s' % scope[:40])
        if scope not in cleaned:
            cleaned.append(scope)
    if not cleaned:
        raise ValueError('Choose at least one scope.')
    return [s for s in SCOPES if s in cleaned]


def normalize_ip_list(value):
    if isinstance(value, str):
        value = re.split(r'[\s,]+', value)
    networks = []
    for item in value or []:
        item = str(item).strip()
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError('Not an IP address or CIDR range: %s' % item[:60])
        text = str(network.network_address) if network.num_addresses == 1 else str(network)
        if text not in networks:
            networks.append(text)
    if len(networks) > MAX_ALLOWED_IPS:
        raise ValueError('At most %d IP addresses or ranges.' % MAX_ALLOWED_IPS)
    return networks


def ip_allowed(token, address):
    allowed = token.ip_list()
    if not allowed:
        return True
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    for item in allowed:
        try:
            if ip in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def scope_allows(token_scopes, required):
    if required is None:
        return True
    if SCOPE_PROVISIONING in token_scopes:
        return True       # provisioning includes read
    return required in token_scopes


def create_token(owner, name, scopes, expires_days=None, allowed_ips=None, created_by=None):
    """Create a token for ``owner``. Returns (ApiToken, plaintext). The plaintext is not stored."""
    from .models import ApiToken

    name = str(name or '').strip()
    if not NAME_RE.match(name):
        raise ValueError('Give the token a name of 1 to 64 characters.')
    scope_list = normalize_scopes(scopes)
    ip_list = normalize_ip_list(allowed_ips)
    expires_at = None
    if expires_days not in (None, '', 0, '0'):
        try:
            days = int(expires_days)
        except (TypeError, ValueError):
            raise ValueError('Expiry must be a number of days.')
        if days < 1 or days > MAX_EXPIRY_DAYS:
            raise ValueError('Expiry must be between 1 and %d days.' % MAX_EXPIRY_DAYS)
        expires_at = timezone.now() + timedelta(days=days)
    if active_tokens(owner.pk).count() >= MAX_ACTIVE_TOKENS:
        raise ValueError('This account already has %d active tokens. Revoke one first.' % MAX_ACTIVE_TOKENS)

    for _ in range(5):
        key_id = secrets.token_hex(8)
        if not ApiToken.objects.filter(key_id=key_id).exists():
            break
    secret = secrets.token_urlsafe(32)[:43]
    while len(secret) < 43:          # token_urlsafe(32) is 43 characters; keep the format strict
        secret += secrets.token_urlsafe(4)
    secret = secret[:43]
    token = ApiToken.objects.create(
        owner_id=owner.pk, name=name, key_id=key_id, token_hash=hash_secret(secret),
        scopes=','.join(scope_list), allowed_ips='\n'.join(ip_list), expires_at=expires_at,
        created_by_id=getattr(created_by, 'pk', None) or owner.pk)
    return token, '%s%s_%s' % (TOKEN_PREFIX, key_id, secret)


def active_tokens(owner_id):
    from .models import ApiToken
    return ApiToken.objects.filter(owner_id=owner_id, revoked_at__isnull=True).exclude(
        expires_at__lte=timezone.now())


def revoke_token(token, by):
    if token.revoked_at is None:
        token.revoked_at = timezone.now()
        token.revoked_by_id = getattr(by, 'pk', None)
        token.save(update_fields=['revoked_at', 'revoked_by_id'])
    return token


def revoke_all_for(owner_id, by=None):
    from .models import ApiToken
    return ApiToken.objects.filter(owner_id=owner_id, revoked_at__isnull=True).update(
        revoked_at=timezone.now(), revoked_by_id=getattr(by, 'pk', None))


def token_status(token, now=None):
    now = now or timezone.now()
    if token.revoked_at:
        return 'revoked'
    if token.expires_at and token.expires_at <= now:
        return 'expired'
    return 'active'


def describe(token, owner_name=None):
    return {
        'id': token.pk,
        'name': token.name,
        'owner': owner_name,
        'prefix': '%s%s_…' % (TOKEN_PREFIX, token.key_id),
        'scopes': token.scope_list(),
        'allowed_ips': token.ip_list(),
        'created_at': token.created_at.isoformat() if token.created_at else None,
        'expires_at': token.expires_at.isoformat() if token.expires_at else None,
        'last_used_at': token.last_used_at.isoformat() if token.last_used_at else None,
        'last_used_ip': token.last_used_ip,
        'status': token_status(token),
    }


def authenticate(request, required_scope):
    """Verify the request's Bearer personal token.

    Returns (Administrator, ApiToken). Raises TokenError with a message safe to return.
    """
    from loginSystem.models import Administrator
    from .models import ApiToken

    if rate_limited(request):
        raise TokenError('Too many failed attempts. Try again later.', 429)

    raw = extract_bearer(request)
    match = TOKEN_RE.match(raw)
    if not match:
        _record_failure(request)
        raise TokenError('Could not authorize access to API.')
    key_id, secret = match.groups()
    token = ApiToken.objects.filter(key_id=key_id).first()
    digest = hash_secret(secret)
    if not hmac.compare_digest(digest, token.token_hash if token else _DUMMY_HASH) or token is None:
        _record_failure(request)
        raise TokenError('Could not authorize access to API.')

    now = timezone.now()
    if token.revoked_at:
        _record_failure(request)
        raise TokenError('This API token has been revoked.')
    if token.expires_at and token.expires_at <= now:
        raise TokenError('This API token has expired.')
    address = client_ip(request)
    if not ip_allowed(token, address):
        raise TokenError('This API token is not allowed from this IP address.', 403)
    if not scope_allows(token.scope_list(), required_scope):
        raise TokenError("This API token lacks the '%s' scope." % required_scope, 403)

    try:
        owner = Administrator.objects.get(pk=token.owner_id)
    except Administrator.DoesNotExist:
        raise TokenError('Could not authorize access to API.')
    if not owner.api or getattr(owner, 'state', 'ACTIVE') != 'ACTIVE':
        raise TokenError('API access is not enabled for this account.', 403)

    if (token.last_used_at is None or (now - token.last_used_at).total_seconds() > LAST_USED_GRANULARITY
            or token.last_used_ip != address[:64]):
        ApiToken.objects.filter(pk=token.pk).update(last_used_at=now, last_used_ip=address[:64])
    owner._ic_api_token = token
    return owner, token

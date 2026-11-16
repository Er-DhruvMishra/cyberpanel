"""State of the Cloudflare add-on: per-account tokens, zone links, the audit log and a short GET cache.

Everything lives in STATE_DIR, the panel user's private directory (mode 0700). Each account's
token is its own file, tokens/user-<id>.token (the administrators' server-wide token is
tokens/server.token), written mode 0600 and never sent back to a browser. Zone links are
links/user-<id>.json; the audit log is one JSON line per change in audit.log.
"""
import hashlib
import json
import os
import re
import threading
import time

from universalAddons.cloudflare import client as cf
from universalAddons.cloudflare.client import CloudflareError

STATE_DIR = '/home/cyberpanel/ua-cloudflare'
PANEL_USER = 'cyberpanel'
MACHINE_IP = '/etc/cyberpanel/machineIP'
SERVER_KEY = 'server'
CACHE_TTL = 45
CACHE_MAX = 400
AUDIT_READ_BYTES = 256 * 1024
_KEY_RE = re.compile(r'^(?:server|user-\d{1,10})$')


def account_key(user_id):
    return 'user-%d' % int(user_id)


def _check_key(key):
    if not _KEY_RE.match(key or ''):
        raise CloudflareError('Invalid account.')
    return key


def _path(*parts):
    return os.path.join(STATE_DIR, *parts)


def _write_private(path, text):
    """Atomically write `text` mode 0600 (owned by the panel user when written as root)."""
    directory = os.path.dirname(path)
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    temporary = '%s.%d.tmp' % (path, os.getpid())
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            try:
                import pwd
                entry = pwd.getpwnam(PANEL_USER)
                os.fchown(fd, entry.pw_uid, entry.pw_gid)
            except KeyError:
                pass
        with os.fdopen(fd, 'w') as handle:
            fd = None
            handle.write(text)
    finally:
        if fd is not None:
            os.close(fd)
    os.replace(temporary, path)


def _read_json(path, default):
    try:
        with open(path) as handle:
            value = json.load(handle)
        return value if isinstance(value, type(default)) else default
    except (OSError, ValueError):
        return default


# ---------------------------------------------------------------------------------------- tokens

def load_token(key):
    try:
        with open(_path('tokens', _check_key(key) + '.token')) as handle:
            return handle.read().strip()
    except OSError:
        return ''


def save_token(key, api_token, http=None):
    """Verify the token with Cloudflare, then store it. Returns the verify status (never the token)."""
    api_token = cf.token(api_token)
    status = verify(key, api_token=api_token, http=http)
    if status.get('status') not in ('active',):
        raise CloudflareError('Cloudflare says this token is %s; it was not saved.' % status.get('status', 'invalid'))
    _write_private(_path('tokens', _check_key(key) + '.token'), api_token + '\n')
    _write_private(_path('tokens', key + '.status.json'), json.dumps(status))
    cache_clear(key)
    return status


def forget_token(key):
    _check_key(key)
    for name in (key + '.token', key + '.status.json'):
        try:
            os.unlink(_path('tokens', name))
        except OSError:
            pass
    cache_clear(key)


def verify(key, api_token=None, http=None):
    """GET /user/tokens/verify. Stores and returns {status, expires_on, checked_at}."""
    api_token = api_token or load_token(key)
    if not api_token:
        return {'status': 'missing'}
    try:
        result = cf.Client(api_token, http).verify() or {}
        status = {'status': str(result.get('status') or 'unknown'), 'expires_on': result.get('expires_on'),
                  'not_before': result.get('not_before')}
    except CloudflareError as exc:
        if exc.status in (401, 403):
            status = {'status': 'invalid', 'detail': str(exc)}
        else:
            raise
    status['checked_at'] = int(time.time())
    return status


def token_state(key):
    saved = bool(load_token(key))
    state = {'saved': saved}
    if saved:
        state['verify'] = _read_json(_path('tokens', key + '.status.json'), {})
    return state


def store_verify(key, status):
    if load_token(key):
        _write_private(_path('tokens', _check_key(key) + '.status.json'), json.dumps(status))


def client_for(key, http=None):
    api_token = load_token(key)
    if not api_token:
        raise CloudflareError('Save a Cloudflare API token first.' if key != SERVER_KEY else
                              'No server-wide Cloudflare token is saved.')
    return cf.Client(api_token, http)


# ----------------------------------------------------------------------------------------- cache

_cache = {}
_cache_lock = threading.Lock()


def cached(key, label, fetch, ttl=CACHE_TTL):
    """Cache a GET result for `ttl` seconds per account. On a 429 an older copy is served if there is one."""
    now = time.time()
    with _cache_lock:
        hit = _cache.get((key, label))
    if hit and hit[0] > now:
        return hit[1]
    try:
        value = fetch()
    except CloudflareError as exc:
        if exc.status == 429 and hit:
            return hit[1]
        raise
    with _cache_lock:
        if len(_cache) >= CACHE_MAX:
            for old in sorted(_cache, key=lambda k: _cache[k][0])[:CACHE_MAX // 4]:
                _cache.pop(old, None)
        _cache[(key, label)] = (now + ttl, value)
    return value


def cache_clear(key, zone=None):
    with _cache_lock:
        for entry in [k for k in _cache if k[0] == key and (zone is None or zone in k[1] or k[1] == 'zones')]:
            _cache.pop(entry, None)


# ----------------------------------------------------------------------------------------- links

def links(user_id):
    raw = _read_json(_path('links', account_key(user_id) + '.json'), {})
    return {z: d for z, d in raw.items() if cf.ID_RE.match(z) and isinstance(d, str)}


def set_link(user_id, zone, domain):
    current = links(user_id)
    if domain:
        current[cf.zone_id(zone)] = domain
    else:
        current.pop(cf.zone_id(zone), None)
    _write_private(_path('links', account_key(user_id) + '.json'), json.dumps(current, sort_keys=True))
    return current


def site_in_zone(domain, zone_name):
    domain, zone_name = domain.lower(), zone_name.lower()
    return domain == zone_name or domain.endswith('.' + zone_name)


# ------------------------------------------------------------------------------------- audit log

def audit(context, zone, action, detail=None, source=None):
    entry = {'at': int(time.time()), 'user_id': int(context.user_id),
             'user': getattr(context.admin_obj, 'userName', ''), 'zone': zone or '', 'action': action,
             'token': source or 'own'}
    if detail:
        entry['detail'] = str(detail)[:300]
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    fd = os.open(_path('audit.log'), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as handle:
        handle.write(json.dumps(entry, sort_keys=True) + '\n')


def audit_entries(user_id=None, limit=200):
    try:
        with open(_path('audit.log'), 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - AUDIT_READ_BYTES))
            lines = handle.read().decode('utf-8', 'replace').splitlines()
    except OSError:
        return []
    found = []
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and (user_id is None or entry.get('user_id') == int(user_id)):
            found.append(entry)
            if len(found) >= limit:
                break
    return found


# ----------------------------------------------------------------------------- server and DNS info

def server_ip():
    try:
        with open(MACHINE_IP) as handle:
            value = handle.read().split('\n', 1)[0].strip()
    except OSError:
        return ''
    import ipaddress
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        return ''


def public_nameservers(name, resolver=None):
    if resolver is None:
        from universalAddons.emaildebug.service import DigResolver
        resolver = DigResolver()
    return sorted({n.lower().rstrip('.') for n in resolver.query(name, 'NS')})


def ns_check(zone, resolver=None):
    wanted = sorted(n.lower() for n in zone.get('name_servers') or [])
    try:
        actual = public_nameservers(zone.get('name', ''), resolver)
    except Exception:
        actual = []
    return {'cloudflare': wanted, 'public': actual,
            'points_to_cloudflare': bool(actual) and set(actual) == set(wanted),
            'checked': bool(actual)}


# ---------------------------------------------------------------------------- PowerDNS import

def _local_zone(site, models):
    parts = site.split('.')
    for index in range(len(parts) - 1):
        zone = models.Domains.objects.filter(name='.'.join(parts[index:])).first()
        if zone is not None:
            return zone
    return None


def _txt(content):
    chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', content or '')
    return ''.join(chunks) if chunks else (content or '')


def powerdns_candidate(record, zone_name):
    """A panel PowerDNS record as a page-style record dict, or None for types we do not import."""
    rtype = (record.type or '').upper()
    if rtype not in cf.RECORD_TYPES or getattr(record, 'disabled', 0):
        return None
    base = {'type': rtype, 'name': (record.name or '').lower(), 'ttl': record.ttl or 1, 'proxied': False}
    content = (record.content or '').strip()
    if rtype == 'TXT':
        base['content'] = _txt(content)
    elif rtype == 'MX':
        base.update(content=content.rstrip('.'), priority=record.prio or 0)
    elif rtype == 'SRV':
        fields = content.split()
        if len(fields) == 4:   # some panels store "prio weight port target"
            fields = fields[1:]
        if len(fields) != 3:
            return dict(base, invalid='SRV content not understood')
        base.update(priority=record.prio or 0, weight=fields[0], port=fields[1], target=fields[2])
    elif rtype == 'CAA':
        match = re.match(r'^(\d+)\s+(\w+)\s+"?([^"]*)"?$', content)
        if not match:
            return dict(base, invalid='CAA content not understood')
        base.update(flags=match.group(1), tag=match.group(2).lower(), value=match.group(3))
    else:
        base['content'] = content.rstrip('.')
    return base


def _signature(body):
    data = body.get('data')
    if data:
        value = json.dumps(data, sort_keys=True)
    else:
        value = _txt(body.get('content', '')) if body['type'] == 'TXT' else str(body.get('content', '')).lower()
    return (body['type'], body['name'], value, body.get('priority'))


def import_preview(site, zone_name, existing, models=None):
    """What importing the panel's PowerDNS records for `site` into the Cloudflare zone would do.

    Returns rows with action create / exists / conflict / skip; only create rows can be applied, and
    apply recomputes this list server-side, so the browser never supplies record content.
    """
    if models is None:
        from dns import models
    local = _local_zone(site, models)
    if local is None:
        raise CloudflareError('This server has no PowerDNS zone for %s.' % site)
    have = {_signature(dict(r, name=r.get('name', '').lower())) for r in existing}
    names = {}
    for r in existing:
        names.setdefault(r.get('name', '').lower(), set()).add(r.get('type'))
    rows = []
    for record in models.Records.objects.filter(domainOwner=local).order_by('name', 'type'):
        candidate = powerdns_candidate(record, zone_name)
        if candidate is None:
            continue
        row = {'type': candidate['type'], 'name': candidate['name']}
        if not site_in_zone(candidate['name'] or '', zone_name):
            rows.append(dict(row, action='skip', reason='outside the Cloudflare zone'))
            continue
        if candidate.get('invalid'):
            rows.append(dict(row, action='skip', reason=candidate['invalid']))
            continue
        try:
            body = cf.validate_record(candidate, zone_name)
        except CloudflareError as exc:
            rows.append(dict(row, action='skip', reason=str(exc)))
            continue
        row['content'] = body.get('content') or ' '.join(str(v) for v in (body.get('data') or {}).values())
        at_name = names.get(body['name'], set())
        if _signature(body) in have:
            rows.append(dict(row, action='exists'))
        elif body['type'] == 'CNAME' and at_name or 'CNAME' in at_name:
            rows.append(dict(row, action='conflict', reason='a CNAME cannot share its name with other records'))
        else:
            key = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]
            rows.append(dict(row, action='create', key=key, body=body))
    return rows


# --------------------------------------------------------------------------- origin certificate

def origin_key_and_csr(hostnames):
    """A new P-256 key and a CSR for `hostnames` (PEM strings)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames]), critical=False).sign(key, hashes.SHA256())
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    return key_pem, csr.public_bytes(serialization.Encoding.PEM).decode()

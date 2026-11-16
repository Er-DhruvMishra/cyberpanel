"""Free subdomains for new websites (replaces the vendor's *.cyberpanel.website service).

A site created as <label>.<base> gets A (and AAAA, when the server has IPv6) records from the
configured provider. Rules for labels: lower case letters, digits and single hyphens, 3-40
characters, not reserved, not already used; one free subdomain per site; each one remembers its
owner, and only that owner (or an administrator) may release it.

Settings live in STATE_DIR (the panel user's private directory): config.json holds the public
settings, <provider>.token the API tokens. Both are written mode 0600 by the panel user and tokens
are never returned to a browser.
"""
import ipaddress
import json
import os
import re
import socket

from freeSubdomains import providers
from freeSubdomains.providers import ProviderError

STATE_DIR = '/home/cyberpanel/free-subdomains'
PANEL_USER = 'cyberpanel'

LABEL_MIN, LABEL_MAX = 3, 40
LABEL_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$')
DOMAIN_RE = re.compile(r'^(?=.{4,200}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
ZONE_ID_RE = re.compile(r'^[a-f0-9]{32}$')
TOKEN_RE = re.compile(r'^[A-Za-z0-9_.\-]{20,200}$')

RESERVED = frozenset('''
www www1 www2 mail mail1 mail2 smtp smtps imap imaps pop pop3 mx mx1 mx2 webmail email autodiscover autoconfig
ns ns1 ns2 ns3 ns4 dns dns1 dns2 ftp sftp ssh admin administrator root sysadmin hostmaster postmaster webmaster
abuse security noc support help billing sales info contact status api app apps cdn static assets media
panel cpanel whm portal login signin signup account accounts dashboard server host hosting hostedon cloud
indianscloud cyberpanel localhost test demo dev staging vpn proxy gateway secure ssl acme mysql phpmyadmin
national ncr cptest
'''.split())

DEFAULTS = {
    'enabled': True,
    'provider': 'powerdns',
    'base': 'hostedon.indianscloud.com',
    'ttl': 300,
    'ipv4': '',             # blank: this server's IP (/etc/cyberpanel/machineIP)
    'ipv6': 'auto',         # 'auto', 'off' or an address
    'per_user_limit': 5,    # free subdomains per non-administrator account; 0 = no limit
    'extra_reserved': [],
    'cloudflare_zone_id': '',
}


class FreeSubdomainError(ValueError):
    """A request the user can correct; the message is safe to show."""


# ------------------------------------------------------------------------------------ storage

def _path(name):
    return os.path.join(STATE_DIR, name)


def _write_private(path, text):
    """Atomically write `text` mode 0600, owned by the panel user."""
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    temporary = path + '.tmp'
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


def load_config():
    config = dict(DEFAULTS)
    try:
        with open(_path('config.json')) as handle:
            stored = json.load(handle)
        if isinstance(stored, dict):
            for key, default in DEFAULTS.items():
                if key in stored and isinstance(stored[key], type(default)):
                    config[key] = stored[key]
    except (OSError, ValueError):
        pass
    return config


def _token(provider):
    try:
        with open(_path('%s.token' % provider)) as handle:
            return handle.read().strip()
    except OSError:
        return ''


def public_config():
    """Settings for the admin page: never a token, only whether one is saved."""
    config = load_config()
    config['tokens'] = {name: bool(_token(name)) for name in ('cloudflare', 'desec')}
    config['providers'] = [{'key': cls.key, 'title': cls.title} for cls in providers.PROVIDERS.values()]
    config['reserved'] = sorted(RESERVED)
    return config


def validate_config(raw):
    """Clean a settings object from the admin page. Raises FreeSubdomainError."""
    if not isinstance(raw, dict):
        raise FreeSubdomainError('Invalid settings.')
    config = load_config()
    if 'enabled' in raw:
        config['enabled'] = raw['enabled'] is True
    provider = raw.get('provider', config['provider'])
    if provider not in providers.PROVIDERS:
        raise FreeSubdomainError('Unknown provider.')
    config['provider'] = provider
    base = str(raw.get('base', config['base'])).strip().lower().rstrip('.')
    if not DOMAIN_RE.match(base):
        raise FreeSubdomainError('Enter the base domain, for example hostedon.example.com.')
    config['base'] = base
    try:
        ttl = int(raw.get('ttl', config['ttl']))
    except (TypeError, ValueError):
        raise FreeSubdomainError('TTL must be a number of seconds.')
    if not 60 <= ttl <= 86400:
        raise FreeSubdomainError('TTL must be between 60 and 86400 seconds.')
    config['ttl'] = ttl
    ipv4 = str(raw.get('ipv4', config['ipv4'])).strip()
    if ipv4:
        try:
            if ipaddress.ip_address(ipv4).version != 4:
                raise ValueError
        except ValueError:
            raise FreeSubdomainError('IPv4 address is not valid.')
    config['ipv4'] = ipv4
    ipv6 = str(raw.get('ipv6', config['ipv6'])).strip().lower() or 'auto'
    if ipv6 not in ('auto', 'off'):
        try:
            if ipaddress.ip_address(ipv6).version != 6:
                raise ValueError
        except ValueError:
            raise FreeSubdomainError("IPv6 must be 'auto', 'off' or an IPv6 address.")
    config['ipv6'] = ipv6
    try:
        limit = int(raw.get('per_user_limit', config['per_user_limit']))
    except (TypeError, ValueError):
        raise FreeSubdomainError('Per-user limit must be a number.')
    if not 0 <= limit <= 1000:
        raise FreeSubdomainError('Per-user limit must be between 0 and 1000.')
    config['per_user_limit'] = limit
    extra = raw.get('extra_reserved', config['extra_reserved'])
    if isinstance(extra, str):
        extra = re.split(r'[\s,]+', extra)
    if not isinstance(extra, list):
        raise FreeSubdomainError('Reserved names must be a list.')
    cleaned = sorted({str(e).strip().lower() for e in extra if str(e).strip()})
    for name in cleaned:
        if not LABEL_RE.match(name) or len(name) > 63:
            raise FreeSubdomainError('Reserved name %r is not a valid label.' % name)
    config['extra_reserved'] = cleaned
    zone_id = str(raw.get('cloudflare_zone_id', config['cloudflare_zone_id'])).strip().lower()
    if zone_id and not ZONE_ID_RE.match(zone_id):
        raise FreeSubdomainError('The Cloudflare zone ID is 32 hexadecimal characters.')
    config['cloudflare_zone_id'] = zone_id
    return config


def clean_secrets(raw):
    """{'cloudflare': token, 'desec': token}; blank values mean 'keep the saved token'."""
    secrets = {}
    for name, value in (raw or {}).items() if isinstance(raw, dict) else ():
        if name not in ('cloudflare', 'desec') or not isinstance(value, str):
            raise FreeSubdomainError('Invalid token field.')
        value = value.strip()
        if value:
            if not TOKEN_RE.match(value):
                raise FreeSubdomainError('The %s API token has an unexpected format.' % name)
            secrets[name] = value
    return secrets


def save(config, secrets):
    for name, token in secrets.items():
        _write_private(_path('%s.token' % name), token + '\n')
    _write_private(_path('config.json'), json.dumps(config, indent=2, sort_keys=True))
    return public_config()


def forget_token(name):
    if name not in ('cloudflare', 'desec'):
        raise FreeSubdomainError('Unknown provider.')
    try:
        os.unlink(_path('%s.token' % name))
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------------- providers

def make_provider(config=None, secrets=None):
    config = config or load_config()
    secrets = secrets or {}
    key = config['provider']
    if key == 'powerdns':
        return providers.LocalPowerDNS(config['base'])
    if key == 'cloudflare':
        return providers.Cloudflare(config['base'], config['cloudflare_zone_id'],
                                    secrets.get('cloudflare') or _token('cloudflare'))
    if key == 'desec':
        return providers.Desec(config['base'], secrets.get('desec') or _token('desec'))
    raise FreeSubdomainError('Unknown provider.')


def apply_test(config, secrets=None):
    """Check settings and credentials against the provider without creating anything."""
    try:
        message = make_provider(config, secrets).test()
    except ProviderError as exc:
        raise FreeSubdomainError(str(exc))
    ipv4, ipv6 = addresses(config)
    if not ipv4:
        raise FreeSubdomainError('No IPv4 address: set one, or check /etc/cyberpanel/machineIP.')
    return '%s New names will point to %s%s.' % (message, ipv4, ' and ' + ipv6 if ipv6 else '')


def server_ipv4():
    try:
        from plogical.acl import ACLManager
        value = ACLManager.GetServerIP().strip()
        return value if ipaddress.ip_address(value).version == 4 else ''
    except Exception:
        return ''


def server_ipv6():
    """This server's global IPv6 source address, if it has one (UDP connect sends no packet)."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
            probe.connect(('2606:4700:4700::1111', 53))
            address = ipaddress.ip_address(probe.getsockname()[0].split('%')[0])
        return str(address) if address.is_global else ''
    except (OSError, ValueError):
        return ''


def addresses(config):
    ipv4 = config.get('ipv4') or server_ipv4()
    setting = config.get('ipv6', 'auto')
    ipv6 = '' if setting == 'off' else (server_ipv6() if setting == 'auto' else setting)
    return ipv4, ipv6


# -------------------------------------------------------------------------------------- names

def offered_base(config=None):
    """The base shown on the website-creation page, or '' when the service is off."""
    config = config or load_config()
    if not config.get('enabled') or not config.get('base'):
        return ''
    if config['provider'] == 'powerdns':
        try:
            make_provider(config).zone()
        except Exception:
            return ''
    return config['base']


def split(fqdn, config=None):
    """(label, base) when `fqdn` is a name under the configured base, else None."""
    config = config or load_config()
    base = config.get('base') or ''
    fqdn = (fqdn or '').strip().lower().rstrip('.')
    if not base or not fqdn.endswith('.' + base):
        return None
    return fqdn[:-(len(base) + 1)], base


def clean_label(label, config=None):
    config = config or load_config()
    label = (label or '').strip().lower()
    if not LABEL_MIN <= len(label) <= LABEL_MAX:
        raise FreeSubdomainError('The subdomain name must be %d to %d characters.' % (LABEL_MIN, LABEL_MAX))
    if not LABEL_RE.match(label):
        raise FreeSubdomainError('Use lower-case letters, digits and hyphens only (no dots, and no hyphen at '
                                 'the start or end).')
    if '--' in label:
        raise FreeSubdomainError('The subdomain name cannot contain two hyphens in a row.')
    if label in RESERVED or label in set(config.get('extra_reserved') or ()):
        raise FreeSubdomainError('%s is reserved. Choose another name.' % label)
    return label


def _model():
    from freeSubdomains.models import FreeSubdomain
    return FreeSubdomain


def _site_exists(domain):
    try:
        from websiteFunctions.models import ChildDomains, Websites
        return Websites.objects.filter(domain=domain).exists() or ChildDomains.objects.filter(domain=domain).exists()
    except Exception:
        return False


def availability(label, config=None):
    """(fqdn, None) when free, else (fqdn or None, reason)."""
    config = config or load_config()
    try:
        label = clean_label(label, config)
    except FreeSubdomainError as exc:
        return None, str(exc)
    fqdn = '%s.%s' % (label, config['base'])
    if _model().objects.filter(fqdn=fqdn).exists() or _site_exists(fqdn):
        return fqdn, '%s is already taken.' % fqdn
    return fqdn, None


def reserve(fqdn, owner_id, owner_name, created_by_id, is_admin=False, config=None):
    """Create the DNS records for `fqdn` (a name under the base) and record its owner.

    Idempotent for a retry by the same owner while no site uses the name yet.
    """
    from django.db import IntegrityError, transaction
    config = config or load_config()
    if not config.get('enabled'):
        raise FreeSubdomainError('Free subdomains are turned off on this server.')
    parts = split(fqdn, config)
    if parts is None:
        raise FreeSubdomainError('%s is not under %s.' % (fqdn, config.get('base')))
    label = clean_label(parts[0], config)
    fqdn = '%s.%s' % (label, config['base'])
    Model = _model()
    existing = Model.objects.filter(fqdn=fqdn).first()
    if existing is not None:
        if existing.owner_id == owner_id and not _site_exists(fqdn):
            return existing
        raise FreeSubdomainError('%s is already taken.' % fqdn)
    if _site_exists(fqdn):
        raise FreeSubdomainError('%s is already taken.' % fqdn)
    limit = config.get('per_user_limit') or 0
    if not is_admin and limit and Model.objects.filter(owner_id=owner_id).count() >= limit:
        raise FreeSubdomainError('This account already has %d free subdomains, the most allowed.' % limit)
    ipv4, ipv6 = addresses(config)
    if not ipv4:
        raise FreeSubdomainError('This server has no IPv4 address configured for free subdomains.')
    try:
        with transaction.atomic():
            row = Model.objects.create(label=label, base=config['base'], fqdn=fqdn, site=fqdn, owner_id=owner_id,
                                       owner_name=owner_name or '', created_by_id=created_by_id,
                                       provider=config['provider'])
    except IntegrityError:
        raise FreeSubdomainError('%s is already taken.' % fqdn)
    try:
        refs = make_provider(config).create(fqdn, ipv4, ipv6, config['ttl'])
    except Exception as exc:
        row.delete()
        if isinstance(exc, ProviderError):
            raise FreeSubdomainError('Could not create the DNS record: %s' % exc)
        raise FreeSubdomainError('Could not create the DNS record for %s.' % fqdn)
    row.refs = json.dumps(refs)
    row.save(update_fields=['refs'])
    return row


def _remove(row):
    config = load_config()
    config['provider'] = row.provider
    config['base'] = row.base
    try:
        make_provider(config).delete(row.fqdn, json.loads(row.refs or '{}'))
    except ProviderError as exc:
        raise FreeSubdomainError('Could not delete the DNS record: %s' % exc)
    row.delete()


def release(fqdn, requester_id, is_admin=False):
    """Delete the records of a free subdomain: only its owner, its creator or an administrator."""
    row = _model().objects.filter(fqdn=(fqdn or '').strip().lower()).first()
    if row is None:
        raise FreeSubdomainError('%s is not a free subdomain on this server.' % fqdn)
    if not (is_admin or requester_id in (row.owner_id, row.created_by_id)):
        raise PermissionError('You can only release your own free subdomains.')
    if _site_exists(row.fqdn):
        raise FreeSubdomainError('%s is still used by a website. Delete the website instead.' % row.fqdn)
    _remove(row)


def site_deleted(domain):
    """Called after a website or child domain was deleted (ownership already checked by the caller)."""
    row = _model().objects.filter(site=(domain or '').strip().lower()).first()
    if row is None or _site_exists(row.site):
        return False
    try:
        _remove(row)
    except Exception as exc:
        try:
            from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter
            CyberCPLogFileWriter.writeToFile('Free subdomain %s: %s' % (domain, exc))
        except Exception:
            pass
        return False
    return True


def listing():
    rows = []
    for row in _model().objects.all():
        rows.append({'fqdn': row.fqdn, 'site': row.site, 'owner': row.owner_name, 'provider': row.provider,
                     'created': row.created.isoformat() if row.created else '', 'in_use': _site_exists(row.site)})
    return rows


def creation_request(data, domain, config=None):
    """Does this website/child-domain creation request use a free subdomain?

    True for the website-creation page's "use a free subdomain" option and for any name under the
    configured base (API callers), so such names always get their DNS records and an owner.
    """
    config = config or load_config()
    flagged = str((data or {}).get('freeSubdomain', '')).strip().lower() in ('1', 'true', 'yes', 'on')
    if not config.get('enabled'):
        if flagged:
            raise FreeSubdomainError('Free subdomains are turned off on this server.')
        return False
    parts = split(domain, config)
    if parts is None:
        if flagged:
            raise FreeSubdomainError('%s is not under %s.' % (domain, config.get('base')))
        return False
    clean_label(parts[0], config)
    return True

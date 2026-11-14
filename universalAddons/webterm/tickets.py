"""Single-use, short-lived connection tickets for the web terminal (root side only).

The panel view asks the runner (root) to issue a ticket after it has checked the session, site
ownership and policy. The ticket is a 256-bit random token; only its SHA-256 is used as the file
name, so the root-only directory never holds the token itself. The websocket service consumes a
ticket exactly once: os.rename() claims the file atomically, so two connections racing with the
same ticket cannot both win. A claimed ticket is deleted whether or not it was still valid.
"""
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import time

TICKET_DIR = os.environ.get('UA_WEBTERM_TICKETS', '/var/lib/cyberpanel-universal/webterm/tickets')
TTL = 60
MAX_OUTSTANDING_PER_USER = 5
MAX_OUTSTANDING = 200
_TOKEN = re.compile(r'^[A-Za-z0-9_-]{43}$')
_NAME = re.compile(r'^[0-9a-f]{64}\.json$')


class TicketError(ValueError):
    pass


def address_key(address):
    """IPv4 by its /24, IPv6 by its /48 (IPv4-mapped IPv6 folded to IPv4).

    Mobile carriers (CGNAT) send a client's separate connections - the panel page on :8090 and
    the websocket on :443 - out through different public addresses of the same /24, so an exact
    IPv4 match refuses legitimate users. The ticket is still single-use, 60 s and origin-bound."""
    try:
        parsed = ipaddress.ip_address(str(address or '').strip())
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address):
        if parsed.ipv4_mapped:
            parsed = parsed.ipv4_mapped
        else:
            return str(ipaddress.ip_network('%s/48' % parsed, strict=False))
    return str(ipaddress.ip_network('%s/24' % parsed, strict=False))


def _ensure_dir(directory):
    os.makedirs(directory, mode=0o700, exist_ok=True)
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise TicketError('The ticket directory has unsafe ownership or permissions.')


def _path(token, directory):
    if not isinstance(token, str) or not _TOKEN.match(token):
        raise TicketError('Invalid ticket.')
    return os.path.join(directory, hashlib.sha256(token.encode('ascii')).hexdigest() + '.json')


def prune(directory=None, now=None):
    """Delete expired tickets; return the live ones' records (for the outstanding caps)."""
    directory = directory or TICKET_DIR
    now = time.time() if now is None else now
    live = []
    try:
        names = os.listdir(directory)
    except OSError:
        return live
    for name in names[:5000]:
        path = os.path.join(directory, name)
        if not _NAME.match(name):  # leftovers of a claim that crashed half-way
            try:
                if now - os.lstat(path).st_mtime > TTL:
                    os.unlink(path)
            except OSError:
                pass
            continue
        try:
            with open(path) as handle:
                record = json.load(handle)
            if record.get('expires', 0) <= now:
                os.unlink(path)
            else:
                live.append(record)
        except (OSError, ValueError):
            try:
                os.unlink(path)
            except OSError:
                pass
    return live


def issue(record, directory=None, now=None, ttl=TTL):
    """Store `record` (user_id, username, is_admin, domain, system_user, root, ip, host) under a
    new ticket and return the token. The caller has already validated every field."""
    directory = directory or TICKET_DIR
    now = time.time() if now is None else now
    if address_key(record.get('ip')) is None:
        raise TicketError('Unknown client address.')
    _ensure_dir(directory)
    live = prune(directory, now)
    if len(live) >= MAX_OUTSTANDING:
        raise TicketError('Too many terminal connections are being opened; try again in a minute.')
    if sum(1 for r in live if r.get('user_id') == record.get('user_id')) >= MAX_OUTSTANDING_PER_USER:
        raise TicketError('Too many unused terminal tickets; wait a minute and connect again.')
    token = secrets.token_urlsafe(32)
    data = dict(record, ip=address_key(record['ip']), issued=int(now), expires=now + ttl)
    fd = os.open(_path(token, directory), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle)
    return token


def consume(token, address, directory=None, now=None):
    """Claim a ticket once. Raises TicketError unless it exists, is unexpired and was issued to
    the same client address. Returns the stored record."""
    directory = directory or TICKET_DIR
    now = time.time() if now is None else now
    path = _path(token, directory)
    claimed = '%s.claimed-%d-%s' % (path, os.getpid(), secrets.token_hex(4))
    try:
        os.rename(path, claimed)
    except OSError:
        raise TicketError('Unknown or already used ticket.')
    try:
        fd = os.open(claimed, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise TicketError('Unknown or already used ticket.')
            record = json.load(handle)
    except (OSError, ValueError):
        raise TicketError('Unknown or already used ticket.')
    finally:
        try:
            os.unlink(claimed)
        except OSError:
            pass
    if not isinstance(record, dict) or record.get('expires', 0) <= now:
        raise TicketError('The ticket has expired; connect again.')
    if address is not None:  # None: proxied without a client-address header (see service.client_address)
        current = address_key(address)
        if current is None or current != record.get('ip'):
            raise TicketError('The ticket was issued to a different address.')
    return record

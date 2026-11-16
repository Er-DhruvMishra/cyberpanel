"""Outbound HTTP(S) and TCP for user-supplied targets, with SSRF protection.

Every request resolves the host name once, refuses the request when any resolved address is not a
public (global) address, and then connects to that very address: a DNS answer that changes between
the check and the connection (DNS rebinding) cannot send the request somewhere else. TLS still
verifies the certificate against the host name (SNI). Redirects are followed only on request, and
every hop is checked again. Administrators may additionally reach this server itself (loopback and
the server's own addresses) when `allow_local` is set; private ranges stay refused for everyone.
"""
import http.client
import ipaddress
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

MAX_BODY = 1024 * 1024
USER_AGENT = 'IndiansCloud-Monitor/1.0'


class GuardError(ValueError):
    pass


def server_addresses(path='/etc/cyberpanel/machineIP'):
    """Addresses of this server an administrator may monitor (loopback plus the panel's public IP)."""
    found = {ipaddress.ip_address('127.0.0.1'), ipaddress.ip_address('::1')}
    try:
        with open(path) as handle:
            found.add(ipaddress.ip_address(handle.read().split('\n', 1)[0].strip()))
    except (OSError, ValueError):
        pass
    return found


def _plain(address):
    address = ipaddress.ip_address(address)
    if address.version == 6 and address.ipv4_mapped:
        return address.ipv4_mapped
    if address.version == 6 and address.sixtofour:
        return address.sixtofour
    if address.version == 6 and address in ipaddress.ip_network('64:ff9b::/96'):   # NAT64
        return ipaddress.ip_address(int(address) & 0xffffffff)
    return address


def address_allowed(address, allow_local=False, local=None):
    """May a request go to `address`? Only global addresses, or this server's own for administrators."""
    address = _plain(address)
    if allow_local and address in {_plain(a) for a in (local if local is not None else server_addresses())}:
        return True
    if address.is_loopback or address.is_link_local or address.is_private or address.is_multicast \
            or address.is_reserved or address.is_unspecified:
        return False
    if address.version == 4 and address in ipaddress.ip_network('100.64.0.0/10'):   # carrier-grade NAT
        return False
    return address.is_global


def resolve(host, port, allow_local=False, resolver=socket.getaddrinfo, local=None):
    """Resolve once; return one allowed address to connect to, or raise GuardError."""
    if not host or len(host) > 253:
        raise GuardError('Invalid host.')
    try:
        infos = resolver(host, port, 0, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        raise GuardError('Cannot resolve %s (%s).' % (host, exc))
    addresses = []
    for info in infos:
        address = info[4][0].split('%', 1)[0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise GuardError('Cannot resolve %s.' % host)
    for address in addresses:
        if not address_allowed(address, allow_local, local):
            raise GuardError('%s resolves to %s, a private, loopback or link-local address; it cannot be '
                             'checked from IndiansCloud.' % (host, address))
    return addresses[0]


def split_url(url):
    parts = urlsplit(url or '')
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise GuardError('Enter an http:// or https:// URL.')
    if parts.username or parts.password:
        raise GuardError('URLs with a user name or password are not supported.')
    try:
        port = parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError:
        raise GuardError('Invalid port in the URL.')
    path = parts.path or '/'
    if parts.query:
        path += '?' + parts.query
    return parts.scheme, parts.hostname.lower().rstrip('.'), port, path


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address
        self._ctx = context

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


def cert_expiry(sock):
    """Unix time the peer certificate expires, or None."""
    try:
        cert = sock.getpeercert()
        return int(ssl.cert_time_to_seconds(cert['notAfter'])) if cert and cert.get('notAfter') else None
    except (ValueError, KeyError, AttributeError):
        return None


def request(url, method='GET', body=None, headers=None, timeout=10, allow_local=False, max_redirects=0,
            read_limit=MAX_BODY, resolver=socket.getaddrinfo, connection_factory=None, local=None):
    """One guarded HTTP(S) request. Returns {status, headers, body, ms, cert_expires, url}."""
    headers = dict(headers or {})
    headers.setdefault('User-Agent', USER_AGENT)
    started = time.monotonic()
    for hop in range(max_redirects + 1):
        scheme, host, port, path = split_url(url)
        address = resolve(host, port, allow_local, resolver, local)
        if connection_factory is not None:
            conn = connection_factory(scheme, host, port, address, timeout)
        elif scheme == 'https':
            conn = _PinnedHTTPS(host, port, address, timeout, ssl.create_default_context())
        else:
            conn = _PinnedHTTP(host, port, address, timeout)
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            expires = cert_expiry(conn.sock) if scheme == 'https' else None
            data = response.read(read_limit)
            status, location = response.status, response.getheader('Location')
            response_headers = dict(response.getheaders())
        except ssl.SSLError as exc:
            raise GuardError('TLS error: %s' % (getattr(exc, 'reason', None) or exc))
        except (OSError, http.client.HTTPException) as exc:
            raise GuardError('%s: %s' % (type(exc).__name__, exc))
        finally:
            conn.close()
        if status in (301, 302, 303, 307, 308) and location and hop < max_redirects:
            url = urljoin(url, location)
            if status == 303:
                method, body = 'GET', None
            continue
        return {'status': status, 'headers': response_headers, 'body': data, 'url': url,
                'ms': int((time.monotonic() - started) * 1000), 'cert_expires': expires}
    raise GuardError('Too many redirects.')


def tcp_check(host, port, timeout=10, allow_local=False, resolver=socket.getaddrinfo, connect=None, local=None):
    """Connect to host:port (guarded). Returns milliseconds taken."""
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise GuardError('Invalid port.')
    address = resolve((host or '').lower().rstrip('.'), port, allow_local, resolver, local)
    started = time.monotonic()
    try:
        sock = (connect or socket.create_connection)((address, port), timeout)
        sock.close()
    except OSError as exc:
        raise GuardError('TCP %s:%d: %s' % (host, port, exc))
    return int((time.monotonic() - started) * 1000)

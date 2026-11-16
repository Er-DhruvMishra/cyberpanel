"""Cloudflare API v4 client and input validation for the Cloudflare add-on.

Same style as freeSubdomains.providers.Cloudflare: server-side `requests`, fixed timeouts, no
redirects, Bearer token, and errors raised as CloudflareError with a message that is safe to show
(it never contains the token). Every value that reaches a URL path or a request body is checked
here first: zone and record ids are 32 hex characters, record types and setting names come from
whitelists, names must lie inside the zone.
"""
import ipaddress
import json
import re
from urllib.parse import urlsplit

API = 'https://api.cloudflare.com/client/v4'
GRAPHQL = API + '/graphql'
API_TIMEOUT = (5, 20)

ID_RE = re.compile(r'^[a-f0-9]{32}$')
TOKEN_RE = re.compile(r'^[A-Za-z0-9_\-]{30,200}$')
LABEL_RE = re.compile(r'^(?:\*|_?[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?|_[a-z0-9_-]{1,62})$')
HOST_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
COUNTRY_RE = re.compile(r'^(?:[A-Z]{2}|T1|XX)$')

RECORD_TYPES = ('A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV', 'CAA')
PROXIABLE = ('A', 'AAAA', 'CNAME')
CAA_TAGS = ('issue', 'issuewild', 'iodef')
MAX_PURGE_URLS = 30

# Zone settings this add-on reads and changes, with the values each accepts.
ON_OFF = ('on', 'off')
SETTINGS = {
    # cache
    'development_mode': ON_OFF,
    'cache_level': ('basic', 'simplified', 'aggressive'),
    'browser_cache_ttl': (0, 30, 60, 120, 300, 1200, 1800, 3600, 7200, 10800, 14400, 18000, 28800, 43200, 57600,
                          72000, 86400, 172800, 259200, 345600, 432000, 691200, 1382400, 2073600, 2678400, 5356800,
                          16070400, 31536000),
    'always_online': ON_OFF,
    # SSL/TLS
    'ssl': ('off', 'flexible', 'full', 'strict'),
    'always_use_https': ON_OFF,
    'min_tls_version': ('1.0', '1.1', '1.2', '1.3'),
    'automatic_https_rewrites': ON_OFF,
    # security
    'security_level': ('essentially_off', 'low', 'medium', 'high', 'under_attack'),
    'browser_check': ON_OFF,
    # speed
    'brotli': ON_OFF,
    'rocket_loader': ON_OFF,
    'early_hints': ON_OFF,
    'http3': ON_OFF,
}
SETTING_GROUPS = {
    'cache': ('development_mode', 'cache_level', 'browser_cache_ttl', 'always_online'),
    'ssl': ('ssl', 'always_use_https', 'min_tls_version', 'automatic_https_rewrites'),
    'security': ('security_level', 'browser_check'),
    'speed': ('brotli', 'rocket_loader', 'early_hints', 'http3'),
}
ACCESS_MODES = {'block': 'block', 'challenge': 'managed_challenge', 'allow': 'whitelist'}
ANALYTICS_RANGES = {'24h': 1, '7d': 7, '30d': 30}

# What a scoped token needs, shown on the page (Cloudflare dashboard names).
TOKEN_PERMISSIONS = (
    ('Zone', 'Zone', 'Read', 'list zones, status, plan and name servers'),
    ('Zone', 'DNS', 'Edit', 'DNS records, import and "point to this server"'),
    ('Zone', 'Cache Purge', 'Purge', 'purge everything or by URL'),
    ('Zone', 'Zone Settings', 'Edit', 'cache, SSL/TLS, security and speed settings'),
    ('Zone', 'Analytics', 'Read', 'traffic charts'),
    ('Zone', 'Firewall Services', 'Edit', 'IP access rules (only if you use them)'),
    ('Zone', 'SSL and Certificates', 'Edit', 'Origin CA certificate (optional)'),
)


class CloudflareError(ValueError):
    """A failure the user can act on; the message is safe to show."""

    def __init__(self, message, status=None, retry_after=None):
        super().__init__(message)
        self.status, self.retry_after = status, retry_after


# ----------------------------------------------------------------------------------- validation

def zone_id(value):
    value = str(value or '').strip().lower()
    if not ID_RE.match(value):
        raise CloudflareError('Invalid zone id.')
    return value


def record_id(value):
    value = str(value or '').strip().lower()
    if not ID_RE.match(value):
        raise CloudflareError('Invalid record id.')
    return value


def token(value):
    value = str(value or '').strip()
    if not TOKEN_RE.match(value):
        raise CloudflareError('That does not look like a Cloudflare API token (letters, digits, - and _ only, '
                              'usually 40 characters). Global API keys are not supported; create a scoped token.')
    return value


def hostname(value, what='host name'):
    value = str(value or '').strip().lower().rstrip('.')
    if not HOST_RE.match(value):
        raise CloudflareError('Invalid %s.' % what)
    return value


def record_name(value, zone_name):
    """'@', a name relative to the zone, or a full name inside it -> the full name."""
    zone_name = hostname(zone_name, 'zone name')
    value = str(value or '').strip().lower().rstrip('.')
    if value in ('', '@'):
        return zone_name
    if value != zone_name and not value.endswith('.' + zone_name):
        value = value + '.' + zone_name
    if len(value) > 253:
        raise CloudflareError('The name is too long.')
    relative = value[:-len(zone_name)].rstrip('.')
    labels = relative.split('.') if relative else []
    for index, label in enumerate(labels):
        if not LABEL_RE.match(label) or (label == '*' and index != 0):
            raise CloudflareError('Invalid record name %s.' % value)
    return value


def _ttl(value):
    try:
        value = int(value if value not in (None, '') else 1)
    except (TypeError, ValueError):
        raise CloudflareError('TTL must be a number.')
    if value != 1 and not 60 <= value <= 86400:
        raise CloudflareError('TTL must be 1 (automatic) or 60-86400 seconds.')
    return value


def _int(value, low, high, what):
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise CloudflareError('%s must be a number.' % what)
    if not low <= value <= high:
        raise CloudflareError('%s must be between %d and %d.' % (what, low, high))
    return value


def validate_record(raw, zone_name):
    """Clean a DNS record from the page into a Cloudflare request body."""
    if not isinstance(raw, dict):
        raise CloudflareError('Invalid record.')
    rtype = str(raw.get('type', '')).upper()
    if rtype not in RECORD_TYPES:
        raise CloudflareError('Record type must be one of %s.' % ', '.join(RECORD_TYPES))
    name = record_name(raw.get('name'), zone_name)
    body = {'type': rtype, 'name': name, 'ttl': _ttl(raw.get('ttl'))}
    content = str(raw.get('content', '')).strip()
    if rtype == 'A':
        try:
            body['content'] = str(ipaddress.IPv4Address(content))
        except ValueError:
            raise CloudflareError('An A record needs an IPv4 address.')
    elif rtype == 'AAAA':
        try:
            body['content'] = str(ipaddress.IPv6Address(content))
        except ValueError:
            raise CloudflareError('An AAAA record needs an IPv6 address.')
    elif rtype == 'CNAME':
        body['content'] = hostname(content, 'CNAME target')
    elif rtype == 'TXT':
        if not content or len(content) > 2048 or any(ord(c) < 32 or ord(c) == 127 for c in content):
            raise CloudflareError('TXT content must be 1-2048 printable characters on one line.')
        body['content'] = content
    elif rtype == 'MX':
        body['content'] = hostname(content, 'mail server')
        body['priority'] = _int(raw.get('priority', 10), 0, 65535, 'Priority')
    elif rtype == 'SRV':
        first = name.split('.')
        if len(first) < 3 or not first[0].startswith('_') or first[1] not in ('_tcp', '_udp', '_tls'):
            raise CloudflareError('An SRV name looks like _service._tcp.example.com.')
        target = str(raw.get('target', '')).strip().lower().rstrip('.')
        body['data'] = {'priority': _int(raw.get('priority', 10), 0, 65535, 'Priority'),
                        'weight': _int(raw.get('weight', 5), 0, 65535, 'Weight'),
                        'port': _int(raw.get('port'), 0, 65535, 'Port'),
                        'target': '.' if target in ('', '.') else hostname(target, 'SRV target')}
    elif rtype == 'CAA':
        tag = str(raw.get('tag', 'issue')).strip().lower()
        if tag not in CAA_TAGS:
            raise CloudflareError('CAA tag must be issue, issuewild or iodef.')
        value = str(raw.get('value', content)).strip()
        if not value or len(value) > 255 or not re.match(r'^[\x21-\x7e]+$', value) or '"' in value:
            raise CloudflareError('Invalid CAA value.')
        body['data'] = {'flags': _int(raw.get('flags', 0), 0, 255, 'Flags'), 'tag': tag, 'value': value}
    if rtype in PROXIABLE:
        body['proxied'] = raw.get('proxied') is True
        if body['proxied']:
            body['ttl'] = 1
    comment = str(raw.get('comment', '') or '').strip()
    if comment:
        if len(comment) > 100 or any(ord(c) < 32 for c in comment):
            raise CloudflareError('The comment must be at most 100 characters on one line.')
        body['comment'] = comment
    return body


def validate_setting(key, value):
    if key not in SETTINGS:
        raise CloudflareError('Unknown setting.')
    allowed = SETTINGS[key]
    if key == 'browser_cache_ttl':
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise CloudflareError('Invalid browser cache TTL.')
    else:
        value = str(value)
    if value not in allowed:
        raise CloudflareError('Invalid value for %s.' % key.replace('_', ' '))
    return value


def validate_purge_urls(urls, zone_name):
    if not isinstance(urls, list) or not urls:
        raise CloudflareError('Enter one or more URLs.')
    if len(urls) > MAX_PURGE_URLS:
        raise CloudflareError('Cloudflare accepts at most %d URLs per purge.' % MAX_PURGE_URLS)
    zone_name = hostname(zone_name, 'zone name')
    clean = []
    for url in urls:
        url = str(url or '').strip()
        parts = urlsplit(url)
        host = (parts.hostname or '').lower()
        if parts.scheme not in ('http', 'https') or len(url) > 2048 or any(c.isspace() for c in url) or \
                parts.username or parts.password or not (host == zone_name or host.endswith('.' + zone_name)):
            raise CloudflareError('%s is not an http(s) URL on %s.' % (url[:80], zone_name))
        clean.append(url)
    return clean


def validate_access_rule(raw):
    if not isinstance(raw, dict):
        raise CloudflareError('Invalid rule.')
    mode = ACCESS_MODES.get(str(raw.get('mode', '')))
    if not mode:
        raise CloudflareError('Choose block, challenge or allow.')
    value = str(raw.get('value', '')).strip()
    if COUNTRY_RE.match(value.upper()) and len(value) == 2:   # no address is two characters long
        target = {'target': 'country', 'value': value.upper()}
    else:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise CloudflareError('Enter an IPv4/IPv6 address, a range (CIDR) or a two-letter country code.')
        if '/' in value and network.num_addresses > 1:
            if (network.version == 4 and network.prefixlen not in (16, 24)) or \
                    (network.version == 6 and network.prefixlen not in (32, 48, 64)):
                raise CloudflareError('Cloudflare accepts IPv4 ranges /16 or /24 and IPv6 ranges /32, /48 or /64.')
            target = {'target': 'ip_range' if network.version == 4 else 'ip6_range', 'value': str(network)}
        else:
            target = {'target': 'ip' if network.version == 4 else 'ip6', 'value': str(network.network_address)}
    note = str(raw.get('notes', '') or '').strip()
    if len(note) > 200 or any(ord(c) < 32 for c in note):
        raise CloudflareError('The note must be at most 200 characters on one line.')
    return {'mode': mode, 'configuration': target, 'notes': note or 'Added from IndiansCloud'}


# ------------------------------------------------------------------------------------- GraphQL

ANALYTICS_FIELDS = ('requests cachedRequests bytes cachedBytes threats pageViews '
                    'countryMap { clientCountryName requests threats }')


def analytics_query(zone, range_key, now=None):
    """GraphQL query and variables for traffic over 24h (hourly groups) or 7d/30d (daily groups).

    Both datasets are available on the Free plan. Returns (query, variables).
    """
    import datetime
    zone = zone_id(zone)
    if range_key not in ANALYTICS_RANGES:
        raise CloudflareError('Choose 24h, 7d or 30d.')
    now = now or datetime.datetime.utcnow()
    if range_key == '24h':
        end = now.replace(minute=0, second=0, microsecond=0) + datetime.timedelta(hours=1)
        start = end - datetime.timedelta(hours=24)
        query = ('query IndiansCloudTraffic($zoneTag: string, $start: Time, $end: Time) { viewer { '
                 'zones(filter: {zoneTag: $zoneTag}) { series: httpRequests1hGroups(limit: 24, '
                 'filter: {datetime_geq: $start, datetime_lt: $end}, orderBy: [datetime_ASC]) { '
                 'dimensions { when: datetime } sum { %s } uniq { uniques } } } } }' % ANALYTICS_FIELDS)
        variables = {'zoneTag': zone, 'start': start.strftime('%Y-%m-%dT%H:%M:%SZ'),
                     'end': end.strftime('%Y-%m-%dT%H:%M:%SZ')}
    else:
        days = ANALYTICS_RANGES[range_key]
        end = now.date()
        start = end - datetime.timedelta(days=days - 1)
        query = ('query IndiansCloudTraffic($zoneTag: string, $start: Date, $end: Date) { viewer { '
                 'zones(filter: {zoneTag: $zoneTag}) { series: httpRequests1dGroups(limit: %d, '
                 'filter: {date_geq: $start, date_leq: $end}, orderBy: [date_ASC]) { '
                 'dimensions { when: date } sum { %s } uniq { uniques } } } } }' % (days, ANALYTICS_FIELDS))
        variables = {'zoneTag': zone, 'start': start.isoformat(), 'end': end.isoformat()}
    return query, variables


def summarize_analytics(data):
    """Turn the GraphQL answer into chart series and totals for the page."""
    zones = (((data or {}).get('viewer') or {}).get('zones') or [])
    groups = (zones[0].get('series') if zones else None) or []
    series, countries = [], {}
    totals = dict.fromkeys(('requests', 'cachedRequests', 'bytes', 'cachedBytes', 'threats', 'pageViews', 'uniques'), 0)
    for group in groups:
        total = group.get('sum') or {}
        row = {'when': (group.get('dimensions') or {}).get('when'),
               'uniques': int((group.get('uniq') or {}).get('uniques') or 0)}
        for key in ('requests', 'cachedRequests', 'bytes', 'cachedBytes', 'threats', 'pageViews'):
            row[key] = int(total.get(key) or 0)
        for key in totals:
            totals[key] += row[key]
        series.append(row)
        for country in total.get('countryMap') or []:
            name = country.get('clientCountryName') or 'XX'
            entry = countries.setdefault(name, {'country': name, 'requests': 0, 'threats': 0})
            entry['requests'] += int(country.get('requests') or 0)
            entry['threats'] += int(country.get('threats') or 0)
    totals['uncachedRequests'] = totals['requests'] - totals['cachedRequests']
    totals['uncachedBytes'] = totals['bytes'] - totals['cachedBytes']
    top = sorted(countries.values(), key=lambda c: -c['requests'])[:10]
    return {'series': series, 'totals': totals, 'countries': top}


# --------------------------------------------------------------------------------------- client

def _requests():
    import requests
    return requests


class Client:
    """One Cloudflare API token. `http` is a requests-like object (mocked in tests)."""

    def __init__(self, api_token, http=None):
        self.token = api_token
        self.http = http

    def _send(self, method, url, **kwargs):
        if not self.token:
            raise CloudflareError('Save a Cloudflare API token first.')
        http = self.http or _requests()
        try:
            return http.request(method, url, timeout=API_TIMEOUT, allow_redirects=False,
                                headers={'Authorization': 'Bearer ' + self.token,
                                         'Content-Type': 'application/json'}, **kwargs)
        except Exception as exc:
            raise CloudflareError('Could not reach Cloudflare: %s' % type(exc).__name__)

    @staticmethod
    def _rate_limited(response):
        if response.status_code == 429:
            try:
                wait = int(response.headers.get('Retry-After', '60') or 60)
            except (TypeError, ValueError):
                wait = 60
            raise CloudflareError('Cloudflare rate limit reached; try again in %d seconds.' % wait,
                                  status=429, retry_after=wait)

    def call(self, method, path, params=None, body=None, full=False):
        response = self._send(method, API + path, params=params,
                              data=json.dumps(body) if body is not None else None)
        self._rate_limited(response)
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        if response.status_code >= 300 or not payload.get('success', False):
            errors = '; '.join(str(e.get('message', ''))[:200] for e in payload.get('errors') or []
                               if isinstance(e, dict))
            if response.status_code in (401, 403) and not errors:
                errors = 'the token lacks the permission for this action'
            raise CloudflareError('Cloudflare refused the request (HTTP %s)%s' % (
                response.status_code, ': ' + errors if errors else '.'), status=response.status_code)
        return payload if full else payload.get('result')

    def graphql(self, query, variables):
        response = self._send('POST', GRAPHQL, data=json.dumps({'query': query, 'variables': variables}))
        self._rate_limited(response)
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        errors = (payload or {}).get('errors') if isinstance(payload, dict) else None
        if response.status_code >= 300 or errors:
            message = '; '.join(str(e.get('message', ''))[:200] for e in errors or [] if isinstance(e, dict))
            raise CloudflareError('Cloudflare analytics refused the query (HTTP %s)%s' % (
                response.status_code, ': ' + message if message else '.'), status=response.status_code)
        return (payload or {}).get('data') or {}

    # -- requests used by the views (kept here so tests can check exactly what is sent)

    def verify(self):
        return self.call('GET', '/user/tokens/verify')

    def zones(self):
        found, page = [], 1
        while page <= 10:   # up to 500 zones
            payload = self.call('GET', '/zones', params={'per_page': 50, 'page': page}, full=True)
            found.extend(payload.get('result') or [])
            info = payload.get('result_info') or {}
            if page >= int(info.get('total_pages') or 1):
                break
            page += 1
        return found

    def zone(self, zone):
        return self.call('GET', '/zones/%s' % zone_id(zone))

    def dns_records(self, zone):
        found, page = [], 1
        while page <= 20:
            payload = self.call('GET', '/zones/%s/dns_records' % zone_id(zone),
                                params={'per_page': 100, 'page': page}, full=True)
            found.extend(payload.get('result') or [])
            info = payload.get('result_info') or {}
            if page >= int(info.get('total_pages') or 1):
                break
            page += 1
        return found

    def dns_create(self, zone, body):
        return self.call('POST', '/zones/%s/dns_records' % zone_id(zone), body=body)

    def dns_update(self, zone, rid, body):
        return self.call('PUT', '/zones/%s/dns_records/%s' % (zone_id(zone), record_id(rid)), body=body)

    def dns_patch(self, zone, rid, body):
        return self.call('PATCH', '/zones/%s/dns_records/%s' % (zone_id(zone), record_id(rid)), body=body)

    def dns_delete(self, zone, rid):
        return self.call('DELETE', '/zones/%s/dns_records/%s' % (zone_id(zone), record_id(rid)))

    def purge(self, zone, urls=None):
        body = {'files': urls} if urls else {'purge_everything': True}
        return self.call('POST', '/zones/%s/purge_cache' % zone_id(zone), body=body)

    def settings(self, zone):
        return self.call('GET', '/zones/%s/settings' % zone_id(zone))

    def set_setting(self, zone, key, value):
        value = validate_setting(key, value)
        return self.call('PATCH', '/zones/%s/settings/%s' % (zone_id(zone), key), body={'value': value})

    def access_rules(self, zone):
        return self.call('GET', '/zones/%s/firewall/access_rules/rules' % zone_id(zone),
                         params={'per_page': 100})

    def access_rule_add(self, zone, rule):
        return self.call('POST', '/zones/%s/firewall/access_rules/rules' % zone_id(zone), body=rule)

    def access_rule_delete(self, zone, rid):
        return self.call('DELETE', '/zones/%s/firewall/access_rules/rules/%s' % (zone_id(zone), record_id(rid)))

    def analytics(self, zone, range_key):
        query, variables = analytics_query(zone, range_key)
        return summarize_analytics(self.graphql(query, variables))

    def origin_certificate(self, hostnames, csr, days=5475):
        return self.call('POST', '/certificates', body={
            'hostnames': hostnames, 'csr': csr, 'request_type': 'origin-ecc', 'requested_validity': days})

"""DNS tools: DNSSEC through pdnsutil, and editable DNS templates for new zones.

Plain logic shared by actions.py, views.py, plogical/dnsUtilities.py (dnsTemplate) and the tests.
Importing this module needs only the standard library: dnsTemplate() calls it while a website is
being created, so it must never fail on import.

Templates
  * Stored in TEMPLATES_FILE (root writes it through the runner; mode 0644, nothing secret):
    {"version": 1, "ipv6": "", "default": <template or null>, "resellers": {"<admin id>": <template>}}
  * A template is {"records": [{"name", "type", "content", "ttl", "prio"}...]}. Names are relative
    to the zone ("@", "www", "_dmarc") or contain {domain}. Placeholders: {domain} {ip} {ipv6}
    {hostname} {ns1} {ns2}. Records that use {ipv6} are skipped while no IPv6 address is set.
  * New zones use the template of the account's reseller (or the reseller's own one), else the
    administrator's default, else the panel's fixed records (no template saved = unchanged).
"""
import ipaddress
import json
import re
import socket

TEMPLATES_FILE = '/etc/cyberpanel/universal-dns-templates.json'
NAMESERVERS_FILE = '/home/cyberpanel/defaultNameservers'
MACHINE_IP_FILE = '/etc/cyberpanel/machineIP'
PDNS_CONF = '/etc/pdns/pdns.conf'
PDNSUTIL = '/usr/bin/pdnsutil'

TYPES = ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA')
PLACEHOLDERS = ('domain', 'ip', 'ipv6', 'hostname', 'ns1', 'ns2')
MAX_RECORDS = 60
ZONE_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
HOST_RE = re.compile(r'^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$')
LABEL_NAME_RE = re.compile(r'^(@|\*|(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_.-]{0,200}[A-Za-z0-9_])?)$')
_PLACEHOLDER = re.compile(r'\{([a-z0-9]+)\}')
_CAA = re.compile(r'^(0|128) (issue|issuewild|iodef) "[^"\\\x00-\x1f]{0,255}"$')
_SRV = re.compile(r'^(\d{1,5}) (\d{1,5}) (\S+)$')


class DNSToolsError(ValueError):
    pass


def check_zone(zone):
    zone = str(zone or '').strip().lower().rstrip('.')
    if not ZONE_RE.match(zone):
        raise DNSToolsError('Invalid zone name.')
    return zone


# ----------------------------------------------------------------------------- PowerDNS configuration

def parse_pdns_conf(text):
    values = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, value = line.partition('=')
        values[key.strip()] = value.split('#')[0].strip()
    return values


def _yes(value):
    return str(value or '').strip().lower() in ('yes', 'true', '1', 'on')


def dnssec_support(conf):
    """(ok, problems, facts) for running DNSSEC with this pdns.conf. Secrets are never returned."""
    backends = [b.strip().split(':')[0] for b in conf.get('launch', '').split(',') if b.strip()]
    problems = []
    if not backends:
        problems.append('pdns.conf has no launch= backend.')
    for backend in backends:
        if backend in ('gmysql', 'gpgsql', 'godbc'):
            if not _yes(conf.get('%s-dnssec' % backend)):
                problems.append('The %s backend has DNSSEC off: add "%s-dnssec=yes" to /etc/pdns/pdns.conf, make sure '
                                'the cryptokeys and domainmetadata tables exist, then restart pdns.' % (backend, backend))
        elif backend == 'bind' and not conf.get('bind-dnssec-db'):
            problems.append('The bind backend needs bind-dnssec-db set for DNSSEC.')
    facts = {'backends': backends, 'api': _yes(conf.get('api')) and bool(conf.get('api-key')),
             'webserver_open': _yes(conf.get('webserver')) and conf.get('webserver-allow-from', '').replace(' ', '')
             in ('0.0.0.0/0', '0.0.0.0/0,::/0', '::/0,0.0.0.0/0')}
    return not problems, problems, facts


# ----------------------------------------------------------------------------- pdnsutil output

_DS = re.compile(r'^DS = (\S+) IN DS (\d+) (\d+) (\d+) ([0-9A-Fa-f]+)\s*;?\s*(?:\(\s*([^)]*?)\s*\))?')
_DNSKEY = re.compile(r'^(?:\w+ )?DNSKEY = (\S+) IN DNSKEY (\d+) (\d+) (\d+) (\S+)')
_KEY = re.compile(r'^ID = (\d+) \((\w+)\), flags = (\d+), tag = (\d+), algo = (\d+), bits = (\d+)\s*(.*)$')


def parse_show_zone(text):
    """What `pdnsutil show-zone <zone>` says: secured or not, keys, DNSKEY and DS records."""
    out = {'secured': False, 'keys': [], 'ds': [], 'dnskey': [], 'nsec': None, 'raw': (text or '')[-4000:]}
    for raw in (text or '').splitlines():
        line = raw.strip()
        if 'not actively secured' in line:
            out['secured'] = False
        if line.startswith('Zone has NSEC3'):
            out['nsec'] = 'NSEC3'
        elif line.startswith('Zone has NSEC'):
            out['nsec'] = 'NSEC'
        key = _KEY.match(line)
        if key:
            out['keys'].append({'id': int(key.group(1)), 'type': key.group(2), 'flags': int(key.group(3)),
                                'tag': int(key.group(4)), 'algorithm': int(key.group(5)), 'bits': int(key.group(6)),
                                'active': 'Active' in key.group(7) and 'Inactive' not in key.group(7)})
            continue
        ds = _DS.match(line)
        if ds:
            out['ds'].append({'owner': ds.group(1), 'tag': int(ds.group(2)), 'algorithm': int(ds.group(3)),
                              'digest_type': int(ds.group(4)), 'digest': ds.group(5).upper(),
                              'note': (ds.group(6) or '').strip(),
                              'record': '%s IN DS %s %s %s %s' % (ds.group(1), ds.group(2), ds.group(3), ds.group(4),
                                                                   ds.group(5).upper())})
            continue
        dnskey = _DNSKEY.match(line)
        if dnskey:
            out['dnskey'].append({'owner': dnskey.group(1), 'flags': int(dnskey.group(2)),
                                  'protocol': int(dnskey.group(3)), 'algorithm': int(dnskey.group(4)),
                                  'key': dnskey.group(5)})
    out['secured'] = bool(out['keys']) and any(k['active'] for k in out['keys'])
    # Registrars want SHA-256 (digest type 2); keep it first, drop SHA-1 (type 1) from the suggestion.
    out['ds'].sort(key=lambda d: (d['digest_type'] != 2, d['digest_type']))
    out['recommended_ds'] = [d for d in out['ds'] if d['digest_type'] == 2]
    return out


def pdnsutil_argv(op, zone):
    zone = check_zone(zone)
    ops = {'show': ['show-zone', zone], 'secure': ['secure-zone', zone], 'rectify': ['rectify-zone', zone],
           'disable': ['disable-dnssec', zone], 'check': ['check-zone', zone]}
    if op not in ops:
        raise DNSToolsError('Unknown DNSSEC operation.')
    return [PDNSUTIL] + ops[op]


# ----------------------------------------------------------------------------- templates

DEFAULT_RECORDS = [   # what the panel's fixed dnsTemplate() creates, as a starting point for editing
    {'name': '@', 'type': 'A', 'content': '{ip}', 'ttl': 3600, 'prio': 0},
    {'name': 'www', 'type': 'CNAME', 'content': '{domain}', 'ttl': 3600, 'prio': 0},
    {'name': 'ftp', 'type': 'CNAME', 'content': '{domain}', 'ttl': 3600, 'prio': 0},
    {'name': '@', 'type': 'MX', 'content': '{domain}', 'ttl': 3600, 'prio': 10},
    {'name': '@', 'type': 'TXT', 'content': 'v=spf1 a mx ip4:{ip} ~all', 'ttl': 3600, 'prio': 0},
    {'name': '_dmarc', 'type': 'TXT', 'content': 'v=DMARC1; p=none;', 'ttl': 3600, 'prio': 0},
    {'name': '_domainkey', 'type': 'TXT', 'content': 't=y; o=~;', 'ttl': 3600, 'prio': 0},
]


def _placeholders_ok(text, what):
    for name in _PLACEHOLDER.findall(text):
        if name not in PLACEHOLDERS:
            raise DNSToolsError('%s: unknown placeholder {%s}. Use %s.' % (
                what, name, ', '.join('{%s}' % p for p in PLACEHOLDERS)))
    stripped = _PLACEHOLDER.sub('', text)
    if '{' in stripped or '}' in stripped:
        raise DNSToolsError('%s: braces are only allowed around a placeholder.' % what)


def validate_template(template):
    """A clean template dict, or DNSToolsError. Contents are checked again after rendering."""
    if not isinstance(template, dict) or not isinstance(template.get('records'), list):
        raise DNSToolsError('A template is a list of records.')
    records = template['records']
    if not 1 <= len(records) <= MAX_RECORDS:
        raise DNSToolsError('A template has 1 to %d records.' % MAX_RECORDS)
    clean = []
    for number, record in enumerate(records, 1):
        what = 'Record %d' % number
        if not isinstance(record, dict):
            raise DNSToolsError('%s is not a record.' % what)
        rtype = str(record.get('type', '')).upper()
        if rtype not in TYPES:
            raise DNSToolsError('%s: type must be one of %s.' % (what, ', '.join(TYPES)))
        name = str(record.get('name', '')).strip() or '@'
        content = str(record.get('content', '')).strip()
        for value, label in ((name, 'name'), (content, 'content')):
            if '\x00' in value or '\n' in value or '\r' in value:
                raise DNSToolsError('%s: the %s must be a single line.' % (what, label))
            _placeholders_ok(value, '%s %s' % (what, label))
        if set(_PLACEHOLDER.findall(name)) - {'domain'}:
            raise DNSToolsError('%s: names may only use the {domain} placeholder.' % what)
        if not content or len(content) > 1000:
            raise DNSToolsError('%s: content is required (at most 1000 characters).' % what)
        if not LABEL_NAME_RE.match(_PLACEHOLDER.sub('x', name)):
            raise DNSToolsError('%s: invalid name %r.' % (what, name))
        try:
            ttl = int(record.get('ttl', 3600))
            prio = int(record.get('prio', 0) or 0)
        except (TypeError, ValueError):
            raise DNSToolsError('%s: TTL and priority are numbers.' % what)
        if not 60 <= ttl <= 604800:
            raise DNSToolsError('%s: TTL between 60 and 604800 seconds.' % what)
        if not 0 <= prio <= 65535:
            raise DNSToolsError('%s: priority between 0 and 65535.' % what)
        clean.append({'name': name, 'type': rtype, 'content': content, 'ttl': ttl,
                      'prio': prio if rtype in ('MX', 'SRV') else 0})
    # Render once with sample values so content errors show when saving, not at zone creation.
    render_template({'records': clean}, sample_values())
    return {'records': clean}


def sample_values(domain='example.com'):
    return {'domain': domain, 'ip': '192.0.2.10', 'ipv6': '2001:db8::10', 'hostname': 'server.example.net',
            'ns1': 'ns1.' + domain, 'ns2': 'ns2.' + domain}


def _fill(text, values):
    return _PLACEHOLDER.sub(lambda m: values.get(m.group(1), ''), text)


def _absolute(name, domain, values):
    if name == '@':
        return domain
    if '{domain}' in name:
        full = _fill(name, values)
    else:
        full = _fill(name, values) + '.' + domain
    full = full.lower().rstrip('.')
    if full != domain and not full.endswith('.' + domain):
        raise DNSToolsError('%s is outside the zone %s.' % (full, domain))
    return full


def _check_content(rtype, content, what):
    if rtype == 'A':
        try:
            ipaddress.IPv4Address(content)
        except ValueError:
            raise DNSToolsError('%s: %r is not an IPv4 address.' % (what, content))
    elif rtype == 'AAAA':
        try:
            ipaddress.IPv6Address(content)
        except ValueError:
            raise DNSToolsError('%s: %r is not an IPv6 address.' % (what, content))
    elif rtype in ('CNAME', 'MX'):
        if not HOST_RE.match(content):
            raise DNSToolsError('%s: %r is not a host name.' % (what, content))
    elif rtype == 'SRV':
        match = _SRV.match(content)
        if not match or int(match.group(1)) > 65535 or int(match.group(2)) > 65535 or \
                not (match.group(3) == '.' or HOST_RE.match(match.group(3))):
            raise DNSToolsError('%s: SRV content is "weight port target" (priority goes in its own field).' % what)
    elif rtype == 'CAA':
        if not _CAA.match(content):
            raise DNSToolsError('%s: CAA content looks like: 0 issue "letsencrypt.org".' % what)
    elif rtype == 'TXT':
        if any(ord(c) < 32 for c in content) or len(content) > 1000:
            raise DNSToolsError('%s: TXT text must be printable.' % what)


def render_template(template, values):
    """Records with every placeholder filled in, validated. {ipv6} records are skipped while
    there is no IPv6 address. Returns [{'name', 'type', 'content', 'ttl', 'prio'}]."""
    domain = check_zone(values.get('domain'))
    values = dict(values, domain=domain)
    out = []
    for number, record in enumerate(template.get('records', []), 1):
        what = 'Record %d (%s %s)' % (number, record.get('type'), record.get('name'))
        if not values.get('ipv6') and '{ipv6}' in record['name'] + record['content']:
            continue
        name = _absolute(record['name'], domain, values)
        content = _fill(record['content'], values).strip()
        if record['type'] in ('CNAME', 'MX'):
            content = content.rstrip('.')
        _check_content(record['type'], content, what)
        if record['type'] == 'SRV' and not re.match(r'^_[A-Za-z0-9-]+\._(tcp|udp|tls)\.', name):
            raise DNSToolsError('%s: SRV names look like _service._tcp.' % what)
        out.append({'name': name, 'type': record['type'], 'content': content, 'ttl': record['ttl'],
                    'prio': record['prio']})
    cnames = {r['name'] for r in out if r['type'] == 'CNAME'}
    for record in out:
        if record['name'] in cnames and record['type'] != 'CNAME':
            raise DNSToolsError('%s has a CNAME and other records; a CNAME must be alone.' % record['name'])
    if domain in cnames:
        raise DNSToolsError('The zone apex cannot be a CNAME.')
    return out


# ----------------------------------------------------------------------------- template file

def load_templates(path=None):
    data = {'version': 1, 'ipv6': '', 'default': None, 'resellers': {}}
    try:
        with open(path or TEMPLATES_FILE) as handle:
            stored = json.load(handle)
    except (OSError, ValueError):
        return data
    if isinstance(stored, dict):
        if isinstance(stored.get('ipv6'), str):
            data['ipv6'] = stored['ipv6']
        if isinstance(stored.get('default'), dict):
            data['default'] = stored['default']
        if isinstance(stored.get('resellers'), dict):
            data['resellers'] = {str(k): v for k, v in stored['resellers'].items() if isinstance(v, dict)}
    return data


def check_ipv6(value):
    value = str(value or '').strip()
    if not value:
        return ''
    try:
        address = ipaddress.IPv6Address(value)
    except ValueError:
        raise DNSToolsError('%r is not an IPv6 address.' % value)
    if address.is_loopback or address.is_link_local or address.is_unspecified:
        raise DNSToolsError('Use a public IPv6 address of this server.')
    return str(address)


def template_for(data, admin_id, owner_id=None):
    """(template, source) that applies to zones created by this account."""
    for key, source in ((admin_id, 'reseller'), (owner_id, 'reseller')):
        if key is not None and str(key) in data['resellers']:
            return data['resellers'][str(key)], '%s:%s' % (source, key)
    if data.get('default'):
        return data['default'], 'default'
    return None, 'fixed'


def nameservers(domain, path=None):
    try:
        with open(path or NAMESERVERS_FILE) as handle:
            lines = [l.strip().rstrip('.') for l in handle if len(l.strip()) > 5]
    except OSError:
        lines = []
    return (lines + ['ns1.' + domain, 'ns2.' + domain])[:2] if len(lines) < 2 else lines[:2]


def zone_values(domain, ip, ipv6='', hostname=None, ns_path=None):
    ns = nameservers(domain, ns_path)
    return {'domain': domain, 'ip': ip, 'ipv6': ipv6, 'hostname': hostname or socket.getfqdn(),
            'ns1': ns[0], 'ns2': ns[1]}


def records_for_new_zone(domain, admin_id, owner_id, ip, path=None):
    """Rendered records for a new zone, or None when no template applies (fixed records)."""
    data = load_templates(path)
    template, _ = template_for(data, admin_id, owner_id)
    if not template:
        return None
    return render_template(validate_template(template), zone_values(domain, ip, data['ipv6']))


def machine_ip(path=None):
    try:
        with open(path or MACHINE_IP_FILE) as handle:
            return handle.read().split('\n', 1)[0].strip()
    except OSError:
        return ''


# ----------------------------------------------------------------------------- applying to an existing zone

PROTECTED = ('SOA', 'NS')


def _key(record):
    return (record['name'].lower(), record['type'], record['content'], int(record.get('prio') or 0))


def plan_apply(existing, rendered, mode):
    """What applying a template does. `existing`: the zone's records [{'id', 'name', 'type',
    'content', 'prio', 'ttl'}]. mode 'add': only add records that are missing, skip conflicts.
    mode 'replace': for every name/type the template sets, remove the zone's other records of that
    name and type (and anything a CNAME would clash with). SOA and NS are never touched."""
    if mode not in ('add', 'replace'):
        raise DNSToolsError('Mode must be add or replace.')
    have = {_key(r) for r in existing}
    by_name = {}
    for record in existing:
        by_name.setdefault(record['name'].lower(), []).append(record)
    add, remove, skipped = [], [], []
    removed_ids = set()
    template_pairs = {(r['name'], r['type']) for r in rendered}
    template_keys = {_key(r) for r in rendered}
    if mode == 'replace':
        for record in existing:
            if record['type'] in PROTECTED or _key(record) in template_keys:
                continue
            name = record['name'].lower()
            clash = (name, record['type']) in template_pairs or \
                (name, 'CNAME') in template_pairs or \
                (record['type'] == 'CNAME' and any(n == name for n, _ in template_pairs))
            if clash and record.get('id') not in removed_ids:
                remove.append(record)
                removed_ids.add(record.get('id'))
    for record in rendered:
        if _key(record) in have:
            continue
        others = [r for r in by_name.get(record['name'], []) if r.get('id') not in removed_ids]
        if record['type'] == 'CNAME' and any(r['type'] != 'CNAME' or r['content'] != record['content'] for r in others):
            skipped.append(dict(record, reason='other records exist at this name (a CNAME must be alone)'))
            continue
        if record['type'] != 'CNAME' and any(r['type'] == 'CNAME' for r in others):
            skipped.append(dict(record, reason='a CNAME exists at this name'))
            continue
        if mode == 'add' and record['type'] in ('A', 'AAAA', 'CNAME') and \
                any(r['type'] == record['type'] for r in others):
            skipped.append(dict(record, reason='a %s record exists at this name' % record['type']))
            continue
        add.append(record)
    return {'add': add, 'remove': remove, 'skipped': skipped}

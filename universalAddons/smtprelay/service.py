"""SMTP Relay: send outgoing mail through the administrator's own smarthost (pure logic, no I/O).

Postfix settings this module owns in main.cf (MANAGED_KEYS); it writes them between the BEGIN/END
markers and removes every other definition of them, so a second render changes nothing:

  relayhost                            [host]:port of the global relay ("relay all mail" only)
  sender_dependent_relayhost_maps      sender domain -> its relay (per-domain relays, "selected domains")
  smtp_sender_dependent_authentication yes when per-domain relays exist (credentials looked up per sender)
  smtp_sasl_auth_enable                yes when any relay has credentials
  smtp_sasl_password_maps              the credential map, /etc/postfix/sasl_passwd (mode 600, root)
  smtp_sasl_security_options           noanonymous
  smtp_sasl_tls_security_options       noanonymous
  smtp_tls_policy_maps                 per relay: "encrypt" (STARTTLS / implicit TLS) or "none"
  smtp_tls_wrappermode                 yes only for implicit TLS (port 465); see validate_config

Passwords never leave the root side: the page sends them once, they are written to sasl_passwd,
and every answer to the browser says only whether a password is stored.
"""
import ipaddress
import re

MAIN_CF = '/etc/postfix/main.cf'
SASL_MAP = '/etc/postfix/sasl_passwd'
SENDER_MAP = '/etc/postfix/indianscloud_sender_relay'
TLS_MAP = '/etc/postfix/indianscloud_relay_tls'
MAP_FILES = (SASL_MAP, SENDER_MAP, TLS_MAP)

MANAGED_KEYS = (
    'relayhost',
    'sender_dependent_relayhost_maps',
    'smtp_sender_dependent_authentication',
    'smtp_sasl_auth_enable',
    'smtp_sasl_password_maps',
    'smtp_sasl_security_options',
    'smtp_sasl_tls_security_options',
    'smtp_tls_policy_maps',
    'smtp_tls_wrappermode',
)
BEGIN = '# BEGIN IndiansCloud SMTP Relay (managed by the panel at /addons/smtp-relay/; do not edit by hand)'
END = '# END IndiansCloud SMTP Relay'
# Comment lines older relay code (the vendor's paid relay) wrote above the same keys.
LEGACY_COMMENTS = ('# CyberMail SMTP Relay Configuration',)

PORTS = (587, 465, 25)
TLS_MODES = ('starttls', 'implicit', 'none')
SCOPES = ('all', 'selected')
MAX_DOMAINS = 200
DB_SUFFIX = {'hash': '.db', 'btree': '.db', 'lmdb': '.lmdb', 'cdb': '.cdb', 'dbm': '.dir', 'sdbm': '.dir'}

_HOST = re.compile(r'^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
_DOMAIN = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$')
_USER = re.compile(r'^[^\s:\x00]{1,256}$')
_EMAIL = re.compile(r'^[A-Za-z0-9.!#%&*+/=?^_`{|}~-]{1,64}@([A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}$')


class RelayError(ValueError):
    pass


# ----------------------------------------------------------------------------- validation

def clean_host(value):
    host = str(value or '').strip().lower().rstrip('.')
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if address.version != 4:
            raise RelayError('Use a host name or an IPv4 address for the relay.')
        return str(address)
    if not _HOST.match(host) or '.' not in host:
        raise RelayError('"%s" is not a valid relay host name.' % str(value)[:80])
    return host


def clean_domain(value):
    domain = str(value or '').strip().lower().rstrip('.')
    if not _DOMAIN.match(domain):
        raise RelayError('"%s" is not a valid sender domain.' % str(value)[:80])
    return domain


def clean_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise RelayError('Choose port 587, 465 or 25.')
    if port not in PORTS:
        raise RelayError('Choose port 587, 465 or 25.')
    return port


def clean_tls(value):
    if value not in TLS_MODES:
        raise RelayError('Choose STARTTLS, implicit TLS or no encryption.')
    return value


def clean_username(value):
    username = str(value or '').strip()
    if username and not _USER.match(username):
        raise RelayError('The user name may not contain spaces or ":" (and at most 256 characters).')
    return username


def clean_password(value):
    """A password to store, or '' for "keep the stored one". Postfix trims a map value, and a
    line break would start a new map entry, so neither is allowed."""
    if value is None:
        return ''
    if not isinstance(value, str):
        raise RelayError('Invalid password.')
    if value == '':
        return ''
    if len(value) > 256 or any(c in value for c in '\r\n\x00') or value != value.strip():
        raise RelayError('The password may not contain line breaks or start or end with a space '
                         '(and at most 256 characters).')
    return value


def clean_email(value, what='address'):
    address = str(value or '').strip()
    if not _EMAIL.match(address) or len(address) > 254:
        raise RelayError('Enter a valid email %s.' % what)
    return address


def nexthop(host, port):
    return '[%s]:%d' % (host, port)


def _relay(data, label, required=True):
    data = data if isinstance(data, dict) else {}
    if not data.get('host'):
        if required:
            raise RelayError('Enter the %s host.' % label)
        return None
    relay = {'host': clean_host(data.get('host')), 'port': clean_port(data.get('port', 587)),
             'tls': clean_tls(data.get('tls', 'starttls')), 'username': clean_username(data.get('username'))}
    return relay


def validate_config(data):
    """The relay settings from the page (or the stored file), checked and normalised. Raises RelayError.

    scope 'all': every message leaves through the global relay, except senders of listed domains
    that have their own relay. scope 'selected': only listed domains relay (through their own relay,
    or the global one when they have none); everything else is delivered directly.
    """
    if not isinstance(data, dict):
        raise RelayError('Invalid settings.')
    scope = data.get('scope', 'all')
    if scope not in SCOPES:
        raise RelayError('Choose whether to relay all mail or only selected domains.')
    domains_in = data.get('domains') or []
    if not isinstance(domains_in, list) or len(domains_in) > MAX_DOMAINS:
        raise RelayError('At most %d sender domains.' % MAX_DOMAINS)
    relay = _relay(data.get('relay'), 'relay', required=(scope == 'all'))
    domains, seen = [], set()
    for entry in domains_in:
        if not isinstance(entry, dict):
            raise RelayError('Invalid sender domain entry.')
        domain = clean_domain(entry.get('domain'))
        if domain in seen:
            raise RelayError('%s is listed twice.' % domain)
        seen.add(domain)
        own = _relay(entry, 'relay', required=False)
        item = {'domain': domain, 'host': '', 'port': None, 'tls': None, 'username': clean_username(entry.get('username'))}
        if own:
            item.update(own)
        elif relay is None:
            raise RelayError('%s has no relay of its own; enter one, or set the global relay.' % domain)
        elif scope == 'all' and not item['username']:
            raise RelayError('%s would use the global relay with the global credentials, which already happens for '
                             'all mail; remove it, or give it its own relay or credentials.' % domain)
        domains.append(item)
    if scope == 'selected' and not domains:
        raise RelayError('Add at least one sender domain to relay, or choose "Relay all mail".')
    config = {'scope': scope, 'relay': relay, 'domains': sorted(domains, key=lambda d: d['domain'])}
    modes_by_hop = {}
    for r in [relay] + [d for d in domains if d['host']]:
        if r and modes_by_hop.setdefault(nexthop(r['host'], r['port']), r['tls']) != r['tls']:
            raise RelayError('%s is listed with two different encryption settings.' % nexthop(r['host'], r['port']))
    # smtp_tls_wrappermode can only be set for the whole smtp transport in main.cf. Implicit TLS is
    # therefore possible only when every message goes to a relay and every relay speaks implicit TLS;
    # otherwise direct deliveries (port 25) or STARTTLS relays would break.
    modes = {r['tls'] for r in used_relays(config)}
    if 'implicit' in modes and (scope != 'all' or modes != {'implicit'}):
        raise RelayError('Implicit TLS (port 465) can only be used when all mail is relayed and every relay uses '
                         'implicit TLS. Use STARTTLS on port 587 instead.')
    return config


def used_relays(config):
    """Every distinct relay (host, port, tls) the configuration sends mail to."""
    found = {}
    if config.get('relay') and config['scope'] == 'all':
        r = config['relay']
        found[nexthop(r['host'], r['port'])] = r
    for entry in config.get('domains', []):
        r = entry if entry.get('host') else config.get('relay')
        if r:
            found.setdefault(nexthop(r['host'], r['port']), {k: r[k] for k in ('host', 'port', 'tls')})
    return list(found.values())


def domain_relay(config, entry):
    return entry if entry.get('host') else config['relay']


def warnings(config):
    out = []
    for r in used_relays(config):
        if r['tls'] == 'none':
            out.append('%s is used without encryption: credentials and mail cross the network in clear text.'
                       % nexthop(r['host'], r['port']))
        if r['tls'] == 'implicit' and r['port'] != 465:
            out.append('Implicit TLS is normally on port 465 (%s).' % nexthop(r['host'], r['port']))
        if r['tls'] == 'starttls' and r['port'] == 465:
            out.append('Port 465 normally expects implicit TLS, not STARTTLS (%s).' % nexthop(r['host'], r['port']))
        if r['port'] == 25:
            out.append('Many providers block outgoing port 25; port 587 is the usual submission port (%s).'
                       % nexthop(r['host'], r['port']))
    return out


# ----------------------------------------------------------------------------- credentials

def credential_keys(config):
    """sasl_passwd key -> username for every relay that authenticates."""
    keys = {}
    relay = config.get('relay')
    if relay and relay.get('username'):
        keys[nexthop(relay['host'], relay['port'])] = relay['username']
    for entry in config.get('domains', []):
        if entry.get('username'):
            keys['@' + entry['domain']] = entry['username']
    return keys


def secret_slot(key):
    """The page names passwords 'global' or 'domain:<name>'; sasl_passwd keys are [host]:port or @domain."""
    return 'domain:' + key[1:] if key.startswith('@') else 'global'


def parse_sasl(text):
    """sasl_passwd -> {key: (username, password)}."""
    entries = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or ':' not in parts[1]:
            continue
        user, password = parts[1].split(':', 1)
        entries[parts[0]] = (user, password)
    return entries


def resolve_passwords(config, new_secrets, stored):
    """{sasl key: (user, password)} for the new config. A blank new password keeps the stored one,
    but only for the same key and user name; a relay that authenticates must end up with a password."""
    new_secrets = new_secrets if isinstance(new_secrets, dict) else {}
    result = {}
    for key, username in credential_keys(config).items():
        slot = secret_slot(key)
        password = clean_password(new_secrets.get(slot))
        if not password:
            old = stored.get(key)
            if slot == 'global' and old is None:
                # the global relay moved to another host or port: keep its password for the same user name
                previous = [v for k, v in stored.items() if not k.startswith('@')]
                old = previous[0] if len(previous) == 1 else None
            if old and old[0] == username:
                password = old[1]
        if not password:
            label = 'the global relay' if slot == 'global' else slot.split(':', 1)[1]
            raise RelayError('Enter the password for %s.' % label)
        result[key] = (username, password)
    return result


def public_config(config, stored):
    """What the browser may see: the settings, and whether each password is stored. Never a password."""
    if not config:
        return None
    keys = credential_keys(config)
    out = {'scope': config['scope'], 'relay': None, 'domains': []}
    if config.get('relay'):
        r = dict(config['relay'])
        key = nexthop(r['host'], r['port'])
        r['has_password'] = key in keys and key in stored
        out['relay'] = r
    for entry in config.get('domains', []):
        e = dict(entry)
        e['has_password'] = bool(e.get('username')) and ('@' + e['domain']) in stored
        out['domains'].append(e)
    return out


# ----------------------------------------------------------------------------- rendering

def render_maps(config, passwords):
    """{path: text} for the three map files. `passwords` comes from resolve_passwords."""
    head = '# Managed by IndiansCloud SMTP Relay (/addons/smtp-relay/). Changes here are overwritten.\n'
    sasl = head + ''.join('%s %s:%s\n' % (key, user, password) for key, (user, password) in sorted(passwords.items()))
    sender = head
    for entry in config.get('domains', []):
        r = domain_relay(config, entry)
        sender += '@%s %s\n' % (entry['domain'], nexthop(r['host'], r['port']))
    tls = head + ''.join('%s %s\n' % (nexthop(r['host'], r['port']), 'none' if r['tls'] == 'none' else 'encrypt')
                         for r in sorted(used_relays(config), key=lambda r: nexthop(r['host'], r['port'])))
    return {SASL_MAP: sasl, SENDER_MAP: sender, TLS_MAP: tls}


def managed_values(config, db_type='hash'):
    """The main.cf key = value pairs for `config` (in order), or [] to relay nothing."""
    if not config:
        return []
    values = []
    if config['scope'] == 'all':
        values.append(('relayhost', nexthop(config['relay']['host'], config['relay']['port'])))
    if credential_keys(config):
        values += [('smtp_sasl_auth_enable', 'yes'),
                   ('smtp_sasl_password_maps', '%s:%s' % (db_type, SASL_MAP)),
                   ('smtp_sasl_security_options', 'noanonymous'),
                   ('smtp_sasl_tls_security_options', 'noanonymous')]
    values.append(('smtp_tls_policy_maps', '%s:%s' % (db_type, TLS_MAP)))
    if config.get('domains'):
        values += [('sender_dependent_relayhost_maps', '%s:%s' % (db_type, SENDER_MAP)),
                   ('smtp_sender_dependent_authentication', 'yes')]
    if {r['tls'] for r in used_relays(config)} == {'implicit'}:
        values.append(('smtp_tls_wrappermode', 'yes'))
    return values


def _key_of(line):
    match = re.match(r'^([A-Za-z0-9_]+)\s*=', line)
    return match.group(1) if match else None


def split_main_cf(text):
    """(lines without the managed block or any managed key, {key: value} of managed keys found outside it)."""
    kept, foreign = [], {}
    lines = (text or '').splitlines(True)
    i, inside = 0, False
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip('\r\n')
        if stripped == BEGIN:
            inside = True
        elif stripped == END and inside:
            inside = False
        elif inside or stripped in LEGACY_COMMENTS:
            pass
        elif _key_of(line) in MANAGED_KEYS:
            key = _key_of(line)
            value = line.split('=', 1)[1].strip()
            while i + 1 < len(lines) and lines[i + 1][:1] in (' ', '\t') and lines[i + 1].strip():
                i += 1  # continuation line of the same parameter
                value += ' ' + lines[i].strip()
            foreign[key] = value
        else:
            kept.append(line)
        i += 1
    while kept and not kept[-1].strip():
        kept.pop()
    if kept and not kept[-1].endswith('\n'):
        kept[-1] += '\n'
    return kept, foreign


def render_main_cf(text, config, db_type='hash'):
    """main.cf with the managed block for `config` (None: without it, i.e. direct delivery)."""
    kept, _ = split_main_cf(text)
    values = managed_values(config, db_type)
    if not values:
        return ''.join(kept)
    block = ['\n', BEGIN + '\n'] + ['%s = %s\n' % pair for pair in values] + [END + '\n']
    return ''.join(kept) + ''.join(block)


def foreign_settings(text, config, db_type='hash'):
    """Managed keys set outside the block to a value this module would not write (to confirm a takeover)."""
    _, found = split_main_cf(text)
    ours = dict(managed_values(config, db_type)) if config else {}
    defaults = {'smtp_sasl_auth_enable': 'no', 'smtp_tls_wrappermode': 'no', 'smtp_sender_dependent_authentication': 'no'}
    return {k: v for k, v in found.items() if v and v != ours.get(k) and v != defaults.get(k)}


def map_path(path, db_type):
    return path + DB_SUFFIX.get(db_type, '.db')


# ----------------------------------------------------------------------------- transcript, status

def mask_transcript(lines):
    """Hide credentials: the AUTH command's argument and every client line until the server ends the
    exchange (any reply other than 334)."""
    out, masking = [], False
    for direction, text in lines:
        if direction == 'C':
            upper = text.upper()
            if upper.startswith('AUTH '):
                parts = text.split()
                shown = ' '.join(['AUTH'] + parts[1:2] + (['****'] if len(parts) > 2 else []))
                out.append((direction, shown))
                masking = True
                continue
            if masking:
                out.append((direction, '****'))
                continue
        elif direction == 'S' and masking and not text.startswith('334'):
            masking = False
        out.append((direction, text))
    return out


def queue_summary(json_lines, limit=50000):
    """Counts from `postqueue -j` output (one JSON object per line), and the commonest delay reasons."""
    import json
    counts, reasons, total, truncated = {}, {}, 0, False
    for line in json_lines:
        if total >= limit:
            truncated = True
            break
        try:
            item = json.loads(line)
        except (ValueError, TypeError):
            continue
        total += 1
        queue = str(item.get('queue_name', 'unknown'))[:20]
        counts[queue] = counts.get(queue, 0) + 1
        for recipient in item.get('recipients', [])[:5]:
            reason = str(recipient.get('delay_reason') or '').strip()
            if reason:
                reason = re.sub(r'\s+', ' ', reason)[:160]
                reasons[reason] = reasons.get(reason, 0) + 1
    top = sorted(reasons.items(), key=lambda kv: -kv[1])[:5]
    return {'total': total, 'by_queue': counts, 'top_reasons': [{'reason': r, 'count': c} for r, c in top],
            'truncated': truncated}


def relay_log_lines(lines, hosts, limit=60):
    """The newest mail log lines about the relays: smtp client deliveries to them, and SASL problems."""
    hosts = [h.lower() for h in hosts if h]
    picked = []
    for line in lines:
        low = line.lower()
        if 'postfix/smtp[' not in low:
            continue
        about_relay = any('relay=%s[' % h in low or 'relay=[%s]' % h in low or ' %s[' % h in low for h in hosts)
        if about_relay or 'sasl' in low or 'relayhost' in low:
            picked.append(line.rstrip('\n')[:600])
    return picked[-limit:]

"""Fail2ban ban manager: plain logic (parsing, validation, the managed whitelist drop-in).

The whitelist is a drop-in that fail2ban reads after jail.local, so it must not lose what
jail.local already ignores: its [DEFAULT] line starts with %(known/ignoreip)s (the value read
before it, fail2ban 0.10+) and only appends the panel's entries. actions.py also checks after the
reload that every address ignored before is still ignored, and rolls back otherwise.
"""
import ipaddress
import re

from universalAddons.sshsec import service as ssh
from universalAddons.sshsec.service import SSHSecError

DROPIN = '/etc/fail2ban/jail.d/zz-indianscloud-ignoreip.local'
BACKUP_DIR = '/var/lib/cyberpanel-universal/bans-backups'
CONFIG_ORDER = ('/etc/fail2ban/jail.conf', '/etc/fail2ban/jail.d/*.conf', '/etc/fail2ban/jail.local',
                '/etc/fail2ban/jail.d/*.local')
HEADER = '# Managed by IndiansCloud Add-ons > Fail2ban bans; changes here are overwritten.'
JAIL_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$')
MAX_WHITELIST = 200


class BansError(ValueError):
    pass


def check_jail(name, live=None):
    name = str(name or '').strip()
    if not JAIL_RE.match(name):
        raise BansError('Invalid jail name.')
    if live is not None and name not in live:
        raise BansError('There is no running jail %s.' % name)
    return name


def check_ip(text):
    """A single IPv4/IPv6 address for ban/unban (no networks, no names)."""
    text = str(text or '').strip()
    try:
        network = ssh.parse_target(text)
    except SSHSecError as exc:
        raise BansError(str(exc))
    if network.num_addresses != 1:
        raise BansError('Ban and unban take a single address.')
    return str(network.network_address)


def check_entry(text):
    """A whitelist entry: an address or a CIDR network."""
    try:
        network = ssh.parse_target(str(text or '').strip())
    except SSHSecError as exc:
        raise BansError(str(exc))
    return str(network.network_address) if network.num_addresses == 1 else str(network)


# ----------------------------------------------------------------------------- fail2ban-client output

def parse_jails(text):
    return [j for j in ssh.parse_f2b_jails(text) if JAIL_RE.match(j)]


def _count(pattern, text):
    match = re.search(pattern + r':\s*(\d+)', text or '')
    return int(match.group(1)) if match else None


def parse_jail_status(text):
    """`fail2ban-client status <jail>`."""
    files = re.search(r'(?:File list|Journal matches):\s*(.*)', text or '')
    return {'currently_failed': _count('Currently failed', text), 'total_failed': _count('Total failed', text),
            'currently_banned': _count('Currently banned', text), 'total_banned': _count('Total banned', text),
            'banned': ssh.parse_f2b_banned(text),
            'logs': files.group(1).split() if files else []}


def parse_ignore(text):
    """`fail2ban-client get <jail> ignoreip` (tree output) or a plain space-separated list."""
    items = ssh.parse_f2b_list(text)
    if not items and text and 'ignored' not in text:
        items = text.split()
    return [i for i in items if re.match(r'^[0-9A-Fa-f:./]+$', i)]


def covers(entries, ip):
    """Entries (addresses or networks) of `entries` that contain the address `ip`."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return []
    found = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if network.version == address.version and address in network:
            found.append(entry)
    return found


# ----------------------------------------------------------------------------- jail configuration

def parse_ini_sections(text):
    """{section: {key: value}} of a fail2ban .conf/.local (continuation lines joined)."""
    sections, current, key = {}, None, None
    for raw in (text or '').splitlines():
        if not raw.strip() or raw.lstrip().startswith(('#', ';')):
            continue
        header = re.match(r'^\[([^\]]+)\]\s*$', raw.strip())
        if header:
            current, key = header.group(1).strip(), None
            sections.setdefault(current, {})
            continue
        if current is None:
            continue
        if raw[:1] in (' ', '\t') and key:
            sections[current][key] += ' ' + raw.strip()
            continue
        match = re.match(r'^([A-Za-z0-9_.-]+)\s*[=:]\s*(.*)$', raw.strip())
        if match:
            key = match.group(1).lower()
            sections[current][key] = match.group(2).strip()
    return sections


def jail_filters(texts, jails):
    """Effective filter name of each jail from config texts read in fail2ban's order."""
    merged = {}
    for text in texts:
        for section, values in parse_ini_sections(text).items():
            merged.setdefault(section, {}).update(values)
    default = merged.get('DEFAULT', {}).get('filter', '%(__name__)s')
    result = {}
    for jail in jails:
        value = merged.get(jail, {}).get('filter', default)
        value = value.replace('%(__name__)s', jail).replace('[mode=%(mode)s]', '')
        mode = merged.get(jail, {}).get('mode')
        result[jail] = value.strip() + (' (mode %s)' % mode if mode and 'mode=' not in value else '')
    return result


# ----------------------------------------------------------------------------- the managed drop-in

def render_dropin(entries):
    entries = [check_entry(e) for e in entries]
    if len(entries) > MAX_WHITELIST:
        raise BansError('The whitelist holds at most %d entries.' % MAX_WHITELIST)
    lines = [HEADER,
             '# Addresses fail2ban never bans, added to what jail.local and the other files already ignore.',
             '[DEFAULT]',
             'ignoreip = %(known/ignoreip)s' + ''.join(' ' + e for e in entries)]
    return '\n'.join(lines) + '\n'


def parse_dropin(text):
    for line in (text or '').splitlines():
        match = re.match(r'^ignoreip\s*=\s*%\(known/ignoreip\)s(.*)$', line.strip())
        if match:
            return [e for e in match.group(1).split() if e]
    return []

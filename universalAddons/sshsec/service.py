"""SSH Security: log analysis, sshd audit rules, IP validation and firewalld rule text.

Pure functions only (no subprocess, no root): actions.py feeds them command output and files.

Blocking uses one firewalld rich rule per address, `rule family="ipv4" source address="X" drop`,
added to the permanent configuration and to the runtime configuration separately. Why rich rules
and not an ipset: it is the exact format CyberPanel's own firewall page and its IP-block action
write, so the blocks are visible and removable there too, and there is no extra ipset object
that a firewalld reset or a CyberPanel update could leave dangling. A few hundred rules cost
nothing; MAX_BLOCKS caps the registry well below the point where an ipset would pay off.
Why no `firewall-cmd --reload`: a reload rebuilds the runtime from the permanent configuration
and silently drops every runtime-only rule, which is exactly how fail2ban's firewallcmd-rich-rules
action stores its bans.
"""
import calendar
import ipaddress
import re
import time
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime

WINDOWS = {'24h': 86400, '7d': 7 * 86400, '30d': 30 * 86400}
MIN_PREFIX = {4: 16, 6: 32}       # refuse blocks broader than a /16 (IPv4) or /32 (IPv6)
MAX_BLOCKS = 1000
REASON_RE = re.compile(r'^[A-Za-z0-9 .,_/#@+=-]{0,200}$')
_TARGET_RE = re.compile(r'^[0-9A-Fa-f.:]{2,45}(/[0-9]{1,3})?$')

# Byte budgets that keep analysis bounded on logs of a gigabyte or more.
MAX_BYTES_PER_FILE = 256 * 1024 * 1024
MAX_BYTES_TOTAL = 512 * 1024 * 1024
TOP_N = 50


class SSHSecError(Exception):
    pass


# ----------------------------------------------------------------------------- addresses

NEVER_BLOCK = [ipaddress.ip_network(n) for n in ('127.0.0.0/8', '::1/128', '0.0.0.0/32', '::/128')]
NOT_ROUTABLE = [ipaddress.ip_network(n) for n in ('169.254.0.0/16', 'fe80::/10', '224.0.0.0/4', 'ff00::/8',
                                                  '255.255.255.255/32')]
PRIVATE = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10',
                                             'fc00::/7')]


def _overlaps(a, b):
    return a.version == b.version and a.overlaps(b)


def _unmap(address):
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def parse_address(text):
    """A single IPv4/IPv6 address from a log line or request header, or None."""
    try:
        return _unmap(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        return None


def parse_target(text):
    """Strictly parse an address or CIDR network to block. Raises SSHSecError."""
    text = str(text or '').strip()
    if not _TARGET_RE.match(text):
        raise SSHSecError('Enter an IPv4 or IPv6 address, or a network in CIDR form (e.g. 203.0.113.0/24).')
    address, _, prefix = text.partition('/')
    if prefix and (len(prefix) > 1 and prefix.startswith('0')):
        raise SSHSecError('Invalid prefix length.')
    if re.search(r'(^|[.:])0\d+\.|\.0\d+$', address):  # Python < 3.9.5 accepted (and misread) 010.1.1.1
        raise SSHSecError('IPv4 octets must not have leading zeros.')
    try:
        host = ipaddress.ip_address(address)
    except ValueError:
        raise SSHSecError('%s is not a valid IP address.' % address)
    if isinstance(host, ipaddress.IPv6Address) and host.ipv4_mapped:
        host = host.ipv4_mapped
        if prefix:
            raise SSHSecError('Write IPv4-mapped networks in IPv4 form.')
    try:
        network = ipaddress.ip_network('%s/%s' % (host, prefix) if prefix else str(host), strict=True)
    except ValueError as exc:
        if 'host bits' in str(exc):
            raise SSHSecError('%s has host bits set; did you mean %s?' % (
                text, ipaddress.ip_network('%s/%s' % (host, prefix), strict=False)))
        raise SSHSecError('Invalid network: %s' % text)
    if network.prefixlen < MIN_PREFIX[network.version]:
        raise SSHSecError('Refusing to block a network wider than /%d for IPv%d.' % (
            MIN_PREFIX[network.version], network.version))
    return network


def block_checks(network, client_ips=(), server_ips=()):
    """Return (refusals, confirmations). Any refusal blocks the action; confirmations need the
    administrator to tick 'I know' first."""
    refusals, confirm = [], []
    for ip in client_ips:
        address = parse_address(ip)
        if address is not None and address.version == network.version and address in network:
            refusals.append('%s is the address you are connected from; blocking it would lock you out.' % address)
    for ip in server_ips:
        address = parse_address(ip)
        if address is not None and address.version == network.version and address in network:
            refusals.append('%s belongs to this server.' % address)
    for special in NEVER_BLOCK:
        if _overlaps(network, special):
            refusals.append('%s overlaps %s (loopback/unspecified).' % (network, special))
    for special in NOT_ROUTABLE:
        if _overlaps(network, special):
            refusals.append('%s overlaps %s (link-local, multicast or broadcast).' % (network, special))
    for special in PRIVATE:
        if _overlaps(network, special):
            confirm.append('%s is in the private range %s (LAN, VPN or containers).' % (network, special))
    return refusals, confirm


def client_ips(meta):
    """The addresses the current admin may be connecting from: CyberPanel's own resolution
    (CyberCP.sessionSecurity.get_client_ip: CF-Connecting-IP, else REMOTE_ADDR), plus REMOTE_ADDR and
    the first X-Forwarded-For hop in case a proxy sits in front."""
    found = []
    candidates = [meta.get('HTTP_CF_CONNECTING_IP'), meta.get('REMOTE_ADDR'),
                  (meta.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0]]
    for value in candidates:
        address = parse_address(value) if value else None
        if address is not None and str(address) not in found:
            found.append(str(address))
    return found


def validate_reason(text):
    text = str(text or '').strip()
    if not REASON_RE.match(text):
        raise SSHSecError('Reason: up to 200 letters, digits, spaces and . , _ / # @ + = - only.')
    return text


def decode_target(value):
    """The page sends ':' as '-' because CyberPanel's request filter rejects colons."""
    if not isinstance(value, str) or len(value) > 64:
        raise SSHSecError('Invalid address.')
    return value.replace('-', ':')


# ----------------------------------------------------------------------------- firewalld

def rich_rule(network):
    return 'rule family="ipv%d" source address="%s" drop' % (network.version, network)


def firewall_argvs(op, zone, network):
    """argv lists to add/remove a block, permanent first, then runtime (no reload)."""
    if op not in ('add', 'remove'):
        raise ValueError('op')
    if not re.match(r'^[A-Za-z0-9_-]{1,32}$', zone or ''):
        raise SSHSecError('Invalid firewalld zone.')
    flag = '--%s-rich-rule=%s' % (op, rich_rule(network))
    return [['firewall-cmd', '--permanent', '--zone=' + zone, flag], ['firewall-cmd', '--zone=' + zone, flag]]


_RICH_SOURCE = re.compile(r'source address="([^"]+)"')
_RICH_IPSET = re.compile(r'source ipset="([^"]+)"')
_RICH_PORT = re.compile(r'port port="([^"]+)"')


def parse_rich_rules(text):
    """Blocking rich rules: [{'network', 'action', 'port', 'rule'}] (drop/reject only)."""
    rules = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line.startswith('rule ') or 'source NOT' in line:
            continue
        action = 'drop' if re.search(r'\bdrop\s*$', line) else ('reject' if re.search(r'\breject\b', line) else None)
        if not action:
            continue
        port = _RICH_PORT.search(line)
        source, ipset = _RICH_SOURCE.search(line), _RICH_IPSET.search(line)
        entry = {'action': action, 'port': port.group(1) if port else '', 'rule': line}
        if source:
            try:
                entry['network'] = ipaddress.ip_network(source.group(1), strict=False)
            except ValueError:
                continue
        elif ipset:
            entry['ipset'] = ipset.group(1)
        else:
            continue
        rules.append(entry)
    return rules


def parse_ip_addr(text):
    """Server addresses from `ip -o addr show`."""
    found = []
    for line in (text or '').splitlines():
        match = re.search(r'\binet6? ([0-9A-Fa-f:.]+)/\d+', line)
        if match and parse_address(match.group(1)) is not None:
            found.append(str(parse_address(match.group(1))))
    return found


def parse_f2b_jails(text):
    match = re.search(r'Jail list:\s*(.*)', text or '')
    return [j.strip() for j in match.group(1).split(',') if j.strip()] if match else []


def parse_f2b_banned(text):
    match = re.search(r'Banned IP list:\s*(.*)', text or '')
    return [ip for ip in (match.group(1).split() if match else []) if parse_address(ip) is not None or '/' in ip]


def parse_f2b_list(text):
    """`fail2ban-client get <jail> ignoreip` style tree output."""
    return [m.group(1) for m in re.finditer(r'^\s*[|`]- (\S+)', text or '', re.M)]


class BlockIndex:
    """Which firewalld rules / ipsets / fail2ban jails already cover an address."""

    def __init__(self):
        self.entries = []  # (network, label)

    def add(self, network, label):
        if isinstance(network, str):
            try:
                network = ipaddress.ip_network(network, strict=False)
            except ValueError:
                return
        self.entries.append((network, label))

    def labels(self, ip):
        address = parse_address(ip)
        if address is None:
            return []
        out = []
        for network, label in self.entries:
            if network.version == address.version and address in network and label not in out:
                out.append(label)
        return out


# ----------------------------------------------------------------------------- log lines

_MONTHS = {m: i for i, m in enumerate(('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct',
                                       'Nov', 'Dec'), 1)}
_SYSLOG_TS = re.compile(rb'^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d):(\d\d):(\d\d) ')
_ISO_TS = re.compile(rb'^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:?\d\d)? ')


def line_time(line, now=None):
    """Epoch seconds of a syslog (Mon dd hh:mm:ss, year inferred) or ISO-8601 log line, or None."""
    match = _ISO_TS.match(line)
    if match:
        y, mo, d, h, mi, s = (int(x) for x in match.groups()[:6])
        zone = match.group(7)
        try:
            stamp = datetime(y, mo, d, h, mi, s)
        except ValueError:
            return None
        if zone is None:
            return time.mktime(stamp.timetuple())
        zone = zone.decode()
        offset = 0
        if zone != 'Z':
            sign = -1 if zone[0] == '-' else 1
            digits = zone[1:].replace(':', '')
            offset = sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
        return calendar.timegm(stamp.timetuple()) - offset
    match = _SYSLOG_TS.match(line)
    if match:
        month = _MONTHS.get(match.group(1).decode())
        if not month:
            return None
        now = now or time.time()
        year = time.localtime(now).tm_year
        day, h, mi, s = (int(x) for x in match.groups()[1:])
        for candidate in (year, year - 1):
            try:
                stamp = time.mktime((candidate, month, day, h, mi, s, 0, 0, -1))
            except (OverflowError, ValueError):
                return None
            if stamp <= now + 86400:   # syslog has no year: a date "in the future" is last year's
                return stamp
        return None
    return None


def sshd_message(line):
    """(pid or None, message) of an sshd line, or None for other programs."""
    if b'sshd' not in line:
        return None
    text = line.decode('utf-8', 'replace').rstrip('\r\n')
    # Strip the timestamp: syslog has three fields (Mon dd hh:mm:ss), ISO one.
    head = r'^\S+ \S+ ' if _ISO_TS.match(line) else r'^\S+ +\d+ \S+ \S+ '
    match = re.match(head + r'sshd(?:-session)?(?:\[(\d+)\])?: (.*)$', text)
    if not match:
        return None
    return (int(match.group(1)) if match.group(1) else None), match.group(2)


_IP = r'(?P<ip>[0-9A-Fa-f:.]{2,45})'
R_FAILED = re.compile(r'^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from ' + _IP + r' port \d+')
R_ACCEPTED = re.compile(r'^Accepted (?P<method>\S+) for (?P<user>\S+) from ' + _IP + r' port \d+')
R_INVALID = re.compile(r'^Invalid user (?P<user>.*?) from ' + _IP + r'(?: port \d+)?\s*$')
R_MAXAUTH = re.compile(r'^(?:error: )?(?:maximum authentication attempts exceeded for|Disconnecting) '
                       r'(?:(?:invalid|authenticating) user )?(?P<user>.*?) (?:from )?' + _IP +
                       r' port \d+.*(?:Too many authentication failures|ssh2)')
R_PREAUTH_USER = re.compile(r'^(?:Connection closed by|Disconnected from|Connection reset by) '
                            r'(?:authenticating|invalid) user (?P<user>.*?) ' + _IP + r' port \d+')
R_PROBE = re.compile(r'^(?:Connection closed by|Connection reset by|Disconnected from|Received disconnect from|'
                     r'Timeout before authentication for|Did not receive identification string from|'
                     r'Unable to negotiate with|Bad protocol version identification .* from|'
                     r'banner exchange: Connection from|ssh_dispatch_run_fatal: Connection from|'
                     r'Protocol major versions differ for|error: kex_exchange_identification: .* from) ' + _IP +
                     r'(?: port \d+)?')
_NEEDS_PREAUTH = ('Connection closed', 'Connection reset', 'Disconnected', 'Received disconnect')
_REPEATED = re.compile(r'^message repeated (\d+) times: \[ ?(.*?) ?\]$')


CONN_LIMIT = 100000
_AUTH_KINDS = ('accepted', 'failed', 'invalid', 'maxauth', 'preauth_user')


class Analyzer:
    """Aggregates sshd messages. feed() in any order; result() summarises.

    A "probe" is a connection (one sshd pid) that closed before authentication without ever
    trying a user name: a port scan, a banner grab or a disconnect flood. Brute-force clients also
    end with "Received disconnect ... [preauth]", so closes are only counted once the connection is
    known to have had no auth attempt. The lines of one connection are adjacent in time, so a
    bounded LRU of recent connections works in either reading order (files forward, journal reverse).
    """

    def __init__(self, cutoff=0):
        self.cutoff = cutoff
        self.ips = defaultdict(lambda: {'failed': 0, 'invalid': 0, 'root': 0, 'probes': 0, 'maxauth': 0,
                                        'accepted': 0, 'first': None, 'last': None, 'users': Counter()})
        self.users = defaultdict(lambda: {'failed': 0, 'invalid': False, 'ips': set(), 'accepted': 0})
        self.accepted = []
        self.lines = 0
        self.earliest = self.latest = None
        self.conns = OrderedDict()

    def _settle(self, key, conn):
        if conn['closed'] and not conn['authed']:
            self.ips[key[1]]['probes'] += 1

    def _connection(self, pid, ip, kind):
        key = (pid, ip)
        conn = self.conns.pop(key, None) or {'authed': False, 'closed': False}
        self.conns[key] = conn
        if kind in _AUTH_KINDS:
            conn['authed'] = True
        elif kind == 'probe':
            conn['closed'] = True
        while len(self.conns) > CONN_LIMIT:
            self._settle(*self.conns.popitem(last=False))

    def _touch(self, ip, ts):
        entry = self.ips[ip]
        entry['first'] = ts if entry['first'] is None else min(entry['first'], ts)
        entry['last'] = ts if entry['last'] is None else max(entry['last'], ts)
        return entry

    def feed(self, ts, message, pid=None):
        if ts is None or ts < self.cutoff:
            return None
        repeated = _REPEATED.match(message)
        if repeated:  # rsyslog collapses identical lines
            kind = None
            for _ in range(min(int(repeated.group(1)), 1000)):
                kind = self.feed(ts, repeated.group(2), pid)
            return kind
        self.lines += 1
        self.earliest = ts if self.earliest is None else min(self.earliest, ts)
        self.latest = ts if self.latest is None else max(self.latest, ts)
        for pattern, kind in ((R_ACCEPTED, 'accepted'), (R_FAILED, 'failed'), (R_INVALID, 'invalid'),
                              (R_MAXAUTH, 'maxauth'), (R_PREAUTH_USER, 'preauth_user'), (R_PROBE, 'probe')):
            match = pattern.match(message)
            if not match:
                continue
            if kind == 'probe' and message.startswith(_NEEDS_PREAUTH) and '[preauth]' not in message:
                return None  # a normal logout after a successful session
            address = parse_address(match.group('ip'))
            if address is None:
                continue
            ip = str(address)
            entry = self._touch(ip, ts)
            user = match.groupdict().get('user')
            if pid is not None:
                self._connection(pid, ip, kind)
            if kind == 'accepted':
                entry['accepted'] += 1
                self.users[user]['accepted'] += 1
                self.accepted.append({'time': int(ts), 'user': user, 'ip': ip, 'method': match.group('method')})
            elif kind == 'failed':
                entry['failed'] += 1
                entry['users'][user] += 1
                record = self.users[user]
                record['failed'] += 1
                record['ips'].add(ip)
                if match.group('invalid'):
                    record['invalid'] = True
                if user == 'root':
                    entry['root'] += 1
            elif kind == 'invalid':
                entry['invalid'] += 1
                self.users[user]['invalid'] = True
                self.users[user]['ips'].add(ip)
            elif kind == 'maxauth':
                entry['maxauth'] += 1
            elif kind == 'probe' and pid is None:
                entry['probes'] += 1  # no pid to tell connections apart: count every close
            return kind
        return None

    def result(self, blocked=None):
        while self.conns:
            self._settle(*self.conns.popitem(last=False))
        blocked = blocked or BlockIndex()
        rows = []
        for ip, e in self.ips.items():
            attempts = e['failed'] + e['invalid']
            if not attempts and not e['probes'] and not e['maxauth']:
                continue  # only successful logins
            kinds = []
            if attempts >= 5:
                kinds.append('brute-force')
            if e['probes'] >= 5 and attempts == 0:
                kinds.append('scan')
            elif e['probes'] >= 20 and e['probes'] >= attempts:
                kinds.append('disconnect flood')
            rows.append({'ip': ip, 'failed': e['failed'], 'invalid': e['invalid'], 'root': e['root'],
                         'probes': e['probes'], 'score': attempts + e['probes'], 'accepted': e['accepted'],
                         'first': int(e['first']), 'last': int(e['last']), 'kinds': kinds,
                         'users': [u for u, _ in e['users'].most_common(5)], 'blocked_by': blocked.labels(ip)})
        rows.sort(key=lambda r: (-r['score'], -r['last']))
        users = sorted(({'user': u, 'failed': r['failed'], 'invalid': r['invalid'], 'ips': len(r['ips']),
                         'accepted': r['accepted']} for u, r in self.users.items() if r['failed'] or r['invalid']),
                       key=lambda r: -r['failed'])
        logins = defaultdict(lambda: {'count': 0, 'last': 0})
        for item in self.accepted:
            key = (item['user'], item['ip'], item['method'])
            logins[key]['count'] += 1
            logins[key]['last'] = max(logins[key]['last'], item['time'])
        success = sorted(({'user': u, 'ip': ip, 'method': m, 'count': v['count'], 'last': v['last'],
                           'blocked_by': blocked.labels(ip)} for (u, ip, m), v in logins.items()),
                         key=lambda r: -r['last'])
        scans = [r for r in rows if 'scan' in r['kinds'] or 'disconnect flood' in r['kinds']]
        return {
            'totals': {
                'failed': sum(e['failed'] for e in self.ips.values()),
                'invalid_user': sum(e['invalid'] for e in self.ips.values()),
                'root_failed': sum(e['root'] for e in self.ips.values()),
                'probes': sum(e['probes'] for e in self.ips.values()),
                'accepted': len(self.accepted),
                'root_accepted': sum(1 for a in self.accepted if a['user'] == 'root'),
                'attacking_ips': len(rows),
                'already_blocked': sum(1 for r in rows if r['blocked_by']),
                'lines': self.lines,
            },
            'top_ips': rows[:TOP_N],
            'top_users': users[:TOP_N],
            'successful': success[:100],
            'scans': scans[:20],
            'root_ips': sorted((r for r in rows if r['root']), key=lambda r: -r['root'])[:20],
            'earliest': int(self.earliest) if self.earliest else None,
            'latest': int(self.latest) if self.latest else None,
        }


def seek_time(handle, size, cutoff, now=None, probe=4096):
    """Byte offset near the first line at or after `cutoff`, by bisection on line timestamps.
    Lines without a timestamp are skipped over. The caller reads on from the returned offset."""
    low, high = 0, size
    while high - low > probe * 4:
        mid = (low + high) // 2
        handle.seek(mid)
        handle.readline()  # finish the partial line
        stamp = None
        for _ in range(50):
            line = handle.readline()
            if not line:
                break
            stamp = line_time(line, now)
            if stamp is not None:
                break
        if stamp is None or stamp >= cutoff:
            high = mid
        else:
            low = mid
    return low


def scan_stream(handle, analyzer, cutoff, budget, now=None):
    """Feed sshd lines from a binary stream; returns bytes consumed (stops at `budget`)."""
    used = 0
    for line in handle:
        used += len(line)
        if used > budget:
            break
        parsed = sshd_message(line)
        if parsed is None:
            continue
        analyzer.feed(line_time(line, now), parsed[1], parsed[0])
    return used


# ----------------------------------------------------------------------------- sshd audit

def parse_sshd_t(text):
    """`sshd -T` output to {key: value}; repeated keys (port, listenaddress, allowusers) joined by spaces."""
    config = {}
    for line in (text or '').splitlines():
        key, _, value = line.strip().partition(' ')
        if not key:
            continue
        key = key.lower()
        config[key] = (config[key] + ' ' + value) if key in config else value
    return config


def audit(config, f2b, root_keys=None, client=()):
    """Rows {id, title, value, status (pass/warn/fail/info), detail, fix} for the page.
    f2b: {'installed', 'running', 'jail', 'ignoreip': [...], 'maxretry', 'bantime', 'findtime'}."""
    rows = []

    def add(rid, title, value, status, detail, fix=''):
        rows.append({'id': rid, 'title': title, 'value': value, 'status': status, 'detail': detail, 'fix': fix})

    keys_note = ''
    if root_keys == 0:
        keys_note = ' root has no authorized_keys yet: add your key and test a key login in a second session first.'
    root = config.get('permitrootlogin', 'unknown')
    if root == 'yes':
        add('permitrootlogin', 'PermitRootLogin', root, 'warn',
            'root may log in with a password, the account bots try most.',
            'Set "PermitRootLogin prohibit-password" once key login works.' + keys_note)
    elif root in ('prohibit-password', 'without-password', 'forced-commands-only'):
        add('permitrootlogin', 'PermitRootLogin', root, 'pass', 'root may log in with a key only.')
    elif root == 'no':
        add('permitrootlogin', 'PermitRootLogin', root, 'pass', 'Direct root login is disabled.')
    else:
        add('permitrootlogin', 'PermitRootLogin', root, 'info', 'Could not read the setting.')

    password = config.get('passwordauthentication', 'unknown')
    kbd = config.get('kbdinteractiveauthentication', config.get('challengeresponseauthentication', 'no'))
    if password == 'yes':
        add('passwordauthentication', 'PasswordAuthentication', password, 'warn',
            'Passwords can be guessed; keys cannot.',
            'Set "PasswordAuthentication no" only after every admin has a working key. Keep a console '
            '(VNC/IPMI) open while you change it.' + keys_note)
    elif password == 'no':
        add('passwordauthentication', 'PasswordAuthentication', password, 'pass',
            'Only key authentication is accepted.' + (' Keyboard-interactive is still on, which can also '
                                                    'ask for a password.' if kbd == 'yes' else ''))
    else:
        add('passwordauthentication', 'PasswordAuthentication', password, 'info', 'Could not read the setting.')

    if config.get('permitemptypasswords') == 'yes':
        add('permitemptypasswords', 'PermitEmptyPasswords', 'yes', 'fail', 'Accounts without a password can log in.',
            'Set "PermitEmptyPasswords no".')

    port = config.get('port', '22')
    add('port', 'Port', port, 'info',
        'Port 22 receives most automated scans; a different port cuts log noise but adds no real security.'
        if '22' in port.split() else 'SSH listens on a non-standard port, which reduces automated noise.',
        'If you move it: open the new port in firewalld, allow it in SELinux (semanage port -a -t ssh_port_t), '
        'test it in a second session, then remove 22.' if '22' in port.split() else '')

    try:
        tries = int(config.get('maxauthtries', '6'))
    except ValueError:
        tries = 6
    add('maxauthtries', 'MaxAuthTries', str(tries), 'pass' if tries <= 4 else 'warn',
        '%d password guesses per connection.' % tries, '' if tries <= 4 else 'Set "MaxAuthTries 3" or 4.')

    pubkey = config.get('pubkeyauthentication', 'yes')
    add('pubkeyauthentication', 'PubkeyAuthentication', pubkey, 'pass' if pubkey == 'yes' else
        ('fail' if password == 'no' else 'warn'),
        'Key login is enabled.' if pubkey == 'yes' else 'Key login is disabled.',
        '' if pubkey == 'yes' else 'Set "PubkeyAuthentication yes".')

    x11 = config.get('x11forwarding', 'no')
    add('x11forwarding', 'X11Forwarding', x11, 'warn' if x11 == 'yes' else 'pass',
        'Graphical forwarding is rarely needed on a server.' if x11 == 'yes' else 'Disabled.',
        'Set "X11Forwarding no".' if x11 == 'yes' else '')

    allow = ' '.join(config.get(k, '') for k in ('allowusers', 'allowgroups')).strip()
    add('allowusers', 'AllowUsers / AllowGroups', allow or '(not set)', 'pass' if allow else 'info',
        'Only the listed accounts may log in.' if allow else 'Every account with a shell may log in over SSH.',
        '' if allow else 'Consider "AllowUsers" with your own admin account(s); list yourself or you will be '
                         'locked out.')

    if not f2b.get('installed'):
        add('fail2ban', 'fail2ban sshd jail', 'not installed', 'warn', 'Nothing bans repeated password guessers.',
            'Install fail2ban (dnf/apt install fail2ban) and enable its sshd jail.')
    elif not f2b.get('running'):
        add('fail2ban', 'fail2ban sshd jail', 'service stopped', 'warn', 'fail2ban is installed but not running.',
            'systemctl enable --now fail2ban')
    elif not f2b.get('jail'):
        add('fail2ban', 'fail2ban sshd jail', 'not enabled', 'warn', 'fail2ban runs, but has no sshd jail.',
            'Use "Enable fail2ban sshd jail" below.')
    else:
        detail = 'Active: %s retries within %ss ban for %ss.' % (f2b.get('maxretry', '?'), f2b.get('findtime', '?'),
                                                               f2b.get('bantime', '?'))
        fix = ''
        ignored = BlockIndex()
        for item in f2b.get('ignoreip') or []:
            ignored.add(item, 'ignore')
        missing = [ip for ip in client if not ignored.labels(ip)]
        if missing:
            fix = ('Your address %s is not in ignoreip; a few typos would ban you for the ban time. Add it to '
                   'ignoreip in /etc/fail2ban/jail.local if it is static.' % ', '.join(missing))
        add('fail2ban', 'fail2ban sshd jail', 'enabled', 'pass', detail, fix)
    return rows


def f2b_jail_text(ports):
    """Contents of /etc/fail2ban/jail.d/cp-sshd.local: enable the stock sshd jail, nothing else."""
    ports = [p for p in (ports or []) if re.match(r'^\d{1,5}$', p)] or ['ssh']
    return ('# Written by CyberPanel Universal Add-ons (SSH Security). Enables the stock sshd jail;\n'
            '# all other settings come from jail.conf / jail.local. Delete this file to undo.\n'
            '[sshd]\nenabled = true\nport = %s\n' % ','.join(ports))

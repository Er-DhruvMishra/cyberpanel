"""Email Debugger: DNS, blocklist, port/TLS, log and spam-score diagnostics.

Pure logic with injectable I/O (resolver, command runner, socket factory) so every check is
unit-testable without root, network or Django. Nothing here changes system state except
send_test_message(), which hands one message to the local sendmail.
"""
import os
import re
import socket
import ssl
import subprocess
import time
from collections import Counter, OrderedDict

PASS, WARN, FAIL, INFO = 'pass', 'warn', 'fail', 'info'

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$')
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+=-]{1,64}@[A-Za-z0-9.-]{1,253}$')
IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

DNSBL_ZONES = (
    ('zen.spamhaus.org', 'Spamhaus ZEN'),
    ('bl.spamcop.net', 'SpamCop'),
    ('b.barracudacentral.org', 'Barracuda'),
    ('dnsbl.sorbs.net', 'SORBS'),
    ('psbl.surriel.com', 'PSBL'),
    ('dnsbl-1.uceprotect.net', 'UCEPROTECT L1'),
)

# port -> (name, mode) where mode is 'tls' (implicit TLS), 'smtp' (STARTTLS) or 'plain'
MAIL_PORTS = OrderedDict([
    (25, ('SMTP', 'smtp')),
    (465, ('SMTPS', 'tls')),
    (587, ('Submission', 'smtp')),
    (993, ('IMAPS', 'tls')),
    (995, ('POP3S', 'tls')),
    (143, ('IMAP', 'plain')),
    (110, ('POP3', 'plain')),
])


def valid_domain(value):
    return bool(value) and bool(DOMAIN_RE.match(value))


def valid_email(value):
    if not value or not EMAIL_RE.match(value):
        return False
    return valid_domain(value.rsplit('@', 1)[1])


def result(check_id, title, status, detail, fix=''):
    return {'id': check_id, 'title': title, 'status': status, 'detail': detail, 'fix': fix}


# --------------------------------------------------------------------------- DNS

class DigResolver:
    """Resolve with `dig +short` (bind-utils/dnsutils is installed with the panel)."""

    def __init__(self, server=None, timeout=4, runner=subprocess.run):
        self.server = server
        self.timeout = timeout
        self.runner = runner

    def query(self, name, rtype):
        argv = ['dig', '+short', '+time=%d' % self.timeout, '+tries=1', name, rtype]
        if self.server:
            argv.insert(1, '@' + self.server)
        try:
            out = self.runner(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              universal_newlines=True, timeout=self.timeout * 3)
        except (OSError, subprocess.SubprocessError):
            return []
        answers = []
        for line in (out.stdout or '').splitlines():
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            if rtype == 'TXT':
                # dig prints TXT as one or more quoted chunks; join them.
                line = ''.join(re.findall(r'"((?:[^"\\]|\\.)*)"', line)) or line
            answers.append(line.rstrip('.') if rtype in ('MX', 'CNAME', 'PTR', 'NS') else line)
        return answers


def _a_records(resolver, name):
    return [r for r in resolver.query(name, 'A') if IPV4_RE.match(r)]


def check_mx(resolver, domain, server_ips):
    records = resolver.query(domain, 'MX')
    if not records:
        return result('mx', 'MX record', FAIL, 'No MX record for %s.' % domain,
                      'Add an MX record pointing to mail.%s.' % domain)
    hosts = []
    for record in records:
        parts = record.split()
        hosts.append(parts[-1].rstrip('.') if parts else record)
    resolved = {host: _a_records(resolver, host) for host in hosts}
    ours = [h for h, ips in resolved.items() if set(ips) & set(server_ips)]
    detail = ', '.join('%s (%s)' % (h, ', '.join(ips) or 'no A record') for h, ips in resolved.items())
    if not any(resolved.values()):
        return result('mx', 'MX record', FAIL, 'MX hosts do not resolve: ' + detail,
                      'Give the MX host an A record.')
    if server_ips and not ours:
        return result('mx', 'MX record', WARN, 'MX points elsewhere: ' + detail,
                      'Fine if mail is hosted externally; otherwise point MX at this server.')
    return result('mx', 'MX record', PASS, detail)


def check_mail_host(resolver, domain, server_ips):
    name = 'mail.' + domain
    ips = _a_records(resolver, name)
    if not ips:
        return result('mailhost', name, FAIL, '%s has no A record.' % name,
                      'Add an A record for %s pointing to this server.' % name)
    if server_ips and not set(ips) & set(server_ips):
        return result('mailhost', name, WARN, '%s resolves to %s, not this server (%s).'
                      % (name, ', '.join(ips), ', '.join(server_ips)),
                      'Point %s at this server so clients and certificates match.' % name)
    return result('mailhost', name, PASS, '%s -> %s' % (name, ', '.join(ips)))


def _spf_records(resolver, domain):
    return [t for t in resolver.query(domain, 'TXT') if t.lower().startswith('v=spf1')]


def spf_evaluate(resolver, domain, ip, _depth=0, _counter=None):
    """Return (matched_mechanism_or_None, lookup_count, errors) for ip against domain's SPF.

    Implements the mechanisms that matter in practice (ip4, a, mx, include, redirect, all)
    and counts DNS-querying terms toward the RFC 7208 limit of 10.
    """
    counter = _counter if _counter is not None else [0]
    errors = []
    records = _spf_records(resolver, domain)
    if not records:
        return None, counter[0], ['no SPF record at %s' % domain]
    if len(records) > 1:
        errors.append('multiple SPF records at %s (permerror)' % domain)
    redirect = None
    for term in records[0].split()[1:]:
        qualifier = term[0] if term[0] in '+-~?' else '+'
        body = term[1:] if term[0] in '+-~?' else term
        mech, _, arg = body.partition(':')
        mech = mech.lower()
        if mech.startswith('redirect='):
            redirect = body.split('=', 1)[1]
            continue
        if mech in ('include', 'a', 'mx', 'exists', 'ptr') or mech.startswith('a/') or mech.startswith('mx/'):
            counter[0] += 1
        if mech == 'ip4' and ip and _ip_in_cidr(ip, arg):
            return qualifier + body, counter[0], errors
        if mech == 'a' and ip in _a_records(resolver, arg or domain):
            return qualifier + body, counter[0], errors
        if mech == 'mx':
            for record in resolver.query(arg or domain, 'MX'):
                counter[0] += 0  # MX host lookups count against the void/limit only loosely
                if ip in _a_records(resolver, record.split()[-1]):
                    return qualifier + body, counter[0], errors
        if mech == 'include' and arg and _depth < 10:
            matched, _, sub_errors = spf_evaluate(resolver, arg, ip, _depth + 1, counter)
            errors.extend(sub_errors)
            if matched and not matched.startswith(('-', '~', '?')) and not matched.endswith('all'):
                return qualifier + body, counter[0], errors
        if mech == 'all':
            return qualifier + 'all', counter[0], errors
    if redirect and _depth < 10:
        counter[0] += 1
        return spf_evaluate(resolver, redirect, ip, _depth + 1, counter)
    return None, counter[0], errors


def _ip_in_cidr(ip, cidr):
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def check_spf(resolver, domain, sending_ip):
    records = _spf_records(resolver, domain)
    if not records:
        return result('spf', 'SPF', FAIL, 'No SPF record.',
                      'Add TXT "v=spf1 a mx ip4:%s ~all" at %s.' % (sending_ip or '<server ip>', domain))
    matched, lookups, errors = spf_evaluate(resolver, domain, sending_ip)
    detail = records[0]
    if lookups > 10:
        errors.append('%d DNS lookups (limit 10, permerror)' % lookups)
    if errors:
        return result('spf', 'SPF', FAIL, detail + ' | ' + '; '.join(errors),
                      'Publish exactly one SPF record with at most 10 lookups.')
    if not sending_ip:
        return result('spf', 'SPF', INFO, detail)
    if matched and matched[0] == '+' and not matched.endswith('all'):
        return result('spf', 'SPF', PASS, '%s (this server matches %s)' % (detail, matched[1:]))
    if matched and matched == '+all':
        return result('spf', 'SPF', WARN, detail + ' (+all authorises every host)',
                      'Replace +all with ~all or -all.')
    return result('spf', 'SPF', FAIL, '%s (this server %s is not authorised)' % (detail, sending_ip),
                  'Add ip4:%s to the SPF record.' % sending_ip)


def _dkim_public_key(text):
    match = re.search(r'p=([A-Za-z0-9+/=\s"]+)', text)
    return re.sub(r'[\s"]', '', match.group(1)) if match else ''


def check_dkim(resolver, domain, selector='default', key_dir='/etc/opendkim/keys'):
    name = '%s._domainkey.%s' % (selector, domain)
    published = ''.join(resolver.query(name, 'TXT'))
    local_key = ''
    key_file = os.path.join(key_dir, domain, selector + '.txt')
    try:
        with open(key_file) as handle:
            local_key = _dkim_public_key(handle.read())
    except OSError:
        pass
    if not published:
        fix = 'Publish the TXT record from %s.' % key_file if local_key else 'Generate DKIM keys for the domain in the panel.'
        return result('dkim', 'DKIM', FAIL, 'No DKIM record at %s.' % name, fix)
    published_key = _dkim_public_key(published)
    if not published_key:
        return result('dkim', 'DKIM', FAIL, 'DKIM record at %s has no p= key.' % name,
                      'Re-publish the record from %s.' % key_file)
    if local_key and published_key != local_key:
        return result('dkim', 'DKIM', FAIL, 'Published key at %s does not match %s.' % (name, key_file),
                      'Update the DNS record with the key from %s.' % key_file)
    if not local_key:
        return result('dkim', 'DKIM', WARN, 'Record published at %s, but no local key found in %s.'
                      % (name, key_file), 'Mail from this server will not be signed with that key.')
    return result('dkim', 'DKIM', PASS, 'Key at %s matches the signing key.' % name)


def check_dmarc(resolver, domain):
    records = [t for t in resolver.query('_dmarc.' + domain, 'TXT') if t.lower().startswith('v=dmarc1')]
    if not records:
        return result('dmarc', 'DMARC', WARN, 'No DMARC record.',
                      'Add TXT "v=DMARC1; p=none; rua=mailto:postmaster@%s" at _dmarc.%s.' % (domain, domain))
    if len(records) > 1:
        return result('dmarc', 'DMARC', FAIL, 'Multiple DMARC records.', 'Keep exactly one.')
    tags = dict(part.strip().split('=', 1) for part in records[0].split(';') if '=' in part)
    policy = tags.get('p', '').strip().lower()
    if policy not in ('none', 'quarantine', 'reject'):
        return result('dmarc', 'DMARC', FAIL, records[0] + ' (invalid p= tag)', 'Set p=none, quarantine or reject.')
    status = PASS if policy in ('quarantine', 'reject') else INFO
    return result('dmarc', 'DMARC', status, '%s (policy: %s)' % (records[0], policy),
                  '' if status == PASS else 'Move to p=quarantine once reports look clean.')


def reverse_name(ip):
    match = IPV4_RE.match(ip or '')
    if not match:
        return None
    return '.'.join(reversed(match.groups())) + '.in-addr.arpa'


def check_ptr(resolver, ip, hostname):
    name = reverse_name(ip)
    if not name:
        return result('ptr', 'Reverse DNS (PTR)', INFO, 'No IPv4 sending address to check.')
    ptrs = resolver.query(name, 'PTR')
    if not ptrs:
        return result('ptr', 'Reverse DNS (PTR)', FAIL, '%s has no PTR record.' % ip,
                      'Ask your hosting provider to set the PTR of %s to %s.' % (ip, hostname or 'your mail hostname'))
    ptr = ptrs[0]
    forward = _a_records(resolver, ptr)
    if ip not in forward:
        return result('ptr', 'Reverse DNS (PTR)', FAIL, '%s -> %s, but %s does not resolve back to %s.'
                      % (ip, ptr, ptr, ip), 'Add an A record %s -> %s.' % (ptr, ip))
    if hostname and ptr.lower() != hostname.lower():
        return result('ptr', 'Reverse DNS (PTR)', WARN, '%s -> %s (forward-confirmed), but Postfix '
                      'myhostname is %s.' % (ip, ptr, hostname),
                      'Use the same name for PTR and myhostname.')
    return result('ptr', 'Reverse DNS (PTR)', PASS, '%s -> %s (forward-confirmed)' % (ip, ptr))


def check_dnsbl(resolver, ip, zones=DNSBL_ZONES):
    reverse = reverse_name(ip)
    if not reverse:
        return []
    prefix = reverse[:-len('.in-addr.arpa')]
    results = []
    for zone, label in zones:
        answers = _a_records(resolver, '%s.%s' % (prefix, zone))
        # 127.255.255.x answers are resolver/usage errors (e.g. Spamhaus via public DNS).
        listed = [a for a in answers if a.startswith('127.') and not a.startswith('127.255.255.')]
        blocked = [a for a in answers if a.startswith('127.255.255.')]
        if listed:
            txt = ' '.join(resolver.query('%s.%s' % (prefix, zone), 'TXT'))[:200]
            results.append(result('dnsbl:' + zone, label, FAIL, 'Listed (%s) %s' % (', '.join(listed), txt),
                                  'Stop the abuse source first, then request delisting from %s.' % label))
        elif blocked:
            results.append(result('dnsbl:' + zone, label, INFO, 'Query refused by %s (public resolver); '
                                  'result unknown.' % label))
        else:
            results.append(result('dnsbl:' + zone, label, PASS, 'Not listed'))
    return results


def domain_report(resolver, domain, server_ips, sending_ip, hostname, key_dir='/etc/opendkim/keys'):
    return [
        check_mx(resolver, domain, server_ips),
        check_mail_host(resolver, domain, server_ips),
        check_spf(resolver, domain, sending_ip),
        check_dkim(resolver, domain, key_dir=key_dir),
        check_dmarc(resolver, domain),
    ]


def server_report(resolver, sending_ip, hostname):
    return [check_ptr(resolver, sending_ip, hostname)] + check_dnsbl(resolver, sending_ip)


# --------------------------------------------------------------------------- ports / TLS

def _certificate_summary(der, expected_name, now=None):
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    cert = x509.load_der_x509_certificate(der)
    names = []
    try:
        names = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value \
            .get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    subject_cn = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    not_after = getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after
    expires = not_after.timestamp() if hasattr(not_after, 'timestamp') else 0
    now = now or time.time()
    self_signed = cert.issuer == cert.subject
    matches = bool(expected_name) and any(_name_matches(expected_name, n) for n in (names or subject_cn))
    return {
        'subject': ', '.join(subject_cn) or cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'names': names,
        'days_left': int((expires - now) // 86400),
        'self_signed': self_signed,
        'name_matches': matches,
    }


def _name_matches(hostname, pattern):
    hostname, pattern = hostname.lower().rstrip('.'), pattern.lower().rstrip('.')
    if pattern.startswith('*.'):
        return hostname.count('.') == pattern.count('.') and hostname.endswith(pattern[1:])
    return hostname == pattern


def _smtp_starttls(sock, timeout):
    sock.settimeout(timeout)
    reader = sock.makefile('rb')
    banner = reader.readline()
    if not banner.startswith(b'220'):
        raise OSError('unexpected banner %r' % banner[:60])
    sock.sendall(b'EHLO cyberpanel-debugger\r\n')
    capabilities = []
    while True:
        line = reader.readline()
        if not line:
            raise OSError('connection closed during EHLO')
        capabilities.append(line[4:].strip().upper())
        if line[3:4] != b'-':
            break
    if b'STARTTLS' not in capabilities:
        return False
    sock.sendall(b'STARTTLS\r\n')
    if not reader.readline().startswith(b'220'):
        raise OSError('STARTTLS refused')
    return True


def check_port(host, port, expected_name=None, timeout=6, connect=socket.create_connection, mode=None):
    name, default_mode = MAIL_PORTS.get(port, (str(port), 'plain'))
    mode = mode or default_mode
    title = '%s (%d)' % (name, port)
    try:
        sock = connect((host, port), timeout=timeout)
    except OSError as error:
        return result('port:%d' % port, title, FAIL, 'Cannot connect: %s' % error,
                      'Check that the service is running and the port is open in the firewall.')
    try:
        if mode == 'plain':
            return result('port:%d' % port, title, PASS, 'Accepting connections.')
        if mode == 'smtp' and not _smtp_starttls(sock, timeout):
            return result('port:%d' % port, title, WARN, 'Connected, but STARTTLS is not offered.',
                          'Enable TLS in Postfix (smtpd_tls_cert_file/key_file).')
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        tls = context.wrap_socket(sock, server_hostname=expected_name or host)
        sock = tls
        info = _certificate_summary(tls.getpeercert(binary_form=True), expected_name)
        detail = '%s, certificate %s (issuer %s), %d days left' % (
            tls.version(), info['subject'], info['issuer'], info['days_left'])
        if info['days_left'] < 0:
            return result('port:%d' % port, title, FAIL, detail + ', EXPIRED', 'Renew the mail certificate.')
        if info['self_signed']:
            return result('port:%d' % port, title, WARN, detail + ', self-signed',
                          'Issue a trusted certificate for the mail hostname.')
        if expected_name and not info['name_matches']:
            return result('port:%d' % port, title, WARN, '%s, not valid for %s' % (detail, expected_name),
                          'Issue a certificate that covers %s.' % expected_name)
        status = WARN if info['days_left'] < 14 else PASS
        return result('port:%d' % port, title, status, detail,
                      'Renew soon.' if status == WARN else '')
    except (OSError, ssl.SSLError, ValueError) as error:
        return result('port:%d' % port, title, FAIL, 'TLS handshake failed: %s' % error,
                      'Check the certificate configuration for this service.')
    finally:
        try:
            sock.close()
        except OSError:
            pass


def ports_report(host, expected_name=None, ports=None, connect=socket.create_connection):
    return [check_port(host, port, expected_name, connect=connect) for port in (ports or MAIL_PORTS)]


# --------------------------------------------------------------------------- logs

_SYSLOG_TS = re.compile(r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:?\d{2}|Z)?)\s+\S+\s+')
_POSTFIX = re.compile(r'(?P<prog>postfix(?:-[\w]+)?/[\w/-]+)\[\d+\]: (?P<msg>.*)$')
_QUEUED = re.compile(r'^(?P<qid>[0-9A-F]{6,}|[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]{10,}): (?P<rest>.*)$')
_KV = re.compile(r'(\w[\w-]*)=(<[^>]*>|[^,\s]*(?:\s\([^)]*\))?)')
_SASL_FAIL = re.compile(r'warning: (?P<host>[^\[\s]*)\[(?P<ip>[^\]]+)\]: SASL \w+ authentication failed')
_STATUS_REASON = re.compile(r'status=\w+ \((?P<reason>.*)\)$')


def parse_line(line):
    """Parse one syslog line into an event dict, or None if it is not a Postfix line."""
    ts_match = _SYSLOG_TS.match(line)
    body = line[ts_match.end():] if ts_match else line
    match = _POSTFIX.search(body)
    if not match:
        return None
    prog, msg = match.group('prog'), match.group('msg')
    event = {'ts': ts_match.group('ts') if ts_match else '', 'prog': prog.split('/', 1)[-1], 'raw': line.rstrip('\n')}
    sasl = _SASL_FAIL.search(msg)
    if sasl:
        event.update(kind='sasl_fail', ip=sasl.group('ip'))
        return event
    queued = _QUEUED.match(msg)
    if not queued:
        event['kind'] = 'other'
        return event
    event['qid'] = queued.group('qid')
    rest = queued.group('rest')
    fields = {key: value.strip('<>') for key, value in _KV.findall(rest)}
    if 'status' in fields:
        fields['status'] = fields['status'].split(' ', 1)[0]
        reason = _STATUS_REASON.search(rest)
        if reason:
            fields['reason'] = reason.group('reason')
    event['kind'] = 'queue'
    event['fields'] = fields
    if rest == 'removed':
        event['removed'] = True
    return event


def read_log_tail(paths=('/var/log/maillog', '/var/log/mail.log'), max_bytes=20 * 1024 * 1024):
    """Return the last max_bytes of the first existing mail log, as text lines."""
    for path in paths:
        try:
            with open(path, 'rb') as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                start = max(0, size - max_bytes)
                # Read one byte before the window to know whether it starts mid-line.
                handle.seek(max(0, start - 1))
                data = handle.read()
        except OSError:
            continue
        if start > 0:
            starts_on_boundary = data[:1] == b'\n'
            data = data[1:]
            if not starts_on_boundary:
                data = data.split(b'\n', 1)[1] if b'\n' in data else b''
        return path, data.decode('utf-8', 'replace').splitlines()
    return None, []


def build_messages(lines):
    """Group queue events by queue ID into message records, in log order."""
    messages = OrderedDict()
    sasl_failures = Counter()
    for line in lines:
        event = parse_line(line)
        if not event:
            continue
        if event['kind'] == 'sasl_fail':
            sasl_failures[event['ip']] += 1
            continue
        if event['kind'] != 'queue':
            continue
        record = messages.setdefault(event['qid'], {
            'qid': event['qid'], 'first_seen': event['ts'], 'from': '', 'client': '', 'sasl_username': '',
            'message_id': '', 'size': '', 'deliveries': [], 'removed': False,
        })
        fields = event['fields']
        for key in ('from', 'client', 'sasl_username', 'size'):
            if key in fields and not record[key]:
                record[key] = fields[key]
        if 'message-id' in fields:
            record['message_id'] = fields['message-id']
        if 'to' in fields and 'status' in fields:
            record['deliveries'].append({
                'ts': event['ts'], 'to': fields['to'], 'relay': fields.get('relay', ''),
                'dsn': fields.get('dsn', ''), 'status': fields['status'], 'delay': fields.get('delay', ''),
                'reason': fields.get('reason', ''),
            })
        if event.get('removed'):
            record['removed'] = True
    return messages, sasl_failures


def search_messages(messages, query='', status=''):
    """Filter message records by address/queue-ID/message-ID substring and delivery status."""
    query = (query or '').strip().lower()
    out = []
    for record in messages.values():
        if status and not any(d['status'] == status for d in record['deliveries']):
            continue
        if query:
            haystack = ' '.join([record['qid'], record['from'], record['sasl_username'], record['message_id'],
                                 record['client']] + [d['to'] for d in record['deliveries']]).lower()
            if query not in haystack:
                continue
        out.append(record)
    return out


def _normalise_reason(reason):
    reason = re.sub(r'\b[0-9a-f]{8,}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b|<[^>]*>', '…', reason)
    return reason[:160]


def log_summary(messages, sasl_failures, top=10):
    senders, recipients_domains, statuses, reasons = Counter(), Counter(), Counter(), Counter()
    for record in messages.values():
        sender = record['sasl_username'] or record['from']
        if sender and record['deliveries']:
            senders[sender] += len(record['deliveries'])
        for delivery in record['deliveries']:
            statuses[delivery['status']] += 1
            if '@' in delivery['to']:
                recipients_domains[delivery['to'].rsplit('@', 1)[1].lower()] += 1
            if delivery['status'] in ('deferred', 'bounced') and delivery['reason']:
                reasons[_normalise_reason(delivery['reason'])] += 1
    return {
        'messages': len(messages),
        'statuses': dict(statuses),
        'top_senders': senders.most_common(top),
        'top_recipient_domains': recipients_domains.most_common(top),
        'top_problems': reasons.most_common(top),
        'sasl_failures': sasl_failures.most_common(top),
    }


# --------------------------------------------------------------------------- queue / spam / test mail

def queue_summary(runner=subprocess.run):
    """Summarise `postqueue -j` (one JSON object per line)."""
    import json
    try:
        out = runner(['postqueue', '-j'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                     universal_newlines=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        return {'error': str(error)}
    count, oldest, destinations, queues = 0, None, Counter(), Counter()
    for line in (out.stdout or '').splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        count += 1
        queues[item.get('queue_name', '?')] += 1
        arrival = item.get('arrival_time')
        if arrival and (oldest is None or arrival < oldest):
            oldest = arrival
        for recipient in item.get('recipients', []):
            address = recipient.get('address', '')
            if '@' in address:
                destinations[address.rsplit('@', 1)[1].lower()] += 1
    return {
        'count': count,
        'queues': dict(queues),
        'oldest_age_hours': round((time.time() - oldest) / 3600, 1) if oldest else 0,
        'top_destinations': destinations.most_common(10),
    }


def spam_score(message, runner=subprocess.run, which=None):
    """Score a raw RFC 5322 message with rspamc or spamc, whichever is installed."""
    import shutil
    which = which or shutil.which
    if len(message) > 2 * 1024 * 1024:
        return {'error': 'Message is larger than 2 MB.'}
    if which('rspamc'):
        argv, engine = ['rspamc', 'symbols'], 'Rspamd'
    elif which('spamc'):
        argv, engine = ['spamc', '-R'], 'SpamAssassin'
    else:
        return {'error': 'Neither Rspamd (rspamc) nor SpamAssassin (spamc) is installed.'}
    try:
        out = runner(argv, input=message, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                     universal_newlines=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        return {'error': str(error)}
    report = (out.stdout or '') + (out.stderr or '')
    score = None
    match = re.search(r'Action: .*?\n.*?Score: (-?[\d.]+) / ([\d.]+)', report, re.S) or \
        re.search(r'^(-?[\d.]+)/([\d.]+)', report, re.M)
    if match:
        score = {'score': float(match.group(1)), 'threshold': float(match.group(2))}
    return {'engine': engine, 'score': score, 'report': report[:20000]}


def send_test_message(sender, recipient, hostname, runner=subprocess.run):
    """Hand a test message to the local sendmail. Returns the Message-ID to trace in the log."""
    if not valid_email(sender) or not valid_email(recipient):
        raise ValueError('Invalid sender or recipient address.')
    message_id = '<cp-debug-%d.%s@%s>' % (int(time.time()), os.urandom(4).hex(), hostname or 'localhost')
    body = (
        'From: %s\nTo: %s\nSubject: CyberPanel email debugger test\nMessage-ID: %s\n'
        'Date: %s\n\nThis is a test message sent by the CyberPanel email debugger.\n'
        % (sender, recipient, message_id, time.strftime('%a, %d %b %Y %H:%M:%S %z'))
    )
    out = runner(['sendmail', '-f', sender, '--', recipient], input=body, stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE, universal_newlines=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError((out.stderr or 'sendmail failed').strip()[:500])
    return message_id.strip('<>')

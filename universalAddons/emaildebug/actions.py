"""Root-side Email Debugger actions (dispatched by universalAddons/runner.py).

Arguments arrive from the web process but are re-validated here: this is the trust boundary.
"""
import subprocess

from universalAddons.emaildebug import service

MACHINE_IP_FILE = '/etc/cyberpanel/machineIP'


def _server_ip():
    try:
        with open(MACHINE_IP_FILE) as handle:
            ip = handle.read().split('\n', 1)[0].strip()
    except OSError:
        return ''
    return ip if service.IPV4_RE.match(ip) else ''


def _hostname():
    try:
        out = subprocess.run(['postconf', '-h', 'myhostname'], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, universal_newlines=True, timeout=15)
        name = (out.stdout or '').strip()
    except (OSError, subprocess.SubprocessError):
        name = ''
    return name if service.valid_domain(name) else ''


def context():
    return {'server_ip': _server_ip(), 'hostname': _hostname()}


def dns(domain):
    domain = (domain or '').strip().lower()
    if not service.valid_domain(domain):
        raise ValueError('Invalid domain name.')
    ip, hostname = _server_ip(), _hostname()
    resolver = service.DigResolver()
    return {
        'domain': domain,
        'server_ip': ip,
        'hostname': hostname,
        'domain_checks': service.domain_report(resolver, domain, [ip] if ip else [], ip, hostname),
        'server_checks': service.server_report(resolver, ip, hostname),
    }


def ports(target='local'):
    if target not in ('local', 'public'):
        raise ValueError('Invalid target.')
    hostname = _hostname()
    host = '127.0.0.1' if target == 'local' else (_server_ip() or '127.0.0.1')
    return {'host': host, 'hostname': hostname, 'checks': service.ports_report(host, hostname or None)}


def logs(query='', status='', limit=200):
    query = str(query or '')[:200]
    if status not in ('', 'sent', 'deferred', 'bounced', 'expired', 'undeliverable'):
        raise ValueError('Invalid status filter.')
    limit = max(1, min(int(limit or 200), 1000))
    path, lines = service.read_log_tail()
    if not path:
        raise ValueError('No mail log found (/var/log/maillog or /var/log/mail.log).')
    messages, sasl = service.build_messages(lines)
    matches = service.search_messages(messages, query, status)
    return {
        'log': path,
        'lines_scanned': len(lines),
        'summary': service.log_summary(messages, sasl),
        'total_matches': len(matches),
        'messages': matches[-limit:][::-1],  # newest first
    }


def queue():
    return service.queue_summary()


def spam(message):
    if not isinstance(message, str) or not message.strip():
        raise ValueError('Paste a complete message, including headers.')
    return service.spam_score(message)


def send(sender, recipient):
    return {'message_id': service.send_test_message(sender, recipient, _hostname())}


ACTIONS = {
    'context': context,
    'dns': dns,
    'ports': ports,
    'logs': logs,
    'queue': queue,
    'spam': spam,
    'send': send,
}

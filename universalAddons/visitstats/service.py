"""Visitor statistics: GoAccess reports per site, or a small built-in summary when GoAccess is missing.

Reports are built by root from the site's OpenLiteSpeed access log, /home/<site>/logs/<site>.access_log
(child domains share their master site's log), and kept under REPORT_DIR (root only, 0700). They are
never in a document root: the panel serves them through a view that checks the caller owns the site,
with a sandboxing Content-Security-Policy (the report embeds request paths, referrers and user
agents sent by anyone on the internet).

The log is opened by root without following links (every path component O_NOFOLLOW) and must be a
regular file with one link, so a site user cannot point it at another file. GoAccess reads it
through /dev/fd/N, the already opened file.
"""
import html
import ipaddress
import json
import os
import re
import stat
import time
from collections import Counter

REPORT_DIR = os.environ.get('UA_VISITSTATS_DIR', '/var/lib/cyberpanel-universal/visitstats')
ON_DEMAND_INTERVAL = 10 * 60      # a site owner may rebuild a report once per 10 minutes
GOACCESS_TIMEOUT = 1800
MEMORY_LIMIT = 1024 * 1024 * 1024
MAX_KEYS = 100000                 # cap on distinct values the built-in summary keeps per table
TOP = 25
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]{1,10}) (?P<path>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?')


class StatsError(ValueError):
    pass


# ----------------------------------------------------------------------------- paths and settings

def site_dir(domain, base=None):
    if not DOMAIN_RE.match(domain or ''):
        raise StatsError('Invalid site.')
    return os.path.join(base or REPORT_DIR, domain)


def ensure_dir(domain, base=None):
    base = base or REPORT_DIR
    os.makedirs(base, mode=0o700, exist_ok=True)
    os.chmod(base, 0o700)
    path = site_dir(domain, base)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def report_path(domain, base=None):
    return os.path.join(site_dir(domain, base), 'report.html')


def _read_json(path):
    try:
        with open(path) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def load_meta(domain, base=None):
    meta = _read_json(os.path.join(site_dir(domain, base), 'meta.json'))
    meta['anonymize'] = meta.get('anonymize', True) is not False   # privacy first: anonymised by default
    return meta


def save_meta(domain, meta, base=None):
    path = os.path.join(ensure_dir(domain, base), 'meta.json')
    with open(path + '.tmp', 'w') as handle:
        json.dump(meta, handle)
    os.replace(path + '.tmp', path)


def rate_limited(meta, now, interval=ON_DEMAND_INTERVAL):
    """Seconds to wait before the next on-demand report, or 0."""
    last = meta.get('requested', 0)
    return max(0, int(interval - (now - last))) if isinstance(last, (int, float)) else 0


# ----------------------------------------------------------------------------- the access log

def log_names(home):
    """(home directory, logs subdirectory, current log file name) for a site home /home/<master>."""
    master = os.path.basename(home.rstrip('/'))
    if not DOMAIN_RE.match(master) or os.path.dirname(home.rstrip('/')) != '/home':
        raise StatsError('Unexpected site home %s.' % home)
    return home.rstrip('/'), 'logs', '%s.access_log' % master


def _open_logs_dir(home):
    fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return os.open('logs', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
    finally:
        os.close(fd)


def open_log_file(dir_fd, name):
    """Open one log file inside the logs directory: no links, a regular file with one link only."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise StatsError('%s is not a plain log file.' % name)
    return fd


def open_logs(home, since=0, listdir=os.listdir):
    """File descriptors of the current access log and of rotated, uncompressed logs changed since
    `since` (so lines written just before a rotation are not lost). Oldest first."""
    home, _, current = log_names(home)
    try:
        dir_fd = _open_logs_dir(home)
    except OSError:
        raise StatsError('This site has no logs directory yet.')
    try:
        names = [n for n in listdir(dir_fd) if n == current or (n.startswith(current + '.') and
                                                                not n.endswith(('.gz', '.bz2', '.xz', '.zst')))]
        opened = []
        for name in names:
            try:
                fd = open_log_file(dir_fd, name)
            except (OSError, StatsError):
                continue
            mtime = os.fstat(fd).st_mtime
            if name != current and mtime < since:
                os.close(fd)
                continue
            opened.append((name != current, mtime, fd))
    finally:
        os.close(dir_fd)
    if not any(not rotated for rotated, _, _ in opened):
        for _, _, fd in opened:
            os.close(fd)
        raise StatsError('This site has no access log yet (no visits recorded).')
    opened.sort(key=lambda item: (not item[0], item[1]))
    return [fd for _, _, fd in opened]


# ----------------------------------------------------------------------------- GoAccess

def goaccess_version(output):
    match = re.search(r'GoAccess\s*-\s*(\d+)\.(\d+)(?:\.(\d+))?', output or '')
    return tuple(int(x or 0) for x in match.groups()) if match else None


def goaccess_command(binary, version, fds, db_dir, output, anonymize, title):
    argv = ['nice', '-n', '19', 'ionice', '-c', '3', binary, '--log-format=COMBINED', '--no-global-config',
            '--html-report-title=%s' % title, '-o', output]
    if anonymize:
        argv.append('--anonymize-ip')
    if version and version >= (1, 4, 0):
        argv += ['--persist', '--restore', '--db-path=%s' % db_dir]
    argv += ['/dev/fd/%d' % fd for fd in fds]
    return argv


# ----------------------------------------------------------------------------- built-in summary

def anonymize_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return '-'
    if address.version == 4:
        return str(ipaddress.ip_network('%s/24' % address, strict=False).network_address)
    return str(ipaddress.ip_network('%s/48' % address, strict=False).network_address)


def _day_key(day):
    try:
        return time.strftime('%Y-%m-%d', time.strptime(day, '%d/%b/%Y'))
    except ValueError:
        return '9999-' + day


def summarise(lines, anonymize=True):
    """Counts from COMBINED log lines: visits (unique visitor per day), pages, referrers, statuses, IPs."""
    hits, bytes_sent, bad = 0, 0, 0
    pages, referrers, statuses, ips, days = Counter(), Counter(), Counter(), Counter(), Counter()
    visitors = set()

    def bump(counter, key):
        if key in counter or len(counter) < MAX_KEYS:
            counter[key] += 1

    for raw in lines:
        line = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else raw
        match = COMBINED_RE.match(line.strip())
        if not match:
            bad += 1
            continue
        hits += 1
        ip = anonymize_ip(match.group('ip')) if anonymize else match.group('ip')
        day = match.group('time').split(':', 1)[0]
        size = match.group('size')
        bytes_sent += int(size) if size.isdigit() else 0
        status = match.group('status')
        statuses[status] += 1
        bump(ips, ip)
        if len(visitors) < MAX_KEYS * 10:
            visitor = (ip, day, match.group('agent') or '')
            if visitor not in visitors:
                visitors.add(visitor)
                days[day] += 1
        path = match.group('path').split('?', 1)[0][:300]
        if status[0] in '23':
            bump(pages, path)
        referer = (match.group('referer') or '')[:300]
        if referer and referer != '-':
            bump(referrers, referer)
    return {'hits': hits, 'visits': sum(days.values()), 'bytes': bytes_sent, 'unparsed': bad,
            'days': sorted(days.items(), key=lambda kv: _day_key(kv[0]))[-31:],
            'pages': pages.most_common(TOP), 'referrers': referrers.most_common(TOP),
            'statuses': sorted(statuses.items()), 'ips': ips.most_common(TOP), 'anonymized': bool(anonymize)}


def summary_html(summary, domain, generated=None):
    esc = html.escape

    def table(title, rows, head):
        body = ''.join('<tr><td>%s</td><td class="n">%s</td></tr>' % (esc(str(k)), esc(str(v))) for k, v in rows)
        return '<h2>%s</h2><table><tr><th>%s</th><th class="n">Count</th></tr>%s</table>' % (
            esc(title), esc(head), body or '<tr><td colspan="2">None</td></tr>')

    when = time.strftime('%Y-%m-%d %H:%M', time.localtime(generated or time.time()))
    return ('<!doctype html><html><head><meta charset="utf-8"><title>%s - IndiansCloud visitor statistics</title>'
            '<style>body{font-family:system-ui,sans-serif;margin:24px;color:#1e293b}table{border-collapse:collapse;'
            'margin-bottom:20px;min-width:50%%}td,th{border-bottom:1px solid #e2e8f0;padding:6px 10px;text-align:left;'
            'word-break:break-all}.n{text-align:right}.cards span{display:inline-block;background:#f1f5f9;'
            'border-radius:8px;padding:10px 16px;margin:0 8px 8px 0}</style></head><body>'
            '<h1>%s</h1><p>Built-in summary of the current access log (GoAccess is not installed), %s.%s</p>'
            '<div class="cards"><span><b>%d</b> visits</span><span><b>%d</b> requests</span><span><b>%.1f MB</b> sent'
            '</span></div>%s%s%s%s%s</body></html>') % (
        esc(domain), esc(domain), esc(when), ' IP addresses are anonymised.' if summary['anonymized'] else '',
        summary['visits'], summary['hits'], summary['bytes'] / 1048576.0,
        table('Visits per day', summary['days'], 'Day'), table('Top pages', summary['pages'], 'Page'),
        table('Top referrers', summary['referrers'], 'Referrer'), table('Status codes', summary['statuses'], 'Status'),
        table('Top visitor IPs', summary['ips'], 'IP address'))


def read_lines(fds, limit_bytes=2 * 1024 * 1024 * 1024):
    """Lines of the given open log files, in order, reading at most limit_bytes in total."""
    total = 0
    for fd in fds:
        with os.fdopen(os.dup(fd), 'rb') as handle:
            for line in handle:
                total += len(line)
                if total > limit_bytes:
                    return
                yield line


# ----------------------------------------------------------------------------- serving

REPORT_HEADERS = {
    # The report is untrusted HTML (it shows what visitors sent). Sandboxed without same-origin, its
    # scripts cannot read panel cookies or call panel endpoints; nothing may load from elsewhere.
    'Content-Security-Policy': "sandbox allow-scripts allow-popups; default-src 'none'; "
                               "script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
                               "font-src data:; frame-ancestors 'self'",
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'private, no-store',
    'Referrer-Policy': 'no-referrer',
}

"""Uptime monitoring: monitors, checks, the down/up state machine, history and statistics.

Everything lives in one SQLite file owned by the panel user (the web process and the minute cron
both run as that user; root is never involved). Results are kept for 30 days as one compact row
per check (monitor id, time, ok, milliseconds).

Checks go through notify.netguard: the host is resolved once, private, loopback and link-local
addresses are refused, and the connection goes to the address that was checked. Only monitors
saved by an administrator may reach this server itself (allow_local).
"""
import contextlib
import ipaddress
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

from universalAddons.notify import netguard

DB_PATH = os.environ.get('UA_UPTIME_DB', '/home/cyberpanel/ua-uptime/uptime.sqlite3')
INTERVALS = (1, 5, 15)
KEEP_DAYS = 30
FAILS_FOR_DOWN = 2
TIMEOUT = 8
MAX_REDIRECTS = 2
CONCURRENCY = 8
CERT_WARN_DAYS = 14
DEFAULT_LIMIT = 10
HOST_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
NAME_RE = re.compile(r'^[\w .,:/()@&+-]{1,60}$')

SCHEMA = """
CREATE TABLE IF NOT EXISTS monitors (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    port INTEGER,
    keyword TEXT NOT NULL DEFAULT '',
    keyword_mode TEXT NOT NULL DEFAULT '',
    interval INTEGER NOT NULL DEFAULT 5,
    allow_local INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL DEFAULT 'unknown',
    fails INTEGER NOT NULL DEFAULT 0,
    last_check INTEGER NOT NULL DEFAULT 0,
    last_ms INTEGER,
    last_error TEXT NOT NULL DEFAULT '',
    cert_expires INTEGER,
    created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS monitors_owner ON monitors (owner_id);
CREATE TABLE IF NOT EXISTS results (
    monitor_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    ok INTEGER NOT NULL,
    ms INTEGER,
    PRIMARY KEY (monitor_id, ts)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS results_ts ON results (ts);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    monitor_id INTEGER NOT NULL,
    started INTEGER NOT NULL,
    ended INTEGER,
    reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS incidents_monitor ON incidents (monitor_id, started);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""
FIELDS = ('id', 'owner_id', 'name', 'kind', 'target', 'port', 'keyword', 'keyword_mode', 'interval', 'allow_local',
          'enabled', 'state', 'fails', 'last_check', 'last_ms', 'last_error', 'cert_expires', 'created')


class UptimeError(ValueError):
    pass


# ----------------------------------------------------------------------------- store

def connect(path=None):
    path = path or DB_PATH
    if path != ':memory:':
        directory = os.path.dirname(path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        if not os.path.exists(path):
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600))
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA busy_timeout = 15000')
    if path != ':memory:':
        db.execute('PRAGMA journal_mode = WAL')
    db.executescript(SCHEMA)
    return db


@contextlib.contextmanager
def opened(path=None):
    db = connect(path)
    try:
        yield db
        db.commit()
    finally:
        db.close()


def _row(row):
    return {key: row[key] for key in FIELDS} if row is not None else None


def get(db, monitor_id):
    return _row(db.execute('SELECT * FROM monitors WHERE id = ?', (monitor_id,)).fetchone())


def owned(db, monitor_id, owner_id, is_admin=False):
    """The monitor if the caller may manage it (administrators: any), else PermissionError."""
    if isinstance(monitor_id, bool) or not isinstance(monitor_id, int):
        raise UptimeError('Invalid monitor.')
    monitor = get(db, monitor_id)
    if monitor is None or (not is_admin and monitor['owner_id'] != owner_id):
        raise PermissionError('Unknown monitor.')
    return monitor


def list_monitors(db, owner_id=None):
    if owner_id is None:
        rows = db.execute('SELECT * FROM monitors ORDER BY owner_id, name, id')
    else:
        rows = db.execute('SELECT * FROM monitors WHERE owner_id = ? ORDER BY name, id', (owner_id,))
    return [_row(r) for r in rows]


def count(db, owner_id):
    return db.execute('SELECT COUNT(*) FROM monitors WHERE owner_id = ?', (owner_id,)).fetchone()[0]


# ----------------------------------------------------------------------------- validation

def _str(spec, key, limit):
    value = spec.get(key, '')
    if value is None:
        value = ''
    if not isinstance(value, str) or len(value) > limit:
        raise UptimeError('Invalid %s.' % key)
    return value.strip()


def _host(value):
    value = (value or '').strip().lower().rstrip('.')
    try:
        return str(ipaddress.ip_address(value.strip('[]')))
    except ValueError:
        pass
    if not HOST_RE.match(value):
        raise UptimeError('Enter a host name or IP address.')
    return value


def validate(spec):
    """Clean monitor settings from the browser (no network)."""
    if not isinstance(spec, dict):
        raise UptimeError('Invalid monitor.')
    kind = spec.get('kind', 'http')
    if kind not in ('http', 'tcp'):
        raise UptimeError('Choose an HTTP(S) or TCP check.')
    interval = spec.get('interval', 5)
    if isinstance(interval, bool) or interval not in INTERVALS:
        raise UptimeError('Check every 1, 5 or 15 minutes.')
    clean = {'kind': kind, 'interval': interval, 'enabled': spec.get('enabled', True) is not False,
             'keyword': '', 'keyword_mode': '', 'port': None}
    if kind == 'http':
        url = _str(spec, 'url', 500)
        try:
            scheme, host, port, _ = netguard.split_url(url)
        except netguard.GuardError as exc:
            raise UptimeError(str(exc))
        clean['target'] = url
        keyword = _str(spec, 'keyword', 100)
        mode = spec.get('keyword_mode') or ''
        if mode not in ('', 'present', 'absent'):
            raise UptimeError('Invalid keyword rule.')
        if keyword and not mode:
            mode = 'present'
        if mode and not keyword:
            raise UptimeError('Enter the keyword to look for.')
        clean.update(keyword=keyword, keyword_mode=mode)
        default_name = host
    else:
        clean['target'] = _host(_str(spec, 'host', 253))
        port = spec.get('port')
        if isinstance(port, str) and port.isdigit():
            port = int(port)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise UptimeError('Enter a TCP port from 1 to 65535.')
        clean['port'] = port
        default_name = '%s:%d' % (clean['target'], port)
    name = _str(spec, 'name', 60) or default_name[:60]
    if not NAME_RE.match(name):
        raise UptimeError('Use letters, digits and spaces in the monitor name.')
    clean['name'] = name
    return clean


def target_host_port(monitor):
    if monitor['kind'] == 'tcp':
        return monitor['target'], monitor['port']
    _, host, port, _ = netguard.split_url(monitor['target'])
    return host, port


def check_target(monitor, allow_local, resolver=None, local=None):
    """Refuse a target that resolves to a private, loopback or link-local address (at save time)."""
    host, port = target_host_port(monitor)
    try:
        netguard.resolve(host, port, allow_local, resolver or netguard.socket.getaddrinfo, local)
    except netguard.GuardError as exc:
        raise UptimeError(str(exc))


def save(db, owner_id, spec, is_admin=False, limit=DEFAULT_LIMIT, monitor_id=None, resolver=None, now=None,
         local=None):
    clean = validate(spec)
    check_target(clean, is_admin, resolver, local)
    now = int(time.time() if now is None else now)
    if monitor_id is None:
        if not is_admin and count(db, owner_id) >= limit:
            raise UptimeError('Your account may have at most %d monitors.' % limit)
        cursor = db.execute(
            'INSERT INTO monitors (owner_id, name, kind, target, port, keyword, keyword_mode, interval, allow_local, '
            'enabled, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (owner_id, clean['name'], clean['kind'], clean['target'], clean['port'], clean['keyword'],
             clean['keyword_mode'], clean['interval'], int(bool(is_admin)), int(clean['enabled']), now))
        monitor_id = cursor.lastrowid
    else:
        current = get(db, monitor_id)
        changed_target = (current['kind'], current['target'], current['port']) != \
            (clean['kind'], clean['target'], clean['port'])
        db.execute('UPDATE monitors SET name = ?, kind = ?, target = ?, port = ?, keyword = ?, keyword_mode = ?, '
                   'interval = ?, allow_local = ?, enabled = ? WHERE id = ?',
                   (clean['name'], clean['kind'], clean['target'], clean['port'], clean['keyword'],
                    clean['keyword_mode'], clean['interval'], int(bool(is_admin)), int(clean['enabled']), monitor_id))
        if changed_target:
            db.execute("UPDATE monitors SET state = 'unknown', fails = 0, cert_expires = NULL WHERE id = ?",
                       (monitor_id,))
    db.commit()
    return get(db, monitor_id)


def delete(db, monitor_id):
    for table, column in (('results', 'monitor_id'), ('incidents', 'monitor_id'), ('monitors', 'id')):
        db.execute('DELETE FROM %s WHERE %s = ?' % (table, column), (monitor_id,))
    db.commit()


# ----------------------------------------------------------------------------- checks

def run_check(monitor, http=None, tcp=None, local=None):
    """One check. Returns {'ok', 'ms', 'error', 'cert_expires'}."""
    allow_local = bool(monitor.get('allow_local'))
    try:
        if monitor['kind'] == 'tcp':
            ms = (tcp or netguard.tcp_check)(monitor['target'], monitor['port'], timeout=TIMEOUT,
                                              allow_local=allow_local, local=local)
            return {'ok': True, 'ms': ms, 'error': '', 'cert_expires': None}
        response = (http or netguard.request)(monitor['target'], timeout=TIMEOUT, allow_local=allow_local,
                                              max_redirects=MAX_REDIRECTS, local=local)
    except netguard.GuardError as exc:
        return {'ok': False, 'ms': None, 'error': str(exc)[:300], 'cert_expires': None}
    result = {'ok': True, 'ms': response['ms'], 'error': '', 'cert_expires': response.get('cert_expires')}
    if not 200 <= response['status'] < 400:
        result.update(ok=False, error='HTTP %d' % response['status'])
    elif monitor.get('keyword_mode'):
        found = monitor['keyword'].encode('utf-8') in (response.get('body') or b'')
        if monitor['keyword_mode'] == 'present' and not found:
            result.update(ok=False, error='Keyword "%s" not found' % monitor['keyword'])
        if monitor['keyword_mode'] == 'absent' and found:
            result.update(ok=False, error='Keyword "%s" found' % monitor['keyword'])
    return result


def transition(state, fails, ok, needed=FAILS_FOR_DOWN):
    """The down/up state machine. Returns (new state, new failure count, 'down'/'up'/None).

    A monitor is down after `needed` failures in a row and up again after one success. The first
    success of a new monitor makes it up without an "up" event (nothing was down).
    """
    if ok:
        return 'up', 0, ('up' if state == 'down' else None)
    fails += 1
    if fails >= needed and state != 'down':
        return 'down', fails, 'down'
    return state, fails, None


def _notify(*args, **kwargs):
    from universalAddons import notify
    return notify.send(*args, **kwargs)


def apply_result(db, monitor, result, now, notifier=_notify):
    """Store a check result, move the state machine, open/close incidents and send alerts."""
    now = int(now)
    state, fails, change = transition(monitor['state'], monitor['fails'], result['ok'])
    db.execute('INSERT OR REPLACE INTO results (monitor_id, ts, ok, ms) VALUES (?, ?, ?, ?)',
               (monitor['id'], now, int(result['ok']), result['ms']))
    db.execute('UPDATE monitors SET state = ?, fails = ?, last_check = ?, last_ms = ?, last_error = ?, '
               'cert_expires = COALESCE(?, cert_expires) WHERE id = ?',
               (state, fails, now, result['ms'], result['error'], result.get('cert_expires'), monitor['id']))
    label = monitor['name']
    if change == 'down':
        db.execute('INSERT INTO incidents (monitor_id, started, reason) VALUES (?, ?, ?)',
                   (monitor['id'], now, result['error'][:300]))
    elif change == 'up':
        db.execute('UPDATE incidents SET ended = ? WHERE monitor_id = ? AND ended IS NULL', (now, monitor['id']))
    db.commit()
    try:
        if change == 'down':
            notifier(monitor['owner_id'], 'uptime', '%s is DOWN' % label,
                     '%s (%s) failed %d checks in a row: %s' % (label, describe(monitor), fails, result['error']),
                     'error', key='uptime:%d' % monitor['id'], state='down')
        elif change == 'up':
            notifier(monitor['owner_id'], 'uptime', '%s is back UP' % label,
                     '%s (%s) answers again (%s ms).' % (label, describe(monitor), result['ms']),
                     'info', key='uptime:%d' % monitor['id'], state='up', recovery=True)
        expires = result.get('cert_expires')
        if expires:
            days = int((expires - now) // 86400)
            if days <= CERT_WARN_DAYS:
                notifier(monitor['owner_id'], 'ssl_expiry', 'Certificate of %s expires in %d day(s)' % (label, days),
                         'The TLS certificate served by %s expires on %s.' % (describe(monitor), time.strftime(
                             '%Y-%m-%d', time.gmtime(expires))), 'warning' if days > 3 else 'error',
                         key='uptime-cert:%d' % monitor['id'], state='expiring:%d' % days, window=86400)
    except Exception:
        pass   # an alert that cannot be sent never stops the checks
    return state, change


def describe(monitor):
    return monitor['target'] if monitor['kind'] == 'http' else '%s:%s' % (monitor['target'], monitor['port'])


def due(db, now):
    rows = db.execute('SELECT * FROM monitors WHERE enabled = 1 AND last_check + interval * 60 - 10 <= ? '
                      'ORDER BY last_check LIMIT 500', (int(now),))
    return [_row(r) for r in rows]


def run_due(db, now=None, checker=run_check, notifier=_notify, concurrency=CONCURRENCY, local=None):
    now = time.time() if now is None else now
    monitors = due(db, now)
    if not monitors:
        return 0
    local = netguard.server_addresses() if local is None else local
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, len(monitors)))) as pool:
        results = list(pool.map(lambda m: checker(m, local=local), monitors))
    for monitor, result in zip(monitors, results):
        apply_result(db, monitor, result, now, notifier)
    return len(monitors)


def prune(db, now=None):
    cutoff = int((time.time() if now is None else now) - KEEP_DAYS * 86400)
    db.execute('DELETE FROM results WHERE ts < ?', (cutoff,))
    db.execute('DELETE FROM incidents WHERE ended IS NOT NULL AND ended < ?', (cutoff,))
    db.execute("DELETE FROM results WHERE monitor_id NOT IN (SELECT id FROM monitors)")
    db.commit()


# ----------------------------------------------------------------------------- statistics

def uptime_percent(db, monitor_id, since):
    row = db.execute('SELECT COUNT(*), SUM(ok) FROM results WHERE monitor_id = ? AND ts >= ?',
                     (monitor_id, int(since))).fetchone()
    return round(100.0 * (row[1] or 0) / row[0], 2) if row[0] else None


def buckets(db, monitor_id, now, hours=24, count_=48):
    """[(average ms or None, failures, checks)] over the last `hours`, oldest first."""
    start = int(now - hours * 3600)
    size = hours * 3600 / float(count_)
    out = [[0, 0, 0, 0] for _ in range(count_)]   # ms sum, ms count, failures, checks
    for ts, ok, ms in db.execute('SELECT ts, ok, ms FROM results WHERE monitor_id = ? AND ts >= ? ORDER BY ts',
                                 (monitor_id, start)):
        index = min(count_ - 1, int((ts - start) / size))
        bucket = out[index]
        bucket[3] += 1
        if ok:
            if ms is not None:
                bucket[0] += ms
                bucket[1] += 1
        else:
            bucket[2] += 1
    return [((b[0] // b[1]) if b[1] else None, b[2], b[3]) for b in out]


def sparkline_svg(points, width=240, height=40):
    """Inline SVG: response time line, red marks where checks failed, grey where there is no data."""
    values = [p[0] for p in points if p[0] is not None]
    top = max(values) if values else 1
    step = width / float(max(1, len(points) - 1))
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" '
             'role="img" aria-label="Response time, last 24 hours" class="ua-spark">' % (width, height, width, height)]
    for index, (ms, failures, checks) in enumerate(points):
        if failures:
            parts.append('<rect x="%.1f" y="0" width="%.1f" height="%d" fill="#ef4444" opacity="0.35"/>'
                         % (max(0, index * step - step / 2), step, height))
    segments, current = [], []
    for index, (ms, _, _) in enumerate(points):
        if ms is None:
            if current:
                segments.append(current)
            current = []
            continue
        y = height - 3 - (height - 6) * (ms / float(top or 1))
        current.append('%.1f,%.1f' % (index * step, y))
    if current:
        segments.append(current)
    for segment in segments:
        if len(segment) == 1:
            x, y = segment[0].split(',')
            parts.append('<circle cx="%s" cy="%s" r="1.5" fill="#2563eb"/>' % (x, y))
        else:
            parts.append('<polyline fill="none" stroke="#2563eb" stroke-width="1.5" points="%s"/>' % ' '.join(segment))
    parts.append('</svg>')
    return ''.join(parts)


def summary(db, monitor, now=None):
    now = time.time() if now is None else now
    points = buckets(db, monitor['id'], now)
    ms = [p[0] for p in points if p[0] is not None]
    cert_days = int((monitor['cert_expires'] - now) // 86400) if monitor.get('cert_expires') else None
    return dict(monitor, target_label=describe(monitor),
                uptime_24h=uptime_percent(db, monitor['id'], now - 86400),
                uptime_7d=uptime_percent(db, monitor['id'], now - 7 * 86400),
                uptime_30d=uptime_percent(db, monitor['id'], now - 30 * 86400),
                avg_ms=(sum(ms) // len(ms)) if ms else None, sparkline=sparkline_svg(points), cert_days=cert_days)


def incidents(db, monitor_id, limit=50):
    rows = db.execute('SELECT started, ended, reason FROM incidents WHERE monitor_id = ? ORDER BY started DESC LIMIT ?',
                      (monitor_id, limit))
    return [{'started': r[0], 'ended': r[1], 'reason': r[2],
             'minutes': ((r[1] or int(time.time())) - r[0]) // 60} for r in rows]


def recent_results(db, monitor_id, limit=30):
    rows = db.execute('SELECT ts, ok, ms FROM results WHERE monitor_id = ? ORDER BY ts DESC LIMIT ?',
                      (monitor_id, limit))
    return [{'ts': r[0], 'ok': bool(r[1]), 'ms': r[2]} for r in rows]

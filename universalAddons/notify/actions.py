"""Root-side notification actions (dispatched by universalAddons/runner.py).

server_check runs from cron every five minutes. It looks at the disks, swap and the services on the
Services page, and once an hour at the websites' disk usage against their package quota. Only when
something is wrong (or was wrong at the previous run) does it load the panel database and notify
the administrators (and site owners, for quotas) who have saved notification settings: these alerts
are new, so nobody receives them without opting in on the Notifications page.
"""
import json
import os
import subprocess
import time

from universalAddons.notify import service

STATE_FILE = os.environ.get('UA_NOTIFY_SERVER_STATE', '/var/lib/cyberpanel-universal/notify-server.json')
CRON_FILE = '/etc/cron.d/cyberpanel-universal-notify'
FS_TYPES = ('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'zfs')
QUOTA_EVERY = 3600
QUOTA_PERCENT = 90

# Units shown on the Services page (core services and the extra ones), when installed and enabled.
SERVICE_UNITS = (
    ('lsws', 'LiteSpeed web server'), ('mariadb', 'MariaDB'), ('mysqld', 'MySQL'), ('pdns', 'PowerDNS'),
    ('pure-ftpd', 'Pure-FTPd'), ('postfix', 'Postfix'), ('dovecot', 'Dovecot (IMAP/POP3)'),
    ('opendkim', 'OpenDKIM'), ('spamassassin', 'SpamAssassin'), ('rspamd', 'Rspamd'), ('mailscanner', 'MailScanner'),
    ('cpecs', 'Email limits policy (cpecs)'), ('cp-webterm', 'Web Terminal'), ('httpd', 'Apache httpd'),
    ('redis', 'Redis'), ('memcached', 'Memcached'), ('elasticsearch', 'Elasticsearch'), ('docker', 'Docker'),
)


# ----------------------------------------------------------------------------- measurements

def disks(mounts='/proc/mounts', statvfs=os.statvfs):
    """[(mount point, percent used)] of local disk filesystems, like df."""
    seen, rows = set(), []
    try:
        with open(mounts) as handle:
            lines = handle.read().splitlines()
    except OSError:
        return rows
    for line in lines:
        parts = line.split()
        if len(parts) < 3 or parts[2] not in FS_TYPES or parts[0] in seen:
            continue
        seen.add(parts[0])
        try:
            info = statvfs(parts[1])
        except OSError:
            continue
        used = info.f_blocks - info.f_bfree
        if used + info.f_bavail <= 0:
            continue
        rows.append((parts[1], int(round(100.0 * used / (used + info.f_bavail)))))
    return rows


def swap_percent(meminfo='/proc/meminfo'):
    values = {}
    try:
        with open(meminfo) as handle:
            for line in handle:
                name, _, rest = line.partition(':')
                values[name] = int(rest.split()[0]) if rest.split() else 0
    except (OSError, ValueError):
        return None
    total = values.get('SwapTotal', 0)
    if not total:
        return None
    return int(round(100.0 * (total - values.get('SwapFree', 0)) / total))


def parse_show(text):
    """Parse `systemctl show -p Id,LoadState,UnitFileState,ActiveState u1 u2...` output."""
    units, current = {}, {}
    for line in (text or '').splitlines() + ['']:
        if not line.strip():
            if current.get('Id'):
                units[current['Id'].rsplit('.service', 1)[0]] = current
            current = {}
            continue
        key, _, value = line.partition('=')
        current[key] = value
    return units


def down_services(runner=subprocess.run):
    """Labels of enabled services that are not running."""
    names = [unit for unit, _ in SERVICE_UNITS]
    try:
        output = runner(['systemctl', 'show', '-p', 'Id,LoadState,UnitFileState,ActiveState', '--'] +
                        ['%s.service' % n for n in names], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        universal_newlines=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    units = parse_show(output)
    down = []
    for unit, label in SERVICE_UNITS:
        info = units.get(unit) or {}
        if info.get('LoadState') == 'loaded' and info.get('UnitFileState') == 'enabled' \
                and info.get('ActiveState') not in ('active', 'activating', 'reloading'):
            down.append('%s (%s)' % (label, unit))
    return down


def conditions(thresholds, measure=None):
    """{key: (state, title, body, event)} for every condition currently checked."""
    measure = measure or {}
    disk_rows = measure['disks'] if 'disks' in measure else disks()
    swap = measure['swap'] if 'swap' in measure else swap_percent()
    down = measure['down'] if 'down' in measure else down_services()
    host = service.hostname()
    found = {}
    for mount, percent in disk_rows:
        high = percent >= thresholds['disk']
        found['disk:%s' % mount] = ('high' if high else 'ok', 'server_disk',
                                    ('Disk %s is %d%% full on %s' if high else 'Disk %s is back to %d%% on %s')
                                    % (mount, percent, host),
                                    'The filesystem mounted at %s is %d%% used (alert threshold %d%%).'
                                    % (mount, percent, thresholds['disk']))
    if swap is not None:
        high = swap >= thresholds['swap']
        found['swap'] = ('high' if high else 'ok', 'server_swap',
                         ('Swap is %d%% used on %s' if high else 'Swap is back to %d%% on %s') % (swap, host),
                         'Swap usage is %d%% (alert threshold %d%%). Heavy swapping slows every site; look for '
                         'processes using a lot of memory.' % (swap, thresholds['swap']))
    found['services'] = ('down:' + ','.join(sorted(down)) if down else 'ok', 'server_service',
                         ('Service down on %s: %s' % (host, ', '.join(down))) if down
                         else 'All services are running again on %s' % host,
                         ('These enabled services are not running: %s. Open Server Status > Services in '
                          'IndiansCloud to start them.' % ', '.join(down)) if down else 'Every enabled service runs.')
    return found


# ----------------------------------------------------------------------------- the check

def _load_state():
    try:
        with open(STATE_FILE) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(data):
    os.makedirs(os.path.dirname(STATE_FILE), mode=0o700, exist_ok=True)
    with open(STATE_FILE + '.tmp', 'w') as handle:
        json.dump(data, handle)
    os.replace(STATE_FILE + '.tmp', STATE_FILE)


def _configured_accounts():
    try:
        names = os.listdir(os.path.join(service.NOTIFY_DIR, 'accounts'))
    except OSError:
        return []
    return sorted(int(n[:-5]) for n in names if n.endswith('.json') and n[:-5].isdigit())


def server_check(measure=None, admins=None, sender=None, now=None):
    now = time.time() if now is None else now
    sender = sender or service.send
    configured = set(_configured_accounts())
    if not configured:
        return {'checked': False, 'reason': 'nobody has saved notification settings'}
    measure = measure if measure is not None else {'disks': disks(), 'swap': swap_percent(), 'down': down_services()}
    state = _load_state()
    previous = state.get('conditions', {})
    # One threshold set for the server: the first configured administrator's (defaults otherwise).
    thresholds = dict(service.DEFAULT_THRESHOLDS)
    found = None
    result = {'checked': True, 'alerts': 0}
    if admins is None:
        quiet = previous and all(v == 'ok' for v in previous.values())
        probe = conditions(thresholds, measure)
        if quiet and all(v[0] == 'ok' for v in probe.values()) and now - state.get('quota_at', 0) < QUOTA_EVERY:
            state['conditions'] = {k: v[0] for k, v in probe.items()}
            _save_state(state)
            return result   # nothing wrong now or before: no database needed
        admins = [pk for pk, _ in service.admin_accounts() if pk in configured]
    else:
        admins = [pk for pk in admins if pk in configured]
    if admins:
        thresholds = service.load_account(admins[0])['thresholds']
    found = conditions(thresholds, measure)
    for key, (cond, event, title, body) in found.items():
        recovery = cond == 'ok'
        for pk in admins:
            outcome = sender(pk, event, title, body, 'info' if recovery else 'critical', key='server:' + key,
                             state=cond, recovery=recovery)
            result['alerts'] += outcome.get('sent', 0) if isinstance(outcome, dict) else 0
    state['conditions'] = {k: v[0] for k, v in found.items()}
    if now - state.get('quota_at', 0) >= QUOTA_EVERY:
        state['quota_at'] = now
        try:
            result['quota_alerts'] = quota_check(configured, sender)
        except Exception as exc:
            result['quota_error'] = str(exc)[:200]
    _save_state(state)
    return result


def quota_rows():
    """[(owner pk, domain, used MB, quota MB)] from the Resource Limits disk scan and the packages."""
    from universalAddons.limits import service as limits
    from universalAddons import django_env
    django_env.setup()
    from websiteFunctions.models import Websites
    cache = limits.load_du_cache()
    rows = []
    for site in Websites.objects.select_related('package', 'admin'):
        quota = getattr(site.package, 'diskSpace', 0) or 0
        usage = cache.get(site.domain)
        if quota > 0 and isinstance(usage, dict) and isinstance(usage.get('kb'), int):
            rows.append((site.admin.pk, site.domain, usage['kb'] // 1024, quota))
    return rows


def quota_check(configured, sender, rows=None):
    sent = 0
    for owner, domain, used, quota in (quota_rows() if rows is None else rows):
        if owner not in configured:
            continue
        percent = int(100.0 * used / quota)
        high = percent >= QUOTA_PERCENT
        outcome = sender(owner, 'disk_quota',
                         ('%s uses %d%% of its disk quota' if high else '%s is back to %d%% of its disk quota')
                         % (domain, percent),
                         '%s uses %d MB of its %d MB disk quota (measured by the last disk scan).' % (domain, used, quota),
                         'info' if not high else 'warning', key='quota:' + domain, state='high' if high else 'ok',
                         recovery=not high)
        sent += outcome.get('sent', 0) if isinstance(outcome, dict) else 0
    return sent


ACTIONS = {
    'server_check': lambda: server_check(),
}

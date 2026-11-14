"""Per-site resource limits through OpenLiteSpeed's own per-external-application settings.

Why this mechanism
- Each site's PHP runs as the site's own Linux user through OpenLiteSpeed's lsphp (LSAPI suEXEC),
  started from the site's `extprocessor <user> { ... }` block in its vhost.conf. OpenLiteSpeed applies
  that block's limits itself as POSIX rlimits on the lsphp processes, so they work on cgroup v1:
    memSoftLimit/memHardLimit  -> RLIMIT_AS   (address space per lsphp process)
    procSoftLimit/procHardLimit -> RLIMIT_NPROC (tasks of the site user; checked at fork)
    maxConns                   -> concurrent requests OpenLiteSpeed sends to the site's PHP
    (PHP_)LSAPI_CHILDREN env   -> PHP worker processes lsphp may fork (the effective CPU cap:
                                  a site can occupy at most this many runnable PHP workers)
    instances, initTimeout, retryTimeout, priority (nice level, relative only)
- CPU shares/quotas through cgroups are NOT used: OpenLiteSpeed's cgroup support needs cgroup v2
  user slices, and on cgroup v1 every lsphp lives in system.slice/lshttpd.service. Nothing here
  writes to /sys/fs/cgroup or moves processes.

Safety model
- Only the listed keys inside the site's own extprocessor (named after the site user, type lsapi)
  change; every other byte of vhost.conf is kept, including line endings and a missing final newline.
- Structural brace balance is checked before and after; brace counts must not change.
- Preview first (unified diff + a token); apply recomputes and refuses if anything changed since.
- Apply = backup, atomic write, graceful OpenLiteSpeed restart, then every changed site must answer
  with the same HTTP status as before. Otherwise all files are restored and OpenLiteSpeed restarted.
"""
import difflib
import hashlib
import json
import os
import re
import subprocess
import time
from collections import OrderedDict

LIMITS_FILE = '/etc/cyberpanel/limits.json'
STATE_DIR = '/var/lib/cyberpanel-universal'
BACKUP_DIR = os.path.join(STATE_DIR, 'limits-backups')
DU_CACHE = os.path.join(STATE_DIR, 'limits-du.json')
LOCK_FILE = os.path.join(STATE_DIR, 'limits.lock')
VHOSTS = '/usr/local/lsws/conf/vhosts'
OVERRIDES = 'overrides'

# An idle lsphp already maps ~620 MB of address space on this host (VSZ), and memSoftLimit is an
# RLIMIT_AS: a limit close to that stops PHP from starting. Below this the preview warns.
LSPHP_SAFE_AS_MB = 900
MIN_MEMORY_MB = 256
MIN_PROCESSES = 10

ENV_CHILDREN = 'children'
# internal key -> (OpenLiteSpeed key, minimum, maximum, label)
FIELDS = OrderedDict([
    ('mem_soft_mb', ('memSoftLimit', MIN_MEMORY_MB, 65536, 'Memory soft limit per PHP process (MB)')),
    ('mem_hard_mb', ('memHardLimit', MIN_MEMORY_MB, 65536, 'Memory hard limit per PHP process (MB)')),
    ('proc_soft', ('procSoftLimit', MIN_PROCESSES, 10000, 'Process soft limit of the site user')),
    ('proc_hard', ('procHardLimit', MIN_PROCESSES, 10000, 'Process hard limit of the site user')),
    ('max_conns', ('maxConns', 1, 200, 'Concurrent PHP connections')),
    ('children', (ENV_CHILDREN, 1, 200, 'PHP worker processes (LSAPI_CHILDREN)')),
    ('instances', ('instances', 1, 20, 'lsphp instances')),
    ('init_timeout', ('initTimeout', 1, 3600, 'Initial request timeout (s)')),
    ('retry_timeout', ('retryTimeout', 0, 3600, 'Retry timeout (s)')),
    ('priority', ('priority', 0, 19, 'CPU priority (nice 0-19; relative, not a cap)')),
])
OLS_KEYS = {spec[0]: key for key, spec in FIELDS.items() if spec[0] != ENV_CHILDREN}
MEMORY_KEYS = ('mem_soft_mb', 'mem_hard_mb')

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
PACKAGE_RE = re.compile(r'^[A-Za-z0-9_.-]{1,50}$')

_OPEN = re.compile(r'^\s*([A-Za-z_][\w.]*)(?:\s+(\S+))?\s*\{\s*$')
_CLOSE = re.compile(r'^\s*\}\s*$')
_KEY_LINE = re.compile(r'^(\s*)([A-Za-z_]\w*)(\s+)(.*?)(\s*)$')
_ENV_LINE = re.compile(r'^(\s*env\s+)((?:PHP_)?LSAPI_CHILDREN)(\s*=\s*)(\S*?)(\s*)$')


class LimitsError(ValueError):
    pass


def run(argv, runner=subprocess.run, timeout=120):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=timeout)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


# ----------------------------------------------------------------------------- validation / defaults

def validate_limits(data, partial=True):
    """Clean a limits dict. Missing, None or '' means "inherit / leave as is"."""
    if not isinstance(data, dict):
        raise LimitsError('Limits must be an object.')
    unknown = sorted(set(data) - set(FIELDS))
    if unknown:
        raise LimitsError('Unknown limit %s.' % unknown[0])
    clean = {}
    for key, (ols_key, low, high, label) in FIELDS.items():
        value = data.get(key)
        if value is None or value == '':
            continue
        if isinstance(value, bool):
            raise LimitsError('%s must be a whole number.' % label)
        if isinstance(value, str) and re.match(r'^\d{1,6}$', value.strip()):
            value = int(value.strip())
        if not isinstance(value, int):
            raise LimitsError('%s must be a whole number.' % label)
        if not low <= value <= high:
            raise LimitsError('%s must be between %d and %d.' % (label, low, high))
        clean[key] = value
    check_consistency(clean)
    return clean


def check_consistency(limits):
    pairs = (('mem_soft_mb', 'mem_hard_mb', 'The memory soft limit cannot be above the hard limit.'),
             ('proc_soft', 'proc_hard', 'The process soft limit cannot be above the hard limit.'),
             ('max_conns', 'children', 'Concurrent connections cannot exceed PHP workers (LSAPI_CHILDREN); '
                                       'OpenLiteSpeed would queue requests on workers that do not exist.'))
    for low, high, message in pairs:
        if low in limits and high in limits and limits[low] > limits[high]:
            raise LimitsError(message)
    return limits


def host_resources(meminfo='/proc/meminfo', cpu_count=os.cpu_count):
    total_mb = 0
    try:
        with open(meminfo) as handle:
            for line in handle:
                if line.startswith('MemTotal:'):
                    total_mb = int(line.split()[1]) // 1024
                    break
    except (OSError, ValueError, IndexError):
        pass
    return {'total_mb': total_mb or 1024, 'cores': cpu_count() or 1}


def _floor64(value):
    return int(value) // 64 * 64


def default_limits(total_mb, cores):
    """Sensible per-site limits for a host of this size (never below the hard floors)."""
    # Address space per lsphp process: ~30% of RAM, between 768 MB and OpenLiteSpeed's 2047 MB default.
    hard = min(2047, max(768, _floor64(total_mb * 0.30)))
    soft = max(MIN_MEMORY_MB, min(hard, _floor64(hard * 0.9)))
    # Concurrency is the real CPU limit: at most two PHP workers per core for one site.
    children = max(2, min(10, cores * 2))
    # RLIMIT_NPROC counts every task of the site user (cron, SSH, Node apps, threads), so keep headroom.
    proc_soft = max(MIN_PROCESSES, min(400, 50 * cores))
    proc_hard = max(proc_soft, min(500, proc_soft + proc_soft // 2))
    return {'mem_soft_mb': soft, 'mem_hard_mb': hard, 'proc_soft': proc_soft, 'proc_hard': proc_hard,
            'max_conns': children, 'children': children}


# ----------------------------------------------------------------------------- store

def load_store(path=None):
    """{'packages': {name: limits}, 'overrides': {site: limits}} from the on-disk format
    {package_name: limits, "overrides": {site: limits}}. Invalid entries are dropped."""
    try:
        with open(path or LIMITS_FILE) as handle:
            raw = json.load(handle)
    except (OSError, ValueError):
        raw = {}
    store = {'packages': {}, 'overrides': {}}
    if not isinstance(raw, dict):
        return store
    for name, limits in raw.items():
        if name == OVERRIDES:
            for site, site_limits in (limits.items() if isinstance(limits, dict) else ()):
                try:
                    if DOMAIN_RE.match(site):
                        store['overrides'][site] = validate_limits(site_limits)
                except LimitsError:
                    pass
        elif PACKAGE_RE.match(name):
            try:
                store['packages'][name] = validate_limits(limits)
            except LimitsError:
                pass
    return store


def save_store(store, path=None):
    path = path or LIMITS_FILE
    raw = OrderedDict((name, store['packages'][name]) for name in sorted(store['packages']) if store['packages'][name])
    raw[OVERRIDES] = OrderedDict((site, store['overrides'][site]) for site in sorted(store['overrides'])
                                 if store['overrides'][site])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = '%s.tmp.%d' % (path, os.getpid())
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(raw, handle, indent=2)
        handle.write('\n')
    os.replace(temporary, path)
    return raw


def set_profile(store, scope, name, limits):
    """scope 'package' or 'site'; empty limits remove the profile/override."""
    clean = validate_limits(limits)
    if scope == 'package':
        if not PACKAGE_RE.match(name or '') or name == OVERRIDES:
            raise LimitsError('Invalid package name.')
        table = store['packages']
    elif scope == 'site':
        if not DOMAIN_RE.match(name or ''):
            raise LimitsError('Invalid site.')
        table = store['overrides']
    else:
        raise LimitsError('Invalid scope.')
    if clean:
        table[name] = clean
    else:
        table.pop(name, None)
    return clean


def effective(package, domain, store, defaults):
    """Merge defaults <- package profile <- site override; returns (limits, source per key)."""
    limits, source = dict(defaults), {key: 'default' for key in defaults}
    for origin, layer in (('package', store['packages'].get(package, {})), ('site', store['overrides'].get(domain, {}))):
        for key, value in layer.items():
            limits[key] = value
            source[key] = origin
    return limits, source


# ----------------------------------------------------------------------------- vhost.conf parsing

def _split(line):
    """(content, line ending) of one line from splitlines(keepends=True)."""
    if line.endswith('\r\n'):
        return line[:-2], '\r\n'
    if line.endswith('\n'):
        return line[:-1], '\n'
    return line, ''


def blocks(text):
    """Top-level blocks as dicts {kind, name, start, end} (line indexes of the opening and closing line).

    Structural braces only: a block opens with a line ending in '{' and closes with a line that is
    just '}'. Braces inside values (e.g. "%{Referer}i" in logFormat) are not structure.
    Raises LimitsError if the structure is unbalanced."""
    found, depth, current = [], 0, None
    for index, line in enumerate(text.splitlines()):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        match = _OPEN.match(line)
        if match:
            if depth == 0:
                current = {'kind': match.group(1), 'name': match.group(2) or '', 'start': index}
            depth += 1
        elif _CLOSE.match(line):
            depth -= 1
            if depth < 0:
                raise LimitsError('Unbalanced braces: "}" without a block on line %d.' % (index + 1))
            if depth == 0:
                current['end'] = index
                found.append(current)
                current = None
    if depth != 0:
        raise LimitsError('Unbalanced braces: a block opened on line %d is never closed.' % (current['start'] + 1))
    return found


def braces_balanced(text):
    try:
        blocks(text)
        return True
    except LimitsError:
        return False


def find_extprocessor(text, name):
    matches = [b for b in blocks(text) if b['kind'] == 'extprocessor' and b['name'] == name]
    if not matches:
        raise LimitsError('vhost.conf has no extprocessor %s.' % name)
    if len(matches) > 1:
        raise LimitsError('vhost.conf defines extprocessor %s more than once.' % name)
    return matches[0]


def parse_mem_mb(value):
    """OpenLiteSpeed size ('2047M', '2G', '512000K', bytes) -> MB, or None."""
    match = re.match(r'^\s*(\d+)\s*([KMGkmg]?)\s*$', value or '')
    if not match:
        return None
    number, unit = int(match.group(1)), match.group(2).upper()
    return {'': number // (1024 * 1024), 'K': number // 1024, 'M': number, 'G': number * 1024}[unit]


def _to_int(value):
    return int(value) if re.match(r'^\d+$', (value or '').strip()) else None


def parse_extprocessor(text, name):
    """Raw key/values of one extprocessor plus the limits in internal form."""
    block = find_extprocessor(text, name)
    lines = text.splitlines()
    raw, env, nested = OrderedDict(), [], 0
    for line in lines[block['start'] + 1:block['end']]:
        if _OPEN.match(line):
            nested += 1
            continue
        if _CLOSE.match(line):
            nested -= 1
            continue
        if nested or line.strip().startswith('#'):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        if parts[0] == 'env':
            env.append(parts[1].strip())
        else:
            raw[parts[0]] = parts[1].strip()
    limits = {}
    for ols_key, key in OLS_KEYS.items():
        if ols_key in raw:
            limits[key] = parse_mem_mb(raw[ols_key]) if key in MEMORY_KEYS else _to_int(raw[ols_key])
    for item in env:
        match = re.match(r'^(?:PHP_)?LSAPI_CHILDREN\s*=\s*(\d+)$', item)
        if match:
            limits['children'] = int(match.group(1))
    return {'name': name, 'type': raw.get('type', ''), 'ext_user': raw.get('extUser', ''), 'path': raw.get('path', ''),
            'raw': dict(raw), 'env': env, 'limits': limits}


def _format(key, value):
    return '%dM' % value if key in MEMORY_KEYS else str(value)


def _same(key, current_text, value):
    if key in MEMORY_KEYS:
        return parse_mem_mb(current_text) == value
    return _to_int(current_text) == value


def edit_extprocessor(text, name, limits):
    """Return vhost text with only the given limit keys of extprocessor `name` set (None = untouched).

    Existing lines keep their indentation, spacing and line ending; a value that already equals the
    target (numerically) is not rewritten. Missing keys are added just before the closing brace."""
    limits = {k: v for k, v in limits.items() if v is not None}
    unknown = set(limits) - set(FIELDS)
    if unknown:
        raise LimitsError('Unknown limit %s.' % sorted(unknown)[0])
    block = find_extprocessor(text, name)
    lines = text.splitlines(keepends=True)
    seen, nested, indent, eol = set(), 0, None, None
    for index in range(block['start'] + 1, block['end']):
        content, ending = _split(lines[index])
        if _OPEN.match(content):
            nested += 1
            continue
        if _CLOSE.match(content):
            nested -= 1
            continue
        if nested or content.strip().startswith('#'):
            continue
        env = _ENV_LINE.match(content)
        if env:
            seen.add('children')
            if 'children' in limits and not _same('children', env.group(4), limits['children']):
                lines[index] = env.group(1) + env.group(2) + env.group(3) + str(limits['children']) + env.group(5) + ending
            continue
        match = _KEY_LINE.match(content)
        if not match:
            continue
        if indent is None:
            indent, eol = match.group(1), ending or None
        key = OLS_KEYS.get(match.group(2))
        if key is None:
            continue
        seen.add(key)
        if key in limits and not _same(key, match.group(4), limits[key]):
            lines[index] = match.group(1) + match.group(2) + match.group(3) + _format(key, limits[key]) + match.group(5) + ending
    missing = [key for key in FIELDS if key in limits and key not in seen]
    if missing:
        indent = indent if indent is not None else '  '
        eol = eol or ('\r\n' if '\r\n' in text else '\n')
        added = []
        for key in missing:
            if key == 'children':
                added.append('%s%s%s%s' % (indent, 'env'.ljust(24), 'LSAPI_CHILDREN=%d' % limits[key], eol))
            else:
                added.append('%s%s%s%s' % (indent, FIELDS[key][0].ljust(24), _format(key, limits[key]), eol))
        lines[block['end']:block['end']] = added
    result = ''.join(lines)
    if result.count('{') != text.count('{') or result.count('}') != text.count('}') or not braces_balanced(result):
        raise LimitsError('Refusing to write: the edit would change the brace structure of vhost.conf.')
    return result


def unified_diff(before, after, path):
    return ''.join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        fromfile=path, tofile=path + ' (new)', n=2))


# ----------------------------------------------------------------------------- plans

def vhost_path(domain, vhosts=None):
    return os.path.join(vhosts or VHOSTS, domain, 'vhost.conf')


def plan_site(site, limits, vhosts=None, usage=None):
    """site = {'domain','user',...}. Returns what applying `limits` would change (nothing is written)."""
    path = vhost_path(site['domain'], vhosts)
    plan = {'domain': site['domain'], 'user': site['user'], 'vhost_path': path, 'target': dict(limits),
            'changed': False, 'diff': '', 'warnings': [], 'error': ''}
    try:
        if not USER_RE.match(site.get('user') or ''):
            raise LimitsError('The site has no valid Linux user.')
        with open(path) as handle:
            before = handle.read()
        current = parse_extprocessor(before, site['user'])
        if current['type'] != 'lsapi':
            raise LimitsError('extprocessor %s is not an lsapi (PHP) handler.' % site['user'])
        if current['ext_user'] and current['ext_user'] != site['user']:
            raise LimitsError('extprocessor %s runs as %s, not the site user.' % (site['user'], current['ext_user']))
        merged = dict(current['limits'])
        merged.update({k: v for k, v in limits.items() if v is not None})
        check_consistency(merged)
        after = edit_extprocessor(before, site['user'], limits)
    except FileNotFoundError:
        plan['error'] = 'No OpenLiteSpeed vhost.conf for this site.'
        return plan
    except (OSError, LimitsError) as exc:
        plan['error'] = str(exc)
        return plan
    plan.update(before=before, after=after, current=current['limits'], changed=after != before,
                diff=unified_diff(before, after, path))
    plan['warnings'] = warnings_for(merged, usage)
    return plan


def warnings_for(limits, usage=None):
    notes = []
    soft = limits.get('mem_soft_mb')
    idle_mb = (usage or {}).get('vsz_max_kb', 0) // 1024
    threshold = max(LSPHP_SAFE_AS_MB, idle_mb + 256)
    if soft is not None and soft < threshold:
        notes.append('Memory soft limit %d MB is an address-space limit (RLIMIT_AS); lsphp maps about %d MB at idle, '
                     'so PHP may fail to start. The health check will roll it back if so.' % (soft, max(idle_mb, 620)))
    if limits.get('children', 0) and limits.get('proc_soft', 10 ** 6) < limits['children'] + 10:
        notes.append('Process limit leaves little room above the %d PHP workers for cron jobs and SSH.' % limits['children'])
    tasks = (usage or {}).get('tasks', 0)
    if tasks and limits.get('proc_soft') is not None and tasks >= limits['proc_soft']:
        notes.append('The site user already runs %d tasks, at or above the new process limit %d: new PHP workers '
                     'would fail to fork.' % (tasks, limits['proc_soft']))
    return notes


def plan_token(plans):
    digest = hashlib.sha256()
    for plan in sorted(plans, key=lambda p: p['domain']):
        if plan.get('changed'):
            digest.update(('%s\0%s\0%s\0' % (plan['vhost_path'], plan['before'], plan['after'])).encode('utf-8'))
    return digest.hexdigest()[:32]


def public_plan(plan):
    return {k: v for k, v in plan.items() if k not in ('before', 'after')}


# ----------------------------------------------------------------------------- apply / rollback

def http_status(domain, runner=subprocess.run):
    """(scheme, HTTP status) of the site's front page via 127.0.0.1; ('', '000') if it does not answer."""
    for scheme, port in (('https', '443'), ('http', '80')):
        code, out = run(['curl', '-sS', '-k', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '20',
                         '--resolve', '%s:%s:127.0.0.1' % (domain, port), '%s://%s/' % (scheme, domain)],
                        runner, timeout=40)
        status = out.strip()[-3:]
        if code == 0 and status.isdigit() and status != '000':
            return [scheme, status]
    return ['', '000']


def apply_plans(plans, status_of=None, do_restart=None, backup_root=None, log=None, sleep=time.sleep, attempts=3):
    """Write every changed plan, restart once, then require every changed site to answer exactly as before.
    Any failure restores every file and restarts OpenLiteSpeed again."""
    from universalAddons.htaccess import service as hs
    status_of = status_of or http_status
    do_restart = do_restart or hs.restart
    say = log or (lambda text: None)
    changed = [p for p in plans if p.get('changed') and not p.get('error')]
    if not changed:
        return {'applied': [], 'restarted': False}
    before = {}
    for plan in changed:
        before[plan['domain']] = status_of(plan['domain'])
        say('%s answers %s before the change' % (plan['domain'], ' '.join(before[plan['domain']]).strip()))
    for plan in changed:
        with open(plan['vhost_path']) as handle:
            if handle.read() != plan['before']:
                raise LimitsError('%s changed since the preview; preview again.' % plan['vhost_path'])
    saved = hs._backup([p['vhost_path'] for p in changed], backup_root or BACKUP_DIR)
    say('backed up %d vhost.conf file(s)' % len(saved))
    try:
        for plan in changed:
            hs._write_atomic(plan['vhost_path'], plan['after'])
            with open(plan['vhost_path']) as handle:
                written = handle.read()
            if written != plan['after'] or not braces_balanced(written):
                raise LimitsError('%s did not read back as written.' % plan['vhost_path'])
        say('graceful OpenLiteSpeed restart')
        if not do_restart():
            raise LimitsError('OpenLiteSpeed did not come back after the restart.')
        failures, after = [], {}
        for plan in changed:
            for attempt in range(attempts):
                after[plan['domain']] = status_of(plan['domain'])
                if after[plan['domain']] == before[plan['domain']]:
                    break
                sleep(3)
            say('%s answers %s after the change' % (plan['domain'], ' '.join(after[plan['domain']]).strip()))
            if after[plan['domain']] != before[plan['domain']]:
                failures.append('%s answered %s instead of %s' % (plan['domain'], ' '.join(after[plan['domain']]).strip(),
                                                                  ' '.join(before[plan['domain']]).strip()))
        if failures:
            raise LimitsError('Health check failed: %s.' % '; '.join(failures))
    except Exception as exc:
        hs._restore(saved)
        do_restart()
        say('rolled back: %s' % exc)
        raise LimitsError('%s The previous vhost.conf files were restored and OpenLiteSpeed restarted.' % exc)
    return {'applied': [p['domain'] for p in changed], 'restarted': True, 'statuses': after}


# ----------------------------------------------------------------------------- usage (/proc), quota, du

def proc_usage(proc='/proc'):
    """Per uid: lsphp process count, their total RSS and largest VSZ (KB), and all tasks of the uid.
    Needs root: /proc is mounted with hidepid=2."""
    usage = {}
    try:
        pids = [name for name in os.listdir(proc) if name.isdigit()]
    except OSError:
        return usage
    for pid in pids:
        try:
            with open(os.path.join(proc, pid, 'status')) as handle:
                fields = dict(line.split(':', 1) for line in handle if ':' in line)
        except OSError:
            continue
        try:
            uid = int(fields['Uid'].split()[0])
        except (KeyError, ValueError, IndexError):
            continue
        entry = usage.setdefault(uid, {'lsphp': 0, 'rss_kb': 0, 'vsz_max_kb': 0, 'tasks': 0})
        entry['tasks'] += _kb(fields.get('Threads')) or 1
        if fields.get('Name', '').strip() == 'lsphp':
            entry['lsphp'] += 1
            entry['rss_kb'] += _kb(fields.get('VmRSS'))
            entry['vsz_max_kb'] = max(entry['vsz_max_kb'], _kb(fields.get('VmSize')))
    return usage


def _kb(value):
    try:
        return int((value or '0').split()[0])
    except (ValueError, IndexError):
        return 0


def usage_by_user(users, proc='/proc', getpwnam=None):
    import pwd
    getpwnam = getpwnam or pwd.getpwnam
    by_uid = proc_usage(proc)
    result = {}
    for user in users:
        try:
            uid = getpwnam(user).pw_uid
        except (KeyError, TypeError):
            continue
        result[user] = by_uid.get(uid, {'lsphp': 0, 'rss_kb': 0, 'vsz_max_kb': 0, 'tasks': 0})
    return result


def parse_repquota_csv(text):
    users = {}
    lines = (text or '').splitlines()
    if not lines or not lines[0].startswith('User,'):
        return users
    header = lines[0].split(',')
    for line in lines[1:]:
        values = line.split(',')
        if len(values) != len(header):
            continue
        row = dict(zip(header, values))
        try:
            users[row['User']] = {'kb': int(row['BlockUsed']), 'kb_soft': int(row['BlockSoftLimit']),
                                  'kb_hard': int(row['BlockHardLimit']), 'files': int(row['FileUsed']),
                                  'files_soft': int(row['FileSoftLimit']), 'files_hard': int(row['FileHardLimit'])}
        except (KeyError, ValueError):
            continue
    return users


def quota_report(mounts='/proc/mounts', fstab='/etc/fstab', which=None, runner=subprocess.run):
    """Report only: are quotas enabled on /, and per-user usage if repquota can tell. Changes nothing."""
    import shutil
    which = which or shutil.which
    options, fstab_options = [], []
    try:
        with open(mounts) as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 4 and parts[1] == '/' and parts[0] != 'rootfs':
                    options = parts[3].split(',')
    except OSError:
        pass
    try:
        with open(fstab) as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 4 and not parts[0].startswith('#') and parts[1] == '/':
                    fstab_options = parts[3].split(',')
    except OSError:
        pass
    mounted = {'usrquota': any(o in ('usrquota', 'quota') or o.startswith('usrjquota=') for o in options),
               'grpquota': any(o == 'grpquota' or o.startswith('grpjquota=') for o in options)}
    report = {'mount_options': options, 'fstab_options': fstab_options, 'usrquota': mounted['usrquota'],
              'grpquota': mounted['grpquota'], 'repquota': which('repquota') or '', 'state': '', 'users': {}}
    if report['repquota'] and mounted['usrquota']:
        code, out = run([report['repquota'], '-u', '-O', 'csv', '/'], runner, timeout=60)
        if code == 0:
            report['users'] = parse_repquota_csv(out)
        quotaon = which('quotaon')
        if quotaon:
            code, out = run([quotaon, '-p', '/'], runner, timeout=30)
            report['state'] = out.strip()[:500]
    return report


def load_du_cache(path=None):
    try:
        with open(path or DU_CACHE) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_du_cache(data, path=None):
    path = path or DU_CACHE
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    temporary = path + '.tmp'
    with open(temporary, 'w') as handle:
        json.dump(data, handle)
    os.replace(temporary, path)


def du_kb(path, runner=subprocess.run):
    """Disk usage of one site home in KB, at idle CPU and I/O priority, one filesystem."""
    code, out = run(['nice', '-n', '19', 'ionice', '-c3', 'du', '-sk', '--one-file-system', path], runner, timeout=1800)
    match = re.match(r'^(\d+)\s', out.strip().splitlines()[-1] if out.strip() else '')
    if not match:
        raise LimitsError('du failed for %s: %s' % (path, out.strip()[-200:]))
    return int(match.group(1))


def cgroup_facts(exists=os.path.exists):
    return {'cgroup_v2': exists('/sys/fs/cgroup/cgroup.controllers'),
            'ols_cgroups': False,
            'note': 'OpenLiteSpeed only places lsphp in per-user cgroups on cgroup v2 (user slices); on cgroup v1 '
                    'every lsphp stays in system.slice/lshttpd.service, so no per-site CPU quota is possible '
                    'without moving processes. Per-site CPU is bounded by the number of PHP workers instead.'}

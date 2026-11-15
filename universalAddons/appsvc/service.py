"""Server applications (Elasticsearch, Redis, Memcached): settings, managed files, secrets, health.

Everything here is plain logic that the root-side actions (actions.py) and the tests share.

Configuration rules:
- The panel writes only files it owns, or one clearly marked block, never the vendor's settings:
  * Elasticsearch: a BEGIN/END block at the end of elasticsearch.yml (ES 7 reads no conf.d for the
    yml), the heap in jvm.options.d/cyberpanel-heap.options (shared with the panel's installer), and
    bootstrap.password in the keystore when security is on.
  * Redis: its settings in a separate file pulled in by an `include` line, which sits in a marked
    block at the end of redis.conf (Redis has no conf.d, and the last value read wins), plus a
    systemd drop-in that lets systemd stop Redis with SIGTERM (the vendor's redis-shutdown script
    reads only redis.conf, so it cannot know a changed port or password).
  * Memcached: PORT, MAXCONN, CACHESIZE and the -l option in /etc/sysconfig/memcached.
- Every change is backed up first; a change whose service does not come back healthy is undone.
- Generated passwords live in root-only files and are handed out once.
"""
import base64
import http.client
import ipaddress
import json
import os
import re
import secrets as _secrets
import shlex
import shutil
import socket
import subprocess
import time

STATE_DIR = '/etc/cyberpanel/appsvc'                       # generated passwords (root-only)
WORK_DIR = '/var/lib/cyberpanel-universal/appsvc'          # backups and locks (root-only)
LEGACY_DIR = '/home/cyberpanel'                            # markers of the old Applications page

MARK_BEGIN = '# BEGIN panel-managed settings (Add-ons > Applications). Do not edit inside this block.'
MARK_END = '# END panel-managed settings'
_BEGIN_PREFIX = '# BEGIN panel-managed settings'
_END_PREFIX = '# END panel-managed settings'

ES_YML = '/etc/elasticsearch/elasticsearch.yml'
ES_HEAP = '/etc/elasticsearch/jvm.options.d/cyberpanel-heap.options'
ES_KEYSTORE = '/etc/elasticsearch/elasticsearch.keystore'
ES_KEYSTORE_TOOL = '/usr/share/elasticsearch/bin/elasticsearch-keystore'
ES_INSTALL_LOCK = '/home/cyberpanel/.elasticsearch-install.lock'   # taken by ServiceManager.InstallElasticSearch
ES_LOG_DIR = '/var/log/elasticsearch'

REDIS_CONFS = ('/etc/redis.conf', '/etc/redis/redis.conf')
REDIS_DROPIN_NAME = 'redis-panel-managed.conf'
REDIS_SYSTEMD_DROPIN = '/etc/systemd/system/redis.service.d/panel-managed.conf'
REDIS_SOCKET = '/run/redis/redis.sock'
REDIS_LOG = '/var/log/redis/redis.log'

MEMCACHED_SYSCONFIG = '/etc/sysconfig/memcached'

APPS = {
    'elasticsearch': {'title': 'Elasticsearch', 'package': 'elasticsearch', 'unit': 'elasticsearch',
                      'data_dir': '/var/lib/elasticsearch', 'min_ram_mb': 1024, 'min_disk_mb': 2048,
                      'legacy': 'Elasticsearch', 'about': 'Full-text search engine (7.x, from Elastic\'s repository).'},
    'redis': {'title': 'Redis', 'package': 'redis', 'unit': 'redis', 'data_dir': '/var/lib/redis',
              'min_ram_mb': 128, 'min_disk_mb': 256, 'legacy': 'Redis',
              'about': 'In-memory key-value store (the OS AppStream package), e.g. for WordPress object cache.'},
    'memcached': {'title': 'Memcached', 'package': 'memcached', 'unit': 'memcached', 'data_dir': None,
                  'min_ram_mb': 96, 'min_disk_mb': 64, 'legacy': None,
                  'about': 'Simple in-memory cache (the OS package); no persistence and no authentication.'},
}
ORDER = ('elasticsearch', 'redis', 'memcached')

SKIPPED = [{
    'key': 'opensearch', 'title': 'OpenSearch',
    'reason': 'Not offered. OpenSearch publishes EL8 packages, but it uses the same ports (9200/9300) and the '
              'same Java memory budget as Elasticsearch, so the two cannot share this server, and OpenSearch 2.x '
              'turns on its security plugin with TLS certificates and an admin password that would need a '
              'manager of their own. Elasticsearch 7 covers the same uses (ElasticPress, Magento, site search).',
}]

REDIS_POLICIES = ('noeviction', 'allkeys-lru', 'volatile-lru', 'allkeys-lfu', 'volatile-lfu',
                  'allkeys-random', 'volatile-random', 'volatile-ttl')
PERSISTENCE = ('off', 'rdb', 'aof')
SOCKET_PERMS = ('770', '777')
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')


class AppError(ValueError):
    pass


def run(argv, timeout=120, input_text=None, runner=subprocess.run, env=None):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout, input=input_text, env=env)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


def app_info(key):
    if key not in APPS:
        raise AppError('Unknown application.')
    return APPS[key]


# ----------------------------------------------------------------------------- host facts

def meminfo_mb(path='/proc/meminfo'):
    values = {}
    try:
        with open(path) as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    values[parts[0].rstrip(':')] = int(parts[1]) // 1024
    except OSError:
        pass
    return values.get('MemTotal', 0), values.get('MemAvailable', values.get('MemFree', 0))


def disk_free_mb(path='/var/lib'):
    try:
        return shutil.disk_usage(path).free // (1024 * 1024)
    except OSError:
        return 0


def preflight_checks(key, ram_total_mb, ram_available_mb, disk_mb, installed):
    """Checks for installing `key`; `force` (an explicit confirmation) may override RAM/disk only."""
    info = app_info(key)
    return [
        {'id': 'installed', 'ok': not installed, 'hard': True,
         'detail': '%s is %s.' % (info['title'], 'already installed' if installed else 'not installed yet')},
        {'id': 'ram', 'ok': ram_available_mb >= info['min_ram_mb'], 'hard': False,
         'detail': '%d MB of RAM available (of %d MB); %s wants at least %d MB free.' % (
             ram_available_mb, ram_total_mb, info['title'], info['min_ram_mb'])},
        {'id': 'disk', 'ok': disk_mb >= info['min_disk_mb'], 'hard': False,
         'detail': '%d MB free under /var/lib; %s wants at least %d MB.' % (disk_mb, info['title'], info['min_disk_mb'])},
    ]


def preflight_refusal(checks, force):
    """None when installing may go ahead, else the reason (soft checks can be overridden by force)."""
    hard = [c['detail'] for c in checks if not c['ok'] and c.get('hard')]
    if hard:
        return ' '.join(hard)
    soft = [c['detail'] for c in checks if not c['ok']]
    if soft and force is not True:
        return 'Below the recommended minimum: %s Tick "install anyway" to go ahead.' % ' '.join(soft)
    return None


# ----------------------------------------------------------------------------- marked blocks

def split_block(text):
    """(before, block body lines or None, after) of the panel-managed block in text."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip().startswith(_BEGIN_PREFIX)), None)
    if start is None:
        return text, None, ''
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip().startswith(_END_PREFIX)), None)
    if end is None:
        raise AppError('The panel-managed block in this file has a BEGIN line but no END line; fix the file by hand.')
    before = '\n'.join(lines[:start])
    after = '\n'.join(lines[end + 1:])
    return before, lines[start + 1:end], after


def apply_block(text, body_lines):
    """Text with the managed block holding body_lines (in place, or appended); no body removes it."""
    before, block, after = split_block(text)
    if block is None:
        before, after = text.rstrip('\n'), ''
    parts = [before.rstrip('\n')] if before.strip() else []
    if body_lines:
        parts.append('\n'.join([MARK_BEGIN] + list(body_lines) + [MARK_END]))
    if after.strip():
        parts.append(after.strip('\n'))
    return '\n'.join(parts) + '\n' if parts else ''


def outside_block(text):
    before, block, after = split_block(text)
    return before + '\n' + after if block is not None else text


# ----------------------------------------------------------------------------- Elasticsearch

ES_KEYS = {
    'network_host': 'network.host', 'http_port': 'http.port', 'single_node': 'discovery.type',
    'security': 'xpack.security.enabled', 'cluster_name': 'cluster.name', 'node_name': 'node.name',
    'index_buffer': 'indices.memory.index_buffer_size', 'fielddata': 'indices.fielddata.cache.size',
}


def es_heap_bounds(ram_mb):
    return 256, max(256, min(31744, (ram_mb // 2) // 64 * 64))


def es_default_heap(ram_mb):
    """The panel installer's default: RAM/6 rounded down to 128 MB, between 256 MB and 1 GB."""
    return max(256, min(1024, (ram_mb // 6) // 128 * 128)) if ram_mb else 512


def parse_yml_flat(text):
    """Top-level `a.b.c: value` settings of an elasticsearch.yml (comments and nesting ignored)."""
    values = {}
    for line in text.splitlines():
        if not line or line[0] in ' \t#-':
            continue
        key, sep, value = line.partition(':')
        if not sep:
            continue
        value = value.split(' #')[0].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        values[key.strip()] = value
    return values


def yml_conflicts(text, keys):
    """Managed keys that elasticsearch.yml also sets outside the block (ES refuses duplicate keys)."""
    outside = outside_block(text)
    flat = parse_yml_flat(outside)
    roots = {line.split(':')[0].strip() for line in outside.splitlines()
             if line and line[0] not in ' \t#-' and line.rstrip().endswith(':')}
    return sorted(k for k in keys if k in flat or k.split('.')[0] in roots)


def heap_from_text(text):
    match = re.search(r'^-Xmx(\d+)([mMgG])\s*$', text or '', re.M)
    if not match:
        return None
    return int(match.group(1)) * (1024 if match.group(2).lower() == 'g' else 1)


def heap_text(heap_mb):
    # Same file and format as ServiceManager.configureElasticSearchJvm, so either may write it.
    return '# Set by CyberPanel: heap sized for this server (RAM/6, 256 MB - 1 GB)\n-Xms%dm\n-Xmx%dm\n' % (heap_mb, heap_mb)


def es_current(yml_text, heap_file_text, ram_mb):
    flat = parse_yml_flat(yml_text or '')
    _, block, _ = split_block(yml_text or '')
    port = flat.get('http.port', '9200')
    heap = heap_from_text(heap_file_text)

    def percent(value):
        match = re.match(r'^(\d+)%$', value or '')
        return int(match.group(1)) if match else ''
    return {
        'heap_mb': heap or es_default_heap(ram_mb), 'heap_managed': heap is not None,
        'network_host': flat.get('network.host', '127.0.0.1'),
        'http_port': int(port) if port.isdigit() else 9200,
        'single_node': flat.get('discovery.type') == 'single-node',
        'security': flat.get('xpack.security.enabled', 'false').lower() == 'true',
        'cluster_name': flat.get('cluster.name', ''), 'node_name': flat.get('node.name', ''),
        'index_buffer': percent(flat.get('indices.memory.index_buffer_size')),
        'fielddata': percent(flat.get('indices.fielddata.cache.size')),
        'managed': block is not None,
    }


def is_loopback(host):
    if host in ('_local_', 'localhost'):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _host(value, what, allow_any=True):
    value = str(value or '').strip()
    if value == '_local_' or (allow_any and value in ('0.0.0.0', '::')):
        return value
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise AppError('%s must be an IP address of this server.' % what)


def _int(value, low, high, what):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise AppError('%s must be a whole number.' % what)
    if isinstance(value, bool) or not low <= number <= high:
        raise AppError('%s must be between %d and %d.' % (what, low, high))
    return number


def _bool(value):
    return value is True


def _percent(value, low, high, what):
    if value in ('', None):
        return ''
    return _int(value, low, high, what + ' (%)')


def _name(value, what):
    value = str(value or '').strip()
    if value and not NAME_RE.match(value):
        raise AppError('%s may use letters, digits, dot, dash and underscore (up to 64).' % what)
    return value


def validate_es(settings, ram_mb, yml_text='', confirm_exposed=False):
    """Normalised Elasticsearch settings and warnings; raises AppError when they cannot be applied."""
    if not isinstance(settings, dict):
        raise AppError('Settings must be an object.')
    low, high = es_heap_bounds(ram_mb)
    cfg = {
        'heap_mb': _int(settings.get('heap_mb'), low, high, 'Heap size (MB, at most half of the %d MB of RAM)' % ram_mb),
        'network_host': _host(settings.get('network_host', '127.0.0.1'), 'network.host'),
        'http_port': _int(settings.get('http_port', 9200), 1024, 65535, 'http.port'),
        'single_node': _bool(settings.get('single_node')),
        'security': _bool(settings.get('security')),
        'rotate_password': _bool(settings.get('rotate_password')),
        'cluster_name': _name(settings.get('cluster_name'), 'Cluster name'),
        'node_name': _name(settings.get('node_name'), 'Node name'),
        'index_buffer': _percent(settings.get('index_buffer'), 5, 50, 'Indexing buffer'),
        'fielddata': _percent(settings.get('fielddata'), 5, 35, 'Fielddata cache'),
    }
    if 9300 <= cfg['http_port'] <= 9400:
        raise AppError('http.port must not be in 9300-9400 (Elasticsearch\'s transport ports).')
    warnings = []
    if cfg['heap_mb'] > ram_mb // 4:
        warnings.append('A %d MB heap is over a quarter of RAM; leave room for MySQL, PHP and the page cache.' % cfg['heap_mb'])
    if not is_loopback(cfg['network_host']):
        if not cfg['single_node']:
            raise AppError('Listening beyond loopback needs discovery.type single-node (otherwise the production '
                           'bootstrap checks stop Elasticsearch from starting).')
        warnings.append('DANGER: Elasticsearch will listen on %s, reachable from the network%s. Firewall port %d.' % (
            cfg['network_host'], '' if cfg['security'] else ' WITHOUT A PASSWORD: anyone can read and delete every index',
            cfg['http_port']))
        if confirm_exposed is not True:
            raise AppError('Elasticsearch would listen on %s, beyond this server. Tick the confirmation to do this.'
                           % cfg['network_host'])
    conflicts = yml_conflicts(yml_text or '', [ES_KEYS[k] for k in es_block_keys(cfg)])
    if conflicts:
        raise AppError('elasticsearch.yml already sets %s outside the panel block; remove those lines there first '
                       '(Elasticsearch refuses a setting given twice).' % ', '.join(conflicts))
    if cfg['single_node'] and 'cluster.initial_master_nodes' in parse_yml_flat(outside_block(yml_text or '')):
        raise AppError('discovery.type single-node cannot be combined with cluster.initial_master_nodes, which '
                       'elasticsearch.yml sets.')
    return cfg, warnings


def es_block_keys(cfg):
    keys = ['network_host', 'http_port', 'security']
    keys += [k for k in ('single_node', 'cluster_name', 'node_name', 'index_buffer', 'fielddata') if cfg.get(k)]
    return keys


def render_es_block(cfg):
    lines = ['network.host: "%s"' % cfg['network_host'], 'http.port: %d' % cfg['http_port']]
    if cfg['single_node']:
        lines.append('discovery.type: single-node')
    lines.append('xpack.security.enabled: %s' % ('true' if cfg['security'] else 'false'))
    if cfg['cluster_name']:
        lines.append('cluster.name: "%s"' % cfg['cluster_name'])
    if cfg['node_name']:
        lines.append('node.name: "%s"' % cfg['node_name'])
    if cfg['index_buffer']:
        lines.append('indices.memory.index_buffer_size: %d%%' % cfg['index_buffer'])
    if cfg['fielddata']:
        lines.append('indices.fielddata.cache.size: %d%%' % cfg['fielddata'])
    return lines


def es_health_target(cfg):
    host = cfg['network_host']
    return ('127.0.0.1' if host in ('_local_', '0.0.0.0', '::') else host), cfg['http_port']


def es_health(host, port, password=None, timeout=5, connection=http.client.HTTPConnection):
    """(healthy, detail): Elasticsearch answers HTTP on host:port (401 counts as up)."""
    headers = {}
    if password:
        headers['Authorization'] = 'Basic ' + base64.b64encode(('elastic:%s' % password).encode()).decode()
    try:
        conn = connection(host, port, timeout=timeout)
        conn.request('GET', '/_cluster/health', headers=headers)
        response = conn.getresponse()
        body = response.read(65536).decode('utf-8', 'replace')
        conn.close()
    except (OSError, http.client.HTTPException) as exc:
        return False, 'no answer on %s:%d (%s)' % (host, port, exc)
    if response.status == 200:
        try:
            status = json.loads(body).get('status', '?')
        except ValueError:
            status = '?'
        # Any 200 is up: a red index that was red before the change must not undo the change.
        return True, 'HTTP 200, cluster status %s' % status
    if response.status == 401:
        return True, 'HTTP 401: answering, but the stored elastic password was not accepted'
    return False, 'HTTP %d' % response.status


# ----------------------------------------------------------------------------- Redis

def parse_directives(text):
    """Redis config directives: name -> list of argument lists, in file order."""
    found = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        if parts:
            found.setdefault(parts[0].lower(), []).append(parts[1:])
    return found


def _last(directives, name, default=None):
    values = directives.get(name)
    return values[-1] if values else default


def redis_effective(main_text, dropin_text=None):
    """Effective Redis settings: redis.conf, then the managed include (last value wins)."""
    merged = {}
    for text in (main_text, dropin_text if dropin_text is not None and split_block(main_text or '')[1] else None):
        for name, values in parse_directives(text).items():
            if name == 'save':
                for args in values:   # `save ""` resets, other save lines add
                    merged['save'] = [] if args in ([''], []) else merged.get('save', []) + [args]
            else:
                merged[name] = merged.get(name, []) + values
    return merged


def redis_current(main_text, dropin_text=None):
    d = redis_effective(main_text, dropin_text)
    bind = [a.lstrip('-') for a in (_last(d, 'bind') or ['127.0.0.1'])]
    port = (_last(d, 'port') or ['6379'])[0]
    memory = (_last(d, 'maxmemory') or ['0'])[0].lower()
    match = re.match(r'^(\d+)(mb|m|gb|g|kb|k|b)?$', memory)
    scale = {'gb': 1024, 'g': 1024, 'mb': 1, 'm': 1, 'kb': 1 / 1024, 'k': 1 / 1024, 'b': 1 / 1048576, None: 1 / 1048576}
    mb = int(int(match.group(1)) * scale[match.group(2)]) if match else 0
    aof = (_last(d, 'appendonly') or ['no'])[0].lower() == 'yes'
    socket_path = (_last(d, 'unixsocket') or [''])[0]
    perm = (_last(d, 'unixsocketperm') or ['770'])[0]
    managed_main = split_block(main_text or '')[1] is not None
    return {
        'maxmemory_mb': mb, 'policy': (_last(d, 'maxmemory-policy') or ['noeviction'])[0],
        'bind': bind, 'port': int(port) if port.isdigit() else 6379,
        'password': bool((_last(d, 'requirepass') or [''])[0]),
        'persistence': 'aof' if aof else ('rdb' if d.get('save', [['default']]) else 'off'),
        'unixsocket': bool(socket_path), 'socket_path': socket_path or REDIS_SOCKET,
        'socket_perm': perm if perm in SOCKET_PERMS else '770', 'managed': managed_main,
    }


def redis_password_in(main_text, dropin_text=None):
    """The requirepass Redis is running with (root side only; never returned to the browser)."""
    return (_last(redis_effective(main_text, dropin_text), 'requirepass') or [''])[0]


def validate_redis(settings, ram_mb, confirm_exposed=False):
    if not isinstance(settings, dict):
        raise AppError('Settings must be an object.')
    bind = settings.get('bind', ['127.0.0.1'])
    if isinstance(bind, str):
        bind = bind.replace(',', ' ').split()
    if not isinstance(bind, list) or not 1 <= len(bind) <= 4:
        raise AppError('Give one to four bind addresses.')
    cfg = {
        'maxmemory_mb': _int(settings.get('maxmemory_mb', 0), 0, max(16, ram_mb // 2),
                             'maxmemory (MB, 0 = no limit, at most half of the %d MB of RAM)' % ram_mb),
        'policy': str(settings.get('policy', 'allkeys-lru')),
        'bind': [_host(b, 'bind', allow_any=True) for b in bind],
        'port': _int(settings.get('port', 6379), 0, 65535, 'port'),
        'password': _bool(settings.get('password')),
        'rotate_password': _bool(settings.get('rotate_password')),
        'persistence': str(settings.get('persistence', 'rdb')),
        'unixsocket': _bool(settings.get('unixsocket')),
        'socket_perm': str(settings.get('socket_perm', '770')),
    }
    if 0 < cfg['maxmemory_mb'] < 16:
        raise AppError('maxmemory must be 0 (no limit) or at least 16 MB.')
    if cfg['policy'] not in REDIS_POLICIES:
        raise AppError('Unknown maxmemory-policy.')
    if cfg['persistence'] not in PERSISTENCE:
        raise AppError('Persistence must be off, rdb or aof.')
    if cfg['socket_perm'] not in SOCKET_PERMS:
        raise AppError('Socket permissions must be 770 or 777.')
    if cfg['port'] == 0 and not cfg['unixsocket']:
        raise AppError('Port 0 turns TCP off; turn the Unix socket on as well.')
    if 0 < cfg['port'] < 1024:
        raise AppError('port must be 0 (socket only) or between 1024 and 65535.')
    warnings = []
    if cfg['maxmemory_mb'] == 0:
        warnings.append('No maxmemory: Redis can grow until the server runs out of memory.')
    elif cfg['policy'] == 'noeviction':
        warnings.append('With noeviction, writes fail once maxmemory is reached; caches normally use allkeys-lru.')
    exposed = [b for b in cfg['bind'] if not is_loopback(b)]
    if exposed:
        if not cfg['password']:
            raise AppError('Redis may listen beyond loopback (%s) only with a password.' % ', '.join(exposed))
        warnings.append('DANGER: Redis will listen on %s, reachable from the network. Firewall port %d.'
                        % (', '.join(exposed), cfg['port']))
        if confirm_exposed is not True:
            raise AppError('Redis would listen on %s, beyond this server. Tick the confirmation to do this.'
                           % ', '.join(exposed))
    if cfg['unixsocket'] and cfg['socket_perm'] == '777':
        warnings.append('Socket mode 777: every local account, including each site\'s PHP, can connect%s.' % (
            '' if cfg['password'] else ' and, without a password, read every key'))
    return cfg, warnings


def render_redis_dropin(cfg, password=None):
    lines = ['# Managed by the panel (Add-ons > Applications); changes here are overwritten.',
             'bind %s' % ' '.join(cfg['bind']), 'port %d' % cfg['port']]
    lines.append('maxmemory %dmb' % cfg['maxmemory_mb'])
    lines.append('maxmemory-policy %s' % cfg['policy'])
    lines.append('requirepass %s' % password if cfg['password'] and password else 'requirepass ""')
    lines.append('save ""')
    if cfg['persistence'] == 'rdb':
        lines += ['save 900 1', 'save 300 10', 'save 60 10000']
    lines.append('appendonly %s' % ('yes' if cfg['persistence'] == 'aof' else 'no'))
    if cfg['persistence'] == 'aof':
        lines.append('appendfsync everysec')
    if cfg['unixsocket']:
        lines += ['unixsocket %s' % REDIS_SOCKET, 'unixsocketperm %s' % cfg['socket_perm']]
    return '\n'.join(lines) + '\n'


def redis_dropin_path(conf_path):
    return os.path.join(os.path.dirname(conf_path), REDIS_DROPIN_NAME)


def redis_include_block(conf_path):
    return ['include %s' % redis_dropin_path(conf_path)]


REDIS_SYSTEMD_TEXT = ('# Managed by the panel (Add-ons > Applications).\n'
                      '# Stop Redis with SIGTERM (a clean, saving shutdown): the stock redis-shutdown helper reads\n'
                      '# only redis.conf and cannot reach a Redis whose port or password the panel changed.\n'
                      '[Service]\nExecStop=\n')


def resp_encode(*args):
    out = ['*%d\r\n' % len(args)]
    for arg in args:
        data = str(arg)
        out.append('$%d\r\n%s\r\n' % (len(data.encode()), data))
    return ''.join(out).encode()


def _resp_read(stream):
    line = stream.readline()
    if not line:
        raise OSError('connection closed')
    kind, rest = line[:1], line[1:].rstrip(b'\r\n').decode('utf-8', 'replace')
    if kind == b'+':
        return rest
    if kind == b'-':
        raise AppError('Redis: %s' % rest)
    if kind == b':':
        return int(rest)
    if kind == b'$':
        size = int(rest)
        if size < 0:
            return None
        data = stream.read(size + 2)
        return data[:-2].decode('utf-8', 'replace')
    if kind == b'*':
        return [_resp_read(stream) for _ in range(max(0, int(rest)))]
    raise OSError('unexpected reply from Redis')


def redis_command(args_list, host='127.0.0.1', port=6379, password=None, socket_path=None, timeout=5,
                  connect=socket.create_connection):
    """Run Redis commands over TCP or the Unix socket; returns their replies (AUTH first if needed)."""
    if socket_path:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(socket_path)
    else:
        sock = connect((host, port), timeout=timeout)
    try:
        stream = sock.makefile('rb')
        commands = ([('AUTH', password)] if password else []) + list(args_list)
        sock.sendall(b''.join(resp_encode(*c) for c in commands))
        replies = [_resp_read(stream) for _ in commands]
        return replies[1:] if password else replies
    finally:
        sock.close()


def redis_target(cfg):
    host = next((b for b in cfg['bind'] if is_loopback(b)), cfg['bind'][0])
    if host in ('0.0.0.0',):
        host = '127.0.0.1'
    if host == '::':
        host = '::1'
    if cfg['port'] == 0 or (cfg.get('unixsocket') and not cfg['port']):
        return {'socket_path': cfg.get('socket_path') or REDIS_SOCKET}
    return {'host': host, 'port': cfg['port']}


def redis_health(target, password=None, command=redis_command):
    try:
        reply = command([('PING',)], password=password, **target)[0]
    except (OSError, AppError) as exc:
        return False, 'no PONG (%s)' % exc
    return reply == 'PONG', 'PING -> %s' % reply


def redis_info(text):
    info = {}
    for line in (text or '').splitlines():
        key, sep, value = line.partition(':')
        if sep:
            info[key.strip()] = value.strip()
    return info


# ----------------------------------------------------------------------------- Memcached

def parse_sysconfig(text):
    values = {}
    for line in (text or '').splitlines():
        match = re.match(r'^\s*([A-Z_][A-Z0-9_]*)=(.*)$', line)
        if match:
            raw = match.group(2).strip()
            try:
                parsed = shlex.split(raw)
                values[match.group(1)] = parsed[0] if parsed else ''
            except ValueError:
                values[match.group(1)] = raw.strip('"')
    return values


def _listen_from_options(options):
    try:
        tokens = shlex.split(options or '')
    except ValueError:
        tokens = (options or '').split()
    for i, token in enumerate(tokens):
        if token in ('-l', '--listen') and i + 1 < len(tokens):
            return tokens[i + 1]
        if token.startswith('--listen='):
            return token.split('=', 1)[1]
        if token.startswith('-l') and len(token) > 2:
            return token[2:]
    return ''


def memcached_current(text):
    values = parse_sysconfig(text)

    def number(name, default):
        value = values.get(name, '')
        return int(value) if value.isdigit() else default
    listen = _listen_from_options(values.get('OPTIONS', ''))
    return {'memory_mb': number('CACHESIZE', 64), 'max_conn': number('MAXCONN', 1024),
            'port': number('PORT', 11211), 'listen': [a for a in listen.split(',') if a] or ['0.0.0.0'],
            'managed': True}


def validate_memcached(settings, ram_mb, confirm_exposed=False):
    if not isinstance(settings, dict):
        raise AppError('Settings must be an object.')
    listen = settings.get('listen', ['127.0.0.1'])
    if isinstance(listen, str):
        listen = listen.replace(',', ' ').split()
    if not isinstance(listen, list) or not 1 <= len(listen) <= 4:
        raise AppError('Give one to four listen addresses.')
    cfg = {
        'memory_mb': _int(settings.get('memory_mb', 64), 16, max(16, ram_mb // 2),
                          'Memory (-m, MB, at most half of the %d MB of RAM)' % ram_mb),
        'max_conn': _int(settings.get('max_conn', 1024), 64, 65536, 'Connections (-c)'),
        'port': _int(settings.get('port', 11211), 1024, 65535, 'port'),
        'listen': [_host(a, 'listen', allow_any=True) for a in listen],
    }
    warnings = []
    exposed = [a for a in cfg['listen'] if not is_loopback(a)]
    if exposed:
        warnings.append('DANGER: Memcached has no password; listening on %s lets anyone who can reach port %d '
                        'read and change every cached value.' % (', '.join(exposed), cfg['port']))
        if confirm_exposed is not True:
            raise AppError('Memcached would listen on %s, beyond this server. Tick the confirmation to do this.'
                           % ', '.join(exposed))
    return cfg, warnings


def _set_listen(options, listen):
    try:
        tokens = shlex.split(options or '')
    except ValueError:
        raise AppError('OPTIONS in %s cannot be parsed; fix it by hand.' % MEMCACHED_SYSCONFIG)
    kept, skip = [], False
    for token in tokens:
        if skip:
            skip = False
            continue
        if token in ('-l', '--listen'):
            skip = True
            continue
        if token.startswith('--listen=') or (token.startswith('-l') and len(token) > 2):
            continue
        kept.append(token)
    if any('"' in t or '\\' in t for t in kept):
        raise AppError('OPTIONS in %s holds quotes or backslashes; fix it by hand.' % MEMCACHED_SYSCONFIG)
    return ' '.join(['-l', ','.join(listen)] + kept)


def render_sysconfig(text, cfg):
    """/etc/sysconfig/memcached with the managed variables replaced in place (others kept)."""
    current = parse_sysconfig(text)
    wanted = {'PORT': str(cfg['port']), 'MAXCONN': str(cfg['max_conn']), 'CACHESIZE': str(cfg['memory_mb']),
              'OPTIONS': _set_listen(current.get('OPTIONS', ''), cfg['listen'])}
    out, seen = [], set()
    for line in (text or '').splitlines():
        match = re.match(r'^\s*([A-Z_][A-Z0-9_]*)=', line)
        if match and match.group(1) in wanted:
            name = match.group(1)
            if name in seen:
                continue
            seen.add(name)
            out.append('%s="%s"' % (name, wanted[name]))
        else:
            out.append(line)
    if 'USER' not in current:
        out.insert(0, 'USER="memcached"')
    for name in ('PORT', 'MAXCONN', 'CACHESIZE', 'OPTIONS'):
        if name not in seen:
            out.append('%s="%s"' % (name, wanted[name]))
    return '\n'.join(out) + '\n'


def memcached_target(cfg):
    host = next((a for a in cfg['listen'] if is_loopback(a)), cfg['listen'][0])
    return {'host': '127.0.0.1' if host == '0.0.0.0' else ('::1' if host == '::' else host), 'port': cfg['port']}


def memcached_stats(host='127.0.0.1', port=11211, timeout=5, connect=socket.create_connection):
    sock = connect((host, port), timeout=timeout)
    try:
        sock.sendall(b'stats\r\n')
        data = b''
        while not data.endswith(b'END\r\n') and len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    stats = {}
    for line in data.decode('utf-8', 'replace').splitlines():
        parts = line.split(' ', 2)
        if len(parts) == 3 and parts[0] == 'STAT':
            stats[parts[1]] = parts[2]
    return stats


def memcached_health(target, stats=memcached_stats):
    try:
        values = stats(**target)
    except OSError as exc:
        return False, 'no answer (%s)' % exc
    if 'version' not in values:
        return False, 'unexpected reply to stats'
    return True, 'stats: version %s, %s connections' % (values['version'], values.get('curr_connections', '?'))


# ----------------------------------------------------------------------------- health waiting

def wait_healthy(check, timeout, interval=3, sleep=time.sleep, clock=time.monotonic):
    deadline = clock() + timeout
    ok, detail = check()
    while not ok and clock() < deadline:
        sleep(interval)
        ok, detail = check()
    return ok, detail


# ----------------------------------------------------------------------------- secrets

def new_password():
    return _secrets.token_urlsafe(24)


def secret_path(key, state_dir=None):
    app_info(key)
    return os.path.join(state_dir or STATE_DIR, '%s.secret.json' % key)


def _private_write(path, data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    os.chmod(os.path.dirname(path), 0o700)
    temporary = path + '.tmp'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def load_secret(key, state_dir=None):
    try:
        with open(secret_path(key, state_dir)) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) and data.get('password') else None
    except (OSError, ValueError):
        return None


def store_secret(key, password, state_dir=None):
    """Keep a new generated password, to be revealed once."""
    _private_write(secret_path(key, state_dir), {'password': password, 'revealed': False, 'created': int(time.time())})


def drop_secret(key, state_dir=None):
    try:
        os.unlink(secret_path(key, state_dir))
    except OSError:
        pass


def secret_status(key, state_dir=None):
    data = load_secret(key, state_dir)
    if not data:
        return {'stored': False, 'reveal_pending': False}
    return {'stored': True, 'reveal_pending': not data.get('revealed'), 'created': data.get('created')}


def reveal_secret(key, state_dir=None):
    """The generated password, exactly once; afterwards only a new password can be shown."""
    data = load_secret(key, state_dir)
    if not data:
        raise AppError('No generated password is stored for this application.')
    if data.get('revealed'):
        raise AppError('This password was already shown once. Generate a new one to see a password again.')
    data['revealed'] = True
    data['revealed_at'] = int(time.time())
    _private_write(secret_path(key, state_dir), data)
    return data['password']


def redact(text, hidden):
    text = str(text)
    for value in hidden:
        if value:
            text = text.replace(value, '********')
    return text


# ----------------------------------------------------------------------------- backups and rollback

def backup_root(key, work_dir=None):
    app_info(key)
    return os.path.join(work_dir or WORK_DIR, 'backups', key)


def snapshot(paths, root, keep=10):
    """Save the current content (or absence), mode and owner of each path; returns the snapshot dir."""
    os.makedirs(root, mode=0o700, exist_ok=True)
    os.chmod(os.path.dirname(root), 0o700)
    name = time.strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(3).hex()
    target = os.path.join(root, name)
    os.makedirs(target, mode=0o700)
    manifest = {'created': int(time.time()), 'files': {}}
    for path in paths:
        entry = {'exists': os.path.isfile(path)}
        if entry['exists']:
            info = os.stat(path)
            with open(path, 'rb') as handle:
                entry['data'] = base64.b64encode(handle.read()).decode('ascii')
            entry.update(mode=info.st_mode & 0o7777, uid=info.st_uid, gid=info.st_gid)
        manifest['files'][path] = entry
    fd = os.open(os.path.join(target, 'manifest.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(manifest, handle)
    for old in list_snapshots(root)[:-keep]:
        shutil.rmtree(os.path.join(root, old), ignore_errors=True)
    return target


def list_snapshots(root):
    try:
        return sorted(n for n in os.listdir(root) if os.path.isfile(os.path.join(root, n, 'manifest.json')))
    except OSError:
        return []


def restore(snapshot_dir):
    with open(os.path.join(snapshot_dir, 'manifest.json')) as handle:
        manifest = json.load(handle)
    for path, entry in manifest['files'].items():
        if not entry['exists']:
            try:
                os.unlink(path)
            except OSError:
                pass
            continue
        write_file(path, base64.b64decode(entry['data']), entry['mode'], entry['uid'], entry['gid'])
    return sorted(manifest['files'])


def write_file(path, data, mode=None, uid=None, gid=None, new_mode=0o644):
    """Atomic write; an existing file keeps its mode and owner unless they are given, a new one
    gets new_mode."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if os.path.isfile(path):
        info = os.stat(path)
        mode = info.st_mode & 0o7777 if mode is None else mode
        uid = info.st_uid if uid is None else uid
        gid = info.st_gid if gid is None else gid
    elif mode is None:
        mode = new_mode
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = '%s.panel-tmp' % path
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
    if uid is not None or gid is not None:
        try:
            os.chown(temporary, -1 if uid is None else uid, -1 if gid is None else gid)
        except PermissionError:
            pass
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def apply_with_rollback(paths, write, restart, healthy, root, log=lambda text: None, keep_snapshot=True):
    """Snapshot `paths`, write(), restart() and check healthy(); undo everything if it is not healthy.

    Returns (snapshot dir or None, health detail). On failure the previous files are restored, the
    service restarted again and AppError raised (saying whether the old configuration came back).
    """
    saved = snapshot(paths, root)
    try:
        write()
        restart()
        ok, detail = healthy()
    except Exception as exc:  # anything going wrong after the first write is undone the same way
        ok, detail = False, str(exc)
    if ok:
        log('Healthy: %s' % detail)
        if not keep_snapshot:
            shutil.rmtree(saved, ignore_errors=True)
            saved = None
        return saved, detail
    log('Not healthy (%s); restoring the previous configuration' % detail)
    restore(saved)
    shutil.rmtree(saved, ignore_errors=True)
    try:
        restart()
        back, back_detail = healthy()
    except Exception as exc:
        back, back_detail = False, str(exc)
    raise AppError('The service did not come back healthy (%s). The previous configuration was restored%s.' % (
        detail, ' and the service is running again' if back else ', but the service is still not healthy (%s); '
                                                                'check its log' % back_detail))


# ----------------------------------------------------------------------------- status helpers

def parse_systemctl_show(text):
    values = {}
    for line in (text or '').splitlines():
        key, sep, value = line.partition('=')
        if sep:
            values[key] = value
    return values


def memory_current(values):
    raw = values.get('MemoryCurrent', '')
    if raw.isdigit() and int(raw) < 2 ** 63:
        return int(raw)
    return None


def parse_ss(text, pid):
    """Listening addresses of process `pid` from `ss -Hltnp` output."""
    found = []
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) >= 6 and re.search(r'\bpid=%d\b' % pid, line):
            found.append(parts[3])
    return sorted(set(found))


def ports_in_use(text, exclude_pid=None):
    used = set()
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        if exclude_pid and re.search(r'\bpid=%d\b' % exclude_pid, line):
            continue
        port = parts[3].rsplit(':', 1)[-1]
        if port.isdigit():
            used.add(int(port))
    return used


def tail_lines(path, count=50, chunk=65536):
    try:
        with open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - chunk))
            data = handle.read()
    except OSError:
        return None
    return data.decode('utf-8', 'replace').splitlines()[-count:]


# ----------------------------------------------------------------------------- connection info

def connection_info(key, cfg, password_set):
    """What a site owner needs to connect, with examples (never the password itself)."""
    secret = '<the password shown once by the panel>' if password_set else None
    if key == 'elasticsearch':
        host, port = es_health_target(cfg)
        url = 'http://%s:%d' % (host if ':' not in host else '[%s]' % host, port)
        auth = "\ndefine( 'EP_ES_CREDENTIALS', [ 'username' => 'elastic', 'password' => '%s' ] );" % secret if password_set else ''
        return {'host': host, 'port': port, 'url': url, 'auth': 'user elastic, password set' if password_set else 'none',
                'examples': [
                    {'title': 'WordPress (ElasticPress), wp-config.php',
                     'code': "define( 'EP_HOST', '%s' );%s" % (url, auth)},
                    {'title': 'Command line', 'code': 'curl %s%s/_cluster/health' % ('-u elastic ' if password_set else '', url)},
                    {'title': 'Magento 2', 'code': 'bin/magento config:set catalog/search/engine elasticsearch7\n'
                                                  'bin/magento config:set catalog/search/elasticsearch7_server_hostname %s\n'
                                                  'bin/magento config:set catalog/search/elasticsearch7_server_port %d'
                                                  % (host, port)}]}
    if key == 'redis':
        target = redis_target(cfg)
        host, port = target.get('host', '127.0.0.1'), cfg['port']
        sock = cfg['socket_path'] if cfg.get('unixsocket') else None
        lines = ["define( 'WP_REDIS_HOST', '%s' );" % host, "define( 'WP_REDIS_PORT', %d );" % port]
        if sock:
            lines = ["define( 'WP_REDIS_SCHEME', 'unix' );", "define( 'WP_REDIS_PATH', '%s' );" % sock] + \
                (lines if port else [])
        if password_set:
            lines.append("define( 'WP_REDIS_PASSWORD', '%s' );" % secret)
        php = "$redis = new Redis();\n$redis->connect('%s'%s);" % (sock or host, '' if sock else ', %d' % port)
        if password_set:
            php += "\n$redis->auth('%s');" % secret
        return {'host': host, 'port': port, 'socket': sock, 'auth': 'password set' if password_set else 'none',
                'examples': [
                    {'title': 'WordPress (Redis Object Cache plugin), wp-config.php', 'code': '\n'.join(lines)},
                    {'title': 'LiteSpeed Cache > Cache > Object', 'code': 'Method: Redis\nHost: %s\nPort: %s%s' % (
                        sock or host, '0' if sock else port, '\nPassword: %s' % secret if password_set else '')},
                    {'title': 'PHP (phpredis)', 'code': php}]}
    target = memcached_target(cfg)
    return {'host': target['host'], 'port': cfg['port'], 'auth': 'none (Memcached has no passwords)',
            'examples': [
                {'title': 'LiteSpeed Cache > Cache > Object', 'code': 'Method: Memcached\nHost: %s\nPort: %d'
                 % (target['host'], cfg['port'])},
                {'title': 'W3 Total Cache > Object Cache', 'code': 'Memcached hostname:port: %s:%d' % (target['host'], cfg['port'])},
                {'title': 'PHP (memcached extension)',
                 'code': "$m = new Memcached();\n$m->addServer('%s', %d);" % (target['host'], cfg['port'])}],
            'note': 'Every site on this server shares one Memcached without passwords: use a key prefix per site, '
                    'and do not cache secrets in it.'}


FIELDS = {
    'elasticsearch': [
        {'name': 'heap_mb', 'label': 'Heap size (MB)', 'type': 'number',
         'help': 'Xms = Xmx, written to jvm.options.d/cyberpanel-heap.options. At most half of RAM.'},
        {'name': 'network_host', 'label': 'network.host', 'type': 'text',
         'help': '127.0.0.1 keeps Elasticsearch on this server. Anything else exposes it to the network.'},
        {'name': 'http_port', 'label': 'http.port', 'type': 'number'},
        {'name': 'single_node', 'label': 'discovery.type: single-node', 'type': 'bool'},
        {'name': 'security', 'label': 'xpack.security.enabled (elastic user with a generated password)', 'type': 'bool'},
        {'name': 'rotate_password', 'label': 'Generate a new elastic password', 'type': 'bool', 'transient': True},
        {'name': 'cluster_name', 'label': 'cluster.name (blank = default)', 'type': 'text'},
        {'name': 'node_name', 'label': 'node.name (blank = host name)', 'type': 'text'},
        {'name': 'index_buffer', 'label': 'indices.memory.index_buffer_size (%, blank = 10)', 'type': 'number'},
        {'name': 'fielddata', 'label': 'indices.fielddata.cache.size (%, blank = unbounded)', 'type': 'number'},
    ],
    'redis': [
        {'name': 'maxmemory_mb', 'label': 'maxmemory (MB, 0 = no limit)', 'type': 'number'},
        {'name': 'policy', 'label': 'maxmemory-policy', 'type': 'select', 'options': list(REDIS_POLICIES)},
        {'name': 'bind', 'label': 'bind (space-separated)', 'type': 'list',
         'help': '127.0.0.1 keeps Redis on this server.'},
        {'name': 'port', 'label': 'port (0 = Unix socket only)', 'type': 'number'},
        {'name': 'password', 'label': 'requirepass (generated password)', 'type': 'bool'},
        {'name': 'rotate_password', 'label': 'Generate a new password', 'type': 'bool', 'transient': True},
        {'name': 'persistence', 'label': 'Persistence', 'type': 'select', 'options': list(PERSISTENCE),
         'help': 'off: cache only. rdb: snapshots. aof: append-only log. Switching keeps the current data.'},
        {'name': 'unixsocket', 'label': 'Unix socket %s' % REDIS_SOCKET, 'type': 'bool'},
        {'name': 'socket_perm', 'label': 'Socket permissions', 'type': 'select', 'options': list(SOCKET_PERMS),
         'help': '770: the redis group only. 777: every local account (each site\'s PHP); use a password.'},
    ],
    'memcached': [
        {'name': 'memory_mb', 'label': 'Memory (-m, MB)', 'type': 'number'},
        {'name': 'max_conn', 'label': 'Connections (-c)', 'type': 'number'},
        {'name': 'listen', 'label': 'Listen (-l, space-separated)', 'type': 'list',
         'help': '127.0.0.1 keeps Memcached on this server. It has no passwords.'},
        {'name': 'port', 'label': 'Port (-p)', 'type': 'number'},
    ],
}

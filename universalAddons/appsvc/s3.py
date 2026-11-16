"""S3-compatible object storage (Garage): settings, files, download verification, admin API, OLS proxy.

Plain logic shared by actions.py and the tests (no root needed here).

Why Garage (checked November 2026): a single static Rust binary (x86_64 musl), a few tens of MB of
RAM on a single node, AGPL-3.0, actively released (v2.5.0, 2026-10-24), S3 API used with rclone and
the AWS SDKs, and an admin HTTP API (v2) for buckets, access keys, per-key bucket permissions
(read / write / owner) and bucket quotas. MinIO's community edition is source-only since October
2025 (no binaries or images) and its repository has been archived; SeaweedFS publishes only MD5
sums and needs master + volume + filer + S3 processes; Ceph RGW is far too heavy for 3.7 GB.

Configuration rules match the other applications:
  * /etc/garage.toml holds the panel's settings in one marked block (TOML: top-level keys first,
    then the [s3_api], [s3_web] and [admin] tables). Lines after the block belong to [admin].
  * The systemd unit garage.service is the panel's own file; MemoryMax and the writable data
    directory sit in a drop-in (garage.service.d/panel-managed.conf).
  * The RPC secret and the admin token are root:garage 0640 files in /etc/garage (never shown).
  * The admin API (3903) and RPC (3901) always listen on 127.0.0.1 only.

Download verification: Garage publishes no checksum file next to its binaries, so the panel takes
the binary from two official channels and requires them to agree byte for byte:
  1. the dxflrs/garage image on Docker Hub for the pinned tag, verified through the registry's
     content addresses (tag -> manifest list digest -> amd64 manifest digest -> layer sha256),
     the binary extracted from that layer;
  2. the release binary from garagehq.deuxfleurs.fr over HTTPS.
A SHA-256 pinned in PINNED_SHA256 (when set for the version) must match as well.
"""
import hashlib
import http.client
import json
import os
import re
import tarfile

from universalAddons.appsvc import service as sv
from universalAddons.appsvc.service import AppError

KEY = 's3'
VERSION = 'v2.5.0'                     # Garage release offered here (2026-10-24)
ARCH = 'x86_64-unknown-linux-musl'
RELEASE_URL = 'https://garagehq.deuxfleurs.fr/_releases/%s/%s/garage'
REGISTRY_REPO = 'dxflrs/garage'
REGISTRY_TOKEN_URL = 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull'
REGISTRY_BASE = 'https://registry-1.docker.io/v2/%s'
# SHA-256 of the x86_64 release binary, per version, once a maintainer has recorded it; when set it
# must match too. Unset: the two official channels must agree (see the module docstring).
PINNED_SHA256 = {}
MAX_BINARY = 256 * 1024 * 1024         # refuse anything absurdly large
MAX_LAYER = 128 * 1024 * 1024

BIN = '/usr/local/bin/garage'
CONF = '/etc/garage.toml'
SECRET_DIR = '/etc/garage'
RPC_SECRET = '/etc/garage/rpc_secret'
ADMIN_TOKEN = '/etc/garage/admin_token'
METRICS_TOKEN = '/etc/garage/metrics_token'
UNIT = 'garage'
UNIT_FILE = '/etc/systemd/system/garage.service'
DROPIN = '/etc/systemd/system/garage.service.d/panel-managed.conf'
USER = 'garage'
DEFAULT_DATA_DIR = '/var/lib/garage'
STATE_FILE = 'garage.json'             # in sv.STATE_DIR: installed version, public endpoint
RPC_PORT = 3901
ADMIN_PORT = 3903
DATA_PREFIXES = ('/var/lib/', '/srv/', '/data/', '/mnt/', '/opt/')
DATA_DIR_RE = re.compile(r'^/[A-Za-z0-9._/-]{1,200}$')
REGION_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,31}$')
BUCKET_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')
KEY_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
KEY_ID_RE = re.compile(r'^GK[0-9a-f]{24}$')
BUCKET_ID_RE = re.compile(r'^[0-9a-f]{64}$')
DOMAIN_RE = re.compile(r'^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
RESERVED_PORTS = (RPC_PORT, ADMIN_PORT)
MANAGED_HEADER = '# Managed by the panel (IndiansCloud Add-ons > Applications); changes here are overwritten.'

VHOST_BEGIN = '# BEGIN cp-appsvc-s3 (IndiansCloud S3 endpoint; managed by the panel, do not edit)'
VHOST_END = '# END cp-appsvc-s3'
VHOST_HANDLER = 'cp_appsvc_s3'

FIELDS = sv.FIELDS[KEY]        # the Tweaks form (defined with the other applications' fields)


def defaults(ram_mb=0):
    return {'s3_port': 3900, 'bind': '127.0.0.1', 'region': 'garage', 'data_dir': DEFAULT_DATA_DIR,
            'memory_mb': 256, 'replication_factor': '1', 'web_port': 0}


def memory_bounds(ram_mb):
    return 128, max(128, ram_mb // 4)


# ----------------------------------------------------------------------------- validation

def _port(value, what):
    port = sv._int(value, 1024, 65535, what)
    if port in RESERVED_PORTS:
        raise AppError('%s must not be %d or %d (Garage\'s RPC and admin ports).' % (what, RPC_PORT, ADMIN_PORT))
    return port


def clean_data_dir(value):
    path = str(value or '').strip().rstrip('/')
    if not DATA_DIR_RE.fullmatch(path) or '/../' in path + '/' or '/./' in path + '/' or '//' in path:
        raise AppError('Data directory: an absolute path of letters, digits, . _ - and /.')
    if not any(path.startswith(prefix) and len(path) > len(prefix) for prefix in DATA_PREFIXES):
        raise AppError('Data directory must be a directory inside /var/lib, /srv, /data, /mnt or /opt.')
    if path in ('/var/lib/mysql', '/var/lib/cyberpanel-universal') or path.startswith(('/var/lib/mysql/',
                                                                                        '/var/lib/cyberpanel')):
        raise AppError('Choose a directory of its own for the object data.')
    return path


def validate(settings, ram_mb, confirm_exposed=False, endpoint=None):
    """Normalised Garage settings and warnings; raises AppError when they cannot be applied.

    Listening beyond loopback is allowed only once the HTTPS endpoint (OLS proxy) exists, and only
    with the explicit confirmation."""
    if not isinstance(settings, dict):
        raise AppError('Settings must be an object.')
    base = dict(defaults(ram_mb), **{k: v for k, v in settings.items() if v not in (None, '')})
    low, high = memory_bounds(ram_mb)
    cfg = {
        's3_port': _port(base['s3_port'], 'S3 API port'),
        'bind': sv._host(base['bind'], 'Listen address', allow_any=True),
        'region': str(base['region']).strip(),
        'data_dir': clean_data_dir(base['data_dir']),
        'memory_mb': sv._int(base['memory_mb'], low, high, 'Memory cap (MB, at most a quarter of the %d MB of RAM)'
                             % ram_mb),
        'replication_factor': str(base['replication_factor']),
        'web_port': 0 if str(base['web_port']) == '0' else _port(base['web_port'], 'Static website port'),
    }
    if not REGION_RE.fullmatch(cfg['region']):
        raise AppError('Region: 2-32 lowercase letters, digits and dashes (for example garage or eu-1).')
    if cfg['replication_factor'] != '1':
        raise AppError('This is a single node: replication_factor must be 1.')
    if cfg['web_port'] and cfg['web_port'] == cfg['s3_port']:
        raise AppError('The website port must differ from the S3 API port.')
    warnings = []
    if not sv.is_loopback(cfg['bind']):
        if not endpoint:
            raise AppError('Set up the HTTPS endpoint (an OpenLiteSpeed proxy with the panel\'s SSL) before letting '
                           'the S3 API listen on %s: without it, access keys and data would cross the network '
                           'in plain HTTP.' % cfg['bind'])
        warnings.append('DANGER: the S3 API will ALSO answer plain HTTP on %s:%d, reachable from the network. Object '
                        'data and request signatures travel unencrypted on that port; customers should use https://%s '
                        'instead. Firewall port %d unless you really need it.'
                        % (cfg['bind'], cfg['s3_port'], endpoint, cfg['s3_port']))
        if confirm_exposed is not True:
            raise AppError('The S3 API would listen on %s, beyond this server. Tick the confirmation to do this.'
                           % cfg['bind'])
    return cfg, warnings


# ----------------------------------------------------------------------------- garage.toml

def _addr(host, port):
    return '%s:%d' % ('[%s]' % host if ':' in host else host, port)


def render_block(cfg, endpoint=None):
    """The managed block of /etc/garage.toml (top-level keys, then the tables)."""
    data = cfg['data_dir']
    lines = [
        'metadata_dir = "%s/meta"' % data,
        'data_dir = "%s/data"' % data,
        'db_engine = "sqlite"',
        'replication_factor = %s' % cfg['replication_factor'],
        'consistency_mode = "consistent"',
        'rpc_bind_addr = "127.0.0.1:%d"' % RPC_PORT,
        'rpc_public_addr = "127.0.0.1:%d"' % RPC_PORT,
        'rpc_secret_file = "%s"' % RPC_SECRET,
        '',
        '[s3_api]',
        's3_region = "%s"' % cfg['region'],
        'api_bind_addr = "%s"' % _addr(cfg['bind'], cfg['s3_port']),
    ]
    if endpoint:
        lines.append('public_endpoint = "https://%s"' % endpoint)
    if cfg['web_port']:
        lines += ['', '[s3_web]', 'bind_addr = "%s"' % _addr(cfg['bind'], cfg['web_port']),
                  'root_domain = ".web.localhost"', 'index = "index.html"']
    lines += ['', '[admin]', 'api_bind_addr = "127.0.0.1:%d"' % ADMIN_PORT,
              'admin_token_file = "%s"' % ADMIN_TOKEN, 'metrics_token_file = "%s"' % METRICS_TOKEN]
    return lines


def render_conf(text, cfg, endpoint=None):
    """garage.toml with the managed block in place (a new file gets a header first)."""
    if not (text or '').strip():
        text = MANAGED_HEADER + '\n# Settings you add yourself go AFTER the END line and belong to the [admin] table.\n'
    return sv.apply_block(text, render_block(cfg, endpoint))


def _toml_value(raw):
    raw = raw.split(' #')[0].strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        return raw[1:-1]
    return int(raw) if raw.isdigit() else raw


def parse_toml_flat(lines):
    """{'key' or 'table.key': value} of simple TOML lines (strings and integers)."""
    values, table = {}, ''
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.match(r'^\[([a-z0-9_]+)\]$', line)
        if match:
            table = match.group(1) + '.'
            continue
        key, sep, raw = line.partition('=')
        if sep:
            values[table + key.strip()] = _toml_value(raw)
    return values


def outside_conflicts(text):
    """Top-level keys or tables that garage.toml sets outside the panel block (TOML refuses duplicates)."""
    before, block, after = sv.split_block(text or '')
    if block is None:
        return []
    mine = set(parse_toml_flat(render_block(dict(defaults(), web_port=3902), 'x.example')))
    found = []
    top = parse_toml_flat(before.splitlines())
    found += sorted(k for k in top if k in mine or '.' in k)
    for line in (before + '\n' + after).splitlines():
        match = re.match(r'^\s*\[([a-z0-9_]+)\]\s*$', line)
        if match:
            found.append('[%s]' % match.group(1))
    return found


def _split_addr(value, default_port):
    match = re.match(r'^\[?([0-9a-fA-F.:]+?)\]?:(\d+)$', str(value or ''))
    if not match:
        return '127.0.0.1', default_port
    return match.group(1), int(match.group(2))


def memory_from_dropin(text):
    match = re.search(r'^Memory(?:Max|Limit)=(\d+)M\s*$', text or '', re.M)
    return int(match.group(1)) if match else None


def current(conf_text, dropin_text=None):
    """The settings in effect, from the managed block of garage.toml and the systemd drop-in."""
    _, block, _ = sv.split_block(conf_text or '')
    if block is None:
        return dict(defaults(), managed=False)
    flat = parse_toml_flat(block)
    bind, port = _split_addr(flat.get('s3_api.api_bind_addr'), 3900)
    web_port = _split_addr(flat.get('s3_web.bind_addr'), 0)[1] if 's3_web.bind_addr' in flat else 0
    meta = str(flat.get('metadata_dir', DEFAULT_DATA_DIR + '/meta'))
    return {'s3_port': port, 'bind': bind, 'region': str(flat.get('s3_api.s3_region', 'garage')),
            'data_dir': os.path.dirname(meta) if meta.endswith('/meta') else meta,
            'memory_mb': memory_from_dropin(dropin_text) or defaults()['memory_mb'],
            'replication_factor': str(flat.get('replication_factor', 1)), 'web_port': web_port,
            'public_endpoint': str(flat.get('s3_api.public_endpoint', '')) or None, 'managed': True}


# ----------------------------------------------------------------------------- systemd

def render_unit(systemd_version=239):
    lines = [
        MANAGED_HEADER,
        '[Unit]',
        'Description=Garage S3-compatible object storage (IndiansCloud Applications)',
        'After=network-online.target',
        'Wants=network-online.target',
        '',
        '[Service]',
        'Type=simple',
        'User=%s' % USER,
        'Group=%s' % USER,
        'ExecStart=%s -c %s server' % (BIN, CONF),
        'Environment=RUST_LOG=garage=info',
        'Restart=on-failure',
        'RestartSec=5',
        'TimeoutStopSec=60',
        'UMask=0027',
        'LimitNOFILE=65536',
        # --- sandbox (the data directory is made writable by the drop-in)
        'NoNewPrivileges=yes',
        'CapabilityBoundingSet=',
        'AmbientCapabilities=',
        'PrivateTmp=yes',
        'PrivateDevices=yes',
        'ProtectSystem=strict',
        'ProtectHome=yes',
        'ProtectKernelTunables=yes',
        'ProtectKernelModules=yes',
        'ProtectControlGroups=yes',
        'RestrictRealtime=yes',
        'RestrictNamespaces=yes',
        'LockPersonality=yes',
        'MemoryDenyWriteExecute=yes',
        'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
        'SystemCallArchitectures=native',
        'SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @raw-io @reboot @swap',
        'SystemCallErrorNumber=EPERM',
        'InaccessiblePaths=-/etc/cyberpanel -/usr/local/CyberCP -/usr/local/lscp -/root -/var/lib/mysql '
        '-/etc/letsencrypt -/etc/opendkim -/etc/pdns -/home/vmail -/etc/shadow -/etc/gshadow',
    ]
    if systemd_version >= 242:
        lines += ['RestrictSUIDSGID=yes', 'ProtectHostname=yes']
    if systemd_version >= 244:
        lines.append('ProtectKernelLogs=yes')
    lines += ['', '[Install]', 'WantedBy=multi-user.target', '']
    return '\n'.join(lines)


def render_dropin(cfg, unified=False):
    """MemoryMax (cgroup v2), plus MemoryLimit on the legacy hierarchy (EL8), and the writable data dir."""
    memory = ['MemoryMax=%dM' % cfg['memory_mb']] + ([] if unified else ['MemoryLimit=%dM' % cfg['memory_mb']])
    return '\n'.join([MANAGED_HEADER, '[Service]'] + memory + ['ReadWritePaths=%s' % cfg['data_dir'], ''])


# ----------------------------------------------------------------------------- download verification

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def check_digest(data, expected):
    """data (bytes) must hash to the registry digest `sha256:<hex>`."""
    if not re.match(r'^sha256:[0-9a-f]{64}$', expected or ''):
        raise AppError('Unexpected digest format from the registry.')
    actual = 'sha256:' + hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise AppError('Checksum mismatch: the registry said %s, the data hashes to %s.' % (expected, actual))
    return actual


def pick_amd64(index):
    """The linux/amd64 manifest digest of a manifest list / OCI index."""
    for entry in (index or {}).get('manifests') or []:
        platform = entry.get('platform') or {}
        if platform.get('os') == 'linux' and platform.get('architecture') == 'amd64':
            return entry.get('digest')
    raise AppError('The Garage image has no linux/amd64 build.')


def single_layer(manifest):
    layers = (manifest or {}).get('layers') or []
    if len(layers) != 1 or not str(layers[0].get('mediaType', '')).endswith(('tar.gzip', 'tar+gzip')):
        raise AppError('Unexpected Garage image layout (expected one gzip layer with the binary).')
    if int(layers[0].get('size') or 0) > MAX_LAYER:
        raise AppError('The Garage image layer is unexpectedly large.')
    return layers[0]['digest']


def extract_binary(layer_path, target):
    """Copy the one regular file /garage out of a verified image layer (nothing else is extracted)."""
    with tarfile.open(layer_path, 'r:gz') as archive:
        for member in archive:
            name = member.name.lstrip('./')
            if name != 'garage':
                continue
            if not member.isreg() or member.size > MAX_BINARY:
                raise AppError('The image\'s /garage is not a regular file of a sane size.')
            source = archive.extractfile(member)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    handle.write(chunk)
            return sha256_file(target)
    raise AppError('The Garage image layer has no /garage binary.')


def verify_agreement(direct_sha, image_sha, version=VERSION, pinned=None):
    """Both official channels (and the pin, when there is one) must give the same binary."""
    pinned = PINNED_SHA256 if pinned is None else pinned
    if direct_sha != image_sha:
        raise AppError('The release binary from garagehq.deuxfleurs.fr (sha256 %s) differs from the one in the '
                       'official Docker image (sha256 %s). Nothing was installed.' % (direct_sha, image_sha))
    expected = pinned.get(version)
    if expected and expected != direct_sha:
        raise AppError('The downloaded binary (sha256 %s) does not match the SHA-256 pinned for Garage %s (%s). '
                       'Nothing was installed.' % (direct_sha, version, expected))
    return 'sha256 %s: release binary and Docker image agree%s' % (
        direct_sha, ', and match the pinned checksum' if expected else '')


# ----------------------------------------------------------------------------- admin API

def admin_call(method, path, token, body=None, timeout=10, connection=http.client.HTTPConnection):
    """(status, parsed JSON or text) from the admin API on 127.0.0.1 (the token never leaves root)."""
    headers = {'Authorization': 'Bearer %s' % token} if token else {}
    payload = None
    if body is not None:
        payload = json.dumps(body)
        headers['Content-Type'] = 'application/json'
    try:
        conn = connection('127.0.0.1', ADMIN_PORT, timeout=timeout)
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        raw = response.read(4 * 1024 * 1024).decode('utf-8', 'replace')
        conn.close()
    except (OSError, http.client.HTTPException) as exc:
        raise AppError('The Garage admin API on 127.0.0.1:%d did not answer (%s).' % (ADMIN_PORT, exc))
    try:
        data = json.loads(raw) if raw.strip()[:1] in ('{', '[') else raw
    except ValueError:
        data = raw
    return response.status, data


def api(method, path, token, body=None, call=None):
    status, data = (call or admin_call)(method, path, token, body)
    if status != 200:
        message = data.get('message') if isinstance(data, dict) else str(data)[:300]
        raise AppError('Garage refused (HTTP %d): %s' % (status, sv.redact(message or '', [token])))
    return data


def health(token=None, call=None):
    """(healthy, detail) from GET /health and, with the token, GetClusterHealth."""
    call = call or admin_call
    try:
        status, text = call('GET', '/health', None)
    except AppError as exc:
        return False, str(exc)
    if status != 200:
        return False, 'GET /health -> HTTP %d' % status
    if not token:
        return True, 'GET /health -> 200'
    try:
        status, data = call('GET', '/v2/GetClusterHealth', token)
    except AppError as exc:
        return False, str(exc)
    if status != 200 or not isinstance(data, dict):
        return False, 'GetClusterHealth -> HTTP %d' % status
    return data.get('status') == 'healthy', 'GET /health -> 200; cluster %s, %s/%s partitions ok' % (
        data.get('status'), data.get('partitionsAllOk'), data.get('partitions'))


def layout_changes(status, layout, capacity_bytes):
    """The UpdateClusterLayout body that gives this single node its role, or None when it has one."""
    nodes = (status or {}).get('nodes') or []
    if len(nodes) != 1:
        raise AppError('Expected exactly one Garage node, found %d.' % len(nodes))
    node = nodes[0]['id']
    if any(r.get('id') == node for r in (layout or {}).get('roles') or []):
        return None
    return {'roles': [{'id': node, 'zone': 'dc1', 'capacity': max(1024 ** 3, int(capacity_bytes)), 'tags': []}]}


def bootstrap(token, capacity_bytes, call=None, log=lambda text: None):
    """Give the single node its layout role on first start (and after a data-directory change)."""
    status = api('GET', '/v2/GetClusterStatus', token, call=call)
    layout = api('GET', '/v2/GetClusterLayout', token, call=call)
    change = layout_changes(status, layout, capacity_bytes)
    if change is None:
        return False
    api('POST', '/v2/UpdateClusterLayout', token, change, call=call)
    api('POST', '/v2/ApplyClusterLayout', token, {'version': int(layout.get('version') or 0) + 1}, call=call)
    log('Assigned the single node its storage role (zone dc1) and applied layout version %d'
        % (int(layout.get('version') or 0) + 1))
    return True


def bucket_name(name):
    name = str(name or '').strip()
    if not BUCKET_RE.fullmatch(name) or name.startswith('xn--') or name.endswith('-s3alias'):
        raise AppError('Bucket names: 3-63 lowercase letters, digits and dashes, starting and ending with a letter '
                       'or digit (no dots, so HTTPS certificates stay valid).')
    if re.match(r'^\d+(\.\d+){3}$', name):
        raise AppError('A bucket name must not look like an IP address.')
    return name


def key_name(name):
    name = str(name or '').strip()
    if not KEY_NAME_RE.fullmatch(name):
        raise AppError('Key names: letters, digits, dot, dash and underscore (up to 64).')
    return name


def key_id(value):
    value = str(value or '').strip()
    if not KEY_ID_RE.fullmatch(value):
        raise AppError('Invalid access key ID.')
    return value


def bucket_id(value):
    value = str(value or '').strip()
    if not BUCKET_ID_RE.fullmatch(value):
        raise AppError('Invalid bucket ID.')
    return value


def permissions(read, write, owner):
    return {'read': read is True, 'write': write is True, 'owner': owner is True}


def quotas(max_size_mb, max_objects):
    """{'maxSize': bytes or None, 'maxObjects': n or None}; blank / 0 means no quota."""
    out = {}
    for name, value, high, scale in (('maxSize', max_size_mb, 100 * 1024 * 1024, 1024 * 1024),
                                     ('maxObjects', max_objects, 10 ** 12, 1)):
        if value in (None, '', 0, '0'):
            out[name] = None
            continue
        out[name] = sv._int(value, 1, high, 'Quota %s' % ('size (MB)' if name == 'maxSize' else 'objects')) * scale
    return out


def scrub(data):
    """Drop any secret access key from admin API data that is going to the page or a log."""
    if isinstance(data, dict):
        return {k: scrub(v) for k, v in data.items() if k not in ('secretAccessKey', 'secret_access_key')}
    if isinstance(data, list):
        return [scrub(v) for v in data]
    return data


def inventory(token, call=None):
    """Buckets (with size, objects, quotas, keys) and access keys, without any secret."""
    buckets = []
    for item in api('GET', '/v2/ListBuckets', token, call=call) or []:
        info = api('GET', '/v2/GetBucketInfo?id=%s' % bucket_id(item['id']), token, call=call)
        buckets.append({'id': item['id'], 'name': (item.get('globalAliases') or [''])[0],
                        'bytes': info.get('bytes'), 'objects': info.get('objects'),
                        'quotas': info.get('quotas') or {},
                        'keys': [{'id': k.get('accessKeyId'), 'name': k.get('name'), 'permissions': k.get('permissions')}
                                 for k in info.get('keys') or []]})
    keys = [{'id': k.get('id') or k.get('accessKeyId'), 'name': k.get('name'), 'expired': k.get('expired')}
            for k in api('GET', '/v2/ListKeys', token, call=call) or []]
    return scrub({'buckets': sorted(buckets, key=lambda b: b['name']), 'keys': sorted(keys, key=lambda k: k['name'] or '')})


# ----------------------------------------------------------------------------- OpenLiteSpeed endpoint

def clean_domain(value):
    domain = str(value or '').strip().lower().rstrip('.')
    if not DOMAIN_RE.fullmatch(domain):
        raise AppError('Enter a domain or subdomain, for example s3.example.com.')
    return domain


def render_vhost_block(port):
    """Proxy the whole (dedicated) site to Garage's S3 API on loopback, like Universal Apps does."""
    return '\n\n'.join([
        VHOST_BEGIN,
        'extprocessor %s {\n  type                    proxy\n  address                 127.0.0.1:%d\n'
        '  maxConns                200\n  pcKeepAliveTimeout      60\n  initTimeout             60\n'
        '  retryTimeout            0\n  respBuffer              0\n}' % (VHOST_HANDLER, port),
        'context / {\n  type                    proxy\n  handler                 %s\n'
        '  addDefaultCharset       off\n}' % VHOST_HANDLER,
        VHOST_END]) + '\n'


def strip_vhost_block(text):
    pattern = re.compile(r'\n?' + re.escape(VHOST_BEGIN) + r'.*?' + re.escape(VHOST_END) + r'\n?', re.S)
    return re.sub(r'\n{3,}', '\n\n', pattern.sub('\n', text or ''))


def vhost_problems(text):
    """Why this vhost cannot carry the S3 endpoint (empty list: it can)."""
    base = strip_vhost_block(text)
    problems = []
    if not re.search(r'^vhssl\s*\{', base, re.M):
        problems.append('the site has no SSL certificate yet (issue one in the panel first)')
    if re.search(r'^context\s+/\s*\{', base, re.M):
        problems.append('the vhost already has its own "context /" (the S3 endpoint needs a dedicated site)')
    if re.search(r'^extprocessor\s+%s\s*\{' % VHOST_HANDLER, base, re.M):
        problems.append('an extprocessor %s exists outside the panel block' % VHOST_HANDLER)
    return problems


def apply_vhost(text, port):
    base = strip_vhost_block(text).rstrip('\n') + '\n'
    block = render_vhost_block(port)
    match = re.search(r'^vhssl\s*\{', base, re.M)
    out = base[:match.start()] + block + '\n' + base[match.start():] if match else base + '\n' + block
    return re.sub(r'\n{3,}', '\n\n', out)


# ----------------------------------------------------------------------------- connection info

def connection_info(cfg, endpoint=None):
    """Endpoint, region, addressing style and client examples (never a secret)."""
    host = {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(cfg['bind'], cfg['bind'])
    local = 'http://%s' % _addr(host, cfg['s3_port'])
    url = 'https://%s' % endpoint if endpoint else local
    region = cfg['region']
    key, secret = 'GK...', '<the secret shown once when the key was created>'
    examples = [
        {'title': 'rclone (~/.config/rclone/rclone.conf)',
         'code': '[indianscloud-s3]\ntype = s3\nprovider = Other\nendpoint = %s\nregion = %s\n'
                 'force_path_style = true\naccess_key_id = %s\nsecret_access_key = %s' % (url, region, key, secret)},
        {'title': 'AWS CLI',
         'code': 'aws configure set aws_access_key_id %s\naws configure set aws_secret_access_key \'%s\'\n'
                 'aws configure set region %s\naws configure set default.s3.addressing_style path\n'
                 'aws --endpoint-url %s s3 ls s3://BUCKET/' % (key, secret, region, url)},
        {'title': 'PHP (aws/aws-sdk-php)',
         'code': "$s3 = new Aws\\S3\\S3Client([\n    'version' => 'latest',\n    'region' => '%s',\n"
                 "    'endpoint' => '%s',\n    'use_path_style_endpoint' => true,\n"
                 "    'credentials' => ['key' => '%s', 'secret' => '%s'],\n]);" % (region, url, key, secret)},
    ]
    backup = {'link': '/addons/destinations/', 'preset': 'MinIO / other S3-compatible',
              'endpoint': endpoint or _addr(host, cfg['s3_port']), 'region': region, 'use_http': not endpoint}
    return {'host': endpoint or host, 'port': 443 if endpoint else cfg['s3_port'], 'url': url, 'local_url': local,
            'region': region, 'style': 'path-style (https://host/BUCKET/key); virtual-host style is not set up',
            'auth': 'an access key per customer or app (AWS Signature V4)', 'examples': examples, 'backup': backup,
            'note': ('Customers use %s.' % url) if endpoint else
                    'Local only: sites on this server can use %s. Set up the HTTPS endpoint below for customers.' % local}

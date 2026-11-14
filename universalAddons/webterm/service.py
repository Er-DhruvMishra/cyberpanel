"""Web terminal: configuration, policy, systemd unit and audit log (no Django imports).

Transport: lscpd (the panel's web server on :8090) has its virtual host compiled into the binary
and reads no context configuration, so it cannot proxy a websocket to a local backend. The
terminal service therefore listens on its own port (default 8095) with TLS from the panel's
certificate (/usr/local/lscp/conf/cert.pem, key.pem), like upstream's :8888 server. Setting
"listen" to 127.0.0.1, "tls" to false and "public_url" to a wss:// URL lets it run behind a
reverse proxy instead (for example an OpenLiteSpeed websocket context); "trust_proxy" then makes
it take the client address from X-Forwarded-For, but only from a loopback peer.
"""
import ipaddress
import json
import os
import re
import subprocess
import time
from urllib.parse import urlsplit

SERVICE = 'cp-webterm.service'
UNIT_PATH = '/etc/systemd/system/' + SERVICE
CONFIG_FILE = '/etc/cyberpanel/webterm.json'
POLICY_FILE = '/etc/cyberpanel/universal-apps.json'  # shared with universalAddons.access
AUDIT_LOG = '/var/log/cyberpanel-webterm.log'
LOGROTATE_PATH = '/etc/logrotate.d/cp-webterm'
PYTHON = '/usr/local/CyberCP/bin/python'
SERVER = '/usr/local/CyberCP/universalAddons/webterm/server.py'
WS_PATH = '/cp-webterm/ws'  # proxied by OpenLiteSpeed on the chosen site (no extra port)
POLICY_KEYS = ('terminal_for_users', 'terminal_root_for_admins')

DEFAULT_CONFIG = {
    'listen': '127.0.0.1',
    'port': 8095,
    'tls': False,
    'cert': '/usr/local/lscp/conf/cert.pem',
    'key': '/usr/local/lscp/conf/key.pem',
    'public_url': '',        # wss://<site>/cp-webterm/ws, set by setup
    'site': '',              # the OpenLiteSpeed site whose vhost proxies the websocket
    'trust_proxy': True,
    'memory_mb': 1024,       # cgroup cap for the service and every shell it runs
    'cpu_percent': 200,
}

HOST_RE = re.compile(r'^(\[[0-9a-fA-F:.]{2,45}\]|[A-Za-z0-9.-]{1,253})(:\d{1,5})?$')


class WebtermError(ValueError):
    pass


# ----------------------------------------------------------------------------- configuration

def load_config(path=None):
    config = dict(DEFAULT_CONFIG)
    try:
        with open(path or CONFIG_FILE) as handle:
            stored = json.load(handle)
    except (OSError, ValueError):
        stored = {}
    if isinstance(stored, dict):
        for key, default in DEFAULT_CONFIG.items():
            value = stored.get(key)
            if isinstance(value, type(default)) and not (isinstance(default, int) and isinstance(value, bool)):
                config[key] = value
    return validate_config(config)


def validate_config(config):
    try:
        ipaddress.ip_address(config['listen'])
    except ValueError:
        raise WebtermError('listen must be an IP address.')
    if not 1024 <= config['port'] <= 65535:
        raise WebtermError('port must be between 1024 and 65535.')
    if config['public_url']:
        parts = urlsplit(config['public_url'])
        if parts.scheme != 'wss' or not parts.netloc or parts.query or parts.fragment:
            raise WebtermError('public_url must be a wss:// URL without a query string.')
    if not config['tls'] and not config['public_url']:
        # Browsers block ws:// from an https page anyway; plain text is only for a local proxy.
        if not ipaddress.ip_address(config['listen']).is_loopback:
            raise WebtermError('Without TLS the service must listen on 127.0.0.1 behind a proxy.')
    if not 128 <= config['memory_mb'] <= 16384:
        raise WebtermError('memory_mb must be between 128 and 16384.')
    if not 10 <= config['cpu_percent'] <= 6400:
        raise WebtermError('cpu_percent must be between 10 and 6400.')
    return config


def save_config(config, path=None):
    path = path or CONFIG_FILE
    clean = validate_config(dict(DEFAULT_CONFIG, **config))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + '.tmp', 'w') as handle:
        json.dump(clean, handle, indent=2, sort_keys=True)
    os.chmod(path + '.tmp', 0o644)  # the panel reads the port; no secrets in here
    os.replace(path + '.tmp', path)
    return clean


def client_url_info(config):
    """What the page needs to build the websocket URL."""
    return {'port': config['port'], 'path': WS_PATH, 'public_url': config['public_url'], 'tls': config['tls']}


# ----------------------------------------------------------------------------- policy

def terminal_policy(path=None):
    """The two terminal switches, read straight from the shared policy file (default off)."""
    policy = {key: False for key in POLICY_KEYS}
    try:
        with open(path or POLICY_FILE) as handle:
            stored = json.load(handle)
        for key in POLICY_KEYS:
            if stored.get(key) is True:
                policy[key] = True
    except (OSError, ValueError, AttributeError):
        pass
    return policy


def save_terminal_policy(values, path=None):
    """Update only the terminal keys of the shared policy file, keeping everything else."""
    path = path or POLICY_FILE
    try:
        with open(path) as handle:
            stored = json.load(handle)
        if not isinstance(stored, dict):
            stored = {}
    except (OSError, ValueError):
        stored = {}
    for key in POLICY_KEYS:
        if key in values:
            if not isinstance(values[key], bool):
                raise WebtermError('%s must be true or false.' % key)
            stored[key] = values[key]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + '.tmp', 'w') as handle:
        json.dump(stored, handle, indent=2, sort_keys=True)
    os.chmod(path + '.tmp', 0o644)
    os.replace(path + '.tmp', path)
    return terminal_policy(path)


# ----------------------------------------------------------------------------- request checks

def valid_host(host):
    return isinstance(host, str) and bool(HOST_RE.match(host))


def origin_allowed(origin, host, public_url=''):
    """The websocket handshake's Origin must be the panel page that asked for the ticket."""
    if not origin or not valid_host(host):
        return False
    parts = urlsplit(origin)
    return parts.scheme in ('https', 'http') and parts.netloc.lower() == host.lower() and not parts.path.strip('/')


def client_address(peer, forwarded_for, trust_proxy, cf_connecting_ip=''):
    """The client's address as the panel saw it.

    Direct connections: the TCP peer. Through the trusted local proxy (OpenLiteSpeed): the
    CF-Connecting-IP header if present (the panel prefers it too), else the last X-Forwarded-For
    hop. A proxied connection without either header returns None ("unknown"): the ticket is then
    accepted without the address check, still single-use, 60 s and bound to the panel's origin.
    """
    peer = (peer or '').strip()
    try:
        loopback = ipaddress.ip_address(peer).is_loopback
    except ValueError:
        loopback = False
    if trust_proxy and loopback:
        if cf_connecting_ip:
            return cf_connecting_ip.strip()
        if forwarded_for:
            return forwarded_for.split(',')[-1].strip()
        return None
    return peer


# ----------------------------------------------------------------------------- systemd

def systemd_version(runner=subprocess.run):
    try:
        out = runner(['systemctl', '--version'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     universal_newlines=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return 239
    match = re.search(r'systemd (\d+)', out or '')
    return int(match.group(1)) if match else 239


def cgroup_v2():
    return os.path.exists('/sys/fs/cgroup/cgroup.controllers')


def render_unit(config, version=239, unified=False):
    """The service runs as root (it must switch to each site's user) with only the restrictions
    that leave a normal shell working: no setuid/setgid elevation (NoNewPrivileges, so sudo, su
    and crontab do not work inside the terminal), a memory/CPU/task cap for all shells together,
    and a raised OOM score so the kernel kills terminals before the panel or databases."""
    config = validate_config(dict(DEFAULT_CONFIG, **config))
    lines = [
        '# Managed by CyberPanel Universal (Web Terminal). Changes are overwritten.',
        '[Unit]',
        'Description=CyberPanel Universal web terminal',
        'After=network.target',
        '',
        '[Service]',
        'Type=simple',
        'User=root',
        'Group=root',
        'ExecStart=%s %s' % (PYTHON, SERVER),
        'Environment="PYTHONDONTWRITEBYTECODE=1" "PYTHONUNBUFFERED=1"',
        'WorkingDirectory=/',
        'Restart=on-failure',
        'RestartSec=5',
        'TimeoutStopSec=15',
        'KillMode=control-group',
        'UMask=0077',
        'NoNewPrivileges=yes',
        'OOMScoreAdjust=300',
        'TasksMax=512',
        'LimitNOFILE=4096',
        'CPUQuota=%d%%' % config['cpu_percent'],
        ('MemoryMax=%dM' if unified else 'MemoryLimit=%dM') % config['memory_mb'],
    ]
    if version >= 242:
        lines.append('ProtectHostname=yes')
    lines += ['', '[Install]', 'WantedBy=multi-user.target', '']
    return '\n'.join(lines)


def render_logrotate():
    return ('%s {\n    weekly\n    rotate 12\n    compress\n    missingok\n    notifempty\n'
            '    create 0600 root root\n}\n' % AUDIT_LOG)


def service_status(runner=subprocess.run):
    try:
        out = runner(['systemctl', 'show', SERVICE, '--property=ActiveState,SubState,MainPID,UnitFileState,'
                      'ExecMainStartTimestamp,MemoryCurrent'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     universal_newlines=True, timeout=30).stdout or ''
    except (OSError, subprocess.SubprocessError):
        out = ''
    values = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
    memory = values.get('MemoryCurrent', '')
    return {'state': values.get('ActiveState', 'unknown'), 'sub': values.get('SubState', ''),
            'enabled': values.get('UnitFileState', ''), 'since': values.get('ExecMainStartTimestamp', ''),
            'running': values.get('ActiveState') == 'active',
            'memory_mb': round(int(memory) / 1048576, 1) if memory.isdigit() else None}


# ----------------------------------------------------------------------------- audit log

_SAFE = re.compile(r'[^A-Za-z0-9._@:/+-]')


def audit_line(event, now=None, **fields):
    """One line per event; values are reduced to a safe character set (no log injection).
    Keystrokes and terminal output are never logged."""
    stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() if now is None else now))
    parts = ['%s=%s' % (key, _SAFE.sub('_', str(value))[:120]) for key, value in fields.items()]
    return '%s %s %s\n' % (stamp, _SAFE.sub('_', event)[:30], ' '.join(parts))


def audit(event, path=None, **fields):
    try:
        fd = os.open(path or AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as handle:
            handle.write(audit_line(event, **fields))
    except OSError:
        pass

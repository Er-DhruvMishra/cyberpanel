"""More server applications: PostgreSQL, MongoDB, RabbitMQ, Oracle Instant Client, and the Oracle
Database feasibility gate. Plain logic shared by actions.py and the tests (no root needed here).

Configuration rules are the same as in service.py: the panel writes only files it owns (or one
marked block), never the vendor's settings, and every change is backed up and rolled back if the
service does not come back healthy.
  * PostgreSQL: panel-managed.conf in the data directory, pulled in by an `include` line in a marked
    block at the end of postgresql.conf (last value wins), and a marked block at the TOP of
    pg_hba.conf (first matching line wins).
  * MongoDB: a systemd drop-in that sets OPTIONS (command-line options override /etc/mongod.conf).
  * RabbitMQ: /etc/rabbitmq/conf.d/90-panel-managed.conf and a systemd drop-in for epmd.
Repositories are official ones with GPG checking on, in /etc/yum.repos.d/cp-*.repo.
"""
import os
import re
import socket

from universalAddons.appsvc import service as sv
from universalAddons.appsvc.service import AppError

OS_RELEASE = '/etc/os-release'
MANAGED_HEADER = '# Managed by the panel (IndiansCloud Add-ons > Applications); changes here are overwritten.'


def el_version(path=OS_RELEASE):
    """(id, major version) of an RPM-based OS, e.g. ('centos', 8); (id, None) elsewhere."""
    values = {}
    try:
        with open(path) as handle:
            for line in handle:
                key, sep, value = line.strip().partition('=')
                if sep:
                    values[key] = value.strip().strip('"')
    except OSError:
        pass
    like = (values.get('ID', '') + ' ' + values.get('ID_LIKE', '')).split()
    major = values.get('VERSION_ID', '').split('.')[0]
    if ('rhel' in like or 'fedora' in like) and major.isdigit():
        return values.get('ID', ''), int(major)
    return values.get('ID', ''), None


def os_check(key, el):
    """Hard preflight check: the new applications are offered for EL 8 and 9 only."""
    title = sv.app_info(key)['title']
    ok = el in (8, 9)
    return {'id': 'os', 'ok': ok, 'hard': True,
            'detail': ('%s packages are published for EL %s.' % (title, el)) if ok else
                      '%s is offered here only on EL 8 or 9 (RPM based).' % title}


def _repo_section(repo_id, name, baseurl, gpgkeys, extra=''):
    return ('[%s]\nname=%s\nbaseurl=%s\nenabled=1\ngpgcheck=1\n%sgpgkey=%s\n' % (
        repo_id, name, baseurl, extra, '\n       '.join(gpgkeys)))


# ----------------------------------------------------------------------------- PostgreSQL

PG_GPG_KEY = 'https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-RHEL'
PG_ADMIN_NAMES = ('postgres', 'template0', 'template1', 'public', 'root', 'admin')
PG_NAME_RE = re.compile(r'^[a-z][a-z0-9_]{1,62}$')
PG_AUTH = ('scram-sha-256', 'md5')
PG_PANEL_FILE = 'panel-managed.conf'


def pg_repo_id(major):
    return 'cp-pgdg%d' % int(major)


def pg_repo_file(major):
    return '/etc/yum.repos.d/%s.repo' % pg_repo_id(major)


def pg_repo_text(major, el):
    major, el = int(major), int(el)
    if major not in sv.PG_MAJORS:
        raise AppError('PostgreSQL %d is not offered (choose %s).' % (major, ' or '.join(map(str, sv.PG_MAJORS))))
    return _repo_section(pg_repo_id(major), 'PostgreSQL %d for RHEL %d - $basearch (PGDG, added by IndiansCloud)' % (major, el),
                         'https://download.postgresql.org/pub/repos/yum/%d/redhat/rhel-%d-$basearch' % (major, el),
                         [PG_GPG_KEY], extra='repo_gpgcheck=1\n')


def pg_packages(major):
    return ['postgresql%d-server' % major, 'postgresql%d' % major, 'postgresql%d-libs' % major,
            'postgresql%d-contrib' % major]


def pg_paths(major):
    base = '/var/lib/pgsql/%d' % major
    data = base + '/data'
    return {'base': base, 'data': data, 'conf': data + '/postgresql.conf', 'hba': data + '/pg_hba.conf',
            'panel': data + '/' + PG_PANEL_FILE, 'bin': '/usr/pgsql-%d/bin' % major,
            'setup': '/usr/pgsql-%d/bin/postgresql-%d-setup' % (major, major), 'log': data + '/log'}


def pg_default_shared_buffers(ram_mb):
    """1/16 of RAM in 32 MB steps, between 128 MB and 1 GB (a shared hosting server, not a DB box)."""
    return max(128, min(1024, (ram_mb // 16) // 32 * 32)) if ram_mb else 128


def pg_defaults(ram_mb):
    return {'shared_buffers_mb': pg_default_shared_buffers(ram_mb), 'work_mem_mb': 4, 'max_connections': 100,
            'listen_addresses': ['127.0.0.1'], 'auth_method': 'scram-sha-256'}


def parse_pg_conf(text):
    """name -> value of postgresql.conf-style `name = value` lines (last one wins, comments ignored)."""
    values = {}
    for line in (text or '').splitlines():
        match = re.match(r"^\s*([a-z_.]+)\s*=?\s*('(?:[^']|'')*'|[^\s#']+)", line)
        if match:
            value = match.group(2)
            if len(value) >= 2 and value[0] == value[-1] == "'":
                value = value[1:-1].replace("''", "'")
            values[match.group(1)] = value
    return values


def pg_size_mb(value, unit_kb):
    """Size setting in MB; a bare number counts in units of `unit_kb` kB (8 for shared_buffers, 1 for work_mem)."""
    match = re.match(r'^(\d+)\s*(kB|MB|GB|TB)?$', str(value or '').strip())
    if not match:
        return None
    number, unit = int(match.group(1)), match.group(2)
    kb = number * {None: unit_kb, 'kB': 1, 'MB': 1024, 'GB': 1024 ** 2, 'TB': 1024 ** 3}[unit]
    return kb // 1024


def pg_current(conf_text, panel_text, hba_text, ram_mb=0):
    merged = parse_pg_conf(conf_text)
    managed = sv.split_block(conf_text or '')[1] is not None
    if managed and panel_text:
        merged.update(parse_pg_conf(panel_text))
    listen = merged.get('listen_addresses', 'localhost')
    listen = [a.strip() for a in listen.split(',') if a.strip()] or ['localhost']
    listen = ['127.0.0.1' if a == 'localhost' else ('0.0.0.0' if a == '*' else a) for a in listen]
    _, hba_block, _ = sv.split_block(hba_text or '')
    method = 'scram-sha-256'
    for line in hba_block or []:
        parts = line.split()
        if parts and parts[0] == 'host' and parts[-1] in PG_AUTH:
            method = parts[-1]
            break
    connections = merged.get('max_connections', '100')
    return {'shared_buffers_mb': pg_size_mb(merged.get('shared_buffers', '128MB'), 8) or 128,
            'work_mem_mb': pg_size_mb(merged.get('work_mem', '4MB'), 1) or 4,
            'max_connections': int(connections) if connections.isdigit() else 100,
            'listen_addresses': listen, 'auth_method': method,
            'managed': managed, 'hba_managed': hba_block is not None}


def validate_pg(settings, ram_mb, confirm_exposed=False):
    if not isinstance(settings, dict):
        raise AppError('Settings must be an object.')
    listen = settings.get('listen_addresses', ['127.0.0.1'])
    if isinstance(listen, str):
        listen = listen.replace(',', ' ').split()
    if not isinstance(listen, list) or not 1 <= len(listen) <= 4:
        raise AppError('Give one to four listen addresses.')
    cfg = {
        'shared_buffers_mb': sv._int(settings.get('shared_buffers_mb', 128), 32, max(32, ram_mb // 4),
                                     'shared_buffers (MB, at most a quarter of the %d MB of RAM)' % ram_mb),
        'work_mem_mb': sv._int(settings.get('work_mem_mb', 4), 1, 256, 'work_mem (MB)'),
        'max_connections': sv._int(settings.get('max_connections', 100), 10, 1000, 'max_connections'),
        'listen_addresses': [sv._host(a, 'listen_addresses', allow_any=True) for a in listen],
        'auth_method': str(settings.get('auth_method', 'scram-sha-256')),
    }
    if cfg['auth_method'] not in PG_AUTH:
        raise AppError('The password method must be scram-sha-256 or md5.')
    warnings = []
    if cfg['max_connections'] * cfg['work_mem_mb'] > ram_mb // 2:
        warnings.append('max_connections x work_mem is %d MB, over half of RAM: many busy connections at once could '
                        'run the server out of memory.' % (cfg['max_connections'] * cfg['work_mem_mb']))
    if cfg['auth_method'] == 'md5':
        warnings.append('md5 is weaker than scram-sha-256; use it only for old client libraries.')
    exposed = [a for a in cfg['listen_addresses'] if not sv.is_loopback(a)]
    if exposed:
        warnings.append('DANGER: PostgreSQL will listen on %s and accept password logins from any address. '
                        'Firewall port 5432.' % ', '.join(exposed))
        if confirm_exposed is not True:
            raise AppError('PostgreSQL would listen on %s, beyond this server. Tick the confirmation to do this.'
                           % ', '.join(exposed))
    return cfg, warnings


def render_pg_panel(cfg):
    return '\n'.join([
        MANAGED_HEADER,
        "listen_addresses = '%s'" % ','.join(cfg['listen_addresses']),
        'max_connections = %d' % cfg['max_connections'],
        'shared_buffers = %dMB' % cfg['shared_buffers_mb'],
        'work_mem = %dMB' % cfg['work_mem_mb'],
        "password_encryption = 'scram-sha-256'",
    ]) + '\n'


def pg_include_block():
    return ["include '%s'" % PG_PANEL_FILE]


def render_pg_hba_block(cfg):
    method = cfg['auth_method']
    lines = ['local   all   postgres                   peer',
             'local   all   all                        %s' % method,
             'host    all   all       127.0.0.1/32     %s' % method,
             'host    all   all       ::1/128          %s' % method]
    if any(not sv.is_loopback(a) for a in cfg['listen_addresses']):
        lines += ['host    all   all       0.0.0.0/0        %s' % method,
                  'host    all   all       ::/0             %s' % method]
    return lines


def pg_ident(name):
    if not isinstance(name, str) or not PG_NAME_RE.match(name):
        raise AppError('Names use lowercase letters, digits and _ (2-63, starting with a letter).')
    if name in PG_ADMIN_NAMES or name.startswith('pg_'):
        raise AppError('%s is reserved.' % name)
    return '"%s"' % name


def pg_create_sql(database, user, password):
    """CREATE ROLE + DATABASE owned by it; sent to psql on stdin (never on a command line)."""
    if not re.match(r'^[A-Za-z0-9_-]{16,128}$', password or ''):
        raise AppError('Unexpected password format.')
    db, role = pg_ident(database), pg_ident(user)
    return '\n'.join([
        "CREATE ROLE %s LOGIN PASSWORD '%s';" % (role, password),
        'CREATE DATABASE %s OWNER %s;' % (db, role),
        'REVOKE ALL ON DATABASE %s FROM PUBLIC;' % db,
        'GRANT ALL ON DATABASE %s TO %s;' % (db, role),
    ]) + '\n'


def pg_connection_info(cfg, major):
    host = next((a for a in cfg['listen_addresses'] if sv.is_loopback(a)), '127.0.0.1')
    host = '127.0.0.1' if host in ('0.0.0.0',) else host
    return {'host': host, 'port': 5432, 'auth': 'a user and password per database (%s)' % cfg['auth_method'],
            'examples': [
                {'title': 'PHP (PDO)', 'code': "$db = new PDO('pgsql:host=%s;port=5432;dbname=DBNAME', 'USER', 'PASSWORD');" % host},
                {'title': 'Laravel .env', 'code': 'DB_CONNECTION=pgsql\nDB_HOST=%s\nDB_PORT=5432\nDB_DATABASE=DBNAME\n'
                                                  'DB_USERNAME=USER\nDB_PASSWORD=PASSWORD' % host},
                {'title': 'Command line', 'code': '%s/psql -h %s -U USER DBNAME' % (pg_paths(major)['bin'], host)}],
            'note': 'Create a database and its user below; the password is shown once.'}


# ----------------------------------------------------------------------------- MongoDB

MONGO_SERIES = '8.0'
MONGO_GPG_KEY = 'https://pgp.mongodb.com/server-8.0.asc'
MONGO_REPO_ID = 'cp-mongodb-org-8.0'
MONGO_REPO_FILE = '/etc/yum.repos.d/cp-mongodb-org-8.0.repo'
MONGO_CONF = '/etc/mongod.conf'
MONGO_SYSCONFIG = '/etc/sysconfig/mongod'
MONGO_DROPIN = '/etc/systemd/system/mongod.service.d/panel-managed.conf'
MONGO_PORT = 27017
MONGO_ADMIN = 'admin'
MONGOSH = '/usr/bin/mongosh'


def mongo_repo_text(el):
    return _repo_section(MONGO_REPO_ID, 'MongoDB %s Community for RHEL %d (MongoDB, added by IndiansCloud)' % (MONGO_SERIES, el),
                         'https://repo.mongodb.org/yum/redhat/%d/mongodb-org/%s/x86_64/' % (int(el), MONGO_SERIES),
                         [MONGO_GPG_KEY])


def mongo_cache_bounds(ram_mb):
    return 0.25, max(0.25, round((ram_mb / 2.0) / 1024, 2))


def mongo_defaults(ram_mb):
    return {'cache_gb': 0.25, 'bind_ip': ['127.0.0.1'], 'auth': True}


def _mongo_opts(text):
    match = re.search(r'^Environment="OPTIONS=([^"]*)"\s*$', text or '', re.M)
    return match.group(1).split() if match else None


def mongo_current(dropin_text, conf_text=''):
    """Settings from the panel's drop-in, else from /etc/mongod.conf (flat key lookup)."""
    opts = _mongo_opts(dropin_text)
    if opts is not None:
        def value(flag, default=None):
            return opts[opts.index(flag) + 1] if flag in opts and opts.index(flag) + 1 < len(opts) else default
        try:
            cache = float(value('--wiredTigerCacheSizeGB', '0') or 0)
        except ValueError:
            cache = 0
        return {'cache_gb': cache, 'bind_ip': (value('--bind_ip', '127.0.0.1') or '').split(','),
                'auth': '--auth' in opts, 'managed': True}
    bind = re.search(r'^\s*bindIp:\s*([^\s#]+)', conf_text or '', re.M)
    cache = re.search(r'^\s*cacheSizeGB:\s*([\d.]+)', conf_text or '', re.M)
    auth = re.search(r'^\s*authorization:\s*"?enabled', conf_text or '', re.M)
    return {'cache_gb': float(cache.group(1)) if cache else 0, 'bind_ip': (bind.group(1) if bind else '127.0.0.1').split(','),
            'auth': bool(auth), 'managed': False}


def validate_mongo(settings, ram_mb, confirm_exposed=False):
    if not isinstance(settings, dict):
        raise AppError('Settings must be an object.')
    bind = settings.get('bind_ip', ['127.0.0.1'])
    if isinstance(bind, str):
        bind = bind.replace(',', ' ').split()
    if not isinstance(bind, list) or not 1 <= len(bind) <= 4:
        raise AppError('Give one to four bind addresses.')
    low, high = mongo_cache_bounds(ram_mb)
    cfg = {'cache_gb': sv._float(settings.get('cache_gb', 0.25), low, high, 'cacheSizeGB (at most half of RAM)'),
           'bind_ip': [sv._host(b, 'bindIp', allow_any=True) for b in bind],
           'auth': sv._bool(settings.get('auth')), 'rotate_password': sv._bool(settings.get('rotate_password'))}
    warnings = []
    if not cfg['auth']:
        warnings.append('Without authorization every local account (each site\'s PHP) can read and change every database.')
    exposed = [b for b in cfg['bind_ip'] if not sv.is_loopback(b)]
    if exposed:
        if not cfg['auth']:
            raise AppError('MongoDB may listen beyond loopback (%s) only with authorization on.' % ', '.join(exposed))
        warnings.append('DANGER: MongoDB will listen on %s, reachable from the network. Firewall port %d.'
                        % (', '.join(exposed), MONGO_PORT))
        if confirm_exposed is not True:
            raise AppError('MongoDB would listen on %s, beyond this server. Tick the confirmation to do this.'
                           % ', '.join(exposed))
    return cfg, warnings


def render_mongo_dropin(cfg):
    options = ['-f', MONGO_CONF, '--wiredTigerCacheSizeGB', '%g' % cfg['cache_gb'], '--bind_ip', ','.join(cfg['bind_ip'])]
    options.append('--auth' if cfg['auth'] else '--noauth')
    return (MANAGED_HEADER + '\n# Command-line options override /etc/mongod.conf, which the panel leaves alone.\n'
            '[Service]\nEnvironment="OPTIONS=%s"\n' % ' '.join(options))


def mongo_sysconfig_conflict(text):
    """/etc/sysconfig/mongod is read after Environment= and would override the panel's OPTIONS."""
    return bool(re.search(r'^\s*OPTIONS\s*=', text or '', re.M))


def mongo_target(cfg):
    host = next((b for b in cfg['bind_ip'] if sv.is_loopback(b)), cfg['bind_ip'][0])
    return {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(host, host)


def mongo_uri(host):
    return 'mongodb://%s:%d/admin' % ('[%s]' % host if ':' in host else host, MONGO_PORT)


def mongo_user_script(password, old_password=None):
    """mongosh script that creates the admin user, or changes its password (run from a 0600 file)."""
    for value in (password, old_password):
        if value is not None and not re.match(r'^[A-Za-z0-9_-]{16,128}$', value):
            raise AppError('Unexpected password format.')
    lines = ["const admin = db.getSiblingDB('admin');"]
    if old_password:
        lines.append("admin.auth('%s', '%s');" % (MONGO_ADMIN, old_password))
    lines += ["if (admin.getUser('%s') === null) {" % MONGO_ADMIN,
              "  admin.createUser({user: '%s', pwd: '%s', roles: [{role: 'root', db: 'admin'}]});" % (MONGO_ADMIN, password),
              "  print('created');",
              "} else {",
              "  admin.changeUserPassword('%s', '%s');" % (MONGO_ADMIN, password),
              "  print('changed');",
              "}"]
    return '\n'.join(lines) + '\n'


def mongo_auth_check_script(password):
    if not re.match(r'^[A-Za-z0-9_-]{16,128}$', password or ''):
        raise AppError('Unexpected password format.')
    return ("const admin = db.getSiblingDB('admin');\nadmin.auth('%s', '%s');\n"
            "print(admin.runCommand({listDatabases: 1, nameOnly: true}).ok);\n" % (MONGO_ADMIN, password))


def mongo_connection_info(cfg, password_set):
    host = mongo_target(cfg)
    secret = '<the password shown once by the panel>'
    uri = 'mongodb://%s%s:%d/?authSource=admin' % ('%s:%s@' % (MONGO_ADMIN, secret) if password_set else '',
                                                    host, MONGO_PORT)
    return {'host': host, 'port': MONGO_PORT, 'url': uri,
            'auth': 'user %s (root), password set' % MONGO_ADMIN if password_set else 'none',
            'examples': [{'title': 'Connection string', 'code': uri},
                         {'title': 'Command line', 'code': 'mongosh "mongodb://%s:%d" -u %s --authenticationDatabase admin'
                          % (host, MONGO_PORT, MONGO_ADMIN)},
                         {'title': 'PHP (mongodb extension + mongodb/mongodb)', 'code': "$client = new MongoDB\\Client('%s');" % uri}],
            'note': 'The admin user has the root role: create a user per site with only the roles it needs.'}


# ----------------------------------------------------------------------------- RabbitMQ

RABBIT_REPO_FILE = '/etc/yum.repos.d/cp-rabbitmq.repo'
RABBIT_KEY_RELEASE = 'https://github.com/rabbitmq/signing-keys/releases/download/3.0/rabbitmq-release-signing-key.asc'
RABBIT_KEY_ERLANG = 'https://github.com/rabbitmq/signing-keys/releases/download/3.0/cloudsmith.rabbitmq-erlang.E495BB49CC4BBE5B.key'
RABBIT_KEY_SERVER = 'https://github.com/rabbitmq/signing-keys/releases/download/3.0/cloudsmith.rabbitmq-server.9F4587F226208342.key'
RABBIT_KEYS = (RABBIT_KEY_RELEASE, RABBIT_KEY_ERLANG, RABBIT_KEY_SERVER)
RABBIT_CONF_DIR = '/etc/rabbitmq/conf.d'
RABBIT_DROPIN = '/etc/rabbitmq/conf.d/90-panel-managed.conf'
RABBIT_SYSTEMD_DROPIN = '/etc/systemd/system/rabbitmq-server.service.d/panel-managed.conf'
RABBIT_SYSTEMD_TEXT = (MANAGED_HEADER + '\n# Keep the Erlang port mapper (epmd, 4369) on loopback.\n'
                       '[Service]\nEnvironment=ERL_EPMD_ADDRESS=127.0.0.1\n')
RABBIT_PORT = 5672


def rabbit_repo_text(el):
    el = int(el)
    sections = []
    for repo_id, kind, keys in (('cp-rabbitmq-erlang', 'erlang', [RABBIT_KEY_ERLANG]),
                                ('cp-rabbitmq-server', 'rabbitmq', [RABBIT_KEY_SERVER, RABBIT_KEY_RELEASE])):
        for arch in ('$basearch', 'noarch'):
            suffix = '' if arch == '$basearch' else '-noarch'
            sections.append(_repo_section(
                repo_id + suffix, 'Team RabbitMQ %s for EL %d %s (added by IndiansCloud)' % (kind, el, arch),
                'https://yum1.rabbitmq.com/%s/el/%d/%s\n        https://yum2.rabbitmq.com/%s/el/%d/%s' % (
                    kind, el, arch, kind, el, arch), keys + ([RABBIT_KEY_RELEASE] if kind == 'erlang' and suffix else []),
                extra='sslverify=1\nmetadata_expire=300\n'))
    return '\n'.join(sections)


def rabbit_defaults(ram_mb):
    return {'memory_mb': 256, 'bind': '127.0.0.1', 'disk_free_limit_mb': 1024}


def rabbit_current(text):
    values = {}
    for line in (text or '').splitlines():
        key, sep, value = line.partition('=')
        if sep and not line.lstrip().startswith('#'):
            values[key.strip()] = value.strip()
    listener = values.get('listeners.tcp.default', '')
    bind = listener.rsplit(':', 1)[0] if ':' in listener else '0.0.0.0'

    def mb(name, default):
        match = re.match(r'^(\d+)MB$', values.get(name, ''))
        return int(match.group(1)) if match else default
    return {'memory_mb': mb('vm_memory_high_watermark.absolute', 0), 'bind': bind or '0.0.0.0',
            'disk_free_limit_mb': mb('disk_free_limit.absolute', 50), 'managed': bool(values)}


def validate_rabbit(settings, ram_mb, confirm_exposed=False):
    if not isinstance(settings, dict):
        raise AppError('Settings must be an object.')
    cfg = {'memory_mb': sv._int(settings.get('memory_mb', 256), 128, max(128, ram_mb // 2),
                                'Memory high watermark (MB, at most half of the %d MB of RAM)' % ram_mb),
           'bind': sv._host(settings.get('bind', '127.0.0.1'), 'Listener address', allow_any=True),
           'disk_free_limit_mb': sv._int(settings.get('disk_free_limit_mb', 1024), 50, 102400, 'Disk free limit (MB)')}
    warnings = []
    if not sv.is_loopback(cfg['bind']):
        warnings.append('DANGER: RabbitMQ will accept AMQP connections on %s:%d. Create a user with a strong '
                        'password first (guest works only from 127.0.0.1) and firewall the port.' % (cfg['bind'], RABBIT_PORT))
        if confirm_exposed is not True:
            raise AppError('RabbitMQ would listen on %s, beyond this server. Tick the confirmation to do this.' % cfg['bind'])
    return cfg, warnings


def render_rabbit_conf(cfg):
    return '\n'.join([
        MANAGED_HEADER,
        'listeners.tcp.default = %s:%d' % (cfg['bind'], RABBIT_PORT),
        'vm_memory_high_watermark.absolute = %dMB' % cfg['memory_mb'],
        'disk_free_limit.absolute = %dMB' % cfg['disk_free_limit_mb'],
        'distribution.listener.interface = 127.0.0.1',
    ]) + '\n'


def amqp_probe(host, port=RABBIT_PORT, timeout=5, connect=socket.create_connection):
    """(healthy, detail): the broker answers the AMQP 0-9-1 protocol header with connection.start."""
    try:
        sock = connect((host, port), timeout=timeout)
        try:
            sock.sendall(b'AMQP\x00\x00\x09\x01')
            data = sock.recv(16)
        finally:
            sock.close()
    except OSError as exc:
        return False, 'no answer on %s:%d (%s)' % (host, port, exc)
    if data[:1] == b'\x01' and len(data) >= 7:
        return True, 'AMQP 0-9-1 connection.start received'
    return False, 'unexpected reply from %s:%d' % (host, port)


def rabbit_target(cfg):
    return {'0.0.0.0': '127.0.0.1', '::': '::1'}.get(cfg['bind'], cfg['bind'])


def rabbit_connection_info(cfg):
    host = rabbit_target(cfg)
    return {'host': host, 'port': RABBIT_PORT, 'url': 'amqp://%s:%d/' % (host, RABBIT_PORT),
            'auth': 'guest/guest from 127.0.0.1 only; add users with rabbitmqctl',
            'examples': [{'title': 'Add a user for an app', 'code': 'rabbitmqctl add_user APPUSER\n'
                                                                    'rabbitmqctl set_permissions -p / APPUSER ".*" ".*" ".*"'},
                         {'title': 'Laravel (vladimir-yuldashev/laravel-queue-rabbitmq) .env',
                          'code': 'QUEUE_CONNECTION=rabbitmq\nRABBITMQ_HOST=%s\nRABBITMQ_PORT=%d' % (host, RABBIT_PORT)}]}


# ----------------------------------------------------------------------------- Oracle

ORACLE_CLIENT_REPO_ID = 'cp-oracle-instantclient23'
ORACLE_CLIENT_REPO_FILE = '/etc/yum.repos.d/cp-oracle-instantclient23.repo'
ORACLE_GPG_KEY = 'https://yum.oracle.com/RPM-GPG-KEY-oracle-ol%d'
ORACLE_CLIENT_ROOT = '/usr/lib/oracle'


def oracle_client_repo_text(el):
    el = int(el)
    # includepkgs: this Oracle Linux repository may only ever supply Instant Client packages here.
    return _repo_section(ORACLE_CLIENT_REPO_ID, 'Oracle Instant Client 23 for Oracle Linux %d (Oracle, added by IndiansCloud)' % el,
                         'https://yum.oracle.com/repo/OracleLinux/OL%d/oracle/instantclient23/$basearch/' % el,
                         [ORACLE_GPG_KEY % el], extra='includepkgs=oracle-instantclient-*\n')


def oracle_client_connection_info(lib_dir):
    lib_dir = lib_dir or '/usr/lib/oracle/23/client64/lib'
    return {'host': 'remote', 'port': 1521, 'auth': 'the remote database\'s users',
            'examples': [{'title': 'SQL*Plus', 'code': 'sqlplus USER@//db.example.com:1521/SERVICE_NAME'},
                         {'title': 'PHP oci8 (build once per PHP version)',
                          'code': 'echo "instantclient,%s" | /usr/local/lsws/lsphpXX/bin/pecl install oci8' % lib_dir},
                         {'title': 'PHP', 'code': "$c = oci_connect('USER', 'PASSWORD', '//db.example.com:1521/SERVICE_NAME');"}],
            'note': 'Instant Client is only the client libraries; there is no Oracle Database server here.'}


ORACLE_DB_MIN_RAM_MB = 2048
ORACLE_DB_DISK_MB = 10240
ORACLE_DB_OS = ('ol', 'rhel')


def oracle_db_checks(os_id, el, ram_total_mb, ram_available_mb, committed_mb, disk_mb):
    """Feasibility of Oracle Database 23ai Free. Hard checks cannot be overridden; the RAM check
    needs an explicit confirmation of the warning."""
    budget_ok = committed_mb + ORACLE_DB_MIN_RAM_MB <= ram_total_mb * sv.BUDGET_SHARE
    return [
        {'id': 'os', 'hard': True, 'ok': os_id in ORACLE_DB_OS and el in (8, 9),
         'detail': 'Oracle supports Database Free on Oracle Linux and RHEL 8/9 only (this server: %s %s).' % (os_id or '?', el or '?')},
        {'id': 'preinstall', 'hard': True, 'ok': os_id == 'ol',
         'detail': 'oracle-database-preinstall-23ai is only in Oracle Linux repositories. On other systems it is a '
                   'single downloaded RPM that changes kernel settings server-wide, not a signed repository.'},
        {'id': 'disk', 'hard': True, 'ok': disk_mb >= ORACLE_DB_DISK_MB,
         'detail': '%d MB free; Oracle Database Free needs %d MB.' % (disk_mb, ORACLE_DB_DISK_MB)},
        {'id': 'ram', 'hard': False, 'ok': ram_available_mb >= ORACLE_DB_MIN_RAM_MB and budget_ok,
         'detail': '%d MB of RAM available (of %d MB); the other applications already take %d MB, and Oracle '
                   'recommends %d MB more for the database.' % (ram_available_mb, ram_total_mb, committed_mb,
                                                                ORACLE_DB_MIN_RAM_MB)},
    ]


def oracle_db_refusal(checks, confirm_ram):
    """None when Oracle Database Free could go ahead, else why not (RAM only with confirm_ram=True)."""
    hard = [c['detail'] for c in checks if c['hard'] and not c['ok']]
    if hard:
        return 'Oracle Database Free cannot be installed here: %s' % ' '.join(hard)
    ram = [c['detail'] for c in checks if not c['hard'] and not c['ok']]
    if ram and confirm_ram is not True:
        return ('RAM warning: %s Confirm the RAM warning to go ahead anyway.' % ' '.join(ram))
    return None

"""Hosted applications (Node.js, Python, .NET, Java) behind OpenLiteSpeed.

Each app is a systemd service running as the *site's own Linux user* with a hardened sandbox,
listening on a private 127.0.0.1 port; OpenLiteSpeed reverse-proxies a URL prefix of the site to
it. Nothing here runs app code as root.

Security model
- Ownership: the web layer only lets users manage apps of sites they own; every root action
  re-checks that the app belongs to the domain it was called with.
- Sandbox (systemd): NoNewPrivileges, empty capability set, PrivateTmp/PrivateDevices,
  ProtectSystem=strict with only the app directory writable, kernel tunables/modules/cgroups
  protected, namespaces/realtime/personality restricted, panel and credential paths
  inaccessible, memory/CPU/task limits.
- Inputs: app ids, paths, module names and env keys are validated against strict patterns;
  nothing user-supplied reaches a shell, and ExecStart only contains validated tokens.
- Secrets: environment variables live in a root-only EnvironmentFile read by systemd.

Java
- `jar`: an executable (e.g. Spring Boot) JAR, `java -jar`. Spring Boot picks up SERVER_PORT,
  SERVER_ADDRESS=127.0.0.1 and, under a sub-path, SERVER_SERVLET_CONTEXT_PATH from the environment.
- `war`: a WAR on embedded Tomcat 9 (Heroku webapp-runner; javax.servlet, so Jakarta EE 9+ WARs
  need Tomcat 10+ and are not supported). It binds 127.0.0.1 only (-Aaddress=, Tomcat's connector
  `address` attribute), takes the context path from --path, and expands the WAR under the
  service's private /tmp (--temp-directory), so the app directory stays as uploaded.
- The heap is capped at 3/4 of the memory limit (-Xmx) to leave room for metaspace, code cache and
  thread stacks inside the cgroup limit; SerialGC keeps the footprint small.
- Extra JVM options are limited to -X..., -XX:... and -D<key>=<value> tokens from a small character
  set; agents (-javaagent, -agentlib, -Xrun), boot class path changes, option files and
  OnError/OnOutOfMemoryError commands are refused, as are -D overrides of the port/address/path.
- /tmp is noexec on some hosts. Libraries that unpack native code into java.io.tmpdir and load it
  from there (e.g. snappy-java, netty-tcnative) then fail; point -Djava.io.tmpdir at a directory
  inside the app directory for those.
"""
import json
import os
import re
import shutil
import socket
import subprocess

APPS_DIR = '/etc/cyberpanel/universal-apps'
UNIT_DIR = '/etc/systemd/system'
PORT_RANGE = (20000, 29999)
MARK_BEGIN = '# BEGIN cp-ua-apps (managed by CyberPanel; do not edit)'
MARK_END = '# END cp-ua-apps'
KINDS = ('node', 'python', 'dotnet', 'java')
PY_MODES = ('wsgi', 'asgi', 'script')
JAVA_MODES = ('jar', 'war')
MAX_JVM_OPTS = 10

APP_ID_RE = re.compile(r'^[a-z][a-z0-9-]{1,30}$')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
REL_PATH_RE = re.compile(r'^(?!.*\.\.)[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$')
MODULE_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.]{0,100}:[A-Za-z_][A-Za-z0-9_]{0,60}$')
PREFIX_RE = re.compile(r'^/([A-Za-z0-9._-]+/)*$')
ENV_KEY_RE = re.compile(r'^[A-Z_][A-Z0-9_]{0,63}$')
VERSION_RE = re.compile(r'^\d{1,3}(\.\d{1,4}){1,3}$')
RESERVED_ENV = {'PORT', 'HOST', 'APP_BASE_PATH', 'SCRIPT_NAME', 'ASPNETCORE_URLS', 'PATH', 'HOME', 'USER', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
                'PYTHONPATH', 'NODE_OPTIONS', 'DOTNET_ROOT', 'SERVER_PORT', 'SERVER_ADDRESS',
                'SERVER_SERVLET_CONTEXT_PATH', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS'}
JVM_VALUE = r'[A-Za-z0-9._:/=-]'
JVM_OPT_RES = (
    re.compile(r'^-X[a-z][A-Za-z0-9]*(:%s+)?$' % JVM_VALUE),                      # -Xss512k, -Xmx384m, -Xlog:gc
    re.compile(r'^-XX:([+-][A-Za-z][A-Za-z0-9]{1,80}|[A-Za-z][A-Za-z0-9]{1,80}=%s+)$' % JVM_VALUE),  # -XX:+UseG1GC
    re.compile(r'^-D[A-Za-z0-9_][A-Za-z0-9._-]{0,100}=%s{0,500}$' % JVM_VALUE),  # -Dspring.profiles.active=prod
)
# Loading code into the JVM, or changing what the panel sets, is not an "option".
JVM_DENY_RE = re.compile(r'^(-Xrun|-Xbootclasspath|-Xdebug|-XX:[+-]?(OnError|OnOutOfMemoryError|Flags|VMOptionsFile)\b'
                         r'|-D(server\.port|server\.address|server\.servlet\.context-path)=)', re.I)


class AppError(ValueError):
    pass


def run(argv, runner=subprocess.run, timeout=600, env=None):
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout, env=env)
    except FileNotFoundError:
        return 127, '%s: not installed' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, '%s: timed out' % argv[0]
    return out.returncode, out.stdout or ''


# ----------------------------------------------------------------------------- storage

def load_apps(apps_dir=None):
    try:
        with open(os.path.join(apps_dir or APPS_DIR, 'apps.json')) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def save_apps(apps, apps_dir=None):
    directory = apps_dir or APPS_DIR
    os.makedirs(os.path.join(directory, 'env'), mode=0o700, exist_ok=True)
    temporary = os.path.join(directory, 'apps.json.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(apps, handle, indent=2, sort_keys=True)
    os.replace(temporary, os.path.join(directory, 'apps.json'))


# ----------------------------------------------------------------------------- validation

def validate(spec, site, policy, existing_apps, runtimes_installed):
    """Return a clean app record. site = {'domain','user','home'}; raises AppError."""
    app_id = str(spec.get('id', '')).strip().lower()
    if not APP_ID_RE.match(app_id):
        raise AppError('App name: 2-31 characters, lowercase letters, digits and dashes, starting with a letter.')
    current = existing_apps.get(app_id)
    if current and current['domain'] != site['domain']:
        raise AppError('An app called %s already exists on another site.' % app_id)
    if not current:
        same_site = [a for a in existing_apps.values() if a['domain'] == site['domain']]
        if len(same_site) >= policy['max_apps_per_site']:
            raise AppError('This site already has the maximum of %d apps.' % policy['max_apps_per_site'])
    kind = spec.get('kind')
    if kind not in KINDS:
        raise AppError('Choose Node.js, Python, .NET or Java.')
    version = str(spec.get('runtime', ''))
    if not any(r['version'] == version for r in runtimes_installed.get(kind, [])):
        raise AppError('Runtime %s %s is not installed. Ask the administrator to install it.' % (kind, version))
    directory = os.path.normpath(str(spec.get('dir') or os.path.join(site['home'], 'apps', app_id)))
    if not directory.startswith(site['home'].rstrip('/') + '/') or directory.startswith(
            os.path.join(site['home'], 'logs')) or not re.match(r'^[A-Za-z0-9._/-]+$', directory):
        raise AppError('The app directory must be inside %s.' % site['home'])
    record = {'id': app_id, 'domain': site['domain'], 'user': site['user'], 'home': site['home'], 'dir': directory,
              'kind': kind, 'runtime': version}
    if kind == 'node':
        entry = str(spec.get('entry') or 'server.js')
        if entry != 'npm-start' and not REL_PATH_RE.match(entry):
            raise AppError('Entry file must be a relative path such as server.js, or "npm-start".')
        record['entry'] = entry
    elif kind == 'python':
        mode = spec.get('mode') or 'wsgi'
        if mode not in PY_MODES:
            raise AppError('Python apps run as WSGI, ASGI or a plain script.')
        target = str(spec.get('entry') or ('app:app' if mode != 'script' else 'main.py'))
        if mode == 'script' and not REL_PATH_RE.match(target):
            raise AppError('Script must be a relative path such as main.py.')
        if mode != 'script' and not MODULE_RE.match(target):
            raise AppError('Use module:callable, e.g. app:app or myproject.wsgi:application.')
        try:
            workers = int(spec.get('workers', 2))
        except (TypeError, ValueError):
            raise AppError('Workers must be a number.')
        if not 1 <= workers <= 8:
            raise AppError('Workers must be between 1 and 8.')
        record.update(mode=mode, entry=target, workers=workers)
    elif kind == 'java':
        mode = spec.get('mode') or 'jar'
        if mode not in JAVA_MODES:
            raise AppError('Java apps run as an executable JAR or a WAR.')
        entry = str(spec.get('entry') or 'app.' + mode)
        if not REL_PATH_RE.match(entry) or not entry.endswith('.' + mode):
            raise AppError('Name the .%s to run as a relative path, e.g. app.%s.' % (mode, mode))
        options = spec.get('jvm_opts', current.get('jvm_opts', []) if current else [])
        record.update(mode=mode, entry=entry, jvm_opts=validate_jvm_opts(options))
    else:
        entry = str(spec.get('entry') or '')
        if not REL_PATH_RE.match(entry) or not entry.endswith('.dll'):
            raise AppError('Name the published .dll to run, e.g. MyApp.dll.')
        record['entry'] = entry
    prefix = str(spec.get('prefix') or '/')
    if not prefix.endswith('/'):
        prefix += '/'
    if not PREFIX_RE.match(prefix) or prefix.startswith('/.well-known/'):
        raise AppError('URL path must look like / or /api/.')
    for other in existing_apps.values():
        if other['id'] != app_id and other['domain'] == site['domain'] and other['prefix'] == prefix:
            raise AppError('%s already serves %s on this site.' % (other['id'], prefix))
    record['prefix'] = prefix
    websocket = str(spec.get('websocket') or '')
    if websocket and not PREFIX_RE.match(websocket if websocket.endswith('/') else websocket + '/'):
        raise AppError('WebSocket path must look like /ws/.')
    record['websocket'] = websocket.rstrip('/') if websocket else ''
    try:
        memory = int(spec.get('memory_mb', policy['default_memory_mb']))
        cpu = int(spec.get('cpu_percent', 100))
    except (TypeError, ValueError):
        raise AppError('Memory and CPU limits must be numbers.')
    if not 64 <= memory <= policy['max_memory_mb']:
        raise AppError('Memory limit must be between 64 and %d MB.' % policy['max_memory_mb'])
    if not 5 <= cpu <= policy['max_cpu_percent']:
        raise AppError('CPU limit must be between 5 and %d%%.' % policy['max_cpu_percent'])
    record.update(memory_mb=memory, cpu_percent=cpu)
    record['env'] = validate_env(spec.get('env', current.get('env', {}) if current else {}))
    record['port'] = current['port'] if current else None
    return record


def validate_env(env):
    if not isinstance(env, dict) or len(env) > 100:
        raise AppError('Environment must be up to 100 KEY=value pairs.')
    clean = {}
    for key, value in env.items():
        if not ENV_KEY_RE.match(str(key)) or key in RESERVED_ENV:
            raise AppError('Environment variable name %r is not allowed.' % key)
        value = str(value)
        if len(value) > 4096 or any(c in value for c in '\x00\r\n'):
            raise AppError('Environment value for %s must be one line, up to 4096 characters.' % key)
        clean[key] = value
    return clean


def validate_jvm_opts(options):
    """Extra JVM options: a whitespace-separated string or a list of single tokens."""
    if options is None:
        return []
    if isinstance(options, str):
        options = options.split()
    if not isinstance(options, (list, tuple)):
        raise AppError('JVM options must be a list.')
    options = [str(o) for o in options]
    if len(options) > MAX_JVM_OPTS:
        raise AppError('Up to %d JVM options are allowed.' % MAX_JVM_OPTS)
    for option in options:
        if not any(r.match(option) for r in JVM_OPT_RES) or JVM_DENY_RE.match(option):
            raise AppError('JVM option %r is not allowed. Use -X..., -XX:... or -Dkey=value without spaces '
                           '(no agents or command hooks).' % option[:80])
    return options


def allocate_port(apps, is_free=None):
    used = {a.get('port') for a in apps.values()}
    is_free = is_free or port_is_free
    for port in range(PORT_RANGE[0], PORT_RANGE[1] + 1):
        if port not in used and is_free(port):
            return port
    raise AppError('No free application ports left.')


def port_is_free(port):
    probe = socket.socket()
    try:
        probe.bind(('127.0.0.1', port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


# ----------------------------------------------------------------------------- command line / unit

def base_path(app):
    """URL prefix the app is served under, without the trailing slash ('' at the site root)."""
    return app.get('prefix', '/').rstrip('/')


def exec_argv(app, runtime):
    """ExecStart argv for an app (validated tokens only)."""
    directory = app['dir']
    if app['kind'] == 'node':
        if app['entry'] == 'npm-start':
            return [runtime['npm'], 'start', '--silent']
        return [runtime['path'], os.path.join(directory, app['entry'])]
    if app['kind'] == 'python':
        venv = os.path.join(directory, '.venv', 'bin')
        if app['mode'] == 'wsgi':
            return [os.path.join(venv, 'gunicorn'), '--bind', '127.0.0.1:%d' % app['port'], '--workers',
                    str(app['workers']), '--access-logfile', '-', app['entry']]
        if app['mode'] == 'asgi':
            argv = [os.path.join(venv, 'uvicorn'), '--host', '127.0.0.1', '--port', str(app['port']), '--workers',
                    str(app['workers']), '--proxy-headers']
            if base_path(app):
                argv += ['--root-path', base_path(app)]
            return argv + [app['entry']]
        return [os.path.join(venv, 'python'), os.path.join(directory, app['entry'])]
    if app['kind'] == 'java':
        return java_argv(app, runtime)
    return [runtime['path'], os.path.join(directory, app['entry'])]


def java_argv(app, runtime):
    from universalAddons.apps import runtimes as rt
    options = list(app.get('jvm_opts') or [])
    argv = [runtime['path']]
    if not any(o.startswith('-Xmx') for o in options):
        argv.append('-Xmx%dm' % (app['memory_mb'] * 3 // 4))
    if not any(re.match(r'^-XX:\+Use\w*GC$', o) for o in options):
        argv.append('-XX:+UseSerialGC')
    argv += ['-Djava.io.tmpdir=/tmp'] + options
    target = os.path.join(app['dir'], app['entry'])
    if app.get('mode') == 'war':
        argv += ['-jar', rt.webapp_runner_path(), '--port', str(app['port']), '-Aaddress=127.0.0.1',
                 '--temp-directory', '/tmp/webapp-runner']
        if base_path(app):
            argv += ['--path', base_path(app)]
        return argv + [target]
    return argv + ['-jar', target]


def systemd_version(runner=subprocess.run):
    code, out = run(['systemctl', '--version'], runner, timeout=30)
    match = re.search(r'systemd (\d+)', out)
    return int(match.group(1)) if match else 239


def cgroup_v2():
    return os.path.exists('/sys/fs/cgroup/cgroup.controllers')


def unit_name(app_id):
    return 'cp-app-%s.service' % app_id


def render_unit(app, runtime, version=239, unified=False):
    argv = exec_argv(app, runtime)
    # '+' is needed by -XX:+Flag; the absolute first token keeps systemd's '+', '!', '-', '@' prefixes out.
    if not argv[0].startswith('/'):
        raise AppError('Unsafe command-line token %r.' % argv[0])
    for token in argv:
        if not re.match(r'^[A-Za-z0-9._:/=+-]+$', token):
            raise AppError('Unsafe command-line token %r.' % token)
    # OpenLiteSpeed forwards the full path, prefix included; APP_BASE_PATH tells the app its prefix
    # (ASP.NET Core: app.UsePathBase(...); Express: mount routes under it). gunicorn and uvicorn
    # apply it themselves through SCRIPT_NAME / --root-path.
    environment = {'PORT': str(app['port']), 'HOST': '127.0.0.1', 'NODE_ENV': 'production',
                   'APP_BASE_PATH': base_path(app)}
    if app['kind'] == 'node':
        # Only the app directory is writable: npm's cache/logs go to the service's private /tmp.
        environment.update(PATH=os.path.dirname(runtime['path']) + ':/usr/bin:/bin', npm_config_cache='/tmp/.npm',
                           npm_config_update_notifier='false')
    if app['kind'] == 'dotnet':
        environment.update(ASPNETCORE_URLS='http://127.0.0.1:%d' % app['port'],
                           DOTNET_ROOT=os.path.dirname(runtime['path']),
                           ASPNETCORE_FORWARDEDHEADERS_ENABLED='true',
                           DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1', DOTNET_GCHeapHardLimit=hex(app['memory_mb'] * 1024 * 1024 * 8 // 10))
    if app['kind'] == 'python':
        environment['PYTHONUNBUFFERED'] = '1'
        if app.get('mode') == 'wsgi' and base_path(app):
            environment['SCRIPT_NAME'] = base_path(app)
    if app['kind'] == 'java' and app.get('mode', 'jar') == 'jar':
        # Spring Boot binds server.port/server.address from these; X-Forwarded-* from OpenLiteSpeed (127.0.0.1).
        environment.update(SERVER_PORT=str(app['port']), SERVER_ADDRESS='127.0.0.1',
                           SERVER_FORWARD_HEADERS_STRATEGY='native')
        if base_path(app):
            environment['SERVER_SERVLET_CONTEXT_PATH'] = base_path(app)
    lines = [
        '# Managed by CyberPanel Universal (Apps). Changes are overwritten.',
        '[Unit]',
        'Description=CyberPanel app %s (%s)' % (app['id'], app['domain']),
        'After=network.target',
        '',
        '[Service]',
        'Type=simple',
        'User=%s' % app['user'],
        'Group=%s' % app['user'],
        'WorkingDirectory=%s' % app['dir'],
        'ExecStart=%s' % ' '.join(argv),
    ]
    lines += ['Environment="%s=%s"' % (key, value) for key, value in sorted(environment.items())]
    lines += [
        'EnvironmentFile=-%s' % os.path.join(APPS_DIR, 'env', app['id'] + '.env'),
        'Restart=on-failure',
        'RestartSec=3',
        'TimeoutStopSec=20',
        'UMask=0027',
        # --- sandbox
        'NoNewPrivileges=yes',
        'CapabilityBoundingSet=',
        'AmbientCapabilities=',
        'PrivateTmp=yes',
        'PrivateDevices=yes',
        'ProtectSystem=strict',
        'ReadWritePaths=%s' % app['dir'],
        'ProtectKernelTunables=yes',
        'ProtectKernelModules=yes',
        'ProtectControlGroups=yes',
        'RestrictRealtime=yes',
        'RestrictNamespaces=yes',
        'LockPersonality=yes',
        'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
        'SystemCallArchitectures=native',
        'SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @raw-io @reboot @swap',
        'SystemCallErrorNumber=EPERM',
        'InaccessiblePaths=-/etc/cyberpanel -/usr/local/CyberCP -/usr/local/lscp -/root -/var/lib/mysql '
        '-/etc/letsencrypt -/etc/opendkim -/etc/pdns -/home/vmail -/etc/shadow -/etc/gshadow',
    ]
    if version >= 242:
        lines += ['RestrictSUIDSGID=yes', 'ProtectHostname=yes']
    if version >= 244:
        lines.append('ProtectKernelLogs=yes')
    # --- resource limits
    if unified:
        lines.append('MemoryMax=%dM' % app['memory_mb'])
    else:
        lines.append('MemoryLimit=%dM' % app['memory_mb'])
    # A JVM runs ~20 internal threads besides Tomcat's 200 request threads.
    if app['kind'] == 'java':
        lines.append('SuccessExitStatus=143')  # the JVM exits 128+SIGTERM on a normal stop
    lines += ['CPUQuota=%d%%' % app['cpu_percent'], 'TasksMax=%d' % (512 if app['kind'] == 'java' else 256),
              'LimitNOFILE=8192', '',
              '[Install]', 'WantedBy=multi-user.target', '']
    return '\n'.join(lines)


def render_env_file(env):
    def quote(value):
        return '"%s"' % value.replace('\\', '\\\\').replace('"', '\\"')
    return ''.join('%s=%s\n' % (key, quote(value)) for key, value in sorted(env.items()))


# ----------------------------------------------------------------------------- OpenLiteSpeed proxy

def render_vhost_block(apps_for_domain):
    parts = [MARK_BEGIN]
    for app in sorted(apps_for_domain, key=lambda a: (-len(a['prefix']), a['id'])):
        if not app.get('enabled', True) or not app.get('port'):
            continue
        handler = 'cpapp_%s' % app['id'].replace('-', '_')
        parts.append('extprocessor %s {\n  type                    proxy\n  address                 127.0.0.1:%d\n'
                     '  maxConns                100\n  pcKeepAliveTimeout      60\n  initTimeout             60\n'
                     '  retryTimeout            0\n  respBuffer              0\n}' % (handler, app['port']))
        parts.append('context %s {\n  type                    proxy\n  handler                 %s\n'
                     '  addDefaultCharset       off\n}' % (app['prefix'], handler))
        if app.get('websocket'):
            parts.append('websocket %s {\n  address                 127.0.0.1:%d\n}' % (app['websocket'], app['port']))
    parts.append(MARK_END)
    return '\n\n'.join(parts) + '\n'


def apply_to_vhost(vhost_text, apps_for_domain):
    from universalAddons.htaccess.translator import strip_managed
    base = strip_managed(vhost_text, MARK_BEGIN, MARK_END).rstrip('\n') + '\n'
    active = [a for a in apps_for_domain if a.get('enabled', True) and a.get('port')]
    if not active:
        return re.sub(r'\n{3,}', '\n\n', base)
    block = render_vhost_block(active)
    match = re.search(r'^vhssl\s*\{', base, re.M)
    text = base[:match.start()] + block + '\n' + base[match.start():] if match else base + '\n' + block
    return re.sub(r'\n{3,}', '\n\n', text)


def vhost_conflicts(vhost_text, apps_for_domain):
    from universalAddons.htaccess.translator import strip_managed
    text = strip_managed(vhost_text, MARK_BEGIN, MARK_END)
    return ['context %s' % a['prefix'] for a in apps_for_domain
            if re.search(r'^context\s+%s\s*\{' % re.escape(a['prefix']), text, re.M)]


# ----------------------------------------------------------------------------- dependencies

def as_user(app, argv, extra_env=None):
    env = ['env', '-i', 'HOME=%s' % app['home'], 'USER=%s' % app['user'], 'LANG=C.UTF-8',
           'PATH=/usr/bin:/bin'] + ['%s=%s' % kv for kv in sorted((extra_env or {}).items())]
    return ['sudo', '-u', app['user'], '--'] + env + argv


def install_dependencies(app, runtime, runner=subprocess.run, log=None):
    """Prepare the app directory as the site user (venv + pip, npm ci, or .dll/.jar/.war check)."""
    say = log or (lambda text: None)
    directory = app['dir']
    if app['kind'] == 'python':
        venv = os.path.join(directory, '.venv')
        if not os.path.exists(os.path.join(venv, 'bin', 'python')):
            code, out = run(as_user(app, [runtime['path'], '-m', 'venv', venv]), runner)
            say(out[-2000:])
            if code != 0:
                raise AppError('Could not create the virtualenv.')
        pip = [os.path.join(venv, 'bin', 'python'), '-m', 'pip', 'install', '--no-cache-dir', '--disable-pip-version-check']
        packages = {'wsgi': ['gunicorn'], 'asgi': ['uvicorn']}.get(app['mode'], [])
        if os.path.exists(os.path.join(directory, 'requirements.txt')):
            code, out = run(as_user(app, pip + ['-r', os.path.join(directory, 'requirements.txt')]), runner, timeout=1800)
            say(out[-4000:])
            if code != 0:
                raise AppError('pip install -r requirements.txt failed; see the log.')
        if packages:
            code, out = run(as_user(app, pip + packages), runner, timeout=900)
            say(out[-2000:])
            if code != 0:
                raise AppError('Could not install %s.' % ', '.join(packages))
    elif app['kind'] == 'java':
        # Nothing to install: the JAR/WAR is self-contained. It must be readable by the site user.
        entry = os.path.join(directory, app['entry'])
        if not os.path.isfile(entry):
            raise AppError('%s was not found. Upload the app files first.' % app['entry'])
        code, out = run(['sudo', '-u', app['user'], '--', 'test', '-r', entry], runner, timeout=30)
        if code != 0:
            raise AppError('%s is not readable by %s; fix its owner or permissions.' % (app['entry'], app['user']))
        say('%s is present (%d KB).' % (app['entry'], os.path.getsize(entry) // 1024))
        return True
    elif app['kind'] == 'node':
        if os.path.exists(os.path.join(directory, 'package.json')):
            cache = os.path.join(directory, '.npm-cache')
            command = 'ci' if os.path.exists(os.path.join(directory, 'package-lock.json')) else 'install'
            env = {'PATH': os.path.dirname(runtime['path']) + ':/usr/bin:/bin', 'npm_config_cache': cache,
                   'npm_config_update_notifier': 'false', 'npm_config_fund': 'false', 'npm_config_audit': 'false'}
            code, out = run(as_user(app, [runtime['npm'], command, '--omit=dev', '--prefix', directory], env),
                            runner, timeout=1800)
            say(out[-4000:])
            shutil.rmtree(cache, ignore_errors=True)  # keep the footprint small
            if code != 0:
                raise AppError('npm %s failed; see the log.' % command)
        elif app['entry'] == 'npm-start':
            raise AppError('"npm start" needs a package.json in the app directory.')
    if app['kind'] != 'python' or app['mode'] == 'script':
        entry = os.path.join(directory, app['entry']) if app['entry'] != 'npm-start' else None
        if entry and not os.path.isfile(entry):
            raise AppError('%s was not found. Upload the app files first.' % app['entry'])
    return True


def wait_listening(port, seconds=30, sleep=None):
    import time
    sleep = sleep or time.sleep
    for _ in range(seconds * 2):
        probe = socket.socket()
        probe.settimeout(0.5)
        try:
            probe.connect(('127.0.0.1', port))
            return True
        except OSError:
            sleep(0.5)
        finally:
            probe.close()
    return False


def status(app, runner=subprocess.run):
    code, out = run(['systemctl', 'show', unit_name(app['id']), '--property=ActiveState,SubState,MainPID,'
                     'MemoryCurrent,NRestarts,ExecMainStartTimestamp'], runner, timeout=30)
    values = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
    memory = values.get('MemoryCurrent', '')
    return {'state': values.get('ActiveState', 'unknown'), 'sub': values.get('SubState', ''),
            'pid': values.get('MainPID', '0'), 'restarts': values.get('NRestarts', '0'),
            'since': values.get('ExecMainStartTimestamp', ''),
            'memory_mb': round(int(memory) / 1048576, 1) if memory.isdigit() else None}


def logs(app, lines=200, runner=subprocess.run):
    lines = max(10, min(int(lines), 2000))
    code, out = run(['journalctl', '-u', unit_name(app['id']), '-n', str(lines), '--no-pager', '-o', 'short-iso'],
                    runner, timeout=60)
    return out.splitlines()[-lines:]

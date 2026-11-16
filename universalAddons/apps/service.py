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
- Kotlin (JVM): Ktor, Spring Boot (Kotlin) and http4k apps are JARs, so they are Java apps with
  flavor "kotlin" and the same runner. Optional Gradle build on deploy (`./gradlew shadowJar` or
  `bootJar`, as the site user, --no-daemon, Kotlin compiler in-process so nothing lingers) with
  JAVA_HOME at the selected Java, which must be a JDK (install "Temurin JDK"). The wrapper
  downloads Gradle itself (into ~/.gradle); set distributionSha256Sum in gradle-wrapper.properties
  to have it verified. Ktor's EngineMain takes `-host=` / `-port=` arguments, which the panel adds
  when "Ktor arguments" is on (it binds 0.0.0.0 otherwise). Ktor embeddedServer(...) and http4k
  apps read the port themselves: System.getenv("PORT"), host "127.0.0.1" (HOST).

Ruby
- `rack`: config.ru on puma; `rails`: the same plus Rails conventions. Deploy (as the site user):
  `bundle config set --local deployment true`, path vendor/bundle, without development:test,
  `bundle install`, then for Rails `rails assets:precompile` (when app/assets or app/javascript
  exists) and `rails db:migrate` (both can be switched off). Gemfile.lock and puma are required.
- puma gets `--bind tcp://127.0.0.1:$PORT` on the command line, which takes precedence over
  `port`/`bind` in config/puma.rb (Rails' default would listen on 0.0.0.0).
- RAILS_ENV/RACK_ENV=production, RAILS_LOG_TO_STDOUT, RAILS_SERVE_STATIC_FILES (OpenLiteSpeed
  forwards everything to puma), RAILS_RELATIVE_URL_ROOT=APP_BASE_PATH under a sub-path. Rails does
  not strip the prefix by itself: config.ru needs `map ENV.fetch("RAILS_RELATIVE_URL_ROOT", "/") do
  run Rails.application end` (Rack apps: map ENV["APP_BASE_PATH"]). Behind the proxy, set
  config.assume_ssl = true when force_ssl is on.
- SECRET_KEY_BASE is generated once (128 hex characters) and kept in the app's root-only env file;
  it is never returned by list or save. Deploy commands get the app environment through sudo's
  environment (--preserve-env with names only), never on a command line other users could read.

Go, Deno, Bun
- Go: runs a compiled binary from the app directory (no runtime needed). Optional `go build` on
  deploy with a panel-installed toolchain, GOTOOLCHAIN=local (go.mod cannot fetch another
  toolchain), CGO_ENABLED=0. GOMAXPROCS/GOMEMLIMIT follow the CPU and memory limits.
- Deno: `deno run` (Deno.serve on PORT) or `deno serve --host 127.0.0.1 --port $PORT`, with
  permissions limited to network, environment and the app directory unless "all" is chosen;
  DENO_DIR is inside the app directory (the only writable path).
- Bun: `bun <entry>` or `bun run start`; dependencies with `bun install --production`.
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
KINDS = ('node', 'python', 'dotnet', 'java', 'ruby', 'go', 'deno', 'bun')
PY_MODES = ('wsgi', 'asgi', 'script')
JAVA_MODES = ('jar', 'war')
JAVA_FLAVORS = ('java', 'kotlin')
GRADLE_TASKS = ('', 'shadowJar', 'bootJar')
RUBY_MODES = ('rack', 'rails')
DENO_MODES = ('run', 'serve')
DENO_PERMS = ('scoped', 'all')
MAX_JVM_OPTS = 10
GO_PACKAGE_RE = re.compile(r'^\.(/[A-Za-z0-9._-]+)*(/\.\.\.)?$')  # ., ./cmd/server

APP_ID_RE = re.compile(r'^[a-z][a-z0-9-]{1,30}$')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
REL_PATH_RE = re.compile(r'^(?!.*\.\.)[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$')
MODULE_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.]{0,100}:[A-Za-z_][A-Za-z0-9_]{0,60}$')
PREFIX_RE = re.compile(r'^/([A-Za-z0-9._-]+/)*$')
ENV_KEY_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,127}$')  # .NET uses Section__Key names
VERSION_RE = re.compile(r'^\d{1,3}(\.\d{1,4}){1,3}$')
RESERVED_ENV = {'PORT', 'HOST', 'APP_BASE_PATH', 'SCRIPT_NAME', 'ASPNETCORE_URLS', 'PATH', 'HOME', 'USER', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
                'PYTHONPATH', 'NODE_OPTIONS', 'DOTNET_ROOT', 'SERVER_PORT', 'SERVER_ADDRESS',
                'SERVER_SERVLET_CONTEXT_PATH', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS',
                'RAILS_RELATIVE_URL_ROOT', 'BUNDLE_GEMFILE', 'BUNDLE_PATH', 'BUNDLE_DEPLOYMENT', 'BUNDLE_WITHOUT',
                'DENO_DIR', 'GOTOOLCHAIN'}
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


def run(argv, runner=subprocess.run, timeout=600, env=None, cwd=None):
    extra = {'cwd': cwd} if cwd else {}
    try:
        out = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                     timeout=timeout, env=env, **extra)
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
        raise AppError('Choose Node.js, Python, .NET, Java/Kotlin, Ruby, Go, Deno or Bun.')
    version = str(spec.get('runtime') or '')
    go_build = kind == 'go' and bool(spec.get('build', current.get('build') if current else False))
    if kind == 'go' and not go_build and not version:
        pass  # a compiled binary needs no toolchain
    elif not any(r['version'] == version for r in runtimes_installed.get(kind, [])):
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
        record.update(mode=mode, entry=target, workers=_workers(spec))
    elif kind == 'java':
        mode = spec.get('mode') or 'jar'
        if mode not in JAVA_MODES:
            raise AppError('Java apps run as an executable JAR or a WAR.')
        entry = str(spec.get('entry') or 'app.' + mode)
        if not REL_PATH_RE.match(entry) or not entry.endswith('.' + mode):
            raise AppError('Name the .%s to run as a relative path, e.g. app.%s.' % (mode, mode))
        options = spec.get('jvm_opts', current.get('jvm_opts', []) if current else [])
        record.update(mode=mode, entry=entry, jvm_opts=validate_jvm_opts(options))
        keep = (lambda key, default: spec.get(key, current.get(key, default) if current else default))
        flavor = keep('flavor', 'java') or 'java'
        build = keep('build', '') or ''
        if flavor not in JAVA_FLAVORS:
            raise AppError('Java apps are Java or Kotlin (JVM).')
        if build not in GRADLE_TASKS:
            raise AppError('The Gradle build task is shadowJar or bootJar (or none).')
        if build and mode != 'jar':
            raise AppError('Gradle builds produce a JAR; choose the JAR mode.')
        record.update(flavor=flavor, build=build, ktor_args=keep('ktor_args', False) is True and mode == 'jar')
    elif kind == 'ruby':
        mode = spec.get('mode') or 'rails'
        if mode not in RUBY_MODES:
            raise AppError('Ruby apps are Rack (config.ru) or Rails.')
        entry = str(spec.get('entry') or 'config.ru')
        if not REL_PATH_RE.match(entry) or not entry.endswith('.ru'):
            raise AppError('Name the rackup file as a relative path, e.g. config.ru.')
        record.update(mode=mode, entry=entry, workers=_workers(spec, 1))  # 1: puma single mode, least memory
        if mode == 'rails':
            keep = (lambda key: spec.get(key, current.get(key, True) if current else True) is not False)
            record.update(precompile=keep('precompile'), migrate=keep('migrate'))
    elif kind == 'go':
        entry = str(spec.get('entry') or 'app')
        if not REL_PATH_RE.match(entry):
            raise AppError('Name the compiled binary as a relative path, e.g. app or bin/server.')
        package = str(spec.get('package') or (current.get('package') if current else '') or '.')
        if not GO_PACKAGE_RE.match(package) or '..' in package.replace('/...', ''):
            raise AppError('The Go package to build must be . or a path such as ./cmd/server.')
        record.update(entry=entry, build=go_build, package=package)
    elif kind == 'deno':
        mode = spec.get('mode') or 'run'
        perms = spec.get('deno_perms') or (current.get('deno_perms') if current else '') or 'scoped'
        if mode not in DENO_MODES or perms not in DENO_PERMS:
            raise AppError('Deno apps use deno run or deno serve, with scoped or all permissions.')
        entry = str(spec.get('entry') or 'main.ts')
        if not REL_PATH_RE.match(entry):
            raise AppError('Entry file must be a relative path such as main.ts.')
        record.update(mode=mode, entry=entry, deno_perms=perms)
    elif kind == 'bun':
        entry = str(spec.get('entry') or 'index.ts')
        if entry != 'bun-start' and not REL_PATH_RE.match(entry):
            raise AppError('Entry file must be a relative path such as index.ts, or "bun-start".')
        record['entry'] = entry
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
    if kind == 'ruby' and record['mode'] == 'rails' and not record['env'].get('SECRET_KEY_BASE'):
        # Generated once; a new env list without it keeps the stored key (it is never sent to the browser).
        record['env']['SECRET_KEY_BASE'] = ((current or {}).get('env') or {}).get('SECRET_KEY_BASE') or new_secret_key_base()
    record['port'] = current['port'] if current else None
    return record


def new_secret_key_base():
    import secrets
    return secrets.token_hex(64)  # what `rails secret` produces: 128 hex characters


def _workers(spec, default=2):
    try:
        workers = int(spec.get('workers', default))
    except (TypeError, ValueError):
        raise AppError('Workers must be a number.')
    if not 1 <= workers <= 8:
        raise AppError('Workers must be between 1 and 8.')
    return workers


def validate_env(env):
    if not isinstance(env, dict) or len(env) > 100:
        raise AppError('Environment must be up to 100 KEY=value pairs.')
    clean = {}
    for key, value in env.items():
        if not ENV_KEY_RE.match(str(key)) or str(key).upper() in RESERVED_ENV:
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
    if app['kind'] == 'ruby':
        # The CLI bind wins over port/bind in config/puma.rb, so the app stays on loopback.
        argv = [ruby_tool(runtime, 'bundle'), 'exec', 'puma', '--bind', 'tcp://127.0.0.1:%d' % app['port']]
        if app.get('workers', 1) > 1:
            argv += ['--workers', str(app['workers'])]
        return argv + [os.path.join(directory, app['entry'])]
    if app['kind'] == 'go':
        return [os.path.join(directory, app['entry'])]
    if app['kind'] == 'deno':
        if app.get('deno_perms') == 'all':
            perms = ['--allow-all']
        else:
            perms = ['--allow-net', '--allow-env', '--allow-read=%s' % directory, '--allow-write=%s' % directory]
        if app.get('mode') == 'serve':
            return [runtime['path'], 'serve', '--host', '127.0.0.1', '--port', str(app['port'])] + perms + \
                [os.path.join(directory, app['entry'])]
        return [runtime['path'], 'run', '--no-prompt'] + perms + [os.path.join(directory, app['entry'])]
    if app['kind'] == 'bun':
        if app['entry'] == 'bun-start':
            return [runtime['path'], 'run', 'start']
        return [runtime['path'], os.path.join(directory, app['entry'])]
    return [runtime['path'], os.path.join(directory, app['entry'])]


def ruby_tool(runtime, name):
    """bundle/gem/rake next to the selected ruby."""
    return os.path.join(os.path.dirname(runtime['path']), name)


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
    argv += ['-jar', target]
    if app.get('ktor_args'):
        argv += ['-host=127.0.0.1', '-port=%d' % app['port']]  # Ktor EngineMain (commandLineEnvironment)
    return argv


def systemd_version(runner=subprocess.run):
    code, out = run(['systemctl', '--version'], runner, timeout=30)
    match = re.search(r'systemd (\d+)', out)
    return int(match.group(1)) if match else 239


def cgroup_v2():
    return os.path.exists('/sys/fs/cgroup/cgroup.controllers')


def unit_name(app_id):
    return 'cp-app-%s.service' % app_id


def runtime_environment(app, runtime):
    """Unit environment for the Ruby, Go, Deno and Bun app kinds (the others are set in render_unit)."""
    directory, kind = app['dir'], app['kind']
    if kind == 'ruby':
        environment = {'PATH': os.path.dirname(runtime['path']) + ':/usr/bin:/bin', 'RAILS_ENV': 'production',
                       'RACK_ENV': 'production', 'RAILS_LOG_TO_STDOUT': '1', 'RAILS_SERVE_STATIC_FILES': '1',
                       'BUNDLE_GEMFILE': os.path.join(directory, 'Gemfile'), 'BUNDLE_DEPLOYMENT': '1',
                       'BUNDLE_PATH': os.path.join(directory, 'vendor', 'bundle'), 'BUNDLE_WITHOUT': 'development:test',
                       'MALLOC_ARENA_MAX': '2'}  # glibc arenas otherwise inflate threaded Ruby's memory
        if base_path(app):
            environment['RAILS_RELATIVE_URL_ROOT'] = base_path(app)
        return environment
    if kind == 'go':
        return {'PATH': '/usr/bin:/bin', 'GOMAXPROCS': str(max(1, -(-app['cpu_percent'] // 100))),
                'GOMEMLIMIT': '%dMiB' % (app['memory_mb'] * 9 // 10)}
    if kind == 'deno':
        return {'PATH': os.path.dirname(runtime['path']) + ':/usr/bin:/bin', 'DENO_DIR': os.path.join(directory, '.deno'),
                'DENO_NO_UPDATE_CHECK': '1', 'DENO_NO_PROMPT': '1', 'NO_COLOR': '1'}
    if kind == 'bun':
        return {'PATH': os.path.dirname(runtime['path']) + ':/usr/bin:/bin', 'BUN_RUNTIME_TRANSPILER_CACHE_PATH': '0',
                'BUN_INSTALL_CACHE_DIR': '/tmp/.bun-cache', 'DO_NOT_TRACK': '1'}
    return {}


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
    environment.update(runtime_environment(app, runtime))
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


def as_user_env(app, argv, env):
    """(argv, environment) running argv as the site user with `env` passed through the process environment.

    Only variable names reach sudo's command line (--preserve-env); values such as SECRET_KEY_BASE or
    DATABASE_URL stay out of /proc/<pid>/cmdline, which every local user can read. PATH is set after
    sudo because sudoers' secure_path would replace it.
    """
    path = env.get('PATH', '/usr/bin:/bin')
    full = {'HOME': app['home'], 'USER': app['user'], 'LOGNAME': app['user'], 'LANG': 'C.UTF-8'}
    full.update((key, value) for key, value in env.items() if key != 'PATH')
    argv = ['sudo', '-u', app['user'], '--preserve-env=%s' % ','.join(sorted(full)), '--', 'env', 'PATH=' + path] + argv
    return argv, full


def _require_files(app, names):
    for name, hint in names:
        if not os.path.isfile(os.path.join(app['dir'], name)):
            raise AppError('%s was not found in %s. %s' % (name, app['dir'], hint))


def ruby_deploy(app, runtime, runner=subprocess.run, log=None):
    """bundle install in deployment mode into vendor/bundle; Rails: assets:precompile and db:migrate."""
    say = log or (lambda text: None)
    directory = app['dir']
    _require_files(app, (('Gemfile', 'Upload the app files first.'),
                         ('Gemfile.lock', 'Deployment mode installs exactly the locked gems: run "bundle lock" and '
                                          'upload Gemfile.lock.'),
                         (app['entry'], 'puma serves the rackup file (config.ru).')))
    with open(os.path.join(directory, 'Gemfile.lock'), errors='replace') as handle:
        if not re.search(r'^    puma \(', handle.read(), re.M):
            raise AppError('puma is not in Gemfile.lock: run "bundle add puma" and upload Gemfile and Gemfile.lock.')
    env = dict(runtime_environment(app, runtime))
    env.update(app.get('env', {}))  # DATABASE_URL, SECRET_KEY_BASE, ... for precompile and migrations
    bundle = ruby_tool(runtime, 'bundle')

    def step(title, argv, timeout=1800):
        say('--> ' + title)
        command, environment = as_user_env(app, argv, env)
        code, out = run(command, runner, timeout=timeout, env=environment, cwd=directory)
        say(out[-4000:])
        if code != 0:
            raise AppError('%s failed; see the log.' % title)
    step('bundle config set --local deployment true', [bundle, 'config', 'set', '--local', 'deployment', 'true'], 120)
    step('bundle config set --local path vendor/bundle', [bundle, 'config', 'set', '--local', 'path', 'vendor/bundle'], 120)
    step('bundle config set --local without development test',
         [bundle, 'config', 'set', '--local', 'without', 'development test'], 120)
    step('bundle install', [bundle, 'install', '--jobs', '2'])
    if app.get('mode') == 'rails':
        if not app.get('precompile', True):
            say('assets:precompile is switched off.')
        elif any(os.path.isdir(os.path.join(directory, 'app', name)) for name in ('assets', 'javascript')):
            step('rails assets:precompile', [bundle, 'exec', 'rails', 'assets:precompile'])
        else:
            say('No app/assets or app/javascript (API-only app): assets:precompile skipped.')
        if app.get('migrate', True):
            step('rails db:migrate', [bundle, 'exec', 'rails', 'db:migrate'], 900)
        else:
            say('db:migrate is switched off.')
    return True


def gradle_build(app, runtime, runner=subprocess.run, log=None):
    """./gradlew <shadowJar|bootJar> as the site user, JAVA_HOME at the app's (JDK) runtime."""
    from universalAddons.apps import runtimes as rt
    say = log or (lambda text: None)
    directory = app['dir']
    _require_files(app, (('gradlew', 'Gradle builds use the project wrapper: upload gradlew and gradle/wrapper/ '
                                      'with the sources.'),))
    home = rt.java_home(runtime)
    if not rt.has_javac(home):
        raise AppError('Gradle needs a JDK, and Java %s on this server is a JRE. Ask the administrator to install '
                       '"Java %s (Temurin JDK)" and select it.' % (app['runtime'], app['runtime'].split('.')[0]))
    env = {'JAVA_HOME': home, 'PATH': os.path.join(home, 'bin') + ':/usr/bin:/bin',
           'GRADLE_USER_HOME': os.path.join(app['home'], '.gradle')}
    # No daemons left behind on a small server: --no-daemon, and the Kotlin compiler in-process.
    argv = ['/bin/sh', os.path.join(directory, 'gradlew'), '--no-daemon', '--console=plain', '-p', directory,
            '-Pkotlin.compiler.execution.strategy=in-process', app['build']]
    say('--> ./gradlew %s (JAVA_HOME=%s)' % (app['build'], home))
    code, out = run(as_user(app, argv, env), runner, timeout=2700, cwd=directory)
    say(out[-4000:])
    if code != 0:
        raise AppError('./gradlew %s failed; see the log.' % app['build'])
    return True


def go_build(app, runtime, runner=subprocess.run, log=None):
    say = log or (lambda text: None)
    directory = app['dir']
    if not runtime:
        raise AppError('Choose a Go toolchain to build with.')
    _require_files(app, (('go.mod', 'go build needs the module sources.'),))
    env = {'PATH': os.path.dirname(runtime['path']) + ':/usr/bin:/bin', 'GOPATH': os.path.join(app['home'], 'go'),
           'GOCACHE': os.path.join(app['home'], '.cache', 'go-build'), 'GOTOOLCHAIN': 'local', 'CGO_ENABLED': '0',
           'GOFLAGS': '-buildvcs=false'}
    argv = [runtime['path'], 'build', '-trimpath', '-o', os.path.join(directory, app['entry']), app['package']]
    say('--> go build -o %s %s' % (app['entry'], app['package']))
    code, out = run(as_user(app, argv, env), runner, timeout=1800, cwd=directory)
    say(out[-4000:])
    if code != 0:
        raise AppError('go build failed; see the log.')
    run(as_user(app, [runtime['path'], 'clean', '-cache'], env), runner, timeout=300, cwd=directory)  # keep modules only
    return True


def install_dependencies(app, runtime, runner=subprocess.run, log=None):
    """Prepare the app directory as the site user (venv + pip, npm ci, bundle install, builds, entry checks)."""
    say = log or (lambda text: None)
    directory = app['dir']
    if app['kind'] == 'ruby':
        return ruby_deploy(app, runtime, runner, log)
    if app['kind'] == 'go':
        if app.get('build'):
            go_build(app, runtime, runner, log)
        entry = os.path.join(directory, app['entry'])
        if not os.path.isfile(entry):
            raise AppError('%s was not found. Upload the compiled binary (GOOS=linux) or turn on go build.' % app['entry'])
        code, out = run(['sudo', '-u', app['user'], '--', 'test', '-x', entry], runner, timeout=30)
        if code != 0:
            raise AppError('%s is not executable by %s (chmod 755 it).' % (app['entry'], app['user']))
        return True
    if app['kind'] in ('deno', 'bun'):
        tool = runtime['path']
        if app['kind'] == 'deno':
            _require_files(app, ((app['entry'], 'Upload the app files first.'),))
            env = {'PATH': os.path.dirname(tool) + ':/usr/bin:/bin', 'DENO_DIR': os.path.join(directory, '.deno'),
                   'DENO_NO_UPDATE_CHECK': '1', 'NO_COLOR': '1'}
            code, out = run(as_user(app, [tool, 'cache', os.path.join(directory, app['entry'])], env), runner,
                            timeout=1800, cwd=directory)
            say(out[-4000:])
            if code != 0:
                raise AppError('deno cache failed; see the log.')
            return True
        if os.path.exists(os.path.join(directory, 'package.json')):
            cache = os.path.join(directory, '.bun-cache')
            frozen = any(os.path.exists(os.path.join(directory, n)) for n in ('bun.lock', 'bun.lockb'))
            env = {'PATH': os.path.dirname(tool) + ':/usr/bin:/bin', 'BUN_INSTALL_CACHE_DIR': cache, 'DO_NOT_TRACK': '1'}
            code, out = run(as_user(app, [tool, 'install', '--production'] + (['--frozen-lockfile'] if frozen else []),
                                    env), runner, timeout=1800, cwd=directory)
            say(out[-4000:])
            shutil.rmtree(cache, ignore_errors=True)
            if code != 0:
                raise AppError('bun install failed; see the log.')
        elif app['entry'] == 'bun-start':
            raise AppError('"bun run start" needs a package.json in the app directory.')
        if app['entry'] != 'bun-start':
            _require_files(app, ((app['entry'], 'Upload the app files first.'),))
        return True
    if app['kind'] == 'java' and app.get('build'):
        gradle_build(app, runtime, runner, log)
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

"""Git deploy: connect a repository to a site, deploy on push (signed webhooks) or on demand.

Security model
- Git, builds and the optional .indianscloud/deploy.sh run as the site's own Linux user
  (siteinfo.run_as: uid/gid drop, clean environment, timeout), never as root in the site.
- Repository URLs: https://host/path, git@host:path or ssh://[user@]host[:port]/path only. No
  file://, ext::, local paths, credentials in the URL, or loopback hosts; git only speaks https
  and ssh (GIT_ALLOW_PROTOCOL) and never prompts.
- Private repositories: a per-site ed25519 deploy key made by the site user in ~/.ssh (0600);
  only the public half is ever returned. Or an HTTPS token, stored root-only (0600) and never
  returned; it reaches git through the environment (an http.extraHeader), never argv or .git/config.
- Webhooks: a random 128-bit id per site and a separate secret. GitHub (X-Hub-Signature-256),
  Gitea/Gogs (X-Gitea-Signature / X-Gogs-Signature) and Bitbucket (X-Hub-Signature) deliveries
  must carry an HMAC-SHA256 of the body; GitLab sends the secret itself (X-Gitlab-Token). All
  comparisons are constant-time. Only pushes to the configured branch deploy; deliveries are
  rate limited, and one deploy runs at a time per site (later pushes are queued, not lost).
"""
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time

from universalAddons import siteinfo
from universalAddons.siteinfo import SiteError

STATE_DIR = '/etc/cyberpanel/universal-gitdeploy'
DATA_DIR = '/var/lib/cyberpanel-universal/gitdeploy'
HOOK_ID_RE = re.compile(r'^[0-9a-f]{32}$')
BRANCH_RE = re.compile(r'^(?!-)(?!.*\.\.)(?!.*//)(?!.*@\{)(?!.*\.lock(/|$))[A-Za-z0-9._/-]{1,100}(?<![/.])$')
_HOST = r'(?P<host>[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?){1,10})'
_REPO_PATH = r'(?P<path>(?!-)(?!.*\.\.)[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+){0,9})'
HTTPS_RE = re.compile(r'^https://%s(:(?P<port>\d{1,5}))?/%s/?$' % (_HOST, _REPO_PATH))
SCP_RE = re.compile(r'^(?P<user>[A-Za-z0-9._-]{1,64})@%s:%s$' % (_HOST, _REPO_PATH))
SSH_RE = re.compile(r'^ssh://((?P<user>[A-Za-z0-9._-]{1,64})@)?%s(:(?P<port>\d{1,5}))?/%s$' % (_HOST, _REPO_PATH))
TOKEN_RE = re.compile(r'^[A-Za-z0-9_.:+/=~-]{8,512}$')
TOKEN_USER_RE = re.compile(r'^[A-Za-z0-9._@-]{1,100}$')
MODES = ('pull', 'releases')
AUTHS = ('public', 'key', 'token')
STEPS = ('composer_install', 'npm_build', 'artisan_migrate', 'artisan_optimize', 'restart_app')
STEP_TITLES = {'composer_install': 'composer install --no-dev', 'npm_build': 'npm ci && npm run build',
               'artisan_migrate': 'php artisan migrate --force', 'artisan_optimize': 'php artisan optimize',
               'restart_app': 'Restart the Universal Apps app'}
CUSTOM_SCRIPT = '.indianscloud/deploy.sh'
DEFAULT_FILES = {'index.html', '.htaccess', '.well-known', 'cgi-bin'}
SHARED_ITEMS = ('.env', 'storage')
MAX_HISTORY = 20
MAX_BODY = 2 * 1024 * 1024
RATE_WINDOW, RATE_MAX = 60, 5          # accepted webhook deploys per id per window
STEP_TIMEOUT, SCRIPT_TIMEOUT_MAX = 1800, 1800
RELEASE_RE = re.compile(r'^\d{8}-\d{6}-[0-9a-f]{4}$')
APP_ID_RE = re.compile(r'^[a-z][a-z0-9-]{1,30}$')


class DeployError(SiteError):
    pass


# ----------------------------------------------------------------------------- validation

def _loopback(host):
    host = host.lower()
    return host in ('localhost', 'localhost.localdomain') or host.endswith('.localhost') or \
        re.match(r'^(127|0|10|169\.254|192\.168)\.', host) is not None or \
        re.match(r'^172\.(1[6-9]|2\d|3[01])\.', host) is not None or re.match(r'^[\d.]+$', host) is not None


def check_repo(url):
    """(kind, url) with kind 'https' or 'ssh' for an acceptable repository URL; DeployError otherwise."""
    url = str(url or '').strip()
    if len(url) > 300 or any(c in url for c in ' \t\r\n\x00\\\'"`$;|&<>'):
        raise DeployError('Invalid repository URL.')
    for kind, pattern in (('https', HTTPS_RE), ('ssh', SCP_RE), ('ssh', SSH_RE)):
        match = pattern.match(url)
        if match:
            if _loopback(match.group('host')):
                raise DeployError('The repository must be on a public Git host, not this server or a private address.')
            port = match.groupdict().get('port')
            if port and not 1 <= int(port) <= 65535:
                raise DeployError('Invalid port.')
            return kind, url
    raise DeployError('Use https://host/owner/repo(.git), git@host:owner/repo.git or ssh://git@host/owner/repo.git. '
                      'Local paths, file:// and other transports are not accepted.')


def check_branch(branch):
    branch = str(branch or '').strip()
    if not BRANCH_RE.match(branch):
        raise DeployError('Invalid branch name.')
    return branch


def validate_config(spec, site, existing=None, app_ids=()):
    """The stored configuration for a connect/save request (no secrets in it)."""
    if not isinstance(spec, dict):
        raise DeployError('Invalid settings.')
    kind, url = check_repo(spec.get('url'))
    auth = spec.get('auth') or ('key' if kind == 'ssh' else 'public')
    if auth not in AUTHS:
        raise DeployError('Invalid authentication.')
    if kind == 'ssh' and auth != 'key':
        raise DeployError('SSH URLs use the deploy key.')
    if kind == 'https' and auth == 'key':
        raise DeployError('A deploy key needs an SSH URL (git@host:owner/repo.git).')
    default_target = os.path.relpath(site.docroot, site.home)
    try:
        target = siteinfo.check_rel(spec.get('target') or default_target, allow_empty=False)
    except SiteError as exc:
        raise DeployError(str(exc))
    if target.split('/')[0].startswith('.'):
        raise DeployError('The target cannot be a hidden directory of the home (such as .ssh).')
    mode = spec.get('mode') or 'pull'
    if mode not in MODES:
        raise DeployError('Invalid deploy mode.')
    keep = spec.get('keep', 5)
    if isinstance(keep, bool) or not isinstance(keep, int) or not 2 <= keep <= 20:
        raise DeployError('Keep between 2 and 20 releases.')
    steps = spec.get('steps') or []
    if not isinstance(steps, list) or any(s not in STEPS for s in steps):
        raise DeployError('Unknown post-deploy step.')
    restart_app = str(spec.get('restart_app') or '')
    if 'restart_app' in steps:
        if not APP_ID_RE.match(restart_app) or restart_app not in app_ids:
            raise DeployError('Choose which Universal Apps app of this site to restart.')
    else:
        restart_app = ''
    script = spec.get('custom_script') is True
    script_timeout = spec.get('script_timeout', 600)
    if isinstance(script_timeout, bool) or not isinstance(script_timeout, int) or \
            not 10 <= script_timeout <= SCRIPT_TIMEOUT_MAX:
        raise DeployError('The script timeout must be 10 to %d seconds.' % SCRIPT_TIMEOUT_MAX)
    token_user = str(spec.get('token_user') or 'x-access-token')
    if not TOKEN_USER_RE.match(token_user):
        raise DeployError('Invalid token user name.')
    previous = existing or {}
    return {
        'id': previous.get('id') or secrets.token_hex(16),
        'secret': previous.get('secret') or secrets.token_hex(20),
        'domain': site.domain, 'url': url, 'kind': kind, 'auth': auth, 'token_user': token_user,
        'branch': check_branch(spec.get('branch') or 'main'), 'target': target, 'mode': mode, 'keep': keep,
        'steps': [s for s in STEPS if s in steps], 'restart_app': restart_app, 'custom_script': script,
        'script_timeout': script_timeout, 'created': previous.get('created') or int(time.time()),
    }


def check_token(token):
    token = str(token or '').strip()
    if not TOKEN_RE.match(token):
        raise DeployError('The access token looks invalid.')
    return token


def public_config(config, include_secret=False):
    """What the page may see: never the token; the webhook secret only when asked for."""
    shown = {k: v for k, v in config.items() if k not in ('secret',)}
    shown['secret'] = config.get('secret') if include_secret else ''
    return shown


# ----------------------------------------------------------------------------- state

def _ensure_dir(path, mode=0o700):
    os.makedirs(path, mode=mode, exist_ok=True)
    os.chmod(path, mode)


def _write_private(path, data):
    _ensure_dir(os.path.dirname(path))
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(data)
    os.replace(path + '.tmp', path)


def load_configs(state_dir=None):
    try:
        with open(os.path.join(state_dir or STATE_DIR, 'sites.json')) as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_configs(configs, state_dir=None):
    _write_private(os.path.join(state_dir or STATE_DIR, 'sites.json'), json.dumps(configs, indent=2, sort_keys=True))


def config_for(domain, state_dir=None):
    config = load_configs(state_dir).get((domain or '').lower())
    if not config:
        raise DeployError('No repository is connected to %s.' % domain)
    return config


def config_by_hook(hook_id, state_dir=None):
    if not HOOK_ID_RE.match(hook_id or ''):
        return None
    for config in load_configs(state_dir).values():
        if hmac.compare_digest(str(config.get('id', '')).encode(), hook_id.encode()):
            return config
    return None


def token_path(config, state_dir=None):
    if not HOOK_ID_RE.match(config.get('id', '')):
        raise DeployError('Invalid configuration.')
    return os.path.join(state_dir or STATE_DIR, 'tokens', config['id'])


def save_token(config, token, state_dir=None):
    _ensure_dir(os.path.join(state_dir or STATE_DIR, 'tokens'))
    _write_private(token_path(config, state_dir), check_token(token))


def load_token(config, state_dir=None):
    try:
        with open(token_path(config, state_dir)) as handle:
            return handle.read().strip()
    except OSError:
        return ''


def data_dir(config, base=None):
    if not HOOK_ID_RE.match(config.get('id', '')):
        raise DeployError('Invalid configuration.')
    path = os.path.join(base or DATA_DIR, config['id'])
    _ensure_dir(path)
    return path


def load_history(config, base=None):
    try:
        with open(os.path.join(data_dir(config, base), 'history.json')) as handle:
            items = json.load(handle)
        return items if isinstance(items, list) else []
    except (OSError, ValueError):
        return []


def add_history(config, entry, log_lines, base=None):
    """Record one deploy (newest first), keeping MAX_HISTORY entries and their logs."""
    directory = data_dir(config, base)
    items = load_history(config, base)
    entry = dict(entry, n=(items[0]['n'] + 1) if items else 1)
    logs = os.path.join(directory, 'logs')
    _ensure_dir(logs)
    _write_private(os.path.join(logs, '%d.log' % entry['n']), '\n'.join(log_lines or []) + '\n')
    items.insert(0, entry)
    for old in items[MAX_HISTORY:]:
        try:
            os.unlink(os.path.join(logs, '%d.log' % old['n']))
        except OSError:
            pass
    items = items[:MAX_HISTORY]
    _write_private(os.path.join(directory, 'history.json'), json.dumps(items))
    return entry


def history_log(config, n, base=None):
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise DeployError('Invalid deploy.')
    try:
        with open(os.path.join(data_dir(config, base), 'logs', '%d.log' % n)) as handle:
            return handle.read()[-200000:].splitlines()
    except OSError:
        raise DeployError('That log is no longer kept.')


# ----------------------------------------------------------------------------- one deploy at a time, rate limit

class Busy(Exception):
    pass


class SiteLock:
    """flock on a per-site file; held by the running deploy job."""

    def __init__(self, config, base=None):
        self.path = os.path.join(data_dir(config, base), 'lock')
        self.handle = None

    def acquire(self):
        self.handle = open(self.path, 'a')
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            self.handle = None
            raise Busy()
        return self

    def release(self):
        if self.handle:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
            self.handle.close()
            self.handle = None

    def held_elsewhere(self):
        try:
            self.acquire()
        except Busy:
            return True
        self.release()
        return False


def pending_path(config, base=None):
    return os.path.join(data_dir(config, base), 'pending')


def rate_allowed(config, now=None, base=None, window=RATE_WINDOW, limit=RATE_MAX):
    """True (and the delivery counted) while fewer than `limit` arrived in the last `window` s."""
    now = time.time() if now is None else now
    path = os.path.join(data_dir(config, base), 'rate.json')
    with open(path, 'a+') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        try:
            stamps = [t for t in json.loads(handle.read() or '[]') if isinstance(t, (int, float)) and now - t < window]
        except ValueError:
            stamps = []
        allowed = len(stamps) < limit
        if allowed:
            stamps.append(now)
        handle.seek(0)
        handle.truncate()
        handle.write(json.dumps(stamps))
    return allowed


# ----------------------------------------------------------------------------- webhooks

def _hmac_hex(secret, body):
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _same(a, b):
    return hmac.compare_digest(str(a).encode('utf-8', 'replace'), str(b).encode('utf-8', 'replace'))


def verify_webhook(headers, body, secret):
    """The provider whose signature on `body` matches `secret`, or None (missing or bad signature)."""
    h = {str(k).lower(): str(v).strip() for k, v in (headers or {}).items()}
    if not secret or not isinstance(body, bytes):
        return None
    if 'x-hub-signature-256' in h:  # GitHub (and GitHub-compatible senders)
        return 'github' if _same(h['x-hub-signature-256'], 'sha256=' + _hmac_hex(secret, body)) else None
    if 'x-gitlab-token' in h:
        return 'gitlab' if _same(h['x-gitlab-token'], secret) else None
    for name in ('x-gitea-signature', 'x-gogs-signature'):
        if name in h:
            return 'gitea' if _same(h[name].lower(), _hmac_hex(secret, body)) else None
    if 'x-hub-signature' in h:  # Bitbucket Cloud and Data Center: sha256=<hex>
        value = h['x-hub-signature']
        return 'bitbucket' if value.startswith('sha256=') and _same(value, 'sha256=' + _hmac_hex(secret, body)) else None
    return None


def event_kind(provider, headers):
    """'push', 'ping' or 'other' for a verified delivery."""
    h = {str(k).lower(): str(v).strip().lower() for k, v in (headers or {}).items()}
    if provider == 'github':
        event = h.get('x-github-event', '')
    elif provider == 'gitlab':
        event = h.get('x-gitlab-event', '')
        return 'push' if event == 'push hook' else 'other'
    elif provider == 'gitea':
        event = h.get('x-gitea-event') or h.get('x-gogs-event', '')
    else:
        event = h.get('x-event-key', '')
        if event in ('repo:push', 'repo:refs_changed'):
            return 'push'
        return 'ping' if event == 'diagnostics:ping' else 'other'
    return event if event in ('push', 'ping') else 'other'


def pushed_branches(provider, payload):
    """Branch names a push delivery updated (deleted branches are left out)."""
    branches = set()
    if not isinstance(payload, dict):
        return branches
    if provider in ('github', 'gitlab', 'gitea'):
        ref = payload.get('ref')
        deleted = payload.get('deleted') is True or payload.get('after') == '0' * 40
        if isinstance(ref, str) and ref.startswith('refs/heads/') and not deleted:
            branches.add(ref[len('refs/heads/'):])
        return branches
    push = payload.get('push')
    if isinstance(push, dict):  # Bitbucket Cloud
        for change in push.get('changes') or []:
            new = change.get('new') if isinstance(change, dict) else None
            if isinstance(new, dict) and new.get('type') == 'branch' and isinstance(new.get('name'), str):
                branches.add(new['name'])
    for change in payload.get('changes') or []:  # Bitbucket Data Center
        if not isinstance(change, dict) or change.get('type') == 'DELETE':
            continue
        ref = change.get('ref') or {}
        if isinstance(ref, dict) and ref.get('type') == 'BRANCH' and isinstance(ref.get('displayId'), str):
            branches.add(ref['displayId'])
    return branches


DUMMY_SECRET = secrets.token_hex(20)


def check_delivery(config, headers, body):
    """(http status, outcome) for a delivery; authentication failures come back as (404, None).

    An unknown id is checked against a throw-away secret so it costs the same as a wrong one.
    """
    provider = verify_webhook(headers, body, (config or {}).get('secret') or DUMMY_SECRET)
    if not config or not provider:
        return 404, None
    kind = event_kind(provider, headers)
    if kind == 'ping':
        return 200, {'status': 'pong', 'provider': provider}
    if kind != 'push':
        return 202, {'status': 'ignored', 'reason': 'not a push event'}
    try:
        payload = json.loads(body.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        return 400, {'status': 'ignored', 'reason': 'invalid JSON'}
    if config['branch'] not in pushed_branches(provider, payload):
        return 202, {'status': 'ignored', 'reason': 'push to another branch'}
    return 202, {'status': 'deploy', 'provider': provider}


# ----------------------------------------------------------------------------- git as the site user

def key_path(site, config):
    return os.path.join(site.home, '.ssh', 'indianscloud_deploy_%s' % config['id'][:12])


def git_env(site, config, token=''):
    env = {'GIT_TERMINAL_PROMPT': '0', 'GIT_ALLOW_PROTOCOL': 'https:ssh', 'GIT_ASKPASS': '/bin/false',
           'SSH_ASKPASS': '/bin/false'}
    if config['auth'] == 'key':
        key = key_path(site, config)
        env['GIT_SSH_COMMAND'] = ('ssh -i %s -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new '
                                  '-o UserKnownHostsFile=%s/.ssh/known_hosts' % (key, site.home))
    elif config['auth'] == 'token' and token:
        basic = base64.b64encode(('%s:%s' % (config.get('token_user') or 'x-access-token', token)).encode()).decode()
        # The same mechanism as `git -c`, but in the environment: never visible in the process list.
        env['GIT_CONFIG_PARAMETERS'] = "'http.extraheader=Authorization: Basic %s'" % basic
    return env


def generate_key(site, config, runner=None, replace=False):
    """Create (or keep) the site's deploy key as the site user; returns the public key."""
    kwargs = {'runner': runner} if runner else {}
    key = key_path(site, config)
    siteinfo.run_as(site, ['mkdir', '-p', '-m', '0700', os.path.join(site.home, '.ssh')], timeout=30, **kwargs)
    if replace:
        siteinfo.run_as(site, ['rm', '-f', '--', key, key + '.pub'], timeout=30, **kwargs)
    if not siteinfo.exists_nofollow(key):
        code, out = siteinfo.run_as(site, ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C',
                                           'indianscloud-deploy@%s' % site.domain, '-f', key], timeout=60, **kwargs)
        if code != 0:
            raise DeployError('Could not create the deploy key: ' + out.strip()[-300:])
    siteinfo.run_as(site, ['chmod', '0600', '--', key], timeout=30, **kwargs)
    return public_key(site, config)


def public_key(site, config):
    """The .pub half only (the private key never leaves the site user's ~/.ssh)."""
    try:
        text = siteinfo.read_owned(site, key_path(site, config) + '.pub', 4096)
    except (OSError, SiteError):
        return ''
    text = (text or '').strip()
    return text if text.startswith('ssh-ed25519 ') and '\n' not in text and 'PRIVATE' not in text else ''


class Deployer:
    """One deploy of `config` to `site`, every command as the site user."""

    def __init__(self, site, config, token='', log=None, runner=None, find_composer=None, find_npm=None,
                 restart_app=None, now=None):
        self.site, self.config, self.token = site, config, token
        self.say = log or (lambda text: None)
        self.kwargs = {'runner': runner} if runner else {}
        self.find_composer = find_composer
        self.find_npm = find_npm
        self.restart_app = restart_app
        self.now = now
        self.env = git_env(site, config, token)
        self.target = site.home_rel(config['target'])
        self.base = os.path.join(site.home, '.indianscloud', 'deploy', config['id'][:12])

    # -- helpers
    def run(self, argv, cwd=None, timeout=STEP_TIMEOUT, env=None, path=None, check=True, show=None):
        self.say('$ ' + (show or ' '.join(argv)))
        code, out = siteinfo.run_as(self.site, argv, cwd=cwd, extra_env=env, timeout=timeout, path=path,
                                    **self.kwargs)
        text = out.strip()
        if self.token:
            text = text.replace(self.token, '***')
        if text:
            self.say(text[-20000:])
        if check and code != 0:
            raise DeployError('%s exited with status %d.' % (os.path.basename(argv[0]), code))
        return code, out

    def git(self, *args, cwd=None, check=True):
        return self.run(['git'] + list(args), cwd=cwd, env=self.env, check=check, timeout=900)

    def _check_empty(self, path):
        real = self.site.inside(path)
        extra = [n for n in os.listdir(real) if n not in DEFAULT_FILES]
        if extra:
            raise DeployError('%s is not empty (%s). Empty it, or choose another directory.' % (
                self.config['target'], ', '.join(sorted(extra)[:5])))

    # -- modes
    def deploy(self):
        if self.config['mode'] == 'releases':
            return self.deploy_release()
        return self.deploy_pull()

    def deploy_pull(self):
        target = self.target
        branch = self.config['branch']
        if os.path.islink(target):
            raise DeployError('%s is a link; "pull into directory" needs a real directory.' % self.config['target'])
        if not os.path.isdir(os.path.join(target, '.git')):
            if os.path.isdir(target):
                self._check_empty(target)
                self.run(['rm', '-f', '--', os.path.join(target, 'index.html')])
            else:
                self.site.inside(os.path.dirname(target))
                self.run(['mkdir', '-p', '--', target])
            self.git('init', '-q', cwd=target)
            self.git('remote', 'add', 'origin', self.config['url'], cwd=target)
        else:
            self.git('remote', 'set-url', 'origin', self.config['url'], cwd=target)
        self.git('-c', 'protocol.file.allow=never', 'fetch', '--depth', '50', '--no-tags', 'origin',
                 '+refs/heads/%s:refs/remotes/origin/%s' % (branch, branch), cwd=target)
        self.git('checkout', '-q', '-f', '-B', branch, 'refs/remotes/origin/%s' % branch, cwd=target)
        commit = self.git('rev-parse', 'HEAD', cwd=target)[1].strip()[-40:]
        self.post_steps(target, commit)
        return {'commit': commit, 'dir': target}

    def release_name(self):
        now = self.now or time.time()
        return time.strftime('%Y%m%d-%H%M%S', time.localtime(now)) + '-' + secrets.token_hex(2)

    def deploy_release(self):
        base, branch = self.base, self.config['branch']
        if os.path.isdir(self.target) and not os.path.islink(self.target):
            self._check_empty(self.target)  # before building anything
        releases, shared, repo = (os.path.join(base, n) for n in ('releases', 'shared', 'repo.git'))
        self.run(['mkdir', '-p', '-m', '0755', '--', releases, shared])
        if not os.path.isdir(repo):
            self.git('init', '-q', '--bare', repo)
        self.git('--git-dir=' + repo, '-c', 'protocol.file.allow=never', 'fetch', '--depth', '50', '--no-tags',
                 self.config['url'], '+refs/heads/%s:refs/heads/%s' % (branch, branch))
        commit = self.git('--git-dir=' + repo, 'rev-parse', 'refs/heads/' + branch)[1].strip()[-40:]
        if not re.match(r'^[0-9a-f]{40}$', commit):
            raise DeployError('Could not read the pushed commit.')
        name = self.release_name()
        release = os.path.join(releases, name)
        self.run(['mkdir', '-p', '--', release])
        self.git('--git-dir=' + repo, '--work-tree=' + release, 'checkout', '-f', commit, '--', '.')
        self.link_shared(release, shared)
        self.post_steps(release, commit)
        self.switch(name)
        self.prune()
        return {'commit': commit, 'release': name, 'dir': release}

    def link_shared(self, release, shared):
        """Keep .env and storage/ across releases: shared/<item>, linked into each release."""
        laravel = siteinfo.exists_nofollow(os.path.join(release, 'artisan'))
        for item in SHARED_ITEMS:
            shared_item = os.path.join(shared, item)
            in_release = os.path.join(release, item)
            if item == 'storage' and laravel and not siteinfo.exists_nofollow(shared_item) and \
                    os.path.isdir(in_release):
                self.run(['cp', '-a', '--', in_release, shared_item])  # first release seeds shared/storage
            if siteinfo.exists_nofollow(shared_item):
                self.run(['rm', '-rf', '--one-file-system', '--', in_release])
                self.run(['ln', '-s', '--', os.path.relpath(shared_item, release), in_release])

    def current_link(self):
        return os.path.join(self.base, 'current')

    def current_release(self):
        try:
            return os.path.basename(os.readlink(self.current_link()))
        except OSError:
            return ''

    def releases(self):
        try:
            return sorted(n for n in os.listdir(os.path.join(self.base, 'releases')) if RELEASE_RE.match(n))
        except OSError:
            return []

    def switch(self, name):
        """Point current at releases/<name> atomically, and the target directory at current."""
        if not RELEASE_RE.match(name) or name not in self.releases():
            raise DeployError('Unknown release.')
        temporary = os.path.join(self.base, '.current.new')
        self.run(['rm', '-f', '--', temporary])
        self.run(['ln', '-s', '--', os.path.join('releases', name), temporary])
        self.run(['mv', '-T', '-f', '--', temporary, self.current_link()])
        target = self.target
        if os.path.islink(target):
            if os.path.realpath(target) != os.path.realpath(self.current_link()):
                raise DeployError('%s links somewhere else; remove the link first.' % self.config['target'])
            return
        if os.path.isdir(target):
            self._check_empty(target)
            self.run(['rm', '-rf', '--one-file-system', '--', target])
        else:
            self.site.inside(os.path.dirname(target))
        self.run(['ln', '-s', '--', self.current_link(), target])
        self.say('%s now links to %s' % (self.config['target'], self.current_link()))

    def prune(self):
        """Keep the newest `keep` releases (and always the current one)."""
        keep = int(self.config.get('keep', 5))
        current = self.current_release()
        for name in [n for n in self.releases()[:-keep] if n != current]:
            self.run(['rm', '-rf', '--one-file-system', '--', os.path.join(self.base, 'releases', name)])

    def rollback(self):
        if self.config['mode'] != 'releases':
            raise DeployError('Rollback needs the "releases" deploy mode.')
        names, current = self.releases(), self.current_release()
        if current not in names or names.index(current) == 0:
            raise DeployError('There is no earlier release to go back to.')
        previous = names[names.index(current) - 1]
        self.switch(previous)
        if 'restart_app' in self.config.get('steps', []):
            self.step_restart_app()
        return {'release': previous, 'from': current}

    # -- post-deploy steps
    def post_steps(self, directory, commit):
        steps = self.config.get('steps', [])
        php = self.site.php
        if 'composer_install' in steps:
            composer = self.find_composer() if self.find_composer else ''
            if not composer:
                raise DeployError('Composer is not installed on this server.')
            self.run([php, composer, 'install', '--no-dev', '--no-interaction', '--prefer-dist',
                      '--optimize-autoloader', '--no-ansi'], cwd=directory, env={'COMPOSER_NO_INTERACTION': '1'})
        if 'npm_build' in steps:
            npm = self.find_npm() if self.find_npm else ''
            if not npm:
                raise DeployError('npm was not found: install a Node.js runtime from the Universal Apps add-on.')
            path = os.path.dirname(npm) + ':' + siteinfo.USER_PATH
            self.run([npm, 'ci', '--no-audit', '--no-fund'], cwd=directory, path=path)
            self.run([npm, 'run', 'build'], cwd=directory, path=path)
        if 'artisan_migrate' in steps:
            self.run([php, 'artisan', 'migrate', '--force', '--no-interaction', '--no-ansi'], cwd=directory)
        if 'artisan_optimize' in steps:
            self.run([php, 'artisan', 'optimize', '--no-interaction', '--no-ansi'], cwd=directory)
        if self.config.get('custom_script'):
            self.custom_script(directory, commit)
        if 'restart_app' in steps:
            self.step_restart_app()

    def custom_script(self, directory, commit):
        script = os.path.join(directory, CUSTOM_SCRIPT)
        try:
            info = os.lstat(script)
        except OSError:
            self.say('No %s in the repository; skipped.' % CUSTOM_SCRIPT)
            return
        if not stat.S_ISREG(info.st_mode):
            raise DeployError('%s must be a regular file.' % CUSTOM_SCRIPT)
        self.run(['/bin/bash', CUSTOM_SCRIPT], cwd=directory, timeout=int(self.config.get('script_timeout', 600)),
                 env={'DEPLOY_DIR': directory, 'DEPLOY_COMMIT': commit, 'DEPLOY_BRANCH': self.config['branch'],
                      'PHP_BINARY': self.site.php})

    def step_restart_app(self):
        app_id = self.config.get('restart_app')
        if not app_id or not self.restart_app:
            return
        self.say('Restarting app %s' % app_id)
        self.restart_app(app_id, self.site.domain)

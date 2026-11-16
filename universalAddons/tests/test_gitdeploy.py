"""Git deploy: repository URL validation, webhook signatures per provider (good, bad, missing), the
branch filter, the session-less CSRF-exempt hook, rate limiting, ownership, deploy-key and token
secrecy, releases with rollback, one deploy at a time, and the page."""
import base64
import getpass
import hashlib
import hmac
import json
import os
import subprocess
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.template.loader import render_to_string
from django.test import Client, SimpleTestCase

from universalAddons import siteinfo
from universalAddons.gitdeploy import actions, service as svc, views
from universalAddons.gitdeploy.service import DeployError
from universalAddons.tests import helpers
from universalAddons.tests.helpers import FOREIGN, OWNED

MINE = OWNED[0]
SECRET = 'f' * 40
HOOK = 'a1' * 16
TOKEN = 'ghp_' + 'T0k3n' * 6
PUSH_MAIN = json.dumps({'ref': 'refs/heads/main', 'after': 'b' * 40}).encode()


def temp_site():
    home = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
    site = siteinfo.Site('example.com', 'examp1234', '/home/example.com', '/home/example.com/public_html',
                         'example.com', '/usr/local/lsws/lsphp82/bin/php')
    site.user = getpass.getuser()
    site.home, site.docroot = home, os.path.join(home, 'public_html')
    os.makedirs(site.docroot)
    return site


def config(**extra):
    base = {'id': HOOK, 'secret': SECRET, 'domain': 'example.com', 'url': 'https://github.com/acme/site.git',
            'kind': 'https', 'auth': 'public', 'token_user': 'x-access-token', 'branch': 'main',
            'target': 'public_html', 'mode': 'pull', 'keep': 3, 'steps': [], 'restart_app': '',
            'custom_script': False, 'script_timeout': 600}
    base.update(extra)
    return base


def sign(body, secret=SECRET):
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ----------------------------------------------------------------------------- URLs and branches

class Repositories(SimpleTestCase):
    def test_accepted_urls(self):
        for url, kind in (('https://github.com/acme/site.git', 'https'), ('https://gitlab.com/group/sub/repo', 'https'),
                          ('https://git.example.org:8443/acme/site.git', 'https'),
                          ('git@github.com:acme/site.git', 'ssh'), ('ssh://git@bitbucket.org/acme/site.git', 'ssh'),
                          ('ssh://git@git.example.org:2222/acme/site.git', 'ssh')):
            self.assertEqual(svc.check_repo(url), (kind, url))

    def test_refused_urls(self):
        for url in ('file:///home/other/repo', '/home/other.example.net/repo', '../repo', 'repo',
                    'http://github.com/acme/site.git', 'https://user:pass@github.com/acme/site.git',
                    'ext::sh -c touch% /tmp/pwned', 'git://github.com/acme/site.git', 'https://localhost/acme/x',
                    'https://127.0.0.1/acme/x', 'https://10.0.0.5/acme/x', 'git@localhost:acme/x',
                    'git@github.com:-oProxyCommand=touch/x', 'https://github.com/acme/../../x',
                    'https://github.com/acme/site.git?x=1', 'https://github.com/acme/site;id', 'git@github.com:/etc/passwd',
                    'https://github.com/acme/$(id)', 'ssh://-oProxyCommand=x/acme/repo', '', None):
            with self.assertRaises(DeployError, msg=url):
                svc.check_repo(url)

    def test_branches(self):
        for good in ('main', 'release/2.0', 'feature_x-1'):
            self.assertEqual(svc.check_branch(good), good)
        for bad in ('-main', 'a..b', 'a b', 'main.lock', 'x/', 'a@{1}', '', 'a;b', 'x' * 101):
            with self.assertRaises(DeployError, msg=bad):
                svc.check_branch(bad)

    def test_config_validation(self):
        site = temp_site()
        spec = {'url': 'git@github.com:acme/site.git', 'branch': 'main', 'steps': ['artisan_optimize', 'composer_install']}
        result = svc.validate_config(spec, site)
        self.assertEqual(result['auth'], 'key')
        self.assertEqual(result['target'], 'public_html')
        self.assertEqual(result['steps'], ['composer_install', 'artisan_optimize'])  # fixed order
        self.assertTrue(svc.HOOK_ID_RE.match(result['id']))
        self.assertEqual(len(result['secret']), 40)
        self.assertEqual(svc.validate_config(spec, site, existing=result)['id'], result['id'])
        for bad in ({'target': '../other'}, {'target': '.ssh'}, {'target': '/etc'}, {'mode': 'rsync'}, {'keep': 50},
                    {'steps': ['rm -rf']}, {'steps': ['restart_app'], 'restart_app': 'nope'},
                    {'url': 'https://github.com/a/b', 'auth': 'key'}, {'auth': 'token'}, {'script_timeout': 99999}):
            with self.assertRaises(DeployError, msg=bad):
                svc.validate_config(dict(spec, **bad), site)
        ok = svc.validate_config(dict(spec, steps=['restart_app'], restart_app='api'), site, app_ids=['api'])
        self.assertEqual(ok['restart_app'], 'api')


# ----------------------------------------------------------------------------- webhook signatures

class Signatures(SimpleTestCase):
    body = PUSH_MAIN

    def test_github(self):
        good = {'X-Hub-Signature-256': 'sha256=' + sign(self.body), 'X-GitHub-Event': 'push'}
        self.assertEqual(svc.verify_webhook(good, self.body, SECRET), 'github')
        self.assertEqual(svc.verify_webhook({'x-hub-signature-256': good['X-Hub-Signature-256']}, self.body, SECRET), 'github')
        self.assertIsNone(svc.verify_webhook({'X-Hub-Signature-256': 'sha256=' + sign(self.body, 'e' * 40)}, self.body, SECRET))
        self.assertIsNone(svc.verify_webhook({'X-Hub-Signature-256': sign(self.body)}, self.body, SECRET))  # no prefix
        self.assertIsNone(svc.verify_webhook(good, self.body + b' ', SECRET))                               # body changed
        self.assertIsNone(svc.verify_webhook({'X-GitHub-Event': 'push'}, self.body, SECRET))               # missing

    def test_gitlab(self):
        self.assertEqual(svc.verify_webhook({'X-Gitlab-Token': SECRET, 'X-Gitlab-Event': 'Push Hook'}, self.body, SECRET),
                         'gitlab')
        self.assertIsNone(svc.verify_webhook({'X-Gitlab-Token': 'wrong'}, self.body, SECRET))
        self.assertIsNone(svc.verify_webhook({'X-Gitlab-Token': ''}, self.body, SECRET))
        self.assertIsNone(svc.verify_webhook({'X-Gitlab-Event': 'Push Hook'}, self.body, SECRET))

    def test_gitea_and_gogs(self):
        self.assertEqual(svc.verify_webhook({'X-Gitea-Signature': sign(self.body)}, self.body, SECRET), 'gitea')
        self.assertEqual(svc.verify_webhook({'X-Gogs-Signature': sign(self.body)}, self.body, SECRET), 'gitea')
        self.assertIsNone(svc.verify_webhook({'X-Gitea-Signature': sign(self.body, 'x' * 40)}, self.body, SECRET))
        self.assertIsNone(svc.verify_webhook({'X-Gitea-Event': 'push'}, self.body, SECRET))

    def test_bitbucket(self):
        self.assertEqual(svc.verify_webhook({'X-Hub-Signature': 'sha256=' + sign(self.body), 'X-Event-Key': 'repo:push'},
                                            self.body, SECRET), 'bitbucket')
        self.assertIsNone(svc.verify_webhook({'X-Hub-Signature': 'sha1=' + sign(self.body)}, self.body, SECRET))
        self.assertIsNone(svc.verify_webhook({'X-Hub-Signature': 'sha256=' + '0' * 64}, self.body, SECRET))
        self.assertIsNone(svc.verify_webhook({'X-Event-Key': 'repo:push'}, self.body, SECRET))

    def test_no_secret_or_odd_values_never_verify(self):
        self.assertIsNone(svc.verify_webhook({'X-Gitlab-Token': ''}, self.body, ''))
        self.assertIsNone(svc.verify_webhook({'X-Gitlab-Token': 'é' * 3}, self.body, SECRET))
        self.assertIsNone(svc.verify_webhook({'X-Hub-Signature-256': 'sha256=' + sign(self.body)}, 'text', SECRET))

    def test_compares_in_constant_time(self):
        with mock.patch('universalAddons.gitdeploy.service.hmac.compare_digest', return_value=False) as compare:
            svc.verify_webhook({'X-Gitlab-Token': SECRET}, self.body, SECRET)
            svc.verify_webhook({'X-Hub-Signature-256': 'sha256=x'}, self.body, SECRET)
        self.assertEqual(compare.call_count, 2)


class BranchFilter(SimpleTestCase):
    def delivery(self, payload, provider='github', cfg=None):
        body = json.dumps(payload).encode()
        headers = {'github': {'X-Hub-Signature-256': 'sha256=' + sign(body), 'X-GitHub-Event': 'push'},
                   'gitlab': {'X-Gitlab-Token': SECRET, 'X-Gitlab-Event': 'Push Hook'},
                   'gitea': {'X-Gitea-Signature': sign(body), 'X-Gitea-Event': 'push'},
                   'bitbucket': {'X-Hub-Signature': 'sha256=' + sign(body), 'X-Event-Key': 'repo:push'}}[provider]
        return svc.check_delivery(cfg if cfg is not None else config(), headers, body)

    def test_only_the_configured_branch_deploys(self):
        for provider in ('github', 'gitlab', 'gitea'):
            self.assertEqual(self.delivery({'ref': 'refs/heads/main'}, provider), (202, {'status': 'deploy', 'provider': provider}))
            self.assertEqual(self.delivery({'ref': 'refs/heads/dev'}, provider)[1]['status'], 'ignored')
            self.assertEqual(self.delivery({'ref': 'refs/tags/main'}, provider)[1]['status'], 'ignored')
        self.assertEqual(self.delivery({'ref': 'refs/heads/main', 'deleted': True})[1]['status'], 'ignored')
        cloud = {'push': {'changes': [{'new': {'type': 'branch', 'name': 'main'}}]}}
        self.assertEqual(self.delivery(cloud, 'bitbucket')[1]['status'], 'deploy')
        other = {'push': {'changes': [{'new': {'type': 'branch', 'name': 'dev'}}, {'new': None}]}}
        self.assertEqual(self.delivery(other, 'bitbucket')[1]['status'], 'ignored')
        server = {'changes': [{'ref': {'type': 'BRANCH', 'displayId': 'main'}, 'type': 'UPDATE'}]}
        self.assertEqual(self.delivery(server, 'bitbucket')[1]['status'], 'deploy')

    def test_ping_and_other_events(self):
        body = b'{"zen": "x"}'
        self.assertEqual(svc.check_delivery(config(), {'X-Hub-Signature-256': 'sha256=' + sign(body),
                                                       'X-GitHub-Event': 'ping'}, body)[1]['status'], 'pong')
        self.assertEqual(svc.check_delivery(config(), {'X-Hub-Signature-256': 'sha256=' + sign(body),
                                                       'X-GitHub-Event': 'issues'}, body)[1]['status'], 'ignored')

    def test_unknown_hook_and_bad_signature_look_the_same(self):
        good = {'X-Hub-Signature-256': 'sha256=' + sign(PUSH_MAIN), 'X-GitHub-Event': 'push'}
        self.assertEqual(svc.check_delivery(None, good, PUSH_MAIN), (404, None))
        self.assertEqual(svc.check_delivery(config(secret='e' * 40), good, PUSH_MAIN), (404, None))
        self.assertEqual(svc.check_delivery(config(), {}, PUSH_MAIN), (404, None))


# ----------------------------------------------------------------------------- the hook endpoint

class HookEndpoint(SimpleTestCase):
    url = '/addons/git-deploy/hook/%s/' % HOOK

    def post(self, headers, body=PUSH_MAIN, result=None, side_effect=None, url=None):
        client = Client(enforce_csrf_checks=True)  # no session, no CSRF token: the hook must not need either
        extra = {'HTTP_' + k.upper().replace('-', '_'): v for k, v in headers.items()}
        with mock.patch('universalAddons.privileged.call_private', return_value=result, side_effect=side_effect) as call:
            views._seen.clear()
            response = client.post(url or self.url, data=body, content_type='application/json', **extra)
        return response, call

    def test_signed_delivery_reaches_the_root_side(self):
        headers = {'X-Hub-Signature-256': 'sha256=' + sign(PUSH_MAIN), 'X-GitHub-Event': 'push'}
        response, call = self.post(headers, result={'http': 202, 'status': 'deploying'})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(json.loads(response.content), {'status': 'deploying'})
        args = call.call_args
        self.assertEqual(args.args, ('gitdeploy', 'hook'))
        self.assertEqual(args.kwargs['hook_id'], HOOK)
        self.assertEqual(base64.b64decode(args.kwargs['body']), PUSH_MAIN)
        self.assertEqual(args.kwargs['headers']['X-Hub-Signature-256'], headers['X-Hub-Signature-256'])

    def test_failures_reveal_nothing(self):
        bad = {'X-Hub-Signature-256': 'sha256=' + '0' * 64}
        for response, call in (self.post({}),                                                   # missing signature
                               self.post(bad, result={'http': 404}),                            # wrong signature
                               self.post(bad, side_effect=RuntimeError('Unknown module'))):     # runner error
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.content, b'')
        self.post({})[1].assert_not_called()
        # A malformed id never reaches the runner (the middleware does not even exempt such a path).
        from django.test import RequestFactory
        request = RequestFactory().post('/x', data=PUSH_MAIN, content_type='application/json', HTTP_X_GITLAB_TOKEN=SECRET)
        with mock.patch('universalAddons.privileged.call_private') as call:
            response = views.hook(request, '../../etc')
        self.assertEqual((response.status_code, response.content), (404, b''))
        call.assert_not_called()

    def test_get_and_oversized_bodies_refused(self):
        client = Client()
        with mock.patch('universalAddons.privileged.call_private') as call:
            self.assertEqual(client.get(self.url).status_code, 404)
            call.assert_not_called()

    def test_view_is_csrf_exempt_and_session_free(self):
        self.assertTrue(getattr(views.hook, 'csrf_exempt', False))
        source = open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                   'CyberCP', 'secMiddleware.py')).read()
        self.assertIn(r"^/addons/git-deploy/hook/[0-9a-f]{32}/$", source)

    def test_web_side_rate_limit(self):
        views._seen.clear()
        limit = views.WEB_RATE['per_hook'][0]
        self.assertTrue(all(views._web_rate_ok(HOOK, now=1000) for _ in range(limit)))
        self.assertFalse(views._web_rate_ok(HOOK, now=1001))
        self.assertTrue(views._web_rate_ok('b2' * 16, now=1001))  # other hooks are not affected
        self.assertTrue(views._web_rate_ok(HOOK, now=1000 + views.WEB_RATE['per_hook'][1] + 1))
        views._seen.clear()


class RootHook(SimpleTestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        self.data = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        self.patches = [mock.patch.object(svc, 'STATE_DIR', self.state), mock.patch.object(svc, 'DATA_DIR', self.data)]
        for p in self.patches:
            p.start()
        svc.save_configs({'example.com': config()})

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def deliver(self, headers, body=PUSH_MAIN, hook_id=HOOK):
        with mock.patch('universalAddons.jobs.spawn', return_value={'job_id': 'c' * 24}) as spawn:
            result = actions.hook(hook_id, headers, base64.b64encode(body).decode())
        return result, spawn

    def test_good_push_spawns_one_deploy_and_is_rate_limited(self):
        headers = {'X-Hub-Signature-256': 'sha256=' + sign(PUSH_MAIN), 'X-GitHub-Event': 'push'}
        for _ in range(svc.RATE_MAX):
            result, spawn = self.deliver(headers)
            self.assertEqual(result, {'http': 202, 'status': 'deploying'})
            spawn.assert_called_once_with('gitdeploy', 'deploy_run', {'domain': 'example.com', 'trigger': 'webhook:github'})
        result, spawn = self.deliver(headers)
        self.assertEqual(result['http'], 429)
        spawn.assert_not_called()

    def test_bad_missing_unknown_deliver_nothing(self):
        for headers, hook_id in (({'X-Hub-Signature-256': 'sha256=' + sign(PUSH_MAIN, 'e' * 40)}, HOOK), ({}, HOOK),
                                 ({'X-Hub-Signature-256': 'sha256=' + sign(PUSH_MAIN)}, 'b2' * 16),
                                 ({'X-Gitlab-Token': SECRET}, '../../etc')):
            result, spawn = self.deliver(headers, hook_id=hook_id)
            self.assertEqual(result, {'http': 404})
            spawn.assert_not_called()
        with mock.patch('universalAddons.jobs.spawn') as spawn:
            self.assertEqual(actions.hook(HOOK, {}, 'not base64!'), {'http': 404})
        spawn.assert_not_called()

    def test_other_branch_is_ignored(self):
        body = json.dumps({'ref': 'refs/heads/dev'}).encode()
        result, spawn = self.deliver({'X-Gitlab-Token': SECRET, 'X-Gitlab-Event': 'Push Hook'}, body)
        self.assertEqual(result['status'], 'ignored')
        spawn.assert_not_called()

    def test_one_deploy_at_a_time_and_later_pushes_are_queued(self):
        cfg = config()
        held = svc.SiteLock(cfg).acquire()
        try:
            self.assertTrue(svc.SiteLock(cfg).held_elsewhere())
            with self.assertRaises(svc.Busy):
                svc.SiteLock(cfg).acquire()
            with mock.patch.object(actions, '_site', return_value=temp_site()), \
                    mock.patch('universalAddons.jobs.JOB_DIR', self.data):
                data = actions.deploy_run('d' * 24, 'example.com', 'webhook:github')
            self.assertEqual(data['result'], {'queued': True})
            self.assertTrue(os.path.exists(svc.pending_path(cfg)))
        finally:
            held.release()
        self.assertFalse(svc.SiteLock(cfg).held_elsewhere())


# ----------------------------------------------------------------------------- ownership

class Access(SimpleTestCase):
    FEATURE = 'gitdeploy_for_users'

    def call(self, view, body, admin=False, on=True, result=None, private=False):
        target = 'universalAddons.privileged.call_private' if private else 'universalAddons.privileged.call'
        with mock.patch(target, return_value=result if result is not None else {}) as runner:
            status, data, _ = helpers.post(view, body, admin=admin, policy={self.FEATURE: True} if on else {})
        return status, data, runner

    def test_owner_cannot_touch_another_site(self):
        for view in (views.status, views.key, views.secret, views.disconnect, views.deploy, views.rollback):
            status, _, runner = self.call(view, {'domain': FOREIGN})
            self.assertEqual(status, 403, view.__name__)
            runner.assert_not_called()
        status, _, runner = self.call(views.log, {'domain': FOREIGN, 'n': 1})
        self.assertEqual(status, 403)
        status, _, runner = self.call(views.save, {'domain': FOREIGN, 'repo': {'url': 'https://github.com/a/b'}}, private=True)
        self.assertEqual(status, 403)
        runner.assert_not_called()

    def test_policy_off_refuses_users_only(self):
        status, _, runner = self.call(views.status, {'domain': MINE}, on=False)
        self.assertEqual(status, 403)
        runner.assert_not_called()
        status, _, runner = self.call(views.status, {'domain': FOREIGN}, on=False, admin=True)
        self.assertEqual(status, 200)

    def test_owner_allowed_and_token_goes_privately(self):
        status, data, runner = self.call(views.status, {'domain': MINE}, result={'hook_path': '/addons/git-deploy/hook/%s/' % HOOK})
        self.assertEqual(status, 200)
        self.assertTrue(data['result']['hook_url'].endswith('/addons/git-deploy/hook/%s/' % HOOK))
        body = {'domain': MINE, 'repo': {'url': 'https://github.com/acme/private.git', 'auth': 'token'},
                'secrets': {'token': TOKEN}}
        status, _, runner = self.call(views.save, body, private=True, result={})
        self.assertEqual(status, 200)
        runner.assert_called_once_with('gitdeploy', 'save', domain=MINE, spec=body['repo'], token=TOKEN)

    def test_bad_urls_never_reach_the_runner(self):
        for repo in ({'url': 'file:///etc'}, {'url': '/home/other/repo'}, {'url': 'https://github.com/a/b', 'branch': '-x'},
                     'https://github.com/a/b'):
            status, _, runner = self.call(views.save, {'domain': MINE, 'repo': repo}, private=True)
            self.assertEqual(status, 400, repo)
            runner.assert_not_called()

    def test_jobs_bound_to_session(self):
        status, _, runner = self.call(views.job, {'job': 'e' * 24})
        self.assertEqual(status, 403)
        runner.assert_not_called()


# ----------------------------------------------------------------------------- secrecy

class Secrecy(SimpleTestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        self.data = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        self.patches = [mock.patch.object(svc, 'STATE_DIR', self.state), mock.patch.object(svc, 'DATA_DIR', self.data)]
        for p in self.patches:
            p.start()
        self.site = temp_site()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_deploy_key_only_public_half_is_returned(self):
        cfg = config(auth='key', url='git@github.com:acme/site.git', kind='ssh')
        calls = []

        def keygen(site, argv, **kwargs):
            calls.append(argv)
            if argv[0] == 'ssh-keygen':
                path = argv[argv.index('-f') + 1]
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'w') as handle:
                    handle.write('-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYDATA\n-----END OPENSSH PRIVATE KEY-----\n')
                os.chmod(path, 0o600)
                with open(path + '.pub', 'w') as handle:
                    handle.write('ssh-ed25519 AAAAC3NzaPUBLIC indianscloud-deploy@example.com\n')
            return 0, ''
        with mock.patch.object(siteinfo, 'run_as', side_effect=keygen):
            public = svc.generate_key(self.site, cfg)
        self.assertEqual(public, 'ssh-ed25519 AAAAC3NzaPUBLIC indianscloud-deploy@example.com')
        keygen_argv = [c for c in calls if c[0] == 'ssh-keygen'][0]
        self.assertEqual(keygen_argv[keygen_argv.index('-t') + 1], 'ed25519')
        self.assertTrue(keygen_argv[-1].startswith(os.path.join(self.site.home, '.ssh') + '/'))
        self.assertEqual(oct(os.stat(svc.key_path(self.site, cfg)).st_mode & 0o777), '0o600')
        # a .pub that is really a private key is never shown
        with open(svc.key_path(self.site, cfg) + '.pub', 'w') as handle:
            handle.write(open(svc.key_path(self.site, cfg)).read())
        self.assertEqual(svc.public_key(self.site, cfg), '')

    def test_status_never_contains_the_token_or_the_secret(self):
        cfg = config(auth='token')
        svc.save_configs({'example.com': cfg})
        svc.save_token(cfg, TOKEN)
        self.assertEqual(oct(os.stat(svc.token_path(cfg)).st_mode & 0o777), '0o600')
        self.assertEqual(oct(os.stat(os.path.join(self.state, 'sites.json')).st_mode & 0o777), '0o600')
        with mock.patch.object(actions, '_site', return_value=self.site), \
                mock.patch.object(actions, '_app_ids', return_value=[]):
            result = actions.status('example.com')
        text = json.dumps(result)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(SECRET, text)
        self.assertTrue(result['has_token'])
        self.assertEqual(svc.public_config(cfg, include_secret=True)['secret'], SECRET)

    def test_token_reaches_git_through_the_environment_only(self):
        cfg = config(auth='token')
        seen = []

        def runner(argv, **kwargs):
            seen.append((argv, kwargs.get('env', {})))
            out = ('remote: denied for %s' % TOKEN) if 'fetch' in argv else ('b' * 40 if 'rev-parse' in argv else '')
            return SimpleNamespace(returncode=0, stdout=out)
        log = []
        deployer = svc.Deployer(self.site, cfg, TOKEN, log=log.append, runner=runner)
        deployer.deploy_pull()
        for argv, env in seen:
            self.assertNotIn(TOKEN, ' '.join(argv))
        fetch_env = [env for argv, env in seen if 'fetch' in argv][0]
        header = base64.b64decode(fetch_env['GIT_CONFIG_PARAMETERS'].split('Basic ')[1].rstrip("'")).decode()
        self.assertEqual(header, 'x-access-token:' + TOKEN)
        self.assertEqual(fetch_env['GIT_ALLOW_PROTOCOL'], 'https:ssh')
        self.assertEqual(fetch_env['GIT_TERMINAL_PROMPT'], '0')
        self.assertNotIn(TOKEN, '\n'.join(log))  # git output is redacted
        self.assertIn('***', '\n'.join(log))

    def test_git_runs_as_the_site_user(self):
        seen = []

        def runner(argv, **kwargs):
            seen.append(kwargs)
            return SimpleNamespace(returncode=0, stdout='b' * 40)
        svc.Deployer(self.site, config(), '', runner=runner).deploy_pull()
        self.assertTrue(seen)
        for kwargs in seen:
            self.assertEqual(kwargs['user'], os.getuid())
            self.assertNotEqual(kwargs['user'], 0)
            self.assertEqual(kwargs['extra_groups'], [])


# ----------------------------------------------------------------------------- releases and rollback

def executing_runner(git_files=None):
    """Run coreutils for real (as the test user), fake git: checkout writes the given files."""
    git_files = git_files or {'index.php': '<?php echo 1;'}
    commands = []

    def runner(argv, **kwargs):
        command = argv[4:] if argv[:1] == ['timeout'] else argv
        commands.append(command)
        if command[0] == 'git':
            if 'rev-parse' in command:
                return SimpleNamespace(returncode=0, stdout='c' * 40 + '\n')
            if 'checkout' in command:
                tree = [a for a in command if a.startswith('--work-tree=')]
                if tree:
                    for name, text in git_files.items():
                        path = os.path.join(tree[0].split('=', 1)[1], name)
                        os.makedirs(os.path.dirname(path), exist_ok=True)
                        with open(path, 'w') as handle:
                            handle.write(text)
            if 'init' in command and '--bare' in command:
                os.makedirs(command[-1], exist_ok=True)
            return SimpleNamespace(returncode=0, stdout='')
        out = subprocess.run(command, cwd=kwargs.get('cwd'), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             universal_newlines=True)
        return SimpleNamespace(returncode=out.returncode, stdout=out.stdout)
    runner.commands = commands
    return runner


class Releases(SimpleTestCase):
    def test_build_switch_prune_and_rollback(self):
        site = temp_site()
        with open(os.path.join(site.docroot, 'index.html'), 'w') as handle:
            handle.write('default page')
        cfg = config(mode='releases', keep=2)
        names = iter(['20250101-000001-aaaa', '20250101-000002-bbbb', '20250101-000003-cccc'])
        runner = executing_runner()
        deployer = svc.Deployer(site, cfg, '', runner=runner)
        deployer.release_name = lambda: next(names)
        first = deployer.deploy()
        self.assertTrue(os.path.islink(site.docroot))
        self.assertEqual(open(os.path.join(site.docroot, 'index.php')).read(), '<?php echo 1;')
        self.assertEqual(deployer.current_release(), first['release'])
        deployer.deploy()
        third = deployer.deploy()
        self.assertEqual(deployer.releases(), ['20250101-000002-bbbb', '20250101-000003-cccc'])  # keep=2
        self.assertEqual(deployer.current_release(), third['release'])
        back = deployer.rollback()
        self.assertEqual(back, {'release': '20250101-000002-bbbb', 'from': '20250101-000003-cccc'})
        self.assertEqual(os.readlink(deployer.current_link()), 'releases/20250101-000002-bbbb')
        with self.assertRaisesRegex(DeployError, 'earlier release'):
            deployer.rollback()
        self.assertTrue(any(c[:2] == ['mv', '-T'] for c in runner.commands))  # atomic switch

    def test_shared_env_and_storage_are_linked_into_releases(self):
        site = temp_site()
        cfg = config(mode='releases')
        runner = executing_runner({'artisan': '#!php', 'storage/logs/.gitignore': '*', 'public/index.php': 'x'})
        deployer = svc.Deployer(site, cfg, '', runner=runner)
        shared = os.path.join(deployer.base, 'shared')
        os.makedirs(shared)
        with open(os.path.join(shared, '.env'), 'w') as handle:
            handle.write('APP_ENV=production\n')
        result = deployer.deploy()
        release = result['dir']
        self.assertTrue(os.path.islink(os.path.join(release, '.env')))
        self.assertTrue(os.path.islink(os.path.join(release, 'storage')))
        self.assertTrue(os.path.isdir(os.path.join(shared, 'storage', 'logs')))

    def test_non_empty_target_is_never_replaced(self):
        site = temp_site()
        with open(os.path.join(site.docroot, 'my-files.php'), 'w') as handle:
            handle.write('x')
        runner = executing_runner()
        for mode in ('releases', 'pull'):
            with self.assertRaisesRegex(DeployError, 'not empty'):
                svc.Deployer(site, config(mode=mode), '', runner=runner).deploy()
        self.assertTrue(os.path.isfile(os.path.join(site.docroot, 'my-files.php')))

    def test_post_steps_whitelist_and_custom_script(self):
        site = temp_site()
        cfg = config(steps=['composer_install', 'artisan_migrate'], custom_script=True, script_timeout=120)
        seen = []

        def runner(argv, **kwargs):
            seen.append(argv)
            return SimpleNamespace(returncode=0, stdout='')
        os.makedirs(os.path.join(site.docroot, '.indianscloud'))
        with open(os.path.join(site.docroot, '.indianscloud', 'deploy.sh'), 'w') as handle:
            handle.write('echo hi\n')
        deployer = svc.Deployer(site, cfg, '', runner=runner, find_composer=lambda: '/usr/bin/composer')
        deployer.post_steps(site.docroot, 'c' * 40)
        self.assertIn(['timeout', '-k', '10', '1800', site.php, '/usr/bin/composer', 'install', '--no-dev', '--no-interaction',
                       '--prefer-dist', '--optimize-autoloader', '--no-ansi'], seen)
        self.assertIn(['timeout', '-k', '10', '1800', site.php, 'artisan', 'migrate', '--force', '--no-interaction', '--no-ansi'], seen)
        self.assertIn(['timeout', '-k', '10', '120', '/bin/bash', '.indianscloud/deploy.sh'], seen)
        with self.assertRaisesRegex(DeployError, 'Composer'):
            svc.Deployer(site, cfg, '', runner=runner, find_composer=lambda: '').post_steps(site.docroot, 'c' * 40)

    def test_history_keeps_the_last_20(self):
        data = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        cfg = config()
        for i in range(25):
            svc.add_history(cfg, {'ts': i, 'state': 'ok'}, ['line %d' % i], base=data)
        items = svc.load_history(cfg, base=data)
        self.assertEqual(len(items), 20)
        self.assertEqual(items[0]['n'], 25)
        self.assertEqual(svc.history_log(cfg, 25, base=data), ['line 24'])
        with self.assertRaises(DeployError):
            svc.history_log(cfg, 1, base=data)


# ----------------------------------------------------------------------------- page

class Pages(SimpleTestCase):
    def test_page_follows_the_policy(self):
        self.assertEqual(helpers.page(views.page, policy={})[0], 403)
        self.assertEqual(helpers.page(views.page, policy={'gitdeploy_for_users': True})[0], 200)
        self.assertEqual(helpers.page(views.page, admin=True)[0], 200)

    def test_template_renders(self):
        html = render_to_string('universalAddons/gitdeploy.html', {'is_admin': False, 'site': MINE})
        self.assertIn('id="ua-gitdeploy"', html)
        self.assertIn('IndiansCloud', html)
        self.assertIn('data-site="%s"' % MINE, html)

    def test_registered(self):
        from django.urls import reverse
        from universalAddons import registry, runner
        self.assertEqual(reverse('ua-gitdeploy'), '/addons/git-deploy/')
        self.assertEqual(reverse('ua-gitdeploy-hook', args=[HOOK]), '/addons/git-deploy/hook/%s/' % HOOK)
        self.assertIn('gitdeploy', [m.key for m in registry.MODULES])
        self.assertEqual(runner.MODULES['gitdeploy'], 'universalAddons.gitdeploy.actions')

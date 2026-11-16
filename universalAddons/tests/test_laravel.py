"""Laravel Toolkit: command whitelist, ownership, .env masking, safe file reads, scheduler, worker
unit, public/ web root, Composer installer check, pages, and the child-domain free subdomain option."""
import getpass
import hashlib
import json
import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.template.loader import get_template, render_to_string
from django.test import RequestFactory, SimpleTestCase

from universalAddons import siteinfo
from universalAddons.laravel import actions, service as lv, views
from universalAddons.laravel.service import LaravelError
from universalAddons.siteinfo import SiteError
from universalAddons.tests import helpers
from universalAddons.tests.helpers import FOREIGN, OWNED

MINE = OWNED[0]
USER = getpass.getuser()


def temp_site(docroot_rel='public_html'):
    """A Site whose home is a fresh temp directory owned by the test user."""
    home = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
    site = siteinfo.Site('example.com', 'examp1234', '/home/example.com', '/home/example.com/public_html',
                         'example.com', '/usr/local/lsws/lsphp82/bin/php')
    site.user = USER
    site.home, site.docroot = home, os.path.join(home, docroot_rel)
    os.makedirs(site.docroot, exist_ok=True)
    return site


def make_app(directory, version='11.9.2', env=None):
    os.makedirs(os.path.join(directory, 'public'), exist_ok=True)
    with open(os.path.join(directory, 'artisan'), 'w') as handle:
        handle.write('#!/usr/bin/env php\n')
    with open(os.path.join(directory, 'composer.json'), 'w') as handle:
        json.dump({'require': {'php': '^8.2', 'laravel/framework': '^11.0'}}, handle)
    vendor = os.path.join(directory, 'vendor', 'laravel', 'framework', 'src', 'Illuminate', 'Foundation')
    os.makedirs(vendor)
    with open(os.path.join(vendor, 'Application.php'), 'w') as handle:
        handle.write("<?php class Application { const VERSION = '%s'; }" % version)
    if env is not None:
        with open(os.path.join(directory, '.env'), 'w') as handle:
            handle.write(env)


class Recorder:
    def __init__(self, answers=None):
        self.calls = []
        self.answers = answers or {}

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        for prefix, answer in self.answers.items():
            if tuple(argv[:len(prefix)]) == prefix:
                code, out = answer(argv, kwargs) if callable(answer) else answer
                return SimpleNamespace(returncode=code, stdout=out)
        return SimpleNamespace(returncode=0, stdout='')


# ----------------------------------------------------------------------------- whitelist

class CommandWhitelist(SimpleTestCase):
    def test_known_commands_build_fixed_argv(self):
        self.assertEqual(lv.build_command('artisan', 'migrate:status'), ['migrate:status', '--no-interaction', '--no-ansi'])
        self.assertEqual(lv.build_command('artisan', 'migrate', {}, confirmed=True)[:2], ['migrate', '--force'])
        self.assertEqual(lv.build_command('composer', 'install', confirmed=True)[:2], ['install', '--no-dev'])
        self.assertIn('--optimize', lv.build_command('composer', 'dump-autoload', {'optimize': True}))
        for name in ('cache:clear', 'config:clear', 'config:cache', 'route:clear', 'route:cache', 'view:clear',
                     'view:cache', 'optimize', 'storage:link', 'queue:restart', 'up'):
            self.assertEqual(lv.build_command('artisan', name)[0], name)

    def test_unknown_commands_and_tools_refused(self):
        for tool, name in (('artisan', 'tinker'), ('artisan', 'db:wipe'), ('artisan', 'migrate:fresh'),
                           ('artisan', 'migrate --force; rm -rf /'), ('composer', 'require'), ('composer', 'exec'),
                           ('shell', 'ls'), (None, None), ('artisan', ['migrate'])):
            with self.assertRaises(LaravelError, msg=(tool, name)):
                lv.build_command(tool, name, confirmed=True)

    def test_dangerous_commands_need_confirmation(self):
        for tool, name in (('artisan', 'migrate'), ('artisan', 'down'), ('composer', 'install'), ('composer', 'update')):
            with self.assertRaisesRegex(LaravelError, 'Confirm'):
                lv.build_command(tool, name)
            with self.assertRaisesRegex(LaravelError, 'Confirm'):
                lv.build_command(tool, name, confirmed='yes')  # only a real true counts

    def test_options_are_typed_and_validated(self):
        self.assertIn('--seed', lv.build_command('artisan', 'migrate', {'seed': True}, True))
        self.assertNotIn('--seed', lv.build_command('artisan', 'migrate', {'seed': False}, True))
        argv = lv.build_command('artisan', 'down', {'secret': 'let-me-in_2024', 'retry': 60}, True)
        self.assertIn('--secret=let-me-in_2024', argv)
        self.assertIn('--retry=60', argv)
        for options in ({'seed': 'yes'}, {'path': '/etc'}, {'retry': 0}, {'retry': 10 ** 6}, {'retry': True},
                        {'retry': '60'}, {'secret': 'x; rm -rf ~'}, {'secret': 'short'}, {'secret': '--force'}, ['x']):
            name = 'migrate' if 'seed' in options or 'path' in options else 'down'
            with self.assertRaises(LaravelError, msg=options):
                lv.build_command('artisan', name, options, True)
        with self.assertRaises(LaravelError):
            lv.build_command('artisan', 'cache:clear', {'store': 'redis'})

    def test_runs_with_the_site_php_in_the_app_directory(self):
        site = temp_site()
        with mock.patch.object(siteinfo, 'run_as', return_value=(0, 'ok')) as run_as:
            actions.run_tool(site, site.docroot, 'artisan', ['migrate:status', '--no-interaction'], lambda t: None)
        self.assertEqual(run_as.call_args.args[1][:3], ['/usr/local/lsws/lsphp82/bin/php', 'artisan', 'migrate:status'])
        self.assertEqual(run_as.call_args.kwargs['cwd'], site.docroot)
        with mock.patch.object(siteinfo, 'run_as', return_value=(1, 'boom')), self.assertRaises(LaravelError):
            actions.run_tool(site, site.docroot, 'artisan', ['up'], lambda t: None)

    def test_run_as_drops_to_the_site_user_with_a_clean_environment(self):
        site = temp_site()
        runner = Recorder()
        siteinfo.run_as(site, ['/usr/bin/php', 'artisan', 'up'], cwd=site.docroot, timeout=120, runner=runner,
                        extra_env={'GIT_CONFIG_PARAMETERS': 'secret'})
        argv, kwargs = runner.calls[0]
        self.assertEqual(argv[:4], ['timeout', '-k', '10', '120'])
        self.assertEqual(argv[4:], ['/usr/bin/php', 'artisan', 'up'])
        self.assertEqual(kwargs['user'], os.getuid())
        self.assertEqual(kwargs['extra_groups'], [])
        self.assertEqual(kwargs['env']['HOME'], site.home)
        self.assertNotIn('PYTHONPATH', kwargs['env'])
        self.assertEqual(kwargs['env']['GIT_CONFIG_PARAMETERS'], 'secret')
        self.assertNotIn('secret', ' '.join(argv))
        with self.assertRaises(SiteError):
            siteinfo.run_as(site, ['echo', 'a\x00b'], runner=runner)


# ----------------------------------------------------------------------------- ownership / ACL

class Access(SimpleTestCase):
    FEATURE = 'laravel_for_users'

    def call(self, view, body, admin=False, on=True, result=None, private=False):
        policy = {self.FEATURE: True} if on else {}
        target = 'universalAddons.privileged.call_private' if private else 'universalAddons.privileged.call'
        with mock.patch(target, return_value=result if result is not None else {}) as runner:
            status, data, session = helpers.post(view, body, admin=admin, policy=policy)
        return status, data, runner

    def test_policy_off_refuses_users(self):
        status, _, runner = self.call(views.info, {'domain': MINE}, on=False)
        self.assertEqual(status, 403)
        runner.assert_not_called()

    def test_owner_cannot_touch_another_site(self):
        bodies = [(views.info, {}), (views.env, {}), (views.logs, {}), (views.scheduler, {'enable': True}),
                  (views.worker, {'enable': True}), (views.worker_logs, {}), (views.public, {'method': 'auto'}),
                  (views.install, {}), (views.command, {'command': {'tool': 'artisan', 'name': 'up'}})]
        for view, extra in bodies:
            status, data, runner = self.call(view, dict(extra, domain=FOREIGN))
            self.assertEqual(status, 403, (view.__name__, data))
            runner.assert_not_called()
        status, _, runner = self.call(views.env_set, {'domain': FOREIGN, 'entry': {'key': 'APP_ENV', 'value': 'x'}},
                                      private=True)
        self.assertEqual(status, 403)
        runner.assert_not_called()

    def test_owner_allowed_on_own_site(self):
        status, _, runner = self.call(views.info, {'domain': MINE, 'path': 'app'})
        self.assertEqual(status, 200)
        runner.assert_called_once_with('laravel', 'info', domain=MINE, path='app')
        status, _, runner = self.call(views.command, {'domain': MINE, 'path': '',
                                                      'command': {'tool': 'artisan', 'name': 'migrate:status'}},
                                      result={'job_id': 'a' * 24})
        self.assertEqual(status, 200)
        runner.assert_called_once_with('laravel', 'command', domain=MINE, path='', tool='artisan',
                                       name='migrate:status', options={}, confirmed=False)

    def test_listing_is_limited_to_own_sites(self):
        status, _, runner = self.call(views.apps, {})
        runner.assert_called_once_with('laravel', 'list', domains=sorted(OWNED))
        status, _, runner = self.call(views.apps, {}, admin=True)
        runner.assert_called_once_with('laravel', 'list', domains=None)

    def test_bad_commands_and_paths_never_reach_the_runner(self):
        for body in ({'command': {'tool': 'artisan', 'name': 'tinker'}},
                     {'command': {'tool': 'artisan', 'name': 'migrate'}},              # unconfirmed
                     {'command': {'tool': 'artisan', 'name': 'up', 'options': {'x': 1}}},
                     {'tool': 'artisan', 'name': 'up'},                                 # not nested
                     {'path': '../other.example.net', 'command': {'tool': 'artisan', 'name': 'up'}},
                     {'path': '/etc', 'command': {'tool': 'artisan', 'name': 'up'}}):
            status, data, runner = self.call(views.command, dict(body, domain=MINE))
            self.assertEqual(status, 400, (body, data))
            runner.assert_not_called()

    def test_env_values_go_through_a_private_spool(self):
        status, _, runner = self.call(views.env_set, {'domain': MINE, 'entry': {'key': 'MAIL_PASSWORD', 'value': 'p@ss:w$rd'}},
                                      private=True)
        self.assertEqual(status, 200)
        runner.assert_called_once_with('laravel', 'env_set', domain=MINE, path='', key='MAIL_PASSWORD', value='p@ss:w$rd')
        for entry in ({'key': 'bad key', 'value': 'x'}, {'key': 'A', 'value': 'two\nlines'}, 'APP_ENV=x'):
            status, _, runner = self.call(views.env_set, {'domain': MINE, 'entry': entry}, private=True)
            self.assertEqual(status, 400, entry)
            runner.assert_not_called()

    def test_composer_install_is_admin_only(self):
        status, _, runner = self.call(views.composer, {})
        self.assertEqual(status, 403)
        runner.assert_not_called()
        status, _, runner = self.call(views.composer, {}, admin=True, result={'job_id': 'b' * 24})
        self.assertEqual(status, 200)
        runner.assert_called_once_with('laravel', 'composer_install')

    def test_jobs_only_visible_to_their_session(self):
        status, _, runner = self.call(views.job, {'job': 'c' * 24})
        self.assertEqual(status, 403)
        runner.assert_not_called()


# ----------------------------------------------------------------------------- .env

ENV = """APP_NAME="My App"
APP_ENV=production
APP_KEY=base64:c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0
APP_DEBUG=true
APP_URL=https://example.com
LOG_LEVEL=debug
DB_PASSWORD='hunter2'
AWS_SECRET_ACCESS_KEY=abcd1234
MAIL_PASSWORD=
# a comment
export STRIPE_KEY=sk_live_x
"""


class EnvMasking(SimpleTestCase):
    def test_only_safe_keys_have_values(self):
        rows = {r['key']: r for r in lv.masked_env(ENV)}
        self.assertEqual(rows['APP_ENV']['value'], 'production')
        self.assertEqual(rows['APP_NAME']['value'], 'My App')
        self.assertEqual(rows['APP_URL']['value'], 'https://example.com')
        self.assertEqual(rows['LOG_LEVEL']['value'], 'debug')
        for key in ('APP_KEY', 'DB_PASSWORD', 'AWS_SECRET_ACCESS_KEY', 'STRIPE_KEY'):
            self.assertTrue(rows[key]['masked'], key)
            self.assertEqual(rows[key]['value'], '')
            self.assertTrue(rows[key]['set'])
        self.assertFalse(rows['MAIL_PASSWORD']['set'])
        text = json.dumps(lv.masked_env(ENV))
        for secret in ('hunter2', 'abcd1234', 'sk_live_x', 'c2VjcmV0'):
            self.assertNotIn(secret, text)

    def test_a_safe_name_with_a_secret_hint_stays_masked(self):
        with mock.patch.object(lv, 'SAFE_ENV_KEYS', lv.SAFE_ENV_KEYS + ('APP_SECRET_TOKEN',)):
            self.assertTrue(lv.masked_env('APP_SECRET_TOKEN=x')[0]['masked'])

    def test_single_key_edits(self):
        self.assertIn('APP_DEBUG=false\n', lv.env_with(ENV, 'APP_DEBUG', 'false'))
        self.assertEqual(lv.env_with(ENV, 'APP_DEBUG', 'false').count('APP_DEBUG'), 1)
        self.assertTrue(lv.env_with(ENV, 'NEW_KEY', 'a b"c').endswith('NEW_KEY="a b\\"c"\n'))
        self.assertIn('STRIPE_KEY=sk_test', lv.env_with(ENV, 'STRIPE_KEY', 'sk_test'))
        self.assertEqual(dict(lv.parse_env(lv.env_with(ENV, 'NEW_KEY', 'a b"c')))['NEW_KEY'], 'a b"c')
        for key, value in (('lower', 'x'), ('A B', 'x'), ('APP_ENV', 'a\nINJECTED=1'), ('APP_ENV', 'x' * 5000)):
            with self.assertRaises(LaravelError):
                lv.env_with(ENV, key, value)

    def test_env_set_backs_up_and_writes_as_the_user(self):
        site = temp_site()
        make_app(site.docroot, env=ENV)
        calls = []

        def fake_run_as(s, argv, **kwargs):
            calls.append(argv)
            return 0, ''
        with mock.patch.object(actions, '_site', return_value=site), \
                mock.patch.object(siteinfo, 'run_as', side_effect=fake_run_as):
            result = actions.env_set('example.com', '', 'APP_DEBUG', 'false')
        self.assertTrue(result['changed'])
        self.assertEqual(calls[0][:3], ['cp', '-p', '--'])               # backup first
        self.assertTrue(calls[0][-1].split('/')[-1].startswith('.env.backup-'))
        self.assertEqual(calls[1][0], 'tee')                             # then the new file, as the site user
        self.assertEqual(calls[-1][:3], ['mv', '-f', '--'])
        self.assertNotIn('hunter2', json.dumps(result))

    def test_info_warns_about_debug_in_production(self):
        site = temp_site()
        make_app(site.docroot, env=ENV)
        result = lv.info(site, '', unit_state=lambda u: {}, cron=lambda s, m: False)
        self.assertEqual(result['laravel'], '11.9.2')
        self.assertEqual(result['php_version'], '8.2')
        self.assertEqual(result['app_env'], 'production')
        self.assertTrue(result['app_debug'])
        self.assertTrue(any('APP_DEBUG' in w for w in result['warnings']))
        self.assertFalse(result['maintenance'])
        self.assertNotIn('hunter2', json.dumps(result))


# ----------------------------------------------------------------------------- detection and safe reads

class Detection(SimpleTestCase):
    def test_finds_apps_in_docroot_and_subdirectories(self):
        site = temp_site()
        make_app(os.path.join(site.docroot, 'shop'))
        make_app(os.path.join(site.docroot, 'a', 'api'))
        os.makedirs(os.path.join(site.docroot, 'plain'))
        with open(os.path.join(site.docroot, 'plain', 'composer.json'), 'w') as handle:
            json.dump({'require': {'symfony/console': '^6'}}, handle)
        open(os.path.join(site.docroot, 'plain', 'artisan'), 'w').close()
        self.assertEqual(sorted(a['path'] for a in lv.scan(site)), ['a/api', 'shop'])
        make_app(site.docroot)
        self.assertEqual([a['path'] for a in lv.scan(site)], [''])

    def test_links_out_of_the_site_are_not_followed(self):
        site = temp_site()
        outside = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        make_app(outside)
        os.symlink(outside, os.path.join(site.docroot, 'linked'))
        self.assertEqual(lv.scan(site), [])
        with self.assertRaises(SiteError):
            lv.app_dir(site, 'linked')
        # a log that is a link to another file is refused, even inside the site
        make_app(site.docroot)
        os.makedirs(os.path.join(site.docroot, 'storage', 'logs'))
        secret = os.path.join(outside, 'shadow')
        with open(secret, 'w') as handle:
            handle.write('root:$6$secret\n')
        os.symlink(secret, os.path.join(site.docroot, 'storage', 'logs', 'laravel.log'))
        with self.assertRaises((OSError, SiteError)):
            lv.log_tail(site, os.path.realpath(site.docroot))

    def test_files_of_other_users_are_refused(self):
        site = temp_site()
        path = os.path.join(site.docroot, 'x.txt')
        with open(path, 'w') as handle:
            handle.write('x')
        self.assertEqual(siteinfo.read_owned(site, path), 'x')
        with self.assertRaises(SiteError):
            siteinfo.read_owned(site, path, uid=os.getuid() + 1)

    def test_log_tail_returns_the_last_200_lines(self):
        site = temp_site()
        make_app(site.docroot)
        logs = os.path.join(site.docroot, 'storage', 'logs')
        os.makedirs(logs)
        with open(os.path.join(logs, 'laravel.log'), 'w') as handle:
            handle.write(''.join('line %d\n' % i for i in range(500)))
        result = lv.log_tail(site, os.path.realpath(site.docroot))
        self.assertEqual(len(result['lines']), 200)
        self.assertEqual(result['lines'][-1], 'line 499')

    def test_paths_are_validated(self):
        for bad in ('../x', '/etc', 'a/../../b', 'a b', 'a;b', '.', 'a//b', '-'):
            if bad == '-':
                self.assertEqual(siteinfo.check_rel(bad), '-')  # a plain name is fine; argv is never a shell
                continue
            with self.assertRaises(SiteError, msg=bad):
                siteinfo.check_rel(bad)
        self.assertEqual(siteinfo.check_rel('public_html/app/'), 'public_html/app')


# ----------------------------------------------------------------------------- scheduler, worker, public/

class Background(SimpleTestCase):
    def test_scheduler_line_in_the_site_crontab(self):
        site = temp_site()
        runner = Recorder({('crontab', '-l'): (0, 'MAILTO=""\n0 3 * * * /bin/true\n')})
        lv.set_scheduler(site, '/home/example.com/public_html', True, runner=runner)
        written = runner.calls[-1][1]['input']
        self.assertIn('* * * * * cd /home/example.com/public_html && /usr/local/lsws/lsphp82/bin/php artisan schedule:run', written)
        self.assertIn('0 3 * * * /bin/true', written)
        self.assertEqual(runner.calls[-1][0], ['crontab', '-u', site.user, '-'])
        runner = Recorder({('crontab', '-l'): (0, written)})
        lv.set_scheduler(site, '/home/example.com/public_html', False, runner=runner)
        self.assertNotIn('schedule:run', runner.calls[-1][1]['input'])
        self.assertIn('/bin/true', runner.calls[-1][1]['input'])
        with self.assertRaises(LaravelError):
            lv.scheduler_line(site, '/home/x/a b; reboot')

    def test_worker_unit_runs_as_the_site_user_in_a_sandbox(self):
        worker = {'domain': 'example.com', 'dir': '/home/example.com/public_html', 'user': 'examp1234',
                  'home': '/home/example.com', 'php': '/usr/local/lsws/lsphp82/bin/php', 'memory_mb': 256}
        unit = lv.render_worker_unit(worker, 239, unified=False)
        for line in ('User=examp1234', 'Group=examp1234', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=',
                     'ProtectSystem=strict', 'ReadWritePaths=/home/example.com/public_html', 'MemoryLimit=256M',
                     'PrivateTmp=yes', 'Restart=always'):
            self.assertIn(line + '\n', unit)
        self.assertIn('ExecStart=/usr/local/lsws/lsphp82/bin/php /home/example.com/public_html/artisan queue:work', unit)
        self.assertNotIn('User=root', unit)
        self.assertIn('MemoryMax=256M', lv.render_worker_unit(worker, 250, unified=True))
        for bad in ({'dir': '/home/x/a b'}, {'user': 'root;x'}, {'queue': 'a b'}):
            with self.assertRaises(LaravelError):
                lv.render_worker_unit(dict(worker, **bad))
        self.assertEqual(lv.unit_name(lv.worker_id('a.com', '/home/a.com/public_html'))[:11], 'cp-laravel-')
        with self.assertRaises(LaravelError):
            lv.unit_name('../../etc')

    def test_docroot_edit_and_method_choice(self):
        text = 'docRoot                   $VH_ROOT/public_html\nvhDomain $VH_NAME\n'
        updated, previous = lv.replace_docroot(text, '/home/a.com/public_html/public')
        self.assertEqual(previous, '$VH_ROOT/public_html')
        self.assertIn('docRoot                   /home/a.com/public_html/public\n', updated)
        with self.assertRaises(LaravelError):
            lv.replace_docroot('docRoot a\ndocRoot b\n', '/x')
        self.assertIn('DocumentRoot /home/a/public',
                      lv.replace_apache_docroot('  DocumentRoot /home/a/public_html\n', '/home/a/public'))
        site = temp_site()
        make_app(os.path.join(site.docroot, 'app'))
        with self.assertRaisesRegex(LaravelError, 'subdirectory'):
            lv.choose_method(site, os.path.realpath(os.path.join(site.docroot, 'app')), 'vhost')
        self.assertEqual(lv.choose_method(site, os.path.realpath(os.path.join(site.docroot, 'app'))), 'htaccess')

    def test_htaccess_block_is_idempotent(self):
        once = lv.with_block('RewriteEngine On\n')
        self.assertEqual(lv.with_block(once), once)
        self.assertEqual(lv.strip_block(once), 'RewriteEngine On\n')
        self.assertIn('RewriteRule ^(?!public/)(.*)$ public/$1 [L]', once)

    def test_vhost_move_restores_on_failed_restart(self):
        site = temp_site()
        make_app(site.docroot)
        vhosts = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        os.makedirs(os.path.join(vhosts, site.vhost))
        conf = os.path.join(vhosts, site.vhost, 'vhost.conf')
        original = 'docRoot                   $VH_ROOT/public_html\n'
        with open(conf, 'w') as handle:
            handle.write(original)
        state = os.path.join(vhosts, 'state.json')
        with mock.patch.object(actions, '_site', return_value=site), mock.patch.object(lv, 'STATE_FILE', state), \
                mock.patch('universalAddons.htaccess.service.BACKUP_DIR', os.path.join(vhosts, 'bk')):
            with self.assertRaisesRegex(LaravelError, 'restored'):
                actions.point_public('example.com', '', 'vhost', restart=lambda: False, vhosts=vhosts, apache_dirs=())
            self.assertEqual(open(conf).read(), original)
            result = actions.point_public('example.com', '', 'vhost', restart=lambda: True, vhosts=vhosts, apache_dirs=())
        self.assertEqual(result['method'], 'vhost')
        self.assertIn(os.path.join(os.path.realpath(site.docroot), 'public'), open(conf).read())


# ----------------------------------------------------------------------------- composer installer

class ComposerInstaller(SimpleTestCase):
    def runner(self, content, signature):
        def answer(argv, kwargs):
            if '-o' in argv:
                with open(argv[argv.index('-o') + 1], 'wb') as handle:
                    handle.write(content)
                return 0, ''
            if argv[0] == 'curl':
                return 0, signature
            return 0, 'Composer successfully installed'
        return Recorder({('curl',): answer, ('/usr/bin/php',): answer})

    def test_hash_mismatch_installs_nothing(self):
        runner = self.runner(b'<?php evil();', 'a' * 96)
        work = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        with self.assertRaisesRegex(LaravelError, 'SHA-384'):
            actions.install_composer(runner, target=os.path.join(work, 'composer'), workdir=work)
        self.assertFalse(any(argv[0] == '/usr/bin/php' for argv, _ in runner.calls))
        self.assertEqual(os.listdir(work), [])  # temporary files removed

    def test_verified_installer_runs(self):
        content = b'<?php // installer'
        runner = self.runner(content, hashlib.sha384(content).hexdigest() + '\n')
        work = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
        target = os.path.join(work, 'composer')
        open(target, 'w').close()
        result = actions.install_composer(runner, target=target, workdir=work)
        self.assertEqual(result['path'], target)
        php = [argv for argv, _ in runner.calls if argv[0] == '/usr/bin/php'][0]
        self.assertIn('--install-dir=' + work, php)
        self.assertIn(lv.COMPOSER_SIG_URL, [a for argv, _ in runner.calls for a in argv])

    def test_composer_found_in_the_usual_places(self):
        self.assertEqual(lv.find_composer(lambda p: p == '/usr/bin/composer'), '/usr/bin/composer')
        self.assertEqual(lv.find_composer(lambda p: False), '')


# ----------------------------------------------------------------------------- pages

class Pages(SimpleTestCase):
    def test_page_follows_the_policy(self):
        self.assertEqual(helpers.page(views.page, policy={})[0], 403)
        status, values = helpers.page(views.page, policy={'laravel_for_users': True})
        self.assertEqual(status, 200)
        self.assertIs(values['is_admin'], False)
        self.assertEqual(helpers.page(views.page, admin=True)[0], 200)

    def test_template_renders(self):
        html = render_to_string('universalAddons/laravel.html', {'is_admin': True, 'site': 'a.com'})
        self.assertIn('id="ua-laravel"', html)
        self.assertIn('data-site="a.com"', html)
        self.assertIn('IndiansCloud', html)

    def test_site_pages_link_to_the_toolkit(self):
        for name in ('websiteFunctions/website.html', 'baseTemplate/siteWorkspace.html'):
            source = get_template(name).template.source
            self.assertIn('/addons/laravel/?site={{ domain|urlencode }}', source, name)
            self.assertIn('/addons/git-deploy/?site={{ domain|urlencode }}', source, name)

    def test_registered(self):
        from django.urls import reverse
        from universalAddons import registry, runner
        self.assertEqual(reverse('ua-laravel'), '/addons/laravel/')
        self.assertIn('laravel', [m.key for m in registry.MODULES])
        self.assertEqual(runner.MODULES['laravel'], 'universalAddons.laravel.actions')


# ----------------------------------------------------------------------------- free subdomain for child domains

class ChildDomainFreeSubdomain(SimpleTestCase):
    def test_create_domain_template_offers_the_option(self):
        source = get_template('websiteFunctions/createDomain.html').template.source
        for needle in ('{% if free_subdomain_base %}', 'id="useFreeSubdomain"', '{% trans "Use a free subdomain" %}',
                       'ng-change="checkFreeSubdomain()"', 'ng-model="freeSubdomainLabel"'):
            self.assertIn(needle, source)
        html = render_to_string('websiteFunctions/createDomain.html', {'free_subdomain_base': 'hostedon.example.org',
                                                                       'websiteList': ['a.com'], 'phps': ['PHP 8.2'],
                                                                       'defaultSite': 'a.com', 'Randam_String': 'AbC123'})
        self.assertIn('Use a free subdomain', html)
        self.assertIn('.hostedon.example.org', html)
        html = render_to_string('websiteFunctions/createDomain.html', {'free_subdomain_base': '', 'websiteList': ['a.com'],
                                                                       'phps': ['PHP 8.2'], 'defaultSite': 'a.com'})
        self.assertNotIn('id="useFreeSubdomain"', html)

    def test_controller_sends_the_free_subdomain_and_uses_the_check_endpoint(self):
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        for path in ('websiteFunctions/static/websiteFunctions/websiteFunctions.js', 'static/websiteFunctions/websiteFunctions.js'):
            text = open(os.path.join(root, path)).read()
            start = text.index("app.controller('websitePages'")
            controller = text[start:text.index('app.controller(', start + 10)]
            self.assertIn("'/addons/free-subdomains/ajax/check'", controller, path)
            self.assertIn('freeSubdomain: freeSubdomain', controller, path)

    def test_check_endpoint_serves_child_domain_creators(self):
        from freeSubdomains import service, views as fviews
        request = RequestFactory().post('/x', data=json.dumps({'label': 'blog', 'purpose': 'child'}),
                                        content_type='application/json')
        request.session = {'userID': 7}
        with mock.patch('plogical.acl.ACLManager.loadedACL', return_value={'admin': 0, 'createWebsite': 0}), \
                mock.patch('plogical.acl.ACLManager.findAllSites', return_value=['mine.example.com']), \
                mock.patch.object(service, 'load_config', return_value={}), \
                mock.patch.object(service, 'offered_base', return_value='hostedon.example.org'), \
                mock.patch.object(service, 'availability', return_value=('blog.hostedon.example.org', None)):
            body = json.loads(fviews.check(request).content)
        self.assertEqual((body['status'], body['available']), (1, True))
        with mock.patch('plogical.acl.ACLManager.loadedACL', return_value={'admin': 0, 'createWebsite': 0}), \
                mock.patch('plogical.acl.ACLManager.findAllSites', return_value=[]):
            self.assertEqual(fviews.check(request).status_code, 403)

    def test_create_domain_view_passes_the_base(self):
        source = open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                   'websiteFunctions', 'website.py')).read()
        start = source.index("'websiteFunctions/createDomain.html'")
        self.assertIn("'free_subdomain_base': free_subdomain_base", source[start:start + 400])


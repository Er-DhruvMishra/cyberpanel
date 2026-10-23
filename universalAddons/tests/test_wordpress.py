import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from universalAddons.wordpress import service as wp, views
from universalAddons.wordpress.service import WPError


class Recorder:
    """Fake subprocess.run: answers by matching the WP-CLI sub-command (args after --no-color)."""

    def __init__(self, answers=None, default=(0, '')):
        self.answers = answers or {}
        self.default = default
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        key = tuple(argv[argv.index('--no-color') + 1:]) if '--no-color' in argv else tuple(argv)
        for prefix, answer in self.answers.items():
            if key[:len(prefix)] == prefix:
                code, out = answer(argv, kwargs) if callable(answer) else answer
                return SimpleNamespace(returncode=code, stdout=out)
        return SimpleNamespace(returncode=self.default[0], stdout=self.default[1])

    def wp_calls(self):
        return [tuple(a[a.index('--no-color') + 1:]) for a, _ in self.calls if '--no-color' in a]


def site(docroot='/home/example.com/public_html'):
    return wp.Site('example.com', 'examp1234', docroot, '/usr/local/lsws/lsphp81/bin/php')


class SiteBasics(unittest.TestCase):
    def test_runs_as_site_user_with_site_php(self):
        runner = Recorder()
        site().wp('plugin', 'list', runner=runner)
        argv = runner.calls[0][0]
        self.assertEqual(argv[:6], ['sudo', '-u', 'examp1234', '-H', '--', '/usr/local/lsws/lsphp81/bin/php'])
        self.assertIn('--path=/home/example.com/public_html', argv)
        self.assertNotIn('--allow-root', argv)

    def test_rejects_unsafe_sites(self):
        for args in (('bad domain', 'u', '/home/x/public_html'), ('a.com', 'root;id', '/home/x'),
                     ('a.com', 'u', '/etc/wordpress'), ('a.com', 'u', '/home/x/../../etc')):
            with self.assertRaises(WPError, msg=args):
                wp.Site(args[0], args[1], args[2], '/usr/bin/php')

    def test_php_for_vhost(self):
        vhosts = tempfile.mkdtemp()
        os.makedirs(os.path.join(vhosts, 'a.com'))
        with open(os.path.join(vhosts, 'a.com', 'vhost.conf'), 'w') as handle:
            handle.write('extprocessor x {\n  path /usr/local/lsws/lsphp81/bin/lsphp\n}\n')
        with mock.patch('os.path.exists', side_effect=lambda p: p == '/usr/local/lsws/lsphp81/bin/php'):
            self.assertEqual(wp.php_for_vhost('a.com', vhosts), '/usr/local/lsws/lsphp81/bin/php')
        self.assertEqual(wp.php_for_vhost('missing.com', vhosts), '/usr/bin/php')

    def test_find_installs(self):
        root = tempfile.mkdtemp()
        a = os.path.join(root, 'a', 'public_html')
        b = os.path.join(root, 'b', 'public_html')
        c = os.path.join(root, 'c', 'public_html')
        for path in (a, b, c):
            os.makedirs(path)
        open(os.path.join(a, 'wp-config.php'), 'w').close()
        open(os.path.join(root, 'b', 'wp-config.php'), 'w').close()  # config above docroot
        open(os.path.join(b, 'wp-load.php'), 'w').close()
        found = wp.find_installs([('a.com', 'u', a, 'a.com'), ('b.com', 'u', b, 'b.com'), ('c.com', 'u', c, 'c.com')])
        self.assertEqual([f['domain'] for f in found], ['a.com', 'b.com'])


class Health(unittest.TestCase):
    def test_health_check_parses_status_and_fatal_page(self):
        ok = Recorder({('curl',): (0, '<html>fine</html>\n200')})
        self.assertTrue(wp.health_check(site(), 'https://example.com', ok)['ok'])
        argv = ok.calls[0][0]
        self.assertIn('example.com:443:127.0.0.1', argv)
        broken = Recorder({('curl',): (0, 'There has been a critical error on this website.\n500')})
        result = wp.health_check(site(), 'https://example.com', broken)
        self.assertEqual((result['ok'], result['fatal_marker']), (False, True))
        with self.assertRaises(WPError):
            wp.health_check(site(), 'javascript:alert(1)', ok)


class SafeUpdate(unittest.TestCase):
    def test_rolls_back_when_update_breaks_site(self):
        health = iter(['ok\n200', 'There has been a critical error\n500'])
        runner = Recorder({('option', 'get', 'home'): (0, 'https://example.com\n'),
                           ('curl',): lambda a, k: (0, next(health))})
        with mock.patch.object(wp, 'snapshot', return_value='20261024-010101-abcd'), \
                mock.patch.object(wp, 'rollback') as rollback:
            with self.assertRaisesRegex(WPError, 'rolled back to snapshot 20261024-010101-abcd'):
                wp.safe_update(site(), 'plugins', runner)
        rollback.assert_called_once()
        self.assertIn(('plugin', 'update', '--all'), runner.wp_calls())

    def test_keeps_update_when_healthy(self):
        runner = Recorder({('option', 'get', 'home'): (0, 'https://example.com\n'), ('curl',): (0, 'ok\n200')})
        with mock.patch.object(wp, 'snapshot', return_value='20261024-010101-abcd'), \
                mock.patch.object(wp, 'rollback') as rollback, mock.patch.object(wp, 'prune_snapshots'):
            result = wp.safe_update(site(), 'all', runner)
        rollback.assert_not_called()
        self.assertEqual(result['snapshot'], '20261024-010101-abcd')
        calls = runner.wp_calls()
        self.assertLess(calls.index(('core', 'update')), calls.index(('plugin', 'update', '--all')))

    def test_bad_scope(self):
        with self.assertRaises(WPError):
            wp.safe_update(site(), 'everything', Recorder())


class SettingsAndHardening(unittest.TestCase):
    def test_wp_cron_toggle_sets_constant_and_cron(self):
        runner = Recorder()
        written = []
        wp.set_flag(site(), 'DISABLE_WP_CRON', True, runner, cron_writer=lambda s, e, r: written.append(e))
        self.assertIn(('config', 'set', 'DISABLE_WP_CRON', 'true', '--raw', '--type=constant'), runner.wp_calls())
        self.assertEqual(written, [True])

    def test_site_cron_replaces_only_its_own_line(self):
        s = site()
        existing = '0 1 * * * /other/job\n' + wp.cron_line(s) + '\n'
        runner = Recorder({('crontab', '-l'): (0, existing)})
        wp.write_site_cron(s, False, runner)
        written = [k.get('input') for a, k in runner.calls if a[:2] == ['crontab', '-u']][0]
        self.assertEqual(written, '0 1 * * * /other/job\n')
        runner = Recorder({('crontab', '-l'): (0, existing)})
        wp.write_site_cron(s, True, runner)
        written = [k.get('input') for a, k in runner.calls if a[:2] == ['crontab', '-u']][0]
        self.assertEqual(written.count('cp-ua-wpcron'), 1)

    def test_xmlrpc_block_keeps_existing_rules(self):
        directory = tempfile.mkdtemp()
        with open(os.path.join(directory, '.htaccess'), 'w') as handle:
            handle.write('# BEGIN WordPress\nRewriteRule . /index.php [L]\n# END WordPress\n')
        s = wp.Site('example.com', 'u', '/home/example.com/public_html', '/usr/bin/php')
        s.docroot = directory
        captured = {}

        def runner(argv, **kwargs):
            captured['text'] = kwargs.get('input')
            return SimpleNamespace(returncode=0, stdout='')
        wp.set_xmlrpc_block(s, True, runner)
        self.assertTrue(captured['text'].startswith('# BEGIN cp-ua xmlrpc'))
        self.assertIn('# BEGIN WordPress', captured['text'])
        with open(os.path.join(directory, '.htaccess'), 'w') as handle:
            handle.write(captured['text'])
        wp.set_xmlrpc_block(s, False, runner)
        self.assertEqual(captured['text'], '# BEGIN WordPress\nRewriteRule . /index.php [L]\n# END WordPress\n')

    def test_config_secret_written_without_command_line(self):
        with tempfile.NamedTemporaryFile('w', suffix='.php', delete=False) as handle:
            handle.write("<?php\ndefine( 'DB_NAME', 'db' );\ndefine('DB_PASSWORD',\"old\");\n")
        wp.set_config_secret(handle.name, 'DB_PASSWORD', "p'w\\x")
        with open(handle.name) as result:
            text = result.read()
        self.assertIn("define( 'DB_PASSWORD', 'p\\'w\\\\x' )", text)
        self.assertIn("define( 'DB_NAME', 'db' )", text)
        if shutil.which('php'):
            check = subprocess.run(['php', '-r', 'include $argv[1]; echo DB_PASSWORD;', handle.name],
                                   stdout=subprocess.PIPE, universal_newlines=True)
            self.assertEqual(check.stdout, "p'w\\x")
        os.unlink(handle.name)

    def test_manage_item_validation(self):
        runner = Recorder()
        wp.manage_item(site(), 'plugin', 'update', 'akismet', runner)
        for args in (('plugin', 'update', '../x'), ('plugin', 'eval', 'x'), ('core', 'update', 'x'),
                     ('theme', 'deactivate', 'twentytwenty')):
            with self.assertRaises(WPError, msg=args):
                wp.manage_item(site(), *args, runner=runner)


class LoginAndInstall(unittest.TestCase):
    def test_one_time_login_stores_only_a_hash(self):
        stored = {}

        def option_update(argv, kwargs):
            stored['value'] = json.loads(argv[argv.index('cp_ua_login_token') + 1])
            return 0, 'Success'
        runner = Recorder({('user', 'list'): (0, '[{"ID": 3, "user_login": "editor-boss"}]'),
                           ('option', 'update', 'cp_ua_login_token'): option_update,
                           ('option', 'get', 'home'): (0, 'https://example.com/\n')})
        result = wp.one_time_login(site(), runner)
        token = result['url'].split('cp_ua_login=', 1)[1]
        self.assertEqual(stored['value']['hash'], hashlib.sha256(token.encode()).hexdigest())
        self.assertNotIn(token, json.dumps(stored))
        self.assertEqual(stored['value']['user'], 3)
        self.assertTrue(result['url'].startswith('https://example.com/?cp_ua_login='))

    @unittest.skipUnless(shutil.which('php'), 'php not installed')
    def test_mu_plugin_is_valid_php(self):
        with tempfile.NamedTemporaryFile('w', suffix='.php', delete=False) as handle:
            handle.write(wp.MU_PLUGIN)
        result = subprocess.run(['php', '-l', handle.name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True)
        os.unlink(handle.name)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_install_validation_and_secret_handling(self):
        for args in (('', 'boss', 'a@b.com'), ('Shop', 'admin', 'a@b.com'), ('Shop', 'boss', 'nope'),
                     ('Sh\nop', 'boss', 'a@b.com')):
            with self.assertRaises(WPError, msg=args):
                wp.validate_install(*args)
        docroot = tempfile.mkdtemp()
        open(os.path.join(docroot, 'index.html'), 'w').close()
        s = wp.Site('example.com', 'u', '/home/example.com/public_html', '/usr/bin/php')
        s.docroot = docroot
        runner = Recorder()
        result = wp.install_wordpress(s, 'Shop', 'boss', 'boss@example.com', lambda: ('db1', 'db1', 'S3cret!'),
                                      runner=runner)
        self.assertNotIn('admin_password', result)
        for argv, kwargs in runner.calls:
            self.assertFalse(any('S3cret!' in a for a in argv), argv)
        self.assertTrue(any(k.get('input') == 'S3cret!\n' for _, k in runner.calls))
        self.assertFalse(os.path.exists(os.path.join(docroot, 'index.html')))

    def test_install_refuses_non_empty_docroot(self):
        docroot = tempfile.mkdtemp()
        open(os.path.join(docroot, 'shop.php'), 'w').close()
        s = wp.Site('example.com', 'u', '/home/example.com/public_html', '/usr/bin/php')
        s.docroot = docroot
        with self.assertRaisesRegex(WPError, 'not empty'):
            wp.install_wordpress(s, 'Shop', 'boss', 'b@example.com', lambda: None, runner=Recorder())

    def test_clone_guards(self):
        a = site()
        with self.assertRaisesRegex(WPError, 'same'):
            wp.clone(a, a, lambda: None, runner=Recorder())


class WordPressViews(SimpleTestCase):
    def post(self, view, body, is_admin=1):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': is_admin}):
            response = view(request)
        return response.status_code, json.loads(response.content)

    def test_admin_only(self):
        for name in ('sites', 'info', 'item', 'flag', 'autoupdates', 'hardening', 'fix', 'performance', 'login',
                     'snapshots', 'update', 'snapshot', 'rollback', 'clone', 'push', 'install', 'wpcli', 'job'):
            with mock.patch('universalAddons.privileged.call') as call:
                self.assertEqual(self.post(getattr(views, name), {}, is_admin=0)[0], 403, name)
            call.assert_not_called()

    def test_validation_before_runner(self):
        bad = [(views.item, {'domain': 'a.com', 'kind': 'plugin', 'action': 'eval', 'slug': 'x'}),
               (views.flag, {'domain': 'a.com', 'flag': 'WP_HOME', 'enable': True}),
               (views.fix, {'domain': 'a.com', 'fix': 'rm'}),
               (views.update, {'domain': 'a.com', 'scope': 'x'}),
               (views.rollback, {'domain': 'a.com', 'snapshot': '../x'}),
               (views.clone, {'source': 'a.com', 'target': 'a.com'}),
               (views.info, {'domain': 'not a domain'})]
        with mock.patch('universalAddons.privileged.call') as call:
            for view, body in bad:
                self.assertEqual(self.post(view, body)[0], 400, body)
        call.assert_not_called()

    def test_update_forwarded(self):
        with mock.patch('universalAddons.privileged.call', return_value={'job_id': 'j'}) as call:
            self.post(views.update, {'domain': 'Example.com', 'scope': 'plugins'})
        call.assert_called_once_with('wordpress', 'update', domain='example.com', scope='plugins')


if __name__ == '__main__':
    unittest.main()

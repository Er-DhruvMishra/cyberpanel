import json
import os
import shutil
import tempfile
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import include, path

from universalAddons.apache import actions, service as sv, views
from universalAddons.tests.test_limits import USER, VHOST

# The module is not in universalAddons/urls.py yet: give the page test its own URLconf.
from CyberCP.urls import urlpatterns as _project_urls  # noqa: E402

urlpatterns = [path('addons/apache/', include('universalAddons.apache.urls'))] + list(_project_urls)

SITE = {'domain': 'example.com', 'user': USER, 'state': 1}
TOTAL_MB = 3736  # the production host
PORT = 8086
OK = {'scheme': 'https', 'status': '200', 'fingerprint': 'title:Example', 'redirect': ''}
VHOST_NO_ACME = VHOST[:VHOST.index('context /.well-known/acme-challenge')]


def layout_in(tmp, version='72'):
    layout = sv.fpm_layout(version)
    layout.update(pool_dir=os.path.join(tmp, 'php%s-fpm.d' % version), run_dir='/var/opt/remi/php%s/run/php-fpm' % version)
    os.makedirs(layout['pool_dir'], exist_ok=True)
    return layout


class FakeServices:
    def __init__(self, answers, httpd_ok=True, fpm_ok=True, reload_ok=True):
        self.answers, self.calls = list(answers), []
        self.httpd_ok, self.fpm_ok, self.reload_ok = httpd_ok, fpm_ok, reload_ok

    def probe(self, domain):
        self.calls.append('probe')
        return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]

    def httpd_test(self):
        self.calls.append('httpd -t')
        return self.httpd_ok, 'Syntax OK' if self.httpd_ok else 'AH00526: Syntax error on line 3'

    def fpm_test(self, layout):
        self.calls.append('php-fpm -t')
        return self.fpm_ok, 'test is successful' if self.fpm_ok else 'ERROR: unknown entry'

    def reload_or_start(self, unit):
        self.calls.append('reload ' + unit)
        return self.reload_ok

    def restart_ols(self):
        self.calls.append('restart ols')
        return True


class Rendering(SimpleTestCase):
    def setUp(self):
        self.layout = sv.fpm_layout('74')
        self.facts = {'domain': 'example.com', 'user': USER, 'docroot': '/home/example.com/public_html',
                      'aliases': ['www.example.com', 'shop.example.org', 'bad alias;'], 'home': '/home/example.com'}

    def test_base_conf_is_loopback_only_and_small(self):
        text = sv.render_base_conf(PORT)
        self.assertIn('Listen 127.0.0.1:8086', text)
        self.assertNotIn('Listen 80', text)
        self.assertNotIn(':443', text)
        self.assertIn('MaxRequestWorkers        32', text)
        self.assertIn('RemoteIPInternalProxy 127.0.0.1', text)
        self.assertIn('Require all denied', text)  # catch-all default vhost
        for port in (80, 443, 8090, 7080, 0, 70000, True):
            with self.assertRaises(sv.ApacheError):
                sv.render_base_conf(port)

    def test_site_conf(self):
        text = sv.render_site_conf(self.facts, PORT, self.layout)
        self.assertIn('<VirtualHost 127.0.0.1:8086>', text)
        self.assertIn('ServerName example.com', text)
        self.assertIn('ServerAlias www.example.com shop.example.org\n', text)
        self.assertIn('DocumentRoot "/home/example.com/public_html"', text)
        self.assertIn('AllowOverride All', text)
        self.assertIn('SetHandler "proxy:unix:/var/opt/remi/php74/run/php-fpm/cp-ua-example.com.sock|fcgi://cp-ua-example.com/"', text)
        self.assertIn('SetEnvIf X-Forwarded-Proto "^https$" HTTPS=on', text)
        self.assertNotIn('FollowSymLinks\n', text)
        with self.assertRaises(sv.ApacheError):
            sv.render_site_conf(dict(self.facts, docroot='/etc/../root'), PORT, self.layout)
        with self.assertRaises(sv.ApacheError):
            sv.render_site_conf(dict(self.facts, docroot='/home/other.com/public_html'), PORT, self.layout)

    def test_pool(self):
        pool = sv.validate_pool({}, TOTAL_MB)
        text = sv.render_pool(self.facts, pool, self.layout, 'nobody', 'nobody')
        for line in ('[cp-ua-example.com]', 'user = %s' % USER, 'group = %s' % USER,
                     'listen = /var/opt/remi/php74/run/php-fpm/cp-ua-example.com.sock', 'listen.owner = nobody',
                     'listen.group = nobody', 'listen.mode = 0660', 'pm = ondemand', 'pm.max_children = 5',
                     'pm.max_requests = 500', 'php_admin_value[open_basedir] = /home/example.com/:/tmp/',
                     'php_admin_value[memory_limit] = 256M'):
            self.assertIn(line + '\n', text)
        self.assertNotIn('pm.start_servers', text)
        dynamic = sv.render_pool(self.facts, sv.validate_pool({'pm': 'dynamic', 'start_servers': 2, 'max_spare_servers': 3},
                                                              TOTAL_MB), self.layout, 'apache', 'apache')
        self.assertIn('pm.start_servers = 2\npm.min_spare_servers = 1\npm.max_spare_servers = 3\n', dynamic)
        with self.assertRaises(sv.ApacheError):
            sv.render_pool(dict(self.facts, user='root;x'), pool, self.layout, 'nobody', 'nobody')

    def test_ols_block(self):
        block = sv.render_vhost_block(PORT, add_acme=False)
        self.assertTrue(block.startswith('# BEGIN cp-ua-apache'))
        self.assertIn('extprocessor cpua_apache {\n  type                    proxy\n  address                 127.0.0.1:8086\n', block)
        self.assertIn('context / {\n  type                    proxy\n  handler                 cpua_apache\n', block)
        self.assertNotIn('acme-challenge', block)
        self.assertIn('location                %s' % sv.ACME_LOCATION, sv.render_vhost_block(PORT, add_acme=True))
        self.assertTrue(sv.braces_balanced(block))


class VhostEditing(SimpleTestCase):
    def test_block_before_vhssl_keeps_ssl_and_is_idempotent(self):
        once = sv.apply_block(VHOST, PORT)
        self.assertEqual(once.count(sv.MARK_BEGIN), 1)
        self.assertLess(once.index(sv.MARK_BEGIN), once.index('vhssl  {'))
        self.assertIn('certFile                /etc/letsencrypt/live/example.com/fullchain.pem', once)
        self.assertEqual(sv.apply_block(once, PORT), once)
        self.assertTrue(sv.braces_balanced(once))
        moved = sv.apply_block(once, 8087)
        self.assertEqual(moved.count(sv.MARK_BEGIN), 1)
        self.assertIn('127.0.0.1:8087', moved)
        self.assertNotIn('127.0.0.1:8086', moved)

    def test_remove_restores_the_original(self):
        self.assertEqual(sv.remove_block(sv.apply_block(VHOST, PORT)), sv.remove_block(VHOST))
        self.assertEqual(sv.remove_block(VHOST).count('{'), VHOST.count('{'))
        self.assertFalse(sv.block_present(sv.remove_block(sv.apply_block(VHOST, PORT))))

    def test_acme_challenge_stays_on_ols(self):
        with_acme = sv.apply_block(VHOST, PORT)
        self.assertEqual(with_acme.count('context /.well-known/acme-challenge'), 1)  # CyberPanel's own context is kept
        without = sv.apply_block(VHOST_NO_ACME, PORT)
        self.assertEqual(without.count('context /.well-known/acme-challenge'), 1)  # ours is added inside the block
        inside = without[without.index(sv.MARK_BEGIN):without.index(sv.MARK_END)]
        self.assertIn('context /.well-known/acme-challenge', inside)
        self.assertEqual(sv.apply_block(without, PORT), without)
        self.assertFalse(sv.block_present(sv.remove_block(without)))

    def test_brace_balance_and_conflicts(self):
        with self.assertRaisesRegex(sv.ApacheError, 'never closed'):
            sv.apply_block(VHOST.replace('}\n\nphpIniOverride', '\nphpIniOverride', 1), PORT)
        with self.assertRaisesRegex(sv.ApacheError, 'without a block'):
            sv.apply_block(VHOST + '}\n', PORT)
        with self.assertRaisesRegex(sv.ApacheError, 'context /'):
            sv.apply_block(VHOST + '\ncontext / {\n  location $DOC_ROOT/\n}\n', PORT)
        self.assertTrue(sv.braces_balanced(VHOST))  # %{Referer}i inside a value is not structure

    def test_parse_vhost(self):
        facts = sv.parse_vhost(VHOST, 'example.com', USER)
        self.assertEqual(facts['php'], '72')
        self.assertEqual(facts['docroot'], '/home/example.com/public_html')
        self.assertEqual(facts['aliases'], ['www.example.com'])
        with self.assertRaisesRegex(sv.ApacheError, 'no extprocessor'):
            sv.parse_vhost(VHOST, 'example.com', 'other123')


class PoolPolicy(SimpleTestCase):
    def test_defaults_for_this_host(self):
        self.assertEqual(dict(sv.default_pool(TOTAL_MB)), {'pm': 'ondemand', 'max_children': 5, 'start_servers': 1,
                                                          'min_spare_servers': 1, 'max_spare_servers': 2,
                                                          'max_requests': 500, 'memory_limit_mb': 256})
        self.assertEqual(sv.pool_bounds(TOTAL_MB, 256)['max_children'], (1, 7))
        self.assertEqual(sv.pool_bounds(TOTAL_MB)['memory_limit_mb'], (32, 928))
        self.assertEqual(sv.default_pool(1024)['max_children'], 2)

    def test_bounds(self):
        self.assertEqual(sv.validate_pool({'max_children': '7'}, TOTAL_MB)['max_children'], 7)
        self.assertEqual(sv.validate_pool({'max_children': 14, 'memory_limit_mb': 128}, TOTAL_MB)['max_children'], 14)
        bad = [{'max_children': 8}, {'max_children': 0}, {'memory_limit_mb': 2048}, {'memory_limit_mb': 16},
               {'max_requests': -1}, {'max_requests': 100001}, {'pm': 'adaptive'}, {'max_children': True},
               {'max_children': '5; rm'}, {'listen': '/tmp/x'},
               {'pm': 'dynamic', 'min_spare_servers': 3, 'max_spare_servers': 2},
               {'pm': 'dynamic', 'start_servers': 3, 'max_spare_servers': 2},
               {'pm': 'dynamic', 'max_children': 2, 'max_spare_servers': 3, 'start_servers': 1}]
        for data in bad:
            with self.assertRaises(sv.ApacheError, msg=data):
                sv.validate_pool(data, TOTAL_MB)
        with self.assertRaisesRegex(sv.ApacheError, 'half of this server'):
            sv.validate_pool({'max_children': 8}, TOTAL_MB)
        with self.assertRaises(sv.ApacheError):
            sv.validate_pool('pm=static', TOTAL_MB)

    def test_ram_estimate(self):
        pool = sv.validate_pool({'pm': 'static', 'max_children': 4, 'memory_limit_mb': 128}, TOTAL_MB)
        self.assertEqual(sv.pool_ram(pool), {'idle_mb': 100, 'peak_mb': 240, 'worst_mb': 512})
        self.assertEqual(sv.pool_ram(sv.default_pool(TOTAL_MB))['idle_mb'], 0)


class Plans(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.vhosts = os.path.join(self.tmp, 'vhosts')
        self.conf_d = os.path.join(self.tmp, 'conf.d')
        os.makedirs(os.path.join(self.vhosts, 'example.com'))
        os.makedirs(self.conf_d)
        self.vhost = os.path.join(self.vhosts, 'example.com', 'vhost.conf')
        with open(self.vhost, 'w') as handle:
            handle.write(VHOST)
        self.layouts = {'72': layout_in(self.tmp, '72'), '74': layout_in(self.tmp, '74')}
        self.pool = sv.validate_pool({}, TOTAL_MB)
        self.backups = os.path.join(self.tmp, 'backups')

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def plan(self, mode='apache', pool=None):
        return sv.plan(SITE, mode, pool or (None if mode == 'ols' else self.pool), PORT, self.layouts, 'nobody', 'nobody',
                       self.vhosts, self.conf_d)

    def files(self):
        return {name: os.path.exists(path) for name, path in (
            ('httpd', os.path.join(self.conf_d, 'cp-ua-example.com.conf')),
            ('pool', os.path.join(self.layouts['72']['pool_dir'], 'cp-ua-example.com.conf')))}

    def apply(self, result, services):
        return sv.apply_plan(result, services=services, backup_root=self.backups, sleep=lambda s: None)

    def test_plan_lists_three_files(self):
        result = self.plan()
        self.assertEqual([c['role'] for c in result['changes']], ['vhost', 'httpd', 'pool'])
        self.assertEqual(result['php'], '72')
        self.assertTrue(result['changed'])
        self.assertIn('+context / {', result['diff'])
        self.assertEqual(len(result['token']), 32)
        public = sv.public_plan(result)
        self.assertNotIn('changes', public)
        self.assertEqual([f['action'] for f in public['files']], ['modify', 'create', 'create'])

    def test_missing_fpm_and_tune_needs_apache_mode(self):
        with self.assertRaisesRegex(sv.ApacheError, 'PHP-FPM 7.2 is not installed'):
            sv.plan(SITE, 'apache', self.pool, PORT, {'74': self.layouts['74']}, 'nobody', 'nobody', self.vhosts, self.conf_d)
        with self.assertRaisesRegex(sv.ApacheError, 'not served by Apache'):
            self.plan('tune')
        with self.assertRaisesRegex(sv.ApacheError, 'Invalid mode'):
            self.plan('nginx')

    def test_switch_and_back_with_ordered_reloads(self):
        services = FakeServices([OK])
        outcome = self.apply(self.plan(), services)
        self.assertTrue(outcome['applied'])
        self.assertEqual(self.files(), {'httpd': True, 'pool': True})
        with open(self.vhost) as handle:
            self.assertTrue(sv.block_present(handle.read()))
        reloads = [c for c in services.calls if c.startswith(('reload', 'restart'))]
        self.assertEqual(reloads, ['reload php72-php-fpm', 'reload httpd', 'restart ols'])
        self.assertLess(services.calls.index('httpd -t'), services.calls.index('reload php72-php-fpm'))
        self.assertLess(services.calls.index('php-fpm -t'), services.calls.index('reload php72-php-fpm'))
        # Nothing left to do when applied again.
        self.assertFalse(self.plan()['changed'])

        back = FakeServices([OK])
        self.apply(self.plan('ols'), back)
        self.assertEqual(self.files(), {'httpd': False, 'pool': False})
        with open(self.vhost) as handle:
            self.assertEqual(handle.read(), sv.remove_block(VHOST))
        self.assertEqual([c for c in back.calls if c.startswith(('reload', 'restart'))],
                         ['restart ols', 'reload httpd', 'reload php72-php-fpm'])

    def test_tune_touches_only_the_pool(self):
        self.apply(self.plan(), FakeServices([OK]))
        result = self.plan('tune', sv.validate_pool({'max_children': 3}, TOTAL_MB))
        self.assertEqual([c['role'] for c in result['changes']], ['pool'])
        services = FakeServices([OK])
        self.apply(result, services)
        self.assertEqual([c for c in services.calls if c.startswith(('reload', 'restart', 'httpd'))], ['reload php72-php-fpm'])
        with open(os.path.join(self.layouts['72']['pool_dir'], 'cp-ua-example.com.conf')) as handle:
            self.assertIn('pm.max_children = 3\n', handle.read())

    def test_rollback_on_httpd_syntax_error(self):
        services = FakeServices([OK], httpd_ok=False)
        with self.assertRaisesRegex(sv.ApacheError, 'httpd -t failed.*rolled back'):
            self.apply(self.plan(), services)
        with open(self.vhost) as handle:
            self.assertEqual(handle.read(), VHOST)
        self.assertEqual(self.files(), {'httpd': False, 'pool': False})
        self.assertNotIn('php-fpm -t', services.calls)
        # The restored state is reloaded in order.
        self.assertEqual([c for c in services.calls if c.startswith(('reload', 'restart'))],
                         ['reload php72-php-fpm', 'reload httpd', 'restart ols'])

    def test_rollback_on_fpm_syntax_error(self):
        with self.assertRaisesRegex(sv.ApacheError, 'php-fpm -t failed.*rolled back'):
            self.apply(self.plan(), FakeServices([OK], fpm_ok=False))
        self.assertEqual(self.files(), {'httpd': False, 'pool': False})

    def test_rollback_on_health_check_mismatch(self):
        for after in (dict(OK, status='502'), dict(OK, fingerprint='title:Index of /'),
                      dict(OK, status='301', redirect='https://example.com/')):
            services = FakeServices([OK, after])
            with self.assertRaisesRegex(sv.ApacheError, 'Health check failed.*rolled back'):
                self.apply(self.plan(), services)
            with open(self.vhost) as handle:
                self.assertEqual(handle.read(), VHOST)
            self.assertEqual(self.files(), {'httpd': False, 'pool': False})
            self.assertEqual(services.calls.count('probe'), 4)  # baseline + 3 attempts

    def test_recovers_after_a_slow_start(self):
        outcome = self.apply(self.plan(), FakeServices([OK, dict(OK, status='503'), OK]))
        self.assertTrue(outcome['applied'])

    def test_rollback_on_failed_reload(self):
        with self.assertRaisesRegex(sv.ApacheError, 'did not come back'):
            self.apply(self.plan(), FakeServices([OK], reload_ok=False))
        self.assertEqual(self.files(), {'httpd': False, 'pool': False})

    def test_refuses_without_baseline_or_after_edits(self):
        with self.assertRaisesRegex(sv.ApacheError, 'does not answer'):
            self.apply(self.plan(), FakeServices([dict(OK, scheme='', status='000')]))
        result = self.plan()
        with open(self.vhost, 'a') as handle:
            handle.write('\n# edited\n')
        with self.assertRaisesRegex(sv.ApacheError, 'changed since the preview'):
            self.apply(result, FakeServices([OK]))
        self.assertNotEqual(self.plan()['token'], result['token'])

    def test_stale_pool_of_another_version_is_removed(self):
        stale = os.path.join(self.layouts['74']['pool_dir'], 'cp-ua-example.com.conf')
        with open(stale, 'w') as handle:
            handle.write('[cp-ua-example.com]\n')
        result = self.plan()
        self.assertEqual(result['changes'][-1]['role'], 'stale pool')
        services = FakeServices([OK])
        self.apply(result, services)
        self.assertFalse(os.path.exists(stale))
        self.assertIn('reload php74-php-fpm', services.calls)


class HostFacts(SimpleTestCase):
    def test_run_identity_from_dump(self):
        dump = 'ServerRoot: "/etc/httpd"\nUser: name="nobody" id=65534\nGroup: name="nobody" id=65534\n'
        runner = lambda argv, **kw: mock.Mock(returncode=0, stdout=dump)
        self.assertEqual(sv.httpd_run_identity(runner), ('nobody', 'nobody'))
        conf = os.path.join(tempfile.mkdtemp(), 'httpd.conf')
        with open(conf, 'w') as handle:
            handle.write('User apache\nGroup apache\n')
        missing = lambda argv, **kw: mock.Mock(returncode=1, stdout='')
        self.assertEqual(sv.httpd_run_identity(missing, conf), ('apache', 'apache'))

    def test_listens_and_port_choice(self):
        root = tempfile.mkdtemp()
        for directory in ('conf', 'conf.d', 'conf.modules.d'):
            os.makedirs(os.path.join(root, directory))
        with open(os.path.join(root, 'conf', 'httpd.conf'), 'w') as handle:
            handle.write('Listen 8083\nListen 8082\n#Listen 80\n')
        with open(os.path.join(root, 'conf.d', 'other.conf'), 'w') as handle:
            handle.write('Listen 127.0.0.1:8086\n')
        with open(os.path.join(root, 'conf.d', sv.BASE_CONF_NAME), 'w') as handle:
            handle.write('Listen 127.0.0.1:8099\n')
        listens = sv.httpd_listens(root)
        self.assertEqual(listens, [('*', 8083), ('*', 8082), ('127.0.0.1', 8086)])
        self.assertEqual(sv.choose_port(listens, in_use=lambda p: p == 8087, preferred=8086), 8088)
        with self.assertRaisesRegex(sv.ApacheError, 'already listens'):
            sv.validate_port(8086, listens)
        shutil.rmtree(root)

    def test_installed_fpm_prefers_remi(self):
        present = {'/usr/sbin/php-fpm', '/opt/remi/php56/root/usr/sbin/php-fpm', '/etc/opt/remi/php56/php-fpm.d'}
        runner = lambda argv, **kw: mock.Mock(returncode=0, stdout='7.2.24')
        found = sv.installed_fpm(exists=lambda p: p in present, runner=runner)
        self.assertEqual(sorted(found), ['56', '72'])
        self.assertEqual(found['72']['service'], 'php-fpm')
        self.assertEqual(found['56']['service'], 'php56-php-fpm')
        self.assertEqual(found['56']['run_dir'], '/var/opt/remi/php56/run/php-fpm')

    def test_install_plan_for_this_host(self):
        mem = {'total_mb': TOTAL_MB, 'available_mb': 1449, 'swap_free_mb': 1935, 'cores': 2}
        plan = sv.install_plan(['56', '74', '81'], {'56': sv.fpm_layout('56')}, True, True, mem)
        self.assertEqual(plan['missing'], ['74', '81'])
        self.assertNotIn('httpd', plan['packages'])
        self.assertIn('php74-php-fpm', plan['packages'])
        self.assertIn('php81-php-mysqlnd', plan['packages'])
        self.assertEqual(plan['ram_steady_mb'], 40)
        self.assertFalse(plan['needs_confirm'])
        self.assertIn('includepkgs=php74-* php81-* remi-libzip*', plan['repo_text'])
        self.assertIn('gpgcheck=1', plan['repo_text'])
        self.assertIn('[cp-ua-remi-safe]', plan['repo_text'])
        low = sv.install_plan(['74'], {}, False, False, dict(mem, available_mb=500))
        self.assertTrue(low['needs_confirm'])
        self.assertIn('httpd', low['packages'])
        self.assertEqual(low['ram_steady_mb'], sv.HTTPD_MB + sv.FPM_MASTER_MB)

    def test_www_pool_ondemand(self):
        text = '[www]\nuser = apache\npm = dynamic\npm.max_children = 50\n'
        changed = sv.www_pool_ondemand(text)
        self.assertIn('pm = ondemand', changed)
        self.assertIn('pm.max_children = 50', changed)
        self.assertEqual(sv.www_pool_ondemand(changed), changed)

    def test_probe_and_fingerprint(self):
        body = '<html><head><title>\n  Example   Shop </title></head><body>' + 'x' * 10 + '</body></html>'
        calls = []

        def runner(argv, **kw):
            calls.append(argv)
            return mock.Mock(returncode=0, stdout=body + '\n' + sv.PROBE_MARK + '200 ')
        answer = sv.probe('example.com', runner, nonce='ab12')
        self.assertEqual(answer, {'scheme': 'https', 'status': '200', 'fingerprint': 'title:Example Shop', 'redirect': ''})
        self.assertIn('example.com:443:127.0.0.1', calls[0])
        self.assertIn('https://example.com/?cp_ua_probe=ab12', calls[0])
        redirect = lambda argv, **kw: mock.Mock(returncode=0, stdout='\n' + sv.PROBE_MARK + '301 https://example.com/?cp_ua_probe=ab12')
        self.assertEqual(sv.probe('example.com', redirect, nonce='ab12')['redirect'], 'https://example.com/')
        down = lambda argv, **kw: mock.Mock(returncode=7, stdout='curl: (7) Failed to connect\n' + sv.PROBE_MARK + '000 ')
        self.assertEqual(sv.probe('example.com', down)['status'], '000')
        self.assertEqual(sv.page_fingerprint('{"ok": 12345}'), 'text:{"ok": }')

    def test_state_round_trip(self):
        path = os.path.join(tempfile.mkdtemp(), 'state.json')
        sv.save_state({'port': 8086, 'sites': {'example.com': {'pool': {'pm': 'ondemand'}}, 'bad domain': {}}}, path)
        state = sv.load_state(path)
        self.assertEqual(state['port'], 8086)
        self.assertEqual(list(state['sites']), ['example.com'])
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o600')


class Actions(SimpleTestCase):
    def test_install_refuses_low_ram_unless_confirmed(self):
        low = {'total_mb': TOTAL_MB, 'available_mb': 450, 'swap_free_mb': 0, 'cores': 2}
        with mock.patch.object(sv, 'meminfo', return_value=low), \
                mock.patch.object(sv, 'installed_fpm', return_value={}), \
                mock.patch('universalAddons.apache.actions.os.path.exists', return_value=True), \
                mock.patch('universalAddons.jobs.spawn', return_value={'job_id': 'x'}) as spawn:
            with self.assertRaisesRegex(sv.ApacheError, '450 MB'):
                actions.install(['74'])
            spawn.assert_not_called()
            self.assertEqual(actions.install(['74'], confirm=True), {'job_id': 'x'})
            spawn.assert_called_once_with('apache', 'install_run', {'versions': ['74'], 'confirm': True})

    def test_apply_checks_token(self):
        with self.assertRaisesRegex(sv.ApacheError, 'Preview'):
            actions.apply('example.com', 'apache', 'nope')
        fake = {'token': 'a' * 32, 'changed': True}
        with mock.patch.object(actions, '_plan', return_value=fake), \
                mock.patch('universalAddons.jobs.spawn', return_value={'job_id': 'x'}) as spawn:
            with self.assertRaisesRegex(sv.ApacheError, 'changed since the preview'):
                actions.apply('example.com', 'apache', 'b' * 32)
            actions.apply('example.com', 'apache', 'a' * 32, {'max_children': 3})
            spawn.assert_called_once_with('apache', 'apply_run', {'site': 'example.com', 'mode': 'apache',
                                                                  'token': 'a' * 32, 'pool': {'max_children': 3}})

    def test_site_lookup(self):
        with mock.patch.object(actions, '_sites', return_value=[SITE, {'domain': 'off.com', 'user': 'off12', 'state': 0}]):
            self.assertEqual(actions._site('Example.com'), SITE)
            with self.assertRaisesRegex(sv.ApacheError, 'suspended'):
                actions._site('off.com')
            with self.assertRaisesRegex(sv.ApacheError, 'Unknown'):
                actions._site('other.com')
            with self.assertRaisesRegex(sv.ApacheError, 'Invalid'):
                actions._site('../etc')


class AccessControl(SimpleTestCase):
    def post(self, view, body, admin=1):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('universalAddons.privileged.call', return_value={'job_id': 'j'}) as call, \
                mock.patch.object(sv, 'meminfo', return_value={'total_mb': TOTAL_MB, 'available_mb': 1400,
                                                               'swap_free_mb': 0, 'cores': 2}):
            response = view(request)
        return response.status_code, call

    def test_admin_only(self):
        body = {'site': 'example.com', 'mode': 'apache', 'token': 'a' * 32, 'job': 'b' * 24, 'versions': ['74']}
        for view in (views.overview, views.preview, views.apply, views.install, views.job):
            status, call = self.post(view, body, admin=0)
            self.assertEqual(status, 403, view.__name__)
            call.assert_not_called()
        request = RequestFactory().post('/x', data='{}', content_type='application/json')
        request.session = {}
        self.assertEqual(views.overview(request).status_code, 401)
        get = RequestFactory().get('/x')
        get.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': 1}):
            self.assertEqual(views.preview(get).status_code, 405)

    def test_input_validation(self):
        bad = [(views.preview, {'site': 'not a domain', 'mode': 'apache'}),
               (views.preview, {'site': 'example.com', 'mode': 'nginx'}),
               (views.preview, {'site': ['example.com'], 'mode': 'apache'}),
               (views.preview, {'site': 'example.com', 'mode': 'apache', 'pool': {'max_children': 99}}),
               (views.preview, {'site': 'example.com', 'mode': 'tune', 'pool': {'listen': '/tmp/x.sock'}}),
               (views.apply, {'site': 'example.com', 'mode': 'apache', 'token': 'xyz'}),
               (views.install, {'versions': ['99']}), (views.install, {'versions': '74'}),
               (views.install, {'versions': ['74'], 'confirm': 'yes'}),
               (views.job, {'job': '../../etc/passwd'})]
        for view, body in bad:
            status, call = self.post(view, body)
            self.assertEqual(status, 400, body)
            call.assert_not_called()

    def test_calls_pass_through(self):
        status, call = self.post(views.preview, {'site': 'Example.COM', 'mode': 'apache', 'pool': {'max_children': '4'}})
        self.assertEqual(status, 200)
        pool = dict(sv.default_pool(TOTAL_MB), max_children=4)
        call.assert_called_once_with('apache', 'preview', site='example.com', mode='apache', pool=pool)
        status, call = self.post(views.preview, {'site': 'example.com', 'mode': 'ols', 'pool': {'max_children': 99}})
        call.assert_called_once_with('apache', 'preview', site='example.com', mode='ols', pool=None)
        status, call = self.post(views.apply, {'site': 'example.com', 'mode': 'tune', 'token': 'a' * 32})
        call.assert_called_once_with('apache', 'apply', site='example.com', mode='tune', token='a' * 32,
                                     pool=sv.default_pool(TOTAL_MB))
        status, call = self.post(views.install, {'versions': ['8.1', '74', '74']})
        call.assert_called_once_with('apache', 'install', versions=['74', '81'], confirm=False)


@override_settings(ROOT_URLCONF=__name__)
class PageRenders(SimpleTestCase):
    def test_page_renders(self):
        request = RequestFactory().get('/addons/apache/')
        request.session = {}
        html = render_to_string('universalAddons/apache.html', {'request': request, 'admin': 1})
        self.assertIn('ua-wrap', html)
        self.assertIn('data-base="/addons/apache/"', html)
        self.assertIn('apache.js', html)

    def test_js_ids_exist_in_template(self):
        import re
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, 'static/universalAddons/apache.js')) as handle:
            ids = set(re.findall(r"\$\('([a-z-]+)'\)", handle.read()))
        with open(os.path.join(here, 'templates/universalAddons/apache.html')) as handle:
            html = handle.read()
        self.assertEqual(sorted(i for i in ids if 'id="%s"' % i not in html and i != 'ap-pm'), [])

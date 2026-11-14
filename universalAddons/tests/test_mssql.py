import json
import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase

from universalAddons import access
from universalAddons.mssql import actions, service as sq, views


class Platform(SimpleTestCase):
    def test_repo_mapping(self):
        self.assertEqual(sq.repo_for('rhel', 8)[2], '2022')
        self.assertIn('rhel/9/mssql-server-2025', sq.repo_for('rhel', 9)[1])
        self.assertIn('ubuntu/24.04/mssql-server-2025', sq.repo_for('debian', 24)[1])
        for family, version in (('rhel', 7), ('debian', 18), ('openeuler', 22)):
            with self.assertRaises(sq.SQLError):
                sq.repo_for(family, version)

    def test_preflight_this_kind_of_server(self):
        checks = {c['id']: c['ok'] for c in sq.preflight({'family': 'rhel', 'version': 8}, 'x86_64', 3736, 4900, False)}
        self.assertEqual(checks, {'os': True, 'arch': True, 'ram': True, 'disk': False, 'installed': True})
        checks = {c['id']: c['ok'] for c in sq.preflight({'family': 'rhel', 'version': 8}, 'aarch64', 1024, 9000, True)}
        self.assertEqual((checks['arch'], checks['ram'], checks['installed']), (False, False, False))

    def test_default_memory_limit(self):
        self.assertEqual(sq.default_memory_limit_mb(3736), 1245)
        self.assertEqual(sq.default_memory_limit_mb(1024), 512)
        self.assertEqual(sq.default_memory_limit_mb(65536), 4096)


class Secrets(SimpleTestCase):
    def test_generated_passwords_meet_policy(self):
        for _ in range(50):
            password = sq.strong_password()
            self.assertEqual(sq.validate_password(password), password)

    def test_password_rules(self):
        sq.validate_password('Correct-Horse-9')
        for bad in ('short1A!', "has'quote1Aa", 'has]bracket1Aa', 'alllowercaseletters', 'Tab\tchar1aA!'):
            with self.assertRaises(sq.SQLError, msg=bad):
                sq.validate_password(bad)


class SQLText(SimpleTestCase):
    def test_names_and_quoting(self):
        self.assertEqual(sq.database_name('shop1234', 'Orders'), 'shop1234_orders')
        for bad in ('x', 'bad-name', '1db', 'a; DROP DATABASE x'):
            with self.assertRaises(sq.SQLError):
                sq.database_name('shop1234', bad)
        with self.assertRaises(sq.SQLError):
            sq.quote_ident('a]; DROP LOGIN sa; --')
        self.assertEqual(sq.quote_string("it's"), "N'it''s'")

    def test_create_isolates_login(self):
        sql = sq.create_sql('shop1234_orders', 'Pass-word-123')
        self.assertIn('CREATE LOGIN [shop1234_orders] WITH PASSWORD = N\'Pass-word-123\', CHECK_POLICY = ON', sql)
        self.assertIn('DENY VIEW ANY DATABASE TO [shop1234_orders];', sql)
        self.assertIn('ALTER AUTHORIZATION ON DATABASE::[shop1234_orders] TO [shop1234_orders];', sql)
        self.assertNotIn('sysadmin', sql)

    def test_sqlcmd_keeps_secrets_off_the_command_line(self):
        seen = {}

        def runner(argv, **kwargs):
            seen['argv'], seen['env'] = argv, kwargs['env']
            seen['sql'] = open(argv[argv.index('-i') + 1]).read()
            seen['mode'] = oct(os.stat(argv[argv.index('-i') + 1]).st_mode & 0o777)
            return SimpleNamespace(returncode=0, stdout='ok')
        sq.sqlcmd(sq.create_sql('shop1234_orders', 'Login-Secret-1'), 'Sa-Secret-99', runner, sqlcmd_path='/x/sqlcmd')
        joined = ' '.join(seen['argv'])
        self.assertNotIn('Sa-Secret-99', joined)
        self.assertNotIn('Login-Secret-1', joined)
        self.assertEqual(seen['env']['SQLCMDPASSWORD'], 'Sa-Secret-99')
        self.assertIn('Login-Secret-1', seen['sql'])
        self.assertEqual(seen['mode'], '0o600')
        self.assertFalse(os.path.exists(seen['argv'][seen['argv'].index('-i') + 1]), 'SQL file removed')

    def test_sqlcmd_error_raises(self):
        with self.assertRaisesRegex(sq.SQLError, 'Login failed'):
            sq.sqlcmd('SELECT 1', 'x', lambda argv, **k: SimpleNamespace(returncode=1, stdout="Login failed for user 'sa'"))


class Ownership(SimpleTestCase):
    def test_actions_refuse_other_sites_databases(self):
        state = tempfile.mkdtemp()
        sq.save_registry({'shop1234_orders': {'domain': 'shop.example.com', 'login': 'shop1234_orders', 'created': 1}}, state)
        with mock.patch.object(sq, 'STATE_DIR', state), mock.patch.object(sq, 'sqlcmd') as run_sql:
            for call in (lambda: actions.drop('shop1234_orders', 'other.com'),
                         lambda: actions.reset_password('shop1234_orders', 'other.com')):
                with self.assertRaisesRegex(sq.SQLError, 'Unknown database'):
                    call()
            run_sql.assert_not_called()
            self.assertEqual(actions.list_databases(['other.com'])['databases'], [])

    def test_install_requires_licence_acceptance(self):
        with self.assertRaisesRegex(sq.SQLError, 'accept'):
            actions.install(accept_eula=False)
        with self.assertRaisesRegex(sq.SQLError, 'accept'):
            actions.install(accept_eula='yes')


class Views(SimpleTestCase):
    def post(self, view, body, admin=0, owns=True, policy=None):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 3}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('loginSystem.models.Administrator.objects.get', return_value=object()), \
                mock.patch('universalAddons.access.ACLManager.checkOwnership', return_value=1 if owns else 0), \
                mock.patch('universalAddons.access.load_policy', return_value=dict(access.DEFAULT_POLICY, **(policy or {}))), \
                mock.patch('universalAddons.mssql.views.ACLManager.findAllSites', return_value=['shop.example.com']), \
                mock.patch('universalAddons.privileged.call', return_value={}) as call:
            response = view(request)
        return response.status_code, json.loads(response.content), call

    def test_server_management_is_admin_only(self):
        for view in (views.overview, views.install, views.service):
            status, _, call = self.post(view, {'acceptEula': True, 'action': 'restart'}, policy={'mssql_for_users': True})
            self.assertEqual(status, 403)
            call.assert_not_called()

    def test_install_passes_explicit_acceptance_only(self):
        _, _, call = self.post(views.install, {'acceptEula': 'true'}, admin=1)
        self.assertIs(call.call_args[1]['accept_eula'], False)
        _, _, call = self.post(views.install, {'acceptEula': True, 'memoryLimitMb': 1024}, admin=1)
        self.assertEqual(call.call_args[1], {'accept_eula': True, 'memory_limit_mb': 1024})

    def test_users_need_policy_and_ownership(self):
        self.assertEqual(self.post(views.databases, {})[0], 403)
        status, _, call = self.post(views.create, {'domain': 'other.com', 'name': 'orders'}, owns=False,
                                    policy={'mssql_for_users': True})
        self.assertEqual(status, 403)
        call.assert_not_called()
        status, _, call = self.post(views.create, {'domain': 'shop.example.com', 'name': 'orders',
                                                   'passwordByPass': 'Strong-Pass-123'}, policy={'mssql_for_users': True})
        call.assert_called_once_with('mssql', 'create', domain='shop.example.com', name='orders', password='Strong-Pass-123')


class PagesRender(SimpleTestCase):
    """Render every add-on page so a missing URL name or template error fails the suite."""

    def test_all_pages_render(self):
        from universalAddons.registry import module_status
        request = RequestFactory().get('/addons/')
        request.session = {}
        context = {'request': request, 'admin': 1, 'modules': module_status(), 'domains': ['a.com'], 'sites': ['a.com'],
                   'is_admin': True, 'enabled': True, 'start': '/home',
                   'default_site': 'a.com', 'version': '1.6.21', 'prefix': '/webmail-rc/', 'db_name': 'cp_roundcube'}
        pages = ['hub', 'emaildebug', 'rootfm', 'rspamd', 'sslv2', 'backupv2', 'wordpress', 'htaccess', 'apps', 'mssql', 'storage', 'emaillimits', 'sshsec', 'mysqlmgr', 'roundcube', 'limits', 'apache', 'webterm']
        for page in pages:
            # No request: the panel's context processors query the database, which unit tests do not have.
            html = render_to_string('universalAddons/%s.html' % page, context)
            self.assertIn('ua-wrap', html, page)
        disabled = render_to_string('universalAddons/apps.html', dict(context, enabled=False, is_admin=False))
        self.assertIn('has not enabled apps', disabled)


class Repositories(SimpleTestCase):
    def test_tools_repo_has_its_own_id(self):
        text = sq.tools_repo_text(8)
        self.assertIn('[cp-microsoft-prod]', text)
        self.assertIn('baseurl=https://packages.microsoft.com/rhel/8/prod/', text)
        self.assertIn('gpgcheck=1', text)
        self.assertNotIn('packages-microsoft-com-prod', text)

    def test_foreign_install_is_never_reconfigured(self):
        state = tempfile.mkdtemp()
        data = tempfile.mkdtemp()
        os.makedirs(os.path.join(data, 'data'))
        open(os.path.join(data, 'data', 'master.mdf'), 'w').close()
        with mock.patch.object(sq, 'STATE_DIR', state), mock.patch.object(sq, 'DATA_DIR', data), \
                mock.patch('universalAddons.mssql.actions.os.path.exists',
                           side_effect=lambda p: p == '/opt/mssql/bin/sqlservr' or os.path.isfile(p)):
            self.assertTrue(actions._foreign_install())
            self.assertFalse(actions._installed())
            with self.assertRaisesRegex(sq.SQLError, 'outside the panel'):
                actions.install(accept_eula=True)


class MemoryProtection(SimpleTestCase):
    def test_dropin_prefers_killing_sql_server_and_caps_it(self):
        v1 = sq.protect_dropin_text(1024, unified=False)
        self.assertIn('OOMScoreAdjust=500', v1)
        self.assertIn('MemoryLimit=1536M', v1)
        self.assertIn('MemoryMax=1536M', sq.protect_dropin_text(1024, unified=True))

    def test_written_atomically(self):
        path = os.path.join(tempfile.mkdtemp(), 'd', 'x.conf')
        sq.write_protect_dropin(768, path)
        self.assertIn('=1280M', open(path).read())
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o644')

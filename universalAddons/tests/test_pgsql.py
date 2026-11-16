import base64
import hashlib
import hmac
import json
import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from universalAddons.pgsql import actions, service as pg, views
from universalAddons.tests.helpers import page, post

POLICY_ON = {'pgsql_for_users': True}


class Names(SimpleTestCase):
    def test_prefix_matches_the_panel_mysql_prefix(self):
        self.assertEqual(pg.db_prefix('example.com'), 'exam')
        self.assertEqual(pg.db_prefix('my-site.org'), 'mysi')     # hyphens removed, then cut to 4
        self.assertEqual(pg.db_prefix('short.io'), 'short')       # 5 characters are kept
        self.assertEqual(pg.db_prefix('abc.co.uk'), 'abc')

    def test_full_name(self):
        self.assertEqual(pg.full_name('example.com', 'Shop_1'), 'exam_shop_1')
        with self.assertRaises(pg.PGError):
            pg.full_name('example.com', 'x' * 28)

    def test_injection_attempts_are_refused(self):
        for bad in ('a"; DROP DATABASE postgres; --', "a'b", 'a b', 'a-b', '', '../x', 'shop\x00', 'é', 'a;b',
                    ':"x"', '\\getenv'):
            with self.assertRaises(pg.PGError, msg=bad):
                pg.full_name('example.com', bad)
        for bad in ('postgres', 'template1', 'pg_monitor', 'ua_tmp_0011223344556677', 'Exam_x', 'exam_x"'):
            with self.assertRaises(pg.PGError, msg=bad):
                pg.check_name(bad)
        with self.assertRaises(pg.PGError):       # a domain whose prefix is "pg" would make a reserved pg_ name
            pg.full_name('pg.com', 'shop')

    def test_quote_ident_and_literal(self):
        self.assertEqual(pg.quote_ident('a"b'), '"a""b"')
        self.assertEqual(pg.quote_ident('exam_shop'), '"exam_shop"')
        self.assertEqual(pg.quote_literal("it's"), "'it''s'")
        with self.assertRaises(pg.PGError):
            pg.quote_ident('a\x00b')


class Scripts(SimpleTestCase):
    def test_values_travel_in_the_environment_never_in_the_sql(self):
        secret = pg.scram_secret('Abcdefgh12345678')
        text, env = pg.script('create_role', role='exam_shop', secret=secret)
        self.assertEqual(text, pg.SCRIPTS['create_role'])     # constant text
        self.assertNotIn('exam_shop', text)
        self.assertNotIn(secret, text)
        self.assertIn(':"role"', text)
        self.assertIn(":'secret'", text)
        self.assertEqual(env, {'UA_ROLE': 'exam_shop', 'UA_SECRET': secret})

    def test_every_script_quotes_with_psql_variables(self):
        for name, text in pg.SCRIPTS.items():
            self.assertNotIn('%', text.replace("LIKE 'ua\\_tmp\\_%'", ''), name)
            for line in text.splitlines():
                if line.startswith('\\getenv'):
                    self.assertRegex(line, r'^\\getenv [a-z]+ UA_[A-Z]+$')

    def test_bad_values_are_refused(self):
        with self.assertRaises(pg.PGError):
            pg.script('drop_db', db='x"; DROP DATABASE y; --')
        with self.assertRaises(pg.PGError):
            pg.script('password', role='exam_shop', secret='plain-password')   # only SCRAM secrets
        with self.assertRaises(pg.PGError):
            pg.script('drop_db', db='exam_shop', role='exam_shop')            # a value the script does not read
        with self.assertRaises(pg.PGError):
            pg.script('temp_role', role='ua_tmp_0011223344556677', secret=pg.scram_secret('Abcdefgh12345678'),
                      owner='exam_shop', until="now'); DROP")

    def test_temp_roles_are_allowed_where_scripts_need_them(self):
        text, env = pg.script('drop_role', role='ua_tmp_0011223344556677')
        self.assertEqual(env['UA_ROLE'], 'ua_tmp_0011223344556677')

    def test_scram_secret(self):
        salt = b'0123456789abcdef'
        secret = pg.scram_secret('Abcdefgh12345678', salt=salt)
        head, keys = secret.split('$')[1], secret.split('$')[2]
        self.assertEqual(head, '4096:' + base64.b64encode(salt).decode())
        salted = hashlib.pbkdf2_hmac('sha256', b'Abcdefgh12345678', salt, 4096)
        stored = base64.b64encode(hashlib.sha256(hmac.new(salted, b'Client Key', hashlib.sha256).digest()).digest())
        self.assertEqual(keys.split(':')[0], stored.decode())
        self.assertTrue(secret.startswith('SCRAM-SHA-256$'))
        with self.assertRaises(pg.PGError):
            pg.scram_secret("bad'password")

    def test_generated_passwords(self):
        password = pg.new_password()
        self.assertRegex(password, r'^[A-Za-z0-9]{24}$')

    def test_sizes_and_formats(self):
        self.assertEqual(pg.parse_sizes('exam_shop|8000\npostgres|7000\nbad|x\n'), {'exam_shop': 8000, 'postgres': 7000})
        self.assertEqual(pg.dump_format(b'PGDMP\x01\x0e'), 'custom')
        self.assertEqual(pg.dump_format(b'--\n-- PostgreSQL database dump\n'), 'plain')
        for bad in (b'\x1f\x8b\x08\x00', b'\x00\x01binary'):
            with self.assertRaises(pg.PGError):
                pg.dump_format(bad)
        self.assertEqual(pg.count_errors('ok\npsql:<stdin>:3: ERROR:  x\nERROR: y\n'), 2)
        self.assertEqual(pg.backup_name('exam_shop', '20261116-101500'), 'exam_shop-20261116-101500.dump')
        self.assertTrue(pg.BACKUP_RE.match('exam_shop-20261116-101500.dump'))
        self.assertFalse(pg.BACKUP_RE.match('../exam_shop-20261116-101500.dump'))


class Quota(SimpleTestCase):
    def test_mysql_and_postgresql_count_together(self):
        self.assertEqual(pg.quota_check(5, 2, 1), '3 of 5')
        with self.assertRaisesRegex(pg.PGError, 'MySQL and PostgreSQL together'):
            pg.quota_check(3, 2, 1)
        with self.assertRaises(pg.PGError):
            pg.quota_check(1, 1, 0)
        self.assertEqual(pg.quota_check(0, 40, 40), '80 of unlimited')


class Registry(SimpleTestCase):
    def reg(self):
        reg = pg.empty_registry()
        reg['databases'] = {'exam_a': {'domain': 'example.com', 'owner': 'exam_a', 'grants': {'exam_r': 'read'}},
                            'othe_b': {'domain': 'other.net', 'owner': 'othe_b', 'grants': {}}}
        reg['roles'] = {'exam_a': {'domain': 'example.com'}, 'exam_r': {'domain': 'example.com'},
                        'othe_b': {'domain': 'other.net'}}
        return reg

    def test_ownership(self):
        reg = self.reg()
        self.assertEqual(pg.require_db(reg, 'example.com', 'exam_a')['owner'], 'exam_a')
        with self.assertRaises(pg.PGError):
            pg.require_db(reg, 'example.com', 'othe_b')         # another site's database
        with self.assertRaises(pg.PGError):
            pg.require_role(reg, 'example.com', 'othe_b')
        view = pg.site_view(reg, {'example.com'})
        self.assertEqual([d['name'] for d in view['databases']], ['exam_a'])
        self.assertEqual({r['name']: r['databases'] for r in view['roles']}, {'exam_a': [], 'exam_r': ['exam_a']})
        self.assertEqual(pg.count_for_site(reg, 'example.com'), 1)

    def test_normalise_drops_junk(self):
        reg = pg.normalise_registry({'databases': {'a': 'x', 'exam_a': {'domain': 'd'}}, 'roles': []})
        self.assertEqual(list(reg['databases']), ['exam_a'])
        self.assertEqual(reg['databases']['exam_a']['grants'], {})
        self.assertEqual(reg['roles'], {})


class Actions(SimpleTestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        patches = [mock.patch.object(pg, 'STATE_DIR', self.dir),
                   mock.patch.object(pg, 'REGISTRY', os.path.join(self.dir, 'registry.json')),
                   mock.patch.object(pg, 'installed_major', return_value=17)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.calls = []

        def fake_psql(script, database='postgres', **values):
            self.calls.append((script, database, values))
            return '0\n' if script == 'exists' else ''
        patch = mock.patch.object(actions, 'psql', side_effect=fake_psql)
        patch.start()
        self.addCleanup(patch.stop)

    def website(self, limit, mysql):
        site = SimpleNamespace(domain='example.com', package=SimpleNamespace(dataBases=limit),
                               databases_set=SimpleNamespace(all=lambda: SimpleNamespace(count=lambda: mysql)))
        return mock.patch.object(actions, '_website', return_value=(site, None))

    def test_create_registers_and_returns_the_password_once(self):
        with self.website(5, 1):
            result = actions.create_db('example.com', 'shop')
        self.assertEqual(result['database'], 'exam_shop')
        self.assertRegex(result['password'], r'^[A-Za-z0-9]{24}$')
        names = [c[0] for c in self.calls]
        self.assertEqual(names, ['exists', 'create_role', 'create_db', 'own_schema'])
        self.assertTrue(self.calls[1][2]['secret'].startswith('SCRAM-SHA-256$'))
        stored = open(pg.REGISTRY).read()
        self.assertNotIn(result['password'], stored)            # never stored
        self.assertEqual(json.loads(stored)['databases']['exam_shop']['domain'], 'example.com')
        self.assertEqual(oct(os.stat(pg.REGISTRY).st_mode & 0o777), '0o600')

    def test_quota_counts_mysql_too(self):
        with self.website(2, 2):
            with self.assertRaisesRegex(pg.PGError, 'together'):
                actions.create_db('example.com', 'shop')
        with self.website(2, 1):
            actions.create_db('example.com', 'shop')
            with self.assertRaisesRegex(pg.PGError, 'together'):
                actions.create_db('example.com', 'blog')

    def test_other_sites_databases_are_refused(self):
        with self.website(0, 0):
            actions.create_db('example.com', 'shop')
        for call in (lambda: actions.drop_db('other.net', 'exam_shop'),
                     lambda: actions.reset_password('other.net', 'exam_shop'),
                     lambda: actions.grant('other.net', 'exam_shop', 'exam_shop'),
                     lambda: actions.adminer_login('other.net', 'exam_shop'),
                     lambda: actions.backup('other.net', 'exam_shop')):
            with mock.patch.object(pg, 'adminer_installed', return_value=True):
                with self.assertRaises(pg.PGError):
                    call()

    def test_grant_and_drop(self):
        with self.website(0, 0):
            actions.create_db('example.com', 'shop')
        actions.create_role('example.com', 'reader')
        actions.grant('example.com', 'exam_shop', 'exam_reader', 'read')
        self.assertIn(('grant_read', 'exam_shop', {'role': 'exam_reader', 'owner': 'exam_shop'}), self.calls)
        with self.assertRaisesRegex(pg.PGError, 'owns'):
            actions.drop_role('example.com', 'exam_shop')
        actions.drop_role('example.com', 'exam_reader')
        self.assertIn(('revoke_connect', 'postgres', {'db': 'exam_shop', 'role': 'exam_reader'}), self.calls)
        result = actions.drop_db('example.com', 'exam_shop')
        self.assertEqual(result['dropped_role'], 'exam_shop')
        self.assertEqual(actions.load_registry()['databases'], {})


class Views(SimpleTestCase):
    def test_users_need_the_switch_and_ownership(self):
        status, body, _ = post(views.overview, {})
        self.assertEqual(status, 403)
        with mock.patch('universalAddons.pgsql.views.ACLManager.findAllSites', return_value=['mine.example.com']):
            status, body, _ = post(views.create_db, {'domain': 'other.example.net', 'name': 'shop'}, policy=POLICY_ON)
            self.assertEqual(status, 403)
            status, body, _ = post(views.create_db, {'domain': 'mine.example.com', 'name': 'x"y'}, policy=POLICY_ON)
            self.assertEqual(status, 400)
            with mock.patch('universalAddons.pgsql.views.privileged.call', return_value={'database': 'mine_shop'}) as call:
                status, body, _ = post(views.create_db, {'domain': 'mine.example.com', 'name': 'shop'}, policy=POLICY_ON)
            self.assertEqual(status, 200)
            call.assert_called_once_with('pgsql', 'create_db', domain='mine.example.com', name='shop')

    def test_adminer_install_is_admin_only(self):
        status, _, _ = post(views.adminer_install, {}, policy=POLICY_ON)
        self.assertEqual(status, 403)

    def test_page_hidden_from_users_until_postgresql_is_installed(self):
        with mock.patch.object(pg, 'installed_major', return_value=None), \
                mock.patch('universalAddons.pgsql.views.is_admin', return_value=False), \
                mock.patch('universalAddons.pgsql.views.load_policy', return_value=POLICY_ON), \
                mock.patch('universalAddons.pgsql.views.forbidden', return_value=SimpleNamespace(status_code=403)) as refused:
            status, _ = page(views.page)
        self.assertEqual(status, 403)
        self.assertIn('not available', refused.call_args[0][1])
        with mock.patch.object(pg, 'installed_major', return_value=None), \
                mock.patch('universalAddons.pgsql.views.is_admin', return_value=True), \
                mock.patch('universalAddons.pgsql.views.ACLManager.findAllSites', return_value=['a.com']), \
                mock.patch('universalAddons.pgsql.views.ACLManager.loadedACL', return_value={'admin': 1}):
            status, values = page(views.page, admin=True)
        self.assertEqual(status, 200)
        self.assertFalse(values['installed'])

    def test_hub_hides_the_addon_from_users_while_postgresql_is_missing(self):
        from universalAddons.registry import requirement_problems
        self.assertTrue(requirement_problems('pgsql', exists=lambda p: False))
        self.assertEqual(requirement_problems('pgsql', exists=lambda p: p == '/usr/pgsql-16/bin/psql'), [])


class Adminer(SimpleTestCase):
    def test_pinned_release_and_wrapper(self):
        self.assertRegex(pg.ADMINER_SHA256, r'^[0-9a-f]{64}$')
        self.assertTrue(pg.ADMINER_URL.startswith('https://github.com/vrana/adminer/releases/download/v'))
        self.assertIn("'127.0.0.1:5432'", pg.ADMINER_WRAPPER)          # server fixed: no other hosts reachable
        self.assertIn("include __DIR__ . '/%s';" % pg.ADMINER_FILE, pg.ADMINER_WRAPPER)
        self.assertIn("'pgsql'", pg.ADMINER_WRAPPER)

    def test_checksum(self):
        path = os.path.join(tempfile.mkdtemp(), 'f')
        with open(path, 'wb') as handle:
            handle.write(b'abc')
        self.assertEqual(pg.sha256_file(path), hashlib.sha256(b'abc').hexdigest())

    def test_login_page_posts_to_adminer(self):
        from django.template.loader import render_to_string
        html = render_to_string('universalAddons/pgsql_adminer_login.html', {'login': {
            'username': 'ua_tmp_0011223344556677', 'password': 'Pw1"<x', 'database': 'exam_shop',
            'minutes': 30, 'url': '/adminer/'}})
        self.assertIn('name="auth[driver]" value="pgsql"', html)
        self.assertIn('value="Pw1&quot;&lt;x"', html)                   # escaped
        self.assertIn('action="/adminer/?pgsql=127.0.0.1', html)

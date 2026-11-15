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
        pages = ['hub', 'emaildebug', 'rootfm', 'rspamd', 'sslv2', 'backupv2', 'wordpress', 'htaccess', 'apps', 'mssql', 'storage', 'emaillimits', 'sshsec', 'mysqlmgr', 'roundcube', 'limits', 'apache', 'webterm', 'appsvc']
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


# ----------------------------------------------------------------------------- database viewer

def _sqlcmd_output(*docs):
    """What sqlcmd prints for a viewer batch: a marker line before each document, then the end marker."""
    lines = []
    for doc in docs:
        lines += ['', '----------', sq.DOC_MARK + '   ', '', sq.FOR_JSON_HEADER, '-' * 40]
        if doc is not None:
            text = json.dumps(doc)
            lines += [text[i:i + 2033] for i in range(0, len(text), 2033)]  # FOR JSON's row chunks
    return '\n'.join(lines + ['', sq.END_MARK, '']) + '\n'


class ViewerIdentifiers(SimpleTestCase):
    def test_object_names(self):
        self.assertEqual(sq.quote_ident('visits', 'object'), '[visits]')
        self.assertEqual(sq.quote_ident('__EFMigrationsHistory', 'object'), '[__EFMigrationsHistory]')
        self.assertEqual(sq.quote_ident('Order Lines', 'object'), '[Order Lines]')
        self.assertEqual(sq.object_name('dbo', 'visits'), '[dbo].[visits]')
        for bad in ('', 'a]; DROP TABLE x; --', 'x.y', "o'brien", 'a' * 129, '1abc', None, 5, 'a\nb'):
            with self.assertRaises(sq.SQLError, msg=repr(bad)):
                sq.quote_ident(bad, 'object')
        with self.assertRaises(sq.SQLError):
            sq.quote_ident('__EFMigrationsHistory')  # databases keep the stricter rule
        self.assertEqual(sq.quote_column('we]ird'), '[we]]ird]')  # names read back from sys.columns: QUOTENAME

    def test_rows_sql_pages_by_primary_key(self):
        cols = [{'name': 'id', 'base': 'int', 'pk': 1}, {'name': 'blob', 'base': 'varbinary', 'max_length': -1},
                {'name': 'note', 'base': 'nvarchar', 'max_length': -1}, {'name': 'where', 'base': 'geography', 'clr': True}]
        sql = sq.rows_sql('shop1234_orders', 'dbo', 'visits', cols, 2)
        self.assertIn('FROM [dbo].[visits] ORDER BY [id] OFFSET 100 ROWS FETCH NEXT 50 ROWS ONLY', sql)
        self.assertIn('CONVERT(varbinary(32), [blob]), 1)', sql)
        self.assertIn('[where].ToString()', sql)
        self.assertIn("EXECUTE AS LOGIN = N'shop1234_orders';", sql)
        self.assertIn('ORDER BY (SELECT NULL)', sq.rows_sql('l1', 'dbo', 'v', [{'name': 'a', 'base': 'int'}], 0))
        with self.assertRaises(sq.SQLError):
            sq.rows_sql('l1', 'dbo', 'v', cols, -1)


class ReadOnlyFilter(SimpleTestCase):
    ALLOWED = [
        'SELECT * FROM dbo.visits',
        'select top 5 id from visits order by id;',
        'SELECT 1;   \n  ',
        'WITH v AS (SELECT * FROM visits) SELECT COUNT(*) FROM v',
        "SELECT 'DROP TABLE x; EXEC xp_cmdshell ''y''' AS s",         # words inside strings are data
        "SELECT N'GO' AS g, 'INSERT; DELETE' AS i",
        'SELECT [delete], [exec] FROM [update]',                          # bracketed names
        'SELECT 1 -- DROP TABLE visits\n',                                # keyword only inside a comment
        'SELECT /* EXEC */ 1 AS a',
        'SELECT * FROM visits ORDER BY id OFFSET 10 ROWS FETCH NEXT 5 ROWS ONLY',
        "SELECT * FROM visits WHERE url LIKE '%;%'",
    ]
    REFUSED = [
        'DELETE FROM visits',
        'UPDATE visits SET a = 1',
        'INSERT INTO visits VALUES (1)',
        'SELECT * INTO copy FROM visits',
        'WITH v AS (SELECT 1 a) DELETE FROM visits',
        'EXEC sp_who',
        'SELECT 1; SELECT 2',
        'SELECT 1; DROP TABLE visits',
        'SELECT 1;;',
        'SELECT 1\nGO\nSELECT 2',
        'SELECT 1 GO',
        'SELECT 1 REVERT SELECT * FROM sys.sql_logins',                     # no ; needed between statements
        'SELECT 1 /* */ DELETE FROM visits',
        'SELECT 1 -- hidden\n; DROP TABLE visits',
        "SELECT 1 /* /* */ ' */ EXEC xp_cmdshell 'id' --'",              # nested comments as SQL Server reads them
        'SELECT 1 /* unterminated',
        "SELECT 'unterminated",
        'SELECT * FROM OPENROWSET(BULK \'/etc/passwd\', SINGLE_CLOB) x',
        'SELECT * FROM OPENQUERY(x, \'SELECT 1\')',
        'SELECT master.dbo.xp_dirtree(1)',
        'SELECT 1 WAITFOR DELAY \'00:10\'',
        'SELECT 1 SET ROWCOUNT 0',
        "SELECT 'a\n:!! id\n'",                                          # sqlcmd shell escape at a line start
        ':r /etc/passwd',
        'DBCC CHECKDB',
        'SHUTDOWN',
        '',
        '   ',
        'TRUNCATE TABLE visits',
        'x' * (sq.MAX_QUERY_CHARS + 1),
    ]

    def test_allowed(self):
        for sql in self.ALLOWED:
            sq.readonly_query(sql)

    def test_refused(self):
        for sql in self.REFUSED:
            with self.assertRaises(sq.SQLError, msg=sql):
                sq.readonly_query(sql)

    def test_trailing_semicolon_removed_only_once(self):
        self.assertEqual(sq.readonly_query('SELECT 1; -- done').strip(), 'SELECT 1 -- done')
        self.assertEqual(sq.readonly_query("SELECT ';'").strip(), "SELECT ';'")

    def test_strip_keeps_positions(self):
        sql = "SELECT 'x;y' /* c */ -- z\n[a]"
        bare = sq.strip_sql(sql)
        self.assertEqual(len(bare), len(sql))
        self.assertNotIn(';', bare)
        self.assertTrue(bare.startswith('SELECT '))

    def test_generated_sql_is_sandboxed(self):
        sql = sq.query_sql('shop1234_orders', 'SELECT * FROM visits; -- tail;')
        for part in ('SET LOCK_TIMEOUT 5000;', 'BEGIN TRANSACTION;', "EXECUTE AS LOGIN = N'shop1234_orders';",
                     'SET ROWCOUNT 500;', 'REVERT;', 'ROLLBACK;', 'FOR JSON PATH, INCLUDE_NULL_VALUES'):
            self.assertIn(part, sql)
        order = [sql.index(p) for p in ('BEGIN TRANSACTION', 'EXECUTE AS LOGIN', 'SELECT * FROM visits', 'REVERT', 'ROLLBACK')]
        self.assertEqual(order, sorted(order))
        self.assertIn('SELECT * FROM visits -- tail;\nFOR JSON PATH', sql)  # own line, after the comment
        self.assertIn("sys.dm_exec_describe_first_result_set(N'SELECT * FROM visits -- tail;'", sql)
        with self.assertRaises(sq.SQLError):
            sq.query_sql('shop1234_orders', 'DELETE FROM visits')
        with self.assertRaises(sq.SQLError):
            sq.viewer_sql("x'; DROP LOGIN sa; --", ['SELECT 1;'])

    def test_viewer_runs_in_the_database_with_unlimited_width(self):
        seen = {}

        def runner(argv, **kwargs):
            seen['argv'] = argv
            seen['sql'] = open(argv[argv.index('-i') + 1]).read()
            return SimpleNamespace(returncode=0, stdout=_sqlcmd_output([{'a': 1}]))
        docs = sq.viewer_run(sq.tables_sql('shop1234_orders'), 'Sa-Secret-99', 'shop1234_orders', runner)
        self.assertEqual(sq.records(docs[0]), [{'a': 1}])
        argv = seen['argv']
        self.assertEqual(argv[argv.index('-d') + 1], 'shop1234_orders')
        self.assertEqual(argv[argv.index('-y') + 1], '0')
        self.assertNotIn('-h', argv)  # sqlcmd refuses -h with -y 0
        self.assertIn('-x', argv)
        self.assertEqual(argv[argv.index('-t') + 1], '30')
        self.assertNotIn('-W', argv)
        self.assertNotIn('Sa-Secret-99', ' '.join(argv))
        self.assertIn('sys.dm_db_partition_stats', seen['sql'])


class ResultParsing(SimpleTestCase):
    def test_documents_nulls_and_chunks(self):
        long_text = 'x' * 5000 + ' '  # trailing space at a chunk boundary must survive
        out = _sqlcmd_output(None, [{'id': 1, 'v': None, 's': long_text}])
        empty, rows = sq.documents(out)
        self.assertIsNone(empty)
        self.assertEqual(sq.records(rows), [{'id': 1, 'v': None, 's': long_text}])
        self.assertEqual(sq.documents(sq.DOC_MARK + '\nNULL\n' + sq.END_MARK + '\n'), [None])
        with self.assertRaises(sq.SQLError):
            sq.documents('Msg 208, Level 16\n')

    def test_query_result_with_binary_nulls_and_duplicate_names(self):
        import base64
        describe = [{'name': 'id', 'type': 'int', 'error_message': None},
                    {'name': 'id', 'type': 'int', 'error_message': None},
                    {'name': 'hash', 'type': 'varbinary(max)', 'error_message': None},
                    {'name': 'note', 'type': 'nvarchar(max)', 'error_message': None}]
        blob = bytes(range(40))
        text = ('[{"id":1,"id":7,"hash":"%s","note":null},{"id":2,"id":8,"hash":null,"note":"%s"}]'
                % (base64.b64encode(blob).decode(), 'y' * 1500))
        out = '%s\n%s\n%s\n%s\n%s\n' % (sq.DOC_MARK, json.dumps(describe), sq.DOC_MARK, text, sq.END_MARK)
        docs = sq.documents(out)
        result = sq.result_table(docs[0], docs[1])
        self.assertEqual(result['columns'], ['id', 'id', 'hash', 'note'])
        self.assertEqual(result['rows'][0][:2], [1, 7])
        self.assertEqual(result['rows'][0][2], '0x' + blob[:32].hex().upper() + '...')
        self.assertIsNone(result['rows'][0][3])
        self.assertIsNone(result['rows'][1][2])
        self.assertEqual(len(result['rows'][1][3]), sq.MAX_TEXT + 3)
        self.assertFalse(result['capped'])
        # A base64-looking string in a text column is left alone.
        self.assertEqual(sq.display_value('AAEC'), 'AAEC')
        self.assertEqual(sq.display_value('AAEC', binary=True), '0x000102')

    def test_empty_result_keeps_column_names(self):
        describe = [{'name': 'a', 'type': 'int', 'error_message': None}]
        self.assertEqual(sq.result_table(describe, None), {'columns': ['a'], 'rows': [], 'capped': False})

    def test_size_limit(self):
        with self.assertRaisesRegex(sq.SQLError, '2 MB'):
            sq.check_size({'rows': ['x' * (sq.MAX_OUTPUT_BYTES + 1)]})

    def test_display_types(self):
        self.assertEqual(sq.display_type({'type': 'nvarchar', 'base': 'nvarchar', 'max_length': 100}), 'nvarchar(50)')
        self.assertEqual(sq.display_type({'type': 'varchar', 'base': 'varchar', 'max_length': -1}), 'varchar(max)')
        self.assertEqual(sq.display_type({'type': 'decimal', 'base': 'decimal', 'precision': 10, 'scale': 2}), 'decimal(10,2)')


class ViewerOwnership(SimpleTestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp()
        sq.save_registry({'shop1234_orders': {'domain': 'shop.example.com', 'login': 'shop1234_orders', 'created': 1}}, self.state)

    def test_other_sites_databases_are_refused(self):
        with mock.patch.object(sq, 'STATE_DIR', self.state), mock.patch.object(actions, '_installed', return_value=True), \
                mock.patch.object(sq, 'sa_password', return_value='x'), mock.patch.object(sq, 'sqlcmd') as run_sql:
            for call in (lambda: actions.tables('shop1234_orders', 'other.com'),
                         lambda: actions.columns('shop1234_orders', 'other.com', 'dbo', 'visits'),
                         lambda: actions.rows('shop1234_orders', 'other.com', 'dbo', 'visits'),
                         lambda: actions.query('shop1234_orders', 'other.com', 'SELECT 1'),
                         lambda: actions.tables('nope_db', 'shop.example.com')):
                with self.assertRaisesRegex(sq.SQLError, 'Unknown database'):
                    call()
            run_sql.assert_not_called()

    def test_owner_browses_rows(self):
        columns = [{'name': 'id', 'type': 'int', 'base': 'int', 'clr': False, 'max_length': 4, 'nullable': False, 'pk': 1},
                   {'name': 'url', 'type': 'nvarchar', 'base': 'nvarchar', 'clr': False, 'max_length': 400, 'nullable': True, 'pk': None}]
        outputs = [_sqlcmd_output(columns), _sqlcmd_output([{'c0': 1, 'c1': None}, {'c0': 2, 'c1': '/'}])]
        sqls = []

        def fake(sql, password, runner, database, options, timeout):
            sqls.append((sql, database))
            return outputs.pop(0)
        with mock.patch.object(sq, 'STATE_DIR', self.state), mock.patch.object(actions, '_installed', return_value=True), \
                mock.patch.object(sq, 'sa_password', return_value='x'), mock.patch.object(sq, 'sqlcmd', side_effect=fake):
            result = actions.rows('shop1234_orders', 'shop.example.com', 'dbo', 'visits', 1)
        self.assertEqual(result['columns'], ['id', 'url'])
        self.assertEqual(result['rows'], [[1, None], [2, '/']])
        self.assertTrue(all(db == 'shop1234_orders' for _, db in sqls))
        self.assertIn("OBJECT_ID(N'[dbo].[visits]')", sqls[0][0])
        self.assertIn('OFFSET 50 ROWS', sqls[1][0])

    def test_refused_query_never_reaches_the_server(self):
        with mock.patch.object(sq, 'STATE_DIR', self.state), mock.patch.object(sq, 'sqlcmd') as run_sql:
            with self.assertRaises(sq.SQLError):
                actions.query('shop1234_orders', 'shop.example.com', 'DROP TABLE visits')
            run_sql.assert_not_called()


class ViewerViews(Views):
    BODY = {'name': 'shop1234_orders', 'domain': 'other.com', 'schema': 'dbo', 'table': 'visits'}

    def test_users_need_policy_and_ownership(self):
        for view in (views.tables, views.columns, views.rows, views.query):
            self.assertEqual(self.post(view, dict(self.BODY, content='SELECT 1'), owns=True)[0], 403)  # policy off
            status, _, call = self.post(view, dict(self.BODY, content='SELECT 1'), owns=False, policy={'mssql_for_users': True})
            self.assertEqual(status, 403, view.__name__)
            call.assert_not_called()

    def test_owner_and_admin_reach_the_runner(self):
        body = dict(self.BODY, domain='shop.example.com', page=3)
        _, _, call = self.post(views.rows, body, policy={'mssql_for_users': True})
        call.assert_called_once_with('mssql', 'rows', name='shop1234_orders', domain='shop.example.com',
                                     schema='dbo', table='visits', page=3)
        # Administrators may browse any site's database, even with the user feature off.
        _, _, call = self.post(views.tables, dict(self.BODY), admin=1, owns=False)
        call.assert_called_once_with('mssql', 'tables', name='shop1234_orders', domain='other.com')
        _, _, call = self.post(views.query, dict(self.BODY, content="SELECT ';' AS x;"), admin=1, owns=False)
        call.assert_called_once_with('mssql', 'query', name='shop1234_orders', domain='other.com', sql="SELECT ';' AS x;")

    def test_bad_input_is_refused_before_the_runner(self):
        for view, body in ((views.columns, dict(self.BODY, table='x]; DROP TABLE y')),
                           (views.rows, dict(self.BODY, page=-1)),
                           (views.rows, dict(self.BODY, page='2')),
                           (views.tables, dict(self.BODY, name='bad name')),
                           (views.query, dict(self.BODY, content='DELETE FROM visits')),
                           (views.query, dict(self.BODY, content='SELECT 1 GO')),
                           (views.query, dict(self.BODY, content=['SELECT 1']))):
            status, _, call = self.post(view, body, admin=1)
            self.assertEqual(status, 400, body)
            call.assert_not_called()


class ViewerErrors(SimpleTestCase):
    def test_error_keeps_sql_servers_message(self):
        out = sq.DOC_MARK + '\n[{"error_message":"x"}]\n' + sq.DOC_MARK + "\nMsg 208, Level 16, State 1\nInvalid object name 'nosuch'."
        with self.assertRaises(sq.SQLError) as caught:
            sq.viewer_run('SELECT 1', 'x', 'shop1234_orders', lambda argv, **k: SimpleNamespace(returncode=1, stdout=out))
        self.assertEqual(str(caught.exception), "SQL Server reported an error: Msg 208, Level 16, State 1\nInvalid object name 'nosuch'.")

    def test_capped_runner_stops_at_the_limit(self):
        with self.assertRaisesRegex(sq.SQLError, '2 MB'):
            sq.capped_runner(['sh', '-c', 'head -c 5000 /dev/zero'], timeout=10, limit=1000)
        self.assertEqual(sq.capped_runner(['sh', '-c', 'printf ok'], timeout=10).stdout, 'ok')


# ----------------------------------------------------------------------------- changes (DML mode)

class ChangeFilter(SimpleTestCase):
    ALLOWED = {
        'UPDATE dbo.visits SET at = SYSDATETIME() WHERE id = 4': ('UPDATE', True, False),
        'update visits set a = 1, b = (SELECT MAX(x) FROM y WHERE y.k = visits.k) where id in (select id from z);': ('UPDATE', True, False),
        'DELETE FROM visits WHERE id = 3': ('DELETE', True, False),
        'DELETE TOP (5) FROM visits': ('DELETE', False, False),
        'DELETE FROM visits OUTPUT deleted.* WHERE id = 1': ('DELETE', True, True),
        'INSERT INTO visits (at) VALUES (SYSDATETIME())': ('INSERT', False, False),
        'INSERT visits DEFAULT VALUES': ('INSERT', False, False),
        'INSERT INTO visits (at) OUTPUT inserted.id VALUES (SYSDATETIME()), (NULL)': ('INSERT', False, True),
        'INSERT INTO t (a) SELECT 1 UNION ALL SELECT 2 EXCEPT SELECT 3': ('INSERT', False, False),
        'INSERT INTO t (a) SELECT v FROM (VALUES (1), (2)) AS x(v)': ('INSERT', False, False),
        'WITH old AS (SELECT TOP 10 * FROM visits ORDER BY at) DELETE FROM old': ('DELETE', False, False),
        "UPDATE visits SET note = N'SET; DELETE -- not code' WHERE id = 1": ('UPDATE', True, False),
        'UPDATE [update] SET [delete] = 1 WHERE [where] = 2': ('UPDATE', True, False),
        ('MERGE INTO t USING s ON t.id = s.id WHEN MATCHED AND s.gone = 1 THEN DELETE '
         'WHEN MATCHED THEN UPDATE SET t.a = s.a WHEN NOT MATCHED THEN INSERT (id, a) VALUES (s.id, s.a) '
         'OUTPUT $action, inserted.id;'): ('MERGE', False, True),
        'SELECT * FROM visits': ('SELECT', True, False),
    }
    REFUSED = [
        'CREATE TABLE x (a int)', 'ALTER TABLE visits ADD b int', 'DROP TABLE visits', 'TRUNCATE TABLE visits',
        'UPDATE visits SET a = 1 WHERE id = 1 DROP TABLE visits',
        'EXEC sp_who', 'EXECUTE xp_cmdshell', 'INSERT INTO t EXEC sp_who', 'SELECT * FROM sys.sp_helptext',
        'GRANT SELECT ON visits TO public', 'DENY SELECT ON visits TO x', 'REVOKE SELECT ON visits FROM x',
        "BACKUP DATABASE x TO DISK = '/tmp/x'", "RESTORE DATABASE x FROM DISK = '/tmp/x'", 'SHUTDOWN', 'DBCC CHECKIDENT(visits)',
        "INSERT INTO t SELECT * FROM OPENROWSET(BULK '/etc/passwd', SINGLE_CLOB) x",
        "DELETE FROM OPENQUERY(srv, 'SELECT 1')", "UPDATE OPENDATASOURCE('x', 'y').a.b.c SET a = 1",
        'UPDATE visits SET a = 1 WHERE id = 1\nGO\nDELETE FROM visits', 'UPDATE visits SET a = 1 GO',
        "UPDATE visits SET a = 1 WHERE id = 1\n:!! id", 'USE master', 'UPDATE visits SET a = 1; DELETE FROM visits',
        'UPDATE visits SET a = 1 DELETE FROM visits',                       # no ';' needed between statements
        'DELETE FROM visits WHERE id = 1 INSERT INTO visits DEFAULT VALUES',
        'INSERT INTO visits VALUES (1) SELECT * FROM sys.sql_logins',
        'INSERT INTO t SELECT 1 SELECT 2', 'UPDATE visits SET a = 1 WHERE id = 1 SELECT 1',
        'UPDATE visits SET a = 1 SET ROWCOUNT 0', 'DELETE FROM visits SET ROWCOUNT 0',
        'UPDATE visits SET a = 1 WHERE b IN (SELECT 1) BEGIN TRANSACTION', 'BEGIN TRAN', 'COMMIT', 'ROLLBACK',
        'SELECT * INTO copy FROM visits', 'INSERT INTO t OUTPUT inserted.* INTO audit VALUES (1)',
        'DELETE FROM t OUTPUT deleted.* INTO audit', 'UPDATE STATISTICS visits',
        'UPDATE visits SET a = 1 WHERE id = 1 DISABLE TRIGGER trg ON visits', 'REVERT', 'DECLARE @x int',
        'MERGE t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a = 1 UPDATE t SET b = 2',
        'INSERT INTO t SELECT * FROM (DELETE FROM x OUTPUT deleted.*) d',  # nested DML
        'UPDATE visits SET a = 1 /* unterminated', 'MERGE t USING s ON 1 = 1 WHEN MATCHED THEN DELETE; DROP TABLE t',
        'x' * (sq.MAX_QUERY_CHARS + 1), '',
    ]

    def test_allowed(self):
        for sql, (verb, where, output) in self.ALLOWED.items():
            info = sq.change_query(sql)
            self.assertEqual((info['verb'], info['where'], info['output']), (verb, where, output), sql)

    def test_refused(self):
        for sql in self.REFUSED:
            with self.assertRaises(sq.SQLError, msg=sql):
                sq.change_query(sql)

    def test_read_only_mode_still_refuses_changes(self):
        for sql in list(self.ALLOWED)[:-1]:
            with self.assertRaises(sq.SQLError, msg=sql):
                sq.readonly_query(sql)
        with self.assertRaisesRegex(sq.SQLError, 'Allow changes'):
            sq.refuse_readonly('DELETE FROM visits WHERE id = 1', sq.SQLError('x'))
        with self.assertRaisesRegex(sq.SQLError, '^x$'):
            sq.refuse_readonly('DROP TABLE visits', sq.SQLError('x'))

    def test_dml_batch_is_sandboxed_and_committed(self):
        sql = sq.dml_sql('shop1234_orders', "UPDATE visits SET note = N'it''s' WHERE id = 4 -- tail")
        order = [sql.index(p) for p in ('SET XACT_ABORT ON;', 'BEGIN TRANSACTION;', "EXECUTE AS LOGIN = N'shop1234_orders';",
                                        'EXEC sp_executesql @ua_run', 'REVERT;', 'COMMIT;', sq.END_MARK)]
        self.assertEqual(order, sorted(order))
        self.assertIn('SET LOCK_TIMEOUT 5000;', sql)
        self.assertNotIn('ROLLBACK', sql)
        self.assertNotIn('SET ROWCOUNT', sql)  # would cap the rows a change affects
        # The statement is one N'' literal (quotes doubled), with ';' on its own line after a trailing comment.
        self.assertIn("DECLARE @ua_q nvarchar(max) = N'UPDATE visits SET note = N''it''''s'' WHERE id = 4 -- tail\n;';", sql)
        self.assertIn('@@ROWCOUNT', sql)
        out = sq.dml_sql('shop1234_orders', 'DELETE FROM visits OUTPUT deleted.id WHERE id = 1')
        self.assertIn('INSERT INTO #ua_out EXEC sp_executesql @q', out)
        self.assertIn('sys.dm_exec_describe_first_result_set(@ua_q', out)
        self.assertIn('TOP (500)', out)
        self.assertIn('ROLLBACK;', sq.dml_sql('shop1234_orders', 'DELETE FROM visits WHERE id = 1', commit=False))
        with self.assertRaises(sq.SQLError):
            sq.dml_sql('shop1234_orders', 'SELECT 1')
        with self.assertRaises(sq.SQLError):
            sq.dml_sql('shop1234_orders', 'DROP TABLE visits')

    def test_change_result(self):
        describe = [{'name': 'old_at', 'type': 'datetime2(7)'}, {'name': 'id', 'type': 'int'}, {'name': 'h', 'type': 'varbinary(8)'}]
        out = _sqlcmd_output(describe, [{'c1': '2030-01-01T00:00:00', 'c2': 4, 'c3': 'AAE='}], {'affected': 1})
        result = sq.change_result(sq.documents(out), 'update')
        self.assertEqual(result['affected'], 1)
        self.assertEqual(result['columns'], ['old_at', 'id', 'h'])
        self.assertEqual(result['rows'], [['2030-01-01T00:00:00', 4, '0x0001']])
        plain = sq.change_result(sq.documents(_sqlcmd_output(None, None, {'affected': 7})), 'delete')
        self.assertEqual((plain['affected'], plain['columns'], plain['rows']), (7, [], []))


class ChangeActions(SimpleTestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp()
        sq.save_registry({'shop1234_orders': {'domain': 'shop.example.com', 'login': 'shop1234_orders', 'created': 1}}, self.state)

    def patched(self, outputs=None):
        sent = []

        def fake(sql, password, runner, database, options, timeout):
            sent.append(sql)
            return outputs.pop(0)
        return sent, (mock.patch.object(sq, 'STATE_DIR', self.state), mock.patch.object(actions, '_installed', return_value=True),
                      mock.patch.object(sq, 'sa_password', return_value='x'), mock.patch.object(sq, 'sqlcmd', side_effect=fake))

    def run_with(self, call, outputs=None):
        sent, patches = self.patched(list(outputs or []))
        with patches[0], patches[1], patches[2], patches[3]:
            return call(), sent

    def test_dml_only_with_write(self):
        with self.assertRaisesRegex(sq.SQLError, 'Allow changes'):
            self.run_with(lambda: actions.query('shop1234_orders', 'shop.example.com', 'DELETE FROM visits WHERE id = 1'))
        with self.assertRaisesRegex(sq.SQLError, 'Allow changes'):
            self.run_with(lambda: actions.query('shop1234_orders', 'shop.example.com', 'INSERT INTO visits DEFAULT VALUES', write='true'))
        result, sent = self.run_with(lambda: actions.query('shop1234_orders', 'shop.example.com', 'DELETE FROM visits WHERE id = 1',
                                                           write=True), [_sqlcmd_output(None, None, {'affected': 1})])
        self.assertEqual(result['affected'], 1)
        self.assertIn('COMMIT;', sent[0])
        # A SELECT with "Allow changes" is still the read-only, rolled-back path.
        result, sent = self.run_with(lambda: actions.query('shop1234_orders', 'shop.example.com', 'SELECT 1 AS a', write=True),
                                     [_sqlcmd_output([{'name': 'a', 'type': 'int', 'error_message': None}], [{'a': 1}])])
        self.assertEqual(result['rows'], [[1]])
        self.assertIn('ROLLBACK;', sent[0])
        self.assertNotIn('COMMIT', sent[0])

    def test_whole_table_changes_need_confirm_all(self):
        for sql in ('DELETE FROM visits', 'UPDATE visits SET at = NULL', 'WITH c AS (SELECT * FROM visits WHERE id > 1) DELETE FROM c'):
            with self.assertRaisesRegex(sq.SQLError, 'confirm'):
                self.run_with(lambda: actions.query('shop1234_orders', 'shop.example.com', sql, write=True))
            with self.assertRaisesRegex(sq.SQLError, 'confirm'):
                self.run_with(lambda: actions.query('shop1234_orders', 'shop.example.com', sql, write=True, confirm_all='yes'))
            result, sent = self.run_with(lambda: actions.query('shop1234_orders', 'shop.example.com', sql, write=True, confirm_all=True),
                                         [_sqlcmd_output(None, None, {'affected': 3})])
            self.assertEqual(result['affected'], 3)
        # INSERT and MERGE have no WHERE to forget.
        self.run_with(lambda: actions.query('shop1234_orders', 'shop.example.com', 'INSERT INTO visits DEFAULT VALUES', write=True),
                      [_sqlcmd_output(None, None, {'affected': 1})])

    def test_ddl_and_exec_refused_even_with_write(self):
        for sql in ('DROP TABLE visits', 'EXEC sp_who', 'CREATE TABLE x (a int)', 'TRUNCATE TABLE visits', 'ALTER TABLE visits ADD b int'):
            sent, patches = self.patched([])
            with patches[0], patches[1], patches[2], patches[3]:
                with self.assertRaises(sq.SQLError, msg=sql):
                    actions.query('shop1234_orders', 'shop.example.com', sql, write=True, confirm_all=True)
            self.assertEqual(sent, [])

    def test_new_actions_check_ownership(self):
        sent, patches = self.patched([])
        with patches[0], patches[1], patches[2], patches[3]:
            for call in (lambda: actions.structure('shop1234_orders', 'other.com', 'dbo', 'visits'),
                         lambda: actions.update_row('shop1234_orders', 'other.com', 'dbo', 'visits', {'id': 1}, {'at': None}),
                         lambda: actions.delete_row('shop1234_orders', 'other.com', 'dbo', 'visits', {'id': 1}),
                         lambda: actions.insert_row('shop1234_orders', 'other.com', 'dbo', 'visits', {}),
                         lambda: actions.query('shop1234_orders', 'other.com', 'DELETE FROM visits WHERE id = 1', write=True),
                         lambda: actions.rows('shop1234_orders', 'other.com', 'dbo', 'visits', 0, 25, 'id'),
                         lambda: actions.insert_row('nope_db', 'shop.example.com', 'dbo', 'visits', {})):
                with self.assertRaisesRegex(sq.SQLError, 'Unknown database'):
                    call()
        self.assertEqual(sent, [])

    COLUMNS = [{'name': 'id', 'type': 'int', 'base': 'int', 'max_length': 4, 'nullable': False, 'pk': 1, 'identity': True, 'kind': 'table'},
               {'name': 'at', 'type': 'datetime2', 'base': 'datetime2', 'max_length': 8, 'scale': 7, 'nullable': True, 'pk': None}]

    def test_owner_edits_a_row(self):
        result, sent = self.run_with(lambda: actions.update_row('shop1234_orders', 'shop.example.com', 'dbo', 'visits',
                                                                {'id': '4'}, {'at': '2030-01-01'}),
                                     [_sqlcmd_output(self.COLUMNS), _sqlcmd_output(None, None, {'affected': 1})])
        self.assertEqual(result['affected'], 1)
        self.assertIn("EXEC sp_executesql N'UPDATE [dbo].[visits] SET [at] = @p0 WHERE [id] = @k0;", sent[1])
        self.assertIn("@p0 = N'2030-01-01', @k0 = N'4'", sent[1])
        self.assertIn('IF @ua_n > 1 BEGIN ROLLBACK;', sent[1])
        self.assertIn("EXECUTE AS LOGIN = N'shop1234_orders';", sent[1])
        with self.assertRaisesRegex(sq.SQLError, 'identity'):
            self.run_with(lambda: actions.update_row('shop1234_orders', 'shop.example.com', 'dbo', 'visits', {'id': '4'}, {'id': '5'}),
                          [_sqlcmd_output(self.COLUMNS)])


class RowStatements(SimpleTestCase):
    COLUMNS = [
        {'name': 'id', 'type': 'int', 'base': 'int', 'max_length': 4, 'nullable': False, 'pk': 1, 'identity': True, 'kind': 'table'},
        {'name': 'code', 'type': 'nvarchar', 'base': 'nvarchar', 'max_length': 20, 'nullable': False, 'pk': 2},
        {'name': 'name', 'type': 'nvarchar', 'base': 'nvarchar', 'max_length': -1, 'nullable': True},
        {'name': 'qty', 'type': 'smallint', 'base': 'smallint', 'max_length': 2, 'nullable': True},
        {'name': 'price', 'type': 'decimal', 'base': 'decimal', 'max_length': 9, 'precision': 6, 'scale': 2, 'nullable': True},
        {'name': 'ok', 'type': 'bit', 'base': 'bit', 'max_length': 1, 'nullable': True},
        {'name': 'hash', 'type': 'varbinary', 'base': 'varbinary', 'max_length': 4, 'nullable': True},
        {'name': 'total', 'type': 'decimal', 'base': 'decimal', 'max_length': 9, 'precision': 9, 'scale': 2, 'nullable': True, 'computed': True},
        {'name': 'ver', 'type': 'timestamp', 'base': 'timestamp', 'max_length': 8, 'nullable': False},
        {'name': 'where]', 'type': 'char', 'base': 'char', 'max_length': 3, 'nullable': True},
    ]

    def test_update_parameters(self):
        statement, params = sq.row_statement('update', 'dbo', 'items', self.COLUMNS, {'id': 7, 'code': "A'1"},
                                             {'name': 'Grüße 😀 \'quoted\'', 'qty': None, 'ok': True, 'where]': 'x'})
        self.assertEqual(statement, 'UPDATE [dbo].[items] SET [name] = @p0, [ok] = @p1, [qty] = @p2, [where]]] = @p3 '
                                    'WHERE [id] = @k0 AND [code] = @k1;')
        self.assertEqual(params, [('@p0', 'nvarchar(max)', "N'Grüße 😀 ''quoted'''"), ('@p1', 'bit', "N'1'"),
                                  ('@p2', 'smallint', 'NULL'), ('@p3', 'char(3)', "N'x'"),
                                  ('@k0', 'int', "N'7'"), ('@k1', 'nvarchar(10)', "N'A''1'")])
        batch = sq.row_sql('shop1234_orders', 'dbo', 'items', self.COLUMNS, 'update', {'id': 7, 'code': 'A'}, {'qty': '3'})
        self.assertIn("N'@p0 smallint, @k0 int, @k1 nvarchar(10), @ua_rc bigint OUTPUT', @p0 = N'3', @k0 = N'7', @k1 = N'A', "
                      "@ua_rc = @ua_n OUTPUT;", batch)
        self.assertIn('COMMIT;', batch)

    def test_values_never_enter_the_statement(self):
        evil = "x'); DROP TABLE items; --"
        statement, params = sq.row_statement('update', 'dbo', 'items', self.COLUMNS, {'id': 1, 'code': "a'--"}, {'name': evil})
        self.assertNotIn('DROP', statement)
        self.assertNotIn("a'", statement)
        batch = sq.row_sql('l1', 'dbo', 'items', self.COLUMNS, 'update', {'id': 1, 'code': 'a'}, {'name': evil})
        self.assertIn("@p0 = N'x''); DROP TABLE items; --'", batch)

    def test_insert_skips_identity_computed_rowversion_and_empty(self):
        statement, params = sq.row_statement('insert', 'dbo', 'items', self.COLUMNS,
                                             values={'id': '99', 'code': 'Ü1', 'name': '', 'qty': None, 'total': '1', 'ver': '0x00',
                                                     'hash': '0xBEEF', 'price': '1234.56'})
        self.assertEqual(statement, 'INSERT INTO [dbo].[items] ([code], [qty], [price], [hash]) VALUES (@p0, @p1, @p2, @p3);')
        self.assertEqual([p[1:] for p in params], [('nvarchar(10)', "N'Ü1'"), ('smallint', 'NULL'), ('decimal(6,2)', "N'1234.56'"),
                                                   ('varbinary(4)', '0xBEEF')])
        self.assertEqual(sq.row_statement('insert', 'dbo', 'items', self.COLUMNS, values={'id': ''}),
                         ('INSERT INTO [dbo].[items] DEFAULT VALUES;', []))
        with self.assertRaisesRegex(sq.SQLError, 'Unknown column'):
            sq.row_statement('insert', 'dbo', 'items', self.COLUMNS, values={'nope': '1'})
        view = [dict(self.COLUMNS[2], kind='view')]
        with self.assertRaisesRegex(sq.SQLError, 'tables'):
            sq.row_statement('insert', 'dbo', 'v', view, values={'name': 'x'})

    def test_delete_parameters(self):
        statement, params = sq.row_statement('delete', 'dbo', 'items', self.COLUMNS, {'code': 'a', 'id': '3'})
        self.assertEqual(statement, 'DELETE FROM [dbo].[items] WHERE [id] = @k0 AND [code] = @k1;')
        self.assertEqual(params, [('@k0', 'int', "N'3'"), ('@k1', 'nvarchar(10)', "N'a'")])
        for key in ({'id': '3'}, {'id': '3', 'code': 'a', 'qty': 1}, {'id': None, 'code': 'a'}, ['3'], None):
            with self.assertRaises(sq.SQLError, msg=key):
                sq.row_statement('delete', 'dbo', 'items', self.COLUMNS, key)
        with self.assertRaisesRegex(sq.SQLError, 'primary key'):
            sq.row_statement('delete', 'dbo', 'log', [self.COLUMNS[2]], {'name': 'x'})

    def test_type_validation(self):
        key = {'id': 1, 'code': 'a'}
        for values in ({'qty': '40000'}, {'qty': '1.5'}, {'qty': ''}, {'qty': True}, {'price': '12345.6'}, {'price': 'abc'},
                       {'ok': 'maybe'}, {'hash': 'BEEF'}, {'hash': '0x0102030405'}, {'where]': 'abcd'}, {'code': None},
                       {'total': '1'}, {'ver': '0x00'}, {'name': 'a\x00b'}, {'nope': 1}, {'name': ['x']}, {}):
            with self.assertRaises(sq.SQLError, msg=values):
                sq.row_statement('update', 'dbo', 'items', self.COLUMNS, key, values)
        ok = {'qty': '-32768', 'price': '-9999.99', 'ok': 'false', 'hash': '0x', 'where]': 'abc', 'name': None}
        _, params = sq.row_statement('update', 'dbo', 'items', self.COLUMNS, key, ok)
        self.assertIn(('@p0', 'varbinary(4)', '0x'), params)
        self.assertIn(('@p2', 'bit', "N'0'"), params)
        guid = {'name': 'g', 'type': 'uniqueidentifier', 'base': 'uniqueidentifier', 'max_length': 16, 'nullable': False}
        self.assertEqual(sq.value_literal(guid, '6F9619FF-8B86-D011-B42D-00C04FC964FF'), "N'6F9619FF-8B86-D011-B42D-00C04FC964FF'")
        with self.assertRaises(sq.SQLError):
            sq.value_literal(guid, "6F9619FF' OR 1=1 --")
        when = {'name': 'w', 'base': 'datetime2', 'scale': 3, 'nullable': True}
        self.assertEqual(sq.param_type(when), 'datetime2(3)')
        with self.assertRaises(sq.SQLError):
            sq.value_literal(when, "2024-01-01'; DROP")
        self.assertIsNone(sq.param_type({'base': 'geography', 'clr': True}))


class ExportAndBrowse(SimpleTestCase):
    def test_csv_quoting(self):
        text = sq.to_csv(['id', 'note, "quoted"', 'ü'], [[1, 'a,b', None], [2, 'say "hi"\nnext line', True],
                                                      [3, '', [('k', 'v')]], [4, ' lead', 'Grüße 😀']])
        self.assertTrue(text.startswith('﻿'))
        self.assertEqual(text[1:].split('\r\n'), [
            'id,"note, ""quoted""",ü', '1,"a,b",', '2,"say ""hi""\nnext line",1', '3,,"{""k"": ""v""}"', '4, lead,Grüße 😀', ''])
        import csv
        import io
        self.assertEqual(list(csv.reader(io.StringIO(text[1:])))[2], ['2', 'say "hi"\nnext line', '1'])

    def test_json_export(self):
        self.assertEqual(json.loads(sq.to_json(['id', 'id', 'x'], [[1, 2, None]])), [{'id': 1, 'id_2': 2, 'x': None}])

    COLUMNS = [{'name': 'id', 'base': 'int', 'pk': 1}, {'name': 'note', 'base': 'ntext'}, {'name': 'odd]name', 'base': 'nvarchar', 'max_length': 20},
               {'name': 'at', 'base': 'datetime'}, {'name': 'g', 'base': 'geography', 'clr': True}]

    def test_sort_and_filter_names_are_validated(self):
        for kwargs in ({'sort': 'nope'}, {'sort': 'note'}, {'sort': 'g'}, {'sort': 'ID'}, {'page_size': 30}, {'page_size': True},
                       {'filter_column': 'nope', 'filter_text': 'x'}, {'filter_column': None, 'filter_text': 'x'},
                       {'filter_column': 'id', 'filter_text': 'x' * 201}, {'filter_column': 'id', 'filter_text': 5}):
            with self.assertRaises(sq.SQLError, msg=kwargs):
                sq.browse_options(self.COLUMNS, **dict({'page_size': 25}, **kwargs))
        sql = sq.rows_sql('l1', 'dbo', 't', self.COLUMNS, 1, 25, 'odd]name', True, 'odd]name', "50%_off' [x]")
        self.assertIn('ORDER BY [odd]]name] DESC, [id] OFFSET 25 ROWS FETCH NEXT 25 ROWS ONLY', sql)
        self.assertIn("WHERE CONVERT(nvarchar(max), [odd]]name]) LIKE @f ESCAPE N''\\''", sql)
        # The filter text is only the parameter value, wildcards escaped.
        self.assertIn("@f = N'%50\\%\\_off'' \\[x]%';", sql)
        self.assertEqual(sql.count('50%'), 0)
        self.assertEqual(sql.count('off'), 1)
        self.assertEqual(sq.like_pattern('a\\b%c_d[e'), '%a\\\\b\\%c\\_d\\[e%')
        self.assertIn('CONVERT(nvarchar(max), [at], 121) LIKE', sq.rows_sql('l1', 'dbo', 't', self.COLUMNS, 0, 50, None, False, 'at', '2024'))
        self.assertIn('[g].ToString() LIKE', sq.rows_sql('l1', 'dbo', 't', self.COLUMNS, 0, 50, None, False, 'g', 'POINT'))
        self.assertIn('CONVERT(nvarchar(4000), [id]) AS [k0]', sql)  # exact key text for edit/delete

    def test_structure_sql(self):
        sql = sq.structure_sql('l1', 'dbo', 'visits')
        for part in ('sys.indexes', 'sys.foreign_keys', 'sys.dm_db_partition_stats', "OBJECT_ID(N'[dbo].[visits]')", 'ROLLBACK;'):
            self.assertIn(part, sql)
        self.assertEqual(sql.count(sq.DOC_MARK), 3)
        with self.assertRaises(sq.SQLError):
            sq.structure_sql('l1', 'dbo', 'x]; DROP TABLE y')


class ChangeViews(Views):
    BODY = {'name': 'shop1234_orders', 'domain': 'shop.example.com', 'schema': 'dbo', 'table': 'visits'}
    USERS = {'mssql_for_users': True}

    def test_new_endpoints_need_policy_and_ownership(self):
        body = dict(self.BODY, row={'key': {'id': 1}, 'values': {'at': None}}, format='csv', source='rows')
        for view in (views.structure, views.update_row, views.delete_row, views.insert_row, views.export):
            self.assertEqual(self.post(view, body)[0], 403, view.__name__)  # policy off
            status, _, call = self.post(view, dict(body, domain='other.com'), owns=False, policy=self.USERS)
            self.assertEqual(status, 403, view.__name__)
            call.assert_not_called()

    def test_query_write_flags(self):
        status, _, call = self.post(views.query, dict(self.BODY, content='DELETE FROM visits WHERE id = 1'), policy=self.USERS)
        self.assertEqual(status, 400)
        call.assert_not_called()
        status, data, call = self.post(views.query, dict(self.BODY, content='DELETE FROM visits', write=True), policy=self.USERS)
        self.assertTrue(data['result']['needs_confirm'])
        call.assert_not_called()
        _, _, call = self.post(views.query, dict(self.BODY, content='DELETE FROM visits', write=True, confirm_all=True), policy=self.USERS)
        call.assert_called_once_with('mssql', 'query', name='shop1234_orders', domain='shop.example.com', sql='DELETE FROM visits',
                                     write=True, confirm_all=True)
        status, _, call = self.post(views.query, dict(self.BODY, content='DROP TABLE visits', write=True, confirm_all=True), policy=self.USERS)
        self.assertEqual(status, 400)
        call.assert_not_called()

    def test_row_data_travels_in_the_row_object(self):
        row = {'key': {'id': 4}, 'values': {"we]ird; (name)": "it's; DROP", 'at': None}}
        _, _, call = self.post(views.update_row, dict(self.BODY, row=row), policy=self.USERS)
        call.assert_called_once_with('mssql', 'update_row', name='shop1234_orders', domain='shop.example.com', schema='dbo',
                                     table='visits', key={'id': 4}, values=row['values'])
        _, _, call = self.post(views.insert_row, dict(self.BODY, row={'values': {}}), policy=self.USERS)
        call.assert_called_once_with('mssql', 'insert_row', name='shop1234_orders', domain='shop.example.com', schema='dbo',
                                     table='visits', values={})
        for view, bad in ((views.update_row, {'key': {'id': 4}, 'values': {}}), (views.update_row, {'key': 4, 'values': {'a': 1}}),
                          (views.delete_row, {'key': None}), (views.insert_row, {'values': {'a': {'nested': 1}}}),
                          (views.insert_row, {'values': {'a': 'x' * (sq.MAX_ROW_CHARS + 1)}}), (views.insert_row, 'x')):
            status, _, call = self.post(view, dict(self.BODY, row=bad), policy=self.USERS)
            self.assertEqual(status, 400, bad)
            call.assert_not_called()

    def test_browse_options(self):
        body = dict(self.BODY, page=2, browse={'pageSize': 100, 'sort': 'at', 'desc': True, 'filterColumn': 'at', 'filterText': "50%; '"})
        _, _, call = self.post(views.rows, body, policy=self.USERS)
        call.assert_called_once_with('mssql', 'rows', name='shop1234_orders', domain='shop.example.com', schema='dbo', table='visits',
                                     page=2, page_size=100, sort='at', descending=True, filter_column='at', filter_text="50%; '")
        for browse in ({'pageSize': 10}, {'pageSize': '25'}, {'filterText': 'x'}, {'sort': ['a']}, 'x', {'filterText': 'x' * 201, 'filterColumn': 'a'}):
            status, _, call = self.post(views.rows, dict(self.BODY, browse=browse), policy=self.USERS)
            self.assertEqual(status, 400, browse)
            call.assert_not_called()

    def export(self, body):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 3}
        result = {'columns': ['id', 'note'], 'rows': [[1, 'a,"b"']]}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': 1}), \
                mock.patch('loginSystem.models.Administrator.objects.get', return_value=object()), \
                mock.patch('universalAddons.privileged.call', return_value=result) as call:
            return views.export(request), call

    def test_export(self):
        response, call = self.export(dict(self.BODY, source='rows', format='csv', page=0, browse={'pageSize': 25}))
        self.assertEqual(response['Content-Type'], 'text/csv; charset=utf-8')
        self.assertEqual(response['Content-Disposition'], 'attachment; filename="shop1234_orders_dbo_visits_page1.csv"')
        self.assertEqual(response.content.decode('utf-8'), '﻿id,note\r\n1,"a,""b"""\r\n')
        self.assertEqual(call.call_args[0][:2], ('mssql', 'rows'))
        response, call = self.export(dict(self.BODY, source='query', format='json', content='SELECT 1'))
        self.assertEqual(json.loads(response.content), [{'id': 1, 'note': 'a,"b"'}])
        call.assert_called_once_with('mssql', 'query', name='shop1234_orders', domain='shop.example.com', sql='SELECT 1')
        for body in (dict(self.BODY, source='query', format='csv', content='DELETE FROM visits WHERE id = 1'),
                     dict(self.BODY, source='rows', format='xlsx'), dict(self.BODY, source='other', format='csv'),
                     dict(self.BODY, source='rows', format='csv', table='x]; DROP')):
            response, call = self.export(body)
            self.assertEqual(response.status_code, 400, body)
            call.assert_not_called()


class CsvInjection(SimpleTestCase):
    def test_formula_cells_are_neutralised_numbers_kept(self):
        out = sq.to_csv(['a', 'b'], [['=HYPERLINK("x")', '-12.5'], ['@SUM(A1)', '+1-2']])
        self.assertIn("'=HYPERLINK", out)
        self.assertIn('-12.5', out)
        self.assertNotIn("'-12.5", out)
        self.assertIn("'@SUM", out)
        self.assertIn("'+1-2", out)

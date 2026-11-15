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

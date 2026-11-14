import json
import os
import shutil
import tempfile
from contextlib import contextmanager
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import include, path

from universalAddons.mysqlmgr import actions, service as sv, views
from universalAddons.mysqlmgr.service import GB, MB, MySQLError

# URLconf for the render test until the module is mounted in universalAddons/urls.py.
import CyberCP.urls  # noqa: E402
urlpatterns = list(CyberCP.urls.urlpatterns) + [path('addons/mysql/', include('universalAddons.mysqlmgr.urls'))]


def variables(**extra):
    v = {'version': '10.3.28-MariaDB', 'innodb_buffer_pool_size': str(128 * MB), 'innodb_buffer_pool_chunk_size':
         str(128 * MB), 'innodb_buffer_pool_instances': '1', 'key_buffer_size': str(128 * MB),
         'query_cache_type': 'OFF', 'query_cache_size': str(MB), 'tmp_table_size': str(16 * MB),
         'max_heap_table_size': str(16 * MB), 'table_open_cache': '2000', 'table_definition_cache': '400',
         'innodb_log_file_size': str(48 * MB), 'innodb_log_files_in_group': '2', 'max_connections': '151',
         'thread_cache_size': '151', 'innodb_flush_method': 'fsync', 'slow_query_log': 'OFF',
         'long_query_time': '10.000000', 'innodb_force_recovery': '0', 'open_files_limit': '32184',
         'aria_pagecache_buffer_size': str(128 * MB), 'innodb_log_buffer_size': str(16 * MB),
         'sort_buffer_size': str(2 * MB), 'join_buffer_size': '262144', 'read_buffer_size': '131072',
         'read_rnd_buffer_size': '262144', 'thread_stack': '299008', 'binlog_cache_size': '32768'}
    v.update({k: str(x) for k, x in extra.items()})
    return v


def counters(**extra):
    s = {'Uptime': '864000', 'Questions': '8640000', 'Threads_connected': '11', 'Max_used_connections': '16',
         'Innodb_buffer_pool_read_requests': '1000000', 'Innodb_buffer_pool_reads': '50000',
         'Innodb_buffer_pool_pages_total': '8191', 'Innodb_buffer_pool_pages_free': '100',
         'Created_tmp_tables': '10000', 'Created_tmp_disk_tables': '500', 'Open_tables': '500',
         'Opened_tables': '600', 'Innodb_os_log_written': str(240 * 10 * MB), 'Connections': '5000',
         'Threads_created': '20', 'Slow_queries': '3'}
    s.update({k: str(x) for k, x in extra.items()})
    return s


ROOMY = {'total': 8 * GB, 'available': 5 * GB, 'swap_total': 2 * GB, 'swap_free': 2 * GB, 'oom_kills': 0}
SHORT = {'total': 3736 * MB, 'available': 488 * MB, 'swap_total': 1828 * MB, 'swap_free': 0, 'oom_kills': 9}
ENGINES = {'InnoDB': {'tables': 1857, 'bytes': 2 * GB, 'index_bytes': 0},
           'MyISAM': {'tables': 25, 'bytes': 291940, 'index_bytes': 100000}}


def recs(result):
    return {r['variable']: r for r in result['recommendations']}


class Advisor(SimpleTestCase):
    def test_buffer_pool_sized_from_data_and_ram(self):
        r = recs(sv.advise(variables(), counters(), ROOMY, ENGINES, 1900))
        # 2 GiB of data * 1.2 = 2.4 GiB, rounded up to the 128M chunk; ceiling 40% of 8 GiB = 3200M
        self.assertEqual(r['innodb_buffer_pool_size']['recommended'], '2560M')
        self.assertTrue(r['innodb_buffer_pool_size']['applicable'])
        small = recs(sv.advise(variables(), counters(), {'total': 2 * GB, 'available': GB, 'swap_total': 0,
                                                         'swap_free': 0}, ENGINES, 1900))
        self.assertEqual(small['innodb_buffer_pool_size']['recommended'], '512M', '25% of 2 GiB')

    def test_memory_pressure_never_raises_memory(self):
        result = sv.advise(variables(), counters(Max_used_connections=150), SHORT, ENGINES, 1900)
        r = recs(result)
        self.assertEqual(r['innodb_buffer_pool_size']['level'], 'warn')
        self.assertFalse(r['innodb_buffer_pool_size']['applicable'])
        self.assertFalse(r['max_connections']['applicable'])
        self.assertEqual(len(result['pressure']), 3)
        self.assertEqual(r['key_buffer_size']['recommended'], '8M', 'freeing memory is still suggested')

    def test_key_buffer_and_query_cache(self):
        r = recs(sv.advise(variables(), counters(), ROOMY, ENGINES, 1900))
        self.assertEqual(r['key_buffer_size']['recommended'], '8M')
        self.assertEqual(r['query_cache_size']['recommended'], '0')
        self.assertTrue(r['query_cache_size']['optional'])
        busy = recs(sv.advise(variables(query_cache_type='ON', query_cache_size=64 * MB),
                              counters(Qcache_hits=100, Qcache_inserts=9000, Qcache_not_cached=900), ROOMY, ENGINES, 10))
        self.assertEqual(busy['query_cache_type']['recommended'], 'OFF')

    def test_tmp_tables(self):
        r = recs(sv.advise(variables(tmp_table_size=32 * MB), counters(), ROOMY, ENGINES, 10))
        self.assertEqual(r['max_heap_table_size']['recommended'], '32M', 'unequal limits are equalised')
        r = recs(sv.advise(variables(), counters(Created_tmp_disk_tables=5000), ROOMY, ENGINES, 10))
        self.assertEqual(r['tmp_table_size']['recommended'], '32M')
        self.assertEqual(r['max_heap_table_size']['recommended'], '32M')

    def test_counter_advice_is_tentative_after_restart(self):
        result = sv.advise(variables(), counters(Uptime=119), ROOMY, ENGINES, 10)
        self.assertTrue(recs(result)['max_connections']['tentative'])
        self.assertIn('running for only', result['notes'][0])

    def test_force_recovery_is_critical_and_not_applicable(self):
        r = recs(sv.advise(variables(innodb_force_recovery=3), counters(), ROOMY, ENGINES, 10))
        self.assertEqual(r['innodb_force_recovery']['level'], 'critical')
        self.assertFalse(r['innodb_force_recovery']['applicable'])

    def test_table_caches_and_redo_log(self):
        r = recs(sv.advise(variables(), counters(), ROOMY, ENGINES, 1913))
        self.assertEqual(r['table_definition_cache']['recommended'], '2200')
        # 10 MB/h * 2400 h... = 240*10MB over 10 days -> 10 MB/h; 25% of the 2560M pool = 640M over 2 files
        self.assertEqual(r['innodb_log_file_size']['recommended'], '320M')

    def test_datadir_summary_opens_no_tables(self):
        files = [('shop', 'orders.frm', 900), ('shop', 'orders.ibd', 64 * MB), ('shop', '#sql-ib12.ibd', 9 * GB),
                 ('mysql', 'user.frm', 10), ('mysql', 'user.MYI', 4096), ('mysql', 'user.MYD', 1000),
                 ('performance_schema', 'x.frm', 1)]
        engines, tables = sv.datadir_summary(files)
        self.assertEqual(tables, 2)
        self.assertEqual(engines['InnoDB'], {'tables': 1, 'bytes': 64 * MB, 'index_bytes': 0})
        self.assertEqual(engines['MyISAM'], {'tables': 1, 'bytes': 5096, 'index_bytes': 4096})

    def test_metrics(self):
        m = sv.metrics(variables(), counters())
        self.assertEqual(m['qps'], 10.0)
        self.assertEqual(m['buffer_pool_hit'], 0.95)
        self.assertEqual(m['tmp_disk_ratio'], 0.05)


class DropIn(SimpleTestCase):
    def test_normalise_and_render(self):
        clean, warnings = sv.validate_settings({'innodb_buffer_pool_size': '384m', 'key_buffer_size': 8388608,
                                                'innodb_flush_method': 'o_direct', 'slow_query_log': '1',
                                                'long_query_time': '2'}, variables(), 3736 * MB)
        self.assertEqual(clean, {'innodb_buffer_pool_size': '384M', 'key_buffer_size': '8M',
                                 'innodb_flush_method': 'O_DIRECT', 'slow_query_log': 'ON', 'long_query_time': '2'})
        text = sv.render_dropin(clean, '2026-11-14 12:00:00')
        self.assertIn('[mysqld]\ninnodb_buffer_pool_size = 384M\ninnodb_flush_method = O_DIRECT\n', text)
        self.assertEqual(sv.parse_dropin(text), clean)

    def test_rejects_bad_input(self):
        for settings in ({'innodb_force_recovery': '0'}, {'datadir': '/tmp'}, {'max_connections': '1e9'},
                         {'innodb_buffer_pool_size': '384M\ninit_file=/tmp/x'}, {'innodb_buffer_pool_size': '3T'},
                         {'innodb_flush_method': 'nosync'}, {'max_connections': True}, {'max_connections': 5},
                         {'query_cache_size': '20K'}, {'slow_query_log': 'maybe'}, 'x'):
            with self.assertRaises(MySQLError, msg=settings):
                sv.validate_settings(settings, variables(), 3736 * MB)

    def test_memory_limits(self):
        with self.assertRaisesRegex(MySQLError, '75%'):
            sv.validate_settings({'innodb_buffer_pool_size': '3G'}, variables(), 3736 * MB)
        with self.assertRaisesRegex(MySQLError, '80%'):
            sv.validate_settings({'innodb_buffer_pool_size': '2560M', 'key_buffer_size': '512M'}, variables(), 3736 * MB)
        _, warnings = sv.validate_settings({'innodb_buffer_pool_size': '200M', 'tmp_table_size': '32M'}, variables(),
                                           3736 * MB)
        self.assertEqual(len(warnings), 2, warnings)

    def test_include_dir_and_overrides(self):
        cnf = '[client-server]\n!includedir /etc/my.cnf.d\n\n[mysqld]\ninnodb_force_recovery = 3\nmax-connections=200\n' \
              '[client]\nport=3306\n'
        self.assertEqual(sv.choose_include_dir(cnf, lambda p: True), '/etc/my.cnf.d')
        self.assertIsNone(sv.choose_include_dir(cnf, lambda p: False))
        self.assertEqual(sv.overridden_after_include(cnf, '/etc/my.cnf.d'),
                         {'innodb_force_recovery': 5, 'max_connections': 6})
        self.assertEqual(sv.find_option([('/etc/my.cnf', cnf)], 'innodb_force_recovery'),
                         [{'path': '/etc/my.cnf', 'line': 5, 'value': '3'}])

    def test_help_verbose_check(self):
        out = ('2026-11-14 0 [Note] Plugin disabled.\nVariables (--variable-name=value)\n'
               'and boolean options {FALSE|TRUE}                            Value (after reading options)\n'
               '---------------------------------------------------------- ----------------\n'
               'innodb-buffer-pool-size                                    402653184\n'
               'innodb-flush-method                                        O_DIRECT\n'
               'max-connections                                            151\n'
               'slow-query-log                                             TRUE\n\nTo see what values ...\n')
        effective, errors = sv.parse_help_verbose(out)
        self.assertEqual(errors, [])
        self.assertEqual(effective['innodb_buffer_pool_size'], '402653184')
        self.assertEqual(sv.compare_effective({'innodb_buffer_pool_size': '384M', 'innodb_flush_method': 'O_DIRECT',
                                               'slow_query_log': 'ON', 'max_connections': '300'}, effective),
                         [{'variable': 'max_connections', 'wanted': '300', 'effective': '151'}])
        _, errors = sv.parse_help_verbose("0 [ERROR] /usr/libexec/mysqld: unknown variable 'bogus=1'\n")
        self.assertEqual(len(errors), 1)


class Kill(SimpleTestCase):
    def proc(self, **extra):
        p = {'id': 50, 'user': 'aura_iya', 'host': 'localhost:1', 'db': 'aura_iya', 'command': 'Query', 'time': 90,
             'state': 'Sending data', 'info': 'SELECT 1'}
        p.update(extra)
        return p

    def test_guards(self):
        users = ('cyberpanel',)
        self.assertEqual(sv.kill_refusal(self.proc(), 7, users), '')
        for bad in (self.proc(user='system user', command='Daemon'), self.proc(command='Binlog Dump'),
                    self.proc(command='Slave_SQL'), self.proc(user='event_scheduler'), self.proc(id=7),
                    self.proc(user='cyberpanel'), None):
            self.assertTrue(sv.kill_refusal(bad, 7, users), bad)

    def test_thread_ids_are_integers(self):
        self.assertEqual(sv.kill_sql(42, 'query'), 'KILL QUERY 42')
        self.assertEqual(sv.kill_sql('42', 'connection'), 'KILL CONNECTION 42')
        for bad in (True, '1; DROP DATABASE x', '-1', 0, '1.5', None, [1], 2 ** 64):
            with self.assertRaises(MySQLError, msg=bad):
                sv.kill_sql(bad, 'query')
        with self.assertRaises(MySQLError):
            sv.kill_sql(1, 'everything')

    def test_kill_action_rechecks_on_the_server(self):
        executed = []

        @contextmanager
        def creds():
            yield '/dev/null'
        own = [['99']]
        rows = [['5', 'cyberpanel', 'localhost', 'cyberpanel', 'Sleep', '3', '', '']]
        with mock.patch.object(actions, 'credentials', creds), \
                mock.patch.object(actions, 'query_sets', return_value=[own, rows]), \
                mock.patch.object(actions, 'query', side_effect=lambda sql, d: executed.append(sql)):
            with self.assertRaisesRegex(MySQLError, 'panel'):
                actions.kill(5, 'query', panel_users=['cyberpanel'])
            self.assertEqual(executed, [])
            rows[0][1] = 'shop'
            actions.kill(5, 'connection', panel_users=['cyberpanel'])
        self.assertEqual(executed, ['KILL CONNECTION 5'])

    def test_process_rows(self):
        rows = sv.process_rows([['1', 'system user', '', '', 'Daemon', '0', 'InnoDB shutdown handler', ''],
                                ['16', 'moni_tor', 'localhost:39170', 'moni_tor', 'Sleep', '1', '', ''],
                                ['57', 'root', 'localhost', '', 'Query', '4', 'Filling schema table', 'SELECT']])
        self.assertEqual([r['id'] for r in rows], [57, 1, 16])


class ApplyRevert(SimpleTestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.dir = os.path.join(self.root, 'my.cnf.d')
        os.makedirs(self.dir)
        self.target = os.path.join(self.dir, sv.DROPIN_NAME)

        @contextmanager
        def creds():
            yield '/dev/null'
        self.patches = [
            mock.patch.object(actions, 'credentials', creds),
            mock.patch.object(actions, '_snapshot', return_value=[variables(), counters()]),
            mock.patch.object(actions, 'host_memory', return_value=dict(SHORT)),
            mock.patch.object(actions, 'dropin_path', return_value=self.target),
            mock.patch.object(actions, 'overrides', return_value={}),
            mock.patch.object(actions, 'BACKUP_DIR', os.path.join(self.root, 'backups')),
        ]
        for p in self.patches:
            p.start()
        self.check = mock.patch.object(actions, 'check_config', return_value={'ok': True, 'errors': [], 'mismatches': []})
        self.check_mock = self.check.start()

    def tearDown(self):
        mock.patch.stopall()
        shutil.rmtree(self.root)

    def test_apply_backup_and_revert(self):
        actions.apply({'key_buffer_size': '8M'})
        self.assertEqual(sv.parse_dropin(open(self.target).read()), {'key_buffer_size': '8M'})
        actions.apply({'key_buffer_size': '16M', 'innodb_flush_method': 'O_DIRECT'})
        self.assertEqual(len(actions.backups()), 2, 'one ".absent" marker and one copy')
        result = actions.revert()
        self.assertEqual(result['restored'], {'key_buffer_size': '8M'})
        self.assertEqual(sv.parse_dropin(open(self.target).read()), {'key_buffer_size': '8M'})
        result = actions.revert()
        self.assertTrue(result['removed'])
        self.assertFalse(os.path.exists(self.target), 'reverting past the first apply removes the drop-in')
        with self.assertRaises(MySQLError):
            actions.revert()
        self.assertEqual([n for n in os.listdir(self.dir)], [], 'no stray files in the include directory')

    def test_rejected_configuration_is_rolled_back(self):
        actions.apply({'key_buffer_size': '8M'})
        self.check_mock.return_value = {'ok': False, 'errors': ['[ERROR] unknown variable'], 'mismatches': []}
        with self.assertRaisesRegex(MySQLError, 'restored'):
            actions.apply({'key_buffer_size': '16M'})
        self.assertEqual(sv.parse_dropin(open(self.target).read()), {'key_buffer_size': '8M'})
        self.assertEqual(len(actions.backups()), 1, 'a rolled-back apply leaves no revert point')

    def test_apply_validates_before_writing(self):
        with self.assertRaises(MySQLError):
            actions.apply({'innodb_buffer_pool_size': '3G'})
        self.assertFalse(os.path.exists(self.target))


class Upgrade(SimpleTestCase):
    def test_report_for_this_server(self):
        os_info = sv.parse_os_release('NAME="CentOS Linux"\nVERSION_ID="8"\nID="centos"\nID_LIKE="rhel fedora"\n'
                                      'PRETTY_NAME="CentOS Linux 8"\n')
        dbs = [{'name': 'shop', 'tables': 10, 'bytes': 2 * GB, 'free_bytes': 0, 'system': False},
               {'name': 'mysql', 'tables': 31, 'bytes': 8 * MB, 'free_bytes': 0, 'system': True}]
        r = sv.upgrade_report('10.3.28-MariaDB', os_info, dbs, 3 * GB, 17 * GB, '2026-11-14', force_recovery=3,
                              shim_present=True)
        self.assertTrue(r['is_eol'])
        self.assertEqual(r['recommended'], '10.11')
        self.assertEqual([t['version'] for t in r['targets'] if not t['supported']], ['10.6'])
        self.assertTrue(r['disk_ok'])
        self.assertFalse(r['ready'])
        self.assertIn('force_recovery', r['blockers'][0])
        self.assertIn('Django 4.2', r['django'])
        r = sv.upgrade_report('10.3.28-MariaDB', os_info, dbs, 14 * GB, 15 * GB, '2026-11-14')
        self.assertTrue(r['disk_ok'], 'a 2 GB logical dump fits')
        self.assertIn('physical copy', ' '.join(r['warnings']))
        r = sv.upgrade_report('10.3.28-MariaDB', os_info, dbs, 14 * GB, 4 * GB, '2026-11-14')
        self.assertFalse(r['disk_ok'])


class Views(SimpleTestCase):
    def post(self, view, body, admin=1):
        request = RequestFactory().post('/x', data=json.dumps(body), content_type='application/json')
        request.session = {'userID': 1}
        with mock.patch('universalAddons.access.ACLManager.loadedACL', return_value={'admin': admin}), \
                mock.patch('universalAddons.privileged.call', return_value={'ok': 1}) as call:
            response = view(request)
        return response.status_code, call

    def test_admin_only(self):
        for view in (views.status, views.processes, views.kill, views.advise, views.apply, views.revert,
                     views.restart, views.upgrade, views.check):
            status, call = self.post(view, {'thread': 5, 'settings': {'key_buffer_size': '8M'}, 'confirm': True}, admin=0)
            self.assertEqual(status, 403, view.__name__)
            call.assert_not_called()

    def test_input_validation(self):
        for view, body in ((views.kill, {'thread': '5; DROP'}), (views.kill, {'thread': 5, 'mode': 'all'}),
                           (views.apply, {'settings': {'datadir': '/tmp'}}), (views.apply, {'settings': {}}),
                           (views.apply, {'settings': {'key_buffer_size': '8M;'}}), (views.restart, {}),
                           (views.job, {'job': '../x'})):
            status, call = self.post(view, body)
            self.assertEqual(status, 400, body)
            call.assert_not_called()

    def test_calls_pass_through(self):
        status, call = self.post(views.kill, {'thread': 5})
        self.assertEqual(status, 200)
        call.assert_called_once_with('mysqlmgr', 'kill', thread=5, mode='query', panel_users=['cyberpanel'])
        status, call = self.post(views.apply, {'settings': {'key_buffer_size': '8M'}})
        call.assert_called_once_with('mysqlmgr', 'apply', settings={'key_buffer_size': '8M'})
        status, call = self.post(views.restart, {'confirm': True})
        call.assert_called_once_with('mysqlmgr', 'restart', auto_revert=True)


@override_settings(ROOT_URLCONF=__name__)
class PageRenders(SimpleTestCase):
    def test_page_renders(self):
        request = RequestFactory().get('/addons/mysql/')
        request.session = {}
        html = render_to_string('universalAddons/mysqlmgr.html', {'request': request, 'admin': 1})
        self.assertIn('ua-wrap', html)
        self.assertIn('data-base="/addons/mysql/"', html)
        self.assertIn('mysqlmgr.js', html)

"""Applications add-on: the newer applications (SQL Server bridge, PostgreSQL, MongoDB, RabbitMQ,
Oracle Instant Client), uninstall previews, the memory budget and the Services page registry."""
import json
import os
import tempfile
import time
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase

from universalAddons import jobs
from universalAddons.appsvc import actions, more as mo, service as sv, views
from universalAddons.mssql import service as sq
from universalAddons.tests import helpers
from universalAddons.tests.test_appsvc import run_job, sandbox

RAM = 3736

STOCK_PG_CONF = """# PostgreSQL configuration file
listen_addresses = 'localhost'		# what IP address(es) to listen on;
max_connections = 100			# (change requires restart)
shared_buffers = 128MB			# min 128kB
#work_mem = 4MB				# min 64kB
"""

STOCK_HBA = """# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
"""

PG_SETTINGS = {'shared_buffers_mb': 256, 'work_mem_mb': 8, 'max_connections': 50,
               'listen_addresses': ['127.0.0.1'], 'auth_method': 'scram-sha-256'}

DNF_PREVIEW = """Dependencies resolved.
================================================================================
 Package                         Arch     Version            Repository    Size
================================================================================
Removing:
 postgresql17-server             x86_64   17.2-1PGDG.rhel8   @cp-pgdg17    25 M
Removing dependent packages:
 postgresql17-contrib-with-a-really-long-name
                                 x86_64   17.2-1PGDG.rhel8   @cp-pgdg17   2.6 M
Removing unused dependencies:
 postgresql17                    x86_64   17.2-1PGDG.rhel8   @cp-pgdg17   7.9 M
 postgresql17-libs               x86_64   17.2-1PGDG.rhel8   @cp-pgdg17   1.0 M

Transaction Summary
================================================================================
Remove  4 Packages

Freed space: 37 M
Operation aborted.
"""


class Specs(SimpleTestCase):
    def test_postgresql_files_render_and_are_idempotent(self):
        cfg, warnings = mo.validate_pg(PG_SETTINGS, RAM)
        self.assertEqual(warnings, [])
        panel = mo.render_pg_panel(cfg)
        self.assertIn("listen_addresses = '127.0.0.1'\nmax_connections = 50\nshared_buffers = 256MB\nwork_mem = 8MB", panel)
        conf = sv.apply_block(STOCK_PG_CONF, mo.pg_include_block())
        self.assertTrue(conf.startswith(STOCK_PG_CONF.rstrip('\n')))
        self.assertTrue(conf.rstrip().endswith("include 'panel-managed.conf'\n" + sv.MARK_END))
        self.assertEqual(sv.apply_block(conf, mo.pg_include_block()), conf, 'idempotent')
        hba = sv.apply_block_top(STOCK_HBA, mo.render_pg_hba_block(cfg))
        self.assertTrue(hba.startswith(sv.MARK_BEGIN + '\nlocal   all   postgres'), 'first-match file: block on top')
        self.assertTrue(hba.endswith(STOCK_HBA))
        self.assertEqual(sv.apply_block_top(hba, mo.render_pg_hba_block(cfg)), hba, 'idempotent')
        self.assertNotIn('0.0.0.0/0', hba)
        current = mo.pg_current(conf, panel, hba, RAM)
        self.assertEqual({k: current[k] for k in PG_SETTINGS}, PG_SETTINGS)
        self.assertTrue(current['managed'] and current['hba_managed'])
        # Without the include line the panel file is not in effect.
        self.assertEqual(mo.pg_current(STOCK_PG_CONF, panel, STOCK_HBA)['shared_buffers_mb'], 128)
        self.assertEqual(mo.pg_current(STOCK_PG_CONF, None, STOCK_HBA)['listen_addresses'], ['127.0.0.1'])

    def test_postgresql_validation(self):
        for bad in ({'shared_buffers_mb': 1000}, {'shared_buffers_mb': 16}, {'work_mem_mb': 0}, {'max_connections': 5000},
                    {'auth_method': 'trust'}, {'listen_addresses': ['localhost; rm']}):
            with self.assertRaises(sv.AppError, msg=bad):
                mo.validate_pg(dict(PG_SETTINGS, **bad), RAM)
        _, warnings = mo.validate_pg(dict(PG_SETTINGS, work_mem_mb=64, max_connections=500), RAM)
        self.assertTrue(any('over half of RAM' in w for w in warnings))
        with self.assertRaisesRegex(sv.AppError, 'confirmation'):
            mo.validate_pg(dict(PG_SETTINGS, listen_addresses=['0.0.0.0']), RAM)
        cfg, warnings = mo.validate_pg(dict(PG_SETTINGS, listen_addresses=['0.0.0.0']), RAM, confirm_exposed=True)
        self.assertIn('host    all   all       0.0.0.0/0        scram-sha-256', mo.render_pg_hba_block(cfg))
        self.assertTrue(any('DANGER' in w for w in warnings))

    def test_postgresql_create_sql(self):
        sql = mo.pg_create_sql('shop', 'shop_user', 'A' * 32)
        self.assertIn('CREATE ROLE "shop_user" LOGIN PASSWORD \'%s\';' % ('A' * 32), sql)
        self.assertIn('CREATE DATABASE "shop" OWNER "shop_user";', sql)
        self.assertIn('REVOKE ALL ON DATABASE "shop" FROM PUBLIC;', sql)
        for bad in ('postgres', 'pg_shadow', 'Shop', 'a', 'x"; drop', 'template1'):
            with self.assertRaises(sv.AppError, msg=bad):
                mo.pg_create_sql(bad, 'u_ok', 'A' * 32)
        with self.assertRaises(sv.AppError):
            mo.pg_create_sql('shop', 'shop', "x'; DROP ROLE postgres; --" + 'a' * 20)

    def test_postgresql_database_password_goes_through_stdin_once(self):
        with mock.patch.object(actions, '_pg_major', return_value=17), \
                mock.patch.object(actions, '_busy', return_value=False), \
                mock.patch.object(actions, '_current', return_value=dict(mo.pg_defaults(RAM))), \
                mock.patch.object(sv, 'meminfo_mb', return_value=(RAM, 2000)), \
                mock.patch.object(sv, 'run', return_value=(0, '')) as run:
            result = actions.pg_create('shop', 'shop')
        argv, kwargs = run.call_args[0][0], run.call_args[1]
        self.assertNotIn(result['password'], ' '.join(argv))
        self.assertIn(result['password'], kwargs['input_text'])
        self.assertEqual(argv[:4], ['runuser', '-u', 'postgres', '--'])
        self.assertEqual((result['host'], result['port']), ('127.0.0.1', 5432))

    def test_mongodb_dropin(self):
        cfg, _ = mo.validate_mongo({'cache_gb': 0.5, 'bind_ip': ['127.0.0.1'], 'auth': True}, RAM)
        text = mo.render_mongo_dropin(cfg)
        self.assertIn('Environment="OPTIONS=-f /etc/mongod.conf --wiredTigerCacheSizeGB 0.5 --bind_ip 127.0.0.1 --auth"', text)
        self.assertEqual(mo.render_mongo_dropin(mo.validate_mongo(dict(mo.mongo_current(text)), RAM)[0]), text, 'round trip')
        self.assertEqual(mo.mongo_current(text)['cache_gb'], 0.5)
        off = mo.render_mongo_dropin(dict(cfg, auth=False))
        self.assertIn('--noauth', off)
        self.assertFalse(mo.mongo_current(off)['auth'])
        self.assertEqual(mo.mongo_current(None, 'net:\n  port: 27017\n  bindIp: 127.0.0.1\n')['managed'], False)
        for bad in ({'cache_gb': 0.1}, {'cache_gb': 5}, {'cache_gb': 'lots'}, {'bind_ip': ['x']}):
            with self.assertRaises(sv.AppError, msg=bad):
                mo.validate_mongo(dict({'cache_gb': 0.5, 'bind_ip': ['127.0.0.1'], 'auth': True}, **bad), RAM)
        with self.assertRaisesRegex(sv.AppError, 'only with authorization'):
            mo.validate_mongo({'cache_gb': 0.5, 'bind_ip': ['0.0.0.0'], 'auth': False}, RAM, confirm_exposed=True)
        self.assertTrue(mo.mongo_sysconfig_conflict('OPTIONS="-f /etc/other.conf"\n'))
        self.assertFalse(mo.mongo_sysconfig_conflict('# OPTIONS=\n'))

    def test_mongodb_scripts_run_from_a_private_file(self):
        script = mo.mongo_user_script('B' * 32, old_password='C' * 32)
        self.assertIn("admin.auth('admin', '%s');" % ('C' * 32), script)
        self.assertIn("roles: [{role: 'root', db: 'admin'}]", script)
        with self.assertRaises(sv.AppError):
            mo.mongo_user_script("x'); db.dropDatabase(); ('" + 'a' * 20)
        with sandbox(), mock.patch.object(sv, 'run', return_value=(0, 'created')) as run:
            actions._mongosh(script, '127.0.0.1')
        argv = run.call_args[0][0]
        self.assertNotIn('B' * 32, ' '.join(argv))
        self.assertIn('--file', argv)
        self.assertFalse(os.path.exists(argv[argv.index('--file') + 1]), 'the script file is removed')

    def test_rabbitmq_conf(self):
        cfg, _ = mo.validate_rabbit({'memory_mb': 256, 'bind': '127.0.0.1', 'disk_free_limit_mb': 1024}, RAM)
        text = mo.render_rabbit_conf(cfg)
        self.assertIn('listeners.tcp.default = 127.0.0.1:5672\nvm_memory_high_watermark.absolute = 256MB', text)
        current = mo.rabbit_current(text)
        self.assertEqual((current['memory_mb'], current['bind'], current['disk_free_limit_mb']), (256, '127.0.0.1', 1024))
        self.assertEqual(mo.render_rabbit_conf(mo.validate_rabbit(current, RAM)[0]), text, 'idempotent')
        with self.assertRaisesRegex(sv.AppError, 'confirmation'):
            mo.validate_rabbit(dict(cfg, bind='0.0.0.0'), RAM)
        with self.assertRaises(sv.AppError):
            mo.validate_rabbit(dict(cfg, memory_mb=4000), RAM)
        self.assertIn('ERL_EPMD_ADDRESS=127.0.0.1', mo.RABBIT_SYSTEMD_TEXT)

        class Sock:
            def __init__(self, reply):
                self.reply = reply

            def sendall(self, data):
                self.sent = data

            def recv(self, size):
                return self.reply

            def close(self):
                pass
        self.assertTrue(mo.amqp_probe('127.0.0.1', connect=lambda *a, **k: Sock(b'\x01\x00\x00\x00\x00\x01\xf4'))[0])
        self.assertFalse(mo.amqp_probe('127.0.0.1', connect=lambda *a, **k: Sock(b'AMQP\x00\x00\x09\x01'))[0])

    def test_repositories_are_official_signed_and_cp_prefixed(self):
        texts = [mo.pg_repo_text(17, 8), mo.pg_repo_text(16, 8), mo.mongo_repo_text(8), mo.rabbit_repo_text(8),
                 mo.oracle_client_repo_text(8)]
        for text in texts:
            ids = [line.strip('[]') for line in text.splitlines() if line.startswith('[')]
            self.assertTrue(ids and all(i.startswith('cp-') for i in ids), ids)
            self.assertEqual(sum(1 for line in text.splitlines() if line == 'gpgcheck=1'), len(ids))
            self.assertNotIn('gpgcheck=0', text)
            self.assertNotIn('http://', text)
        self.assertIn('https://download.postgresql.org/pub/repos/yum/17/redhat/rhel-8-$basearch', texts[0])
        self.assertIn('https://repo.mongodb.org/yum/redhat/8/mongodb-org/8.0/x86_64/', texts[2])
        self.assertIn('includepkgs=oracle-instantclient-*', texts[4])
        self.assertIn('gpgkey=https://yum.oracle.com/RPM-GPG-KEY-oracle-ol8', texts[4])
        with self.assertRaises(sv.AppError):
            mo.pg_repo_text(15, 8)
        for path in (mo.pg_repo_file(17), mo.MONGO_REPO_FILE, mo.RABBIT_REPO_FILE, mo.ORACLE_CLIENT_REPO_FILE):
            self.assertTrue(os.path.basename(path).startswith('cp-'), path)

    def test_os_check(self):
        with tempfile.NamedTemporaryFile('w', delete=False) as handle:
            handle.write('NAME="CentOS Linux"\nVERSION="8"\nID="centos"\nID_LIKE="rhel fedora"\nVERSION_ID="8"\n')
        self.assertEqual(mo.el_version(handle.name), ('centos', 8))
        self.assertTrue(mo.os_check('postgresql', 8)['ok'])
        self.assertFalse(mo.os_check('postgresql', None)['ok'])


class Budget(SimpleTestCase):
    def test_caps_over_70_percent_warn(self):
        self.assertIsNone(sv.budget_warning({'A': 1000, 'B': 1500}, RAM))
        warning = sv.budget_warning({'SQL Server': 1024, 'Elasticsearch': 1024, 'MongoDB': 768}, RAM)
        self.assertIn('2816 MB', warning)
        self.assertIn('over 70%', warning)
        self.assertEqual(sv.cap_mb('mongodb', {'cache_gb': 0.5}), 512)
        self.assertEqual(sv.cap_mb('postgresql', {'shared_buffers_mb': 256}), 320)
        self.assertEqual(sv.cap_mb('mssql', {'memory_limit_mb': 1024}), 1024)

    def test_preflight_adds_os_and_budget_checks(self):
        caps = {'SQL Server 2022 Express': 1024, 'Elasticsearch': 1408}
        with mock.patch.object(actions, '_caps', return_value=caps), \
                mock.patch.object(actions, '_el', return_value=8):
            checks = actions._preflight_checks('mongodb', RAM, 1100, 20000, False)
        ids = {c['id']: c for c in checks}
        self.assertTrue(ids['os']['ok'])
        self.assertFalse(ids['budget']['ok'])           # 1024 + 1408 + 256 > 2615
        self.assertFalse(ids['budget']['hard'])
        self.assertIn('install anyway', sv.preflight_refusal(checks, False))
        self.assertIsNone(sv.preflight_refusal(checks, True))
        with mock.patch.object(actions, '_caps', return_value={}), mock.patch.object(actions, '_el', return_value=8):
            checks = actions._preflight_checks('mssql', RAM, 3000, 20000, False)
        self.assertIn('SQL Server add-on', sv.preflight_refusal(checks, True), 'installed from its own add-on')


class SqlServerMemory(SimpleTestCase):
    def test_bounds(self):
        self.assertEqual(sq.memory_limit_bounds(RAM), (512, 3224))
        self.assertEqual(sq.validate_memory_limit(1024, RAM), 1024)
        self.assertEqual(sq.validate_memory_limit('3224', RAM), 3224)
        for bad in (511, 3225, 'lots', True, None, -1):
            with self.assertRaises(sq.SQLError, msg=bad):
                sq.validate_memory_limit(bad, RAM)
        self.assertEqual(sq.max_server_memory_mb(1024), 768)
        self.assertEqual(sq.max_server_memory_mb(512), 384)
        sql = sq.max_server_memory_sql(768)
        self.assertIn("EXEC sp_configure 'max server memory (MB)', 768;", sql)
        self.assertIn("EXEC sp_configure 'show advanced options', 1;", sql)
        cfg, warnings = actions.validate_mssql({'memory_limit_mb': 1024}, RAM)
        self.assertEqual(cfg, {'memory_limit_mb': 1024, 'max_server_memory_mb': 768})
        self.assertEqual(warnings, [])
        self.assertTrue(actions.validate_mssql({'memory_limit_mb': 3000}, RAM)[1])
        with self.assertRaisesRegex(sv.AppError, 'between 512 and 3224'):
            actions.validate_mssql({'memory_limit_mb': 4096}, RAM)

    def test_job_uses_the_mssql_module_and_rolls_back(self):
        from universalAddons.mssql import actions as ma
        with sandbox() as base:
            conf, dropin, state = os.path.join(base, 'mssql.conf'), os.path.join(base, 'cyberpanel-memory.conf'), os.path.join(base, 'mssql')
            os.makedirs(state)
            with open(conf, 'w') as handle:
                handle.write('[memory]\nmemorylimitmb = 1024\n')
            sq._private_write(os.path.join(state, 'sa.json'), {'password': 'x', 'memory_limit_mb': 1024})

            def write(limit):
                with open(conf, 'w') as handle:
                    handle.write('[memory]\nmemorylimitmb = %d\n' % limit)
                sq.write_protect_dropin(limit, path=dropin)
                return limit
            with mock.patch.object(sq, 'MSSQL_CONF_FILE', conf), mock.patch.object(sq, 'PROTECT_DROPIN', dropin), \
                    mock.patch.object(sq, 'STATE_DIR', state), \
                    mock.patch.object(ma, '_installed', return_value=True), \
                    mock.patch.object(ma, 'write_memory_limit', side_effect=write) as written, \
                    mock.patch.object(actions, '_version', side_effect=lambda app: '16.0' if app == 'mssql' else None), \
                    mock.patch.object(actions, '_restart') as restart, \
                    mock.patch.object(actions, '_wait_healthy', return_value=(True, 'sa login answered')):
                with mock.patch.object(ma, 'apply_max_server_memory', side_effect=sq.SQLError('boom')):
                    data = run_job(actions.configure_run, app='mssql', settings={'memory_limit_mb': 1536})
                self.assertEqual(data['state'], 'failed', data)
                self.assertIn('previous configuration was restored', data['error'])
                with open(conf) as handle:
                    self.assertIn('1024', handle.read())
                self.assertFalse(os.path.exists(dropin), 'the drop-in that did not exist before is gone again')
                self.assertEqual(restart.call_count, 2)
                with mock.patch.object(ma, 'apply_max_server_memory', return_value=1216) as applied:
                    data = run_job(actions.configure_run, app='mssql', settings={'memory_limit_mb': 1536})
                self.assertEqual(data['state'], 'done', data)
                applied.assert_called_once_with(1536)
                written.assert_called_with(1536)
                self.assertIn('max server memory 1216 MB', json.dumps(data['result']))
                with open(dropin) as handle:
                    self.assertIn('=2048M', handle.read())


class Uninstall(SimpleTestCase):
    def test_dnf_preview_parser(self):
        parsed = sv.parse_dnf_removal(DNF_PREVIEW)
        self.assertEqual(parsed['packages'], ['postgresql17-server', 'postgresql17-contrib-with-a-really-long-name',
                                              'postgresql17', 'postgresql17-libs'])
        self.assertEqual(parsed['freed'], '37 M')
        self.assertEqual(sv.parse_dnf_removal('No match for argument: x\nNo packages marked for removal.\n')['packages'], [])

    def _preview(self, app='postgresql', packages=('postgresql17-server',), age=0, state='done'):
        job_id = os.urandom(12).hex()
        job = jobs.Job(job_id)
        job.data.update(module='appsvc', action='remove_preview_run', state=state,
                        result={'Preview removal': {'app': app, 'packages': list(packages)}})
        job._save()
        if age:
            job.data['updated'] = int(time.time()) - age
            with open(job.path, 'w') as handle:
                json.dump(job.data, handle)
        return job_id

    def test_confirmation_logic(self):
        with sandbox():
            good = self._preview()
            with self.assertRaisesRegex(sv.AppError, 'Confirm'):
                actions.removal_confirmation('postgresql', False, False, '', good)
            with self.assertRaisesRegex(sv.AppError, 'Preview what will be removed first'):
                actions.removal_confirmation('postgresql', True, False, '', None)
            with self.assertRaisesRegex(sv.AppError, 'Type postgresql'):
                actions.removal_confirmation('postgresql', True, True, 'PostgreSQL 17', good)
            with self.assertRaisesRegex(sv.AppError, 'something else'):
                actions.removal_confirmation('mongodb', True, False, '', good)
            with self.assertRaisesRegex(sv.AppError, 'older than'):
                actions.removal_confirmation('postgresql', True, False, '', self._preview(age=4000))
            with self.assertRaisesRegex(sv.AppError, 'not finished'):
                actions.removal_confirmation('postgresql', True, False, '', self._preview(state='running'))
            with self.assertRaisesRegex(sv.AppError, 'Docker manager'):
                actions.removal_confirmation('docker', True, False, '', None)
            self.assertEqual(actions.removal_confirmation('postgresql', True, True, ' postgresql ', good),
                             ['postgresql17-server'])
            self.assertIsNone(actions.removal_confirmation('redis', True, False, '', None), 'the old page\'s API')
            with mock.patch.object(actions, '_version', return_value='17.2'), \
                    mock.patch.object(actions, '_busy', return_value=False), \
                    mock.patch('universalAddons.jobs.spawn', return_value={'job_id': 'x'}) as spawn:
                actions.remove('mssql', confirm=True, preview_job=self._preview('mssql', ['mssql-server']))
            spawn.assert_called_with('appsvc', 'remove_run', {'app': 'mssql', 'delete_data': False,
                                                              'packages': ['mssql-server']})

    def test_view_needs_a_preview_for_new_apps(self):
        with mock.patch('universalAddons.privileged.call', return_value={'job_id': 'x'}) as call:
            status, body, _ = helpers.post(views.remove, {'app': 'postgresql', 'confirm': True}, admin=True)
            self.assertEqual(status, 400)
            self.assertIn('Preview', body['error_message'])
            status, _, _ = helpers.post(views.remove, {'app': 'postgresql', 'confirm': True, 'previewJob': '../x'}, admin=True)
            self.assertEqual(status, 400)
            call.assert_not_called()
            helpers.post(views.remove, {'app': 'postgresql', 'confirm': True, 'previewJob': 'ab' * 12}, admin=True)
            call.assert_called_with('appsvc', 'remove', app='postgresql', confirm=True, delete_data=False,
                                    confirm_name='', preview_job='ab' * 12)
            helpers.post(views.remove_preview, {'app': 'mongodb'}, admin=True)
            call.assert_called_with('appsvc', 'remove_preview', app='mongodb')

    def test_removal_stops_when_the_package_list_changed(self):
        with sandbox() as base:
            data_dir = os.path.join(base, 'mongo')
            os.makedirs(data_dir)
            apps = dict(sv.APPS, mongodb=dict(sv.APPS['mongodb'], data_dir=data_dir))
            calls = []

            def run(argv, **kwargs):
                calls.append(argv)
                if argv[:3] == ['dnf', 'remove', '--assumeno']:
                    return 1, ' Package Arch\nRemoving:\n mongodb-org-server x86_64 8.0.4 @cp 100 M\n' \
                              'Removing unused dependencies:\n mongodb-mongosh x86_64 2.3 @cp 80 M\n\nOperation aborted.\n'
                return 0, ''
            with mock.patch.object(sv, 'APPS', apps), mock.patch.object(sv, 'run', side_effect=run), \
                    mock.patch.object(actions, '_installed_packages', side_effect=lambda names: list(names)):
                data = run_job(actions.remove_run, app='mongodb', delete_data=True, packages=['mongodb-org-server'])
                self.assertEqual(data['state'], 'failed')
                self.assertIn('different set of packages', data['error'])
                self.assertFalse(any(argv[:3] == ['dnf', '-y', 'remove'] for argv in calls))
                self.assertTrue(os.path.isdir(data_dir), 'nothing deleted')
                with mock.patch.object(actions, '_version', return_value=None):
                    data = run_job(actions.remove_run, app='mongodb', delete_data=False,
                                   packages=['mongodb-org-server', 'mongodb-mongosh'])
                self.assertEqual(data['state'], 'done', data)
                self.assertIn(['dnf', '-y', 'remove', 'mongodb-org-server', 'mongodb-mongosh'], calls)
                self.assertTrue(os.path.isdir(data_dir), 'data kept without the typed confirmation')


class OracleDatabase(SimpleTestCase):
    def test_refused_without_ram_confirmation(self):
        checks = mo.oracle_db_checks('ol', 8, RAM, 1100, 2432, 20000)
        refusal = mo.oracle_db_refusal(checks, False)
        self.assertTrue(refusal.startswith('RAM warning'), refusal)
        self.assertIsNone(mo.oracle_db_refusal(checks, True), 'only the RAM warning, and it was confirmed')

    def test_refused_on_centos_even_with_confirmation(self):
        checks = mo.oracle_db_checks('centos', 8, RAM, 1100, 2432, 20000)
        refusal = mo.oracle_db_refusal(checks, True)
        self.assertIn('cannot be installed here', refusal)
        self.assertIn('Oracle Linux repositories', refusal)
        roomy = mo.oracle_db_checks('ol', 8, 16000, 12000, 1024, 20000)
        self.assertIsNone(mo.oracle_db_refusal(roomy, False))
        self.assertIn('oracle_db', [s['key'] for s in sv.SKIPPED])
        self.assertNotIn('oracle_db', sv.APPS, 'no installer for the database itself')

    def test_view_passes_the_confirmation_only_when_true(self):
        with mock.patch('universalAddons.privileged.call', return_value={}) as call:
            helpers.post(views.oracle_db_check, {'confirmRam': 'yes'}, admin=True)
            call.assert_called_with('appsvc', 'oracle_db_check', confirm_ram=False)
            helpers.post(views.oracle_db_check, {'confirmRam': True}, admin=True)
            call.assert_called_with('appsvc', 'oracle_db_check', confirm_ram=True)


class ServicesPage(SimpleTestCase):
    def test_registry_feeds_extra_services(self):
        from serverStatus import views as status_views
        units = [u for u, _, _ in status_views.EXTRA_SERVICES]
        for unit in ('elasticsearch', 'redis', 'memcached', 'mssql-server', 'postgresql-16', 'postgresql-17',
                     'mongod', 'rabbitmq-server'):
            self.assertIn(unit, units)
            self.assertEqual(status_views.EXTRA_ACTIONS[unit], ('start', 'stop', 'restart'))
        self.assertEqual(len(units), len(set(units)), 'no duplicates')
        self.assertNotIn('lscpd', units)
        self.assertNotIn('sshd', units)
        self.assertNotIn('docker', units, 'Docker has its own card')
        self.assertEqual(status_views.EXTRA_ACTIONS['firewalld'], ('restart',))

    def test_only_installed_units_are_listed(self):
        from serverStatus import views as status_views
        commands = []

        def executor(command):
            commands.append(command)
            if command.startswith('systemctl list-unit-files'):
                return ('redis.service enabled\npostgresql-17.service enabled\ncp-app-shop.service enabled\n'
                        'cp-app-Bad_Name.service enabled\n')
            if command.startswith('systemctl is-active'):
                return 'active\nfailed\nactive\n'
            return ''
        table = [(1048576, 'redis.service', 'redis-server'), (2097152, 'cp-app-shop.service', 'dotnet')]
        extra = status_views.extra_services(table, executor=executor)
        self.assertEqual([e['unit'] for e in extra], ['redis', 'postgresql-17', 'cp-app-shop'])
        self.assertIn("'cp-app-*.service'", commands[0])
        self.assertEqual(commands[1], 'systemctl is-active redis postgresql-17 cp-app-shop')
        shop = extra[2]
        self.assertEqual((shop['actions'], shop['running'], shop['mem'], shop['label']), (['restart'], True, 2097152, 'Site app shop'))
        self.assertEqual((extra[1]['running'], extra[1]['mem']), (False, 0))
        self.assertNotIn('mongod', [e['unit'] for e in extra], 'not installed, not listed')

    def test_site_app_units_can_only_be_restarted(self):
        from serverStatus import views as status_views

        def call(service, action):
            request = RequestFactory().post('/x', data=json.dumps({'service': service, 'action': action}),
                                            content_type='application/json')
            request.session = {'userID': 1}
            with mock.patch.object(status_views.ACLManager, 'loadedACL', return_value={'admin': 1}), \
                    mock.patch.object(status_views.ProcessUtilities, 'outputExecutioner', return_value=(1, '')) as run:
                return json.loads(status_views.servicesAction(request).content), run
        response, run = call('cp-app-shop', 'restart')
        self.assertEqual(response['serviceAction'], 1)
        self.assertEqual(run.call_args[0][0], 'sudo systemctl restart cp-app-shop')
        for service, action in (('cp-app-shop', 'stop'), ('cp-app-../x', 'restart'), ('cp-app-a;reboot', 'restart')):
            response, run = call(service, action)
            self.assertEqual(response['serviceAction'], 0, service)
            run.assert_not_called()
        response, run = call('postgresql-17', 'stop')
        self.assertEqual(response['serviceAction'], 1)


class Status(SimpleTestCase):
    def test_runtimes_summary_is_read_only(self):
        fake = {'node': [{'version': '24.22.3', 'size': 100, 'source': 'nodejs.org'}], 'dotnet': [],
                'python': [{'version': '3.9.21', 'source': None}], 'java': []}
        with mock.patch('universalAddons.apps.runtimes.installed', return_value=fake), \
                mock.patch.object(actions, '_du', return_value=300):
            result = actions.runtimes()
        node = next(k for k in result['kinds'] if k['kind'] == 'node')
        self.assertEqual((node['versions'], node['bytes']), (['24.22.3'], 100))
        self.assertIsNone(next(k for k in result['kinds'] if k['kind'] == 'python')['bytes'])
        with mock.patch('universalAddons.apps.runtimes.installed', side_effect=OSError('x')):
            self.assertIn('error', actions.runtimes())

    def test_controls_refused_for_client_and_status_kinds(self):
        with self.assertRaisesRegex(sv.AppError, 'no service'):
            actions.control('oracle_client', 'start')
        with self.assertRaisesRegex(sv.AppError, 'Docker manager'):
            actions.control('docker', 'stop')
        with self.assertRaisesRegex(sv.AppError, 'no settings'):
            actions._validate('oracle_client', {}, RAM, False)

    def test_new_views_are_admin_only(self):
        for view in (views.remove_preview, views.pg_create, views.disk, views.runtimes, views.oracle_db_check):
            with mock.patch('universalAddons.privileged.call', return_value={}) as call:
                self.assertEqual(helpers.post(view, {'app': 'mongodb'}, admin=False)[0], 403, view.__name__)
                call.assert_not_called()
        with mock.patch('universalAddons.privileged.call', return_value={}) as call:
            self.assertEqual(helpers.post(views.pg_create, {'database': 'postgres', 'user': 'x1'}, admin=True)[0], 400)
            self.assertEqual(helpers.post(views.install, {'app': 'postgresql', 'major': '15'}, admin=True)[0], 400)
            call.assert_not_called()
            helpers.post(views.install, {'app': 'postgresql', 'major': '16'}, admin=True)
            call.assert_called_with('appsvc', 'install', app='postgresql', force=False, major=16)
            helpers.post(views.configure, {'app': 'mongodb', 'settings': {'cache_gb': 0.5}}, admin=True)
            call.assert_called_with('appsvc', 'configure', app='mongodb', settings={'cache_gb': 0.5}, confirm_exposed=False)

    def test_page_renders_every_application(self):
        status, values = helpers.page(views.page, admin=True)
        self.assertEqual(status, 200)
        self.assertEqual([a['key'] for a in values['apps']], list(sv.ORDER))
        request = RequestFactory().get('/addons/applications/')
        request.session = {}
        html = render_to_string('universalAddons/appsvc.html', dict(values, request=request))
        for key in sv.ORDER:
            self.assertIn('id="as-pane-%s"' % key, html)
        self.assertIn('id="as-pane-overview-disk"', html)
        self.assertIn('href="/addons/mssql/"', html)
        self.assertIn('href="/docker/"', html)
        self.assertIn('data-runtimes="/addons/apps/"', html)
        self.assertIn('class="as-major"', html)
        self.assertIn('as-pg-create', html)
        self.assertIn('Oracle Database 23ai Free', html)
        self.assertIn('Show what will be removed', html)
        self.assertIn('IndiansCloud', html)

import json
import os
import tempfile
from contextlib import ExitStack, contextmanager
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase

from universalAddons import jobs
from universalAddons.appsvc import actions, service as sv, views
from universalAddons.tests import helpers

STOCK_YML = """# ======================== Elasticsearch Configuration =========================
#cluster.name: my-application
#node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
#network.host: 192.168.0.1
#http.port: 9200
"""

STOCK_REDIS = """bind 127.0.0.1
protected-mode yes
port 6379
daemonize no
supervised no
logfile /var/log/redis/redis.log
save 900 1
save 300 10
save 60 10000
dir /var/lib/redis
appendonly no
"""

STOCK_MEMCACHED = 'PORT="11211"\nUSER="memcached"\nMAXCONN="1024"\nCACHESIZE="64"\nOPTIONS="-l 127.0.0.1,::1"\n'

ES_CFG = {'heap_mb': 512, 'network_host': '127.0.0.1', 'http_port': 9200, 'single_node': True, 'security': False}


class Blocks(SimpleTestCase):
    def test_block_appended_once_and_replaced_in_place(self):
        cfg, _ = sv.validate_es(ES_CFG, 3736, STOCK_YML)
        once = sv.apply_block(STOCK_YML, sv.render_es_block(cfg))
        self.assertTrue(once.startswith(STOCK_YML.rstrip('\n')))
        self.assertEqual(once.count(sv.MARK_BEGIN), 1)
        self.assertIn('network.host: "127.0.0.1"\nhttp.port: 9200\ndiscovery.type: single-node\nxpack.security.enabled: false', once)
        self.assertEqual(sv.apply_block(once, sv.render_es_block(cfg)), once, 'idempotent')
        cfg2, _ = sv.validate_es(dict(ES_CFG, http_port=9201, cluster_name='shop'), 3736, once)
        twice = sv.apply_block(once + '# a line the admin added later\n', sv.render_es_block(cfg2))
        self.assertEqual(twice.count(sv.MARK_BEGIN), 1)
        self.assertIn('http.port: 9201', twice)
        self.assertNotIn('\nhttp.port: 9200', twice)
        self.assertTrue(twice.rstrip().endswith('# a line the admin added later'), 'text after the block is kept')
        self.assertEqual(sv.apply_block(once, []), STOCK_YML, 'an empty body removes the block')

    def test_broken_block_is_refused(self):
        with self.assertRaisesRegex(sv.AppError, 'no END'):
            sv.apply_block(STOCK_YML + sv.MARK_BEGIN + '\nhttp.port: 1\n', ['x'])

    def test_yml_settings_outside_the_block_are_not_duplicated(self):
        text = STOCK_YML + 'http.port: 9250\n'
        with self.assertRaisesRegex(sv.AppError, 'http.port'):
            sv.validate_es(ES_CFG, 3736, text)
        with self.assertRaisesRegex(sv.AppError, 'xpack'):
            sv.validate_es(ES_CFG, 3736, STOCK_YML + 'xpack:\n  security.enabled: true\n')
        with self.assertRaisesRegex(sv.AppError, 'initial_master_nodes'):
            sv.validate_es(ES_CFG, 3736, STOCK_YML + 'cluster.initial_master_nodes: ["a"]\n')
        managed = sv.apply_block(STOCK_YML, sv.render_es_block(sv.validate_es(ES_CFG, 3736, STOCK_YML)[0]))
        sv.validate_es(dict(ES_CFG, http_port=9201), 3736, managed)  # its own block is no conflict
        current = sv.es_current(managed, sv.heap_text(768), 3736)
        self.assertEqual((current['heap_mb'], current['http_port'], current['single_node'], current['managed']),
                         (768, 9200, True, True))

    def test_redis_include_block_and_dropin(self):
        conf = '/etc/redis.conf'
        once = sv.apply_block(STOCK_REDIS, sv.redis_include_block(conf))
        self.assertTrue(once.rstrip().endswith('include /etc/redis-panel-managed.conf\n' + sv.MARK_END))
        self.assertEqual(sv.apply_block(once, sv.redis_include_block(conf)), once)
        cfg, _ = sv.validate_redis({'maxmemory_mb': 256, 'policy': 'allkeys-lru', 'bind': ['127.0.0.1'], 'port': 6379,
                                    'password': True, 'persistence': 'off', 'unixsocket': True, 'socket_perm': '770'}, 3736)
        dropin = sv.render_redis_dropin(cfg, 'Secret-1')
        current = sv.redis_current(once, dropin)
        self.assertEqual((current['maxmemory_mb'], current['persistence'], current['password'], current['unixsocket']),
                         (256, 'off', True, True))
        self.assertEqual(sv.redis_password_in(once, dropin), 'Secret-1')
        # Without the include line in redis.conf the drop-in file is not in effect.
        self.assertEqual(sv.redis_current(STOCK_REDIS, dropin)['persistence'], 'rdb')
        self.assertFalse(sv.redis_current(STOCK_REDIS, dropin)['password'])
        aof, _ = sv.validate_redis(dict(cfg, persistence='aof', password=False), 3736)
        self.assertEqual(sv.redis_current(once, sv.render_redis_dropin(aof))['persistence'], 'aof')
        self.assertIn('requirepass ""', sv.render_redis_dropin(aof))

    def test_memcached_sysconfig_is_edited_in_place(self):
        cfg, _ = sv.validate_memcached({'memory_mb': 128, 'max_conn': 2048, 'port': 11211, 'listen': ['127.0.0.1']}, 3736)
        text = sv.render_sysconfig(STOCK_MEMCACHED.replace('"-l 127.0.0.1,::1"', '"-l 0.0.0.0 -U 0"'), cfg)
        self.assertEqual(text, 'PORT="11211"\nUSER="memcached"\nMAXCONN="2048"\nCACHESIZE="128"\nOPTIONS="-l 127.0.0.1 -U 0"\n')
        self.assertEqual(sv.render_sysconfig(text, cfg), text, 'idempotent')
        self.assertEqual(sv.memcached_current(text), {'memory_mb': 128, 'max_conn': 2048, 'port': 11211,
                                                      'listen': ['127.0.0.1'], 'managed': True})


class Validation(SimpleTestCase):
    def test_heap_is_bounded_by_ram(self):
        self.assertEqual(sv.es_heap_bounds(3736), (256, 1856))
        self.assertEqual(sv.validate_es(dict(ES_CFG, heap_mb=1856), 3736)[0]['heap_mb'], 1856)
        for heap in (1920, 128, 'lots', True):
            with self.assertRaises(sv.AppError, msg=heap):
                sv.validate_es(dict(ES_CFG, heap_mb=heap), 3736)
        _, warnings = sv.validate_es(dict(ES_CFG, heap_mb=1500), 3736)
        self.assertTrue(any('quarter of RAM' in w for w in warnings))

    def test_cache_sizes_are_bounded_by_ram(self):
        base = {'policy': 'allkeys-lru', 'bind': ['127.0.0.1'], 'port': 6379, 'persistence': 'rdb'}
        self.assertEqual(sv.validate_redis(dict(base, maxmemory_mb=1868), 3736)[0]['maxmemory_mb'], 1868)
        for value in (1869, 8, -1):
            with self.assertRaises(sv.AppError):
                sv.validate_redis(dict(base, maxmemory_mb=value), 3736)
        with self.assertRaises(sv.AppError):
            sv.validate_memcached({'memory_mb': 2000, 'max_conn': 1024, 'port': 11211, 'listen': ['127.0.0.1']}, 3736)

    def test_exposure_needs_confirmation_and_safeguards(self):
        with self.assertRaisesRegex(sv.AppError, 'single-node'):
            sv.validate_es(dict(ES_CFG, network_host='0.0.0.0', single_node=False), 3736, confirm_exposed=True)
        with self.assertRaisesRegex(sv.AppError, 'confirmation'):
            sv.validate_es(dict(ES_CFG, network_host='0.0.0.0'), 3736)
        _, warnings = sv.validate_es(dict(ES_CFG, network_host='0.0.0.0'), 3736, confirm_exposed=True)
        self.assertTrue(any('WITHOUT A PASSWORD' in w for w in warnings))
        base = {'maxmemory_mb': 64, 'policy': 'allkeys-lru', 'port': 6379, 'persistence': 'rdb'}
        with self.assertRaisesRegex(sv.AppError, 'only with a password'):
            sv.validate_redis(dict(base, bind=['0.0.0.0']), 3736, confirm_exposed=True)
        sv.validate_redis(dict(base, bind=['0.0.0.0'], password=True), 3736, confirm_exposed=True)
        with self.assertRaisesRegex(sv.AppError, 'confirmation'):
            sv.validate_memcached({'memory_mb': 64, 'max_conn': 1024, 'port': 11211, 'listen': ['10.0.0.5']}, 3736)
        for bad in (['127.0.0.1; rm -rf /'], ['localhost'], ['1.2.3.4.5']):
            with self.assertRaises(sv.AppError):
                sv.validate_redis(dict(base, bind=bad), 3736)
        with self.assertRaises(sv.AppError):
            sv.validate_es(dict(ES_CFG, cluster_name='a b'), 3736)
        with self.assertRaises(sv.AppError):
            sv.validate_es(dict(ES_CFG, http_port=9300), 3736)

    def test_preflight_minimums(self):
        checks = sv.preflight_checks('elasticsearch', 3736, 700, 5000, False)
        self.assertIn('install anyway', sv.preflight_refusal(checks, False))
        self.assertIsNone(sv.preflight_refusal(checks, True))
        checks = sv.preflight_checks('redis', 3736, 2000, 5000, True)
        self.assertIn('already installed', sv.preflight_refusal(checks, True))


@contextmanager
def sandbox():
    """Temporary state, job and backup directories, and a host with 3.7 GB of RAM."""
    base = tempfile.mkdtemp()
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(sv, 'STATE_DIR', os.path.join(base, 'state')))
        stack.enter_context(mock.patch.object(sv, 'WORK_DIR', os.path.join(base, 'work')))
        stack.enter_context(mock.patch.object(jobs, 'JOB_DIR', os.path.join(base, 'jobs')))
        stack.enter_context(mock.patch.object(sv, 'meminfo_mb', return_value=(3736, 2000)))
        stack.enter_context(mock.patch.object(actions, '_systemd', return_value={'MainPID': '0', 'ActiveState': 'active'}))
        stack.enter_context(mock.patch.object(actions, '_ss', return_value=''))
        os.makedirs(os.path.join(base, 'jobs'))
        yield base


def run_job(func, **args):
    job_id = os.urandom(12).hex()
    func(job_id, **args)
    return jobs.status(job_id)


class Secrets(SimpleTestCase):
    def test_password_is_revealed_once(self):
        with sandbox():
            sv.store_secret('redis', 'pw-123')
            self.assertEqual(sv.secret_status('redis')['reveal_pending'], True)
            self.assertEqual(actions.reveal('redis'), {'app': 'redis', 'password': 'pw-123'})
            with self.assertRaisesRegex(sv.AppError, 'already shown'):
                actions.reveal('redis')
            self.assertEqual(sv.secret_status('redis'), {'stored': True, 'reveal_pending': False,
                                                         'created': sv.load_secret('redis')['created']})
            self.assertEqual(oct(os.stat(sv.secret_path('redis')).st_mode & 0o777), '0o600')
            self.assertEqual(oct(os.stat(sv.STATE_DIR).st_mode & 0o777), '0o700')

    def test_connection_info_never_holds_the_password(self):
        cfg, _ = sv.validate_redis({'maxmemory_mb': 64, 'policy': 'allkeys-lru', 'bind': ['127.0.0.1'], 'port': 6379,
                                    'password': True, 'persistence': 'rdb', 'unixsocket': True}, 3736)
        info = json.dumps(sv.connection_info('redis', dict(cfg, socket_path=sv.REDIS_SOCKET), True))
        self.assertIn('WP_REDIS_PASSWORD', info)
        self.assertIn('shown once', info)
        self.assertIn('/run/redis/redis.sock', info)

    def test_generated_redis_password_reaches_only_the_config_and_one_reveal(self):
        with sandbox() as base:
            conf = os.path.join(base, 'redis.conf')
            with open(conf, 'w') as handle:
                handle.write(STOCK_REDIS)
            settings = {'maxmemory_mb': 128, 'policy': 'allkeys-lru', 'bind': ['127.0.0.1'], 'port': 6379,
                        'password': True, 'persistence': 'rdb', 'unixsocket': False, 'socket_perm': '770'}
            with mock.patch.object(sv, 'REDIS_CONFS', (conf,)), \
                    mock.patch.object(sv, 'REDIS_SYSTEMD_DROPIN', os.path.join(base, 'systemd', 'panel-managed.conf')), \
                    mock.patch.object(actions, '_version', side_effect=lambda app: '5.0.3' if app == 'redis' else None), \
                    mock.patch.object(actions, '_restart') as restart, \
                    mock.patch.object(actions, '_wait_healthy', return_value=(True, 'PING -> PONG')):
                data = run_job(actions.configure_run, app='redis', settings=settings)
                self.assertEqual(data['state'], 'done', data)
                restart.assert_called_once_with('redis')
                password = sv.load_secret('redis')['password']
                self.assertNotIn(password, json.dumps(data))
                with open(sv.redis_dropin_path(conf)) as handle:
                    self.assertIn('requirepass %s' % password, handle.read())
                with open(conf) as handle:
                    self.assertIn('include %s' % sv.redis_dropin_path(conf), handle.read())
                self.assertNotIn(password, json.dumps(actions._app_status('redis', 3736, 2000, 5000)))
                self.assertEqual(actions.reveal('redis')['password'], password)
                with self.assertRaises(sv.AppError):
                    actions.reveal('redis')
                # Applying again keeps the same password (and does not offer it again).
                data = run_job(actions.configure_run, app='redis', settings=dict(settings, maxmemory_mb=200))
                self.assertEqual(data['result']['Apply Redis settings']['password_generated'], False)
                self.assertEqual(sv.load_secret('redis')['password'], password)
                self.assertEqual(len(sv.list_snapshots(sv.backup_root('redis'))), 2)


class Rollback(SimpleTestCase):
    def test_failed_health_check_restores_files(self):
        base = tempfile.mkdtemp()
        kept, created = os.path.join(base, 'kept.conf'), os.path.join(base, 'created.conf')
        with open(kept, 'w') as handle:
            handle.write('old\n')
        os.chmod(kept, 0o640)
        restarts, logged = [], []

        def write():
            sv.write_file(kept, 'new\n')
            sv.write_file(created, 'brand new\n')
        health = iter([(False, 'no answer'), (True, 'back')])
        with self.assertRaisesRegex(sv.AppError, 'previous configuration was restored and the service is running again'):
            sv.apply_with_rollback([kept, created], write, lambda: restarts.append(1), lambda: next(health),
                                   os.path.join(base, 'backups'), log=logged.append)
        with open(kept) as handle:
            self.assertEqual(handle.read(), 'old\n')
        self.assertEqual(oct(os.stat(kept).st_mode & 0o777), '0o640')
        self.assertFalse(os.path.exists(created))
        self.assertEqual(len(restarts), 2)
        self.assertEqual(sv.list_snapshots(os.path.join(base, 'backups')), [], 'no snapshot left for a failed change')

    def test_restart_failure_is_rolled_back_too(self):
        base = tempfile.mkdtemp()
        path = os.path.join(base, 'f')
        with open(path, 'w') as handle:
            handle.write('a')
        calls = []

        def restart():
            calls.append(1)
            if len(calls) == 1:
                raise sv.AppError('systemctl restart failed')
        with self.assertRaisesRegex(sv.AppError, 'systemctl restart failed'):
            sv.apply_with_rollback([path], lambda: sv.write_file(path, 'b'), restart, lambda: (True, 'ok'),
                                   os.path.join(base, 'b'))
        with open(path) as handle:
            self.assertEqual(handle.read(), 'a')

    def test_memcached_job_rolls_back_and_revert_walks_back(self):
        with sandbox() as base:
            path = os.path.join(base, 'memcached')
            with open(path, 'w') as handle:
                handle.write(STOCK_MEMCACHED)
            settings = {'memory_mb': 256, 'max_conn': 2048, 'port': 11211, 'listen': ['127.0.0.1']}
            with mock.patch.object(sv, 'MEMCACHED_SYSCONFIG', path), \
                    mock.patch.object(actions, '_version', side_effect=lambda app: '1.5.22' if app == 'memcached' else None), \
                    mock.patch.object(actions, '_restart') as restart:
                with mock.patch.object(actions, '_wait_healthy', return_value=(False, 'no answer (refused)')):
                    data = run_job(actions.configure_run, app='memcached', settings=settings)
                self.assertEqual(data['state'], 'failed')
                self.assertIn('previous configuration was restored', data['error'])
                self.assertEqual(restart.call_count, 2)
                with open(path) as handle:
                    self.assertEqual(handle.read(), STOCK_MEMCACHED)
                with mock.patch.object(actions, '_wait_healthy', return_value=(True, 'stats: version 1.5.22')):
                    self.assertEqual(run_job(actions.configure_run, app='memcached', settings=settings)['state'], 'done')
                    with open(path) as handle:
                        self.assertIn('CACHESIZE="256"', handle.read())
                    self.assertEqual(run_job(actions.revert_run, app='memcached')['state'], 'done')
                with open(path) as handle:
                    self.assertEqual(handle.read(), STOCK_MEMCACHED)
                self.assertEqual(sv.list_snapshots(sv.backup_root('memcached')), [])
                with self.assertRaisesRegex(sv.AppError, 'no earlier configuration'):
                    actions.revert('memcached')

    def test_health_checks(self):
        class Conn:
            def __init__(self, status, body):
                self.status, self.body = status, body

            def __call__(self, host, port, timeout):
                return self

            def request(self, method, url, headers):
                self.headers = headers

            def getresponse(self):
                return self

            def read(self, size):
                return self.body

            def close(self):
                pass
        self.assertEqual(sv.es_health('127.0.0.1', 9200, connection=Conn(200, b'{"status":"yellow"}')),
                         (True, 'HTTP 200, cluster status yellow'))
        self.assertFalse(sv.es_health('127.0.0.1', 9200, connection=Conn(503, b''))[0])
        self.assertEqual(sv.redis_health({'host': '127.0.0.1', 'port': 6379}, command=lambda *a, **k: ['PONG']),
                         (True, 'PING -> PONG'))

        def refused(*args, **kwargs):
            raise OSError('refused')
        self.assertFalse(sv.redis_health({'host': '127.0.0.1', 'port': 6379}, command=refused)[0])
        self.assertTrue(sv.memcached_health({'host': '127.0.0.1', 'port': 11211},
                                            stats=lambda **k: {'version': '1.5.22', 'curr_connections': '2'})[0])
        ticks = iter(range(100))
        self.assertEqual(sv.wait_healthy(lambda: (False, 'down'), 5, sleep=lambda s: None, clock=lambda: next(ticks)),
                         (False, 'down'))

    def test_status_parsers(self):
        ss = ('LISTEN 0 128 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=713617,fd=6))\n'
              'LISTEN 0 128 [::ffff:127.0.0.1]:9200 *:* users:(("java",pid=42,fd=300))\n')
        self.assertEqual(sv.parse_ss(ss, 713617), ['127.0.0.1:6379'])
        self.assertEqual(sv.ports_in_use(ss, exclude_pid=42), {6379})
        self.assertEqual(sv.memory_current({'MemoryCurrent': '350068736'}), 350068736)
        self.assertIsNone(sv.memory_current({'MemoryCurrent': '[not set]'}))
        self.assertIsNone(sv.memory_current({'MemoryCurrent': '18446744073709551615'}))
        self.assertEqual(sv.resp_encode('AUTH', 'p w'), b'*2\r\n$4\r\nAUTH\r\n$3\r\np w\r\n')


class RemoveConfirm(SimpleTestCase):
    def test_actions_require_confirmation(self):
        with mock.patch.object(actions, '_version', return_value='5.0.3'), \
                mock.patch.object(actions, '_busy', return_value=False), \
                mock.patch('universalAddons.jobs.spawn', return_value={'job_id': 'x'}) as spawn:
            with self.assertRaisesRegex(sv.AppError, 'Confirm'):
                actions.remove('redis')
            with self.assertRaisesRegex(sv.AppError, 'Type redis'):
                actions.remove('redis', confirm=True, delete_data=True, confirm_name='Redis!')
            spawn.assert_not_called()
            actions.remove('redis', confirm=True)
            spawn.assert_called_with('appsvc', 'remove_run', {'app': 'redis', 'delete_data': False})
            actions.remove('redis', confirm=True, delete_data=True, confirm_name=' Redis ')
            spawn.assert_called_with('appsvc', 'remove_run', {'app': 'redis', 'delete_data': True})

    def test_view_requires_confirmation(self):
        with mock.patch('universalAddons.privileged.call', return_value={'job_id': 'x'}) as call:
            status, body, _ = helpers.post(views.remove, {'app': 'redis'}, admin=True)
            self.assertEqual(status, 400)
            status, _, _ = helpers.post(views.remove, {'app': 'redis', 'confirm': True, 'deleteData': True,
                                                       'confirmName': 'elasticsearch'}, admin=True)
            self.assertEqual(status, 400)
            call.assert_not_called()
            helpers.post(views.remove, {'app': 'redis', 'confirm': True, 'deleteData': 'yes', 'confirmName': 'x'}, admin=True)
            call.assert_called_with('appsvc', 'remove', app='redis', confirm=True, delete_data=False, confirm_name='')
            helpers.post(views.remove, {'app': 'redis', 'confirm': True, 'deleteData': True, 'confirmName': 'redis'}, admin=True)
            call.assert_called_with('appsvc', 'remove', app='redis', confirm=True, delete_data=True, confirm_name='redis')

    def test_data_is_kept_unless_asked(self):
        with sandbox() as base:
            data_dir = os.path.join(base, 'data')
            os.makedirs(data_dir)
            apps = dict(sv.APPS, memcached=dict(sv.APPS['memcached'], data_dir=data_dir))
            with mock.patch.object(sv, 'APPS', apps), \
                    mock.patch.object(actions, '_version', return_value=None), \
                    mock.patch.object(sv, 'run', return_value=(0, 'ok')):
                data = run_job(actions.remove_run, app='memcached', delete_data=False)
            self.assertEqual(data['state'], 'done', data)
            self.assertTrue(os.path.isdir(data_dir))


class Access(SimpleTestCase):
    VIEWS = (views.overview, views.logs, views.preflight, views.install, views.remove, views.configure, views.revert,
             views.control, views.reveal, views.job)

    def test_everything_is_admin_only(self):
        body = {'app': 'redis', 'op': 'start', 'job': 'ab' * 12, 'confirm': True, 'settings': {}}
        with mock.patch('universalAddons.privileged.call', return_value={}) as call:
            for view in self.VIEWS:
                self.assertEqual(helpers.post(view, body, admin=False)[0], 403, view.__name__)
                self.assertEqual(helpers.post(view, body, session={})[0], 401, view.__name__)
            call.assert_not_called()
        self.assertEqual(helpers.page(views.page, admin=False)[0], 403)

    def test_admin_calls_and_validation(self):
        with mock.patch('universalAddons.privileged.call', return_value={'job_id': 'x'}) as call:
            helpers.post(views.install, {'app': 'Redis', 'force': 'yes'}, admin=True)
            call.assert_called_with('appsvc', 'install', app='redis', force=False)
            helpers.post(views.configure, {'app': 'redis', 'settings': {'port': 6380}, 'confirmExposed': True}, admin=True)
            call.assert_called_with('appsvc', 'configure', app='redis', settings={'port': 6380}, confirm_exposed=True)
            call.reset_mock()
            for view, body in ((views.install, {'app': 'mysql'}), (views.control, {'app': 'redis', 'op': 'kill'}),
                               (views.configure, {'app': 'redis', 'settings': {'dir': '/'}}),
                               (views.configure, {'app': 'redis', 'settings': {'port': {'x': 1}}}),
                               (views.revert, {'app': 'redis'}), (views.job, {'job': '../x'})):
                self.assertEqual(helpers.post(view, body, admin=True)[0], 400, (view.__name__, body))
            call.assert_not_called()

    def test_legacy_api_uses_the_same_jobs(self):
        call = mock.Mock(return_value={'job_id': 'x'})
        views.legacy_remove_install('Elasticsearch', 'Installing', call=call)
        call.assert_called_with('appsvc', 'install', app='elasticsearch', force=False)
        views.legacy_remove_install('Redis', 'Removing', call=call)
        call.assert_called_with('appsvc', 'remove', app='redis', confirm=True, delete_data=False, confirm_name='')
        with self.assertRaises(ValueError):
            views.legacy_remove_install('Memcached', 'Installing', call=call)

    def test_legacy_page_redirects_administrators(self):
        from manageServices import views as legacy
        request = RequestFactory().get('/manageservices/manageApplications')
        request.session = {'userID': 1}
        with mock.patch('manageServices.views.ACLManager.loadedACL', return_value={'admin': 1}):
            response = legacy.manageApplications(request)
        self.assertEqual((response.status_code, response['Location']), (302, '/addons/applications/'))
        request = RequestFactory().post('/manageservices/removeInstall', data=json.dumps(
            {'appName': 'Redis', 'status': 'Installing'}), content_type='application/json')
        request.session = {'userID': 1}
        with mock.patch('manageServices.views.ACLManager.loadedACL', return_value={'admin': 1}), \
                mock.patch('universalAddons.privileged.call', return_value={'job_id': 'x'}) as call:
            response = legacy.removeInstall(request)
        self.assertEqual(json.loads(response.content), {'status': 1})
        call.assert_called_once_with('appsvc', 'install', app='redis', force=False)


class Page(SimpleTestCase):
    def test_page_renders(self):
        status, values = helpers.page(views.page, admin=True)
        self.assertEqual(status, 200)
        self.assertEqual(values['_template'], 'universalAddons/appsvc.html')
        self.assertEqual([a['key'] for a in values['apps']], ['elasticsearch', 'redis', 'memcached'])
        request = RequestFactory().get('/addons/applications/')
        request.session = {}
        html = render_to_string('universalAddons/appsvc.html', dict(values, request=request))
        self.assertIn('ua-wrap', html)
        self.assertIn('data-base="/addons/applications/"', html)
        self.assertIn('id="as-pane-memcached"', html)
        self.assertIn('OpenSearch', html)
        self.assertIn('appsvc.js', html)

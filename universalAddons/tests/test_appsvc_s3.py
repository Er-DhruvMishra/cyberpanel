"""Applications add-on: S3-compatible object storage (Garage) - configuration, names, secrets, verified
downloads, rollback, uninstall, the HTTPS endpoint, the page and the Services page."""
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
from contextlib import ExitStack, contextmanager
from unittest import mock

from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase

from universalAddons.appsvc import actions, s3, service as sv, views
from universalAddons.tests import helpers
from universalAddons.tests.test_appsvc import run_job, sandbox

RAM = 3736
NODE = 'a1' * 32
SECRET = 'f00dfeed' * 8


class FakeGarage:
    """Enough of Garage's admin API v2 for the panel's calls."""

    def __init__(self, with_role=True):
        self.roles = [{'id': NODE, 'zone': 'dc1'}] if with_role else []
        self.version = 1 if with_role else 0
        self.buckets, self.keys, self.calls = {}, {}, []

    def __call__(self, method, path, token, body=None):
        self.calls.append((method, path, body))
        route, _, query = path.partition('?')
        args = dict(p.split('=', 1) for p in query.split('&') if '=' in p)
        if route == '/health':
            return (200, 'Garage is fully operational') if self.roles else (503, 'no quorum')
        if token != 'admin-token':
            return 403, {'message': 'Forbidden'}
        if route == '/v2/GetClusterHealth':
            return 200, {'status': 'healthy', 'partitions': 256, 'partitionsAllOk': 256}
        if route == '/v2/GetClusterStatus':
            return 200, {'layoutVersion': self.version, 'nodes': [{'id': NODE, 'isUp': True, 'draining': False}]}
        if route == '/v2/GetClusterLayout':
            return 200, {'version': self.version, 'roles': self.roles}
        if route == '/v2/UpdateClusterLayout':
            self.staged = body['roles']
            return 200, {}
        if route == '/v2/ApplyClusterLayout':
            self.roles, self.version = self.staged, body['version']
            return 200, {}
        if route == '/v2/CreateBucket':
            bucket_id = hashlib.sha256(body['globalAlias'].encode()).hexdigest()
            self.buckets[bucket_id] = {'id': bucket_id, 'globalAliases': [body['globalAlias']], 'objects': 0,
                                       'bytes': 0, 'quotas': {'maxSize': None, 'maxObjects': None}, 'keys': []}
            return 200, self.buckets[bucket_id]
        if route == '/v2/ListBuckets':
            return 200, [{'id': b['id'], 'globalAliases': b['globalAliases']} for b in self.buckets.values()]
        if route == '/v2/GetBucketInfo':
            for bucket in self.buckets.values():
                if args.get('id') == bucket['id'] or args.get('globalAlias') in bucket['globalAliases']:
                    return 200, bucket
            return 404, {'message': 'Bucket not found'}
        if route == '/v2/UpdateBucket':
            self.buckets[args['id']]['quotas'] = body['quotas']
            return 200, self.buckets[args['id']]
        if route == '/v2/DeleteBucket':
            del self.buckets[args['id']]
            return 200, {}
        if route == '/v2/CreateKey':
            key = 'GK' + os.urandom(12).hex()
            self.keys[key] = {'id': key, 'name': body['name'], 'expired': False}
            return 200, {'accessKeyId': key, 'name': body['name'], 'secretAccessKey': SECRET}
        if route == '/v2/ListKeys':   # a careless server could include secrets: the panel must drop them
            return 200, [dict(k, secretAccessKey=SECRET) for k in self.keys.values()]
        if route == '/v2/DeleteKey':
            del self.keys[args['id']]
            return 200, {}
        if route in ('/v2/AllowBucketKey', '/v2/DenyBucketKey'):
            bucket = self.buckets[body['bucketId']]
            entry = next((k for k in bucket['keys'] if k['accessKeyId'] == body['accessKeyId']), None)
            if entry is None:
                entry = {'accessKeyId': body['accessKeyId'], 'name': self.keys[body['accessKeyId']]['name'],
                         'permissions': {'read': False, 'write': False, 'owner': False}}
                bucket['keys'].append(entry)
            for name, on in body['permissions'].items():
                if on:
                    entry['permissions'][name] = route == '/v2/AllowBucketKey'
            return 200, {}
        return 404, {'message': 'unknown %s' % route}


@contextmanager
def s3_sandbox(garage=None, installed=True, running=True):
    """sandbox() plus Garage's files under a temporary root and a fake admin API."""
    with sandbox() as base, ExitStack() as stack:
        etc = os.path.join(base, 'etc')
        os.makedirs(os.path.join(etc, 'garage'))
        paths = {'BIN': os.path.join(base, 'garage'), 'CONF': os.path.join(etc, 'garage.toml'),
                 'SECRET_DIR': os.path.join(etc, 'garage'), 'RPC_SECRET': os.path.join(etc, 'garage', 'rpc_secret'),
                 'ADMIN_TOKEN': os.path.join(etc, 'garage', 'admin_token'),
                 'METRICS_TOKEN': os.path.join(etc, 'garage', 'metrics_token'),
                 'UNIT_FILE': os.path.join(etc, 'garage.service'),
                 'DROPIN': os.path.join(etc, 'garage.service.d', 'panel-managed.conf'),
                 'DEFAULT_DATA_DIR': os.path.join(base, 'lib', 'garage'),
                 'DATA_PREFIXES': (os.path.join(base, 'lib') + '/',)}
        for name, value in paths.items():
            stack.enter_context(mock.patch.object(s3, name, value))
        fake = garage or FakeGarage()
        stack.enter_context(mock.patch.object(s3, 'admin_call', fake))
        stack.enter_context(mock.patch.object(actions, '_owner', return_value=(os.getuid(), os.getgid())))
        stack.enter_context(mock.patch.object(actions, '_systemd', return_value={
            'MainPID': '0', 'ActiveState': 'active' if running else 'inactive'}))
        if installed:
            with open(paths['BIN'], 'wb') as handle:
                handle.write(b'\x7fELF fake garage')
            with open(paths['ADMIN_TOKEN'], 'w') as handle:
                handle.write('admin-token\n')
            cfg, _ = s3.validate(s3.defaults(), RAM)
            with open(paths['CONF'], 'w') as handle:
                handle.write(s3.render_conf('', cfg))
            os.makedirs(os.path.dirname(paths['DROPIN']))
            with open(paths['DROPIN'], 'w') as handle:
                handle.write(s3.render_dropin(cfg))
            os.makedirs(os.path.join(cfg['data_dir'], 'meta'))
            actions._s3_save_state(version=s3.VERSION)
        stack.enter_context(mock.patch.object(actions, '_version', side_effect=lambda app: (
            actions._s3_version() if app == 's3' else None)))
        yield base, fake, paths


def defaults_in(base):
    return dict(s3.defaults(), data_dir=os.path.join(base, 'lib', 'garage'))


class Config(SimpleTestCase):
    def test_rendering_is_idempotent_and_round_trips(self):
        cfg, warnings = s3.validate(s3.defaults(), RAM)
        self.assertEqual(warnings, [])
        text = s3.render_conf('', cfg)
        self.assertTrue(text.startswith(s3.MANAGED_HEADER))
        self.assertEqual(text.count(sv.MARK_BEGIN), 1)
        for line in ('metadata_dir = "/var/lib/garage/meta"', 'data_dir = "/var/lib/garage/data"', 'db_engine = "sqlite"',
                     'replication_factor = 1', 'rpc_bind_addr = "127.0.0.1:3901"', 's3_region = "garage"',
                     'api_bind_addr = "127.0.0.1:3900"', 'api_bind_addr = "127.0.0.1:3903"',
                     'admin_token_file = "%s"' % s3.ADMIN_TOKEN, 'rpc_secret_file = "%s"' % s3.RPC_SECRET):
            self.assertIn('\n' + line + '\n', text)
        self.assertNotIn('[s3_web]', text, 'the website port is off by default')
        self.assertNotIn('public_endpoint', text)
        self.assertLess(text.index('replication_factor'), text.index('[s3_api]'), 'top-level keys before tables')
        self.assertEqual(s3.render_conf(text, cfg), text, 'idempotent')
        dropin = s3.render_dropin(cfg)
        self.assertIn('MemoryMax=256M', dropin)
        self.assertIn('MemoryLimit=256M', dropin, 'EL8 runs the legacy cgroup hierarchy')
        self.assertNotIn('MemoryLimit', s3.render_dropin(cfg, unified=True))
        self.assertIn('ReadWritePaths=/var/lib/garage', dropin)
        current = s3.current(text, dropin)
        self.assertEqual({k: current[k] for k in s3.defaults()}, s3.defaults())
        self.assertEqual(s3.render_conf(text, s3.validate(current, RAM)[0]), text, 'round trip')
        # A changed setting replaces the block in place and keeps the admin's own lines after it.
        cfg2, _ = s3.validate(dict(s3.defaults(), s3_port=3910, region='eu-1', web_port=3902, memory_mb=384), RAM)
        mine = text + 'metrics_require_token = true\n'
        changed = s3.render_conf(mine, cfg2, endpoint='s3.example.com')
        self.assertEqual(changed.count(sv.MARK_BEGIN), 1)
        self.assertIn('api_bind_addr = "127.0.0.1:3910"', changed)
        self.assertIn('public_endpoint = "https://s3.example.com"', changed)
        self.assertIn('[s3_web]\nbind_addr = "127.0.0.1:3902"', changed)
        self.assertTrue(changed.rstrip().endswith('metrics_require_token = true'))
        now = s3.current(changed, s3.render_dropin(cfg2))
        self.assertEqual((now['s3_port'], now['region'], now['web_port'], now['memory_mb'], now['public_endpoint']),
                         (3910, 'eu-1', 3902, 384, 'https://s3.example.com'))
        self.assertEqual(s3.current('', None)['managed'], False)
        v6, _ = s3.validate(dict(s3.defaults(), bind='::1'), RAM)
        self.assertIn('api_bind_addr = "[::1]:3900"', '\n'.join(s3.render_block(v6)))
        self.assertEqual(s3.current(s3.render_conf('', v6))['bind'], '::1')

    def test_unit_is_hardened(self):
        unit = s3.render_unit(239)
        for line in ('User=garage', 'ExecStart=/usr/local/bin/garage -c /etc/garage.toml server', 'NoNewPrivileges=yes',
                     'ProtectSystem=strict', 'ProtectHome=yes', 'PrivateTmp=yes', 'CapabilityBoundingSet=',
                     'MemoryDenyWriteExecute=yes', 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'):
            self.assertIn('\n' + line + '\n', unit)
        self.assertIn('-/etc/cyberpanel', unit)
        self.assertNotIn('ProtectKernelLogs', unit, 'not known to systemd 239')
        self.assertIn('ProtectKernelLogs=yes', s3.render_unit(245))

    def test_validation(self):
        for bad in ({'s3_port': 80}, {'s3_port': 3901}, {'s3_port': 3903}, {'web_port': 3900}, {'region': 'EU 1'},
                    {'region': 'x'}, {'replication_factor': '3'}, {'memory_mb': 64}, {'memory_mb': 2000},
                    {'data_dir': '/etc/garage'}, {'data_dir': '/var/lib'}, {'data_dir': '/var/lib/../etc'},
                    {'data_dir': '/var/lib/mysql'}, {'data_dir': 'relative'}, {'data_dir': '/home/user/s3'},
                    {'bind': 'example.com'}, {'s3_port': True}):
            with self.assertRaises(sv.AppError, msg=bad):
                s3.validate(dict(s3.defaults(), **bad), RAM)
        self.assertEqual(s3.validate(dict(s3.defaults(), data_dir='/srv/s3/'), RAM)[0]['data_dir'], '/srv/s3')

    def test_public_listen_needs_the_https_endpoint_and_a_confirmation(self):
        public = dict(s3.defaults(), bind='0.0.0.0')
        with self.assertRaisesRegex(sv.AppError, 'HTTPS endpoint'):
            s3.validate(public, RAM, confirm_exposed=True)
        with self.assertRaisesRegex(sv.AppError, 'confirmation'):
            s3.validate(public, RAM, confirm_exposed=False, endpoint='s3.example.com')
        cfg, warnings = s3.validate(public, RAM, confirm_exposed=True, endpoint='s3.example.com')
        self.assertTrue(warnings[0].startswith('DANGER'))
        self.assertIn('https://s3.example.com', warnings[0])
        self.assertIn('api_bind_addr = "0.0.0.0:3900"', '\n'.join(s3.render_block(cfg)))
        self.assertIn('api_bind_addr = "127.0.0.1:3903"', '\n'.join(s3.render_block(cfg)), 'admin API stays local')

    def test_settings_outside_the_block_are_refused(self):
        cfg, _ = s3.validate(s3.defaults(), RAM)
        text = s3.render_conf('', cfg)
        self.assertEqual(s3.outside_conflicts(text), [])
        self.assertEqual(s3.outside_conflicts('replication_factor = 3\n' + text), ['replication_factor'])
        self.assertIn('[s3_api]', s3.outside_conflicts(text + '[s3_api]\nroot_domain = ".x"\n'))

    def test_budget_and_registry(self):
        self.assertEqual(sv.cap_mb('s3', {'memory_mb': 256}), 256)
        self.assertEqual(actions._default_cap('s3', RAM), 256)
        self.assertIn('s3', sv.ORDER)
        self.assertIn(('garage', 'S3 Object Storage (Garage)', sv.SERVICE_ACTIONS), sv.service_units())
        with mock.patch.object(actions, '_caps', return_value={'SQL Server 2022 Express': 1024, 'Elasticsearch': 1024}), \
                mock.patch.object(actions, '_el', return_value=8), \
                mock.patch.object(actions.platform, 'machine', return_value='x86_64'):
            checks = {c['id']: c for c in actions._preflight_checks('s3', RAM, 1500, 20000, False)}
        self.assertTrue(checks['os']['ok'] and checks['arch']['ok'])
        self.assertTrue(checks['budget']['ok'], 'with 2048 MB elsewhere, 256 MB more stays under 70%')
        with mock.patch.object(actions, '_caps', return_value={'SQL Server 2022 Express': 2400}), \
                mock.patch.object(actions, '_el', return_value=8), \
                mock.patch.object(actions.platform, 'machine', return_value='aarch64'):
            checks = {c['id']: c for c in actions._preflight_checks('s3', RAM, 1500, 20000, False)}
        self.assertFalse(checks['budget']['ok'])
        self.assertFalse(checks['arch']['ok'] or not checks['arch']['hard'])


class Names(SimpleTestCase):
    def test_bucket_and_key_names(self):
        for good in ('abc', 'shop-backups', 'a1b2', 'x' * 63):
            self.assertEqual(s3.bucket_name(good), good)
        for bad in ('ab', 'x' * 64, 'Shop', 'shop_backups', 'shop.backups', '-shop', 'shop-', 'xn--abc', '192.168.1.10',
                    'shop-s3alias', '', None, '../etc', 'a b c', 'ab\nc'):
            with self.assertRaises(sv.AppError, msg=bad):
                s3.bucket_name(bad)
        for good in ('shop-app', 'Shop_App.1', 'a'):
            self.assertEqual(s3.key_name(good), good)
        for bad in ('', '-x', 'x' * 65, 'a b', 'a;rm', '../x'):
            with self.assertRaises(sv.AppError, msg=bad):
                s3.key_name(bad)
        self.assertEqual(s3.key_id('GK' + 'a' * 24), 'GK' + 'a' * 24)
        for bad in ('GK' + 'a' * 23, 'gk' + 'a' * 24, 'GK' + 'g' * 24, '', 'GK' + 'a' * 24 + '&x=1'):
            with self.assertRaises(sv.AppError, msg=bad):
                s3.key_id(bad)
        with self.assertRaises(sv.AppError):
            s3.bucket_id('a' * 63)
        self.assertEqual(s3.clean_domain('S3.Example.com.'), 's3.example.com')
        for bad in ('localhost', 'a..b.com', '-a.example.com', 'exa mple.com', 'x.com/..'):
            with self.assertRaises(sv.AppError, msg=bad):
                s3.clean_domain(bad)
        self.assertEqual(s3.quotas('', None), {'maxSize': None, 'maxObjects': None})
        self.assertEqual(s3.quotas(10, '5'), {'maxSize': 10 * 1024 * 1024, 'maxObjects': 5})
        with self.assertRaises(sv.AppError):
            s3.quotas(-1, None)

    def test_views_validate_before_anything_runs_as_root(self):
        with mock.patch('universalAddons.privileged.call', return_value={}) as call:
            for view, body in ((views.s3_bucket, {'op': 'create', 'bucket': 'Bad_Name'}),
                               (views.s3_bucket, {'op': 'create', 'bucket': 'good-name', 'maxSizeMb': 'lots'}),
                               (views.s3_bucket, {'op': 'delete', 'bucket': 'good-name', 'confirmName': 'other'}),
                               (views.s3_bucket, {'op': 'nuke', 'bucket': 'good-name'}),
                               (views.s3_key, {'op': 'create', 'name': 'a b'}),
                               (views.s3_key, {'op': 'delete', 'key': 'GK' + 'a' * 24}),
                               (views.s3_key, {'op': 'delete', 'key': 'x', 'confirm': True}),
                               (views.s3_permission, {'bucket': 'good-name', 'key': 'nope'}),
                               (views.s3_endpoint, {'op': 'set', 'domain': '../etc'})):
                self.assertEqual(helpers.post(view, body, admin=True)[0], 400, (view.__name__, body))
            call.assert_not_called()
            for view in (views.s3_bucket, views.s3_key, views.s3_permission, views.s3_endpoint):
                self.assertEqual(helpers.post(view, {'op': 'create', 'bucket': 'abc', 'name': 'abc'}, admin=False)[0], 403)
            call.assert_not_called()
            helpers.post(views.s3_bucket, {'op': 'create', 'bucket': 'shop', 'maxSizeMb': 100}, admin=True)
            call.assert_called_with('appsvc', 's3_bucket_create', name='shop', max_size_mb=100, max_objects=None)
            helpers.post(views.s3_permission, {'bucket': 'shop', 'key': 'GK' + 'b' * 24, 'read': True, 'write': 'yes'},
                         admin=True)
            call.assert_called_with('appsvc', 's3_permission', bucket='shop', key='GK' + 'b' * 24, read=True,
                                    write=False, owner=False)
            helpers.post(views.s3_endpoint, {'op': 'set', 'domain': 'S3.example.com'}, admin=True)
            call.assert_called_with('appsvc', 's3_endpoint', op='set', domain='s3.example.com')
            helpers.post(views.configure, {'app': 's3', 'settings': {'memory_mb': 300}}, admin=True)
            call.assert_called_with('appsvc', 'configure', app='s3', settings={'memory_mb': 300}, confirm_exposed=False)
            call.reset_mock()
            self.assertEqual(helpers.post(views.configure, {'app': 's3', 'settings': {'rpc_secret': 'x'}}, admin=True)[0], 400)
            call.assert_not_called()


class Management(SimpleTestCase):
    def test_secret_is_shown_once_and_never_in_status_or_logs(self):
        with s3_sandbox() as (base, garage, paths):
            created = actions.s3_key_create('shop-app')
            self.assertEqual(created['secret'], SECRET)
            self.assertTrue(s3.KEY_ID_RE.match(created['id']))
            status = json.dumps(actions._app_status('s3', RAM, 2000, 5000))
            self.assertIn(created['id'], status)
            self.assertNotIn(SECRET, status, 'not in the status, even if the API offered it')
            self.assertNotIn('admin-token', status)
            with mock.patch.object(sv, 'run', return_value=(0, 'garage[1]: admin-token used; key %s' % created['id'])):
                lines = actions._logs('s3', {})
            self.assertNotIn('admin-token', '\n'.join(lines))
            for folder, _, names in os.walk(base):
                for name in names:
                    with open(os.path.join(folder, name), 'rb') as handle:
                        self.assertNotIn(SECRET.encode(), handle.read(), 'the panel stores no secret: %s' % name)
            self.assertNotIn('GetKeyInfo', json.dumps(garage.calls), 'the panel never asks Garage for a secret again')

    def test_buckets_permissions_and_quotas(self):
        with s3_sandbox() as (base, garage, paths):
            actions.s3_bucket_create('shop-backups', max_size_mb=100)
            bucket = next(iter(garage.buckets.values()))
            self.assertEqual(bucket['quotas'], {'maxSize': 100 * 1024 * 1024, 'maxObjects': None})
            key = actions.s3_key_create('shop')['id']
            actions.s3_permission('shop-backups', key, read=True, write=True)
            self.assertEqual(bucket['keys'][0]['permissions'], {'read': True, 'write': True, 'owner': False})
            actions.s3_permission('shop-backups', key, read=True)
            self.assertEqual(bucket['keys'][0]['permissions'], {'read': True, 'write': False, 'owner': False})
            denied = [c for c in garage.calls if c[1] == '/v2/DenyBucketKey'][-1][2]
            self.assertEqual(denied['permissions'], {'read': False, 'write': True, 'owner': True})
            actions.s3_bucket_quota('shop-backups', None, 1000)
            self.assertEqual(bucket['quotas'], {'maxSize': None, 'maxObjects': 1000})
            inventory = actions._app_status('s3', RAM, 2000, 5000)['inventory']
            self.assertEqual(inventory['buckets'][0]['name'], 'shop-backups')
            self.assertEqual(inventory['keys'][0]['name'], 'shop')
            with self.assertRaisesRegex(sv.AppError, 'Type the bucket name'):
                actions.s3_bucket_delete('shop-backups', 'shop')
            bucket['objects'] = 3
            with self.assertRaisesRegex(sv.AppError, 'empty it first'):
                actions.s3_bucket_delete('shop-backups', 'shop-backups')
            bucket['objects'] = 0
            actions.s3_bucket_delete('shop-backups', 'shop-backups')
            actions.s3_key_delete(key)
            self.assertEqual((garage.buckets, garage.keys), ({}, {}))
        with s3_sandbox(running=False):
            with self.assertRaisesRegex(sv.AppError, 'Start S3'):
                actions.s3_bucket_create('shop')

    def test_health_bootstraps_the_single_node_layout(self):
        garage = FakeGarage(with_role=False)
        with s3_sandbox(garage):
            self.assertEqual(s3.health(None, call=garage), (False, 'GET /health -> HTTP 503'))
            ok, detail = actions._health_once('s3')
            self.assertTrue(ok, detail)
            self.assertEqual(garage.roles[0]['id'], NODE)
            self.assertGreaterEqual(garage.roles[0]['capacity'], 1024 ** 3)
            self.assertEqual(garage.version, 1)
            calls = len(garage.calls)
            self.assertTrue(actions._health_once('s3')[0])
            self.assertNotIn('/v2/UpdateClusterLayout', [c[1] for c in garage.calls[calls:]], 'only once')

    def test_connection_info(self):
        cfg, _ = s3.validate(s3.defaults(), RAM)
        local = s3.connection_info(cfg)
        self.assertEqual(local['url'], 'http://127.0.0.1:3900')
        self.assertTrue(local['backup']['use_http'])
        info = s3.connection_info(cfg, 's3.example.com')
        text = json.dumps(info)
        self.assertEqual((info['url'], info['region'], info['port']), ('https://s3.example.com', 'garage', 443))
        self.assertIn('path-style', info['style'])
        self.assertIn('force_path_style = true', text)
        self.assertIn('use_path_style_endpoint', text)
        self.assertIn('aws --endpoint-url https://s3.example.com', text)
        self.assertEqual(info['backup']['link'], '/addons/destinations/')
        self.assertFalse(info['backup']['use_http'])
        self.assertIn(info['backup']['preset'], text)


class Rollback(SimpleTestCase):
    def test_failed_health_check_restores_the_configuration(self):
        with s3_sandbox() as (base, garage, paths):
            with open(paths['CONF']) as handle:
                before = handle.read()
            settings = dict(defaults_in(base), memory_mb=300, region='eu-1')
            with mock.patch.object(actions, '_restart') as restart:
                with mock.patch.object(actions, '_wait_healthy', return_value=(False, 'GET /health -> HTTP 503')):
                    data = run_job(actions.configure_run, app='s3', settings=settings)
                self.assertEqual(data['state'], 'failed', data)
                self.assertIn('previous configuration was restored', data['error'])
                self.assertEqual(restart.call_count, 2)
                with open(paths['CONF']) as handle:
                    self.assertEqual(handle.read(), before)
                with open(paths['DROPIN']) as handle:
                    self.assertIn('MemoryMax=256M', handle.read())
                with mock.patch.object(actions, '_wait_healthy', return_value=(True, 'GET /health -> 200')):
                    data = run_job(actions.configure_run, app='s3', settings=settings)
                self.assertEqual(data['state'], 'done', data)
                with open(paths['CONF']) as handle:
                    self.assertIn('s3_region = "eu-1"', handle.read())
                with open(paths['DROPIN']) as handle:
                    self.assertIn('MemoryMax=300M', handle.read())
                restart.assert_called_with('s3')

    def test_data_dir_change_refused_while_buckets_exist(self):
        with s3_sandbox() as (base, garage, paths):
            actions.s3_bucket_create('shop')
            with self.assertRaisesRegex(sv.AppError, 'no buckets'):
                actions._validate('s3', dict(defaults_in(base), data_dir=os.path.join(base, 'lib', 'other')), RAM, False)
            with self.assertRaisesRegex(sv.AppError, 'HTTPS endpoint'):
                actions._validate('s3', dict(defaults_in(base), bind='0.0.0.0'), RAM, True)


def _blob(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def _layer(binary):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as archive:
        info = tarfile.TarInfo('garage')
        info.size = len(binary)
        archive.addfile(info, io.BytesIO(binary))
    return gzip.compress(raw.getvalue())


class Download(SimpleTestCase):
    def fetch(self, release=b'GARAGE-BINARY', image=b'GARAGE-BINARY', layer_served=None, manifest_digest=None):
        layer = _layer(image)
        manifest = json.dumps({'layers': [{'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip',
                                           'size': len(layer), 'digest': _blob(layer)}]}).encode()
        index = json.dumps({'manifests': [
            {'digest': _blob(b'arm'), 'platform': {'os': 'linux', 'architecture': 'arm64'}},
            {'digest': manifest_digest or _blob(manifest), 'platform': {'os': 'linux', 'architecture': 'amd64'}}]}).encode()
        urls = []

        def get(url, headers=None, **kwargs):
            urls.append(url)
            if url.startswith('https://auth.docker.io/'):
                return b'{"token": "t"}', {}
            if url.endswith('/manifests/' + s3.VERSION):
                return index, {'docker-content-digest': _blob(index)}
            if '/manifests/sha256:' in url:
                return manifest, {}
            raise AssertionError(url)

        def download(url, target, limit, headers=None):
            urls.append(url)
            data = (layer_served or layer) if '/blobs/' in url else release
            with open(target, 'wb') as handle:
                handle.write(data)
            return hashlib.sha256(data).hexdigest()
        job = mock.Mock()
        with sandbox() as base, mock.patch.object(actions, '_http_get', side_effect=get), \
                mock.patch.object(actions, '_http_download', side_effect=download):
            work = os.path.join(base, 'dl')
            os.makedirs(work)
            path, sha, detail = actions._s3_fetch(job, work)
            with open(path, 'rb') as handle:
                content = handle.read()
        return content, sha, detail, urls

    def test_verified_binary_from_two_official_channels(self):
        content, sha, detail, urls = self.fetch()
        self.assertEqual(content, b'GARAGE-BINARY')
        self.assertEqual(sha, hashlib.sha256(b'GARAGE-BINARY').hexdigest())
        self.assertIn('agree', detail)
        self.assertIn('https://garagehq.deuxfleurs.fr/_releases/%s/x86_64-unknown-linux-musl/garage' % s3.VERSION, urls)
        self.assertTrue(all(u.startswith('https://') for u in urls))
        self.assertTrue(any('/v2/dxflrs/garage/blobs/sha256:' in u for u in urls))

    def test_mismatches_stop_the_install(self):
        with self.assertRaisesRegex(sv.AppError, 'differs from the one in the official Docker image'):
            self.fetch(release=b'TAMPERED')
        with self.assertRaisesRegex(sv.AppError, 'Checksum mismatch on the image layer'):
            self.fetch(layer_served=_layer(b'OTHER'))
        with self.assertRaisesRegex(sv.AppError, 'Checksum mismatch'):
            self.fetch(manifest_digest=_blob(b'not the manifest'))
        with mock.patch.dict(s3.PINNED_SHA256, {s3.VERSION: '0' * 64}):
            with self.assertRaisesRegex(sv.AppError, 'pinned'):
                self.fetch()
        with mock.patch.dict(s3.PINNED_SHA256, {s3.VERSION: hashlib.sha256(b'GARAGE-BINARY').hexdigest()}):
            self.assertIn('pinned checksum', self.fetch()[2])

    def test_layer_extraction_takes_only_the_binary(self):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as archive:
            link = tarfile.TarInfo('garage')
            link.type, link.linkname = tarfile.SYMTYPE, '/etc/shadow'
            archive.addfile(link)
        with sandbox() as base:
            layer = os.path.join(base, 'l.tar.gz')
            with open(layer, 'wb') as handle:
                handle.write(gzip.compress(raw.getvalue()))
            with self.assertRaisesRegex(sv.AppError, 'not a regular file'):
                s3.extract_binary(layer, os.path.join(base, 'out'))
        with self.assertRaises(sv.AppError):
            s3.single_layer({'layers': [{'mediaType': 'x', 'digest': 'sha256:' + '0' * 64}] * 2})
        with self.assertRaisesRegex(sv.AppError, 'amd64'):
            s3.pick_amd64({'manifests': [{'digest': 'x', 'platform': {'os': 'linux', 'architecture': 'arm64'}}]})


class Uninstall(SimpleTestCase):
    def _preview(self, files):
        job_id = os.urandom(12).hex()
        from universalAddons import jobs
        job = jobs.Job(job_id)
        job.data.update(module='appsvc', action='remove_preview_run', state='done',
                        result={'Preview removal': {'app': 's3', 'packages': files}})
        job._save()
        return job_id

    def test_preview_then_confirm_and_data_kept_unless_typed(self):
        with s3_sandbox() as (base, garage, paths), mock.patch.object(sv, 'run', return_value=(0, '')):
            plan = run_job(actions.remove_preview_run, app='s3')['result']['Preview removal']
            self.assertIn(paths['BIN'], plan['files'])
            self.assertIn(paths['SECRET_DIR'], plan['files'])
            self.assertEqual(plan['data_dir'], os.path.join(base, 'lib', 'garage'))
            with self.assertRaisesRegex(sv.AppError, 'Preview what will be removed first'):
                actions.removal_confirmation('s3', True, False, '', None)
            preview = self._preview(plan['packages'])
            with self.assertRaisesRegex(sv.AppError, 'Type s3'):
                actions.removal_confirmation('s3', True, True, 'garage', preview)
            self.assertEqual(actions.removal_confirmation('s3', True, True, 'S3', preview), plan['packages'])
            changed = run_job(actions.remove_run, app='s3', delete_data=False, packages=plan['packages'][:-1])
            self.assertEqual(changed['state'], 'failed')
            self.assertTrue(os.path.exists(paths['BIN']), 'nothing removed when the plan changed')
            data = run_job(actions.remove_run, app='s3', delete_data=False, packages=plan['packages'])
            self.assertEqual(data['state'], 'done', data)
            for name in ('BIN', 'CONF', 'DROPIN', 'SECRET_DIR'):
                self.assertFalse(os.path.exists(paths[name]), name)
            self.assertTrue(os.path.isdir(plan['data_dir']), 'data kept without the typed confirmation')
            self.assertIsNone(actions._version('s3'))
        with s3_sandbox() as (base, garage, paths), mock.patch.object(sv, 'run', return_value=(0, '')):
            plan = actions._s3_removal_plan()
            data = run_job(actions.remove_run, app='s3', delete_data=True, packages=plan['packages'])
            self.assertEqual(data['state'], 'done', data)
            self.assertFalse(os.path.exists(plan['data_dir']))

    def test_view_needs_preview_and_typed_name(self):
        with mock.patch('universalAddons.privileged.call', return_value={'job_id': 'x'}) as call:
            self.assertEqual(helpers.post(views.remove, {'app': 's3', 'confirm': True}, admin=True)[0], 400)
            self.assertEqual(helpers.post(views.remove, {'app': 's3', 'confirm': True, 'deleteData': True,
                                                         'confirmName': 'garage', 'previewJob': 'ab' * 12}, admin=True)[0], 400)
            call.assert_not_called()
            helpers.post(views.remove, {'app': 's3', 'confirm': True, 'deleteData': True, 'confirmName': 's3',
                                        'previewJob': 'ab' * 12}, admin=True)
            call.assert_called_with('appsvc', 'remove', app='s3', confirm=True, delete_data=True, confirm_name='s3',
                                    preview_job='ab' * 12)


VHOST = """docRoot                   $VH_ROOT/public_html
vhDomain                  $VH_NAME

vhssl  {
  keyFile                 /etc/letsencrypt/live/s3.example.com/privkey.pem
  certFile                /etc/letsencrypt/live/s3.example.com/fullchain.pem
}
"""


class Endpoint(SimpleTestCase):
    def test_vhost_block(self):
        text = s3.apply_vhost(VHOST, 3900)
        self.assertEqual(s3.apply_vhost(text, 3900), text, 'idempotent')
        self.assertIn('address                 127.0.0.1:3900', text)
        self.assertIn('context / {\n  type                    proxy\n  handler                 cp_appsvc_s3', text)
        self.assertLess(text.index(s3.VHOST_BEGIN), text.index('vhssl'))
        self.assertEqual(s3.strip_vhost_block(text).strip(), VHOST.strip())
        self.assertEqual(s3.vhost_problems(VHOST), [])
        self.assertEqual(s3.vhost_problems(text), [], 'its own block is no problem')
        self.assertIn('SSL', s3.vhost_problems('docRoot $VH_ROOT/public_html\n')[0])
        self.assertIn('context /', ' '.join(s3.vhost_problems(VHOST + 'context / {\n  type proxy\n}\n')))

    def test_endpoint_job_writes_vhost_and_public_endpoint(self):
        from universalAddons.htaccess import service as hs
        with s3_sandbox() as (base, garage, paths):
            vhosts = os.path.join(base, 'vhosts')
            os.makedirs(os.path.join(vhosts, 's3.example.com'))
            vhost = os.path.join(vhosts, 's3.example.com', 'vhost.conf')
            with open(vhost, 'w') as handle:
                handle.write(VHOST)
            with mock.patch.object(hs, 'VHOSTS', vhosts), mock.patch.object(hs, 'BACKUP_DIR', os.path.join(base, 'hb')), \
                    mock.patch.object(hs, 'restart', return_value=True), mock.patch.object(actions, '_restart'), \
                    mock.patch.object(actions, '_wait_healthy', return_value=(True, 'GET /health -> 200')):
                with self.assertRaisesRegex(sv.AppError, 'No OpenLiteSpeed vhost'):
                    actions.s3_endpoint('set', 'other.example.com')
                data = run_job(actions.s3_endpoint_run, op='set', domain='s3.example.com')
                self.assertEqual(data['state'], 'done', data)
                with open(vhost) as handle:
                    self.assertIn(s3.VHOST_BEGIN, handle.read())
                with open(paths['CONF']) as handle:
                    self.assertIn('public_endpoint = "https://s3.example.com"', handle.read())
                self.assertEqual(actions._current('s3', RAM)['endpoint'], 's3.example.com')
                self.assertEqual(actions._app_status('s3', RAM, 2000, 5000)['connection']['url'], 'https://s3.example.com')
                # Public listening is allowed now (with the confirmation); removing the endpoint then is refused.
                cfg, warnings = actions._validate('s3', dict(defaults_in(base), bind='0.0.0.0'), RAM, True)
                self.assertTrue(warnings[0].startswith('DANGER'))
                with mock.patch.object(actions, '_wait_healthy', return_value=(False, 'down')):
                    failed = run_job(actions.s3_endpoint_run, op='remove')
                self.assertEqual(failed['state'], 'failed')
                with open(vhost) as handle:
                    self.assertIn(s3.VHOST_BEGIN, handle.read(), 'the proxy came back with the rollback')
                self.assertEqual(actions._current('s3', RAM)['endpoint'], 's3.example.com')
                data = run_job(actions.s3_endpoint_run, op='remove')
                self.assertEqual(data['state'], 'done', data)
                with open(vhost) as handle:
                    self.assertEqual(handle.read().strip(), VHOST.strip())
                with open(paths['CONF']) as handle:
                    self.assertNotIn('public_endpoint', handle.read())


class Page(SimpleTestCase):
    def test_page_renders_the_s3_pane(self):
        status, values = helpers.page(views.page, admin=True)
        self.assertEqual(status, 200)
        request = RequestFactory().get('/addons/applications/')
        request.session = {}
        html = render_to_string('universalAddons/appsvc.html', dict(values, request=request))
        for needle in ('id="as-pane-s3"', 'S3 Object Storage (Garage)', 'as-s3-bucket-create', 'as-s3-key-create',
                       'as-s3-perm-save', 'as-s3-endpoint-set', 'HTTPS endpoint for customers', 'shown once',
                       'type s3', 'IndiansCloud'):
            self.assertIn(needle, html)
        self.assertEqual(len(re.findall(r'id="as-pane-s3"', html)), 1)
        self.assertNotIn('CyberPanel', re.sub(r'<script[^>]*>.*?</script>', '', html.split('id="as-pane-s3"')[1]
                                             .split('id="as-pane-oracle_client"')[0], flags=re.S))

    def test_status_when_not_installed(self):
        with s3_sandbox(installed=False), mock.patch.object(actions, '_el', return_value=8), \
                mock.patch.object(actions, '_caps', return_value={}):
            status = actions._app_status('s3', RAM, 2000, 5000)
        self.assertFalse(status['installed'])
        self.assertIn('os', [c['id'] for c in status['preflight']])


class ServicesPage(SimpleTestCase):
    def test_services_list_includes_garage_when_installed(self):
        from serverStatus import views as status_views
        self.assertIn('garage', [u for u, _, _ in status_views.EXTRA_SERVICES])
        self.assertEqual(status_views.EXTRA_ACTIONS['garage'], ('start', 'stop', 'restart'))

        def executor(installed):
            def run(command):
                if command.startswith('systemctl list-unit-files'):
                    return 'redis.service enabled\n' + ('garage.service enabled\n' if installed else '')
                if command.startswith('systemctl is-active'):
                    return 'active\n' * len(command.split()[2:])
                return ''
            return run
        units = [e['unit'] for e in status_views.extra_services([], executor=executor(True))]
        self.assertIn('garage', units)
        units = [e['unit'] for e in status_views.extra_services([], executor=executor(False))]
        self.assertNotIn('garage', units)
